package com.techrebbe.supernote.spreadprobe.v2;

import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Event-driven owner-transfer coordinator. It never calls firmware while
 * holding its own monitor; native callbacks may therefore complete
 * synchronously without deadlocking the page-ownership state. The controller
 * is thread-confined to the thread that constructs it. Android/Binder
 * callbacks must be marshalled to that owner before entering this class.
 */
public final class NativeReaderController {
    public enum InputResult { PASS_NATIVE, CONSUMED, BLOCKED }

    public static final class DownDecision {
        public final InputResult result;
        public final long gestureTokenId;

        private DownDecision(InputResult result, long gestureTokenId) {
            this.result = result;
            this.gestureTokenId = gestureTokenId;
        }
    }

    public interface Port {
        void freezeInput(ActivationMachine.Token token);
        void requestSourceSave(ActivationMachine.Token token);
        void disableWriter(ActivationMachine.Token token);
        void requestTargetLoad(ActivationMachine.Token token);
        void replayPen(
            ActivationMachine.Token token,
            List<GestureBuffer.Sample> sourceSamples
        );
        void replayFingerHit(
            ActivationMachine.Token token,
            PointD sourcePoint
        );
        void navigateSwipe(
            SpreadSnapshot sourceSnapshot,
            double deltaX,
            double deltaY
        );
        void releaseInput(ActivationMachine.Token token);
        void requestRollback(ActivationMachine.Token token);
        void disableFeature(ActivationMachine.Token token, String reason);
    }

    private enum ReplayKind { NONE, PEN, FINGER }

    private static final class Context {
        final SpreadSnapshot sourceSnapshot;
        final PageSlot targetSlot;
        final GestureRouter.Token gesture;
        final ReplayKind replayKind;
        final double downX;
        final double downY;
        ActivationMachine.Token activation;
        GestureBuffer penBuffer;
        PointD fingerSourcePoint;
        PointD lastPenSourcePoint;
        NativeAuthority targetAuthority;
        boolean fingerMoved;
        boolean inputComplete;
        boolean targetPublished;
        boolean replayRequested;
        boolean sourceSaveHandled;
        boolean targetLoadHandled;
        boolean targetReadyHandled;
        boolean replayCompletionHandled;
        boolean rollbackRequested;

        Context(
            SpreadSnapshot sourceSnapshot,
            PageSlot targetSlot,
            GestureRouter.Token gesture,
            ReplayKind replayKind,
            double downX,
            double downY
        ) {
            this.sourceSnapshot = sourceSnapshot;
            this.targetSlot = targetSlot;
            this.gesture = gesture;
            this.replayKind = replayKind;
            this.downX = downX;
            this.downY = downY;
        }
    }

    private static final double FINGER_TAP_SLOP_SQUARED = 24.0 * 24.0;

    private final Object lock = new Object();
    private final SpreadSession session;
    private final Port port;
    private final int maxPenSamples;
    private final int maxPenBytes;
    private final long maxPenDurationMs;
    private final long ownerThreadId;
    private Context context;
    private volatile boolean retired;

    public NativeReaderController(
        SpreadSession session,
        Port port,
        int maxPenSamples,
        int maxPenBytes,
        long maxPenDurationMs
    ) {
        this.session = Objects.requireNonNull(session, "session");
        this.port = Objects.requireNonNull(port, "port");
        if (maxPenSamples < 2 || maxPenBytes < 96 || maxPenDurationMs <= 0) {
            throw new IllegalArgumentException("invalid pen replay bounds");
        }
        this.maxPenSamples = maxPenSamples;
        this.maxPenBytes = maxPenBytes;
        this.maxPenDurationMs = maxPenDurationMs;
        this.ownerThreadId = Thread.currentThread().getId();
    }

    public DownDecision onDown(
        int pointerId,
        double screenX,
        double screenY,
        double pressure,
        long eventTimeMs,
        GestureRouter.Tool tool,
        List<RectD> visibleNativeChrome
    ) {
        assertOwnerThread();
        if (!validInputSample(
            pointerId,
            screenX,
            screenY,
            pressure,
            eventTimeMs
        ) || tool == null) {
            return decision(InputResult.BLOCKED, null);
        }
        SpreadSnapshot snapshot = session.snapshot();
        if (snapshot == null || retired) {
            return decision(InputResult.BLOCKED, null);
        }
        synchronized (lock) {
            if (retired || context != null) {
                return decision(InputResult.BLOCKED, null);
            }
        }
        GestureRouter.Token gesture;
        try {
            gesture = session.gestures().begin(
                snapshot,
                pointerId,
                screenX,
                screenY,
                tool,
                visibleNativeChrome
            );
        } catch (RuntimeException exception) {
            return decision(InputResult.BLOCKED, null);
        }
        if (gesture.route == GestureRouter.Route.NATIVE_CHROME
            || gesture.route == GestureRouter.Route.ACTIVE_DOCUMENT) {
            return decision(InputResult.PASS_NATIVE, gesture);
        }
        if (gesture.route == GestureRouter.Route.BLOCKED) {
            session.gestures().finish(gesture.id, pointerId);
            return decision(InputResult.BLOCKED, gesture);
        }

        PageSlot target = snapshot.slotForPage(gesture.sourcePageIndex);
        if (target == null || target.isBlank()) {
            session.gestures().finish(gesture.id, pointerId);
            return decision(InputResult.BLOCKED, gesture);
        }
        if (gesture.route == GestureRouter.Route.ACTIVATE_AND_REPLAY_HIT) {
            ReplayKind replayKind = target.containsContent(screenX, screenY)
                ? ReplayKind.FINGER : ReplayKind.NONE;
            Context pending = new Context(
                snapshot,
                target,
                gesture,
                replayKind,
                screenX,
                screenY
            );
            if (replayKind == ReplayKind.FINGER) {
                pending.fingerSourcePoint = target.mapToSource(
                    screenX,
                    screenY
                );
            }
            synchronized (lock) {
                if (retired || context != null) {
                    session.gestures().finish(gesture.id, pointerId);
                    return decision(InputResult.BLOCKED, gesture);
                }
                context = pending;
            }
            return decision(InputResult.CONSUMED, gesture);
        }

        Context pending = new Context(
            snapshot,
            target,
            gesture,
            ReplayKind.PEN,
            screenX,
            screenY
        );
        pending.activation = session.activation().begin(
            snapshot,
            target.sourcePageIndex,
            true
        );
        if (pending.activation == null) {
            session.gestures().finish(gesture.id, pointerId);
            return decision(InputResult.BLOCKED, gesture);
        }
        pending.penBuffer = new GestureBuffer(
            gesture.id,
            maxPenSamples,
            maxPenBytes,
            maxPenDurationMs
        );
        PointD sourcePoint = target.mapToSource(screenX, screenY);
        pending.lastPenSourcePoint = sourcePoint;
        if (!pending.penBuffer.append(
            gesture.id,
            new GestureBuffer.Sample(
                eventTimeMs,
                GestureBuffer.Action.DOWN,
                sourcePoint.x,
                sourcePoint.y,
                pressure
            )
        )) {
            session.gestures().finish(gesture.id, pointerId);
            requestRollback(pending, "initial_pen_buffer_failed");
            return decision(InputResult.BLOCKED, gesture);
        }
        boolean accepted;
        synchronized (lock) {
            if (retired || context != null) {
                accepted = false;
            } else {
                context = pending;
                accepted = true;
            }
        }
        if (!accepted) {
            session.gestures().finish(gesture.id, pointerId);
            requestRollback(pending, "activation_context_race");
            return decision(InputResult.BLOCKED, gesture);
        }
        startActivation(pending);
        return decision(InputResult.CONSUMED, gesture);
    }

    public InputResult onMotion(
        long gestureTokenId,
        int pointerId,
        GestureBuffer.Action action,
        double screenX,
        double screenY,
        double pressure,
        long eventTimeMs
    ) {
        assertOwnerThread();
        if (action == null || action == GestureBuffer.Action.DOWN) {
            return InputResult.BLOCKED;
        }
        GestureRouter.Token gesture = session.gestures().current(
            gestureTokenId,
            pointerId
        );
        if (gesture == null) {
            return InputResult.BLOCKED;
        }
        if (!validInputSample(
            pointerId,
            screenX,
            screenY,
            pressure,
            eventTimeMs
        )) {
            session.gestures().finish(gestureTokenId, pointerId);
            Context invalid;
            synchronized (lock) {
                invalid = context != null && context.gesture == gesture
                    ? context : null;
            }
            if (invalid != null && invalid.activation != null) {
                requestRollback(invalid, "invalid_motion_sample");
            }
            return InputResult.BLOCKED;
        }
        if (gesture.route == GestureRouter.Route.NATIVE_CHROME
            || gesture.route == GestureRouter.Route.ACTIVE_DOCUMENT) {
            if (isTerminal(action)) {
                session.gestures().finish(gestureTokenId, pointerId);
            }
            return InputResult.PASS_NATIVE;
        }
        Context current;
        synchronized (lock) {
            current = context;
        }
        if (current == null || current.gesture != gesture
            || !session.gestures().authorityCurrent(
                gesture,
                current.sourceSnapshot
            )) {
            session.gestures().finish(gestureTokenId, pointerId);
            return InputResult.BLOCKED;
        }

        if (gesture.tool == GestureRouter.Tool.FINGER) {
            double deltaX = screenX - current.downX;
            double deltaY = screenY - current.downY;
            if (deltaX * deltaX + deltaY * deltaY
                > FINGER_TAP_SLOP_SQUARED) {
                current.fingerMoved = true;
            }
            if (action == GestureBuffer.Action.CANCEL) {
                finishGestureOnly(current, pointerId);
                return InputResult.CONSUMED;
            }
            if (action == GestureBuffer.Action.UP) {
                session.gestures().finish(
                    current.gesture.id,
                    pointerId
                );
                if (current.fingerMoved) {
                    clearContext(current);
                    try {
                        port.navigateSwipe(
                            current.sourceSnapshot,
                            deltaX,
                            deltaY
                        );
                    } catch (Throwable throwable) {
                        hardDisable(null, "finger_swipe_failed");
                    }
                } else {
                    if (!beginDeferredFingerActivation(current)) {
                        return InputResult.BLOCKED;
                    }
                    startActivation(current);
                }
            }
            return InputResult.CONSUMED;
        }

        PointD sourcePoint = current.lastPenSourcePoint;
        if (current.targetSlot.containsContent(screenX, screenY)) {
            sourcePoint = current.targetSlot.mapToSource(screenX, screenY);
            current.lastPenSourcePoint = sourcePoint;
        } else if (!isTerminal(action)) {
            return InputResult.CONSUMED;
        }
        GestureBuffer.Action bufferedAction = action;
        if (!current.penBuffer.append(
            gestureTokenId,
            new GestureBuffer.Sample(
                eventTimeMs,
                bufferedAction,
                sourcePoint.x,
                sourcePoint.y,
                pressure
            )
        )) {
            session.gestures().finish(gestureTokenId, pointerId);
            requestRollback(current, "pen_buffer_bound_exceeded");
            return InputResult.BLOCKED;
        }
        if (isTerminal(action)) {
            session.gestures().finish(gestureTokenId, pointerId);
            synchronized (lock) {
                if (context == current) {
                    current.inputComplete = true;
                }
            }
            if (action == GestureBuffer.Action.CANCEL) {
                requestRollback(current, "pen_contact_cancelled");
            } else {
                requestReplayIfReady(current);
            }
        }
        return InputResult.CONSUMED;
    }

    public boolean onInactiveHover(
        double screenX,
        double screenY,
        List<RectD> visibleNativeChrome
    ) {
        assertOwnerThread();
        SpreadSnapshot snapshot = session.snapshot();
        if (snapshot == null || retired) {
            return false;
        }
        if (session.gestures().classifyHover(
            snapshot,
            screenX,
            screenY,
            GestureRouter.Tool.STYLUS,
            visibleNativeChrome
        ) != GestureRouter.Route.ACTIVATE_AND_BUFFER_PEN) {
            return false;
        }
        PageSlot slot = snapshot.slotAt(screenX, screenY);
        if (slot == null || slot.isBlank()
            || slot.sourcePageIndex == snapshot.activePageIndex) {
            return false;
        }
        Context pending = new Context(
            snapshot,
            slot,
            null,
            ReplayKind.NONE,
            screenX,
            screenY
        );
        pending.inputComplete = true;
        boolean accepted;
        synchronized (lock) {
            if (retired || context != null
                || session.gestures().hasActiveGesture()) {
                accepted = false;
            } else {
                context = pending;
                accepted = true;
            }
        }
        if (!accepted) {
            return false;
        }
        pending.activation = session.activation().begin(
            snapshot,
            slot.sourcePageIndex,
            false
        );
        if (pending.activation == null) {
            clearContext(pending);
            return false;
        }
        startActivation(pending);
        return true;
    }

    public void onActivationTimeout(ActivationMachine.Token token) {
        assertOwnerThread();
        Context current;
        boolean replayMayHaveMutated;
        synchronized (lock) {
            current = matchingContext(token);
            replayMayHaveMutated = current != null
                && current.replayRequested;
        }
        if (current == null) {
            return;
        }
        if (replayMayHaveMutated) {
            hardDisable(token, "native_replay_timeout_uncertain");
        } else {
            requestRollback(current, "activation_timeout");
        }
    }

    public void onSourceSaveComplete(
        ActivationMachine.Token token,
        boolean success
    ) {
        assertOwnerThread();
        Context current;
        synchronized (lock) {
            current = matchingContext(token);
            if (current == null || current.sourceSaveHandled) {
                return;
            }
            current.sourceSaveHandled = true;
        }
        if (!success || !session.activation().sourceSaved(token)) {
            requestRollback(current, "source_save_failed_or_stale");
            return;
        }
        try {
            port.disableWriter(token);
            port.requestTargetLoad(token);
        } catch (Throwable throwable) {
            requestRollback(current, "target_load_request_failed");
        }
    }

    public void onTargetLoadComplete(
        ActivationMachine.Token token,
        int loadedPage,
        boolean success
    ) {
        assertOwnerThread();
        Context current;
        boolean ordered;
        synchronized (lock) {
            current = matchingContext(token);
            if (current == null || current.targetLoadHandled) {
                return;
            }
            ordered = current.sourceSaveHandled;
            current.targetLoadHandled = true;
        }
        if (!ordered || !success
            || !session.activation().targetLoaded(token, loadedPage)) {
            requestRollback(current, "target_load_failed_or_wrong_page");
        }
    }

    public void onTargetReady(
        ActivationMachine.Token token,
        NativeAuthority authority,
        SpreadSnapshot publishedTarget
    ) {
        assertOwnerThread();
        Context current;
        boolean ordered;
        synchronized (lock) {
            current = matchingContext(token);
            if (current == null || current.targetReadyHandled) {
                return;
            }
            ordered = current.targetLoadHandled;
            current.targetReadyHandled = true;
        }
        if (!ordered || !session.activation().targetVerified(token, authority)
            || !session.publishActivated(token, publishedTarget)) {
            requestRollback(current, "target_authority_or_publication_failed");
            return;
        }
        boolean contextLost;
        synchronized (lock) {
            if (context != current) {
                contextLost = true;
            } else {
                contextLost = false;
                current.targetAuthority = authority;
                current.targetPublished = true;
            }
        }
        if (contextLost) {
            hardDisable(token, "target_publication_context_lost");
            return;
        }
        if (current.replayKind == ReplayKind.NONE) {
            finishSuccessfulActivation(current);
        } else {
            requestReplayIfReady(current);
        }
    }

    public void onReplayComplete(
        ActivationMachine.Token token,
        boolean success
    ) {
        assertOwnerThread();
        Context current;
        boolean ordered;
        synchronized (lock) {
            current = matchingContext(token);
            if (current == null || current.replayCompletionHandled) {
                return;
            }
            ordered = current.replayRequested;
            current.replayCompletionHandled = true;
        }
        if (!ordered) {
            hardDisable(token, "native_replay_completed_before_request");
            return;
        }
        if (!success || current.targetAuthority == null
            || !session.activation().replayComplete(
                token,
                current.targetAuthority
            )) {
            hardDisable(token, "native_replay_failed_or_uncertain");
            return;
        }
        finishSuccessfulActivation(current);
    }

    public void onRollbackReady(
        ActivationMachine.Token token,
        NativeAuthority sourceAuthority,
        SpreadSnapshot publishedSource
    ) {
        assertOwnerThread();
        Context current = current(token);
        if (current == null) {
            return;
        }
        if (!session.activation().rollbackVerified(token, sourceAuthority)
            || !session.publishRollback(token, publishedSource)) {
            onRollbackFailed(token, "rollback_authority_failed");
            return;
        }
        clearContext(current);
        try {
            port.releaseInput(token);
        } catch (Throwable throwable) {
            hardDisable(token, "rollback_release_failed");
        }
    }

    public void onRollbackFailed(
        ActivationMachine.Token token,
        String reason
    ) {
        assertOwnerThread();
        if (token == null) {
            hardDisable(null, reason);
            return;
        }
        if (current(token) == null) {
            return;
        }
        session.activation().rollbackFailed(token);
        hardDisable(token, reason);
    }

    public void retire() {
        assertOwnerThread();
        synchronized (lock) {
            retired = true;
            context = null;
        }
        session.retire();
    }

    private boolean beginDeferredFingerActivation(Context pending) {
        ActivationMachine.Token token = session.activation().begin(
            pending.sourceSnapshot,
            pending.targetSlot.sourcePageIndex,
            pending.replayKind != ReplayKind.NONE
        );
        if (token == null) {
            clearContext(pending);
            return false;
        }
        pending.activation = token;
        pending.inputComplete = true;
        return true;
    }

    private void startActivation(Context pending) {
        ActivationMachine.Token token = pending.activation;
        try {
            port.freezeInput(token);
            port.requestSourceSave(token);
        } catch (Throwable throwable) {
            requestRollback(pending, "source_save_request_failed");
        }
    }

    private void requestReplayIfReady(Context expected) {
        GestureBuffer penBuffer;
        ReplayKind initialKind;
        synchronized (lock) {
            if (retired || context != expected || expected.replayRequested
                || !expected.targetPublished || !expected.inputComplete) {
                return;
            }
            initialKind = expected.replayKind;
            penBuffer = expected.penBuffer;
        }

        List<GestureBuffer.Sample> penSamples =
            Collections.<GestureBuffer.Sample>emptyList();
        if (initialKind == ReplayKind.PEN) {
            if (penBuffer == null || !penBuffer.isReplayable()) {
                requestRollback(expected, "pen_buffer_not_replayable");
                return;
            }
            penSamples = penBuffer.immutableSamples();
        } else if (initialKind != ReplayKind.FINGER) {
            return;
        }

        ActivationMachine.Token token;
        PointD fingerPoint;
        synchronized (lock) {
            if (retired || context != expected || expected.replayRequested
                || !expected.targetPublished || !expected.inputComplete
                || expected.replayKind != initialKind
                || expected.penBuffer != penBuffer) {
                return;
            }
            expected.replayRequested = true;
            token = expected.activation;
            fingerPoint = expected.fingerSourcePoint;
        }
        try {
            if (initialKind == ReplayKind.PEN) {
                port.replayPen(token, penSamples);
            } else {
                port.replayFingerHit(token, fingerPoint);
            }
        } catch (Throwable throwable) {
            hardDisable(token, "native_replay_request_threw");
        }
    }

    private void requestRollback(Context expected, String reason) {
        ActivationMachine.Token token = expected == null
            ? null : expected.activation;
        if (token == null) {
            hardDisable(token, reason + "_without_transaction");
            return;
        }
        synchronized (lock) {
            if (retired || expected.rollbackRequested) {
                return;
            }
            if (context != null && context != expected) {
                return;
            }
            expected.rollbackRequested = true;
        }
        if (!session.activation().fail(token)) {
            ActivationMachine.Status status = session.activation().status();
            if (status.transactionId == token.id
                && (status.state == ActivationMachine.State.ROLLING_BACK
                    || status.state
                        == ActivationMachine.State.ROLLBACK_PUBLISHING)) {
                return;
            }
            hardDisable(token, reason + "_transaction_rejected_rollback");
            return;
        }
        try {
            port.requestRollback(token);
        } catch (Throwable throwable) {
            onRollbackFailed(token, reason + "_rollback_request_failed");
        }
    }

    private void finishSuccessfulActivation(Context expected) {
        ActivationMachine.Token token = expected.activation;
        clearContext(expected);
        try {
            port.releaseInput(token);
        } catch (Throwable throwable) {
            hardDisable(token, "activation_release_failed");
        }
    }

    private void finishGestureOnly(Context expected, int pointerId) {
        if (expected.gesture != null) {
            session.gestures().finish(expected.gesture.id, pointerId);
        }
        clearContext(expected);
    }

    private void clearContext(Context expected) {
        synchronized (lock) {
            if (context == expected) {
                context = null;
            }
        }
    }

    private Context current(ActivationMachine.Token token) {
        synchronized (lock) {
            return matchingContext(token);
        }
    }

    private Context matchingContext(ActivationMachine.Token token) {
        return !retired && context != null
            && context.activation == token ? context : null;
    }

    private void hardDisable(
        ActivationMachine.Token token,
        String reason
    ) {
        synchronized (lock) {
            retired = true;
            context = null;
        }
        session.retire();
        try {
            port.disableFeature(token, reason);
        } catch (Throwable ignored) {
            // The in-memory authority is already retired. There is no safe
            // fallback call after the firmware port itself fails.
        }
    }

    private static boolean isTerminal(GestureBuffer.Action action) {
        return action == GestureBuffer.Action.UP
            || action == GestureBuffer.Action.CANCEL;
    }

    private static boolean validInputSample(
        int pointerId,
        double screenX,
        double screenY,
        double pressure,
        long eventTimeMs
    ) {
        return pointerId >= 0 && eventTimeMs >= 0
            && Double.isFinite(screenX) && Double.isFinite(screenY)
            && Double.isFinite(pressure) && pressure >= 0.0;
    }

    private void assertOwnerThread() {
        if (Thread.currentThread().getId() != ownerThreadId) {
            throw new IllegalStateException(
                "NativeReaderController callback was not marshalled "
                + "to its owner thread"
            );
        }
    }

    private static DownDecision decision(
        InputResult result,
        GestureRouter.Token token
    ) {
        return new DownDecision(
            result,
            token == null ? -1L : token.id
        );
    }
}
