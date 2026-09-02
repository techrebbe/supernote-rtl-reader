package com.techrebbe.supernote.spreadprobe.v2;

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
        void replayFingerHit(
            ActivationMachine.Token token,
            PointD sourcePoint
        );
        int navigationTarget(
            SpreadSnapshot sourceSnapshot,
            double deltaX,
            double deltaY
        );
        void releaseInput(ActivationMachine.Token token);
        void requestRollback(ActivationMachine.Token token);
        void disableFeature(ActivationMachine.Token token, String reason);
    }

    private enum ReplayKind { NONE, DROP_PEN, FINGER }

    private static final class Context {
        final SpreadSnapshot sourceSnapshot;
        final PageSlot targetSlot;
        final GestureRouter.Token gesture;
        final ReplayKind replayKind;
        final double downX;
        final double downY;
        ActivationMachine.Token activation;
        PointD fingerSourcePoint;
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
    private final long ownerThreadId;
    private Context context;
    private volatile boolean retired;

    public NativeReaderController(
        SpreadSession session,
        Port port
    ) {
        this.session = Objects.requireNonNull(session, "session");
        this.port = Objects.requireNonNull(port, "port");
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
            ReplayKind.DROP_PEN,
            screenX,
            screenY
        );
        pending.activation = session.activation().begin(
            snapshot,
            target.sourcePageIndex,
            ActivationMachine.CompletionMode.DRAIN_CONTACT
        );
        if (pending.activation == null) {
            session.gestures().finish(gesture.id, pointerId);
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
        GestureAction action,
        double screenX,
        double screenY,
        double pressure,
        long eventTimeMs
    ) {
        assertOwnerThread();
        if (action == null || action == GestureAction.DOWN) {
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
            if (invalid != null) {
                if (invalid.activation != null) {
                    requestRollback(invalid, "invalid_motion_sample");
                } else {
                    clearContext(invalid);
                }
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
            if (action == GestureAction.CANCEL) {
                finishGestureOnly(current, pointerId);
                return InputResult.CONSUMED;
            }
            if (action == GestureAction.UP) {
                session.gestures().finish(
                    current.gesture.id,
                    pointerId
                );
                if (current.fingerMoved) {
                    try {
                        int target = port.navigationTarget(
                            current.sourceSnapshot,
                            deltaX,
                            deltaY
                        );
                        startNavigation(current, target);
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

        if (isTerminal(action)) {
            session.gestures().finish(gestureTokenId, pointerId);
            synchronized (lock) {
                if (context == current) {
                    current.inputComplete = true;
                }
            }
            completeDroppedContactIfReady(current);
        }
        return InputResult.CONSUMED;
    }

    /** Starts the same save/disable/load transaction for native toolbar turns. */
    public boolean requestNavigation(int targetPage) {
        assertOwnerThread();
        SpreadSnapshot snapshot = session.snapshot();
        if (snapshot == null || retired || targetPage < 0
            || targetPage >= snapshot.pageCount
            || targetPage == snapshot.activePageIndex
            || session.gestures().hasActiveGesture()) {
            return false;
        }
        Context pending = new Context(
            snapshot,
            null,
            null,
            ReplayKind.NONE,
            Double.NaN,
            Double.NaN
        );
        pending.inputComplete = true;
        synchronized (lock) {
            if (retired || context != null) {
                return false;
            }
            context = pending;
        }
        pending.activation = session.activation().begin(
            snapshot,
            targetPage,
            ActivationMachine.CompletionMode.IMMEDIATE
        );
        if (pending.activation == null) {
            clearContext(pending);
            return false;
        }
        startActivation(pending);
        return true;
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
        ) != GestureRouter.Route.ACTIVATE_AND_DRAIN_PEN) {
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
            ActivationMachine.CompletionMode.IMMEDIATE
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
        } else if (current.replayKind == ReplayKind.DROP_PEN) {
            completeDroppedContactIfReady(current);
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
            pending.replayKind == ReplayKind.FINGER
                ? ActivationMachine.CompletionMode.REPLAY_INPUT
                : ActivationMachine.CompletionMode.IMMEDIATE
        );
        if (token == null) {
            clearContext(pending);
            return false;
        }
        pending.activation = token;
        pending.inputComplete = true;
        return true;
    }

    private void startNavigation(Context sourceGesture, int targetPage) {
        if (targetPage < 0
            || targetPage == sourceGesture.sourceSnapshot.activePageIndex) {
            clearContext(sourceGesture);
            return;
        }
        Context pending = new Context(
            sourceGesture.sourceSnapshot,
            null,
            null,
            ReplayKind.NONE,
            sourceGesture.downX,
            sourceGesture.downY
        );
        pending.inputComplete = true;
        synchronized (lock) {
            if (retired || context != sourceGesture) {
                return;
            }
            context = pending;
        }
        pending.activation = session.activation().begin(
            pending.sourceSnapshot,
            targetPage,
            ActivationMachine.CompletionMode.IMMEDIATE
        );
        if (pending.activation == null) {
            clearContext(pending);
            return;
        }
        startActivation(pending);
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
        ReplayKind initialKind;
        synchronized (lock) {
            if (retired || context != expected || expected.replayRequested
                || !expected.targetPublished || !expected.inputComplete) {
                return;
            }
            initialKind = expected.replayKind;
        }

        if (initialKind != ReplayKind.FINGER) {
            return;
        }

        ActivationMachine.Token token;
        PointD fingerPoint;
        synchronized (lock) {
            if (retired || context != expected || expected.replayRequested
                || !expected.targetPublished || !expected.inputComplete
                || expected.replayKind != initialKind
            ) {
                return;
            }
            expected.replayRequested = true;
            token = expected.activation;
            fingerPoint = expected.fingerSourcePoint;
        }
        try {
            port.replayFingerHit(token, fingerPoint);
        } catch (Throwable throwable) {
            hardDisable(token, "native_replay_request_threw");
        }
    }

    private void completeDroppedContactIfReady(Context expected) {
        ActivationMachine.Token token;
        NativeAuthority authority;
        synchronized (lock) {
            if (retired || context != expected || !expected.inputComplete
                || !expected.targetPublished
                || expected.replayKind != ReplayKind.DROP_PEN) {
                return;
            }
            token = expected.activation;
            authority = expected.targetAuthority;
        }
        if (!session.activation().contactDrained(token, authority)) {
            hardDisable(token, "dropped_pen_contact_drain_failed");
            return;
        }
        finishSuccessfulActivation(expected);
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

    private static boolean isTerminal(GestureAction action) {
        return action == GestureAction.UP
            || action == GestureAction.CANCEL;
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
