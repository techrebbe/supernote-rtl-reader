package com.techrebbe.supernote.spreadprobe.v2android;

import android.app.Activity;
import android.content.res.Configuration;
import android.graphics.Bitmap;
import android.graphics.RectF;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.util.Log;
import android.view.MotionEvent;

import com.techrebbe.supernote.spreadprobe.v2.NativeAuthority;
import com.techrebbe.supernote.spreadprobe.v2.NativeReaderController;
import com.techrebbe.supernote.spreadprobe.v2.NativeReaderFirmwarePort;
import com.techrebbe.supernote.spreadprobe.v2.NativeReaderV2LayoutFactory;
import com.techrebbe.supernote.spreadprobe.v2.NativeReaderV2MarkerClaim;
import com.techrebbe.supernote.spreadprobe.v2.NativeReaderV2Navigation;
import com.techrebbe.supernote.spreadprobe.v2.NativeSaveWitness;
import com.techrebbe.supernote.spreadprobe.v2.NativeWriterGeometry;
import com.techrebbe.supernote.spreadprobe.v2.GestureAction;
import com.techrebbe.supernote.spreadprobe.v2.GestureRouter;
import com.techrebbe.supernote.spreadprobe.v2.PageSlot;
import com.techrebbe.supernote.spreadprobe.v2.PointD;
import com.techrebbe.supernote.spreadprobe.v2.RectD;
import com.techrebbe.supernote.spreadprobe.v2.SpreadSession;
import com.techrebbe.supernote.spreadprobe.v2.SpreadSnapshot;

import java.util.Objects;
import java.util.Collections;
import java.util.ArrayList;
import java.util.List;
import java.util.ArrayDeque;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Owner-thread Android runtime for one admitted original PDF. No legacy
 * Native Spread state is consulted or mutated here.
 */
public final class NativeReaderV2Runtime
    implements NativeReaderFirmwarePort.Bridge {

    /** The hook layer owns the one-contact bypass used for a replayed finger tap. */
    public interface FingerReplayInjector {
        void replayFingerTap(Activity activity, PointD screenPoint);
    }

    /** Immediate cross-stream contact authority owned by the hook shell. */
    public interface PhysicalContactFence {
        boolean stylusContactActive();
    }

    /** Releases the hook-level admission fence only after native authority exists. */
    public interface ActivationListener {
        void onRuntimeInputAuthorityReady(NativeReaderV2Runtime runtime);
    }

    private static final String TAG = "SN_NATIVE_READER_V2";
    private static final long READY_RETRY_MS = 60L;
    private static final int READY_RETRY_LIMIT = 40;
    private static final long ACTIVATION_TIMEOUT_MS = 10_000L;
    private static final int MAX_DEFERRED_NAVIGATION = 16;

    private final Activity activity;
    private final NativeReaderV2DocumentGate.Evidence evidence;
    private final NativeReaderV2MarkerClaim claim;
    private final NativeReaderV2FirmwareAccess firmware;
    private final NativeReaderV2Compositor compositor;
    private final NativeReaderV2StatusOverlay statusOverlay;
    private final Handler ownerHandler;
    private final long ownerThreadId;
    private final long activityGeneration;
    private final NativeSaveWitness saveWitness = new NativeSaveWitness();
    private final FingerReplayInjector fingerReplayInjector;
    private final PhysicalContactFence physicalContactFence;
    private final ActivationListener activationListener;
    private final ExecutorService projectionExecutor =
        Executors.newSingleThreadExecutor();

    // Read by the firmware's native pen callback before samples are posted to
    // the owner thread. Volatile publication is required; SpreadSession then
    // publishes its immutable snapshot through AtomicReference.
    private volatile SpreadSession session;
    private NativeReaderFirmwarePort port;
    private NativeReaderController controller;
    private NativeReaderV2FirmwareAccess.Components components;
    private NativeReaderV2Compositor.Result visible;
    private NativeReaderV2FirmwareAccess.PageGeometryLease pageGeometryLease;
    private NativeReaderV2FirmwareAccess.PresentationScaleLease
        presentationScaleLease;
    private NativeWriterGeometry writerGeometryLease;
    private NativeReaderFirmwarePort.Observation latestObservation;
    private long layoutGeneration;
    private long markRevision;
    private long refreshGeneration;
    private boolean writerDisabled;
    private volatile boolean inputFrozen;
    private volatile boolean retired;
    // Published on the firmware callback thread before Supernote receives
    // the first sample. The owner-thread GestureRouter token may be posted a
    // little later, so refresh also consults this zero-work contact latch.
    private volatile boolean nativePenCallbackContact;
    private volatile List<RectD> nativeChromeMasks = Collections.emptyList();
    private volatile List<RectD> trackedChromeMasks = Collections.emptyList();
    private boolean internalPageLoad;
    private boolean samePageReloadPrepared;
    private boolean nativeLifecycleHandoffPending;
    private boolean nativeLifecycleCallbackCompleted;
    private boolean nativeLifecyclePause;
    private String nativeLifecycleHandoffReason;
    private boolean saveWitnessFault;
    private boolean detachmentPrepared;
    private boolean containedFailClosed;
    private boolean activationReported;
    private long compositionGeneration;
    private long fingerGestureToken;
    private int fingerPointerId = -1;
    private boolean fingerContact;
    private boolean fingerConsumed;
    private boolean fingerConcurrentBlocked;
    private long penGestureToken;
    private boolean penContact;
    private boolean penSuppressed;
    private int lastPenX;
    private int lastPenY;
    private long lastPenEventTimeMs;
    private Integer deferredReplayLoadTarget;
    private final ArrayDeque<DeferredNavigation> deferredNavigation =
        new ArrayDeque<>();

    public NativeReaderV2Runtime(
        Activity activity,
        NativeReaderV2DocumentGate.Evidence evidence,
        NativeReaderV2FirmwareAccess firmware,
        long activityGeneration,
        FingerReplayInjector fingerReplayInjector,
        PhysicalContactFence physicalContactFence,
        ActivationListener activationListener
    ) {
        this.activity = Objects.requireNonNull(activity, "activity");
        this.evidence = Objects.requireNonNull(evidence, "evidence");
        this.claim = evidence.claim;
        this.firmware = Objects.requireNonNull(firmware, "firmware");
        this.fingerReplayInjector = Objects.requireNonNull(
            fingerReplayInjector,
            "fingerReplayInjector"
        );
        this.physicalContactFence = Objects.requireNonNull(
            physicalContactFence,
            "physicalContactFence"
        );
        this.activationListener = Objects.requireNonNull(
            activationListener,
            "activationListener"
        );
        if (activityGeneration <= 0L || Looper.myLooper() != activity.getMainLooper()) {
            throw new IllegalArgumentException(
                "runtime must be constructed on its activity owner thread"
            );
        }
        this.activityGeneration = activityGeneration;
        this.ownerHandler = new Handler(activity.getMainLooper());
        this.ownerThreadId = Thread.currentThread().getId();
        this.compositor = new NativeReaderV2Compositor(firmware);
        this.statusOverlay = new NativeReaderV2StatusOverlay(activity);
    }

    public Activity activity() {
        return activity;
    }

    public String admittedDocumentPath() {
        return claim.canonicalDocumentPath;
    }

    public boolean admissionEvidenceStillCurrent() {
        return NativeReaderV2DocumentGate.evidenceStillCurrent(evidence);
    }

    public boolean ownsViewModel(Object candidate) {
        assertOwnerThread();
        return !retired && components != null
            && components.viewModel == candidate;
    }

    public boolean ownsNote(Object candidate) {
        assertOwnerThread();
        return !retired && components != null
            && components.note == candidate;
    }

    public boolean isLandscapeActive() {
        assertOwnerThread();
        return !retired && session != null && session.snapshot() != null
            && session.snapshot().mode == SpreadSnapshot.Mode.SPREAD;
    }

    public boolean isInternalPageLoad() {
        assertOwnerThread();
        return internalPageLoad;
    }

    public int adjustPortraitTurnOffset(int nativeOffset) {
        assertOwnerThread();
        if (retired || isLandscapeActive() || nativeOffset == 0) {
            return nativeOffset;
        }
        return claim.config.direction
            == com.techrebbe.supernote.spreadprobe.v2.SpreadPairing.Direction.RTL
                ? -nativeOffset : nativeOffset;
    }

    public boolean requestNavigation(int targetPage) {
        assertOwnerThread();
        SpreadSnapshot snapshot = session == null ? null : session.snapshot();
        if (retired || snapshot == null || targetPage < 0
            || targetPage >= snapshot.pageCount) return false;
        if (canStartNavigationNow()
            && controller.requestNavigation(targetPage)) return true;
        return enqueueNavigation(DeferredNavigation.absolute(
            snapshot,
            targetPage
        ));
    }

    public boolean requestNativeTurn(int nativeOffset) {
        assertOwnerThread();
        SpreadSnapshot snapshot = session == null ? null : session.snapshot();
        if (retired || snapshot == null || nativeOffset == 0) return false;
        int target = NativeReaderV2Navigation.offsetTarget(
            snapshot,
            claim.config,
            nativeOffset
        );
        if (target < 0) return true;
        if (canStartNavigationNow()
            && controller.requestNavigation(target)) return true;
        return enqueueNavigation(DeferredNavigation.offset(
            snapshot,
            nativeOffset
        ));
    }

    /**
     * Captures an internal-link load emitted synchronously by a replayed
     * inactive-page finger hit.  Letting that nested load run immediately
     * would replace the native page while the activation transaction is
     * still proving its replay result.  The exact target is therefore
     * suppressed once and executed on the owner queue after replay commits.
     */
    public boolean deferNativeLoadDuringReplay(int targetPage) {
        assertOwnerThread();
        if (retired || port == null
            || port.phase() != NativeReaderFirmwarePort.Phase.REPLAYING
            || session == null || targetPage < 0
            || targetPage >= session.snapshot().pageCount) {
            return false;
        }
        if (deferredReplayLoadTarget != null
            && deferredReplayLoadTarget.intValue() != targetPage) {
            disableNativeReaderV2("conflicting_replayed_link_targets");
            return false;
        }
        if (deferredReplayLoadTarget == null) {
            deferredReplayLoadTarget = targetPage;
            postGuarded("deferred_replay_load", new Runnable() {
                @Override public void run() {
                    drainDeferredReplayLoad();
                }
            });
        }
        return true;
    }

    public boolean isCurrentNativePage(int targetPage) {
        assertOwnerThread();
        SpreadSnapshot snapshot = session == null ? null : session.snapshot();
        return !retired && snapshot != null
            && targetPage == snapshot.activePageIndex;
    }

    /**
     * Relinquishes the complete v2 presentation contract before the firmware
     * performs an in-place reload of the already-active source page.
     */
    public boolean prepareSamePageReload() {
        assertOwnerThread();
        if (retired || !isLandscapeActive() || latestObservation == null
            || port == null || port.phase() != NativeReaderFirmwarePort.Phase.IDLE) {
            return false;
        }
        inputFrozen = true;
        ++refreshGeneration;
        if (!saveCurrentSourceNow()) {
            disableNativeReaderV2("same_page_reload_save_failed");
            return false;
        }
        NativeReaderV2FirmwareAccess.Components current = inspectNativeCurrent();
        firmware.disableWriter(current, "SN_NATIVE_READER_V2 same-page reload");
        writerDisabled = true;
        restoreWriterGeometry();
        restorePageGeometry();
        restorePresentationScale();
        samePageReloadPrepared = true;
        retireTransactionalCore();
        return true;
    }

    /**
     * Relinquishes every v2-owned native object before DocumentViewModel
     * mutates its URI and tears down the old page cache. This boundary is
     * mandatory for cross-document links as well as same-file reopen.
     */
    public boolean prepareNativeDocumentOpen() {
        assertOwnerThread();
        if (retired) return false;
        inputFrozen = true;
        samePageReloadPrepared = false;
        ++refreshGeneration;
        if (port != null && port.phase() != NativeReaderFirmwarePort.Phase.IDLE) {
            disableNativeReaderV2("document_open_during_writer_transfer");
            return false;
        }
        if (latestObservation != null && !saveCurrentSourceNow()) {
            disableNativeReaderV2("document_open_source_save_failed");
            return false;
        }
        try {
            NativeReaderV2FirmwareAccess.Components current =
                inspectNativeCurrent();
            if (writerGeometryLease != null || pageGeometryLease != null) {
                firmware.disableWriter(
                    current,
                    "SN_NATIVE_READER_V2 native document open"
                );
                writerDisabled = true;
            }
            restoreWriterGeometry();
            restorePageGeometry();
            restorePresentationScale();
            retireTransactionalCore();
            // The projector is a native SuperNoteNote instance bound to the
            // old document's .mark path. Do not leave that file/native state
            // alive across DocumentViewModel's URI mutation, even when the
            // next document is ordinary and never creates another projector.
            firmware.releaseProjectionReader();
            removeStatusOverlayQuietly("native_document_open");
            detachmentPrepared = true;
            return true;
        } catch (RuntimeException failure) {
            Log.e(TAG, "native document-open restoration failed", failure);
            disableNativeReaderV2("document_open_restore_failed");
            return false;
        }
    }

    /** Restores stock page geometry before DocumentViewModel changes crop. */
    public boolean prepareNativeScaleChange() {
        assertOwnerThread();
        return prepareSamePageReload();
    }

    /**
     * Rebuilds the native page from its newly committed crop rectangle before
     * v2 reads any display, digest, or handwriting bitmap from that state.
     */
    public void completeNativeScaleChange(boolean firmwareSucceeded) {
        assertOwnerThread();
        if (retired) return;
        if (!firmwareSucceeded || !samePageReloadPrepared) {
            disableNativeReaderV2("native_scale_change_failed");
            return;
        }
        NativeReaderV2FirmwareAccess.Components current =
            inspectNativeCurrent();
        internalPageLoad = true;
        try {
            firmware.reloadDocumentPage(current);
        } finally {
            internalPageLoad = false;
        }
        scheduleRefresh("native_scale_changed");
    }

    public int targetForNativeOffset(int nativeOffset) {
        assertOwnerThread();
        SpreadSnapshot snapshot = session == null ? null : session.snapshot();
        return NativeReaderV2Navigation.offsetTarget(
            snapshot,
            claim.config,
            nativeOffset
        );
    }

    public boolean suppressNativePresentation() {
        assertOwnerThread();
        return !retired && (isLandscapeActive() || samePageReloadPrepared);
    }

    /**
     * Lock-free callback-thread classifier. A PASS decision is safe only for
     * visible native chrome or the already-published active writer page.
     * Every other sample is suppressed and marshalled to the owner thread.
     */
    public boolean mayPassNativePenImmediately(
        double x,
        double y,
        List<RectD> visibleNativeChrome
    ) {
        // A retired adapter and an admitted portrait document are completely
        // native.  Returning false here would suppress the firmware's
        // digital-position callback even though v2 has no spread writer to
        // receive it.  Only a live, frozen landscape transaction fails
        // closed.
        if (retired) return true;
        if (nativeLifecycleHandoffPending) return false;
        if (inputFrozen) return false;
        SpreadSession currentSession = session;
        SpreadSnapshot snapshot = currentSession == null
            ? null : currentSession.snapshot();
        if (snapshot == null || snapshot.mode != SpreadSnapshot.Mode.SPREAD) {
            return true;
        }
        for (RectD rect : safeChrome(visibleNativeChrome)) {
            if (rect != null && rect.contains(x, y)) return true;
        }
        for (RectD rect : nativeChromeMasks) {
            if (rect != null && rect.contains(x, y)) return true;
        }
        if (!snapshot.writerReady) return false;
        PageSlot slot = snapshot.slotAt(x, y);
        return slot != null && !slot.isBlank()
            && slot.sourcePageIndex == snapshot.activePageIndex
            && slot.containsContent(x, y);
    }

    /** Establishes refresh exclusion before native pen DOWN is dispatched. */
    public void noteNativePenCallbackContact() {
        // Admission may be live just before the first landscape session is
        // published. Latch every contact owned by this runtime, including a
        // portrait contact; the terminal path below releases it even when no
        // v2 controller exists.
        nativePenCallbackContact = !retired;
    }

    public void postNativePenPosition(
        int x,
        int y,
        int pressure,
        long eventTimeMs,
        List<RectD> visibleNativeChrome
    ) {
        final List<RectD> chrome = combinedChrome(visibleNativeChrome);
        postGuarded("native_pen_position", new Runnable() {
            @Override public void run() {
                routeNativePenPosition(
                    x,
                    y,
                    pressure,
                    eventTimeMs,
                    chrome
                );
            }
        });
    }

    public void onNativePresentationChanged(String reason) {
        assertOwnerThread();
        if (!retired) scheduleRefresh(reason);
    }

    public void onNativeDisableAreasChanged() {
        assertOwnerThread();
        NativeWriterGeometry geometry = writerGeometryLease;
        if (retired || inputFrozen || geometry == null || writerDisabled) return;
        try {
            NativeReaderV2FirmwareAccess.Components current =
                inspectNativeCurrent();
            SpreadSnapshot snapshot = session == null
                ? null : session.snapshot();
            List<RectD> overlayMasks = statusOverlay.protectedAreas(
                snapshot,
                claim.config.showHeader,
                current.documentLayout.getWidth(),
                current.documentLayout.getHeight()
            );
            List<RectD> writerChrome = concatenateMasks(
                trackedChromeMasks,
                overlayMasks
            );
            nativeChromeMasks = concatenateMasks(
                firmware.nativeChromeDisabledAreas(current), writerChrome
            );
            firmware.refreshWriterDisabledAreas(
                current,
                geometry,
                writerChrome
            );
        } catch (RuntimeException failure) {
            Log.e(TAG, "native chrome mask refresh failed", failure);
            disableNativeReaderV2("native_chrome_mask_refresh_failed");
        }
    }

    /**
     * Publishes the exact visible Android chrome into both the fast input
     * classifier and DrawPath's native disabled-area list. Passing an EMR
     * contact to a popup is safe only when the native writer is physically
     * masked beneath the same rectangle.
     */
    public void onTrackedNativeChromeChanged(List<RectD> visibleChrome) {
        assertOwnerThread();
        trackedChromeMasks = Collections.unmodifiableList(
            new ArrayList<>(safeChrome(visibleChrome))
        );
        onNativeDisableAreasChanged();
    }

    /**
     * Returns true only when the Activity touch must be consumed by v2.
     * Native chrome and the active document page continue through unchanged.
     */
    public boolean routeFinger(
        MotionEvent event,
        List<RectD> visibleNativeChrome
    ) {
        assertOwnerThread();
        if (retired || event == null) return false;
        int action = event.getActionMasked();
        if (nativeLifecycleHandoffPending) {
            boolean consume = fingerConsumed;
            if (action == MotionEvent.ACTION_UP
                || action == MotionEvent.ACTION_CANCEL) {
                clearFingerRoute();
                completeNativeLifecycleHandoffIfReady();
            }
            return consume;
        }
        if (controller == null) return false;
        if (action == MotionEvent.ACTION_DOWN) {
            fingerContact = true;
            fingerConsumed = true;
            fingerConcurrentBlocked = physicalContactFence
                .stylusContactActive();
            if (fingerConcurrentBlocked) return true;
            if (event.getPointerCount() != 1) return true;
            fingerPointerId = event.getPointerId(0);
            NativeReaderController.DownDecision decision = controller.onDown(
                fingerPointerId,
                event.getX(0),
                event.getY(0),
                event.getPressure(0),
                event.getEventTime(),
                GestureRouter.Tool.FINGER,
                combinedChrome(visibleNativeChrome)
            );
            fingerGestureToken = decision.gestureTokenId;
            fingerConsumed = decision.result
                != NativeReaderController.InputResult.PASS_NATIVE;
            return fingerConsumed;
        }
        if (!fingerContact) return inputFrozen;
        if (action == MotionEvent.ACTION_POINTER_DOWN
            || action == MotionEvent.ACTION_POINTER_UP) {
            cancelFingerGesture(event.getEventTime());
            fingerConcurrentBlocked = true;
            return true;
        }
        boolean terminal = action == MotionEvent.ACTION_UP
            || action == MotionEvent.ACTION_CANCEL;
        if (fingerConcurrentBlocked) {
            if (terminal) finishFingerRoute(true);
            return true;
        }
        if (fingerGestureToken <= 0L || fingerPointerId < 0) {
            boolean consume = fingerConsumed;
            if (terminal) finishFingerRoute(consume);
            return consume;
        }
        int pointerIndex = event.findPointerIndex(fingerPointerId);
        if (pointerIndex < 0) {
            controller.onMotion(
                fingerGestureToken,
                fingerPointerId,
                GestureAction.CANCEL,
                0.0,
                0.0,
                0.0,
                Math.max(0L, event.getEventTime())
            );
            boolean consume = fingerConsumed;
            finishFingerRoute(consume);
            return consume;
        }
        GestureAction routeAction = motionAction(action);
        if (routeAction == null) return fingerConsumed;
        if (routeAction == GestureAction.UP
            && physicalContactFence.stylusContactActive()) {
            cancelFingerGesture(event.getEventTime());
            finishFingerRoute(true);
            return true;
        }
        controller.onMotion(
            fingerGestureToken,
            fingerPointerId,
            routeAction,
            event.getX(pointerIndex),
            event.getY(pointerIndex),
            event.getPressure(pointerIndex),
            event.getEventTime()
        );
        if (routeAction == GestureAction.UP
            || routeAction == GestureAction.CANCEL) {
            boolean consume = fingerConsumed;
            finishFingerRoute(consume);
            return consume;
        }
        return fingerConsumed;
    }

    /**
     * Constant-time route for the native DrawPath callback. The hook supplies
     * a prepublished immutable chrome snapshot; no view traversal, I/O, or
     * serialization occurs here.
     */
    public boolean routeNativePenPosition(
        int x,
        int y,
        int pressure,
        long eventTimeMs,
        List<RectD> visibleNativeChrome
    ) {
        assertOwnerThread();
        if (retired) return false;
        lastPenX = x;
        lastPenY = y;
        lastPenEventTimeMs = eventTimeMs;
        if (nativeLifecycleHandoffPending) {
            if (pressure <= 0) {
                clearPenRoute();
                nativePenCallbackContact = false;
                completeNativeLifecycleHandoffIfReady();
            }
            return false;
        }
        if (controller == null) {
            boolean latched = nativePenCallbackContact;
            if (pressure <= 0) {
                nativePenCallbackContact = false;
                if (latched && isLandscape()) {
                    scheduleRefresh("native_pen_contact_before_session");
                }
            }
            return false;
        }
        if (pressure > 0 && !penContact) {
            NativeReaderController.DownDecision decision = controller.onDown(
                0,
                x,
                y,
                pressure,
                eventTimeMs,
                GestureRouter.Tool.STYLUS,
                combinedChrome(visibleNativeChrome)
            );
            penContact = true;
            penGestureToken = decision.gestureTokenId;
            penSuppressed = decision.result
                != NativeReaderController.InputResult.PASS_NATIVE;
            return penSuppressed;
        }
        if (penContact) {
            GestureAction action = pressure > 0
                ? GestureAction.MOVE : GestureAction.UP;
            NativeReaderController.InputResult result = controller.onMotion(
                penGestureToken,
                0,
                action,
                x,
                y,
                Math.max(0, pressure),
                eventTimeMs
            );
            boolean suppress = penSuppressed
                || result != NativeReaderController.InputResult.PASS_NATIVE;
            if (pressure <= 0) {
                clearPenRoute();
                nativePenCallbackContact = false;
                // Native setBitmap/digest callbacks can arrive before the
                // digital-position stream reports contact-up. Any refresh
                // posted by those callbacks is deliberately ignored while
                // the gesture token is live; this post-contact refresh is the
                // one authoritative opportunity to publish settled state.
                if (isLandscapeActive()) {
                    scheduleRefresh("native_pen_contact_complete");
                }
            }
            return suppress;
        }
        if (inputFrozen) return true;
        return controller.onInactiveHover(
            x,
            y,
            combinedChrome(visibleNativeChrome)
        );
    }

    /**
     * Android UP corroborates a physical terminal when the firmware omits its
     * pressure-zero sample. Cancel the owner-thread gesture, but keep the hook
     * shell suppressing native samples until a real pressure-zero boundary is
     * observed so a late packet cannot be mistaken for a new stroke.
     */
    public void cancelMissingNativePenTerminal() {
        assertOwnerThread();
        if (retired || !nativePenCallbackContact) return;
        if (controller != null && penContact && penGestureToken > 0L) {
            try {
                controller.onMotion(
                    penGestureToken,
                    0,
                    GestureAction.CANCEL,
                    lastPenX,
                    lastPenY,
                    0.0,
                    Math.max(0L, lastPenEventTimeMs)
                );
            } catch (RuntimeException failure) {
                Log.e(TAG, "missing native pen terminal cancellation failed",
                    failure);
            }
        }
        clearPenRoute();
        nativePenCallbackContact = false;
        if (isLandscapeActive()) {
            scheduleRefresh("native_pen_terminal_missing_cancelled");
        }
    }

    /** Called after setImage/configuration/page-ready firmware callbacks. */
    public void scheduleRefresh(String reason) {
        assertOwnerThread();
        if (retired) return;
        long generation = ++refreshGeneration;
        final String refreshReason = reason == null ? "signal" : reason;
        postGuarded("refresh:" + refreshReason, new Runnable() {
            @Override public void run() {
                refreshWhenReady(generation, 0, refreshReason);
            }
        });
    }

    public void beforeConfigurationChange() {
        assertOwnerThread();
        if (retired) return;
        if (hasLiveInputContact()) {
            beginNativeLifecycleHandoff(
                "configuration_change_during_contact",
                false
            );
            return;
        }
        inputFrozen = true;
        samePageReloadPrepared = false;
        ++refreshGeneration;
        if (port != null && port.phase() != NativeReaderFirmwarePort.Phase.IDLE) {
            disableNativeReaderV2("rotation_during_writer_transfer");
            return;
        }
        if (latestObservation != null && !saveCurrentSourceNow()) {
            disableNativeReaderV2("rotation_source_save_failed");
            return;
        }
        if (components != null) {
            firmware.disableWriter(
                inspectNativeCurrent(),
                "SN_NATIVE_READER_V2 configuration change"
            );
            writerDisabled = true;
            restoreWriterGeometry();
            restorePageGeometry();
            restorePresentationScale();
        }
        retireTransactionalCore();
    }

    public void afterConfigurationChange() {
        assertOwnerThread();
        if (retired) return;
        if (nativeLifecycleHandoffPending) {
            nativeLifecycleCallbackCompleted = true;
            completeNativeLifecycleHandoffIfReady();
            return;
        }
        scheduleRefresh("configuration_changed");
    }

    public void beforeLifecyclePause() {
        assertOwnerThread();
        if (retired || latestObservation == null) return;
        if (hasLiveInputContact()) {
            beginNativeLifecycleHandoff("pause_during_contact", true);
            return;
        }
        inputFrozen = true;
        samePageReloadPrepared = false;
        ++refreshGeneration;
        if (port != null && port.phase() != NativeReaderFirmwarePort.Phase.IDLE) {
            disableNativeReaderV2("pause_during_writer_transfer");
            return;
        }
        if (!saveCurrentSourceNow()) {
            disableNativeReaderV2("pause_source_save_failed");
            return;
        }
        firmware.disableWriter(
            inspectNativeCurrent(),
            "SN_NATIVE_READER_V2 lifecycle pause"
        );
        writerDisabled = true;
        restoreWriterGeometry();
        restorePageGeometry();
        restorePresentationScale();
        retireTransactionalCore();
    }

    /** Completes a live-contact pause only after stock onPause has settled it. */
    public void afterLifecyclePause() {
        assertOwnerThread();
        if (retired || !nativeLifecycleHandoffPending
            || !nativeLifecyclePause) return;
        // Stock onPause has already cancelled selection, disabled DrawPath,
        // cleared its surface, and reloaded the native page. A missing input
        // terminal must not strand v2's restoration leases while the
        // Activity is backgrounded.
        nativePenCallbackContact = false;
        clearPenRoute();
        clearFingerRoute();
        nativeLifecycleCallbackCompleted = true;
        completeNativeLifecycleHandoffIfReady();
    }

    public void onNativeSaveMarkData(
        Object note,
        String markPath,
        int oneBasedPage,
        boolean cleanTrail,
        boolean result
    ) {
        assertOwnerThread();
        if (!saveWitness.active()) return;
        try {
            saveWitness.observe(
                note,
                markPath,
                oneBasedPage,
                cleanTrail,
                result
            );
        } catch (RuntimeException failure) {
            saveWitnessFault = true;
            Log.e(TAG, "save witness observation failed", failure);
        }
    }

    public boolean retire(String reason) {
        assertOwnerThread();
        if (retired) return true;
        if (!detachmentPrepared && latestObservation != null) {
            // A hook-discovery, revalidation, or component fault is not a
            // license to abandon a live writer. Preserve routing ownership
            // until the source is witnessed saved and stock presentation is
            // restored. If any boundary is unavailable, stay installed and
            // block input fail-closed.
            if (hasLiveInputContact() || port != null
                && port.phase() != NativeReaderFirmwarePort.Phase.IDLE
                || !restoreStockPresentationForRetirement(reason)) {
                containFailClosed(reason);
                return false;
            }
            detachmentPrepared = true;
        }
        retirePrepared(reason, false);
        return true;
    }

    /**
     * Called only after the pinned native Activity has completed its own
     * onDestroy save/disable/clear sequence. Its component objects are dead;
     * invoking restorative firmware setters now would mutate invalid state
     * and, before the stock save, could reinterpret a live trail under the
     * stock transform. Dead leases are therefore discarded only here.
     */
    public void retireAfterNativeDestroy(String reason) {
        assertOwnerThread();
        if (retired) {
            firmware.releaseComponentIds(components);
            components = null;
            return;
        }
        NativeReaderV2FirmwareAccess.Components releasedComponents = components;
        retired = true;
        projectionExecutor.shutdown();
        inputFrozen = true;
        nativePenCallbackContact = false;
        samePageReloadPrepared = false;
        clearNativeLifecycleHandoff();
        ++refreshGeneration;
        retireTransactionalCore();
        pageGeometryLease = null;
        presentationScaleLease = null;
        writerGeometryLease = null;
        writerDisabled = true;
        visible = null;
        latestObservation = null;
        components = null;
        firmware.releaseComponentIds(releasedComponents);
        removeStatusOverlayQuietly("native_activity_destroyed");
        Log.w(TAG, "runtime released after native destroy reason=" + reason);
    }

    private void retirePrepared(String reason, boolean keepWriterDisabled) {
        assertOwnerThread();
        if (retired) return;
        NativeReaderV2FirmwareAccess.Components releasedComponents = components;
        retired = true;
        projectionExecutor.shutdown();
        inputFrozen = true;
        nativePenCallbackContact = false;
        samePageReloadPrepared = false;
        clearNativeLifecycleHandoff();
        ++refreshGeneration;
        retireTransactionalCore();
        restoreWriterGeometryQuietly("runtime_retire");
        restorePageGeometryQuietly("runtime_retire");
        restorePresentationScaleQuietly("runtime_retire");
        if (keepWriterDisabled) {
            try {
                firmware.disableWriter(
                    inspectNativeCurrent(),
                    "SN_NATIVE_READER_V2 fail-closed retirement"
                );
                writerDisabled = true;
            } catch (RuntimeException failure) {
                Log.e(TAG, "writer fail-close failed during retirement",
                    failure);
            }
        }
        // The Android views can still reference the last composed bitmaps.
        // Recycling here produces use-after-recycle draws. Activity teardown
        // or the next native presentation owns their eventual release.
        visible = null;
        latestObservation = null;
        components = null;
        firmware.releaseComponentIds(releasedComponents);
        removeStatusOverlayQuietly("runtime_retire");
        Log.w(TAG, "runtime retired reason=" + reason);
    }

    private boolean restoreStockPresentationForRetirement(String reason) {
        inputFrozen = true;
        samePageReloadPrepared = false;
        ++refreshGeneration;
        try {
            if (!saveCurrentSourceNow()) return false;
            NativeReaderV2FirmwareAccess.Components current =
                inspectNativeCurrent();
            firmware.disableWriter(
                current,
                "SN_NATIVE_READER_V2 safe retirement " + reason
            );
            writerDisabled = true;
            restoreWriterGeometry();
            restorePageGeometry();
            restorePresentationScale();
            internalPageLoad = true;
            try {
                firmware.reloadDocumentPage(current);
            } finally {
                internalPageLoad = false;
            }
            retireTransactionalCore();
            recycleVisible();
            removeStatusOverlayQuietly("safe_retirement");
            return true;
        } catch (RuntimeException failure) {
            Log.e(TAG, "stock presentation restoration failed reason="
                + reason, failure);
            return false;
        }
    }

    private void containFailClosed(String reason) {
        inputFrozen = true;
        samePageReloadPrepared = false;
        containedFailClosed = true;
        ++refreshGeneration;
        try {
            NativeReaderV2FirmwareAccess.Components current =
                inspectNativeCurrent();
            firmware.disableWriter(
                current,
                "SN_NATIVE_READER_V2 contained failure " + reason
            );
            writerDisabled = true;
        } catch (RuntimeException failure) {
            Log.e(TAG, "writer containment failed reason=" + reason, failure);
        }
        Log.e(TAG, "runtime retained fail-closed reason=" + reason);
    }

    /**
     * Freezes v2 without abandoning its restoration leases. The stock
     * lifecycle callback is allowed to cancel/settle the live contact first;
     * only its after-hook or the matching terminal sample may complete the
     * save/disable/restore boundary.
     */
    private void beginNativeLifecycleHandoff(
        String reason,
        boolean pause
    ) {
        inputFrozen = true;
        samePageReloadPrepared = false;
        ++refreshGeneration;
        nativeLifecycleHandoffPending = true;
        nativeLifecycleCallbackCompleted = false;
        nativeLifecyclePause = pause;
        nativeLifecycleHandoffReason = reason;
        Log.w(TAG, "runtime deferring native lifecycle restore reason="
            + reason);
    }

    private void completeNativeLifecycleHandoffIfReady() {
        if (!nativeLifecycleHandoffPending
            || !nativeLifecycleCallbackCompleted
            || hasPhysicalInputContact()) return;
        boolean pause = nativeLifecyclePause;
        String reason = nativeLifecycleHandoffReason == null
            ? "native_lifecycle" : nativeLifecycleHandoffReason;
        clearNativeLifecycleHandoff();
        if (port != null && port.phase() != NativeReaderFirmwarePort.Phase.IDLE) {
            disableNativeReaderV2(reason + "_during_writer_transfer");
            return;
        }
        if (latestObservation != null && !saveCurrentSourceNow()) {
            disableNativeReaderV2(reason + "_source_save_failed");
            return;
        }
        try {
            if (components != null) {
                firmware.disableWriter(
                    inspectNativeCurrent(),
                    "SN_NATIVE_READER_V2 native lifecycle settled"
                );
                writerDisabled = true;
            }
            restoreWriterGeometry();
            restorePageGeometry();
            restorePresentationScale();
            retireTransactionalCore();
            removeStatusOverlayQuietly("native_lifecycle_settled");
            if (!pause) scheduleRefresh("configuration_changed_after_contact");
            Log.i(TAG, "native lifecycle restore completed reason=" + reason);
        } catch (RuntimeException failure) {
            Log.e(TAG, "native lifecycle restore failed reason=" + reason,
                failure);
            disableNativeReaderV2(reason + "_restore_failed");
        }
    }

    private boolean hasPhysicalInputContact() {
        return nativePenCallbackContact || fingerContact || penContact;
    }

    private void clearNativeLifecycleHandoff() {
        nativeLifecycleHandoffPending = false;
        nativeLifecycleCallbackCompleted = false;
        nativeLifecyclePause = false;
        nativeLifecycleHandoffReason = null;
    }

    private boolean hasLiveInputContact() {
        SpreadSession current = session;
        return nativePenCallbackContact || fingerContact || penContact
            || current != null && current.gestures().hasActiveGesture();
    }

    @Override
    public NativeReaderFirmwarePort.Observation observe() {
        assertOwnerThread();
        if (retired || latestObservation == null) return null;
        NativeReaderV2FirmwareAccess.Components current =
            inspectNativeCurrent();
        if (!sameNativeIdentity(current, latestObservation.snapshot)) {
            return null;
        }
        if (!writerDisabled) {
            NativeReaderFirmwarePort.Observation stable = latestObservation;
            if (stable.markRevision == markRevision) return stable;
            // A witnessed native save advances the runtime revision before a
            // new spread bitmap/layout is necessarily published. Never hand
            // the transaction port the older cached revision: its post-save
            // observation must describe the save that just completed.
            return new NativeReaderFirmwarePort.Observation(
                stable.authority,
                stable.snapshot,
                true,
                markRevision
            );
        }
        SpreadSnapshot source = latestObservation.snapshot;
        SpreadSnapshot disabled = new SpreadSnapshot(
            source.documentId,
            source.activityGeneration,
            source.layoutGeneration,
            source.pageCount,
            source.activePageIndex,
            source.mode,
            source.leftOrFull,
            source.right,
            null,
            false
        );
        return new NativeReaderFirmwarePort.Observation(
            null,
            disabled,
            false,
            markRevision
        );
    }

    @Override
    public boolean isStableObservationCurrent(
        NativeReaderFirmwarePort.Observation expected
    ) {
        assertOwnerThread();
        NativeReaderFirmwarePort.Observation current = observe();
        return current != null && expected != null
            && current.snapshot.sameAuthorityEpoch(expected.snapshot)
            && current.snapshot.activePageIndex
                == expected.snapshot.activePageIndex
            && current.writerEnabled == expected.writerEnabled
            && Objects.equals(current.authority, expected.authority);
    }

    @Override
    public void freezeDocumentInput() {
        assertOwnerThread();
        requireLive();
        inputFrozen = true;
    }

    @Override
    public void requestNativeSourceSave(SourceSaveCallback callback) {
        assertOwnerThread();
        requireLive();
        Objects.requireNonNull(callback, "callback");
        final NativeReaderV2FirmwareAccess.Components expected =
            inspectNativeCurrent();
        if (!sourceSaveAuthorityMatches(expected)) {
            postGuarded(
                "source_save_authority_rejection",
                () -> callback.onComplete(false, null)
            );
            return;
        }
        // Admission identity checks and PDF/marker lstat calls stay off the
        // input/UI thread. Native saveTrails itself remains owner-thread
        // confined, bracketed by worker-side authority checks.
        projectionExecutor.execute(new Runnable() {
            @Override public void run() {
                try {
                    final boolean admitted = NativeReaderV2DocumentGate
                        .fastEvidenceStillCurrent(evidence);
                    postGuarded("queued_source_save", new Runnable() {
                        @Override public void run() {
                            performBracketedSourceSave(
                                expected,
                                callback,
                                admitted
                            );
                        }
                    });
                } catch (Throwable failure) {
                    postGuarded("source_save_prevalidation_failure", () -> {
                        Log.e(TAG, "source-save prevalidation failed", failure);
                        callback.onComplete(false, null);
                        containFailClosed("source_save_prevalidation_failed");
                    });
                }
            }
        });
    }

    private void performBracketedSourceSave(
        NativeReaderV2FirmwareAccess.Components expected,
        SourceSaveCallback callback,
        boolean admittedBeforeSave
    ) {
        assertOwnerThread();
        if (!admittedBeforeSave || retired) {
            callback.onComplete(false, null);
            return;
        }
        NativeReaderV2FirmwareAccess.Components source;
        try {
            source = inspectNativeCurrent();
        } catch (RuntimeException failure) {
            Log.e(TAG, "queued source-save inspection failed", failure);
            callback.onComplete(false, null);
            return;
        }
        if (!sourceSaveAuthorityMatches(source)
            || source.presenter != expected.presenter
            || source.note != expected.note
            || source.readerPage != expected.readerPage) {
            callback.onComplete(false, null);
            return;
        }
        final boolean saved = saveSourceWithWitness(
            source,
            "source save failed"
        );
        projectionExecutor.execute(new Runnable() {
            @Override public void run() {
                try {
                    final boolean admittedAfterSave = saved
                        && NativeReaderV2DocumentGate.fastEvidenceStillCurrent(
                            evidence
                        );
                    postGuarded("source_save_postvalidation", new Runnable() {
                        @Override public void run() {
                            NativeReaderFirmwarePort.Observation observation = null;
                            boolean complete = admittedAfterSave;
                            if (complete) {
                                try {
                                    observation = observe();
                                } catch (RuntimeException failure) {
                                    Log.e(TAG,
                                        "post-save authority observation failed",
                                        failure);
                                    complete = false;
                                }
                            }
                            callback.onComplete(complete, observation);
                        }
                    });
                } catch (Throwable failure) {
                    postGuarded("source_save_postvalidation_failure", () -> {
                        Log.e(TAG, "source-save postvalidation failed", failure);
                        callback.onComplete(false, null);
                        containFailClosed("source_save_postvalidation_failed");
                    });
                }
            }
        });
    }

    @Override
    public void postToOwnerThread(Runnable callback) {
        if (callback == null) return;
        // Always cross a queue boundary. Synchronous native callbacks must not
        // chain disable/load/publication work onto the originating input or
        // save callback stack.
        postGuarded("controller_continuation", callback);
    }

    @Override
    public void scheduleActivationTimeout(Runnable callback) {
        if (callback == null) {
            throw new IllegalArgumentException(
                "activation timeout callback is required"
            );
        }
        ownerHandler.postDelayed(
            guarded("activation_timeout", callback),
            ACTIVATION_TIMEOUT_MS
        );
    }

    @Override
    public void disableNativeWriter() {
        assertOwnerThread();
        requireLive();
        NativeReaderV2FirmwareAccess.Components current =
            inspectNativeCurrent();
        firmware.disableWriter(current, "SN_NATIVE_READER_V2 transfer");
        writerDisabled = true;
    }

    @Override
    public void loadNativePage(int zeroBasedPageIndex) {
        assertOwnerThread();
        requireLive();
        NativeReaderV2FirmwareAccess.Components current =
            inspectNativeCurrent();
        restoreWriterGeometry();
        restorePageGeometry();
        internalPageLoad = true;
        try {
            firmware.loadDocumentPage(current, zeroBasedPageIndex);
        } finally {
            internalPageLoad = false;
        }
        scheduleRefresh("transaction_page_load");
    }

    @Override
    public void replayNativeFingerHit(PointD sourcePoint) {
        assertOwnerThread();
        requireLive();
        SpreadSnapshot snapshot = session.snapshot();
        PageSlot slot = snapshot.slotForPage(snapshot.activePageIndex);
        if (slot == null || !slot.sourceBox.contains(sourcePoint.x, sourcePoint.y)) {
            throw new IllegalStateException("finger replay point is not authoritative");
        }
        PointD screenPoint = slot.mapToScreen(sourcePoint.x, sourcePoint.y);
        if (!slot.containsContent(screenPoint.x, screenPoint.y)) {
            throw new IllegalStateException(
                "finger replay mapped outside authoritative content"
            );
        }
        fingerReplayInjector.replayFingerTap(activity, screenPoint);
    }

    @Override
    public int nativeSpreadNavigationTarget(
        SpreadSnapshot sourceSnapshot,
        double deltaX,
        double deltaY
    ) {
        assertOwnerThread();
        return NativeReaderV2Navigation.swipeTarget(
            sourceSnapshot,
            claim.config,
            deltaX,
            deltaY
        );
    }

    @Override
    public void releaseDocumentInput() {
        assertOwnerThread();
        requireLive();
        inputFrozen = false;
        postGuarded("deferred_navigation_release", this::drainNavigation);
    }

    @Override
    public void disableNativeReaderV2(String reason) {
        assertOwnerThread();
        if (retired) return;
        containFailClosed(reason);
    }

    private void refreshWhenReady(long generation, int attempt, String reason) {
        if (retired || generation != refreshGeneration) return;
        SpreadSession currentSession = session;
        if (nativePenCallbackContact || currentSession != null
            && currentSession.gestures().hasActiveGesture()) {
            // Never disable/reprogram DrawPath or replace its bitmaps in the
            // middle of a native pen, lasso, eraser, highlighter, or finger
            // contact. The terminal pen sample schedules a fresh generation.
            Log.d(TAG, "refresh deferred until native gesture completes reason="
                + reason);
            return;
        }
        NativeReaderFirmwarePort currentPort = port;
        if (currentPort != null) {
            NativeReaderFirmwarePort.Phase phase = currentPort.phase();
            if (phase == NativeReaderFirmwarePort.Phase.FROZEN
                || phase == NativeReaderFirmwarePort.Phase.SOURCE_SAVED
                || phase == NativeReaderFirmwarePort.Phase.TARGET_READY
                || phase == NativeReaderFirmwarePort.Phase.REPLAYING) {
                // These phases do not own a native page-publication edge.
                // Source-save and replay callbacks may emit bitmap signals,
                // but only TARGET_LOADING, ROLLBACK_LOADING, or stable IDLE
                // may publish them into the spread authority.
                Log.d(TAG, "refresh ignored during transaction phase="
                    + phase + " reason=" + reason);
                return;
            }
        }
        try {
            NativeReaderV2FirmwareAccess.Components current =
                inspectNativeCurrent();
            if (!isLandscape()) {
                leaveSpreadForPortrait(current, reason);
                return;
            }
            if (!current.writerReady()
                || firmware.originBitmap(current, current.readerPage) == null) {
                retryRefresh(generation, attempt, reason);
                return;
            }
            if (!beginComposition(current, generation, attempt, reason)) {
                retryRefresh(generation, attempt, reason);
            }
        } catch (RuntimeException failure) {
            if (failure instanceof AdmissionEvidenceChangedException) {
                Log.e(TAG, "admission evidence revoked reason=" + reason,
                    failure);
                disableNativeReaderV2("admission_evidence_changed");
                return;
            }
            if (attempt < READY_RETRY_LIMIT) {
                retryRefresh(generation, attempt, reason);
            } else {
                Log.e(TAG, "ready convergence failed reason=" + reason, failure);
                disableNativeReaderV2("ready_convergence_failed");
            }
        }
    }

    private void retryRefresh(long generation, int attempt, String reason) {
        if (attempt >= READY_RETRY_LIMIT) {
            disableNativeReaderV2("ready_timeout:" + reason);
            return;
        }
        ownerHandler.postDelayed(
            guarded(
                "refresh_retry:" + reason,
                () -> refreshWhenReady(generation, attempt + 1, reason)
            ),
            READY_RETRY_MS
        );
    }

    private boolean beginComposition(
        NativeReaderV2FirmwareAccess.Components current,
        long generation,
        int attempt,
        String reason
    ) {
        long nextLayout = layoutGeneration + 1L;
        RectD canvas = new RectD(
            0,
            0,
            current.documentLayout.getWidth(),
            current.documentLayout.getHeight()
        );
        NativeAuthority authority = firmware.authority(
            current,
            claim.documentId,
            activityGeneration,
            nextLayout
        );
        if (authority == null) return false;
        SpreadSnapshot snapshot = NativeReaderV2LayoutFactory.landscape(
            claim.documentId,
            activityGeneration,
            nextLayout,
            current.pageCount,
            current.readerPage,
            canvas,
            claim.config.showDivider ? 8.0 : 0.0,
            claim.config,
            page -> sourceBox(current, page),
            authority,
            true
        );
        if (!visiblePagesReady(current, snapshot)) return false;
        Bitmap activeInk = writerGeometryLease == null
            ? null : firmware.liveHandwritingBitmap(current);
        if (activeInk == null && firmware.sourceHasTrails(current)) {
            // A dirty native writer without its live bitmap is transient and
            // cannot be replaced by the older committed mark page.
            return false;
        }

        boolean inputWasFrozen = inputFrozen;
        inputFrozen = true;
        compositionGeneration = generation;
        try {
            projectionExecutor.execute(new Runnable() {
                @Override public void run() {
                    NativeReaderV2Compositor.Result prepared = null;
                    Throwable failure = null;
                    try {
                        if (!NativeReaderV2DocumentGate
                            .fastEvidenceStillCurrent(evidence)) {
                            throw new AdmissionEvidenceChangedException(
                                "authority changed before projection"
                            );
                        }
                        // Inactive .mark projection and bitmap composition are
                        // intentionally off the input/UI thread.
                        prepared = compositor.compose(
                            current,
                            snapshot,
                            activeInk
                        );
                        if (!NativeReaderV2DocumentGate
                            .fastEvidenceStillCurrent(evidence)) {
                            throw new AdmissionEvidenceChangedException(
                                "authority changed during projection"
                            );
                        }
                    } catch (Throwable caught) {
                        failure = caught;
                    }
                    final NativeReaderV2Compositor.Result result = prepared;
                    final Throwable projectionFailure = failure;
                    postGuarded("projection_completion", new Runnable() {
                        @Override public void run() {
                            completeComposition(
                                current,
                                snapshot,
                                authority,
                                canvas,
                                nextLayout,
                                generation,
                                attempt,
                                reason,
                                inputWasFrozen,
                                result,
                                projectionFailure
                            );
                        }
                    });
                }
            });
            return true;
        } catch (RuntimeException failure) {
            inputFrozen = inputWasFrozen;
            throw failure;
        }
    }

    private void completeComposition(
        NativeReaderV2FirmwareAccess.Components captured,
        SpreadSnapshot snapshot,
        NativeAuthority authority,
        RectD canvas,
        long nextLayout,
        long generation,
        int attempt,
        String reason,
        boolean inputWasFrozen,
        NativeReaderV2Compositor.Result next,
        Throwable projectionFailure
    ) {
        assertOwnerThread();
        if (retired || generation != refreshGeneration
            || compositionGeneration != generation) {
            if (next != null) next.recycle();
            return;
        }
        if (projectionFailure != null || next == null) {
            if (next != null) next.recycle();
            inputFrozen = inputWasFrozen;
            if (projectionFailure instanceof AdmissionEvidenceChangedException) {
                Log.e(TAG, "projection authority revoked", projectionFailure);
                containFailClosed("projection_authority_changed");
            } else if (attempt < READY_RETRY_LIMIT) {
                Log.w(TAG, "projection preflight failed; retrying", projectionFailure);
                retryRefresh(generation, attempt, reason);
            } else {
                Log.e(TAG, "projection failed closed", projectionFailure);
                containFailClosed("projection_failed");
            }
            return;
        }
        NativeReaderV2FirmwareAccess.Components current;
        try {
            current = inspectNativeCurrent();
            if (!sameNativeIdentity(current, snapshot)
                || current.presenter != captured.presenter
                || current.note != captured.note
                || current.documentLayout.getWidth() != (int) canvas.width()
                || current.documentLayout.getHeight() != (int) canvas.height()) {
                throw new IllegalStateException(
                    "projection authority changed before publication"
                );
            }
            publishPreparedComposition(
                current,
                snapshot,
                authority,
                canvas,
                nextLayout,
                reason,
                next
            );
        } catch (RuntimeException failure) {
            if (next != visible) next.recycle();
            inputFrozen = inputWasFrozen;
            Log.e(TAG, "projection publication failed", failure);
            containFailClosed("projection_publication_failed");
        }
    }

    private boolean publishPreparedComposition(
        NativeReaderV2FirmwareAccess.Components current,
        SpreadSnapshot snapshot,
        NativeAuthority authority,
        RectD canvas,
        long nextLayout,
        String reason,
        NativeReaderV2Compositor.Result next
    ) {
        boolean committed = false;
        boolean presentationPublicationAttempted = false;
        NativeReaderV2Compositor.Result previous = visible;
        try {
            firmware.disableWriter(current, "SN_NATIVE_READER_V2 compose");
            writerDisabled = true;
            restoreWriterGeometry();
            restorePageGeometry();
            if (presentationScaleLease == null) {
                presentationScaleLease = firmware.capturePresentationScale(
                    current
                );
            }
            // Once any setter is attempted, either the old or new pixels may
            // remain owned by one of three independent native views. Failed
            // publication must preserve both generations rather than risk a
            // use-after-recycle draw.
            presentationPublicationAttempted = true;
            NativeReaderV2Hooks.runInternalPresentation(new Runnable() {
                @Override public void run() {
                    firmware.setBackground(current, next.background);
                    firmware.setLiveInkBitmap(current, next.ink);
                    firmware.setDigestBitmap(current, next.digest);
                }
            });
            NativeWriterGeometry geometry = NativeWriterGeometry.from(
                snapshot,
                canvas,
                current.presenterRotation
            );
            PageSlot activeSlot = snapshot.slotForPage(
                snapshot.activePageIndex
            );
            pageGeometryLease = firmware.programPageGeometry(
                current,
                activeSlot
            );
            // Treat the lease as live before crossing the reflective/Binder
            // boundary. A partial failure must still restore stock geometry.
            writerGeometryLease = geometry;
            List<RectD> overlayMasks = statusOverlay.protectedAreas(
                snapshot,
                claim.config.showHeader,
                current.documentLayout.getWidth(),
                current.documentLayout.getHeight()
            );
            List<RectD> writerChrome = concatenateMasks(
                trackedChromeMasks,
                overlayMasks
            );
            nativeChromeMasks = concatenateMasks(
                firmware.nativeChromeDisabledAreas(current), writerChrome
            );
            firmware.programWriterGeometry(
                current,
                geometry,
                writerChrome
            );
            writerDisabled = false;
            NativeReaderFirmwarePort.Observation observation =
                new NativeReaderFirmwarePort.Observation(
                    authority,
                    snapshot,
                    true,
                    markRevision
                );
            components = current;
            latestObservation = observation;
            visible = next;
            layoutGeneration = nextLayout;

            if (session == null) {
                session = new SpreadSession();
                if (!session.publish(snapshot)) {
                    throw new IllegalStateException(
                        "initial spread authority publication failed"
                    );
                }
                port = new NativeReaderFirmwarePort(this, observation);
                controller = new NativeReaderController(session, port);
                port.attachController(controller);
                inputFrozen = false;
            } else if (port.phase() == NativeReaderFirmwarePort.Phase.IDLE) {
                if (!session.publish(snapshot)) {
                    throw new IllegalStateException(
                        "stable spread authority publication failed"
                    );
                }
                port.publishStableObservation(observation);
                inputFrozen = false;
            } else {
                port.onFirmwarePageReady(observation);
            }
            committed = true;
            samePageReloadPrepared = false;
            if (previous != null) previous.recycle();
            updateStatusOverlay(snapshot);
            reportActivationReady();
            postGuarded("deferred_navigation_publication", this::drainNavigation);
            Log.i(TAG, "spread published page=" + current.readerPage
                + " layout=" + nextLayout + " reason=" + reason);
            return true;
        } finally {
            if (!committed) {
                if (presentationPublicationAttempted) {
                    // The views own these pixels now. Preserve them and stop
                    // the feature rather than recycling either generation or
                    // retrying with partially published authority. A setter
                    // can fail after an earlier layer has already committed.
                    visible = next;
                    if (controller != null) controller.retire();
                    containedFailClosed = true;
                    inputFrozen = true;
                    nativePenCallbackContact = false;
                    samePageReloadPrepared = false;
                    ++refreshGeneration;
                    removeStatusOverlayQuietly("compose_failed");
                    Log.e(TAG, "presentation installed without authority; disabled");
                } else {
                    next.recycle();
                }
                restorePageGeometryQuietly("compose_failed");
                restoreWriterGeometryQuietly("compose_failed");
                restorePresentationScaleQuietly("compose_failed");
                try {
                    firmware.disableWriter(
                        current,
                        "SN_NATIVE_READER_V2 compose failed"
                    );
                } catch (RuntimeException disableFailure) {
                    Log.e(TAG, "writer fail-close failed after compose",
                        disableFailure);
                }
                writerDisabled = true;
            }
        }
    }

    private void leaveSpreadForPortrait(
        NativeReaderV2FirmwareAccess.Components current,
        String reason
    ) {
        if (writerGeometryLease != null) {
            firmware.disableWriter(current, "SN_NATIVE_READER_V2 portrait restore");
            writerDisabled = true;
            restoreWriterGeometry();
        }
        restorePageGeometry();
        restorePresentationScale();
        samePageReloadPrepared = false;
        retireTransactionalCore();
        // A converged portrait callback has replaced both native views, so
        // the former spread bitmaps are no longer view-owned.
        recycleVisible();
        components = current;
        latestObservation = null;
        writerDisabled = false;
        inputFrozen = false;
        reportActivationReady();
        removeStatusOverlayQuietly("portrait");
        Log.i(TAG, "portrait native reader restored reason=" + reason);
    }

    private RectD sourceBox(
        NativeReaderV2FirmwareAccess.Components current,
        int page
    ) {
        Bitmap bitmap = firmware.originBitmap(current, page);
        if (bitmap == null || bitmap.isRecycled()) {
            throw new IllegalStateException("visible source page is unavailable");
        }
        // Sizing is an authority decision of the v2 projection. FIT consumes
        // the complete origin page; NATIVE_FILL crops that same complete page
        // exactly once inside PageProjectionFactory. Feeding the firmware's
        // already-cropped display box into either path made FIT inherit stale
        // crop state and made FILL clip twice.
        return new RectD(0, 0, bitmap.getWidth(), bitmap.getHeight());
    }

    private boolean visiblePagesReady(
        NativeReaderV2FirmwareAccess.Components current,
        SpreadSnapshot snapshot
    ) {
        return slotReady(current, snapshot.leftOrFull)
            && (snapshot.right == null || slotReady(current, snapshot.right));
    }

    private boolean slotReady(
        NativeReaderV2FirmwareAccess.Components current,
        PageSlot slot
    ) {
        if (slot.isBlank()) return true;
        Bitmap bitmap = firmware.originBitmap(current, slot.sourcePageIndex);
        return bitmap != null && !bitmap.isRecycled();
    }

    /**
     * Native-only identity check reserved for restoring already-held leases.
     * Revoking the external marker must stop all new authorized work, but it
     * must never prevent v2 from disabling DrawPath and putting the exact
     * firmware objects it already modified back into stock form.
     */
    private NativeReaderV2FirmwareAccess.Components inspectNativeCurrent() {
        NativeReaderV2FirmwareAccess.Components current = firmware.inspect(activity);
        if (!claim.canonicalDocumentPath.equals(current.documentPath)
            || !claim.markPath.equals(current.markPath)
            || current.pageCount <= 0) {
            throw new IllegalStateException(
                "native document identity no longer matches admission"
            );
        }
        return current;
    }

    private boolean sameNativeIdentity(
        NativeReaderV2FirmwareAccess.Components current,
        SpreadSnapshot snapshot
    ) {
        return current != null && snapshot != null
            && components != null
            && claim.canonicalDocumentPath.equals(current.documentPath)
            && claim.markPath.equals(current.markPath)
            && claim.markPath.equals(components.markPath)
            && current.readerPage == snapshot.activePageIndex
            && current.pageCount == snapshot.pageCount
            && current.viewModel == components.viewModel
            && current.presenter == components.presenter
            && current.handWriteView == components.handWriteView
            && current.eventCallback == components.eventCallback
            && current.image == components.image
            && current.digestImage == components.digestImage
            && current.documentLayout == components.documentLayout
            && current.note == components.note
            && current.client == components.client
            && current.binder == components.binder;
    }

    private boolean isLandscape() {
        return activity.getResources().getConfiguration().orientation
            == Configuration.ORIENTATION_LANDSCAPE;
    }

    private void recycleVisible() {
        NativeReaderV2Compositor.Result previous = visible;
        visible = null;
        if (previous != null) previous.recycle();
    }

    private void restorePageGeometry() {
        NativeReaderV2FirmwareAccess.PageGeometryLease lease = pageGeometryLease;
        if (lease == null) return;
        NativeReaderV2FirmwareAccess.Components current = inspectNativeCurrent();
        firmware.restorePageGeometry(current, lease);
        pageGeometryLease = null;
    }

    private void restorePageGeometryQuietly(String reason) {
        try {
            restorePageGeometry();
        } catch (RuntimeException failure) {
            Log.e(TAG, "page geometry restore failed reason=" + reason, failure);
        }
    }

    private void restoreWriterGeometry() {
        if (writerGeometryLease == null) return;
        NativeReaderV2FirmwareAccess.Components current = inspectNativeCurrent();
        firmware.restoreNativeWriterGeometry(current);
        writerGeometryLease = null;
    }

    private void restoreWriterGeometryQuietly(String reason) {
        try {
            restoreWriterGeometry();
        } catch (RuntimeException failure) {
            Log.e(TAG, "writer geometry restore failed reason=" + reason, failure);
        }
    }

    private void restorePresentationScale() {
        NativeReaderV2FirmwareAccess.PresentationScaleLease lease =
            presentationScaleLease;
        if (lease == null) return;
        firmware.restorePresentationScale(lease);
        presentationScaleLease = null;
    }

    private void restorePresentationScaleQuietly(String reason) {
        try {
            restorePresentationScale();
        } catch (RuntimeException failure) {
            Log.e(TAG, "presentation scale restore failed reason="
                + reason, failure);
        }
    }

    private boolean saveCurrentSourceNow() {
        NativeReaderV2FirmwareAccess.Components source;
        try {
            source = inspectNativeCurrent();
        } catch (RuntimeException failure) {
            Log.e(TAG, "configuration save inspection failed", failure);
            return false;
        }
        if (!source.writerReady() || latestObservation == null
            || !sameNativeIdentity(source, latestObservation.snapshot)) {
            return false;
        }
        return saveSourceWithWitness(
            source,
            "configuration source save failed"
        );
    }

    private boolean sourceSaveAuthorityMatches(
        NativeReaderV2FirmwareAccess.Components source
    ) {
        return source != null && source.writerReady() && components != null
            && latestObservation != null
            && source.presenter == components.presenter
            && source.note == components.note
            && source.readerPage
                == latestObservation.snapshot.activePageIndex
            && sameNativeIdentity(source, latestObservation.snapshot);
    }

    private boolean saveSourceWithWitness(
        NativeReaderV2FirmwareAccess.Components source,
        String failureMessage
    ) {
        NativeSaveWitness.Token token = null;
        try {
            // Match the stock page-turn boundary. Closing the native lasso can
            // commit a pending move/scale, so this must precede both the dirty
            // observation and the witnessed save.
            firmware.prepareSourceForTransfer(source);
            boolean dirty = firmware.sourceHasTrails(source);
            token = saveWitness.begin(
                source.note,
                source.markPath,
                source.readerPage + 1,
                dirty
            );
            saveWitnessFault = false;
            firmware.saveSource(source);
            boolean saved = !saveWitnessFault && saveWitness.finish(token);
            if (saved && dirty) markRevision++;
            return saved;
        } catch (RuntimeException failure) {
            if (token != null && saveWitness.active()) {
                saveWitness.abort(token);
            }
            Log.e(TAG, failureMessage, failure);
            return false;
        }
    }

    private void retireTransactionalCore() {
        if (controller != null) controller.retire();
        if (session != null) session.retire();
        controller = null;
        port = null;
        session = null;
        latestObservation = null;
        deferredReplayLoadTarget = null;
        deferredNavigation.clear();
        clearFingerRoute();
        clearPenRoute();
    }

    private void drainDeferredReplayLoad() {
        assertOwnerThread();
        Integer boxedTarget = deferredReplayLoadTarget;
        deferredReplayLoadTarget = null;
        if (boxedTarget == null || retired) return;
        int target = boxedTarget.intValue();
        if (port == null || session == null
            || port.phase() != NativeReaderFirmwarePort.Phase.IDLE) {
            disableNativeReaderV2("replayed_link_transaction_not_settled");
            return;
        }
        if (target != session.snapshot().activePageIndex) {
            if (!controller.requestNavigation(target)) {
                disableNativeReaderV2("replayed_link_navigation_rejected");
            }
            return;
        }
        if (!prepareSamePageReload()) {
            disableNativeReaderV2("replayed_same_page_link_rejected");
            return;
        }
        NativeReaderV2FirmwareAccess.Components current =
            inspectNativeCurrent();
        internalPageLoad = true;
        try {
            firmware.loadDocumentPage(current, target);
        } finally {
            internalPageLoad = false;
        }
        scheduleRefresh("replayed_same_page_link");
    }

    private boolean canStartNavigationNow() {
        return !retired && !inputFrozen && !hasPhysicalInputContact()
            && controller != null && port != null
            && port.phase() == NativeReaderFirmwarePort.Phase.IDLE
            && session != null
            && !session.gestures().hasActiveGesture();
    }

    private boolean enqueueNavigation(DeferredNavigation request) {
        if (request == null || retired || containedFailClosed) return false;
        DeferredNavigation tail = deferredNavigation.peekLast();
        if (tail != null && tail.sameCommand(request)) {
            return true;
        }
        if (deferredNavigation.size() >= MAX_DEFERRED_NAVIGATION) {
            containFailClosed("deferred_navigation_overflow");
            return false;
        }
        deferredNavigation.addLast(request);
        Log.i(TAG, "navigation deferred kind=" + request.kind
            + " source=" + request.sourcePage + " value=" + request.value);
        return true;
    }

    private void drainNavigation() {
        assertOwnerThread();
        if (!canStartNavigationNow() || deferredNavigation.isEmpty()) return;
        SpreadSnapshot snapshot = session.snapshot();
        DeferredNavigation request = deferredNavigation.peekFirst();
        if (!request.documentId.equals(snapshot.documentId)
            || request.activityGeneration != snapshot.activityGeneration
            || snapshot.layoutGeneration < request.layoutGeneration) {
            deferredNavigation.clear();
            containFailClosed("deferred_navigation_authority_changed");
            return;
        }
        if (snapshot.activePageIndex != request.sourcePage) {
            // The command was classified against another visible page. It may
            // not be reinterpreted after a page/load publication, including a
            // publication caused by an earlier deferred command.
            deferredNavigation.clear();
            Log.w(TAG, "stale deferred navigation discarded source="
                + request.sourcePage + " current="
                + snapshot.activePageIndex);
            return;
        }
        int target = request.kind == DeferredNavigation.Kind.ABSOLUTE
            ? request.value
            : NativeReaderV2Navigation.offsetTarget(
                snapshot,
                claim.config,
                request.value
            );
        if (target < 0 || target == snapshot.activePageIndex) {
            deferredNavigation.removeFirst();
            postGuarded("deferred_navigation_next", this::drainNavigation);
            return;
        }
        if (controller.requestNavigation(target)) {
            deferredNavigation.removeFirst();
        }
    }

    private static List<RectD> safeChrome(List<RectD> chrome) {
        return chrome == null ? Collections.<RectD>emptyList() : chrome;
    }

    private List<RectD> combinedChrome(List<RectD> visibleChrome) {
        List<RectD> tracked = safeChrome(visibleChrome);
        List<RectD> nativeMasks = nativeChromeMasks;
        if (tracked.isEmpty()) return nativeMasks;
        if (nativeMasks.isEmpty()) return tracked;
        ArrayList<RectD> combined = new ArrayList<>(
            tracked.size() + nativeMasks.size()
        );
        combined.addAll(tracked);
        combined.addAll(nativeMasks);
        return Collections.unmodifiableList(combined);
    }

    private static List<RectD> concatenateMasks(
        List<RectD> first,
        List<RectD> second
    ) {
        List<RectD> safeFirst = safeChrome(first);
        List<RectD> safeSecond = safeChrome(second);
        if (safeFirst.isEmpty()) return safeSecond;
        if (safeSecond.isEmpty()) return safeFirst;
        ArrayList<RectD> combined = new ArrayList<>(
            safeFirst.size() + safeSecond.size()
        );
        combined.addAll(safeFirst);
        combined.addAll(safeSecond);
        return Collections.unmodifiableList(combined);
    }

    private static GestureAction motionAction(int action) {
        if (action == MotionEvent.ACTION_MOVE) return GestureAction.MOVE;
        if (action == MotionEvent.ACTION_UP) return GestureAction.UP;
        if (action == MotionEvent.ACTION_CANCEL) return GestureAction.CANCEL;
        return null;
    }

    private void clearFingerRoute() {
        fingerGestureToken = 0L;
        fingerPointerId = -1;
        fingerContact = false;
        fingerConsumed = false;
        fingerConcurrentBlocked = false;
    }

    private void cancelFingerGesture(long eventTimeMs) {
        if (controller != null && fingerGestureToken > 0L
            && fingerPointerId >= 0) {
            controller.onMotion(
                fingerGestureToken,
                fingerPointerId,
                GestureAction.CANCEL,
                0.0,
                0.0,
                0.0,
                Math.max(0L, eventTimeMs)
            );
        }
        fingerGestureToken = 0L;
        fingerPointerId = -1;
        fingerConsumed = true;
    }

    private void finishFingerRoute(boolean consumed) {
        clearFingerRoute();
        // A native toolbar action or active-page finger contact may update
        // handwriting, digest, selection, or link state synchronously while
        // the contact token is still live. Its earlier callback refresh is
        // deliberately ignored; publish exactly once after contact-up.
        if (!consumed && isLandscapeActive()) {
            scheduleRefresh("native_finger_contact_complete");
        }
    }

    private void clearPenRoute() {
        penGestureToken = 0L;
        penContact = false;
        penSuppressed = false;
    }

    private void updateStatusOverlay(SpreadSnapshot snapshot) {
        try {
            statusOverlay.update(
                snapshot,
                claim.config.showHeader,
                claim.config.direction.name()
            );
        } catch (RuntimeException failure) {
            Log.e(TAG, "status overlay update failed", failure);
            removeStatusOverlayQuietly("update_failed");
        }
    }

    private void removeStatusOverlayQuietly(String reason) {
        try {
            statusOverlay.remove();
        } catch (RuntimeException failure) {
            Log.e(TAG, "status overlay removal failed reason=" + reason,
                failure);
        }
    }

    private void requireLive() {
        if (retired || components == null || latestObservation == null) {
            throw new IllegalStateException("Native Reader v2 is not live");
        }
    }

    private void reportActivationReady() {
        if (activationReported || retired || containedFailClosed) return;
        activationReported = true;
        activationListener.onRuntimeInputAuthorityReady(this);
    }

    private void postGuarded(String label, Runnable action) {
        ownerHandler.post(guarded(label, action));
    }

    private Runnable guarded(String label, Runnable action) {
        Objects.requireNonNull(action, "action");
        return new Runnable() {
            @Override public void run() {
                if (retired) return;
                try {
                    action.run();
                } catch (Throwable failure) {
                    Log.e(TAG, "queued continuation failed label=" + label,
                        failure);
                    containFailClosed("queued_continuation_failed:" + label);
                }
            }
        };
    }

    private void assertOwnerThread() {
        if (Thread.currentThread().getId() != ownerThreadId) {
            throw new IllegalStateException(
                "Native Reader v2 runtime used from a foreign thread"
            );
        }
    }

    private static final class AdmissionEvidenceChangedException
        extends IllegalStateException {
        AdmissionEvidenceChangedException(String message) {
            super(message);
        }
    }

    private static final class DeferredNavigation {
        enum Kind { ABSOLUTE, OFFSET }

        final Kind kind;
        final String documentId;
        final long activityGeneration;
        final long layoutGeneration;
        final int sourcePage;
        final int value;

        private DeferredNavigation(
            Kind kind,
            SpreadSnapshot snapshot,
            int value
        ) {
            this.kind = kind;
            this.documentId = snapshot.documentId;
            this.activityGeneration = snapshot.activityGeneration;
            this.layoutGeneration = snapshot.layoutGeneration;
            this.sourcePage = snapshot.activePageIndex;
            this.value = value;
        }

        static DeferredNavigation absolute(
            SpreadSnapshot snapshot,
            int target
        ) {
            return new DeferredNavigation(Kind.ABSOLUTE, snapshot, target);
        }

        static DeferredNavigation offset(
            SpreadSnapshot snapshot,
            int offset
        ) {
            return new DeferredNavigation(Kind.OFFSET, snapshot, offset);
        }

        boolean sameCommand(DeferredNavigation other) {
            return other != null && kind == other.kind
                && value == other.value
                && sourcePage == other.sourcePage
                && layoutGeneration == other.layoutGeneration
                && activityGeneration == other.activityGeneration
                && documentId.equals(other.documentId);
        }
    }
}
