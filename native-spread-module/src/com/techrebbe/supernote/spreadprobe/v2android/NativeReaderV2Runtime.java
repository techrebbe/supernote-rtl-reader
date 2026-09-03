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
import com.techrebbe.supernote.spreadprobe.v2.NativeComponentIdentityRegistry;
import com.techrebbe.supernote.spreadprobe.v2.AtomicInputAdmission;
import com.techrebbe.supernote.spreadprobe.v2.NativeAsyncSaveFence;
import com.techrebbe.supernote.spreadprobe.v2.NativePresentationRestoreWitness;
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
import java.util.concurrent.TimeUnit;

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

        /**
         * Runs a native-presentation publication while holding the same lock
         * that publishes physical stylus DOWN. This makes the boundary
         * atomic: either the presentation finishes before the contact starts,
         * or the caller observes the live contact and defers publication.
         */
        boolean runWhenStylusIdle(Runnable publication);
    }

    /** Releases the hook-level admission fence only after native authority exists. */
    public interface ActivationListener {
        void onRuntimeInputAuthorityReady(NativeReaderV2Runtime runtime);
    }

    /** Hook owner removes a runtime only after stock owns all three views. */
    public interface DetachmentListener {
        void onRuntimeDetachmentReady(
            NativeReaderV2Runtime runtime,
            String reason
        );
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
    private final NativeAsyncSaveFence sourceSaveFence =
        new NativeAsyncSaveFence();
    private final AtomicInputAdmission inputAdmission =
        new AtomicInputAdmission();
    private final NativePresentationRestoreWitness stockRestoreWitness =
        new NativePresentationRestoreWitness();
    private final FingerReplayInjector fingerReplayInjector;
    private final PhysicalContactFence physicalContactFence;
    private final ActivationListener activationListener;
    private final DetachmentListener detachmentListener;
    private final ExecutorService projectionExecutor =
        Executors.newSingleThreadExecutor();

    // Read by the firmware's native pen callback before samples are posted to
    // the owner thread. Volatile publication is required; SpreadSession then
    // publishes its immutable snapshot through AtomicReference.
    private volatile SpreadSession session;
    private NativeReaderFirmwarePort port;
    private NativeReaderController controller;
    private NativeReaderV2FirmwareAccess.Components components;
    private NativeComponentIdentityRegistry.Lease componentIdentityLease;
    private NativeReaderV2Compositor.Result visible;
    private NativeReaderV2FirmwareAccess.PageGeometryLease pageGeometryLease;
    private NativeReaderV2FirmwareAccess.PresentationScaleLease
        presentationScaleLease;
    private NativeWriterGeometry writerGeometryLease;
    private NativeReaderFirmwarePort.Observation latestObservation;
    private long layoutGeneration;
    private long markRevision;
    private long refreshGeneration;
    private long lifecycleEpoch = 1L;
    private volatile boolean lifecycleSuspended;
    private boolean writerDisabled;
    private volatile boolean inputFrozen;
    private volatile AtomicInputAdmission.FreezeToken inputFreezeToken;
    private AtomicInputAdmission.FreezeToken transactionInputFreezeToken;
    private volatile boolean retired;
    private volatile boolean projectionShutdown;
    // Published on the firmware callback thread before Supernote receives
    // the first sample. The owner-thread GestureRouter token may be posted a
    // little later, so refresh also consults this zero-work contact latch.
    private volatile boolean nativePenCallbackContact;
    private boolean compositionDeferredForPhysicalContact;
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
    private boolean preservingUnsavedSource;
    private String pendingContainmentReason;
    private boolean stockPresentationRestorePending;
    private long stockPresentationSignalGeneration;
    private long stockPresentationReloadGeneration;
    private long activeStockPresentationReloadGeneration;
    private Bitmap stockRestoreBackground;
    private Bitmap stockRestoreInk;
    private Bitmap stockRestoreDigest;
    private NativePresentationRestoreWitness.Token stockRestoreToken;
    private String pendingRetirementReason;
    private volatile Object expectedWriterDisablePresenter;
    private volatile boolean writerDisableInFlight;
    private boolean writerDisableAcknowledged;
    private volatile Object expectedWriterEnablePresenter;
    private volatile Object expectedWriterEnableNote;
    private volatile int expectedWriterEnablePage = -1;
    private volatile long expectedWriterEnableActivityGeneration = -1L;
    private volatile long expectedWriterEnableLayoutGeneration = -1L;
    private volatile long expectedWriterEnableRefreshGeneration = -1L;
    private volatile NativeWriterGeometry expectedWriterEnableGeometry;
    private volatile boolean writerEnableInFlight;
    private boolean writerEnablePrimed;
    private boolean writerGeometryAcknowledged;
    private boolean writerEnableAcknowledged;
    private boolean activationReported;
    private long compositionGeneration;
    private long fingerGestureToken;
    private int fingerPointerId = -1;
    private boolean fingerContact;
    private boolean fingerConsumed;
    private boolean fingerConcurrentBlocked;
    private boolean fingerIngressAdmitted;
    private long penGestureToken;
    private boolean penContact;
    private boolean penSuppressed;
    private volatile boolean stylusIngressAdmitted;
    private int lastPenX;
    private int lastPenY;
    private long lastPenEventTimeMs;
    private Integer deferredReplayLoadTarget;
    private volatile SourceSaveAttempt activeSourceSaveAttempt;
    private final ArrayDeque<DeferredNavigation> deferredNavigation =
        new ArrayDeque<>();

    public NativeReaderV2Runtime(
        Activity activity,
        NativeReaderV2DocumentGate.Evidence evidence,
        NativeReaderV2FirmwareAccess firmware,
        long activityGeneration,
        FingerReplayInjector fingerReplayInjector,
        PhysicalContactFence physicalContactFence,
        ActivationListener activationListener,
        DetachmentListener detachmentListener
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
        this.detachmentListener = Objects.requireNonNull(
            detachmentListener,
            "detachmentListener"
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

    /**
     * Starts activation only after a final worker-side proof of every
     * persisted authority object. The admission fence remains installed until
     * the resulting portrait or landscape publication reports ready.
     */
    public void start() {
        assertOwnerThread();
        if (retired || containedFailClosed) return;
        freezeInputIngress();
        final long activationLifecycleEpoch = lifecycleEpoch;
        executeProjection("activation_evidence", new Runnable() {
            @Override public void run() {
                try {
                    final boolean current = NativeReaderV2DocumentGate
                        .evidenceStillCurrent(evidence);
                    postGuarded("activation_evidence", new Runnable() {
                        @Override public void run() {
                            if (lifecycleSuspended
                                || lifecycleEpoch != activationLifecycleEpoch) {
                                return;
                            }
                            if (!current) {
                                containFailClosed(
                                    "activation_publication_evidence_changed"
                                );
                                return;
                            }
                            scheduleRefresh("document_admitted_revalidated");
                        }
                    });
                } catch (Throwable failure) {
                    postGuarded("activation_evidence_failure", () -> {
                        if (lifecycleSuspended
                            || lifecycleEpoch != activationLifecycleEpoch) {
                            return;
                        }
                        Log.e(TAG, "activation evidence check failed", failure);
                        containFailClosed(
                            "activation_publication_evidence_failed"
                        );
                    });
                }
            }
        });
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
        return !retired && !lifecycleSuspended
            && session != null && session.snapshot() != null
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
        if (retired || lifecycleSuspended || snapshot == null || targetPage < 0
            || targetPage >= snapshot.pageCount) return false;
        if (tryStartNavigationAtomically(targetPage)) return true;
        return enqueueNavigation(DeferredNavigation.absolute(
            snapshot,
            targetPage
        ));
    }

    public boolean requestNativeTurn(int nativeOffset) {
        assertOwnerThread();
        SpreadSnapshot snapshot = session == null ? null : session.snapshot();
        if (retired || lifecycleSuspended || snapshot == null
            || nativeOffset == 0) return false;
        int target = NativeReaderV2Navigation.offsetTarget(
            snapshot,
            claim.config,
            nativeOffset
        );
        if (target < 0) return true;
        if (tryStartNavigationAtomically(target)) return true;
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
        if (retired || lifecycleSuspended || !isLandscapeActive()
            || latestObservation == null
            || port == null || port.phase() != NativeReaderFirmwarePort.Phase.IDLE) {
            return false;
        }
        if (reserveInputIngressIfIdle() == null) return false;
        ++refreshGeneration;
        if (!saveCurrentSourceNow()) {
            disableNativeReaderV2("same_page_reload_save_failed");
            return false;
        }
        NativeReaderV2FirmwareAccess.Components current = inspectNativeCurrent();
        disableWriterWithWitness(
            current,
            "SN_NATIVE_READER_V2 same-page reload"
        );
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
        if (detachmentPrepared || !ownsModifiedNativePresentation()) {
            detachmentPrepared = true;
            return true;
        }
        pendingRetirementReason = "native_document_open";
        if (stockPresentationRestorePending) return false;
        if (hasLiveInputContact() || port != null
            && port.phase() != NativeReaderFirmwarePort.Phase.IDLE
            && !(preservingUnsavedSource && port.phase()
                == NativeReaderFirmwarePort.Phase.DISABLED)) {
            freezeInputIngress();
            Log.i(TAG, "native document open queued until authority settles");
            return false;
        }
        if (!beginStockPresentationRestoration(
                "native_document_open",
                "native_document_open"
            )) {
            containFailClosed("document_open_restore_failed");
        }
        // The triggering open is suppressed. It may be retried only after all
        // three stock presentation layers acknowledge replacement.
        return false;
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
        return !retired && !lifecycleSuspended
            && !stockPresentationRestorePending
            && (isLandscapeActive() || samePageReloadPrepared);
    }

    /**
     * Lock-free callback-thread classifier. A PASS decision is safe only for
     * visible native chrome or the already-published active writer page.
     * Every other sample is suppressed and marshalled to the owner thread.
     */
    public boolean beginNativePenContactImmediately(
        double x,
        double y,
        List<RectD> visibleNativeChrome
    ) {
        if (!inputAdmission.begin(AtomicInputAdmission.Contact.STYLUS)) {
            return false;
        }
        stylusIngressAdmitted = true;
        nativePenCallbackContact = !retired;
        return mayPassNativePenImmediately(x, y, visibleNativeChrome);
    }

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
        if (lifecycleSuspended || nativeLifecycleHandoffPending) return false;
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

    /** Rechecks deferred lifecycle/containment after the hook fence releases. */
    public void postPhysicalContactFenceReleased() {
        postGuarded("physical_contact_fence_released", new Runnable() {
            @Override public void run() {
                if (stylusIngressAdmitted) {
                    inputAdmission.end(AtomicInputAdmission.Contact.STYLUS);
                    stylusIngressAdmitted = false;
                    nativePenCallbackContact = false;
                }
                settlePendingContainment();
                completeNativeLifecycleHandoffIfReady();
                if (compositionDeferredForPhysicalContact
                    && !physicalContactFence.stylusContactActive()) {
                    compositionDeferredForPhysicalContact = false;
                    if (!retired && !containedFailClosed
                        && !lifecycleSuspended && isLandscape()) {
                        scheduleRefresh("physical_contact_publication_released");
                    }
                }
            }
        });
    }

    public void onNativePresentationChanged(String reason) {
        assertOwnerThread();
        if (!retired && !stockPresentationRestorePending) {
            scheduleRefresh(reason);
        }
    }

    public void onNativeStockBackgroundPresented(
        Object receiver,
        Bitmap replacement
    ) {
        noteStockPresentationLayer(
            NativePresentationRestoreWitness.Layer.BACKGROUND,
            receiver,
            replacement
        );
    }

    public void onNativeStockInkPresented(
        Object receiver,
        Bitmap replacement
    ) {
        noteStockPresentationLayer(
            NativePresentationRestoreWitness.Layer.INK,
            receiver,
            replacement
        );
    }

    public void onNativeStockDigestPresented(
        Object receiver,
        Bitmap replacement
    ) {
        noteStockPresentationLayer(
            NativePresentationRestoreWitness.Layer.DIGEST,
            receiver,
            replacement
        );
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
        if (action == MotionEvent.ACTION_DOWN) {
            fingerContact = true;
            fingerConsumed = true;
            fingerPointerId = event.getPointerId(event.getActionIndex());
            fingerIngressAdmitted = inputAdmission.begin(
                AtomicInputAdmission.Contact.FINGER
            );
            if (!fingerIngressAdmitted) {
                fingerConcurrentBlocked = true;
                return true;
            }
            fingerConcurrentBlocked = physicalContactFence
                .stylusContactActive();
            if (fingerConcurrentBlocked) return true;
            if (event.getPointerCount() != 1) return true;
            fingerPointerId = event.getPointerId(0);
            if (controller == null) {
                fingerConsumed = false;
                return false;
            }
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
        if (controller == null) {
            boolean terminal = action == MotionEvent.ACTION_UP
                || action == MotionEvent.ACTION_CANCEL;
            if (terminal && fingerContact) finishFingerRoute(false);
            return false;
        }
        if (!fingerContact) return inputFrozen;
        if ((action == MotionEvent.ACTION_POINTER_DOWN
            || action == MotionEvent.ACTION_POINTER_UP) && fingerConsumed) {
            cancelFingerGesture(event.getEventTime());
            fingerConcurrentBlocked = true;
            return true;
        }
        if (action == MotionEvent.ACTION_POINTER_DOWN
            || action == MotionEvent.ACTION_POINTER_UP) {
            // PASS_NATIVE is immutable for the complete physical contact.
            // Stock already received DOWN; swallowing a later pointer edge
            // without a matching CANCEL/UP would strand its touch target.
            return false;
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
            if (inputFrozen) {
                penContact = true;
                penGestureToken = 0L;
                penSuppressed = true;
                return true;
            }
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
            if (penGestureToken <= 0L) {
                if (pressure <= 0) {
                    clearPenRoute();
                    nativePenCallbackContact = false;
                    postGuarded(
                        "pending_restore_after_blocked_pen",
                        this::settlePendingStockRestoration
                    );
                }
                return true;
            }
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
                postGuarded(
                    "pending_containment_after_native_pen",
                    () -> {
                        settlePendingContainment();
                        settlePendingStockRestoration();
                    }
                );
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
        postGuarded(
            "pending_containment_after_missing_terminal",
            () -> {
                settlePendingContainment();
                settlePendingStockRestoration();
            }
        );
    }

    /** Called after setImage/configuration/page-ready firmware callbacks. */
    public void scheduleRefresh(String reason) {
        assertOwnerThread();
        if (retired || containedFailClosed || detachmentPrepared
            || lifecycleSuspended || nativeLifecycleHandoffPending) return;
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
        // Invalidate every callback from the outgoing presentation before
        // stock configuration handling can settle or reject the live contact.
        advanceLifecycleEpoch();
        if (hasLiveInputContact()) {
            beginNativeLifecycleHandoff(
                "configuration_change_during_contact",
                false
            );
            return;
        }
        if (supersedeInputIngressIfIdle() == null) {
            beginNativeLifecycleHandoff(
                "configuration_change_during_contact",
                false
            );
            return;
        }
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
            disableWriterWithWitness(
                inspectNativeCurrent(),
                "SN_NATIVE_READER_V2 configuration change"
            );
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
        if (retired) return;
        lifecycleSuspended = true;
        advanceLifecycleEpoch();
        cancelActiveSourceSave();
        freezeInputIngress();
        ++refreshGeneration;
        if (latestObservation == null) return;
        if (hasLiveInputContact()) {
            beginNativeLifecycleHandoff("pause_during_contact", true);
            return;
        }
        if (supersedeInputIngressIfIdle() == null) {
            beginNativeLifecycleHandoff("pause_during_contact", true);
            return;
        }
        samePageReloadPrepared = false;
        if (port != null && port.phase() != NativeReaderFirmwarePort.Phase.IDLE) {
            disableNativeReaderV2("pause_during_writer_transfer");
            return;
        }
        if (!saveCurrentSourceNow()) {
            disableNativeReaderV2("pause_source_save_failed");
            return;
        }
        disableWriterWithWitness(
            inspectNativeCurrent(),
            "SN_NATIVE_READER_V2 lifecycle pause"
        );
        restoreWriterGeometry();
        restorePageGeometry();
        restorePresentationScale();
        retireTransactionalCore();
    }

    /**
     * Called only after the hook worker revalidates the persisted admission
     * evidence for the current resumed Activity generation.
     */
    public void onLifecycleResumeRevalidated() {
        assertOwnerThread();
        if (retired || containedFailClosed || !lifecycleSuspended) return;
        lifecycleSuspended = false;
        advanceLifecycleEpoch();
        scheduleRefresh("resume_authority_revalidated");
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

    /**
     * Completion edge emitted by the hook around the firmware's actual
     * disableHandWrite call. A void reflection return is not authority; only
     * this observed after-hook may acknowledge the armed disable attempt.
     */
    public void onNativeWriterDisableCompleted(
        Object presenter,
        boolean success
    ) {
        if (!writerDisableInFlight
            || expectedWriterDisablePresenter != presenter) return;
        // Stock can call the same presenter method independently. Ignore an
        // unrelated completion before asserting the v2 owner-thread contract;
        // only the synchronous invocation armed by disableWriterWithWitness
        // is allowed to acknowledge this transaction edge.
        assertOwnerThread();
        writerDisableAcknowledged = success;
        if (success) writerDisabled = true;
    }

    /** Receipt from the exact sendWriteInfo invocation armed by v2. */
    public void onNativeWriterEnableCompleted(
        Object presenter,
        boolean success
    ) {
        if (!writerEnableInFlight
            || expectedWriterEnablePresenter != presenter) return;
        if (Thread.currentThread().getId() != ownerThreadId) return;
        assertOwnerThread();
        if (!success
            || expectedWriterEnableActivityGeneration != activityGeneration
            || expectedWriterEnableLayoutGeneration != layoutGeneration + 1L
            || expectedWriterEnableRefreshGeneration != refreshGeneration
            || compositionGeneration != expectedWriterEnableRefreshGeneration) {
            writerEnablePrimed = false;
            return;
        }
        try {
            NativeReaderV2FirmwareAccess.Components current =
                inspectNativeCurrent();
            writerEnablePrimed = current.presenter == presenter
                && current.note == expectedWriterEnableNote
                && current.readerPage == expectedWriterEnablePage
                && current.presenterMarkPage == expectedWriterEnablePage + 1;
        } catch (RuntimeException failure) {
            writerEnablePrimed = false;
        }
    }

    /**
     * Final firmware-side receipt emitted by Note.screenRotation only after
     * DrawPath accepted Binder transaction 10. This is separate from the
     * earlier sendWriteInfo priming receipt.
     */
    public void onNativeWriterGeometryCompleted(
        Object note,
        int rotationCode,
        int originX,
        int originY,
        boolean success
    ) {
        if (!writerEnableInFlight || expectedWriterEnableNote != note) return;
        if (Thread.currentThread().getId() != ownerThreadId) return;
        assertOwnerThread();
        NativeWriterGeometry geometry = expectedWriterEnableGeometry;
        if (!success || geometry == null
            || rotationCode != geometry.rotation + 2000
            || originX != geometry.originX || originY != geometry.originY
            || expectedWriterEnableActivityGeneration != activityGeneration
            || expectedWriterEnableLayoutGeneration != layoutGeneration + 1L
            || expectedWriterEnableRefreshGeneration != refreshGeneration
            || compositionGeneration != expectedWriterEnableRefreshGeneration) {
            writerGeometryAcknowledged = false;
            return;
        }
        try {
            NativeReaderV2FirmwareAccess.Components current =
                inspectNativeCurrent();
            writerGeometryAcknowledged = current.note == note
                && current.presenter == expectedWriterEnablePresenter
                && current.readerPage == expectedWriterEnablePage
                && current.presenterMarkPage == expectedWriterEnablePage + 1
                && current.presenterRotation == geometry.rotation
                && current.documentLayout.getWidth() == geometry.viewWidth
                && current.documentLayout.getHeight() == geometry.viewHeight;
        } catch (RuntimeException failure) {
            writerGeometryAcknowledged = false;
        }
    }

    public boolean retire(String reason) {
        assertOwnerThread();
        if (retired) return true;
        if (!detachmentPrepared && ownsModifiedNativePresentation()) {
            // A hook-discovery, revalidation, or component fault is not a
            // license to abandon a live writer. Preserve routing ownership
            // until the source is witnessed saved and stock presentation is
            // restored. If any boundary is unavailable, stay installed and
            // block input fail-closed.
            if (stockPresentationRestorePending) return false;
            if (hasLiveInputContact() || !transactionAllowsStockRestoration()) {
                pendingRetirementReason = reason;
                containFailClosed(reason);
                return false;
            }
            pendingRetirementReason = reason;
            if (!beginStockPresentationRestoration(reason, "safe_retirement")) {
                containFailClosed(reason);
            }
            return false;
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
            components = null;
            return;
        }
        NativeComponentIdentityRegistry.Lease releasedIdentityLease =
            componentIdentityLease;
        componentIdentityLease = null;
        cancelActiveSourceSave();
        retired = true;
        shutdownProjectionWorker(releasedIdentityLease);
        freezeInputIngress();
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
        removeStatusOverlayQuietly("native_activity_destroyed");
        Log.w(TAG, "runtime released after native destroy reason=" + reason);
    }

    private void retirePrepared(String reason, boolean keepWriterDisabled) {
        assertOwnerThread();
        if (retired) return;
        NativeComponentIdentityRegistry.Lease releasedIdentityLease =
            componentIdentityLease;
        componentIdentityLease = null;
        cancelActiveSourceSave();
        retired = true;
        shutdownProjectionWorker(releasedIdentityLease);
        freezeInputIngress();
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
                disableWriterWithWitness(
                    inspectNativeCurrent(),
                    "SN_NATIVE_READER_V2 fail-closed retirement"
                );
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
        removeStatusOverlayQuietly("runtime_retire");
        Log.w(TAG, "runtime retired reason=" + reason);
    }

    private boolean beginStockPresentationRestoration(
        String retirementReason,
        String operation
    ) {
        // A stock reload owns a new ingress epoch even if an older projection
        // already held the gate. No completion from that projection may thaw
        // the restoration boundary.
        if (supersedeInputIngressIfIdle() == null) return false;
        samePageReloadPrepared = false;
        ++refreshGeneration;
        try {
            if (latestObservation != null && !saveCurrentSourceNow()) {
                return false;
            }
            if (preservingUnsavedSource) {
                if (port == null
                    || port.phase() != NativeReaderFirmwarePort.Phase.DISABLED) {
                    throw new IllegalStateException(
                        "preserved source lost its disabled transaction authority"
                    );
                }
                // The retry above has now witnessed the retained live source
                // save. Only at that boundary may the disabled transaction be
                // retired and ordinary stock teardown resume.
                port.retireDisabledForStock();
                preservingUnsavedSource = false;
            }
            NativeReaderV2FirmwareAccess.Components current =
                inspectNativeCurrent();
            disableWriterWithWitness(
                current,
                "SN_NATIVE_READER_V2 stock restore " + operation
            );
            restoreWriterGeometry();
            restorePageGeometry();
            restorePresentationScale();
            NativeReaderV2Compositor.Result oldPresentation = visible;
            SpreadSnapshot oldSnapshot = latestObservation == null
                ? null : latestObservation.snapshot;
            if (oldPresentation == null || oldSnapshot == null) {
                throw new IllegalStateException(
                    "stock restoration lacks prior presentation authority"
                );
            }
            activeStockPresentationReloadGeneration =
                nextStockPresentationReloadGeneration();
            stockRestoreBackground = null;
            stockRestoreInk = null;
            stockRestoreDigest = null;
            stockRestoreToken = stockRestoreWitness.begin(
                oldSnapshot,
                current.image,
                current.handWriteView,
                current.activity,
                oldPresentation.background,
                oldPresentation.ink,
                oldPresentation.digest,
                stockPresentationSignalGeneration,
                activeStockPresentationReloadGeneration
            );
            stockPresentationRestorePending = true;
            pendingRetirementReason = retirementReason;
            internalPageLoad = true;
            try {
                firmware.reloadDocumentPage(current);
            } finally {
                internalPageLoad = false;
            }
            // Completion is asynchronous and requires explicit replacement of
            // background, handwriting, and digest views. No component identity
            // or v2 bitmap is released at this point.
            return true;
        } catch (RuntimeException failure) {
            abortStockPresentationRestoration();
            Log.e(TAG, "stock presentation restoration failed operation="
                + operation, failure);
            return false;
        }
    }

    private void noteStockPresentationLayer(
        NativePresentationRestoreWitness.Layer layer,
        Object receiver,
        Bitmap replacement
    ) {
        assertOwnerThread();
        if (retired || !stockPresentationRestorePending) return;
        NativePresentationRestoreWitness.Token token = stockRestoreToken;
        SpreadSnapshot observed = latestObservation == null
            ? null : latestObservation.snapshot;
        ++stockPresentationSignalGeneration;
        if (token == null || observed == null
            || !stockRestoreWitness.observe(
                token,
                layer,
                activeStockPresentationReloadGeneration,
                stockPresentationSignalGeneration,
                receiver,
                replacement,
                observed
            )) {
            abortStockPresentationRestoration();
            containFailClosed("stock_presentation_receipt_mismatch");
            return;
        }
        if (layer == NativePresentationRestoreWitness.Layer.BACKGROUND) {
            stockRestoreBackground = replacement;
        } else if (layer == NativePresentationRestoreWitness.Layer.INK) {
            stockRestoreInk = replacement;
        } else {
            stockRestoreDigest = replacement;
        }
        finishStockPresentationRestorationIfReady(token);
    }

    /** Acknowledges only a native load-completion callback, never setImage. */
    public void onNativeStockPageReady(Object receiver, String signalName) {
        assertOwnerThread();
        if (retired || !stockPresentationRestorePending
            || !("displayChanged".equals(signalName)
                || "loadPageChanged".equals(signalName))) return;
        NativePresentationRestoreWitness.Token token = stockRestoreToken;
        if (stockRestoreWitness.pageReadyObserved(token)) return;
        SpreadSnapshot observed = latestObservation == null
            ? null : latestObservation.snapshot;
        NativeReaderV2FirmwareAccess.Components current;
        try {
            current = inspectNativeCurrent();
        } catch (RuntimeException failure) {
            abortStockPresentationRestoration();
            containFailClosed("stock_presentation_page_ready_inspection_failed");
            return;
        }
        ++stockPresentationSignalGeneration;
        if (token == null || observed == null
            || current.activity != receiver
            || current.readerPage != token.page
            || !stockRestoreWitness.observePageReady(
                token,
                activeStockPresentationReloadGeneration,
                stockPresentationSignalGeneration,
                receiver,
                observed,
                current.presenterMarkPage
            )) {
            abortStockPresentationRestoration();
            containFailClosed("stock_presentation_page_ready_mismatch");
            return;
        }
        finishStockPresentationRestorationIfReady(token);
    }

    private void finishStockPresentationRestorationIfReady(
        NativePresentationRestoreWitness.Token token
    ) {
        if (!stockRestoreWitness.ready(token)) return;
        try {
            NativeReaderV2FirmwareAccess.Components current =
                inspectNativeCurrent();
            if (current.activity != activity
                || components == null
                || current.image != components.image
                || current.handWriteView != components.handWriteView
                || current.readerPage != token.page
                || current.presenterMarkPage != token.page + 1
                || activityGeneration != token.activityGeneration
                || !stockRestoreWitness.installedLayersMatch(
                    token,
                    stockRestoreBackground,
                    stockRestoreInk,
                    stockRestoreDigest
                )
                || !firmware.stockPresentationLayersMatch(
                    current,
                    stockRestoreBackground,
                    stockRestoreInk,
                    stockRestoreDigest
                )
                || !stockRestoreWitness.finish(token)) {
                throw new IllegalStateException(
                    "stock presentation receipts lost native authority"
                );
            }
            stockPresentationRestorePending = false;
            stockRestoreToken = null;
            clearStockPresentationReceipts();
            retireTransactionalCore();
            recycleVisible();
            latestObservation = null;
            writerDisabled = false;
            preservingUnsavedSource = false;
            detachmentPrepared = true;
            removeStatusOverlayQuietly("stock_presentation_restored");
            final String reason = pendingRetirementReason;
            pendingRetirementReason = null;
            if (reason != null) {
                postGuarded("detachment_ready", () ->
                    detachmentListener.onRuntimeDetachmentReady(this, reason)
                );
            }
            Log.i(TAG, "stock presentation restoration acknowledged");
        } catch (RuntimeException failure) {
            abortStockPresentationRestoration();
            Log.e(TAG, "stock presentation acknowledgment failed", failure);
            containFailClosed("stock_presentation_acknowledgment_failed");
        }
    }

    private long nextStockPresentationReloadGeneration() {
        if (stockPresentationReloadGeneration == Long.MAX_VALUE) {
            throw new IllegalStateException(
                "stock presentation reload generation exhausted"
            );
        }
        return ++stockPresentationReloadGeneration;
    }

    private void abortStockPresentationRestoration() {
        stockPresentationRestorePending = false;
        stockRestoreWitness.abort();
        stockRestoreToken = null;
        clearStockPresentationReceipts();
    }

    private void clearStockPresentationReceipts() {
        activeStockPresentationReloadGeneration = 0L;
        stockRestoreBackground = null;
        stockRestoreInk = null;
        stockRestoreDigest = null;
    }

    private boolean ownsModifiedNativePresentation() {
        return visible != null || session != null || writerGeometryLease != null
            || pageGeometryLease != null || presentationScaleLease != null
            || latestObservation != null;
    }

    private boolean transactionAllowsStockRestoration() {
        if (port == null) return true;
        NativeReaderFirmwarePort.Phase phase = port.phase();
        return phase == NativeReaderFirmwarePort.Phase.IDLE
            || preservingUnsavedSource
                && phase == NativeReaderFirmwarePort.Phase.DISABLED;
    }

    private void settlePendingStockRestoration() {
        assertOwnerThread();
        if (retired || stockPresentationRestorePending
            || pendingRetirementReason == null || hasLiveInputContact()
            || !transactionAllowsStockRestoration()) return;
        String reason = pendingRetirementReason;
        if (!beginStockPresentationRestoration(reason, reason)) {
            containFailClosed(reason + "_restore_failed");
        }
    }

    private void containFailClosed(String reason) {
        if (retired) return;
        cancelActiveSourceSave();
        freezeInputIngress();
        samePageReloadPrepared = false;
        containedFailClosed = true;
        ++refreshGeneration;
        if (hasPhysicalInputContact()) {
            pendingContainmentReason = reason == null
                ? "contained_failure_during_contact" : reason;
            Log.e(TAG, "runtime containment deferred until contact terminal reason="
                + pendingContainmentReason);
            return;
        }
        disableContainedWriter(reason);
    }

    private void settlePendingContainment() {
        assertOwnerThread();
        if (retired || pendingContainmentReason == null
            || hasPhysicalInputContact()) return;
        String reason = pendingContainmentReason;
        pendingContainmentReason = null;
        disableContainedWriter(reason);
        if (pendingRetirementReason != null
            && !stockPresentationRestorePending
            && ownsModifiedNativePresentation()
            && transactionAllowsStockRestoration()) {
            String retirementReason = pendingRetirementReason;
            if (!beginStockPresentationRestoration(
                    retirementReason,
                    "deferred_safe_retirement"
                )) {
                Log.e(TAG, "deferred stock restoration could not start reason="
                    + retirementReason);
            }
        }
    }

    private void disableContainedWriter(String reason) {
        if (preservingUnsavedSource) {
            Log.e(TAG, "runtime retained unsaved live source fail-closed reason="
                + reason);
            return;
        }
        try {
            NativeReaderV2FirmwareAccess.Components current =
                inspectNativeCurrent();
            disableWriterWithWitness(
                current,
                "SN_NATIVE_READER_V2 contained failure " + reason
            );
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
        freezeInputIngress();
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
                disableWriterWithWitness(
                    inspectNativeCurrent(),
                    "SN_NATIVE_READER_V2 native lifecycle settled"
                );
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
        return nativePenCallbackContact || fingerContact || penContact
            || physicalContactFence.stylusContactActive();
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
            || physicalContactFence.stylusContactActive()
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
        AtomicInputAdmission.FreezeToken current = inputFreezeToken;
        if (current != null && inputAdmission.current(current)
            && !inputAdmission.contactActive()) {
            transactionInputFreezeToken = current;
        } else {
            transactionInputFreezeToken = freezeInputIngress();
        }
    }

    @Override
    public void requestNativeSourceSave(SourceSaveCallback callback) {
        assertOwnerThread();
        requireLive();
        Objects.requireNonNull(callback, "callback");
        final NativeReaderV2FirmwareAccess.Components expected =
            inspectNativeCurrent();
        final SpreadSnapshot snapshot = latestObservation == null
            ? null : latestObservation.snapshot;
        if (!sourceSaveAuthorityMatches(expected) || snapshot == null
            || sourceSaveFence.active()) {
            postGuarded(
                "source_save_authority_rejection",
                () -> callback.onComplete(false, null)
            );
            return;
        }
        final SourceSaveAttempt attempt;
        try {
            attempt = new SourceSaveAttempt(
                sourceSaveFence.begin(snapshot, markRevision),
                snapshot,
                expected,
                callback
            );
            activeSourceSaveAttempt = attempt;
        } catch (RuntimeException invalid) {
            Log.e(TAG, "source-save fence admission failed", invalid);
            callback.onComplete(false, null);
            containFailClosed("source_save_fence_admission_failed");
            return;
        }
        // Admission identity checks and PDF/marker lstat calls stay off the
        // input/UI thread. Native saveTrails itself remains owner-thread
        // confined, bracketed by worker-side authority checks.
        if (!executeProjection("source_save_prevalidation", new Runnable() {
            @Override public void run() {
                try {
                    if (!sourceSaveAttemptCurrent(attempt)) return;
                    final boolean admitted = NativeReaderV2DocumentGate
                        .fastEvidenceStillCurrent(evidence);
                    postGuarded("queued_source_save", new Runnable() {
                        @Override public void run() {
                            performBracketedSourceSave(
                                attempt,
                                admitted
                            );
                        }
                    });
                } catch (Throwable failure) {
                    postGuarded("source_save_prevalidation_failure", () -> {
                        if (!sourceSaveAttemptCurrent(attempt)) return;
                        Log.e(TAG, "source-save prevalidation failed", failure);
                        finishSourceSaveAttempt(attempt, false, null);
                        containFailClosed("source_save_prevalidation_failed");
                    });
                }
            }
        })) {
            finishSourceSaveAttempt(attempt, false, null);
        }
    }

    private void performBracketedSourceSave(
        SourceSaveAttempt attempt,
        boolean admittedBeforeSave
    ) {
        assertOwnerThread();
        if (!sourceSaveAttemptCurrent(attempt)) return;
        if (!admittedBeforeSave || retired) {
            finishSourceSaveAttempt(attempt, false, null);
            return;
        }
        NativeReaderV2FirmwareAccess.Components source;
        try {
            source = inspectNativeCurrent();
        } catch (RuntimeException failure) {
            Log.e(TAG, "queued source-save inspection failed", failure);
            finishSourceSaveAttempt(attempt, false, null);
            return;
        }
        if (!sourceSaveAuthorityMatches(source)
            || source.presenter != attempt.expected.presenter
            || source.note != attempt.expected.note
            || source.readerPage != attempt.expected.readerPage
            || !sourceSaveAttemptCurrent(attempt)) {
            finishSourceSaveAttempt(attempt, false, null);
            return;
        }
        final boolean saved = saveSourceWithWitness(
            source,
            "source save failed"
        );
        if (!executeProjection("source_save_postvalidation", new Runnable() {
            @Override public void run() {
                try {
                    if (!sourceSaveAttemptCurrent(attempt)) return;
                    final boolean admittedAfterSave = saved
                        && NativeReaderV2DocumentGate.fastEvidenceStillCurrent(
                            evidence
                        );
                    postGuarded("source_save_postvalidation", new Runnable() {
                        @Override public void run() {
                            if (!sourceSaveAttemptCurrent(attempt)) return;
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
                            finishSourceSaveAttempt(
                                attempt,
                                complete,
                                observation
                            );
                        }
                    });
                } catch (Throwable failure) {
                    postGuarded("source_save_postvalidation_failure", () -> {
                        if (!sourceSaveAttemptCurrent(attempt)) return;
                        Log.e(TAG, "source-save postvalidation failed", failure);
                        finishSourceSaveAttempt(attempt, false, null);
                        containFailClosed("source_save_postvalidation_failed");
                    });
                }
            }
        })) {
            finishSourceSaveAttempt(attempt, false, null);
            containFailClosed("source_save_postvalidation_not_scheduled");
        }
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
        disableWriterWithWitness(current, "SN_NATIVE_READER_V2 transfer");
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
        if (pendingRetirementReason != null) {
            freezeInputIngress();
            transactionInputFreezeToken = null;
            postGuarded(
                "pending_stock_restoration_release",
                this::settlePendingStockRestoration
            );
        } else {
            AtomicInputAdmission.FreezeToken transaction =
                transactionInputFreezeToken;
            transactionInputFreezeToken = null;
            releaseInputIngress(transaction);
            postGuarded("deferred_navigation_release", this::drainNavigation);
        }
    }

    @Override
    public void preserveUnsavedNativeSource(String reason) {
        assertOwnerThread();
        if (retired) return;
        cancelActiveSourceSave();
        preservingUnsavedSource = true;
        containedFailClosed = true;
        freezeInputIngress();
        samePageReloadPrepared = false;
        ++refreshGeneration;
        Log.e(TAG, "unsaved source preserved behind input fence reason="
            + reason);
        settlePendingStockRestoration();
    }

    @Override
    public void disableNativeReaderV2(String reason) {
        assertOwnerThread();
        if (retired) return;
        containFailClosed(reason);
    }

    private void refreshWhenReady(long generation, int attempt, String reason) {
        if (retired || containedFailClosed || detachmentPrepared
            || lifecycleSuspended || nativeLifecycleHandoffPending
            || generation != refreshGeneration) return;
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
        if (lifecycleSuspended || generation != refreshGeneration) {
            return false;
        }
        long nextLayout = layoutGeneration + 1L;
        RectD canvas = new RectD(
            0,
            0,
            current.documentLayout.getWidth(),
            current.documentLayout.getHeight()
        );
        if (componentIdentityLease == null) {
            componentIdentityLease =
                firmware.acquireComponentIdentityLease(current);
        }
        NativeAuthority authority = firmware.authority(
            current,
            claim.documentId,
            activityGeneration,
            nextLayout,
            componentIdentityLease
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
        AtomicInputAdmission.FreezeToken compositionFreeze =
            reserveInputIngressIfIdle();
        if (compositionFreeze == null) return false;
        final long compositionLifecycleEpoch = lifecycleEpoch;
        compositionGeneration = generation;
        try {
            boolean accepted = executeProjection("spread_composition", new Runnable() {
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
                    if (retired || projectionShutdown
                        || Thread.currentThread().isInterrupted()) {
                        if (prepared != null) prepared.recycle();
                        return;
                    }
                    final NativeReaderV2Compositor.Result result = prepared;
                    final Throwable projectionFailure = failure;
                    boolean posted = ownerHandler.post(new Runnable() {
                        @Override public void run() {
                            try {
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
                                    compositionFreeze,
                                    compositionLifecycleEpoch,
                                    result,
                                    projectionFailure
                                );
                            } catch (Throwable completionFailure) {
                                if (result != null && result != visible) {
                                    result.recycle();
                                }
                                Log.e(TAG,
                                    "projection completion failed closed",
                                    completionFailure);
                                if (!retired) {
                                    containFailClosed(
                                        "projection_completion_failed"
                                    );
                                }
                            }
                        }
                    });
                    if (!posted && result != null) result.recycle();
                }
            });
            if (!accepted && !inputWasFrozen) {
                releaseInputIngress(compositionFreeze);
            }
            return accepted;
        } catch (RuntimeException failure) {
            if (!inputWasFrozen) releaseInputIngress(compositionFreeze);
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
        AtomicInputAdmission.FreezeToken compositionFreeze,
        long compositionLifecycleEpoch,
        NativeReaderV2Compositor.Result next,
        Throwable projectionFailure
    ) {
        assertOwnerThread();
        if (retired || lifecycleSuspended
            || lifecycleEpoch != compositionLifecycleEpoch
            || generation != refreshGeneration
            || compositionGeneration != generation) {
            if (next != null) next.recycle();
            if (!retired && !containedFailClosed
                && compositionGeneration == generation) {
                if (!inputWasFrozen) releaseInputIngress(compositionFreeze);
            }
            return;
        }
        if (projectionFailure != null || next == null) {
            if (next != null) next.recycle();
            if (!inputWasFrozen) releaseInputIngress(compositionFreeze);
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
            boolean publicationAdmitted = physicalContactFence.runWhenStylusIdle(
                new Runnable() {
                    @Override public void run() {
                        publishPreparedComposition(
                            current,
                            snapshot,
                            authority,
                            canvas,
                            nextLayout,
                            reason,
                            compositionFreeze,
                            compositionLifecycleEpoch,
                            next
                        );
                    }
                }
            );
            if (!publicationAdmitted) {
                if (next != visible) next.recycle();
                if (!inputWasFrozen) releaseInputIngress(compositionFreeze);
                compositionDeferredForPhysicalContact = true;
                Log.d(TAG,
                    "composition publication deferred until physical stylus "
                        + "contact ends reason=" + reason);
            }
        } catch (RuntimeException failure) {
            if (next != visible) next.recycle();
            if (!inputWasFrozen) releaseInputIngress(compositionFreeze);
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
        AtomicInputAdmission.FreezeToken compositionFreeze,
        long compositionLifecycleEpoch,
        NativeReaderV2Compositor.Result next
    ) {
        if (retired || containedFailClosed || detachmentPrepared
            || lifecycleSuspended
            || lifecycleEpoch != compositionLifecycleEpoch
            || !inputAdmission.current(compositionFreeze)
            || physicalContactFence.stylusContactActive()) {
            throw new IllegalStateException(
                "contained or detached runtime cannot publish a composition"
            );
        }
        boolean committed = false;
        boolean presentationPublicationAttempted = false;
        NativeReaderV2Compositor.Result previous = visible;
        try {
            disableWriterWithWitness(current, "SN_NATIVE_READER_V2 compose");
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
            programWriterGeometryWithWitness(
                current,
                geometry,
                writerChrome,
                snapshot,
                nextLayout
            );
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
                releaseInputIngress(compositionFreeze);
            } else if (port.phase() == NativeReaderFirmwarePort.Phase.IDLE) {
                if (!session.publish(snapshot)) {
                    throw new IllegalStateException(
                        "stable spread authority publication failed"
                    );
                }
                port.publishStableObservation(observation);
                releaseInputIngress(compositionFreeze);
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
                    freezeInputIngress();
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
                    disableWriterWithWitness(
                        current,
                        "SN_NATIVE_READER_V2 compose failed"
                    );
                } catch (RuntimeException disableFailure) {
                    Log.e(TAG, "writer fail-close failed after compose",
                        disableFailure);
                }
            }
        }
    }

    private void leaveSpreadForPortrait(
        NativeReaderV2FirmwareAccess.Components current,
        String reason
    ) {
        if (writerGeometryLease != null) {
            disableWriterWithWitness(
                current,
                "SN_NATIVE_READER_V2 portrait restore"
            );
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
        releaseInputIngress(inputFreezeToken);
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

    private void disableWriterWithWitness(
        NativeReaderV2FirmwareAccess.Components current,
        String reason
    ) {
        if (current == null || current.presenter == null
            || writerDisableInFlight) {
            throw new IllegalStateException(
                "native writer disable lacks exclusive presenter authority"
            );
        }
        expectedWriterDisablePresenter = current.presenter;
        writerDisableInFlight = true;
        writerDisableAcknowledged = false;
        try {
            firmware.disableWriter(current, reason);
            if (!writerDisableAcknowledged || !writerDisabled) {
                throw new IllegalStateException(
                    "native writer disable did not reach its firmware after-hook"
                );
            }
        } finally {
            writerDisableInFlight = false;
            expectedWriterDisablePresenter = null;
            writerDisableAcknowledged = false;
        }
    }

    private void programWriterGeometryWithWitness(
        NativeReaderV2FirmwareAccess.Components current,
        NativeWriterGeometry geometry,
        List<RectD> writerChrome,
        SpreadSnapshot snapshot,
        long nextLayout
    ) {
        if (current == null || geometry == null || snapshot == null
            || writerEnableInFlight
            || current.presenter == null || current.note == null
            || nextLayout <= layoutGeneration
            || snapshot.layoutGeneration != nextLayout
            || snapshot.activityGeneration != activityGeneration
            || snapshot.activePageIndex != current.readerPage) {
            throw new IllegalStateException(
                "native writer enable lacks exact publication authority"
            );
        }
        expectedWriterEnablePresenter = current.presenter;
        expectedWriterEnableNote = current.note;
        expectedWriterEnablePage = current.readerPage;
        expectedWriterEnableActivityGeneration = snapshot.activityGeneration;
        expectedWriterEnableLayoutGeneration = nextLayout;
        expectedWriterEnableRefreshGeneration = compositionGeneration;
        expectedWriterEnableGeometry = geometry;
        writerEnableInFlight = true;
        writerEnablePrimed = false;
        writerGeometryAcknowledged = false;
        writerEnableAcknowledged = false;
        try {
            firmware.programWriterGeometry(current, geometry, writerChrome);
            NativeReaderV2FirmwareAccess.Components observed =
                inspectNativeCurrent();
            writerEnableAcknowledged = writerEnablePrimed
                && writerGeometryAcknowledged;
            if (!writerEnableAcknowledged
                || observed.presenter != current.presenter
                || observed.note != current.note
                || observed.readerPage != current.readerPage
                || observed.presenterMarkPage != current.readerPage + 1
                || observed.presenterRotation != geometry.rotation
                || observed.documentLayout.getWidth() != geometry.viewWidth
                || observed.documentLayout.getHeight() != geometry.viewHeight) {
                throw new IllegalStateException(
                    "native writer enable lacked firmware-observed authority"
                );
            }
            writerDisabled = false;
        } finally {
            writerEnableInFlight = false;
            expectedWriterEnablePresenter = null;
            expectedWriterEnableNote = null;
            expectedWriterEnablePage = -1;
            expectedWriterEnableActivityGeneration = -1L;
            expectedWriterEnableLayoutGeneration = -1L;
            expectedWriterEnableRefreshGeneration = -1L;
            expectedWriterEnableGeometry = null;
            writerEnablePrimed = false;
            writerGeometryAcknowledged = false;
            writerEnableAcknowledged = false;
        }
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

    /** Safe from both the projection worker and the owner thread. */
    private boolean sourceSaveAttemptCurrent(SourceSaveAttempt attempt) {
        return attempt != null && activeSourceSaveAttempt == attempt
            && sourceSaveFence.current(attempt.token, attempt.snapshot);
    }

    private void finishSourceSaveAttempt(
        SourceSaveAttempt attempt,
        boolean success,
        NativeReaderFirmwarePort.Observation observation
    ) {
        assertOwnerThread();
        if (!sourceSaveAttemptCurrent(attempt)) return;
        if (!sourceSaveFence.complete(attempt.token)) return;
        activeSourceSaveAttempt = null;
        attempt.callback.onComplete(success, success ? observation : null);
    }

    /** Invalidates queued worker and Handler continuations without callbacks. */
    private void cancelActiveSourceSave() {
        if (activeSourceSaveAttempt == null) return;
        sourceSaveFence.cancel();
        activeSourceSaveAttempt = null;
    }

    private boolean saveSourceWithWitness(
        NativeReaderV2FirmwareAccess.Components source,
        String failureMessage
    ) {
        NativeSaveWitness.Token token = null;
        boolean dirty = false;
        boolean markAuthorityNoted = false;
        try {
            // Match the stock page-turn boundary. Closing the native lasso can
            // commit a pending move/scale, so this must precede both the dirty
            // observation and the witnessed save.
            firmware.prepareSourceForTransfer(source);
            dirty = firmware.sourceHasTrails(source);
            token = saveWitness.begin(
                source.note,
                source.markPath,
                source.readerPage + 1,
                dirty
            );
            saveWitnessFault = false;
            firmware.saveSource(source);
            boolean saved = !saveWitnessFault && saveWitness.finish(token);
            evidence.noteWitnessedMarkSave(dirty, saved);
            markAuthorityNoted = true;
            if (saved && dirty) markRevision++;
            return saved;
        } catch (RuntimeException failure) {
            if (token != null && saveWitness.active()) {
                saveWitness.abort(token);
            }
            if (dirty && !markAuthorityNoted) {
                try {
                    evidence.noteWitnessedMarkSave(true, false);
                } catch (RuntimeException authorityFailure) {
                    failure.addSuppressed(authorityFailure);
                }
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
        transactionInputFreezeToken = null;
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
            if (!tryStartNavigationAtomically(target)) {
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

    private boolean tryStartNavigationAtomically(int target) {
        if (retired || containedFailClosed || hasPhysicalInputContact()
            || controller == null || port == null || session == null
            || port.phase() != NativeReaderFirmwarePort.Phase.IDLE
            || session.gestures().hasActiveGesture()) {
            return false;
        }
        AtomicInputAdmission.FreezeToken navigationFreeze =
            reserveInputIngressIfIdle();
        if (navigationFreeze == null) return false;
        transactionInputFreezeToken = navigationFreeze;
        boolean started = false;
        try {
            if (!retired && !containedFailClosed
                && port.phase() == NativeReaderFirmwarePort.Phase.IDLE
                && !session.gestures().hasActiveGesture()) {
                started = controller.requestNavigation(target);
            }
            return started;
        } finally {
            if (!started) {
                if (transactionInputFreezeToken == navigationFreeze) {
                    transactionInputFreezeToken = null;
                }
                releaseInputIngress(navigationFreeze);
            }
        }
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
        if (retired || inputFrozen || hasPhysicalInputContact()
            || controller == null || port == null || session == null
            || port.phase() != NativeReaderFirmwarePort.Phase.IDLE
            || session.gestures().hasActiveGesture()
            || deferredNavigation.isEmpty()) return;
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
        if (tryStartNavigationAtomically(target)) {
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
        if (fingerIngressAdmitted) {
            inputAdmission.end(AtomicInputAdmission.Contact.FINGER);
            fingerIngressAdmitted = false;
        }
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
        postGuarded(
            "pending_containment_after_finger",
            () -> {
                settlePendingContainment();
                settlePendingStockRestoration();
            }
        );
    }

    private void clearPenRoute() {
        penGestureToken = 0L;
        penContact = false;
        penSuppressed = false;
    }

    private AtomicInputAdmission.FreezeToken freezeInputIngress() {
        AtomicInputAdmission.FreezeToken token = inputAdmission.freeze();
        inputFreezeToken = token;
        inputFrozen = true;
        return token;
    }

    /** Atomically reserves a contact-free boundary for native mutation. */
    private AtomicInputAdmission.FreezeToken reserveInputIngressIfIdle() {
        AtomicInputAdmission.FreezeToken current = inputFreezeToken;
        if (inputFrozen) {
            return current != null && inputAdmission.current(current)
                && !inputAdmission.contactActive() ? current : null;
        }
        AtomicInputAdmission.FreezeToken token = inputAdmission.freezeIfIdle();
        if (token == null) return null;
        inputFreezeToken = token;
        inputFrozen = true;
        return token;
    }

    /** Replaces an older freeze epoch without crossing a live contact. */
    private AtomicInputAdmission.FreezeToken supersedeInputIngressIfIdle() {
        AtomicInputAdmission.FreezeToken token =
            inputAdmission.supersedeIfIdle();
        if (token == null) return null;
        inputFreezeToken = token;
        inputFrozen = true;
        return token;
    }

    /** A stale owner can never release a later lifecycle/restoration epoch. */
    private boolean releaseInputIngress(
        AtomicInputAdmission.FreezeToken token
    ) {
        if (token == null || retired || containedFailClosed
            || lifecycleSuspended || nativeLifecycleHandoffPending
            || stockPresentationRestorePending || detachmentPrepared
            || pendingRetirementReason != null) {
            return false;
        }
        if (!inputAdmission.release(token)) return false;
        if (inputFreezeToken == token) inputFreezeToken = null;
        inputFrozen = inputAdmission.frozen();
        return true;
    }

    private void advanceLifecycleEpoch() {
        if (lifecycleEpoch == Long.MAX_VALUE) {
            throw new IllegalStateException("lifecycle epoch exhausted");
        }
        lifecycleEpoch++;
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
        if (retired || containedFailClosed || lifecycleSuspended
            || components == null
            || latestObservation == null) {
            throw new IllegalStateException("Native Reader v2 is not live");
        }
    }

    private void reportActivationReady() {
        if (activationReported || retired || containedFailClosed
            || lifecycleSuspended) return;
        activationReported = true;
        activationListener.onRuntimeInputAuthorityReady(this);
    }

    private void postGuarded(String label, Runnable action) {
        ownerHandler.post(guarded(label, action));
    }

    private boolean executeProjection(String label, Runnable action) {
        Objects.requireNonNull(action, "action");
        if (retired || projectionShutdown) return false;
        try {
            projectionExecutor.execute(action);
            return true;
        } catch (RuntimeException rejected) {
            if (!retired && !projectionShutdown) {
                postGuarded("projection_rejected:" + label, () -> {
                    Log.e(TAG, "projection work rejected label=" + label,
                        rejected);
                    containFailClosed("projection_work_rejected:" + label);
                });
            }
            return false;
        }
    }

    /**
     * Cancels speculative work immediately, then releases identity bookkeeping
     * only after any already-running native projection has relinquished every
     * captured component. Lifecycle callbacks never wait on that drain.
     */
    private void shutdownProjectionWorker(
        NativeComponentIdentityRegistry.Lease releasedIdentityLease
    ) {
        if (projectionShutdown) return;
        projectionShutdown = true;
        projectionExecutor.shutdownNow();
        Thread cleanup = new Thread(new Runnable() {
            @Override public void run() {
                boolean interrupted = false;
                try {
                    while (true) {
                        try {
                            if (projectionExecutor.awaitTermination(
                                    1L,
                                    TimeUnit.SECONDS
                                )) break;
                        } catch (InterruptedException stop) {
                            interrupted = true;
                        }
                    }
                    firmware.releaseProjectionReader();
                    firmware.releaseComponentIdentityLease(
                        releasedIdentityLease
                    );
                } catch (RuntimeException failure) {
                    Log.e(TAG, "projection worker cleanup failed", failure);
                } finally {
                    evidence.close();
                    if (interrupted) Thread.currentThread().interrupt();
                }
            }
        }, "NativeReaderV2ProjectionCleanup");
        cleanup.setDaemon(true);
        cleanup.start();
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

    private static final class SourceSaveAttempt {
        final NativeAsyncSaveFence.Token token;
        final SpreadSnapshot snapshot;
        final NativeReaderV2FirmwareAccess.Components expected;
        final SourceSaveCallback callback;

        SourceSaveAttempt(
            NativeAsyncSaveFence.Token token,
            SpreadSnapshot snapshot,
            NativeReaderV2FirmwareAccess.Components expected,
            SourceSaveCallback callback
        ) {
            this.token = Objects.requireNonNull(token, "token");
            this.snapshot = Objects.requireNonNull(snapshot, "snapshot");
            this.expected = Objects.requireNonNull(expected, "expected");
            this.callback = Objects.requireNonNull(callback, "callback");
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
