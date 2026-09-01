package com.techrebbe.supernote.spreadprobe.v2;

import java.util.Objects;

/**
 * Exact-firmware transaction boundary for Native Reader v2.
 *
 * <p>The bridge is intentionally narrower than the vendor object graph.  It
 * exposes only operations whose completion can be followed by a fresh,
 * immutable authority observation.  The Android/Xposed layer is responsible
 * for constructing those observations from the inspected firmware and for
 * calling {@link #onFirmwarePageReady(Observation)} on the controller's owner
 * thread after the document image and handwriting page are both ready.</p>
 *
 * <p>This class never edits a {@code .mark} file and never treats a method
 * return as sufficient target-page authority.  A target or rollback becomes
 * publishable only after a complete post-load observation agrees on the
 * document, activity, layout, source page, mark page, and native component
 * identities.</p>
 */
public final class NativeReaderFirmwarePort
    implements NativeReaderController.Port {

    public enum Phase {
        IDLE,
        FROZEN,
        SOURCE_SAVED,
        TARGET_LOADING,
        TARGET_READY,
        REPLAYING,
        ROLLBACK_LOADING,
        DISABLED
    }

    /** The firmware calls are provided by the pinned Android adapter. */
    public interface Bridge {
        interface SourceSaveCallback {
            void onComplete(boolean saved, Observation observation);
        }

        Observation observe();
        /** Constant-time check against adapter-owned, already-published state. */
        boolean isStableObservationCurrent(Observation expected);
        void freezeDocumentInput();
        void requestNativeSourceSave(SourceSaveCallback callback);
        void postToOwnerThread(Runnable callback);
        void disableNativeWriter();
        void loadNativePage(int zeroBasedPageIndex);
        void replayNativeFingerHit(PointD sourcePoint);
        void navigateNativeSpread(
            SpreadSnapshot sourceSnapshot,
            double deltaX,
            double deltaY
        );
        void releaseDocumentInput();
        void disableNativeReaderV2(String reason);
    }

    /**
     * One atomic read of the native reader's page and writer authority.
     * {@code snapshot} must have been derived from the same object identities
     * and layout generation as {@code authority}; mixed-time observations are
     * rejected.
     */
    public static final class Observation {
        public final NativeAuthority authority;
        public final SpreadSnapshot snapshot;
        public final boolean writerEnabled;
        public final long markRevision;

        public Observation(
            NativeAuthority authority,
            SpreadSnapshot snapshot,
            boolean writerEnabled,
            long markRevision
        ) {
            this.authority = authority;
            this.snapshot = Objects.requireNonNull(snapshot, "snapshot");
            if (markRevision < 0L) {
                throw new IllegalArgumentException(
                    "mark revision must be non-negative"
                );
            }
            if (writerEnabled != snapshot.writerReady) {
                throw new IllegalArgumentException(
                    "writer observation disagrees with snapshot"
                );
            }
            if (writerEnabled) {
                if (authority == null
                    || !authority.equals(snapshot.writerAuthority)) {
                    throw new IllegalArgumentException(
                        "writer authority observation is incomplete"
                    );
                }
            } else if (authority != null || snapshot.writerAuthority != null) {
                throw new IllegalArgumentException(
                    "disabled writer published an authority"
                );
            }
            this.writerEnabled = writerEnabled;
            this.markRevision = markRevision;
        }
    }

    private final Bridge bridge;
    private final long ownerThreadId;
    private NativeReaderController controller;
    private ActivationMachine.Token token;
    private Phase phase = Phase.IDLE;
    private long sourceMarkRevision = -1L;
    private NativeAuthority targetAuthority;
    private Observation stableObservation;
    private boolean sourceSaveCompletionHandled;

    public NativeReaderFirmwarePort(
        Bridge bridge,
        Observation initialObservation
    ) {
        this.bridge = Objects.requireNonNull(bridge, "bridge");
        this.ownerThreadId = Thread.currentThread().getId();
        this.stableObservation = requireStableObservation(initialObservation);
    }

    /** One-time wiring after the controller has received this port. */
    public void attachController(NativeReaderController controller) {
        assertOwnerThread();
        if (this.controller != null || controller == null) {
            throw new IllegalStateException(
                "firmware port controller already attached or missing"
            );
        }
        this.controller = controller;
    }

    public Phase phase() {
        assertOwnerThread();
        return phase;
    }

    /**
     * Replaces the cached stable authority after navigation/rotation that did
     * not use an activation transaction. It is forbidden while an activation
     * owns input.
     */
    public void publishStableObservation(Observation observation) {
        assertOwnerThread();
        requireAttached();
        requirePhase(Phase.IDLE);
        Observation next = requireStableObservation(observation);
        Observation previous = stableObservation;
        if (!previous.snapshot.documentId.equals(next.snapshot.documentId)
            || previous.snapshot.activityGeneration
                != next.snapshot.activityGeneration) {
            throw new IllegalArgumentException(
                "stable firmware identity changed; construct a new port"
            );
        }
        if (next.snapshot.layoutGeneration
            <= previous.snapshot.layoutGeneration) {
            throw new IllegalArgumentException(
                "stable firmware layout generation did not advance"
            );
        }
        stableObservation = next;
    }

    @Override
    public void freezeInput(ActivationMachine.Token requested) {
        assertOwnerThread();
        requireAttached();
        requirePhase(Phase.IDLE);
        requireNewToken(requested);
        Observation source = requireObservation(
            stableObservation,
            requested,
            requested.sourcePage,
            requested.layoutGeneration,
            true,
            false
        );
        if (!bridge.isStableObservationCurrent(source)) {
            throw new IllegalStateException(
                "cached firmware authority is no longer current"
            );
        }
        token = requested;
        sourceMarkRevision = source.markRevision;
        sourceSaveCompletionHandled = false;
        phase = Phase.FROZEN;
        bridge.freezeDocumentInput();
    }

    @Override
    public void requestSourceSave(ActivationMachine.Token requested) {
        assertOwnerThread();
        requireCurrent(requested, Phase.FROZEN);
        bridge.requestNativeSourceSave(
            new Bridge.SourceSaveCallback() {
                @Override
                public void onComplete(
                    boolean saved,
                    Observation observation
                ) {
                    postSourceSaveCompletion(
                        requested,
                        saved,
                        observation
                    );
                }
            }
        );
    }

    private void postSourceSaveCompletion(
        ActivationMachine.Token requested,
        boolean saved,
        Observation observation
    ) {
        Runnable completion = new Runnable() {
            @Override
            public void run() {
                onSourceSaveCompleted(requested, saved, observation);
            }
        };
        bridge.postToOwnerThread(completion);
    }

    private void onSourceSaveCompleted(
        ActivationMachine.Token requested,
        boolean saved,
        Observation after
    ) {
        assertOwnerThread();
        if (token != requested || phase != Phase.FROZEN
            || sourceSaveCompletionHandled) {
            return;
        }
        sourceSaveCompletionHandled = true;
        boolean current = observationMatches(
            after,
            requested,
            requested.sourcePage,
            requested.layoutGeneration,
            true,
            false
        );
        boolean revisionValid = after != null
            && after.markRevision >= sourceMarkRevision;
        phase = saved && current && revisionValid
            ? Phase.SOURCE_SAVED : Phase.FROZEN;
        controller.onSourceSaveComplete(
            requested,
            saved && current && revisionValid
        );
    }

    @Override
    public void disableWriter(ActivationMachine.Token requested) {
        assertOwnerThread();
        requireCurrent(requested, Phase.SOURCE_SAVED);
        bridge.disableNativeWriter();
        Observation disabled = bridge.observe();
        if (disabled == null || disabled.writerEnabled
            || !sameTransactionIdentity(disabled.snapshot, requested)
            || disabled.snapshot.activePageIndex != requested.sourcePage) {
            throw new IllegalStateException(
                "firmware writer did not disable on the source page"
            );
        }
    }

    @Override
    public void requestTargetLoad(ActivationMachine.Token requested) {
        assertOwnerThread();
        requireCurrent(requested, Phase.SOURCE_SAVED);
        phase = Phase.TARGET_LOADING;
        bridge.loadNativePage(requested.targetPage);
    }

    @Override
    public void replayFingerHit(
        ActivationMachine.Token requested,
        PointD sourcePoint
    ) {
        assertOwnerThread();
        requireCurrent(requested, Phase.TARGET_READY);
        Objects.requireNonNull(sourcePoint, "sourcePoint");
        phase = Phase.REPLAYING;
        bridge.replayNativeFingerHit(sourcePoint);
        finishReplay(requested);
    }

    @Override
    public void navigateSwipe(
        SpreadSnapshot sourceSnapshot,
        double deltaX,
        double deltaY
    ) {
        assertOwnerThread();
        requireAttached();
        if (phase != Phase.IDLE || sourceSnapshot == null
            || !Double.isFinite(deltaX) || !Double.isFinite(deltaY)) {
            throw new IllegalStateException(
                "native navigation requested without stable authority"
            );
        }
        Observation current = bridge.observe();
        if (current == null || !current.writerEnabled
            || !current.snapshot.sameAuthorityEpoch(sourceSnapshot)
            || current.snapshot.activePageIndex
                != sourceSnapshot.activePageIndex) {
            throw new IllegalStateException(
                "native navigation authority is stale"
            );
        }
        bridge.navigateNativeSpread(sourceSnapshot, deltaX, deltaY);
    }

    @Override
    public void releaseInput(ActivationMachine.Token requested) {
        assertOwnerThread();
        requireCurrent(
            requested,
            Phase.TARGET_READY,
            Phase.REPLAYING,
            Phase.ROLLBACK_LOADING
        );
        bridge.releaseDocumentInput();
        clearTransaction();
    }

    @Override
    public void requestRollback(ActivationMachine.Token requested) {
        assertOwnerThread();
        requireAttached();
        if (requested == null || token != requested
            || phase == Phase.DISABLED || phase == Phase.IDLE
            || phase == Phase.REPLAYING) {
            throw new IllegalStateException(
                "rollback requested without recoverable authority"
            );
        }
        phase = Phase.ROLLBACK_LOADING;
        targetAuthority = null;
        bridge.disableNativeWriter();
        bridge.loadNativePage(requested.sourcePage);
    }

    @Override
    public void disableFeature(
        ActivationMachine.Token requested,
        String reason
    ) {
        assertOwnerThread();
        requireAttached();
        phase = Phase.DISABLED;
        token = null;
        sourceMarkRevision = -1L;
        targetAuthority = null;
        bridge.disableNativeReaderV2(
            reason == null ? "unspecified_failure" : reason
        );
    }

    /**
     * Called by the pinned firmware observer only when both the document page
     * and its handwriting writer report ready. Intermediate image callbacks
     * are ignored by the Android layer and must not call this method.
     */
    public void onFirmwarePageReady(Observation ready) {
        assertOwnerThread();
        requireAttached();
        ActivationMachine.Token current = token;
        if (current == null) {
            return;
        }
        if (phase == Phase.TARGET_LOADING) {
            NativeAuthority authority = readyAuthority(
                ready, current, current.targetPage
            );
            if (authority == null) {
                controller.onTargetLoadComplete(
                    current,
                    current.targetPage,
                    false
                );
                return;
            }
            phase = Phase.TARGET_READY;
            targetAuthority = authority;
            stableObservation = ready;
            controller.onTargetLoadComplete(
                current,
                current.targetPage,
                true
            );
            controller.onTargetReady(current, authority, ready.snapshot);
            return;
        }
        if (phase == Phase.ROLLBACK_LOADING) {
            NativeAuthority authority = readyAuthority(
                ready, current, current.sourcePage
            );
            if (authority == null) {
                controller.onRollbackFailed(
                    current,
                    "native_source_rollback_authority_failed"
                );
                return;
            }
            stableObservation = ready;
            controller.onRollbackReady(current, authority, ready.snapshot);
        }
    }

    /** Fail the current native load without manufacturing a ready callback. */
    public void onFirmwarePageLoadFailed(int zeroBasedPageIndex) {
        assertOwnerThread();
        requireAttached();
        ActivationMachine.Token current = token;
        if (current == null) {
            return;
        }
        if (phase == Phase.TARGET_LOADING
            && zeroBasedPageIndex == current.targetPage) {
            controller.onTargetLoadComplete(current, zeroBasedPageIndex, false);
        } else if (phase == Phase.ROLLBACK_LOADING
            && zeroBasedPageIndex == current.sourcePage) {
            controller.onRollbackFailed(
                current,
                "native_source_rollback_load_failed"
            );
        }
    }

    private void finishReplay(ActivationMachine.Token requested) {
        Observation after = bridge.observe();
        boolean success = targetAuthority != null && observationMatches(
            after,
            requested,
            requested.targetPage,
            targetAuthority.layoutGeneration,
            true,
            false
        ) && targetAuthority.equals(after.authority);
        if (success) {
            stableObservation = after;
        }
        controller.onReplayComplete(requested, success);
    }

    private NativeAuthority readyAuthority(
        Observation observation,
        ActivationMachine.Token requested,
        int page
    ) {
        if (!observationMatches(
            observation,
            requested,
            page,
            -1L,
            true,
            true
        ) || observation.snapshot.layoutGeneration
            <= requested.layoutGeneration) {
            return null;
        }
        return observation.authority;
    }

    private Observation requireObservation(
        Observation observation,
        ActivationMachine.Token requested,
        int page,
        long exactLayoutGeneration,
        boolean writerEnabled,
        boolean allowNewLayout
    ) {
        if (!observationMatches(
            observation,
            requested,
            page,
            exactLayoutGeneration,
            writerEnabled,
            allowNewLayout
        )) {
            throw new IllegalStateException(
                "firmware authority observation does not match transaction"
            );
        }
        return observation;
    }

    private static Observation requireStableObservation(
        Observation observation
    ) {
        Objects.requireNonNull(observation, "observation");
        if (!observation.writerEnabled || observation.authority == null
            || !observation.authority.equals(
                observation.snapshot.writerAuthority
            )) {
            throw new IllegalArgumentException(
                "stable observation lacks native writer authority"
            );
        }
        return observation;
    }

    private static boolean observationMatches(
        Observation observation,
        ActivationMachine.Token requested,
        int page,
        long exactLayoutGeneration,
        boolean writerEnabled,
        boolean allowNewLayout
    ) {
        if (observation == null || requested == null
            || observation.writerEnabled != writerEnabled
            || !sameTransactionIdentity(observation.snapshot, requested)
            || observation.snapshot.activePageIndex != page) {
            return false;
        }
        long layout = observation.snapshot.layoutGeneration;
        if (allowNewLayout) {
            if (layout <= requested.layoutGeneration) {
                return false;
            }
        } else if (exactLayoutGeneration >= 0L
            && layout != exactLayoutGeneration) {
            return false;
        }
        return !writerEnabled || observation.authority != null
            && observation.authority.matches(
                requested.documentId,
                requested.activityGeneration,
                layout,
                page
            );
    }

    private static boolean sameTransactionIdentity(
        SpreadSnapshot snapshot,
        ActivationMachine.Token requested
    ) {
        return snapshot != null && requested != null
            && requested.documentId.equals(snapshot.documentId)
            && requested.activityGeneration == snapshot.activityGeneration;
    }

    private void requireNewToken(ActivationMachine.Token requested) {
        if (requested == null || token != null) {
            throw new IllegalStateException("missing or overlapping transaction");
        }
    }

    private void requireCurrent(
        ActivationMachine.Token requested,
        Phase... allowed
    ) {
        requireAttached();
        if (requested == null || token != requested) {
            throw new IllegalStateException("stale firmware transaction token");
        }
        for (Phase candidate : allowed) {
            if (phase == candidate) {
                return;
            }
        }
        throw new IllegalStateException(
            "firmware transaction phase mismatch: " + phase
        );
    }

    private void requirePhase(Phase expected) {
        if (phase != expected) {
            throw new IllegalStateException(
                "firmware port expected " + expected + " but was " + phase
            );
        }
    }

    private void requireAttached() {
        if (controller == null) {
            throw new IllegalStateException(
                "firmware port has no controller"
            );
        }
    }

    private void clearTransaction() {
        token = null;
        sourceMarkRevision = -1L;
        targetAuthority = null;
        sourceSaveCompletionHandled = false;
        phase = Phase.IDLE;
    }

    private void assertOwnerThread() {
        if (Thread.currentThread().getId() != ownerThreadId) {
            throw new IllegalStateException(
                "firmware port callback was not marshalled to its owner thread"
            );
        }
    }
}
