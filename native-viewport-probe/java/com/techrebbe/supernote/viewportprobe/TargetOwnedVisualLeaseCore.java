package com.techrebbe.supernote.viewportprobe;

import java.util.IdentityHashMap;

/**
 * Offline state model for one target-process visual child. This class does not
 * load code into Android, establish reader authority, or certify file integrity.
 * A future adapter must implement Port on the document process's main Looper.
 * The static slot is only unique within one class loader; cross-loader and
 * bootstrap ownership remain unproven. Scheduling is a wakeup, not a promise
 * that Android's uptime-based Handler fires at an elapsed-realtime deadline.
 */
public final class TargetOwnedVisualLeaseCore {
    public enum State { PREPARED, INSERTED, REMOVING, REMOVED, QUARANTINED }
    public enum Reason {
        HOST_STOP, DEADLINE, PAUSE, ROOT_LOSS, PROCESS_LOSS, DRIFT, INSERTION_FAILURE
    }
    public enum Result { PENDING, LIVE_STRUCTURE_RESTORED, UNKNOWN }

    /** Immutable capability handed to the owned child before it can attach. */
    public static final class DrawGate {
        private final TargetOwnedVisualLeaseCore lease;

        private DrawGate(TargetOwnedVisualLeaseCore lease) { this.lease = lease; }

        public boolean mayDraw() { return lease.mayDraw(); }
    }

    /** Must construct the child with this exact gate; no late binding. */
    public interface Factory { Object create(DrawGate drawGate); }
    public interface Registration { void release(); }

    public interface Port {
        // All evidence mutations are main-Looper-confined and synchronously
        // advance this monotonic revision before changing root/scene,
        // hierarchy, child metadata, or draw policy. Its read must be pure,
        // non-reentrant, and never reuse a value during a lease. Other Port
        // reads may reenter; the final revision read fences those effects.
        long evidenceMutationRevision();
        void requireMainThread();
        long elapsedRealtimeMillis();
        // A completed child-paint pass, not an onDraw/pre-draw entry or a
        // hierarchy inferred from child indices. Revisions increase when a
        // paint pass begins, and the frame snapshot is captured after it ends.
        long startedPaintRevision();
        PaintFrame lastCompletedPaintFrame();
        boolean processAlive();
        boolean rootAlive();
        Object root();
        Snapshot snapshot();
        Object parentOf(Object child);
        // Must reject a child not already bound to this exact gate identity.
        // The owned insertion is exactly one evidence mutation. This call
        // must not reenter unrelated scene/hierarchy changes; if it cannot
        // guarantee that, it must throw and leave cleanup to exact identity.
        void add(Object child, int provenSlot, DrawGate drawGate);
        void remove(Object child);
        void requestDraw(Object child);
        // Must throw if Handler.post returns false. A rejected cleanup wakeup
        // is an authority failure, not a successfully queued stop.
        void dispatch(Runnable callback);
        // Implementations must throw if Handler.post/postDelayed returns false.
        void schedule(Runnable callback, long delayMillis);
        void cancel(Runnable callback);
        // Registration must be atomic: a null/throw leaves no callbacks armed.
        Registration armLifecycle(Runnable onPause, Runnable onRootLoss,
                Runnable onPageOrLayoutDrift);
    }

    public static final class PaintFrame {
        public final long begunRevision;
        public final long completedElapsedRealtimeMillis;
        public final Snapshot snapshot;

        public PaintFrame(long begunRevision, long completedElapsedRealtimeMillis,
                Snapshot snapshot) {
            if (begunRevision <= 0 || completedElapsedRealtimeMillis < 0 || snapshot == null) {
                throw new IllegalArgumentException("incomplete completed paint frame");
            }
            this.begunRevision = begunRevision;
            this.completedElapsedRealtimeMillis = completedElapsedRealtimeMillis;
            this.snapshot = snapshot;
        }
    }

    /**
     * Immutable captured evidence. Children are in direct-root order; the
     * effective draw-order vector separately records exact bottom-to-top child
     * identities actually dispatched to drawChild. paintExpected is independently
     * derived from each child's visibility/draw policy, never from that vector;
     * a non-painted structural child must remain in children and parents. Each
     * child string covers stable class, ID, visibility,
     * bounds, Z, and layout parameters, but not an absolute draw rank (which
     * legitimately shifts when our child is inserted). Draw-policy evidence
     * covers the ordering mechanism; scene evidence covers available
     * page/URI/render and root geometry. A Port unable to establish effective
     * draw order must reject rather than guess from direct child order.
     * Strings are restoration evidence only, never removal authority.
     */
    public static final class Snapshot {
        private final Object root;
        private final Object[] children;
        private final Object[] parents;
        private final String[] childEvidence;
        private final boolean[] paintExpected;
        private final Object[] effectiveDrawOrder;
        private final String drawPolicyEvidence;
        private final String sceneEvidence;

        public Snapshot(Object root, Object[] children, Object[] parents,
                String[] childEvidence, Object[] effectiveDrawOrder,
                String drawPolicyEvidence, String sceneEvidence) {
            this(root, children, parents, childEvidence, allPaintExpected(children),
                    effectiveDrawOrder, drawPolicyEvidence, sceneEvidence);
            if (children.length != effectiveDrawOrder.length) {
                throw new IllegalArgumentException("all-visible paint order is incomplete");
            }
        }

        // The all-visible constructor above preserves the unwired emulator
        // Port's existing contract. A Port with a GONE/INVISIBLE child must
        // supply this independent expectation explicitly.
        public Snapshot(Object root, Object[] children, Object[] parents,
                String[] childEvidence, boolean[] paintExpected,
                Object[] effectiveDrawOrder, String drawPolicyEvidence,
                String sceneEvidence) {
            if (root == null || children == null || parents == null || childEvidence == null
                    || paintExpected == null || effectiveDrawOrder == null
                    || drawPolicyEvidence == null
                    || sceneEvidence == null || children.length != parents.length
                    || children.length != childEvidence.length
                    || children.length != paintExpected.length) {
                throw new IllegalArgumentException("incomplete hierarchy snapshot");
            }
            this.root = root;
            this.children = children.clone();
            this.parents = parents.clone();
            this.childEvidence = childEvidence.clone();
            this.paintExpected = paintExpected.clone();
            this.effectiveDrawOrder = effectiveDrawOrder.clone();
            this.drawPolicyEvidence = drawPolicyEvidence;
            this.sceneEvidence = sceneEvidence;
        }

        private static boolean[] allPaintExpected(Object[] children) {
            if (children == null) return null;
            boolean[] expected = new boolean[children.length];
            for (int i = 0; i < expected.length; i++) expected[i] = true;
            return expected;
        }

        private boolean validNine(Object expectedRoot) {
            if (root != expectedRoot || children.length != 9) return false;
            IdentityHashMap<Object, Boolean> expected = new IdentityHashMap<Object, Boolean>();
            IdentityHashMap<Object, Boolean> painted = new IdentityHashMap<Object, Boolean>();
            int expectedPaintCount = 0;
            for (int i = 0; i < 9; i++) {
                if (children[i] == null || parents[i] != expectedRoot
                        || childEvidence[i] == null
                        || expected.put(children[i], paintExpected[i]) != null) {
                    return false;
                }
                if (paintExpected[i]) expectedPaintCount++;
            }
            // The offline representation admits the existing nine-visible
            // host or one non-painted stock child, not arbitrary omissions.
            if (expectedPaintCount < 8 || effectiveDrawOrder.length != expectedPaintCount) {
                return false;
            }
            for (Object child : effectiveDrawOrder) {
                if (expected.get(child) != Boolean.TRUE
                        || painted.put(child, true) != null) return false;
            }
            return true;
        }

        private boolean sameNine(Snapshot other) {
            if (other == null || root != other.root || children.length != 9
                    || other.children.length != 9
                    || other.effectiveDrawOrder.length != effectiveDrawOrder.length
                    || !drawPolicyEvidence.equals(other.drawPolicyEvidence)
                    || !sceneEvidence.equals(other.sceneEvidence)) return false;
            for (int i = 0; i < 9; i++) {
                if (children[i] != other.children[i] || parents[i] != other.parents[i]
                        || paintExpected[i] != other.paintExpected[i]
                        || !childEvidence[i].equals(other.childEvidence[i])) return false;
            }
            for (int i = 0; i < effectiveDrawOrder.length; i++) {
                if (effectiveDrawOrder[i] != other.effectiveDrawOrder[i]) return false;
            }
            return true;
        }

        private boolean sameNinePlusOwned(Snapshot other, Object owned,
                int directSlot, int paintSlot) {
            if (other == null || root != other.root || other.children.length != 10
                    || other.effectiveDrawOrder.length != effectiveDrawOrder.length + 1
                    || paintSlot > effectiveDrawOrder.length
                    || other.children[directSlot] != owned
                    || other.effectiveDrawOrder[paintSlot] != owned
                    || other.parents[directSlot] != root
                    || !other.paintExpected[directSlot]
                    || other.childEvidence[directSlot] == null
                    || !drawPolicyEvidence.equals(other.drawPolicyEvidence)
                    || !sceneEvidence.equals(other.sceneEvidence)) return false;
            for (int i = 0; i < 9; i++) {
                int directAt = i < directSlot ? i : i + 1;
                if (children[i] != other.children[directAt]
                        || parents[i] != other.parents[directAt]
                        || paintExpected[i] != other.paintExpected[directAt]
                        || !childEvidence[i].equals(other.childEvidence[directAt])) return false;
            }
            for (int i = 0; i < effectiveDrawOrder.length; i++) {
                int paintAt = i < paintSlot ? i : i + 1;
                if (effectiveDrawOrder[i] != other.effectiveDrawOrder[paintAt]) return false;
            }
            return true;
        }
    }

    /** A quarantined lease deliberately keeps its slot; it cannot admit a retry. */
    static final class Slot {
        private TargetOwnedVisualLeaseCore holder;

        private synchronized boolean acquire(TargetOwnedVisualLeaseCore lease) {
            if (holder != null) return false;
            holder = lease;
            return true;
        }

        private synchronized void release(TargetOwnedVisualLeaseCore lease) {
            if (holder != lease) throw new IllegalStateException("lease slot changed");
            holder = null;
        }

        synchronized boolean occupied() { return holder != null; }
    }

    /** One slot per process/class loader, not a cross-loader rollback owner. */
    private static final Slot PROCESS_SLOT = new Slot();

    private final Slot slot;
    private final Port port;
    private final DrawGate drawGate;
    private final int insertSlot;
    private final int paintSlot;
    private final long lifetimeMillis;
    private final long maxDeadlineLatenessMillis;
    private final long maxVerificationGapMillis;
    private final long maxPaintWaitMillis;
    private final Runnable deadlineCallback = new Runnable() {
        @Override public void run() {
            port.requireMainThread();
            long now = port.elapsedRealtimeMillis();
            if (state == State.REMOVED || state == State.QUARANTINED) return;
            recordDeadlineLateness(now);
            long remaining = deadlineMillis - now;
            if (remaining > 0) {
                try { port.schedule(this, remaining); }
                catch (Throwable schedulingFailure) {
                    failure = schedulingFailure;
                    cleanup(Reason.INSERTION_FAILURE);
                }
            }
            else cleanup(Reason.DEADLINE);
        }
    };
    private final Runnable verifyCallback = new Runnable() {
        @Override public void run() { verifySecondSample(); }
    };
    private final Runnable paintPollCallback = new Runnable() {
        @Override public void run() { inspectPaintWait(); }
    };
    private volatile State state = State.PREPARED;
    private volatile Result result = Result.PENDING;
    private Reason reason;
    private Throwable failure;
    private Object root;
    private Object owned;
    private String ownedEvidence;
    private Snapshot before;
    private long baselineEvidenceRevision = -1;
    private long postAddEvidenceRevision = -1;
    private long admissionEvidenceRevision = -1;
    private Registration registration;
    private long deadlineMillis;
    private long firstSampleMillis = -1;
    private long paintFenceRevision = -1;
    private long paintWaitStartedMillis = -1;
    private PaintFrame restorationProofFrame;
    private long restorationEvidenceRevision = -1;
    private boolean removalPaintRequired;
    private boolean waitingAdmission;
    private boolean waitingRestorationFrame;
    private boolean adding;
    private boolean everInserted;
    private boolean deadlineLatenessExceeded;
    private Reason pendingDuringAdd;
    private volatile Reason pendingCleanupRequest;
    private volatile boolean dispatchFailed;
    private volatile Reason lifecycleInvalidation;
    private volatile boolean lossRequested;
    private volatile boolean finalizing;
    private volatile boolean invalidatedWhileFinalizing;

    private TargetOwnedVisualLeaseCore(Slot slot, Port port, int insertSlot, int paintSlot,
            long lifetimeMillis, long maxDeadlineLatenessMillis,
            long maxVerificationGapMillis, long maxPaintWaitMillis) {
        this.slot = slot;
        this.port = port;
        this.drawGate = new DrawGate(this);
        this.insertSlot = insertSlot;
        this.paintSlot = paintSlot;
        this.lifetimeMillis = lifetimeMillis;
        this.maxDeadlineLatenessMillis = maxDeadlineLatenessMillis;
        this.maxVerificationGapMillis = maxVerificationGapMillis;
        this.maxPaintWaitMillis = maxPaintWaitMillis;
    }

    /**
     * The caller must supply pre-reviewed elapsed-realtime deadline-lateness,
     * two-sample verification-gap, and completed-paint wait/freshness bounds.
     * No Nomad/device bounds are selected by this offline model.
     */
    public static TargetOwnedVisualLeaseCore start(Port port, Factory factory,
            int provenDirectSlot, int provenPaintSlot, long lifetimeMillis,
            long maxDeadlineLatenessMillis,
            long maxVerificationGapMillis, long maxPaintWaitMillis) {
        return startForTest(PROCESS_SLOT, port, factory, provenDirectSlot, provenPaintSlot,
                lifetimeMillis, maxDeadlineLatenessMillis, maxVerificationGapMillis,
                maxPaintWaitMillis);
    }

    // Isolated slots are available only to the same-package deterministic tests.
    static TargetOwnedVisualLeaseCore startForTest(Slot slot, Port port, Factory factory,
            int provenDirectSlot, int provenPaintSlot, long lifetimeMillis,
            long maxDeadlineLatenessMillis,
            long maxVerificationGapMillis, long maxPaintWaitMillis) {
        if (slot == null || port == null || factory == null || provenDirectSlot < 0
                || provenDirectSlot > 9 || provenPaintSlot < 0 || provenPaintSlot > 9
                || lifetimeMillis <= 0
                || maxDeadlineLatenessMillis < 0 || maxVerificationGapMillis < 0
                || maxPaintWaitMillis <= 0) {
            throw new IllegalArgumentException("invalid lease arguments");
        }
        port.requireMainThread();
        TargetOwnedVisualLeaseCore lease = new TargetOwnedVisualLeaseCore(
                slot, port, provenDirectSlot, provenPaintSlot,
                lifetimeMillis, maxDeadlineLatenessMillis,
                maxVerificationGapMillis, maxPaintWaitMillis);
        if (!slot.acquire(lease)) throw new IllegalStateException("trial already active");
        lease.prepareAndInsert(factory);
        return lease;
    }

    private void prepareAndInsert(Factory factory) {
        try {
            if (!port.processAlive()) {
                quarantine(Reason.PROCESS_LOSS, null);
                return;
            }
            if (!port.rootAlive()) {
                quarantine(Reason.ROOT_LOSS, null);
                return;
            }
            baselineEvidenceRevision = port.evidenceMutationRevision();
            if (baselineEvidenceRevision < 0) {
                quarantine(Reason.DRIFT, null);
                return;
            }
            root = port.root();
            before = port.snapshot();
            if (root == null || !before.validNine(root)
                    || paintSlot > before.effectiveDrawOrder.length
                    || port.evidenceMutationRevision() != baselineEvidenceRevision) {
                quarantine(Reason.DRIFT, null);
                return;
            }
            long now = port.elapsedRealtimeMillis();
            if (now < 0 || now > Long.MAX_VALUE - lifetimeMillis) {
                quarantine(Reason.DRIFT, null);
                return;
            }
            deadlineMillis = now + lifetimeMillis;
            // The process-local slot is already held. The child receives its
            // final gate in construction, before add or any paint callback.
            owned = factory.create(drawGate);
            if (owned == null) {
                cleanup(Reason.INSERTION_FAILURE);
                return;
            }
            for (Object stock : before.children) {
                if (stock == owned) {
                    quarantine(Reason.INSERTION_FAILURE, null);
                    return;
                }
            }
            if (port.parentOf(owned) != null) {
                // A factory must not lend a child from any other hierarchy.
                quarantine(Reason.INSERTION_FAILURE, null);
                return;
            }
            registration = port.armLifecycle(
                    lifecycleCallback(Reason.PAUSE), lifecycleCallback(Reason.ROOT_LOSS),
                    lifecycleCallback(Reason.DRIFT));
            if (registration == null) {
                cleanup(Reason.INSERTION_FAILURE);
                return;
            }
            long remaining = deadlineMillis - port.elapsedRealtimeMillis();
            if (remaining <= 0) {
                cleanup(Reason.DEADLINE);
                return;
            }
            port.schedule(deadlineCallback, remaining);
            if (state != State.PREPARED) return;
            Reason preAdd = preInsertionBlock();
            if (preAdd != null) {
                cleanup(preAdd);
                return;
            }
            if (state != State.PREPARED) return; // A Port read may reenter stop.
            if (pendingCleanupRequest != null) {
                cleanup(pendingCleanupRequest);
                return;
            }
            adding = true;
            try {
                port.add(owned, insertSlot, drawGate);
                // Pin before any further Port read can reenter and mutate the
                // scene; an ABA before the paint poll must never be adopted.
                postAddEvidenceRevision = port.evidenceMutationRevision();
            } catch (Throwable addFailure) {
                failure = addFailure;
                pendingDuringAdd = Reason.INSERTION_FAILURE;
            } finally {
                adding = false;
            }
            if (pendingDuringAdd != null) {
                cleanup(pendingDuringAdd);
                return;
            }
            if (baselineEvidenceRevision == Long.MAX_VALUE
                    || postAddEvidenceRevision != baselineEvidenceRevision + 1) {
                cleanup(Reason.DRIFT);
                return;
            }
            if (pendingCleanupRequest != null) {
                cleanup(pendingCleanupRequest);
                return;
            }
            if (lifecycleInvalidation != null) {
                cleanup(lifecycleInvalidation);
                return;
            }
            if (!port.processAlive()) {
                cleanup(Reason.PROCESS_LOSS);
                return;
            }
            if (!port.rootAlive() || port.root() != root) {
                cleanup(Reason.ROOT_LOSS);
                return;
            }
            if (port.elapsedRealtimeMillis() >= deadlineMillis) {
                cleanup(Reason.DEADLINE);
                return;
            }
            if (port.parentOf(owned) != root) {
                quarantine(Reason.INSERTION_FAILURE, null);
                return;
            }
            if (port.evidenceMutationRevision() != postAddEvidenceRevision) {
                cleanup(Reason.DRIFT);
                return;
            }
            // A hierarchy read here cannot establish what was painted. A
            // frame begun during add is also stale: require a later completed
            // pass whose begin revision is beyond this post-add fence.
            paintFenceRevision = port.startedPaintRevision();
            paintWaitStartedMillis = port.elapsedRealtimeMillis();
            if (paintFenceRevision < 1 || paintWaitStartedMillis >= deadlineMillis) {
                cleanup(Reason.DEADLINE);
                return;
            }
            if (port.evidenceMutationRevision() != postAddEvidenceRevision) {
                cleanup(Reason.DRIFT);
                return;
            }
            waitingAdmission = true;
            port.schedule(paintPollCallback, 1);
        } catch (Throwable unexpected) {
            failure = unexpected;
            if (before != null) cleanup(Reason.INSERTION_FAILURE);
            else quarantine(Reason.INSERTION_FAILURE, unexpected);
        }
    }

    private Runnable lifecycleCallback(final Reason invalidation) {
        return new Runnable() {
            @Override public void run() { requestCleanup(invalidation); }
        };
    }

    private Reason preInsertionBlock() {
        long evidenceAtStart = port.evidenceMutationRevision();
        if (evidenceAtStart < 0 || evidenceAtStart != baselineEvidenceRevision) {
            return Reason.DRIFT;
        }
        if (pendingCleanupRequest != null) return pendingCleanupRequest;
        if (!port.processAlive()) return Reason.PROCESS_LOSS;
        if (!port.rootAlive() || port.root() != root) return Reason.ROOT_LOSS;
        if (lifecycleInvalidation != null) return lifecycleInvalidation;
        if (!before.sameNine(port.snapshot())) return Reason.DRIFT;
        long now = port.elapsedRealtimeMillis();
        if (now >= deadlineMillis) return Reason.DEADLINE;
        PaintFrame frame = port.lastCompletedPaintFrame();
        long started = port.startedPaintRevision();
        PaintFrame confirmedFrame = port.lastCompletedPaintFrame();
        long confirmedStarted = port.startedPaintRevision();
        // Paint reads can consume time or observe a superseding pass. Judge
        // freshness and revision only from a clock sampled after all reads.
        long confirmedNow = port.elapsedRealtimeMillis();
        if (confirmedNow >= deadlineMillis) return Reason.DEADLINE;
        if (frame == null || frame != confirmedFrame
                || started != frame.begunRevision
                || confirmedStarted != frame.begunRevision
                || frame.completedElapsedRealtimeMillis > confirmedNow
                || confirmedNow - frame.completedElapsedRealtimeMillis > maxPaintWaitMillis
                || !before.sameNine(frame.snapshot)) return Reason.DRIFT;
        if (port.evidenceMutationRevision() != evidenceAtStart) return Reason.DRIFT;
        if (pendingCleanupRequest != null) return pendingCleanupRequest;
        return null;
    }

    private void inspectPaintWait() {
        port.requireMainThread();
        if (!waitingAdmission && !waitingRestorationFrame) return;
        try {
            if (waitingAdmission && state == State.PREPARED) {
                inspectAdmissionFrame();
            } else if (waitingRestorationFrame && state == State.REMOVING) {
                inspectRestorationFrame();
            }
        } catch (Throwable paintFailure) {
            if (failure == null) failure = paintFailure;
            if (state == State.PREPARED) cleanup(Reason.INSERTION_FAILURE);
            else if (state == State.REMOVING) quarantine(reason, paintFailure);
        }
    }

    private boolean paintWaitExpired(long now) {
        return paintWaitStartedMillis < 0 || now < paintWaitStartedMillis
                || now - paintWaitStartedMillis >= maxPaintWaitMillis;
    }

    private void inspectAdmissionFrame() {
        long evidenceAtStart = port.evidenceMutationRevision();
        if (evidenceAtStart != postAddEvidenceRevision) {
            cleanup(Reason.DRIFT);
            return;
        }
        if (pendingCleanupRequest != null) { cleanup(pendingCleanupRequest); return; }
        if (!port.processAlive()) { cleanup(Reason.PROCESS_LOSS); return; }
        if (!port.rootAlive() || port.root() != root) { cleanup(Reason.ROOT_LOSS); return; }
        if (lifecycleInvalidation != null) { cleanup(lifecycleInvalidation); return; }
        long now = port.elapsedRealtimeMillis();
        if (now >= deadlineMillis) { cleanup(Reason.DEADLINE); return; }
        if (paintWaitExpired(now)) { cleanup(Reason.DRIFT); return; }
        PaintFrame frame = port.lastCompletedPaintFrame();
        if (frame != null && frame.begunRevision > paintFenceRevision) {
            Snapshot current = port.snapshot();
            if (frame.completedElapsedRealtimeMillis < paintWaitStartedMillis
                    || frame.completedElapsedRealtimeMillis > now
                    || frame.begunRevision != port.startedPaintRevision()
                    || port.parentOf(owned) != root
                    || !before.sameNinePlusOwned(frame.snapshot, owned,
                            insertSlot, paintSlot)
                    || !before.sameNinePlusOwned(current, owned,
                            insertSlot, paintSlot)
                    || !frame.snapshot.childEvidence[insertSlot].equals(
                            current.childEvidence[insertSlot])) {
                cleanup(Reason.DRIFT);
                return;
            }
            if (!port.processAlive()) { cleanup(Reason.PROCESS_LOSS); return; }
            if (!port.rootAlive() || port.root() != root) { cleanup(Reason.ROOT_LOSS); return; }
            if (lifecycleInvalidation != null) { cleanup(lifecycleInvalidation); return; }
            if (pendingCleanupRequest != null) { cleanup(pendingCleanupRequest); return; }
            long confirmedNow = port.elapsedRealtimeMillis();
            if (confirmedNow >= deadlineMillis) {
                cleanup(Reason.DEADLINE);
                return;
            }
            if (paintWaitExpired(confirmedNow)) { cleanup(Reason.DRIFT); return; }
            if (port.evidenceMutationRevision() != evidenceAtStart) {
                cleanup(Reason.DRIFT);
                return;
            }
            synchronized (this) {
                if (state != State.PREPARED || !waitingAdmission) return;
                if (pendingCleanupRequest != null) {
                    cleanup(pendingCleanupRequest);
                    return;
                }
                ownedEvidence = frame.snapshot.childEvidence[insertSlot];
                admissionEvidenceRevision = evidenceAtStart;
                waitingAdmission = false;
                state = State.INSERTED;
                everInserted = true;
            }
            try {
                if (pendingCleanupRequest != null) {
                    cleanup(pendingCleanupRequest);
                    return;
                }
                port.requestDraw(owned); // The admission frame painted no owned pixels.
            } catch (Throwable drawRequestFailure) {
                failure = drawRequestFailure;
                cleanup(Reason.INSERTION_FAILURE);
            }
            return;
        }
        port.schedule(paintPollCallback, 1);
    }

    private void inspectRestorationFrame() {
        long evidenceAtStart = port.evidenceMutationRevision();
        if (evidenceAtStart < 0) { quarantine(reason, null); return; }
        if (lossRequested || !port.processAlive() || !port.rootAlive()
                || port.root() != root) {
            removeFromLostRootIfOwned();
            quarantine(reason, null);
            return;
        }
        long now = port.elapsedRealtimeMillis();
        if (paintWaitExpired(now)) { quarantine(reason, null); return; }
        PaintFrame frame = port.lastCompletedPaintFrame();
        if (frame != null && frame.begunRevision > paintFenceRevision) {
            if (frame.completedElapsedRealtimeMillis < paintWaitStartedMillis
                    || frame.completedElapsedRealtimeMillis > now
                    || frame.begunRevision != port.startedPaintRevision()
                    || !before.sameNine(frame.snapshot) || !liveOriginalNine()) {
                quarantine(reason, null);
                return;
            }
            if (port.lastCompletedPaintFrame() != frame
                    || port.startedPaintRevision() != frame.begunRevision) {
                quarantine(reason, null);
                return;
            }
            long confirmedNow = port.elapsedRealtimeMillis();
            if (paintWaitExpired(confirmedNow)
                    || port.evidenceMutationRevision() != evidenceAtStart) {
                quarantine(reason, null);
                return;
            }
            if (state != State.REMOVING || !waitingRestorationFrame) return;
            waitingRestorationFrame = false;
            restorationProofFrame = frame;
            restorationEvidenceRevision = evidenceAtStart;
            firstSampleMillis = confirmedNow;
            port.schedule(verifyCallback, 1);
            return;
        }
        port.schedule(paintPollCallback, 1);
    }

    public void requestCleanup(final Reason requested) {
        if (requested == null) throw new IllegalArgumentException("cleanup reason required");
        synchronized (this) {
            if (state == State.REMOVED || state == State.QUARANTINED) return;
            if (pendingCleanupRequest == null) pendingCleanupRequest = requested;
            if (requested == Reason.ROOT_LOSS || requested == Reason.PROCESS_LOSS) {
                lossRequested = true;
            }
            if (requested == Reason.PAUSE || requested == Reason.ROOT_LOSS
                    || requested == Reason.PROCESS_LOSS || requested == Reason.DRIFT) {
                if (lifecycleInvalidation == null) lifecycleInvalidation = requested;
                if (finalizing) invalidatedWhileFinalizing = true;
            }
        }
        try {
            port.dispatch(new Runnable() {
                @Override public void run() { cleanup(requested); }
            });
        } catch (Throwable rejectedDispatch) {
            synchronized (this) {
                // A redundant request whose proof already committed does not
                // retroactively invalidate that terminal result. Otherwise
                // publish failure under the same lock as terminal commit.
                if (state == State.REMOVED) return;
                if (failure == null) failure = rejectedDispatch;
                dispatchFailed = true;
            }
            // Only the main Looper may mutate the hierarchy. If dispatch was
            // rejected off-main, expose UNKNOWN/quarantine and retain the slot;
            // a later main-thread callback may still remove the exact child.
            try {
                port.requireMainThread();
                cleanup(requested);
            } catch (Throwable notOnMainOrCleanupFailed) {
                if (failure == null) failure = notOnMainOrCleanupFailed;
            }
        }
    }

    /**
     * Call before painting any pixel. Observed drift suppresses this draw, but
     * stock synchronous pre-transition invalidation and stale composited pixels
     * are not proved by this check. The owned witness detects changes from its
     * inserted state; it does not validate the initial geometry envelope.
     */
    public boolean mayDraw() {
        port.requireMainThread();
        if (pendingCleanupRequest != null || dispatchFailed) return false;
        if (state == State.PREPARED && waitingAdmission) {
            long pendingNow = port.elapsedRealtimeMillis();
            if (pendingNow >= deadlineMillis) requestCleanup(Reason.DEADLINE);
            else if (paintWaitExpired(pendingNow)) requestCleanup(Reason.DRIFT);
            return false;
        }
        if (state != State.INSERTED) return false;
        long evidenceAtStart = port.evidenceMutationRevision();
        if (evidenceAtStart < 0 || evidenceAtStart != admissionEvidenceRevision) {
            requestCleanup(Reason.DRIFT);
            return false;
        }
        long now = port.elapsedRealtimeMillis();
        if (now >= deadlineMillis) {
            recordDeadlineLateness(now);
            requestCleanup(Reason.DEADLINE);
            return false;
        }
        if (!port.processAlive()) {
            requestCleanup(Reason.PROCESS_LOSS);
            return false;
        }
        if (!port.rootAlive() || port.root() != root) {
            requestCleanup(Reason.ROOT_LOSS);
            return false;
        }
        if (lifecycleInvalidation != null) {
            requestCleanup(lifecycleInvalidation);
            return false;
        }
        try {
            Snapshot drawWitness = port.snapshot();
            if (port.parentOf(owned) == root && ownedEvidence != null
                    && before.sameNinePlusOwned(drawWitness, owned, insertSlot, paintSlot)
                    && ownedEvidence.equals(drawWitness.childEvidence[insertSlot])) {
                if (!port.processAlive()) {
                    requestCleanup(Reason.PROCESS_LOSS);
                    return false;
                }
                if (!port.rootAlive() || port.root() != root) {
                    requestCleanup(Reason.ROOT_LOSS);
                    return false;
                }
                now = port.elapsedRealtimeMillis();
                if (now >= deadlineMillis) {
                    recordDeadlineLateness(now);
                    requestCleanup(Reason.DEADLINE);
                    return false;
                }
                if (lifecycleInvalidation == null && pendingCleanupRequest == null
                        && !dispatchFailed) {
                    if (port.evidenceMutationRevision() == evidenceAtStart) return true;
                    requestCleanup(Reason.DRIFT);
                    return false;
                }
                Reason signaled = lifecycleInvalidation != null
                        ? lifecycleInvalidation : pendingCleanupRequest;
                if (signaled != null) requestCleanup(signaled);
                return false;
            }
        } catch (Throwable drawWitnessFailure) {
            failure = drawWitnessFailure;
        }
        requestCleanup(Reason.DRIFT);
        return false;
    }

    private void cleanup(Reason requested) {
        port.requireMainThread();
        if (state == State.REMOVED || state == State.QUARANTINED) return;
        if (state == State.REMOVING) {
            if (requested == Reason.ROOT_LOSS || requested == Reason.PROCESS_LOSS) {
                removeFromLostRootIfOwned();
                quarantine(requested, null);
            }
            return;
        }
        if (adding) {
            if (pendingDuringAdd == null) pendingDuringAdd = requested;
            return;
        }
        reason = requested;
        waitingAdmission = false;
        try {
            if (!port.processAlive()) {
                quarantine(requested, null);
                return;
            }
            if (!port.rootAlive() || port.root() != root) {
                removeFromLostRootIfOwned();
                quarantine(requested, null);
                return;
            }
            State prior = state;
            if (prior == State.INSERTED) recordDeadlineLateness(port.elapsedRealtimeMillis());
            state = State.REMOVING;
            Object parent = owned == null ? null : port.parentOf(owned);
            boolean removedAttachedChild = false;
            if (parent == root) {
                // An add may have attached before INSERTED was recorded.
                if (pastLatenessBound(port.elapsedRealtimeMillis())) {
                    deadlineLatenessExceeded = true;
                }
                port.remove(owned); // Exact owned object only; never index, tag, or equals.
                if (pastLatenessBound(port.elapsedRealtimeMillis())) {
                    deadlineLatenessExceeded = true;
                }
                if (port.parentOf(owned) != null) {
                    quarantine(requested, null);
                    return;
                }
                removedAttachedChild = true;
            } else if (parent != null || prior == State.INSERTED) {
                quarantine(requested, null);
                return;
            }
            long evidenceAfterRemoval = port.evidenceMutationRevision();
            if (evidenceAfterRemoval < 0 || !liveOriginalNine()
                    || port.evidenceMutationRevision() != evidenceAfterRemoval) {
                quarantine(requested, null);
                return;
            }
            if (removedAttachedChild) {
                // A frame begun before remove may finish afterward and still
                // depict the ten-child scene. Require a later nine-child pass.
                paintFenceRevision = port.startedPaintRevision();
                paintWaitStartedMillis = port.elapsedRealtimeMillis();
                removalPaintRequired = true;
                waitingRestorationFrame = true;
                port.schedule(paintPollCallback, 1);
            } else {
                restorationEvidenceRevision = evidenceAfterRemoval;
                firstSampleMillis = port.elapsedRealtimeMillis();
                port.schedule(verifyCallback, 1);
            }
        } catch (Throwable cleanupFailure) {
            quarantine(requested, cleanupFailure);
        }
    }

    private void removeFromLostRootIfOwned() {
        try {
            // The original root may still own this exact child after detach.
            // Never use the new/current root or a positional substitute.
            if (port.processAlive() && owned != null && root != null
                    && port.parentOf(owned) == root) port.remove(owned);
        } catch (Throwable removalFailure) {
            if (failure == null) failure = removalFailure;
            // The caller quarantines; there is no speculative second removal.
        }
    }

    private boolean liveOriginalNine() {
        return port.processAlive() && port.rootAlive() && port.root() == root
                && (owned == null || port.parentOf(owned) == null)
                && before != null && before.sameNine(port.snapshot());
    }

    private boolean pastLatenessBound(long now) {
        return now >= deadlineMillis
                && now - deadlineMillis > maxDeadlineLatenessMillis;
    }

    private void recordDeadlineLateness(long now) {
        if (state == State.INSERTED && pastLatenessBound(now)) {
            deadlineLatenessExceeded = true;
        }
    }

    private void verifySecondSample() {
        port.requireMainThread();
        if (state != State.REMOVING) return;
        try {
            if (restorationEvidenceRevision < 0
                    || port.evidenceMutationRevision() != restorationEvidenceRevision) {
                quarantine(reason, null);
                return;
            }
            if (lossRequested) {
                removeFromLostRootIfOwned();
                quarantine(reason, null);
                return;
            }
            if (verificationGapExceeded()) {
                quarantine(reason, null);
                return;
            }
            if (!liveOriginalNine()) {
                quarantine(reason, null);
                return;
            }
            if (!restorationPaintStillCurrent()) {
                quarantine(reason, null);
                return;
            }
            if (verificationGapExceeded()) {
                quarantine(reason, null);
                return;
            }
            if (deadlineLatenessExceeded) {
                quarantine(reason, null);
                return;
            }
            finalizing = true;
            try {
                port.cancel(deadlineCallback);
                if (finalizationUnsafe()) return;
                if (registration != null) registration.release();
                if (finalizationUnsafe()) return;
                // Callback teardown may itself trigger a hierarchy transition.
                if (verificationGapExceeded() || !liveOriginalNine()
                        || !restorationPaintStillCurrent()
                        || verificationGapExceeded()) {
                    quarantine(reason, null);
                    return;
                }
                synchronized (this) {
                    if (finalizationUnsafe()) return;
                    // A paint-proof Port read can reenter scene/hierarchy
                    // invalidation without beginning another paint. Finish
                    // the commit witness with a fresh live-nine read.
                    if (verificationGapExceeded() || !restorationPaintStillCurrent()
                            || !liveOriginalNine() || verificationGapExceeded()
                            || port.evidenceMutationRevision()
                                    != restorationEvidenceRevision) {
                        quarantine(reason, null);
                        return;
                    }
                    // The last Port read may reenter requestCleanup. Recheck
                    // its published signal under the same terminal-commit lock.
                    if (state != State.REMOVING) return;
                    if (lossRequested || invalidatedWhileFinalizing) {
                        removeFromLostRootIfOwned();
                        quarantine(reason, null);
                        return;
                    }
                    state = State.REMOVED;
                    result = (everInserted && failure == null && lifecycleInvalidation == null
                            && (reason == Reason.HOST_STOP || reason == Reason.DEADLINE))
                            ? Result.LIVE_STRUCTURE_RESTORED : Result.UNKNOWN;
                    slot.release(this);
                }
            } finally {
                finalizing = false;
            }
        } catch (Throwable verificationFailure) {
            quarantine(reason, verificationFailure);
        }
    }

    private boolean finalizationUnsafe() {
        if (state != State.REMOVING) return true;
        if (dispatchFailed) {
            quarantine(reason, null);
            return true;
        }
        if (lossRequested || !port.processAlive() || !port.rootAlive()
                || port.root() != root) {
            removeFromLostRootIfOwned();
            quarantine(reason, null);
            return true;
        }
        if (invalidatedWhileFinalizing) {
            quarantine(reason, null);
            return true;
        }
        return false;
    }

    private boolean verificationGapExceeded() {
        long now = port.elapsedRealtimeMillis();
        return firstSampleMillis < 0 || now < firstSampleMillis
                || now - firstSampleMillis > maxVerificationGapMillis;
    }

    private boolean restorationPaintStillCurrent() {
        if (!removalPaintRequired) return !everInserted;
        PaintFrame accepted = restorationProofFrame;
        if (accepted == null || !before.sameNine(accepted.snapshot)) return false;
        PaintFrame latest = port.lastCompletedPaintFrame();
        long started = port.startedPaintRevision();
        PaintFrame confirmedLatest = port.lastCompletedPaintFrame();
        long confirmedStarted = port.startedPaintRevision();
        long now = port.elapsedRealtimeMillis();
        return latest == accepted && confirmedLatest == accepted
                && started == accepted.begunRevision
                && confirmedStarted == accepted.begunRevision
                && accepted.completedElapsedRealtimeMillis >= paintWaitStartedMillis
                && accepted.completedElapsedRealtimeMillis <= now
                && now - accepted.completedElapsedRealtimeMillis < maxPaintWaitMillis;
    }

    private void quarantine(Reason why, Throwable cause) {
        if (reason == null) reason = why;
        if (failure == null) failure = cause;
        state = State.QUARANTINED;
        result = Result.UNKNOWN;
        waitingAdmission = false;
        waitingRestorationFrame = false;
        // Retain the slot for read-only diagnosis; never guess a repair.
    }

    public State state() { return dispatchFailed ? State.QUARANTINED : state; }
    public Result result() { return dispatchFailed ? Result.UNKNOWN : result; }
    public Reason reason() { return reason; }
    public Throwable failure() { return failure; }
    public Object ownedChild() { return owned; }
    public boolean deadlineLatenessExceeded() { return deadlineLatenessExceeded; }
}
