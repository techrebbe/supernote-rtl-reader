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

    public interface Factory { Object create(); }
    public interface Registration { void release(); }

    public interface Port {
        void requireMainThread();
        long elapsedRealtimeMillis();
        boolean processAlive();
        boolean rootAlive();
        Object root();
        Snapshot snapshot();
        Object parentOf(Object child);
        void add(Object child, int provenSlot);
        void remove(Object child);
        void dispatch(Runnable callback);
        void schedule(Runnable callback, long delayMillis);
        void cancel(Runnable callback);
        // Registration must be atomic: a null/throw leaves no callbacks armed.
        Registration armLifecycle(Runnable onPause, Runnable onRootLoss,
                Runnable onPageOrLayoutDrift);
    }

    /**
     * Immutable captured evidence. Each canonical child string must cover its
     * class, ID, draw order, visibility, bounds, Z, and layout parameters; the
     * scene string must cover the available page/URI/render and root geometry.
     * Strings are compared only as restoration evidence, never removal authority.
     */
    public static final class Snapshot {
        private final Object root;
        private final Object[] children;
        private final Object[] parents;
        private final String[] childEvidence;
        private final String sceneEvidence;

        public Snapshot(Object root, Object[] children, Object[] parents,
                String[] childEvidence, String sceneEvidence) {
            if (root == null || children == null || parents == null || childEvidence == null
                    || sceneEvidence == null || children.length != parents.length
                    || children.length != childEvidence.length) {
                throw new IllegalArgumentException("incomplete hierarchy snapshot");
            }
            this.root = root;
            this.children = children.clone();
            this.parents = parents.clone();
            this.childEvidence = childEvidence.clone();
            this.sceneEvidence = sceneEvidence;
        }

        private boolean validNine(Object expectedRoot) {
            if (root != expectedRoot || children.length != 9) return false;
            IdentityHashMap<Object, Boolean> seen = new IdentityHashMap<Object, Boolean>();
            for (int i = 0; i < 9; i++) {
                if (children[i] == null || parents[i] != expectedRoot
                        || childEvidence[i] == null || seen.put(children[i], true) != null) {
                    return false;
                }
            }
            return true;
        }

        private boolean sameNine(Snapshot other) {
            if (other == null || root != other.root || children.length != 9
                    || other.children.length != 9
                    || !sceneEvidence.equals(other.sceneEvidence)) return false;
            for (int i = 0; i < 9; i++) {
                if (children[i] != other.children[i] || parents[i] != other.parents[i]
                        || !childEvidence[i].equals(other.childEvidence[i])) return false;
            }
            return true;
        }

        private boolean sameNinePlusOwned(Snapshot other, Object owned, int slot) {
            if (other == null || root != other.root || other.children.length != 10
                    || other.children[slot] != owned || other.parents[slot] != root
                    || other.childEvidence[slot] == null
                    || !sceneEvidence.equals(other.sceneEvidence)) return false;
            for (int i = 0; i < 9; i++) {
                int at = i < slot ? i : i + 1;
                if (children[i] != other.children[at] || parents[i] != other.parents[at]
                        || !childEvidence[i].equals(other.childEvidence[at])) return false;
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
    private final int insertSlot;
    private final long lifetimeMillis;
    private final long maxDeadlineLatenessMillis;
    private final long maxVerificationGapMillis;
    private final Runnable deadlineCallback = new Runnable() {
        @Override public void run() {
            port.requireMainThread();
            long now = port.elapsedRealtimeMillis();
            if (state == State.REMOVED || state == State.QUARANTINED) return;
            recordDeadlineLateness(now);
            long remaining = deadlineMillis - now;
            if (remaining > 0) port.schedule(this, remaining);
            else cleanup(Reason.DEADLINE);
        }
    };
    private final Runnable verifyCallback = new Runnable() {
        @Override public void run() { verifySecondSample(); }
    };
    private State state = State.PREPARED;
    private Result result = Result.PENDING;
    private Reason reason;
    private Throwable failure;
    private Object root;
    private Object owned;
    private String ownedEvidence;
    private Snapshot before;
    private Registration registration;
    private long deadlineMillis;
    private long firstSampleMillis = -1;
    private boolean adding;
    private boolean everInserted;
    private boolean deadlineLatenessExceeded;
    private Reason pendingDuringAdd;
    private volatile Reason lifecycleInvalidation;
    private volatile boolean lossRequested;
    private volatile boolean finalizing;
    private volatile boolean invalidatedWhileFinalizing;

    private TargetOwnedVisualLeaseCore(Slot slot, Port port, int insertSlot,
            long lifetimeMillis, long maxDeadlineLatenessMillis,
            long maxVerificationGapMillis) {
        this.slot = slot;
        this.port = port;
        this.insertSlot = insertSlot;
        this.lifetimeMillis = lifetimeMillis;
        this.maxDeadlineLatenessMillis = maxDeadlineLatenessMillis;
        this.maxVerificationGapMillis = maxVerificationGapMillis;
    }

    /**
     * The caller must supply pre-reviewed elapsed-realtime deadline-lateness
     * and two-sample verification-gap bounds. No Nomad/device bounds are
     * selected by this offline model.
     */
    public static TargetOwnedVisualLeaseCore start(Port port, Factory factory,
            int provenSlot, long lifetimeMillis, long maxDeadlineLatenessMillis,
            long maxVerificationGapMillis) {
        return startForTest(PROCESS_SLOT, port, factory, provenSlot,
                lifetimeMillis, maxDeadlineLatenessMillis, maxVerificationGapMillis);
    }

    // Isolated slots are available only to the same-package deterministic tests.
    static TargetOwnedVisualLeaseCore startForTest(Slot slot, Port port, Factory factory,
            int provenSlot, long lifetimeMillis, long maxDeadlineLatenessMillis,
            long maxVerificationGapMillis) {
        if (slot == null || port == null || factory == null || provenSlot < 0
                || provenSlot > 9 || lifetimeMillis <= 0
                || maxDeadlineLatenessMillis < 0 || maxVerificationGapMillis < 0) {
            throw new IllegalArgumentException("invalid lease arguments");
        }
        port.requireMainThread();
        TargetOwnedVisualLeaseCore lease = new TargetOwnedVisualLeaseCore(
                slot, port, provenSlot, lifetimeMillis, maxDeadlineLatenessMillis,
                maxVerificationGapMillis);
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
            root = port.root();
            before = port.snapshot();
            if (root == null || !before.validNine(root)) {
                quarantine(Reason.DRIFT, null);
                return;
            }
            long now = port.elapsedRealtimeMillis();
            if (now < 0 || now > Long.MAX_VALUE - lifetimeMillis) {
                quarantine(Reason.DRIFT, null);
                return;
            }
            deadlineMillis = now + lifetimeMillis;
            owned = factory.create(); // The process-local slot is already held.
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
            adding = true;
            try {
                port.add(owned, insertSlot);
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
            Snapshot insertedWitness = port.snapshot();
            if (!before.sameNinePlusOwned(insertedWitness, owned, insertSlot)) {
                cleanup(Reason.DRIFT);
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
            if (lifecycleInvalidation != null) {
                cleanup(lifecycleInvalidation);
                return;
            }
            ownedEvidence = insertedWitness.childEvidence[insertSlot];
            state = State.INSERTED;
            everInserted = true;
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
        if (!port.processAlive()) return Reason.PROCESS_LOSS;
        if (!port.rootAlive() || port.root() != root) return Reason.ROOT_LOSS;
        if (lifecycleInvalidation != null) return lifecycleInvalidation;
        if (!before.sameNine(port.snapshot())) return Reason.DRIFT;
        return port.elapsedRealtimeMillis() >= deadlineMillis ? Reason.DEADLINE : null;
    }

    public void requestCleanup(final Reason requested) {
        if (requested == null) throw new IllegalArgumentException("cleanup reason required");
        synchronized (this) {
            if (requested == Reason.ROOT_LOSS || requested == Reason.PROCESS_LOSS) {
                lossRequested = true;
            }
            if (requested == Reason.PAUSE || requested == Reason.ROOT_LOSS
                    || requested == Reason.PROCESS_LOSS || requested == Reason.DRIFT) {
                if (lifecycleInvalidation == null) lifecycleInvalidation = requested;
                if (finalizing) invalidatedWhileFinalizing = true;
            }
        }
        port.dispatch(new Runnable() {
            @Override public void run() { cleanup(requested); }
        });
    }

    /**
     * Call before painting any pixel. Observed drift suppresses this draw, but
     * stock synchronous pre-transition invalidation and stale composited pixels
     * are not proved by this check. The owned witness detects changes from its
     * inserted state; it does not validate the initial geometry envelope.
     */
    public boolean mayDraw() {
        port.requireMainThread();
        if (state != State.INSERTED) return false;
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
                    && before.sameNinePlusOwned(drawWitness, owned, insertSlot)
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
                if (lifecycleInvalidation == null) return true;
                requestCleanup(lifecycleInvalidation);
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
            } else if (parent != null || prior == State.INSERTED) {
                quarantine(requested, null);
                return;
            }
            if (!liveOriginalNine()) {
                quarantine(requested, null);
                return;
            }
            firstSampleMillis = port.elapsedRealtimeMillis();
            port.schedule(verifyCallback, 1); // A second main-loop sample after settling.
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
                        || verificationGapExceeded()) {
                    quarantine(reason, null);
                    return;
                }
                synchronized (this) {
                    if (finalizationUnsafe()) return;
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

    private void quarantine(Reason why, Throwable cause) {
        if (reason == null) reason = why;
        if (failure == null) failure = cause;
        state = State.QUARANTINED;
        result = Result.UNKNOWN;
        // Retain the slot for read-only diagnosis; never guess a repair.
    }

    public State state() { return state; }
    public Result result() { return result; }
    public Reason reason() { return reason; }
    public Throwable failure() { return failure; }
    public Object ownedChild() { return owned; }
    public boolean deadlineLatenessExceeded() { return deadlineLatenessExceeded; }
}
