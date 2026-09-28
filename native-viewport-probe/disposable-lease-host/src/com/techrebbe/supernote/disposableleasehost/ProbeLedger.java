package com.techrebbe.supernote.disposableleasehost;

/** One lock binds slot state and event bounds into a coherent evidence cut. */
public final class ProbeLedger {
    public static final class Snapshot {
        public final long firstRetainedSequence;
        public final long lastSequence;
        public final int eventCapacity;
        public final boolean slotOccupied;
        public final int slotOwnerIdentityHash;
        public final String slotOwnerClass;
        public final long slotClaimCount;
        public final EventRing.Event[] events;

        private Snapshot(EventRing ring, LeaseSlot slot, long after) {
            firstRetainedSequence = ring.firstRetainedSequence();
            lastSequence = ring.lastSequence();
            eventCapacity = ring.capacity();
            slotOccupied = slot.occupied();
            slotOwnerIdentityHash = slot.ownerIdentityHash();
            slotOwnerClass = slot.ownerClass();
            slotClaimCount = slot.claims();
            events = ring.after(after);
        }
    }

    private final EventRing ring;
    private final LeaseSlot slot = new LeaseSlot();

    public ProbeLedger(int eventCapacity) { ring = new EventRing(eventCapacity); }

    public synchronized EventRing.Event record(long elapsedMs, String name, String detail) {
        return ring.append(elapsedMs, name, detail);
    }

    public synchronized boolean claim(long elapsedMs, Object owner) {
        boolean result = slot.claim(owner);
        ring.append(elapsedMs, result ? "LEASE_SLOT_CLAIMED" : "LEASE_SLOT_COLLISION",
                "owner=" + System.identityHashCode(owner));
        return result;
    }

    public synchronized boolean release(long elapsedMs, Object owner) {
        boolean result = slot.release(owner);
        ring.append(elapsedMs, result ? "LEASE_SLOT_RELEASED" : "LEASE_SLOT_RELEASE_REJECTED",
                "owner=" + System.identityHashCode(owner));
        return result;
    }

    public synchronized Snapshot snapshot(long after) { return new Snapshot(ring, slot, after); }
}
