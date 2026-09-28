package com.techrebbe.supernote.disposableleasehost;

/** App-primary-loader strong root for one test lease; it does not clean up views. */
public final class LeaseSlot {
    private Object owner;
    private long claims;

    public synchronized boolean claim(Object candidate) {
        if (candidate == null) throw new IllegalArgumentException("null owner");
        if (owner != null) return false;
        owner = candidate;
        claims++;
        return true;
    }

    public synchronized boolean release(Object candidate) {
        if (candidate == null || owner != candidate) return false;
        owner = null;
        return true;
    }

    public synchronized boolean occupied() { return owner != null; }
    public synchronized long claims() { return claims; }
    public synchronized int ownerIdentityHash() {
        return owner == null ? 0 : System.identityHashCode(owner);
    }
    public synchronized String ownerClass() {
        return owner == null ? "" : owner.getClass().getName();
    }
}
