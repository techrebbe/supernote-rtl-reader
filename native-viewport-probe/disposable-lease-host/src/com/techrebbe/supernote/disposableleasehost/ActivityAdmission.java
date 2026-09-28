package com.techrebbe.supernote.disposableleasehost;

/** Strong, exact-reference gate for one live activity and its original root. */
public final class ActivityAdmission {
    private Object activity;
    private Object root;
    private long serial;
    private long collisions;

    public synchronized long claim(Object candidate, Object candidateRoot) {
        if (candidate == null || candidateRoot == null) {
            throw new IllegalArgumentException("activity and root required");
        }
        if (activity != null) {
            collisions++;
            return -1;
        }
        activity = candidate;
        root = candidateRoot;
        serial++;
        return serial;
    }

    public synchronized boolean release(Object candidate) {
        if (activity != candidate || candidate == null) return false;
        activity = null;
        root = null;
        return true;
    }

    public synchronized Object activity() { return activity; }
    public synchronized Object root() { return root; }
    public synchronized long serial() { return serial; }
    public synchronized long collisions() { return collisions; }
    public synchronized int liveCount() { return activity == null ? 0 : 1; }
}
