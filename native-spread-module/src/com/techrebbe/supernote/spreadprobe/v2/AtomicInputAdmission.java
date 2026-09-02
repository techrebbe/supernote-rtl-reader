package com.techrebbe.supernote.spreadprobe.v2;

/**
 * One synchronized admission point for physical input and transaction freezes.
 * A contact and a freeze can never both win the same boundary.
 */
public final class AtomicInputAdmission {
    public enum Contact { FINGER, STYLUS }

    private boolean frozen;
    private boolean fingerActive;
    private boolean stylusActive;
    private long generation;

    public synchronized boolean begin(Contact contact) {
        if (contact == null || frozen || fingerActive || stylusActive) {
            return false;
        }
        if (contact == Contact.FINGER) fingerActive = true;
        else stylusActive = true;
        return true;
    }

    public synchronized void end(Contact contact) {
        if (contact == Contact.FINGER) fingerActive = false;
        else if (contact == Contact.STYLUS) stylusActive = false;
    }

    /** Freezes new ingress while allowing an already-classified contact to drain. */
    public synchronized long freeze() {
        frozen = true;
        return ++generation;
    }

    /** Atomically reserves a contact-free boundary for toolbar/navigation work. */
    public synchronized long freezeIfIdle() {
        if (frozen || fingerActive || stylusActive) return -1L;
        frozen = true;
        return ++generation;
    }

    public synchronized void release() {
        frozen = false;
    }

    public synchronized boolean frozen() {
        return frozen;
    }

    public synchronized boolean contactActive() {
        return fingerActive || stylusActive;
    }

    public synchronized long generation() {
        return generation;
    }
}
