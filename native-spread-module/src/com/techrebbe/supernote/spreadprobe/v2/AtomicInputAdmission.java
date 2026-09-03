package com.techrebbe.supernote.spreadprobe.v2;

/**
 * One synchronized admission point for physical input and transaction freezes.
 * A contact and a freeze can never both win the same boundary.
 */
public final class AtomicInputAdmission {
    public enum Contact { FINGER, STYLUS }

    /**
     * Unforgeable ownership of one frozen ingress epoch.  A later freeze
     * supersedes this object even when ingress was already frozen, so stale
     * asynchronous work cannot thaw a lifecycle or restoration fence.
     */
    public static final class FreezeToken {
        public final long generation;

        private FreezeToken(long generation) {
            this.generation = generation;
        }
    }

    private FreezeToken freezeToken;
    private boolean fingerActive;
    private boolean stylusActive;
    private long generation;

    public synchronized boolean begin(Contact contact) {
        if (contact == null || freezeToken != null
            || fingerActive || stylusActive) {
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
    public synchronized FreezeToken freeze() {
        freezeToken = nextToken();
        return freezeToken;
    }

    /** Atomically reserves a contact-free boundary for toolbar/navigation work. */
    public synchronized FreezeToken freezeIfIdle() {
        if (freezeToken != null || fingerActive || stylusActive) return null;
        freezeToken = nextToken();
        return freezeToken;
    }

    /**
     * Atomically replaces any older frozen epoch, but never cuts through a
     * live contact.  Lifecycle and stock-restoration boundaries use this to
     * revoke every earlier completion's authority to release ingress.
     */
    public synchronized FreezeToken supersedeIfIdle() {
        if (fingerActive || stylusActive) return null;
        freezeToken = nextToken();
        return freezeToken;
    }

    /** Releases only the exact epoch owned by the caller. */
    public synchronized boolean release(FreezeToken token) {
        if (token == null || token != freezeToken) return false;
        freezeToken = null;
        return true;
    }

    public synchronized boolean current(FreezeToken token) {
        return token != null && token == freezeToken;
    }

    public synchronized boolean frozen() {
        return freezeToken != null;
    }

    public synchronized boolean contactActive() {
        return fingerActive || stylusActive;
    }

    public synchronized long generation() {
        return generation;
    }

    private FreezeToken nextToken() {
        if (generation == Long.MAX_VALUE) {
            throw new IllegalStateException("input admission generation exhausted");
        }
        return new FreezeToken(++generation);
    }
}
