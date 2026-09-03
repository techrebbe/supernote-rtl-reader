package com.techrebbe.supernote.spreadprobe.v2;

import java.util.concurrent.atomic.AtomicLong;

/**
 * Process-wide bounded admission for the externally reachable handshake.
 * At most one request may retain a firmware snapshot or publication authority.
 */
public final class NativeHandshakeSingleFlight {
    private final AtomicLong nextToken = new AtomicLong(0L);
    private final AtomicLong owner = new AtomicLong(0L);

    /** Returns a non-zero generation token, or zero while another request owns admission. */
    public long tryBegin() {
        if (owner.get() != 0L) return 0L;
        long token = nextToken.incrementAndGet();
        if (token == 0L) token = nextToken.incrementAndGet();
        return owner.compareAndSet(0L, token) ? token : 0L;
    }

    /** Releases admission only for the exact generation that still owns it. */
    public boolean finish(long token) {
        return token != 0L && owner.compareAndSet(token, 0L);
    }

    public boolean current(long token) {
        return token != 0L && owner.get() == token;
    }

    /**
     * Publication authority requires both exact generation ownership and an
     * absolute, monotonic deadline that is checked when the work is consumed.
     */
    public boolean currentBefore(
        long token,
        long nowUptimeMs,
        long deadlineUptimeMs
    ) {
        return nowUptimeMs < deadlineUptimeMs && current(token);
    }

    public boolean pending() {
        return owner.get() != 0L;
    }
}
