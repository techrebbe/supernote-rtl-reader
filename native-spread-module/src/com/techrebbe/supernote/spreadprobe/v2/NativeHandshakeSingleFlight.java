package com.techrebbe.supernote.spreadprobe.v2;

import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Process-wide bounded admission for the externally reachable handshake.
 * At most one request may retain a firmware snapshot or queued runnable.
 */
public final class NativeHandshakeSingleFlight {
    private final AtomicBoolean pending = new AtomicBoolean(false);

    public boolean tryBegin() {
        return pending.compareAndSet(false, true);
    }

    public void finish() {
        pending.set(false);
    }

    public boolean pending() {
        return pending.get();
    }
}
