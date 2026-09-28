package com.techrebbe.supernote.disposableleasehost;

/**
 * Monotone paint-pass generations, independent of layout/invalidation epochs.
 * A pass is evidence only after its exact begin generation completes.
 */
public final class LeasePaintPassLedger {
    private long begun;
    private long completed;

    public long begin() {
        if (begun == Long.MAX_VALUE) throw new IllegalStateException("paint revision exhausted");
        return ++begun;
    }

    public void complete(long revision) {
        if (revision <= 0 || revision != begun || revision <= completed) {
            throw new IllegalStateException("paint completion is not the active pass");
        }
        completed = revision;
    }

    public long begunRevision() { return begun; }
    public long completedRevision() { return completed; }
}
