package com.techrebbe.supernote.disposableleasehost;

/**
 * Main-Looper-owned evidence revision. The owner must call beforeMutation()
 * before every scene, hierarchy, geometry, child-metadata, or draw-policy
 * change. The reader is a plain, non-reentrant field read.
 */
public final class LeaseEvidenceMutationLedger {
    private long revision = 1;

    public long beforeMutation() {
        if (revision == Long.MAX_VALUE) {
            throw new IllegalStateException("evidence revision exhausted");
        }
        return ++revision;
    }

    public long revision() { return revision; }

    public boolean isCurrent(long capturedRevision) {
        return capturedRevision > 0 && capturedRevision == revision;
    }
}
