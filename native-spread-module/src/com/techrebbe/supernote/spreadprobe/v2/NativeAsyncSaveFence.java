package com.techrebbe.supernote.spreadprobe.v2;

import java.util.Objects;

/** Generation-bound authority for the worker/owner/worker native-save pipeline. */
public final class NativeAsyncSaveFence {
    public static final class Token {
        public final long id;
        public final String documentId;
        public final long activityGeneration;
        public final long layoutGeneration;
        public final int sourcePage;
        public final long markRevision;

        private Token(
            long id,
            String documentId,
            long activityGeneration,
            long layoutGeneration,
            int sourcePage,
            long markRevision
        ) {
            this.id = id;
            this.documentId = documentId;
            this.activityGeneration = activityGeneration;
            this.layoutGeneration = layoutGeneration;
            this.sourcePage = sourcePage;
            this.markRevision = markRevision;
        }
    }

    private long nextId = 1L;
    private Token current;

    public synchronized Token begin(SpreadSnapshot snapshot, long markRevision) {
        Objects.requireNonNull(snapshot, "snapshot");
        if (current != null || nextId <= 0L || markRevision < 0L) {
            throw new IllegalStateException("invalid or overlapping async save");
        }
        current = new Token(
            nextId++,
            snapshot.documentId,
            snapshot.activityGeneration,
            snapshot.layoutGeneration,
            snapshot.activePageIndex,
            markRevision
        );
        return current;
    }

    public synchronized boolean current(Token token, SpreadSnapshot snapshot) {
        return token != null && token == current && snapshot != null
            && token.documentId.equals(snapshot.documentId)
            && token.activityGeneration == snapshot.activityGeneration
            && token.layoutGeneration == snapshot.layoutGeneration
            && token.sourcePage == snapshot.activePageIndex;
    }

    public synchronized boolean complete(Token token) {
        if (token == null || token != current) return false;
        current = null;
        return true;
    }

    /** Invalidates every queued continuation from the prior generation. */
    public synchronized void cancel() {
        current = null;
        if (nextId == Long.MAX_VALUE) {
            throw new IllegalStateException("async save generation exhausted");
        }
        nextId++;
    }

    public synchronized boolean active() {
        return current != null;
    }
}
