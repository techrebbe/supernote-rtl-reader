package com.techrebbe.supernote.disposableleasehost;

/** A frame is fresh only when it completed after the latest invalidation. */
public final class PaintEpoch {
    private long requiredRevision = 1;
    private long observedRevision;
    private long completedFrames;

    public long invalidate() { return ++requiredRevision; }
    public long beginFrame() { return requiredRevision; }
    public void completeFrame(long begunRevision) {
        completedFrames++;
        observedRevision = begunRevision;
    }
    public boolean fresh() {
        return completedFrames > 0 && observedRevision == requiredRevision;
    }
    public long requiredRevision() { return requiredRevision; }
    public long observedRevision() { return observedRevision; }
    public long completedFrames() { return completedFrames; }
}
