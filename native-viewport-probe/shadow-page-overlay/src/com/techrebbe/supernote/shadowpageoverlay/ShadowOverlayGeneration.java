package com.techrebbe.supernote.shadowpageoverlay;

/** One live view lease; stale callbacks cannot act on a later SHOW. */
public final class ShadowOverlayGeneration {
    private Object owner;
    private long generation;

    public long begin(Object view) {
        if (view == null || owner != null || generation == Long.MAX_VALUE) {
            throw new IllegalStateException("overlay generation cannot be admitted");
        }
        owner = view;
        return ++generation;
    }

    public boolean owns(Object view, long expectedGeneration) {
        return owner != null && owner == view && generation == expectedGeneration;
    }

    public void clear() {
        owner = null;
    }
}
