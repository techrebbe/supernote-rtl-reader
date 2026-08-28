package com.techrebbe.supernote.virtualspread;

/** Host-testable identity rule for one native page completion callback. */
public final class NativeViewportCompletionAuthority {
    private NativeViewportCompletionAuthority() {
    }

    public static boolean isCurrent(
        Object boundViewModel,
        Object boundPageInfo,
        long boundGeneration,
        Object liveViewModel,
        Object livePageInfo,
        long currentGeneration
    ) {
        return boundViewModel != null
            && boundPageInfo != null
            && boundViewModel == liveViewModel
            && boundPageInfo == livePageInfo
            && boundGeneration >= 0L
            && boundGeneration == currentGeneration;
    }
}
