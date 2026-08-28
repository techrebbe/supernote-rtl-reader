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

    /**
     * One completion may publish only for the exact load request that created
     * it. Logical page equality alone is insufficient because two loads of the
     * same page can carry different native fit/translation geometry.
     */
    public static boolean isCurrentRequest(
        Object boundViewModel,
        Object boundNativeMupdf,
        int boundPage,
        long boundRequestSerial,
        Object liveViewModel,
        Object liveNativeMupdf,
        int livePage,
        long currentRequestSerial
    ) {
        return boundViewModel != null
            && boundNativeMupdf != null
            && boundViewModel == liveViewModel
            && boundNativeMupdf == liveNativeMupdf
            && boundPage >= 0
            && boundPage == livePage
            && boundRequestSerial > 0L
            && boundRequestSerial == currentRequestSerial;
    }
}
