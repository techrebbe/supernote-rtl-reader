package com.techrebbe.supernote.virtualspread;

/** Pure lifecycle ownership rules for the memory-only viewport authority. */
public final class NativeViewportLifecycleAuthority {
    private NativeViewportLifecycleAuthority() {}

    /** Only the activity that still owns the live reader may clear it. */
    public static boolean mayClearForDestroyedActivity(
        Object destroyingActivity,
        Object activeActivity
    ) {
        return destroyingActivity != null
            && destroyingActivity == activeActivity;
    }

    /**
     * Verification binding for the same document must not erase knowledge of
     * an already-started native page load. A real document replacement does.
     */
    public static boolean pendingAfterStateBinding(
        boolean loadPending,
        boolean documentChanged
    ) {
        return loadPending && !documentChanged;
    }
}
