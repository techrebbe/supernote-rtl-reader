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

    /**
     * An exact-current native load can finish before asynchronous manifest
     * verification publishes authority. Its callback may not publish, but it
     * has still completed the load that owned the pending marker. Clearing
     * that marker lets the subsequently verified manifest synthesize one
     * exact-current completion. An unmatched or older callback must retain it.
     */
    public static boolean pendingAfterUnpublishedCompletion(
        boolean loadPending,
        boolean exactCurrentRequest
    ) {
        return loadPending && !exactCurrentRequest;
    }
}
