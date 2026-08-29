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
     * A page-load callback may mutate the process-wide provider only while
     * its view model is still owned by the active DocumentActivity.
     */
    public static boolean callbackOwnsActiveReader(
        Object callbackViewModel,
        Object activeActivity,
        Object activeViewModel
    ) {
        return callbackOwnsActiveReader(
            callbackViewModel,
            activeActivity,
            activeViewModel,
            false
        );
    }

    /**
     * The replacement activity owns the reader from the beginning of
     * onCreate, before firmware necessarily assigns documentViewModel. Only a
     * callback running inside that exact creation scope may use the temporary
     * null-field fallback; once the field is assigned, identity remains exact.
     */
    public static boolean callbackOwnsActiveReader(
        Object callbackViewModel,
        Object activeActivity,
        Object activeViewModel,
        boolean activeActivityIsCreating
    ) {
        return callbackViewModel != null
            && activeActivity != null
            && (callbackViewModel == activeViewModel
                || (activeActivityIsCreating && activeViewModel == null));
    }

    /** A new activity must claim ownership before its onCreate body runs. */
    public static boolean beginsReaderOwnership(
        Object creatingActivity,
        Object activeActivity
    ) {
        return creatingActivity != null && creatingActivity != activeActivity;
    }

    /** Late callbacks from a replaced activity cannot reclaim ownership. */
    public static boolean activityCallbackOwnsReader(
        Object callbackActivity,
        Object activeActivity
    ) {
        return callbackActivity != null && callbackActivity == activeActivity;
    }

    /** Release a destroyed activity's state unless its view model was reused. */
    public static boolean mayReleaseDestroyedViewModel(
        Object destroyedViewModel,
        Object activeViewModel,
        boolean destroyingActivityOwnsReader
    ) {
        return destroyedViewModel != null
            && (destroyingActivityOwnsReader
                || destroyedViewModel != activeViewModel);
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
