import com.techrebbe.supernote.virtualspread.NativeViewportLifecycleAuthority;

public final class NativeViewportLifecycleAuthorityTest {
    public static void main(String[] args) {
        activeActivityMayClearAuthority();
        replacedActivityCannotClearAuthority();
        activeViewModelOwnsCallbackCleanup();
        replacementClaimsOwnershipBeforeOnCreateBody();
        creatingActivityMayOwnEarlyCallback();
        creatingActivityCannotOverrideAssignedViewModel();
        activeActivityOwnsLifecycleCallback();
        replacedActivityCannotReclaimLifecycleCallback();
        replacedViewModelCannotClearAuthority();
        destroyedObsoleteViewModelIsReleased();
        reusedActiveViewModelIsPreserved();
        manifestBindingPreservesPendingLoad();
        documentReplacementClearsPendingLoad();
        exactUnpublishedCompletionClearsPendingLoad();
        staleUnpublishedCompletionPreservesPendingLoad();
        System.out.println("NativeViewportLifecycleAuthorityTest passed");
    }

    private static void activeActivityMayClearAuthority() {
        Object activity = new Object();
        require(NativeViewportLifecycleAuthority
            .mayClearForDestroyedActivity(activity, activity));
    }

    private static void replacedActivityCannotClearAuthority() {
        require(!NativeViewportLifecycleAuthority
            .mayClearForDestroyedActivity(new Object(), new Object()));
        require(!NativeViewportLifecycleAuthority
            .mayClearForDestroyedActivity(null, new Object()));
    }

    private static void activeViewModelOwnsCallbackCleanup() {
        Object activity = new Object();
        Object viewModel = new Object();
        require(NativeViewportLifecycleAuthority.callbackOwnsActiveReader(
            viewModel,
            activity,
            viewModel
        ));
    }

    private static void replacementClaimsOwnershipBeforeOnCreateBody() {
        Object current = new Object();
        Object replacement = new Object();
        require(NativeViewportLifecycleAuthority.beginsReaderOwnership(
            replacement,
            current
        ));
        require(!NativeViewportLifecycleAuthority.beginsReaderOwnership(
            current,
            current
        ));
        require(!NativeViewportLifecycleAuthority.beginsReaderOwnership(
            null,
            current
        ));
    }

    private static void creatingActivityMayOwnEarlyCallback() {
        require(NativeViewportLifecycleAuthority.callbackOwnsActiveReader(
            new Object(),
            new Object(),
            null,
            true
        ));
    }

    private static void creatingActivityCannotOverrideAssignedViewModel() {
        Object callback = new Object();
        require(!NativeViewportLifecycleAuthority.callbackOwnsActiveReader(
            callback,
            new Object(),
            new Object(),
            true
        ));
        require(!NativeViewportLifecycleAuthority.callbackOwnsActiveReader(
            callback,
            new Object(),
            null,
            false
        ));
    }

    private static void activeActivityOwnsLifecycleCallback() {
        Object activity = new Object();
        require(NativeViewportLifecycleAuthority.activityCallbackOwnsReader(
            activity,
            activity
        ));
    }

    private static void replacedActivityCannotReclaimLifecycleCallback() {
        require(!NativeViewportLifecycleAuthority.activityCallbackOwnsReader(
            new Object(),
            new Object()
        ));
        require(!NativeViewportLifecycleAuthority.activityCallbackOwnsReader(
            null,
            new Object()
        ));
    }

    private static void replacedViewModelCannotClearAuthority() {
        Object oldViewModel = new Object();
        Object newViewModel = new Object();
        require(!NativeViewportLifecycleAuthority.callbackOwnsActiveReader(
            oldViewModel,
            new Object(),
            newViewModel
        ));
        require(!NativeViewportLifecycleAuthority.callbackOwnsActiveReader(
            oldViewModel,
            null,
            oldViewModel
        ));
    }

    private static void destroyedObsoleteViewModelIsReleased() {
        require(NativeViewportLifecycleAuthority
            .mayReleaseDestroyedViewModel(
                new Object(),
                new Object(),
                false
            ));
        Object active = new Object();
        require(NativeViewportLifecycleAuthority
            .mayReleaseDestroyedViewModel(active, active, true));
    }

    private static void reusedActiveViewModelIsPreserved() {
        Object reused = new Object();
        require(!NativeViewportLifecycleAuthority
            .mayReleaseDestroyedViewModel(reused, reused, false));
        require(!NativeViewportLifecycleAuthority
            .mayReleaseDestroyedViewModel(null, reused, false));
    }

    private static void manifestBindingPreservesPendingLoad() {
        require(NativeViewportLifecycleAuthority.pendingAfterStateBinding(
            true,
            false
        ));
    }

    private static void documentReplacementClearsPendingLoad() {
        require(!NativeViewportLifecycleAuthority.pendingAfterStateBinding(
            true,
            true
        ));
        require(!NativeViewportLifecycleAuthority.pendingAfterStateBinding(
            false,
            false
        ));
    }

    private static void exactUnpublishedCompletionClearsPendingLoad() {
        require(!NativeViewportLifecycleAuthority
            .pendingAfterUnpublishedCompletion(true, true));
        require(!NativeViewportLifecycleAuthority
            .pendingAfterUnpublishedCompletion(false, true));
    }

    private static void staleUnpublishedCompletionPreservesPendingLoad() {
        require(NativeViewportLifecycleAuthority
            .pendingAfterUnpublishedCompletion(true, false));
        require(!NativeViewportLifecycleAuthority
            .pendingAfterUnpublishedCompletion(false, false));
    }

    private static void require(boolean condition) {
        if (!condition) {
            throw new AssertionError("condition was false");
        }
    }
}
