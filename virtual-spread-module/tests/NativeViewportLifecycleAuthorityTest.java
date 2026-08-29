import com.techrebbe.supernote.virtualspread.NativeViewportLifecycleAuthority;

public final class NativeViewportLifecycleAuthorityTest {
    public static void main(String[] args) {
        activeActivityMayClearAuthority();
        replacedActivityCannotClearAuthority();
        activeViewModelOwnsCallbackCleanup();
        replacedViewModelCannotClearAuthority();
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
