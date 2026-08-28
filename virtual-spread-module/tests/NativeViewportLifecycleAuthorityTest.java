import com.techrebbe.supernote.virtualspread.NativeViewportLifecycleAuthority;

public final class NativeViewportLifecycleAuthorityTest {
    public static void main(String[] args) {
        activeActivityMayClearAuthority();
        replacedActivityCannotClearAuthority();
        manifestBindingPreservesPendingLoad();
        documentReplacementClearsPendingLoad();
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

    private static void require(boolean condition) {
        if (!condition) {
            throw new AssertionError("condition was false");
        }
    }
}
