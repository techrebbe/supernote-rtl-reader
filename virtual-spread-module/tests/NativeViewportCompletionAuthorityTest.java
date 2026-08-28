import com.techrebbe.supernote.virtualspread.NativeViewportCompletionAuthority;
import com.techrebbe.supernote.virtualspread.NativeViewportGenerationFence;

public final class NativeViewportCompletionAuthorityTest {
    public static void main(String[] arguments) {
        exactCompletionIdentityIsAccepted();
        olderGenerationOnSamePageObjectIsRejected();
        olderPageObjectAtSameLogicalIndexIsRejected();
        unboundCompletionIsRejected();
        overlappingSamePageReloadCannotAdoptTheNewGeneration();
        exactInitiatingLoadRequestIsAccepted();
        olderSamePageRequestIsRejected();
        replacedDocumentRequestIsRejected();
        onlyTheLivePageWorkerMayBeginARefreshGeneration();
        System.out.println("NativeViewportCompletionAuthorityTest passed");
    }

    private static void exactCompletionIdentityIsAccepted() {
        Object viewModel = new Object();
        Object pageInfo = new Object();
        require(NativeViewportCompletionAuthority.isCurrent(
            viewModel, pageInfo, 9L, viewModel, pageInfo, 9L
        ));
    }

    private static void olderGenerationOnSamePageObjectIsRejected() {
        Object viewModel = new Object();
        Object pageInfo = new Object();
        require(!NativeViewportCompletionAuthority.isCurrent(
            viewModel, pageInfo, 8L, viewModel, pageInfo, 9L
        ));
    }

    private static void olderPageObjectAtSameLogicalIndexIsRejected() {
        Object viewModel = new Object();
        require(!NativeViewportCompletionAuthority.isCurrent(
            viewModel, new Object(), 9L, viewModel, new Object(), 9L
        ));
    }

    private static void unboundCompletionIsRejected() {
        Object viewModel = new Object();
        Object pageInfo = new Object();
        require(!NativeViewportCompletionAuthority.isCurrent(
            viewModel, null, 9L, viewModel, pageInfo, 9L
        ));
        require(!NativeViewportCompletionAuthority.isCurrent(
            viewModel, pageInfo, -1L, viewModel, pageInfo, -1L
        ));
    }

    private static void overlappingSamePageReloadCannotAdoptTheNewGeneration() {
        NativeViewportGenerationFence fence =
            new NativeViewportGenerationFence();
        Object session = new Object();
        Object viewModel = new Object();
        Object samePageInfo = new Object();

        fence.begin(session, 20L);
        long olderCompletionGeneration = 20L;
        fence.begin(session, 21L);

        require(!NativeViewportCompletionAuthority.isCurrent(
            viewModel,
            samePageInfo,
            olderCompletionGeneration,
            viewModel,
            samePageInfo,
            21L
        ));
        require(!fence.accepts(session, olderCompletionGeneration));
        require(fence.accepts(session, 21L));
    }

    private static void exactInitiatingLoadRequestIsAccepted() {
        Object viewModel = new Object();
        Object nativeMupdf = new Object();
        require(NativeViewportCompletionAuthority.isCurrentRequest(
            viewModel,
            nativeMupdf,
            4,
            12L,
            viewModel,
            nativeMupdf,
            4,
            12L
        ));
    }

    private static void olderSamePageRequestIsRejected() {
        Object viewModel = new Object();
        Object nativeMupdf = new Object();
        require(!NativeViewportCompletionAuthority.isCurrentRequest(
            viewModel,
            nativeMupdf,
            4,
            11L,
            viewModel,
            nativeMupdf,
            4,
            12L
        ));
    }

    private static void replacedDocumentRequestIsRejected() {
        Object viewModel = new Object();
        require(!NativeViewportCompletionAuthority.isCurrentRequest(
            viewModel,
            new Object(),
            4,
            12L,
            viewModel,
            new Object(),
            4,
            12L
        ));
    }

    private static void onlyTheLivePageWorkerMayBeginARefreshGeneration() {
        require(NativeViewportCompletionAuthority.isCurrentWorkerPage(4, 4));
        require(!NativeViewportCompletionAuthority.isCurrentWorkerPage(3, 4));
        require(!NativeViewportCompletionAuthority.isCurrentWorkerPage(5, 4));
        require(!NativeViewportCompletionAuthority.isCurrentWorkerPage(-1, 4));
        require(!NativeViewportCompletionAuthority.isCurrentWorkerPage(0, -1));
    }

    private static void require(boolean condition) {
        if (!condition) {
            throw new AssertionError("condition was false");
        }
    }
}
