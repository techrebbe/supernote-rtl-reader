import com.techrebbe.supernote.virtualspread.NativeViewportGenerationFence;

public final class NativeViewportGenerationFenceTest {
    public static void main(String[] arguments) {
        samePageReloadRejectsTheOldPublication();
        aNewSessionCannotReuseTheOldSessionGeneration();
        clearRequiresTheOwningSession();
        generationsAreStrictlyMonotonicWithinASession();
        System.out.println("NativeViewportGenerationFenceTest passed");
    }

    private static void samePageReloadRejectsTheOldPublication() {
        NativeViewportGenerationFence fence =
            new NativeViewportGenerationFence();
        Object session = new Object();
        fence.begin(session, 7L);
        require(fence.accepts(session, 7L));
        fence.begin(session, 8L);
        require(!fence.accepts(session, 7L));
        require(fence.accepts(session, 8L));
    }

    private static void aNewSessionCannotReuseTheOldSessionGeneration() {
        NativeViewportGenerationFence fence =
            new NativeViewportGenerationFence();
        Object first = new Object();
        Object second = new Object();
        fence.begin(first, 12L);
        fence.begin(second, 0L);
        require(!fence.accepts(first, 12L));
        require(fence.accepts(second, 0L));
    }

    private static void clearRequiresTheOwningSession() {
        NativeViewportGenerationFence fence =
            new NativeViewportGenerationFence();
        Object owner = new Object();
        fence.begin(owner, 1L);
        require(!fence.clear(new Object()));
        require(fence.accepts(owner, 1L));
        require(fence.clear(owner));
        require(!fence.accepts(owner, 1L));
        require(fence.clear(owner));
    }

    private static void generationsAreStrictlyMonotonicWithinASession() {
        final NativeViewportGenerationFence fence =
            new NativeViewportGenerationFence();
        final Object owner = new Object();
        fence.begin(owner, 4L);
        expectFailure(new Runnable() {
            @Override
            public void run() {
                fence.begin(owner, 4L);
            }
        });
        expectFailure(new Runnable() {
            @Override
            public void run() {
                fence.begin(owner, 3L);
            }
        });
        require(fence.accepts(owner, 4L));
    }

    private static void require(boolean condition) {
        if (!condition) {
            throw new AssertionError("condition was false");
        }
    }

    private static void expectFailure(Runnable action) {
        try {
            action.run();
            throw new AssertionError("expected fail-closed rejection");
        } catch (IllegalArgumentException expected) {
            // Expected.
        }
    }
}
