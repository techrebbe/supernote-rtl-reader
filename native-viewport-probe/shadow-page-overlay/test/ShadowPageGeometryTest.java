import com.techrebbe.supernote.shadowpageoverlay.ShadowPageGeometry;
import com.techrebbe.supernote.shadowpageoverlay.ShadowOverlayGeneration;

/** Host-only assertions: these positions are the reviewed 1872x1404 snapshot. */
public final class ShadowPageGeometryTest {
    private static int checks;

    private static void check(boolean condition) {
        checks++;
        if (!condition) throw new AssertionError("geometry check " + checks);
    }

    private static void placement(String mode, int x, int y, int width, int height) {
        ShadowPageGeometry.Placement actual =
                ShadowPageGeometry.placement(mode, 1872, 1404);
        check(actual != null);
        check(actual.x == x);
        check(actual.y == y);
        check(actual.width == width);
        check(actual.height == height);
        check(actual.width > 0 && actual.height > 0);
        check(actual.width * 4 == actual.height * 3);
        check(actual.x >= 0 && actual.y >= 0);
        check(actual.x + actual.width <= 1872);
        check(actual.y + actual.height <= 1404);
    }

    private static void rejects(String mode, int width, int height) {
        boolean rejected = false;
        try {
            ShadowPageGeometry.placement(mode, width, height);
        } catch (IllegalArgumentException expected) {
            rejected = true;
        }
        check(rejected);
    }

    private static void rejectsBegin(ShadowOverlayGeneration owner, Object view) {
        boolean rejected = false;
        try {
            owner.begin(view);
        } catch (IllegalArgumentException | IllegalStateException expected) {
            rejected = true;
        }
        check(rejected);
    }

    private static void testGenerationFencesStaleCallbacks() {
        ShadowOverlayGeneration owner = new ShadowOverlayGeneration();
        Object oldView = new String("same visual owner");
        Object equalButDistinctView = new String("same visual owner");
        Object newView = new Object();
        check(oldView != equalButDistinctView && oldView.equals(equalButDistinctView));
        check(!owner.owns(oldView, 0));
        rejectsBegin(owner, null);

        long oldGeneration = owner.begin(oldView);
        check(oldGeneration > 0);
        check(owner.owns(oldView, oldGeneration));
        check(!owner.owns(equalButDistinctView, oldGeneration));
        check(!owner.owns(newView, oldGeneration));
        check(!owner.owns(oldView, oldGeneration + 1));
        rejectsBegin(owner, oldView);
        rejectsBegin(owner, newView);

        owner.clear();
        check(!owner.owns(oldView, oldGeneration));
        owner.clear(); // teardown remains safe when repeated
        check(!owner.owns(oldView, oldGeneration));

        long newGeneration = owner.begin(newView);
        check(newGeneration > oldGeneration);
        check(owner.owns(newView, newGeneration));
        check(!owner.owns(oldView, oldGeneration));
        check(!owner.owns(newView, oldGeneration));
        // Simulate an old timeout delivered after the new SHOW. It must not
        // clear the new owner even if callback removal failed or raced.
        if (owner.owns(oldView, oldGeneration)) owner.clear();
        check(owner.owns(newView, newGeneration));

        owner.clear();
        long reusedGeneration = owner.begin(oldView);
        check(reusedGeneration > newGeneration);
        check(!owner.owns(oldView, oldGeneration));
        check(owner.owns(oldView, reusedGeneration));
        if (owner.owns(oldView, oldGeneration)) owner.clear();
        check(owner.owns(oldView, reusedGeneration));
        owner.clear();
        check(!owner.owns(oldView, reusedGeneration));
    }

    public static void main(String[] args) {
        testGenerationFencesStaleCallbacks();
        placement("FULL", 409, 0, 1053, 1404);
        placement("LEFT", 0, 78, 936, 1248);
        placement("RIGHT", 936, 78, 936, 1248);

        ShadowPageGeometry.Placement left =
                ShadowPageGeometry.placement("LEFT", 1872, 1404);
        ShadowPageGeometry.Placement right =
                ShadowPageGeometry.placement("RIGHT", 1872, 1404);
        check(left.x + left.width == right.x);
        check(right.x + right.width == 1872);
        check(left.y == right.y && left.height == right.height);

        for (String mode : new String[]{null, "", "full", "Full", "LEFT ",
                "RIGHT\n", "CENTER", "TEARDOWN", "BASELINE"}) {
            rejects(mode, 1872, 1404);
        }
        for (int[] dimensions : new int[][]{
                {0, 1404}, {1872, 0}, {-1872, 1404}, {1872, -1404},
                {1404, 1872}, {1871, 1404}, {1872, 1403},
                {1873, 1404}, {1872, 1405},
                {Integer.MAX_VALUE, Integer.MAX_VALUE}
        }) {
            for (String mode : new String[]{"FULL", "LEFT", "RIGHT"}) {
                rejects(mode, dimensions[0], dimensions[1]);
            }
        }
        System.out.println("PASS " + checks + " shadow geometry checks (host only)");
    }
}
