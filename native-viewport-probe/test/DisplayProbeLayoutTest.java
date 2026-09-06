import com.techrebbe.supernote.viewportprobe.DisplayProbeLayout;
import com.techrebbe.supernote.viewportprobe.DisplayProbeLifecycle;
import static com.techrebbe.supernote.viewportprobe.DisplayProbeLayout.Placement.*;

public final class DisplayProbeLayoutTest {
    private static int checks;
    private static void require(boolean value) { checks++; if (!value) throw new AssertionError("check " + checks); }
    public static void main(String[] args) {
        DisplayProbeLayout left = DisplayProbeLayout.fit(1872, 1404, LEFT);
        require(left.left == 0 && left.top == 78 && left.width == 936 && left.height == 1248);
        DisplayProbeLayout right = DisplayProbeLayout.fit(1872, 1404, RIGHT);
        require(right.left == 936 && right.top == 78 && right.width == 936 && right.height == 1248);
        DisplayProbeLayout full = DisplayProbeLayout.fit(1404, 1872, RIGHT);
        require(full.effectivePlacement == FULL && full.left == 0 && full.top == 0);
        require(full.width == 1404 && full.height == 1872);
        // Different chrome/insets, odd host bounds and rotation cannot resize
        // the canonical buffer or introduce X/Y aspect distortion.
        for (int w = 900; w <= 1900; w += 13) {
            for (int h = 900; h <= 1900; h += 17) {
                for (DisplayProbeLayout.Placement p : DisplayProbeLayout.Placement.values()) {
                    DisplayProbeLayout f = DisplayProbeLayout.fit(w, h, p);
                    require(f.width * 4 == f.height * 3 && f.width > 0 && f.height > 0);
                    require(f.left >= 0 && f.top >= 0 && f.left + f.width <= w && f.top + f.height <= h);
                    require(w > h || f.effectivePlacement == FULL);
                    if (w > h && p == LEFT) require(f.left + f.width <= w / 2);
                    if (w > h && p == RIGHT) require(f.left >= w / 2);
                }
            }
        }
        for (int[] bad : new int[][]{{0,0},{-1,1404},{3,1872},{1404,8193}}) {
            try { DisplayProbeLayout.fit(bad[0], bad[1], FULL); throw new AssertionError("accepted invalid size"); }
            catch (IllegalArgumentException expected) { checks++; }
        }
        require(DisplayProbeLayout.BUFFER_WIDTH == 1404 && DisplayProbeLayout.BUFFER_HEIGHT == 1872);
        DisplayProbeLifecycle cold = new DisplayProbeLifecycle(false);
        require(cold.canCreate() && !cold.isActive());
        require(!cold.claimCalibration());
        cold.activate();
        require(!cold.canCreate() && cold.isActive());
        require(cold.claimCalibration());
        require(!cold.claimCalibration());
        cold.stop();
        require(!cold.canCreate() && !cold.isActive());
        require(!cold.claimCalibration());
        cold.stop();
        require(!cold.canCreate());
        for (DisplayProbeLifecycle stopped : new DisplayProbeLifecycle[]{cold, new DisplayProbeLifecycle(true)}) {
            require(!stopped.canCreate() && !stopped.isActive());
            require(!stopped.claimCalibration());
            try { stopped.activate(); throw new AssertionError("restored/stopped host restarted"); }
            catch (IllegalStateException expected) { checks++; }
        }
        require(new DisplayProbeLifecycle(false).canCreate());
        System.out.println("Display surface layout: " + checks + " assertions PASS (not native pen geometry)");
    }
}
