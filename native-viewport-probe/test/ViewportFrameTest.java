import com.techrebbe.supernote.viewportprobe.ViewportFrame;
import com.techrebbe.supernote.spreadprobe.v2.PointD;
import com.techrebbe.supernote.spreadprobe.v2.RectD;
import java.util.Arrays;
import java.util.Collections;

public final class ViewportFrameTest {
    private static final String DOC = String.join("", Collections.nCopies(64, "a"));
    private static int assertions;
    private static void check(boolean condition) { assertions++; if (!condition) throw new AssertionError(); }
    private static void equal(double a, double b) { check(Math.abs(a - b) < 1e-9); }
    private static void rejects(Runnable action) {
        boolean rejected = false;
        try { action.run(); } catch (IllegalArgumentException | IllegalStateException error) { rejected = true; }
        check(rejected);
    }
    public static void main(String[] args) {
        RectD nativePage = new RectD(0, 0, 1404, 1872);
        ViewportFrame full = new ViewportFrame(DOC, 1, 1, nativePage, nativePage);
        ViewportFrame left = new ViewportFrame(DOC, 1, 2, nativePage, new RectD(0, 0, 936, 1404));
        ViewportFrame right = new ViewportFrame(DOC, 1, 3, nativePage, new RectD(936, 0, 1872, 1404));
        equal(full.nativeToScreen.a, 1);
        equal(left.nativeToScreen.a, 2.0/3); equal(left.pageOnScreen.top, 78);
        equal(right.pageOnScreen.left, 936); equal(right.pageOnScreen.bottom, 1326);
        // Independent arithmetic for the observed Box C stroke, not agreement
        // between two copies of the production transform formula.
        PointD a = left.nativeToScreen.map(939, 388);
        equal(a.x, 626); equal(a.y, 336.6666666666667);
        PointD b = right.nativeToScreen.map(939, 388);
        equal(b.x, 1562); equal(b.y, a.y);
        RectD toolbar = new RectD(0, 0, 1872, 100);
        ViewportFrame.Contact chrome = right.beginContact(1000, 90, Arrays.asList(toolbar));
        check(chrome.route == ViewportFrame.ContactRoute.NATIVE_CHROME);
        rejects(() -> chrome.documentPoint(1100, 300, right));
        check(right.beginContact(1000, 90, Collections.emptyList()).route == ViewportFrame.ContactRoute.DOCUMENT);
        ViewportFrame.Contact ink = left.beginContact(626, 336.6666666666667, Arrays.asList(toolbar));
        equal(ink.documentPoint(626, 336.6666666666667, left).x, 939);
        // Remains document input when crossing a toolbar or the opposite half.
        check(ink.route == ViewportFrame.ContactRoute.DOCUMENT);
        ink.documentPoint(950, 49, left);
        rejects(() -> ink.documentPoint(626, 336, right));
        check(left.beginContact(936, 500, Collections.emptyList()).route == ViewportFrame.ContactRoute.OUTSIDE);
        check(left.beginContact(100, 30, Collections.emptyList()).route == ViewportFrame.ContactRoute.OUTSIDE);
        for (RectD source : Arrays.asList(nativePage, new RectD(0,0,1872,1404), new RectD(0,0,1000,1000),
                                          new RectD(17,29,917,2229), new RectD(-100,-200,2900,300))) {
            for (RectD window : Arrays.asList(nativePage, left.viewport, right.viewport, new RectD(100,140,850,1200))) {
                ViewportFrame f = new ViewportFrame(DOC, 7, 4, source, window);
                equal(f.nativeToScreen.a, f.nativeToScreen.d);
                check(f.pageOnScreen.left >= window.left - 1e-9 && f.pageOnScreen.top >= window.top - 1e-9);
                check(f.pageOnScreen.right <= window.right + 1e-9 && f.pageOnScreen.bottom <= window.bottom + 1e-9);
                for (double t : new double[]{0, .1, .5, .9, 1}) {
                    double x = source.left + source.width()*t, y = source.top + source.height()*(1-t);
                    PointD screen = f.nativeToScreen.map(x,y), roundtrip = f.screenToNative.map(screen.x,screen.y);
                    equal(roundtrip.x,x); equal(roundtrip.y,y);
                }
            }
        }
        rejects(() -> new ViewportFrame(DOC,0,1,nativePage,nativePage));
        rejects(() -> new ViewportFrame(DOC,1,0,nativePage,nativePage));
        rejects(() -> new ViewportFrame("wrong",1,1,nativePage,nativePage));
        System.out.println("PASS " + assertions + " viewport contract assertions; no hardware adapter certified");
    }
}
