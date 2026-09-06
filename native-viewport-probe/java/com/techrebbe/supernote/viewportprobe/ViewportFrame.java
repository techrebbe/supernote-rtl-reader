package com.techrebbe.supernote.viewportprobe;

import com.techrebbe.supernote.spreadprobe.v2.Affine2D;
import com.techrebbe.supernote.spreadprobe.v2.PointD;
import com.techrebbe.supernote.spreadprobe.v2.RectD;
import java.util.List;
import java.util.Objects;

/**
 * Pure presentation contract for the one-page probe, not a native adapter.
 * Canonical native canvas remains unchanged; no producer may derive geometry
 * from the already-fitted bitmap or from a previous screen orientation.
 */
public final class ViewportFrame {
    public enum ContactRoute { NATIVE_CHROME, DOCUMENT, OUTSIDE }
    public final String documentSha256;
    public final int nativePage;
    public final long generation;
    public final RectD canonicalCanvas;
    public final RectD viewport;
    public final RectD pageOnScreen;
    public final Affine2D nativeToScreen;
    public final Affine2D screenToNative;

    public ViewportFrame(String documentSha256, int nativePage, long generation,
                         RectD canonicalCanvas, RectD viewport) {
        if (documentSha256 == null || !documentSha256.matches("[0-9a-f]{64}")
            || nativePage < 1 || generation < 1) throw new IllegalArgumentException("missing page authority");
        this.documentSha256 = documentSha256;
        this.nativePage = nativePage;
        this.generation = generation;
        this.canonicalCanvas = Objects.requireNonNull(canonicalCanvas);
        this.viewport = Objects.requireNonNull(viewport);
        double scale = Math.min(viewport.width() / canonicalCanvas.width(),
                                viewport.height() / canonicalCanvas.height());
        double x = viewport.left + (viewport.width() - canonicalCanvas.width() * scale) / 2;
        double y = viewport.top + (viewport.height() - canonicalCanvas.height() * scale) / 2;
        nativeToScreen = new Affine2D(scale, 0, 0, scale,
            x - scale * canonicalCanvas.left, y - scale * canonicalCanvas.top);
        screenToNative = nativeToScreen.derivedInverse();
        pageOnScreen = nativeToScreen.mapBounds(canonicalCanvas);
    }

    public Contact beginContact(double x, double y, List<RectD> currentlyVisibleChrome) {
        // Chrome rectangles come from actual visible views at DOWN, not fixed
        // top/bottom bands. The returned route must not be reclassified on MOVE.
        PointD point = new PointD(x, y);
        Objects.requireNonNull(currentlyVisibleChrome);
        for (RectD rect : currentlyVisibleChrome) {
            if (Objects.requireNonNull(rect).contains(point.x, point.y))
                return new Contact(this, ContactRoute.NATIVE_CHROME);
        }
        return new Contact(this, pageOnScreen.contains(x, y)
            ? ContactRoute.DOCUMENT : ContactRoute.OUTSIDE);
    }

    public static final class Contact {
        public final ViewportFrame frame;
        public final ContactRoute route;
        private Contact(ViewportFrame frame, ContactRoute route) { this.frame = frame; this.route = route; }
        public PointD documentPoint(double x, double y, ViewportFrame current) {
            if (current != frame || route != ContactRoute.DOCUMENT) {
                throw new IllegalStateException("stale or non-document contact");
            }
            // Clipping is an adapter responsibility; crossing chrome does not
            // arm a toolbar control or choose another page midway through ink.
            return frame.screenToNative.map(x, y);
        }
    }
}
