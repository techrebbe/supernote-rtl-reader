package com.techrebbe.supernote.shadowpageoverlay;

/** Fixed display-0 placements for the disposable, visual-only overlay. */
public final class ShadowPageGeometry {
    public static final int DISPLAY_WIDTH = 1872;
    public static final int DISPLAY_HEIGHT = 1404;
    public static final int CANVAS_WIDTH = 1404;
    public static final int CANVAS_HEIGHT = 1872;

    private ShadowPageGeometry() { }

    public static Placement placement(String mode, int displayWidth, int displayHeight) {
        if (displayWidth != DISPLAY_WIDTH || displayHeight != DISPLAY_HEIGHT) {
            throw new IllegalArgumentException("display-0 geometry is not the pinned landscape frame");
        }
        if ("FULL".equals(mode)) return new Placement(409, 0, 1053, 1404);
        if ("LEFT".equals(mode)) return new Placement(0, 78, 936, 1248);
        if ("RIGHT".equals(mode)) return new Placement(936, 78, 936, 1248);
        throw new IllegalArgumentException("unknown shadow overlay placement");
    }

    public static final class Placement {
        public final int x;
        public final int y;
        public final int width;
        public final int height;

        private Placement(int x, int y, int width, int height) {
            this.x = x;
            this.y = y;
            this.width = width;
            this.height = height;
        }
    }
}
