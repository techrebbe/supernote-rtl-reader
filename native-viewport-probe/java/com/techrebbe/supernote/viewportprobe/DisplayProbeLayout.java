package com.techrebbe.supernote.viewportprobe;

/** Surface presentation only. These coordinates are NOT native saved EMR coordinates. */
public final class DisplayProbeLayout {
    public static final int BUFFER_WIDTH = 1404;
    public static final int BUFFER_HEIGHT = 1872;
    public enum Placement { FULL, LEFT, RIGHT }

    public final int left, top, width, height;
    public final Placement effectivePlacement;

    private DisplayProbeLayout(int left, int top, int width, int height, Placement placement) {
        this.left = left;
        this.top = top;
        this.width = width;
        this.height = height;
        this.effectivePlacement = placement;
    }

    public static DisplayProbeLayout fit(int hostWidth, int hostHeight, Placement requested) {
        if (hostWidth < 4 || hostHeight < 4 || hostWidth > 8192 || hostHeight > 8192
                || requested == null) throw new IllegalArgumentException("invalid host geometry");
        Placement placement = hostWidth > hostHeight ? requested : Placement.FULL;
        int slotLeft = placement == Placement.RIGHT ? hostWidth / 2 : 0;
        int slotWidth = placement == Placement.FULL ? hostWidth
                : placement == Placement.LEFT ? hostWidth / 2 : hostWidth - slotLeft;
        // Largest integer-pixel rectangle with EXACT 3:4 buffer aspect ratio.
        // Do not independently round dimensions and introduce a small stretch.
        int unit = Math.min(slotWidth / 3, hostHeight / 4);
        if (unit < 1) throw new IllegalArgumentException("host too small");
        int width = unit * 3;
        int height = unit * 4;
        return new DisplayProbeLayout(slotLeft + (slotWidth - width) / 2,
                (hostHeight - height) / 2, width, height, placement);
    }
}
