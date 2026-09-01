package com.techrebbe.supernote.spreadprobe.v2;

import java.util.Objects;

/**
 * One exact DrawPath/mark geometry derived from the published page slot.
 * Rendering and every native tool must consume this same value.
 */
public final class NativeWriterGeometry {
    private static final double INTEGER_TOLERANCE = 0.501;

    public final int rotation;
    public final int viewWidth;
    public final int viewHeight;
    public final int virtualWidth;
    public final int virtualHeight;
    public final int originX;
    public final int originY;
    public final RectD writableBounds;

    private NativeWriterGeometry(
        int rotation,
        int viewWidth,
        int viewHeight,
        int virtualWidth,
        int virtualHeight,
        int originX,
        int originY,
        RectD writableBounds
    ) {
        this.rotation = rotation;
        this.viewWidth = viewWidth;
        this.viewHeight = viewHeight;
        this.virtualWidth = virtualWidth;
        this.virtualHeight = virtualHeight;
        this.originX = originX;
        this.originY = originY;
        this.writableBounds = writableBounds;
    }

    public static NativeWriterGeometry from(
        SpreadSnapshot snapshot,
        RectD physicalCanvas,
        int presenterRotation
    ) {
        Objects.requireNonNull(snapshot, "snapshot");
        Objects.requireNonNull(physicalCanvas, "physicalCanvas");
        if (snapshot.mode != SpreadSnapshot.Mode.SPREAD
            || !snapshot.writerReady || snapshot.writerAuthority == null
            || presenterRotation != 90 && presenterRotation != 270) {
            throw new IllegalArgumentException(
                "complete landscape writer authority is required"
            );
        }
        if (Math.abs(physicalCanvas.left) > INTEGER_TOLERANCE
            || Math.abs(physicalCanvas.top) > INTEGER_TOLERANCE) {
            throw new IllegalArgumentException(
                "native canvas must use physical screen origin"
            );
        }
        PageSlot active = snapshot.slotForPage(snapshot.activePageIndex);
        if (active == null || active.isBlank()) {
            throw new IllegalArgumentException("active page slot is missing");
        }
        RectD writable = intersection(
            active.screenBounds,
            active.contentBounds,
            physicalCanvas
        );
        int viewWidth = exactPixel(physicalCanvas.right, "canvas width");
        int viewHeight = exactPixel(physicalCanvas.bottom, "canvas height");
        int left = exactPixel(writable.left, "writable left");
        int top = exactPixel(writable.top, "writable top");
        int virtualWidth = exactPixel(writable.width(), "writable width");
        int virtualHeight = exactPixel(writable.height(), "writable height");
        int right = left + virtualWidth;
        int bottom = top + virtualHeight;
        if (viewWidth <= viewHeight || virtualWidth <= 0 || virtualHeight <= 0
            || left < 0 || top < 0 || right > viewWidth
            || bottom > viewHeight) {
            throw new IllegalArgumentException(
                "writer geometry escapes the landscape canvas"
            );
        }
        return new NativeWriterGeometry(
            presenterRotation,
            viewWidth,
            viewHeight,
            virtualWidth,
            virtualHeight,
            viewWidth - right,
            -top,
            new RectD(left, top, right, bottom)
        );
    }

    private static RectD intersection(RectD first, RectD second, RectD third) {
        double left = Math.max(first.left, Math.max(second.left, third.left));
        double top = Math.max(first.top, Math.max(second.top, third.top));
        double right = Math.min(
            first.right,
            Math.min(second.right, third.right)
        );
        double bottom = Math.min(
            first.bottom,
            Math.min(second.bottom, third.bottom)
        );
        if (!(right > left && bottom > top)) {
            throw new IllegalArgumentException(
                "active page has no writable physical content"
            );
        }
        return new RectD(left, top, right, bottom);
    }

    private static int exactPixel(double value, String label) {
        if (!Double.isFinite(value) || value < 0.0
            || value > Integer.MAX_VALUE) {
            throw new IllegalArgumentException("invalid " + label);
        }
        int rounded = (int) Math.round(value);
        if (Math.abs(value - rounded) > INTEGER_TOLERANCE) {
            throw new IllegalArgumentException(label + " is not pixel aligned");
        }
        return rounded;
    }
}
