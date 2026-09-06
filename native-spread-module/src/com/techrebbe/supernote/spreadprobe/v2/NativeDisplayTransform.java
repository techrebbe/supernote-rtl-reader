package com.techrebbe.supernote.spreadprobe.v2;

import java.util.Objects;

/** Exact affine form of Supernote's display-crop mapToOrigin contract. */
public final class NativeDisplayTransform {
    private static final double TOLERANCE = 1.0e-6;

    private NativeDisplayTransform() {}

    /**
     * Maps a coordinate in the stock full-screen displayed page back into
     * the original page bitmap. The padding calculation deliberately uses
     * Java's truncation-to-int, matching the inspected TrimmingUtil method.
     */
    public static Affine2D displayToOrigin(
        RectD visibleSource,
        RectD fullSource
    ) {
        Objects.requireNonNull(visibleSource, "visibleSource");
        Objects.requireNonNull(fullSource, "fullSource");
        requireContained(visibleSource, fullSource);
        if (sameBounds(visibleSource, fullSource)) {
            return Affine2D.identity();
        }
        double displayWidth = fullSource.width();
        double displayHeight = fullSource.height();
        double scale = Math.min(
            displayWidth / visibleSource.width(),
            displayHeight / visibleSource.height()
        );
        if (!Double.isFinite(scale) || scale <= 0.0) {
            throw new IllegalArgumentException("invalid native crop scale");
        }
        int paddingX = nativePadding(
            visibleSource.left - fullSource.left,
            displayWidth,
            visibleSource.width(),
            scale
        );
        int paddingY = nativePadding(
            visibleSource.top - fullSource.top,
            displayHeight,
            visibleSource.height(),
            scale
        );
        return new Affine2D(
            1.0 / scale,
            0.0,
            0.0,
            1.0 / scale,
            visibleSource.left - paddingX / scale,
            visibleSource.top - paddingY / scale
        );
    }

    /** Maps pixels of a cropped native bitmap into original-page pixels. */
    public static Affine2D croppedBitmapToOrigin(
        int bitmapWidth,
        int bitmapHeight,
        RectD visibleSource,
        RectD fullSource
    ) {
        if (bitmapWidth <= 0 || bitmapHeight <= 0) {
            throw new IllegalArgumentException("cropped bitmap has no size");
        }
        Objects.requireNonNull(visibleSource, "visibleSource");
        Objects.requireNonNull(fullSource, "fullSource");
        requireContained(visibleSource, fullSource);
        return new Affine2D(
            visibleSource.width() / bitmapWidth,
            0.0,
            0.0,
            visibleSource.height() / bitmapHeight,
            visibleSource.left,
            visibleSource.top
        );
    }

    private static int nativePadding(
        double leading,
        double displayExtent,
        double cropExtent,
        double scale
    ) {
        double remaining = displayExtent - cropExtent;
        if (Math.abs(remaining) <= TOLERANCE) return 0;
        double ratio = leading / remaining;
        double value = (displayExtent - cropExtent * scale) * ratio;
        if (!Double.isFinite(value)
            || value < Integer.MIN_VALUE || value > Integer.MAX_VALUE) {
            throw new IllegalArgumentException("native crop padding overflow");
        }
        return (int) value;
    }

    private static void requireContained(RectD inner, RectD outer) {
        if (inner.left < outer.left - TOLERANCE
            || inner.top < outer.top - TOLERANCE
            || inner.right > outer.right + TOLERANCE
            || inner.bottom > outer.bottom + TOLERANCE) {
            throw new IllegalArgumentException(
                "native crop escapes the original page"
            );
        }
    }

    private static boolean sameBounds(RectD first, RectD second) {
        return Math.abs(first.left - second.left) <= TOLERANCE
            && Math.abs(first.top - second.top) <= TOLERANCE
            && Math.abs(first.right - second.right) <= TOLERANCE
            && Math.abs(first.bottom - second.bottom) <= TOLERANCE;
    }
}
