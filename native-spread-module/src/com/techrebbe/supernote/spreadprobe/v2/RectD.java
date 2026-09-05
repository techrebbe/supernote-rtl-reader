package com.techrebbe.supernote.spreadprobe.v2;

import java.util.Objects;

/** Immutable half-open rectangle: [left,right) x [top,bottom). */
public final class RectD {
    public final double left;
    public final double top;
    public final double right;
    public final double bottom;

    public RectD(double left, double top, double right, double bottom) {
        if (!Double.isFinite(left) || !Double.isFinite(top)
            || !Double.isFinite(right) || !Double.isFinite(bottom)) {
            throw new IllegalArgumentException("rectangle coordinates must be finite");
        }
        if (!(right > left) || !(bottom > top)) {
            throw new IllegalArgumentException("rectangle must have positive area");
        }
        this.left = left;
        this.top = top;
        this.right = right;
        this.bottom = bottom;
    }

    public double width() {
        return right - left;
    }

    public double height() {
        return bottom - top;
    }

    public boolean contains(double x, double y) {
        return Double.isFinite(x) && Double.isFinite(y)
            && x >= left && x < right && y >= top && y < bottom;
    }

    public boolean overlaps(RectD other) {
        Objects.requireNonNull(other, "other");
        return left < other.right && right > other.left
            && top < other.bottom && bottom > other.top;
    }

    public boolean contains(PointD point, double tolerance) {
        Objects.requireNonNull(point, "point");
        if (!Double.isFinite(tolerance) || tolerance < 0.0) {
            throw new IllegalArgumentException("invalid tolerance");
        }
        return point.x >= left - tolerance && point.x <= right + tolerance
            && point.y >= top - tolerance && point.y <= bottom + tolerance;
    }
}
