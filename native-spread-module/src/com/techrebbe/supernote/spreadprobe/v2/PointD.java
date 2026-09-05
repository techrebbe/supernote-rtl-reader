package com.techrebbe.supernote.spreadprobe.v2;

import java.util.Objects;

public final class PointD {
    public final double x;
    public final double y;

    public PointD(double x, double y) {
        if (!Double.isFinite(x) || !Double.isFinite(y)) {
            throw new IllegalArgumentException("point coordinates must be finite");
        }
        this.x = x;
        this.y = y;
    }

    @Override
    public boolean equals(Object value) {
        if (!(value instanceof PointD)) {
            return false;
        }
        PointD other = (PointD) value;
        return Double.doubleToLongBits(x) == Double.doubleToLongBits(other.x)
            && Double.doubleToLongBits(y) == Double.doubleToLongBits(other.y);
    }

    @Override
    public int hashCode() {
        return Objects.hash(x, y);
    }
}
