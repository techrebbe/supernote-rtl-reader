package com.techrebbe.supernote.spreadprobe.v2;

import java.util.Objects;

/** Immutable PDF-style affine transform. The inverse is always derived. */
public final class Affine2D {
    private static final double MIN_RELATIVE_DETERMINANT = 1.0e-12;

    public final double a;
    public final double b;
    public final double c;
    public final double d;
    public final double e;
    public final double f;

    public Affine2D(
        double a,
        double b,
        double c,
        double d,
        double e,
        double f
    ) {
        requireFinite(a, "a");
        requireFinite(b, "b");
        requireFinite(c, "c");
        requireFinite(d, "d");
        requireFinite(e, "e");
        requireFinite(f, "f");
        double determinant = a * d - b * c;
        double linearNorm = Math.max(
            1.0,
            Math.max(Math.abs(a), Math.max(Math.abs(b),
                Math.max(Math.abs(c), Math.abs(d))))
        );
        if (!Double.isFinite(determinant)
            || Math.abs(determinant)
                <= MIN_RELATIVE_DETERMINANT * linearNorm * linearNorm) {
            throw new IllegalArgumentException("singular or unstable affine");
        }
        this.a = a;
        this.b = b;
        this.c = c;
        this.d = d;
        this.e = e;
        this.f = f;
    }

    public static Affine2D identity() {
        return new Affine2D(1.0, 0.0, 0.0, 1.0, 0.0, 0.0);
    }

    public static Affine2D fromAndroidMatrix(double[] values) {
        if (values == null || values.length != 9) {
            throw new IllegalArgumentException("Android matrix requires 9 values");
        }
        for (int index = 0; index < values.length; index++) {
            requireFinite(values[index], "matrix[" + index + "]");
        }
        if (Double.doubleToLongBits(values[6])
                != Double.doubleToLongBits(0.0)
            || Double.doubleToLongBits(values[7])
                != Double.doubleToLongBits(0.0)
            || Double.doubleToLongBits(values[8])
                != Double.doubleToLongBits(1.0)) {
            throw new IllegalArgumentException(
                "perspective Android matrices are unsupported"
            );
        }
        return new Affine2D(
            values[0],
            values[3],
            values[1],
            values[4],
            values[2],
            values[5]
        );
    }

    public PointD map(double x, double y) {
        requireFinite(x, "x");
        requireFinite(y, "y");
        return new PointD(a * x + c * y + e, b * x + d * y + f);
    }

    public Affine2D then(Affine2D next) {
        Objects.requireNonNull(next, "next");
        return new Affine2D(
            next.a * a + next.c * b,
            next.b * a + next.d * b,
            next.a * c + next.c * d,
            next.b * c + next.d * d,
            next.a * e + next.c * f + next.e,
            next.b * e + next.d * f + next.f
        );
    }

    public Affine2D derivedInverse() {
        double determinant = a * d - b * c;
        return new Affine2D(
            d / determinant,
            -b / determinant,
            -c / determinant,
            a / determinant,
            (c * f - d * e) / determinant,
            (b * e - a * f) / determinant
        );
    }

    public RectD mapBounds(RectD source) {
        Objects.requireNonNull(source, "source");
        PointD[] corners = new PointD[] {
            map(source.left, source.top),
            map(source.right, source.top),
            map(source.left, source.bottom),
            map(source.right, source.bottom),
        };
        double left = corners[0].x;
        double right = corners[0].x;
        double top = corners[0].y;
        double bottom = corners[0].y;
        for (int index = 1; index < corners.length; index++) {
            left = Math.min(left, corners[index].x);
            right = Math.max(right, corners[index].x);
            top = Math.min(top, corners[index].y);
            bottom = Math.max(bottom, corners[index].y);
        }
        return new RectD(left, top, right, bottom);
    }

    private static void requireFinite(double value, String label) {
        if (!Double.isFinite(value)) {
            throw new IllegalArgumentException(label + " must be finite");
        }
    }

    @Override
    public boolean equals(Object value) {
        if (!(value instanceof Affine2D)) {
            return false;
        }
        Affine2D other = (Affine2D) value;
        return Double.doubleToLongBits(a) == Double.doubleToLongBits(other.a)
            && Double.doubleToLongBits(b) == Double.doubleToLongBits(other.b)
            && Double.doubleToLongBits(c) == Double.doubleToLongBits(other.c)
            && Double.doubleToLongBits(d) == Double.doubleToLongBits(other.d)
            && Double.doubleToLongBits(e) == Double.doubleToLongBits(other.e)
            && Double.doubleToLongBits(f) == Double.doubleToLongBits(other.f);
    }

    @Override
    public int hashCode() {
        return Objects.hash(a, b, c, d, e, f);
    }
}
