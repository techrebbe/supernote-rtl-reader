package com.techrebbe.supernote.spreadprobe.v2;

import java.util.Objects;

/** One authoritative PDF/page hit-test transform for the active native slot. */
public final class NativePageTransform {
    public final Affine2D ctm;
    public final Affine2D revertCtm;
    public final int offsetX;
    public final int offsetY;

    private NativePageTransform(
        Affine2D ctm,
        int offsetX,
        int offsetY
    ) {
        this.ctm = ctm;
        this.revertCtm = ctm.derivedInverse();
        this.offsetX = offsetX;
        this.offsetY = offsetY;
    }

    public static NativePageTransform from(
        Affine2D originalCtm,
        int originalOffsetX,
        int originalOffsetY,
        PageSlot activeSlot
    ) {
        return from(
            originalCtm,
            originalOffsetX,
            originalOffsetY,
            activeSlot,
            Affine2D.identity()
        );
    }

    public static NativePageTransform from(
        Affine2D originalCtm,
        int originalOffsetX,
        int originalOffsetY,
        PageSlot activeSlot,
        Affine2D displayToOrigin
    ) {
        Objects.requireNonNull(originalCtm, "originalCtm");
        Objects.requireNonNull(activeSlot, "activeSlot");
        Objects.requireNonNull(displayToOrigin, "displayToOrigin");
        if (activeSlot.isBlank()) {
            throw new IllegalArgumentException("blank slot has no page transform");
        }
        // Stock hit testing first applies TrimmingUtil.mapToOrigin() to the
        // physical touch and only then subtracts PageInfo's offset and applies
        // revertCtm. Therefore the installed PageInfo forward map must land in
        // that post-trimming coordinate space: original -> spread screen ->
        // stock mapToOrigin. Full-page fixtures make the last map identity and
        // cannot distinguish this order, so keep the cropped-page regression.
        Affine2D projection = activeSlot.sourceToScreen.then(
            displayToOrigin
        );
        double scaleX = projection.a;
        double scaleY = projection.d;
        if (scaleX <= 0.0 || scaleY <= 0.0
            || Math.abs(scaleX - scaleY) > 1.0e-6
            || Math.abs(projection.b) > 1.0e-9
            || Math.abs(projection.c) > 1.0e-9) {
            throw new IllegalArgumentException(
                "native PageInfo requires an axis-aligned uniform projection"
            );
        }
        Affine2D linearProjection = new Affine2D(
            projection.a,
            projection.b,
            projection.c,
            projection.d,
            0.0,
            0.0
        );
        Affine2D transformedCtm = originalCtm.then(linearProjection);
        PointD transformedOffset = projection.map(
            originalOffsetX,
            originalOffsetY
        );
        return new NativePageTransform(
            transformedCtm,
            exactRoundedInt(
                transformedOffset.x,
                "offsetX"
            ),
            exactRoundedInt(
                transformedOffset.y,
                "offsetY"
            )
        );
    }

    private static int exactRoundedInt(double value, String name) {
        if (!Double.isFinite(value)
            || value < Integer.MIN_VALUE || value > Integer.MAX_VALUE) {
            throw new IllegalArgumentException(name + " is outside native range");
        }
        return (int) Math.round(value);
    }
}
