package com.techrebbe.supernote.spreadprobe.v2;

import java.util.Objects;

/**
 * Derives both page slots from the native reader's observed full-page affine.
 * No tool is permitted to guess an independent fit or rotation.
 */
public final class PageProjectionFactory {
    private PageProjectionFactory() {}

    public static PageSlot portrait(
        int sourcePageIndex,
        RectD sourceBox,
        RectD nativeCanvas,
        Affine2D nativePageToCanvas
    ) {
        Objects.requireNonNull(nativeCanvas, "nativeCanvas");
        return new PageSlot(
            sourcePageIndex,
            PageSlot.Side.FULL,
            sourceBox,
            nativeCanvas,
            nativePageToCanvas
        );
    }

    public static PageSlot landscapeSlot(
        int sourcePageIndex,
        PageSlot.Side side,
        RectD sourceBox,
        RectD nativeCanvas,
        Affine2D nativePageToCanvas,
        RectD physicalSlot
    ) {
        if (side != PageSlot.Side.LEFT && side != PageSlot.Side.RIGHT) {
            throw new IllegalArgumentException("landscape side must be physical");
        }
        Objects.requireNonNull(sourceBox, "sourceBox");
        Objects.requireNonNull(nativeCanvas, "nativeCanvas");
        Objects.requireNonNull(nativePageToCanvas, "nativePageToCanvas");
        Objects.requireNonNull(physicalSlot, "physicalSlot");

        double slotTolerance = Math.max(
            0.5,
            Math.max(nativeCanvas.width(), nativeCanvas.height()) * 1.0e-9
        );
        if (!nativeCanvas.contains(
            new PointD(physicalSlot.left, physicalSlot.top),
            slotTolerance
        ) || !nativeCanvas.contains(
            new PointD(physicalSlot.right, physicalSlot.bottom),
            slotTolerance
        )) {
            throw new IllegalArgumentException(
                "physical slot escapes the native canvas"
            );
        }

        RectD nativePageBounds = nativePageToCanvas.mapBounds(sourceBox);
        double nativeTolerance = Math.max(
            0.5,
            Math.max(nativeCanvas.width(), nativeCanvas.height()) * 1.0e-9
        );
        if (!nativeCanvas.contains(
            new PointD(nativePageBounds.left, nativePageBounds.top),
            nativeTolerance
        ) || !nativeCanvas.contains(
            new PointD(nativePageBounds.right, nativePageBounds.bottom),
            nativeTolerance
        )) {
            throw new IllegalArgumentException(
                "native reader is not presenting a complete full page"
            );
        }

        double scale = Math.min(
            physicalSlot.width() / nativePageBounds.width(),
            physicalSlot.height() / nativePageBounds.height()
        );
        if (!Double.isFinite(scale) || scale <= 0.0) {
            throw new IllegalArgumentException("invalid landscape projection scale");
        }
        double translatedLeft = physicalSlot.left
            + (physicalSlot.width() - nativePageBounds.width() * scale) / 2.0;
        double translatedTop = physicalSlot.top
            + (physicalSlot.height() - nativePageBounds.height() * scale) / 2.0;
        Affine2D nativeCanvasToSlot = new Affine2D(
            scale,
            0.0,
            0.0,
            scale,
            translatedLeft - nativePageBounds.left * scale,
            translatedTop - nativePageBounds.top * scale
        );
        return new PageSlot(
            sourcePageIndex,
            side,
            sourceBox,
            physicalSlot,
            nativePageToCanvas.then(nativeCanvasToSlot)
        );
    }
}
