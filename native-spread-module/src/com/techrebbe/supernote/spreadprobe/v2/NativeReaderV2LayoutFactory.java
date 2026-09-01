package com.techrebbe.supernote.spreadprobe.v2;

import java.util.Objects;

/** Builds one immutable spread from original-page dimensions only. */
public final class NativeReaderV2LayoutFactory {
    public interface PageGeometrySource {
        RectD sourceBox(int zeroBasedPageIndex);
    }

    private NativeReaderV2LayoutFactory() {}

    public static SpreadSnapshot landscape(
        String documentId,
        long activityGeneration,
        long layoutGeneration,
        int pageCount,
        int activePageIndex,
        RectD nativeCanvas,
        double dividerWidth,
        NativeReaderV2Config config,
        PageGeometrySource pages,
        NativeAuthority writerAuthority,
        boolean writerReady
    ) {
        Objects.requireNonNull(config, "config");
        Objects.requireNonNull(pages, "pages");
        Objects.requireNonNull(nativeCanvas, "nativeCanvas");
        if (!config.enabled || dividerWidth < 0.0
            || !Double.isFinite(dividerWidth)
            || dividerWidth >= nativeCanvas.width()) {
            throw new IllegalArgumentException("invalid spread layout request");
        }
        SpreadPairing.Pair pair = SpreadPairing.forPage(
            activePageIndex,
            pageCount,
            config.direction,
            config.coverSeparate
        );
        double half = nativeCanvas.left + nativeCanvas.width() / 2.0;
        double halfDivider = dividerWidth / 2.0;
        RectD leftPhysical = new RectD(
            nativeCanvas.left,
            nativeCanvas.top,
            half - halfDivider,
            nativeCanvas.bottom
        );
        RectD rightPhysical = new RectD(
            half + halfDivider,
            nativeCanvas.top,
            nativeCanvas.right,
            nativeCanvas.bottom
        );
        PageProjectionFactory.Sizing sizing =
            config.sizing == NativeReaderV2Config.Sizing.NATIVE_FILL
                ? PageProjectionFactory.Sizing.FILL
                : PageProjectionFactory.Sizing.FIT;
        PageSlot left = slot(
            pair.leftPage,
            PageSlot.Side.LEFT,
            leftPhysical,
            nativeCanvas,
            pages,
            sizing
        );
        PageSlot right = slot(
            pair.rightPage,
            PageSlot.Side.RIGHT,
            rightPhysical,
            nativeCanvas,
            pages,
            sizing
        );
        return new SpreadSnapshot(
            documentId,
            activityGeneration,
            layoutGeneration,
            pageCount,
            activePageIndex,
            SpreadSnapshot.Mode.SPREAD,
            left,
            right,
            writerAuthority,
            writerReady
        );
    }

    private static PageSlot slot(
        int pageIndex,
        PageSlot.Side side,
        RectD physicalSlot,
        RectD nativeCanvas,
        PageGeometrySource pages,
        PageProjectionFactory.Sizing sizing
    ) {
        if (pageIndex < 0) {
            return PageSlot.blank(side, physicalSlot);
        }
        RectD source = Objects.requireNonNull(
            pages.sourceBox(pageIndex),
            "source page geometry"
        );
        Affine2D fullPage = fit(source, nativeCanvas);
        return PageProjectionFactory.landscapeSlot(
            pageIndex,
            side,
            source,
            nativeCanvas,
            fullPage,
            physicalSlot,
            sizing
        );
    }

    private static Affine2D fit(RectD source, RectD destination) {
        double scale = Math.min(
            destination.width() / source.width(),
            destination.height() / source.height()
        );
        if (!Double.isFinite(scale) || scale <= 0.0) {
            throw new IllegalArgumentException("invalid source-page geometry");
        }
        double left = destination.left
            + (destination.width() - source.width() * scale) / 2.0;
        double top = destination.top
            + (destination.height() - source.height() * scale) / 2.0;
        return new Affine2D(
            scale,
            0.0,
            0.0,
            scale,
            left - source.left * scale,
            top - source.top * scale
        );
    }
}
