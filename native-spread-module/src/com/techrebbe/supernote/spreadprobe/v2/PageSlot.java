package com.techrebbe.supernote.spreadprobe.v2;

import java.util.Objects;

public final class PageSlot {
    public enum Side { FULL, LEFT, RIGHT }

    public final int sourcePageIndex;
    public final Side side;
    public final RectD sourceBox;
    public final RectD screenBounds;
    public final RectD contentBounds;
    public final Affine2D sourceToScreen;

    public PageSlot(
        int sourcePageIndex,
        Side side,
        RectD sourceBox,
        RectD screenBounds,
        Affine2D sourceToScreen
    ) {
        if (sourcePageIndex < 0) {
            throw new IllegalArgumentException("source page index must be zero-based");
        }
        this.sourcePageIndex = sourcePageIndex;
        this.side = Objects.requireNonNull(side, "side");
        this.sourceBox = Objects.requireNonNull(sourceBox, "sourceBox");
        this.screenBounds = Objects.requireNonNull(screenBounds, "screenBounds");
        this.sourceToScreen = Objects.requireNonNull(
            sourceToScreen,
            "sourceToScreen"
        );
        this.contentBounds = sourceToScreen.mapBounds(sourceBox);
        validateMappedCorners();
    }

    private PageSlot(Side side, RectD screenBounds) {
        if (side == Side.FULL) {
            throw new IllegalArgumentException("portrait cannot be a blank page");
        }
        this.sourcePageIndex = -1;
        this.side = Objects.requireNonNull(side, "side");
        this.sourceBox = null;
        this.screenBounds = Objects.requireNonNull(screenBounds, "screenBounds");
        this.sourceToScreen = null;
        this.contentBounds = null;
    }

    public static PageSlot blank(Side side, RectD screenBounds) {
        return new PageSlot(side, screenBounds);
    }

    public boolean isBlank() {
        return sourcePageIndex < 0;
    }

    public boolean containsScreen(double x, double y) {
        return screenBounds.contains(x, y);
    }

    public boolean containsContent(double x, double y) {
        if (contentBounds == null || !screenBounds.contains(x, y)
            || !contentBounds.contains(x, y)) {
            return false;
        }
        PointD source = sourceToScreen.derivedInverse().map(x, y);
        return sourceBox.contains(source.x, source.y);
    }

    public PointD mapToScreen(double sourceX, double sourceY) {
        requireSourcePage();
        return sourceToScreen.map(sourceX, sourceY);
    }

    public PointD mapToSource(double screenX, double screenY) {
        requireSourcePage();
        return sourceToScreen.derivedInverse().map(screenX, screenY);
    }

    private void requireSourcePage() {
        if (isBlank()) {
            throw new IllegalStateException("blank slot has no page transform");
        }
    }

    private void validateMappedCorners() {
        if (!contentBounds.overlaps(screenBounds)) {
            throw new IllegalArgumentException(
                "page transform does not intersect its physical slot"
            );
        }
    }
}
