package com.techrebbe.supernote.virtualspread;

import java.util.ArrayDeque;

/** Pure, device-independent RTL half-page navigation. */
public final class VirtualSpreadNavigation {
    public enum Half {
        LEFT,
        RIGHT
    }

    public enum Kind {
        SAME_SPREAD,
        OTHER_SPREAD,
        BOUNDARY
    }

    public static final class Spread {
        public final boolean hasLeft;
        public final boolean hasRight;

        public Spread(boolean hasLeft, boolean hasRight) {
            this.hasLeft = hasLeft;
            this.hasRight = hasRight;
        }

        public boolean has(Half half) {
            return half == Half.LEFT ? hasLeft : hasRight;
        }
    }

    public static final class Plan {
        public final Kind kind;
        public final int targetPage;
        public final Half targetHalf;

        private Plan(Kind kind, int targetPage, Half targetHalf) {
            this.kind = kind;
            this.targetPage = targetPage;
            this.targetHalf = targetHalf;
        }

        public static Plan same(int page, Half half) {
            return new Plan(Kind.SAME_SPREAD, page, half);
        }

        public static Plan other(int page, Half half) {
            return new Plan(Kind.OTHER_SPREAD, page, half);
        }

        public static Plan boundary(int page, Half half) {
            return new Plan(Kind.BOUNDARY, page, half);
        }
    }

    /** Enabled state for Supernote's physical previous/next buttons. */
    public static final class PageBarState {
        public final boolean previousEnabled;
        public final boolean nextEnabled;

        private PageBarState(
            boolean previousEnabled,
            boolean nextEnabled
        ) {
            this.previousEnabled = previousEnabled;
            this.nextEnabled = nextEnabled;
        }
    }

    /** Manifest record used to recover a link's intended target half. */
    public static final class LinkTarget {
        public final int sourcePage;
        public final int targetPage;
        public final Half sourceHalf;
        public final Half targetHalf;
        public final float x0;
        public final float y0;
        public final float x1;
        public final float y1;

        public LinkTarget(
            int sourcePage,
            int targetPage,
            Half sourceHalf,
            Half targetHalf,
            float x0,
            float y0,
            float x1,
            float y1
        ) {
            this.sourcePage = sourcePage;
            this.targetPage = targetPage;
            this.sourceHalf = sourceHalf;
            this.targetHalf = targetHalf;
            this.x0 = x0;
            this.y0 = y0;
            this.x1 = x1;
            this.y1 = y1;
        }

        public LinkTarget(
            int sourcePage,
            int targetPage,
            Half targetHalf,
            float x0,
            float y0,
            float x1,
            float y1
        ) {
            this(
                sourcePage,
                targetPage,
                null,
                targetHalf,
                x0,
                y0,
                x1,
                y1
            );
        }
    }

    /** One successful native internal-link traversal. */
    public static final class LinkVisit {
        public final int sourcePage;
        public final Half sourceHalf;
        public final int targetPage;

        private LinkVisit(
            int sourcePage,
            Half sourceHalf,
            int targetPage
        ) {
            this.sourcePage = sourcePage;
            this.sourceHalf = sourceHalf;
            this.targetPage = targetPage;
        }
    }

    /**
     * Mirrors only the successful links observed in the current reader
     * process. Native BackLinkUtils remains the authoritative history owner.
     */
    public static final class LinkHistory {
        private final ArrayDeque<LinkVisit> visits = new ArrayDeque<>();

        public void record(
            int sourcePage,
            Half sourceHalf,
            int targetPage
        ) {
            if (sourcePage < 0 || targetPage < 0 || sourceHalf == null) {
                return;
            }
            visits.addFirst(new LinkVisit(
                sourcePage,
                sourceHalf,
                targetPage
            ));
        }

        public LinkVisit takeBack(int sourcePage, int targetPage) {
            LinkVisit candidate = visits.peekFirst();
            if (!matches(candidate, sourcePage, targetPage)) {
                visits.clear();
                return null;
            }
            return visits.removeFirst();
        }

        public LinkVisit takeOriginal(int sourcePage, int targetPage) {
            LinkVisit candidate = visits.peekLast();
            visits.clear();
            return matches(candidate, sourcePage, targetPage)
                ? candidate : null;
        }

        public void clear() {
            visits.clear();
        }

        public int size() {
            return visits.size();
        }

        private static boolean matches(
            LinkVisit visit,
            int sourcePage,
            int targetPage
        ) {
            return visit != null
                && visit.sourcePage == sourcePage
                && visit.targetPage == targetPage;
        }
    }

    private VirtualSpreadNavigation() {
    }

    public static int reverseLandscapeOffset(int nativeOffset) {
        return -nativeOffset;
    }

    /** True only when the persisted double geometry survives Android floats. */
    public static boolean runtimeGeometryIsRepresentable(
        double pageWidth,
        double pageHeight,
        double gutter
    ) {
        if (!finite(pageWidth) || !finite(pageHeight) || !finite(gutter)
            || pageWidth <= 0.0 || pageHeight <= 0.0 || gutter < 0.0) {
            return false;
        }
        double slotWidth = (pageWidth - gutter) / 2.0;
        float runtimeSlotWidth = (
            (float) pageWidth - (float) gutter
        ) / 2.0f;
        return runtimePositiveFloat(pageWidth)
            && runtimePositiveFloat(pageHeight)
            && runtimeNonnegativeFloat(gutter)
            && runtimePositiveFloat(slotWidth)
            && finite(runtimeSlotWidth)
            && runtimeSlotWidth > 0.0f;
    }

    /** True only when a link survives Android's top-down float conversion. */
    public static boolean runtimeRectIsRepresentable(
        double pageHeight,
        double x0,
        double y0,
        double x1,
        double y1
    ) {
        if (!finite(pageHeight) || pageHeight <= 0.0
            || !finite(x0) || !finite(y0) || !finite(x1) || !finite(y1)
            || x0 > x1 || y0 > y1) {
            return false;
        }
        float narrowedPageHeight = (float) pageHeight;
        float narrowedX0 = (float) x0;
        float narrowedY0 = (float) y0;
        float narrowedX1 = (float) x1;
        float narrowedY1 = (float) y1;
        float topDownY0 = narrowedPageHeight - narrowedY1;
        float topDownY1 = narrowedPageHeight - narrowedY0;
        return finite(narrowedPageHeight)
            && narrowedPageHeight > 0.0f
            && finite(narrowedX0)
            && finite(narrowedY0)
            && finite(narrowedX1)
            && finite(narrowedY1)
            && finite(topDownY0)
            && finite(topDownY1)
            && (x0 == x1 || narrowedX0 < narrowedX1)
            && (y0 == y1 || narrowedY0 < narrowedY1)
            && (y0 == y1 || topDownY0 < topDownY1);
    }

    private static boolean runtimePositiveFloat(double value) {
        if (!finite(value) || value <= 0.0) {
            return false;
        }
        float narrowed = (float) value;
        return finite(narrowed) && narrowed > 0.0f;
    }

    private static boolean runtimeNonnegativeFloat(double value) {
        if (!finite(value) || value < 0.0) {
            return false;
        }
        float narrowed = (float) value;
        return finite(narrowed)
            && (value == 0.0 ? narrowed == 0.0f : narrowed > 0.0f);
    }

    private static boolean finite(double value) {
        return !Double.isNaN(value) && !Double.isInfinite(value);
    }

    public static PageBarState pageBarState(
        Spread[] spreads,
        int currentPage,
        Half currentHalf,
        boolean portrait
    ) {
        if (spreads == null || spreads.length == 0
            || currentPage < 0 || currentPage >= spreads.length) {
            return new PageBarState(false, false);
        }
        if (!portrait) {
            return new PageBarState(
                currentPage < spreads.length - 1,
                currentPage > 0
            );
        }
        return new PageBarState(
            planPortrait(spreads, currentPage, currentHalf, -1).kind
                != Kind.BOUNDARY,
            planPortrait(spreads, currentPage, currentHalf, 1).kind
                != Kind.BOUNDARY
        );
    }

    public static Half matchLinkTarget(
        LinkTarget[] targets,
        int sourcePage,
        int targetPage,
        float x0,
        float y0,
        float x1,
        float y1,
        float pageHeight,
        float tolerance
    ) {
        LinkTarget target = matchLink(
            targets,
            sourcePage,
            targetPage,
            x0,
            y0,
            x1,
            y1,
            pageHeight,
            tolerance
        );
        return target == null ? null : target.targetHalf;
    }

    public static LinkTarget matchLink(
        LinkTarget[] targets,
        int sourcePage,
        int targetPage,
        float x0,
        float y0,
        float x1,
        float y1,
        float pageHeight,
        float tolerance
    ) {
        if (targets == null || !finite(tolerance) || tolerance < 0.0f
            || !finite(pageHeight) || pageHeight <= 0.0f
            || !finite(x0) || !finite(y0)
            || !finite(x1) || !finite(y1)
            || x0 > x1 || y0 > y1) {
            return null;
        }
        LinkTarget matched = null;
        for (LinkTarget target : targets) {
            if (target == null
                || target.sourcePage != sourcePage
                || target.targetPage != targetPage
                || target.targetHalf == null
                || !finite(target.x0) || !finite(target.y0)
                || !finite(target.x1) || !finite(target.y1)
                || target.x0 > target.x1 || target.y0 > target.y1) {
                continue;
            }
            // The manifest is bottom-up, while MuPDF reports top-down bounds.
            // Convert the manifest once and compare in MuPDF's coordinates;
            // converting the large native bounds back loses low Y bits.
            float expectedNativeY0 = pageHeight - target.y1;
            float expectedNativeY1 = pageHeight - target.y0;
            if (!finite(expectedNativeY0) || !finite(expectedNativeY1)
                || (target.y0 < target.y1
                    && expectedNativeY0 >= expectedNativeY1)
                || Math.abs(target.x0 - x0) > tolerance
                || Math.abs(expectedNativeY0 - y0) > tolerance
                || Math.abs(target.x1 - x1) > tolerance
                || Math.abs(expectedNativeY1 - y1) > tolerance) {
                continue;
            }
            if (matched != null
                && (matched.targetHalf != target.targetHalf
                    || matched.sourceHalf != target.sourceHalf)) {
                return null;
            }
            matched = target;
        }
        return matched;
    }

    /**
     * Best-effort recovery for native history created before this process.
     * It fails closed if matching links originate on both halves.
     */
    public static Half inferLinkSourceHalf(
        LinkTarget[] targets,
        int sourcePage,
        int targetPage
    ) {
        if (targets == null) {
            return null;
        }
        Half matched = null;
        for (LinkTarget target : targets) {
            if (target == null
                || target.sourcePage != sourcePage
                || target.targetPage != targetPage
                || target.sourceHalf == null) {
                continue;
            }
            if (matched != null && matched != target.sourceHalf) {
                return null;
            }
            matched = target.sourceHalf;
        }
        return matched;
    }

    private static boolean finite(float value) {
        return !Float.isNaN(value) && !Float.isInfinite(value);
    }

    public static Half firstReadableHalf(Spread spread) {
        if (spread != null && spread.hasRight) {
            return Half.RIGHT;
        }
        return Half.LEFT;
    }

    public static Half lastReadableHalf(Spread spread) {
        if (spread != null && spread.hasLeft) {
            return Half.LEFT;
        }
        return Half.RIGHT;
    }

    /**
     * Plans source-page reading order for an RTL virtual-spread document.
     * A physical rightward gesture arrives from Supernote as a negative offset.
     */
    public static Plan planPortrait(
        Spread[] spreads,
        int currentPage,
        Half currentHalf,
        int nativeOffset
    ) {
        if (spreads == null || spreads.length == 0
            || currentPage < 0 || currentPage >= spreads.length
            || nativeOffset == 0) {
            return Plan.boundary(currentPage, currentHalf);
        }

        Spread current = spreads[currentPage];
        Half normalized = normalize(current, currentHalf);
        boolean forward = nativeOffset < 0;

        if (forward) {
            if (normalized == Half.RIGHT && current.hasLeft) {
                return Plan.same(currentPage, Half.LEFT);
            }
            for (int page = currentPage + 1; page < spreads.length; page++) {
                if (hasAny(spreads[page])) {
                    return Plan.other(page, firstReadableHalf(spreads[page]));
                }
            }
        } else {
            if (normalized == Half.LEFT && current.hasRight) {
                return Plan.same(currentPage, Half.RIGHT);
            }
            for (int page = currentPage - 1; page >= 0; page--) {
                if (hasAny(spreads[page])) {
                    return Plan.other(page, lastReadableHalf(spreads[page]));
                }
            }
        }
        return Plan.boundary(currentPage, normalized);
    }

    private static Half normalize(Spread spread, Half requested) {
        if (spread == null) {
            return requested == null ? Half.RIGHT : requested;
        }
        if (requested != null && spread.has(requested)) {
            return requested;
        }
        return firstReadableHalf(spread);
    }

    private static boolean hasAny(Spread spread) {
        return spread != null && (spread.hasLeft || spread.hasRight);
    }
}
