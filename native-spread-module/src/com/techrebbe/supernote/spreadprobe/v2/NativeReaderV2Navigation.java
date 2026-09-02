package com.techrebbe.supernote.spreadprobe.v2;

/** Pure page-target selection; all actual navigation remains transactional. */
public final class NativeReaderV2Navigation {
    private static final double MINIMUM_SWIPE = 24.0;

    private NativeReaderV2Navigation() {}

    public static int swipeTarget(
        SpreadSnapshot snapshot,
        NativeReaderV2Config config,
        double deltaX,
        double deltaY
    ) {
        if (snapshot == null || config == null || !config.enabled
            || !Double.isFinite(deltaX) || !Double.isFinite(deltaY)) {
            return -1;
        }
        if (Math.abs(deltaX) < MINIMUM_SWIPE
            || Math.abs(deltaX) <= Math.abs(deltaY)) {
            return -1;
        }
        boolean forward = config.direction == SpreadPairing.Direction.RTL
            ? deltaX > 0.0 : deltaX < 0.0;
        if (snapshot.mode == SpreadSnapshot.Mode.PORTRAIT) {
            return bounded(
                snapshot.activePageIndex + (forward ? 1 : -1),
                snapshot.pageCount
            );
        }
        int lowest = Integer.MAX_VALUE;
        int highest = -1;
        for (PageSlot slot : new PageSlot[] {
            snapshot.leftOrFull,
            snapshot.right
        }) {
            if (slot != null && !slot.isBlank()) {
                lowest = Math.min(lowest, slot.sourcePageIndex);
                highest = Math.max(highest, slot.sourcePageIndex);
            }
        }
        int candidate = forward ? highest + 1 : lowest - 1;
        return bounded(candidate, snapshot.pageCount);
    }

    public static int offsetTarget(
        SpreadSnapshot snapshot,
        NativeReaderV2Config config,
        int nativeOffset
    ) {
        if (snapshot == null || config == null || !config.enabled
            || nativeOffset == 0) {
            return -1;
        }
        // DocumentViewModel.turnPage() already reports a physical gesture:
        // -1 is a rightward swipe and +1 is a leftward swipe. swipeTarget()
        // is the one authoritative place that applies reading direction.
        // Flipping RTL here as well would reverse it twice.
        double physicalDelta = nativeOffset > 0 ? -100.0 : 100.0;
        return swipeTarget(snapshot, config, physicalDelta, 0.0);
    }

    private static int bounded(int page, int pageCount) {
        return page >= 0 && page < pageCount ? page : -1;
    }
}
