package com.techrebbe.supernote.spreadprobe.v2;

import java.util.Objects;

/** One immutable authority snapshot consumed by every rendering/input tool. */
public final class SpreadSnapshot {
    public enum Mode { PORTRAIT, SPREAD }

    public final String documentId;
    public final long activityGeneration;
    public final long layoutGeneration;
    public final int pageCount;
    public final int activePageIndex;
    public final Mode mode;
    public final PageSlot leftOrFull;
    public final PageSlot right;
    public final NativeAuthority writerAuthority;
    public final boolean writerReady;

    public SpreadSnapshot(
        String documentId,
        long activityGeneration,
        long layoutGeneration,
        int pageCount,
        int activePageIndex,
        Mode mode,
        PageSlot leftOrFull,
        PageSlot right,
        NativeAuthority writerAuthority,
        boolean writerReady
    ) {
        this.documentId = Objects.requireNonNull(documentId, "documentId");
        if (documentId.isEmpty() || activityGeneration <= 0
            || layoutGeneration <= 0 || pageCount <= 0
            || activePageIndex < 0 || activePageIndex >= pageCount) {
            throw new IllegalArgumentException("invalid spread snapshot identity");
        }
        this.activityGeneration = activityGeneration;
        this.layoutGeneration = layoutGeneration;
        this.pageCount = pageCount;
        this.activePageIndex = activePageIndex;
        this.mode = Objects.requireNonNull(mode, "mode");
        this.leftOrFull = Objects.requireNonNull(leftOrFull, "leftOrFull");
        this.right = right;
        this.writerAuthority = writerAuthority;
        this.writerReady = writerReady;
        validate();
    }

    public PageSlot slotForPage(int pageIndex) {
        if (pageIndex >= 0 && leftOrFull.sourcePageIndex == pageIndex) {
            return leftOrFull;
        }
        if (pageIndex >= 0 && right != null
            && right.sourcePageIndex == pageIndex) {
            return right;
        }
        return null;
    }

    public PageSlot slotAt(double x, double y) {
        if (leftOrFull.containsScreen(x, y)) {
            return leftOrFull;
        }
        if (right != null && right.containsScreen(x, y)) {
            return right;
        }
        return null;
    }

    public boolean sameAuthorityEpoch(SpreadSnapshot other) {
        return other != null
            && documentId.equals(other.documentId)
            && activityGeneration == other.activityGeneration
            && layoutGeneration == other.layoutGeneration;
    }

    private void validate() {
        if (mode == Mode.PORTRAIT) {
            if (leftOrFull.side != PageSlot.Side.FULL || right != null
                || leftOrFull.sourcePageIndex != activePageIndex) {
                throw new IllegalArgumentException("invalid portrait surface");
            }
        } else {
            if (leftOrFull.side != PageSlot.Side.LEFT || right == null
                || right.side != PageSlot.Side.RIGHT
                || (leftOrFull.isBlank() && right.isBlank())
                || (!leftOrFull.isBlank() && !right.isBlank()
                    && leftOrFull.sourcePageIndex == right.sourcePageIndex)
                || leftOrFull.screenBounds.overlaps(right.screenBounds)
                || leftOrFull.screenBounds.right
                    > right.screenBounds.left
                || slotForPage(activePageIndex) == null) {
                throw new IllegalArgumentException("invalid spread surfaces");
            }
        }
        if (leftOrFull.sourcePageIndex >= pageCount
            || (right != null && right.sourcePageIndex >= pageCount)) {
            throw new IllegalArgumentException("visible page outside document");
        }
        if (writerReady) {
            if (writerAuthority == null || !writerAuthority.matches(
                documentId,
                activityGeneration,
                layoutGeneration,
                activePageIndex
            )) {
                throw new IllegalArgumentException("writer authority is stale");
            }
        } else if (writerAuthority != null) {
            throw new IllegalArgumentException(
                "unready writer authority must not be published"
            );
        }
    }
}
