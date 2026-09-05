package com.techrebbe.supernote.spreadprobe.v2;

/** Pure zero-based pairing logic. A value of -1 represents a virtual blank. */
public final class SpreadPairing {
    public enum Direction { RTL, LTR }

    public static final class Pair {
        public final int leftPage;
        public final int rightPage;

        private Pair(int leftPage, int rightPage) {
            this.leftPage = leftPage;
            this.rightPage = rightPage;
        }

        public boolean contains(int page) {
            return leftPage == page || rightPage == page;
        }
    }

    private SpreadPairing() {}

    public static Pair forPage(
        int pageIndex,
        int pageCount,
        Direction direction,
        boolean coverSeparate
    ) {
        if (pageCount <= 0 || pageIndex < 0 || pageIndex >= pageCount
            || direction == null) {
            throw new IllegalArgumentException("invalid page pairing request");
        }
        int first;
        int second;
        if (coverSeparate && pageIndex == 0) {
            first = 0;
            second = -1;
        } else {
            int offset = coverSeparate ? 1 : 0;
            first = offset + ((pageIndex - offset) / 2) * 2;
            second = first + 1 < pageCount ? first + 1 : -1;
        }
        if (direction == Direction.RTL) {
            return new Pair(second, first);
        }
        return new Pair(first, second);
    }
}
