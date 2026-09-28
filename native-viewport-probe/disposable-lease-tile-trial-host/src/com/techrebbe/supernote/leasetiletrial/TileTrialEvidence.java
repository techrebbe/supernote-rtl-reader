package com.techrebbe.supernote.leasetiletrial;

/** Pure-Java, one-shot evidence model for a synthetic tile, not lease admission. */
public final class TileTrialEvidence {
    public static final int ORIGINAL_COUNT = 9;
    public static final int TILE_INDEX = 1;
    public static final long EXPIRY_MS = 2000;
    public static final long MAX_BASELINE_AGE_MS = 1000;
    public enum Phase {
        WAIT_BASELINE, READY, ARMED, INSERTED, TEN_PAINTED,
        WAIT_NINE_PAINT, RESTORED, UNKNOWN
    }

    /** A structural cut may have an empty paint order; only actual frames have a revision. */
    public static final class Cut {
        public final Object root;
        public final Object[] children;
        public final Object[] parents;
        public final String[] evidence;
        public final Object[] painted;
        public final String scene;
        public final long paintRevision;
        public final long completedElapsedMs;

        public Cut(Object root, Object[] children, Object[] parents, String[] evidence,
                Object[] painted, String scene, long paintRevision, long completedElapsedMs) {
            if (root == null || children == null || parents == null || evidence == null
                    || painted == null || scene == null || scene.isEmpty()
                    || children.length != parents.length || children.length != evidence.length
                    || paintRevision < 0 || completedElapsedMs < 0) {
                throw new IllegalArgumentException("incomplete tile cut");
            }
            this.root = root;
            this.children = children.clone();
            this.parents = parents.clone();
            this.evidence = evidence.clone();
            this.painted = painted.clone();
            this.scene = scene;
            this.paintRevision = paintRevision;
            this.completedElapsedMs = completedElapsedMs;
        }

        public boolean completedPaint() {
            return paintRevision > 0 && completedElapsedMs > 0
                    && painted.length == children.length;
        }
    }

    private Phase phase = Phase.WAIT_BASELINE;
    private String reason = "PENDING";
    private Object activity;
    private Object root;
    private Object[] originals;
    private String[] originalEvidence;
    private String scene;
    private Object tile;
    private boolean attempted;
    private long baselinePaintRevision;
    private long tenPaintRevision;
    private long deadlineElapsedMs;

    public Phase phase() { return phase; }
    public String reason() { return reason; }
    public boolean attempted() { return attempted; }
    public long deadlineElapsedMs() { return deadlineElapsedMs; }
    public long baselinePaintRevision() { return baselinePaintRevision; }
    public long tenPaintRevision() { return tenPaintRevision; }

    public void onFrame(Object currentActivity, Cut frame) {
        if (phase == Phase.UNKNOWN) return;
        if (phase == Phase.WAIT_BASELINE) {
            if (!exactBaseline(frame)) return; // The first layout may still be settling.
            activity = currentActivity;
            root = frame.root;
            originals = frame.children.clone();
            originalEvidence = frame.evidence.clone();
            scene = frame.scene;
            baselinePaintRevision = frame.paintRevision;
            phase = Phase.READY;
            reason = "NINE_PAINTED_READY";
            return;
        }
        if (currentActivity != activity || frame == null || frame.root != root) {
            unknown("ACTIVITY_OR_ROOT_CHANGED");
            return;
        }
        if (attempted && phase != Phase.RESTORED
                && frame.completedElapsedMs >= deadlineElapsedMs) {
            unknown("FRAME_AFTER_DEADLINE");
            return;
        }
        if (phase == Phase.READY) {
            if (!sameNine(frame) || !exactPaintOrder(frame)) unknown("BASELINE_DRIFT");
            else baselinePaintRevision = frame.paintRevision;
        } else if (phase == Phase.ARMED || phase == Phase.INSERTED
                || phase == Phase.TEN_PAINTED) {
            if (!sameTen(frame) || !exactPaintOrder(frame)
                    || frame.paintRevision <= baselinePaintRevision) {
                unknown("TEN_PAINT_MISMATCH");
            } else {
                tenPaintRevision = frame.paintRevision;
                phase = Phase.TEN_PAINTED;
                reason = "TEN_PAINTED";
            }
        } else if (phase == Phase.WAIT_NINE_PAINT) {
            if (!sameNine(frame) || !exactPaintOrder(frame)
                    || tenPaintRevision <= baselinePaintRevision
                    || frame.paintRevision <= tenPaintRevision) {
                unknown("RESTORATION_PAINT_MISMATCH");
            } else {
                phase = Phase.RESTORED;
                reason = "EXACT_NINE_RESTORED_AFTER_TEN_PAINT";
            }
        } else if (phase == Phase.RESTORED) {
            if (!sameNine(frame) || !exactPaintOrder(frame)
                    || frame.paintRevision <= tenPaintRevision) {
                unknown("POST_RESTORATION_PAINT_DRIFT");
            }
        }
    }

    /** Called only after a successful app-owned Handler post, before add. */
    public boolean arm(Object currentActivity, Cut live, long nowElapsedMs) {
        if (phase != Phase.READY || attempted || currentActivity != activity
                || live == null || !sameNine(live)
                || live.paintRevision != baselinePaintRevision
                || !exactPaintOrder(live) || nowElapsedMs < live.completedElapsedMs
                || nowElapsedMs - live.completedElapsedMs > MAX_BASELINE_AGE_MS
                || nowElapsedMs > Long.MAX_VALUE - EXPIRY_MS) return false;
        attempted = true;
        deadlineElapsedMs = nowElapsedMs + EXPIRY_MS;
        phase = Phase.ARMED;
        reason = "EXPIRY_ARMED";
        return true;
    }

    public boolean onAdded(Object currentActivity, Object owned, Cut live) {
        if (phase != Phase.ARMED || currentActivity != activity || owned == null
                || owned == root || owned == activity) return false;
        for (Object original : originals) {
            if (owned == original) {
                unknown("OWNED_IS_ORIGINAL");
                return false;
            }
        }
        tile = owned;
        if (!sameTen(live)) { unknown("ADD_STRUCTURE_AMBIGUOUS"); return false; }
        phase = Phase.INSERTED;
        reason = "TEN_STRUCTURAL";
        return true;
    }

    public void onRemoved(Object currentActivity, Object owned, Cut live) {
        if ((phase != Phase.INSERTED && phase != Phase.TEN_PAINTED)
                || currentActivity != activity || owned != tile || !sameNine(live)) {
            unknown("REMOVE_STRUCTURE_AMBIGUOUS");
            return;
        }
        phase = Phase.WAIT_NINE_PAINT;
        reason = "NINE_STRUCTURAL_WAIT_PAINT";
    }

    public boolean expired(long nowElapsedMs) {
        return attempted && nowElapsedMs >= deadlineElapsedMs;
    }

    /** Only a scheduled add/remove layout that leaves all nine originals untouched is known. */
    public static boolean unchangedOriginalLayout(Cut before, Cut after,
            Object[] originals, boolean rootBoundsChanged) {
        if (rootBoundsChanged || before == null || after == null || originals == null
                || originals.length != ORIGINAL_COUNT || before.root != after.root
                || before.children.length != after.children.length
                || (before.children.length != ORIGINAL_COUNT
                        && before.children.length != ORIGINAL_COUNT + 1)
                || !before.scene.equals(after.scene)) return false;
        for (int i = 0; i < before.children.length; i++) {
            if (before.children[i] != after.children[i]
                    || before.parents[i] != after.parents[i]) return false;
        }
        for (int i = 0; i < ORIGINAL_COUNT; i++) {
            int foundAt = -1;
            for (int at = 0; at < before.children.length; at++) {
                if (before.children[at] == originals[i]) {
                    if (foundAt != -1) return false;
                    foundAt = at;
                }
            }
            if (foundAt < 0 || before.parents[foundAt] != before.root
                    || !before.evidence[foundAt].equals(after.evidence[foundAt])) return false;
        }
        return true;
    }

    public void unknown(String why) {
        if (phase == Phase.UNKNOWN) return;
        phase = Phase.UNKNOWN;
        reason = why == null || why.isEmpty() ? "UNKNOWN" : why;
    }

    private boolean exactBaseline(Cut cut) {
        if (cut == null || cut.children.length != ORIGINAL_COUNT
                || !exactPaintOrder(cut)) return false;
        for (int i = 0; i < ORIGINAL_COUNT; i++) {
            if (cut.children[i] == null || cut.parents[i] != cut.root
                    || cut.evidence[i] == null || cut.evidence[i].isEmpty()
                    || !uniqueAt(cut.children, i)) return false;
        }
        return true;
    }

    private boolean sameNine(Cut cut) {
        if (cut == null || cut.root != root || cut.children.length != ORIGINAL_COUNT
                || !scene.equals(cut.scene)) return false;
        for (int i = 0; i < ORIGINAL_COUNT; i++) {
            if (cut.children[i] != originals[i] || cut.parents[i] != root
                    || !originalEvidence[i].equals(cut.evidence[i])) return false;
        }
        return true;
    }

    private boolean sameTen(Cut cut) {
        if (cut == null || cut.root != root || cut.children.length != ORIGINAL_COUNT + 1
                || !scene.equals(cut.scene)
                || cut.children[TILE_INDEX] != tile || cut.parents[TILE_INDEX] != root
                || cut.evidence[TILE_INDEX] == null || cut.evidence[TILE_INDEX].isEmpty()) {
            return false;
        }
        for (int i = 0; i < ORIGINAL_COUNT; i++) {
            int at = i < TILE_INDEX ? i : i + 1;
            if (cut.children[at] != originals[i] || cut.parents[at] != root
                    || !originalEvidence[i].equals(cut.evidence[at])) return false;
        }
        return true;
    }

    private static boolean exactPaintOrder(Cut cut) {
        if (cut == null || !cut.completedPaint()) return false;
        for (int i = 0; i < cut.children.length; i++) {
            if (cut.painted[i] != cut.children[i]) return false;
        }
        return true;
    }

    private static boolean uniqueAt(Object[] values, int at) {
        for (int before = 0; before < at; before++) {
            if (values[before] == values[at]) return false;
        }
        return true;
    }
}
