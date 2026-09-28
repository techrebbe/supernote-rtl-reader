package com.techrebbe.supernote.leasetrial;

import java.util.IdentityHashMap;

/** Pure-Java proof for one no-child, real-layout emulator trial. */
public final class TrialEvidence {
    public static final int ORIGINAL_COUNT = 9;
    public static final long DEADLINE_MS = 5000;
    public static final long BASELINE_FRESHNESS_MS = 2000;
    public static final long SECOND_SAMPLE_GAP_MS = 25;
    public static final long MAX_SECOND_SAMPLE_GAP_MS = 1000;

    public enum State { WAIT_LAYOUT, WAIT_PAINT, WAIT_SECOND_SAMPLE, PASS, UNKNOWN }

    public static final class Cut {
        public final Object root;
        private final Object[] children;
        private final Object[] parents;
        private final String[] childEvidence;
        private final Object[] effectivePaintOrder;
        public final String scene;
        public final long mutationRevision;
        public final long startedPaintRevision;
        public final long completedPaintRevision;
        public final long completedPaintElapsedMs;

        public Cut(Object root, Object[] children, Object[] parents,
                String[] childEvidence, Object[] effectivePaintOrder, String scene,
                long mutationRevision, long startedPaintRevision,
                long completedPaintRevision, long completedPaintElapsedMs) {
            if (root == null || children == null || parents == null
                    || childEvidence == null || effectivePaintOrder == null
                    || scene == null || scene.isEmpty()
                    || children.length != ORIGINAL_COUNT
                    || parents.length != ORIGINAL_COUNT
                    || childEvidence.length != ORIGINAL_COUNT
                    || effectivePaintOrder.length != ORIGINAL_COUNT
                    || mutationRevision < 0 || startedPaintRevision < 0
                    || completedPaintRevision < 0 || completedPaintElapsedMs < 0) {
                throw new IllegalArgumentException("incomplete nine-child evidence");
            }
            this.root = root;
            this.children = children.clone();
            this.parents = parents.clone();
            this.childEvidence = childEvidence.clone();
            this.effectivePaintOrder = effectivePaintOrder.clone();
            this.scene = scene;
            this.mutationRevision = mutationRevision;
            this.startedPaintRevision = startedPaintRevision;
            this.completedPaintRevision = completedPaintRevision;
            this.completedPaintElapsedMs = completedPaintElapsedMs;
        }

        public Object childAt(int index) { return children[index]; }
        public Object parentAt(int index) { return parents[index]; }
        public String childEvidenceAt(int index) { return childEvidence[index]; }
        public Object paintedAt(int index) { return effectivePaintOrder[index]; }
        public Object[] childrenCopy() { return children.clone(); }
        public Object[] parentsCopy() { return parents.clone(); }
        public String[] childEvidenceCopy() { return childEvidence.clone(); }

        public boolean exactNinePainted() {
            if (completedPaintRevision <= 0
                    || completedPaintRevision != startedPaintRevision
                    || completedPaintElapsedMs <= 0) return false;
            IdentityHashMap<Object, Boolean> seen = new IdentityHashMap<>();
            for (int i = 0; i < ORIGINAL_COUNT; i++) {
                if (children[i] == null || parents[i] != root
                        || childEvidence[i] == null || childEvidence[i].isEmpty()
                        || seen.put(children[i], Boolean.TRUE) != null
                        || effectivePaintOrder[i] != children[i]) return false;
            }
            return true;
        }

        public boolean sameNine(Cut other) {
            if (other == null || root != other.root || !scene.equals(other.scene)) return false;
            for (int i = 0; i < ORIGINAL_COUNT; i++) {
                if (children[i] != other.children[i] || parents[i] != other.parents[i]
                        || childEvidence[i] == null
                        || !childEvidence[i].equals(other.childEvidence[i])) return false;
            }
            return true;
        }

        public boolean sameNineAndRevision(Cut other) {
            return sameNine(other) && mutationRevision == other.mutationRevision;
        }
    }

    private final Cut baseline;
    private final long deadlineElapsedMs;
    private State state = State.WAIT_LAYOUT;
    private String reason = "PENDING";
    private Cut layoutEntry;
    private Cut laterPaint;
    private Cut secondSample;
    private int layoutCalls;

    private TrialEvidence(Cut baseline, long deadlineElapsedMs) {
        this.baseline = baseline;
        this.deadlineElapsedMs = deadlineElapsedMs;
    }

    public static TrialEvidence begin(Cut baseline, long nowElapsedMs) {
        if (baseline == null || !baseline.exactNinePainted()
                || nowElapsedMs < baseline.completedPaintElapsedMs
                || nowElapsedMs - baseline.completedPaintElapsedMs > BASELINE_FRESHNESS_MS
                || nowElapsedMs > Long.MAX_VALUE - DEADLINE_MS) {
            throw new IllegalStateException("fresh actual nine-child paint required");
        }
        return new TrialEvidence(baseline, nowElapsedMs + DEADLINE_MS);
    }

    /** Called only from the root's actual onLayout callback, before any child layout. */
    public boolean onLayout(Cut entry, boolean changed, boolean childRequestedLayout,
            long nowElapsedMs) {
        layoutCalls++;
        if (state != State.WAIT_LAYOUT || layoutCalls != 1
                || nowElapsedMs >= deadlineElapsedMs || changed || childRequestedLayout
                || entry == null || !baseline.sameNineAndRevision(entry)
                || entry.startedPaintRevision != baseline.startedPaintRevision
                || entry.completedPaintRevision != baseline.completedPaintRevision
                || entry.completedPaintElapsedMs != baseline.completedPaintElapsedMs
                || !entry.exactNinePainted()) {
            unknown("LAYOUT_NOT_NOOP_OR_BASELINE_STALE");
            return false;
        }
        layoutEntry = entry;
        state = State.WAIT_PAINT;
        return true;
    }

    /** The caller must supply a frame completed by real dispatchDraw/drawChild calls. */
    public void onCompletedPaint(Cut frame, long nowElapsedMs) {
        if (state != State.WAIT_PAINT) return;
        if (nowElapsedMs >= deadlineElapsedMs || frame == null
                || !frame.exactNinePainted()
                || !baseline.sameNineAndRevision(frame)
                || frame.startedPaintRevision <= baseline.startedPaintRevision
                || frame.completedPaintElapsedMs < layoutEntry.completedPaintElapsedMs
                || frame.completedPaintElapsedMs > nowElapsedMs) {
            unknown("POST_LAYOUT_PAINT_MISMATCH");
            return;
        }
        laterPaint = frame;
        state = State.WAIT_SECOND_SAMPLE;
    }

    /** A separate later sample verifies no child, scene, or paint change after the pass. */
    public void onSecondSample(Cut live, long nowElapsedMs) {
        if (state != State.WAIT_SECOND_SAMPLE) return;
        if (nowElapsedMs < laterPaint.completedPaintElapsedMs + SECOND_SAMPLE_GAP_MS) return;
        if (nowElapsedMs >= deadlineElapsedMs
                || nowElapsedMs - laterPaint.completedPaintElapsedMs
                        > MAX_SECOND_SAMPLE_GAP_MS
                || live == null || !live.exactNinePainted()
                || !laterPaint.sameNineAndRevision(live)
                || live.startedPaintRevision != laterPaint.startedPaintRevision
                || live.completedPaintRevision != laterPaint.completedPaintRevision
                || live.completedPaintElapsedMs != laterPaint.completedPaintElapsedMs) {
            unknown("ROLLBACK_SAMPLE_UNSTABLE");
            return;
        }
        secondSample = live;
        reason = "EXACT_NINE_NO_CHILD_VERIFIED";
        state = State.PASS;
    }

    public void expire(long nowElapsedMs) {
        if (nowElapsedMs >= deadlineElapsedMs && state != State.PASS
                && state != State.UNKNOWN) unknown("TRIAL_TIMEOUT");
    }

    public void unknown(String why) {
        if (state == State.PASS || state == State.UNKNOWN) return;
        reason = why == null || why.isEmpty() ? "UNKNOWN" : why;
        state = State.UNKNOWN;
    }

    public State state() { return state; }
    public String reason() { return reason; }
    public Cut baseline() { return baseline; }
    public Cut layoutEntry() { return layoutEntry; }
    public Cut laterPaint() { return laterPaint; }
    public Cut secondSample() { return secondSample; }
    public int layoutCalls() { return layoutCalls; }
    public long deadlineElapsedMs() { return deadlineElapsedMs; }
    public boolean rollbackVerified() { return state == State.PASS && secondSample != null; }
}
