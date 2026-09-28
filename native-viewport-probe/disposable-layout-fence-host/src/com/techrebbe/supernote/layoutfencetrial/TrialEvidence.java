package com.techrebbe.supernote.layoutfencetrial;

import java.util.IdentityHashMap;
import java.util.Arrays;

/** Pure-Java, path-scoped evidence. This never certifies complete mutation coverage. */
public final class TrialEvidence {
    public static final int ORIGINAL_COUNT = 9;
    public static final long DEADLINE_MS = 5000;
    public static final long BASELINE_FRESHNESS_MS = 2000;
    public static final long SECOND_SAMPLE_GAP_MS = 25;
    public static final long MAX_SECOND_SAMPLE_GAP_MS = 1000;

    public enum Command {
        PARENT_PLUS("parent-plus-one"),
        PARENT_MINUS("parent-minus-one"),
        UNCHANGED("unchanged-bounds"),
        DIRECT_LAYOUT("direct-root-layout"),
        DIRECT_OFFSET("direct-root-offset"),
        ABA("away-back-aba");

        public final String wire;
        Command(String wire) { this.wire = wire; }

        public static Command fromWire(String wire) {
            for (Command value : values()) if (value.wire.equals(wire)) return value;
            throw new IllegalArgumentException("unsupported one-shot command");
        }

        boolean parentFirst() {
            return this == PARENT_PLUS || this == PARENT_MINUS
                    || this == UNCHANGED || this == ABA;
        }

        boolean needsLaterRestore() {
            return this != UNCHANGED && this != ABA;
        }
    }

    public enum State {
        WAIT_FIRST_CALL, WAIT_ABA_RETURN, WAIT_FIRST_PAINT, WAIT_RESTORE_CALL,
        WAIT_RESTORE_PAINT, WAIT_SECOND_PAINT_REQUEST, WAIT_SECOND_PAINT,
        WAIT_FINAL_SAMPLE, PASS, UNKNOWN
    }

    public static final class Bounds {
        public final int left;
        public final int top;
        public final int right;
        public final int bottom;

        public Bounds(int left, int top, int right, int bottom) {
            if (right <= left || bottom <= top) throw new IllegalArgumentException("empty bounds");
            this.left = left;
            this.top = top;
            this.right = right;
            this.bottom = bottom;
        }

        public Bounds withRightDelta(int delta) {
            return new Bounds(left, top, right + delta, bottom);
        }

        public Bounds shiftedRight(int delta) {
            return new Bounds(left + delta, top, right + delta, bottom);
        }

        @Override public boolean equals(Object other) {
            if (!(other instanceof Bounds)) return false;
            Bounds value = (Bounds) other;
            return left == value.left && top == value.top
                    && right == value.right && bottom == value.bottom;
        }

        @Override public int hashCode() {
            int result = left;
            result = 31 * result + top;
            result = 31 * result + right;
            return 31 * result + bottom;
        }

        @Override public String toString() {
            return left + "," + top + "," + right + "," + bottom;
        }
    }

    /** An actual completed frame supplies its drawChild identity sequence. */
    public static final class Cut {
        public final Object root;
        public final String rootToken;
        public final String scene;
        public final Bounds bounds;
        public final int childCount;
        private final Object[] children;
        private final Object[] parents;
        private final String[] childEvidence;
        private final Object[] paintedOrder;
        public final long parentPreCallRevision;
        public final long observedWriteOrdinal;
        public final long rootLayoutCalls;
        public final long startedPaintRevision;
        public final long paintStartedElapsedMs;
        public final long paintStartParentRevision;
        public final long paintStartWriteOrdinal;
        public final long completedPaintRevision;
        public final long completedPaintElapsedMs;

        public Cut(Object root, String rootToken, String scene, Bounds bounds, int childCount,
                Object[] children, Object[] parents, String[] childEvidence,
                Object[] paintedOrder, long parentPreCallRevision,
                long observedWriteOrdinal, long rootLayoutCalls,
                long startedPaintRevision, long paintStartedElapsedMs,
                long paintStartParentRevision,
                long paintStartWriteOrdinal, long completedPaintRevision,
                long completedPaintElapsedMs) {
            if (root == null || rootToken == null || rootToken.isEmpty()
                    || scene == null || scene.isEmpty() || bounds == null
                    || children == null || parents == null || childEvidence == null
                    || paintedOrder == null || children.length != ORIGINAL_COUNT
                    || parents.length != ORIGINAL_COUNT
                    || childEvidence.length != ORIGINAL_COUNT
                    || paintedOrder.length != ORIGINAL_COUNT || childCount < 0
                    || parentPreCallRevision < 0 || observedWriteOrdinal < 0
                    || rootLayoutCalls < 0 || startedPaintRevision < 0
                    || paintStartedElapsedMs < 0
                    || paintStartParentRevision < 0 || paintStartWriteOrdinal < 0
                    || completedPaintRevision < 0 || completedPaintElapsedMs < 0) {
                throw new IllegalArgumentException("incomplete cut");
            }
            this.root = root;
            this.rootToken = rootToken;
            this.scene = scene;
            this.bounds = bounds;
            this.childCount = childCount;
            this.children = children.clone();
            this.parents = parents.clone();
            this.childEvidence = childEvidence.clone();
            this.paintedOrder = paintedOrder.clone();
            this.parentPreCallRevision = parentPreCallRevision;
            this.observedWriteOrdinal = observedWriteOrdinal;
            this.rootLayoutCalls = rootLayoutCalls;
            this.startedPaintRevision = startedPaintRevision;
            this.paintStartedElapsedMs = paintStartedElapsedMs;
            this.paintStartParentRevision = paintStartParentRevision;
            this.paintStartWriteOrdinal = paintStartWriteOrdinal;
            this.completedPaintRevision = completedPaintRevision;
            this.completedPaintElapsedMs = completedPaintElapsedMs;
        }

        public Object childAt(int index) { return children[index]; }
        public Object parentAt(int index) { return parents[index]; }
        public String childEvidenceAt(int index) { return childEvidence[index]; }
        public Object paintedAt(int index) { return paintedOrder[index]; }
        public Object[] childrenCopy() { return children.clone(); }
        public Object[] parentsCopy() { return parents.clone(); }
        public String[] childEvidenceCopy() { return childEvidence.clone(); }

        public boolean exactNinePainted() {
            if (childCount != ORIGINAL_COUNT || completedPaintRevision <= 0
                    || startedPaintRevision != completedPaintRevision
                    || completedPaintElapsedMs <= 0
                    || paintStartedElapsedMs <= 0
                    || paintStartedElapsedMs > completedPaintElapsedMs
                    || paintStartParentRevision != parentPreCallRevision
                    || paintStartWriteOrdinal != observedWriteOrdinal) return false;
            IdentityHashMap<Object, Boolean> seen = new IdentityHashMap<>();
            for (int i = 0; i < ORIGINAL_COUNT; i++) {
                if (children[i] == null || parents[i] != root
                        || childEvidence[i] == null || childEvidence[i].isEmpty()
                        || seen.put(children[i], Boolean.TRUE) != null
                        || paintedOrder[i] != children[i]) return false;
            }
            return true;
        }

        public boolean sameOriginals(Cut other) {
            if (other == null || root != other.root
                    || !rootToken.equals(other.rootToken)
                    || !scene.equals(other.scene) || childCount != ORIGINAL_COUNT
                    || other.childCount != ORIGINAL_COUNT) return false;
            for (int i = 0; i < ORIGINAL_COUNT; i++) {
                if (children[i] != other.children[i] || parents[i] != other.parents[i]
                        || childEvidence[i] == null
                        || !childEvidence[i].equals(other.childEvidence[i])) return false;
            }
            return true;
        }

        public boolean sameLiveFrame(Cut other) {
            return sameOriginals(other) && bounds.equals(other.bounds)
                    && parentPreCallRevision == other.parentPreCallRevision
                    && observedWriteOrdinal == other.observedWriteOrdinal
                    && rootLayoutCalls == other.rootLayoutCalls
                    && startedPaintRevision == other.startedPaintRevision
                    && paintStartedElapsedMs == other.paintStartedElapsedMs
                    && paintStartParentRevision == other.paintStartParentRevision
                    && paintStartWriteOrdinal == other.paintStartWriteOrdinal
                    && completedPaintRevision == other.completedPaintRevision
                    && completedPaintElapsedMs == other.completedPaintElapsedMs;
        }
    }

    /** Failure-only, fixed-size comparison of the cut immediately before restore. */
    public static final class RestoreEntryDiff {
        public static final class LongPair {
            public final long firstFrame;
            public final long entry;

            private LongPair(long firstFrame, long entry) {
                this.firstFrame = firstFrame;
                this.entry = entry;
            }
        }

        public final boolean sameRoot;
        public final boolean sameRootToken;
        public final boolean sameScene;
        public final int firstChildCount;
        public final int entryChildCount;
        public final Bounds firstBounds;
        public final Bounds entryBounds;
        public final LongPair parentPreCallRevision;
        public final LongPair observedWriteOrdinal;
        public final LongPair rootLayoutCalls;
        public final LongPair startedPaintRevision;
        public final LongPair paintStartedElapsedMs;
        public final LongPair paintStartParentRevision;
        public final LongPair paintStartWriteOrdinal;
        public final LongPair completedPaintRevision;
        public final LongPair completedPaintElapsedMs;
        private final int[] childIdentityMismatchIndices;
        private final int[] parentIdentityMismatchIndices;
        private final int[] childEvidenceMismatchIndices;

        private RestoreEntryDiff(Cut firstFrame, Cut entry) {
            sameRoot = firstFrame.root == entry.root;
            sameRootToken = firstFrame.rootToken.equals(entry.rootToken);
            sameScene = firstFrame.scene.equals(entry.scene);
            firstChildCount = firstFrame.childCount;
            entryChildCount = entry.childCount;
            firstBounds = firstFrame.bounds;
            entryBounds = entry.bounds;
            parentPreCallRevision = pair(firstFrame.parentPreCallRevision,
                    entry.parentPreCallRevision);
            observedWriteOrdinal = pair(firstFrame.observedWriteOrdinal,
                    entry.observedWriteOrdinal);
            rootLayoutCalls = pair(firstFrame.rootLayoutCalls, entry.rootLayoutCalls);
            startedPaintRevision = pair(firstFrame.startedPaintRevision,
                    entry.startedPaintRevision);
            paintStartedElapsedMs = pair(firstFrame.paintStartedElapsedMs,
                    entry.paintStartedElapsedMs);
            paintStartParentRevision = pair(firstFrame.paintStartParentRevision,
                    entry.paintStartParentRevision);
            paintStartWriteOrdinal = pair(firstFrame.paintStartWriteOrdinal,
                    entry.paintStartWriteOrdinal);
            completedPaintRevision = pair(firstFrame.completedPaintRevision,
                    entry.completedPaintRevision);
            completedPaintElapsedMs = pair(firstFrame.completedPaintElapsedMs,
                    entry.completedPaintElapsedMs);

            int[] children = new int[ORIGINAL_COUNT];
            int[] parents = new int[ORIGINAL_COUNT];
            int[] evidence = new int[ORIGINAL_COUNT];
            int childDifferences = 0;
            int parentDifferences = 0;
            int evidenceDifferences = 0;
            for (int i = 0; i < ORIGINAL_COUNT; i++) {
                if (firstFrame.children[i] != entry.children[i]) {
                    children[childDifferences++] = i;
                }
                if (firstFrame.parents[i] != entry.parents[i]) {
                    parents[parentDifferences++] = i;
                }
                if (firstFrame.childEvidence[i] == null
                        || !firstFrame.childEvidence[i].equals(entry.childEvidence[i])) {
                    evidence[evidenceDifferences++] = i;
                }
            }
            childIdentityMismatchIndices = Arrays.copyOf(children, childDifferences);
            parentIdentityMismatchIndices = Arrays.copyOf(parents, parentDifferences);
            childEvidenceMismatchIndices = Arrays.copyOf(evidence, evidenceDifferences);
        }

        private static LongPair pair(long firstFrame, long entry) {
            return new LongPair(firstFrame, entry);
        }

        public int[] childIdentityMismatchIndices() {
            return childIdentityMismatchIndices.clone();
        }

        public int[] parentIdentityMismatchIndices() {
            return parentIdentityMismatchIndices.clone();
        }

        public int[] childEvidenceMismatchIndices() {
            return childEvidenceMismatchIndices.clone();
        }
    }

    /** A refresh is only an invalidate request; this proves a later completed paint. */
    public static boolean refreshedBaseline(Cut requestEntry, Cut completed, Cut live,
            long paintFloorRevision, long requestElapsedMs, long nowElapsedMs) {
        return requestEntry != null && completed != null && live != null
                && requestEntry.exactNinePainted() && completed.exactNinePainted()
                && completed.sameLiveFrame(live) && live.exactNinePainted()
                && requestEntry.sameOriginals(completed)
                && requestEntry.bounds.equals(completed.bounds)
                && requestEntry.parentPreCallRevision == completed.parentPreCallRevision
                && requestEntry.observedWriteOrdinal == completed.observedWriteOrdinal
                && requestEntry.rootLayoutCalls == completed.rootLayoutCalls
                && paintFloorRevision == requestEntry.startedPaintRevision
                && completed.startedPaintRevision > paintFloorRevision
                && completed.completedPaintRevision > requestEntry.completedPaintRevision
                && requestElapsedMs > 0
                && completed.paintStartedElapsedMs >= requestElapsedMs
                && completed.completedPaintElapsedMs >= requestElapsedMs
                && nowElapsedMs >= completed.completedPaintElapsedMs
                && nowElapsedMs - completed.completedPaintElapsedMs
                        <= BASELINE_FRESHNESS_MS;
    }

    public static final class Trial {
        private final Command command;
        private final Cut baseline;
        private final Bounds firstTarget;
        private final long deadlineElapsedMs;
        private State state = State.WAIT_FIRST_CALL;
        private String reason = "PENDING";
        private Cut pendingEntry;
        private Bounds pendingTarget;
        private long pendingRevision;
        private Cut abaAway;
        private Cut firstAfter;
        private Cut firstFrame;
        private Cut restoreAfter;
        private Cut restoredFrame;
        private Cut secondFrame;
        private Cut secondSample;
        private RestoreEntryDiff restoreEntryDrift;
        private long secondPaintRequestElapsedMs;
        private long secondPaintStartRevisionFloor;
        private boolean bypassObserved;

        private Trial(Command command, Cut baseline, long deadlineElapsedMs) {
            this.command = command;
            this.baseline = baseline;
            this.deadlineElapsedMs = deadlineElapsedMs;
            if (command == Command.PARENT_MINUS) firstTarget = baseline.bounds.withRightDelta(-1);
            else if (command == Command.DIRECT_OFFSET) firstTarget = baseline.bounds.shiftedRight(1);
            else if (command == Command.UNCHANGED) firstTarget = baseline.bounds;
            else firstTarget = baseline.bounds.withRightDelta(1);
        }

        public static Trial begin(Command command, Cut baseline, long nowElapsedMs) {
            if (command == null || baseline == null || !baseline.exactNinePainted()
                    || nowElapsedMs < baseline.completedPaintElapsedMs
                    || nowElapsedMs - baseline.completedPaintElapsedMs > BASELINE_FRESHNESS_MS
                    || nowElapsedMs > Long.MAX_VALUE - DEADLINE_MS) {
                throw new IllegalStateException("fresh completed nine-child baseline required");
            }
            return new Trial(command, baseline, nowElapsedMs + DEADLINE_MS);
        }

        /** Called after a parent-owned revision bump, but before root.layout. */
        public boolean onParentPreCall(Cut entry, Bounds proposed,
                long bumpedRevision, long nowElapsedMs) {
            if (!live(nowElapsedMs) || entry == null || proposed == null
                    || pendingEntry != null || bumpedRevision != entry.parentPreCallRevision + 1) {
                unknown("PARENT_PRECALL_NOT_EXCLUSIVE");
                return false;
            }
            Bounds expected;
            if (state == State.WAIT_FIRST_CALL && command.parentFirst()) {
                if (!baseline.sameLiveFrame(entry)) {
                    unknown("FIRST_ENTRY_NOT_BASELINE");
                    return false;
                }
                expected = firstTarget;
            } else if (state == State.WAIT_ABA_RETURN && command == Command.ABA) {
                if (abaAway == null || !abaAway.sameOriginals(entry)
                        || !abaAway.bounds.equals(entry.bounds)
                        || abaAway.parentPreCallRevision != entry.parentPreCallRevision
                        || abaAway.observedWriteOrdinal != entry.observedWriteOrdinal
                        || entry.startedPaintRevision != baseline.startedPaintRevision) {
                    unknown("ABA_RETURN_ENTRY_DRIFT");
                    return false;
                }
                expected = baseline.bounds;
            } else if (state == State.WAIT_RESTORE_CALL) {
                if (firstFrame == null || !firstFrame.sameLiveFrame(entry)) {
                    if (firstFrame != null && restoreEntryDrift == null) {
                        restoreEntryDrift = new RestoreEntryDiff(firstFrame, entry);
                    }
                    unknown("RESTORE_ENTRY_DRIFT");
                    return false;
                }
                expected = baseline.bounds;
            } else {
                unknown("UNEXPECTED_PARENT_PRECALL");
                return false;
            }
            if (!expected.equals(proposed)) {
                unknown("PARENT_TARGET_MISMATCH");
                return false;
            }
            pendingEntry = entry;
            pendingTarget = proposed;
            pendingRevision = bumpedRevision;
            return true;
        }

        public void onParentLayoutAfter(Cut after, long nowElapsedMs) {
            if (!live(nowElapsedMs) || pendingEntry == null || after == null
                    || !baseline.sameOriginals(after)
                    || !pendingTarget.equals(after.bounds)
                    || after.parentPreCallRevision != pendingRevision
                    || after.observedWriteOrdinal != pendingEntry.observedWriteOrdinal + 1
                    || after.startedPaintRevision != pendingEntry.startedPaintRevision
                    || after.completedPaintRevision != pendingEntry.completedPaintRevision
                    || after.completedPaintElapsedMs != pendingEntry.completedPaintElapsedMs
                    || after.rootLayoutCalls < pendingEntry.rootLayoutCalls
                    || after.rootLayoutCalls > pendingEntry.rootLayoutCalls + 1
                    || (!pendingTarget.equals(pendingEntry.bounds)
                        && after.rootLayoutCalls != pendingEntry.rootLayoutCalls + 1)) {
                unknown("PARENT_LAYOUT_AFTER_MISMATCH");
                return;
            }
            pendingEntry = null;
            pendingTarget = null;
            if (state == State.WAIT_FIRST_CALL) {
                if (command == Command.ABA) {
                    abaAway = after;
                    state = State.WAIT_ABA_RETURN;
                } else {
                    firstAfter = after;
                    state = State.WAIT_FIRST_PAINT;
                }
            } else if (state == State.WAIT_ABA_RETURN) {
                if (after.parentPreCallRevision != baseline.parentPreCallRevision + 2
                        || !after.bounds.equals(baseline.bounds)) {
                    unknown("ABA_REVISION_NOT_MONOTONIC");
                    return;
                }
                firstAfter = after;
                state = State.WAIT_FIRST_PAINT;
            } else if (state == State.WAIT_RESTORE_CALL) {
                restoreAfter = after;
                state = State.WAIT_RESTORE_PAINT;
            } else {
                unknown("PARENT_LAYOUT_STAGE_MISMATCH");
            }
        }

        /** Direct controls deliberately bypass the parent pre-call fence. */
        public void onDirectAfter(Cut before, Cut after, long nowElapsedMs) {
            if (!live(nowElapsedMs) || state != State.WAIT_FIRST_CALL
                    || (command != Command.DIRECT_LAYOUT && command != Command.DIRECT_OFFSET)
                    || before == null || after == null || !baseline.sameLiveFrame(before)
                    || !baseline.sameOriginals(after) || !firstTarget.equals(after.bounds)
                    || after.parentPreCallRevision != before.parentPreCallRevision
                    || after.observedWriteOrdinal != before.observedWriteOrdinal + 1
                    || after.startedPaintRevision != before.startedPaintRevision
                    || after.completedPaintRevision != before.completedPaintRevision
                    || after.completedPaintElapsedMs != before.completedPaintElapsedMs
                    || (command == Command.DIRECT_LAYOUT
                        && after.rootLayoutCalls != before.rootLayoutCalls + 1)
                    || (command == Command.DIRECT_OFFSET
                        && after.rootLayoutCalls != before.rootLayoutCalls)) {
                unknown("DIRECT_BYPASS_NOT_ISOLATED");
                return;
            }
            bypassObserved = true;
            firstAfter = after;
            state = State.WAIT_FIRST_PAINT;
        }

        public void onCompletedPaint(Cut frame, long nowElapsedMs) {
            if (state == State.WAIT_SECOND_PAINT_REQUEST) {
                unknown("UNREQUESTED_SECOND_PAINT");
                return;
            }
            if (state == State.WAIT_SECOND_PAINT) {
                onSecondCompletedPaint(frame, nowElapsedMs);
                return;
            }
            if (state != State.WAIT_FIRST_PAINT && state != State.WAIT_RESTORE_PAINT) return;
            Cut expected = state == State.WAIT_FIRST_PAINT ? firstAfter : restoreAfter;
            if (!live(nowElapsedMs) || frame == null || expected == null
                    || !frame.exactNinePainted() || !baseline.sameOriginals(frame)
                    || !expected.bounds.equals(frame.bounds)
                    || frame.parentPreCallRevision != expected.parentPreCallRevision
                    || frame.observedWriteOrdinal != expected.observedWriteOrdinal
                    || frame.rootLayoutCalls != expected.rootLayoutCalls
                    || frame.paintStartParentRevision != expected.parentPreCallRevision
                    || frame.paintStartWriteOrdinal != expected.observedWriteOrdinal
                    || frame.startedPaintRevision <= baseline.startedPaintRevision
                    || frame.completedPaintElapsedMs > nowElapsedMs) {
                unknown("COMPLETED_PAINT_MISMATCH");
                return;
            }
            if (state == State.WAIT_FIRST_PAINT) {
                firstFrame = frame;
                if (command.needsLaterRestore()) state = State.WAIT_RESTORE_CALL;
                else {
                    restoredFrame = frame;
                    state = State.WAIT_SECOND_PAINT_REQUEST;
                }
            } else {
                if (!frame.bounds.equals(baseline.bounds)
                        || frame.startedPaintRevision <= firstFrame.startedPaintRevision) {
                    unknown("RESTORATION_PAINT_NOT_LATER");
                    return;
                }
                restoredFrame = frame;
                state = State.WAIT_SECOND_PAINT_REQUEST;
            }
        }

        /** The app must request a new frame only after the first restored paint. */
        public boolean requestSecondPaint(Cut live, Cut latestFrame, long nowElapsedMs) {
            if (state != State.WAIT_SECOND_PAINT_REQUEST || !live(nowElapsedMs)
                    || restoredFrame == null || live == null || latestFrame == null
                    || nowElapsedMs < restoredFrame.completedPaintElapsedMs
                            + SECOND_SAMPLE_GAP_MS
                    || nowElapsedMs - restoredFrame.completedPaintElapsedMs
                            > MAX_SECOND_SAMPLE_GAP_MS
                    || !restoredFrame.sameLiveFrame(latestFrame)
                    || !restoredFrame.sameLiveFrame(live)
                    || !live.exactNinePainted() || !baseline.sameOriginals(live)
                    || !baseline.bounds.equals(live.bounds)) {
                unknown("SECOND_PAINT_REQUEST_NOT_FRESH");
                return false;
            }
            secondPaintRequestElapsedMs = nowElapsedMs;
            secondPaintStartRevisionFloor = live.startedPaintRevision;
            state = State.WAIT_SECOND_PAINT;
            return true;
        }

        private void onSecondCompletedPaint(Cut frame, long nowElapsedMs) {
            if (!live(nowElapsedMs) || frame == null || restoredFrame == null
                    || !frame.exactNinePainted() || !restoredFrame.sameOriginals(frame)
                    || !baseline.bounds.equals(frame.bounds)
                    || frame.parentPreCallRevision != restoredFrame.parentPreCallRevision
                    || frame.observedWriteOrdinal != restoredFrame.observedWriteOrdinal
                    || frame.rootLayoutCalls != restoredFrame.rootLayoutCalls
                    || frame.startedPaintRevision <= secondPaintStartRevisionFloor
                    || frame.completedPaintRevision <= restoredFrame.completedPaintRevision
                    || frame.paintStartedElapsedMs < secondPaintRequestElapsedMs
                    || frame.paintStartedElapsedMs < restoredFrame.completedPaintElapsedMs
                            + SECOND_SAMPLE_GAP_MS
                    || frame.completedPaintElapsedMs < frame.paintStartedElapsedMs
                    || frame.completedPaintElapsedMs - restoredFrame.completedPaintElapsedMs
                            > MAX_SECOND_SAMPLE_GAP_MS
                    || frame.completedPaintElapsedMs > nowElapsedMs) {
                unknown("SECOND_COMPLETED_PAINT_MISMATCH");
                return;
            }
            secondFrame = frame;
            state = State.WAIT_FINAL_SAMPLE;
        }

        public void onSecondSample(Cut live, Cut latestFrame, long nowElapsedMs) {
            if (state != State.WAIT_FINAL_SAMPLE) return;
            if (secondFrame == null || nowElapsedMs >= deadlineElapsedMs) {
                unknown("SECOND_SAMPLE_DEADLINE_OR_MISSING_FRAME");
                return;
            }
            if (nowElapsedMs < secondFrame.completedPaintElapsedMs
                    || nowElapsedMs - secondFrame.completedPaintElapsedMs
                            > MAX_SECOND_SAMPLE_GAP_MS
                    || live == null || latestFrame == null
                    || !secondFrame.sameLiveFrame(latestFrame)
                    || !secondFrame.sameLiveFrame(live)
                    || !live.exactNinePainted() || !baseline.sameOriginals(live)
                    || !baseline.bounds.equals(live.bounds)) {
                unknown("SECOND_SAMPLE_NOT_RESTORED");
                return;
            }
            secondSample = live;
            reason = command == Command.DIRECT_LAYOUT || command == Command.DIRECT_OFFSET
                    ? "BYPASS_CONTROL_RESTORED" : "PARENT_PATH_RESTORED";
            state = State.PASS;
        }

        public void expire(long nowElapsedMs) {
            if (state != State.PASS && state != State.UNKNOWN
                    && nowElapsedMs >= deadlineElapsedMs) unknown("TRIAL_TIMEOUT");
        }

        public void unknown(String why) {
            if (state == State.PASS || state == State.UNKNOWN) return;
            state = State.UNKNOWN;
            reason = why == null || why.isEmpty() ? "UNKNOWN" : why;
        }

        private boolean live(long nowElapsedMs) {
            return state != State.PASS && state != State.UNKNOWN
                    && nowElapsedMs < deadlineElapsedMs;
        }

        /** A historical PASS remains current only inside the independent arm lease. */
        public boolean currentlyValid(Cut live, Cut latestFrame, long nowElapsedMs,
                long activeArmDeadlineElapsedMs) {
            return state == State.PASS && secondFrame != null
                    && nowElapsedMs >= secondFrame.completedPaintElapsedMs
                    && activeArmDeadlineElapsedMs > 0
                    && nowElapsedMs < activeArmDeadlineElapsedMs
                    && live != null && latestFrame != null
                    && secondFrame.exactNinePainted()
                    && latestFrame.exactNinePainted()
                    && secondFrame.sameLiveFrame(latestFrame)
                    && secondFrame.sameLiveFrame(live) && live.exactNinePainted()
                    && baseline.sameOriginals(live)
                    && baseline.bounds.equals(live.bounds);
        }

        public Command command() { return command; }
        public State state() { return state; }
        public String reason() { return reason; }
        public Cut baseline() { return baseline; }
        public Cut firstAfter() { return firstAfter; }
        public Cut firstFrame() { return firstFrame; }
        public Cut restoreAfter() { return restoreAfter; }
        public Cut restoredFrame() { return restoredFrame; }
        public Cut secondFrame() { return secondFrame; }
        public Cut secondSample() { return secondSample; }
        public Cut abaAway() { return abaAway; }
        public RestoreEntryDiff restoreEntryDrift() { return restoreEntryDrift; }
        public boolean bypassObserved() { return bypassObserved; }
        public boolean rollbackVerified() { return state == State.PASS && secondSample != null; }
        public boolean completeMutationCoverage() { return false; }
        public long deadlineElapsedMs() { return deadlineElapsedMs; }
    }

    private TrialEvidence() { }
}
