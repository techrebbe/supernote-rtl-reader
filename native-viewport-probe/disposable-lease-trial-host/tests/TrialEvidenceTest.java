package com.techrebbe.supernote.leasetrial;

public final class TrialEvidenceTest {
    private static int assertions;

    private static void yes(boolean condition, String message) {
        assertions++;
        if (!condition) throw new AssertionError(message);
    }

    private static TrialEvidence.Cut cut(Object root, Object[] children,
            String[] evidence, long mutation, long started, long completed, long time) {
        Object[] parents = new Object[9];
        Object[] order = new Object[9];
        for (int i = 0; i < 9; i++) {
            parents[i] = root;
            order[i] = children[i];
        }
        return new TrialEvidence.Cut(root, children, parents, evidence, order,
                "scene=fixed:bounds=0,0,600,400", mutation, started, completed, time);
    }

    private static Object[] children() {
        Object[] children = new Object[9];
        for (int i = 0; i < children.length; i++) children[i] = new Object();
        return children;
    }

    private static String[] evidence() {
        String[] result = new String[9];
        for (int i = 0; i < result.length; i++) result[i] = "child-" + i;
        return result;
    }

    private static void contract() {
        yes(LeaseTrialContract.childCount() == 9, "exactly nine originals");
        yes(!LeaseTrialContract.AUTHORITY.contains("disposableleasehost"),
                "unique provider authority");
        for (int i = 0; i < 9; i++) {
            yes(LeaseTrialContract.childAt(i).id == 0x72000100 + i,
                    "fixed contiguous identity " + i);
        }
    }

    private static void passingTrial() {
        Object root = new Object();
        Object[] children = children();
        String[] evidence = evidence();
        TrialEvidence.Cut baseline = cut(root, children, evidence, 12, 4, 4, 100);
        TrialEvidence trial = TrialEvidence.begin(baseline, 110);
        yes(trial.state() == TrialEvidence.State.WAIT_LAYOUT, "waiting for real layout");
        yes(trial.onLayout(cut(root, children, evidence, 12, 4, 4, 100),
                false, false, 120), "unchanged callback admitted");
        yes(trial.state() == TrialEvidence.State.WAIT_PAINT, "waiting for later paint");
        trial.onCompletedPaint(cut(root, children, evidence, 12, 5, 5, 130), 131);
        yes(trial.state() == TrialEvidence.State.WAIT_SECOND_SAMPLE,
                "paint alone is not rollback proof");
        trial.onSecondSample(cut(root, children, evidence, 12, 5, 5, 130), 160);
        yes(trial.state() == TrialEvidence.State.PASS && trial.rollbackVerified(),
                "two stable samples prove no-child rollback");
        yes(trial.layoutCalls() == 1, "exactly one layout callback");
    }

    private static void changedGeometryRejects() {
        Object root = new Object();
        Object[] children = children();
        String[] baselineEvidence = evidence();
        TrialEvidence trial = TrialEvidence.begin(
                cut(root, children, baselineEvidence, 5, 2, 2, 100), 110);
        String[] changed = evidence();
        changed[4] = "moved";
        yes(!trial.onLayout(cut(root, children, changed, 5, 2, 2, 100),
                false, false, 120), "changed child rejected");
        yes(trial.state() == TrialEvidence.State.UNKNOWN && !trial.rollbackVerified(),
                "changed child never passes");
    }

    private static void mutationAndPaintFailures() {
        Object root = new Object();
        Object[] children = children();
        String[] evidence = evidence();
        TrialEvidence mutated = TrialEvidence.begin(
                cut(root, children, evidence, 5, 2, 2, 100), 110);
        yes(!mutated.onLayout(cut(root, children, evidence, 6, 2, 2, 100),
                false, false, 120), "mutation revision fenced");
        TrialEvidence requestedChildLayout = TrialEvidence.begin(
                cut(root, children, evidence, 5, 2, 2, 100), 110);
        yes(!requestedChildLayout.onLayout(cut(root, children, evidence, 5, 2, 2, 100),
                false, true, 120), "pending child layout rejected");
        TrialEvidence changedRootLayout = TrialEvidence.begin(
                cut(root, children, evidence, 5, 2, 2, 100), 110);
        yes(!changedRootLayout.onLayout(cut(root, children, evidence, 5, 2, 2, 100),
                true, false, 120), "changed root layout rejected");
        TrialEvidence stalePaint = TrialEvidence.begin(
                cut(root, children, evidence, 5, 2, 2, 100), 110);
        yes(stalePaint.onLayout(cut(root, children, evidence, 5, 2, 2, 100),
                false, false, 120), "layout entered");
        stalePaint.onCompletedPaint(cut(root, children, evidence, 5, 2, 2, 100), 121);
        yes(stalePaint.state() == TrialEvidence.State.UNKNOWN,
                "old paint cannot prove no-op pass");
    }

    private static void secondSampleAndTimeout() {
        Object root = new Object();
        Object[] children = children();
        String[] evidence = evidence();
        TrialEvidence baseline = TrialEvidence.begin(
                cut(root, children, evidence, 5, 2, 2, 100), 110);
        baseline.expire(5110);
        yes(baseline.state() == TrialEvidence.State.UNKNOWN,
                "missing callback bounded UNKNOWN");
        TrialEvidence changed = TrialEvidence.begin(
                cut(root, children, evidence, 5, 2, 2, 100), 110);
        yes(changed.onLayout(cut(root, children, evidence, 5, 2, 2, 100),
                false, false, 120), "layout entered");
        changed.onCompletedPaint(cut(root, children, evidence, 5, 3, 3, 130), 131);
        changed.onSecondSample(cut(root, children, evidence, 6, 3, 3, 130), 160);
        yes(changed.state() == TrialEvidence.State.UNKNOWN,
                "post-paint mutation rejects rollback");
    }

    private static void immutableEvidenceAndInvalidOrder() {
        Object root = new Object();
        Object[] children = children();
        String[] evidence = evidence();
        TrialEvidence.Cut snapshot = cut(root, children, evidence, 1, 2, 2, 100);
        children[0] = new Object();
        evidence[0] = "changed input";
        yes(snapshot.exactNinePainted(), "constructor copied input arrays");
        Object[] returned = snapshot.childrenCopy();
        returned[1] = new Object();
        yes(snapshot.exactNinePainted(), "accessor cannot mutate snapshot");
        Object[] wrongOrder = children();
        Object[] parents = new Object[9];
        Object[] painted = wrongOrder.clone();
        for (int i = 0; i < 9; i++) parents[i] = root;
        Object swap = painted[0];
        painted[0] = painted[1];
        painted[1] = swap;
        TrialEvidence.Cut invalid = new TrialEvidence.Cut(root, wrongOrder, parents,
                evidence(), painted, "fixed", 1, 2, 2, 100);
        yes(!invalid.exactNinePainted(), "direct index is not a paint-order substitute");
    }

    public static void main(String[] args) {
        contract();
        passingTrial();
        changedGeometryRejects();
        mutationAndPaintFailures();
        secondSampleAndTimeout();
        immutableEvidenceAndInvalidOrder();
        System.out.println("PASS " + assertions + " no-child evidence assertions");
    }
}
