package com.techrebbe.supernote.leasetiletrial;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

public final class TileTrialEvidenceTest {
    private static int checks;

    private static final class Identity {
        private static int nextId;
        final int id = ++nextId;
        @Override public boolean equals(Object other) { return other instanceof Identity; }
        @Override public int hashCode() { return 1; }
        @Override public String toString() { return "identity-" + id; }
    }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }

    private static TileTrialEvidence.Cut cut(Object root, Object[] children,
            Object[] painted, String scene, long revision, long at) {
        Object[] parents = new Object[children.length];
        String[] evidence = new String[children.length];
        for (int i = 0; i < children.length; i++) {
            parents[i] = root;
            evidence[i] = "visible|id|bounds|layout " + children[i];
        }
        return new TileTrialEvidence.Cut(root, children, parents, evidence,
                painted, scene, revision, at);
    }

    private static Object[] originals() {
        Object[] result = new Object[9];
        for (int i = 0; i < result.length; i++) result[i] = new Identity();
        return result;
    }

    private static Object[] withTile(Object[] original, Object tile) {
        Object[] ten = new Object[10];
        ten[0] = original[0];
        ten[1] = tile;
        for (int i = 1; i < 9; i++) ten[i + 1] = original[i];
        return ten;
    }

    private static void testNineTenNine() {
        Object activity = new Identity();
        Object root = new Identity();
        Object[] nine = originals();
        TileTrialEvidence trial = new TileTrialEvidence();
        TileTrialEvidence.Cut baseline = cut(root, nine, nine, "scene A", 1, 100);
        trial.onFrame(activity, baseline);
        require(trial.phase() == TileTrialEvidence.Phase.READY,
                "nine actual drawChild calls did not create baseline");
        require(trial.arm(activity, baseline, 110) && trial.attempted()
                && trial.deadlineElapsedMs() == 2110,
                "expiry was not armed before structural add");
        Object tile = new Identity();
        Object[] ten = withTile(nine, tile);
        trial.onAdded(activity, tile, cut(root, ten, new Object[0], "scene A", 0, 0));
        require(trial.phase() == TileTrialEvidence.Phase.INSERTED,
                "exact index-one tile did not produce ten structural children");
        trial.onFrame(activity, cut(root, ten, ten, "scene A", 2, 120));
        require(trial.phase() == TileTrialEvidence.Phase.TEN_PAINTED
                && trial.tenPaintRevision() == 2,
                "ten actual drawChild calls were not captured");
        trial.onRemoved(activity, tile, cut(root, nine, new Object[0], "scene A", 0, 0));
        require(trial.phase() == TileTrialEvidence.Phase.WAIT_NINE_PAINT,
                "nine structural children were confused with completed paint");
        trial.onFrame(activity, cut(root, nine, nine, "scene A", 3, 130));
        require(trial.phase() == TileTrialEvidence.Phase.RESTORED
                && !trial.arm(activity, baseline, 140),
                "fresh nine paint failed or one-shot trial restarted");
        trial.onFrame(activity, cut(root, nine, nine, "scene A", 4, 2200));
        require(trial.phase() == TileTrialEvidence.Phase.RESTORED,
                "stable redraw after expiry incorrectly revoked timely restoration");
        Object[] wrongRestoredPaint = nine.clone();
        wrongRestoredPaint[0] = new Identity();
        trial.onFrame(activity, cut(root, nine, wrongRestoredPaint, "scene A", 5, 2210));
        require(trial.phase() == TileTrialEvidence.Phase.UNKNOWN,
                "post-restoration paint drift retained a false PASS");
        trial.unknown("ACTIVITY_PAUSE");
        require(trial.phase() == TileTrialEvidence.Phase.UNKNOWN,
                "lifecycle ambiguity did not revoke restoration");
    }

    private static void testEarlyStopAndWrongPaint() {
        Object activity = new Identity();
        Object root = new Identity();
        Object[] nine = originals();
        TileTrialEvidence.Cut baseline = cut(root, nine, nine, "scene A", 1, 100);
        TileTrialEvidence early = new TileTrialEvidence();
        early.onFrame(activity, baseline);
        require(early.arm(activity, baseline, 100), "early-stop fixture not armed");
        Object tile = new Identity();
        Object[] ten = withTile(nine, tile);
        early.onAdded(activity, tile, cut(root, ten, new Object[0], "scene A", 0, 0));
        early.onRemoved(activity, tile, cut(root, nine, new Object[0], "scene A", 0, 0));
        early.onFrame(activity, cut(root, nine, nine, "scene A", 2, 120));
        require(early.phase() == TileTrialEvidence.Phase.UNKNOWN,
                "early stop fabricated ten-child paint evidence");

        TileTrialEvidence reordered = new TileTrialEvidence();
        reordered.onFrame(activity, baseline);
        require(reordered.arm(activity, baseline, 100), "paint-order fixture not armed");
        reordered.onAdded(activity, tile, cut(root, ten, new Object[0], "scene A", 0, 0));
        Object[] wrongOrder = ten.clone();
        Object changed = wrongOrder[2];
        wrongOrder[2] = wrongOrder[3];
        wrongOrder[3] = changed;
        reordered.onFrame(activity, cut(root, ten, wrongOrder, "scene A", 2, 120));
        require(reordered.phase() == TileTrialEvidence.Phase.UNKNOWN,
                "reordered visible sibling was treated as exact paint");
    }

    private static void testLatestReadyFrameIsArmAuthority() {
        Object activity = new Identity();
        Object root = new Identity();
        Object[] nine = originals();
        TileTrialEvidence trial = new TileTrialEvidence();
        TileTrialEvidence.Cut first = cut(root, nine, nine, "scene A", 1, 100);
        TileTrialEvidence.Cut latest = cut(root, nine, nine, "scene A", 2, 110);
        trial.onFrame(activity, first);
        trial.onFrame(activity, latest);
        require(trial.baselinePaintRevision() == 2
                && !trial.arm(activity, first, 120)
                && trial.arm(activity, latest, 120),
                "start did not bind the latest completed nine-child frame");
    }

    private static void testLatePaintCannotRestore() {
        Object activity = new Identity();
        Object root = new Identity();
        Object[] nine = originals();
        TileTrialEvidence.Cut baseline = cut(root, nine, nine, "scene A", 1, 100);
        TileTrialEvidence late = new TileTrialEvidence();
        late.onFrame(activity, baseline);
        require(late.arm(activity, baseline, 100), "late-paint fixture not armed");
        Object tile = new Identity();
        Object[] ten = withTile(nine, tile);
        late.onAdded(activity, tile, cut(root, ten, new Object[0], "scene A", 0, 0));
        late.onFrame(activity, cut(root, ten, ten, "scene A", 2, 2100));
        require(late.phase() == TileTrialEvidence.Phase.UNKNOWN
                && "FRAME_AFTER_DEADLINE".equals(late.reason()),
                "deadline-expired dispatch fabricated a ten-child paint proof");
        late.onRemoved(activity, tile, cut(root, nine, new Object[0], "scene A", 0, 0));
        late.onFrame(activity, cut(root, nine, nine, "scene A", 3, 2110));
        require(late.phase() == TileTrialEvidence.Phase.UNKNOWN,
                "late ten-child frame was resurrected by later nine-child paint");
    }

    private static void testIdentityParentSceneAndDeadline() {
        Object activity = new Identity();
        Object root = new Identity();
        Object[] nine = originals();
        TileTrialEvidence.Cut baseline = cut(root, nine, nine, "scene A", 1, 100);
        TileTrialEvidence stale = new TileTrialEvidence();
        stale.onFrame(activity, baseline);
        require(!stale.arm(activity, baseline, 1101), "stale baseline admitted a tile");
        require(!stale.expired(5000), "unarmed trial reported expiry");

        TileTrialEvidence foreign = new TileTrialEvidence();
        foreign.onFrame(activity, baseline);
        require(!foreign.arm(new Identity(), baseline, 100),
                "equal-looking Activity bypassed exact identity");
        require(foreign.arm(activity, baseline, 100), "identity fixture not armed");
        Object tile = new Identity();
        Object[] ten = withTile(nine, tile);
        TileTrialEvidence.Cut wrongParent = cut(root, ten, new Object[0], "scene A", 0, 0);
        wrongParent.parents[1] = new Identity();
        require(!foreign.onAdded(activity, tile, wrongParent)
                && foreign.phase() == TileTrialEvidence.Phase.UNKNOWN,
                "foreign tile parent passed add structure");

        TileTrialEvidence drift = new TileTrialEvidence();
        drift.onFrame(activity, baseline);
        require(drift.arm(activity, baseline, 100), "scene fixture not armed");
        require(drift.expired(2100), "deadline was not monotonic and bounded");
        require(!drift.onAdded(activity, tile,
                cut(root, ten, new Object[0], "scene B", 0, 0)),
                "changed root scene passed exact add");
    }

    private static void testExpectedLayoutFence() {
        Object root = new Identity();
        Object[] nine = originals();
        Object[] ten = withTile(nine, new Identity());
        TileTrialEvidence.Cut before = cut(root, ten, new Object[0], "scene A", 0, 0);
        TileTrialEvidence.Cut after = cut(root, ten, new Object[0], "scene A", 0, 0);
        after.evidence[1] = "tile measured and placed";
        require(TileTrialEvidence.unchangedOriginalLayout(before, after, nine, false),
                "expected add layout could not place only the owned tile");
        require(!TileTrialEvidence.unchangedOriginalLayout(before, after, nine, true),
                "root bounds changed during expected tile layout");
        after.evidence[2] = "original one moved";
        require(!TileTrialEvidence.unchangedOriginalLayout(before, after, nine, false),
                "original geometry drift passed expected tile layout");
        TileTrialEvidence.Cut foreignParent = cut(root, ten,
                new Object[0], "scene A", 0, 0);
        foreignParent.parents[2] = new Identity();
        require(!TileTrialEvidence.unchangedOriginalLayout(before, foreignParent,
                nine, false), "reparented original passed expected tile layout");
        TileTrialEvidence.Cut beforeRemove = cut(root, nine,
                new Object[0], "scene A", 0, 0);
        TileTrialEvidence.Cut afterRemove = cut(root, nine,
                new Object[0], "scene A", 0, 0);
        require(TileTrialEvidence.unchangedOriginalLayout(beforeRemove,
                afterRemove, nine, false),
                "expected remove layout changed no original but was rejected");
    }

    private static void testManifestAndSourceIsolation(String manifestPath,
            String activityPath, String providerPath, String statePath) throws Exception {
        String manifest = new String(Files.readAllBytes(Paths.get(manifestPath)),
                StandardCharsets.UTF_8);
        String activity = new String(Files.readAllBytes(Paths.get(activityPath)),
                StandardCharsets.UTF_8);
        String provider = new String(Files.readAllBytes(Paths.get(providerPath)),
                StandardCharsets.UTF_8);
        String state = new String(Files.readAllBytes(Paths.get(statePath)),
                StandardCharsets.UTF_8);
        require(manifest.contains("package=\"com.techrebbe.supernote.leasetiletrial\"")
                && manifest.contains("android:minSdkVersion=\"30\"")
                && manifest.contains("android:targetSdkVersion=\"30\"")
                && !manifest.contains("<uses-permission")
                && manifest.contains("android:name=\".TileTrialActivity\"")
                && manifest.contains("android:name=\".TileTrialProvider\"")
                && manifest.indexOf("<activity") == manifest.lastIndexOf("<activity")
                && !manifest.contains("<service") && !manifest.contains("<receiver"),
                "manifest escaped isolated permissionless API-30 package");
        int armAt = activity.indexOf("main.postDelayed(expiryCallback");
        int addAt = activity.indexOf("root.insertTile(created)");
        require(armAt >= 0 && addAt > armAt
                && activity.contains("root.removeExactTile(exact)")
                && activity.contains("protected boolean drawChild(Canvas canvas")
                && activity.contains("addView(owned, TileTrialEvidence.TILE_INDEX, params)")
                && activity.contains("removeView(owned)")
                && !activity.contains("addViewInLayout")
                && !activity.contains("removeViewInLayout")
                && activity.contains("unchangedOriginalLayout(")
                && activity.contains("unknownDeferred(\"PAINT_HIERARCHY_CHANGED\")")
                && activity.contains("baselinePaint = liveBaseline")
                && activity.contains("completedDrawForDispatch = true")
                && activity.contains("FRAME_AFTER_DEADLINE")
                && !activity.contains("android.permission")
                && !activity.contains("com.supernote.document"),
                "Activity lost safe ordinary add/remove, deferred cleanup, or isolation");
        require(provider.contains("expectedPid")
                && provider.contains("expectedIncarnation")
                && provider.contains("expectedActivityToken")
                && provider.contains("expectedRootToken")
                && provider.contains("matchesProcess(expectedPid")
                && provider.contains("activity.command(command,")
                && state.contains("activityEverAdmitted")
                && state.contains("matchesProcess(int expectedPid"),
                "provider command lost process/activity/root identity fence");
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 4) throw new IllegalArgumentException("source guard paths");
        testNineTenNine();
        testEarlyStopAndWrongPaint();
        testLatestReadyFrameIsArmAuthority();
        testLatePaintCannotRestore();
        testIdentityParentSceneAndDeadline();
        testExpectedLayoutFence();
        testManifestAndSourceIsolation(args[0], args[1], args[2], args[3]);
        System.out.println("TILE_TRIAL_HOST_PASS checks=" + checks);
    }
}
