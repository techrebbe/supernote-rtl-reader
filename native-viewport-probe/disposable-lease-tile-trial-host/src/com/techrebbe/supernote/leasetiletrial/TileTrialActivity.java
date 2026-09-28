package com.techrebbe.supernote.leasetiletrial;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Canvas;
import android.graphics.Color;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.view.Gravity;
import android.view.KeyEvent;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.TextView;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.UUID;

/** Isolated API-30 synthetic host. No reader, PDF, pen, or input authority. */
public final class TileTrialActivity extends Activity {
    private static final int ROOT_ID = 0x72000100;
    private static final int TILE_ID = 0x72000101;
    private static final int FIRST_ORIGINAL_ID = 0x72000200;
    private final View[] originals = new View[TileTrialEvidence.ORIGINAL_COUNT];
    private final Handler main = new Handler(Looper.getMainLooper());
    private final TileTrialEvidence evidence = new TileTrialEvidence();
    private final String activityToken = UUID.randomUUID().toString();
    private TrialRoot root;
    private TileView tile;
    private Runnable expiry;
    private TileTrialEvidence.Cut baselinePaint;
    private TileTrialEvidence.Cut tenStructure;
    private TileTrialEvidence.Cut tenPaint;
    private TileTrialEvidence.Cut nineRestoredStructure;
    private TileTrialEvidence.Cut nineRestoredPaint;
    private String lifecycle = "NEW";
    private boolean admitted;
    private boolean removalAmbiguous;

    @Override public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        if (!TileTrialState.get().admit(this)) { finish(); return; }
        admitted = true;
        root = new TrialRoot();
        root.setId(ROOT_ID);
        root.setBackgroundColor(0xfff7f7f2);
        for (int i = 0; i < originals.length; i++) {
            TextView child = new TextView(this);
            child.setId(FIRST_ORIGINAL_ID + i);
            child.setText("Synthetic " + i);
            child.setTextSize(12f);
            child.setTextColor(Color.BLACK);
            child.setGravity(Gravity.CENTER);
            child.setBackgroundColor((i & 1) == 0 ? 0xffd8e9f1 : 0xffe8e2cf);
            child.setClickable(false);
            child.setFocusable(false);
            FrameLayout.LayoutParams params = new FrameLayout.LayoutParams(dp(96), dp(56));
            params.gravity = Gravity.TOP | Gravity.LEFT;
            params.leftMargin = dp(8 + 104 * (i % 3));
            params.topMargin = dp(8 + 64 * (i / 3));
            root.addView(child, params);
            originals[i] = child;
        }
        setContentView(root);
        lifecycle = "CREATED";
        TileTrialState.get().record("ACTIVITY_CREATE", "activity=" + activityToken);
    }

    @Override protected void onResume() {
        super.onResume();
        if (admitted) {
            lifecycle = "RESUMED";
            TileTrialState.get().record("ACTIVITY_RESUME", "");
        }
    }

    @Override protected void onPause() {
        if (admitted) {
            abort("ACTIVITY_PAUSE");
            lifecycle = "PAUSED";
        }
        super.onPause();
    }

    @Override protected void onStop() {
        if (admitted) {
            abort("ACTIVITY_STOP");
            lifecycle = "STOPPED";
        }
        super.onStop();
    }

    @Override protected void onDestroy() {
        if (admitted) {
            abort("ACTIVITY_DESTROY");
            lifecycle = "DESTROYED";
            TileTrialState.get().release(this);
        }
        super.onDestroy();
    }

    @Override protected void onNewIntent(Intent intent) {
        if (admitted) abort("ACTIVITY_REUSED");
        super.onNewIntent(intent);
    }

    @Override public void onWindowFocusChanged(boolean hasFocus) {
        if (admitted && !hasFocus) abort("WINDOW_FOCUS_LOST");
        super.onWindowFocusChanged(hasFocus);
        if (admitted) TileTrialState.get().record("WINDOW_FOCUS", Boolean.toString(hasFocus));
    }

    boolean command(String value, String expectedActivityToken, String expectedRootToken) {
        requireMain();
        if (!admitted || TileTrialState.get().activity() != this
                || !activityToken.equals(expectedActivityToken)
                || root == null || !root.token.equals(expectedRootToken)) return false;
        if ("start-tile".equals(value)) return startTile();
        if ("stop-tile".equals(value)) return stopTile("EXPLICIT_STOP");
        throw new IllegalArgumentException("unsupported tile command");
    }

    private boolean startTile() {
        if (evidence.phase() != TileTrialEvidence.Phase.READY
                || !"RESUMED".equals(lifecycle) || !root.isAttachedToWindow()
                || !root.hasWindowFocus() || root.isLayoutRequested()
                || !originalsExact() || tile != null) return false;
        final long now = SystemClock.elapsedRealtime();
        final Runnable expiryCallback = new Runnable() {
            @Override public void run() {
                if (tile == null || evidence.phase() == TileTrialEvidence.Phase.UNKNOWN
                        || evidence.phase() == TileTrialEvidence.Phase.RESTORED) return;
                long remaining = evidence.deadlineElapsedMs() - SystemClock.elapsedRealtime();
                if (remaining > 0) {
                    if (!main.postDelayed(this, remaining)) abort("EXPIRY_REPOST_REJECTED");
                    return;
                }
                TileTrialState.get().record("EXPIRY_FIRED", "");
                stopTile("EXPIRY");
            }
        };
        // Android owns this Handler callback before any hierarchy mutation.
        if (!main.postDelayed(expiryCallback, TileTrialEvidence.EXPIRY_MS)) {
            abort("EXPIRY_POST_REJECTED");
            return false;
        }
        TileTrialEvidence.Cut liveBaseline = root.captureCurrent();
        if (!evidence.arm(this, liveBaseline, now)) {
            main.removeCallbacks(expiryCallback);
            return false;
        }
        baselinePaint = liveBaseline;
        expiry = expiryCallback;
        TileTrialState.get().record("EXPIRY_ARMED", "deadline=" + evidence.deadlineElapsedMs());
        TileView created = new TileView();
        tile = created;
        try {
            root.insertTile(created);
            TileTrialEvidence.Cut current = root.captureCurrent();
            tenStructure = current;
            if (!evidence.onAdded(this, created, current)) {
                abort("ADD_STRUCTURE_AMBIGUOUS");
                return false;
            }
            TileTrialState.get().record("TILE_ADDED", "index=1 count=10 tile="
                    + System.identityHashCode(created));
            root.invalidate();
            return true;
        } catch (RuntimeException failure) {
            abort("ADD_EXCEPTION_" + failure.getClass().getSimpleName());
            return false;
        }
    }

    private boolean stopTile(String trigger) {
        requireMain();
        TileTrialEvidence.Phase phase = evidence.phase();
        if (phase != TileTrialEvidence.Phase.INSERTED
                && phase != TileTrialEvidence.Phase.TEN_PAINTED) return false;
        if (tile == null || tile.getParent() != root) {
            abort("TILE_PARENT_AMBIGUOUS");
            return false;
        }
        TileView exact = tile;
        try {
            root.removeExactTile(exact);
            if (exact.getParent() != null) {
                abort("TILE_STILL_PARENTED");
                return false;
            }
            TileTrialEvidence.Cut current = root.captureCurrent();
            nineRestoredStructure = current;
            evidence.onRemoved(this, exact, current);
            if (expiry != null) main.removeCallbacks(expiry);
            TileTrialState.get().record("TILE_REMOVED", "trigger=" + trigger
                    + " count=" + root.getChildCount() + " tile="
                    + System.identityHashCode(exact));
            if (evidence.phase() == TileTrialEvidence.Phase.UNKNOWN) return false;
            root.invalidate();
            return true;
        } catch (RuntimeException failure) {
            abort("REMOVE_EXCEPTION_" + failure.getClass().getSimpleName());
            return false;
        }
    }

    private void abort(String why) {
        requireMain();
        boolean first = evidence.phase() != TileTrialEvidence.Phase.UNKNOWN;
        evidence.unknown(why);
        if (first) TileTrialState.get().record("TRIAL_UNKNOWN", why);
        if (expiry != null) main.removeCallbacks(expiry);
        TileView exact = tile;
        if (exact == null || root == null || removalAmbiguous) return;
        if (exact.getParent() == root) {
            try {
                root.removeExactTile(exact);
                if (exact.getParent() == null) {
                    TileTrialState.get().record("ABORT_EXACT_REMOVE", why);
                } else {
                    quarantineVisual("ABORT_TILE_STILL_PARENTED");
                }
            } catch (RuntimeException failure) {
                quarantineVisual("ABORT_REMOVE_FAILED_"
                        + failure.getClass().getSimpleName());
            }
        } else if (exact.getParent() != null) {
            quarantineVisual("PARENT_AMBIGUOUS_" + why);
        }
    }

    private void quarantineVisual(String why) {
        removalAmbiguous = true; // No speculative second removal or automatic retry.
        TileTrialState.get().record("VISUAL_QUARANTINE", why);
        if (root != null) root.invalidate();
        if (!isFinishing() && !"DESTROYED".equals(lifecycle)) finish();
    }

    private void unknownDeferred(final String why) {
        boolean first = evidence.phase() != TileTrialEvidence.Phase.UNKNOWN;
        evidence.unknown(why);
        if (first) TileTrialState.get().record("TRIAL_UNKNOWN", why);
        // Never remove a child while dispatchDraw, drawChild, or onLayout is active.
        if (!main.post(new Runnable() {
            @Override public void run() { abort(why); }
        })) TileTrialState.get().record("CLEANUP_POST_REJECTED", why);
    }

    private boolean tileMayDraw(TileView candidate) {
        if (tile != candidate || !"RESUMED".equals(lifecycle)) return false;
        if (candidate.getParent() != root) {
            unknownDeferred("TILE_PARENT_AMBIGUOUS_AT_DRAW");
            return false;
        }
        TileTrialEvidence.Phase phase = evidence.phase();
        if (phase != TileTrialEvidence.Phase.INSERTED
                && phase != TileTrialEvidence.Phase.TEN_PAINTED) return false;
        if (evidence.expired(SystemClock.elapsedRealtime())) {
            if (!main.post(new Runnable() {
                @Override public void run() { stopTile("DRAW_DEADLINE"); }
            })) unknownDeferred("DRAW_DEADLINE_POST_REJECTED");
            return false;
        }
        return true;
    }

    private void onCompletedFrame(TileTrialEvidence.Cut frame) {
        TileTrialEvidence.Phase before = evidence.phase();
        if (evidence.attempted() && before != TileTrialEvidence.Phase.RESTORED
                && before != TileTrialEvidence.Phase.UNKNOWN
                && evidence.expired(SystemClock.elapsedRealtime())) {
            unknownDeferred("FRAME_AFTER_DEADLINE");
            return;
        }
        evidence.onFrame(this, frame);
        TileTrialEvidence.Phase after = evidence.phase();
        if (after == TileTrialEvidence.Phase.READY) baselinePaint = frame;
        if (after == TileTrialEvidence.Phase.TEN_PAINTED) tenPaint = frame;
        if (after == TileTrialEvidence.Phase.RESTORED) nineRestoredPaint = frame;
        TileTrialState.get().record("PAINT_COMPLETE", "revision=" + frame.paintRevision
                + " count=" + frame.children.length + " phase=" + after.name());
        if (after == TileTrialEvidence.Phase.UNKNOWN && before != after) {
            TileTrialState.get().record("TRIAL_UNKNOWN", evidence.reason());
            unknownDeferred("PAINT_MISMATCH");
        }
    }

    private boolean originalsExact() {
        if (root == null || root.getChildCount() != originals.length) return false;
        for (int i = 0; i < originals.length; i++) {
            if (root.getChildAt(i) != originals[i] || originals[i].getParent() != root
                    || originals[i].getVisibility() != View.VISIBLE) return false;
        }
        return true;
    }

    String stateJson() {
        requireMain();
        try {
            JSONObject value = new JSONObject();
            value.put("schema", "disposable-lease-tile-trial-state-v1");
            value.put("process", TileTrialState.get().identityJson());
            value.put("activityPresent", admitted);
            value.put("activityToken", activityToken);
            value.put("activityIdentityHash", System.identityHashCode(this));
            value.put("rootIdentityHash", System.identityHashCode(root));
            value.put("rootToken", root.token);
            value.put("sameAdmittedActivity", TileTrialState.get().activity() == this);
            value.put("lifecycle", lifecycle);
            value.put("rootAttached", root.isAttachedToWindow());
            value.put("rootHasFocus", root.hasWindowFocus());
            value.put("rootLayoutCalls", root.layoutCalls);
            value.put("sampleElapsedMs", SystemClock.elapsedRealtime());
            value.put("phase", evidence.phase().name());
            value.put("reason", evidence.reason());
            value.put("startAttempted", evidence.attempted());
            value.put("deadlineElapsedMs", evidence.deadlineElapsedMs());
            value.put("baselinePaintRevision", evidence.baselinePaintRevision());
            value.put("tenPaintRevision", evidence.tenPaintRevision());
            value.put("originalsExact", originalsExact());
            value.put("tileIdentityHash", tile == null ? JSONObject.NULL
                    : System.identityHashCode(tile));
            value.put("tileParentIsRoot", tile != null && tile.getParent() == root);
            value.put("current", cutJson(root.captureCurrent()));
            value.put("lastCompletedPaint", cutJson(root.lastCompleted));
            value.put("baselineNinePaint", cutJson(baselinePaint));
            value.put("tenStructure", cutJson(tenStructure));
            value.put("tenPaint", cutJson(tenPaint));
            value.put("restoredNineStructure", cutJson(nineRestoredStructure));
            value.put("restoredNinePaint", cutJson(nineRestoredPaint));
            return value.toString();
        } catch (JSONException exception) {
            throw new IllegalStateException("tile state JSON failed", exception);
        }
    }

    private Object cutJson(TileTrialEvidence.Cut cut) throws JSONException {
        if (cut == null) return JSONObject.NULL;
        JSONObject value = new JSONObject();
        value.put("rootIdentityHash", System.identityHashCode(cut.root));
        value.put("scene", cut.scene);
        value.put("paintRevision", cut.paintRevision);
        value.put("completedElapsedMs", cut.completedElapsedMs);
        value.put("completedPaint", cut.completedPaint());
        value.put("structuralCount", cut.children.length);
        value.put("paintCount", cut.painted.length);
        JSONArray children = new JSONArray();
        JSONArray painted = new JSONArray();
        for (int i = 0; i < cut.children.length; i++) {
            View child = (View) cut.children[i];
            JSONObject entry = new JSONObject();
            entry.put("index", i);
            entry.put("id", child.getId());
            entry.put("identityHash", System.identityHashCode(child));
            entry.put("parentIsRoot", cut.parents[i] == cut.root);
            entry.put("isOwnedTile", child == tile);
            entry.put("visibility", child.getVisibility());
            entry.put("evidence", cut.evidence[i]);
            children.put(entry);
        }
        for (Object child : cut.painted) painted.put(System.identityHashCode(child));
        value.put("children", children);
        value.put("actualDrawChildOrder", painted);
        return value;
    }

    private String sceneStamp() {
        return "activity=" + activityToken + ":root=" + root.token
                + ":orientation=" + getResources().getConfiguration().orientation
                + ":bounds=" + root.getLeft() + "," + root.getTop() + ","
                + root.getRight() + "," + root.getBottom()
                + ":padding=" + root.getPaddingLeft() + "," + root.getPaddingTop()
                + "," + root.getPaddingRight() + "," + root.getPaddingBottom();
    }

    private int dp(int value) {
        return (int) (value * getResources().getDisplayMetrics().density + 0.5f);
    }

    private static void requireMain() {
        if (Looper.myLooper() != Looper.getMainLooper()) {
            throw new IllegalStateException("tile host requires main Looper");
        }
    }

    private final class TileView extends View {
        boolean completedDrawForDispatch;

        TileView() {
            super(TileTrialActivity.this);
            setId(TILE_ID);
            setBackgroundColor(0xffcc402e);
            setClickable(false);
            setFocusable(false);
            setFocusableInTouchMode(false);
            setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);
        }

        @Override public void draw(Canvas canvas) {
            if (!tileMayDraw(this)) return;
            super.draw(canvas);
            completedDrawForDispatch = true;
        }
        @Override public boolean dispatchTouchEvent(MotionEvent event) { return false; }
        @Override public boolean onHoverEvent(MotionEvent event) { return false; }
        @Override public boolean onGenericMotionEvent(MotionEvent event) { return false; }
        @Override public boolean onKeyDown(int keyCode, KeyEvent event) { return false; }
    }

    private final class TrialRoot extends FrameLayout {
        static final int LAYOUT_NONE = 0;
        static final int LAYOUT_ADD = 1;
        static final int LAYOUT_REMOVE = 2;
        final String token = UUID.randomUUID().toString();
        final ArrayList<PaintedChild> drawing = new ArrayList<>();
        TileTrialEvidence.Cut lastCompleted;
        long startedPaintRevision;
        long mutationRevision;
        long completedMutationRevision = -1;
        long layoutCalls;
        int pendingLayout;
        boolean drawingActive;

        TrialRoot() {
            super(TileTrialActivity.this);
            setChildrenDrawingOrderEnabled(false);
        }

        void insertTile(TileView owned) {
            requireMain();
            if (getChildCount() != TileTrialEvidence.ORIGINAL_COUNT
                    || owned.getParent() != null || pendingLayout != LAYOUT_NONE) {
                throw new IllegalStateException("add boundary");
            }
            FrameLayout.LayoutParams params = new FrameLayout.LayoutParams(dp(96), dp(56));
            params.gravity = Gravity.TOP | Gravity.LEFT;
            params.leftMargin = dp(8);
            params.topMargin = dp(8);
            pendingLayout = LAYOUT_ADD;
            mutationRevision++;
            addView(owned, TileTrialEvidence.TILE_INDEX, params);
        }

        void removeExactTile(TileView owned) {
            requireMain();
            if (owned == null || owned.getParent() != this) {
                throw new IllegalStateException("exact tile parent changed");
            }
            pendingLayout = LAYOUT_REMOVE;
            mutationRevision++;
            removeView(owned);
        }

        @Override protected void onLayout(boolean changed,
                int left, int top, int right, int bottom) {
            layoutCalls++;
            TileTrialEvidence.Cut before = captureStructure();
            int expected = pendingLayout;
            mutationRevision++;
            super.onLayout(changed, left, top, right, bottom);
            if (evidence.phase() == TileTrialEvidence.Phase.WAIT_BASELINE) return;
            TileTrialEvidence.Cut after = captureStructure();
            boolean phaseFits = (expected == LAYOUT_ADD
                    && (evidence.phase() == TileTrialEvidence.Phase.ARMED
                            || evidence.phase() == TileTrialEvidence.Phase.INSERTED))
                    || (expected == LAYOUT_REMOVE
                            && evidence.phase() == TileTrialEvidence.Phase.WAIT_NINE_PAINT);
            if (phaseFits && TileTrialEvidence.unchangedOriginalLayout(
                    before, after, originals, changed)) {
                pendingLayout = LAYOUT_NONE;
                TileTrialState.get().record("EXPECTED_LAYOUT_UNCHANGED",
                        expected == LAYOUT_ADD ? "add" : "remove");
            } else {
                unknownDeferred("ROOT_LAYOUT_AMBIGUOUS");
            }
        }

        @Override protected void onDetachedFromWindow() {
            if (admitted) unknownDeferred("ROOT_DETACHED");
            super.onDetachedFromWindow();
        }

        @Override protected void dispatchDraw(Canvas canvas) {
            requireMain();
            if (drawingActive) {
                unknownDeferred("NESTED_PAINT");
                return;
            }
            if (pendingLayout != LAYOUT_NONE) {
                unknownDeferred("PENDING_LAYOUT_AT_PAINT");
                super.dispatchDraw(canvas);
                return;
            }
            TileTrialEvidence.Cut before = captureStructure();
            long mutationAtStart = mutationRevision;
            long revision = ++startedPaintRevision;
            drawingActive = true;
            drawing.clear();
            try {
                super.dispatchDraw(canvas);
                TileTrialEvidence.Cut after = captureStructure();
                if (!sameStructure(before, after) || mutationRevision != mutationAtStart
                        || drawing.size() != after.children.length) {
                    unknownDeferred("PAINT_HIERARCHY_CHANGED");
                    return;
                }
                Object[] order = new Object[drawing.size()];
                for (int i = 0; i < drawing.size(); i++) {
                    PaintedChild item = drawing.get(i);
                    if (item.index < 0 || item.index >= after.children.length
                            || after.children[item.index] != item.child
                            || !item.evidence.equals(after.evidence[item.index])) {
                        unknownDeferred("DRAW_CHILD_DRIFT");
                        return;
                    }
                    order[i] = item.child;
                }
                TileTrialEvidence.Cut frame = new TileTrialEvidence.Cut(this,
                        after.children, after.parents, after.evidence, order,
                        after.scene, revision, SystemClock.elapsedRealtime());
                lastCompleted = frame;
                completedMutationRevision = mutationRevision;
                onCompletedFrame(frame);
            } finally {
                drawing.clear();
                drawingActive = false;
            }
        }

        @Override protected boolean drawChild(Canvas canvas, View child, long drawingTime) {
            int index = indexOfChild(child);
            String atEntry = childEvidence(child);
            TileView owned = child instanceof TileView ? (TileView) child : null;
            if (owned != null) owned.completedDrawForDispatch = false;
            boolean result = super.drawChild(canvas, child, drawingTime);
            if (drawingActive && (owned == null || owned.completedDrawForDispatch)) {
                drawing.add(new PaintedChild(child, index, atEntry));
            }
            return result;
        }

        TileTrialEvidence.Cut captureCurrent() {
            TileTrialEvidence.Cut structural = captureStructure();
            if (lastCompleted != null && completedMutationRevision == mutationRevision
                    && sameStructure(structural, lastCompleted)) {
                return new TileTrialEvidence.Cut(this, structural.children,
                        structural.parents, structural.evidence, lastCompleted.painted,
                        structural.scene, lastCompleted.paintRevision,
                        lastCompleted.completedElapsedMs);
            }
            return structural;
        }

        private TileTrialEvidence.Cut captureStructure() {
            requireMain();
            int count = getChildCount();
            Object[] children = new Object[count];
            Object[] parents = new Object[count];
            String[] metadata = new String[count];
            for (int i = 0; i < count; i++) {
                View child = getChildAt(i);
                children[i] = child;
                parents[i] = child.getParent();
                metadata[i] = childEvidence(child);
            }
            return new TileTrialEvidence.Cut(this, children, parents, metadata,
                    new Object[0], sceneStamp(), 0, 0);
        }

        private boolean sameStructure(TileTrialEvidence.Cut first,
                TileTrialEvidence.Cut second) {
            if (first.root != second.root || first.children.length != second.children.length
                    || !first.scene.equals(second.scene)) return false;
            for (int i = 0; i < first.children.length; i++) {
                if (first.children[i] != second.children[i]
                        || first.parents[i] != second.parents[i]
                        || !first.evidence[i].equals(second.evidence[i])) return false;
            }
            return true;
        }

        private String childEvidence(View child) {
            ViewGroup.LayoutParams params = child.getLayoutParams();
            return child.getClass().getName() + ":" + child.getId()
                    + ":visibility=" + child.getVisibility()
                    + ":bounds=" + child.getLeft() + "," + child.getTop() + ","
                    + child.getRight() + "," + child.getBottom()
                    + ":alpha=" + Float.floatToRawIntBits(child.getAlpha())
                    + ":z=" + Float.floatToRawIntBits(child.getZ())
                    + ":layout=" + (params == null ? "none"
                            : params.getClass().getName() + "," + params.width + ","
                                    + params.height);
        }

        private final class PaintedChild {
            final View child;
            final int index;
            final String evidence;
            PaintedChild(View child, int index, String evidence) {
                this.child = child;
                this.index = index;
                this.evidence = evidence;
            }
        }
    }
}
