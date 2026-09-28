package com.techrebbe.supernote.leasetrial;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Canvas;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.TextView;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;

/** Separate synthetic Activity for one actual no-child layout/paint preflight. */
public final class LeaseTrialActivity extends Activity {
    private final View[] originals = new View[LeaseTrialContract.childCount()];
    private final Handler main = new Handler(Looper.getMainLooper());
    private TrialRoot root;
    private TrialEvidence trial;
    private long activitySerial;
    private long trialToken;
    private long firstFocusPaintFloorRevision = -1;
    private String lifecycle = "NEW";
    private boolean admitted;
    private final TrialSessionGuard sessionGuard = new TrialSessionGuard();

    @Override public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        root = new TrialRoot();
        activitySerial = LeaseTrialState.get().register(this);
        if (activitySerial < 0) {
            finish();
            return;
        }
        admitted = true;
        root.setId(LeaseTrialContract.ROOT_ID);
        root.setBackgroundColor(0xfff7f7f2);
        for (int i = 0; i < originals.length; i++) {
            LeaseTrialContract.Child spec = LeaseTrialContract.childAt(i);
            TextView child = new TextView(this);
            child.setId(spec.id);
            child.setContentDescription(spec.name);
            child.setText(spec.name);
            child.setTextSize(12f);
            child.setGravity(Gravity.CENTER);
            child.setTextColor(0xff202020);
            child.setBackgroundColor(spec.color);
            child.setFocusable(false);
            child.setClickable(false);
            FrameLayout.LayoutParams params = new FrameLayout.LayoutParams(dp(96), dp(56));
            params.gravity = Gravity.TOP | Gravity.LEFT;
            params.leftMargin = dp(8 + 104 * spec.column);
            params.topMargin = dp(8 + 64 * spec.row);
            root.addView(child, params);
            originals[i] = child;
        }
        if (!originalsExact()) throw new IllegalStateException("nine originals required");
        setContentView(root);
        lifecycle = "CREATED";
        LeaseTrialState.get().record("ACTIVITY_CREATE", "serial=" + activitySerial);
    }

    @Override protected void onStart() {
        super.onStart();
        if (!admitted) return;
        lifecycle = "STARTED";
        LeaseTrialState.get().record("ACTIVITY_START", "");
    }

    @Override protected void onResume() {
        super.onResume();
        if (!admitted) return;
        lifecycle = "RESUMED";
        LeaseTrialState.get().record("ACTIVITY_RESUME", "");
    }

    @Override protected void onPause() {
        if (admitted) {
            taint("ACTIVITY_PAUSED");
            lifecycle = "PAUSED";
            LeaseTrialState.get().record("ACTIVITY_PAUSE", "");
        }
        super.onPause();
    }

    @Override protected void onStop() {
        if (admitted) {
            taint("ACTIVITY_STOPPED");
            lifecycle = "STOPPED";
            LeaseTrialState.get().record("ACTIVITY_STOP", "");
        }
        super.onStop();
    }

    @Override protected void onDestroy() {
        if (admitted) {
            taint("ACTIVITY_DESTROYED");
            lifecycle = "DESTROYED";
            LeaseTrialState.get().record("ACTIVITY_DESTROY", "");
            LeaseTrialState.get().unregister(this);
        }
        super.onDestroy();
    }

    @Override public void onWindowFocusChanged(boolean hasFocus) {
        if (admitted && !hasFocus) taint("WINDOW_FOCUS_LOST");
        super.onWindowFocusChanged(hasFocus);
        if (admitted) LeaseTrialState.get().record("WINDOW_FOCUS", Boolean.toString(hasFocus));
        if (sessionGuard.claimInitialFocusPaint(admitted, hasFocus, trial == null)) {
            firstFocusPaintFloorRevision = root.startedPaintRevision;
            root.invalidate();
        }
    }

    @Override protected void onNewIntent(Intent intent) {
        if (admitted) taint("ACTIVITY_REUSED");
        super.onNewIntent(intent);
    }

    /** The provider dispatches only these bounded commands on the main Looper. */
    public boolean applyCommand(String command) {
        requireMain();
        if (!admitted || LeaseTrialState.get().activity() != this) return false;
        if ("finish".equals(command)) {
            taint("FINISH_REQUESTED");
            finish();
            return true;
        }
        if (!sessionGuard.allowPreflight()
                || !"preflight-noop-layout".equals(command) || trial != null
                || !"RESUMED".equals(lifecycle) || !root.isAttachedToWindow()
                || !root.hasWindowFocus() || root.isLayoutRequested()
                || firstFocusPaintFloorRevision < 0
                || !originalsExact() || root.anyOriginalLayoutRequested()) return false;
        TrialEvidence.Cut baseline = root.lastCompletedFrame();
        TrialEvidence.Cut live = root.captureLive();
        if (baseline == null
                || baseline.startedPaintRevision <= firstFocusPaintFloorRevision
                || !baseline.sameNineAndRevision(live)
                || baseline.startedPaintRevision != live.startedPaintRevision
                || baseline.completedPaintRevision != live.completedPaintRevision
                || baseline.completedPaintElapsedMs != live.completedPaintElapsedMs) return false;
        try {
            trial = TrialEvidence.begin(baseline, SystemClock.elapsedRealtime());
        } catch (IllegalStateException notReady) {
            return false;
        }
        trialToken++;
        LeaseTrialState.get().record("TRIAL_BEGIN", "token=" + trialToken
                + " mutation=" + baseline.mutationRevision
                + " paint=" + baseline.startedPaintRevision);
        final long token = trialToken;
        if (!main.postDelayed(new Runnable() {
            @Override public void run() {
                if (token != trialToken || trial == null) return;
                TrialEvidence.State old = trial.state();
                trial.expire(SystemClock.elapsedRealtime());
                if (old != trial.state()) {
                    LeaseTrialState.get().record("TRIAL_UNKNOWN", trial.reason());
                }
            }
        }, TrialEvidence.DEADLINE_MS)) {
            unknown("TIMEOUT_SCHEDULING_REJECTED");
            return false;
        }
        root.requestLayout();
        return true;
    }

    private boolean tryControlledNoopLayout(boolean changed,
            int left, int top, int right, int bottom) {
        if (trial == null || trial.state() != TrialEvidence.State.WAIT_LAYOUT) {
            if (trial != null && trial.state() != TrialEvidence.State.PASS
                    && trial.state() != TrialEvidence.State.UNKNOWN) {
                unknown("UNEXPECTED_LAYOUT_PASS");
            }
            return false;
        }
        if (!originalsExact() || !"RESUMED".equals(lifecycle)
                || left != root.getLeft() || top != root.getTop()
                || right != root.getRight() || bottom != root.getBottom()) {
            unknown("LAYOUT_ENTRY_CHANGED");
            return false;
        }
        TrialEvidence.Cut entry = root.captureLive();
        boolean accepted = trial.onLayout(entry, changed,
                root.anyOriginalLayoutRequested(), SystemClock.elapsedRealtime());
        LeaseTrialState.get().record(accepted ? "NOOP_LAYOUT_ENTERED" : "NOOP_LAYOUT_REJECTED",
                "token=" + trialToken + " changed=" + changed
                + " mutation=" + entry.mutationRevision);
        if (accepted) root.invalidate();
        return accepted;
    }

    private void onCompletedFrame(TrialEvidence.Cut frame) {
        if (trial != null && trial.state() == TrialEvidence.State.PASS) {
            taint("POST_PASS_PAINT");
            return;
        }
        if (trial == null || trial.state() != TrialEvidence.State.WAIT_PAINT) return;
        trial.onCompletedPaint(frame, SystemClock.elapsedRealtime());
        LeaseTrialState.get().record("POST_LAYOUT_PAINT", "token=" + trialToken
                + " state=" + trial.state() + " paint=" + frame.startedPaintRevision);
        if (trial.state() != TrialEvidence.State.WAIT_SECOND_SAMPLE) return;
        final long token = trialToken;
        if (!main.postDelayed(new Runnable() {
            @Override public void run() {
                if (trial == null || token != trialToken
                        || trial.state() != TrialEvidence.State.WAIT_SECOND_SAMPLE) return;
                if (root.isLayoutRequested() || root.anyOriginalLayoutRequested()) {
                    unknown("SECOND_SAMPLE_HAS_PENDING_LAYOUT");
                    return;
                }
                TrialEvidence.Cut live = root.captureLive();
                trial.onSecondSample(live, SystemClock.elapsedRealtime());
                LeaseTrialState.get().record(trial.state() == TrialEvidence.State.PASS
                        ? "NO_CHILD_PREFLIGHT_PASS" : "TRIAL_UNKNOWN",
                        "token=" + trialToken + " reason=" + trial.reason());
            }
        }, TrialEvidence.SECOND_SAMPLE_GAP_MS + 1)) unknown("SAMPLE_SCHEDULING_REJECTED");
    }

    private void unknown(String reason) {
        if (trial == null || trial.state() == TrialEvidence.State.PASS
                || trial.state() == TrialEvidence.State.UNKNOWN) return;
        trial.unknown(reason);
        LeaseTrialState.get().record("TRIAL_UNKNOWN", "token=" + trialToken
                + " reason=" + reason);
    }

    private void taint(String reason) {
        requireMain();
        if (!sessionGuard.tainted()) {
            sessionGuard.taint(reason);
            LeaseTrialState.get().record("SESSION_TAINTED", "token=" + trialToken
                    + " reason=" + sessionGuard.reason());
        }
        unknown(reason);
    }

    private boolean originalsExact() {
        if (root == null || root.getChildCount() != originals.length) return false;
        for (int i = 0; i < originals.length; i++) {
            if (originals[i] == null || root.getChildAt(i) != originals[i]
                    || originals[i].getParent() != root
                    || originals[i].getVisibility() != View.VISIBLE) return false;
        }
        return true;
    }

    private String sceneStamp() {
        return LeaseTrialContract.SCENE + ":orientation="
                + getResources().getConfiguration().orientation
                + ":root=" + System.identityHashCode(root)
                + ":attached=" + root.isAttachedToWindow()
                + ":bounds=" + root.getLeft() + "," + root.getTop() + ","
                + root.getRight() + "," + root.getBottom()
                + ":padding=" + root.getPaddingLeft() + "," + root.getPaddingTop()
                + "," + root.getPaddingRight() + "," + root.getPaddingBottom()
                + ":count=" + root.getChildCount()
                + ":clip=" + root.getClipChildren() + "," + root.getClipToPadding()
                + ":customOrder=" + root.customDrawingOrderEnabled();
    }

    public String snapshotJson() {
        requireMain();
        try {
            TrialEvidence.Cut currentCut = root.captureLive();
            TrialEvidence.Cut completedCut = root.lastCompletedFrame();
            JSONObject state = new JSONObject();
            state.put("schema", LeaseTrialContract.STATE_SCHEMA);
            state.put("process", LeaseTrialState.get().identityJson());
            state.put("activityPresent", admitted);
            state.put("activitySerial", activitySerial);
            state.put("lifecycle", lifecycle);
            state.put("sampleElapsedMs", SystemClock.elapsedRealtime());
            state.put("rootAttached", root.isAttachedToWindow());
            state.put("rootHasFocus", root.hasWindowFocus());
            state.put("firstFocusPaintFloorRevision", firstFocusPaintFloorRevision);
            state.put("rootLayoutRequested", root.isLayoutRequested());
            state.put("originalsExact", originalsExact());
            state.put("rootLayoutCalls", root.layoutCalls);
            state.put("rootControlledNoopCalls", root.controlledNoopCalls);
            state.put("tainted", sessionGuard.tainted());
            state.put("taintReason", sessionGuard.reason());
            state.put("current", cutJson(currentCut));
            state.put("lastCompletedPaint", cutJson(completedCut));
            JSONObject proof = new JSONObject();
            proof.put("token", trialToken);
            proof.put("state", trial == null ? "IDLE" : trial.state().name());
            proof.put("reason", trial == null ? "NOT_STARTED" : trial.reason());
            proof.put("layoutCalls", trial == null ? 0 : trial.layoutCalls());
            proof.put("rollbackVerified", trial != null && trial.rollbackVerified());
            TrialEvidence.Cut verified = trial == null ? null : trial.secondSample();
            proof.put("currentlyValid", sessionGuard.currentlyValid(verified != null
                    && verified.sameNineAndRevision(currentCut)
                    && currentCut.exactNinePainted()
                    && currentCut.startedPaintRevision == verified.startedPaintRevision
                    && currentCut.completedPaintElapsedMs == verified.completedPaintElapsedMs
                    && "RESUMED".equals(lifecycle) && root.isAttachedToWindow()
                    && root.hasWindowFocus() && !root.isLayoutRequested()
                    && !root.anyOriginalLayoutRequested()));
            proof.put("baseline", cutJson(trial == null ? null : trial.baseline()));
            proof.put("layoutEntry", cutJson(trial == null ? null : trial.layoutEntry()));
            proof.put("postPaint", cutJson(trial == null ? null : trial.laterPaint()));
            proof.put("secondSample", cutJson(trial == null ? null : trial.secondSample()));
            state.put("trial", proof);
            return state.toString();
        } catch (JSONException exception) {
            throw new IllegalStateException("state JSON failed", exception);
        }
    }

    private Object cutJson(TrialEvidence.Cut cut) throws JSONException {
        // JSONObject.put(key, null) removes the key. JSON null must be explicit.
        if (cut == null) return JSONObject.NULL;
        JSONObject value = new JSONObject();
        value.put("rootIdentityHash", System.identityHashCode(cut.root));
        value.put("scene", cut.scene);
        value.put("mutationRevision", cut.mutationRevision);
        value.put("startedPaintRevision", cut.startedPaintRevision);
        value.put("completedPaintRevision", cut.completedPaintRevision);
        value.put("completedPaintElapsedMs", cut.completedPaintElapsedMs);
        value.put("exactNinePainted", cut.exactNinePainted());
        JSONArray children = new JSONArray();
        JSONArray order = new JSONArray();
        for (int i = 0; i < originals.length; i++) {
            JSONObject child = new JSONObject();
            child.put("index", i);
            child.put("identityHash", cut.childAt(i) == null ? 0
                    : System.identityHashCode(cut.childAt(i)));
            child.put("matchesOriginal", cut.childAt(i) == originals[i]);
            child.put("parentIsRoot", cut.parentAt(i) == cut.root);
            child.put("evidence", cut.childEvidenceAt(i));
            children.put(child);
            order.put(cut.paintedAt(i) == null ? 0
                    : System.identityHashCode(cut.paintedAt(i)));
        }
        value.put("children", children);
        value.put("effectivePaintOrder", order);
        return value;
    }

    private int dp(int value) {
        return (int) (value * getResources().getDisplayMetrics().density + 0.5f);
    }

    private static void requireMain() {
        if (Looper.myLooper() != Looper.getMainLooper()) {
            throw new IllegalStateException("trial requires main Looper");
        }
    }

    private final class TrialRoot extends FrameLayout {
        private final ArrayList<View> drawing = new ArrayList<>();
        private TrialEvidence.Cut lastFrame;
        private long mutationRevision;
        private long startedPaintRevision;
        private long layoutCalls;
        private long controlledNoopCalls;
        private boolean drawingActive;

        TrialRoot() {
            super(LeaseTrialActivity.this);
            setChildrenDrawingOrderEnabled(false);
        }

        boolean customDrawingOrderEnabled() { return isChildrenDrawingOrderEnabled(); }

        void beforeMutation() {
            requireMain();
            if (trial != null) taint("UNCONTROLLED_ROOT_MUTATION");
            if (mutationRevision == Long.MAX_VALUE) {
                taint("MUTATION_REVISION_OVERFLOW");
                throw new IllegalStateException("mutation revision exhausted");
            }
            mutationRevision++;
        }

        @Override public void addView(View child, int index, ViewGroup.LayoutParams params) {
            beforeMutation();
            super.addView(child, index, params);
        }

        @Override public void removeView(View child) {
            beforeMutation();
            super.removeView(child);
        }

        @Override protected void onLayout(boolean changed,
                int left, int top, int right, int bottom) {
            layoutCalls++;
            if (tryControlledNoopLayout(changed, left, top, right, bottom)) {
                // Nine original children are already measured/laid out identically.
                // Do not call FrameLayout.onLayout: it may mutate their geometry.
                controlledNoopCalls++;
                return;
            }
            beforeMutation();
            super.onLayout(changed, left, top, right, bottom);
            if (trial != null && trial.state() != TrialEvidence.State.PASS
                    && trial.state() != TrialEvidence.State.UNKNOWN) {
                unknown("UNCONTROLLED_LAYOUT");
            }
        }

        @Override protected void onDetachedFromWindow() {
            if (admitted) taint("ROOT_DETACHED");
            beforeMutation();
            super.onDetachedFromWindow();
        }

        @Override protected void dispatchDraw(Canvas canvas) {
            requireMain();
            if (trial != null && trial.state() == TrialEvidence.State.PASS) {
                taint("POST_PASS_PAINT");
            }
            if (drawingActive) {
                taint("NESTED_PAINT");
                super.dispatchDraw(canvas);
                return;
            }
            TrialEvidence.Cut before = captureLive();
            startedPaintRevision++;
            drawingActive = true;
            drawing.clear();
            try {
                super.dispatchDraw(canvas);
                TrialEvidence.Cut after = captureLive();
                if (before.sameNineAndRevision(after) && originalsExact()
                        && drawing.size() == originals.length) {
                    Object[] order = drawing.toArray(new Object[drawing.size()]);
                    TrialEvidence.Cut complete = new TrialEvidence.Cut(this,
                            after.childrenCopy(), after.parentsCopy(),
                            after.childEvidenceCopy(), order,
                            after.scene, mutationRevision, startedPaintRevision,
                            startedPaintRevision, SystemClock.elapsedRealtime());
                    if (complete.exactNinePainted()) {
                        lastFrame = complete;
                        LeaseTrialState.get().record("PAINT_COMPLETE",
                                "revision=" + startedPaintRevision + " mutation="
                                        + mutationRevision);
                        onCompletedFrame(complete);
                    } else {
                        unknown("PAINT_ORDER_MISMATCH");
                    }
                } else {
                    unknown("PAINT_HIERARCHY_CHANGED");
                }
            } finally {
                drawing.clear();
                drawingActive = false;
            }
        }

        @Override protected boolean drawChild(Canvas canvas, View child, long drawingTime) {
            if (drawingActive) drawing.add(child);
            return super.drawChild(canvas, child, drawingTime);
        }

        boolean anyOriginalLayoutRequested() {
            for (View child : originals) {
                if (child == null || child.isLayoutRequested()) return true;
            }
            return false;
        }

        TrialEvidence.Cut lastCompletedFrame() { return lastFrame; }

        TrialEvidence.Cut captureLive() {
            requireMain();
            Object[] children = new Object[originals.length];
            Object[] parents = new Object[originals.length];
            String[] evidence = new String[originals.length];
            Object[] order = new Object[originals.length];
            for (int i = 0; i < originals.length; i++) {
                View child = i < getChildCount() ? getChildAt(i) : null;
                children[i] = child;
                parents[i] = child == null ? null : child.getParent();
                evidence[i] = child == null ? "MISSING" : childEvidence(child);
                order[i] = lastFrame == null ? null : lastFrame.paintedAt(i);
            }
            return new TrialEvidence.Cut(this, children, parents, evidence, order,
                    sceneStamp(), mutationRevision, startedPaintRevision,
                    lastFrame == null ? 0 : lastFrame.completedPaintRevision,
                    lastFrame == null ? 0 : lastFrame.completedPaintElapsedMs);
        }

        private String childEvidence(View child) {
            StringBuilder value = new StringBuilder();
            value.append(child.getClass().getName()).append(':').append(child.getId())
                    .append(':').append(child.getVisibility())
                    .append(':').append(child.getLeft()).append(',').append(child.getTop())
                    .append(',').append(child.getRight()).append(',').append(child.getBottom())
                    .append(':').append(Float.floatToRawIntBits(child.getAlpha()))
                    .append(':').append(Float.floatToRawIntBits(child.getElevation()))
                    .append(':').append(Float.floatToRawIntBits(child.getTranslationX()))
                    .append(':').append(Float.floatToRawIntBits(child.getTranslationY()))
                    .append(':').append(Float.floatToRawIntBits(child.getTranslationZ()))
                    .append(':').append(Float.floatToRawIntBits(child.getScaleX()))
                    .append(':').append(Float.floatToRawIntBits(child.getScaleY()))
                    .append(':').append(Float.floatToRawIntBits(child.getRotation()))
                    .append(':').append(Float.floatToRawIntBits(child.getZ()));
            ViewGroup.LayoutParams params = child.getLayoutParams();
            if (params == null) value.append(":no-layout");
            else {
                value.append(':').append(params.getClass().getName())
                        .append(':').append(params.width).append(':').append(params.height);
                if (params instanceof FrameLayout.LayoutParams) {
                    FrameLayout.LayoutParams frame = (FrameLayout.LayoutParams) params;
                    value.append(':').append(frame.gravity)
                            .append(':').append(frame.leftMargin).append(',')
                            .append(frame.topMargin).append(',')
                            .append(frame.rightMargin).append(',').append(frame.bottomMargin);
                }
            }
            return value.toString();
        }
    }
}
