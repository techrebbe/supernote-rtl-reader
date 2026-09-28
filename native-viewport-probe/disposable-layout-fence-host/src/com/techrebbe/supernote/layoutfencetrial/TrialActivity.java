package com.techrebbe.supernote.layoutfencetrial;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.Process;
import android.os.SystemClock;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.TextView;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;

/** One synthetic, no-child-added API-30 layout-fence experiment per process. */
public final class TrialActivity extends Activity
        implements TrialParent.Host, TrialRoot.Host {
    static final class SentinelResult {
        final boolean unchanged;
        final String json;

        SentinelResult(boolean unchanged, String json) {
            this.unchanged = unchanged;
            this.json = json;
        }
    }
    static final class RefreshResult {
        final String token;
        final long paintFloorRevision;
        final long completedPaintCountFloor;
        final long requestedElapsedMs;

        RefreshResult(String token, long paintFloorRevision,
                long completedPaintCountFloor, long requestedElapsedMs) {
            this.token = token;
            this.paintFloorRevision = paintFloorRevision;
            this.completedPaintCountFloor = completedPaintCountFloor;
            this.requestedElapsedMs = requestedElapsedMs;
        }
    }
    private final View[] originals = new View[TrialEvidence.ORIGINAL_COUNT];
    private final Handler main = new Handler(Looper.getMainLooper());
    private final TrialSessionGuard session = new TrialSessionGuard();
    private final AtomicBoolean watchdogExpired = new AtomicBoolean();
    private final AtomicBoolean cleanupVerified = new AtomicBoolean();
    private final String activityToken = UUID.randomUUID().toString();
    private TrialParent parent;
    private TrialRoot root;
    private TrialEvidence.Trial trial;
    private TrialEvidence.Cut baseline;
    private TrialEvidence.Cut refreshEntry;
    private TrialEvidence.Cut cleanupFrame;
    private TrialEvidence.Cut cleanupSecondFrame;
    private long activitySerial;
    private volatile long trialToken;
    private long firstFocusPaintFloorRevision = -1;
    private long refreshPaintFloorRevision = -1;
    private long refreshCompletedPaintCountFloor = -1;
    private long refreshRequestedElapsedMs;
    private String refreshToken;
    private long cleanupRequestedElapsedMs;
    private long cleanupSecondRequestElapsedMs;
    private long hardStopElapsedMs;
    private String lifecycle = "NEW";
    private String cleanupStatus = "NOT_REQUIRED";
    private boolean admitted;
    private boolean sceneFrozen;
    private boolean rootLost;
    private boolean cleanupPending;
    private boolean cleanupSecondRequested;
    private boolean unknownRecorded;

    /** Exact Activity token for provider commands; not a substitute for object identity. */
    public String getActivityToken() { return activityToken; }

    /** Exact synthetic root object for an observational, process-scoped hook. */
    public TrialRoot getTrialRoot() { return root; }

    /** One app-owned invalidate; the command must later prove a new completed paint. */
    RefreshResult requestRefresh(Bundle pins) {
        requireMain();
        if (!pinsMatch(pins) || !admitted || TrialProcess.get().activity() != this
                || !TrialProcess.get().refreshDispatching(pins)
                || refreshToken != null || trial != null || session.commandClaimed()
                || !readyForTrial()) return null;
        TrialEvidence.Cut completed = root.lastCompletedFrame();
        TrialEvidence.Cut live = root.captureLive();
        if (completed == null || !completed.exactNinePainted()
                || !completed.sameLiveFrame(live)
                || firstFocusPaintFloorRevision < 0
                || completed.startedPaintRevision <= firstFocusPaintFloorRevision
                || !completed.bounds.equals(parent.baseBounds())) return null;
        long floor = root.getStartedPaintRevision();
        long countFloor = root.getCompletedPaintCount();
        long requestedAt = SystemClock.elapsedRealtime();
        if (!TrialProcess.get().refreshDispatching(pins)) return null;
        root.invalidate();
        if (!TrialProcess.get().refreshDispatching(pins)
                || root.getStartedPaintRevision() != floor
                || root.getCompletedPaintCount() != countFloor
                || root.lastCompletedFrame() != completed
                || !live.sameLiveFrame(root.captureLive())
                || !readyForTrial()) return null;
        refreshEntry = live;
        refreshPaintFloorRevision = floor;
        refreshCompletedPaintCountFloor = countFloor;
        refreshRequestedElapsedMs = requestedAt;
        refreshToken = UUID.randomUUID().toString();
        TrialProcess.get().record("REFRESH_REQUESTED", "paintFloor=" + floor
                + " completedCountFloor=" + countFloor);
        return new RefreshResult(refreshToken, floor, countFloor, requestedAt);
    }

    /** App-owned no-op layout after observer revert/unload; never a new trial. */
    SentinelResult performSentinel(String stage, Bundle pins) {
        requireMain();
        try {
            JSONObject witness = new JSONObject();
            witness.put("stage", stage);
            witness.put("pid", TrialProcess.get().pid());
            witness.put("incarnation", TrialProcess.get().incarnation());
            witness.put("activitySerial", activitySerial);
            witness.put("activityToken", activityToken);
            witness.put("rootToken", root == null ? JSONObject.NULL : root.getRootToken());
            witness.put("rootIdentityHash", root == null ? 0 : System.identityHashCode(root));
            witness.put("sampleElapsedMs", SystemClock.elapsedRealtime());
            if (!pinsMatch(pins) || !TrialProcess.get().sentinelDispatching(stage, pins)
                    || trial == null || trial.state() != TrialEvidence.State.PASS
                    || !cleanupVerified.get() || session.tainted()
                    || !"RESUMED".equals(lifecycle) || !safeRootForCleanup()
                    || !root.hasWindowFocus() || parent.isLayoutRequested()
                    || root.isLayoutRequested() || root.originalsHavePendingLayout(originals)) {
                witness.put("unchanged", false);
                witness.put("reason", "SENTINEL_PRECONDITION_REJECTED");
                TrialProcess.get().record("SENTINEL_REJECTED", stage);
                return new SentinelResult(false, witness.toString());
            }
            TrialEvidence.Cut before = root.captureLive();
            TrialEvidence.Cut beforePaint = root.lastCompletedFrame();
            long beforePaintCount = root.getCompletedPaintCount();
            if (!postPassCurrent(before, beforePaint)) {
                witness.put("unchanged", false);
                witness.put("reason", "SENTINEL_BEFORE_NOT_CURRENT");
                return new SentinelResult(false, witness.toString());
            }
            witness.put("before", cutJson(before));
            witness.put("beforeLastCompletedPaint", cutJson(beforePaint));
            witness.put("beforePaintCount", beforePaintCount);
            // ViewGroup.layout is final. This same-bounds call is made by the app
            // after observer disarm/unload, never by the Frida host.
            root.layout(before.bounds.left, before.bounds.top,
                    before.bounds.right, before.bounds.bottom);
            TrialEvidence.Cut after = root.captureLive();
            TrialEvidence.Cut afterPaint = root.lastCompletedFrame();
            long afterPaintCount = root.getCompletedPaintCount();
            boolean unchanged = pinsMatch(pins)
                    && TrialProcess.get().activity() == this
                    && before.sameLiveFrame(after)
                    && beforePaint != null && beforePaint.sameLiveFrame(afterPaint)
                    && beforePaintCount == afterPaintCount
                    && !session.tainted() && !watchdogExpired.get()
                    && safeRootForCleanup() && root.hasWindowFocus()
                    && !parent.isLayoutRequested() && !root.isLayoutRequested()
                    && !root.originalsHavePendingLayout(originals)
                    && postPassCurrent(after, afterPaint);
            witness.put("after", cutJson(after));
            witness.put("afterLastCompletedPaint", cutJson(afterPaint));
            witness.put("afterPaintCount", afterPaintCount);
            witness.put("unchanged", unchanged);
            witness.put("reason", unchanged ? "EXACT_NOOP_LAYOUT"
                    : "SENTINEL_SCENE_OR_PAINT_DRIFT");
            TrialProcess.get().record(unchanged ? "SENTINEL_PASS" : "SENTINEL_UNKNOWN",
                    stage + " unchanged=" + unchanged);
            return new SentinelResult(unchanged, witness.toString());
        } catch (JSONException exception) {
            throw new IllegalStateException("sentinel JSON failed", exception);
        }
    }

    /** Final disarm must prove the exact two-paint restoration is still current. */
    boolean finishAfterSentinels(Bundle pins) {
        requireMain();
        if (!pinsMatch(pins) || root == null) return false;
        TrialEvidence.Cut live = root.captureLive();
        TrialEvidence.Cut latest = root.lastCompletedFrame();
        return postPassCurrent(live, latest) && TrialProcess.get().finish(pins);
    }

    private boolean postPassCurrent(TrialEvidence.Cut live,
            TrialEvidence.Cut latestFrame) {
        requireMain();
        if (trial == null || trial.state() != TrialEvidence.State.PASS
                || !cleanupVerified.get() || session.tainted()
                || watchdogExpired.get() || !"RESUMED".equals(lifecycle)
                || !safeRootForCleanup() || !root.hasWindowFocus()
                || parent.isLayoutRequested() || root.isLayoutRequested()
                || root.originalsHavePendingLayout(originals)) return false;
        long now = SystemClock.elapsedRealtime();
        long armDeadline = TrialProcess.get().activeArmDeadlineElapsedMs(now);
        return trial.currentlyValid(live, latestFrame, now, armDeadline)
                && TrialProcess.get().activeArmDeadlineElapsedMs(
                        SystemClock.elapsedRealtime()) == armDeadline;
    }

    @Override public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        activitySerial = TrialProcess.get().register(this);
        if (activitySerial < 0) {
            finish();
            return;
        }
        admitted = true;
        root = new TrialRoot(this, TrialContract.rootToken(
                TrialProcess.get().incarnation(), UUID.randomUUID().toString()), this);
        root.setId(TrialContract.ROOT_ID);
        root.setBackgroundColor(0xfff7f7f2);
        parent = new TrialParent(this, root, this, dp(8));
        parent.setId(TrialContract.PARENT_ID);
        parent.setBackgroundColor(0xffdadad6);
        for (int i = 0; i < originals.length; i++) {
            TrialContract.Child spec = TrialContract.childAt(i);
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
        parent.addView(root, new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
        if (!originalsExact() || !parent.exactSoleChild()) {
            throw new IllegalStateException("exact synthetic nine-child scene required");
        }
        setContentView(parent);
        TrialProcess.get().publishPins(this, root.getRootToken());
        sceneFrozen = true;
        lifecycle = "CREATED";
        TrialProcess.get().record("ACTIVITY_CREATE", "serial=" + activitySerial);
    }

    @Override protected void onStart() {
        super.onStart();
        if (!admitted) return;
        lifecycle = "STARTED";
        TrialProcess.get().record("ACTIVITY_START", "");
    }

    @Override protected void onResume() {
        super.onResume();
        if (!admitted) return;
        lifecycle = "RESUMED";
        TrialProcess.get().record("ACTIVITY_RESUME", "");
    }

    @Override protected void onPause() {
        if (admitted) {
            taint("ACTIVITY_PAUSED");
            lifecycle = "PAUSED";
            TrialProcess.get().record("ACTIVITY_PAUSE", "");
        }
        super.onPause();
    }

    @Override protected void onStop() {
        if (admitted) {
            taint("ACTIVITY_STOPPED");
            lifecycle = "STOPPED";
            TrialProcess.get().record("ACTIVITY_STOP", "");
        }
        super.onStop();
    }

    @Override protected void onDestroy() {
        if (admitted) {
            taint("ACTIVITY_DESTROYED");
            lifecycle = "DESTROYED";
            TrialProcess.get().record("ACTIVITY_DESTROY", "");
            TrialProcess.get().unregister(this);
        }
        super.onDestroy();
    }

    @Override public void onWindowFocusChanged(boolean hasFocus) {
        if (admitted && !hasFocus) taint("WINDOW_FOCUS_LOST");
        super.onWindowFocusChanged(hasFocus);
        if (admitted) TrialProcess.get().record("WINDOW_FOCUS", Boolean.toString(hasFocus));
        if (session.claimFirstFocusPaint(admitted, hasFocus)) {
            firstFocusPaintFloorRevision = root.getStartedPaintRevision();
            root.invalidate();
        }
    }

    @Override protected void onNewIntent(Intent intent) {
        if (admitted) taint("ACTIVITY_REUSED");
        super.onNewIntent(intent);
    }

    /** Called on the main Looper with five exact identity pins and the arm token. */
    public boolean applyCommand(TrialEvidence.Command command, Bundle pins) {
        requireMain();
        if (!pinsMatch(pins) || !admitted || TrialProcess.get().activity() != this
                || command == null || trial != null
                || !TrialProcess.get().commandDispatching(pins)
                || refreshEntry == null || refreshToken == null
                || !refreshToken.equals(pins.getString("refreshToken"))
                || !session.claimCommand()) return false;
        if (!readyForTrial()) {
            session.taint("BASELINE_NOT_READY");
            TrialProcess.get().record("COMMAND_REJECTED", "baseline not ready; no retry");
            return false;
        }
        TrialEvidence.Cut completed = root.lastCompletedFrame();
        TrialEvidence.Cut live = root.captureLive();
        long now = SystemClock.elapsedRealtime();
        if (!TrialEvidence.refreshedBaseline(refreshEntry, completed, live,
                    refreshPaintFloorRevision, refreshRequestedElapsedMs, now)
                || root.getCompletedPaintCount() <= refreshCompletedPaintCountFloor
                || firstFocusPaintFloorRevision < 0
                || completed.startedPaintRevision <= firstFocusPaintFloorRevision
                || !completed.bounds.equals(parent.baseBounds())) {
            session.taint("BASELINE_CUT_CHANGED");
            TrialProcess.get().record("COMMAND_REJECTED", "baseline drift; no retry");
            return false;
        }
        try {
            trial = TrialEvidence.Trial.begin(command, completed, now);
        } catch (IllegalStateException notReady) {
            session.taint("BASELINE_PAINT_STALE");
            return false;
        }
        baseline = completed;
        trialToken++;
        hardStopElapsedMs = trial.deadlineElapsedMs() + TrialContract.HARD_STOP_GRACE_MS;
        TrialProcess.get().record("TRIAL_BEGIN", "token=" + trialToken
                + " command=" + command.wire + " root=" + root.getRootToken()
                + " preCallRevision=" + root.getParentPreCallRevision());
        final long token = trialToken;
        try {
            startWatchdog(token, trial.deadlineElapsedMs(), hardStopElapsedMs);
        } catch (RuntimeException startFailure) {
            // No write has been requested or made yet. Reject without entering
            // a trial whose cleanup would depend on an unavailable watchdog.
            trial.unknown("WATCHDOG_START_FAILED");
            session.taint("WATCHDOG_START_FAILED");
            cleanupStatus = "NOT_MUTATED_WATCHDOG_UNAVAILABLE";
            TrialProcess.get().record("TRIAL_UNKNOWN", cleanupStatus);
            return false;
        }
        if (!TrialProcess.get().trialWatchdogStarted(pins)) {
            trial.unknown("ARM_HANDOFF_REJECTED");
            session.taint("ARM_HANDOFF_REJECTED");
            cleanupStatus = "NOT_MUTATED_ARM_HANDOFF_REJECTED";
            return false;
        }
        if (!main.postDelayed(new Runnable() {
            @Override public void run() {
                if (trial == null || token != trialToken || cleanupVerified.get()) return;
                trial.expire(SystemClock.elapsedRealtime());
                if (trial.state() == TrialEvidence.State.UNKNOWN) {
                    unknownAndRestore(trial.reason());
                }
            }
        }, TrialEvidence.DEADLINE_MS)) {
            unknownAndRestore("DEADLINE_POST_REJECTED");
            return false;
        }
        try {
            switch (command) {
                case PARENT_PLUS:
                    parent.setDesiredDelta(1);
                    parent.requestLayout();
                    break;
                case PARENT_MINUS:
                    parent.setDesiredDelta(-1);
                    parent.requestLayout();
                    break;
                case UNCHANGED:
                    parent.setDesiredDelta(0);
                    parent.requestLayout();
                    break;
                case DIRECT_LAYOUT:
                    runDirectLayout();
                    break;
                case DIRECT_OFFSET:
                    runDirectOffset();
                    break;
                case ABA:
                    parent.layoutRootAtDeltaNow(1);
                    if (trial.state() == TrialEvidence.State.WAIT_ABA_RETURN) {
                        parent.layoutRootAtDeltaNow(0);
                    }
                    root.invalidate();
                    break;
                default:
                    unknownAndRestore("UNSUPPORTED_COMMAND");
            }
        } catch (RuntimeException commandFailure) {
            unknownAndRestore("COMMAND_EXCEPTION_" + commandFailure.getClass().getSimpleName());
            return false;
        }
        return trial.state() != TrialEvidence.State.UNKNOWN;
    }

    private void runDirectLayout() {
        TrialEvidence.Cut before = root.captureLive();
        TrialEvidence.Bounds target = before.bounds.withRightDelta(1);
        root.layout(target.left, target.top, target.right, target.bottom);
        trial.onDirectAfter(before, root.captureLive(), SystemClock.elapsedRealtime());
        TrialProcess.get().record("DIRECT_LAYOUT_AFTER_WRITE", "parentPreCallRevision="
                + root.getParentPreCallRevision());
        if (trial.state() == TrialEvidence.State.UNKNOWN) unknownAndRestore(trial.reason());
        root.invalidate();
    }

    private void runDirectOffset() {
        TrialEvidence.Cut before = root.captureLive();
        root.offsetLeftAndRight(1);
        root.noteDirectOffsetAfterWrite();
        trial.onDirectAfter(before, root.captureLive(), SystemClock.elapsedRealtime());
        TrialProcess.get().record("DIRECT_OFFSET_AFTER_WRITE", "parentPreCallRevision="
                + root.getParentPreCallRevision());
        if (trial.state() == TrialEvidence.State.UNKNOWN) unknownAndRestore(trial.reason());
        root.invalidate();
    }

    private boolean pinsMatch(Bundle pins) {
        return pins != null && root != null && TrialProcess.get().pinsMatch(pins);
    }

    private boolean readyForTrial() {
        return "RESUMED".equals(lifecycle) && !session.tainted()
                && root != null && parent != null && parent.exactSoleChild()
                && parent.isAttachedToWindow() && root.isAttachedToWindow()
                && root.hasWindowFocus() && !parent.isLayoutRequested()
                && !root.isLayoutRequested() && !root.originalsHavePendingLayout(originals)
                && originalsExact() && root.getWidth() > 0 && root.getHeight() > 0;
    }

    @Override public void beforeParentRootLayout(TrialEvidence.Bounds target) {
        requireMain();
        TrialEvidence.Cut entry = trial == null ? null : root.captureLive();
        long bumped = root.beforeParentRootLayout();
        TrialProcess.get().record("PARENT_PRECALL", "root=" + root.getRootToken()
                + " revision=" + bumped + " old=" + rawRootBounds()
                + " proposed=" + target);
        if (trial == null) return;
        if (trial.state() == TrialEvidence.State.PASS) {
            taint("POST_PASS_PARENT_LAYOUT");
        } else if (trial.state() != TrialEvidence.State.UNKNOWN) {
            if (!trial.onParentPreCall(entry, target, bumped,
                    SystemClock.elapsedRealtime())) unknownAndRestore(trial.reason());
        }
    }

    @Override public void afterParentRootLayout() {
        requireMain();
        if (trial == null || trial.state() == TrialEvidence.State.UNKNOWN
                || trial.state() == TrialEvidence.State.PASS) return;
        trial.onParentLayoutAfter(root.captureLive(), SystemClock.elapsedRealtime());
        if (trial.state() == TrialEvidence.State.UNKNOWN) unknownAndRestore(trial.reason());
        else TrialProcess.get().record("PARENT_LAYOUT_AFTER", "state=" + trial.state()
                + " bounds=" + rawRootBounds() + " revision="
                + root.getParentPreCallRevision());
    }

    @Override public void onParentAnomaly(String reason) {
        if (sceneFrozen) taint(reason);
    }

    @Override public void onParentDetached() {
        if (admitted) {
            rootLost = true;
            taint("PARENT_DETACHED");
        }
    }

    @Override public void onRootHierarchyChanged() {
        if (sceneFrozen) taint("ROOT_HIERARCHY_CHANGED");
    }

    @Override public void onUnfencedRootLayout() {
        if (trial == null) return;
        TrialProcess.get().record("ROOT_LAYOUT_AFTER_WRITE_UNFENCED",
                "root=" + root.getRootToken() + " parentPreCallRevision="
                        + root.getParentPreCallRevision());
        if (trial.command() != TrialEvidence.Command.DIRECT_LAYOUT
                || trial.state() != TrialEvidence.State.WAIT_FIRST_CALL) {
            unknownAndRestore("UNEXPECTED_UNFENCED_ROOT_LAYOUT");
        }
    }

    @Override public void onRootDetached() {
        if (admitted) {
            rootLost = true;
            taint("ROOT_DETACHED");
        }
    }

    @Override public void onPaintInvalid(String reason) {
        if (trial != null) unknownAndRestore(reason);
        TrialProcess.get().record("PAINT_INVALID", reason);
    }

    @Override public void onCompletedFrame(TrialEvidence.Cut frame) {
        TrialProcess.get().record("PAINT_COMPLETE", "revision="
                + frame.startedPaintRevision + " parentPreCallRevision="
                + frame.parentPreCallRevision + " write=" + frame.observedWriteOrdinal);
        if (trial == null) return;
        if (trial.state() == TrialEvidence.State.PASS) {
            taint("POST_PASS_PAINT");
            return;
        }
        if (trial.state() == TrialEvidence.State.UNKNOWN) {
            considerUnknownCleanupFrame(frame);
            return;
        }
        TrialEvidence.State before = trial.state();
        trial.onCompletedPaint(frame, SystemClock.elapsedRealtime());
        if (trial.state() == TrialEvidence.State.UNKNOWN) {
            unknownAndRestore(trial.reason());
            return;
        }
        if (before == TrialEvidence.State.WAIT_FIRST_PAINT
                && trial.state() == TrialEvidence.State.WAIT_RESTORE_CALL) {
            // Request the parent rollback before another traversal can paint the
            // changed bounds. The request queues layout; it does not mutate them here.
            requestRestore();
        } else if (trial.state() == TrialEvidence.State.WAIT_SECOND_PAINT_REQUEST) {
            scheduleSecondPaint();
        } else if (trial.state() == TrialEvidence.State.WAIT_FINAL_SAMPLE) {
            scheduleFinalSample();
        } else if (cleanupPending && before == TrialEvidence.State.WAIT_RESTORE_CALL) {
            unknownAndRestore("EXTRA_PAINT_BEFORE_RESTORE");
        }
    }

    private void scheduleSecondPaint() {
        final long token = trialToken;
        if (!main.postDelayed(new Runnable() {
            @Override public void run() {
                if (token != trialToken || trial == null
                        || trial.state() != TrialEvidence.State.WAIT_SECOND_PAINT_REQUEST) return;
                if (watchdogExpired.get() || !safeRootForCleanup()
                        || parent.isLayoutRequested() || root.isLayoutRequested()
                        || root.originalsHavePendingLayout(originals)) {
                    unknownAndRestore("SECOND_PAINT_SCENE_NOT_STABLE");
                    return;
                }
                TrialEvidence.Cut live = root.captureLive();
                TrialEvidence.Cut latest = root.lastCompletedFrame();
                if (!trial.requestSecondPaint(live, latest,
                        SystemClock.elapsedRealtime())) {
                    unknownAndRestore(trial.reason());
                    return;
                }
                TrialProcess.get().record("SECOND_PAINT_REQUESTED", "after="
                        + latest.startedPaintRevision);
                root.invalidate();
            }
        }, TrialEvidence.SECOND_SAMPLE_GAP_MS + 5)) {
            unknownAndRestore("SECOND_PAINT_POST_REJECTED");
        }
    }

    private void scheduleFinalSample() {
        final long token = trialToken;
        if (!main.post(new Runnable() {
            @Override public void run() {
                if (token != trialToken || trial == null
                        || trial.state() != TrialEvidence.State.WAIT_FINAL_SAMPLE) return;
                if (watchdogExpired.get() || !safeRootForCleanup()
                        || parent.isLayoutRequested() || root.isLayoutRequested()
                        || root.originalsHavePendingLayout(originals)) {
                    unknownAndRestore("FINAL_SAMPLE_SCENE_NOT_STABLE");
                    return;
                }
                TrialEvidence.Cut live = root.captureLive();
                TrialEvidence.Cut latest = root.lastCompletedFrame();
                trial.onSecondSample(live, latest, SystemClock.elapsedRealtime());
                if (trial.state() != TrialEvidence.State.PASS) {
                    unknownAndRestore(trial.reason());
                    return;
                }
                cleanupVerified.set(true);
                cleanupPending = false;
                cleanupStatus = "RESTORED_VERIFIED";
                TrialProcess.get().record("TRIAL_PASS", "token=" + trialToken
                        + " reason=" + trial.reason()
                        + " completeMutationCoverage=false");
            }
        })) {
            unknownAndRestore("FINAL_SAMPLE_POST_REJECTED");
        }
    }

    private void requestRestore() {
        requireMain();
        if (trial == null || cleanupVerified.get()) return;
        if (!safeRootForCleanup()) {
            cleanupStatus = "QUARANTINED_UNSAFE_ROOT";
            TrialProcess.get().record("RESTORE_QUARANTINED", cleanupStatus);
            return;
        }
        cleanupPending = true;
        cleanupFrame = null;
        cleanupSecondFrame = null;
        cleanupSecondRequested = false;
        cleanupStatus = "RESTORE_REQUESTED";
        cleanupRequestedElapsedMs = SystemClock.elapsedRealtime();
        parent.setDesiredDelta(0);
        parent.requestLayout();
        if (trial.state() == TrialEvidence.State.UNKNOWN) {
            // Same-bounds cleanup may need its own redraw; normal restoration
            // already requests a changed-bounds parent layout.
            root.invalidate();
        }
        TrialProcess.get().record("RESTORE_REQUESTED", "root=" + root.getRootToken());
    }

    private void unknownAndRestore(String reason) {
        requireMain();
        if (trial == null) return;
        if (trial.state() != TrialEvidence.State.PASS) trial.unknown(reason);
        session.taint(reason);
        if (!unknownRecorded) {
            unknownRecorded = true;
            TrialProcess.get().record("TRIAL_UNKNOWN", "token=" + trialToken
                    + " reason=" + trial.reason());
        }
        if (!cleanupVerified.get() && !cleanupPending) requestRestore();
    }

    private void taint(String reason) {
        requireMain();
        if (!session.tainted()) {
            session.taint(reason);
            TrialProcess.get().record("SESSION_TAINTED", reason);
        }
        if (trial != null && trial.state() != TrialEvidence.State.PASS) {
            unknownAndRestore(reason);
        }
    }

    private void considerUnknownCleanupFrame(TrialEvidence.Cut frame) {
        if (!cleanupPending || baseline == null || frame == null
                || frame.completedPaintElapsedMs < cleanupRequestedElapsedMs
                || frame.paintStartedElapsedMs < cleanupRequestedElapsedMs
                || frame.startedPaintRevision <= baseline.startedPaintRevision
                || !frame.exactNinePainted() || !baseline.sameOriginals(frame)
                || !baseline.bounds.equals(frame.bounds)) return;
        if (cleanupFrame == null) {
            cleanupFrame = frame;
            scheduleUnknownSecondPaint();
            return;
        }
        if (!cleanupSecondRequested || cleanupSecondFrame != null
                || frame.startedPaintRevision <= cleanupFrame.startedPaintRevision
                || frame.paintStartedElapsedMs < cleanupSecondRequestElapsedMs
                || frame.paintStartedElapsedMs < cleanupFrame.completedPaintElapsedMs
                        + TrialEvidence.SECOND_SAMPLE_GAP_MS
                || frame.completedPaintElapsedMs - cleanupFrame.completedPaintElapsedMs
                        > TrialEvidence.MAX_SECOND_SAMPLE_GAP_MS
                || frame.parentPreCallRevision != cleanupFrame.parentPreCallRevision
                || frame.observedWriteOrdinal != cleanupFrame.observedWriteOrdinal
                || frame.rootLayoutCalls != cleanupFrame.rootLayoutCalls) {
            cleanupStatus = "CLEANUP_SECOND_PAINT_MISMATCH";
            return;
        }
        cleanupSecondFrame = frame;
        final long token = trialToken;
        if (!main.post(new Runnable() {
            @Override public void run() {
                if (token != trialToken || cleanupVerified.get()
                        || cleanupSecondFrame == null
                        || SystemClock.elapsedRealtime() >= hardStopElapsedMs
                        || !safeRootForCleanup() || parent.isLayoutRequested()
                        || root.isLayoutRequested()
                        || root.originalsHavePendingLayout(originals)) return;
                TrialEvidence.Cut live = root.captureLive();
                TrialEvidence.Cut latest = root.lastCompletedFrame();
                if (cleanupSecondFrame.sameLiveFrame(latest)
                        && cleanupSecondFrame.sameLiveFrame(live)
                        && live.exactNinePainted()
                        && baseline.sameOriginals(live)
                        && baseline.bounds.equals(live.bounds)) {
                    cleanupVerified.set(true);
                    cleanupPending = false;
                    cleanupStatus = "RESTORED_AFTER_UNKNOWN_TWO_PAINTS";
                    TrialProcess.get().record("UNKNOWN_CLEANUP_VERIFIED",
                            "two paints; historical result remains UNKNOWN");
                }
            }
        })) cleanupStatus = "CLEANUP_FINAL_POST_REJECTED";
    }

    private void scheduleUnknownSecondPaint() {
        final long token = trialToken;
        if (!main.postDelayed(new Runnable() {
            @Override public void run() {
                if (token != trialToken || cleanupVerified.get() || cleanupFrame == null
                        || cleanupSecondRequested
                        || SystemClock.elapsedRealtime() >= hardStopElapsedMs
                        || !safeRootForCleanup() || parent.isLayoutRequested()
                        || root.isLayoutRequested()
                        || root.originalsHavePendingLayout(originals)) {
                    cleanupStatus = "CLEANUP_SECOND_REQUEST_REJECTED";
                    return;
                }
                TrialEvidence.Cut live = root.captureLive();
                TrialEvidence.Cut latest = root.lastCompletedFrame();
                long now = SystemClock.elapsedRealtime();
                if (now < cleanupFrame.completedPaintElapsedMs
                            + TrialEvidence.SECOND_SAMPLE_GAP_MS
                        || now - cleanupFrame.completedPaintElapsedMs
                            > TrialEvidence.MAX_SECOND_SAMPLE_GAP_MS
                        || !cleanupFrame.sameLiveFrame(latest)
                        || !cleanupFrame.sameLiveFrame(live)
                        || !live.exactNinePainted()
                        || !baseline.sameOriginals(live)
                        || !baseline.bounds.equals(live.bounds)) {
                    cleanupStatus = "CLEANUP_SECOND_REQUEST_DRIFT";
                    return;
                }
                cleanupSecondRequestElapsedMs = now;
                cleanupSecondRequested = true;
                root.invalidate();
            }
        }, TrialEvidence.SECOND_SAMPLE_GAP_MS + 5)) {
            cleanupStatus = "CLEANUP_SECOND_POST_REJECTED";
        }
    }

    private boolean safeRootForCleanup() {
        return admitted && TrialProcess.get().activity() == this
                && !rootLost
                && parent != null && root != null && parent.exactSoleChild()
                && parent.isAttachedToWindow() && root.isAttachedToWindow()
                && originalsExact();
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

    private void startWatchdog(final long token, final long deadline, final long hardStop) {
        Thread watchdog = new Thread(new Runnable() {
            @Override public void run() {
                waitUntilElapsed(deadline);
                if (cleanupVerified.get() || token != trialToken) return;
                watchdogExpired.set(true);
                // Do not take the main Looper, event-ring, or Handler locks here:
                // a method-entry hook could have stalled while holding one.
                waitUntilElapsed(hardStop);
                if (cleanupVerified.get() || token != trialToken) return;
                // Independent of both the main Looper and any Frida client/session.
                Process.killProcess(Process.myPid());
            }
        }, "layout-fence-disposable-watchdog");
        watchdog.setDaemon(true);
        watchdog.start();
    }

    private static void waitUntilElapsed(long deadline) {
        while (SystemClock.elapsedRealtime() < deadline) {
            long remaining = deadline - SystemClock.elapsedRealtime();
            try { Thread.sleep(Math.max(1, Math.min(remaining, 100))); }
            catch (InterruptedException ignored) {
                // Interruption cannot suppress the independent hard stop.
            }
        }
    }

    @Override public String sceneStamp() {
        return TrialContract.SCENE + ":orientation="
                + getResources().getConfiguration().orientation
                + ":activity=" + activityToken
                + ":parent=" + System.identityHashCode(parent)
                + ":parentSize=" + (parent == null ? 0 : parent.getWidth()) + ","
                + (parent == null ? 0 : parent.getHeight())
                + ":attached=" + (root != null && root.isAttachedToWindow())
                + ":focus=" + (root != null && root.hasWindowFocus())
                + ":rootId=" + (root == null ? 0 : root.getId())
                + ":padding=" + (root == null ? 0 : root.getPaddingLeft()) + ","
                + (root == null ? 0 : root.getPaddingTop()) + ","
                + (root == null ? 0 : root.getPaddingRight()) + ","
                + (root == null ? 0 : root.getPaddingBottom())
                + ":clip=" + (root != null && root.getClipChildren()) + ","
                + (root != null && root.getClipToPadding())
                + ":customOrder=" + (root != null && root.customDrawingOrderEnabled());
    }

    public String snapshotJson() {
        requireMain();
        try {
            TrialEvidence.Cut current = root != null && root.getWidth() > 0
                    && root.getHeight() > 0 ? root.captureLive() : null;
            TrialEvidence.Cut completed = root == null ? null : root.lastCompletedFrame();
            long now = SystemClock.elapsedRealtime();
            JSONObject out = new JSONObject();
            out.put("schema", TrialContract.SCHEMA);
            out.put("process", TrialProcess.get().identityJson());
            out.put("activityPresent", admitted);
            out.put("activitySerial", activitySerial);
            out.put("activityToken", activityToken);
            out.put("rootToken", root == null ? JSONObject.NULL : root.getRootToken());
            out.put("rootIdentityHash", root == null ? 0 : System.identityHashCode(root));
            out.put("lifecycle", lifecycle);
            out.put("sampleElapsedMs", now);
            out.put("rootAttached", root != null && root.isAttachedToWindow());
            out.put("rootHasFocus", root != null && root.hasWindowFocus());
            out.put("parentSoleChild", parent != null && parent.exactSoleChild());
            out.put("rootLost", rootLost);
            out.put("originalsExact", originalsExact());
            out.put("rootLayoutRequested", root != null && root.isLayoutRequested());
            out.put("parentLayoutRequested", parent != null && parent.isLayoutRequested());
            out.put("rootBounds", root == null ? JSONObject.NULL : rawBoundsJson(root));
            out.put("revisionScope", TrialContract.REVISION_SCOPE);
            out.put("parentPreCallRevision", root == null ? 0
                    : root.getParentPreCallRevision());
            out.put("observedWriteOrdinal", root == null ? 0
                    : root.getObservedWriteOrdinal());
            out.put("rootLayoutCallCount", root == null ? 0 : root.getLayoutCallCount());
            out.put("completedPaintCount", root == null ? 0 : root.getCompletedPaintCount());
            out.put("firstFocusPaintFloorRevision", firstFocusPaintFloorRevision);
            out.put("refreshRequested", refreshToken != null);
            out.put("refreshPaintFloorRevision", refreshPaintFloorRevision);
            out.put("refreshCompletedPaintCountFloor",
                    refreshCompletedPaintCountFloor);
            out.put("refreshRequestedElapsedMs", refreshRequestedElapsedMs);
            out.put("commandClaimed", session.commandClaimed());
            out.put("sessionTainted", session.tainted());
            out.put("sessionTaintReason", session.reason());
            out.put("watchdogExpired", watchdogExpired.get());
            out.put("cleanupStatus", cleanupStatus);
            out.put("cleanupVerified", cleanupVerified.get());
            out.put("current", cutJson(current));
            out.put("lastCompletedPaint", cutJson(completed));
            JSONObject proof = new JSONObject();
            proof.put("token", trialToken);
            proof.put("command", trial == null ? JSONObject.NULL : trial.command().wire);
            proof.put("state", trial == null ? "IDLE" : trial.state().name());
            proof.put("reason", trial == null ? "NOT_STARTED" : trial.reason());
            proof.put("bypassObserved", trial != null && trial.bypassObserved());
            proof.put("rollbackVerified", trial != null && trial.rollbackVerified());
            proof.put("completeMutationCoverage", false);
            proof.put("trialDeadlineElapsedMs", trial == null ? 0
                    : trial.deadlineElapsedMs());
            proof.put("activeArmDeadlineElapsedMs",
                    TrialProcess.get().activeArmDeadlineElapsedMs(now));
            proof.put("currentlyValid", postPassCurrent(current, completed));
            proof.put("baseline", cutJson(trial == null ? null : trial.baseline()));
            proof.put("abaAway", cutJson(trial == null ? null : trial.abaAway()));
            proof.put("firstAfter", cutJson(trial == null ? null : trial.firstAfter()));
            proof.put("firstFrame", cutJson(trial == null ? null : trial.firstFrame()));
            proof.put("restoreEntryDrift", restoreEntryDriftJson(
                    trial == null ? null : trial.restoreEntryDrift()));
            proof.put("restoreAfter", cutJson(trial == null ? null : trial.restoreAfter()));
            proof.put("restoredFrame", cutJson(trial == null ? null : trial.restoredFrame()));
            proof.put("secondFrame", cutJson(trial == null ? null : trial.secondFrame()));
            proof.put("secondSample", cutJson(trial == null ? null : trial.secondSample()));
            out.put("trial", proof);
            JSONArray children = new JSONArray();
            for (View child : originals) children.put(child == null ? 0
                    : System.identityHashCode(child));
            out.put("originalChildIdentityHashes", children);
            return out.toString();
        } catch (JSONException exception) {
            throw new IllegalStateException("state JSON failed", exception);
        }
    }

    private static Object cutJson(TrialEvidence.Cut cut) throws JSONException {
        if (cut == null) return JSONObject.NULL;
        JSONObject out = new JSONObject();
        out.put("rootToken", cut.rootToken);
        out.put("rootIdentityHash", System.identityHashCode(cut.root));
        out.put("scene", cut.scene);
        out.put("bounds", boundsJson(cut.bounds));
        out.put("childCount", cut.childCount);
        out.put("parentPreCallRevision", cut.parentPreCallRevision);
        out.put("observedWriteOrdinal", cut.observedWriteOrdinal);
        out.put("rootLayoutCallCount", cut.rootLayoutCalls);
        out.put("startedPaintRevision", cut.startedPaintRevision);
        out.put("paintStartedElapsedMs", cut.paintStartedElapsedMs);
        out.put("paintStartParentRevision", cut.paintStartParentRevision);
        out.put("paintStartWriteOrdinal", cut.paintStartWriteOrdinal);
        out.put("completedPaintRevision", cut.completedPaintRevision);
        out.put("completedPaintElapsedMs", cut.completedPaintElapsedMs);
        out.put("exactNinePainted", cut.exactNinePainted());
        JSONArray children = new JSONArray();
        JSONArray order = new JSONArray();
        for (int i = 0; i < TrialEvidence.ORIGINAL_COUNT; i++) {
            JSONObject child = new JSONObject();
            child.put("index", i);
            child.put("identityHash", cut.childAt(i) == null ? 0
                    : System.identityHashCode(cut.childAt(i)));
            child.put("parentIsRoot", cut.parentAt(i) == cut.root);
            child.put("evidence", cut.childEvidenceAt(i));
            children.put(child);
            order.put(cut.paintedAt(i) == null ? 0
                    : System.identityHashCode(cut.paintedAt(i)));
        }
        out.put("children", children);
        out.put("effectivePaintOrder", order);
        return out;
    }

    /** Only comparison results cross the provider wire, never tokens or child text. */
    private static Object restoreEntryDriftJson(TrialEvidence.RestoreEntryDiff diff)
            throws JSONException {
        if (diff == null) return JSONObject.NULL;
        JSONObject out = new JSONObject();
        out.put("sameRoot", diff.sameRoot);
        out.put("sameRootToken", diff.sameRootToken);
        out.put("sameScene", diff.sameScene);
        out.put("childCount", numberPairJson(diff.firstChildCount, diff.entryChildCount));
        out.put("childIdentityMismatchIndices",
                indexArrayJson(diff.childIdentityMismatchIndices()));
        out.put("parentIdentityMismatchIndices",
                indexArrayJson(diff.parentIdentityMismatchIndices()));
        out.put("childEvidenceMismatchIndices",
                indexArrayJson(diff.childEvidenceMismatchIndices()));
        JSONArray bounds = new JSONArray();
        bounds.put(boundsArrayJson(diff.firstBounds));
        bounds.put(boundsArrayJson(diff.entryBounds));
        out.put("bounds", bounds);
        out.put("parentPreCallRevision", numberPairJson(diff.parentPreCallRevision));
        out.put("observedWriteOrdinal", numberPairJson(diff.observedWriteOrdinal));
        out.put("rootLayoutCalls", numberPairJson(diff.rootLayoutCalls));
        out.put("startedPaintRevision", numberPairJson(diff.startedPaintRevision));
        out.put("paintStartedElapsedMs", numberPairJson(diff.paintStartedElapsedMs));
        out.put("paintStartParentRevision", numberPairJson(diff.paintStartParentRevision));
        out.put("paintStartWriteOrdinal", numberPairJson(diff.paintStartWriteOrdinal));
        out.put("completedPaintRevision", numberPairJson(diff.completedPaintRevision));
        out.put("completedPaintElapsedMs", numberPairJson(diff.completedPaintElapsedMs));
        return out;
    }

    private static JSONArray numberPairJson(TrialEvidence.RestoreEntryDiff.LongPair pair) {
        return numberPairJson(pair.firstFrame, pair.entry);
    }

    private static JSONArray numberPairJson(long firstFrame, long entry) {
        JSONArray out = new JSONArray();
        out.put(firstFrame);
        out.put(entry);
        return out;
    }

    private static JSONArray boundsArrayJson(TrialEvidence.Bounds bounds) {
        JSONArray out = new JSONArray();
        out.put(bounds.left);
        out.put(bounds.top);
        out.put(bounds.right);
        out.put(bounds.bottom);
        return out;
    }

    private static JSONArray indexArrayJson(int[] indices) {
        JSONArray out = new JSONArray();
        for (int index : indices) out.put(index);
        return out;
    }

    private static JSONObject boundsJson(TrialEvidence.Bounds bounds) throws JSONException {
        JSONObject out = new JSONObject();
        out.put("left", bounds.left);
        out.put("top", bounds.top);
        out.put("right", bounds.right);
        out.put("bottom", bounds.bottom);
        return out;
    }

    private static JSONObject rawBoundsJson(View view) throws JSONException {
        JSONObject out = new JSONObject();
        out.put("left", view.getLeft());
        out.put("top", view.getTop());
        out.put("right", view.getRight());
        out.put("bottom", view.getBottom());
        return out;
    }

    private String rawRootBounds() {
        return root.getLeft() + "," + root.getTop() + ","
                + root.getRight() + "," + root.getBottom();
    }

    private int dp(int value) {
        return (int) (value * getResources().getDisplayMetrics().density + 0.5f);
    }

    private static void requireMain() {
        if (Looper.myLooper() != Looper.getMainLooper()) {
            throw new IllegalStateException("trial requires main Looper");
        }
    }
}
