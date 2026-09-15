package com.techrebbe.supernote.nativepagehost;

import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.res.Configuration;
import android.graphics.Color;
import android.hardware.display.DisplayManager;
import android.hardware.display.VirtualDisplay;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.util.DisplayMetrics;
import android.util.Log;
import android.view.Gravity;
import android.view.MotionEvent;
import android.view.SurfaceHolder;
import android.view.SurfaceView;
import android.view.View;
import android.view.Display;
import android.view.WindowManager;
import android.widget.FrameLayout;
import android.widget.TextView;
import com.techrebbe.supernote.viewportprobe.DisplayProbeLayout;
import com.techrebbe.supernote.viewportprobe.NativePageHostLifecycle;
import com.techrebbe.supernote.viewportprobe.NativePageHostLifecycle.CommandResult;
import com.techrebbe.supernote.viewportprobe.NativePageHostLifecycle.FrameResult;
import com.techrebbe.supernote.viewportprobe.NativePageHostLifecycle.ForeignTaskIdentity;
import java.util.UUID;

/**
 * Visual-only host for one externally launched native Document task.
 *
 * <p>This package allocates and presents a fixed VirtualDisplay. It never
 * launches Document, opens a file, injects input, programs the pen service, or
 * reads storage. A root/ADB coordinator owns foreign-task launch, verification,
 * and destruction. Exact live-session acknowledgments form the boundary.</p>
 */
public final class NativePageHostActivity extends Activity implements SurfaceHolder.Callback {
    private static final String TAG = "NATIVE_PAGE_HOST";
    private static final String PREFIX = "com.techrebbe.supernote.nativepagehost.";
    private static final String ACTION_ACK_ATTACHED = PREFIX + "ACK_FOREIGN_ATTACHED";
    private static final String ACTION_PLACE_FULL = PREFIX + "PLACE_FULL";
    private static final String ACTION_PLACE_LEFT = PREFIX + "PLACE_LEFT";
    private static final String ACTION_PLACE_RIGHT = PREFIX + "PLACE_RIGHT";
    private static final String ACTION_BEGIN_CLOSE = PREFIX + "BEGIN_CLOSE";
    private static final String ACTION_ACK_DESTROYED = PREFIX + "ACK_FOREIGN_DESTROYED";
    private static final String ACTION_ACK_NO_FOREIGN = PREFIX + "ACK_NO_FOREIGN_AFTER_FAILURE";
    private static final String ACTION_ACK_NO_FOREIGN_PRE_ATTACH_ABORT =
            PREFIX + "ACK_NO_FOREIGN_PRE_ATTACH_ABORT";
    private static final String EXTRA_SESSION = "session";
    private static final String EXTRA_GENERATION = "generation";
    private static final String EXTRA_DISPLAY = "display";
    private static final String EXTRA_SEQUENCE = "sequence";
    private static final String EXTRA_FOREIGN_PACKAGE = "foreignPackage";
    private static final String EXTRA_FOREIGN_COMPONENT = "foreignComponent";
    private static final String EXTRA_FOREIGN_TASK = "foreignTask";
    private static final String EXTRA_FOREIGN_PID = "foreignPid";
    private static final String EXTRA_FOREIGN_UID = "foreignUid";
    private static final String EXTRA_FOREIGN_START = "foreignStartTicks";
    private static final String EXTRA_FOREIGN_EVIDENCE = "foreignEvidenceSha256";
    private static final String EXTRA_ABSENCE_EVIDENCE = "absenceEvidenceSha256";
    private static final long ATTACH_TIMEOUT_MS = 45_000L;
    private static final long DESTROY_TIMEOUT_MS = 30_000L;
    private static final long PLACEMENT_TIMEOUT_MS = 2_000L;
    private static final long HOST_AUTHORITY_REACQUIRE_TIMEOUT_MS = 1_500L;
    // Hidden from the public SDK, but fixed at 1 << 8 in the pinned Android 11
    // DisplayManager contract. Keeping the value local avoids hidden-API access.
    private static final int VIRTUAL_DISPLAY_FLAG_DESTROY_CONTENT_ON_REMOVAL = 1 << 8;

    private final Handler main = new Handler(Looper.getMainLooper());
    private final String session = UUID.randomUUID().toString();
    private FrameLayout root;
    private SurfaceView surface;
    private TextView status;
    private NativePageHostLifecycle lifecycle;
    private VirtualDisplay virtualDisplay;
    private DisplayProbeLayout.Placement requested = DisplayProbeLayout.Placement.FULL;
    private int displayId = -1;
    private Runnable attachTimeout;
    private Runnable destroyTimeout;
    private Runnable placementTimeout;
    private Runnable displayWatchdog;
    private Runnable hostAuthorityTimeout;
    private boolean releasing;
    private boolean destroyed;
    private boolean fixedBufferReady;
    private boolean canonicalFrameInstalled;
    private boolean frameWasReady;
    private boolean resumed;
    private boolean processCleanupEscalated;
    private boolean frameTransitionPending;
    private long hostAuthorityDeadlineElapsed = -1L;
    private int expectedHostWidth = -1;
    private int expectedHostHeight = -1;
    private boolean deferredCommandPending;
    private String deferredCommandAction;
    private String deferredCommandCapability;
    private long deferredCommandGeneration = -1L;
    private int deferredCommandDisplayId = -1;
    private long deferredCommandSequence = -1L;
    private ForeignTaskIdentity deferredCommandIdentity;

    @Override public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        lifecycle = new NativePageHostLifecycle(savedInstanceState != null, session);
        configureFullscreen();
        createChrome();

        String initialAction;
        try {
            initialAction = getIntent() == null ? null : getIntent().getAction();
        } catch (RuntimeException malformedIntent) {
            log("FRESH_LAUNCH_REJECTED", "reason=malformed_intent");
            finishAndRemoveTask();
            return;
        }
        if (!Intent.ACTION_MAIN.equals(initialAction)) {
            log("FRESH_LAUNCH_REJECTED", "reason=only_exact_MAIN_is_admitted");
            finishAndRemoveTask();
            return;
        }
        if (savedInstanceState != null) {
            log("FAILED", "reason=restored_instance");
            showStatus();
            return;
        }
        if (Build.VERSION.SDK_INT != 30 || !"Supernote Nomad".equals(Build.MODEL)
                || !getPackageManager().hasSystemFeature(
                    PackageManager.FEATURE_ACTIVITIES_ON_SECONDARY_DISPLAYS)) {
            reject("pinned Nomad Android 11 / secondary-display capability required");
            return;
        }

        surface = new SurfaceView(this);
        surface.getHolder().setFixedSize(
                DisplayProbeLayout.BUFFER_WIDTH, DisplayProbeLayout.BUFFER_HEIGHT);
        surface.getHolder().addCallback(this);
        surface.setOnTouchListener((view, event) -> {
            if (event.getActionMasked() == MotionEvent.ACTION_UP
                    && event.getPointerCount() == 1 && status != null) {
                status.setVisibility(status.getVisibility() == View.VISIBLE
                        ? View.GONE : View.VISIBLE);
            }
            return true;
        });
        root.addView(surface, new FrameLayout.LayoutParams(3, 4));
        root.addOnLayoutChangeListener((view, left, top, right, bottom,
                oldLeft, oldTop, oldRight, oldBottom) -> layoutSurface());
        root.post(this::layoutSurface);
        log("SESSION", "readiness=WAITING_FOR_SURFACE visualOnly=true");
        showStatus();
    }

    private void configureFullscreen() {
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_FULLSCREEN);
        getWindow().getDecorView().setSystemUiVisibility(View.SYSTEM_UI_FLAG_FULLSCREEN
                | View.SYSTEM_UI_FLAG_HIDE_NAVIGATION | View.SYSTEM_UI_FLAG_IMMERSIVE_STICKY);
    }

    private void createChrome() {
        root = new FrameLayout(this);
        root.setBackgroundColor(Color.LTGRAY);
        status = new TextView(this);
        status.setTextColor(Color.BLACK);
        status.setBackgroundColor(Color.WHITE);
        status.setTextSize(13);
        status.setPadding(8, 8, 8, 8);
        FrameLayout.LayoutParams chrome = new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.WRAP_CONTENT, FrameLayout.LayoutParams.WRAP_CONTENT,
                Gravity.TOP | Gravity.RIGHT);
        root.addView(status, chrome);
        setContentView(root);
    }

    /** Stylus/eraser input is always swallowed by the host and never forwarded. */
    @Override public boolean dispatchTouchEvent(MotionEvent event) {
        for (int index = 0; index < event.getPointerCount(); index++) {
            int tool = event.getToolType(index);
            if (tool == MotionEvent.TOOL_TYPE_STYLUS || tool == MotionEvent.TOOL_TYPE_ERASER) {
                log("STYLUS_SWALLOWED", "action=" + event.getActionMasked());
                return true;
            }
        }
        return super.dispatchTouchEvent(event);
    }

    @Override protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        if (intent == null) {
            log("COMMAND_IGNORED", "reason=null_intent");
            return;
        }
        String action;
        try {
            action = intent.getAction();
        } catch (RuntimeException malformedIntent) {
            log("COMMAND_IGNORED", "reason=malformed_action");
            return;
        }
        if (action == null || Intent.ACTION_MAIN.equals(action)) {
            log("REFOCUS", "readiness=" + readiness());
            showStatus();
            return;
        }
        if (!isKnownCommand(action)) {
            log("COMMAND_IGNORED", "reason=unknown_action");
            return;
        }
        CommandEnvelope envelope = decodeCommandEnvelope(intent, action);
        if (envelope == null) return;
        if (!lifecycle.commandEnvelopeMatches(envelope.capability, envelope.generation,
                envelope.displayId, envelope.sequence)) {
            log("COMMAND_IGNORED", "reason=unauthenticated_or_stale action=" + scrub(action));
            return;
        }
        // This exact action can only end an empty display. It never reserves a
        // command or acquires presentation authority during Android's pause.
        // Payload access remains after authentication; lifecycle classifies
        // exact replays before checking first-acceptance health and phase.
        if (ACTION_ACK_NO_FOREIGN_PRE_ATTACH_ABORT.equals(action)) {
            processAuthenticatedCommand(envelope, null);
            return;
        }
        // Sticky-failure cleanup and exact already-accepted replays bypass live
        // display/frame checks. A fresh non-cleanup command never crosses failure.
        boolean failedCleanup = lifecycle.isFailed() && isCleanupCommand(action);
        boolean failedExactReplay = lifecycle.isFailed()
                && envelope.sequence <= lifecycle.lastCommandSequence();
        boolean suspendedExactReplay = lifecycle.hostAuthoritySuspended()
                && envelope.sequence <= lifecycle.lastCommandSequence();
        if (lifecycle.isFailed() && !failedCleanup && !failedExactReplay) {
            rejectAlreadyFailed("fresh non-cleanup command rejected after sticky failure");
            return;
        }
        if (!failedCleanup && !failedExactReplay && !suspendedExactReplay
                && lifecycle.hostAuthoritySuspended()) {
            int commandKind = deferredCommandKind(action);
            if (commandKind == 0 || !lifecycle.canDeferFreshCommand(envelope.sequence)) {
                log("COMMAND_REJECTED", "reason=invalid_or_nonfresh_command_during_host_pause"
                        + " action=" + scrub(action));
                releaseForUnexpectedLoss("paused command lacked one fresh typed reservation");
                return;
            }
            ForeignTaskIdentity identity = null;
            if (ACTION_ACK_ATTACHED.equals(action) || ACTION_ACK_DESTROYED.equals(action)) {
                identity = parseForeignIdentity(envelope.extras);
                if (identity == null) {
                    releaseForUnexpectedLoss("deferred command identity was invalid");
                    return;
                }
            }
            deferAuthenticatedCommand(envelope, commandKind, identity);
            return;
        }
        if (!failedCleanup && !failedExactReplay && !suspendedExactReplay
                && !verifyRuntimeAuthorityOrFail("authenticated_command")) return;
        processAuthenticatedCommand(envelope, null);
    }

    private void processAuthenticatedCommand(CommandEnvelope envelope,
            ForeignTaskIdentity retainedIdentity) {
        String action = envelope.action;
        if (ACTION_ACK_ATTACHED.equals(action)) {
            ForeignTaskIdentity identity = retainedIdentity != null
                    ? retainedIdentity : parseForeignIdentity(envelope.extras);
            if (identity == null) return;
            CommandResult result = lifecycle.acknowledgeForeignAttached(
                    envelope.capability, envelope.generation, envelope.displayId,
                    envelope.sequence, identity);
            if (result == CommandResult.ACCEPTED) {
                if (!lifecycle.canPublishFreshAttachReady()) {
                    reject("fresh attach result lacked exact ACTIVE readiness");
                    return;
                }
                cancelAttachTimeout();
                log("READY", foreignDetail(identity) + " readiness=ACTIVE");
                showStatus();
                return;
            }
            if (result == CommandResult.IDEMPOTENT) {
                log("ATTACH_REPLAY", "state=" + lifecycle.state().name()
                        + " freshReady=false failureSticky=" + lifecycle.isFailed());
                showStatus();
                return;
            }
            rejectAlreadyFailed("attach acknowledgment rejected");
            return;
        }
        if (ACTION_PLACE_FULL.equals(action) || ACTION_PLACE_LEFT.equals(action)
                || ACTION_PLACE_RIGHT.equals(action)) {
            DisplayProbeLayout.Placement placement = ACTION_PLACE_LEFT.equals(action)
                    ? DisplayProbeLayout.Placement.LEFT
                    : ACTION_PLACE_RIGHT.equals(action)
                        ? DisplayProbeLayout.Placement.RIGHT : DisplayProbeLayout.Placement.FULL;
            CommandResult result = lifecycle.authorizePlacement(
                    envelope.capability, envelope.generation, envelope.displayId,
                    envelope.sequence, placement);
            if (result == CommandResult.ACCEPTED) {
                requested = lifecycle.frameRequestPlacement();
                canonicalFrameInstalled = false;
                frameWasReady = false;
                armPlacementTimeout(envelope.generation, envelope.sequence);
                layoutSurface();
                log("PLACEMENT_REQUESTED", "requested=" + placement + " effectiveRequest="
                        + requested + " sequence=" + envelope.sequence);
                return;
            }
            if (result == CommandResult.IDEMPOTENT) {
                log("PLACEMENT_REPLAY", "state=" + lifecycle.state().name()
                        + " freshRequest=false failureSticky=" + lifecycle.isFailed());
                showStatus();
                return;
            }
            rejectAlreadyFailed("placement rejected");
            return;
        }
        if (ACTION_BEGIN_CLOSE.equals(action)) {
            CommandResult result = lifecycle.beginClose(envelope.capability, envelope.generation,
                    envelope.displayId, envelope.sequence);
            if (result == CommandResult.ACCEPTED) {
                if (!lifecycle.canPublishFreshCloseWait()) {
                    reject("fresh close result lacked exact WAITING_FOR_FOREIGN_DESTROY readiness");
                    return;
                }
                cancelPlacementTimeout();
                armDestroyTimeout(envelope.generation);
                log("WAIT_FOREIGN_DESTROY", foreignDetail(lifecycle.foreignTask()));
                showStatus();
                return;
            }
            if (result == CommandResult.IDEMPOTENT) {
                log("CLOSE_REPLAY", "state=" + lifecycle.state().name()
                        + " freshWait=false failureSticky=" + lifecycle.isFailed());
                showStatus();
                return;
            }
            rejectAlreadyFailed("close request rejected");
            return;
        }
        if (ACTION_ACK_DESTROYED.equals(action)) {
            ForeignTaskIdentity identity = retainedIdentity != null
                    ? retainedIdentity : parseForeignIdentity(envelope.extras);
            if (identity == null) return;
            CommandResult result = lifecycle.acknowledgeForeignDestroyed(
                    envelope.capability, envelope.generation, envelope.displayId,
                    envelope.sequence, identity);
            if (result == CommandResult.ACCEPTED) {
                cancelDestroyTimeout();
                log("FOREIGN_DESTROYED", foreignDetail(identity));
                if (releaseNormally()) finishAndRemoveTask();
                return;
            }
            if (result == CommandResult.IDEMPOTENT) {
                log("DESTROY_REPLAY", "state=" + lifecycle.state().name()
                        + " freshDestroy=false releaseRetry=" + lifecycle.canReleaseNormally()
                        + " failureSticky=" + lifecycle.isFailed());
                if (releaseNormally()) finishAndRemoveTask();
                return;
            }
            rejectAlreadyFailed("destroy acknowledgment rejected");
            return;
        }
        if (ACTION_ACK_NO_FOREIGN_PRE_ATTACH_ABORT.equals(action)) {
            String evidence = exactString(envelope.extras, EXTRA_ABSENCE_EVIDENCE);
            CommandResult result = lifecycle.acknowledgeNoForeignPreAttachAbort(
                    envelope.capability, envelope.generation, envelope.displayId,
                    envelope.sequence, evidence);
            if (result == CommandResult.ACCEPTED) {
                log("EMPTY_PRE_ATTACH_ABORT", "absenceEvidenceSha256=" + scrub(evidence));
                if (releaseNormally()) finishAndRemoveTask();
                return;
            }
            if (result == CommandResult.IDEMPOTENT) {
                log("EMPTY_PRE_ATTACH_ABORT_REPLAY", "state=" + lifecycle.state().name()
                        + " freshAbort=false releaseRetry=" + lifecycle.canReleaseNormally()
                        + " failureSticky=" + lifecycle.isFailed());
                if (!lifecycle.displayRemoved() && releaseNormally()) finishAndRemoveTask();
                return;
            }
            rejectAlreadyFailed("healthy pre-attach abort rejected");
            return;
        }
        if (ACTION_ACK_NO_FOREIGN.equals(action)) {
            String evidence = exactString(envelope.extras, EXTRA_ABSENCE_EVIDENCE);
            CommandResult result = lifecycle.acknowledgeNoForeignAfterFailure(
                    envelope.capability, envelope.generation, envelope.displayId,
                    envelope.sequence, evidence);
            if (result == CommandResult.ACCEPTED) {
                log("EMPTY_ATTACH_ABORT", "absenceEvidenceSha256=" + scrub(evidence));
                if (releaseNormally()) finishAndRemoveTask();
                return;
            }
            if (result == CommandResult.IDEMPOTENT) {
                log("EMPTY_ABORT_REPLAY", "state=" + lifecycle.state().name()
                        + " freshAbort=false releaseRetry=" + lifecycle.canReleaseNormally()
                        + " failureSticky=" + lifecycle.isFailed());
                if (releaseNormally()) finishAndRemoveTask();
                return;
            }
            rejectAlreadyFailed("empty attach abort rejected");
            return;
        }
    }

    private static final class CommandEnvelope {
        final String action;
        final String capability;
        final long generation;
        final int displayId;
        final long sequence;
        final Bundle extras;

        CommandEnvelope(String action, String capability, long generation, int displayId,
                long sequence, Bundle extras) {
            this.action = action;
            this.capability = capability;
            this.generation = generation;
            this.displayId = displayId;
            this.sequence = sequence;
            this.extras = extras;
        }
    }

    /** Every exported Bundle access before capability admission is exception-contained. */
    private CommandEnvelope decodeCommandEnvelope(Intent intent, String action) {
        try {
            Bundle extras = intent.getExtras();
            if (extras == null) {
                log("COMMAND_IGNORED", "reason=missing_envelope action=" + scrub(action));
                return null;
            }
            Object capability = extras.get(EXTRA_SESSION);
            Object generation = extras.get(EXTRA_GENERATION);
            Object display = extras.get(EXTRA_DISPLAY);
            Object sequence = extras.get(EXTRA_SEQUENCE);
            if (!(capability instanceof String) || !(generation instanceof Long)
                    || !(display instanceof Integer) || !(sequence instanceof Long)) {
                log("COMMAND_IGNORED", "reason=malformed_envelope action=" + scrub(action));
                return null;
            }
            return new CommandEnvelope(action, (String) capability, (Long) generation,
                    (Integer) display, (Long) sequence, extras);
        } catch (RuntimeException malformedBundle) {
            log("COMMAND_IGNORED", "reason=malformed_bundle action=" + scrub(action));
            return null;
        }
    }

    private static boolean isKnownCommand(String action) {
        return ACTION_ACK_ATTACHED.equals(action) || ACTION_PLACE_FULL.equals(action)
                || ACTION_PLACE_LEFT.equals(action) || ACTION_PLACE_RIGHT.equals(action)
                || ACTION_BEGIN_CLOSE.equals(action) || ACTION_ACK_DESTROYED.equals(action)
                || ACTION_ACK_NO_FOREIGN.equals(action)
                || ACTION_ACK_NO_FOREIGN_PRE_ATTACH_ABORT.equals(action);
    }

    private static boolean isCleanupCommand(String action) {
        return ACTION_BEGIN_CLOSE.equals(action) || ACTION_ACK_DESTROYED.equals(action)
                || ACTION_ACK_NO_FOREIGN.equals(action);
    }

    private ForeignTaskIdentity parseForeignIdentity(Bundle extras) {
        try {
            return ForeignTaskIdentity.checked(
                    exactString(extras, EXTRA_FOREIGN_PACKAGE),
                    exactString(extras, EXTRA_FOREIGN_COMPONENT),
                    exactInteger(extras, EXTRA_FOREIGN_TASK),
                    exactInteger(extras, EXTRA_FOREIGN_PID),
                    exactInteger(extras, EXTRA_FOREIGN_UID),
                    exactString(extras, EXTRA_FOREIGN_START),
                    exactString(extras, EXTRA_FOREIGN_EVIDENCE));
        } catch (RuntimeException error) {
            lifecycle.onProtocolFailure("invalid foreign task identity");
            log("COMMAND_REJECTED", "reason=invalid_foreign_identity");
            showStatus();
            return null;
        }
    }

    private static String exactString(Bundle extras, String key) {
        try {
            Object value = extras == null ? null : extras.get(key);
            return value instanceof String ? (String) value : null;
        } catch (RuntimeException malformedBundle) {
            return null;
        }
    }

    private static int exactInteger(Bundle extras, String key) {
        try {
            Object value = extras == null ? null : extras.get(key);
            return value instanceof Integer ? (Integer) value : -1;
        } catch (RuntimeException malformedBundle) {
            return -1;
        }
    }

    private static int deferredCommandKind(String action) {
        if (ACTION_ACK_ATTACHED.equals(action)) return NativePageHostLifecycle.DEFER_ATTACH;
        if (ACTION_PLACE_FULL.equals(action)) return NativePageHostLifecycle.DEFER_PLACE_FULL;
        if (ACTION_PLACE_LEFT.equals(action)) return NativePageHostLifecycle.DEFER_PLACE_LEFT;
        if (ACTION_PLACE_RIGHT.equals(action)) return NativePageHostLifecycle.DEFER_PLACE_RIGHT;
        if (ACTION_BEGIN_CLOSE.equals(action)) return NativePageHostLifecycle.DEFER_BEGIN_CLOSE;
        if (ACTION_ACK_DESTROYED.equals(action)) {
            return NativePageHostLifecycle.DEFER_ACK_DESTROYED;
        }
        return 0;
    }

    /**
     * Retains one already-authenticated typed command across Android's bounded
     * singleTask pause/resume handoff. The Bundle/Intent is deliberately not
     * retained: only exact, strongly typed protocol values survive the callback.
     */
    private void deferAuthenticatedCommand(CommandEnvelope envelope, int commandKind,
            ForeignTaskIdentity identity) {
        long now = SystemClock.elapsedRealtime();
        long lifecycleDeadline = lifecycle.hostAuthorityDeadlineElapsed();
        if (hostAuthorityDeadlineElapsed <= 0
                || hostAuthorityDeadlineElapsed != lifecycleDeadline
                || now > hostAuthorityDeadlineElapsed
                || !physicalDisplayAuthorityStableWhilePaused()) {
            log("COMMAND_REJECTED", "reason=ambiguous_or_expired_deferred_command");
            clearDeferredCommand();
            releaseForUnexpectedLoss("deferred command was expired or lost display authority");
            return;
        }
        if (!lifecycle.reserveDeferredCommand(envelope.capability, envelope.generation,
                envelope.displayId, envelope.sequence, commandKind, identity)) {
            log("COMMAND_REJECTED", "reason=deferred_command_reservation_rejected");
            releaseForUnexpectedLoss("deferred command reservation contradicted lifecycle");
            return;
        }
        deferredCommandPending = true;
        deferredCommandAction = envelope.action;
        deferredCommandCapability = envelope.capability;
        deferredCommandGeneration = envelope.generation;
        deferredCommandDisplayId = envelope.displayId;
        deferredCommandSequence = envelope.sequence;
        deferredCommandIdentity = identity;
        log("COMMAND_DEFERRED", "action=" + scrub(envelope.action)
                + " sequence=" + envelope.sequence
                + " deadlineRemainingMs=" + (hostAuthorityDeadlineElapsed - now));
    }

    private boolean physicalDisplayAuthorityStableWhilePaused() {
        try {
            if (physicalDisplayId() != Display.DEFAULT_DISPLAY
                    || physicalDensityDpi() != lifecycle.admittedDensityDpi()
                    || virtualDisplay == null || displayId <= 0) return false;
            DisplayMetrics metrics = virtualDisplayMetrics();
            return metrics != null && metrics.widthPixels == DisplayProbeLayout.BUFFER_WIDTH
                    && metrics.heightPixels == DisplayProbeLayout.BUFFER_HEIGHT
                    && metrics.densityDpi == lifecycle.admittedDensityDpi();
        } catch (RuntimeException unavailable) {
            return false;
        }
    }

    private void drainDeferredCommandIfReady() {
        if (!deferredCommandPending || destroyed || releasing) return;
        if (hostAuthorityDeadlineElapsed <= 0
                || hostAuthorityDeadlineElapsed != lifecycle.hostAuthorityDeadlineElapsed()
                || SystemClock.elapsedRealtime() > hostAuthorityDeadlineElapsed) {
            clearDeferredCommand();
            releaseForUnexpectedLoss("deferred command host-authority deadline expired");
            return;
        }
        if (lifecycle.hostAuthoritySuspended() || lifecycle.isFailed()
                || !canonicalFrameInstalled || !fixedBufferReady || virtualDisplay == null) {
            if (lifecycle.isFailed()) clearDeferredCommand();
            return;
        }
        if (!verifyRuntimeAuthorityOrFail("deferred_command_replay")) {
            clearDeferredCommand();
            return;
        }
        String action = deferredCommandAction;
        String capability = deferredCommandCapability;
        long generation = deferredCommandGeneration;
        int exactDisplayId = deferredCommandDisplayId;
        long sequence = deferredCommandSequence;
        ForeignTaskIdentity identity = deferredCommandIdentity;
        int commandKind = deferredCommandKind(action);
        clearDeferredCommand();
        if (!lifecycle.consumeDeferredCommand(capability, generation, exactDisplayId,
                sequence, commandKind, identity)) {
            releaseForUnexpectedLoss("deferred command consumption was not exact");
            return;
        }
        log("COMMAND_RESUMED", "action=" + scrub(action) + " sequence=" + sequence);
        processAuthenticatedCommand(new CommandEnvelope(action, capability, generation,
                exactDisplayId, sequence, null), identity);
        completeHostAuthorityTransitionIfReady();
    }

    private void clearDeferredCommand() {
        deferredCommandPending = false;
        deferredCommandAction = null;
        deferredCommandCapability = null;
        deferredCommandGeneration = -1L;
        deferredCommandDisplayId = -1;
        deferredCommandSequence = -1L;
        deferredCommandIdentity = null;
    }

    private void layoutSurface() {
        // Android can deliver a queued layout/surface callback after an
        // acknowledged release and finishAndRemoveTask().  RELEASED is a
        // terminal protocol state: ignore that callback rather than asking the
        // lifecycle to revalidate authority that has intentionally ended.
        if (surface == null || destroyed || lifecycle == null
                || lifecycle.state() == NativePageHostLifecycle.State.RELEASED
                || root.getWidth() < 4 || root.getHeight() < 4) return;
        if (!lifecycle.hostAuthorityAdmitted()) {
            if (!initialHostAuthorityReady()) return;
            if (!lifecycle.admitHostAuthority(physicalDisplayId(), physicalDensityDpi(),
                    resumed, hostVisible(), hasWindowFocus())) {
                rejectAlreadyFailed("host authority admission rejected");
                return;
            }
            log("HOST_AUTHORITY", "display=0 resumed=true visible=true focused=true"
                    + " density=" + lifecycle.admittedDensityDpi());
        } else if (lifecycle.hostAuthoritySuspended()) {
            if (!reacquireHostAuthorityIfReady()) return;
        } else if (virtualDisplay != null && !verifyHostAuthorityOrFail("layout")) {
            return;
        }
        int width = root.getWidth();
        int height = root.getHeight();
        if (!((width == 1404 && height == 1872) || (width == 1872 && height == 1404))) {
            canonicalFrameInstalled = false;
            log("WAIT_HOST_GEOMETRY", "host=" + width + "x" + height);
            return;
        }
        if (!hostGeometryMatchesExpectedConfiguration(width, height)) {
            canonicalFrameInstalled = false;
            log("WAIT_CONFIGURATION_FRAME", "host=" + width + "x" + height
                    + " expected=" + expectedHostWidth + "x" + expectedHostHeight);
            return;
        }
        int[] rootLocation = new int[2];
        root.getLocationOnScreen(rootLocation);
        if (rootLocation[0] != 0 || rootLocation[1] != 0) {
            canonicalFrameInstalled = false;
            if (virtualDisplay != null) {
                releaseForUnexpectedLoss("host root left the physical display origin");
            } else {
                log("WAIT_HOST_ORIGIN", "left=" + rootLocation[0]
                        + " top=" + rootLocation[1]);
            }
            return;
        }
        requested = lifecycle.frameRequestPlacement();
        DisplayProbeLayout frame = DisplayProbeLayout.fit(width, height, requested);
        FrameLayout.LayoutParams params = (FrameLayout.LayoutParams) surface.getLayoutParams();
        if (params.width != frame.width || params.height != frame.height
                || params.leftMargin != frame.left || params.topMargin != frame.top) {
            canonicalFrameInstalled = false;
            params.width = frame.width;
            params.height = frame.height;
            params.leftMargin = frame.left;
            params.topMargin = frame.top;
            surface.setLayoutParams(params);
            return;
        }
        int[] surfaceLocation = new int[2];
        surface.getLocationOnScreen(surfaceLocation);
        if (surfaceLocation[0] != frame.left || surfaceLocation[1] != frame.top
                || surface.getWidth() != frame.width || surface.getHeight() != frame.height) {
            canonicalFrameInstalled = false;
            surface.postOnAnimation(this::layoutSurface);
            return;
        }
        long placementSequence = lifecycle.pendingPlacementSequence();
        FrameResult frameResult = lifecycle.onPhysicalFrameMeasured(width, height,
                surfaceLocation[0], surfaceLocation[1], surface.getWidth(), surface.getHeight(),
                placementSequence);
        if (frameResult == FrameResult.REJECTED) {
            canonicalFrameInstalled = false;
            releaseForUnexpectedLoss("measured physical frame was rejected");
            return;
        }
        canonicalFrameInstalled = frameResult == FrameResult.READY;
        if (frameResult == FrameResult.READY && placementSequence > 0) {
            cancelPlacementTimeout();
            if (lifecycle.isFailed()) {
                // A sticky failed session admits the exact old/target frame pair
                // solely so physical authority and the authenticated cleanup path
                // survive. It never publishes or commits placement readiness.
                log("FAILED_FRAME_AUTHORITY", "sequence=" + placementSequence
                        + " committed=" + lifecycle.placement() + " measured="
                        + frame.effectivePlacement + " rect=" + frame.left + "," + frame.top
                        + "," + frame.width + "," + frame.height);
            } else {
                requested = lifecycle.placement();
                log("PLACEMENT_READY", "sequence=" + placementSequence + " requested="
                        + requested + " effective=" + frame.effectivePlacement + " rect="
                        + frame.left + "," + frame.top + "," + frame.width + "," + frame.height);
            }
        } else if (frameResult == FrameResult.READY && !frameWasReady) {
            frameWasReady = true;
            log("FRAME_READY", "host=" + width + "x" + height + " requested=" + requested
                    + " effective=" + frame.effectivePlacement + " rect=" + frame.left + ","
                    + frame.top + "," + frame.width + "," + frame.height);
        }
        maybeCreateVirtualDisplay();
        drainDeferredCommandIfReady();
        completeHostAuthorityTransitionIfReady();
        showStatus();
    }

    @Override public void onConfigurationChanged(Configuration configuration) {
        // Configuration delivery invalidates the old physical-frame authority even
        // when Android does not first call onPause. Stop continuous admission before
        // changing any frame state, then reuse (never renew) the current bounded
        // transition deadline until the new canonical frame is measured.
        cancelDisplayWatchdog();
        if (virtualDisplay != null && !releasing && !destroyed) {
            beginBoundedHostAuthoritySuspension("configuration_changed");
        }
        super.onConfigurationChanged(configuration);
        canonicalFrameInstalled = false;
        frameWasReady = false;
        if (!admitExpectedHostGeometry(configuration)) {
            if (virtualDisplay != null && !releasing && !destroyed) {
                releaseForUnexpectedLoss("configuration lacked exact portrait/landscape authority");
            }
            return;
        }
        if (releasing || destroyed) return;
        root.post(this::layoutSurface);
    }

    private boolean admitExpectedHostGeometry(Configuration configuration) {
        if (configuration == null) return false;
        if (configuration.orientation == Configuration.ORIENTATION_PORTRAIT) {
            expectedHostWidth = 1404;
            expectedHostHeight = 1872;
            return true;
        }
        if (configuration.orientation == Configuration.ORIENTATION_LANDSCAPE) {
            expectedHostWidth = 1872;
            expectedHostHeight = 1404;
            return true;
        }
        return false;
    }

    private boolean hostGeometryMatchesExpectedConfiguration(int width, int height) {
        return expectedHostWidth <= 0 || expectedHostHeight <= 0
                || (width == expectedHostWidth && height == expectedHostHeight);
    }

    @Override public void surfaceCreated(SurfaceHolder holder) {
        // Wait for the canonical fixed-size surfaceChanged callback.
    }

    @Override public void surfaceChanged(SurfaceHolder holder, int format, int width, int height) {
        if (destroyed) return;
        if (width != DisplayProbeLayout.BUFFER_WIDTH
                || height != DisplayProbeLayout.BUFFER_HEIGHT
                || !holder.getSurface().isValid()) {
            fixedBufferReady = false;
            log("WAIT_SURFACE", "size=" + width + "x" + height);
            if (virtualDisplay != null) {
                releaseForUnexpectedLoss("fixed display buffer changed after admission");
            }
            return;
        }
        fixedBufferReady = true;
        layoutSurface();
        maybeCreateVirtualDisplay();
    }

    private void maybeCreateVirtualDisplay() {
        // This is an independent allocation guard because surfaceChanged()
        // invokes this method even when layoutSurface() returned early.
        if (destroyed || lifecycle == null
                || lifecycle.state() == NativePageHostLifecycle.State.RELEASED
                || lifecycle.isFailed() || virtualDisplay != null
                || !fixedBufferReady || !canonicalFrameInstalled
                || surface == null || !surface.getHolder().getSurface().isValid()) return;
        if (!verifyPreAllocationHostAuthorityOrFail("before_display_creation")
                || !verifyPhysicalFrameOrFail("before_display_creation")) return;
        long admittedGeneration = lifecycle.beginDisplayCreation();
        if (admittedGeneration <= 0) return;
        try {
            int densityDpi = physicalDensityDpi();
            if (densityDpi <= 0) throw new IllegalStateException("missing physical density");
            DisplayManager manager = getSystemService(DisplayManager.class);
            final long callbackGeneration = admittedGeneration;
            int flags = DisplayManager.VIRTUAL_DISPLAY_FLAG_PUBLIC
                    | DisplayManager.VIRTUAL_DISPLAY_FLAG_OWN_CONTENT_ONLY
                    | VIRTUAL_DISPLAY_FLAG_DESTROY_CONTENT_ON_REMOVAL;
            virtualDisplay = manager.createVirtualDisplay(
                    "NativePageVisualOnly-" + session + "-" + admittedGeneration,
                    DisplayProbeLayout.BUFFER_WIDTH, DisplayProbeLayout.BUFFER_HEIGHT,
                    densityDpi, surface.getHolder().getSurface(), flags,
                    new VirtualDisplay.Callback() {
                        @Override public void onPaused() {
                            log("DISPLAY_PAUSED", "callbackGeneration=" + callbackGeneration);
                        }
                        @Override public void onResumed() {
                            log("DISPLAY_RESUMED", "callbackGeneration=" + callbackGeneration);
                        }
                        @Override public void onStopped() {
                            if (!releasing && !destroyed
                                    && displayId > 0
                                    && lifecycle.state() != NativePageHostLifecycle.State.RELEASED
                                    && lifecycle.generation() == callbackGeneration) {
                                releaseForUnexpectedLoss("virtual display stopped unexpectedly");
                            }
                        }
                    }, main);
            if (virtualDisplay == null) {
                throw new IllegalStateException("non-default display allocation failed");
            }
            Display allocatedDisplay = virtualDisplay.getDisplay();
            if (allocatedDisplay == null) {
                throw new IllegalStateException("non-default display allocation failed");
            }
            int allocatedDisplayId = allocatedDisplay.getDisplayId();
            if (allocatedDisplayId <= 0) {
                throw new IllegalStateException("non-default display allocation failed");
            }
            displayId = allocatedDisplayId;
            if (!lifecycle.onDisplayAllocated(admittedGeneration, displayId)) {
                throw new IllegalStateException("display allocation authority failed");
            }
            log("DISPLAY_ALLOCATED", "display=" + displayId
                    + " readiness=METRICS_PENDING cleanupAddressable=true");
            DisplayMetrics actual = virtualDisplayMetrics();
            if (!canonicalFrameInstalled || actual == null
                    || !lifecycle.onDisplayCreated(admittedGeneration, displayId,
                        actual.widthPixels, actual.heightPixels, actual.densityDpi)
                    || densityDpi != actual.densityDpi) {
                throw new IllegalStateException("display lifecycle admission failed");
            }
            log("DISPLAY_READY", "display=" + displayId + " density=" + densityDpi
                    + " buffer=1404x1872 flags=PUBLIC|OWN_CONTENT_ONLY|DESTROY_CONTENT_ON_REMOVAL"
                    + " readiness=WAITING_FOR_FOREIGN_ACK");
            armAttachTimeout(admittedGeneration);
            armDisplayWatchdog();
            showStatus();
        } catch (RuntimeException error) {
            releaseForUnexpectedLoss(error.getClass().getSimpleName() + ": " + error.getMessage());
        }
    }

    private DisplayMetrics virtualDisplayMetrics() {
        if (virtualDisplay == null) return null;
        Display display = virtualDisplay.getDisplay();
        if (display == null || display.getDisplayId() != displayId) return null;
        DisplayMetrics metrics = new DisplayMetrics();
        display.getRealMetrics(metrics);
        return metrics;
    }

    private boolean verifyRuntimeAuthorityOrFail(String checkpoint) {
        if (virtualDisplay == null || releasing || destroyed) return false;
        if (!verifyHostAuthorityOrFail(checkpoint)
                || !verifyPhysicalFrameOrFail(checkpoint)) return false;
        if (!lifecycle.retainsPhysicalHostAuthority()) {
            releaseForUnexpectedLoss("physical host authority was not retained at " + checkpoint);
            return false;
        }
        DisplayMetrics metrics = virtualDisplayMetrics();
        if (metrics == null || !lifecycle.onVirtualDisplayMetrics(
                    metrics.widthPixels, metrics.heightPixels, metrics.densityDpi)) {
            releaseForUnexpectedLoss("display authority changed at " + checkpoint);
            return false;
        }
        return true;
    }

    private boolean verifyPreAllocationHostAuthorityOrFail(String checkpoint) {
        if (virtualDisplay != null || releasing || destroyed) return false;
        if (lifecycle.revalidatePreAllocationHostAuthority(physicalDisplayId(),
                physicalDensityDpi(), resumed, hostVisible(), hasWindowFocus())) return true;
        rejectAlreadyFailed("pre-allocation host authority changed at " + checkpoint);
        return false;
    }

    private void armDisplayWatchdog() {
        cancelDisplayWatchdog();
        displayWatchdog = new Runnable() {
            @Override public void run() {
                if (virtualDisplay != null && !releasing && !destroyed
                        && verifyRuntimeAuthorityOrFail("watchdog")) {
                    main.postDelayed(this, 250L);
                }
            }
        };
        main.postDelayed(displayWatchdog, 250L);
    }

    private void cancelDisplayWatchdog() {
        if (displayWatchdog != null) main.removeCallbacks(displayWatchdog);
        displayWatchdog = null;
    }

    private int physicalDensityDpi() {
        Display display = getDisplay();
        if (display == null) return -1;
        DisplayMetrics metrics = new DisplayMetrics();
        display.getRealMetrics(metrics);
        return metrics.densityDpi;
    }

    private int physicalDisplayId() {
        Display display = getDisplay();
        return display == null ? -1 : display.getDisplayId();
    }

    private boolean hostVisible() {
        return getWindow() != null && getWindow().getDecorView() != null
                && getWindow().getDecorView().getWindowVisibility() == View.VISIBLE
                && getWindow().getDecorView().isShown()
                && !isFinishing() && !destroyed;
    }

    private boolean initialHostAuthorityReady() {
        return physicalDisplayId() == Display.DEFAULT_DISPLAY && physicalDensityDpi() > 0
                && resumed && hostVisible() && hasWindowFocus();
    }

    private void beginBoundedHostAuthoritySuspension(String reason) {
        if (virtualDisplay == null || releasing || destroyed) return;
        cancelDisplayWatchdog();
        canonicalFrameInstalled = false;
        frameWasReady = false;
        frameTransitionPending = true;
        long now = SystemClock.elapsedRealtime();
        long proposedDeadline = now + HOST_AUTHORITY_REACQUIRE_TIMEOUT_MS;
        boolean newlySuspended = lifecycle.suspendHostAuthority(proposedDeadline);
        long exactDeadline = lifecycle.hostAuthorityDeadlineElapsed();
        if (!newlySuspended && !(lifecycle.hostAuthoritySuspended()
                && exactDeadline > 0)) {
            releaseForUnexpectedLoss("host pause could not enter bounded suspension");
            return;
        }
        if (hostAuthorityDeadlineElapsed > 0
                && hostAuthorityDeadlineElapsed != exactDeadline) {
            releaseForUnexpectedLoss("host authority deadline changed during suspension");
            return;
        }
        hostAuthorityDeadlineElapsed = exactDeadline;
        if (now > exactDeadline) {
            clearDeferredCommand();
            releaseForUnexpectedLoss("bounded host authority reacquisition deadline expired");
            return;
        }
        final long exactGeneration = lifecycle.generation();
        removeHostAuthorityTimeoutCallback();
        hostAuthorityTimeout = () -> {
            if (virtualDisplay != null && !releasing && !destroyed
                    && lifecycle.generation() == exactGeneration
                    && (lifecycle.hasHostAuthorityTransition()
                        || lifecycle.hostAuthoritySuspended()
                        || deferredCommandPending || frameTransitionPending)
                    && hostAuthorityDeadlineElapsed == exactDeadline
                    && lifecycle.hostAuthorityDeadlineElapsed() == exactDeadline) {
                clearDeferredCommand();
                releaseForUnexpectedLoss("bounded host authority reacquisition timed out");
            }
        };
        main.postDelayed(hostAuthorityTimeout, Math.max(0L, exactDeadline - now));
        log("HOST_AUTHORITY_SUSPENDED", "reason=" + scrub(reason)
                + " deadlineRemainingMs=" + (exactDeadline - now)
                + " deadlineUnchanged=" + (exactDeadline != proposedDeadline));
    }

    private boolean reacquireHostAuthorityIfReady() {
        if (!lifecycle.hostAuthoritySuspended()) return true;
        if (hostAuthorityDeadlineElapsed <= 0
                || hostAuthorityDeadlineElapsed != lifecycle.hostAuthorityDeadlineElapsed()
                || SystemClock.elapsedRealtime() > hostAuthorityDeadlineElapsed) {
            clearDeferredCommand();
            releaseForUnexpectedLoss("bounded host authority reacquisition deadline expired");
            return false;
        }
        if (!initialHostAuthorityReady()) return false;
        if (!lifecycle.onHostAuthority(physicalDisplayId(), physicalDensityDpi(),
                resumed, hostVisible(), hasWindowFocus())) {
            clearDeferredCommand();
            releaseForUnexpectedLoss("host authority failed bounded reacquisition");
            return false;
        }
        log("HOST_AUTHORITY_REACQUIRED", "display=0 density="
                + lifecycle.admittedDensityDpi());
        return true;
    }

    private void completeHostAuthorityTransitionIfReady() {
        if (virtualDisplay == null || releasing || destroyed
                || lifecycle.hostAuthoritySuspended() || deferredCommandPending
                || !frameTransitionPending || !canonicalFrameInstalled
                || !fixedBufferReady) return;
        long exactDeadline = hostAuthorityDeadlineElapsed;
        if (exactDeadline <= 0 || SystemClock.elapsedRealtime() > exactDeadline
                || exactDeadline != lifecycle.hostAuthorityDeadlineElapsed()) {
            releaseForUnexpectedLoss("host authority transition lost its original deadline");
            return;
        }
        if (!verifyRuntimeAuthorityOrFail("host_authority_transition_complete")) return;
        if (!lifecycle.completeHostAuthorityTransition(exactDeadline)) {
            releaseForUnexpectedLoss("host authority transition completion was not exact");
            return;
        }
        removeHostAuthorityTimeoutCallback();
        hostAuthorityDeadlineElapsed = -1L;
        frameTransitionPending = false;
        log("HOST_AUTHORITY_READY", "deadlinePreserved=true frameAuthority=true");
        armDisplayWatchdog();
    }

    private void removeHostAuthorityTimeoutCallback() {
        if (hostAuthorityTimeout != null) main.removeCallbacks(hostAuthorityTimeout);
        hostAuthorityTimeout = null;
    }

    private void cancelHostAuthorityTimeout(boolean clearPendingCommand) {
        removeHostAuthorityTimeoutCallback();
        hostAuthorityDeadlineElapsed = -1L;
        frameTransitionPending = false;
        if (clearPendingCommand) clearDeferredCommand();
    }

    private boolean verifyHostAuthorityOrFail(String checkpoint) {
        if (lifecycle.onHostAuthority(physicalDisplayId(), physicalDensityDpi(),
                resumed, hostVisible(), hasWindowFocus())) return true;
        releaseForUnexpectedLoss("host authority changed at " + checkpoint);
        return false;
    }

    private boolean verifyPhysicalFrameOrFail(String checkpoint) {
        if (surface == null || root == null || root.getWidth() < 4 || root.getHeight() < 4) {
            releaseForUnexpectedLoss("physical frame missing at " + checkpoint);
            return false;
        }
        int hostWidth = root.getWidth();
        int hostHeight = root.getHeight();
        if (!((hostWidth == 1404 && hostHeight == 1872)
                || (hostWidth == 1872 && hostHeight == 1404))) {
            releaseForUnexpectedLoss("host geometry changed at " + checkpoint);
            return false;
        }
        if (!hostGeometryMatchesExpectedConfiguration(hostWidth, hostHeight)) {
            releaseForUnexpectedLoss("host geometry contradicted configuration at " + checkpoint);
            return false;
        }
        int[] rootLocation = new int[2];
        root.getLocationOnScreen(rootLocation);
        if (rootLocation[0] != 0 || rootLocation[1] != 0) {
            releaseForUnexpectedLoss("host origin changed at " + checkpoint);
            return false;
        }
        int[] surfaceLocation = new int[2];
        surface.getLocationOnScreen(surfaceLocation);
        long sequence = lifecycle.pendingPlacementSequence();
        FrameResult result = lifecycle.onPhysicalFrameMeasured(hostWidth, hostHeight,
                surfaceLocation[0], surfaceLocation[1], surface.getWidth(), surface.getHeight(),
                sequence);
        if (result == FrameResult.REJECTED) {
            releaseForUnexpectedLoss("physical frame changed at " + checkpoint);
            return false;
        }
        if (result == FrameResult.READY && sequence > 0) {
            cancelPlacementTimeout();
            canonicalFrameInstalled = true;
            if (lifecycle.isFailed()) {
                log("FAILED_FRAME_AUTHORITY", "sequence=" + sequence + " checkpoint="
                        + scrub(checkpoint) + " committed=" + lifecycle.placement());
            } else {
                requested = lifecycle.placement();
                log("PLACEMENT_READY", "sequence=" + sequence + " checkpoint="
                        + scrub(checkpoint));
            }
        }
        return true;
    }

    @Override public void surfaceDestroyed(SurfaceHolder holder) {
        if (!destroyed && lifecycle.state() != NativePageHostLifecycle.State.RELEASED) {
            releaseForUnexpectedLoss("host surface lost unexpectedly");
        }
    }

    private void armAttachTimeout(long admittedGeneration) {
        cancelAttachTimeout();
        attachTimeout = () -> {
            if (lifecycle.onAttachTimeout(admittedGeneration)) {
                log("TIMEOUT", "phase=foreign_attach displayRetained=true");
                showStatus();
            }
        };
        main.postDelayed(attachTimeout, ATTACH_TIMEOUT_MS);
    }

    private void armDestroyTimeout(long admittedGeneration) {
        cancelDestroyTimeout();
        destroyTimeout = () -> {
            if (lifecycle.onDestroyTimeout(admittedGeneration)) {
                log("TIMEOUT", "phase=foreign_destroy displayRetained=true"
                        + " exactDestroyAckStillRequired=true");
                showStatus();
            }
        };
        main.postDelayed(destroyTimeout, DESTROY_TIMEOUT_MS);
    }

    private void armPlacementTimeout(long admittedGeneration, long commandSequence) {
        cancelPlacementTimeout();
        placementTimeout = () -> {
            if (lifecycle.onPlacementTimeout(admittedGeneration, commandSequence)) {
                log("TIMEOUT", "phase=placement sequence=" + commandSequence
                        + " emergencyCleanupRequired=true");
                releaseForUnexpectedLoss("sequence-bound placement frame timed out");
            }
        };
        main.postDelayed(placementTimeout, PLACEMENT_TIMEOUT_MS);
    }

    private void cancelAttachTimeout() {
        if (attachTimeout != null) main.removeCallbacks(attachTimeout);
        attachTimeout = null;
    }

    private void cancelDestroyTimeout() {
        if (destroyTimeout != null) main.removeCallbacks(destroyTimeout);
        destroyTimeout = null;
    }

    private void cancelPlacementTimeout() {
        if (placementTimeout != null) main.removeCallbacks(placementTimeout);
        placementTimeout = null;
    }

    private boolean releaseNormally() {
        if (!lifecycle.canReleaseNormally()) {
            reject("normal release lacked exact destruction or absence acknowledgment");
            return false;
        }
        cancelAttachTimeout();
        cancelDestroyTimeout();
        cancelPlacementTimeout();
        cancelDisplayWatchdog();
        cancelHostAuthorityTimeout(true);
        VirtualDisplay old = virtualDisplay;
        int releasedId = displayId;
        if (old != null) {
            releasing = true;
            try {
                old.release();
            } catch (RuntimeException releaseFailure) {
                lifecycle.onReleaseAttemptFailed(false, releaseFailure.getClass().getSimpleName());
                boolean retryAddressable = lifecycle.retainedDisplayCleanupAddressable(releasedId);
                log("RELEASE_FAILED", "display=" + releasedId
                        + " mode=acknowledged_cleanup retained=true retryAddressable="
                        + retryAddressable + " reason="
                        + scrub(releaseFailure.getClass().getSimpleName()));
                if (!retryAddressable) {
                    escalateOwnProcessCleanup("unaddressable acknowledged release failure");
                }
                showStatus();
                return false;
            } finally {
                releasing = false;
            }
        }
        lifecycle.markReleased(false);
        virtualDisplay = null;
        displayId = -1;
        log("DISPLAY_RELEASED", "display=" + releasedId + " mode=acknowledged_cleanup");
        return true;
    }

    private boolean releaseForUnexpectedLoss(String reason) {
        lifecycle.onUnexpectedHostLoss(reason);
        cancelAttachTimeout();
        cancelDestroyTimeout();
        cancelPlacementTimeout();
        cancelDisplayWatchdog();
        cancelHostAuthorityTimeout(true);
        VirtualDisplay old = virtualDisplay;
        int releasedId = displayId;
        if (old != null) {
            releasing = true;
            try {
                old.release();
            } catch (RuntimeException releaseFailure) {
                lifecycle.onReleaseAttemptFailed(true, releaseFailure.getClass().getSimpleName());
                boolean retryAddressable = lifecycle.retainedDisplayCleanupAddressable(releasedId);
                log("RELEASE_FAILED", "display=" + releasedId
                        + " mode=emergency retained=true retryAddressable="
                        + retryAddressable + " reason="
                        + scrub(releaseFailure.getClass().getSimpleName()));
                if (!retryAddressable) {
                    escalateOwnProcessCleanup("unaddressable emergency release failure");
                }
                showStatus();
                return false;
            } finally {
                releasing = false;
            }
        }
        lifecycle.markReleased(true);
        virtualDisplay = null;
        displayId = -1;
        log("FAILED", "reason=" + scrub(reason) + " display=" + releasedId
                + " emergencyDestroyContent=true");
        showStatus();
        return true;
    }

    private void escalateOwnProcessCleanup(String reason) {
        if (processCleanupEscalated) return;
        processCleanupEscalated = true;
        // The current process is the only remaining owner. No PID is retained and
        // no later instance may inherit this session or VirtualDisplay authority.
        log("PROCESS_CLEANUP_ESCALATED",
                "reason=" + scrub(reason) + " owner=android_process_death");
        android.os.Process.killProcess(android.os.Process.myPid());
    }

    private void reject(String reason) {
        lifecycle.onProtocolFailure(reason);
        rejectAlreadyFailed(reason);
    }

    private void rejectAlreadyFailed(String reason) {
        log("COMMAND_REJECTED", "reason=" + scrub(reason) + " readiness=" + readiness());
        showStatus();
    }

    private String readiness() {
        if (lifecycle == null) return "NO_LIFECYCLE";
        if (lifecycle.hostAuthoritySuspended()) {
            return "HOST_AUTHORITY_SUSPENDED_" + lifecycle.state().name();
        }
        return lifecycle.state().name();
    }

    private String foreignDetail(ForeignTaskIdentity task) {
        if (task == null) return "foreign=none";
        return "foreignPackage=" + task.packageName + " foreignComponent="
                + scrub(task.componentName) + " foreignTask=" + task.taskId
                + " foreignPid=" + task.pid + " foreignUid=" + task.uid
                + " foreignStartTicks=" + task.processStartTicks
                + " foreignEvidenceSha256=" + task.verificationSha256;
    }

    private static String scrub(String value) {
        if (value == null) return "null";
        return value.replace('\n', '_').replace('\r', '_').replace(' ', '_');
    }

    private void showStatus() {
        if (status == null || lifecycle == null) return;
        StringBuilder text = new StringBuilder();
        text.append("NATIVE PAGE HOST — VISUAL ONLY\n")
                .append("session=").append(session).append("\n")
                .append("generation=").append(lifecycle.generation())
                .append(" display=").append(displayId).append("\n")
                .append("state=").append(lifecycle.state());
        if (lifecycle.failure() != null) {
            text.append("\nFAILED (sticky): ").append(lifecycle.failure());
            if (lifecycle.foreignTask() != null && !lifecycle.canReleaseNormally()) {
                text.append("\nDestroy the exact foreign task, then send its exact ACK.");
            }
        } else if (lifecycle.hostAuthoritySuspended()) {
            text.append("\nHost authority is temporarily suspended; one exact command may wait.");
        } else if (lifecycle.isWaitingForAttach()) {
            text.append("\nExternally launch + verify Document, then ACK exact task identity.");
        } else if (lifecycle.isActive()) {
            text.append("\nREADY • placement commands require this live session.");
        } else if (lifecycle.isWaitingForDestroy()) {
            text.append("\nWaiting for externally verified foreign-task destruction.");
        }
        text.append("\nStylus is swallowed; no reader launch, pen, file, or root authority.");
        status.setText(text.toString());
    }

    private void log(String event, String detail) {
        Log.i(TAG, event + " session=" + session + " generation="
                + (lifecycle == null ? -1 : lifecycle.generation()) + " " + detail);
    }

    @Override public void onBackPressed() {
        if (virtualDisplay == null && lifecycle.canFinishWithoutCleanup()) {
            log("BACK_ALLOWED", "reason=no_display_or_foreign_cleanup_authority");
            finishAndRemoveTask();
        } else {
            log("BACK_BLOCKED", "reason=authenticated_close_sequence_required");
            showStatus();
        }
    }

    @Override protected void onSaveInstanceState(Bundle state) {
        super.onSaveInstanceState(state);
        state.putBoolean("nativePageHostExisted", true);
        // Session/display/task authority is intentionally never persisted.
    }

    @Override protected void onResume() {
        super.onResume();
        resumed = true;
        if (root != null) root.post(() -> {
            if (reacquireHostAuthorityIfReady()) layoutSurface();
        });
    }

    @Override protected void onPause() {
        resumed = false;
        beginBoundedHostAuthoritySuspension("onPause");
        super.onPause();
    }

    @Override public void onWindowFocusChanged(boolean hasFocus) {
        super.onWindowFocusChanged(hasFocus);
        if (hasFocus) {
            if (root != null) root.post(() -> {
                if (reacquireHostAuthorityIfReady()) layoutSurface();
            });
        } else if (virtualDisplay != null && !releasing && !destroyed) {
            beginBoundedHostAuthoritySuspension("window_focus_lost");
        }
    }

    @Override protected void onDestroy() {
        destroyed = true;
        cancelAttachTimeout();
        cancelDestroyTimeout();
        cancelPlacementTimeout();
        cancelDisplayWatchdog();
        cancelHostAuthorityTimeout(true);
        boolean processCleanupRequired = false;
        if (virtualDisplay != null && lifecycle.state() != NativePageHostLifecycle.State.RELEASED) {
            processCleanupRequired = !releaseForUnexpectedLoss(
                    "host activity destroyed unexpectedly");
        }
        super.onDestroy();
        if (processCleanupRequired) {
            // The Activity instance is now dead, so it cannot truthfully retain a
            // retry owner. Terminating this exact process delegates the remaining
            // Binder/display cleanup to Android without static session/PID state.
            escalateOwnProcessCleanup("release failed during Activity destruction");
        }
    }
}
