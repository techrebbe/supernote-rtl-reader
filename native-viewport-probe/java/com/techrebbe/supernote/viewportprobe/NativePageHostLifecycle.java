package com.techrebbe.supernote.viewportprobe;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/** Pure, fail-closed state machine for the visual-only native-page host. */
public final class NativePageHostLifecycle {
    public static final String REQUIRED_FOREIGN_PACKAGE = "com.supernote.document";
    public static final String REQUIRED_FOREIGN_COMPONENT =
            "com.supernote.document/com.supernote.document.document.DocumentActivity";
    public static final int REQUIRED_PHYSICAL_DISPLAY_ID = 0;
    public static final int DEFER_ATTACH = 1;
    public static final int DEFER_PLACE_FULL = 2;
    public static final int DEFER_PLACE_LEFT = 3;
    public static final int DEFER_PLACE_RIGHT = 4;
    public static final int DEFER_BEGIN_CLOSE = 5;
    public static final int DEFER_ACK_DESTROYED = 6;

    public enum State {
        STARTABLE, CREATING_DISPLAY, DISPLAY_ALLOCATED, WAITING_FOR_FOREIGN_ATTACH, ACTIVE,
        PLACEMENT_PENDING, WAITING_FOR_FOREIGN_DESTROY, RELEASE_AUTHORIZED,
        FAILED, RELEASED
    }

    /** Only CONTRADICTION represents an authenticated, sticky protocol failure. */
    public enum CommandResult {
        ACCEPTED, IDEMPOTENT, UNAUTHENTICATED_OR_STALE, CONTRADICTION
    }

    /** A measured target frame commits placement; the old frame is transitional only. */
    public enum FrameResult { READY, TRANSITIONAL, REJECTED }

    public static final class ForeignTaskIdentity {
        public final String packageName;
        public final String componentName;
        public final int taskId;
        public final int pid;
        public final int uid;
        public final String processStartTicks;
        public final String verificationSha256;

        private ForeignTaskIdentity(String packageName, String componentName, int taskId,
                int pid, int uid, String processStartTicks, String verificationSha256) {
            this.packageName = packageName;
            this.componentName = componentName;
            this.taskId = taskId;
            this.pid = pid;
            this.uid = uid;
            this.processStartTicks = processStartTicks;
            this.verificationSha256 = verificationSha256;
        }

        public static ForeignTaskIdentity checked(String packageName, String componentName,
                int taskId, int pid, int uid, String processStartTicks,
                String verificationSha256) {
            if (!REQUIRED_FOREIGN_PACKAGE.equals(packageName)
                    || !REQUIRED_FOREIGN_COMPONENT.equals(componentName)
                    || taskId <= 0 || pid <= 0 || uid != 1000
                    || processStartTicks == null
                    || !processStartTicks.matches("[1-9][0-9]{0,31}")
                    || verificationSha256 == null
                    || !verificationSha256.matches("[0-9a-f]{64}")) {
                throw new IllegalArgumentException("invalid foreign task identity");
            }
            return new ForeignTaskIdentity(packageName, componentName, taskId, pid, uid,
                    processStartTicks, verificationSha256);
        }

        public boolean exactlyEquals(ForeignTaskIdentity other) {
            return other != null && packageName.equals(other.packageName)
                    && componentName.equals(other.componentName) && taskId == other.taskId
                    && pid == other.pid && uid == other.uid
                    && processStartTicks.equals(other.processStartTicks)
                    && verificationSha256.equals(other.verificationSha256);
        }

        private String commandKey() {
            return packageName + "|" + componentName + "|" + taskId + "|" + pid + "|"
                    + uid + "|" + processStartTicks + "|" + verificationSha256;
        }
    }

    private final byte[] sessionCapability;
    private final String sessionId;
    private State state;
    private long generation;
    private int displayId = -1;
    private int admittedDensityDpi = -1;
    private boolean hostAuthorityAdmitted;
    private boolean hostAuthoritySuspended;
    private long hostAuthorityDeadlineElapsed = -1L;
    private ForeignTaskIdentity foreignTask;
    private DisplayProbeLayout.Placement placement = DisplayProbeLayout.Placement.FULL;
    private DisplayProbeLayout.Placement pendingPlacement;
    private long pendingPlacementSequence;
    private boolean frameReady;
    private String failure;
    private boolean normalReleaseAuthorized;
    private boolean emptyFailureCleanupAuthorized;
    private boolean emptyPreAttachAbortAuthorized;
    private boolean emergencyReleaseRequired;
    private boolean displayRemoved = true;
    private boolean destroyAcknowledgmentEligible;
    private long lastCommandSequence;
    private int deferredCommandKind;
    private long deferredCommandSequence;
    private String deferredCommandKey;
    private final Map<Long, String> acceptedCommands = new HashMap<>();

    public NativePageHostLifecycle(boolean restoredInstance, String sessionId) {
        this.sessionId = requireCanonicalUuid(sessionId);
        this.sessionCapability = sessionId.getBytes(StandardCharsets.US_ASCII);
        if (restoredInstance) {
            state = State.FAILED;
            failure = "restored host cannot inherit display authority";
        } else {
            state = State.STARTABLE;
        }
    }

    private static String requireCanonicalUuid(String value) {
        if (value == null || value.length() != 36) {
            throw new IllegalArgumentException("session must be a canonical UUID");
        }
        try {
            String canonical = UUID.fromString(value).toString();
            if (!canonical.equals(value)) throw new IllegalArgumentException("noncanonical");
            return canonical;
        } catch (IllegalArgumentException error) {
            throw new IllegalArgumentException("session must be a canonical UUID", error);
        }
    }

    public String sessionId() { return sessionId; }
    public State state() { return state; }
    public long generation() { return generation; }
    public int displayId() { return displayId; }
    public int admittedDensityDpi() { return admittedDensityDpi; }
    public boolean hostAuthorityAdmitted() { return hostAuthorityAdmitted; }
    public boolean hostAuthoritySuspended() { return hostAuthoritySuspended; }
    public long hostAuthorityDeadlineElapsed() { return hostAuthorityDeadlineElapsed; }
    public boolean hasHostAuthorityTransition() {
        return hostAuthorityDeadlineElapsed > 0;
    }
    public ForeignTaskIdentity foreignTask() { return foreignTask; }
    public String failure() { return failure; }
    public boolean isFailed() { return failure != null; }
    public boolean isActive() {
        return state == State.ACTIVE && failure == null && !hostAuthoritySuspended;
    }
    /** Only this exact state may be advertised as a newly completed attach. */
    public boolean canPublishFreshAttachReady() {
        return state == State.ACTIVE && failure == null && foreignTask != null
                && !hostAuthoritySuspended;
    }
    /** Only a newly accepted BEGIN_CLOSE may advertise this exact wait phase. */
    public boolean canPublishFreshCloseWait() {
        return state == State.WAITING_FOR_FOREIGN_DESTROY
                && destroyAcknowledgmentEligible && foreignTask != null
                && !normalReleaseAuthorized;
    }
    public boolean isPlacementPending() { return state == State.PLACEMENT_PENDING; }
    public boolean isWaitingForAttach() { return state == State.WAITING_FOR_FOREIGN_ATTACH; }
    public boolean isWaitingForDestroy() {
        return state == State.WAITING_FOR_FOREIGN_DESTROY
                || (failure != null && destroyAcknowledgmentEligible
                    && foreignTask != null && !normalReleaseAuthorized);
    }
    public boolean canReleaseNormally() {
        return normalReleaseAuthorized || emptyFailureCleanupAuthorized
                || emptyPreAttachAbortAuthorized;
    }
    public boolean mustReleaseForHostLoss() { return emergencyReleaseRequired; }
    public boolean displayRemoved() { return displayRemoved; }
    /** Sticky protocol failure does not revoke unchanged physical host ownership. */
    public boolean retainsPhysicalHostAuthority() {
        return hostAuthorityAdmitted && !hostAuthoritySuspended && !displayRemoved
                && displayId > 0 && state != State.RELEASED && !emergencyReleaseRequired;
    }
    /** A retained object is externally retryable only through this exact positive ID. */
    public boolean retainedDisplayCleanupAddressable(int retainedDisplayId) {
        return !displayRemoved && generation > 0 && displayId > 0
                && retainedDisplayId == displayId;
    }
    public boolean canFinishWithoutCleanup() { return displayRemoved && foreignTask == null; }
    public DisplayProbeLayout.Placement placement() { return placement; }
    public DisplayProbeLayout.Placement frameRequestPlacement() {
        return pendingPlacement == null ? placement : pendingPlacement;
    }
    public long pendingPlacementSequence() { return pendingPlacementSequence; }
    public long lastCommandSequence() { return lastCommandSequence; }
    public boolean hasDeferredCommand() { return deferredCommandKey != null; }

    /** Host authority is admitted only while this Activity owns the visible focused default display. */
    public boolean admitHostAuthority(int physicalDisplayId, int densityDpi,
            boolean resumed, boolean visible, boolean focused) {
        if (state != State.STARTABLE || failure != null || hostAuthorityAdmitted
                || physicalDisplayId != REQUIRED_PHYSICAL_DISPLAY_ID || densityDpi <= 0
                || !resumed || !visible || !focused) {
            fail("host physical display/visibility authority admission failed");
            return false;
        }
        admittedDensityDpi = densityDpi;
        hostAuthorityAdmitted = true;
        hostAuthoritySuspended = false;
        return true;
    }

    /**
     * Revalidates only the physical host before a VirtualDisplay exists. This is
     * deliberately distinct from {@link #onHostAuthority}: STARTABLE still has
     * displayRemoved=true and displayId=-1, and must never fabricate allocated
     * display authority merely to pass its first layout.
     */
    public boolean revalidatePreAllocationHostAuthority(int physicalDisplayId, int densityDpi,
            boolean resumed, boolean visible, boolean focused) {
        if (state != State.STARTABLE || failure != null || !hostAuthorityAdmitted
                || hostAuthoritySuspended || !displayRemoved || displayId != -1
                || generation != 0 || !frameReady
                || physicalDisplayId != REQUIRED_PHYSICAL_DISPLAY_ID
                || densityDpi != admittedDensityDpi || !resumed || !visible || !focused) {
            fail("pre-allocation physical host/frame authority revalidation failed");
            return false;
        }
        return true;
    }

    /**
     * Records Android's bounded pause/focus transition without pretending that the
     * host remains authoritative. No presentation command may be applied while
     * this bit is set; exact terminal cleanup does not regain that authority.
     */
    public boolean suspendHostAuthority(long proposedAbsoluteDeadlineElapsed) {
        if (!hostAuthorityAdmitted || displayRemoved || emergencyReleaseRequired
                || state == State.RELEASED || displayId <= 0
                || proposedAbsoluteDeadlineElapsed <= 0) return false;
        if (hostAuthorityDeadlineElapsed > 0) {
            // A pause/configuration/layout churn cycle belongs to one bounded
            // transition. Never renew its original absolute deadline.
            if (hostAuthoritySuspended) return false;
            hostAuthoritySuspended = true;
            return true;
        }
        hostAuthorityDeadlineElapsed = proposedAbsoluteDeadlineElapsed;
        hostAuthoritySuspended = true;
        return true;
    }

    /** Only the next still-fresh command may be reserved during a bounded suspension. */
    public boolean canDeferFreshCommand(long commandSequence) {
        return hostAuthorityAdmitted && hostAuthoritySuspended && failure == null
                && hostAuthorityDeadlineElapsed > 0
                && commandSequence == lastCommandSequence + 1;
    }

    /** Reserves exactly one typed command without committing its sequence or state. */
    public boolean reserveDeferredCommand(String capability, long commandGeneration,
            int commandDisplayId, long commandSequence, int commandKind,
            ForeignTaskIdentity identity) {
        if (!authorize(capability, commandGeneration, commandDisplayId)) return false;
        String key = deferredCommandKey(commandKind, identity);
        boolean phaseValid = false;
        if (commandKind == DEFER_ATTACH) {
            phaseValid = identity != null && state == State.WAITING_FOR_FOREIGN_ATTACH
                    && foreignTask == null && frameReady;
        } else if (commandKind == DEFER_PLACE_FULL || commandKind == DEFER_PLACE_LEFT
                || commandKind == DEFER_PLACE_RIGHT) {
            phaseValid = identity == null && state == State.ACTIVE && frameReady
                    && pendingPlacement == null;
        } else if (commandKind == DEFER_BEGIN_CLOSE) {
            phaseValid = identity == null && foreignTask != null
                    && (state == State.ACTIVE || state == State.PLACEMENT_PENDING);
        } else if (commandKind == DEFER_ACK_DESTROYED) {
            phaseValid = identity != null && foreignTask != null
                    && foreignTask.exactlyEquals(identity) && destroyAcknowledgmentEligible
                    && state == State.WAITING_FOR_FOREIGN_DESTROY;
        }
        if (key == null || !phaseValid || !canDeferFreshCommand(commandSequence)
                || deferredCommandKey != null) {
            clearDeferredCommand();
            contradiction("deferred command was invalid, multiple, or out of sequence");
            return false;
        }
        deferredCommandKind = commandKind;
        deferredCommandSequence = commandSequence;
        deferredCommandKey = key;
        return true;
    }

    /** Consumes only the exact reservation after authority returns, without applying it. */
    public boolean consumeDeferredCommand(String capability, long commandGeneration,
            int commandDisplayId, long commandSequence, int commandKind,
            ForeignTaskIdentity identity) {
        if (!authorize(capability, commandGeneration, commandDisplayId)) return false;
        String key = deferredCommandKey(commandKind, identity);
        if (hostAuthoritySuspended || failure != null || deferredCommandKey == null
                || deferredCommandKind != commandKind
                || deferredCommandSequence != commandSequence
                || key == null || !deferredCommandKey.equals(key)) {
            clearDeferredCommand();
            contradiction("deferred command consumption contradicted exact reservation");
            return false;
        }
        clearDeferredCommand();
        return true;
    }

    private String deferredCommandKey(int commandKind, ForeignTaskIdentity identity) {
        if (commandKind == DEFER_ATTACH) {
            return identity == null ? null : "ATTACH|" + identity.commandKey();
        }
        if (commandKind == DEFER_PLACE_FULL) return identity == null ? "PLACE|FULL" : null;
        if (commandKind == DEFER_PLACE_LEFT) return identity == null ? "PLACE|LEFT" : null;
        if (commandKind == DEFER_PLACE_RIGHT) return identity == null ? "PLACE|RIGHT" : null;
        if (commandKind == DEFER_BEGIN_CLOSE) return identity == null ? "BEGIN_CLOSE" : null;
        if (commandKind == DEFER_ACK_DESTROYED) {
            return identity == null ? null : "DESTROY|" + identity.commandKey();
        }
        return null;
    }

    private void clearDeferredCommand() {
        deferredCommandKind = 0;
        deferredCommandSequence = 0;
        deferredCommandKey = null;
    }

    /** Any allocated-display identity, density, or visibility drift is an emergency loss. */
    public boolean onHostAuthority(int physicalDisplayId, int densityDpi,
            boolean resumed, boolean visible, boolean focused) {
        if (!hostAuthorityAdmitted || displayRemoved || emergencyReleaseRequired
                || state == State.RELEASED || displayId <= 0
                || physicalDisplayId != REQUIRED_PHYSICAL_DISPLAY_ID
                || densityDpi != admittedDensityDpi || !resumed || !visible || !focused) {
            onUnexpectedHostLoss("host physical display/visibility authority changed");
            return false;
        }
        hostAuthoritySuspended = false;
        return true;
    }

    /**
     * Ends the one bounded authority/frame transition only after authority has
     * returned, its canonical physical frame is measured, and any exact deferred
     * command has been consumed. The caller must present the original deadline.
     */
    public boolean completeHostAuthorityTransition(long exactAbsoluteDeadlineElapsed) {
        if (hostAuthorityDeadlineElapsed <= 0
                || exactAbsoluteDeadlineElapsed != hostAuthorityDeadlineElapsed
                || hostAuthoritySuspended || emergencyReleaseRequired || !frameReady
                || deferredCommandKey != null || state == State.RELEASED) return false;
        hostAuthorityDeadlineElapsed = -1L;
        return true;
    }

    public long beginDisplayCreation() {
        if (state != State.STARTABLE || failure != null || !hostAuthorityAdmitted
                || hostAuthoritySuspended
                || !frameReady) return -1;
        generation++;
        state = State.CREATING_DISPLAY;
        displayRemoved = false;
        return generation;
    }

    /**
     * Admits ownership immediately after Android returns the allocated positive ID.
     * This must precede every fallible metrics query so failed-session cleanup stays
     * addressable even if both metrics and the first release attempt fail.
     */
    public boolean onDisplayAllocated(long commandGeneration, int newDisplayId) {
        if (newDisplayId <= 0 || (displayId > 0 && displayId != newDisplayId)) {
            fail("display-allocation callback lacked allocatable display authority");
            return false;
        }
        // Retain the actual positive ID before validating lifecycle order. Even a
        // contradictory callback must leave the allocated object addressable for the
        // exact failed-session cleanup protocol.
        displayId = newDisplayId;
        if (state != State.CREATING_DISPLAY || commandGeneration != generation) {
            fail("display-allocation callback contradicted lifecycle authority");
            return false;
        }
        state = State.DISPLAY_ALLOCATED;
        return true;
    }

    /** Completes readiness only after the allocated display's metrics are authoritative. */
    public boolean onDisplayCreated(long commandGeneration, int newDisplayId,
            int width, int height, int densityDpi) {
        if (newDisplayId <= 0 || displayId != newDisplayId
                || state != State.DISPLAY_ALLOCATED || commandGeneration != generation
                || densityDpi <= 0) {
            fail("display-created callback contradicted lifecycle authority");
            return false;
        }
        if (width != DisplayProbeLayout.BUFFER_WIDTH
                || height != DisplayProbeLayout.BUFFER_HEIGHT
                || densityDpi != admittedDensityDpi) {
            fail("display-created callback did not match fixed display authority");
            return false;
        }
        state = State.WAITING_FOR_FOREIGN_ATTACH;
        return true;
    }

    /** Payloads are parsed only after this exact live-envelope check succeeds. */
    public boolean commandEnvelopeMatches(String capability, long commandGeneration,
            int commandDisplayId, long commandSequence) {
        return commandSequence > 0
                && authorize(capability, commandGeneration, commandDisplayId);
    }

    public CommandResult acknowledgeForeignAttached(String capability, long commandGeneration,
            int commandDisplayId, long commandSequence, ForeignTaskIdentity identity) {
        if (!authorize(capability, commandGeneration, commandDisplayId)) return stale();
        String key = identity == null ? "ATTACH|null" : "ATTACH|" + identity.commandKey();
        CommandResult replay = classifySequence(commandSequence, key);
        if (replay != null) return replay;
        if (deferredCommandKey != null) {
            return contradiction("direct attach attempted to bypass deferred command");
        }
        if (identity == null) return contradiction("authenticated attach lacked identity");
        if (state != State.WAITING_FOR_FOREIGN_ATTACH || foreignTask != null
                || failure != null || !frameReady) {
            return contradiction("authenticated attach contradicted lifecycle/identity");
        }
        foreignTask = identity;
        state = State.ACTIVE;
        return commit(commandSequence, key);
    }

    /** Phase one authenticates the request but does not change the committed placement. */
    public CommandResult authorizePlacement(String capability, long commandGeneration,
            int commandDisplayId, long commandSequence,
            DisplayProbeLayout.Placement requestedPlacement) {
        if (!authorize(capability, commandGeneration, commandDisplayId)) return stale();
        String key = "PLACE|" + (requestedPlacement == null ? "null" : requestedPlacement.name());
        CommandResult replay = classifySequence(commandSequence, key);
        if (replay != null) return replay;
        if (deferredCommandKey != null) {
            return contradiction("direct placement attempted to bypass deferred command");
        }
        if (requestedPlacement == null || state != State.ACTIVE || failure != null
                || !frameReady || pendingPlacement != null) {
            return contradiction("authenticated placement contradicted lifecycle/frame authority");
        }
        pendingPlacement = requestedPlacement;
        pendingPlacementSequence = commandSequence;
        state = State.PLACEMENT_PENDING;
        frameReady = false;
        return commit(commandSequence, key);
    }

    /**
     * Phase two accepts the old exact rectangle during layout and commits only the
     * sequence-bound requested rectangle after Android reports those physical bounds.
     */
    public FrameResult onPhysicalFrameMeasured(int hostWidth, int hostHeight,
            int left, int top, int width, int height, long placementSequence) {
        if (!hostAuthorityAdmitted || hostAuthoritySuspended) {
            fail("physical frame lacked live host authority");
            return FrameResult.REJECTED;
        }
        DisplayProbeLayout committed;
        DisplayProbeLayout target;
        try {
            committed = DisplayProbeLayout.fit(hostWidth, hostHeight, placement);
            target = DisplayProbeLayout.fit(hostWidth, hostHeight, frameRequestPlacement());
        } catch (IllegalArgumentException invalid) {
            onUnexpectedHostLoss("physical frame host geometry became invalid");
            return FrameResult.REJECTED;
        }
        boolean targetMatch = target.exactlyMatches(left, top, width, height);
        if (failure != null) {
            // Sticky protocol failure must not itself destroy a still-authoritative
            // display before the external exact cleanup handshake. Never commit a
            // pending placement after failure, but continue to admit only its two
            // sequence-bound transition rectangles.
            if (pendingPlacement != null && placementSequence == pendingPlacementSequence
                    && (targetMatch || committed.exactlyMatches(left, top, width, height))) {
                // The failed session does not commit the requested placement, but an
                // exact member of the retained old/target frame pair is sufficient
                // physical authority to finish a bounded pause/configuration cycle.
                frameReady = true;
                return FrameResult.READY;
            }
            if (pendingPlacement == null && placementSequence == 0
                    && committed.exactlyMatches(left, top, width, height)) {
                return FrameResult.READY;
            }
            onUnexpectedHostLoss("failed-session physical frame escaped authority");
            return FrameResult.REJECTED;
        }
        if (pendingPlacement != null) {
            if (placementSequence != pendingPlacementSequence) {
                onUnexpectedHostLoss("placement frame sequence changed");
                return FrameResult.REJECTED;
            }
            if (targetMatch) {
                placement = pendingPlacement;
                pendingPlacement = null;
                pendingPlacementSequence = 0;
                frameReady = true;
                if (failure == null && state == State.PLACEMENT_PENDING) {
                    state = State.ACTIVE;
                }
                return FrameResult.READY;
            }
            if (committed.exactlyMatches(left, top, width, height)) {
                return FrameResult.TRANSITIONAL;
            }
            onUnexpectedHostLoss("physical frame escaped two-phase placement authority");
            return FrameResult.REJECTED;
        }
        if (placementSequence != 0 || !targetMatch) {
            onUnexpectedHostLoss("physical frame contradicted committed placement authority");
            return FrameResult.REJECTED;
        }
        frameReady = true;
        return FrameResult.READY;
    }

    public boolean onPlacementTimeout(long timedGeneration, long timedSequence) {
        if (timedGeneration != generation || state != State.PLACEMENT_PENDING
                || pendingPlacement == null || timedSequence != pendingPlacementSequence) {
            return false;
        }
        onUnexpectedHostLoss("sequence-bound placement frame timed out");
        return true;
    }

    /** Cleanup remains reachable from a sticky contradiction with an admitted task. */
    public CommandResult beginClose(String capability, long commandGeneration,
            int commandDisplayId, long commandSequence) {
        if (!authorize(capability, commandGeneration, commandDisplayId)) return stale();
        String key = "BEGIN_CLOSE";
        CommandResult replay = classifySequence(commandSequence, key);
        if (replay != null) return replay;
        if (deferredCommandKey != null) {
            return contradiction("direct close attempted to bypass deferred command");
        }
        if (foreignTask == null) return contradiction("authenticated close lacked foreign task");
        boolean ordinary = failure == null
                && (state == State.ACTIVE || state == State.PLACEMENT_PENDING);
        boolean failedCleanup = failure != null && state == State.FAILED
                && !normalReleaseAuthorized;
        if (!ordinary && !failedCleanup) {
            return contradiction("authenticated close contradicted lifecycle");
        }
        // Preserve any in-flight placement pair while the exact foreign-task cleanup
        // handshake runs. A sticky contradiction may occur after Android installed
        // either the committed or requested frame; dropping that sequence here would
        // make the still-live, otherwise-authoritative surface fail its watchdog.
        destroyAcknowledgmentEligible = true;
        state = State.WAITING_FOR_FOREIGN_DESTROY;
        return commit(commandSequence, key);
    }

    public CommandResult acknowledgeForeignDestroyed(String capability, long commandGeneration,
            int commandDisplayId, long commandSequence, ForeignTaskIdentity identity) {
        if (!authorize(capability, commandGeneration, commandDisplayId)) return stale();
        String key = identity == null ? "DESTROY|null" : "DESTROY|" + identity.commandKey();
        CommandResult replay = classifySequence(commandSequence, key);
        if (replay != null) return replay;
        if (deferredCommandKey != null) {
            return contradiction("direct destroy attempted to bypass deferred command");
        }
        if (foreignTask == null || identity == null || !foreignTask.exactlyEquals(identity)) {
            return contradiction("authenticated destroy contradicted foreign identity");
        }
        if (!destroyAcknowledgmentEligible) {
            return contradiction("destroy acknowledgment arrived before cleanup authority");
        }
        if (!normalReleaseAuthorized
                && (state == State.WAITING_FOR_FOREIGN_DESTROY || failure != null)) {
            normalReleaseAuthorized = true;
            state = State.RELEASE_AUTHORIZED;
            return commit(commandSequence, key);
        }
        return contradiction("foreign task ended outside the exact cleanup sequence");
    }

    /**
     * Terminal cleanup of a healthy, still-empty allocated display. This never
     * creates a synthetic failure or grants presentation/foreign-task authority,
     * including during a bounded host pause. It is deliberately not deferrable.
     */
    public CommandResult acknowledgeNoForeignPreAttachAbort(String capability,
            long commandGeneration, int commandDisplayId, long commandSequence,
            String absenceEvidenceSha256) {
        if (!authorize(capability, commandGeneration, commandDisplayId)) return stale();
        String key = "PRE_ATTACH_ABORT|" + String.valueOf(absenceEvidenceSha256);
        // An exact accepted replay remains release-retry authority even if the
        // first release attempt failed. Fresh commands still require health.
        CommandResult replay = classifySequence(commandSequence, key);
        if (replay != null) return replay;
        if (failure != null || foreignTask != null || deferredCommandKey != null
                || (state != State.DISPLAY_ALLOCATED
                    && state != State.WAITING_FOR_FOREIGN_ATTACH)
                || !retainedDisplayCleanupAddressable(commandDisplayId)
                || absenceEvidenceSha256 == null
                || !absenceEvidenceSha256.matches("[0-9a-f]{64}")) {
            return contradiction("healthy pre-attach abort lacked exact empty-display authority");
        }
        emptyPreAttachAbortAuthorized = true;
        state = State.RELEASE_AUTHORIZED;
        return commit(commandSequence, key);
    }

    /** Exact external absence evidence cleans any failed pre-attach session, not just timeout. */
    public CommandResult acknowledgeNoForeignAfterFailure(String capability,
            long commandGeneration, int commandDisplayId, long commandSequence,
            String verificationSha256) {
        if (!authorize(capability, commandGeneration, commandDisplayId)) return stale();
        String key = "NO_FOREIGN|" + String.valueOf(verificationSha256);
        CommandResult replay = classifySequence(commandSequence, key);
        if (replay != null) return replay;
        if (failure == null || state != State.FAILED || foreignTask != null
                || emptyPreAttachAbortAuthorized
                || verificationSha256 == null
                || !verificationSha256.matches("[0-9a-f]{64}")) {
            return contradiction("empty failed-session cleanup lacked exact absence authority");
        }
        emptyFailureCleanupAuthorized = true;
        state = State.RELEASE_AUTHORIZED;
        return commit(commandSequence, key);
    }

    public boolean onAttachTimeout(long timedGeneration) {
        if (timedGeneration != generation || state != State.WAITING_FOR_FOREIGN_ATTACH) return false;
        fail("foreign attach acknowledgment timed out");
        return true;
    }

    public boolean onDestroyTimeout(long timedGeneration) {
        if (timedGeneration != generation || !isWaitingForDestroy()) return false;
        fail("foreign destruction acknowledgment timed out");
        return true;
    }

    public void onProtocolFailure(String reason) {
        fail(reason == null || reason.length() == 0 ? "protocol failure" : reason);
    }

    public void onUnexpectedHostLoss(String reason) {
        clearDeferredCommand();
        emergencyReleaseRequired = true;
        if (foreignTask != null) destroyAcknowledgmentEligible = true;
        fail(reason == null || reason.length() == 0 ? "unexpected host loss" : reason);
    }

    public void onReleaseAttemptFailed(boolean emergency, String reason) {
        if (emergency) emergencyReleaseRequired = true;
        fail("VirtualDisplay.release failed: "
                + (reason == null || reason.length() == 0 ? "unknown" : reason));
    }

    public boolean onVirtualDisplayMetrics(int width, int height, int densityDpi) {
        if (displayId <= 0 || width != DisplayProbeLayout.BUFFER_WIDTH
                || height != DisplayProbeLayout.BUFFER_HEIGHT
                || densityDpi != admittedDensityDpi) {
            onUnexpectedHostLoss("virtual display metrics changed");
            return false;
        }
        return true;
    }

    public void markReleased(boolean emergency) {
        if (state == State.RELEASED) return;
        if ((!emergency && !canReleaseNormally())
                || (emergency && !emergencyReleaseRequired)) {
            fail("display release lacked lifecycle authority");
            throw new IllegalStateException("display release lacked lifecycle authority");
        }
        displayRemoved = true;
        frameReady = false;
        hostAuthoritySuspended = false;
        hostAuthorityDeadlineElapsed = -1L;
        pendingPlacement = null;
        pendingPlacementSequence = 0;
        clearDeferredCommand();
        if (!emergency || foreignTask == null) state = State.RELEASED;
    }

    private CommandResult stale() { return CommandResult.UNAUTHENTICATED_OR_STALE; }

    private CommandResult classifySequence(long commandSequence, String key) {
        if (commandSequence <= 0) return stale();
        String accepted = acceptedCommands.get(commandSequence);
        if (accepted != null) {
            return accepted.equals(key) ? CommandResult.IDEMPOTENT
                    : contradiction("authenticated command sequence equivocated");
        }
        if (commandSequence != lastCommandSequence + 1) {
            return contradiction("authenticated command sequence was reordered or skipped");
        }
        return null;
    }

    private CommandResult commit(long commandSequence, String key) {
        acceptedCommands.put(commandSequence, key);
        lastCommandSequence = commandSequence;
        return CommandResult.ACCEPTED;
    }

    private CommandResult contradiction(String reason) {
        fail(reason);
        return CommandResult.CONTRADICTION;
    }

    private boolean authorize(String capability, long commandGeneration, int commandDisplayId) {
        if (capability == null || capability.length() != 36
                || commandGeneration != generation || commandDisplayId != displayId
                || displayId <= 0) return false;
        return MessageDigest.isEqual(sessionCapability,
                capability.getBytes(StandardCharsets.US_ASCII));
    }

    private void fail(String reason) {
        if (failure == null) failure = reason;
        clearDeferredCommand();
        if (state != State.RELEASED) state = State.FAILED;
    }
}
