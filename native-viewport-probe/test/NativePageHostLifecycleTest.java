import com.techrebbe.supernote.viewportprobe.DisplayProbeLayout;
import com.techrebbe.supernote.viewportprobe.NativePageHostLifecycle;
import com.techrebbe.supernote.viewportprobe.NativePageHostLifecycle.CommandResult;
import com.techrebbe.supernote.viewportprobe.NativePageHostLifecycle.FrameResult;
import com.techrebbe.supernote.viewportprobe.NativePageHostLifecycle.ForeignTaskIdentity;
import static com.techrebbe.supernote.viewportprobe.DisplayProbeLayout.Placement.*;

public final class NativePageHostLifecycleTest {
    private static int checks;
    private static final String TOKEN = "01234567-89ab-4cde-8fab-0123456789ab";
    private static final String WRONG_TOKEN = "11234567-89ab-4cde-8fab-0123456789ab";
    private static final String COMPONENT =
            "com.supernote.document/com.supernote.document.document.DocumentActivity";
    private static final String PROOF = repeat('a', 64);

    private static String repeat(char value, int count) {
        StringBuilder out = new StringBuilder();
        while (out.length() < count) out.append(value);
        return out.toString();
    }

    private static void require(boolean value) {
        checks++;
        if (!value) throw new AssertionError("check " + checks);
    }

    private static void rejects(Runnable action) {
        try { action.run(); throw new AssertionError("expected rejection"); }
        catch (IllegalArgumentException expected) { checks++; }
    }

    private static ForeignTaskIdentity task() {
        return ForeignTaskIdentity.checked("com.supernote.document", COMPONENT,
                41, 9123, 1000, "6336417", PROOF);
    }

    private static ForeignTaskIdentity taskWith(int taskId, int pid, String start, String proof) {
        return ForeignTaskIdentity.checked("com.supernote.document", COMPONENT,
                taskId, pid, 1000, start, proof);
    }

    private static NativePageHostLifecycle allocated(int displayId) {
        NativePageHostLifecycle value = new NativePageHostLifecycle(false, TOKEN);
        require(value.canFinishWithoutCleanup());
        require(value.admitHostAuthority(0, 320, true, true, true));
        require(value.onPhysicalFrameMeasured(1404, 1872, 0, 0, 1404, 1872, 0)
                == FrameResult.READY);
        require(value.revalidatePreAllocationHostAuthority(0, 320, true, true, true));
        require(value.beginDisplayCreation() == 1);
        require(!value.canFinishWithoutCleanup());
        require(value.onDisplayAllocated(1, displayId));
        return value;
    }

    private static NativePageHostLifecycle waiting(int displayId) {
        NativePageHostLifecycle value = allocated(displayId);
        require(value.onDisplayCreated(1, displayId, 1404, 1872, 320));
        return value;
    }

    private static NativePageHostLifecycle active(int displayId) {
        NativePageHostLifecycle value = waiting(displayId);
        require(value.acknowledgeForeignAttached(TOKEN, 1, displayId, 1, task())
                == CommandResult.ACCEPTED);
        require(value.canPublishFreshAttachReady());
        return value;
    }

    private static void unchanged(NativePageHostLifecycle value, NativePageHostLifecycle.State state,
            String failure, ForeignTaskIdentity identity) {
        require(value.state() == state);
        require(value.failure() == failure);
        require(value.foreignTask() == identity);
        require(!value.canReleaseNormally());
    }

    private static void testHealthyPreAttachAbort() {
        // Both healthy empty phases are eligible without manufacturing a failure,
        // admitting a foreign task, or acquiring suspended presentation authority.
        for (int phase = 0; phase < 2; phase++) {
            int display = 8000 + phase;
            NativePageHostLifecycle healthyPreAttachAbort = phase == 0
                    ? allocated(display) : waiting(display);
            require(healthyPreAttachAbort.acknowledgeNoForeignPreAttachAbort(
                    TOKEN, 1, display, 1, PROOF) == CommandResult.ACCEPTED);
            require(healthyPreAttachAbort.state()
                    == NativePageHostLifecycle.State.RELEASE_AUTHORIZED
                    && !healthyPreAttachAbort.isFailed()
                    && healthyPreAttachAbort.foreignTask() == null
                    && healthyPreAttachAbort.canReleaseNormally()
                    && !healthyPreAttachAbort.displayRemoved()
                    && !healthyPreAttachAbort.canPublishFreshAttachReady()
                    && !healthyPreAttachAbort.mustReleaseForHostLoss()
                    && healthyPreAttachAbort.lastCommandSequence() == 1);
            require(healthyPreAttachAbort.acknowledgeNoForeignPreAttachAbort(
                    TOKEN, 1, display, 1, PROOF) == CommandResult.IDEMPOTENT);
            require(!healthyPreAttachAbort.onAttachTimeout(1));
            healthyPreAttachAbort.markReleased(false);
            require(healthyPreAttachAbort.state() == NativePageHostLifecycle.State.RELEASED
                    && healthyPreAttachAbort.canFinishWithoutCleanup()
                    && !healthyPreAttachAbort.isFailed()
                    && healthyPreAttachAbort.beginDisplayCreation() == -1);
            require(healthyPreAttachAbort.acknowledgeNoForeignPreAttachAbort(
                    TOKEN, 1, display, 1, PROOF) == CommandResult.IDEMPOTENT);
            require(!healthyPreAttachAbort.isFailed());
            require(healthyPreAttachAbort.acknowledgeNoForeignPreAttachAbort(
                    TOKEN, 1, display, 2, PROOF) == CommandResult.CONTRADICTION);
            require(healthyPreAttachAbort.state() == NativePageHostLifecycle.State.RELEASED
                    && healthyPreAttachAbort.displayRemoved()
                    && healthyPreAttachAbort.lastCommandSequence() == 1);
        }

        for (int phase = 0; phase < 2; phase++) {
            int display = 8010 + phase;
            NativePageHostLifecycle pausedPreAttachAbort = phase == 0
                    ? allocated(display) : waiting(display);
            require(pausedPreAttachAbort.suspendHostAuthority(80_100L));
            require(pausedPreAttachAbort.acknowledgeNoForeignPreAttachAbort(
                    TOKEN, 1, display, 1, PROOF) == CommandResult.ACCEPTED);
            require(!pausedPreAttachAbort.isFailed()
                    && pausedPreAttachAbort.hostAuthoritySuspended()
                    && pausedPreAttachAbort.hostAuthorityDeadlineElapsed() == 80_100L
                    && !pausedPreAttachAbort.hasDeferredCommand()
                    && !pausedPreAttachAbort.isActive()
                    && pausedPreAttachAbort.canReleaseNormally());
            pausedPreAttachAbort.markReleased(false);
            require(pausedPreAttachAbort.state() == NativePageHostLifecycle.State.RELEASED
                    && !pausedPreAttachAbort.hostAuthoritySuspended()
                    && !pausedPreAttachAbort.hasHostAuthorityTransition());
        }

        NativePageHostLifecycle preAttachAbortReleaseFailure = waiting(8020);
        require(preAttachAbortReleaseFailure.acknowledgeNoForeignPreAttachAbort(
                TOKEN, 1, 8020, 1, PROOF) == CommandResult.ACCEPTED);
        preAttachAbortReleaseFailure.onReleaseAttemptFailed(false, "injected-pre-attach");
        String releaseFailure = preAttachAbortReleaseFailure.failure();
        require(preAttachAbortReleaseFailure.isFailed()
                && !preAttachAbortReleaseFailure.displayRemoved()
                && preAttachAbortReleaseFailure.retainedDisplayCleanupAddressable(8020)
                && preAttachAbortReleaseFailure.canReleaseNormally());
        require(preAttachAbortReleaseFailure.suspendHostAuthority(80_200L));
        require(preAttachAbortReleaseFailure.acknowledgeNoForeignPreAttachAbort(
                TOKEN, 1, 8020, 1, PROOF) == CommandResult.IDEMPOTENT);
        require(releaseFailure.equals(preAttachAbortReleaseFailure.failure())
                && preAttachAbortReleaseFailure.hostAuthoritySuspended()
                && preAttachAbortReleaseFailure.lastCommandSequence() == 1);
        require(preAttachAbortReleaseFailure.acknowledgeNoForeignPreAttachAbort(
                TOKEN, 1, 8020, 2, PROOF) == CommandResult.CONTRADICTION);
        require(preAttachAbortReleaseFailure.acknowledgeNoForeignPreAttachAbort(
                TOKEN, 1, 8020, 1, repeat('b', 64)) == CommandResult.CONTRADICTION);
        require(preAttachAbortReleaseFailure.acknowledgeNoForeignAfterFailure(
                TOKEN, 1, 8020, 2, PROOF) == CommandResult.CONTRADICTION);
        require(preAttachAbortReleaseFailure.acknowledgeNoForeignAfterFailure(
                TOKEN, 1, 8020, 2, repeat('b', 64)) == CommandResult.CONTRADICTION);
        require(preAttachAbortReleaseFailure.acknowledgeNoForeignPreAttachAbort(
                TOKEN, 1, 8020, 1, PROOF) == CommandResult.IDEMPOTENT);
        require(releaseFailure.equals(preAttachAbortReleaseFailure.failure())
                && preAttachAbortReleaseFailure.lastCommandSequence() == 1
                && preAttachAbortReleaseFailure.canReleaseNormally());
        preAttachAbortReleaseFailure.markReleased(false);
        require(preAttachAbortReleaseFailure.state() == NativePageHostLifecycle.State.RELEASED
                && preAttachAbortReleaseFailure.displayRemoved());

        // Stale envelopes are inert even when their untrusted payload is invalid.
        NativePageHostLifecycle unauthenticatedPreAttachAbort = waiting(8030);
        require(unauthenticatedPreAttachAbort.acknowledgeNoForeignPreAttachAbort(
                WRONG_TOKEN, 1, 8030, 1, null) == CommandResult.UNAUTHENTICATED_OR_STALE);
        require(unauthenticatedPreAttachAbort.acknowledgeNoForeignPreAttachAbort(
                null, 1, 8030, 1, null) == CommandResult.UNAUTHENTICATED_OR_STALE);
        require(unauthenticatedPreAttachAbort.acknowledgeNoForeignPreAttachAbort(
                TOKEN, 2, 8030, 1, null) == CommandResult.UNAUTHENTICATED_OR_STALE);
        require(unauthenticatedPreAttachAbort.acknowledgeNoForeignPreAttachAbort(
                TOKEN, 1, 8031, 1, null) == CommandResult.UNAUTHENTICATED_OR_STALE);
        require(unauthenticatedPreAttachAbort.acknowledgeNoForeignPreAttachAbort(
                TOKEN, 1, 0, 1, null) == CommandResult.UNAUTHENTICATED_OR_STALE);
        require(unauthenticatedPreAttachAbort.acknowledgeNoForeignPreAttachAbort(
                TOKEN, 1, 8030, 0, null) == CommandResult.UNAUTHENTICATED_OR_STALE);
        require(unauthenticatedPreAttachAbort.acknowledgeNoForeignPreAttachAbort(
                TOKEN, 1, 8030, -1, null) == CommandResult.UNAUTHENTICATED_OR_STALE);
        unchanged(unauthenticatedPreAttachAbort,
                NativePageHostLifecycle.State.WAITING_FOR_FOREIGN_ATTACH, null, null);
        require(unauthenticatedPreAttachAbort.lastCommandSequence() == 0);

        String[] invalidAbsenceEvidence = {null, "", repeat('a', 63), repeat('a', 65),
                repeat('A', 64), repeat('g', 64), " " + PROOF, PROOF + "\n"};
        for (int index = 0; index < invalidAbsenceEvidence.length; index++) {
            int display = 8040 + index;
            NativePageHostLifecycle invalidPreAttachEvidence = waiting(display);
            require(invalidPreAttachEvidence.acknowledgeNoForeignPreAttachAbort(
                    TOKEN, 1, display, 1, invalidAbsenceEvidence[index])
                    == CommandResult.CONTRADICTION);
            require(invalidPreAttachEvidence.isFailed()
                    && !invalidPreAttachEvidence.canReleaseNormally()
                    && !invalidPreAttachEvidence.displayRemoved()
                    && invalidPreAttachEvidence.lastCommandSequence() == 0);
        }

        NativePageHostLifecycle preAttachAbortSequenceGap = waiting(8050);
        require(preAttachAbortSequenceGap.acknowledgeNoForeignPreAttachAbort(
                TOKEN, 1, 8050, 2, PROOF) == CommandResult.CONTRADICTION);
        require(preAttachAbortSequenceGap.isFailed()
                && !preAttachAbortSequenceGap.canReleaseNormally()
                && preAttachAbortSequenceGap.lastCommandSequence() == 0);
        NativePageHostLifecycle preAttachAbortEquivocation = waiting(8051);
        require(preAttachAbortEquivocation.acknowledgeNoForeignPreAttachAbort(
                TOKEN, 1, 8051, 1, PROOF) == CommandResult.ACCEPTED);
        require(preAttachAbortEquivocation.acknowledgeNoForeignAfterFailure(
                TOKEN, 1, 8051, 1, PROOF) == CommandResult.CONTRADICTION);
        require(preAttachAbortEquivocation.lastCommandSequence() == 1
                && preAttachAbortEquivocation.canReleaseNormally());
        NativePageHostLifecycle failedEmptyAbortEquivocation = waiting(8052);
        require(failedEmptyAbortEquivocation.onAttachTimeout(1));
        require(failedEmptyAbortEquivocation.acknowledgeNoForeignAfterFailure(
                TOKEN, 1, 8052, 1, PROOF) == CommandResult.ACCEPTED);
        require(failedEmptyAbortEquivocation.acknowledgeNoForeignPreAttachAbort(
                TOKEN, 1, 8052, 1, PROOF) == CommandResult.CONTRADICTION);
        require(failedEmptyAbortEquivocation.lastCommandSequence() == 1);

        // Accepted or deferred foreign identity must never become empty authority.
        for (int phase = 0; phase < 5; phase++) {
            int display = 8060 + phase;
            NativePageHostLifecycle attachedPreAttachAbort = active(display);
            if (phase == 1) require(attachedPreAttachAbort.authorizePlacement(
                    TOKEN, 1, display, 2, LEFT) == CommandResult.ACCEPTED);
            if (phase >= 2) require(attachedPreAttachAbort.beginClose(
                    TOKEN, 1, display, 2) == CommandResult.ACCEPTED);
            if (phase >= 3) require(attachedPreAttachAbort.acknowledgeForeignDestroyed(
                    TOKEN, 1, display, 3, task()) == CommandResult.ACCEPTED);
            if (phase == 4) attachedPreAttachAbort.markReleased(false);
            boolean releaseWasAuthorized = attachedPreAttachAbort.canReleaseNormally();
            long sequence = attachedPreAttachAbort.lastCommandSequence();
            require(attachedPreAttachAbort.acknowledgeNoForeignPreAttachAbort(
                    TOKEN, 1, display, sequence + 1, PROOF) == CommandResult.CONTRADICTION);
            require(attachedPreAttachAbort.foreignTask().exactlyEquals(task())
                    && attachedPreAttachAbort.lastCommandSequence() == sequence
                    && attachedPreAttachAbort.canReleaseNormally() == releaseWasAuthorized);
        }
        NativePageHostLifecycle deferredPreAttachAbort = waiting(8070);
        require(deferredPreAttachAbort.suspendHostAuthority(80_700L));
        require(deferredPreAttachAbort.reserveDeferredCommand(TOKEN, 1, 8070, 1,
                NativePageHostLifecycle.DEFER_ATTACH, task()));
        require(deferredPreAttachAbort.acknowledgeNoForeignPreAttachAbort(
                TOKEN, 1, 8070, 1, PROOF) == CommandResult.CONTRADICTION);
        require(deferredPreAttachAbort.isFailed() && !deferredPreAttachAbort.canReleaseNormally()
                && deferredPreAttachAbort.foreignTask() == null
                && deferredPreAttachAbort.lastCommandSequence() == 0);
        NativePageHostLifecycle preAttachAbortNotDeferrable = waiting(8071);
        require(preAttachAbortNotDeferrable.suspendHostAuthority(80_710L));
        require(!preAttachAbortNotDeferrable.reserveDeferredCommand(
                TOKEN, 1, 8071, 1, 7, null));
        require(!preAttachAbortNotDeferrable.hasDeferredCommand());

        for (int phase = 0; phase < 3; phase++) {
            int display = 8080 + phase;
            NativePageHostLifecycle failedPreAttachAbort = waiting(display);
            if (phase == 0) require(failedPreAttachAbort.onAttachTimeout(1));
            if (phase == 1) failedPreAttachAbort.onProtocolFailure("injected");
            if (phase == 2) failedPreAttachAbort.onUnexpectedHostLoss("injected");
            String priorFailure = failedPreAttachAbort.failure();
            require(failedPreAttachAbort.acknowledgeNoForeignPreAttachAbort(
                    TOKEN, 1, display, 1, PROOF) == CommandResult.CONTRADICTION);
            require(priorFailure.equals(failedPreAttachAbort.failure())
                    && !failedPreAttachAbort.canReleaseNormally()
                    && failedPreAttachAbort.lastCommandSequence() == 0);
            require(failedPreAttachAbort.acknowledgeNoForeignAfterFailure(
                    TOKEN, 1, display, 1, PROOF) == CommandResult.ACCEPTED);
            failedPreAttachAbort.markReleased(false);
        }
        NativePageHostLifecycle unallocatedPreAttachAbort =
                new NativePageHostLifecycle(false, TOKEN);
        require(unallocatedPreAttachAbort.acknowledgeNoForeignPreAttachAbort(
                TOKEN, 0, -1, 1, PROOF) == CommandResult.UNAUTHENTICATED_OR_STALE);
        require(!unallocatedPreAttachAbort.isFailed());
        require(unallocatedPreAttachAbort.admitHostAuthority(0, 320, true, true, true));
        require(unallocatedPreAttachAbort.onPhysicalFrameMeasured(
                1404, 1872, 0, 0, 1404, 1872, 0) == FrameResult.READY);
        require(unallocatedPreAttachAbort.beginDisplayCreation() == 1);
        require(unallocatedPreAttachAbort.acknowledgeNoForeignPreAttachAbort(
                TOKEN, 1, -1, 1, PROOF) == CommandResult.UNAUTHENTICATED_OR_STALE);
        require(unallocatedPreAttachAbort.state() == NativePageHostLifecycle.State.CREATING_DISPLAY
                && !unallocatedPreAttachAbort.isFailed()
                && !unallocatedPreAttachAbort.canReleaseNormally());
    }

    public static void main(String[] args) {
        require(DisplayProbeLayout.BUFFER_WIDTH == 1404);
        require(DisplayProbeLayout.BUFFER_HEIGHT == 1872);
        DisplayProbeLayout portrait = DisplayProbeLayout.fit(1404, 1872, RIGHT);
        require(portrait.effectivePlacement == FULL && portrait.left == 0 && portrait.top == 0
                && portrait.width == 1404 && portrait.height == 1872);
        DisplayProbeLayout left = DisplayProbeLayout.fit(1872, 1404, LEFT);
        require(left.left == 0 && left.top == 78 && left.width == 936 && left.height == 1248);
        DisplayProbeLayout right = DisplayProbeLayout.fit(1872, 1404, RIGHT);
        require(right.left == 936 && right.top == 78 && right.width == 936 && right.height == 1248);
        DisplayProbeLayout full = DisplayProbeLayout.fit(1872, 1404, FULL);
        require(full.left == 409 && full.top == 0 && full.width == 1053 && full.height == 1404);
        require(full.exactlyMatches(409, 0, 1053, 1404));
        require(!full.exactlyMatches(408, 0, 1053, 1404));

        rejects(() -> new NativePageHostLifecycle(false, null));
        rejects(() -> new NativePageHostLifecycle(false, TOKEN.toUpperCase()));
        rejects(() -> ForeignTaskIdentity.checked("other", COMPONENT, 1, 1, 1000, "1", PROOF));
        rejects(() -> ForeignTaskIdentity.checked("com.supernote.document",
                "com.supernote.document/.DocumentActivity", 1, 1, 1000, "1", PROOF));
        rejects(() -> ForeignTaskIdentity.checked("com.supernote.document",
                "com.supernote.document/com.supernote.document.document.OtherActivity",
                1, 1, 1000, "1", PROOF));
        rejects(() -> taskWith(0, 1, "1", PROOF));
        rejects(() -> taskWith(1, 0, "1", PROOF));
        rejects(() -> taskWith(1, 1, "01", PROOF));
        rejects(() -> ForeignTaskIdentity.checked("com.supernote.document", COMPONENT,
                1, 1, 1001, "1", PROOF));
        rejects(() -> taskWith(1, 1, "1", "A" + PROOF.substring(1)));

        NativePageHostLifecycle restored = new NativePageHostLifecycle(true, TOKEN);
        require(restored.isFailed() && restored.canFinishWithoutCleanup());
        require(!restored.revalidatePreAllocationHostAuthority(0, 320, true, true, true));
        require(restored.beginDisplayCreation() == -1);

        // Match the real Activity startup order, including repeated layouts before
        // allocation. STARTABLE revalidates physical host+frame authority without
        // pretending a positive VirtualDisplay already exists.
        NativePageHostLifecycle freshStartup = new NativePageHostLifecycle(false, TOKEN);
        require(freshStartup.admitHostAuthority(0, 320, true, true, true));
        require(freshStartup.onPhysicalFrameMeasured(
                1404, 1872, 0, 0, 1404, 1872, 0) == FrameResult.READY);
        require(freshStartup.revalidatePreAllocationHostAuthority(
                0, 320, true, true, true));
        require(freshStartup.revalidatePreAllocationHostAuthority(
                0, 320, true, true, true));
        require(freshStartup.state() == NativePageHostLifecycle.State.STARTABLE
                && freshStartup.displayRemoved() && freshStartup.displayId() == -1
                && freshStartup.generation() == 0);
        require(freshStartup.beginDisplayCreation() == 1);
        require(freshStartup.onDisplayAllocated(1, 7001));
        require(freshStartup.onDisplayCreated(1, 7001, 1404, 1872, 320));

        NativePageHostLifecycle preallocationNoFrame =
                new NativePageHostLifecycle(false, TOKEN);
        require(preallocationNoFrame.admitHostAuthority(0, 320, true, true, true));
        require(!preallocationNoFrame.revalidatePreAllocationHostAuthority(
                0, 320, true, true, true));
        require(preallocationNoFrame.isFailed() && preallocationNoFrame.beginDisplayCreation() == -1);
        int[][] invalidPreallocationAuthority = new int[][] {
            {1, 320, 1, 1, 1}, {0, 321, 1, 1, 1}, {0, 320, 0, 1, 1},
            {0, 320, 1, 0, 1}, {0, 320, 1, 1, 0}
        };
        for (int[] invalid : invalidPreallocationAuthority) {
            NativePageHostLifecycle candidate = new NativePageHostLifecycle(false, TOKEN);
            require(candidate.admitHostAuthority(0, 320, true, true, true));
            require(candidate.onPhysicalFrameMeasured(
                    1404, 1872, 0, 0, 1404, 1872, 0) == FrameResult.READY);
            require(!candidate.revalidatePreAllocationHostAuthority(invalid[0], invalid[1],
                    invalid[2] != 0, invalid[3] != 0, invalid[4] != 0));
            require(candidate.isFailed() && candidate.displayRemoved()
                    && candidate.beginDisplayCreation() == -1);
        }
        NativePageHostLifecycle preallocationWrongState = waiting(7002);
        require(!preallocationWrongState.revalidatePreAllocationHostAuthority(
                0, 320, true, true, true));
        require(preallocationWrongState.isFailed()
                && preallocationWrongState.retainsPhysicalHostAuthority());

        NativePageHostLifecycle normal = active(7);
        require(normal.admittedDensityDpi() == 320 && normal.isActive());
        require(normal.acknowledgeForeignAttached(TOKEN, 1, 7, 1, task())
                == CommandResult.IDEMPOTENT);
        require(normal.state() == NativePageHostLifecycle.State.ACTIVE
                && normal.canPublishFreshAttachReady() && normal.lastCommandSequence() == 1);
        require(normal.authorizePlacement(TOKEN, 1, 7, 2, FULL) == CommandResult.ACCEPTED);
        require(normal.placement() == FULL && normal.isPlacementPending());
        require(normal.onPhysicalFrameMeasured(1404, 1872, 0, 0, 1404, 1872, 2)
                == FrameResult.READY);
        require(normal.authorizePlacement(TOKEN, 1, 7, 2, FULL) == CommandResult.IDEMPOTENT);
        require(normal.authorizePlacement(TOKEN, 1, 7, 3, LEFT) == CommandResult.ACCEPTED);
        require(normal.placement() == FULL && normal.frameRequestPlacement() == LEFT);
        require(normal.onPhysicalFrameMeasured(1872, 1404, 409, 0, 1053, 1404, 3)
                == FrameResult.TRANSITIONAL);
        require(normal.onPhysicalFrameMeasured(1872, 1404, 0, 78, 936, 1248, 3)
                == FrameResult.READY);
        require(normal.authorizePlacement(TOKEN, 1, 7, 3, LEFT) == CommandResult.IDEMPOTENT);
        require(normal.authorizePlacement(TOKEN, 1, 7, 4, RIGHT) == CommandResult.ACCEPTED);
        require(normal.onPhysicalFrameMeasured(1872, 1404, 936, 78, 936, 1248, 4)
                == FrameResult.READY);
        require(normal.authorizePlacement(TOKEN, 1, 7, 3, LEFT) == CommandResult.IDEMPOTENT);
        require(normal.placement() == RIGHT && normal.lastCommandSequence() == 4);
        require(normal.onHostAuthority(0, 320, true, true, true) && normal.isActive());
        require(normal.onVirtualDisplayMetrics(1404, 1872, 320));
        require(normal.beginClose(TOKEN, 1, 7, 5) == CommandResult.ACCEPTED);
        require(normal.canPublishFreshCloseWait());
        require(normal.beginClose(TOKEN, 1, 7, 5) == CommandResult.IDEMPOTENT);
        require(normal.canPublishFreshCloseWait()
                && normal.state() == NativePageHostLifecycle.State.WAITING_FOR_FOREIGN_DESTROY
                && normal.lastCommandSequence() == 5);
        require(normal.acknowledgeForeignDestroyed(TOKEN, 1, 7, 6, task())
                == CommandResult.ACCEPTED);
        require(normal.acknowledgeForeignDestroyed(TOKEN, 1, 7, 6, task())
                == CommandResult.IDEMPOTENT);
        require(normal.canReleaseNormally() && !normal.canFinishWithoutCleanup());
        normal.markReleased(false);
        require(normal.state() == NativePageHostLifecycle.State.RELEASED);
        require(!normal.canFinishWithoutCleanup()); // task identity remains cleanup evidence

        // Unauthenticated/stale traffic never mutates or poisons the session.
        Object[][] envelopes = new Object[][] {
            {null, 1L, 11}, {"", 1L, 11}, {WRONG_TOKEN, 1L, 11},
            {TOKEN + "x", 1L, 11}, {TOKEN, 0L, 11}, {TOKEN, 2L, 11},
            {TOKEN, 1L, -1}, {TOKEN, 1L, 12}
        };
        for (Object[] envelope : envelopes) {
            NativePageHostLifecycle value = waiting(11);
            NativePageHostLifecycle.State before = value.state();
            String failure = value.failure();
            ForeignTaskIdentity identity = value.foreignTask();
            String token = (String) envelope[0];
            long generation = (Long) envelope[1];
            int display = (Integer) envelope[2];
            require(!value.commandEnvelopeMatches(token, generation, display, 1));
            require(value.acknowledgeForeignAttached(token, generation, display, 1, task())
                    == CommandResult.UNAUTHENTICATED_OR_STALE);
            require(value.authorizePlacement(token, generation, display, 1, LEFT)
                    == CommandResult.UNAUTHENTICATED_OR_STALE);
            require(value.beginClose(token, generation, display, 1)
                    == CommandResult.UNAUTHENTICATED_OR_STALE);
            require(value.acknowledgeForeignDestroyed(token, generation, display, 1, task())
                    == CommandResult.UNAUTHENTICATED_OR_STALE);
            unchanged(value, before, failure, identity);
        }

        // Authenticated contradictions are sticky.
        NativePageHostLifecycle prematurePlacement = waiting(13);
        require(prematurePlacement.authorizePlacement(TOKEN, 1, 13, 1, LEFT)
                == CommandResult.CONTRADICTION);
        require(prematurePlacement.isFailed());
        String firstFailure = prematurePlacement.failure();
        require(prematurePlacement.beginClose(TOKEN, 1, 13, 1) == CommandResult.CONTRADICTION);
        require(prematurePlacement.failure().equals(firstFailure));

        NativePageHostLifecycle badIdentity = active(14);
        require(badIdentity.acknowledgeForeignAttached(TOKEN, 1, 14, 2,
                taskWith(42, 9123, "6336417", PROOF)) == CommandResult.CONTRADICTION);
        require(badIdentity.isFailed());

        NativePageHostLifecycle wrongDestroy = active(15);
        require(wrongDestroy.beginClose(TOKEN, 1, 15, 2) == CommandResult.ACCEPTED);
        require(wrongDestroy.acknowledgeForeignDestroyed(TOKEN, 1, 15, 3,
                taskWith(41, 9124, "6336417", PROOF)) == CommandResult.CONTRADICTION);
        require(wrongDestroy.isFailed() && !wrongDestroy.canReleaseNormally());
        require(wrongDestroy.acknowledgeForeignDestroyed(TOKEN, 1, 15, 3, task())
                == CommandResult.ACCEPTED);
        require(wrongDestroy.isFailed() && wrongDestroy.canReleaseNormally());
        wrongDestroy.markReleased(false);

        NativePageHostLifecycle unexpectedDeath = active(16);
        require(unexpectedDeath.acknowledgeForeignDestroyed(TOKEN, 1, 16, 2, task())
                == CommandResult.CONTRADICTION);
        require(unexpectedDeath.isFailed() && !unexpectedDeath.canReleaseNormally());
        require(unexpectedDeath.acknowledgeForeignDestroyed(TOKEN, 1, 16, 2, task())
                == CommandResult.CONTRADICTION);

        NativePageHostLifecycle attachTimeout = waiting(17);
        require(!attachTimeout.onAttachTimeout(2) && attachTimeout.isWaitingForAttach());
        require(attachTimeout.onAttachTimeout(1) && attachTimeout.isFailed());
        require(attachTimeout.acknowledgeForeignAttached(TOKEN, 1, 17, 1, task())
                == CommandResult.CONTRADICTION);

        NativePageHostLifecycle destroyTimeout = active(18);
        require(destroyTimeout.beginClose(TOKEN, 1, 18, 2) == CommandResult.ACCEPTED);
        require(!destroyTimeout.onDestroyTimeout(2));
        require(destroyTimeout.onDestroyTimeout(1) && destroyTimeout.isFailed());
        require(destroyTimeout.acknowledgeForeignDestroyed(TOKEN, 1, 18, 3, task())
                == CommandResult.ACCEPTED);
        require(destroyTimeout.failure().contains("timed out"));

        NativePageHostLifecycle density = active(19);
        require(density.onHostAuthority(0, 320, true, true, true));
        require(!density.onHostAuthority(0, 321, true, true, true));
        require(density.isFailed() && density.mustReleaseForHostLoss());
        require(!density.canFinishWithoutCleanup());
        density.markReleased(true);
        require(density.state() == NativePageHostLifecycle.State.FAILED);
        require(!density.canFinishWithoutCleanup());
        require(density.acknowledgeForeignDestroyed(TOKEN, 1, 19, 2, task())
                == CommandResult.ACCEPTED);
        require(density.canReleaseNormally());
        density.markReleased(false);
        require(density.state() == NativePageHostLifecycle.State.RELEASED);

        NativePageHostLifecycle cleanupAfterCloseLoss = active(191);
        require(cleanupAfterCloseLoss.beginClose(TOKEN, 1, 191, 2) == CommandResult.ACCEPTED);
        cleanupAfterCloseLoss.onUnexpectedHostLoss("display lost");
        cleanupAfterCloseLoss.markReleased(true);
        require(cleanupAfterCloseLoss.acknowledgeForeignDestroyed(TOKEN, 1, 191, 3, task())
                == CommandResult.ACCEPTED);
        cleanupAfterCloseLoss.markReleased(false);
        require(cleanupAfterCloseLoss.state() == NativePageHostLifecycle.State.RELEASED);

        NativePageHostLifecycle invalidDensity = active(20);
        require(!invalidDensity.onHostAuthority(0, 0, true, true, true));
        require(invalidDensity.failure().contains("authority"));

        NativePageHostLifecycle beforeAttachLoss = waiting(21);
        beforeAttachLoss.onUnexpectedHostLoss("surface lost");
        beforeAttachLoss.markReleased(true);
        require(beforeAttachLoss.state() == NativePageHostLifecycle.State.RELEASED);
        require(beforeAttachLoss.canFinishWithoutCleanup());

        NativePageHostLifecycle withTaskLoss = active(22);
        withTaskLoss.onUnexpectedHostLoss("host destroyed");
        withTaskLoss.markReleased(true);
        require(withTaskLoss.state() == NativePageHostLifecycle.State.FAILED);
        require(!withTaskLoss.canFinishWithoutCleanup());

        NativePageHostLifecycle noAuthority = active(23);
        try { noAuthority.markReleased(false); throw new AssertionError("release"); }
        catch (IllegalStateException expected) { checks++; }
        require(noAuthority.isFailed());

        // The exact destroy ACK cannot create release authority before close begins,
        // including through an identical replay after the sticky contradiction.
        NativePageHostLifecycle prematureDestroy = active(24);
        require(prematureDestroy.acknowledgeForeignDestroyed(TOKEN, 1, 24, 2, task())
                == CommandResult.CONTRADICTION);
        require(!prematureDestroy.canReleaseNormally());
        require(prematureDestroy.acknowledgeForeignDestroyed(TOKEN, 1, 24, 2, task())
                == CommandResult.CONTRADICTION);
        require(!prematureDestroy.canReleaseNormally());

        NativePageHostLifecycle sequenceGap = active(25);
        require(sequenceGap.authorizePlacement(TOKEN, 1, 25, 3, LEFT)
                == CommandResult.CONTRADICTION);
        require(sequenceGap.isFailed() && sequenceGap.placement() == FULL);

        NativePageHostLifecycle sequenceEquivocation = active(26);
        require(sequenceEquivocation.authorizePlacement(TOKEN, 1, 26, 2, LEFT)
                == CommandResult.ACCEPTED);
        require(sequenceEquivocation.authorizePlacement(TOKEN, 1, 26, 2, RIGHT)
                == CommandResult.CONTRADICTION);
        require(sequenceEquivocation.placement() == FULL);

        NativePageHostLifecycle delayedPlacement = active(27);
        require(delayedPlacement.authorizePlacement(TOKEN, 1, 27, 2, LEFT)
                == CommandResult.ACCEPTED);
        require(delayedPlacement.authorizePlacement(TOKEN, 1, 27, 2, LEFT)
                == CommandResult.IDEMPOTENT);
        require(delayedPlacement.onPhysicalFrameMeasured(
                1872, 1404, 0, 78, 936, 1248, 2) == FrameResult.READY);
        require(delayedPlacement.authorizePlacement(TOKEN, 1, 27, 3, RIGHT)
                == CommandResult.ACCEPTED);
        require(delayedPlacement.onPhysicalFrameMeasured(
                1872, 1404, 936, 78, 936, 1248, 3) == FrameResult.READY);
        require(delayedPlacement.placement() == RIGHT
                && delayedPlacement.lastCommandSequence() == 3);

        NativePageHostLifecycle safeEmptyAbort = waiting(28);
        require(safeEmptyAbort.onAttachTimeout(1));
        require(safeEmptyAbort.acknowledgeNoForeignAfterFailure(
                TOKEN, 1, 28, 1, PROOF) == CommandResult.ACCEPTED);
        require(safeEmptyAbort.canReleaseNormally());
        require(safeEmptyAbort.acknowledgeNoForeignAfterFailure(
                TOKEN, 1, 28, 1, PROOF) == CommandResult.IDEMPOTENT);
        safeEmptyAbort.markReleased(false);
        require(safeEmptyAbort.state() == NativePageHostLifecycle.State.RELEASED
                && safeEmptyAbort.canFinishWithoutCleanup());

        NativePageHostLifecycle prematureAbort = waiting(29);
        require(prematureAbort.acknowledgeNoForeignAfterFailure(
                TOKEN, 1, 29, 1, PROOF) == CommandResult.CONTRADICTION);
        require(!prematureAbort.canReleaseNormally());

        NativePageHostLifecycle invalidAbortProof = waiting(30);
        require(invalidAbortProof.onAttachTimeout(1));
        require(invalidAbortProof.acknowledgeNoForeignAfterFailure(
                TOKEN, 1, 30, 1, "bad") == CommandResult.CONTRADICTION);
        require(!invalidAbortProof.canReleaseNormally());

        NativePageHostLifecycle changedDisplay = active(31);
        require(!changedDisplay.onVirtualDisplayMetrics(1403, 1872, 320));
        require(changedDisplay.isFailed() && changedDisplay.mustReleaseForHostLoss());

        // A pre-attach protocol contradiction can be released only after exact absence proof.
        NativePageHostLifecycle failedEmpty = waiting(311);
        require(failedEmpty.authorizePlacement(TOKEN, 1, 311, 1, LEFT)
                == CommandResult.CONTRADICTION);
        require(failedEmpty.onPhysicalFrameMeasured(
                1404, 1872, 0, 0, 1404, 1872, 0) == FrameResult.READY);
        require(failedEmpty.acknowledgeNoForeignAfterFailure(
                TOKEN, 1, 311, 1, PROOF) == CommandResult.ACCEPTED);
        failedEmpty.markReleased(false);
        require(failedEmpty.state() == NativePageHostLifecycle.State.RELEASED
                && failedEmpty.canFinishWithoutCleanup());

        // A post-attach contradiction can enter an exact close/destroy cleanup handshake.
        NativePageHostLifecycle failedWithTask = active(312);
        require(failedWithTask.authorizePlacement(TOKEN, 1, 312, 3, LEFT)
                == CommandResult.CONTRADICTION);
        String sticky = failedWithTask.failure();
        require(failedWithTask.beginClose(TOKEN, 1, 312, 2) == CommandResult.ACCEPTED);
        require(failedWithTask.isWaitingForDestroy() && sticky.equals(failedWithTask.failure()));
        require(failedWithTask.acknowledgeForeignDestroyed(TOKEN, 1, 312, 3, task())
                == CommandResult.ACCEPTED);
        failedWithTask.markReleased(false);
        require(failedWithTask.state() == NativePageHostLifecycle.State.RELEASED);

        // Placement is sequence-bound and cannot commit from wrong or escaped bounds.
        NativePageHostLifecycle placementTimeout = active(313);
        require(placementTimeout.authorizePlacement(TOKEN, 1, 313, 2, LEFT)
                == CommandResult.ACCEPTED);
        require(!placementTimeout.onPlacementTimeout(2, 2));
        require(!placementTimeout.onPlacementTimeout(1, 3));
        require(placementTimeout.onPlacementTimeout(1, 2));
        require(placementTimeout.isFailed() && placementTimeout.mustReleaseForHostLoss());

        NativePageHostLifecycle escapedFrame = active(314);
        require(escapedFrame.authorizePlacement(TOKEN, 1, 314, 2, LEFT)
                == CommandResult.ACCEPTED);
        require(escapedFrame.onPhysicalFrameMeasured(
                1872, 1404, 1, 78, 936, 1248, 2) == FrameResult.REJECTED);
        require(escapedFrame.isFailed() && escapedFrame.mustReleaseForHostLoss());

        // Physical host identity and visibility/focus are exact continuous authority.
        boolean[][] hostMutations = new boolean[][] {
            {false, true, true}, {true, false, true}, {true, true, false}
        };
        for (int index = 0; index < hostMutations.length; index++) {
            NativePageHostLifecycle changedHost = active(315 + index);
            boolean[] flags = hostMutations[index];
            require(!changedHost.onHostAuthority(0, 320, flags[0], flags[1], flags[2]));
            require(changedHost.isFailed() && changedHost.mustReleaseForHostLoss());
        }
        NativePageHostLifecycle wrongPhysicalDisplay = active(318);
        require(!wrongPhysicalDisplay.onHostAuthority(1, 320, true, true, true));
        require(wrongPhysicalDisplay.isFailed());

        // A bounded pause removes live host authority without treating Android's
        // singleTask transition as permanent loss. Exactly one next typed command
        // may be reserved, but it cannot mutate lifecycle state until exact physical
        // authority is reacquired and the reservation is consumed.
        NativePageHostLifecycle deferredAttach = waiting(3181);
        require(deferredAttach.suspendHostAuthority(10_000L));
        require(deferredAttach.hostAuthoritySuspended()
                && deferredAttach.canDeferFreshCommand(1)
                && !deferredAttach.canDeferFreshCommand(2)
                && !deferredAttach.isActive());
        require(deferredAttach.reserveDeferredCommand(TOKEN, 1, 3181, 1,
                NativePageHostLifecycle.DEFER_ATTACH, task())
                && deferredAttach.hasDeferredCommand());
        require(deferredAttach.beginDisplayCreation() == -1); // state cannot restart creation
        require(deferredAttach.onHostAuthority(0, 320, true, true, true));
        require(!deferredAttach.hostAuthoritySuspended()
                && deferredAttach.hostAuthorityDeadlineElapsed() == 10_000L);
        require(deferredAttach.suspendHostAuthority(99_000L));
        require(deferredAttach.hostAuthorityDeadlineElapsed() == 10_000L);
        require(deferredAttach.onHostAuthority(0, 320, true, true, true));
        require(deferredAttach.consumeDeferredCommand(TOKEN, 1, 3181, 1,
                NativePageHostLifecycle.DEFER_ATTACH, task()));
        require(deferredAttach.acknowledgeForeignAttached(
                TOKEN, 1, 3181, 1, task()) == CommandResult.ACCEPTED);
        require(deferredAttach.isActive() && !deferredAttach.hasDeferredCommand()
                && !deferredAttach.completeHostAuthorityTransition(9_999L));
        require(deferredAttach.completeHostAuthorityTransition(10_000L)
                && !deferredAttach.hasHostAuthorityTransition());

        NativePageHostLifecycle deferredPlace = active(3182);
        require(deferredPlace.suspendHostAuthority(10_000L));
        require(deferredPlace.reserveDeferredCommand(TOKEN, 1, 3182, 2,
                NativePageHostLifecycle.DEFER_PLACE_LEFT, null));
        require(deferredPlace.state() == NativePageHostLifecycle.State.ACTIVE
                && deferredPlace.placement() == FULL && !deferredPlace.isActive());
        require(deferredPlace.onHostAuthority(0, 320, true, true, true));
        require(deferredPlace.suspendHostAuthority(99_000L)
                && deferredPlace.hostAuthorityDeadlineElapsed() == 10_000L);
        require(deferredPlace.onHostAuthority(0, 320, true, true, true));
        require(deferredPlace.consumeDeferredCommand(TOKEN, 1, 3182, 2,
                NativePageHostLifecycle.DEFER_PLACE_LEFT, null));
        require(deferredPlace.authorizePlacement(TOKEN, 1, 3182, 2, LEFT)
                == CommandResult.ACCEPTED);
        require(deferredPlace.onPhysicalFrameMeasured(
                1872, 1404, 0, 78, 936, 1248, 2) == FrameResult.READY);
        require(deferredPlace.completeHostAuthorityTransition(10_000L));

        int[] deferredPlacementKinds = new int[] {
            NativePageHostLifecycle.DEFER_PLACE_FULL,
            NativePageHostLifecycle.DEFER_PLACE_LEFT,
            NativePageHostLifecycle.DEFER_PLACE_RIGHT
        };
        DisplayProbeLayout.Placement[] deferredPlacements =
                new DisplayProbeLayout.Placement[] { FULL, LEFT, RIGHT };
        int[][] deferredPlacementFrames = new int[][] {
            {409, 0, 1053, 1404}, {0, 78, 936, 1248}, {936, 78, 936, 1248}
        };
        for (int index = 0; index < deferredPlacementKinds.length; index++) {
            NativePageHostLifecycle deferredPlacementVariant = active(31820 + index);
            require(deferredPlacementVariant.suspendHostAuthority(25_000L));
            require(deferredPlacementVariant.reserveDeferredCommand(
                    TOKEN, 1, 31820 + index, 2, deferredPlacementKinds[index], null));
            require(deferredPlacementVariant.onHostAuthority(0, 320, true, true, true));
            require(deferredPlacementVariant.suspendHostAuthority(75_000L)
                    && deferredPlacementVariant.hostAuthorityDeadlineElapsed() == 25_000L);
            require(deferredPlacementVariant.onHostAuthority(0, 320, true, true, true));
            require(deferredPlacementVariant.consumeDeferredCommand(
                    TOKEN, 1, 31820 + index, 2, deferredPlacementKinds[index], null));
            require(deferredPlacementVariant.authorizePlacement(TOKEN, 1, 31820 + index, 2,
                    deferredPlacements[index]) == CommandResult.ACCEPTED);
            int[] target = deferredPlacementFrames[index];
            require(deferredPlacementVariant.onPhysicalFrameMeasured(1872, 1404,
                    target[0], target[1], target[2], target[3], 2) == FrameResult.READY);
            require(deferredPlacementVariant.completeHostAuthorityTransition(25_000L));
        }

        NativePageHostLifecycle deferredClose = active(3183);
        require(deferredClose.suspendHostAuthority(10_000L));
        require(deferredClose.reserveDeferredCommand(TOKEN, 1, 3183, 2,
                NativePageHostLifecycle.DEFER_BEGIN_CLOSE, null));
        require(deferredClose.onHostAuthority(0, 320, true, true, true));
        require(deferredClose.suspendHostAuthority(99_000L)
                && deferredClose.hostAuthorityDeadlineElapsed() == 10_000L);
        require(deferredClose.onHostAuthority(0, 320, true, true, true));
        require(deferredClose.consumeDeferredCommand(TOKEN, 1, 3183, 2,
                NativePageHostLifecycle.DEFER_BEGIN_CLOSE, null));
        require(deferredClose.beginClose(TOKEN, 1, 3183, 2) == CommandResult.ACCEPTED
                && deferredClose.canPublishFreshCloseWait());
        require(deferredClose.completeHostAuthorityTransition(10_000L));

        NativePageHostLifecycle deferredDestroy = active(3184);
        require(deferredDestroy.beginClose(TOKEN, 1, 3184, 2) == CommandResult.ACCEPTED);
        require(deferredDestroy.suspendHostAuthority(10_000L));
        require(deferredDestroy.reserveDeferredCommand(TOKEN, 1, 3184, 3,
                NativePageHostLifecycle.DEFER_ACK_DESTROYED, task()));
        require(deferredDestroy.onHostAuthority(0, 320, true, true, true));
        require(deferredDestroy.suspendHostAuthority(99_000L)
                && deferredDestroy.hostAuthorityDeadlineElapsed() == 10_000L);
        require(deferredDestroy.onHostAuthority(0, 320, true, true, true));
        require(deferredDestroy.consumeDeferredCommand(TOKEN, 1, 3184, 3,
                NativePageHostLifecycle.DEFER_ACK_DESTROYED, task()));
        require(deferredDestroy.acknowledgeForeignDestroyed(
                TOKEN, 1, 3184, 3, task()) == CommandResult.ACCEPTED
                && deferredDestroy.canReleaseNormally());
        require(deferredDestroy.completeHostAuthorityTransition(10_000L));

        NativePageHostLifecycle persistentPause = waiting(3185);
        require(persistentPause.suspendHostAuthority(10_000L));
        require(!persistentPause.onHostAuthority(0, 320, false, true, true));
        require(persistentPause.isFailed() && persistentPause.mustReleaseForHostLoss());

        NativePageHostLifecycle duplicatePause = waiting(3186);
        require(duplicatePause.suspendHostAuthority(10_000L));
        require(!duplicatePause.suspendHostAuthority(11_000L));
        require(duplicatePause.hostAuthoritySuspended() && !duplicatePause.isFailed()
                && duplicatePause.hostAuthorityDeadlineElapsed() == 10_000L);

        // Persistent configuration/layout churn cannot renew the initial deadline.
        NativePageHostLifecycle persistentGeometryChurn = active(31861);
        require(persistentGeometryChurn.suspendHostAuthority(20_000L));
        for (int churn = 0; churn < 8; churn++) {
            require(persistentGeometryChurn.onHostAuthority(0, 320, true, true, true));
            require(persistentGeometryChurn.hostAuthorityDeadlineElapsed() == 20_000L);
            require(persistentGeometryChurn.suspendHostAuthority(30_000L + churn));
            require(persistentGeometryChurn.hostAuthorityDeadlineElapsed() == 20_000L);
        }
        require(persistentGeometryChurn.onHostAuthority(0, 320, true, true, true));
        require(persistentGeometryChurn.completeHostAuthorityTransition(20_000L));

        NativePageHostLifecycle duplicateDeferred = waiting(3187);
        require(duplicateDeferred.suspendHostAuthority(10_000L));
        require(duplicateDeferred.reserveDeferredCommand(TOKEN, 1, 3187, 1,
                NativePageHostLifecycle.DEFER_ATTACH, task()));
        require(!duplicateDeferred.reserveDeferredCommand(TOKEN, 1, 3187, 1,
                NativePageHostLifecycle.DEFER_ATTACH, task()));
        require(duplicateDeferred.isFailed() && !duplicateDeferred.hasDeferredCommand());

        NativePageHostLifecycle equivocatedDeferred = waiting(3188);
        require(equivocatedDeferred.suspendHostAuthority(10_000L));
        require(equivocatedDeferred.reserveDeferredCommand(TOKEN, 1, 3188, 1,
                NativePageHostLifecycle.DEFER_ATTACH, task()));
        require(!equivocatedDeferred.reserveDeferredCommand(TOKEN, 1, 3188, 1,
                NativePageHostLifecycle.DEFER_ATTACH,
                taskWith(42, 9124, "6336418", repeat('b', 64))));
        require(equivocatedDeferred.isFailed());

        NativePageHostLifecycle directDeferredBypass = waiting(3189);
        require(directDeferredBypass.suspendHostAuthority(10_000L));
        require(directDeferredBypass.reserveDeferredCommand(TOKEN, 1, 3189, 1,
                NativePageHostLifecycle.DEFER_ATTACH, task()));
        require(directDeferredBypass.onHostAuthority(0, 320, true, true, true));
        require(directDeferredBypass.acknowledgeForeignAttached(
                TOKEN, 1, 3189, 1, task()) == CommandResult.CONTRADICTION);
        require(directDeferredBypass.isFailed());

        NativePageHostLifecycle directDeferredPlaceBypass = active(31891);
        require(directDeferredPlaceBypass.suspendHostAuthority(10_000L));
        require(directDeferredPlaceBypass.reserveDeferredCommand(TOKEN, 1, 31891, 2,
                NativePageHostLifecycle.DEFER_PLACE_RIGHT, null));
        require(directDeferredPlaceBypass.onHostAuthority(0, 320, true, true, true));
        require(directDeferredPlaceBypass.authorizePlacement(TOKEN, 1, 31891, 2, RIGHT)
                == CommandResult.CONTRADICTION);

        NativePageHostLifecycle directDeferredCloseBypass = active(31892);
        require(directDeferredCloseBypass.suspendHostAuthority(10_000L));
        require(directDeferredCloseBypass.reserveDeferredCommand(TOKEN, 1, 31892, 2,
                NativePageHostLifecycle.DEFER_BEGIN_CLOSE, null));
        require(directDeferredCloseBypass.onHostAuthority(0, 320, true, true, true));
        require(directDeferredCloseBypass.beginClose(TOKEN, 1, 31892, 2)
                == CommandResult.CONTRADICTION);

        NativePageHostLifecycle directDeferredDestroyBypass = active(31893);
        require(directDeferredDestroyBypass.beginClose(TOKEN, 1, 31893, 2)
                == CommandResult.ACCEPTED);
        require(directDeferredDestroyBypass.suspendHostAuthority(10_000L));
        require(directDeferredDestroyBypass.reserveDeferredCommand(TOKEN, 1, 31893, 3,
                NativePageHostLifecycle.DEFER_ACK_DESTROYED, task()));
        require(directDeferredDestroyBypass.onHostAuthority(0, 320, true, true, true));
        require(directDeferredDestroyBypass.acknowledgeForeignDestroyed(
                TOKEN, 1, 31893, 3, task()) == CommandResult.CONTRADICTION);

        NativePageHostLifecycle wrongDeferredConsumption = active(31894);
        require(wrongDeferredConsumption.suspendHostAuthority(10_000L));
        require(wrongDeferredConsumption.reserveDeferredCommand(TOKEN, 1, 31894, 2,
                NativePageHostLifecycle.DEFER_PLACE_LEFT, null));
        require(wrongDeferredConsumption.onHostAuthority(0, 320, true, true, true));
        require(!wrongDeferredConsumption.consumeDeferredCommand(TOKEN, 1, 31894, 2,
                NativePageHostLifecycle.DEFER_PLACE_RIGHT, null));
        require(wrongDeferredConsumption.isFailed()
                && !wrongDeferredConsumption.hasDeferredCommand());

        NativePageHostLifecycle attachReplayDuringPause = active(3190);
        require(attachReplayDuringPause.suspendHostAuthority(10_000L));
        require(attachReplayDuringPause.acknowledgeForeignAttached(
                TOKEN, 1, 3190, 1, task()) == CommandResult.IDEMPOTENT);
        require(!attachReplayDuringPause.canPublishFreshAttachReady()
                && attachReplayDuringPause.hostAuthoritySuspended());

        NativePageHostLifecycle closeReplayDuringPause = active(3191);
        require(closeReplayDuringPause.beginClose(TOKEN, 1, 3191, 2)
                == CommandResult.ACCEPTED);
        require(closeReplayDuringPause.suspendHostAuthority(10_000L));
        require(closeReplayDuringPause.beginClose(TOKEN, 1, 3191, 2)
                == CommandResult.IDEMPOTENT);
        require(closeReplayDuringPause.isWaitingForDestroy()
                && closeReplayDuringPause.hostAuthoritySuspended());

        NativePageHostLifecycle placementReplayDuringPause = active(31911);
        require(placementReplayDuringPause.authorizePlacement(TOKEN, 1, 31911, 2, LEFT)
                == CommandResult.ACCEPTED);
        require(placementReplayDuringPause.onPhysicalFrameMeasured(
                1872, 1404, 0, 78, 936, 1248, 2) == FrameResult.READY);
        require(placementReplayDuringPause.suspendHostAuthority(10_000L));
        require(placementReplayDuringPause.authorizePlacement(TOKEN, 1, 31911, 2, LEFT)
                == CommandResult.IDEMPOTENT);
        require(placementReplayDuringPause.placement() == LEFT
                && placementReplayDuringPause.hostAuthoritySuspended());

        NativePageHostLifecycle destroyReplayDuringPause = active(31912);
        require(destroyReplayDuringPause.beginClose(TOKEN, 1, 31912, 2)
                == CommandResult.ACCEPTED);
        require(destroyReplayDuringPause.acknowledgeForeignDestroyed(
                TOKEN, 1, 31912, 3, task()) == CommandResult.ACCEPTED);
        require(destroyReplayDuringPause.suspendHostAuthority(10_000L));
        require(destroyReplayDuringPause.acknowledgeForeignDestroyed(
                TOKEN, 1, 31912, 3, task()) == CommandResult.IDEMPOTENT);
        require(destroyReplayDuringPause.canReleaseNormally()
                && destroyReplayDuringPause.hostAuthoritySuspended());

        NativePageHostLifecycle invalidDeferredPhase = waiting(3192);
        require(invalidDeferredPhase.suspendHostAuthority(10_000L));
        require(!invalidDeferredPhase.reserveDeferredCommand(TOKEN, 1, 3192, 1,
                NativePageHostLifecycle.DEFER_PLACE_RIGHT, null));
        require(invalidDeferredPhase.isFailed() && !invalidDeferredPhase.hasDeferredCommand());

        NativePageHostLifecycle failedDeferredDestroy = active(3193);
        require(failedDeferredDestroy.beginClose(TOKEN, 1, 3193, 2)
                == CommandResult.ACCEPTED);
        require(failedDeferredDestroy.suspendHostAuthority(10_000L));
        require(failedDeferredDestroy.reserveDeferredCommand(TOKEN, 1, 3193, 3,
                NativePageHostLifecycle.DEFER_ACK_DESTROYED, task()));
        require(failedDeferredDestroy.onDestroyTimeout(1));
        require(failedDeferredDestroy.isFailed() && !failedDeferredDestroy.hasDeferredCommand());
        require(failedDeferredDestroy.acknowledgeForeignDestroyed(
                TOKEN, 1, 3193, 3, task()) == CommandResult.ACCEPTED);

        // Sticky protocol failure closes ordinary command admission, but it does
        // not fabricate physical host loss. A real watchdog/pause transition may
        // retain and reacquire the unchanged display while the exact close
        // handshake is delivered.
        NativePageHostLifecycle contradictionCleanupThroughPause = active(3194);
        require(contradictionCleanupThroughPause.authorizePlacement(
                TOKEN, 1, 3194, 3, LEFT) == CommandResult.CONTRADICTION);
        String contradictionFailure = contradictionCleanupThroughPause.failure();
        require(contradictionCleanupThroughPause.isFailed()
                && contradictionCleanupThroughPause.retainsPhysicalHostAuthority()
                && !contradictionCleanupThroughPause.mustReleaseForHostLoss());
        require(contradictionCleanupThroughPause.onHostAuthority(
                0, 320, true, true, true));
        require(contradictionCleanupThroughPause.suspendHostAuthority(31_940L));
        require(contradictionCleanupThroughPause.beginClose(
                TOKEN, 1, 3194, 2) == CommandResult.ACCEPTED);
        require(contradictionCleanupThroughPause.onHostAuthority(
                0, 320, true, true, true));
        require(contradictionCleanupThroughPause.onPhysicalFrameMeasured(
                1404, 1872, 0, 0, 1404, 1872, 0) == FrameResult.READY);
        require(contradictionCleanupThroughPause.completeHostAuthorityTransition(31_940L));
        require(contradictionFailure.equals(contradictionCleanupThroughPause.failure())
                && contradictionCleanupThroughPause.retainsPhysicalHostAuthority());
        require(contradictionCleanupThroughPause.authorizePlacement(
                TOKEN, 1, 3194, 3, LEFT) == CommandResult.CONTRADICTION);
        require(contradictionCleanupThroughPause.acknowledgeForeignDestroyed(
                TOKEN, 1, 3194, 3, task()) == CommandResult.ACCEPTED);
        contradictionCleanupThroughPause.markReleased(false);

        NativePageHostLifecycle attachTimeoutCleanupThroughPause = waiting(3195);
        require(attachTimeoutCleanupThroughPause.onAttachTimeout(1));
        String attachFailure = attachTimeoutCleanupThroughPause.failure();
        require(attachTimeoutCleanupThroughPause.retainsPhysicalHostAuthority()
                && !attachTimeoutCleanupThroughPause.mustReleaseForHostLoss());
        require(attachTimeoutCleanupThroughPause.suspendHostAuthority(31_950L));
        require(attachTimeoutCleanupThroughPause.onHostAuthority(
                0, 320, true, true, true));
        require(attachTimeoutCleanupThroughPause.onPhysicalFrameMeasured(
                1404, 1872, 0, 0, 1404, 1872, 0) == FrameResult.READY);
        require(attachTimeoutCleanupThroughPause.completeHostAuthorityTransition(31_950L));
        require(attachFailure.equals(attachTimeoutCleanupThroughPause.failure())
                && attachTimeoutCleanupThroughPause.retainsPhysicalHostAuthority());
        require(attachTimeoutCleanupThroughPause.authorizePlacement(
                TOKEN, 1, 3195, 1, LEFT) == CommandResult.CONTRADICTION);
        require(attachTimeoutCleanupThroughPause.acknowledgeNoForeignAfterFailure(
                TOKEN, 1, 3195, 1, PROOF) == CommandResult.ACCEPTED);
        attachTimeoutCleanupThroughPause.markReleased(false);

        NativePageHostLifecycle destroyTimeoutCleanupThroughPause = active(3196);
        require(destroyTimeoutCleanupThroughPause.beginClose(
                TOKEN, 1, 3196, 2) == CommandResult.ACCEPTED);
        require(destroyTimeoutCleanupThroughPause.onDestroyTimeout(1));
        String destroyFailure = destroyTimeoutCleanupThroughPause.failure();
        require(destroyTimeoutCleanupThroughPause.retainsPhysicalHostAuthority()
                && !destroyTimeoutCleanupThroughPause.mustReleaseForHostLoss());
        require(destroyTimeoutCleanupThroughPause.suspendHostAuthority(31_960L));
        require(destroyTimeoutCleanupThroughPause.acknowledgeForeignDestroyed(
                TOKEN, 1, 3196, 3, task()) == CommandResult.ACCEPTED);
        require(destroyTimeoutCleanupThroughPause.onHostAuthority(
                0, 320, true, true, true));
        require(destroyTimeoutCleanupThroughPause.onPhysicalFrameMeasured(
                1404, 1872, 0, 0, 1404, 1872, 0) == FrameResult.READY);
        require(destroyTimeoutCleanupThroughPause.completeHostAuthorityTransition(31_960L));
        require(destroyFailure.equals(destroyTimeoutCleanupThroughPause.failure())
                && destroyTimeoutCleanupThroughPause.canReleaseNormally()
                && destroyTimeoutCleanupThroughPause.retainsPhysicalHostAuthority());
        destroyTimeoutCleanupThroughPause.markReleased(false);

        // A release exception never claims removal. Exact cleanup remains retryable.
        NativePageHostLifecycle normalReleaseFailure = active(319);
        require(normalReleaseFailure.beginClose(TOKEN, 1, 319, 2) == CommandResult.ACCEPTED);
        require(normalReleaseFailure.acknowledgeForeignDestroyed(TOKEN, 1, 319, 3, task())
                == CommandResult.ACCEPTED);
        normalReleaseFailure.onReleaseAttemptFailed(false, "injected");
        require(normalReleaseFailure.isFailed() && !normalReleaseFailure.displayRemoved()
                && normalReleaseFailure.canReleaseNormally());
        normalReleaseFailure.markReleased(false);
        require(normalReleaseFailure.state() == NativePageHostLifecycle.State.RELEASED);

        NativePageHostLifecycle emergencyReleaseFailure = active(320);
        emergencyReleaseFailure.onUnexpectedHostLoss("injected host loss");
        emergencyReleaseFailure.onReleaseAttemptFailed(true, "injected");
        require(!emergencyReleaseFailure.displayRemoved());
        require(emergencyReleaseFailure.acknowledgeForeignDestroyed(
                TOKEN, 1, 320, 2, task()) == CommandResult.ACCEPTED);
        emergencyReleaseFailure.markReleased(false);
        require(emergencyReleaseFailure.state() == NativePageHostLifecycle.State.RELEASED);

        // A placement contradiction retains the exact old/target frame pair until
        // the admitted foreign task completes its authenticated cleanup handshake.
        NativePageHostLifecycle failedDuringPlacement = active(321);
        require(failedDuringPlacement.authorizePlacement(TOKEN, 1, 321, 2, LEFT)
                == CommandResult.ACCEPTED);
        require(failedDuringPlacement.authorizePlacement(TOKEN, 1, 321, 2, RIGHT)
                == CommandResult.CONTRADICTION);
        require(failedDuringPlacement.onPhysicalFrameMeasured(
                1872, 1404, 409, 0, 1053, 1404, 2) == FrameResult.READY);
        require(failedDuringPlacement.isFailed()
                && failedDuringPlacement.placement() == FULL
                && failedDuringPlacement.frameRequestPlacement() == LEFT
                && failedDuringPlacement.retainsPhysicalHostAuthority());
        require(failedDuringPlacement.suspendHostAuthority(32_100L));
        require(failedDuringPlacement.onHostAuthority(0, 320, true, true, true));
        require(failedDuringPlacement.onPhysicalFrameMeasured(
                1872, 1404, 0, 78, 936, 1248, 2) == FrameResult.READY);
        require(failedDuringPlacement.completeHostAuthorityTransition(32_100L));
        require(failedDuringPlacement.placement() == FULL
                && failedDuringPlacement.frameRequestPlacement() == LEFT);
        require(failedDuringPlacement.beginClose(TOKEN, 1, 321, 3)
                == CommandResult.ACCEPTED);
        require(failedDuringPlacement.onPhysicalFrameMeasured(
                1872, 1404, 0, 78, 936, 1248, 2) == FrameResult.READY);
        require(failedDuringPlacement.acknowledgeForeignDestroyed(
                TOKEN, 1, 321, 4, task()) == CommandResult.ACCEPTED);
        failedDuringPlacement.markReleased(false);
        require(failedDuringPlacement.state() == NativePageHostLifecycle.State.RELEASED);

        NativePageHostLifecycle closeDuringPlacement = active(323);
        require(closeDuringPlacement.authorizePlacement(TOKEN, 1, 323, 2, LEFT)
                == CommandResult.ACCEPTED);
        require(closeDuringPlacement.beginClose(TOKEN, 1, 323, 3)
                == CommandResult.ACCEPTED);
        require(closeDuringPlacement.onPhysicalFrameMeasured(
                1872, 1404, 0, 78, 936, 1248, 2) == FrameResult.READY);
        require(closeDuringPlacement.isWaitingForDestroy());
        require(closeDuringPlacement.acknowledgeForeignDestroyed(
                TOKEN, 1, 323, 4, task()) == CommandResult.ACCEPTED);
        closeDuringPlacement.markReleased(false);
        require(closeDuringPlacement.state() == NativePageHostLifecycle.State.RELEASED);

        // Exact ATTACH retries are neutral replays in every later lifecycle phase.
        NativePageHostLifecycle replayDuringPlacement = active(324);
        require(replayDuringPlacement.authorizePlacement(TOKEN, 1, 324, 2, LEFT)
                == CommandResult.ACCEPTED);
        require(replayDuringPlacement.acknowledgeForeignAttached(
                TOKEN, 1, 324, 1, task()) == CommandResult.IDEMPOTENT);
        require(replayDuringPlacement.state()
                == NativePageHostLifecycle.State.PLACEMENT_PENDING
                && !replayDuringPlacement.canPublishFreshAttachReady()
                && replayDuringPlacement.lastCommandSequence() == 2);

        NativePageHostLifecycle replayWhileClosing = active(325);
        require(replayWhileClosing.beginClose(TOKEN, 1, 325, 2)
                == CommandResult.ACCEPTED);
        require(replayWhileClosing.acknowledgeForeignAttached(
                TOKEN, 1, 325, 1, task()) == CommandResult.IDEMPOTENT);
        require(replayWhileClosing.state()
                == NativePageHostLifecycle.State.WAITING_FOR_FOREIGN_DESTROY
                && !replayWhileClosing.canPublishFreshAttachReady()
                && replayWhileClosing.lastCommandSequence() == 2);
        require(replayWhileClosing.acknowledgeForeignDestroyed(
                TOKEN, 1, 325, 3, task()) == CommandResult.ACCEPTED);
        replayWhileClosing.markReleased(false);

        NativePageHostLifecycle replayReleaseAuthorized = active(326);
        require(replayReleaseAuthorized.beginClose(TOKEN, 1, 326, 2)
                == CommandResult.ACCEPTED);
        require(replayReleaseAuthorized.acknowledgeForeignDestroyed(
                TOKEN, 1, 326, 3, task()) == CommandResult.ACCEPTED);
        require(replayReleaseAuthorized.acknowledgeForeignAttached(
                TOKEN, 1, 326, 1, task()) == CommandResult.IDEMPOTENT);
        require(replayReleaseAuthorized.state()
                == NativePageHostLifecycle.State.RELEASE_AUTHORIZED
                && !replayReleaseAuthorized.canPublishFreshAttachReady()
                && replayReleaseAuthorized.canReleaseNormally());
        replayReleaseAuthorized.markReleased(false);

        NativePageHostLifecycle replayAfterReleaseFailure = active(327);
        require(replayAfterReleaseFailure.beginClose(TOKEN, 1, 327, 2)
                == CommandResult.ACCEPTED);
        require(replayAfterReleaseFailure.acknowledgeForeignDestroyed(
                TOKEN, 1, 327, 3, task()) == CommandResult.ACCEPTED);
        replayAfterReleaseFailure.onReleaseAttemptFailed(false, "injected");
        require(replayAfterReleaseFailure.acknowledgeForeignAttached(
                TOKEN, 1, 327, 1, task()) == CommandResult.IDEMPOTENT);
        require(replayAfterReleaseFailure.state() == NativePageHostLifecycle.State.FAILED
                && !replayAfterReleaseFailure.canPublishFreshAttachReady()
                && replayAfterReleaseFailure.canReleaseNormally());
        require(replayAfterReleaseFailure.acknowledgeForeignDestroyed(
                TOKEN, 1, 327, 3, task()) == CommandResult.IDEMPOTENT);
        replayAfterReleaseFailure.markReleased(false);

        NativePageHostLifecycle replayWhileStickyFailed = active(328);
        require(replayWhileStickyFailed.authorizePlacement(TOKEN, 1, 328, 3, LEFT)
                == CommandResult.CONTRADICTION);
        String replayFailure = replayWhileStickyFailed.failure();
        require(replayWhileStickyFailed.acknowledgeForeignAttached(
                TOKEN, 1, 328, 1, task()) == CommandResult.IDEMPOTENT);
        require(replayWhileStickyFailed.state() == NativePageHostLifecycle.State.FAILED
                && replayFailure.equals(replayWhileStickyFailed.failure())
                && !replayWhileStickyFailed.canPublishFreshAttachReady()
                && replayWhileStickyFailed.lastCommandSequence() == 1);
        require(replayWhileStickyFailed.beginClose(TOKEN, 1, 328, 2)
                == CommandResult.ACCEPTED);
        require(replayWhileStickyFailed.acknowledgeForeignDestroyed(
                TOKEN, 1, 328, 3, task()) == CommandResult.ACCEPTED);
        replayWhileStickyFailed.markReleased(false);

        // BEGIN_CLOSE retries are neutral in the initial wait and every later cleanup
        // phase. Only its first accepted transition has fresh wait readiness.
        NativePageHostLifecycle closeReplayWaiting = active(329);
        require(closeReplayWaiting.beginClose(TOKEN, 1, 329, 2)
                == CommandResult.ACCEPTED);
        require(closeReplayWaiting.canPublishFreshCloseWait());
        require(closeReplayWaiting.beginClose(TOKEN, 1, 329, 2)
                == CommandResult.IDEMPOTENT);
        require(closeReplayWaiting.state()
                == NativePageHostLifecycle.State.WAITING_FOR_FOREIGN_DESTROY
                && closeReplayWaiting.canPublishFreshCloseWait()
                && closeReplayWaiting.lastCommandSequence() == 2);
        require(closeReplayWaiting.acknowledgeForeignDestroyed(
                TOKEN, 1, 329, 3, task()) == CommandResult.ACCEPTED);
        require(!closeReplayWaiting.canPublishFreshCloseWait());
        require(closeReplayWaiting.beginClose(TOKEN, 1, 329, 2)
                == CommandResult.IDEMPOTENT);
        require(closeReplayWaiting.state() == NativePageHostLifecycle.State.RELEASE_AUTHORIZED
                && closeReplayWaiting.canReleaseNormally()
                && closeReplayWaiting.lastCommandSequence() == 3);
        closeReplayWaiting.onReleaseAttemptFailed(false, "injected-close-replay");
        String closeReleaseFailure = closeReplayWaiting.failure();
        require(closeReplayWaiting.beginClose(TOKEN, 1, 329, 2)
                == CommandResult.IDEMPOTENT);
        require(closeReplayWaiting.state() == NativePageHostLifecycle.State.FAILED
                && closeReleaseFailure.equals(closeReplayWaiting.failure())
                && closeReplayWaiting.canReleaseNormally()
                && !closeReplayWaiting.canPublishFreshCloseWait()
                && closeReplayWaiting.lastCommandSequence() == 3);
        require(closeReplayWaiting.acknowledgeForeignDestroyed(
                TOKEN, 1, 329, 3, task()) == CommandResult.IDEMPOTENT);
        closeReplayWaiting.markReleased(false);

        NativePageHostLifecycle closeReplayCannotBecomeNewClose = active(330);
        require(closeReplayCannotBecomeNewClose.beginClose(TOKEN, 1, 330, 2)
                == CommandResult.ACCEPTED);
        require(closeReplayCannotBecomeNewClose.acknowledgeForeignDestroyed(
                TOKEN, 1, 330, 3, task()) == CommandResult.ACCEPTED);
        closeReplayCannotBecomeNewClose.onReleaseAttemptFailed(false, "injected-new-close");
        require(closeReplayCannotBecomeNewClose.beginClose(TOKEN, 1, 330, 4)
                == CommandResult.CONTRADICTION);
        require(closeReplayCannotBecomeNewClose.isFailed()
                && closeReplayCannotBecomeNewClose.canReleaseNormally()
                && closeReplayCannotBecomeNewClose.lastCommandSequence() == 3);

        NativePageHostLifecycle closeSequenceEquivocation = active(331);
        require(closeSequenceEquivocation.beginClose(TOKEN, 1, 331, 2)
                == CommandResult.ACCEPTED);
        require(closeSequenceEquivocation.authorizePlacement(TOKEN, 1, 331, 2, LEFT)
                == CommandResult.CONTRADICTION);
        require(closeSequenceEquivocation.isFailed()
                && closeSequenceEquivocation.lastCommandSequence() == 2
                && !closeSequenceEquivocation.canPublishFreshCloseWait());

        NativePageHostLifecycle badCreatedDisplay = new NativePageHostLifecycle(false, TOKEN);
        require(badCreatedDisplay.admitHostAuthority(0, 320, true, true, true));
        require(badCreatedDisplay.onPhysicalFrameMeasured(
                1404, 1872, 0, 0, 1404, 1872, 0) == FrameResult.READY);
        require(badCreatedDisplay.beginDisplayCreation() == 1);
        require(badCreatedDisplay.onDisplayAllocated(1, 32));
        require(!badCreatedDisplay.onDisplayCreated(1, 32, 3, 4, 320));
        require(badCreatedDisplay.isFailed());
        require(badCreatedDisplay.acknowledgeNoForeignAfterFailure(
                TOKEN, 1, 32, 1, PROOF) == CommandResult.ACCEPTED);
        badCreatedDisplay.markReleased(false);
        require(badCreatedDisplay.state() == NativePageHostLifecycle.State.RELEASED
                && badCreatedDisplay.canFinishWithoutCleanup());

        NativePageHostLifecycle contradictoryCreatedCallback =
                new NativePageHostLifecycle(false, TOKEN);
        require(contradictoryCreatedCallback.admitHostAuthority(
                0, 320, true, true, true));
        require(contradictoryCreatedCallback.onPhysicalFrameMeasured(
                1404, 1872, 0, 0, 1404, 1872, 0) == FrameResult.READY);
        require(contradictoryCreatedCallback.beginDisplayCreation() == 1);
        require(!contradictoryCreatedCallback.onDisplayAllocated(2, 322));
        require(contradictoryCreatedCallback.displayId() == 322
                && contradictoryCreatedCallback.isFailed());
        contradictoryCreatedCallback.onReleaseAttemptFailed(true, "injected");
        require(contradictoryCreatedCallback.acknowledgeNoForeignAfterFailure(
                TOKEN, 1, 322, 1, PROOF) == CommandResult.ACCEPTED);
        contradictoryCreatedCallback.markReleased(false);
        require(contradictoryCreatedCallback.state()
                == NativePageHostLifecycle.State.RELEASED);

        // The positive display ID is lifecycle authority before the first fallible
        // metrics read. A metrics exception plus release exception therefore keeps
        // the exact empty-session cleanup envelope reachable.
        NativePageHostLifecycle metricsException = new NativePageHostLifecycle(false, TOKEN);
        require(metricsException.admitHostAuthority(0, 320, true, true, true));
        require(metricsException.onPhysicalFrameMeasured(
                1404, 1872, 0, 0, 1404, 1872, 0) == FrameResult.READY);
        require(metricsException.beginDisplayCreation() == 1);
        require(!metricsException.retainedDisplayCleanupAddressable(-1)
                && !metricsException.retainedDisplayCleanupAddressable(323));
        require(metricsException.onDisplayAllocated(1, 323));
        require(metricsException.state() == NativePageHostLifecycle.State.DISPLAY_ALLOCATED
                && metricsException.displayId() == 323
                && metricsException.retainedDisplayCleanupAddressable(323)
                && !metricsException.retainedDisplayCleanupAddressable(324));
        metricsException.onUnexpectedHostLoss("injected metrics exception");
        metricsException.onReleaseAttemptFailed(true, "injected release exception");
        require(metricsException.retainedDisplayCleanupAddressable(323));
        require(metricsException.commandEnvelopeMatches(TOKEN, 1, 323, 1));
        require(metricsException.acknowledgeNoForeignAfterFailure(
                TOKEN, 1, 323, 1, PROOF) == CommandResult.ACCEPTED);
        metricsException.markReleased(false);
        require(metricsException.state() == NativePageHostLifecycle.State.RELEASED
                && !metricsException.retainedDisplayCleanupAddressable(323));

        NativePageHostLifecycle preIdReleaseFailure = new NativePageHostLifecycle(false, TOKEN);
        require(preIdReleaseFailure.admitHostAuthority(0, 320, true, true, true));
        require(preIdReleaseFailure.onPhysicalFrameMeasured(
                1404, 1872, 0, 0, 1404, 1872, 0) == FrameResult.READY);
        require(preIdReleaseFailure.beginDisplayCreation() == 1);
        preIdReleaseFailure.onUnexpectedHostLoss("injected pre-id allocation failure");
        preIdReleaseFailure.onReleaseAttemptFailed(true, "injected release exception");
        require(preIdReleaseFailure.isFailed()
                && !preIdReleaseFailure.retainedDisplayCleanupAddressable(-1)
                && !preIdReleaseFailure.commandEnvelopeMatches(TOKEN, 1, -1, 1));

        require(!active(33).commandEnvelopeMatches(TOKEN, 1, 33, 0));
        require(!active(34).commandEnvelopeMatches(TOKEN, 1, 34, -1));

        // Mutation volume protects each envelope field and every exact retry path.
        for (int index = 0; index < 32; index++) {
            NativePageHostLifecycle value = active(100 + index);
            require(value.commandEnvelopeMatches(TOKEN, 1, 100 + index, 2));
            DisplayProbeLayout.Placement target = index % 2 == 0 ? LEFT : RIGHT;
            require(value.authorizePlacement(TOKEN, 1, 100 + index, 2, target)
                    == CommandResult.ACCEPTED);
            int frameLeft = target == LEFT ? 0 : 936;
            require(value.onPhysicalFrameMeasured(1872, 1404, frameLeft, 78,
                    936, 1248, 2) == FrameResult.READY);
            require(!value.isFailed());
            require(value.acknowledgeForeignAttached(TOKEN, 1, 100 + index, 1, task())
                    == CommandResult.IDEMPOTENT);
        }

        testHealthyPreAttachAbort();

        System.out.println("Native page host lifecycle/layout: " + checks
                + " assertions PASS (foreign task and Android callback delivery remain hardware-only)");
    }
}
