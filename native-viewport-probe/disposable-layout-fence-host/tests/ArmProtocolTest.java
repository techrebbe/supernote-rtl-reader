package com.techrebbe.supernote.layoutfencetrial;

/** Deterministic process-arm transition tests; watchdog implementation is guarded separately. */
public final class ArmProtocolTest {
    private static int checks;
    private static void check(boolean value, String message) {
        checks++;
        if (!value) throw new AssertionError(message);
    }

    private static ArmProtocol.Pins pins() {
        return new ArmProtocol.Pins(123, "incarnation", 1,
                "activity-token", "root-token");
    }

    private static void happyPath() {
        ArmProtocol.Pins owner = pins();
        ArmProtocol arm = new ArmProtocol(owner);
        check(arm.state() == ArmProtocol.State.IDLE, "idle before arm");
        check(arm.activeDeadlineElapsedMs(1000) == -1,
                "idle is not an active post-command lease");
        check(arm.prearm(owner, "secret", 1000), "exact prearm");
        check(arm.deadlineElapsedMs() == 31000, "finite monotonic 30s deadline");
        check(arm.activeDeadlineElapsedMs(1001) == -1,
                "prearm alone cannot authorize historical PASS");
        check(!arm.prearm(owner, "other", 1001), "no rearm");
        check(!arm.claimCommand(owner, "secret", "fresh", 1002),
                "command cannot bypass refresh");
        check(!arm.claimRefresh(owner, "wrong", 1002), "wrong arm token denied");
        check(!arm.claimRefresh(new ArmProtocol.Pins(124, "incarnation", 1,
                "activity-token", "root-token"), "secret", 1002),
                "wrong pid denied");
        check(arm.claimRefresh(owner, "secret", 1002),
                "refresh claimed once on Binder path");
        check(!arm.claimRefresh(owner, "secret", 1003), "refresh replay denied");
        check(arm.activeDeadlineElapsedMs(1003) == -1,
                "refresh dispatch cannot authorize PASS");
        check(arm.completeRefresh(owner, "secret", "fresh", 1003),
                "one exact refresh request completed");
        check(!arm.claimCommand(owner, "secret", "wrong", 1004),
                "command requires exact refresh token");
        check(arm.claimCommand(owner, "secret", "fresh", 1004),
                "command consumed after refresh");
        check(arm.activeDeadlineElapsedMs(1005) == -1,
                "dispatching without trial watchdog is not a proof lease");
        check(!arm.claimCommand(owner, "secret", "fresh", 1005),
                "command replay denied");
        check(!arm.claimSentinel("after-disarm", owner, "secret", 1003),
                "sentinel before trial watchdog denied");
        check(arm.trialWatchdogStarted(owner, "secret", 1004),
                "trial watchdog handoff acknowledged");
        check(arm.activeDeadlineElapsedMs(6100) == 31000,
                "active arm outlives five-second trial deadline");
        check(arm.activeDeadlineElapsedMs(31000) == -1,
                "expired arm cannot authorize historical PASS");
        check(!arm.claimSentinel("after-unload", owner, "secret", 1005),
                "unload sentinel cannot run first");
        check(arm.claimSentinel("after-disarm", owner, "secret", 1006),
                "first sentinel one-shot claim");
        check(!arm.claimSentinel("after-disarm", owner, "secret", 1007),
                "first sentinel replay denied");
        check(arm.completeSentinel("after-disarm", owner, "secret", true, 1008),
                "first sentinel exact no-op");
        check(!arm.finish(owner, "secret", 1009), "finish before unload denied");
        check(arm.claimSentinel("after-unload", owner, "secret", 1010),
                "second sentinel one-shot claim");
        check(arm.completeSentinel("after-unload", owner, "secret", true, 1011),
                "second sentinel exact no-op");
        check(arm.finish(owner, "secret", 1012), "explicit final finish");
        check(arm.state() == ArmProtocol.State.FINISHED, "finished terminal");
        check(arm.activeDeadlineElapsedMs(1013) == -1,
                "finished arm cannot authorize a new current proof");
        check(!arm.abort(owner, "secret", 1013), "abort after finish denied");
        check(!arm.prearm(owner, "again", 1014), "finish cannot rearm");
    }

    private static void timeoutAbortAndFailure() {
        ArmProtocol.Pins owner = pins();
        ArmProtocol noCommand = new ArmProtocol(owner);
        check(noCommand.prearm(owner, "one", 2000), "timeout arm");
        check(!noCommand.claimRefresh(owner, "one", 32000),
                "deadline equality cannot request refresh");
        check(!noCommand.claimCommand(owner, "one", "fresh", 32000),
                "deadline equality cannot dispatch command");
        check(noCommand.state() == ArmProtocol.State.ARMED,
                "expired arm does not silently finish");
        check(!noCommand.abort(owner, "wrong", 2001), "wrong-token abort denied");
        check(noCommand.abort(owner, "one", 2002), "exact abort terminal");
        check(noCommand.state() == ArmProtocol.State.ABORTED, "abort terminal state");
        check(!noCommand.claimCommand(owner, "one", "fresh", 2003),
                "aborted command denied");

        ArmProtocol badSentinel = new ArmProtocol(owner);
        check(badSentinel.prearm(owner, "two", 3000), "failure arm");
        check(badSentinel.claimRefresh(owner, "two", 3001), "failure refresh");
        check(badSentinel.completeRefresh(owner, "two", "fresh-two", 3001),
                "failure refresh completed");
        check(badSentinel.claimCommand(owner, "two", "fresh-two", 3001),
                "failure command");
        check(badSentinel.trialWatchdogStarted(owner, "two", 3002),
                "failure handoff");
        check(badSentinel.claimSentinel("after-disarm", owner, "two", 3003),
                "failure sentinel claimed");
        check(!badSentinel.completeSentinel("after-disarm", owner, "two", false, 3004),
                "drifted sentinel fails");
        check(badSentinel.state() == ArmProtocol.State.FAILED,
                "failure remains armed for hard stop");
        check(badSentinel.activeDeadlineElapsedMs(3005) == -1,
                "failed arm cannot authorize current proof");
        check(!badSentinel.claimSentinel("after-disarm", owner, "two", 3005),
                "failed sentinel not retried");
        check(!badSentinel.finish(owner, "two", 3006),
                "failed sentinel cannot disarm watchdog");

        ArmProtocol expiredFinish = new ArmProtocol(owner);
        check(expiredFinish.prearm(owner, "three", 4000), "expiry fixture prearm");
        check(expiredFinish.claimRefresh(owner, "three", 4001),
                "expiry fixture refresh");
        check(expiredFinish.completeRefresh(owner, "three", "fresh-three", 4001),
                "expiry fixture refresh completed");
        check(expiredFinish.claimCommand(owner, "three", "fresh-three", 4001),
                "expiry fixture command");
        check(expiredFinish.trialWatchdogStarted(owner, "three", 4002),
                "expiry fixture watchdog");
        check(expiredFinish.claimSentinel("after-disarm", owner, "three", 4003),
                "expiry fixture disarm sentinel");
        check(expiredFinish.completeSentinel("after-disarm", owner, "three", true, 4004),
                "expiry fixture disarm completion");
        check(expiredFinish.claimSentinel("after-unload", owner, "three", 4005),
                "expiry fixture unload sentinel");
        check(expiredFinish.completeSentinel("after-unload", owner, "three", true, 4006),
                "expiry fixture unload completion");
        check(!expiredFinish.finish(owner, "three", 34000),
                "expired arm cannot finish despite successful sentinels");

        ArmProtocol ambiguous = new ArmProtocol(owner);
        check(ambiguous.prearm(owner, "four", 5000), "ambiguous fixture prearm");
        check(ambiguous.claimRefresh(owner, "four", 5001),
                "ambiguous refresh consumed");
        ambiguous.fail();
        check(!ambiguous.claimRefresh(owner, "four", 5002),
                "ambiguous refresh cannot retry");
        check(!ambiguous.claimCommand(owner, "four", "fresh-four", 5003),
                "ambiguous refresh cannot command");

        ArmProtocol lostResponse = new ArmProtocol(owner);
        check(lostResponse.prearm(owner, "five", 6000),
                "lost-response fixture prearm");
        check(lostResponse.claimRefresh(owner, "five", 6001),
                "lost-response refresh claimed");
        check(lostResponse.completeRefresh(owner, "five", "fresh-five", 6002),
                "lost-response refresh completed internally");
        lostResponse.fail();
        check(!lostResponse.claimCommand(owner, "five", "fresh-five", 6003),
                "ambiguous completed refresh cannot command");
    }

    public static void main(String[] args) {
        happyPath();
        timeoutAbortAndFailure();
        System.out.println("PASS ArmProtocolTest checks=" + checks);
    }
}
