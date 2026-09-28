package com.techrebbe.supernote.leasetrial;

public final class TrialSessionGuardTest {
    private static int assertions;

    private static void check(boolean value) {
        assertions++;
        if (!value) throw new AssertionError("session taint assertion " + assertions);
    }

    public static void main(String[] args) {
        TrialSessionGuard focus = new TrialSessionGuard();
        check(!focus.claimInitialFocusPaint(false, true, true));
        check(!focus.claimInitialFocusPaint(true, false, true));
        check(!focus.claimInitialFocusPaint(true, true, false));
        check(focus.claimInitialFocusPaint(true, true, true));
        check(!focus.claimInitialFocusPaint(true, true, true));

        TrialSessionGuard taintedFocus = new TrialSessionGuard();
        taintedFocus.taint("WINDOW_FOCUS_LOST");
        check(!taintedFocus.claimInitialFocusPaint(true, true, true));

        TrialSessionGuard idle = new TrialSessionGuard();
        check(idle.allowPreflight());
        check(!idle.currentlyValid(false));
        idle.taint("ACTIVITY_REUSED");
        check(!idle.allowPreflight());
        check(!idle.currentlyValid(true));
        check("ACTIVITY_REUSED".equals(idle.reason()));
        idle.taint("WINDOW_FOCUS_LOST");
        check("ACTIVITY_REUSED".equals(idle.reason()));

        TrialSessionGuard passed = new TrialSessionGuard();
        check(passed.currentlyValid(true));
        passed.taint("ACTIVITY_PAUSED");
        check(!passed.currentlyValid(true));
        check(!passed.allowPreflight());
        System.out.println("PASS " + assertions + " session-taint assertions");
    }
}
