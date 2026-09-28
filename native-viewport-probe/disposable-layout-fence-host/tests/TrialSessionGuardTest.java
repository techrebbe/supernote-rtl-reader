package com.techrebbe.supernote.layoutfencetrial;

public final class TrialSessionGuardTest {
    private static int checks;
    private static void check(boolean value, String message) {
        checks++;
        if (!value) throw new AssertionError(message);
    }

    public static void main(String[] args) {
        TrialSessionGuard guard = new TrialSessionGuard();
        check(!guard.claimFirstFocusPaint(false, true), "unadmitted focus denied");
        check(!guard.claimFirstFocusPaint(true, false), "absent focus denied");
        check(guard.claimFirstFocusPaint(true, true), "first focus claimed");
        check(!guard.claimFirstFocusPaint(true, true), "second focus denied");
        check(guard.claimCommand(), "one command claimed");
        check(!guard.claimCommand(), "second command denied");
        guard.taint("PAUSE");
        guard.taint("LATE_DRIFT");
        check(guard.tainted(), "taint sticky");
        check(guard.reason().equals("PAUSE"), "first taint retained");
        check(!guard.claimCommand(), "tainted command denied");
        System.out.println("PASS TrialSessionGuardTest checks=" + checks);
    }
}
