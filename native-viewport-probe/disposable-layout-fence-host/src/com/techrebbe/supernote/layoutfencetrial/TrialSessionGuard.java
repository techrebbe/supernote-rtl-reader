package com.techrebbe.supernote.layoutfencetrial;

/** One command per Activity incarnation, with sticky lifecycle/scene taint. */
final class TrialSessionGuard {
    private boolean commandClaimed;
    private boolean firstFocusPaintClaimed;
    private String firstTaint;

    boolean claimCommand() {
        if (commandClaimed || firstTaint != null) return false;
        commandClaimed = true;
        return true;
    }

    boolean claimFirstFocusPaint(boolean admitted, boolean focused) {
        if (!admitted || !focused || firstFocusPaintClaimed || firstTaint != null) return false;
        firstFocusPaintClaimed = true;
        return true;
    }

    void taint(String reason) {
        if (reason == null || reason.isEmpty()) throw new IllegalArgumentException("reason");
        if (firstTaint == null) firstTaint = reason;
    }

    boolean tainted() { return firstTaint != null; }
    String reason() { return firstTaint == null ? "NONE" : firstTaint; }
    boolean commandClaimed() { return commandClaimed; }
}
