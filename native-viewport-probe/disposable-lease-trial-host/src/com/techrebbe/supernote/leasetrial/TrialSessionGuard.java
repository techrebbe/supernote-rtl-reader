package com.techrebbe.supernote.leasetrial;

/** Main-Looper-local, sticky authority for one disposable Activity incarnation. */
final class TrialSessionGuard {
    private String firstTaint;

    void taint(String reason) {
        if (reason == null || reason.isEmpty()) {
            throw new IllegalArgumentException("taint reason required");
        }
        if (firstTaint == null) firstTaint = reason;
    }

    boolean tainted() { return firstTaint != null; }

    String reason() { return firstTaint == null ? "NONE" : firstTaint; }

    boolean allowPreflight() { return !tainted(); }

    boolean currentlyValid(boolean historicalProofValid) {
        return !tainted() && historicalProofValid;
    }
}
