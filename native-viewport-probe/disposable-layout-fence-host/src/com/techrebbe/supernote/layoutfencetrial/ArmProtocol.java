package com.techrebbe.supernote.layoutfencetrial;

/** Pure-Java, one-process instrumentation lifetime gate. No UI mutation. */
final class ArmProtocol {
    static final long ARM_LIFETIME_MS = 30000;

    enum State {
        IDLE, ARMED, REFRESH_DISPATCHING, REFRESH_REQUESTED,
        COMMAND_DISPATCHING, TRIAL_WATCHDOG_ACTIVE,
        DISARM_SENTINEL_DISPATCHING, DISARM_SENTINEL_DONE,
        UNLOAD_SENTINEL_DISPATCHING, UNLOAD_SENTINEL_DONE,
        FINISHED, ABORTED, FAILED
    }

    static final class Pins {
        final int pid;
        final String incarnation;
        final long activitySerial;
        final String activityToken;
        final String rootToken;

        Pins(int pid, String incarnation, long activitySerial,
                String activityToken, String rootToken) {
            if (pid <= 0 || activitySerial <= 0 || incarnation == null
                    || incarnation.isEmpty() || activityToken == null
                    || activityToken.isEmpty() || rootToken == null
                    || rootToken.isEmpty()) throw new IllegalArgumentException("exact pins required");
            this.pid = pid;
            this.incarnation = incarnation;
            this.activitySerial = activitySerial;
            this.activityToken = activityToken;
            this.rootToken = rootToken;
        }

        boolean same(Pins other) {
            return other != null && pid == other.pid
                    && activitySerial == other.activitySerial
                    && incarnation.equals(other.incarnation)
                    && activityToken.equals(other.activityToken)
                    && rootToken.equals(other.rootToken);
        }
    }

    private final Pins owner;
    private State state = State.IDLE;
    private String armToken;
    private String refreshToken;
    private long deadlineElapsedMs;

    ArmProtocol(Pins owner) { this.owner = owner; }

    synchronized boolean prearm(Pins supplied, String mintedToken, long nowElapsedMs) {
        if (state != State.IDLE || !owner.same(supplied)
                || mintedToken == null || mintedToken.isEmpty()
                || nowElapsedMs < 0 || nowElapsedMs > Long.MAX_VALUE - ARM_LIFETIME_MS) {
            return false;
        }
        armToken = mintedToken;
        deadlineElapsedMs = nowElapsedMs + ARM_LIFETIME_MS;
        state = State.ARMED;
        return true;
    }

    synchronized boolean claimRefresh(Pins supplied, String token, long nowElapsedMs) {
        if (!authorized(supplied, token, nowElapsedMs) || state != State.ARMED) return false;
        state = State.REFRESH_DISPATCHING;
        return true;
    }

    synchronized boolean completeRefresh(Pins supplied, String token,
            String mintedRefreshToken, long nowElapsedMs) {
        if (!authorized(supplied, token, nowElapsedMs)
                || state != State.REFRESH_DISPATCHING
                || mintedRefreshToken == null || mintedRefreshToken.isEmpty()) return false;
        refreshToken = mintedRefreshToken;
        state = State.REFRESH_REQUESTED;
        return true;
    }

    synchronized boolean claimCommand(Pins supplied, String token,
            String suppliedRefreshToken, long nowElapsedMs) {
        if (!authorized(supplied, token, nowElapsedMs)
                || state != State.REFRESH_REQUESTED || refreshToken == null
                || !refreshToken.equals(suppliedRefreshToken)) return false;
        state = State.COMMAND_DISPATCHING;
        return true;
    }

    synchronized boolean trialWatchdogStarted(Pins supplied,
            String token, long nowElapsedMs) {
        if (!authorized(supplied, token, nowElapsedMs)
                || state != State.COMMAND_DISPATCHING) return false;
        state = State.TRIAL_WATCHDOG_ACTIVE;
        return true;
    }

    synchronized boolean claimSentinel(String stage, Pins supplied,
            String token, long nowElapsedMs) {
        if (!authorized(supplied, token, nowElapsedMs)) return false;
        if ("after-disarm".equals(stage) && state == State.TRIAL_WATCHDOG_ACTIVE) {
            state = State.DISARM_SENTINEL_DISPATCHING;
            return true;
        }
        if ("after-unload".equals(stage) && state == State.DISARM_SENTINEL_DONE) {
            state = State.UNLOAD_SENTINEL_DISPATCHING;
            return true;
        }
        return false;
    }

    synchronized boolean completeSentinel(String stage, Pins supplied,
            String token, boolean unchanged, long nowElapsedMs) {
        if (!authorized(supplied, token, nowElapsedMs)) return false;
        if (!unchanged) {
            state = State.FAILED;
            return false;
        }
        if ("after-disarm".equals(stage)
                && state == State.DISARM_SENTINEL_DISPATCHING) {
            state = State.DISARM_SENTINEL_DONE;
            return true;
        }
        if ("after-unload".equals(stage)
                && state == State.UNLOAD_SENTINEL_DISPATCHING) {
            state = State.UNLOAD_SENTINEL_DONE;
            return true;
        }
        return false;
    }

    synchronized boolean finish(Pins supplied, String token, long nowElapsedMs) {
        if (!authorized(supplied, token, nowElapsedMs)
                || state != State.UNLOAD_SENTINEL_DONE) return false;
        state = State.FINISHED;
        return true;
    }

    synchronized boolean abort(Pins supplied, String token, long nowElapsedMs) {
        if (!authorized(supplied, token, nowElapsedMs)
                || state == State.FINISHED || state == State.ABORTED) return false;
        state = State.ABORTED;
        return true;
    }

    synchronized void fail() {
        if (state != State.FINISHED && state != State.ABORTED) state = State.FAILED;
    }

    synchronized State state() { return state; }
    synchronized String armToken() { return armToken; }
    synchronized String refreshToken() { return refreshToken; }
    synchronized long deadlineElapsedMs() { return deadlineElapsedMs; }

    /** Only a live post-command arm may authorize a historical trial PASS. */
    synchronized long activeDeadlineElapsedMs(long nowElapsedMs) {
        if (nowElapsedMs < 0 || nowElapsedMs >= deadlineElapsedMs) return -1;
        switch (state) {
            case TRIAL_WATCHDOG_ACTIVE:
            case DISARM_SENTINEL_DISPATCHING:
            case DISARM_SENTINEL_DONE:
            case UNLOAD_SENTINEL_DISPATCHING:
            case UNLOAD_SENTINEL_DONE:
                return deadlineElapsedMs;
            default:
                return -1;
        }
    }

    private boolean authorized(Pins supplied, String token, long nowElapsedMs) {
        return owner.same(supplied) && armToken != null && armToken.equals(token)
                && nowElapsedMs >= 0 && nowElapsedMs < deadlineElapsedMs;
    }
}
