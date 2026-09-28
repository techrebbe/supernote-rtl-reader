package com.techrebbe.supernote.disposableleasehost;

/** Deterministic lifecycle-cover request state independent of Android timing. */
public final class CoverGate {
    public enum Activation { REJECTED, ACTIVE, FINISH_IMMEDIATELY }
    public enum Uncover { REJECTED, DEFERRED, FINISH_ACTIVE, ALREADY_FINISHING }
    private enum State { IDLE, REQUESTED, ACTIVE, FINISH_REQUESTED }

    private State state = State.IDLE;
    private long generation;
    private boolean deferredUncover;

    public synchronized long requestCover() {
        if (state != State.IDLE) return -1;
        generation++;
        state = State.REQUESTED;
        deferredUncover = false;
        return generation;
    }

    public synchronized void requestFailed(long token) {
        if (generation == token && state == State.REQUESTED) {
            state = State.IDLE;
            deferredUncover = false;
        }
    }

    public synchronized Activation activate(long token) {
        if (generation != token || state != State.REQUESTED) return Activation.REJECTED;
        if (deferredUncover) {
            state = State.FINISH_REQUESTED;
            return Activation.FINISH_IMMEDIATELY;
        }
        state = State.ACTIVE;
        return Activation.ACTIVE;
    }

    public synchronized Uncover requestUncover() {
        if (state == State.IDLE) return Uncover.REJECTED;
        if (state == State.REQUESTED) {
            deferredUncover = true;
            return Uncover.DEFERRED;
        }
        if (state == State.FINISH_REQUESTED) return Uncover.ALREADY_FINISHING;
        state = State.FINISH_REQUESTED;
        return Uncover.FINISH_ACTIVE;
    }

    public synchronized boolean destroyed(long token) {
        if (generation != token || (state != State.ACTIVE
                && state != State.FINISH_REQUESTED)) return false;
        state = State.IDLE;
        deferredUncover = false;
        return true;
    }

    public synchronized String state() { return state.name(); }
    public synchronized long generation() { return generation; }
}
