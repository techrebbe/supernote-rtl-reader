package com.techrebbe.supernote.viewportprobe;

/** STOPPED is sticky. Only a fresh, deliberate host launch gets a new admission. */
public final class DisplayProbeLifecycle {
    private enum State { STARTABLE, ACTIVE, STOPPED }
    private State state;
    private boolean calibrationClaimed;
    public DisplayProbeLifecycle(boolean restoredInstance) {
        state = restoredInstance ? State.STOPPED : State.STARTABLE;
    }
    public boolean canCreate() { return state == State.STARTABLE; }
    public boolean isActive() { return state == State.ACTIVE; }
    public boolean claimCalibration() {
        if (!isActive() || calibrationClaimed) return false;
        calibrationClaimed = true;
        return true;
    }
    public void activate() {
        if (!canCreate()) throw new IllegalStateException("explicit cold restart required");
        state = State.ACTIVE;
    }
    public void stop() { state = State.STOPPED; }
}
