package com.techrebbe.supernote.viewportprobe;

/**
 * Host-executable state seam used directly by the Android lifecycle callbacks.
 * STOPPED is sticky. Only a fresh, deliberate host launch gets a new admission.
 */
public final class DisplayProbeLifecycle {
    private enum State { STARTABLE, CREATING, ACTIVE, STOPPED }
    private State state;
    private boolean calibrationClaimed;

    public DisplayProbeLifecycle(boolean restoredInstance) {
        state = restoredInstance ? State.STOPPED : State.STARTABLE;
    }

    public boolean canCreate() { return state == State.STARTABLE; }
    public boolean isCreating() { return state == State.CREATING; }
    public boolean isActive() { return state == State.ACTIVE; }

    /** Atomically owns the one surface callback allowed to create a display. */
    public boolean onSurfaceReady() {
        if (!canCreate()) return false;
        state = State.CREATING;
        return true;
    }

    public void onDisplayCreated() {
        if (!isCreating()) throw new IllegalStateException("display creation was not admitted");
        state = State.ACTIVE;
    }

    public boolean onCalibrationAttached() {
        if (!isActive() || calibrationClaimed) return false;
        calibrationClaimed = true;
        return true;
    }

    /** Presentation-only callbacks cannot create, stop, or resurrect authority. */
    public void onConfigurationChanged() { /* state intentionally unchanged */ }
    public void onStateSaved() { /* this live instance remains unchanged */ }

    public void onDisplayCreateFailed() { stop(); }
    public void onSurfaceDestroyed() { stop(); }
    public void onDisplayReleased() { stop(); }
    public void onCalibrationEnded() { stop(); }
    public void onFailure() { stop(); }
    public void onActivityDestroyed() { stop(); }

    private void stop() { state = State.STOPPED; }
}
