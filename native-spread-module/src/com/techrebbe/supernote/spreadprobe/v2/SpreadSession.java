package com.techrebbe.supernote.spreadprobe.v2;

import java.util.concurrent.atomic.AtomicReference;

/** Sole in-memory authority for one injected DocumentActivity generation. */
public final class SpreadSession {
    private final AtomicReference<SpreadSnapshot> published =
        new AtomicReference<>();
    private final GestureRouter gestureRouter = new GestureRouter();
    private final ActivationMachine activationMachine = new ActivationMachine();
    private boolean initialized;

    public synchronized boolean publish(SpreadSnapshot next) {
        if (next == null) {
            return false;
        }
        SpreadSnapshot current = published.get();
        if (current != null) {
            if (!next.documentId.equals(current.documentId)
                || next.activityGeneration != current.activityGeneration
                || next.layoutGeneration <= current.layoutGeneration
                || gestureRouter.hasActiveGesture()) {
                return false;
            }
            ActivationMachine.Status status = activationMachine.status();
            if (status.state == ActivationMachine.State.DISABLED
                || status.transactionId > 0) {
                return false;
            }
        }
        if (!initialized) {
            activationMachine.initialize(next);
            initialized = true;
        } else if (activationMachine.status().transactionId < 0
            && !activationMachine.reconcileStableSnapshot(next)) {
            return false;
        }
        gestureRouter.retire();
        published.set(next);
        return true;
    }

    public synchronized boolean publishActivated(
        ActivationMachine.Token token,
        SpreadSnapshot next
    ) {
        if (!validNextSnapshot(next)
            || !activationMachine.targetPublished(token, next)) {
            return false;
        }
        // A drain-only pen contact can still be physically down when the
        // target becomes authoritative. Its DOWN-time route remains valid
        // until the matching UP/CANCEL; the controller retires it at that
        // terminal without synthesizing native pen samples.
        published.set(next);
        return true;
    }

    public synchronized boolean publishRollback(
        ActivationMachine.Token token,
        SpreadSnapshot next
    ) {
        if (!validNextSnapshot(next)
            || !activationMachine.rollbackPublished(token, next)) {
            return false;
        }
        gestureRouter.retire();
        published.set(next);
        return true;
    }

    public SpreadSnapshot snapshot() {
        return published.get();
    }

    public GestureRouter gestures() {
        return gestureRouter;
    }

    public ActivationMachine activation() {
        return activationMachine;
    }

    public synchronized void retire() {
        gestureRouter.retire();
        activationMachine.retire();
        published.set(null);
    }

    private boolean validNextSnapshot(SpreadSnapshot next) {
        SpreadSnapshot current = published.get();
        return next != null && current != null
            && next.documentId.equals(current.documentId)
            && next.activityGeneration == current.activityGeneration
            && next.layoutGeneration > current.layoutGeneration;
    }
}
