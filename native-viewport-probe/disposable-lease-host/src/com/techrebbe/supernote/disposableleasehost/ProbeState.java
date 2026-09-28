package com.techrebbe.supernote.disposableleasehost;

import android.content.Intent;
import android.os.Handler;
import android.os.Looper;
import android.os.Process;
import android.os.SystemClock;

import org.json.JSONException;
import org.json.JSONObject;

import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/** Process-wide evidence retained by Android/app classes, not a Frida script. */
public final class ProbeState {
    public interface MainWork<T> { T run(); }
    public static final String COVER_GENERATION_EXTRA = "cover_generation";

    public static final class EvidenceWindow {
        public final int pid;
        public final String incarnation;
        public final ProbeLedger.Snapshot ledger;

        EvidenceWindow(int pid, String incarnation, ProbeLedger.Snapshot ledger) {
            this.pid = pid;
            this.incarnation = incarnation;
            this.ledger = ledger;
        }
    }

    private static final ProbeState INSTANCE = new ProbeState();
    private static final long MAIN_DISPATCH_TIMEOUT_MS = 5000;

    private final int pid = Process.myPid();
    private final long initializationElapsedRealtimeMs = SystemClock.elapsedRealtime();
    private final long initializationWallMs = System.currentTimeMillis();
    private final String incarnation = UUID.randomUUID().toString();
    private final ProbeLedger ledger = new ProbeLedger(ProbeContract.EVENT_CAPACITY);
    private final ActivityAdmission admission = new ActivityAdmission();
    private final CoverGate coverGate = new CoverGate();
    private final Handler main = new Handler(Looper.getMainLooper());
    private CoverActivity cover;

    private ProbeState() {
        record("PROCESS_INIT", "pid=" + pid + " incarnation=" + incarnation);
    }

    public static ProbeState get() { return INSTANCE; }

    public synchronized long register(ProbeActivity current, ProbeActivity.ProbeRoot root) {
        requireMainThread();
        if (!"IDLE".equals(coverGate.state())) {
            record("ACTIVITY_ADMISSION_REJECTED", "cover still active or pending");
            return -1;
        }
        long serial = admission.claim(current, root);
        record(serial < 0 ? "ACTIVITY_ADMISSION_COLLISION" : "ACTIVITY_ADMITTED",
                "serial=" + serial + " root=" + System.identityHashCode(root));
        return serial;
    }

    public synchronized void unregister(ProbeActivity current) {
        requireMainThread();
        if (admission.release(current)) record("ACTIVITY_RELEASED", "");
    }

    public synchronized ProbeActivity activity() {
        ProbeActivity current = (ProbeActivity) admission.activity();
        return current != null && current.getProbeRoot() == admission.root()
                ? current : null;
    }

    public boolean requestCover(ProbeActivity requester) {
        requireMainThread();
        final long generation;
        synchronized (this) {
            if (activity() != requester) return false;
            generation = coverGate.requestCover();
            if (generation < 0) {
                record("COVER_COLLISION", coverGate.state());
                return false;
            }
            record("COVER_REQUEST", "generation=" + generation);
        }
        try {
            Intent intent = new Intent(requester, CoverActivity.class);
            intent.putExtra(COVER_GENERATION_EXTRA, generation);
            requester.startActivity(intent);
            return true;
        } catch (RuntimeException exception) {
            synchronized (this) {
                coverGate.requestFailed(generation);
                record("COVER_LAUNCH_FAILED", exception.getClass().getSimpleName());
            }
            return false;
        }
    }

    public synchronized CoverGate.Activation registerCover(CoverActivity current,
            long generation) {
        requireMainThread();
        CoverGate.Activation result = coverGate.activate(generation);
        if (result != CoverGate.Activation.REJECTED) cover = current;
        record("COVER_ACTIVATE", "generation=" + generation + " result=" + result);
        return result;
    }

    public synchronized void unregisterCover(CoverActivity current, long generation) {
        requireMainThread();
        if (cover == current) {
            cover = null;
            boolean ended = coverGate.destroyed(generation);
            record(ended ? "COVER_DESTROYED" : "COVER_DESTROY_MISMATCH",
                    "generation=" + generation);
        }
    }

    public boolean uncover() {
        requireMainThread();
        final CoverGate.Uncover result;
        final CoverActivity current;
        synchronized (this) {
            result = coverGate.requestUncover();
            current = cover;
            record("UNCOVER_REQUEST", result.name());
        }
        if (result == CoverGate.Uncover.FINISH_ACTIVE) {
            if (current == null) throw new IllegalStateException("active cover missing");
            current.finish();
        }
        return result != CoverGate.Uncover.REJECTED;
    }

    public synchronized EventRing.Event record(String name, String detail) {
        return ledger.record(SystemClock.elapsedRealtime(), name, detail);
    }

    public synchronized EvidenceWindow evidenceWindow(long after) {
        return new EvidenceWindow(pid, incarnation, ledger.snapshot(after));
    }

    /** A separately loaded helper must call this app-primary ClassLoader slot. */
    public synchronized boolean claimLease(Object owner) {
        requireMainThread();
        ProbeActivity current = activity();
        if (current != null) current.getProbeRoot().invalidatePaintEvidence();
        return ledger.claim(SystemClock.elapsedRealtime(), owner);
    }

    public synchronized boolean releaseLease(Object owner) {
        requireMainThread();
        ProbeActivity current = activity();
        if (current != null) current.getProbeRoot().invalidatePaintEvidence();
        return ledger.release(SystemClock.elapsedRealtime(), owner);
    }

    public synchronized JSONObject identityJson() throws JSONException {
        ProbeLedger.Snapshot cut = ledger.snapshot(0);
        JSONObject result = new JSONObject();
        result.put("pid", pid);
        result.put("incarnation", incarnation);
        result.put("initializationElapsedRealtimeMs", initializationElapsedRealtimeMs);
        result.put("initializationWallMs", initializationWallMs);
        result.put("currentElapsedRealtimeMs", SystemClock.elapsedRealtime());
        result.put("eventFirstRetainedSequence", cut.firstRetainedSequence);
        result.put("eventLastSequence", cut.lastSequence);
        result.put("eventCapacity", cut.eventCapacity);
        result.put("leaseSlotOccupied", cut.slotOccupied);
        result.put("leaseSlotOwnerIdentityHash", cut.slotOwnerIdentityHash);
        result.put("leaseSlotOwnerClass", cut.slotOwnerClass);
        result.put("leaseSlotClaimCount", cut.slotClaimCount);
        result.put("activityLiveCount", admission.liveCount());
        result.put("activitySerial", admission.serial());
        result.put("activityRootIdentityHash", admission.root() == null ? 0
                : System.identityHashCode(admission.root()));
        result.put("activityAdmissionCollisions", admission.collisions());
        result.put("coverState", coverGate.state());
        result.put("coverGeneration", coverGate.generation());
        return result;
    }

    public <T> T onMain(final MainWork<T> work) {
        if (Looper.myLooper() == Looper.getMainLooper()) return work.run();
        final CountDownLatch done = new CountDownLatch(1);
        final AtomicBoolean expired = new AtomicBoolean();
        final AtomicReference<T> answer = new AtomicReference<>();
        final AtomicReference<RuntimeException> error = new AtomicReference<>();
        if (!main.post(new Runnable() {
            @Override public void run() {
                try {
                    if (!expired.get()) answer.set(work.run());
                } catch (RuntimeException exception) {
                    error.set(exception);
                } finally {
                    done.countDown();
                }
            }
        })) throw new IllegalStateException("main Looper unavailable");
        try {
            if (!done.await(MAIN_DISPATCH_TIMEOUT_MS, TimeUnit.MILLISECONDS)) {
                expired.set(true);
                record("MAIN_DISPATCH_TIMEOUT", "outcome-unknown-if-already-running");
                throw new IllegalStateException("main dispatch timeout; command outcome unknown");
            }
        } catch (InterruptedException exception) {
            expired.set(true);
            Thread.currentThread().interrupt();
            throw new IllegalStateException("main dispatch interrupted; outcome unknown", exception);
        }
        if (error.get() != null) throw error.get();
        return answer.get();
    }

    private static void requireMainThread() {
        if (Looper.myLooper() != Looper.getMainLooper()) {
            throw new IllegalStateException("lease slot requires main Looper");
        }
    }
}
