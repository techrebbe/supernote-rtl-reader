package com.techrebbe.supernote.layoutfencetrial;

import android.os.Handler;
import android.os.Looper;
import android.os.Process;
import android.os.SystemClock;
import android.os.Bundle;

import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/** Process-local identity and bounded event ring. No file or remote persistence. */
final class TrialProcess {
    interface MainWork<T> { T run(); }

    static final class Event {
        final long sequence;
        final long elapsedMs;
        final String name;
        final String detail;

        Event(long sequence, long elapsedMs, String name, String detail) {
            this.sequence = sequence;
            this.elapsedMs = elapsedMs;
            this.name = name;
            this.detail = detail;
        }
    }

    static final class Window {
        final int pid;
        final String incarnation;
        final long firstRetained;
        final long lastSequence;
        final Event[] events;

        Window(int pid, String incarnation, long firstRetained, long lastSequence,
                Event[] events) {
            this.pid = pid;
            this.incarnation = incarnation;
            this.firstRetained = firstRetained;
            this.lastSequence = lastSequence;
            this.events = events;
        }
    }

    static final class ArmInfo {
        final String token;
        final long deadlineElapsedMs;

        ArmInfo(String token, long deadlineElapsedMs) {
            this.token = token;
            this.deadlineElapsedMs = deadlineElapsedMs;
        }
    }

    private static final TrialProcess INSTANCE = new TrialProcess();
    private final int pid = Process.myPid();
    private final String incarnation = UUID.randomUUID().toString();
    private final long initializedElapsedMs = SystemClock.elapsedRealtime();
    private final Handler main = new Handler(Looper.getMainLooper());
    private final ArrayDeque<Event> events = new ArrayDeque<>();
    private long nextSequence = 1;
    private long nextActivitySerial = 1;
    private TrialActivity activity;
    private long activitySerial;
    private boolean everRegistered;
    private ArmProtocol.Pins ownerPins;
    private ArmProtocol arm;
    private final AtomicBoolean armFinished = new AtomicBoolean();

    private TrialProcess() { record("PROCESS_INIT", "synthetic-layout-fence-only"); }
    static TrialProcess get() { return INSTANCE; }
    int pid() { return pid; }
    String incarnation() { return incarnation; }

    synchronized long register(TrialActivity value) {
        requireMain();
        if (activity != null || everRegistered) {
            record("ACTIVITY_COLLISION", "replacement Activity in same process rejected");
            return -1;
        }
        activity = value;
        everRegistered = true;
        activitySerial = nextActivitySerial++;
        record("ACTIVITY_ADMITTED", "serial=" + activitySerial);
        return activitySerial;
    }

    synchronized void unregister(TrialActivity value) {
        requireMain();
        if (activity == value) {
            activity = null;
            record("ACTIVITY_RELEASED", "serial=" + activitySerial);
        }
    }

    synchronized TrialActivity activity() { return activity; }

    synchronized void publishPins(TrialActivity owner, String rootToken) {
        requireMain();
        if (activity != owner || ownerPins != null) {
            throw new IllegalStateException("identity already published or Activity lost");
        }
        ownerPins = new ArmProtocol.Pins(pid, incarnation, activitySerial,
                owner.getActivityToken(), rootToken);
        arm = new ArmProtocol(ownerPins);
        record("IDENTITY_PUBLISHED", "serial=" + activitySerial + " root=" + rootToken);
    }

    synchronized ArmInfo prearm(Bundle extras) {
        ArmProtocol.Pins supplied = pinsFromBundle(extras);
        if (activity == null || arm == null || !arm.prearm(supplied,
                UUID.randomUUID().toString(), SystemClock.elapsedRealtime())) return null;
        final long hardDeadline = arm.deadlineElapsedMs();
        final int exactPid = pid;
        Thread watchdog = new Thread(new Runnable() {
            @Override public void run() {
                // This thread never obtains TrialProcess, Activity, Handler or Frida locks.
                while (SystemClock.elapsedRealtime() < hardDeadline) {
                    long remaining = hardDeadline - SystemClock.elapsedRealtime();
                    try { Thread.sleep(Math.max(1, Math.min(remaining, 100))); }
                    catch (InterruptedException ignored) { }
                }
                if (!armFinished.get()) Process.killProcess(exactPid);
            }
        }, "layout-fence-prearm-watchdog");
        watchdog.setDaemon(true);
        try { watchdog.start(); }
        catch (RuntimeException startFailure) {
            arm.fail();
            return null;
        }
        record("PREARM", "hardDeadline=" + hardDeadline);
        return new ArmInfo(arm.armToken(), hardDeadline);
    }

    synchronized boolean claimRefresh(Bundle extras) {
        return arm != null && arm.claimRefresh(pinsFromBundle(extras),
                armTokenFromBundle(extras), SystemClock.elapsedRealtime());
    }

    synchronized boolean refreshDispatching(Bundle extras) {
        return arm != null && arm.state() == ArmProtocol.State.REFRESH_DISPATCHING
                && pinsMatch(extras) && arm.armToken().equals(armTokenFromBundle(extras))
                && SystemClock.elapsedRealtime() < arm.deadlineElapsedMs();
    }

    synchronized boolean completeRefresh(Bundle extras, String refreshToken) {
        if (arm == null) return false;
        boolean completed = arm.completeRefresh(pinsFromBundle(extras),
                armTokenFromBundle(extras), refreshToken, SystemClock.elapsedRealtime());
        if (!completed) arm.fail();
        return completed;
    }

    synchronized void failRefresh() {
        if (arm != null && (arm.state() == ArmProtocol.State.REFRESH_DISPATCHING
                || arm.state() == ArmProtocol.State.REFRESH_REQUESTED)) arm.fail();
    }

    synchronized boolean claimArmedCommand(Bundle extras) {
        return arm != null && arm.claimCommand(pinsFromBundle(extras),
                armTokenFromBundle(extras), refreshTokenFromBundle(extras),
                SystemClock.elapsedRealtime());
    }

    synchronized boolean commandDispatching(Bundle extras) {
        return arm != null && arm.state() == ArmProtocol.State.COMMAND_DISPATCHING
                && pinsMatch(extras) && arm.armToken().equals(armTokenFromBundle(extras))
                && arm.refreshToken().equals(refreshTokenFromBundle(extras))
                && SystemClock.elapsedRealtime() < arm.deadlineElapsedMs();
    }

    synchronized boolean trialWatchdogStarted(Bundle extras) {
        return arm != null && arm.trialWatchdogStarted(pinsFromBundle(extras),
                armTokenFromBundle(extras), SystemClock.elapsedRealtime());
    }

    synchronized boolean claimSentinel(String stage, Bundle extras) {
        return arm != null && arm.claimSentinel(stage, pinsFromBundle(extras),
                armTokenFromBundle(extras), SystemClock.elapsedRealtime());
    }

    synchronized boolean sentinelDispatching(String stage, Bundle extras) {
        if (arm == null || !pinsMatch(extras)
                || !arm.armToken().equals(armTokenFromBundle(extras))) return false;
        return ("after-disarm".equals(stage)
                && arm.state() == ArmProtocol.State.DISARM_SENTINEL_DISPATCHING)
                || ("after-unload".equals(stage)
                && arm.state() == ArmProtocol.State.UNLOAD_SENTINEL_DISPATCHING);
    }

    synchronized boolean completeSentinel(String stage, Bundle extras, boolean unchanged) {
        return arm != null && arm.completeSentinel(stage, pinsFromBundle(extras),
                armTokenFromBundle(extras), unchanged, SystemClock.elapsedRealtime());
    }

    synchronized long activeArmDeadlineElapsedMs(long nowElapsedMs) {
        return arm == null || armFinished.get() ? -1
                : arm.activeDeadlineElapsedMs(nowElapsedMs);
    }

    synchronized boolean finish(Bundle extras) {
        if (arm == null || !arm.finish(pinsFromBundle(extras),
                armTokenFromBundle(extras), SystemClock.elapsedRealtime())) return false;
        armFinished.set(true);
        record("PREARM_FINISHED", "after both post-revert sentinels");
        return true;
    }

    synchronized boolean abort(Bundle extras) {
        if (arm == null || !arm.abort(pinsFromBundle(extras),
                armTokenFromBundle(extras), SystemClock.elapsedRealtime())) return false;
        record("PREARM_ABORT", "terminal self-kill requested");
        return true;
    }

    synchronized boolean pinsMatch(Bundle extras) {
        return ownerPins != null && ownerPins.same(pinsFromBundle(extras));
    }

    private static ArmProtocol.Pins pinsFromBundle(Bundle extras) {
        if (extras == null) return null;
        try {
            return new ArmProtocol.Pins(extras.getInt("pid", -1),
                    extras.getString("incarnation"), extras.getLong("activitySerial", -1),
                    extras.getString("activityToken"), extras.getString("rootToken"));
        } catch (RuntimeException invalid) { return null; }
    }

    private static String armTokenFromBundle(Bundle extras) {
        return extras == null ? null : extras.getString("armToken");
    }

    private static String refreshTokenFromBundle(Bundle extras) {
        return extras == null ? null : extras.getString("refreshToken");
    }

    synchronized void record(String name, String detail) {
        if (name == null || name.isEmpty()) throw new IllegalArgumentException("event name");
        String bounded = detail == null ? "" : detail;
        if (bounded.length() > 240) bounded = bounded.substring(0, 240);
        events.addLast(new Event(nextSequence++, SystemClock.elapsedRealtime(),
                name, bounded));
        while (events.size() > TrialContract.EVENT_CAPACITY) events.removeFirst();
    }

    synchronized Window window(long afterSequence) {
        ArrayList<Event> selected = new ArrayList<>();
        for (Event event : events) {
            if (event.sequence > afterSequence) selected.add(event);
        }
        long first = events.isEmpty() ? nextSequence : events.getFirst().sequence;
        return new Window(pid, incarnation, first, nextSequence - 1,
                selected.toArray(new Event[selected.size()]));
    }

    synchronized JSONObject identityJson() throws JSONException {
        JSONObject json = new JSONObject();
        json.put("pid", pid);
        json.put("incarnation", incarnation);
        json.put("initializedElapsedMs", initializedElapsedMs);
        json.put("sampleElapsedMs", SystemClock.elapsedRealtime());
        json.put("activitySerial", activitySerial);
        json.put("activityPresent", activity != null);
        json.put("everRegistered", everRegistered);
        json.put("identityPublished", ownerPins != null);
        json.put("armState", arm == null ? "UNPUBLISHED" : arm.state().name());
        json.put("armDeadlineElapsedMs", arm == null ? 0 : arm.deadlineElapsedMs());
        json.put("armFinished", armFinished.get());
        json.put("eventFirstRetained", events.isEmpty() ? nextSequence
                : events.getFirst().sequence);
        json.put("eventLastSequence", nextSequence - 1);
        return json;
    }

    <T> T onMain(final MainWork<T> work) {
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
        })) throw new IllegalStateException("main dispatch rejected");
        try {
            if (!done.await(TrialContract.MAIN_DISPATCH_TIMEOUT_MS,
                    TimeUnit.MILLISECONDS)) {
                expired.set(true);
                record("MAIN_DISPATCH_TIMEOUT", "outcome unknown; no retry");
                throw new IllegalStateException("main dispatch timeout; outcome unknown");
            }
        } catch (InterruptedException exception) {
            expired.set(true);
            Thread.currentThread().interrupt();
            throw new IllegalStateException("main dispatch interrupted; outcome unknown",
                    exception);
        }
        if (error.get() != null) throw error.get();
        return answer.get();
    }

    private static void requireMain() {
        if (Looper.myLooper() != Looper.getMainLooper()) {
            throw new IllegalStateException("Activity ownership requires main Looper");
        }
    }
}
