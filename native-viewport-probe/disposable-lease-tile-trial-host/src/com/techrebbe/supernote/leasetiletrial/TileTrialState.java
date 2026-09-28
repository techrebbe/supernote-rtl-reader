package com.techrebbe.supernote.leasetiletrial;

import android.os.Handler;
import android.os.Looper;
import android.os.Process;
import android.os.SystemClock;

import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/** One process incarnation, one Activity admission, and bounded diagnostic events. */
final class TileTrialState {
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

    private static final TileTrialState INSTANCE = new TileTrialState();
    private static final int EVENT_CAPACITY = 256;
    private static final long MAIN_TIMEOUT_MS = 3000;
    private final int pid = Process.myPid();
    private final String incarnation = UUID.randomUUID().toString();
    private final long initializedElapsedMs = SystemClock.elapsedRealtime();
    private final Handler main = new Handler(Looper.getMainLooper());
    private final ArrayDeque<Event> events = new ArrayDeque<>();
    private long nextSequence = 1;
    private boolean activityEverAdmitted;
    private TileTrialActivity activity;

    private TileTrialState() { record("PROCESS_INIT", "synthetic-tile-only"); }
    static TileTrialState get() { return INSTANCE; }

    synchronized boolean admit(TileTrialActivity candidate) {
        requireMain();
        if (candidate == null || activityEverAdmitted) {
            record("ACTIVITY_COLLISION", "new Activity refused in same process");
            return false;
        }
        activityEverAdmitted = true;
        activity = candidate;
        record("ACTIVITY_ADMITTED", "");
        return true;
    }

    synchronized void release(TileTrialActivity candidate) {
        requireMain();
        if (activity == candidate) {
            activity = null;
            record("ACTIVITY_RELEASED", "no retry in this process");
        }
    }

    synchronized TileTrialActivity activity() { return activity; }

    synchronized boolean matchesProcess(int expectedPid, String expectedIncarnation) {
        return expectedPid == pid && incarnation.equals(expectedIncarnation);
    }

    synchronized void record(String name, String detail) {
        if (name == null || name.isEmpty()) throw new IllegalArgumentException("event name");
        String bounded = detail == null ? "" : detail;
        if (bounded.length() > 240) bounded = bounded.substring(0, 240);
        events.addLast(new Event(nextSequence++, SystemClock.elapsedRealtime(), name, bounded));
        while (events.size() > EVENT_CAPACITY) events.removeFirst();
    }

    synchronized Window window(long after) {
        ArrayList<Event> selected = new ArrayList<>();
        for (Event event : events) if (event.sequence > after) selected.add(event);
        return new Window(pid, incarnation,
                events.isEmpty() ? nextSequence : events.getFirst().sequence,
                nextSequence - 1, selected.toArray(new Event[selected.size()]));
    }

    synchronized JSONObject identityJson() throws JSONException {
        JSONObject value = new JSONObject();
        value.put("pid", pid);
        value.put("incarnation", incarnation);
        value.put("initializedElapsedMs", initializedElapsedMs);
        value.put("sampleElapsedMs", SystemClock.elapsedRealtime());
        value.put("activityEverAdmitted", activityEverAdmitted);
        value.put("activityPresent", activity != null);
        value.put("eventFirstRetained", events.isEmpty() ? nextSequence
                : events.getFirst().sequence);
        value.put("eventLastSequence", nextSequence - 1);
        return value;
    }

    <T> T onMain(final MainWork<T> work) {
        if (Looper.myLooper() == Looper.getMainLooper()) return work.run();
        final CountDownLatch done = new CountDownLatch(1);
        final AtomicBoolean timedOut = new AtomicBoolean();
        final AtomicReference<T> answer = new AtomicReference<>();
        final AtomicReference<RuntimeException> error = new AtomicReference<>();
        if (!main.post(new Runnable() {
            @Override public void run() {
                try {
                    if (!timedOut.get()) answer.set(work.run());
                } catch (RuntimeException exception) {
                    error.set(exception);
                } finally {
                    done.countDown();
                }
            }
        })) throw new IllegalStateException("main dispatch rejected");
        try {
            if (!done.await(MAIN_TIMEOUT_MS, TimeUnit.MILLISECONDS)) {
                timedOut.set(true);
                record("MAIN_TIMEOUT", "outcome unknown; inspect events, do not retry");
                throw new IllegalStateException("main timeout; command outcome unknown");
            }
        } catch (InterruptedException exception) {
            timedOut.set(true);
            Thread.currentThread().interrupt();
            throw new IllegalStateException("main interrupted; outcome unknown", exception);
        }
        if (error.get() != null) throw error.get();
        return answer.get();
    }

    private static void requireMain() {
        if (Looper.myLooper() != Looper.getMainLooper()) {
            throw new IllegalStateException("main Looper required");
        }
    }
}
