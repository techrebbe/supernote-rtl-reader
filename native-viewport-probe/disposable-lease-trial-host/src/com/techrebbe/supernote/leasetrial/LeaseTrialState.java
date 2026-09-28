package com.techrebbe.supernote.leasetrial;

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

/** Process-local identity and bounded evidence; separate from the existing host. */
public final class LeaseTrialState {
    public interface MainWork<T> { T run(); }

    public static final class Event {
        public final long sequence;
        public final long elapsedMs;
        public final String name;
        public final String detail;

        Event(long sequence, long elapsedMs, String name, String detail) {
            this.sequence = sequence;
            this.elapsedMs = elapsedMs;
            this.name = name;
            this.detail = detail;
        }
    }

    public static final class Window {
        public final int pid;
        public final String incarnation;
        public final long firstRetained;
        public final long lastSequence;
        public final Event[] events;

        Window(int pid, String incarnation, long firstRetained, long lastSequence,
                Event[] events) {
            this.pid = pid;
            this.incarnation = incarnation;
            this.firstRetained = firstRetained;
            this.lastSequence = lastSequence;
            this.events = events;
        }
    }

    private static final LeaseTrialState INSTANCE = new LeaseTrialState();
    private static final long MAIN_TIMEOUT_MS = 3000;
    private final int pid = Process.myPid();
    private final String incarnation = UUID.randomUUID().toString();
    private final long initializedElapsedMs = SystemClock.elapsedRealtime();
    private final Handler main = new Handler(Looper.getMainLooper());
    private final ArrayDeque<Event> events = new ArrayDeque<>();
    private long nextSequence = 1;
    private long nextActivitySerial = 1;
    private LeaseTrialActivity activity;
    private long activitySerial;

    private LeaseTrialState() { record("PROCESS_INIT", "synthetic-no-child-only"); }
    public static LeaseTrialState get() { return INSTANCE; }

    public synchronized long register(LeaseTrialActivity value) {
        requireMain();
        if (activity != null) {
            record("ACTIVITY_COLLISION", "second live activity rejected");
            return -1;
        }
        activity = value;
        activitySerial = nextActivitySerial++;
        record("ACTIVITY_ADMITTED", "serial=" + activitySerial);
        return activitySerial;
    }

    public synchronized void unregister(LeaseTrialActivity value) {
        requireMain();
        if (activity == value) {
            activity = null;
            record("ACTIVITY_RELEASED", "serial=" + activitySerial);
        }
    }

    public synchronized LeaseTrialActivity activity() { return activity; }

    public synchronized void record(String name, String detail) {
        if (name == null || name.isEmpty()) throw new IllegalArgumentException("event name");
        String bounded = detail == null ? "" : detail;
        if (bounded.length() > 240) bounded = bounded.substring(0, 240);
        events.addLast(new Event(nextSequence++, SystemClock.elapsedRealtime(),
                name, bounded));
        while (events.size() > LeaseTrialContract.EVENT_CAPACITY) events.removeFirst();
    }

    public synchronized Window window(long after) {
        ArrayList<Event> selected = new ArrayList<>();
        for (Event event : events) if (event.sequence > after) selected.add(event);
        long first = events.isEmpty() ? nextSequence : events.getFirst().sequence;
        return new Window(pid, incarnation, first, nextSequence - 1,
                selected.toArray(new Event[selected.size()]));
    }

    public synchronized JSONObject identityJson() throws JSONException {
        JSONObject result = new JSONObject();
        result.put("pid", pid);
        result.put("incarnation", incarnation);
        result.put("initializedElapsedMs", initializedElapsedMs);
        result.put("sampleElapsedMs", SystemClock.elapsedRealtime());
        result.put("activitySerial", activitySerial);
        result.put("activityPresent", activity != null);
        result.put("eventFirstRetained", events.isEmpty() ? nextSequence
                : events.getFirst().sequence);
        result.put("eventLastSequence", nextSequence - 1);
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
        })) throw new IllegalStateException("main dispatch rejected");
        try {
            if (!done.await(MAIN_TIMEOUT_MS, TimeUnit.MILLISECONDS)) {
                expired.set(true);
                record("MAIN_DISPATCH_TIMEOUT", "command outcome unknown");
                throw new IllegalStateException("main dispatch timeout; outcome unknown");
            }
        } catch (InterruptedException exception) {
            expired.set(true);
            Thread.currentThread().interrupt();
            throw new IllegalStateException("main dispatch interrupted; outcome unknown", exception);
        }
        if (error.get() != null) throw error.get();
        return answer.get();
    }

    private static void requireMain() {
        if (Looper.myLooper() != Looper.getMainLooper()) {
            throw new IllegalStateException("activity admission requires main Looper");
        }
    }
}
