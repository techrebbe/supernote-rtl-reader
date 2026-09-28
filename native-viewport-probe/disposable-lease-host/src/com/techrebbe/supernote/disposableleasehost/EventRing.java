package com.techrebbe.supernote.disposableleasehost;

/** Process-local bounded evidence. Sequence numbers never reset within a PID. */
public final class EventRing {
    public static final class Event {
        public final long sequence;
        public final long elapsedMs;
        public final String name;
        public final String detail;

        private Event(long sequence, long elapsedMs, String name, String detail) {
            this.sequence = sequence;
            this.elapsedMs = elapsedMs;
            this.name = name;
            this.detail = detail;
        }
    }

    private final Event[] entries;
    private int head;
    private int count;
    private long nextSequence = 1;

    public EventRing(int capacity) {
        if (capacity < 1 || capacity > 4096) {
            throw new IllegalArgumentException("bounded capacity required");
        }
        entries = new Event[capacity];
    }

    public synchronized Event append(long elapsedMs, String name, String detail) {
        if (elapsedMs < 0 || name == null || name.length() == 0) {
            throw new IllegalArgumentException("invalid event");
        }
        Event event = new Event(nextSequence++, elapsedMs,
                clip(name, 48), clip(detail == null ? "" : detail, 160));
        if (count == entries.length) {
            entries[head] = event;
            head = (head + 1) % entries.length;
        } else {
            entries[(head + count) % entries.length] = event;
            count++;
        }
        return event;
    }

    public synchronized Event[] after(long sequence) {
        Event[] result = new Event[count];
        int selected = 0;
        for (int i = 0; i < count; i++) {
            Event event = entries[(head + i) % entries.length];
            if (event.sequence > sequence) {
                result[selected++] = event;
            }
        }
        Event[] exact = new Event[selected];
        System.arraycopy(result, 0, exact, 0, selected);
        return exact;
    }

    public synchronized long firstRetainedSequence() {
        return count == 0 ? nextSequence : entries[head].sequence;
    }

    public synchronized long lastSequence() { return nextSequence - 1; }
    public synchronized int size() { return count; }
    public int capacity() { return entries.length; }

    private static String clip(String text, int max) {
        return text.length() <= max ? text : text.substring(0, max);
    }
}
