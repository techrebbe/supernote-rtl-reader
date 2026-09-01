package com.techrebbe.supernote.spreadprobe.v2;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Bounded immutable-sample buffer used only while writer ownership changes. */
public final class GestureBuffer {
    public enum Action { DOWN, MOVE, UP, CANCEL }

    public static final class Sample {
        public final long eventTimeMs;
        public final Action action;
        public final double x;
        public final double y;
        public final double pressure;

        public Sample(
            long eventTimeMs,
            Action action,
            double x,
            double y,
            double pressure
        ) {
            if (eventTimeMs < 0 || action == null || !Double.isFinite(x)
                || !Double.isFinite(y) || !Double.isFinite(pressure)
                || pressure < 0.0) {
                throw new IllegalArgumentException("invalid buffered sample");
            }
            this.eventTimeMs = eventTimeMs;
            this.action = action;
            this.x = x;
            this.y = y;
            this.pressure = pressure;
        }
    }

    private static final int ESTIMATED_BYTES_PER_SAMPLE = 48;

    private final long tokenId;
    private final int maxSamples;
    private final int maxBytes;
    private final long maxDurationMs;
    private final List<Sample> samples = new ArrayList<>();
    private long firstEventTimeMs = -1L;
    private long lastEventTimeMs = -1L;
    private boolean terminal;
    private boolean failed;

    public GestureBuffer(
        long tokenId,
        int maxSamples,
        int maxBytes,
        long maxDurationMs
    ) {
        if (tokenId <= 0 || maxSamples < 2
            || maxBytes < 2 * ESTIMATED_BYTES_PER_SAMPLE
            || maxDurationMs <= 0) {
            throw new IllegalArgumentException("invalid gesture buffer bounds");
        }
        this.tokenId = tokenId;
        this.maxSamples = maxSamples;
        this.maxBytes = maxBytes;
        this.maxDurationMs = maxDurationMs;
    }

    public synchronized boolean append(long expectedTokenId, Sample sample) {
        if (expectedTokenId != tokenId || sample == null || terminal || failed) {
            return false;
        }
        if (samples.isEmpty()) {
            if (sample.action != Action.DOWN) {
                return fail();
            }
            firstEventTimeMs = sample.eventTimeMs;
        } else if (sample.action == Action.DOWN
            || sample.eventTimeMs < lastEventTimeMs) {
            return fail();
        }
        int prospectiveCount = samples.size() + 1;
        if (prospectiveCount > maxSamples
            || prospectiveCount * ESTIMATED_BYTES_PER_SAMPLE > maxBytes
            || sample.eventTimeMs - firstEventTimeMs > maxDurationMs) {
            return fail();
        }
        samples.add(sample);
        lastEventTimeMs = sample.eventTimeMs;
        terminal = sample.action == Action.UP || sample.action == Action.CANCEL;
        return true;
    }

    public synchronized List<Sample> immutableSamples() {
        return Collections.unmodifiableList(new ArrayList<>(samples));
    }

    public synchronized boolean isReplayable() {
        return !failed && terminal && !samples.isEmpty()
            && samples.get(0).action == Action.DOWN
            && samples.get(samples.size() - 1).action == Action.UP;
    }

    public synchronized boolean isFailed() {
        return failed;
    }

    private boolean fail() {
        failed = true;
        terminal = true;
        samples.clear();
        return false;
    }
}
