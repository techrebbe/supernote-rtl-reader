package com.techrebbe.supernote.virtualspread;

/**
 * Monotonic, session-bound fence for live native-page publications.
 *
 * The provider owns the record itself; this class keeps the lifecycle rule
 * host-testable without Android framework classes.
 */
public final class NativeViewportGenerationFence {
    private Object session;
    private long generation = -1L;

    public void begin(Object requestedSession, long requestedGeneration) {
        requireSession(requestedSession);
        if (requestedGeneration < 0L) {
            throw new IllegalArgumentException(
                "page-load generation is invalid"
            );
        }
        if (session != null
            && (session == requestedSession
                || session.equals(requestedSession))) {
            if (requestedGeneration <= generation) {
                throw new IllegalArgumentException(
                    "page-load generation is not newer"
                );
            }
        }
        session = requestedSession;
        generation = requestedGeneration;
    }

    public boolean accepts(
        Object requestedSession,
        long requestedGeneration
    ) {
        return requestedSession != null
            && session != null
            && (session == requestedSession
                || session.equals(requestedSession))
            && requestedGeneration == generation;
    }

    public boolean clear(Object requestedSession) {
        if (session == null) {
            return true;
        }
        if (requestedSession == null
            || (session != requestedSession
                && !session.equals(requestedSession))) {
            return false;
        }
        session = null;
        generation = -1L;
        return true;
    }

    private static void requireSession(Object requestedSession) {
        if (requestedSession == null) {
            throw new IllegalArgumentException("session is required");
        }
    }
}
