package com.techrebbe.supernote.spreadprobe.v2;

import java.util.Objects;

/**
 * Owner-thread witness for one presenter save crossing the native
 * SuperNoteNote.saveMarkData boundary.
 */
public final class NativeSaveWitness {
    public static final class Token {
        private final long id;

        private Token(long id) {
            this.id = id;
        }
    }

    private final long ownerThreadId = Thread.currentThread().getId();
    private long nextId = 1L;
    private Attempt current;

    public Token begin(
        Object noteIdentity,
        String markPath,
        int oneBasedPage,
        boolean dirty
    ) {
        assertOwnerThread();
        if (current != null || noteIdentity == null || markPath == null
            || markPath.isEmpty() || oneBasedPage <= 0 || nextId <= 0L) {
            throw new IllegalStateException("invalid or overlapping native save");
        }
        Token token = new Token(nextId++);
        current = new Attempt(
            token,
            noteIdentity,
            markPath,
            oneBasedPage,
            dirty
        );
        return token;
    }

    public void observe(
        Object noteIdentity,
        String markPath,
        int oneBasedPage,
        boolean cleanTrail,
        boolean nativeResult
    ) {
        assertOwnerThread();
        Attempt attempt = current;
        if (attempt == null) return;
        if (attempt.observed || attempt.noteIdentity != noteIdentity
            || !attempt.markPath.equals(markPath)
            || attempt.oneBasedPage != oneBasedPage || !cleanTrail) {
            attempt.invalid = true;
            return;
        }
        attempt.observed = true;
        attempt.nativeResult = nativeResult;
    }

    public boolean finish(Token token) {
        assertOwnerThread();
        Attempt attempt = requireCurrent(token);
        current = null;
        if (attempt.invalid) return false;
        if (attempt.dirty) {
            return attempt.observed && attempt.nativeResult;
        }
        return !attempt.observed;
    }

    public void abort(Token token) {
        assertOwnerThread();
        requireCurrent(token);
        current = null;
    }

    public boolean active() {
        assertOwnerThread();
        return current != null;
    }

    private Attempt requireCurrent(Token token) {
        if (token == null || current == null || current.token != token) {
            throw new IllegalStateException("stale native save witness token");
        }
        return current;
    }

    private void assertOwnerThread() {
        if (Thread.currentThread().getId() != ownerThreadId) {
            throw new IllegalStateException(
                "native save witness used from a foreign thread"
            );
        }
    }

    private static final class Attempt {
        final Token token;
        final Object noteIdentity;
        final String markPath;
        final int oneBasedPage;
        final boolean dirty;
        boolean observed;
        boolean nativeResult;
        boolean invalid;

        Attempt(
            Token token,
            Object noteIdentity,
            String markPath,
            int oneBasedPage,
            boolean dirty
        ) {
            this.token = Objects.requireNonNull(token, "token");
            this.noteIdentity = noteIdentity;
            this.markPath = markPath;
            this.oneBasedPage = oneBasedPage;
            this.dirty = dirty;
        }
    }
}
