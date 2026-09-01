package com.techrebbe.supernote.spreadprobe.v2;

import java.util.Objects;
import java.util.concurrent.atomic.AtomicLong;

/** Serialized, fail-closed writer ownership transfer. */
public final class ActivationMachine {
    public enum State {
        IDLE,
        SOURCE_SAVING,
        TARGET_LOADING,
        TARGET_VERIFYING,
        TARGET_PUBLISHING,
        DRAINING_CONTACT,
        REPLAYING,
        ACTIVE,
        ROLLING_BACK,
        ROLLBACK_PUBLISHING,
        DISABLED
    }

    public enum CompletionMode {
        IMMEDIATE,
        DRAIN_CONTACT,
        REPLAY_INPUT
    }

    public static final class Token {
        public final long id;
        public final String documentId;
        public final long activityGeneration;
        public final long layoutGeneration;
        public final int sourcePage;
        public final int targetPage;
        public final CompletionMode completionMode;

        private Token(
            long id,
            SpreadSnapshot snapshot,
            int targetPage,
            CompletionMode completionMode
        ) {
            this.id = id;
            this.documentId = snapshot.documentId;
            this.activityGeneration = snapshot.activityGeneration;
            this.layoutGeneration = snapshot.layoutGeneration;
            this.sourcePage = snapshot.activePageIndex;
            this.targetPage = targetPage;
            this.completionMode = Objects.requireNonNull(
                completionMode,
                "completionMode"
            );
        }
    }

    public static final class Status {
        public final State state;
        public final int activePage;
        public final boolean writerEnabled;
        public final long transactionId;

        private Status(
            State state,
            int activePage,
            boolean writerEnabled,
            long transactionId
        ) {
            this.state = state;
            this.activePage = activePage;
            this.writerEnabled = writerEnabled;
            this.transactionId = transactionId;
        }
    }

    private final AtomicLong ids = new AtomicLong(1L);
    private State state = State.IDLE;
    private int activePage = -1;
    private boolean writerEnabled;
    private Token current;
    private String documentId;
    private long activityGeneration = -1L;
    private long layoutGeneration = -1L;
    private NativeAuthority verifiedAuthority;

    public synchronized void initialize(SpreadSnapshot snapshot) {
        Objects.requireNonNull(snapshot, "snapshot");
        if (current != null) {
            throw new IllegalStateException("cannot initialize during activation");
        }
        activePage = snapshot.activePageIndex;
        writerEnabled = snapshot.writerReady;
        documentId = snapshot.documentId;
        activityGeneration = snapshot.activityGeneration;
        layoutGeneration = snapshot.layoutGeneration;
        state = snapshot.writerReady ? State.ACTIVE : State.IDLE;
    }

    public synchronized boolean reconcileStableSnapshot(SpreadSnapshot snapshot) {
        Objects.requireNonNull(snapshot, "snapshot");
        if (current != null || state == State.DISABLED
            || documentId == null
            || !documentId.equals(snapshot.documentId)
            || activityGeneration != snapshot.activityGeneration
            || snapshot.layoutGeneration <= layoutGeneration) {
            return false;
        }
        activePage = snapshot.activePageIndex;
        writerEnabled = snapshot.writerReady;
        layoutGeneration = snapshot.layoutGeneration;
        state = snapshot.writerReady ? State.ACTIVE : State.IDLE;
        return true;
    }

    public synchronized Token begin(
        SpreadSnapshot snapshot,
        int targetPage,
        CompletionMode completionMode
    ) {
        Objects.requireNonNull(snapshot, "snapshot");
        if (current != null || state == State.DISABLED
            || targetPage == snapshot.activePageIndex
            || snapshot.slotForPage(targetPage) == null
            || activePage != snapshot.activePageIndex
            || documentId == null
            || !documentId.equals(snapshot.documentId)
            || activityGeneration != snapshot.activityGeneration
            || layoutGeneration != snapshot.layoutGeneration
            || !writerEnabled) {
            return null;
        }
        current = new Token(
            ids.getAndIncrement(),
            snapshot,
            targetPage,
            completionMode
        );
        state = State.SOURCE_SAVING;
        writerEnabled = false;
        return current;
    }

    public synchronized boolean sourceSaved(Token token) {
        return advance(token, State.SOURCE_SAVING, State.TARGET_LOADING);
    }

    public synchronized boolean targetLoaded(Token token, int loadedPage) {
        if (!owns(token) || state != State.TARGET_LOADING
            || loadedPage != token.targetPage) {
            return false;
        }
        state = State.TARGET_VERIFYING;
        return true;
    }

    public synchronized boolean targetVerified(
        Token token,
        NativeAuthority authority
    ) {
        if (!owns(token) || state != State.TARGET_VERIFYING
            || authority == null
            || !authority.documentId.equals(token.documentId)
            || authority.activityGeneration != token.activityGeneration
            || authority.layoutGeneration <= token.layoutGeneration
            || authority.pageIndex != token.targetPage
            || authority.markPageIndex != token.targetPage) {
            return false;
        }
        activePage = token.targetPage;
        verifiedAuthority = authority;
        state = State.TARGET_PUBLISHING;
        return true;
    }

    public synchronized boolean targetPublished(
        Token token,
        SpreadSnapshot snapshot
    ) {
        if (!owns(token) || state != State.TARGET_PUBLISHING
            || snapshot == null || !snapshot.writerReady
            || snapshot.activePageIndex != token.targetPage
            || verifiedAuthority == null
            || !verifiedAuthority.equals(snapshot.writerAuthority)
            || !snapshot.documentId.equals(token.documentId)
            || snapshot.activityGeneration != token.activityGeneration
            || snapshot.layoutGeneration != verifiedAuthority.layoutGeneration) {
            return false;
        }
        layoutGeneration = snapshot.layoutGeneration;
        if (token.completionMode == CompletionMode.REPLAY_INPUT) {
            state = State.REPLAYING;
        } else if (token.completionMode == CompletionMode.DRAIN_CONTACT) {
            state = State.DRAINING_CONTACT;
        } else {
            state = State.ACTIVE;
            writerEnabled = true;
            current = null;
            verifiedAuthority = null;
        }
        return true;
    }

    public synchronized boolean contactDrained(
        Token token,
        NativeAuthority authority
    ) {
        if (!owns(token) || state != State.DRAINING_CONTACT
            || authority == null || verifiedAuthority == null
            || !verifiedAuthority.equals(authority)) {
            return false;
        }
        state = State.ACTIVE;
        writerEnabled = true;
        current = null;
        verifiedAuthority = null;
        return true;
    }

    public synchronized boolean replayComplete(
        Token token,
        NativeAuthority authority
    ) {
        if (!owns(token) || state != State.REPLAYING
            || authority == null || verifiedAuthority == null
            || !verifiedAuthority.equals(authority)) {
            return false;
        }
        state = State.ACTIVE;
        writerEnabled = true;
        current = null;
        verifiedAuthority = null;
        return true;
    }

    public synchronized boolean fail(Token token) {
        if (!owns(token) || state == State.ROLLING_BACK
            || state == State.DISABLED) {
            return false;
        }
        state = State.ROLLING_BACK;
        writerEnabled = false;
        verifiedAuthority = null;
        return true;
    }

    public synchronized boolean rollbackVerified(
        Token token,
        NativeAuthority authority
    ) {
        if (!owns(token) || state != State.ROLLING_BACK
            || authority == null
            || !authority.documentId.equals(token.documentId)
            || authority.activityGeneration != token.activityGeneration
            || authority.layoutGeneration <= token.layoutGeneration
            || authority.pageIndex != token.sourcePage
            || authority.markPageIndex != token.sourcePage) {
            return false;
        }
        activePage = token.sourcePage;
        verifiedAuthority = authority;
        state = State.ROLLBACK_PUBLISHING;
        return true;
    }

    public synchronized boolean rollbackPublished(
        Token token,
        SpreadSnapshot snapshot
    ) {
        if (!owns(token) || state != State.ROLLBACK_PUBLISHING
            || snapshot == null || !snapshot.writerReady
            || snapshot.activePageIndex != token.sourcePage
            || verifiedAuthority == null
            || !verifiedAuthority.equals(snapshot.writerAuthority)
            || !snapshot.documentId.equals(token.documentId)
            || snapshot.activityGeneration != token.activityGeneration
            || snapshot.layoutGeneration != verifiedAuthority.layoutGeneration) {
            return false;
        }
        layoutGeneration = snapshot.layoutGeneration;
        state = State.ACTIVE;
        writerEnabled = true;
        current = null;
        verifiedAuthority = null;
        return true;
    }

    public synchronized boolean rollbackFailed(Token token) {
        if (!owns(token) || (state != State.ROLLING_BACK
            && state != State.ROLLBACK_PUBLISHING)) {
            return false;
        }
        state = State.DISABLED;
        writerEnabled = false;
        current = null;
        verifiedAuthority = null;
        return true;
    }

    public synchronized void retire() {
        current = null;
        activePage = -1;
        writerEnabled = false;
        documentId = null;
        activityGeneration = -1L;
        layoutGeneration = -1L;
        verifiedAuthority = null;
        state = State.DISABLED;
    }

    public synchronized Status status() {
        return new Status(
            state,
            activePage,
            writerEnabled,
            current == null ? -1L : current.id
        );
    }

    private boolean advance(Token token, State expected, State next) {
        if (!owns(token) || state != expected) {
            return false;
        }
        state = next;
        return true;
    }

    private boolean owns(Token token) {
        return token != null && current == token;
    }
}
