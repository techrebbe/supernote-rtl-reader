package com.techrebbe.supernote.spreadprobe.v2;

/**
 * Versioned receipts for the three independent stock presentation layers.
 * Objects are identities: equality is deliberately never substituted for ==.
 */
public final class NativePresentationRestoreWitness {
    public enum Layer { BACKGROUND, INK, DIGEST }

    public static final class Token {
        public final long id;
        public final String documentId;
        public final long activityGeneration;
        public final long layoutGeneration;
        public final long reloadGeneration;
        public final int page;
        private final Object backgroundReceiver;
        private final Object inkReceiver;
        private final Object digestReceiver;
        private final Object oldBackground;
        private final Object oldInk;
        private final Object oldDigest;
        private long lastSignalGeneration;
        private int mask;
        private Object backgroundReplacement;
        private Object inkReplacement;
        private Object digestReplacement;
        private boolean pageReady;
        private boolean invalid;

        private Token(
            long id,
            SpreadSnapshot snapshot,
            Object backgroundReceiver,
            Object inkReceiver,
            Object digestReceiver,
            Object oldBackground,
            Object oldInk,
            Object oldDigest,
            long signalFloor,
            long reloadGeneration
        ) {
            this.id = id;
            this.documentId = snapshot.documentId;
            this.activityGeneration = snapshot.activityGeneration;
            this.layoutGeneration = snapshot.layoutGeneration;
            this.reloadGeneration = reloadGeneration;
            this.page = snapshot.activePageIndex;
            this.backgroundReceiver = backgroundReceiver;
            this.inkReceiver = inkReceiver;
            this.digestReceiver = digestReceiver;
            this.oldBackground = oldBackground;
            this.oldInk = oldInk;
            this.oldDigest = oldDigest;
            this.lastSignalGeneration = signalFloor;
        }
    }

    private long nextId = 1L;
    private Token current;

    public Token begin(
        SpreadSnapshot snapshot,
        Object backgroundReceiver,
        Object inkReceiver,
        Object digestReceiver,
        Object oldBackground,
        Object oldInk,
        Object oldDigest,
        long signalFloor,
        long reloadGeneration
    ) {
        if (current != null || snapshot == null || backgroundReceiver == null
            || inkReceiver == null || digestReceiver == null
            || oldBackground == null || oldInk == null || oldDigest == null
            || signalFloor < 0L || reloadGeneration <= 0L || nextId <= 0L) {
            throw new IllegalStateException("invalid stock restoration witness");
        }
        current = new Token(
            nextId++, snapshot, backgroundReceiver, inkReceiver,
            digestReceiver, oldBackground, oldInk, oldDigest, signalFloor,
            reloadGeneration
        );
        return current;
    }

    public boolean observe(
        Token token,
        Layer layer,
        long reloadGeneration,
        long signalGeneration,
        Object receiver,
        Object replacement,
        SpreadSnapshot observed
    ) {
        if (token == null || token != current || layer == null
            || observed == null || reloadGeneration != token.reloadGeneration
            || signalGeneration <= token.lastSignalGeneration
            || !token.documentId.equals(observed.documentId)
            || token.activityGeneration != observed.activityGeneration
            || token.layoutGeneration != observed.layoutGeneration
            || token.page != observed.activePageIndex) {
            if (token == current) token.invalid = true;
            return false;
        }
        Object expectedReceiver;
        Object oldBitmap;
        int bit;
        if (layer == Layer.BACKGROUND) {
            expectedReceiver = token.backgroundReceiver;
            oldBitmap = token.oldBackground;
            bit = 1;
        } else if (layer == Layer.INK) {
            expectedReceiver = token.inkReceiver;
            oldBitmap = token.oldInk;
            bit = 2;
        } else {
            expectedReceiver = token.digestReceiver;
            oldBitmap = token.oldDigest;
            bit = 4;
        }
        if (receiver != expectedReceiver || replacement == null
            || replacement == oldBitmap || (token.mask & bit) != 0) {
            token.invalid = true;
            return false;
        }
        token.lastSignalGeneration = signalGeneration;
        token.mask |= bit;
        if (layer == Layer.BACKGROUND) token.backgroundReplacement = replacement;
        else if (layer == Layer.INK) token.inkReplacement = replacement;
        else token.digestReplacement = replacement;
        return true;
    }

    /**
     * A stock layer triple is not a reload receipt by itself.  Completion also
     * requires the native Activity's page-ready callback for this exact reload
     * epoch and the current reader/presenter page pair.
     */
    public boolean observePageReady(
        Token token,
        long reloadGeneration,
        long signalGeneration,
        Object receiver,
        SpreadSnapshot observed,
        int presenterMarkPage
    ) {
        if (token == null || token != current || observed == null
            || token.pageReady || reloadGeneration != token.reloadGeneration
            || signalGeneration <= token.lastSignalGeneration
            || receiver != token.digestReceiver
            || !token.documentId.equals(observed.documentId)
            || token.activityGeneration != observed.activityGeneration
            || token.layoutGeneration != observed.layoutGeneration
            || token.page != observed.activePageIndex
            || presenterMarkPage != token.page + 1) {
            if (token == current) token.invalid = true;
            return false;
        }
        token.lastSignalGeneration = signalGeneration;
        token.pageReady = true;
        return true;
    }

    /** Exact identity proof that the acknowledged replacements remain installed. */
    public boolean installedLayersMatch(
        Token token,
        Object background,
        Object ink,
        Object digest
    ) {
        return token != null && token == current && !token.invalid
            && background != null && background == token.backgroundReplacement
            && ink != null && ink == token.inkReplacement
            && digest != null && digest == token.digestReplacement;
    }

    public boolean pageReadyObserved(Token token) {
        return token != null && token == current
            && !token.invalid && token.pageReady;
    }

    public boolean ready(Token token) {
        return token != null && token == current
            && !token.invalid && token.mask == 7 && token.pageReady;
    }

    public boolean finish(Token token) {
        if (!ready(token)) return false;
        current = null;
        return true;
    }

    public void abort() {
        current = null;
    }
}
