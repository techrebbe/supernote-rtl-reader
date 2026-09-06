package com.techrebbe.supernote.spreadprobe.v2;

import java.util.Objects;

/** Exact native objects that jointly prove which page owns the writer. */
public final class NativeAuthority {
    public final String documentId;
    public final long activityGeneration;
    public final long layoutGeneration;
    public final int pageIndex;
    public final long viewModelIdentity;
    public final long presenterIdentity;
    public final long noteIdentity;
    public final long drawPathIdentity;
    public final int markPageIndex;

    public NativeAuthority(
        String documentId,
        long activityGeneration,
        long layoutGeneration,
        int pageIndex,
        long viewModelIdentity,
        long presenterIdentity,
        long noteIdentity,
        long drawPathIdentity,
        int markPageIndex
    ) {
        this.documentId = requireDocumentId(documentId);
        if (activityGeneration <= 0 || layoutGeneration <= 0) {
            throw new IllegalArgumentException("generations must be positive");
        }
        if (pageIndex < 0 || markPageIndex != pageIndex) {
            throw new IllegalArgumentException("native page identities disagree");
        }
        if (viewModelIdentity == 0 || presenterIdentity == 0
            || noteIdentity == 0 || drawPathIdentity == 0) {
            throw new IllegalArgumentException("native component identity missing");
        }
        this.activityGeneration = activityGeneration;
        this.layoutGeneration = layoutGeneration;
        this.pageIndex = pageIndex;
        this.viewModelIdentity = viewModelIdentity;
        this.presenterIdentity = presenterIdentity;
        this.noteIdentity = noteIdentity;
        this.drawPathIdentity = drawPathIdentity;
        this.markPageIndex = markPageIndex;
    }

    public boolean matches(
        String expectedDocumentId,
        long expectedActivityGeneration,
        long expectedLayoutGeneration,
        int expectedPage
    ) {
        return documentId.equals(expectedDocumentId)
            && activityGeneration == expectedActivityGeneration
            && layoutGeneration == expectedLayoutGeneration
            && pageIndex == expectedPage
            && markPageIndex == expectedPage;
    }

    @Override
    public boolean equals(Object value) {
        if (!(value instanceof NativeAuthority)) {
            return false;
        }
        NativeAuthority other = (NativeAuthority) value;
        return documentId.equals(other.documentId)
            && activityGeneration == other.activityGeneration
            && layoutGeneration == other.layoutGeneration
            && pageIndex == other.pageIndex
            && viewModelIdentity == other.viewModelIdentity
            && presenterIdentity == other.presenterIdentity
            && noteIdentity == other.noteIdentity
            && drawPathIdentity == other.drawPathIdentity
            && markPageIndex == other.markPageIndex;
    }

    @Override
    public int hashCode() {
        return Objects.hash(
            documentId,
            activityGeneration,
            layoutGeneration,
            pageIndex,
            viewModelIdentity,
            presenterIdentity,
            noteIdentity,
            drawPathIdentity,
            markPageIndex
        );
    }

    private static String requireDocumentId(String value) {
        Objects.requireNonNull(value, "documentId");
        if (value.isEmpty()) {
            throw new IllegalArgumentException("documentId must not be empty");
        }
        return value;
    }
}
