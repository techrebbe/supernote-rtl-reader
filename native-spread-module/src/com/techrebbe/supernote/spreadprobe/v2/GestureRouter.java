package com.techrebbe.supernote.spreadprobe.v2;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicLong;

/** Gesture-scoped routing. Classification is immutable after ACTION_DOWN. */
public final class GestureRouter {
    public enum Tool { FINGER, STYLUS, ERASER, UNKNOWN }
    public enum Route {
        NATIVE_CHROME,
        ACTIVE_DOCUMENT,
        ACTIVATE_AND_REPLAY_HIT,
        ACTIVATE_AND_DRAIN_PEN,
        BLOCKED
    }

    public static final class Token {
        public final long id;
        public final int pointerId;
        public final String documentId;
        public final long activityGeneration;
        public final long layoutGeneration;
        public final int sourcePageIndex;
        public final Tool tool;
        public final Route route;

        private Token(
            long id,
            int pointerId,
            SpreadSnapshot snapshot,
            int sourcePageIndex,
            Tool tool,
            Route route
        ) {
            this.id = id;
            this.pointerId = pointerId;
            this.documentId = snapshot.documentId;
            this.activityGeneration = snapshot.activityGeneration;
            this.layoutGeneration = snapshot.layoutGeneration;
            this.sourcePageIndex = sourcePageIndex;
            this.tool = tool;
            this.route = route;
        }
    }

    private final AtomicLong ids = new AtomicLong(1L);
    private Token current;

    public synchronized Token begin(
        SpreadSnapshot snapshot,
        int pointerId,
        double x,
        double y,
        Tool tool,
        List<RectD> visibleNativeChrome
    ) {
        Objects.requireNonNull(snapshot, "snapshot");
        Objects.requireNonNull(tool, "tool");
        if (pointerId < 0 || current != null) {
            throw new IllegalStateException("gesture already active or invalid pointer");
        }
        List<RectD> chrome = visibleNativeChrome == null
            ? Collections.<RectD>emptyList()
            : new ArrayList<>(visibleNativeChrome);
        Route route = Route.BLOCKED;
        int page = -1;
        for (RectD rect : chrome) {
            if (rect != null && rect.contains(x, y)) {
                route = Route.NATIVE_CHROME;
                break;
            }
        }
        if (route != Route.NATIVE_CHROME) {
            PageSlot slot = snapshot.slotAt(x, y);
            if (slot != null) {
                page = slot.sourcePageIndex;
                boolean penOutsideContent =
                    (tool == Tool.STYLUS || tool == Tool.ERASER)
                    && !slot.containsContent(x, y);
                if (penOutsideContent) {
                    route = Route.BLOCKED;
                } else if (page == snapshot.activePageIndex
                    && snapshot.writerReady
                    && isDocumentTool(tool)) {
                    route = Route.ACTIVE_DOCUMENT;
                } else if (page >= 0 && snapshot.writerReady
                    && page != snapshot.activePageIndex
                    && tool == Tool.FINGER) {
                    route = Route.ACTIVATE_AND_REPLAY_HIT;
                } else if (page >= 0 && snapshot.writerReady
                    && page != snapshot.activePageIndex
                    && (tool == Tool.STYLUS || tool == Tool.ERASER)) {
                    route = Route.ACTIVATE_AND_DRAIN_PEN;
                }
            }
        }
        current = new Token(
            ids.getAndIncrement(),
            pointerId,
            snapshot,
            page,
            tool,
            route
        );
        return current;
    }

    public synchronized Token current(long tokenId, int pointerId) {
        if (current == null || current.id != tokenId
            || current.pointerId != pointerId) {
            return null;
        }
        return current;
    }

    public synchronized boolean authorityCurrent(
        Token token,
        SpreadSnapshot snapshot
    ) {
        return token != null && current == token && snapshot != null
            && token.documentId.equals(snapshot.documentId)
            && token.activityGeneration == snapshot.activityGeneration
            && token.layoutGeneration == snapshot.layoutGeneration
            && (token.sourcePageIndex < 0
                || snapshot.slotForPage(token.sourcePageIndex) != null);
    }

    public synchronized boolean finish(long tokenId, int pointerId) {
        if (current == null || current.id != tokenId
            || current.pointerId != pointerId) {
            return false;
        }
        current = null;
        return true;
    }

    public synchronized void retire() {
        current = null;
    }

    public synchronized boolean hasActiveGesture() {
        return current != null;
    }

    public Route classifyHover(
        SpreadSnapshot snapshot,
        double x,
        double y,
        Tool tool,
        List<RectD> visibleNativeChrome
    ) {
        Objects.requireNonNull(snapshot, "snapshot");
        if (tool != Tool.STYLUS && tool != Tool.ERASER) {
            return Route.BLOCKED;
        }
        if (visibleNativeChrome != null) {
            for (RectD rect : visibleNativeChrome) {
                if (rect != null && rect.contains(x, y)) {
                    return Route.NATIVE_CHROME;
                }
            }
        }
        PageSlot slot = snapshot.slotAt(x, y);
        if (slot == null) {
            return Route.BLOCKED;
        }
        if (!snapshot.writerReady || slot.isBlank()) {
            return Route.BLOCKED;
        }
        if (!slot.containsContent(x, y)) {
            return Route.BLOCKED;
        }
        return slot.sourcePageIndex == snapshot.activePageIndex
            ? Route.ACTIVE_DOCUMENT : Route.ACTIVATE_AND_DRAIN_PEN;
    }

    private static boolean isDocumentTool(Tool tool) {
        return tool == Tool.FINGER || tool == Tool.STYLUS
            || tool == Tool.ERASER;
    }
}
