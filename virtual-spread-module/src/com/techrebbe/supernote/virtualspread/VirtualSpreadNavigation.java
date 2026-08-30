package com.techrebbe.supernote.virtualspread;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/** Pure, device-independent RTL half-page navigation. */
public final class VirtualSpreadNavigation {
    private static final double NOMAD_LANDSCAPE_ASPECT = 4.0 / 3.0;
    private static final double NOMAD_ASPECT_TOLERANCE = 1e-9;
    private static final double PDF_MIN_PAGE_DIMENSION = 3.0;
    private static final double PDF_MAX_PAGE_DIMENSION = 14400.0;

    /** Small synchronized access-order cache for process-lifetime metadata. */
    public static final class BoundedCache<K, V> {
        private final int maximumEntries;
        private final LinkedHashMap<K, V> values =
            new LinkedHashMap<K, V>(16, 0.75f, true);

        public BoundedCache(int maximumEntries) {
            if (maximumEntries <= 0) {
                throw new IllegalArgumentException(
                    "maximumEntries must be positive"
                );
            }
            this.maximumEntries = maximumEntries;
        }

        public synchronized V get(K key) {
            return values.get(key);
        }

        public synchronized V put(K key, V value) {
            Objects.requireNonNull(key, "key");
            Objects.requireNonNull(value, "value");
            V previous = values.put(key, value);
            while (values.size() > maximumEntries) {
                Map.Entry<K, V> eldest =
                    values.entrySet().iterator().next();
                values.remove(eldest.getKey());
            }
            return previous;
        }

        public synchronized V remove(K key) {
            return values.remove(key);
        }

        public synchronized boolean remove(K key, V expected) {
            Iterator<Map.Entry<K, V>> entries =
                values.entrySet().iterator();
            while (entries.hasNext()) {
                Map.Entry<K, V> entry = entries.next();
                if (Objects.equals(entry.getKey(), key)) {
                    if (!Objects.equals(entry.getValue(), expected)) {
                        return false;
                    }
                    entries.remove();
                    return true;
                }
            }
            return false;
        }

        public synchronized boolean replace(
            K key,
            V expected,
            V replacement
        ) {
            Objects.requireNonNull(replacement, "replacement");
            V current = values.get(key);
            if (!Objects.equals(current, expected)) {
                return false;
            }
            values.put(key, replacement);
            return true;
        }

        public synchronized int size() {
            return values.size();
        }
    }

    public enum Half {
        LEFT,
        RIGHT
    }

    public enum Kind {
        SAME_SPREAD,
        OTHER_SPREAD,
        BOUNDARY
    }

    /** Routing decision for Supernote's shared link/annotation callback. */
    public enum LinkRouting {
        NON_LINK,
        EXTERNAL,
        INTERNAL,
        BLOCKED
    }

    public static final class Spread {
        public final boolean hasLeft;
        public final boolean hasRight;

        public Spread(boolean hasLeft, boolean hasRight) {
            this.hasLeft = hasLeft;
            this.hasRight = hasRight;
        }

        public boolean has(Half half) {
            return half == Half.LEFT ? hasLeft : hasRight;
        }
    }

    public static final class Plan {
        public final Kind kind;
        public final int targetPage;
        public final Half targetHalf;

        private Plan(Kind kind, int targetPage, Half targetHalf) {
            this.kind = kind;
            this.targetPage = targetPage;
            this.targetHalf = targetHalf;
        }

        public static Plan same(int page, Half half) {
            return new Plan(Kind.SAME_SPREAD, page, half);
        }

        public static Plan other(int page, Half half) {
            return new Plan(Kind.OTHER_SPREAD, page, half);
        }

        public static Plan boundary(int page, Half half) {
            return new Plan(Kind.BOUNDARY, page, half);
        }
    }

    /** Enabled state for Supernote's physical previous/next buttons. */
    public static final class PageBarState {
        public final boolean previousEnabled;
        public final boolean nextEnabled;

        private PageBarState(
            boolean previousEnabled,
            boolean nextEnabled
        ) {
            this.previousEnabled = previousEnabled;
            this.nextEnabled = nextEnabled;
        }
    }

    /** Manifest record used to recover a link's intended target half. */
    public static final class LinkTarget {
        public final int sourcePage;
        public final int targetPage;
        public final Half sourceHalf;
        public final Half targetHalf;
        public final boolean resetLandscapeFit;
        public final float x0;
        public final float y0;
        public final float x1;
        public final float y1;

        public LinkTarget(
            int sourcePage,
            int targetPage,
            Half sourceHalf,
            Half targetHalf,
            float x0,
            float y0,
            float x1,
            float y1
        ) {
            this(
                sourcePage,
                targetPage,
                sourceHalf,
                targetHalf,
                false,
                x0,
                y0,
                x1,
                y1
            );
        }

        public LinkTarget(
            int sourcePage,
            int targetPage,
            Half sourceHalf,
            Half targetHalf,
            boolean resetLandscapeFit,
            float x0,
            float y0,
            float x1,
            float y1
        ) {
            this.sourcePage = sourcePage;
            this.targetPage = targetPage;
            this.sourceHalf = sourceHalf;
            this.targetHalf = targetHalf;
            this.resetLandscapeFit = resetLandscapeFit;
            this.x0 = x0;
            this.y0 = y0;
            this.x1 = x1;
            this.y1 = y1;
        }

        public LinkTarget(
            int sourcePage,
            int targetPage,
            Half targetHalf,
            float x0,
            float y0,
            float x1,
            float y1
        ) {
            this(
                sourcePage,
                targetPage,
                null,
                targetHalf,
                x0,
                y0,
                x1,
                y1
            );
        }
    }

    /** Authenticated manifest record for one external URI link. */
    public static final class UriTarget {
        public final int sourcePage;
        public final Half sourceHalf;
        public final String uri;
        public final float x0;
        public final float y0;
        public final float x1;
        public final float y1;

        public UriTarget(
            int sourcePage,
            Half sourceHalf,
            String uri,
            float x0,
            float y0,
            float x1,
            float y1
        ) {
            this.sourcePage = sourcePage;
            this.sourceHalf = sourceHalf;
            this.uri = uri;
            this.x0 = x0;
            this.y0 = y0;
            this.x1 = x1;
            this.y1 = y1;
        }
    }

    /** One successful native internal-link traversal. */
    public static final class LinkVisit {
        public final int sourcePage;
        public final Half sourceHalf;
        public final int targetPage;

        private LinkVisit(
            int sourcePage,
            Half sourceHalf,
            int targetPage
        ) {
            this.sourcePage = sourcePage;
            this.sourceHalf = sourceHalf;
            this.targetPage = targetPage;
        }
    }

    /**
     * Mirrors only the successful links observed in the current reader
     * process. Native BackLinkUtils remains the authoritative history owner.
     */
    public static final class LinkHistory {
        private final ArrayDeque<LinkVisit> visits = new ArrayDeque<>();

        public void record(
            int sourcePage,
            Half sourceHalf,
            int targetPage
        ) {
            if (sourcePage < 0 || targetPage < 0 || sourceHalf == null) {
                return;
            }
            visits.addFirst(new LinkVisit(
                sourcePage,
                sourceHalf,
                targetPage
            ));
        }

        public LinkVisit takeBack(
            int sourcePage,
            int targetPage,
            int currentPage
        ) {
            LinkVisit candidate = peekBack(
                sourcePage,
                targetPage,
                currentPage
            );
            if (candidate == null) {
                visits.clear();
                return null;
            }
            return visits.removeFirst();
        }

        /** Validate Back without consuming the mirrored native visit. */
        public LinkVisit peekBack(
            int sourcePage,
            int targetPage,
            int currentPage
        ) {
            LinkVisit candidate = visits.peekFirst();
            return candidate != null
                && candidate.targetPage == currentPage
                && matches(candidate, sourcePage, targetPage)
                ? candidate : null;
        }

        public LinkVisit takeOriginal(
            int sourcePage,
            int targetPage,
            int currentPage
        ) {
            LinkVisit candidate = peekOriginal(
                sourcePage,
                targetPage,
                currentPage
            );
            visits.clear();
            return candidate;
        }

        /** Validate Original Back without consuming the mirrored history. */
        public LinkVisit peekOriginal(
            int sourcePage,
            int targetPage,
            int currentPage
        ) {
            LinkVisit newest = visits.peekFirst();
            LinkVisit candidate = visits.peekLast();
            return newest != null
                && newest.targetPage == currentPage
                && matches(candidate, sourcePage, targetPage)
                ? candidate : null;
        }

        public void clear() {
            visits.clear();
        }

        public int size() {
            return visits.size();
        }

        private static boolean matches(
            LinkVisit visit,
            int sourcePage,
            int targetPage
        ) {
            return visit != null
                && visit.sourcePage == sourcePage
                && visit.targetPage == targetPage;
        }
    }

    private VirtualSpreadNavigation() {
    }

    /** Accept only an exact JSON string token. */
    public static String exactJsonString(Object value) {
        return value instanceof String ? (String) value : null;
    }

    /** Accept only an exact JSON integer token representable by Java int. */
    public static Integer exactJsonInteger(Object value) {
        if (value instanceof Integer) {
            return (Integer) value;
        }
        if (value instanceof Long) {
            long candidate = ((Long) value).longValue();
            if (candidate >= Integer.MIN_VALUE
                && candidate <= Integer.MAX_VALUE) {
                return Integer.valueOf((int) candidate);
            }
        }
        return null;
    }

    /** Accept only a nonnegative exact JSON integer representable by Java long. */
    public static Long exactNonnegativeJsonLong(Object value) {
        long candidate;
        if (value instanceof Integer) {
            candidate = ((Integer) value).longValue();
        } else if (value instanceof Long) {
            candidate = ((Long) value).longValue();
        } else {
            return null;
        }
        return candidate >= 0L ? Long.valueOf(candidate) : null;
    }

    /** Accept only a finite raw JSON numeric token. */
    public static Double exactFiniteJsonNumber(Object value) {
        if (!(value instanceof Number)) {
            return null;
        }
        double candidate = ((Number) value).doubleValue();
        return finite(candidate) ? Double.valueOf(candidate) : null;
    }

    /** Decode UTF-8 without silently replacing malformed persisted bytes. */
    public static String decodeStrictUtf8(byte[] value) {
        if (value == null) {
            return null;
        }
        try {
            return StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(value))
                .toString();
        } catch (CharacterCodingException error) {
            return null;
        }
    }

    /** Strictly validate one JSON object and reject duplicate names anywhere. */
    public static boolean jsonObjectHasUniqueKeys(String json) {
        if (json == null) {
            return false;
        }
        try {
            return new JsonKeyScanner(json).scanObject();
        } catch (IllegalArgumentException error) {
            return false;
        }
    }

    private static final class JsonKeyScanner {
        private static final int MAX_DEPTH = 128;

        private final String text;
        private int position;

        JsonKeyScanner(String text) {
            this.text = text;
        }

        boolean scanObject() {
            skipWhitespace();
            if (position >= text.length() || text.charAt(position) != '{') {
                return false;
            }
            parseObject(1);
            skipWhitespace();
            return position == text.length();
        }

        private void parseValue(int depth) {
            requireDepth(depth);
            skipWhitespace();
            if (position >= text.length()) {
                fail();
            }
            char token = text.charAt(position);
            if (token == '{') {
                parseObject(depth);
            } else if (token == '[') {
                parseArray(depth);
            } else if (token == '"') {
                parseString(false);
            } else if (token == 't') {
                parseLiteral("true");
            } else if (token == 'f') {
                parseLiteral("false");
            } else if (token == 'n') {
                parseLiteral("null");
            } else {
                parseNumber();
            }
        }

        private void parseObject(int depth) {
            requireDepth(depth);
            expect('{');
            skipWhitespace();
            HashSet<String> names = new HashSet<>();
            if (take('}')) {
                return;
            }
            while (true) {
                skipWhitespace();
                if (position >= text.length()
                    || text.charAt(position) != '"') {
                    fail();
                }
                String name = parseString(true);
                if (!names.add(name)) {
                    fail();
                }
                skipWhitespace();
                expect(':');
                parseValue(depth + 1);
                skipWhitespace();
                if (take('}')) {
                    return;
                }
                expect(',');
            }
        }

        private void parseArray(int depth) {
            requireDepth(depth);
            expect('[');
            skipWhitespace();
            if (take(']')) {
                return;
            }
            while (true) {
                parseValue(depth + 1);
                skipWhitespace();
                if (take(']')) {
                    return;
                }
                expect(',');
            }
        }

        private String parseString(boolean capture) {
            expect('"');
            StringBuilder result = capture ? new StringBuilder() : null;
            while (position < text.length()) {
                char current = text.charAt(position++);
                if (current == '"') {
                    return result == null ? "" : result.toString();
                }
                if (current == '\\') {
                    if (position >= text.length()) {
                        fail();
                    }
                    char escaped = text.charAt(position++);
                    char decoded;
                    if (escaped == '"' || escaped == '\\'
                        || escaped == '/') {
                        decoded = escaped;
                    } else if (escaped == 'b') {
                        decoded = '\b';
                    } else if (escaped == 'f') {
                        decoded = '\f';
                    } else if (escaped == 'n') {
                        decoded = '\n';
                    } else if (escaped == 'r') {
                        decoded = '\r';
                    } else if (escaped == 't') {
                        decoded = '\t';
                    } else if (escaped == 'u') {
                        decoded = parseUnicodeEscape();
                    } else {
                        fail();
                        return "";
                    }
                    if (result != null) {
                        result.append(decoded);
                    }
                } else {
                    if (current < 0x20) {
                        fail();
                    }
                    if (result != null) {
                        result.append(current);
                    }
                }
            }
            fail();
            return "";
        }

        private char parseUnicodeEscape() {
            if (position + 4 > text.length()) {
                fail();
            }
            int value = 0;
            for (int index = 0; index < 4; index++) {
                value = value * 16 + hexValue(text.charAt(position++));
            }
            return (char) value;
        }

        private void parseNumber() {
            if (take('-') && position >= text.length()) {
                fail();
            }
            if (take('0')) {
                // A leading zero can only be followed by a fraction/exponent.
            } else {
                if (position >= text.length()
                    || text.charAt(position) < '1'
                    || text.charAt(position) > '9') {
                    fail();
                }
                while (position < text.length()
                    && isDigit(text.charAt(position))) {
                    position++;
                }
            }
            if (take('.')) {
                requireDigit();
                while (position < text.length()
                    && isDigit(text.charAt(position))) {
                    position++;
                }
            }
            if (position < text.length()
                && (text.charAt(position) == 'e'
                    || text.charAt(position) == 'E')) {
                position++;
                if (position < text.length()
                    && (text.charAt(position) == '+'
                        || text.charAt(position) == '-')) {
                    position++;
                }
                requireDigit();
                while (position < text.length()
                    && isDigit(text.charAt(position))) {
                    position++;
                }
            }
        }

        private void parseLiteral(String literal) {
            if (!text.regionMatches(position, literal, 0, literal.length())) {
                fail();
            }
            position += literal.length();
        }

        private void requireDigit() {
            if (position >= text.length()
                || !isDigit(text.charAt(position))) {
                fail();
            }
        }

        private static boolean isDigit(char value) {
            return value >= '0' && value <= '9';
        }

        private static int hexValue(char value) {
            if (value >= '0' && value <= '9') {
                return value - '0';
            }
            if (value >= 'a' && value <= 'f') {
                return value - 'a' + 10;
            }
            if (value >= 'A' && value <= 'F') {
                return value - 'A' + 10;
            }
            fail();
            return 0;
        }

        private void skipWhitespace() {
            while (position < text.length()) {
                char value = text.charAt(position);
                if (value != ' ' && value != '\t'
                    && value != '\r' && value != '\n') {
                    return;
                }
                position++;
            }
        }

        private boolean take(char expected) {
            if (position < text.length()
                && text.charAt(position) == expected) {
                position++;
                return true;
            }
            return false;
        }

        private void expect(char expected) {
            if (!take(expected)) {
                fail();
            }
        }

        private static void requireDepth(int depth) {
            if (depth > MAX_DEPTH) {
                fail();
            }
        }

        private static void fail() {
            throw new IllegalArgumentException("invalid or duplicate-key JSON");
        }
    }

    public static int reverseLandscapeOffset(int nativeOffset) {
        return -nativeOffset;
    }

    /**
     * Distinguish annotation/digest callbacks and external links from internal
     * page jumps. Only the latter require an authenticated target-half match.
     */
    public static LinkRouting classifyLinkInvocation(
        boolean hasLink,
        Boolean external,
        int targetPage
    ) {
        if (!hasLink) {
            return LinkRouting.NON_LINK;
        }
        if (external == null) {
            return LinkRouting.BLOCKED;
        }
        if (external.booleanValue()) {
            return LinkRouting.EXTERNAL;
        }
        return targetPage >= 0
            ? LinkRouting.INTERNAL
            : LinkRouting.BLOCKED;
    }

    /**
     * Mirrors the exact firmware's immediate-link branch. A link that shares
     * the hit with a digest or annotation opens a native action menu first;
     * navigation has not been selected at that point.
     */
    public static boolean isImmediateLinkInvocation(
        boolean hasLink,
        boolean hasDigest,
        boolean hasAnnotationContent
    ) {
        return hasLink && !hasDigest && !hasAnnotationContent;
    }

    /**
     * An internal replay owns a subsequent native page-load callback. Every
     * other outcome must initialize the verified current spread immediately.
     */
    public static boolean replayRequiresImmediateInitialization(
        LinkRouting routing
    ) {
        return routing != LinkRouting.INTERNAL;
    }

    /**
     * A posted manifest activation may run after a newer UI callback has
     * already bound the published manifest and either initialized the current
     * page or started an authenticated turn, link, or link-history load. In
     * that case a synthetic page-loaded callback would clear the newer state.
     */
    public static boolean manifestActivationRequiresInitialization(
        boolean sameManifestKeyAndRevision,
        long boundVerificationGeneration,
        long activationVerificationGeneration,
        int lastPage,
        int pendingPage,
        boolean hasPendingHalf,
        int pendingLinkPage,
        boolean hasPendingLinkHalf,
        int pendingHistoryPage,
        boolean hasPendingHistoryHalf,
        boolean nativeViewportAuthorityAvailable,
        boolean nativeViewportLoadPending
    ) {
        if (!sameManifestKeyAndRevision
            || boundVerificationGeneration <= 0L
            || boundVerificationGeneration
                != activationVerificationGeneration) {
            return true;
        }
        boolean noPendingNavigation = pendingPage < 0
            && !hasPendingHalf
            && pendingLinkPage < 0
            && !hasPendingLinkHalf
            && pendingHistoryPage < 0
            && !hasPendingHistoryHalf;
        if (lastPage < 0) {
            return noPendingNavigation && !nativeViewportLoadPending;
        }
        // A page callback may win the verification race before the manifest
        // is available. It initializes navigation state but must fail closed
        // for viewport authority because its completion is unbound. Once the
        // manifest activates, synthesize one exact-current completion only
        // when no newer load or navigation owns the page.
        return noPendingNavigation
            && !nativeViewportAuthorityAvailable
            && !nativeViewportLoadPending;
    }

    /** A stale posted activation must never initialize a newer verification. */
    public static boolean manifestActivationBelongsToVerification(
        long latestGeneration,
        long activationGeneration,
        boolean sameNativeDocument
    ) {
        return latestGeneration > 0L
            && activationGeneration > 0L
            && latestGeneration == activationGeneration
            && sameNativeDocument;
    }

    /**
     * A posted cache invalidation may clear only the state and intent that
     * belonged to the removed verification snapshot.
     */
    public static boolean manifestInvalidationMayClear(
        boolean sameDocument,
        boolean sameNativeDocument,
        long boundVerificationGeneration,
        long invalidatedVerificationGeneration,
        long currentIntentGeneration,
        long expectedIntentGeneration
    ) {
        return sameDocument
            && sameNativeDocument
            && boundVerificationGeneration > 0L
            && boundVerificationGeneration
                == invalidatedVerificationGeneration
            && (expectedIntentGeneration < 0L
                || currentIntentGeneration == expectedIntentGeneration);
    }

    /** Verification-only rebinding must retain only its own queued action. */
    public static boolean queuedLinkSurvivesVerificationBinding(
        long queuedVerificationGeneration,
        long bindingVerificationGeneration
    ) {
        return queuedVerificationGeneration > 0L
            && queuedVerificationGeneration == bindingVerificationGeneration;
    }

    /** A native mixed-link menu remains valid only for its verifier owner. */
    public static boolean mixedLinkSurvivesVerificationBinding(
        long candidateVerificationGeneration,
        long bindingVerificationGeneration
    ) {
        return candidateVerificationGeneration > 0L
            && candidateVerificationGeneration == bindingVerificationGeneration;
    }

    /** Only synthetic activation preserves deferred link/menu intent. */
    public static boolean pageLoadPreservesDeferredLinkIntent(
        boolean manifestActivationInitialization
    ) {
        return manifestActivationInitialization;
    }

    /** Replay a deferred native link only in its original document/page window. */
    public static boolean pendingLinkReplayIsCurrent(
        boolean sameDocument,
        boolean sameSnapshot,
        boolean sameNativeDocument,
        boolean samePageLoadGeneration,
        int sourcePage,
        int currentPage,
        long ageMillis,
        long maximumAgeMillis
    ) {
        return sameDocument
            && sameSnapshot
            && sameNativeDocument
            && samePageLoadGeneration
            && sourcePage >= 0
            && sourcePage == currentPage
            && ageMillis >= 0L
            && maximumAgeMillis >= 0L
            && ageMillis <= maximumAgeMillis;
    }

    /** A stale verifier must never consume a link owned by a newer snapshot. */
    public static boolean queuedLinkBelongsToVerification(
        long queuedGeneration,
        long activationGeneration
    ) {
        return queuedGeneration > 0L
            && activationGeneration > 0L
            && queuedGeneration == activationGeneration;
    }

    /** Require an observable page-bound native persistence acknowledgement. */
    public static boolean saveAcknowledgementMatches(
        boolean hadTrails,
        boolean callbackObserved,
        boolean callbackSucceeded,
        boolean sameNote,
        int expectedPage,
        int observedPage,
        boolean sameMarkPath
    ) {
        return !hadTrails || (
            callbackObserved
                && callbackSucceeded
                && sameNote
                && expectedPage > 0
                && observedPage == expectedPage
                && sameMarkPath
        );
    }

    /** Preserve an authenticated explicit native viewport in portrait. */
    public static boolean shouldPreservePortraitLinkViewport(
        boolean internalLinkTarget,
        boolean resetLandscapeFit,
        boolean retainedExplicitLinkViewport
    ) {
        return retainedExplicitLinkViewport
            || (internalLinkTarget && !resetLandscapeFit);
    }

    public static boolean manifestMatchesNativeSnapshot(
        String expectedSource,
        String expectedLayout,
        String expectedLinks,
        String expectedMapping,
        String expectedViewId,
        String expectedGenerator,
        String nativeSource,
        String nativeLayout,
        String nativeLinks,
        String nativeMapping,
        String nativeViewId,
        String nativeGenerator
    ) {
        return manifestMatchesNativeSnapshot(
            null,
            expectedSource,
            expectedLayout,
            expectedLinks,
            expectedMapping,
            null,
            expectedViewId,
            expectedGenerator,
            null,
            nativeSource,
            nativeLayout,
            nativeLinks,
            nativeMapping,
            null,
            nativeViewId,
            nativeGenerator
        );
    }

    public static boolean manifestMatchesNativeSnapshot(
        String expectedSource,
        String expectedLayout,
        String expectedLinks,
        String expectedMapping,
        String expectedNavigation,
        String expectedViewId,
        String expectedGenerator,
        String nativeSource,
        String nativeLayout,
        String nativeLinks,
        String nativeMapping,
        String nativeNavigation,
        String nativeViewId,
        String nativeGenerator
    ) {
        return manifestMatchesNativeSnapshot(
            null,
            expectedSource,
            expectedLayout,
            expectedLinks,
            expectedMapping,
            expectedNavigation,
            expectedViewId,
            expectedGenerator,
            null,
            nativeSource,
            nativeLayout,
            nativeLinks,
            nativeMapping,
            nativeNavigation,
            nativeViewId,
            nativeGenerator
        );
    }

    public static boolean manifestMatchesNativeSnapshot(
        String expectedSchema,
        String expectedSource,
        String expectedLayout,
        String expectedLinks,
        String expectedMapping,
        String expectedNavigation,
        String expectedViewId,
        String expectedGenerator,
        String nativeSchema,
        String nativeSource,
        String nativeLayout,
        String nativeLinks,
        String nativeMapping,
        String nativeNavigation,
        String nativeViewId,
        String nativeGenerator
    ) {
        return (expectedSchema == null
                ? nativeSchema == null
                : expectedSchema.equals(nativeSchema))
            && sameAuthority(expectedSource, nativeSource)
            && sameAuthority(expectedLayout, nativeLayout)
            && sameAuthority(expectedLinks, nativeLinks)
            && sameAuthority(expectedMapping, nativeMapping)
            && (expectedNavigation == null
                ? nativeNavigation == null || nativeNavigation.trim().isEmpty()
                : sameAuthority(expectedNavigation, nativeNavigation))
            && sameViewId(expectedViewId, nativeViewId)
            && expectedGenerator != null
            && expectedGenerator.equals(nativeGenerator);
    }

    /** Bind a bookmark landing record to its authenticated page mapping. */
    public static boolean outlineTargetMatchesMapping(
        int mappingSourcePage,
        int mappingVirtualPage,
        String mappingSide,
        double[] mappingDestination,
        int targetSourcePage,
        int targetVirtualPage,
        String targetSide,
        Double[] targetOperands
    ) {
        if (mappingSourcePage != targetSourcePage
            || mappingVirtualPage != targetVirtualPage
            || mappingSide == null || !mappingSide.equals(targetSide)
            || mappingDestination == null || mappingDestination.length != 4
            || targetOperands == null || targetOperands.length != 4) {
            return false;
        }
        for (int index = 0; index < 4; index++) {
            if (!Double.isFinite(mappingDestination[index])
                || targetOperands[index] == null
                || !Double.isFinite(targetOperands[index].doubleValue())
                || Double.doubleToRawLongBits(mappingDestination[index])
                    != Double.doubleToRawLongBits(
                        targetOperands[index].doubleValue())) {
                return false;
            }
        }
        return true;
    }

    /**
     * MuPDF returns an empty String, rather than null, for an absent document
     * information key on the Nomad. Only a nonblank value claims generated
     * Virtual Spread authority. An unexpected non-String value remains a
     * claim so malformed metadata fails closed instead of becoming native
     * pass-through.
     */
    public static boolean nativeMetadataClaimsVirtualSpread(
        Object source,
        Object layout,
        Object links,
        Object mapping,
        Object viewId,
        Object generator
    ) {
        return nativeMetadataClaimsVirtualSpread(
            null,
            source,
            layout,
            links,
            mapping,
            null,
            viewId,
            generator
        );
    }

    public static boolean nativeMetadataClaimsVirtualSpread(
        Object source,
        Object layout,
        Object links,
        Object mapping,
        Object navigation,
        Object viewId,
        Object generator
    ) {
        return nativeMetadataClaimsVirtualSpread(
            null,
            source,
            layout,
            links,
            mapping,
            navigation,
            viewId,
            generator
        );
    }

    public static boolean nativeMetadataClaimsVirtualSpread(
        Object schema,
        Object source,
        Object layout,
        Object links,
        Object mapping,
        Object navigation,
        Object viewId,
        Object generator
    ) {
        return nativeAuthorityValuePresent(schema)
            || nativeAuthorityValuePresent(source)
            || nativeAuthorityValuePresent(layout)
            || nativeAuthorityValuePresent(links)
            || nativeAuthorityValuePresent(mapping)
            || nativeAuthorityValuePresent(navigation)
            || nativeAuthorityValuePresent(viewId)
            || nativeAuthorityValuePresent(generator);
    }

    private static boolean nativeAuthorityValuePresent(Object value) {
        if (value == null) {
            return false;
        }
        if (!(value instanceof String)) {
            return true;
        }
        return !((String) value).trim().isEmpty();
    }

    private static boolean sameAuthority(String expected, String actual) {
        return lowerSha256(expected)
            && lowerSha256(actual)
            && expected.equals(actual);
    }

    private static boolean lowerSha256(String value) {
        if (value == null || value.length() != 64) {
            return false;
        }
        for (int index = 0; index < value.length(); index++) {
            char current = value.charAt(index);
            if (!((current >= '0' && current <= '9')
                    || (current >= 'a' && current <= 'f'))) {
                return false;
            }
        }
        return true;
    }

    private static boolean sameViewId(String expected, String actual) {
        String prefix = "inkbridge-view-v1-";
        return expected != null
            && actual != null
            && expected.startsWith(prefix)
            && expected.length() == prefix.length() + 64
            && expected.equals(actual);
    }

    /**
     * Validate the geometry carried by one authenticated mapping record.
     * Canonical hashing is handled separately; this rejects self-consistent
     * but unusable geometry before it reaches native page handling.
     */
    public static boolean mappingGeometryIsValid(
        String side,
        int rotation,
        double[] sourceBox,
        double[] normalizedSourceBox,
        double[] slot,
        double[] destination,
        double scale,
        double[] transform,
        double pageWidth,
        double pageHeight,
        double gutter
    ) {
        if (!("left".equals(side) || "right".equals(side))
            || !(rotation == 0 || rotation == 90
                || rotation == 180 || rotation == 270)
            || !positiveRect(sourceBox)
            || !positiveRect(normalizedSourceBox)
            || !positiveRect(slot)
            || !positiveRect(destination)
            || !finiteArray(transform, 6)
            || !Double.isFinite(scale) || scale <= 0.0
            || !runtimeGeometryIsRepresentable(
                pageWidth, pageHeight, gutter)) {
            return false;
        }
        double halfWidth = (pageWidth - gutter) / 2.0;
        double slotLeft = "left".equals(side) ? 0.0 : halfWidth + gutter;
        double slotRight = "left".equals(side) ? halfWidth : pageWidth;
        if (!rectNearlyEquals(slot, slotLeft, 0.0, slotRight, pageHeight)
            || destination[0] < slot[0] - 1.0e-7
            || destination[1] < slot[1] - 1.0e-7
            || destination[2] > slot[2] + 1.0e-7
            || destination[3] > slot[3] + 1.0e-7) {
            return false;
        }

        double sourceWidth = sourceBox[2] - sourceBox[0];
        double sourceHeight = sourceBox[3] - sourceBox[1];
        double normalizedWidth = normalizedSourceBox[2]
            - normalizedSourceBox[0];
        double normalizedHeight = normalizedSourceBox[3]
            - normalizedSourceBox[1];
        boolean quarterTurn = rotation == 90 || rotation == 270;
        if (!nearlyEqual(
                normalizedWidth,
                quarterTurn ? sourceHeight : sourceWidth
            ) || !nearlyEqual(
                normalizedHeight,
                quarterTurn ? sourceWidth : sourceHeight
            )) {
            return false;
        }

        double slotWidth = slot[2] - slot[0];
        double slotHeight = slot[3] - slot[1];
        double expectedScale = Math.min(
            slotWidth / normalizedWidth,
            slotHeight / normalizedHeight
        );
        double expectedWidth = normalizedWidth * expectedScale;
        double expectedHeight = normalizedHeight * expectedScale;
        double expectedLeft = slot[0] + (slotWidth - expectedWidth) / 2.0;
        double expectedBottom = slot[1]
            + (slotHeight - expectedHeight) / 2.0;
        if (!Double.isFinite(expectedScale)
            || !Double.isFinite(expectedWidth)
            || !Double.isFinite(expectedHeight)
            || !nearlyEqual(scale, expectedScale)
            || !rectNearlyEquals(
                destination,
                expectedLeft,
                expectedBottom,
                expectedLeft + expectedWidth,
                expectedBottom + expectedHeight
            )) {
            return false;
        }

        double a = transform[0];
        double b = transform[1];
        double c = transform[2];
        double d = transform[3];
        double determinant = a * d - b * c;
        double expectedA = (rotation == 0 ? scale
            : rotation == 180 ? -scale : 0.0);
        double expectedB = (rotation == 90 ? -scale
            : rotation == 270 ? scale : 0.0);
        double expectedC = (rotation == 90 ? scale
            : rotation == 270 ? -scale : 0.0);
        double expectedD = (rotation == 0 ? scale
            : rotation == 180 ? -scale : 0.0);
        if (!Double.isFinite(determinant) || determinant <= 0.0
            || !sameRawDouble(a, expectedA)
            || !sameRawDouble(b, expectedB)
            || !sameRawDouble(c, expectedC)
            || !sameRawDouble(d, expectedD)) {
            return false;
        }
        double[] xs = new double[] {
            sourceBox[0], sourceBox[2], sourceBox[2], sourceBox[0]
        };
        double[] ys = new double[] {
            sourceBox[1], sourceBox[1], sourceBox[3], sourceBox[3]
        };
        double minX = Double.POSITIVE_INFINITY;
        double minY = Double.POSITIVE_INFINITY;
        double maxX = Double.NEGATIVE_INFINITY;
        double maxY = Double.NEGATIVE_INFINITY;
        for (int index = 0; index < 4; index++) {
            double x = a * xs[index] + c * ys[index] + transform[4];
            double y = b * xs[index] + d * ys[index] + transform[5];
            if (!Double.isFinite(x) || !Double.isFinite(y)) {
                return false;
            }
            minX = Math.min(minX, x);
            minY = Math.min(minY, y);
            maxX = Math.max(maxX, x);
            maxY = Math.max(maxY, y);
        }
        return rectNearlyEquals(destination, minX, minY, maxX, maxY)
            && mappingRoundTripsAreStable(
                rotation,
                sourceBox,
                destination,
                transform
            );
    }

    private static boolean sameRawDouble(double left, double right) {
        return Double.doubleToRawLongBits(left)
            == Double.doubleToRawLongBits(right);
    }

    private static boolean mappingRoundTripsAreStable(
        int rotation,
        double[] sourceBox,
        double[] destination,
        double[] transform
    ) {
        double destinationWidth = destination[2] - destination[0];
        double destinationHeight = destination[3] - destination[1];
        double sourceWidth = sourceBox[2] - sourceBox[0];
        double sourceHeight = sourceBox[3] - sourceBox[1];
        double determinant = transform[0] * transform[3]
            - transform[1] * transform[2];
        double[][] probes = new double[][] {
            {0.0, 0.0},
            {0.25, 0.5},
            {0.5, 0.5},
            {0.75, 0.25},
            {1.0, 1.0}
        };
        for (double[] probe : probes) {
            double normalizedX = probe[0];
            double normalizedY = probe[1];
            double sourceX;
            double sourceY;
            if (rotation == 0) {
                sourceX = sourceBox[0] + normalizedX * sourceWidth;
                sourceY = sourceBox[3] - normalizedY * sourceHeight;
            } else if (rotation == 90) {
                sourceX = sourceBox[0] + normalizedY * sourceWidth;
                sourceY = sourceBox[1] + normalizedX * sourceHeight;
            } else if (rotation == 180) {
                sourceX = sourceBox[2] - normalizedX * sourceWidth;
                sourceY = sourceBox[1] + normalizedY * sourceHeight;
            } else {
                sourceX = sourceBox[2] - normalizedY * sourceWidth;
                sourceY = sourceBox[3] - normalizedX * sourceHeight;
            }
            double spreadX = transform[0] * sourceX
                + transform[2] * sourceY + transform[4];
            double spreadY = transform[1] * sourceX
                + transform[3] * sourceY + transform[5];
            double expectedSpreadX = destination[0]
                + normalizedX * destinationWidth;
            double expectedSpreadY = destination[3]
                - normalizedY * destinationHeight;
            double deltaX = spreadX - transform[4];
            double deltaY = spreadY - transform[5];
            double restoredX = (
                transform[3] * deltaX - transform[2] * deltaY
            ) / determinant;
            double restoredY = (
                -transform[1] * deltaX + transform[0] * deltaY
            ) / determinant;
            double restoredNormalizedX;
            double restoredNormalizedY;
            if (rotation == 0) {
                restoredNormalizedX = (restoredX - sourceBox[0])
                    / sourceWidth;
                restoredNormalizedY = (sourceBox[3] - restoredY)
                    / sourceHeight;
            } else if (rotation == 90) {
                restoredNormalizedX = (restoredY - sourceBox[1])
                    / sourceHeight;
                restoredNormalizedY = (restoredX - sourceBox[0])
                    / sourceWidth;
            } else if (rotation == 180) {
                restoredNormalizedX = (sourceBox[2] - restoredX)
                    / sourceWidth;
                restoredNormalizedY = (restoredY - sourceBox[1])
                    / sourceHeight;
            } else {
                restoredNormalizedX = (sourceBox[3] - restoredY)
                    / sourceHeight;
                restoredNormalizedY = (sourceBox[2] - restoredX)
                    / sourceWidth;
            }
            if (!Double.isFinite(spreadX)
                || !Double.isFinite(spreadY)
                || !Double.isFinite(restoredX)
                || !Double.isFinite(restoredY)
                || Math.abs(spreadX - expectedSpreadX) > 1.0e-12
                || Math.abs(spreadY - expectedSpreadY) > 1.0e-12
                || Math.abs(restoredNormalizedX - normalizedX) > 1.0e-12
                || Math.abs(restoredNormalizedY - normalizedY) > 1.0e-12) {
                return false;
            }
        }
        return true;
    }

    private static boolean positiveRect(double[] rect) {
        return finiteArray(rect, 4)
            && rect[0] < rect[2] && rect[1] < rect[3];
    }

    private static boolean finiteArray(double[] values, int length) {
        if (values == null || values.length != length) {
            return false;
        }
        for (double value : values) {
            if (!Double.isFinite(value)) {
                return false;
            }
        }
        return true;
    }

    private static boolean nearlyEqual(double left, double right) {
        if (!Double.isFinite(left) || !Double.isFinite(right)) {
            return false;
        }
        double magnitude = Math.max(
            1.0,
            Math.max(Math.abs(left), Math.abs(right))
        );
        return Math.abs(left - right) <= 1.0e-7 * magnitude;
    }

    private static boolean rectNearlyEquals(
        double[] actual,
        double left,
        double bottom,
        double right,
        double top
    ) {
        return positiveRect(actual)
            && nearlyEqual(actual[0], left)
            && nearlyEqual(actual[1], bottom)
            && nearlyEqual(actual[2], right)
            && nearlyEqual(actual[3], top);
    }

    /** True only for bounded PDF geometry that survives Android floats. */
    public static boolean runtimeGeometryIsRepresentable(
        double pageWidth,
        double pageHeight,
        double gutter
    ) {
        if (!finite(pageWidth) || !finite(pageHeight) || !finite(gutter)
            || pageWidth < PDF_MIN_PAGE_DIMENSION
            || pageWidth > PDF_MAX_PAGE_DIMENSION
            || pageHeight < PDF_MIN_PAGE_DIMENSION
            || pageHeight > PDF_MAX_PAGE_DIMENSION
            || gutter < 0.0) {
            return false;
        }
        double slotWidth = (pageWidth - gutter) / 2.0;
        float runtimeSlotWidth = (
            (float) pageWidth - (float) gutter
        ) / 2.0f;
        return runtimePositiveFloat(pageWidth)
            && runtimePositiveFloat(pageHeight)
            && runtimeNonnegativeFloat(gutter)
            && runtimePositiveFloat(slotWidth)
            && finite(runtimeSlotWidth)
            && runtimeSlotWidth > 0.0f;
    }

    /** True only for geometry matching the Nomad's 4:3 landscape viewport. */
    public static boolean nomadSpreadAspectIsSupported(
        double pageWidth,
        double pageHeight
    ) {
        if (!finite(pageWidth) || !finite(pageHeight)
            || pageWidth <= 0.0 || pageHeight <= 0.0) {
            return false;
        }
        double aspect = pageWidth / pageHeight;
        return finite(aspect)
            && Math.abs(aspect - NOMAD_LANDSCAPE_ASPECT)
                <= NOMAD_LANDSCAPE_ASPECT * NOMAD_ASPECT_TOLERANCE;
    }

    /** True only when a link survives Android's top-down float conversion. */
    public static boolean runtimeRectIsRepresentable(
        double pageHeight,
        double x0,
        double y0,
        double x1,
        double y1
    ) {
        if (!finite(pageHeight) || pageHeight <= 0.0
            || !finite(x0) || !finite(y0) || !finite(x1) || !finite(y1)
            || x0 >= x1 || y0 >= y1) {
            return false;
        }
        float narrowedPageHeight = (float) pageHeight;
        float narrowedX0 = (float) x0;
        float narrowedY0 = (float) y0;
        float narrowedX1 = (float) x1;
        float narrowedY1 = (float) y1;
        float topDownY0 = narrowedPageHeight - narrowedY1;
        float topDownY1 = narrowedPageHeight - narrowedY0;
        return finite(narrowedPageHeight)
            && narrowedPageHeight > 0.0f
            && finite(narrowedX0)
            && finite(narrowedY0)
            && finite(narrowedX1)
            && finite(narrowedY1)
            && finite(topDownY0)
            && finite(topDownY1)
            && narrowedX0 < narrowedX1
            && narrowedY0 < narrowedY1
            && topDownY0 < topDownY1;
    }

    private static boolean runtimePositiveFloat(double value) {
        if (!finite(value) || value <= 0.0) {
            return false;
        }
        float narrowed = (float) value;
        return finite(narrowed) && narrowed > 0.0f;
    }

    private static boolean runtimeNonnegativeFloat(double value) {
        if (!finite(value) || value < 0.0) {
            return false;
        }
        float narrowed = (float) value;
        return finite(narrowed)
            && (value == 0.0 ? narrowed == 0.0f : narrowed > 0.0f);
    }

    private static boolean finite(double value) {
        return !Double.isNaN(value) && !Double.isInfinite(value);
    }

    public static PageBarState pageBarState(
        Spread[] spreads,
        int currentPage,
        Half currentHalf,
        boolean portrait
    ) {
        if (spreads == null || spreads.length == 0
            || currentPage < 0 || currentPage >= spreads.length) {
            return new PageBarState(false, false);
        }
        if (!portrait) {
            return new PageBarState(
                currentPage < spreads.length - 1,
                currentPage > 0
            );
        }
        return new PageBarState(
            planPortrait(spreads, currentPage, currentHalf, -1).kind
                != Kind.BOUNDARY,
            planPortrait(spreads, currentPage, currentHalf, 1).kind
                != Kind.BOUNDARY
        );
    }

    public static Half matchLinkTarget(
        LinkTarget[] targets,
        int sourcePage,
        int targetPage,
        float x0,
        float y0,
        float x1,
        float y1,
        float pageHeight,
        float tolerance
    ) {
        LinkTarget target = matchLink(
            targets,
            sourcePage,
            targetPage,
            x0,
            y0,
            x1,
            y1,
            pageHeight,
            tolerance
        );
        return target == null ? null : target.targetHalf;
    }

    public static LinkTarget matchLink(
        LinkTarget[] targets,
        int sourcePage,
        int targetPage,
        float x0,
        float y0,
        float x1,
        float y1,
        float pageHeight,
        float tolerance
    ) {
        if (targets == null || !finite(tolerance) || tolerance < 0.0f
            || !finite(pageHeight) || pageHeight <= 0.0f
            || !finite(x0) || !finite(y0)
            || !finite(x1) || !finite(y1)
            || x0 >= x1 || y0 >= y1) {
            return null;
        }
        LinkTarget matched = null;
        for (LinkTarget target : targets) {
            if (target == null
                || target.sourcePage != sourcePage
                || target.targetPage != targetPage
                || target.targetHalf == null
                || !finite(target.x0) || !finite(target.y0)
                || !finite(target.x1) || !finite(target.y1)
                || target.x0 >= target.x1 || target.y0 >= target.y1) {
                continue;
            }
            // The manifest is bottom-up, while MuPDF reports top-down bounds.
            // Convert the manifest once and compare in MuPDF's coordinates;
            // converting the large native bounds back loses low Y bits.
            float expectedNativeY0 = pageHeight - target.y1;
            float expectedNativeY1 = pageHeight - target.y0;
            if (!finite(expectedNativeY0) || !finite(expectedNativeY1)
                || expectedNativeY0 >= expectedNativeY1
                || Math.abs(target.x0 - x0) > tolerance
                || Math.abs(expectedNativeY0 - y0) > tolerance
                || Math.abs(target.x1 - x1) > tolerance
                || Math.abs(expectedNativeY1 - y1) > tolerance) {
                continue;
            }
            if (matched != null
                && (matched.targetHalf != target.targetHalf
                    || matched.sourceHalf != target.sourceHalf
                    || matched.resetLandscapeFit
                        != target.resetLandscapeFit)) {
                return null;
            }
            matched = target;
        }
        return matched;
    }

    /** Match an external callback to the exact authenticated URI record. */
    public static UriTarget matchUriLink(
        UriTarget[] targets,
        int sourcePage,
        String uri,
        float x0,
        float y0,
        float x1,
        float y1,
        float pageHeight,
        float tolerance
    ) {
        if (targets == null || uri == null
            || !finite(tolerance) || tolerance < 0.0f
            || !finite(pageHeight) || pageHeight <= 0.0f
            || !finite(x0) || !finite(y0)
            || !finite(x1) || !finite(y1)
            || x0 >= x1 || y0 >= y1) {
            return null;
        }
        UriTarget matched = null;
        for (UriTarget target : targets) {
            if (target == null
                || target.sourcePage != sourcePage
                || !uri.equals(target.uri)
                || target.sourceHalf == null
                || !finite(target.x0) || !finite(target.y0)
                || !finite(target.x1) || !finite(target.y1)
                || target.x0 >= target.x1 || target.y0 >= target.y1) {
                continue;
            }
            float expectedNativeY0 = pageHeight - target.y1;
            float expectedNativeY1 = pageHeight - target.y0;
            if (!finite(expectedNativeY0) || !finite(expectedNativeY1)
                || expectedNativeY0 >= expectedNativeY1
                || Math.abs(target.x0 - x0) > tolerance
                || Math.abs(expectedNativeY0 - y0) > tolerance
                || Math.abs(target.x1 - x1) > tolerance
                || Math.abs(expectedNativeY1 - y1) > tolerance) {
                continue;
            }
            if (matched != null && matched.sourceHalf != target.sourceHalf) {
                return null;
            }
            matched = target;
        }
        return matched;
    }

    /**
     * Best-effort recovery for native history created before this process.
     * It fails closed if matching links originate on both halves.
     */
    public static Half inferLinkSourceHalf(
        LinkTarget[] targets,
        int sourcePage,
        int targetPage
    ) {
        if (targets == null) {
            return null;
        }
        Half matched = null;
        for (LinkTarget target : targets) {
            if (target == null
                || target.sourcePage != sourcePage
                || target.targetPage != targetPage
                || target.sourceHalf == null) {
                continue;
            }
            if (matched != null && matched != target.sourceHalf) {
                return null;
            }
            matched = target.sourceHalf;
        }
        return matched;
    }

    private static boolean finite(float value) {
        return !Float.isNaN(value) && !Float.isInfinite(value);
    }

    public static Half firstReadableHalf(Spread spread) {
        if (spread != null && spread.hasRight) {
            return Half.RIGHT;
        }
        return Half.LEFT;
    }

    public static Half lastReadableHalf(Spread spread) {
        if (spread != null && spread.hasLeft) {
            return Half.LEFT;
        }
        return Half.RIGHT;
    }

    /**
     * Plans source-page reading order for an RTL virtual-spread document.
     * A physical rightward gesture arrives from Supernote as a negative offset.
     */
    public static Plan planPortrait(
        Spread[] spreads,
        int currentPage,
        Half currentHalf,
        int nativeOffset
    ) {
        if (spreads == null || spreads.length == 0
            || currentPage < 0 || currentPage >= spreads.length
            || nativeOffset == 0) {
            return Plan.boundary(currentPage, currentHalf);
        }

        Spread current = spreads[currentPage];
        Half normalized = normalize(current, currentHalf);
        boolean forward = nativeOffset < 0;

        if (forward) {
            if (normalized == Half.RIGHT && current.hasLeft) {
                return Plan.same(currentPage, Half.LEFT);
            }
            for (int page = currentPage + 1; page < spreads.length; page++) {
                if (hasAny(spreads[page])) {
                    return Plan.other(page, firstReadableHalf(spreads[page]));
                }
            }
        } else {
            if (normalized == Half.LEFT && current.hasRight) {
                return Plan.same(currentPage, Half.RIGHT);
            }
            for (int page = currentPage - 1; page >= 0; page--) {
                if (hasAny(spreads[page])) {
                    return Plan.other(page, lastReadableHalf(spreads[page]));
                }
            }
        }
        return Plan.boundary(currentPage, normalized);
    }

    private static Half normalize(Spread spread, Half requested) {
        if (spread == null) {
            return requested == null ? Half.RIGHT : requested;
        }
        if (requested != null && spread.has(requested)) {
            return requested;
        }
        return firstReadableHalf(spread);
    }

    private static boolean hasAny(Spread spread) {
        return spread != null && (spread.hasLeft || spread.hasRight);
    }
}
