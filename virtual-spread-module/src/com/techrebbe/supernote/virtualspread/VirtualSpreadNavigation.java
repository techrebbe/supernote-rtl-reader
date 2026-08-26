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
     * An internal replay owns a subsequent native page-load callback. Every
     * other outcome must initialize the verified current spread immediately.
     */
    public static boolean replayRequiresImmediateInitialization(
        LinkRouting routing
    ) {
        return routing != LinkRouting.INTERNAL;
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
        String nativeSource,
        String nativeLayout,
        String nativeLinks
    ) {
        return sameAuthority(expectedSource, nativeSource)
            && sameAuthority(expectedLayout, nativeLayout)
            && sameAuthority(expectedLinks, nativeLinks);
    }

    private static boolean sameAuthority(String expected, String actual) {
        return expected != null
            && actual != null
            && expected.length() == 64
            && actual.length() == 64
            && expected.equalsIgnoreCase(actual);
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
