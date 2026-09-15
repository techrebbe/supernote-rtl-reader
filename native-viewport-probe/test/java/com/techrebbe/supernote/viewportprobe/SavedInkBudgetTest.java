package com.techrebbe.supernote.viewportprobe;

import com.example.libsupernote.GoldenTrailRecord;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;

/** Host-only executable regression for the collector's real private counters. */
public final class SavedInkBudgetTest {
    private static final String SHA_A = repeat('a', 64);
    private static final String SHA_B = repeat('b', 64);
    private static final ClassLoader NATIVE_LOADER =
        GoldenTrailRecord.class.getClassLoader();
    private static final String GOLDEN_SHA256 =
        "20a179534dfce744b9be97e8e40c1ab07ef19e1c1ddb618ed38f58002e648158";

    public static void main(String[] args) throws Exception {
        if (args.length > 0 && "--emit-golden".equals(args[0])) {
            if (args.length != 2) {
                throw new IllegalArgumentException("--emit-golden requires an output path");
            }
            String payload = goldenPayload();
            Files.write(Paths.get(args[1]),
                SavedInkReader.strictUtf8Bytes(payload, SavedInkReader.MAX_CAPTURE_BYTES),
                StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
            return;
        }
        if (args.length > 0 && "--emit-golden-frame".equals(args[0])) {
            if (args.length != 2) {
                throw new IllegalArgumentException("--emit-golden-frame requires an output path");
            }
            try (PrintStream output = new PrintStream(Files.newOutputStream(Paths.get(args[1]),
                    StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE), false, "UTF-8")) {
                SavedInkReader.publishEvidenceFrame(output,
                    SavedInkReader.strictUtf8Bytes(goldenPayload(),
                        SavedInkReader.MAX_CAPTURE_BYTES));
            }
            return;
        }

        testValueAndDepthBudgets();
        testFreshAndConcurrentRoots();
        testCanonicalWire();
        testGoldenDigest();
        testCanonicalCap();
        testExactNumericEncoding();
        testPinnedNestedNativeShapes();
        testDisposableAuthorityMetadata();
        testFaultSafeCleanup();
        testShellIdentityGate();
        testDefiningLoaderGate();
        testExactConcreteFastPaths();
        testFieldNameSortWithoutDynamicBootstrap();
        testNativeRecordLoaderIntegration();
        testNumericWrapperObjectKeyCollisions();
        testEvidencePublication();
        System.out.println("SAVED_INK_BUDGET PASS");
    }

    private static final class FieldSortFixture {
        int zeta;
        int alpha;
        int middle;
    }

    private static void testFieldNameSortWithoutDynamicBootstrap() throws Exception {
        Field[] empty = new Field[0];
        SavedInkReader.sortFieldsByName(empty);
        if (empty.length != 0) {
            throw new AssertionError("empty native field inventory changed");
        }
        Field singleton = FieldSortFixture.class.getDeclaredField("middle");
        Field[] one = new Field[] {singleton};
        SavedInkReader.sortFieldsByName(one);
        if (one[0] != singleton) {
            throw new AssertionError("singleton native field inventory changed");
        }
        Field alpha = FieldSortFixture.class.getDeclaredField("alpha");
        Field middle = FieldSortFixture.class.getDeclaredField("middle");
        Field zeta = FieldSortFixture.class.getDeclaredField("zeta");
        Field[] sorted = new Field[] {alpha, middle, zeta};
        SavedInkReader.sortFieldsByName(sorted);
        if (sorted[0] != alpha || sorted[1] != middle || sorted[2] != zeta) {
            throw new AssertionError("sorted native field identities changed");
        }
        Field[] fields = new Field[] {
            zeta,
            middle,
            alpha,
        };
        SavedInkReader.sortFieldsByName(fields);
        String[] expected = new String[] {"alpha", "middle", "zeta"};
        for (int index = 0; index < fields.length; index++) {
            if (!expected[index].equals(fields[index].getName())) {
                throw new AssertionError("native field ordering changed");
            }
        }
        try {
            SavedInkReader.sortFieldsByName(null);
            throw new AssertionError("null native field inventory admitted");
        } catch (IllegalStateException expectedFailure) { }
        try {
            SavedInkReader.sortFieldsByName(new Field[4097]);
            throw new AssertionError("oversized native field inventory admitted");
        } catch (IllegalStateException expectedFailure) { }
    }

    private static void testValueAndDepthBudgets() throws Exception {
        SavedInkReader.EncodingBudget valueBudget = new SavedInkReader.EncodingBudget();
        valueBudget.reserveValues(2_000_000);
        expectValueBound(valueBudget, 1);
        expectValueBound(new SavedInkReader.EncodingBudget(), -1);

        Object accepted = null;
        for (int i = 0; i < 16; ++i) {
            ArrayList<Object> wrapper = new ArrayList<Object>();
            wrapper.add(accepted);
            accepted = wrapper;
        }
        SavedInkReader.encodeTree(accepted, NATIVE_LOADER);
        ArrayList<Object> tooDeep = new ArrayList<Object>();
        tooDeep.add(accepted);
        expectEncodeBound(tooDeep);
        SavedInkReader.encodeTree(repeat('x', 65536), NATIVE_LOADER);
        expectEncodeBound(repeat('x', 65537));
        SavedInkReader.encodeTree(repeatString("\u05e9", 32768), NATIVE_LOADER);
        expectEncodeBound(repeatString("\u05e9", 32769));
        SavedInkReader.encodeTree(repeatString("\ud83d\ude00", 16384), NATIVE_LOADER);
        expectEncodeBound(repeatString("\ud83d\ude00", 16385));
    }

    private static void testFreshAndConcurrentRoots() throws Exception {
        Object value = null;
        for (int i = 0; i < 16; ++i) {
            ArrayList<Object> wrapper = new ArrayList<Object>();
            wrapper.add(value);
            value = wrapper;
        }
        final Object concurrentValue = value;
        final String expected = canonical(SavedInkReader.encodeTree(value, NATIVE_LOADER));
        if (!expected.equals(canonical(SavedInkReader.encodeTree(value, NATIVE_LOADER)))) {
            throw new AssertionError("root encodes are not deterministic");
        }
        SavedInkReader.EncodingBudget unrelated = new SavedInkReader.EncodingBudget();
        unrelated.reserveValues(2_000_000);
        if (!expected.equals(canonical(SavedInkReader.encodeTree(value, NATIVE_LOADER)))) {
            throw new AssertionError("root encode borrowed unrelated budget state");
        }
        final Throwable[] concurrentFailure = new Throwable[1];
        Thread[] workers = new Thread[6];
        for (int index = 0; index < workers.length; ++index) {
            workers[index] = new Thread(new Runnable() {
                @Override public void run() {
                    try {
                        for (int repeat = 0; repeat < 100; ++repeat) {
                            if (!expected.equals(canonical(
                                    SavedInkReader.encodeTree(concurrentValue, NATIVE_LOADER)))) {
                                throw new AssertionError("concurrent root encoding changed output");
                            }
                        }
                    } catch (Throwable error) {
                        synchronized (concurrentFailure) {
                            if (concurrentFailure[0] == null) concurrentFailure[0] = error;
                        }
                    }
                }
            }, "saved-ink-budget-" + index);
            workers[index].start();
        }
        for (Thread worker : workers) worker.join();
        if (concurrentFailure[0] != null) {
            throw new AssertionError("concurrent root budgets were not isolated",
                concurrentFailure[0]);
        }
    }

    private static void testCanonicalWire() {
        assertWire("/", "\"/\"");
        assertWire("</", "\"</\"");
        assertWire("\"", "\"\\\"\"");
        assertWire("\\", "\"\\\\\"");
        assertWire("\b\t\n\f\r", "\"\\b\\t\\n\\f\\r\"");
        assertWire("\u0000\u000b\u001f", "\"\\u0000\\u000b\\u001f\"");
        assertWire("\u007f\u0085", "\"\u007f\u0085\"");
        assertWire("\u2028\u2029", "\"\u2028\u2029\"");
        assertWire("\u05e9\u05dc\u05d5\u05dd e\u0301 \ud83d\ude00",
            "\"\u05e9\u05dc\u05d5\u05dd e\u0301 \ud83d\ude00\"");
        expectCanonicalBound("\ud800", 100);
        expectCanonicalBound("\udc00", 100);

        SavedInkReader.CanonicalObject first = new SavedInkReader.CanonicalObject()
            .put("\ue000", 3).put("z", 1).put("\ud83d\ude00", 2);
        SavedInkReader.CanonicalObject second = new SavedInkReader.CanonicalObject()
            .put("\ud83d\ude00", 2).put("\ue000", 3).put("z", 1);
        String expected = "{\"z\":1,\"\ud83d\ude00\":2,\"\ue000\":3}";
        if (!expected.equals(canonical(first)) || !expected.equals(canonical(second))) {
            throw new AssertionError("canonical object ordering mismatch");
        }
        String orderedArray = canonical(new SavedInkReader.CanonicalArray().put(2).put(1));
        if (!"[2,1]".equals(orderedArray)) throw new AssertionError("array order changed");

        SavedInkReader.CanonicalObject duplicate = new SavedInkReader.CanonicalObject().put("x", null);
        try {
            duplicate.put("x", 1);
            throw new AssertionError("duplicate canonical key admitted");
        } catch (IllegalStateException expectedFailure) { }
    }

    private static void testCanonicalCap() {
        String exactlyAtCap = repeat('x', SavedInkReader.MAX_CAPTURE_BYTES - 2);
        if (SavedInkReader.canonicalJsonBytes(
                exactlyAtCap, SavedInkReader.MAX_CAPTURE_BYTES)
                != SavedInkReader.MAX_CAPTURE_BYTES) {
            throw new AssertionError("exact canonical cap was not measured exactly");
        }
        expectCanonicalBound(exactlyAtCap, SavedInkReader.MAX_CAPTURE_BYTES - 1);
    }

    private static void testGoldenDigest() throws Exception {
        String actual = sha256(goldenPayload().getBytes(StandardCharsets.UTF_8));
        if (!GOLDEN_SHA256.equals(actual)) {
            throw new AssertionError("canonical Java golden digest changed: " + actual);
        }
    }

    private static void testExactNumericEncoding() throws Exception {
        if (!"-2147483648".equals(canonical(SavedInkReader.encodeTree(
                    Integer.MIN_VALUE, NATIVE_LOADER)))
                || !"2147483647".equals(canonical(
                    SavedInkReader.encodeTree(Integer.MAX_VALUE, NATIVE_LOADER)))) {
            throw new AssertionError("signed-32 canonical encoding mismatch");
        }
        if (!("\"" + Long.MIN_VALUE + "\"").equals(canonical(
                    SavedInkReader.encodeTree(Long.MIN_VALUE, NATIVE_LOADER)))
                || !("\"" + Long.MAX_VALUE + "\"").equals(canonical(
                    SavedInkReader.encodeTree(Long.MAX_VALUE, NATIVE_LOADER)))) {
            throw new AssertionError("lossless long encoding mismatch");
        }
        if (!"{\"binary32\":\"80000000\"}".equals(canonical(
                    SavedInkReader.encodeTree(-0.0f, NATIVE_LOADER)))
                || !"{\"binary64\":\"8000000000000000\"}".equals(canonical(
                    SavedInkReader.encodeTree(-0.0d, NATIVE_LOADER)))) {
            throw new AssertionError("signed-zero encoding mismatch");
        }
        expectEncodeBound(Float.NaN);
        expectEncodeBound(Double.POSITIVE_INFINITY);
    }

    private static void testPinnedNestedNativeShapes() throws Exception {
        GoldenTrailRecord.GoldenFlagRect flagRect =
            new GoldenTrailRecord.GoldenFlagRect(
                201, -202, Integer.MAX_VALUE, Integer.MIN_VALUE, 205, -206);
        assertEncodedWire(flagRect,
            "{\"coorOrigin\":-206,\"flag\":205,\"height\":-2147483648,"
            + "\"width\":2147483647,\"x\":201,\"y\":-202}");

        android.graphics.PointF point = new android.graphics.PointF(-0.0f, 1.5f);
        assertEncodedWire(point,
            "[{\"binary32\":\"80000000\"},{\"binary32\":\"3fc00000\"}]");
        ArrayList<Object> contour = new ArrayList<Object>();
        contour.add(point);
        contour.add(new android.graphics.PointF(Float.MIN_VALUE, -Float.MAX_VALUE));
        ArrayList<Object> contours = new ArrayList<Object>();
        contours.add(contour);
        assertEncodedWire(contours,
            "[[[{\"binary32\":\"80000000\"},{\"binary32\":\"3fc00000\"}],"
            + "[{\"binary32\":\"00000001\"},{\"binary32\":\"ff7fffff\"}]]]");

        ArrayList<Object> controls = new ArrayList<Object>();
        controls.add(Integer.MIN_VALUE);
        controls.add(Integer.MAX_VALUE);
        assertEncodedWire(controls, "[-2147483648,2147483647]");

        GoldenTrailRecord.GoldenRecognData recogn =
            new GoldenTrailRecord.GoldenRecognData(
                Integer.MIN_VALUE, Integer.MAX_VALUE, -211, Long.MIN_VALUE);
        assertEncodedWire(recogn,
            "{\"Flag\":-211,\"X\":-2147483648,\"Y\":2147483647,"
            + "\"timestamp\":\"-9223372036854775808\"}");
    }

    private static void testDisposableAuthorityMetadata() {
        int regularReadOnly0440 = 0100000 | 0440;
        int directoryReadOnly0550 = 0040000 | 0550;
        if (!SavedInkReader.admittedDisposableMetadata(
                    1, 1, 0, 2000, regularReadOnly0440)
                || !SavedInkReader.admittedDisposableMetadata(
                    SavedInkReader.MAX_CAPTURE_BYTES, 1, 0, 2000,
                    regularReadOnly0440)) {
            throw new AssertionError("valid root-locked disposable metadata rejected");
        }
        for (long links : new long[] {0, 2}) {
            if (SavedInkReader.admittedDisposableMetadata(
                    1, links, 0, 2000, regularReadOnly0440)) {
                throw new AssertionError("hard-linked disposable input admitted");
            }
        }
        if (SavedInkReader.admittedDisposableMetadata(
                    1, 1, 12345, 2000, regularReadOnly0440)
                || SavedInkReader.admittedDisposableMetadata(
                    1, 1, 2000, 2000, regularReadOnly0440)
                || SavedInkReader.admittedDisposableMetadata(
                    1, 1, 0, 12345, regularReadOnly0440)
                || SavedInkReader.admittedDisposableMetadata(
                    1, 1, 0, 2000, 0100000 | 0400)
                || SavedInkReader.admittedDisposableMetadata(
                    1, 1, 0, 2000, 0100000 | 0640)
                || SavedInkReader.admittedDisposableMetadata(
                    1, 1, 0, 2000, 0100000 | 0441)) {
            throw new AssertionError("unsafe disposable owner/mode admitted");
        }
        if (SavedInkReader.admittedDisposableMetadata(
                    0, 1, 0, 2000, regularReadOnly0440)
                || SavedInkReader.admittedDisposableMetadata(
                    (long)SavedInkReader.MAX_CAPTURE_BYTES + 1L, 1,
                    0, 2000, regularReadOnly0440)) {
            throw new AssertionError("unsafe disposable size admitted");
        }
        if (!SavedInkReader.admittedSnapshotDirectoryMetadata(
                    2, 0, 2000, directoryReadOnly0550)
                || SavedInkReader.admittedSnapshotDirectoryMetadata(
                    2, 2000, 2000, directoryReadOnly0550)
                || SavedInkReader.admittedSnapshotDirectoryMetadata(
                    2, 0, 2000, 0040000 | 0750)
                || SavedInkReader.admittedSnapshotDirectoryMetadata(
                    1, 0, 2000, directoryReadOnly0550)) {
            throw new AssertionError("root-locked directory metadata gate failed");
        }
        for (String valid : new String[] {
                "snapshot.mark", "input-b95c02b0.mark", "A_1.2-z.mark"}) {
            if (!SavedInkReader.admittedSnapshotBasename(valid)) {
                throw new AssertionError("valid snapshot basename rejected: " + valid);
            }
        }
        for (String invalid : new String[] {
                null, "", ".mark", "../x.mark", "x/mark.mark", "x\\mark.mark",
                "snapshot.MARK", "snapshot", "ש.mark"}) {
            if (SavedInkReader.admittedSnapshotBasename(invalid)) {
                throw new AssertionError("unsafe snapshot basename admitted: " + invalid);
            }
        }
        StringBuilder tooLong = new StringBuilder();
        for (int at = 0; at < 123; ++at) tooLong.append('a');
        tooLong.append(".mark");
        if (!SavedInkReader.admittedSnapshotBasename(tooLong.toString())) {
            throw new AssertionError("exact maximum snapshot basename rejected");
        }
        tooLong.insert(0, 'a');
        if (SavedInkReader.admittedSnapshotBasename(tooLong.toString())) {
            throw new AssertionError("overlong snapshot basename admitted");
        }
        SavedInkReader.FileIdentity initial = new SavedInkReader.FileIdentity(
            1, 2, regularReadOnly0440, 1, 0, 2000, 10, 11, 12);
        SavedInkReader.FileIdentity linkAdded = new SavedInkReader.FileIdentity(
            1, 2, regularReadOnly0440, 2, 0, 2000, 10, 11, 12);
        if (initial.same(linkAdded)) {
            throw new AssertionError("link-count mutation did not change file identity");
        }
    }

    private static void testFaultSafeCleanup() throws Exception {
        final ArrayList<Integer> closed = new ArrayList<Integer>();
        Exception primary = new Exception("verification failed");
        try (SavedInkReader.CloseStack cleanup = new SavedInkReader.CloseStack()) {
            cleanup.push(new SavedInkReader.CloseAction() {
                @Override public void close() { closed.add(1); }
            });
            cleanup.push(new SavedInkReader.CloseAction() {
                @Override public void close() throws Exception {
                    closed.add(2);
                    throw new Exception("close failed");
                }
            });
            throw primary;
        } catch (Exception failure) {
            if (failure != primary || failure.getSuppressed().length != 1
                    || !closed.equals(Arrays.asList(2, 1))) {
                throw new AssertionError("verification-failure cleanup was incomplete", failure);
            }
        }
        final boolean[] disarmedClose = new boolean[1];
        try (SavedInkReader.CloseStack cleanup = new SavedInkReader.CloseStack()) {
            cleanup.push(new SavedInkReader.CloseAction() {
                @Override public void close() { disarmedClose[0] = true; }
            });
            cleanup.disarm();
        }
        if (disarmedClose[0]) throw new AssertionError("transferred descriptor was closed");
    }

    private static void testDefiningLoaderGate() {
        SavedInkReader.requireDefinedBy(GoldenTrailRecord.class, NATIVE_LOADER);
        try {
            SavedInkReader.requireDefinedBy(GoldenTrailRecord.class,
                new ClassLoader(NATIVE_LOADER) { });
            throw new AssertionError("foreign defining loader was admitted");
        } catch (IllegalStateException expected) { }
    }

    private static void testShellIdentityGate() {
        SavedInkReader.requireShellProcessIdentity(2000, 2000);
        for (int[] identity : new int[][] {
                {0, 0}, {0, 2000}, {2000, 0}, {1000, 1000}, {2001, 2000}}) {
            try {
                SavedInkReader.requireShellProcessIdentity(identity[0], identity[1]);
                throw new AssertionError("non-shell collector identity admitted");
            } catch (SecurityException expected) { }
        }
    }

    private static void testExactConcreteFastPaths() throws Exception {
        android.graphics.Point point = new android.graphics.Point(7, 8);
        android.graphics.Rect rect = new android.graphics.Rect(1, 2, 3, 4);
        ArrayList<Object> list = new ArrayList<Object>();
        list.add(point);
        SavedInkReader.requireExactConcreteClass(point, android.graphics.Point.class,
            "native point");
        SavedInkReader.requireExactConcreteClass(rect, android.graphics.Rect.class,
            "native rectangle");
        SavedInkReader.requireExactConcreteClass(list, ArrayList.class, "native array");
        SavedInkReader.encodeTree(list, NATIVE_LOADER);

        for (Class<?> expected : new Class<?>[] {
                android.graphics.Point.class, android.graphics.PointF.class,
                android.graphics.Rect.class, android.graphics.RectF.class,
                ArrayList.class}) {
            try {
                SavedInkReader.requireExactConcreteClass(new Object(), expected,
                    "native fast-path value");
                throw new AssertionError("wrong concrete fast-path class admitted");
            } catch (IllegalStateException expectedFailure) { }
        }

        SideEffectList unsafe = new SideEffectList();
        expectEncodeBound(unsafe);
        if (unsafe.accessed) {
            throw new AssertionError("rejected List subtype executed a method");
        }

        SideEffectPointF.accessed = false;
        Object unsafeGeometry = allocateWithoutConstructor(SideEffectPointF.class);
        expectEncodeBound(unsafeGeometry);
        if (SideEffectPointF.accessed) {
            throw new AssertionError("rejected geometry subtype executed a method");
        }
    }

    private static void testNativeRecordLoaderIntegration() throws Exception {
        ArrayList<Object> records = new ArrayList<Object>();
        records.add(new GoldenTrailRecord());
        Object encoded = SavedInkReader.encodeNativeRecordList(records, NATIVE_LOADER,
            GoldenTrailRecord.class.getName());
        if (!(encoded instanceof SavedInkReader.CanonicalArray)) {
            throw new AssertionError("exact native record list was not encoded");
        }
        try {
            SavedInkReader.encodeNativeRecordList(records,
                new ClassLoader(NATIVE_LOADER) { }, GoldenTrailRecord.class.getName());
            throw new AssertionError("production record encode admitted foreign loader");
        } catch (IllegalStateException expected) { }
        try {
            SavedInkReader.encodeNativeRecordList(Arrays.asList(new GoldenTrailRecord()),
                NATIVE_LOADER, GoldenTrailRecord.class.getName());
            throw new AssertionError("non-exact top-level list implementation admitted");
        } catch (IllegalStateException expected) { }
        try {
            SavedInkReader.encodeNativeRecordList(records, NATIVE_LOADER,
                GoldenTrailRecord.GoldenObject.class.getName());
            throw new AssertionError("unexpected top-level native record class admitted");
        } catch (IllegalStateException expected) { }
        try {
            SavedInkReader.encodeTree(new GoldenTrailRecord(),
                new ClassLoader(NATIVE_LOADER) { });
            throw new AssertionError("recursive reflective encode admitted foreign loader");
        } catch (IllegalStateException expected) { }
    }

    private static void testNumericWrapperObjectKeyCollisions() throws Exception {
        expectEncodeBound(new GoldenTrailRecord.Binary32CollisionObject());
        expectEncodeBound(new GoldenTrailRecord.Binary64CollisionObject());
        // Numeric values themselves retain the frozen v2 singleton wrappers.
        if (!"{\"binary32\":\"3f800000\"}".equals(canonical(
                    SavedInkReader.encodeTree(1.0f, NATIVE_LOADER)))
                || !"{\"binary64\":\"3ff0000000000000\"}".equals(canonical(
                    SavedInkReader.encodeTree(1.0d, NATIVE_LOADER)))) {
            throw new AssertionError("numeric wrapper wire changed");
        }
    }

    private static void testEvidencePublication() throws Exception {
        byte[] payload = SavedInkReader.strictUtf8Bytes(
            goldenPayload(), SavedInkReader.MAX_CAPTURE_BYTES);
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        PrintStream output = new PrintStream(bytes, false, "UTF-8");
        SavedInkReader.publishEvidenceFrame(output, payload);
        byte[] expected = new byte[SavedInkReader.EVIDENCE_PREFIX.length + payload.length + 1];
        System.arraycopy(SavedInkReader.EVIDENCE_PREFIX, 0, expected, 0,
            SavedInkReader.EVIDENCE_PREFIX.length);
        System.arraycopy(payload, 0, expected, SavedInkReader.EVIDENCE_PREFIX.length,
            payload.length);
        expected[expected.length - 1] = '\n';
        if (!Arrays.equals(expected, bytes.toByteArray())) {
            throw new AssertionError("collector evidence frame changed");
        }

        PrintStream failed = new PrintStream(new OutputStream() {
            @Override public void write(int value) throws IOException {
                throw new IOException("injected collector stdout failure");
            }
        }, false, "UTF-8");
        try {
            SavedInkReader.publishEvidenceFrame(failed, payload);
            throw new AssertionError("PrintStream write failure was swallowed");
        } catch (IllegalStateException expectedFailure) { }
        if (!failed.checkError()) {
            throw new AssertionError("injected PrintStream failure was not retained");
        }
    }

    private static String canonical(Object value) {
        return SavedInkReader.canonicalJson(value, SavedInkReader.MAX_CAPTURE_BYTES);
    }

    private static String goldenPayload() throws Exception {
        ArrayList<Object> records = new ArrayList<Object>();
        records.add(new GoldenTrailRecord());
        Object encodedTrails = SavedInkReader.encodeNativeRecordList(
            records, NATIVE_LOADER, GoldenTrailRecord.class.getName());
        return SavedInkReader.canonicalJson(
            SavedInkReader.evidenceEnvelope(SHA_A, 1, encodedTrails, SHA_B, SHA_B),
            SavedInkReader.MAX_CAPTURE_BYTES);
    }

    private static String sha256(byte[] value) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(value);
        StringBuilder result = new StringBuilder();
        for (byte part : digest) result.append(String.format("%02x", part & 255));
        return result.toString();
    }

    private static void assertWire(String value, String expected) {
        String actual = SavedInkReader.canonicalJson(value, 1024);
        if (!expected.equals(actual)
                || SavedInkReader.canonicalJsonBytes(value, 1024)
                    != SavedInkReader.strictUtf8Length(expected, 1024)) {
            throw new AssertionError("canonical string mismatch for " + expected);
        }
    }

    private static void assertEncodedWire(Object value, String expected) throws Exception {
        String actual = canonical(SavedInkReader.encodeTree(value, NATIVE_LOADER));
        if (!expected.equals(actual)) {
            throw new AssertionError("native nested wire mismatch: " + actual);
        }
    }

    private static String repeat(char value, int count) {
        char[] values = new char[count];
        Arrays.fill(values, value);
        return new String(values);
    }

    private static String repeatString(String value, int count) {
        StringBuilder result = new StringBuilder(value.length() * count);
        for (int index = 0; index < count; ++index) result.append(value);
        return result.toString();
    }

    private static void expectValueBound(SavedInkReader.EncodingBudget budget, int count) {
        try {
            budget.reserveValues(count);
            throw new AssertionError("expected value bound rejection");
        } catch (IllegalStateException expected) { }
    }

    private static void expectEncodeBound(Object value) throws Exception {
        try {
            SavedInkReader.encodeTree(value, NATIVE_LOADER);
            throw new AssertionError("expected encode bound rejection");
        } catch (IllegalStateException expected) { }
    }

    private static void expectCanonicalBound(Object value, int limit) {
        try {
            SavedInkReader.canonicalJsonBytes(value, limit);
            throw new AssertionError("expected canonical byte/surrogate rejection");
        } catch (IllegalStateException expected) { }
    }

    private static Object allocateWithoutConstructor(Class<?> type) throws Exception {
        // android.jar constructors deliberately throw on a host JVM. Allocate
        // the test-only subtype without its constructor so the production
        // dispatch itself—not an SDK stub—decides whether it is admitted.
        Class<?> unsafeType = Class.forName("sun.misc.Unsafe");
        java.lang.reflect.Field singleton = unsafeType.getDeclaredField("theUnsafe");
        singleton.setAccessible(true);
        Object unsafe = singleton.get(null);
        return unsafeType.getMethod("allocateInstance", Class.class).invoke(unsafe, type);
    }

    private static final class SideEffectList extends ArrayList<Object> {
        boolean accessed;

        @Override public int size() {
            accessed = true;
            return super.size();
        }

        @Override public java.util.Iterator<Object> iterator() {
            accessed = true;
            return super.iterator();
        }
    }

    private static final class SideEffectPointF extends android.graphics.PointF {
        static boolean accessed;

        @Override public boolean equals(Object value) {
            accessed = true;
            return super.equals(value);
        }

        @Override public int hashCode() {
            accessed = true;
            return super.hashCode();
        }

        @Override public String toString() {
            accessed = true;
            return super.toString();
        }
    }
}
