package com.techrebbe.supernote.viewportprobe;

import android.graphics.Point;
import android.graphics.PointF;
import android.graphics.Rect;
import android.graphics.RectF;
import dalvik.system.DexClassLoader;
import org.json.JSONArray;
import org.json.JSONObject;
import java.io.File;
import java.io.FileInputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.List;

/**
 * Disposable-copy reader for a SEPARATE app_process, never Document/DrawPath.
 * Not an APK, LSPosed hook, writer, converter, or production export API.
 * All native state is private to the helper process. No Binder connection.
 */
public final class SavedInkReader {
    private static final String APK_SHA =
        "f008c86ddc42008c36b431410cbc3b29057b4aad9bc26c3577ee13b39b230482";
    private static final String ROOT = "/data/local/tmp/native-viewport-ink-reader/";
    private static final String APK = "/system_ext/app/SupernoteDocument/SupernoteDocument.apk";
    private static final String LIBS = "/system_ext/app/SupernoteDocument/lib/arm64";
    private static final String RECOGNITION_SHA =
        "898129ad25fe90734f2b9760786c846864f3622ebd82c25c5a3ce82ca4174919";
    private static final String PROCESS_SHA =
        "b7af795b72076e1996aa88dee3db32feecc25b89da01e9c96db8a86696c9bff4";
    private static int values;

    public static void main(String[] args) {
        try {
            JSONObject result = collect(args);
            System.out.println("NATIVE_VIEWPORT_INK_EVIDENCE " + result.toString());
        } catch (Throwable error) {
            System.err.println("NATIVE_VIEWPORT_INK_FAILED " + error.getClass().getName()
                + ": " + error.getMessage());
            System.exit(2);
        }
    }

    private static JSONObject collect(String[] args) throws Exception {
        if (args.length != 5 || !args[3].matches("[0-9a-f]{64}")
            || !args[4].matches("[1-9][0-9]*")) {
            throw new IllegalArgumentException("apk nativeLibDir disposableCopy.mark sourceSha256 nativePage1Based");
        }
        int page = Integer.parseInt(args[4]);
        File copy = new File(args[2]);
        String path = copy.getCanonicalPath();
        // Never accepts a Document/MyStyle file or a renamed symlink to one.
        if (!path.equals(copy.getAbsolutePath()) || !path.startsWith(ROOT)
            || !path.endsWith(".mark") || !copy.isFile() || Files.isSymbolicLink(copy.toPath())
            || copy.length() == 0 || copy.length() > 32L * 1024 * 1024) {
            throw new IllegalArgumentException("only a bounded disposable .mark copy is admitted");
        }
        File apk = new File(args[0]);
        File libs = new File(args[1]);
        if (!APK.equals(apk.getCanonicalPath()) || !LIBS.equals(libs.getCanonicalPath())
            || !apk.isFile() || !libs.isDirectory() || !firmwareMatches(apk, libs)) {
            throw new IllegalArgumentException("pinned firmware APK/native library directory required");
        }
        String before = sha(copy);
        // Only the pinned, read-only system APK/library directory is admitted.
        DexClassLoader loader = new DexClassLoader(apk.getCanonicalPath(), ROOT,
            libs.getCanonicalPath(), SavedInkReader.class.getClassLoader());
        Class<?> constants = Class.forName("com.ratta.supernote.documentlib.constants.DocumentConstants", true, loader);
        int deviceType = (Integer)constants.getMethod("getDeviceType").invoke(null);
        if (deviceType != 2) throw new IllegalStateException("this diagnostic is limited to the A6X2 Nomad");
        Class<?> type = Class.forName("com.example.libsupernote.SuperNoteNote", true, loader);
        Object note = type.getMethod("createSuperNoteNote").invoke(null);
        if (note == null) throw new IllegalStateException("no native note");
        JSONObject result;
        try {
            // Native SuperNoteNoteUtils.init uses getDeviceType() + 2, not the
            // device enum itself: Nomad enum 2 therefore initializes with 4.
            if (!Boolean.TRUE.equals(type.getMethod("markInitProcess", int.class).invoke(note, deviceType + 2))) {
                throw new IllegalStateException("native Nomad initialization refused");
            }
            // Match the native SDK's read-only PDF admission: an absent mark
            // page is not evidence of a successfully read empty page. Never
            // call createPageForMark to turn this diagnostic failure into data.
            Object pageInventory = type.getMethod("fetchPagesOfMark", String.class).invoke(note, path);
            if (!(pageInventory instanceof List<?>) || ((List<?>)pageInventory).size() > 100000) {
                throw new IllegalStateException("saved mark page inventory unavailable");
            }
            HashSet<Integer> pages = new HashSet<Integer>();
            for (Object entry : (List<?>)pageInventory) {
                if (!(entry instanceof Integer) || (Integer)entry < 1 || !pages.add((Integer)entry)) {
                    throw new IllegalStateException("invalid saved mark page inventory");
                }
            }
            if (!pages.contains(page)) throw new IllegalStateException("requested page has no saved mark record");
            Object list = type.getMethod("getFilePageTrails", String.class, int.class)
                .invoke(note, path, page);
            if (!(list instanceof List<?>) || ((List<?>)list).size() > 4096) {
                throw new IllegalStateException("no complete bounded saved-page list");
            }
            Object records = encode(list, new IdentityHashMap<Object, Boolean>(), 0);
            result = new JSONObject().put("schema", "native-viewport-ink-evidence-v1")
                .put("sourceSha256", args[3]).put("nativePage", page)
                .put("readMethod", "getFilePageTrails").put("trails", records);
        } finally {
            type.getMethod("freeCommon").invoke(note);
        }
        // No successful publication if cleanup or the final integrity check fails.
        String after = sha(copy);
        if (!before.equals(after) || !firmwareMatches(apk, libs)
            || !path.equals(copy.getCanonicalPath()) || Files.isSymbolicLink(copy.toPath())) {
            throw new IllegalStateException("input authority changed during native read");
        }
        return result.put("markSha256Before", before).put("markSha256After", after)
            .put("complete", true);
    }

    private static boolean firmwareMatches(File apk, File libs) throws Exception {
        return APK_SHA.equals(sha(apk))
            && RECOGNITION_SHA.equals(sha(new File(libs, "librecgnition.so")))
            && PROCESS_SHA.equals(sha(new File(libs, "libratta_sn_process.so")));
    }

    private static String sha(File file) throws Exception {
        MessageDigest hash = MessageDigest.getInstance("SHA-256");
        try (FileInputStream input = new FileInputStream(file)) {
            byte[] buffer = new byte[65536];
            for (int count; (count = input.read(buffer)) != -1;) hash.update(buffer, 0, count);
        }
        StringBuilder result = new StringBuilder();
        for (byte value : hash.digest()) result.append(String.format("%02x", value & 255));
        return result.toString();
    }

    private static Object encode(Object value, IdentityHashMap<Object, Boolean> visiting,
                                 int depth) throws Exception {
        if (++values > 2000000 || depth > 16) throw new IllegalStateException("native data exceeds bound");
        if (value == null) return JSONObject.NULL;
        if (value instanceof String) {
            if (((String)value).length() > 65536) throw new IllegalStateException("oversized string");
            return value;
        }
        if (value instanceof Boolean || value instanceof Integer || value instanceof Short
            || value instanceof Byte) return value;
        if (value instanceof Long) return value.toString(); // preserve all 64 bits
        if (value instanceof Float || value instanceof Double) {
            if (!Double.isFinite(((Number)value).doubleValue())) throw new IllegalStateException("nonfinite native value");
            // Android JSONObject's decimal formatter drops signed zero and
            // float precision/type distinctions. Keep exact native bit patterns.
            return value instanceof Float
                ? new JSONObject().put("binary32", String.format("%08x", Float.floatToRawIntBits((Float)value)))
                : new JSONObject().put("binary64", String.format("%016x", Double.doubleToRawLongBits((Double)value)));
        }
        if (value instanceof Point) return new JSONArray().put(((Point)value).x).put(((Point)value).y);
        if (value instanceof PointF) return new JSONArray()
            .put(encode(((PointF)value).x, visiting, depth + 1))
            .put(encode(((PointF)value).y, visiting, depth + 1));
        if (value instanceof Rect) {
            Rect r = (Rect)value; return new JSONArray().put(r.left).put(r.top).put(r.right).put(r.bottom);
        }
        if (value instanceof RectF) {
            RectF r = (RectF)value; return new JSONArray()
                .put(encode(r.left, visiting, depth + 1)).put(encode(r.top, visiting, depth + 1))
                .put(encode(r.right, visiting, depth + 1)).put(encode(r.bottom, visiting, depth + 1));
        }
        if (visiting.put(value, Boolean.TRUE) != null) throw new IllegalStateException("cyclic native record");
        try {
            if (value instanceof List<?>) {
                List<?> list = (List<?>)value;
                if (list.size() > 200000) throw new IllegalStateException("oversized native array");
                JSONArray array = new JSONArray();
                for (Object child : list) array.put(encode(child, visiting, depth + 1));
                return array;
            }
            Class<?> type = value.getClass();
            if (!type.getName().startsWith("com.example.libsupernote.")
                || type.getSuperclass() != Object.class) {
                throw new IllegalStateException("unhandled native field type: " + type.getName());
            }
            Field[] fields = type.getDeclaredFields();
            Arrays.sort(fields, Comparator.comparing(Field::getName));
            JSONObject object = new JSONObject();
            for (Field field : fields) {
                if (Modifier.isStatic(field.getModifiers())) continue;
                field.setAccessible(true);
                object.put(field.getName(), encode(field.get(value), visiting, depth + 1));
            }
            return object;
        } finally { visiting.remove(value); }
    }
}
