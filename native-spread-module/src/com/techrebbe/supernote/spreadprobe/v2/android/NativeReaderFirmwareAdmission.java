package com.techrebbe.supernote.spreadprobe.v2.android;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * Fail-closed symbol admission for the one inspected SupernoteDocument build.
 * No v2 behavior-changing hook may be installed unless every field and method
 * below resolves with its exact declared type/signature.
 */
public final class NativeReaderFirmwareAdmission {
    public static final String CONTRACT_ID =
        "supernote-document-1.02.446-native-reader-v2-symbols-v2";
    public static final String EXPECTED_SYMBOL_DIGEST =
        "f3df28a4f2c4a8e002371415c2420f49184c5c3971534ebcfe4ce4ffc66ba6d5";

    private static final String ACTIVITY =
        "com.supernote.document.document.DocumentActivity";
    private static final String VIEW_MODEL =
        "com.supernote.document.document.DocumentViewModel";
    private static final String PAGE_INFO =
        "com.supernote.document.document.PageInfo";
    private static final String PRESENTER =
        "com.supernote.document.handwrite.HandWritePresenter";
    private static final String HAND_WRITE_VIEW =
        "com.supernote.document.handwrite.HandWriteView";
    private static final String HAND_WRITE_CLIENT =
        "com.supernote.document.handwrite.HandWriteClient";
    private static final String NATIVE_CALLBACK = ACTIVITY + "$6";

    private static final String[] SYMBOLS = new String[] {
        field(ACTIVITY, "documentViewModel", VIEW_MODEL),
        field(ACTIVITY, "handWritePresenter", PRESENTER),
        field(ACTIVITY, "handWriteView",
            HAND_WRITE_VIEW),
        field(ACTIVITY, "mImage",
            "com.supernote.document.utils.view.DocumentImageView"),
        field(ACTIVITY, "mContentView", "android.view.View"),
        field(ACTIVITY, "documentViewLayout", "android.widget.RelativeLayout"),
        field(ACTIVITY, "eventCallBack",
            "com.ratta.supernote.eventlibrary.NativeEventCallBack"),
        field(ACTIVITY, "documentImageReady", "boolean"),
        field(ACTIVITY, "handWriteInitReady", "boolean"),
        method(ACTIVITY, "dispatchTouchEvent", "boolean",
            "android.view.MotionEvent"),
        method(ACTIVITY, "onCreate", "void", "android.os.Bundle"),
        method(ACTIVITY, "onResume", "void"),
        method(ACTIVITY, "onPause", "void"),
        method(ACTIVITY, "onDestroy", "void"),
        method(ACTIVITY, "onConfigurationChanged", "void",
            "android.content.res.Configuration"),
        method(ACTIVITY, "loadPageChanged", "void",
            "com.supernote.document.document.bean.LoadPageResult"),
        method(ACTIVITY, "displayChanged", "void",
            "com.supernote.document.document.bean.DisplayResult"),
        method(ACTIVITY, "setImage", "void", "android.graphics.Bitmap"),
        method(ACTIVITY, "updateImage", "void", "android.graphics.Bitmap"),
        method(ACTIVITY, "setDigestImage", "void", "android.graphics.Bitmap"),
        method(ACTIVITY, "sendDisableWriteArea", "void"),
        method(ACTIVITY, "sendDisableWriteAreaNotRefreshBitmap", "boolean"),
        method(ACTIVITY, "getDisableRectList", "java.util.List"),
        method(ACTIVITY, "changeSelectTextModel", "void", "int"),
        method(ACTIVITY, "handWriteSelectText", "void",
            "int", "java.util.List"),
        method(ACTIVITY, "showSelectTextPopView", "void"),
        method(ACTIVITY, "onGlobalLayout", "void"),

        field(VIEW_MODEL, "currentPage", "int"),
        field(VIEW_MODEL, "pageCount", "int"),
        field(VIEW_MODEL, "pageInfo", PAGE_INFO),
        field(VIEW_MODEL, "pageInfoHashMap", "java.util.HashMap"),
        field(VIEW_MODEL, "mupdf",
            "com.supernote.document.document.DocumentMupdf"),
        field(VIEW_MODEL, "uri", "android.net.Uri"),
        method(VIEW_MODEL, "loadPage", "void", "int"),
        method(VIEW_MODEL, "turnPage", "void", "int"),
        method(VIEW_MODEL, "reloadPage", "void"),
        method(VIEW_MODEL, "getCurrentPage", "int"),
        method(VIEW_MODEL, "getPageCount", "int"),
        method(VIEW_MODEL, "getPageInfo", PAGE_INFO),
        method(VIEW_MODEL, "getOriginBitmap", "android.graphics.Bitmap"),
        method(VIEW_MODEL, "getShowRect", "android.graphics.RectF"),
        method(VIEW_MODEL, "getDisplayTrimmingRect", "android.graphics.RectF"),
        method(VIEW_MODEL, "checkLink",
            "com.supernote.document.document.bean.CheckLinkResult",
            "com.artifex.mupdf.fitz.Point"),

        field(PAGE_INFO, "ctm", "com.artifex.mupdf.fitz.Matrix"),
        field(PAGE_INFO, "revertCtm", "com.artifex.mupdf.fitz.Matrix"),
        field(PAGE_INFO, "originBitmap", "android.graphics.Bitmap"),
        field(PAGE_INFO, "displayBitmap", "android.graphics.Bitmap"),
        field(PAGE_INFO, "offsetX", "int"),
        field(PAGE_INFO, "offsetY", "int"),
        field(PAGE_INFO, "page", "int"),
        method(PAGE_INFO, "getCtm", "com.artifex.mupdf.fitz.Matrix"),
        method(PAGE_INFO, "getRevertCtm", "com.artifex.mupdf.fitz.Matrix"),
        method(PAGE_INFO, "getOriginBitmap", "android.graphics.Bitmap"),
        method(PAGE_INFO, "getDisplayBitmap", "android.graphics.Bitmap"),
        method(PAGE_INFO, "getOffsetX", "int"),
        method(PAGE_INFO, "getOffsetY", "int"),
        method(PAGE_INFO, "getPage", "int"),
        method(PAGE_INFO, "setOriginBitmap", "void", "android.graphics.Bitmap"),
        method(PAGE_INFO, "setDisplayBitmap", "void", "android.graphics.Bitmap"),
        method(PAGE_INFO, "originBitmapIsLandscape", "boolean"),

        field(PRESENTER, "currentPage", "int"),
        field(PRESENTER, "markPath", "java.lang.String"),
        field(PRESENTER, "screenRotation", "int"),
        field(PRESENTER, "superNoteNote",
            "com.example.libsupernote.SuperNoteNote"),
        field(PRESENTER, "handWriteClient",
            "com.supernote.document.handwrite.HandWriteClient"),
        field(PRESENTER, "view",
            "com.supernote.document.handwrite.HandWriteContract$View"),
        method(PRESENTER, "saveTrails", "void", "boolean"),
        method(PRESENTER, "disableHandWrite", "void", "java.lang.String"),
        method(PRESENTER, "loadPage", "void",
            "int", "android.graphics.RectF"),
        method(PRESENTER, "getCurrentPage", "int"),
        method(PRESENTER, "getMarkPath", "java.lang.String"),
        method(PRESENTER, "getHandWriteOriginBitmap",
            "android.graphics.Bitmap", "int"),
        method(PRESENTER, "showDisplayBitmap", "void",
            "int", "android.graphics.RectF"),
        method(PRESENTER, "sendWriteInfo", "void"),
        method(PRESENTER, "setDisableAreaList", "void",
            "java.lang.String", "java.util.List"),
        method(PRESENTER, "receiveTrials", "void"),
        method(PRESENTER, "refreshBitmap", "void"),
        method(PRESENTER, "setOnGlobalLayout", "void", "boolean"),
        method(PRESENTER, "setPen", "void", "int", "int", "int"),
        method(PRESENTER, "sendEraserInfo", "void", "int"),
        method(PRESENTER, "setAreaSelection", "void"),
        method(PRESENTER, "reWriteTrails", "void"),
        method(PRESENTER, "undo", "void"),
        method(PRESENTER, "redo", "void"),

        method(HAND_WRITE_VIEW, "setBitmap", "void", "android.graphics.Bitmap"),
        method(HAND_WRITE_VIEW, "cancelAreaSelect", "void"),
        method(HAND_WRITE_VIEW, "clearAreaSelectionView", "void"),

        field(HAND_WRITE_CLIENT, "iBinder", "android.os.IBinder"),

        field(NATIVE_CALLBACK, "mPressure", "int"),
        method(NATIVE_CALLBACK, "onDigitalPosition", "void", "int", "int"),
        method(NATIVE_CALLBACK, "onDigital", "void", "int")
    };

    private NativeReaderFirmwareAdmission() {}

    public static final class Report {
        public final String contractId;
        public final String symbolDigest;
        public final int symbolCount;

        private Report(String symbolDigest) {
            this.contractId = CONTRACT_ID;
            this.symbolDigest = symbolDigest;
            this.symbolCount = SYMBOLS.length;
        }
    }

    public static Report verify(ClassLoader classLoader) {
        if (classLoader == null) {
            throw new IllegalArgumentException("classLoader is required");
        }
        String digest = digest(SYMBOLS);
        if (!EXPECTED_SYMBOL_DIGEST.equals(digest)) {
            throw new IllegalStateException(
                "compiled firmware symbol contract digest mismatch: " + digest
            );
        }
        for (String encoded : SYMBOLS) {
            verifySymbol(classLoader, encoded);
        }
        return new Report(digest);
    }

    /** Exposed for deterministic build/package verification. */
    public static String compiledSymbolDigest() {
        return digest(SYMBOLS);
    }

    private static void verifySymbol(ClassLoader classLoader, String encoded) {
        String[] parts = encoded.split("\\|", -1);
        try {
            Class<?> owner = Class.forName(parts[1], false, classLoader);
            if ("F".equals(parts[0])) {
                Field field = owner.getDeclaredField(parts[2]);
                if (!field.getType().getName().equals(parts[3])) {
                    throw new NoSuchFieldException(encoded);
                }
                return;
            }
            String[] parameterNames = parts[4].isEmpty()
                ? new String[0] : parts[4].split(",", -1);
            Class<?>[] parameterTypes = new Class<?>[parameterNames.length];
            for (int index = 0; index < parameterNames.length; index++) {
                parameterTypes[index] = resolveType(
                    classLoader,
                    parameterNames[index]
                );
            }
            Method method = owner.getDeclaredMethod(parts[2], parameterTypes);
            if (!method.getReturnType().getName().equals(parts[3])) {
                throw new NoSuchMethodException(encoded);
            }
        } catch (ReflectiveOperationException exception) {
            throw new IllegalStateException(
                "required firmware symbol is missing or changed: " + encoded,
                exception
            );
        }
    }

    private static Class<?> resolveType(
        ClassLoader classLoader,
        String typeName
    ) throws ClassNotFoundException {
        if ("boolean".equals(typeName)) return Boolean.TYPE;
        if ("int".equals(typeName)) return Integer.TYPE;
        if ("long".equals(typeName)) return Long.TYPE;
        if ("float".equals(typeName)) return Float.TYPE;
        if ("double".equals(typeName)) return Double.TYPE;
        if ("void".equals(typeName)) return Void.TYPE;
        return Class.forName(typeName, false, classLoader);
    }

    private static String field(String owner, String name, String type) {
        return "F|" + owner + "|" + name + "|" + type + "|";
    }

    private static String method(
        String owner,
        String name,
        String returnType,
        String... parameterTypes
    ) {
        StringBuilder value = new StringBuilder()
            .append("M|").append(owner).append('|').append(name)
            .append('|').append(returnType).append('|');
        for (int index = 0; index < parameterTypes.length; index++) {
            if (index > 0) value.append(',');
            value.append(parameterTypes[index]);
        }
        return value.toString();
    }

    private static String digest(String[] symbols) {
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            for (String symbol : symbols) {
                sha256.update(symbol.getBytes(StandardCharsets.UTF_8));
                sha256.update((byte) '\n');
            }
            StringBuilder value = new StringBuilder(64);
            for (byte item : sha256.digest()) {
                value.append(String.format("%02x", item & 0xff));
            }
            return value.toString();
        } catch (Exception exception) {
            throw new IllegalStateException("SHA-256 unavailable", exception);
        }
    }

    static String[] symbolsForTests() {
        return Arrays.copyOf(SYMBOLS, SYMBOLS.length);
    }
}
