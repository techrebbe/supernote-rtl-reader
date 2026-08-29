package com.techrebbe.supernote.virtualspread;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.net.Uri;
import android.os.Binder;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Process;
import android.os.SystemClock;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Memory-only, process-liveness-bound delivery API for the active native
 * Virtual Spread viewport. Shared storage is deliberately not an authority.
 */
public final class NativeViewportProvider extends ContentProvider {
    public static final String AUTHORITY =
        "com.techrebbe.supernote.virtualspread.viewport";
    public static final Uri CONTENT_URI = Uri.parse(
        "content://" + AUTHORITY + "/v1/current"
    );
    public static final String METHOD_PUBLISH = "publish_v1";
    public static final String METHOD_BEGIN_LOAD = "begin_load_v1";
    public static final String METHOD_CLEAR = "clear_v1";
    public static final String METHOD_CLEAR_GENERATION =
        "clear_generation_v1";
    public static final String METHOD_GET = "get_v1";

    private static final String WRITER_PACKAGE = "com.supernote.document";
    private static final String READER_PACKAGE =
        "com.ratta.supernote.pluginhost";
    private static final Object LOCK = new Object();
    private static final NativeViewportGenerationFence LOAD_FENCE =
        new NativeViewportGenerationFence();
    private static Record current;

    private static final class Record implements IBinder.DeathRecipient {
        final NativeViewportDescriptor descriptor;
        final String descriptorJson;
        final String descriptorSha256;
        final String documentPath;
        final String sidecarPath;
        final String generatedPdfSha256;
        final String sidecarSha256;
        final String mappingAuthoritySha256;
        final String snapshotId;
        final String pdfIdentity;
        final String sidecarIdentity;
        final long verificationGeneration;
        final long pageLoadGeneration;
        final long publishedAtElapsedRealtime;
        final IBinder sessionToken;

        Record(Bundle input) {
            descriptor = NativeViewportDescriptor.fromBundle(input);
            descriptorJson = descriptor.authority.canonicalJson();
            descriptorSha256 = sha256(descriptorJson);
            documentPath = exactString(input, "documentPath");
            sidecarPath = exactString(input, "sidecarPath");
            generatedPdfSha256 = exactSha256(
                input, "generatedPdfSha256"
            );
            sidecarSha256 = exactSha256(input, "sidecarSha256");
            mappingAuthoritySha256 = exactSha256(
                input, "mappingAuthoritySha256"
            );
            snapshotId = exactString(input, "snapshotId");
            pdfIdentity = exactString(input, "pdfIdentity");
            sidecarIdentity = exactString(input, "sidecarIdentity");
            verificationGeneration = exactNonNegativeLong(
                input, "verificationGeneration"
            );
            pageLoadGeneration = exactNonNegativeLong(
                input, "pageLoadGeneration"
            );
            sessionToken = input == null ? null
                : input.getBinder("sessionToken");
            if (sessionToken == null || !sessionToken.isBinderAlive()) {
                throw new IllegalArgumentException(
                    "live document-process session token is required"
                );
            }
            if (!sidecarPath.equals(documentPath + ".json")) {
                throw new IllegalArgumentException(
                    "sidecar path is not derived from the active PDF"
                );
            }
            if (!snapshotId.equals(pdfIdentity + ":" + sidecarIdentity)) {
                throw new IllegalArgumentException(
                    "snapshot identity does not bind both activated files"
                );
            }
            publishedAtElapsedRealtime = SystemClock.elapsedRealtime();
        }

        boolean matchesRequest(Bundle request) {
            if (request == null || !sessionToken.isBinderAlive()) {
                return false;
            }
            return LOAD_FENCE.accepts(
                    sessionToken, pageLoadGeneration
                )
                && descriptor.authority.documentId.equals(
                    request.getString("documentId")
                )
                && descriptor.authority.viewId.equals(
                    request.getString("viewId")
                )
                && request.containsKey("virtualPageIndex")
                && descriptor.authority.virtualPageIndex
                    == request.getInt("virtualPageIndex", -1)
                && request.containsKey("nativeWidth")
                && descriptor.authority.nativeWidth
                    == request.getInt("nativeWidth", -1)
                && request.containsKey("nativeHeight")
                && descriptor.authority.nativeHeight
                    == request.getInt("nativeHeight", -1)
                && documentPath.equals(request.getString("documentPath"))
                && generatedPdfSha256.equals(
                    request.getString("generatedPdfSha256")
                )
                && sidecarSha256.equals(
                    request.getString("sidecarSha256")
                )
                && mappingAuthoritySha256.equals(
                    request.getString("mappingAuthoritySha256")
                );
        }

        Bundle response() {
            Bundle response = new Bundle();
            response.putInt("protocolVersion", 1);
            response.putString("status", "ok");
            response.putString("descriptorJson", descriptorJson);
            response.putString("descriptorSha256", descriptorSha256);
            response.putString("documentPath", documentPath);
            response.putString("sidecarPath", sidecarPath);
            response.putString(
                "generatedPdfSha256", generatedPdfSha256
            );
            response.putString("sidecarSha256", sidecarSha256);
            response.putString(
                "mappingAuthoritySha256", mappingAuthoritySha256
            );
            response.putString("snapshotId", snapshotId);
            response.putString("pdfIdentity", pdfIdentity);
            response.putString("sidecarIdentity", sidecarIdentity);
            response.putLong(
                "verificationGeneration", verificationGeneration
            );
            response.putLong("pageLoadGeneration", pageLoadGeneration);
            response.putLong(
                "publishedAtElapsedRealtime",
                publishedAtElapsedRealtime
            );
            return response;
        }

        void link() throws android.os.RemoteException {
            sessionToken.linkToDeath(this, 0);
        }

        void unlink() {
            sessionToken.unlinkToDeath(this, 0);
        }

        @Override
        public void binderDied() {
            synchronized (LOCK) {
                if (current == this) {
                    current = null;
                }
                LOAD_FENCE.clear(sessionToken);
            }
        }
    }

    private static final class NativeViewportDescriptor {
        final NativeViewportAuthority.Descriptor authority;

        NativeViewportDescriptor(
            NativeViewportAuthority.Descriptor authority
        ) {
            this.authority = authority;
        }

        static NativeViewportDescriptor fromBundle(Bundle input) {
            if (input == null) {
                throw new IllegalArgumentException(
                    "viewport publication bundle is required"
                );
            }
            return new NativeViewportDescriptor(
                NativeViewportAuthority.Descriptor.validated(
                    exactString(input, "documentId"),
                    exactString(input, "viewId"),
                    exactNonNegativeInt(input, "virtualPageIndex"),
                    exactPositiveInt(input, "nativeWidth"),
                    exactPositiveInt(input, "nativeHeight"),
                    input.getDoubleArray("spreadToNative")
                )
            );
        }
    }

    @Override
    public boolean onCreate() {
        return true;
    }

    @Override
    public Bundle call(String method, String arg, Bundle extras) {
        if (METHOD_PUBLISH.equals(method)) {
            requireCaller(WRITER_PACKAGE);
            return publish(extras);
        }
        if (METHOD_BEGIN_LOAD.equals(method)) {
            requireCaller(WRITER_PACKAGE);
            return beginLoad(extras);
        }
        if (METHOD_CLEAR.equals(method)) {
            requireCaller(WRITER_PACKAGE);
            return clear(extras);
        }
        if (METHOD_CLEAR_GENERATION.equals(method)) {
            requireCaller(WRITER_PACKAGE);
            return clearGeneration(extras);
        }
        if (METHOD_GET.equals(method)) {
            requireCaller(READER_PACKAGE);
            return get(extras);
        }
        throw new IllegalArgumentException("unsupported viewport API method");
    }

    private Bundle publish(Bundle extras) {
        Record replacement = new Record(extras);
        try {
            replacement.link();
        } catch (android.os.RemoteException error) {
            throw new IllegalStateException(
                "document process died before viewport publication",
                error
            );
        }
        synchronized (LOCK) {
            if (!LOAD_FENCE.accepts(
                    replacement.sessionToken,
                    replacement.pageLoadGeneration
                )) {
                replacement.unlink();
                throw new IllegalStateException(
                    "viewport publication is stale for the active page load"
                );
            }
            Record previous = current;
            current = replacement;
            if (previous != null) {
                previous.unlink();
            }
        }
        Bundle response = new Bundle();
        response.putInt("protocolVersion", 1);
        response.putString("status", "published");
        response.putString(
            "descriptorSha256", replacement.descriptorSha256
        );
        return response;
    }

    private Bundle beginLoad(Bundle extras) {
        IBinder requestedToken = extras == null ? null
            : extras.getBinder("sessionToken");
        long requestedGeneration = exactNonNegativeLong(
            extras, "pageLoadGeneration"
        );
        if (requestedToken == null || !requestedToken.isBinderAlive()) {
            throw new IllegalArgumentException(
                "live document-process session token is required"
            );
        }
        synchronized (LOCK) {
            LOAD_FENCE.begin(requestedToken, requestedGeneration);
            Record previous = current;
            current = null;
            if (previous != null) {
                previous.unlink();
            }
        }
        Bundle response = new Bundle();
        response.putInt("protocolVersion", 1);
        response.putString("status", "begun");
        response.putLong("pageLoadGeneration", requestedGeneration);
        return response;
    }

    private Bundle clear(Bundle extras) {
        IBinder requestedToken = extras == null ? null
            : extras.getBinder("sessionToken");
        boolean cleared;
        synchronized (LOCK) {
            cleared = LOAD_FENCE.clear(requestedToken);
            Record record = current;
            if (record != null && requestedToken != null
                && record.sessionToken.equals(requestedToken)) {
                current = null;
                record.unlink();
            } else if (record != null) {
                cleared = false;
            }
        }
        Bundle response = new Bundle();
        response.putInt("protocolVersion", 1);
        response.putString(
            "status", cleared ? "cleared" : "not_owner"
        );
        return response;
    }

    private Bundle clearGeneration(Bundle extras) {
        IBinder requestedToken = extras == null ? null
            : extras.getBinder("sessionToken");
        long requestedGeneration = exactNonNegativeLong(
            extras, "pageLoadGeneration"
        );
        boolean cleared = false;
        synchronized (LOCK) {
            Record record = current;
            boolean recordMatches = record == null
                || (requestedToken != null
                    && record.sessionToken.equals(requestedToken)
                    && record.pageLoadGeneration == requestedGeneration);
            if (recordMatches && LOAD_FENCE.clearIfCurrent(
                    requestedToken,
                    requestedGeneration
                )) {
                cleared = true;
                if (record != null) {
                    current = null;
                    record.unlink();
                }
            }
        }
        Bundle response = new Bundle();
        response.putInt("protocolVersion", 1);
        response.putString(
            "status", cleared ? "cleared" : "not_generation_owner"
        );
        response.putLong("pageLoadGeneration", requestedGeneration);
        return response;
    }

    private Bundle get(Bundle extras) {
        synchronized (LOCK) {
            Record record = current;
            if (record != null && record.matchesRequest(extras)) {
                return record.response();
            }
        }
        Bundle response = new Bundle();
        response.putInt("protocolVersion", 1);
        response.putString("status", "unavailable");
        return response;
    }

    private void requireCaller(String expectedPackage) {
        if (Binder.getCallingUid() != Process.SYSTEM_UID) {
            throw new SecurityException("viewport API requires system UID");
        }
        String caller = getCallingPackage();
        if (!expectedPackage.equals(caller)) {
            throw new SecurityException(
                "viewport API caller is not authorized"
            );
        }
    }

    private static int exactNonNegativeInt(Bundle bundle, String key) {
        if (bundle == null || !bundle.containsKey(key)) {
            throw new IllegalArgumentException(key + " is required");
        }
        int value = bundle.getInt(key, -1);
        if (value < 0) {
            throw new IllegalArgumentException(key + " is invalid");
        }
        return value;
    }

    private static int exactPositiveInt(Bundle bundle, String key) {
        int value = exactNonNegativeInt(bundle, key);
        if (value <= 1) {
            throw new IllegalArgumentException(key + " is invalid");
        }
        return value;
    }

    private static long exactNonNegativeLong(Bundle bundle, String key) {
        if (bundle == null || !bundle.containsKey(key)) {
            throw new IllegalArgumentException(key + " is required");
        }
        long value = bundle.getLong(key, -1L);
        if (value < 0L) {
            throw new IllegalArgumentException(key + " is invalid");
        }
        return value;
    }

    private static String exactString(Bundle bundle, String key) {
        String value = bundle == null ? null : bundle.getString(key);
        if (value == null || value.length() == 0) {
            throw new IllegalArgumentException(key + " is required");
        }
        return value;
    }

    private static String exactSha256(Bundle bundle, String key) {
        String value = exactString(bundle, key);
        if (value.length() != 64) {
            throw new IllegalArgumentException(key + " is invalid");
        }
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (!((character >= '0' && character <= '9')
                || (character >= 'a' && character <= 'f'))) {
                throw new IllegalArgumentException(key + " is invalid");
            }
        }
        return value;
    }

    private static String sha256(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] bytes = digest.digest(
                value.getBytes(StandardCharsets.UTF_8)
            );
            StringBuilder hex = new StringBuilder(bytes.length * 2);
            for (byte currentByte : bytes) {
                int unsigned = currentByte & 0xff;
                hex.append(Character.forDigit(unsigned >>> 4, 16));
                hex.append(Character.forDigit(unsigned & 0x0f, 16));
            }
            return hex.toString();
        } catch (Exception error) {
            throw new IllegalStateException(
                "SHA-256 is unavailable",
                error
            );
        }
    }

    @Override
    public Cursor query(
        Uri uri,
        String[] projection,
        String selection,
        String[] selectionArgs,
        String sortOrder
    ) {
        return null;
    }

    @Override
    public String getType(Uri uri) {
        return null;
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int update(
        Uri uri,
        ContentValues values,
        String selection,
        String[] selectionArgs
    ) {
        throw new UnsupportedOperationException();
    }
}
