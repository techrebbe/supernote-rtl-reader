package com.techrebbe.supernote.spreadprobe.v2;

import java.util.Locale;
import java.util.Objects;
import java.util.Properties;

/** Pure validation of the companion's committed editable v2 authority. */
public final class NativeReaderV2MarkerClaim {
    public static final int TRANSACTION_PROTOCOL = 2;
    public static final long MINIMUM_COMPANION_MODULE_VERSION = 120L;
    public static final String MODE = "protected-editable-transactional-v1";

    public final String documentId;
    public final String canonicalDocumentPath;
    public final long documentLength;
    public final String documentSha256;
    public final NativeReaderV2Config config;

    private NativeReaderV2MarkerClaim(
        String canonicalDocumentPath,
        long documentLength,
        String documentSha256,
        NativeReaderV2Config config
    ) {
        this.canonicalDocumentPath = canonicalDocumentPath;
        this.documentLength = documentLength;
        this.documentSha256 = documentSha256;
        this.documentId = "sha256:" + documentSha256;
        this.config = config;
    }

    public static NativeReaderV2MarkerClaim admit(
        Properties properties,
        String canonicalDocumentPath,
        long observedDocumentLength,
        String observedDocumentSha256
    ) {
        Objects.requireNonNull(properties, "properties");
        if (canonicalDocumentPath == null || canonicalDocumentPath.isEmpty()
            || observedDocumentLength < 0L
            || !isCanonicalSha256(observedDocumentSha256)) {
            throw new IllegalArgumentException(
                "complete observed document identity is required"
            );
        }
        NativeReaderV2Config config = NativeReaderV2Config.from(properties);
        if (config == null || !config.enabled) {
            throw new IllegalArgumentException(
                "marker does not explicitly enable Native Reader v2"
            );
        }
        requireExact(properties, "editable", "true");
        requireExact(properties, "disposable", "false");
        requireExact(properties, "managedBy", "supernote-rtl-reader");
        requireExact(properties, "mode", MODE);
        requireExact(properties, "transactionProtocol",
            Integer.toString(TRANSACTION_PROTOCOL));
        requireExact(properties, "activationState", "committed");
        requireExact(properties, "backupVerified", "true");
        rejectPresent(properties, "pendingIntent");
        rejectPresent(properties, "previousMarkerPresent");
        rejectPresent(properties, "previousMarkerProtected");
        rejectPresent(properties, "previousMarkerLength");
        rejectPresent(properties, "previousMarkerSha256");
        rejectPresent(properties, "previousMarkerBase64");

        long minimumVersion = strictNonNegativeLong(
            properties,
            "minimumModuleVersionCode"
        );
        if (minimumVersion < MINIMUM_COMPANION_MODULE_VERSION) {
            throw new IllegalArgumentException(
                "marker does not require a supported companion version"
            );
        }
        requireExact(properties, "documentPath", canonicalDocumentPath);
        long claimedLength = strictNonNegativeLong(
            properties,
            "documentLength"
        );
        String claimedSha256 = properties.getProperty("documentSha256");
        if (claimedLength != observedDocumentLength
            || !isCanonicalSha256(claimedSha256)
            || !claimedSha256.equals(observedDocumentSha256)) {
            throw new IllegalArgumentException(
                "marker and observed document identities disagree"
            );
        }
        return new NativeReaderV2MarkerClaim(
            canonicalDocumentPath,
            observedDocumentLength,
            observedDocumentSha256,
            config
        );
    }

    private static long strictNonNegativeLong(
        Properties properties,
        String key
    ) {
        String value = properties.getProperty(key);
        if (value == null || value.isEmpty() || value.charAt(0) == '+'
            || (value.length() > 1 && value.charAt(0) == '0')) {
            throw new IllegalArgumentException("non-canonical integer for " + key);
        }
        try {
            long parsed = Long.parseLong(value);
            if (parsed < 0L) {
                throw new IllegalArgumentException(
                    "negative integer for " + key
                );
            }
            return parsed;
        } catch (NumberFormatException exception) {
            throw new IllegalArgumentException(
                "invalid integer for " + key,
                exception
            );
        }
    }

    private static void requireExact(
        Properties properties,
        String key,
        String expected
    ) {
        if (!expected.equals(properties.getProperty(key))) {
            throw new IllegalArgumentException("invalid marker field " + key);
        }
    }

    private static void rejectPresent(Properties properties, String key) {
        if (properties.containsKey(key)) {
            throw new IllegalArgumentException(
                "committed marker carries pending field " + key
            );
        }
    }

    private static boolean isCanonicalSha256(String value) {
        if (value == null || value.length() != 64
            || !value.equals(value.toLowerCase(Locale.ROOT))) {
            return false;
        }
        for (int index = 0; index < value.length(); index++) {
            char item = value.charAt(index);
            if (!((item >= '0' && item <= '9')
                || (item >= 'a' && item <= 'f'))) {
                return false;
            }
        }
        return true;
    }
}
