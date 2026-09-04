package com.techrebbe.supernote.spreadprobe.v2;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Locale;
import java.util.Objects;
import java.util.Properties;
import java.util.Set;
import java.util.UUID;

/** Pure validation of the companion's committed editable v2 authority. */
public final class NativeReaderV2MarkerClaim {
    public static final int TRANSACTION_PROTOCOL = 2;
    public static final long MINIMUM_COMPANION_MODULE_VERSION = 139L;
    public static final String MODE = "protected-editable-transactional-v1";
    private static final Set<String> COMMITTED_FIELDS =
        Collections.unmodifiableSet(new HashSet<String>(Arrays.asList(
            NativeReaderV2Config.ENGINE_KEY,
            "enabled",
            "direction",
            "coverSeparate",
            "showDivider",
            "showHeader",
            "spreadSizing",
            "editable",
            "disposable",
            "managedBy",
            "mode",
            "transactionProtocol",
            "minimumModuleVersionCode",
            "activationToken",
            "activationState",
            "documentPath",
            "documentLength",
            "documentSha256",
            "backupVerified",
            "backupManifestPath",
            "backupManifestLength",
            "backupManifestSha256",
            "backupSnapshotPath",
            "markPath",
            "originalMarkPresent",
            "markLength",
            "markSha256",
            "backupCreatedAt"
        )));

    public final String documentId;
    public final String canonicalDocumentPath;
    public final long documentLength;
    public final String documentSha256;
    public final NativeReaderV2Config config;
    public final String activationToken;
    public final String backupManifestPath;
    public final long backupManifestLength;
    public final String backupManifestSha256;
    public final String backupSnapshotPath;
    public final String markPath;
    public final boolean originalMarkPresent;
    public final long markLength;
    public final String markSha256;
    public final long backupCreatedAt;

    private NativeReaderV2MarkerClaim(
        String canonicalDocumentPath,
        long documentLength,
        String documentSha256,
        NativeReaderV2Config config,
        String activationToken,
        String backupManifestPath,
        long backupManifestLength,
        String backupManifestSha256,
        String backupSnapshotPath,
        String markPath,
        boolean originalMarkPresent,
        long markLength,
        String markSha256,
        long backupCreatedAt
    ) {
        this.canonicalDocumentPath = canonicalDocumentPath;
        this.documentLength = documentLength;
        this.documentSha256 = documentSha256;
        this.documentId = "sha256:" + documentSha256;
        this.config = config;
        this.activationToken = activationToken;
        this.backupManifestPath = backupManifestPath;
        this.backupManifestLength = backupManifestLength;
        this.backupManifestSha256 = backupManifestSha256;
        this.backupSnapshotPath = backupSnapshotPath;
        this.markPath = markPath;
        this.originalMarkPresent = originalMarkPresent;
        this.markLength = markLength;
        this.markSha256 = markSha256;
        this.backupCreatedAt = backupCreatedAt;
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
        if (!COMMITTED_FIELDS.equals(properties.stringPropertyNames())) {
            throw new IllegalArgumentException(
                "committed marker schema is not exact"
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
        if (minimumVersion != MINIMUM_COMPANION_MODULE_VERSION) {
            throw new IllegalArgumentException(
                "marker requires a different companion contract version"
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
        String activationToken = properties.getProperty("activationToken");
        if (!isCanonicalUuid(activationToken)) {
            throw new IllegalArgumentException(
                "marker activation token is not canonical"
            );
        }
        String backupManifestPath = requiredPath(
            properties,
            "backupManifestPath"
        );
        long backupManifestLength = strictNonNegativeLong(
            properties,
            "backupManifestLength"
        );
        String backupManifestSha256 = properties.getProperty(
            "backupManifestSha256"
        );
        String backupSnapshotPath = requiredPath(
            properties,
            "backupSnapshotPath"
        );
        String markPath = requiredPath(properties, "markPath");
        boolean originalMarkPresent = strictBoolean(
            properties,
            "originalMarkPresent"
        );
        long markLength = strictNonNegativeLong(properties, "markLength");
        String markSha256 = properties.getProperty("markSha256");
        long backupCreatedAt = strictNonNegativeLong(
            properties,
            "backupCreatedAt"
        );
        if (backupManifestLength <= 0L
            || !isCanonicalSha256(backupManifestSha256)
            || originalMarkPresent && (markLength <= 0L
                || !isCanonicalSha256(markSha256))
            || !originalMarkPresent && (markLength != 0L
                || !"ABSENT".equals(markSha256))) {
            throw new IllegalArgumentException(
                "marker recovery identity is inconsistent"
            );
        }
        return new NativeReaderV2MarkerClaim(
            canonicalDocumentPath,
            observedDocumentLength,
            observedDocumentSha256,
            config,
            activationToken,
            backupManifestPath,
            backupManifestLength,
            backupManifestSha256,
            backupSnapshotPath,
            markPath,
            originalMarkPresent,
            markLength,
            markSha256,
            backupCreatedAt
        );
    }

    private static String requiredPath(Properties properties, String key) {
        String value = properties.getProperty(key);
        if (value == null || value.isEmpty() || value.indexOf('\0') >= 0) {
            throw new IllegalArgumentException("invalid marker path " + key);
        }
        return value;
    }

    private static boolean strictBoolean(Properties properties, String key) {
        String value = properties.getProperty(key);
        if ("true".equals(value)) return true;
        if ("false".equals(value)) return false;
        throw new IllegalArgumentException("invalid boolean for " + key);
    }

    private static boolean isCanonicalUuid(String value) {
        if (value == null) return false;
        try {
            return UUID.fromString(value).toString().equals(value);
        } catch (IllegalArgumentException invalid) {
            return false;
        }
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
