package com.techrebbe.supernote.spreadprobe.v2android;

import android.os.Looper;
import android.os.Process;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructStat;
import android.util.Log;

import com.techrebbe.supernote.spreadprobe.v2.NativeReaderV2MarkerClaim;
import com.techrebbe.supernote.spreadprobe.v2.NativeReaderV2AuthorityJournal;
import com.techrebbe.supernote.spreadprobe.v2.NativeReaderV2Config;
import com.techrebbe.supernote.spreadprobe.v2.NativeReaderV2StrictProperties;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Locale;
import java.util.Properties;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;

/** Descriptor-backed, off-UI-thread admission of one exact original PDF. */
public final class NativeReaderV2DocumentGate {
    private static final String TAG = "SN_NATIVE_READER_V2";
    public static final String MARKER_SUFFIX = ".snspread-v3";
    public static final String LEGACY_MARKER_SUFFIX = ".snspread";
    private static final String BACKUP_MANIFEST_SUFFIX =
        ".snspread-backup.properties";
    private static final String BACKUP_SNAPSHOT_SUFFIX =
        ".snspread-backup.mark";
    private static final String LIVE_MARK_CHECKPOINT_SUFFIX =
        ".snspread-live-mark-v1";
    private static final int LINUX_O_DIRECTORY = 0x10000;
    private static final Set<String> LIVE_MARK_CHECKPOINT_FIELDS =
        Collections.unmodifiableSet(new HashSet<String>(Arrays.asList(
            "version",
            "kind",
            "managedBy",
            "documentPath",
            "documentLength",
            "documentSha256",
            "backupManifestPath",
            "backupManifestLength",
            "backupManifestSha256",
            "backupSnapshotPath",
            "markPath",
            "originalMarkPresent",
            "recoveryMarkLength",
            "recoveryMarkSha256",
            "backupCreatedAt",
            "liveMarkPresent",
            "liveMarkLength",
            "liveMarkSha256",
            "witnessGeneration"
        )));
    private static final Set<String> RECOVERY_MANIFEST_FIELDS =
        Collections.unmodifiableSet(new HashSet<String>(Arrays.asList(
            "version",
            "managedBy",
            "documentPath",
            "documentLength",
            "documentSha256",
            "documentModified",
            "markPath",
            "originalMarkPresent",
            "markLength",
            "markSha256",
            "snapshotPath",
            "createdAt"
        )));

    private NativeReaderV2DocumentGate() {}

    /**
     * Minimal worker-thread signal used after the hook has already installed
     * a fail-closed input fence. The marker's content is never trusted here;
     * full admission rejects every malformed or stale byte.
     */
    public static boolean candidateMarkerPresent(String documentPath) {
        if (Looper.myLooper() == Looper.getMainLooper()) {
            throw new IllegalStateException(
                "candidate marker lookup is forbidden on the main thread"
            );
        }
        if (documentPath == null || documentPath.indexOf('\0') >= 0) {
            return false;
        }
        try {
            // This is deliberately a lexical sibling lookup. Resolving the
            // marker (or the document) through canonical paths here would add
            // avoidable UI-thread filesystem work and could hide a hostile
            // symlink before full descriptor-backed admission sees it.
            File document = new File(documentPath).getAbsoluteFile();
            File parent = document.getParentFile();
            if (parent == null) return false;
            String markerPath = new File(
                parent,
                "." + document.getName() + MARKER_SUFFIX
            ).getAbsolutePath();
            String legacyPath = new File(
                parent,
                "." + document.getName() + LEGACY_MARKER_SUFFIX
            ).getAbsolutePath();
            boolean legacyPresent = pathExistsNoFollow(legacyPath);
            try {
                StableBytes journal = readRegularFile(
                    markerPath,
                    NativeReaderV2AuthorityJournal.FILE_SIZE
                );
                if (journal.bytes.length
                    != NativeReaderV2AuthorityJournal.FILE_SIZE) {
                    return true;
                }
                NativeReaderV2AuthorityJournal.Snapshot snapshot =
                    NativeReaderV2AuthorityJournal.inspect(journal.bytes);
                if (snapshot.isEmpty()) return legacyPresent;
                // A valid v3 record supersedes legacy path evidence without
                // deleting or renaming it. OFF is trusted only when its exact
                // payload binds this document and protocol; malformed OFF data
                // remains a fail-closed candidate just like a torn slot.
                if (snapshot.current.state
                    == NativeReaderV2AuthorityJournal.State.OFF) {
                    Properties payload = NativeReaderV2StrictProperties.parse(
                        snapshot.current.payload
                    );
                    return !validOffAuthorityPayload(
                        payload,
                        document.getCanonicalPath()
                    );
                }
                return true;
            } catch (ErrnoException missing) {
                if (missing.errno == OsConstants.ENOENT) return legacyPresent;
                return true;
            }
        } catch (ErrnoException failure) {
            return failure.errno != OsConstants.ENOENT;
        } catch (Throwable ambiguous) {
            return true;
        }
    }

    private static boolean validOffAuthorityPayload(
        Properties payload,
        String canonicalDocumentPath
    ) {
        Set<String> expected = new HashSet<String>(Arrays.asList(
            NativeReaderV2Config.ENGINE_KEY,
            "enabled",
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
            "documentSha256"
        ));
        if (!expected.equals(payload.stringPropertyNames())) return false;
        if (!NativeReaderV2Config.ENGINE_VALUE.equals(
                payload.getProperty(NativeReaderV2Config.ENGINE_KEY))
            || !"false".equals(payload.getProperty("enabled"))
            || !"false".equals(payload.getProperty("editable"))
            || !"false".equals(payload.getProperty("disposable"))
            || !"supernote-rtl-reader".equals(payload.getProperty("managedBy"))
            || !NativeReaderV2MarkerClaim.MODE.equals(payload.getProperty("mode"))
            || !Integer.toString(NativeReaderV2MarkerClaim.TRANSACTION_PROTOCOL)
                .equals(payload.getProperty("transactionProtocol"))
            || !Long.toString(
                NativeReaderV2MarkerClaim.MINIMUM_COMPANION_MODULE_VERSION
            ).equals(payload.getProperty("minimumModuleVersionCode"))
            || !"off".equals(payload.getProperty("activationState"))
            || !canonicalDocumentPath.equals(payload.getProperty("documentPath"))
            || !isCanonicalUuid(payload.getProperty("activationToken"))) {
            return false;
        }
        String length = payload.getProperty("documentLength");
        String digest = payload.getProperty("documentSha256");
        if (length == null || length.isEmpty() || length.charAt(0) == '+'
            || length.charAt(0) == '-' || length.length() > 1
            && length.charAt(0) == '0' || digest == null
            || digest.length() != 64
            || !digest.equals(digest.toLowerCase(Locale.ROOT))) {
            return false;
        }
        try {
            Long.parseLong(length);
        } catch (NumberFormatException invalid) {
            return false;
        }
        for (int index = 0; index < digest.length(); index++) {
            char item = digest.charAt(index);
            if (!((item >= '0' && item <= '9')
                || (item >= 'a' && item <= 'f'))) return false;
        }
        return true;
    }

    public static Evidence admit(String documentPath) {
        if (Looper.myLooper() == Looper.getMainLooper()) {
            throw new IllegalStateException(
                "document admission is forbidden on the main thread"
            );
        }
        try {
            if (documentPath == null || documentPath.indexOf('\0') >= 0) {
                throw new IllegalArgumentException("invalid document path");
            }
            File requested = new File(documentPath);
            String canonical = requested.getCanonicalPath();
            if (!canonical.toLowerCase(Locale.ROOT).endsWith(".pdf")) {
                throw new IllegalArgumentException(
                    "Native Reader v2 requires a PDF path"
                );
            }
            File documentFile = new File(canonical);
            File parent = documentFile.getParentFile();
            if (parent == null) {
                throw new IllegalArgumentException(
                    "Native Reader v2 document has no parent directory"
                );
            }
            // Do not canonicalize the marker itself: canonicalization would
            // resolve a sibling symlink before O_NOFOLLOW sees it, allowing a
            // marker outside the admitted document directory to become the
            // authority file.
            String markerPath = new File(
                parent,
                "." + documentFile.getName() + MARKER_SUFFIX
            ).getAbsolutePath();
            StableBytes markerBefore = readRegularFile(
                markerPath,
                NativeReaderV2AuthorityJournal.FILE_SIZE
            );
            NativeReaderV2AuthorityJournal.Snapshot journalBefore =
                NativeReaderV2AuthorityJournal.inspect(markerBefore.bytes);
            if (journalBefore.current == null
                || journalBefore.current.state
                    != NativeReaderV2AuthorityJournal.State.COMMITTED) {
                throw new IllegalStateException(
                    "Native Reader v2 journal is not committed"
                );
            }
            Properties properties = NativeReaderV2StrictProperties.parse(
                journalBefore.current.payload
            );
            StableDigest document = hashRegularFile(canonical);

            // The tiny marker is intentionally read twice around the expensive
            // PDF hash. A same-inode, same-size, sub-second rewrite cannot
            // smuggle mixed-time configuration into the accepted claim.
            StableBytes markerAfter = readRegularFile(
                markerPath,
                NativeReaderV2AuthorityJournal.FILE_SIZE
            );
            if (!markerBefore.identity.sameFile(markerAfter.identity)
                || !Arrays.equals(markerBefore.bytes, markerAfter.bytes)) {
                throw new IllegalStateException(
                    "Native Reader v2 marker changed during admission"
                );
            }
            NativeReaderV2MarkerClaim claim =
                NativeReaderV2MarkerClaim.admit(
                    properties,
                    canonical,
                    document.identity.size,
                    document.sha256
                );
            RecoveryIdentity recovery = verifyRecoveryEvidence(
                claim,
                documentFile
            );
            MarkAuthority markAuthority = null;
            try {
                // The live .mark is mutable data, unlike the immutable
                // recovery snapshot. Pin its no-follow identity and acquire
                // the process-shared writer lease before authority is ever
                // published to the UI thread.
                markAuthority = MarkAuthority.acquire(claim);
                return new Evidence(
                    claim,
                    markerPath,
                    document.identity,
                    markerAfter.identity,
                    sha256(markerAfter.bytes),
                    journalBefore.current.generation,
                    journalBefore.current.authoritySha256,
                    recovery.manifest,
                    recovery.snapshot,
                    markAuthority
                );
            } catch (Exception failure) {
                if (markAuthority != null) markAuthority.close();
                throw failure;
            }
        } catch (RuntimeException exception) {
            throw exception;
        } catch (Exception exception) {
            throw new IllegalStateException(
                "Native Reader v2 document admission failed",
                exception
            );
        }
    }

    /** Exact worker-thread observation returned to PluginHost as an ACK. */
    public static AuthorityObservation observeAuthority(String documentPath) {
        if (Looper.myLooper() == Looper.getMainLooper()) {
            throw new IllegalStateException(
                "authority observation is forbidden on the main thread"
            );
        }
        try {
            if (documentPath == null || documentPath.indexOf('\0') >= 0) {
                throw new IllegalArgumentException("invalid document path");
            }
            String canonical = new File(documentPath).getCanonicalPath();
            File document = new File(canonical);
            File parent = document.getParentFile();
            if (parent == null || !canonical.toLowerCase(Locale.ROOT)
                    .endsWith(".pdf")) {
                throw new IllegalArgumentException("invalid PDF authority path");
            }
            String journalPath = new File(
                parent,
                "." + document.getName() + MARKER_SUFFIX
            ).getAbsolutePath();
            StableBytes bytes = readRegularFile(
                journalPath,
                NativeReaderV2AuthorityJournal.FILE_SIZE
            );
            NativeReaderV2AuthorityJournal.Snapshot snapshot =
                NativeReaderV2AuthorityJournal.inspect(bytes.bytes);
            if (snapshot.current == null) {
                throw new IllegalStateException("authority journal is empty");
            }
            Properties payload = NativeReaderV2StrictProperties.parse(
                snapshot.current.payload
            );
            String expectedState = snapshot.current.state.name()
                .toLowerCase(Locale.ROOT);
            String activationToken = payload.getProperty("activationToken");
            StableDigest documentIdentity = hashRegularFile(canonical);
            StableBytes bytesAfter = readRegularFile(
                journalPath,
                NativeReaderV2AuthorityJournal.FILE_SIZE
            );
            if (!NativeReaderV2Config.ENGINE_VALUE.equals(
                    payload.getProperty(NativeReaderV2Config.ENGINE_KEY))
                || !"supernote-rtl-reader".equals(
                    payload.getProperty("managedBy"))
                || !Integer.toString(
                    NativeReaderV2MarkerClaim.TRANSACTION_PROTOCOL
                ).equals(payload.getProperty("transactionProtocol"))
                || !Long.toString(
                    NativeReaderV2MarkerClaim.MINIMUM_COMPANION_MODULE_VERSION
                ).equals(payload.getProperty("minimumModuleVersionCode"))
                || !canonical.equals(payload.getProperty("documentPath"))
                || !Long.toString(documentIdentity.identity.size).equals(
                    payload.getProperty("documentLength"))
                || !documentIdentity.sha256.equals(
                    payload.getProperty("documentSha256"))
                || !expectedState.equals(payload.getProperty("activationState"))
                || !isCanonicalUuid(activationToken)
                || !bytes.identity.sameVersion(bytesAfter.identity)
                || !Arrays.equals(bytes.bytes, bytesAfter.bytes)) {
                throw new IllegalStateException(
                    "journal payload does not bind observed authority"
                );
            }
            return new AuthorityObservation(
                journalPath,
                snapshot.current.generation,
                snapshot.current.authoritySha256,
                expectedState,
                activationToken
            );
        } catch (RuntimeException exception) {
            throw exception;
        } catch (Exception exception) {
            throw new IllegalStateException(
                "Native Reader v2 authority observation failed",
                exception
            );
        }
    }

    private static boolean isCanonicalUuid(String value) {
        if (value == null) return false;
        try {
            return UUID.fromString(value).toString().equals(value);
        } catch (IllegalArgumentException invalid) {
            return false;
        }
    }

    private static RecoveryIdentity verifyRecoveryEvidence(
        NativeReaderV2MarkerClaim claim,
        File documentFile
    ) throws Exception {
        File parent = documentFile.getParentFile();
        if (parent == null) {
            throw new IllegalStateException(
                "recovery authority has no document directory"
            );
        }
        String expectedManifest = new File(
            parent,
            "." + documentFile.getName() + BACKUP_MANIFEST_SUFFIX
        ).getAbsolutePath();
        String expectedSnapshot = new File(
            parent,
            "." + documentFile.getName() + BACKUP_SNAPSHOT_SUFFIX
        ).getAbsolutePath();
        String expectedMark = documentFile.getAbsolutePath() + ".mark";
        if (!expectedManifest.equals(claim.backupManifestPath)
            || !expectedSnapshot.equals(claim.backupSnapshotPath)
            || !expectedMark.equals(claim.markPath)) {
            throw new IllegalStateException(
                "recovery paths do not belong to the admitted document"
            );
        }

        StableBytes manifest = readRegularFile(
            expectedManifest,
            NativeReaderV2StrictProperties.MAX_BYTES
        );
        if (manifest.identity.size != claim.backupManifestLength
            || !claim.backupManifestSha256.equals(sha256(manifest.bytes))) {
            throw new IllegalStateException(
                "recovery manifest bytes disagree with marker authority"
            );
        }
        Properties recovery = NativeReaderV2StrictProperties.parse(
            manifest.bytes
        );
        if (!RECOVERY_MANIFEST_FIELDS.equals(
                recovery.stringPropertyNames()
            )) {
            throw new IllegalStateException(
                "recovery manifest schema is not exact"
            );
        }
        requireManifestValue(recovery, "version", "1");
        requireManifestValue(
            recovery,
            "managedBy",
            "supernote-rtl-reader"
        );
        requireManifestValue(
            recovery,
            "documentPath",
            claim.canonicalDocumentPath
        );
        requireManifestValue(
            recovery,
            "documentLength",
            Long.toString(claim.documentLength)
        );
        requireManifestValue(
            recovery,
            "documentSha256",
            claim.documentSha256
        );
        strictNonNegativeDecimal(recovery, "documentModified");
        requireManifestValue(recovery, "markPath", claim.markPath);
        requireManifestValue(
            recovery,
            "originalMarkPresent",
            Boolean.toString(claim.originalMarkPresent)
        );
        requireManifestValue(
            recovery,
            "markLength",
            Long.toString(claim.markLength)
        );
        requireManifestValue(recovery, "markSha256", claim.markSha256);
        requireManifestValue(
            recovery,
            "snapshotPath",
            claim.backupSnapshotPath
        );
        requireManifestValue(
            recovery,
            "createdAt",
            Long.toString(claim.backupCreatedAt)
        );

        if (claim.originalMarkPresent) {
            StableDigest snapshot = hashRegularFile(expectedSnapshot);
            if (snapshot.identity.size != claim.markLength
                || !snapshot.sha256.equals(claim.markSha256)) {
                throw new IllegalStateException(
                    "recovery snapshot bytes disagree with marker authority"
                );
            }
            return new RecoveryIdentity(
                manifest.identity,
                snapshot.identity
            );
        } else if (pathExistsNoFollow(expectedSnapshot)) {
            throw new IllegalStateException(
                "absent-mark recovery unexpectedly contains a snapshot"
            );
        }
        return new RecoveryIdentity(manifest.identity, null);
    }

    /**
     * Reads authority advanced only after a witnessed native save. This is
     * separate from the immutable rollback snapshot, which must never be
     * rewritten merely because stock editing committed newer live bytes.
     */
    private static LiveMarkCheckpoint readLiveMarkCheckpoint(
        NativeReaderV2MarkerClaim claim
    ) throws Exception {
        String checkpointPath = claim.markPath + LIVE_MARK_CHECKPOINT_SUFFIX;
        StableBytes checkpoint = readRegularFile(
            checkpointPath,
            NativeReaderV2StrictProperties.MAX_BYTES
        );
        Properties properties = NativeReaderV2StrictProperties.parse(
            checkpoint.bytes
        );
        if (!LIVE_MARK_CHECKPOINT_FIELDS.equals(
                properties.stringPropertyNames())
            || !"1".equals(properties.getProperty("version"))
            || !"native-reader-v2-live-mark-checkpoint".equals(
                properties.getProperty("kind"))
            || !"supernote-rtl-reader".equals(
                properties.getProperty("managedBy"))
            || !claim.canonicalDocumentPath.equals(
                properties.getProperty("documentPath"))
            || !Long.toString(claim.documentLength).equals(
                properties.getProperty("documentLength"))
            || !claim.documentSha256.equals(
                properties.getProperty("documentSha256"))
            || !claim.backupManifestPath.equals(
                properties.getProperty("backupManifestPath"))
            || !Long.toString(claim.backupManifestLength).equals(
                properties.getProperty("backupManifestLength"))
            || !claim.backupManifestSha256.equals(
                properties.getProperty("backupManifestSha256"))
            || !claim.backupSnapshotPath.equals(
                properties.getProperty("backupSnapshotPath"))
            || !claim.markPath.equals(properties.getProperty("markPath"))
            || !Boolean.toString(claim.originalMarkPresent).equals(
                properties.getProperty("originalMarkPresent"))
            || !Long.toString(claim.markLength).equals(
                properties.getProperty("recoveryMarkLength"))
            || !claim.markSha256.equals(
                properties.getProperty("recoveryMarkSha256"))
            || !Long.toString(claim.backupCreatedAt).equals(
                properties.getProperty("backupCreatedAt"))) {
            throw new IllegalStateException(
                "live mark checkpoint does not bind recovery authority"
            );
        }
        boolean present = strictCheckpointBoolean(
            properties,
            "liveMarkPresent"
        );
        long length = strictCheckpointLong(properties, "liveMarkLength", true);
        String sha256 = properties.getProperty("liveMarkSha256");
        long generation = strictCheckpointLong(
            properties,
            "witnessGeneration",
            false
        );
        if (present ? !isCanonicalSha256(sha256) : length != 0L
            || !"ABSENT".equals(sha256)) {
            throw new IllegalStateException(
                "live mark checkpoint identity is inconsistent"
            );
        }
        return new LiveMarkCheckpoint(
            checkpointPath,
            checkpoint.identity,
            present,
            length,
            sha256,
            generation
        );
    }

    private static boolean strictCheckpointBoolean(
        Properties properties,
        String key
    ) {
        String value = properties.getProperty(key);
        if ("true".equals(value)) return true;
        if ("false".equals(value)) return false;
        throw new IllegalStateException("invalid checkpoint boolean " + key);
    }

    private static long strictCheckpointLong(
        Properties properties,
        String key,
        boolean allowZero
    ) {
        String value = properties.getProperty(key);
        if (value == null || value.isEmpty() || value.charAt(0) == '+'
            || value.charAt(0) == '-' || value.length() > 1
            && value.charAt(0) == '0') {
            throw new IllegalStateException(
                "invalid checkpoint integer " + key
            );
        }
        try {
            long parsed = Long.parseLong(value);
            if (parsed < 0L || !allowZero && parsed == 0L) {
                throw new IllegalStateException(
                    "checkpoint integer is outside bounds " + key
                );
            }
            return parsed;
        } catch (NumberFormatException invalid) {
            throw new IllegalStateException(
                "invalid checkpoint integer " + key,
                invalid
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
                || (item >= 'a' && item <= 'f'))) return false;
        }
        return true;
    }

    private static LiveMarkState readLiveMarkState(String markPath)
        throws Exception {
        Identity identity = optionalRegularIdentity(markPath);
        if (identity == null) return LiveMarkState.absent();
        StableDigest digest = hashRegularFile(markPath);
        if (!identity.sameVersion(digest.identity)) {
            throw new IllegalStateException(
                "live mark changed while its checkpoint was captured"
            );
        }
        return new LiveMarkState(
            true,
            digest.identity,
            digest.identity.size,
            digest.sha256
        );
    }

    private static boolean liveMarkMatchesRecovery(
        NativeReaderV2MarkerClaim claim,
        LiveMarkState live
    ) {
        return claim.originalMarkPresent == live.present
            && (live.present
                ? live.length == claim.markLength
                    && claim.markSha256.equals(live.sha256)
                : claim.markLength == 0L
                    && "ABSENT".equals(claim.markSha256));
    }

    private static boolean liveMarkMatchesCheckpoint(
        LiveMarkState live,
        LiveMarkCheckpoint checkpoint
    ) {
        return live.present == checkpoint.present
            && live.length == checkpoint.length
            && live.sha256.equals(checkpoint.sha256);
    }

    private static byte[] liveMarkCheckpointBytes(
        NativeReaderV2MarkerClaim claim,
        LiveMarkState live,
        long witnessGeneration
    ) throws Exception {
        Properties properties = new Properties();
        properties.setProperty("version", "1");
        properties.setProperty(
            "kind",
            "native-reader-v2-live-mark-checkpoint"
        );
        properties.setProperty("managedBy", "supernote-rtl-reader");
        properties.setProperty("documentPath", claim.canonicalDocumentPath);
        properties.setProperty(
            "documentLength",
            Long.toString(claim.documentLength)
        );
        properties.setProperty("documentSha256", claim.documentSha256);
        properties.setProperty("backupManifestPath", claim.backupManifestPath);
        properties.setProperty(
            "backupManifestLength",
            Long.toString(claim.backupManifestLength)
        );
        properties.setProperty(
            "backupManifestSha256",
            claim.backupManifestSha256
        );
        properties.setProperty("backupSnapshotPath", claim.backupSnapshotPath);
        properties.setProperty("markPath", claim.markPath);
        properties.setProperty(
            "originalMarkPresent",
            Boolean.toString(claim.originalMarkPresent)
        );
        properties.setProperty(
            "recoveryMarkLength",
            Long.toString(claim.markLength)
        );
        properties.setProperty("recoveryMarkSha256", claim.markSha256);
        properties.setProperty(
            "backupCreatedAt",
            Long.toString(claim.backupCreatedAt)
        );
        properties.setProperty(
            "liveMarkPresent",
            Boolean.toString(live.present)
        );
        properties.setProperty(
            "liveMarkLength",
            Long.toString(live.length)
        );
        properties.setProperty("liveMarkSha256", live.sha256);
        properties.setProperty(
            "witnessGeneration",
            Long.toString(witnessGeneration)
        );
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        properties.store(output, "Native Reader v2 witnessed mark authority");
        return output.toByteArray();
    }

    private static void writeLiveMarkCheckpointAtomically(
        File checkpoint,
        byte[] bytes
    ) throws Exception {
        File parent = checkpoint.getParentFile();
        if (parent == null) {
            throw new IllegalStateException("checkpoint has no parent");
        }
        FileDescriptor parentDescriptor = openPinnedDirectory(
            parent.getAbsolutePath()
        );
        File temporary = new File(
            parent,
            "." + checkpoint.getName() + ".tmp-" + Process.myPid()
                + "-" + UUID.randomUUID()
        );
        FileDescriptor temporaryDescriptor = null;
        try {
            Identity parentIdentity = Identity.from(
                Os.fstat(parentDescriptor)
            );
            if (!OsConstants.S_ISDIR(parentIdentity.mode)
                || !parentIdentity.sameFile(Identity.from(
                    Os.lstat(parent.getAbsolutePath())
                ))) {
                throw new IllegalStateException(
                    "checkpoint parent authority is invalid"
                );
            }
            temporaryDescriptor = Os.open(
                temporary.getAbsolutePath(),
                OsConstants.O_WRONLY | OsConstants.O_CREAT
                    | OsConstants.O_EXCL | OsConstants.O_CLOEXEC
                    | OsConstants.O_NOFOLLOW,
                0600
            );
            Identity temporaryIdentity = Identity.from(
                Os.fstat(temporaryDescriptor)
            );
            temporaryIdentity.requireRegular();
            try (FileOutputStream output = new FileOutputStream(
                    Os.dup(temporaryDescriptor))) {
                output.write(bytes);
                output.flush();
            }
            Os.fsync(temporaryDescriptor);
            Identity written = Identity.from(Os.fstat(temporaryDescriptor));
            if (!temporaryIdentity.sameFile(written)
                || written.size != bytes.length
                || !written.sameVersion(Identity.from(
                    Os.lstat(temporary.getAbsolutePath())
                ))) {
                throw new IllegalStateException(
                    "checkpoint staging authority changed"
                );
            }
            Os.rename(
                temporary.getAbsolutePath(),
                checkpoint.getAbsolutePath()
            );
            Identity published = Identity.from(
                Os.lstat(checkpoint.getAbsolutePath())
            );
            if (!written.sameFile(published)
                || !parentIdentity.sameFile(Identity.from(
                    Os.fstat(parentDescriptor)
                ))
                || !parentIdentity.sameFile(Identity.from(
                    Os.lstat(parent.getAbsolutePath())
                ))) {
                throw new IllegalStateException(
                    "checkpoint publication authority changed"
                );
            }
            Os.fsync(parentDescriptor);
            StableBytes verified = readRegularFile(
                checkpoint.getAbsolutePath(),
                NativeReaderV2StrictProperties.MAX_BYTES
            );
            if (!Arrays.equals(bytes, verified.bytes)) {
                throw new IllegalStateException(
                    "checkpoint publication bytes changed"
                );
            }
        } finally {
            if (temporaryDescriptor != null) {
                try { Os.close(temporaryDescriptor); } catch (Exception ignored) {}
            }
            try {
                if (pathExistsNoFollow(temporary.getAbsolutePath())) {
                    Files.deleteIfExists(temporary.toPath());
                    Os.fsync(parentDescriptor);
                }
            } catch (Exception ignored) {}
            Os.close(parentDescriptor);
        }
    }

    /**
     * Opens one exact directory without following a replacement symlink.
     * Android shared storage is commonly FUSE-backed and may reject Linux's
     * O_DIRECTORY flag with EINVAL, so the fallback pins and rechecks the
     * no-follow descriptor instead of weakening path authority.
     */
    private static FileDescriptor openPinnedDirectory(String path)
        throws Exception {
        int commonFlags = OsConstants.O_RDONLY | OsConstants.O_CLOEXEC
            | OsConstants.O_NOFOLLOW;
        try {
            return Os.open(path, commonFlags | LINUX_O_DIRECTORY, 0);
        } catch (ErrnoException failure) {
            if (failure.errno != OsConstants.EINVAL) throw failure;
        }
        Identity before = Identity.from(Os.lstat(path));
        if (!OsConstants.S_ISDIR(before.mode)) {
            throw new IllegalStateException(
                "checkpoint parent is not a directory"
            );
        }
        FileDescriptor descriptor = Os.open(path, commonFlags, 0);
        try {
            Identity pinned = Identity.from(Os.fstat(descriptor));
            Identity after = Identity.from(Os.lstat(path));
            if (!OsConstants.S_ISDIR(pinned.mode)
                || !OsConstants.S_ISDIR(after.mode)
                || !before.sameFile(pinned)
                || !before.sameFile(after)) {
                throw new IllegalStateException(
                    "checkpoint parent changed during FUSE fallback"
                );
            }
            return descriptor;
        } catch (Throwable failure) {
            try { Os.close(descriptor); } catch (Exception ignored) {}
            throw failure;
        }
    }

    private static void requireManifestValue(
        Properties properties,
        String key,
        String expected
    ) {
        if (!expected.equals(properties.getProperty(key))) {
            throw new IllegalStateException(
                "recovery manifest field disagrees with marker: " + key
            );
        }
    }

    private static long strictNonNegativeDecimal(
        Properties properties,
        String key
    ) {
        String value = properties.getProperty(key);
        if (value == null || value.isEmpty() || value.charAt(0) == '+'
            || (value.length() > 1 && value.charAt(0) == '0')) {
            throw new IllegalStateException(
                "recovery manifest integer is not canonical: " + key
            );
        }
        try {
            long parsed = Long.parseLong(value);
            if (parsed < 0L) {
                throw new IllegalStateException(
                    "recovery manifest integer is negative: " + key
                );
            }
            return parsed;
        } catch (NumberFormatException invalid) {
            throw new IllegalStateException(
                "recovery manifest integer is invalid: " + key,
                invalid
            );
        }
    }

    private static boolean pathExistsNoFollow(String path) throws Exception {
        try {
            Os.lstat(path);
            return true;
        } catch (ErrnoException missing) {
            if (missing.errno == OsConstants.ENOENT) return false;
            throw missing;
        }
    }

    /**
     * Cheap resume-time proof that the exact admitted PDF and marker are
     * still the objects previously authorized. This never replaces initial
     * SHA-256 admission; it prevents stale in-memory authority after the
     * companion changes or removes a marker while DocumentActivity is paused.
     */
    public static boolean evidenceStillCurrent(Evidence evidence) {
        if (Looper.myLooper() == Looper.getMainLooper()) {
            throw new IllegalStateException(
                "document revalidation is forbidden on the main thread"
            );
        }
        if (evidence == null || evidence.claim == null) return false;
        try {
            if (!fastEvidenceStillCurrent(evidence)) return false;
            StableBytes marker = readRegularFile(
                evidence.markerPath,
                NativeReaderV2AuthorityJournal.FILE_SIZE
            );
            if (!evidence.markerIdentity.sameVersion(marker.identity)
                || !evidence.markerSha256.equals(sha256(marker.bytes))) {
                return false;
            }
            NativeReaderV2AuthorityJournal.Snapshot journal =
                NativeReaderV2AuthorityJournal.inspect(marker.bytes);
            if (journal.current == null
                || journal.current.state
                    != NativeReaderV2AuthorityJournal.State.COMMITTED
                || journal.current.generation != evidence.journalGeneration
                || !journal.current.authoritySha256.equals(
                    evidence.journalAuthoritySha256
                )) {
                return false;
            }
            verifyRecoveryEvidence(
                evidence.claim,
                new File(evidence.claim.canonicalDocumentPath)
            );
            // Close the verification window: all authority objects must still
            // be the exact versions admitted before the expensive hashes.
            return fastEvidenceStillCurrent(evidence);
        } catch (Exception failure) {
            return false;
        }
    }

    /**
     * Cheap descriptor-identity revalidation used around asynchronous native
     * publication/save boundaries. Even lstat is forbidden on the document UI
     * thread: input routing consumes only already-published in-memory authority.
     */
    public static boolean fastEvidenceStillCurrent(Evidence evidence) {
        if (Looper.myLooper() == Looper.getMainLooper()) {
            throw new IllegalStateException(
                "document identity revalidation is forbidden on the main thread"
            );
        }
        if (evidence == null || evidence.claim == null) return false;
        try {
            if (!evidence.markAuthorityCurrent()) return false;
            if (!evidence.documentIdentity.sameVersion(regularIdentity(
                    evidence.claim.canonicalDocumentPath
                ))) {
                return false;
            }
            if (!evidence.markerIdentity.sameVersion(regularIdentity(
                    evidence.markerPath
                ))) {
                return false;
            }
            if (!evidence.recoveryManifestIdentity.sameVersion(
                    regularIdentity(evidence.claim.backupManifestPath)
                )) {
                return false;
            }
            if (evidence.claim.originalMarkPresent) {
                return evidence.recoverySnapshotIdentity != null
                    && evidence.recoverySnapshotIdentity.sameVersion(
                        regularIdentity(evidence.claim.backupSnapshotPath)
                    );
            }
            return evidence.recoverySnapshotIdentity == null
                && !pathExistsNoFollow(evidence.claim.backupSnapshotPath);
        } catch (Exception failure) {
            return false;
        }
    }

    private static Identity regularIdentity(String path) throws Exception {
        Identity identity = Identity.from(Os.lstat(path));
        identity.requireRegular();
        return identity;
    }

    private static Identity optionalRegularIdentity(String path)
        throws Exception {
        try {
            OpenFile open = OpenFile.open(path);
            try {
                open.verifyUnchangedAndCurrent(path);
                return open.identity;
            } finally {
                open.close();
            }
        } catch (ErrnoException missing) {
            if (missing.errno == OsConstants.ENOENT) return null;
            throw missing;
        }
    }

    private static StableDigest hashRegularFile(String path) throws Exception {
        OpenFile open = OpenFile.open(path);
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            FileDescriptor duplicate = Os.dup(open.descriptor);
            try (FileInputStream input = new FileInputStream(duplicate)) {
                byte[] buffer = new byte[1024 * 1024];
                int count;
                while ((count = input.read(buffer)) != -1) {
                    digest.update(buffer, 0, count);
                }
            }
            open.verifyUnchangedAndCurrent(path);
            return new StableDigest(open.identity, hex(digest.digest()));
        } finally {
            open.close();
        }
    }

    private static StableBytes readRegularFile(
        String path,
        int maximumBytes
    ) throws Exception {
        OpenFile open = OpenFile.open(path);
        try {
            if (open.identity.size <= 0L || open.identity.size > maximumBytes) {
                throw new IllegalStateException("marker size is outside bounds");
            }
            FileDescriptor duplicate = Os.dup(open.descriptor);
            ByteArrayOutputStream output = new ByteArrayOutputStream(
                (int) open.identity.size
            );
            try (FileInputStream input = new FileInputStream(duplicate)) {
                byte[] buffer = new byte[8192];
                int count;
                while ((count = input.read(buffer)) != -1) {
                    if (output.size() + count > maximumBytes) {
                        throw new IllegalStateException("marker exceeded size bound");
                    }
                    output.write(buffer, 0, count);
                }
            }
            open.verifyUnchangedAndCurrent(path);
            return new StableBytes(open.identity, output.toByteArray());
        } finally {
            open.close();
        }
    }

    private static String sha256(byte[] bytes) throws Exception {
        return hex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }

    private static String hex(byte[] bytes) {
        StringBuilder result = new StringBuilder(bytes.length * 2);
        for (byte item : bytes) {
            result.append(String.format("%02x", item & 0xff));
        }
        return result.toString();
    }

    private static final class OpenFile {
        final FileDescriptor descriptor;
        final Identity identity;

        private OpenFile(FileDescriptor descriptor, Identity identity) {
            this.descriptor = descriptor;
            this.identity = identity;
        }

        static OpenFile open(String path) throws Exception {
            FileDescriptor descriptor = Os.open(
                path,
                OsConstants.O_RDONLY
                    | OsConstants.O_CLOEXEC
                    | OsConstants.O_NOFOLLOW,
                0
            );
            try {
                Identity identity = Identity.from(Os.fstat(descriptor));
                identity.requireRegular();
                return new OpenFile(descriptor, identity);
            } catch (Exception exception) {
                Os.close(descriptor);
                throw exception;
            }
        }

        void verifyUnchangedAndCurrent(String path) throws Exception {
            Identity after = Identity.from(Os.fstat(descriptor));
            Identity current = Identity.from(Os.lstat(path));
            if (!identity.sameVersion(after)
                || !identity.sameVersion(current)) {
                throw new IllegalStateException(
                    "admitted file changed or its path was replaced"
                );
            }
        }

        void close() {
            try {
                Os.close(descriptor);
            } catch (Exception ignored) {
                // The admission result is already immutable or failed closed.
            }
        }
    }

    public static final class Identity {
        public final long device;
        public final long inode;
        public final int mode;
        public final long links;
        public final long size;
        public final long modifiedSeconds;
        public final long modifiedNanos;
        public final long changedSeconds;
        public final long changedNanos;

        private Identity(StructStat stat) {
            this.device = stat.st_dev;
            this.inode = stat.st_ino;
            this.mode = stat.st_mode;
            this.links = stat.st_nlink;
            this.size = stat.st_size;
            this.modifiedSeconds = stat.st_mtime;
            this.modifiedNanos = stat.st_mtim.tv_nsec;
            this.changedSeconds = stat.st_ctime;
            this.changedNanos = stat.st_ctim.tv_nsec;
        }

        static Identity from(StructStat stat) {
            if (stat == null) {
                throw new IllegalArgumentException("missing file identity");
            }
            return new Identity(stat);
        }

        void requireRegular() {
            if (!OsConstants.S_ISREG(mode) || links != 1L || size < 0L) {
                throw new IllegalStateException(
                    "authority path is not one regular single-link file"
                );
            }
        }

        boolean sameFile(Identity other) {
            return other != null && device == other.device
                && inode == other.inode;
        }

        boolean sameVersion(Identity other) {
            return sameFile(other) && mode == other.mode
                && links == other.links && size == other.size
                && modifiedSeconds == other.modifiedSeconds
                && modifiedNanos == other.modifiedNanos
                && changedSeconds == other.changedSeconds
                && changedNanos == other.changedNanos;
        }
    }

    public static final class Evidence implements AutoCloseable {
        public final NativeReaderV2MarkerClaim claim;
        public final String markerPath;
        public final Identity documentIdentity;
        public final Identity markerIdentity;
        public final String markerSha256;
        public final long journalGeneration;
        public final String journalAuthoritySha256;
        public final Identity recoveryManifestIdentity;
        public final Identity recoverySnapshotIdentity;
        private final MarkAuthority markAuthority;

        private Evidence(
            NativeReaderV2MarkerClaim claim,
            String markerPath,
            Identity documentIdentity,
            Identity markerIdentity,
            String markerSha256,
            long journalGeneration,
            String journalAuthoritySha256,
            Identity recoveryManifestIdentity,
            Identity recoverySnapshotIdentity,
            MarkAuthority markAuthority
        ) {
            this.claim = claim;
            this.markerPath = markerPath;
            this.documentIdentity = documentIdentity;
            this.markerIdentity = markerIdentity;
            this.markerSha256 = markerSha256;
            this.journalGeneration = journalGeneration;
            this.journalAuthoritySha256 = journalAuthoritySha256;
            this.recoveryManifestIdentity = recoveryManifestIdentity;
            this.recoverySnapshotIdentity = recoverySnapshotIdentity;
            this.markAuthority = markAuthority;
        }

        /** Worker-thread proof of the exact live .mark and writer lease. */
        public boolean markAuthorityCurrent() {
            if (Looper.myLooper() == Looper.getMainLooper()) {
                throw new IllegalStateException(
                    "live mark identity revalidation is forbidden on the main thread"
                );
            }
            return markAuthority != null && markAuthority.revalidate();
        }

        /** Records the one native save allowed to advance live .mark identity. */
        public void noteWitnessedMarkSave(boolean dirty, boolean success) {
            if (markAuthority == null) {
                throw new IllegalStateException("live mark authority is absent");
            }
            markAuthority.noteWitnessedSave(dirty, success);
        }

        @Override public void close() {
            if (markAuthority != null) markAuthority.close();
        }
    }

    public static final class AuthorityObservation {
        public final String journalPath;
        public final long generation;
        public final String authoritySha256;
        public final String state;
        public final String activationToken;

        private AuthorityObservation(
            String journalPath,
            long generation,
            String authoritySha256,
            String state,
            String activationToken
        ) {
            this.journalPath = journalPath;
            this.generation = generation;
            this.authoritySha256 = authoritySha256;
            this.state = state;
            this.activationToken = activationToken;
        }
    }

    /**
     * Session-scoped cross-process lease and no-follow live .mark identity.
     * Native bytes remain exclusively owned by Supernote; v2 observes only
     * file identity transitions after a witnessed native save.
     */
    private static final class MarkAuthority {
        private final NativeReaderV2MarkerClaim claim;
        private final String markPath;
        private final String leasePath;
        private final FileOutputStream leaseStream;
        private final FileLock lease;
        private final Identity leaseIdentity;
        private final ExecutorService checkpointExecutor;
        private Identity markIdentity;
        private long witnessGeneration;
        private boolean expectedTransition;
        private boolean unsafe;
        private boolean closing;
        private boolean closed;
        private boolean leaseReleased;

        private MarkAuthority(
            NativeReaderV2MarkerClaim claim,
            String markPath,
            String leasePath,
            FileOutputStream leaseStream,
            FileLock lease,
            Identity leaseIdentity,
            Identity markIdentity,
            long witnessGeneration
        ) {
            this.claim = claim;
            this.markPath = markPath;
            this.leasePath = leasePath;
            this.leaseStream = leaseStream;
            this.lease = lease;
            this.leaseIdentity = leaseIdentity;
            this.markIdentity = markIdentity;
            this.witnessGeneration = witnessGeneration;
            this.checkpointExecutor = Executors.newSingleThreadExecutor(
                new java.util.concurrent.ThreadFactory() {
                    @Override public Thread newThread(Runnable runnable) {
                        Thread thread = new Thread(
                            runnable,
                            "sn-v2-mark-checkpoint"
                        );
                        thread.setDaemon(true);
                        return thread;
                    }
                }
            );
        }

        static MarkAuthority acquire(NativeReaderV2MarkerClaim claim)
            throws Exception {
            File markFile = new File(claim.markPath).getAbsoluteFile();
            File parent = markFile.getParentFile();
            if (parent == null) {
                throw new IllegalStateException("live mark has no parent");
            }
            String leasePath = new File(
                parent,
                "." + markFile.getName() + ".snspread-writer.lock"
            ).getAbsolutePath();
            FileDescriptor descriptor = Os.open(
                leasePath,
                OsConstants.O_RDWR | OsConstants.O_CREAT
                    | OsConstants.O_CLOEXEC | OsConstants.O_NOFOLLOW,
                0600
            );
            FileOutputStream stream = null;
            FileLock lock = null;
            try {
                Identity descriptorIdentity = Identity.from(
                    Os.fstat(descriptor)
                );
                descriptorIdentity.requireRegular();
                Identity pathIdentity = Identity.from(Os.lstat(leasePath));
                pathIdentity.requireRegular();
                if (!descriptorIdentity.sameVersion(pathIdentity)) {
                    throw new IllegalStateException(
                        "live mark lease path was replaced during acquisition"
                    );
                }
                stream = new FileOutputStream(descriptor);
                descriptor = null;
                try {
                    lock = stream.getChannel().tryLock();
                } catch (OverlappingFileLockException conflict) {
                    throw new IllegalStateException(
                        "another Native Reader v2 writer owns this mark",
                        conflict
                    );
                }
                if (lock == null) {
                    throw new IllegalStateException(
                        "another process owns the live mark writer lease"
                    );
                }
                LiveMarkState liveMark = readLiveMarkState(claim.markPath);
                long witnessGeneration = 0L;
                if (!liveMarkMatchesRecovery(claim, liveMark)) {
                    LiveMarkCheckpoint checkpoint = readLiveMarkCheckpoint(
                        claim
                    );
                    if (!liveMarkMatchesCheckpoint(liveMark, checkpoint)) {
                        throw new IllegalStateException(
                            "live mark lacks witnessed persisted authority"
                        );
                    }
                    witnessGeneration = checkpoint.generation;
                }
                return new MarkAuthority(
                    claim,
                    claim.markPath,
                    leasePath,
                    stream,
                    lock,
                    descriptorIdentity,
                    liveMark.identity,
                    witnessGeneration
                );
            } catch (Exception failure) {
                if (lock != null) {
                    try { lock.release(); } catch (Exception ignored) {}
                }
                if (stream != null) {
                    try { stream.close(); } catch (Exception ignored) {}
                } else if (descriptor != null) {
                    try { Os.close(descriptor); } catch (Exception ignored) {}
                }
                throw failure;
            }
        }

        void noteWitnessedSave(boolean dirty, boolean success) {
            final long generation;
            synchronized (this) {
                if (closing || closed || unsafe) {
                    unsafe = true;
                    throw new IllegalStateException(
                        "live mark save authority is not exclusive"
                    );
                }
                if (!dirty) return;
                if (!success || witnessGeneration == Long.MAX_VALUE) {
                    unsafe = true;
                    throw new IllegalStateException(
                        "witnessed live mark save did not commit safely"
                    );
                }
                expectedTransition = true;
                generation = ++witnessGeneration;
            }
            try {
                checkpointExecutor.execute(new Runnable() {
                    @Override public void run() {
                        persistWitnessedCheckpoint(generation);
                    }
                });
            } catch (RejectedExecutionException rejected) {
                synchronized (this) { unsafe = true; }
                throw new IllegalStateException(
                    "live mark checkpoint worker is unavailable",
                    rejected
                );
            }
        }

        private void persistWitnessedCheckpoint(long generation) {
            try {
                synchronized (this) {
                    if (closed || unsafe || generation != witnessGeneration) {
                        return;
                    }
                }
                if (!revalidateForCheckpoint()) {
                    throw new IllegalStateException(
                        "live mark writer lease changed before checkpoint"
                    );
                }
                StableDigest document = hashRegularFile(
                    claim.canonicalDocumentPath
                );
                if (document.identity.size != claim.documentLength
                    || !document.sha256.equals(claim.documentSha256)) {
                    throw new IllegalStateException(
                        "document changed before live mark checkpoint"
                    );
                }
                verifyRecoveryEvidence(
                    claim,
                    new File(claim.canonicalDocumentPath)
                );
                LiveMarkState live = readLiveMarkState(markPath);
                synchronized (this) {
                    if (closed || unsafe || generation != witnessGeneration) {
                        return;
                    }
                }
                byte[] bytes = liveMarkCheckpointBytes(
                    claim,
                    live,
                    generation
                );
                File checkpoint = new File(
                    markPath + LIVE_MARK_CHECKPOINT_SUFFIX
                );
                writeLiveMarkCheckpointAtomically(checkpoint, bytes);
                LiveMarkCheckpoint persisted = readLiveMarkCheckpoint(claim);
                LiveMarkState after = readLiveMarkState(markPath);
                if (!revalidateForCheckpoint()) {
                    throw new IllegalStateException(
                        "live mark writer lease changed across checkpoint"
                    );
                }
                synchronized (this) {
                    if (closed || generation != witnessGeneration) return;
                    if (!liveMarkMatchesCheckpoint(after, persisted)
                        || persisted.generation != generation) {
                        throw new IllegalStateException(
                            "live mark changed across checkpoint publication"
                        );
                    }
                    markIdentity = after.identity;
                    expectedTransition = false;
                }
                Log.i(TAG, "witnessed live mark checkpoint generation="
                    + generation);
            } catch (Throwable failure) {
                synchronized (this) {
                    if (!closed && generation == witnessGeneration) {
                        unsafe = true;
                    }
                }
                Log.e(TAG, "witnessed live mark checkpoint failed", failure);
            }
        }

        synchronized boolean revalidate() {
            return revalidateLocked(false);
        }

        private synchronized boolean revalidateForCheckpoint() {
            return revalidateLocked(true);
        }

        private boolean revalidateLocked(boolean allowClosing) {
            if (closed || (closing && !allowClosing) || unsafe
                || lease == null || !lease.isValid()) {
                return false;
            }
            try {
                Identity leaseDescriptor = Identity.from(
                    Os.fstat(leaseStream.getFD())
                );
                Identity leaseCurrent = Identity.from(Os.lstat(leasePath));
                leaseDescriptor.requireRegular();
                leaseCurrent.requireRegular();
                if (!leaseIdentity.sameVersion(leaseDescriptor)
                    || !leaseIdentity.sameVersion(leaseCurrent)) {
                    unsafe = true;
                    return false;
                }
                Identity current = optionalRegularIdentity(markPath);
                if (sameVersion(markIdentity, current)) {
                    expectedTransition = false;
                    return true;
                }
                if (!expectedTransition || current == null) {
                    unsafe = true;
                    return false;
                }
                markIdentity = current;
                expectedTransition = false;
                return true;
            } catch (Throwable failure) {
                unsafe = true;
                return false;
            }
        }

        private static boolean sameVersion(Identity first, Identity second) {
            return first == null ? second == null : first.sameVersion(second);
        }

        void close() {
            synchronized (this) {
                if (closing || closed) return;
                closing = true;
            }
            checkpointExecutor.shutdown();
            boolean drained = false;
            try {
                drained = checkpointExecutor.awaitTermination(
                    3L,
                    TimeUnit.SECONDS
                );
            } catch (InterruptedException interrupted) {
                synchronized (this) { unsafe = true; }
                Thread.currentThread().interrupt();
            }
            if (drained) {
                releaseLeaseAfterCheckpointDrain();
                return;
            }
            synchronized (this) { unsafe = true; }
            checkpointExecutor.shutdownNow();
            Thread cleanup = new Thread(new Runnable() {
                @Override public void run() {
                    boolean interrupted = false;
                    while (true) {
                        try {
                            if (checkpointExecutor.awaitTermination(
                                    1L,
                                    TimeUnit.DAYS
                                )) {
                                break;
                            }
                        } catch (InterruptedException retry) {
                            interrupted = true;
                        }
                    }
                    releaseLeaseAfterCheckpointDrain();
                    if (interrupted) Thread.currentThread().interrupt();
                }
            }, "sn-v2-mark-lease-cleanup");
            cleanup.setDaemon(true);
            cleanup.start();
        }

        private void releaseLeaseAfterCheckpointDrain() {
            synchronized (this) {
                if (leaseReleased) return;
                leaseReleased = true;
                closed = true;
            }
            try { lease.release(); } catch (Exception ignored) {}
            try { leaseStream.close(); } catch (Exception ignored) {}
        }
    }

    private static final class RecoveryIdentity {
        final Identity manifest;
        final Identity snapshot;

        RecoveryIdentity(Identity manifest, Identity snapshot) {
            this.manifest = manifest;
            this.snapshot = snapshot;
        }
    }

    private static final class LiveMarkState {
        final boolean present;
        final Identity identity;
        final long length;
        final String sha256;

        LiveMarkState(
            boolean present,
            Identity identity,
            long length,
            String sha256
        ) {
            this.present = present;
            this.identity = identity;
            this.length = length;
            this.sha256 = sha256;
        }

        static LiveMarkState absent() {
            return new LiveMarkState(false, null, 0L, "ABSENT");
        }
    }

    private static final class LiveMarkCheckpoint {
        final String path;
        final Identity identity;
        final boolean present;
        final long length;
        final String sha256;
        final long generation;

        LiveMarkCheckpoint(
            String path,
            Identity identity,
            boolean present,
            long length,
            String sha256,
            long generation
        ) {
            this.path = path;
            this.identity = identity;
            this.present = present;
            this.length = length;
            this.sha256 = sha256;
            this.generation = generation;
        }
    }

    private static final class StableBytes {
        final Identity identity;
        final byte[] bytes;

        StableBytes(Identity identity, byte[] bytes) {
            this.identity = identity;
            this.bytes = bytes;
        }
    }

    private static final class StableDigest {
        final Identity identity;
        final String sha256;

        StableDigest(Identity identity, String sha256) {
            this.identity = identity;
            this.sha256 = sha256;
        }
    }
}
