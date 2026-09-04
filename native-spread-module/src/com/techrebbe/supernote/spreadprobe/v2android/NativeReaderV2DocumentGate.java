package com.techrebbe.supernote.spreadprobe.v2android;

import android.os.Looper;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructStat;

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
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Locale;
import java.util.Properties;
import java.util.Set;
import java.util.UUID;

/** Descriptor-backed, off-UI-thread admission of one exact original PDF. */
public final class NativeReaderV2DocumentGate {
    public static final String MARKER_SUFFIX = ".snspread-v3";
    public static final String LEGACY_MARKER_SUFFIX = ".snspread";
    private static final String BACKUP_MANIFEST_SUFFIX =
        ".snspread-backup.properties";
    private static final String BACKUP_SNAPSHOT_SUFFIX =
        ".snspread-backup.mark";
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
                || !expectedState.equals(payload.getProperty("activationState"))
                || !isCanonicalUuid(activationToken)) {
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
        private final String markPath;
        private final String leasePath;
        private final FileOutputStream leaseStream;
        private final FileLock lease;
        private final Identity leaseIdentity;
        private Identity markIdentity;
        private boolean expectedTransition;
        private boolean unsafe;
        private boolean closed;

        private MarkAuthority(
            String markPath,
            String leasePath,
            FileOutputStream leaseStream,
            FileLock lease,
            Identity leaseIdentity,
            Identity markIdentity
        ) {
            this.markPath = markPath;
            this.leasePath = leasePath;
            this.leaseStream = leaseStream;
            this.lease = lease;
            this.leaseIdentity = leaseIdentity;
            this.markIdentity = markIdentity;
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
                Identity liveMark = optionalRegularIdentity(claim.markPath);
                if (claim.originalMarkPresent) {
                    if (liveMark == null) {
                        throw new IllegalStateException(
                            "live mark disappeared after recovery snapshot"
                        );
                    }
                    StableDigest digest = hashRegularFile(claim.markPath);
                    if (!liveMark.sameVersion(digest.identity)
                        || digest.identity.size != claim.markLength
                        || !claim.markSha256.equals(digest.sha256)) {
                        throw new IllegalStateException(
                            "live mark disagrees with admitted recovery snapshot"
                        );
                    }
                } else if (liveMark != null) {
                    throw new IllegalStateException(
                        "live mark appeared after absent-mark recovery"
                    );
                }
                return new MarkAuthority(
                    claim.markPath,
                    leasePath,
                    stream,
                    lock,
                    descriptorIdentity,
                    liveMark
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

        synchronized void noteWitnessedSave(boolean dirty, boolean success) {
            if (closed || unsafe || expectedTransition) {
                unsafe = true;
                throw new IllegalStateException(
                    "live mark save authority is not exclusive"
                );
            }
            if (dirty) {
                if (!success) {
                    unsafe = true;
                } else {
                    expectedTransition = true;
                }
            }
        }

        synchronized boolean revalidate() {
            if (closed || unsafe || lease == null || !lease.isValid()) {
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

        synchronized void close() {
            if (closed) return;
            closed = true;
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
