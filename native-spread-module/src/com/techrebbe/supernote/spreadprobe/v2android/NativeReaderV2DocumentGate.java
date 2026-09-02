package com.techrebbe.supernote.spreadprobe.v2android;

import android.os.Looper;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructStat;

import com.techrebbe.supernote.spreadprobe.v2.NativeReaderV2MarkerClaim;
import com.techrebbe.supernote.spreadprobe.v2.NativeReaderV2StrictProperties;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Locale;
import java.util.Properties;
import java.util.Set;

/** Descriptor-backed, off-UI-thread admission of one exact original PDF. */
public final class NativeReaderV2DocumentGate {
    public static final String MARKER_SUFFIX = ".snspread";
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
                NativeReaderV2StrictProperties.MAX_BYTES
            );
            Properties properties = NativeReaderV2StrictProperties.parse(
                markerBefore.bytes
            );
            StableDigest document = hashRegularFile(canonical);

            // The tiny marker is intentionally read twice around the expensive
            // PDF hash. A same-inode, same-size, sub-second rewrite cannot
            // smuggle mixed-time configuration into the accepted claim.
            StableBytes markerAfter = readRegularFile(
                markerPath,
                NativeReaderV2StrictProperties.MAX_BYTES
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
            return new Evidence(
                claim,
                markerPath,
                document.identity,
                markerAfter.identity,
                sha256(markerAfter.bytes),
                recovery.manifest,
                recovery.snapshot
            );
        } catch (RuntimeException exception) {
            throw exception;
        } catch (Exception exception) {
            throw new IllegalStateException(
                "Native Reader v2 document admission failed",
                exception
            );
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
                NativeReaderV2StrictProperties.MAX_BYTES
            );
            if (!evidence.markerIdentity.sameVersion(marker.identity)
                || !evidence.markerSha256.equals(sha256(marker.bytes))) {
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
     * Main-thread-safe identity check used before every privileged native
     * operation. Initial admission and resume revalidation still hash the
     * authority bytes off-thread; this guard prevents stale admitted evidence
     * from surviving an in-place rewrite or path replacement between resumes.
     */
    public static boolean fastEvidenceStillCurrent(Evidence evidence) {
        if (evidence == null || evidence.claim == null) return false;
        try {
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

    public static final class Evidence {
        public final NativeReaderV2MarkerClaim claim;
        public final String markerPath;
        public final Identity documentIdentity;
        public final Identity markerIdentity;
        public final String markerSha256;
        public final Identity recoveryManifestIdentity;
        public final Identity recoverySnapshotIdentity;

        private Evidence(
            NativeReaderV2MarkerClaim claim,
            String markerPath,
            Identity documentIdentity,
            Identity markerIdentity,
            String markerSha256,
            Identity recoveryManifestIdentity,
            Identity recoverySnapshotIdentity
        ) {
            this.claim = claim;
            this.markerPath = markerPath;
            this.documentIdentity = documentIdentity;
            this.markerIdentity = markerIdentity;
            this.markerSha256 = markerSha256;
            this.recoveryManifestIdentity = recoveryManifestIdentity;
            this.recoverySnapshotIdentity = recoverySnapshotIdentity;
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
