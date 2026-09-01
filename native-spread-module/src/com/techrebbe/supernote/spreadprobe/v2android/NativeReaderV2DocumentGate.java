package com.techrebbe.supernote.spreadprobe.v2android;

import android.os.Looper;
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
import java.util.Properties;

/** Descriptor-backed, off-UI-thread admission of one exact original PDF. */
public final class NativeReaderV2DocumentGate {
    public static final String MARKER_SUFFIX = ".snspread";

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
            if (!canonical.endsWith(".pdf")) {
                throw new IllegalArgumentException(
                    "Native Reader v2 requires an exact lowercase PDF path"
                );
            }
            String markerPath = canonical + MARKER_SUFFIX;
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
            return new Evidence(
                claim,
                markerPath,
                document.identity,
                markerAfter.identity,
                sha256(markerAfter.bytes)
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
        public final long changedSeconds;

        private Identity(StructStat stat) {
            this.device = stat.st_dev;
            this.inode = stat.st_ino;
            this.mode = stat.st_mode;
            this.links = stat.st_nlink;
            this.size = stat.st_size;
            this.modifiedSeconds = stat.st_mtime;
            this.changedSeconds = stat.st_ctime;
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
                && changedSeconds == other.changedSeconds;
        }
    }

    public static final class Evidence {
        public final NativeReaderV2MarkerClaim claim;
        public final String markerPath;
        public final Identity documentIdentity;
        public final Identity markerIdentity;
        public final String markerSha256;

        private Evidence(
            NativeReaderV2MarkerClaim claim,
            String markerPath,
            Identity documentIdentity,
            Identity markerIdentity,
            String markerSha256
        ) {
            this.claim = claim;
            this.markerPath = markerPath;
            this.documentIdentity = documentIdentity;
            this.markerIdentity = markerIdentity;
            this.markerSha256 = markerSha256;
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
