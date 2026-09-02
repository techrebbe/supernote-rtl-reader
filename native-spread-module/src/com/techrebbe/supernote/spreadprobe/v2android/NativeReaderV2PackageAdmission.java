package com.techrebbe.supernote.spreadprobe.v2android;

import android.system.Os;
import android.system.OsConstants;
import android.system.StructStat;

import java.io.File;
import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.security.MessageDigest;

/** Exact, descriptor-backed admission for the inspected firmware package. */
public final class NativeReaderV2PackageAdmission {
    public static final String EXPECTED_FINGERPRINT =
        "Supernote/Supernote/Supernote:11/RQ2A.210505.003/"
        + "eng.supern.20260616.100032:user/release-keys";
    public static final String EXPECTED_APK_PATH =
        "/system_ext/app/SupernoteDocument/SupernoteDocument.apk";
    public static final long EXPECTED_APK_LENGTH = 138486560L;
    public static final String EXPECTED_APK_SHA256 =
        "f008c86ddc42008c36b431410cbc3b29057b4aad9bc26c3577ee13b39b230482";

    private NativeReaderV2PackageAdmission() {}

    public static Report verifyLoaded(
        String sourceDir,
        String[] splitSourceDirs,
        String fingerprint
    ) {
        if (sourceDir == null
            || !EXPECTED_APK_PATH.equals(new File(sourceDir).getAbsolutePath())) {
            throw new IllegalStateException(
                "active document class loader is not backed by the admitted APK"
            );
        }
        if (splitSourceDirs != null && splitSourceDirs.length != 0) {
            throw new IllegalStateException(
                "active document class loader has unadmitted split APKs"
            );
        }
        return verify(new File(sourceDir), fingerprint);
    }

    public static Report verify(File apk, String fingerprint) {
        if (!EXPECTED_FINGERPRINT.equals(fingerprint)) {
            throw new IllegalStateException("firmware fingerprint mismatch");
        }
        if (apk == null || !EXPECTED_APK_PATH.equals(apk.getAbsolutePath())) {
            throw new IllegalStateException("document APK path mismatch");
        }

        FileDescriptor descriptor = null;
        try {
            descriptor = Os.open(
                EXPECTED_APK_PATH,
                OsConstants.O_RDONLY
                    | OsConstants.O_CLOEXEC
                    | OsConstants.O_NOFOLLOW,
                0
            );
            StructStat before = Os.fstat(descriptor);
            requireRegularExpectedFile(before);
            StructStat pathBefore = Os.lstat(EXPECTED_APK_PATH);
            requireRegularExpectedFile(pathBefore);
            if (!sameIdentity(before, pathBefore)) {
                throw new IllegalStateException(
                    "document APK path does not name admitted descriptor"
                );
            }

            FileDescriptor duplicate = Os.dup(descriptor);
            String digest;
            try (FileInputStream input = new FileInputStream(duplicate)) {
                digest = sha256(input);
            }

            StructStat after = Os.fstat(descriptor);
            StructStat pathAfter = Os.lstat(EXPECTED_APK_PATH);
            if (!sameIdentity(before, after)
                || !sameIdentity(before, pathAfter)) {
                throw new IllegalStateException(
                    "document APK changed or its path was replaced during admission"
                );
            }
            if (!EXPECTED_APK_SHA256.equals(digest)) {
                throw new IllegalStateException("document APK digest mismatch");
            }
            return new Report(digest, before.st_dev, before.st_ino);
        } catch (Exception exception) {
            if (exception instanceof IllegalStateException) {
                throw (IllegalStateException) exception;
            }
            throw new IllegalStateException(
                "could not verify the installed document APK",
                exception
            );
        } finally {
            if (descriptor != null) {
                try {
                    Os.close(descriptor);
                } catch (Exception ignored) {
                    // Admission has already completed or failed closed.
                }
            }
        }
    }

    private static void requireRegularExpectedFile(StructStat stat) {
        if (stat == null || !OsConstants.S_ISREG(stat.st_mode)
            || stat.st_size != EXPECTED_APK_LENGTH || stat.st_nlink != 1) {
            throw new IllegalStateException(
                "document APK descriptor identity mismatch"
            );
        }
    }

    private static boolean sameIdentity(StructStat first, StructStat second) {
        return second != null
            && first.st_dev == second.st_dev
            && first.st_ino == second.st_ino
            && first.st_mode == second.st_mode
            && first.st_nlink == second.st_nlink
            && first.st_size == second.st_size
            && first.st_mtime == second.st_mtime
            && first.st_mtim.tv_nsec == second.st_mtim.tv_nsec
            && first.st_ctime == second.st_ctime
            && first.st_ctim.tv_nsec == second.st_ctim.tv_nsec;
    }

    private static String sha256(FileInputStream input) throws Exception {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] buffer = new byte[1024 * 1024];
        int count;
        while ((count = input.read(buffer)) != -1) {
            sha256.update(buffer, 0, count);
        }
        StringBuilder value = new StringBuilder(64);
        for (byte item : sha256.digest()) {
            value.append(String.format("%02x", item & 0xff));
        }
        return value.toString();
    }

    public static final class Report {
        public final String apkSha256;
        public final long device;
        public final long inode;

        private Report(String apkSha256, long device, long inode) {
            this.apkSha256 = apkSha256;
            this.device = device;
            this.inode = inode;
        }
    }
}
