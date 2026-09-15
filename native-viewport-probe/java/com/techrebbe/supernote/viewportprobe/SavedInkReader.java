package com.techrebbe.supernote.viewportprobe;

import android.graphics.Point;
import android.graphics.PointF;
import android.graphics.Rect;
import android.graphics.RectF;
import android.os.ParcelFileDescriptor;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructStat;
import dalvik.system.DexClassLoader;
import java.io.File;
import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Disposable-copy reader for a SEPARATE app_process, never Document/DrawPath.
 * Not an APK, LSPosed hook, writer, converter, or production export API.
 * All native state is private to the helper process. No Binder connection.
 */
public final class SavedInkReader {
    private static final String APK_SHA =
        "f008c86ddc42008c36b431410cbc3b29057b4aad9bc26c3577ee13b39b230482";
    private static final String ROOT = "/data/local/tmp/native-viewport-ink-reader/";
    private static final String INPUT_ROOT_PATH =
        "/data/local/native-viewport-ink-reader-input";
    private static final String INPUT_ROOT = INPUT_ROOT_PATH + "/";
    private static final String APK = "/system_ext/app/SupernoteDocument/SupernoteDocument.apk";
    private static final String LIBS = "/system_ext/app/SupernoteDocument/lib/arm64";
    private static final String RECOGNITION_SHA =
        "898129ad25fe90734f2b9760786c846864f3622ebd82c25c5a3ce82ca4174919";
    private static final String PROCESS_SHA =
        "b7af795b72076e1996aa88dee3db32feecc25b89da01e9c96db8a86696c9bff4";
    private static final String NATIVE_TRAIL_CLASS =
        "com.example.libsupernote.JniTrailContainer";
    static final byte[] EVIDENCE_PREFIX =
        "NATIVE_VIEWPORT_INK_EVIDENCE ".getBytes(StandardCharsets.US_ASCII);
    // Keep these byte-for-byte equivalent to ink_oracle.py.  The encoded trail
    // tree is capped before publication; the small envelope is checked again.
    static final int MAX_CAPTURE_BYTES = 32 * 1024 * 1024;
    private static final long MAX_FIRMWARE_FILE_BYTES = 256L * 1024 * 1024;
    private static final int MAX_TRAIL_JSON_BYTES = MAX_CAPTURE_BYTES;
    private static final int MAX_DEPTH = 16;
    private static final int MAX_VALUES = 2000000;
    private static final int MAX_STRING_BYTES = 65536;
    private static final int MAX_LIST_ITEMS = 200000;
    private static final int MFD_ALLOW_SEALING = 0x0002;
    // Linux O_DIRECTORY. Android's public OsConstants omits this value even
    // though the kernel ABI and android.system.Os.open support it.
    private static final int O_DIRECTORY = 0x4000;
    private static final int F_ADD_SEALS = 1033;
    private static final int F_GET_SEALS = 1034;
    private static final int REQUIRED_SEALS = 0x0001 | 0x0002 | 0x0004 | 0x0008;
    private static final int ROOT_UID = 0;
    private static final int SHELL_UID = 2000;
    private static final int MODE_PERMISSION_MASK = 07777;
    private static final int SNAPSHOT_DIRECTORY_PERMISSIONS = 0550;
    private static final int SNAPSHOT_FILE_PERMISSIONS = 0440;
    static final String SOURCE_SHA256_AUTHORITY = "external-assertion-v1";

    public static void main(String[] args) {
        try {
            CanonicalObject result = collect(args);
            String payload = canonicalJson(result, MAX_CAPTURE_BYTES);
            byte[] encoded = strictUtf8Bytes(payload, MAX_CAPTURE_BYTES);
            publishEvidenceFrame(System.out, encoded);
        } catch (Throwable error) {
            System.err.println("NATIVE_VIEWPORT_INK_FAILED " + error.getClass().getName()
                + ": " + error.getMessage());
            System.exit(2);
        }
    }

    private static CanonicalObject collect(String[] args) throws Exception {
        // This is an adb-shell diagnostic, not a root helper.  Refuse a root,
        // app, or mixed UID/GID before parsing attacker-controlled arguments,
        // touching any file, authenticating firmware, or loading native code.
        requireShellProcessIdentity(Os.getuid(), Os.getgid());
        if (args.length != 6 || !args[3].matches("[0-9a-f]{64}")
            || !args[4].matches("[0-9a-f]{64}") || !args[5].matches("[1-9][0-9]*")) {
            throw new IllegalArgumentException(
                "apk nativeLibDir disposableCopy.mark expectedMarkSha256 sourceSha256 nativePage1Based");
        }
        int page = Integer.parseInt(args[5]);
        File copy = new File(args[2]);
        String path = copy.getCanonicalPath();
        // Never accepts a Document/MyStyle file or a renamed symlink to one.
        // Root stages this disposable input beneath /data/local, labels it only
        // for shell read access, and leaves neither the directory nor file
        // writable by the shell process that runs this collector.
        if (!path.equals(copy.getAbsolutePath()) || !path.startsWith(INPUT_ROOT)
            || !admittedSnapshotBasename(copy.getName())) {
            throw new IllegalArgumentException(
                "only a root-locked bounded disposable .mark copy is admitted");
        }
        File apk = new File(args[0]);
        File libs = new File(args[1]);
        if (!APK.equals(apk.getAbsolutePath()) || !APK.equals(apk.getCanonicalPath())
            || !LIBS.equals(libs.getAbsolutePath()) || !LIBS.equals(libs.getCanonicalPath())) {
            throw new IllegalArgumentException("pinned firmware APK/native library directory required");
        }
        // Retain the admitted disposable directory so the collector can compare
        // its descriptor-anchored name with the conventional absolute name the
        // firmware requires. Root-owned, non-writable ancestors keep UID 2000
        // from redirecting either name; a trusted root stager remains quiescent
        // for the complete two-capture transaction.
        if (!copy.getParentFile().getCanonicalPath().equals(
                new File(INPUT_ROOT_PATH).getCanonicalPath())
            || copy.getName().contains("/") || copy.getName().contains("\\")) {
            throw new IllegalArgumentException("disposable mark must be a direct child of the admitted root");
        }
        FirmwareAuthority firmware = FirmwareAuthority.open();
        FileDescriptor parent = null;
        ParcelFileDescriptor parentView = null;
        FileDescriptor source = null;
        FileDescriptor sealed = null;
        try {
            firmware.verify();
            parent = Os.open(INPUT_ROOT_PATH, OsConstants.O_RDONLY | OsConstants.O_CLOEXEC
                | OsConstants.O_NOFOLLOW | O_DIRECTORY, 0);
            parentView = ParcelFileDescriptor.dup(parent);
            StructStat parentIdentity = Os.fstat(parent);
            verifyInputDirectory(parent, parentIdentity);
            String anchoredPath = "/proc/self/fd/" + parentView.getFd() + "/" + copy.getName();
            StructStat namedBefore = Os.lstat(anchoredPath);
            if (!OsConstants.S_ISREG(namedBefore.st_mode)) {
                throw new IllegalArgumentException("only a regular disposable mark is admitted");
            }
            source = Os.open(anchoredPath, OsConstants.O_RDONLY | OsConstants.O_CLOEXEC
                | OsConstants.O_NOFOLLOW | OsConstants.O_NONBLOCK, 0);
            StructStat opened = Os.fstat(source);
            StructStat named = Os.lstat(anchoredPath);
            if (!sameFile(opened, named) || !OsConstants.S_ISREG(opened.st_mode)
                || !admittedDisposableMetadata(opened.st_size, opened.st_nlink,
                    opened.st_uid, opened.st_gid, opened.st_mode)) {
                throw new IllegalArgumentException("only a bounded regular disposable mark is admitted");
            }
            sealed = Os.memfd_create("native-viewport-disposable-mark",
                OsConstants.MFD_CLOEXEC | MFD_ALLOW_SEALING);
            String before = copyAndHash(source, sealed, opened.st_size);
            if (!before.equals(args[3])) throw new IllegalStateException("unexpected disposable mark digest");
            if (Os.fcntlInt(sealed, F_ADD_SEALS, REQUIRED_SEALS) != 0
                || Os.fcntlInt(sealed, F_GET_SEALS, 0) != REQUIRED_SEALS) {
                throw new IllegalStateException("could not seal disposable mark snapshot");
            }
            verifyInputAuthority(parent, parentIdentity, source, opened, anchoredPath,
                path, sealed, before);

            // Only the pinned, read-only system APK/library directory is admitted.
            ClassLoader helperLoader = SavedInkReader.class.getClassLoader();
            ClassLoader bootParent = helperLoader == null ? null : helperLoader.getParent();
            DexClassLoader loader = new DexClassLoader(APK, ROOT, LIBS, bootParent);
            Class<?> constants = Class.forName(
                "com.ratta.supernote.documentlib.constants.DocumentConstants", false, loader);
            requireDefinedBy(constants, loader);
            int deviceType = (Integer)constants.getMethod("getDeviceType").invoke(null);
            if (deviceType != 2) throw new IllegalStateException("this diagnostic is limited to the A6X2 Nomad");
            Class<?> type = Class.forName("com.example.libsupernote.SuperNoteNote", false, loader);
            requireDefinedBy(type, loader);
            Object note = type.getMethod("createSuperNoteNote").invoke(null);
            if (note == null || note.getClass() != type) {
                throw new IllegalStateException("native note has unexpected implementation");
            }
            requireDefinedBy(note.getClass(), loader);
            Object records;
            try {
                if (!Boolean.TRUE.equals(type.getMethod("markInitProcess", int.class).invoke(note, deviceType + 2))) {
                    throw new IllegalStateException("native Nomad initialization refused");
                }
                Object pageInventory = type.getMethod("fetchPagesOfMark", String.class)
                    .invoke(note, path);
                requireExactArrayList(pageInventory, "saved mark page inventory");
                if (((List<?>)pageInventory).size() > 100000) {
                    throw new IllegalStateException("saved mark page inventory unavailable");
                }
                HashSet<Integer> pages = new HashSet<Integer>();
                for (Object entry : (List<?>)pageInventory) {
                    if (!(entry instanceof Integer) || (Integer)entry < 1 || !pages.add((Integer)entry)) {
                        throw new IllegalStateException("invalid saved mark page inventory");
                    }
                }
                if (!pages.contains(page)) throw new IllegalStateException("requested page has no saved mark record");
                verifyInputAuthority(parent, parentIdentity, source, opened, anchoredPath,
                    path, sealed, before);
                firmware.verify();
                Object list = type.getMethod("getFilePageTrails", String.class, int.class)
                    .invoke(note, path, page);
                requireExactArrayList(list, "saved-page record list");
                if (((List<?>)list).size() > 4096) {
                    throw new IllegalStateException("no complete bounded saved-page list");
                }
                records = encodeNativeRecordList(
                    list, loader, NATIVE_TRAIL_CLASS);
            } finally {
                type.getMethod("freeCommon").invoke(note);
            }
            StructStat afterDescriptor = Os.fstat(source);
            String after = shaDescriptor(source, opened.st_size);
            String sealedAfter = shaDescriptor(sealed, opened.st_size);
            if (!before.equals(after) || !before.equals(sealedAfter)
                || !sameFile(opened, afterDescriptor)) {
                throw new IllegalStateException("input authority changed during native read");
            }
            verifyInputAuthority(parent, parentIdentity, source, opened, anchoredPath,
                path, sealed, before);
            firmware.verify();
            // Final operation on the input authority: reopen the same basename
            // relative to the retained directory, then verify identity and bytes.
            FileDescriptor finalNamed = Os.open(path, OsConstants.O_RDONLY
                | OsConstants.O_CLOEXEC | OsConstants.O_NOFOLLOW | OsConstants.O_NONBLOCK, 0);
            try {
                StructStat finalStat = Os.fstat(finalNamed);
                StructStat finalNameStat = Os.lstat(path);
                StructStat finalAnchoredStat = Os.lstat(anchoredPath);
                if (!sameFile(opened, finalStat) || !sameFile(opened, finalNameStat)
                    || !sameFile(opened, finalAnchoredStat)
                    || !before.equals(shaDescriptor(finalNamed, opened.st_size))) {
                    throw new IllegalStateException("final disposable mark name changed");
                }
            } finally {
                Os.close(finalNamed);
            }
            return evidenceEnvelope(args[4], page, records, before, after);
        } finally {
            try { if (source != null) Os.close(source); } finally {
                try { if (sealed != null) Os.close(sealed); } finally {
                    try { if (parentView != null) parentView.close(); }
                    finally {
                        try { if (parent != null) Os.close(parent); }
                        finally { firmware.close(); }
                    }
                }
            }
        }
    }

    static CanonicalObject evidenceEnvelope(String assertedSourceSha256, int page,
                                             Object records, String markBefore,
                                             String markAfter) {
        if (assertedSourceSha256 == null || !assertedSourceSha256.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("externally asserted source SHA-256 required");
        }
        if (markBefore == null || !markBefore.matches("[0-9a-f]{64}")
                || markAfter == null || !markAfter.matches("[0-9a-f]{64}")
                || !markBefore.equals(markAfter) || page < 1) {
            throw new IllegalArgumentException("complete stable mark/page authority required");
        }
        return new CanonicalObject()
            .put("complete", true)
            .put("markSha256After", markAfter)
            .put("markSha256Before", markBefore)
            .put("nativePage", page)
            .put("readMethod", "getFilePageTrails")
            .put("schema", "native-viewport-ink-evidence-v2")
            .put("sourceSha256", assertedSourceSha256)
            .put("sourceSha256Authority", SOURCE_SHA256_AUTHORITY)
            .put("trails", records);
    }

    static boolean admittedDisposableMetadata(long size, long links, int uid, int gid, int mode) {
        return size > 0 && size <= MAX_CAPTURE_BYTES && links == 1
            && uid == ROOT_UID && gid == SHELL_UID
            && (mode & MODE_PERMISSION_MASK) == SNAPSHOT_FILE_PERMISSIONS;
    }

    static boolean admittedSnapshotDirectoryMetadata(long links, int uid, int gid, int mode) {
        return links >= 2 && uid == ROOT_UID && gid == SHELL_UID
            && (mode & MODE_PERMISSION_MASK) == SNAPSHOT_DIRECTORY_PERMISSIONS;
    }

    static boolean admittedSnapshotBasename(String name) {
        return name != null && name.length() <= 128
            && name.matches("[A-Za-z0-9][A-Za-z0-9._-]*\\.mark");
    }

    private static void verifyInputDirectory(FileDescriptor parent, StructStat identity)
            throws Exception {
        StructStat retained = Os.fstat(parent);
        StructStat named = Os.lstat(INPUT_ROOT_PATH);
        if (!sameFile(identity, retained) || !sameFile(identity, named)
            || !OsConstants.S_ISDIR(retained.st_mode)
            || !admittedSnapshotDirectoryMetadata(retained.st_nlink,
                retained.st_uid, retained.st_gid, retained.st_mode)) {
            throw new IllegalStateException("root-locked disposable input directory changed");
        }
    }

    private static void verifyInputAuthority(
            FileDescriptor parent, StructStat parentIdentity,
            FileDescriptor source, StructStat sourceIdentity,
            String anchoredPath, String conventionalPath,
            FileDescriptor sealed, String expectedSha) throws Exception {
        verifyInputDirectory(parent, parentIdentity);
        StructStat retained = Os.fstat(source);
        StructStat anchored = Os.lstat(anchoredPath);
        StructStat conventional = Os.lstat(conventionalPath);
        if (!sameFile(sourceIdentity, retained) || !sameFile(sourceIdentity, anchored)
            || !sameFile(sourceIdentity, conventional)
            || !OsConstants.S_ISREG(retained.st_mode)
            || !admittedDisposableMetadata(retained.st_size, retained.st_nlink,
                retained.st_uid, retained.st_gid, retained.st_mode)
            || Os.fcntlInt(sealed, F_GET_SEALS, 0) != REQUIRED_SEALS
            || !expectedSha.equals(shaDescriptor(source, sourceIdentity.st_size))
            || !expectedSha.equals(shaDescriptor(sealed, sourceIdentity.st_size))) {
            throw new IllegalStateException("root-locked disposable input authority changed");
        }
    }

    private static boolean sameFile(StructStat left, StructStat right) {
        return FileIdentity.from(left).same(FileIdentity.from(right));
    }

    static final class FileIdentity {
        final long device;
        final long inode;
        final int mode;
        final long links;
        final int uid;
        final int gid;
        final long size;
        final long modified;
        final long changed;

        FileIdentity(long device, long inode, int mode, long links, int uid, int gid,
                     long size, long modified, long changed) {
            this.device = device;
            this.inode = inode;
            this.mode = mode;
            this.links = links;
            this.uid = uid;
            this.gid = gid;
            this.size = size;
            this.modified = modified;
            this.changed = changed;
        }

        static FileIdentity from(StructStat value) {
            return new FileIdentity(value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
                value.st_uid, value.st_gid, value.st_size, value.st_mtime, value.st_ctime);
        }

        boolean same(FileIdentity other) {
            return other != null && device == other.device && inode == other.inode
                && mode == other.mode && links == other.links && uid == other.uid
                && gid == other.gid && size == other.size && modified == other.modified
                && changed == other.changed;
        }
    }

    private static String shaDescriptor(FileDescriptor descriptor, long expectedSize) throws Exception {
        return shaExactDescriptor(descriptor, expectedSize, MAX_CAPTURE_BYTES);
    }

    private static String copyAndHash(FileDescriptor source, FileDescriptor destination,
                                      long expectedSize) throws Exception {
        MessageDigest hash = MessageDigest.getInstance("SHA-256");
        long total = 0;
        try (FileInputStream input = new FileInputStream(Os.dup(source));
             FileOutputStream output = new FileOutputStream(Os.dup(destination))) {
            byte[] buffer = new byte[65536];
            for (int count; (count = input.read(buffer)) != -1;) {
                total += count;
                if (total > expectedSize) throw new IllegalStateException("source grew during snapshot");
                output.write(buffer, 0, count);
                hash.update(buffer, 0, count);
            }
            output.flush();
        }
        if (total != expectedSize) throw new IllegalStateException("source size changed during snapshot");
        Os.fsync(destination);
        return hex(hash.digest());
    }

    static void requireDefinedBy(Class<?> type, ClassLoader loader) {
        if (type == null || loader == null || type.getClassLoader() != loader) {
            throw new IllegalStateException("firmware class resolved outside pinned APK loader");
        }
    }

    static void requireExactConcreteClass(Object value, Class<?> expected, String label) {
        // Type-specialized encoders read public fields or invoke collection
        // methods without reflective traversal. Admit only the exact reviewed
        // bootstrap implementation so a subtype cannot run overridden methods
        // or hide additional state outside the evidence wire.
        if (value == null || expected == null || value.getClass() != expected) {
            throw new IllegalStateException(label + " has unexpected implementation");
        }
    }

    static void requireShellProcessIdentity(int uid, int gid) {
        if (uid != SHELL_UID || gid != SHELL_UID) {
            throw new SecurityException(
                "saved-ink collector requires exact Android shell UID/GID 2000");
        }
    }

    static void requireExactArrayList(Object value, String label) {
        // JNI currently returns java.util.ArrayList.  Accepting an arbitrary
        // List implementation would leave the top-level native container
        // outside the pinned return-shape contract.
        if (value == null || value.getClass() != ArrayList.class) {
            throw new IllegalStateException(label + " has unexpected implementation");
        }
    }

    /** Publish exactly one bounded collector record and surface PrintStream's
     * otherwise-swallowed write/flush failures. A strict consumer independently
     * rejects a truncated, duplicated, prefixed, or suffixed captured frame. */
    static void publishEvidenceFrame(PrintStream output, byte[] payload) {
        if (output == null || payload == null || payload.length > MAX_CAPTURE_BYTES) {
            throw new IllegalArgumentException("invalid evidence publication");
        }
        if (output.checkError()) {
            throw new IllegalStateException("collector stdout failed before publication");
        }
        output.write(EVIDENCE_PREFIX, 0, EVIDENCE_PREFIX.length);
        output.write(payload, 0, payload.length);
        output.write('\n');
        output.flush();
        if (output.checkError()) {
            throw new IllegalStateException("collector stdout publication was incomplete");
        }
    }

    interface CloseAction {
        void close() throws Exception;
    }

    /** Fault-safe ownership transfer used while constructing descriptor authorities. */
    static final class CloseStack implements AutoCloseable {
        private final ArrayList<CloseAction> actions = new ArrayList<CloseAction>();
        private boolean armed = true;

        void push(CloseAction action) {
            if (!armed || action == null) throw new IllegalStateException("closed cleanup authority");
            actions.add(action);
        }

        void disarm() {
            if (!armed) throw new IllegalStateException("closed cleanup authority");
            armed = false;
            actions.clear();
        }

        @Override public void close() throws Exception {
            if (!armed) return;
            armed = false;
            Exception first = null;
            for (int at = actions.size() - 1; at >= 0; --at) {
                try {
                    actions.get(at).close();
                } catch (Exception error) {
                    if (first == null) first = error;
                    else first.addSuppressed(error);
                }
            }
            actions.clear();
            if (first != null) throw first;
        }
    }

    /** Retained, descriptor-first authority for every executable firmware file.
     *
     * The exact system paths live on the pinned, read-only firmware partition;
     * the helper nevertheless holds each inode throughout class initialization
     * and native use, and reauthenticates both the retained bytes and the current
     * direct-child names before returning evidence. A same-root actor capable of
     * remounting/replacing verified firmware is outside this diagnostic boundary.
     */
    private static final class FirmwareAuthority implements AutoCloseable {
        private FileDescriptor apk;
        private FileDescriptor libs;
        private ParcelFileDescriptor libsView;
        private FileDescriptor recognition;
        private FileDescriptor process;
        private final StructStat apkIdentity;
        private final StructStat libsIdentity;
        private final StructStat recognitionIdentity;
        private final StructStat processIdentity;

        private FirmwareAuthority(FileDescriptor apk, FileDescriptor libs,
                                  ParcelFileDescriptor libsView,
                                  FileDescriptor recognition, FileDescriptor process,
                                  StructStat apkIdentity, StructStat libsIdentity,
                                  StructStat recognitionIdentity,
                                  StructStat processIdentity) {
            this.apk = apk;
            this.libs = libs;
            this.libsView = libsView;
            this.recognition = recognition;
            this.process = process;
            this.apkIdentity = apkIdentity;
            this.libsIdentity = libsIdentity;
            this.recognitionIdentity = recognitionIdentity;
            this.processIdentity = processIdentity;
        }

        static FirmwareAuthority open() throws Exception {
            try (CloseStack cleanup = new CloseStack()) {
                int fileFlags = OsConstants.O_RDONLY | OsConstants.O_CLOEXEC
                    | OsConstants.O_NOFOLLOW | OsConstants.O_NONBLOCK;
                final FileDescriptor apk = Os.open(APK, fileFlags, 0);
                cleanup.push(new CloseAction() {
                    @Override public void close() throws Exception { Os.close(apk); }
                });
                StructStat apkIdentity = requireRegular(apk, "firmware APK");
                final FileDescriptor libs = Os.open(LIBS, OsConstants.O_RDONLY | OsConstants.O_CLOEXEC
                    | OsConstants.O_NOFOLLOW | O_DIRECTORY, 0);
                cleanup.push(new CloseAction() {
                    @Override public void close() throws Exception { Os.close(libs); }
                });
                StructStat libsIdentity = Os.fstat(libs);
                if (!OsConstants.S_ISDIR(libsIdentity.st_mode)) {
                    throw new IllegalStateException("firmware native-library authority is not a directory");
                }
                final ParcelFileDescriptor libsView = ParcelFileDescriptor.dup(libs);
                cleanup.push(new CloseAction() {
                    @Override public void close() throws Exception { libsView.close(); }
                });
                String anchored = "/proc/self/fd/" + libsView.getFd() + "/";
                final FileDescriptor recognition = Os.open(
                    anchored + "librecgnition.so", fileFlags, 0);
                cleanup.push(new CloseAction() {
                    @Override public void close() throws Exception { Os.close(recognition); }
                });
                final FileDescriptor process = Os.open(
                    anchored + "libratta_sn_process.so", fileFlags, 0);
                cleanup.push(new CloseAction() {
                    @Override public void close() throws Exception { Os.close(process); }
                });
                StructStat recognitionIdentity = requireRegular(recognition, "recognition library");
                StructStat processIdentity = requireRegular(process, "process library");
                FirmwareAuthority result = new FirmwareAuthority(
                    apk, libs, libsView, recognition, process, apkIdentity, libsIdentity,
                    recognitionIdentity, processIdentity);
                result.verify();
                cleanup.disarm();
                return result;
            }
        }

        void verify() throws Exception {
            requireSame(apk, apkIdentity, APK, APK_SHA, "firmware APK");
            StructStat retainedDirectory = Os.fstat(libs);
            StructStat namedDirectory = Os.lstat(LIBS);
            if (!sameFile(libsIdentity, retainedDirectory)
                || !sameFile(libsIdentity, namedDirectory)
                || !OsConstants.S_ISDIR(retainedDirectory.st_mode)) {
                throw new IllegalStateException("firmware native-library directory changed");
            }
            String anchored = "/proc/self/fd/" + libsView.getFd() + "/";
            requireSame(recognition, recognitionIdentity,
                anchored + "librecgnition.so", RECOGNITION_SHA, "recognition library");
            requireSame(process, processIdentity,
                anchored + "libratta_sn_process.so", PROCESS_SHA, "process library");
        }

        private static StructStat requireRegular(FileDescriptor descriptor, String label)
                throws Exception {
            StructStat value = Os.fstat(descriptor);
            if (!OsConstants.S_ISREG(value.st_mode) || value.st_size <= 0
                || value.st_size > MAX_FIRMWARE_FILE_BYTES) {
                throw new IllegalStateException(label + " is not one bounded regular file");
            }
            return value;
        }

        private static void requireSame(FileDescriptor descriptor, StructStat identity,
                                        String name, String expectedSha, String label)
                throws Exception {
            StructStat retained = requireRegular(descriptor, label);
            StructStat named = Os.lstat(name);
            if (!sameFile(identity, retained) || !sameFile(identity, named)
                || !expectedSha.equals(shaExactDescriptor(
                    descriptor, identity.st_size, MAX_FIRMWARE_FILE_BYTES))) {
                throw new IllegalStateException(label + " authority changed");
            }
        }

        @Override public void close() throws Exception {
            Exception first = null;
            try { if (process != null) Os.close(process); } catch (Exception error) { first = error; }
            process = null;
            try { if (recognition != null) Os.close(recognition); } catch (Exception error) {
                if (first == null) first = error;
            }
            recognition = null;
            try { if (libsView != null) libsView.close(); } catch (Exception error) {
                if (first == null) first = error;
            }
            libsView = null;
            try { if (libs != null) Os.close(libs); } catch (Exception error) {
                if (first == null) first = error;
            }
            libs = null;
            try { if (apk != null) Os.close(apk); } catch (Exception error) {
                if (first == null) first = error;
            }
            apk = null;
            if (first != null) throw first;
        }
    }

    private static String shaExactDescriptor(FileDescriptor descriptor, long expectedSize,
                                             long maximumSize) throws Exception {
        if (expectedSize <= 0 || expectedSize > maximumSize) {
            throw new IllegalStateException("descriptor size outside bound");
        }
        MessageDigest hash = MessageDigest.getInstance("SHA-256");
        long total = 0;
        byte[] buffer = new byte[65536];
        while (total < expectedSize) {
            int requested = (int)Math.min(buffer.length, expectedSize - total);
            int count = Os.pread(descriptor, buffer, 0, requested, total);
            if (count <= 0) throw new IllegalStateException("descriptor shrank during hash");
            hash.update(buffer, 0, count);
            total += count;
        }
        if (Os.pread(descriptor, buffer, 0, 1, expectedSize) != 0) {
            throw new IllegalStateException("descriptor grew during hash");
        }
        return hex(hash.digest());
    }

    private static String hex(byte[] digest) {
        StringBuilder result = new StringBuilder();
        for (byte value : digest) result.append(String.format("%02x", value & 255));
        return result.toString();
    }

    /** A fresh authority is created for every root tree; failed or concurrent
     * encodes can therefore neither poison nor borrow another tree's budget. */
    static Object encodeTree(Object value, ClassLoader expectedLoader) throws Exception {
        if (expectedLoader == null) {
            throw new IllegalStateException("native object loader authority required");
        }
        EncodingBudget budget = new EncodingBudget();
        Object encoded = encode(value, new IdentityHashMap<Object, Boolean>(), 0,
            budget, expectedLoader);
        canonicalJsonBytes(encoded, MAX_TRAIL_JSON_BYTES);
        return encoded;
    }

    static Object encodeNativeRecordList(Object value, ClassLoader expectedLoader,
                                         String expectedRecordClassName) throws Exception {
        requireExactArrayList(value, "saved-page record list");
        if (expectedRecordClassName == null
                || !expectedRecordClassName.startsWith("com.example.libsupernote.")) {
            throw new IllegalStateException("exact native record class required");
        }
        for (Object record : (List<?>)value) {
            if (record == null || !expectedRecordClassName.equals(record.getClass().getName())) {
                throw new IllegalStateException("unexpected saved-page native record class");
            }
            requireDefinedBy(record.getClass(), expectedLoader);
        }
        return encodeTree(value, expectedLoader);
    }

    private static Object encode(Object value, IdentityHashMap<Object, Boolean> visiting,
                                 int depth, EncodingBudget budget,
                                 ClassLoader expectedLoader) throws Exception {
        budget.reserveValues(1);
        if (depth > MAX_DEPTH) throw new IllegalStateException("native data exceeds bound");
        if (value == null) return null;
        if (value instanceof String) {
            strictUtf8Length((String)value, MAX_STRING_BYTES);
            return value;
        }
        if (value instanceof Boolean || value instanceof Integer) return value;
        if (value instanceof Short || value instanceof Byte) return ((Number)value).intValue();
        if (value instanceof Long) {
            String exact = value.toString();
            return exact; // preserve all 64 bits
        }
        if (value instanceof Float || value instanceof Double) {
            if (depth == MAX_DEPTH) throw new IllegalStateException("native data exceeds bound");
            if (!Double.isFinite(((Number)value).doubleValue())) throw new IllegalStateException("nonfinite native value");
            // Decimal JSON drops signed zero and float precision/type
            // distinctions. Keep exact native bit patterns.
            Object exact = value instanceof Float
                ? new CanonicalObject().put("binary32",
                    String.format("%08x", Float.floatToRawIntBits((Float)value)))
                : new CanonicalObject().put("binary64",
                    String.format("%016x", Double.doubleToRawLongBits((Double)value)));
            budget.reserveValues(1); // wrapper string value
            return exact;
        }
        if (value instanceof Point) {
            requireExactConcreteClass(value, Point.class, "native point");
            if (depth == MAX_DEPTH) throw new IllegalStateException("native data exceeds bound");
            budget.reserveValues(2); // emitted integer children
            return new CanonicalArray().put(((Point)value).x).put(((Point)value).y);
        }
        if (value instanceof PointF) {
            requireExactConcreteClass(value, PointF.class, "native floating point");
            return new CanonicalArray().put(encode(((PointF)value).x, visiting, depth + 1,
                budget, expectedLoader)).put(encode(((PointF)value).y, visiting, depth + 1,
                budget, expectedLoader));
        }
        if (value instanceof Rect) {
            requireExactConcreteClass(value, Rect.class, "native rectangle");
            if (depth == MAX_DEPTH) throw new IllegalStateException("native data exceeds bound");
            budget.reserveValues(4); // emitted integer children
            Rect r = (Rect)value;
            return new CanonicalArray().put(r.left).put(r.top).put(r.right).put(r.bottom);
        }
        if (value instanceof RectF) {
            requireExactConcreteClass(value, RectF.class, "native floating rectangle");
            RectF r = (RectF)value;
            return new CanonicalArray()
                .put(encode(r.left, visiting, depth + 1, budget, expectedLoader))
                .put(encode(r.top, visiting, depth + 1, budget, expectedLoader))
                .put(encode(r.right, visiting, depth + 1, budget, expectedLoader))
                .put(encode(r.bottom, visiting, depth + 1, budget, expectedLoader));
        }
        if (visiting.put(value, Boolean.TRUE) != null) throw new IllegalStateException("cyclic native record");
        try {
            if (value instanceof List<?>) {
                requireExactConcreteClass(value, ArrayList.class, "native array");
                ArrayList<?> list = (ArrayList<?>)value;
                if (list.size() > MAX_LIST_ITEMS) throw new IllegalStateException("oversized native array");
                CanonicalArray array = new CanonicalArray();
                for (Object child : list) {
                    array.put(encode(child, visiting, depth + 1, budget, expectedLoader));
                }
                return array;
            }
            Class<?> type = value.getClass();
            if (!type.getName().startsWith("com.example.libsupernote.")) {
                throw new IllegalStateException("unhandled native field type: " + type.getName());
            }
            // Bind every reflectively inspected object, including nested opaque
            // values, to the same already-authenticated DexClassLoader before
            // discovering or reading even one field.
            requireDefinedBy(type, expectedLoader);
            if (type.getSuperclass() != Object.class) {
                throw new IllegalStateException("unhandled native field type: " + type.getName());
            }
            Field[] fields = type.getDeclaredFields();
            sortFieldsByName(fields);
            CanonicalObject object = new CanonicalObject();
            for (Field field : fields) {
                if (Modifier.isStatic(field.getModifiers())) continue;
                if ("binary32".equals(field.getName()) || "binary64".equals(field.getName())) {
                    // In v2 singleton objects bearing these names are numeric
                    // wrappers. An ordinary reflected object with either name
                    // has no unambiguous wire representation.
                    throw new IllegalStateException(
                        "native object field collides with reserved numeric wrapper");
                }
                field.setAccessible(true);
                object.put(field.getName(), encode(field.get(value), visiting, depth + 1,
                    budget, expectedLoader));
            }
            return object;
        } finally { visiting.remove(value); }
    }

    /** Sort without lambdas/method references. The Nomad's standalone
     * app_process cannot resolve the DEX invoke-custom bootstrap emitted for
     * Comparator.comparing(Field::getName). */
    static void sortFieldsByName(Field[] fields) {
        if (fields == null || fields.length > 4096) {
            throw new IllegalStateException("native field inventory exceeds bound");
        }
        for (int index = 1; index < fields.length; index++) {
            Field value = fields[index];
            String name = value.getName();
            int prior = index - 1;
            while (prior >= 0 && fields[prior].getName().compareTo(name) > 0) {
                fields[prior + 1] = fields[prior];
                prior--;
            }
            fields[prior + 1] = value;
        }
    }

    /** Restricted, frozen JSON value containers. Only the canonical writer may
     * serialize them; platform JSON-library behavior is deliberately irrelevant. */
    static final class CanonicalObject {
        final TreeMap<String, Object> values = new TreeMap<String, Object>();

        CanonicalObject put(String key, Object value) {
            if (key == null) throw new IllegalArgumentException("null canonical object key");
            strictUtf8Length(key, MAX_STRING_BYTES);
            if (values.containsKey(key)) {
                throw new IllegalStateException("duplicate canonical object key");
            }
            values.put(key, value);
            return this;
        }
    }

    static final class CanonicalArray {
        final ArrayList<Object> values = new ArrayList<Object>();

        CanonicalArray put(Object value) {
            values.add(value);
            return this;
        }
    }

    static String canonicalJson(Object value, int limit) {
        StringBuilder output = new StringBuilder();
        CanonicalWriter writer = new CanonicalWriter(output, limit);
        writer.write(value, new IdentityHashMap<Object, Boolean>());
        String result = output.toString();
        if (strictUtf8Length(result, limit) != writer.bytes()) {
            throw new IllegalStateException("canonical JSON byte accounting mismatch");
        }
        return result;
    }

    static int canonicalJsonBytes(Object value, int limit) {
        CanonicalWriter writer = new CanonicalWriter(null, limit);
        writer.write(value, new IdentityHashMap<Object, Boolean>());
        return writer.bytes();
    }

    /** Canonical JSON v2: compact UTF-8, keys sorted by Java UTF-16 order,
     * arrays preserved, slash/C1/U+2028/U+2029 raw, and only JSON-mandated
     * controls plus quote/backslash escaped. */
    private static final class CanonicalWriter {
        private static final char[] HEX = "0123456789abcdef".toCharArray();
        private final StringBuilder output;
        private final int limit;
        private int bytes;

        CanonicalWriter(StringBuilder output, int limit) {
            if (limit < 0) throw new IllegalArgumentException("negative canonical JSON limit");
            this.output = output;
            this.limit = limit;
        }

        int bytes() { return bytes; }

        void write(Object value, IdentityHashMap<Object, Boolean> visiting) {
            if (value == null) { ascii("null"); return; }
            if (value instanceof String) { string((String)value); return; }
            if (value instanceof Boolean || value instanceof Integer) {
                ascii(String.valueOf(value));
                return;
            }
            boolean container = value instanceof CanonicalObject || value instanceof CanonicalArray;
            if (!container) {
                throw new IllegalStateException("noncanonical JSON value: " + value.getClass().getName());
            }
            if (visiting.put(value, Boolean.TRUE) != null) {
                throw new IllegalStateException("cyclic canonical JSON value");
            }
            try {
                if (value instanceof CanonicalArray) {
                    ascii("[");
                    boolean first = true;
                    for (Object child : ((CanonicalArray)value).values) {
                        if (!first) ascii(",");
                        first = false;
                        write(child, visiting);
                    }
                    ascii("]");
                    return;
                }
                ascii("{");
                boolean first = true;
                for (Map.Entry<String, Object> entry :
                        ((CanonicalObject)value).values.entrySet()) {
                    if (!first) ascii(",");
                    first = false;
                    string(entry.getKey());
                    ascii(":");
                    write(entry.getValue(), visiting);
                }
                ascii("}");
            } finally {
                visiting.remove(value);
            }
        }

        private void string(String value) {
            ascii("\"");
            for (int at = 0; at < value.length(); ++at) {
                char current = value.charAt(at);
                switch (current) {
                    case '\"': ascii("\\\""); break;
                    case '\\': ascii("\\\\"); break;
                    case '\b': ascii("\\b"); break;
                    case '\t': ascii("\\t"); break;
                    case '\n': ascii("\\n"); break;
                    case '\f': ascii("\\f"); break;
                    case '\r': ascii("\\r"); break;
                    default:
                        if (current <= 0x1f) {
                            char[] escaped = new char[] {'\\', 'u', '0', '0',
                                HEX[(current >>> 4) & 15], HEX[current & 15]};
                            text(escaped, 6);
                        } else if (Character.isHighSurrogate(current)) {
                            if (++at >= value.length()
                                    || !Character.isLowSurrogate(value.charAt(at))) {
                                throw new IllegalStateException("unpaired UTF-16 surrogate");
                            }
                            reserve(4);
                            if (output != null) output.append(current).append(value.charAt(at));
                        } else if (Character.isLowSurrogate(current)) {
                            throw new IllegalStateException("unpaired UTF-16 surrogate");
                        } else {
                            int count = current <= 0x7f ? 1 : current <= 0x7ff ? 2 : 3;
                            reserve(count);
                            if (output != null) output.append(current);
                        }
                        break;
                }
            }
            ascii("\"");
        }

        private void ascii(String value) {
            for (int at = 0; at < value.length(); ++at) {
                if (value.charAt(at) > 0x7f) {
                    throw new IllegalStateException("internal non-ASCII canonical token");
                }
            }
            reserve(value.length());
            if (output != null) output.append(value);
        }

        private void text(char[] value, int byteCount) {
            reserve(byteCount);
            if (output != null) output.append(value);
        }

        private void reserve(int count) {
            if (count < 0 || bytes > limit - count) {
                throw new IllegalStateException("canonical JSON exceeds byte bound");
            }
            bytes += count;
        }
    }

    static int strictUtf8Length(String value, int limit) {
        int bytes = 0;
        for (int at = 0; at < value.length(); ++at) {
            char current = value.charAt(at);
            int add;
            if (current <= 0x7f) add = 1;
            else if (current <= 0x7ff) add = 2;
            else if (Character.isHighSurrogate(current)) {
                if (++at >= value.length() || !Character.isLowSurrogate(value.charAt(at))) {
                    throw new IllegalStateException("unpaired UTF-16 surrogate");
                }
                add = 4;
            } else if (Character.isLowSurrogate(current)) {
                throw new IllegalStateException("unpaired UTF-16 surrogate");
            } else add = 3;
            if (bytes > limit - add) throw new IllegalStateException("oversized UTF-8 value");
            bytes += add;
        }
        return bytes;
    }

    static byte[] strictUtf8Bytes(String value, int limit) {
        strictUtf8Length(value, limit);
        byte[] encoded = value.getBytes(StandardCharsets.UTF_8);
        if (encoded.length > limit) throw new IllegalStateException("encoded capture exceeds bound");
        return encoded;
    }

    static final class EncodingBudget {
        private int values;

        void reserveValues(int count) {
            if (count < 0 || values > MAX_VALUES - count) {
                throw new IllegalStateException("native data exceeds bound");
            }
            values += count;
        }
    }
}
