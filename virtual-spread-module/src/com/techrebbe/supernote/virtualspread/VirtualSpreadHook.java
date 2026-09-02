package com.techrebbe.supernote.virtualspread;

import android.app.Activity;
import android.content.res.Configuration;
import android.graphics.RectF;
import android.net.Uri;
import android.os.Binder;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.SystemClock;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructStat;
import android.util.Log;

import java.io.File;
import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.lang.ref.WeakReference;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.channels.FileChannel;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.WeakHashMap;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantLock;

import org.json.JSONArray;
import org.json.JSONObject;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

/**
 * Deliberately narrow LSPosed module for generated virtual-spread PDFs.
 *
 * It changes only page-turn direction and Supernote's own split viewport.
 * Supernote remains the sole renderer and annotation owner.
 */
public final class VirtualSpreadHook implements IXposedHookLoadPackage {
    private static final String TARGET_PACKAGE = "com.supernote.document";
    private static final String TARGET_ACTIVITY =
        "com.supernote.document.document.DocumentActivity";
    private static final String TARGET_VIEW_MODEL =
        "com.supernote.document.document.DocumentViewModel";
    private static final String TARGET_PAGE_INFO =
        "com.supernote.document.document.PageInfo";
    private static final String TARGET_LOAD_PAGE_TASK =
        "com.supernote.document.document.DocumentViewModel$6";
    private static final String TARGET_PAGE_BAR =
        "com.ratta.supernote.supernotetoolbarlib.PageBarView";
    private static final String TARGET_BACK_LINK =
        "com.supernote.document.utils.BackLinkUtils";
    private static final String TARGET_BACK_LISTENER =
        "com.supernote.document.document.DocumentActivity$7";
    private static final String TARGET_SUPER_NOTE =
        "com.example.libsupernote.SuperNoteNote";
    private static final String TARGET_FINGERPRINT =
        "Supernote/Supernote/Supernote:11/RQ2A.210505.003/eng.supern.20260616.100032:user/release-keys";
    private static final String TARGET_DOCUMENT_APK =
        "/system_ext/app/SupernoteDocument/SupernoteDocument.apk";
    private static final long TARGET_DOCUMENT_APK_LENGTH = 138486560L;
    private static final String SCHEMA =
        "techrebbe.supernote.virtual-spread/v3";
    private static final String NAVIGATION_SCHEMA =
        "techrebbe.supernote.virtual-spread/v4";
    private static final String GENERATOR_VERSION =
        "techrebbe.supernote.virtual-spread-generator/v1";
    private static final String NAVIGATION_GENERATOR_VERSION =
        "techrebbe.supernote.virtual-spread-generator/v2";
    private static final String VIEW_ID_PREFIX = "inkbridge-view-v1-";
    private static final String TAG = "SN_VIRTUAL_SPREAD";
    private static final String VERSION = "0.0.27";
    private static final long MAX_MANIFEST_BYTES = 8L * 1024L * 1024L;
    private static final int MAX_CACHED_MANIFESTS = 4;
    private static final long PENDING_LINK_MAX_AGE_MS = 60000L;
    private static final long MANIFEST_FRESHNESS_INTERVAL_MS = 2000L;
    private static final long MAX_MANIFEST_FRESHNESS_AGE_MS = 15000L;
    private static final long MANIFEST_RETRY_BACKOFF_MS = 250L;

    private static volatile WeakReference<Activity> activeActivity =
        new WeakReference<>(null);
    private static final ThreadLocal<Activity> CREATING_ACTIVITY =
        new ThreadLocal<>();
    private static final Map<Object, ReaderState> STATES =
        new WeakHashMap<>();
    private static final VirtualSpreadNavigation.BoundedCache<
        String,
        CachedManifest
    > MANIFESTS = new VirtualSpreadNavigation.BoundedCache<>(
        MAX_CACHED_MANIFESTS
    );
    private static final Map<String, VerificationOwner> VERIFYING =
        new ConcurrentHashMap<>();
    private static final Map<String, VerificationOwner>
        LATEST_VERIFICATION_OWNER = new ConcurrentHashMap<>();
    private static final Map<String, CachedManifest> FRESHNESS_CHECKING =
        new ConcurrentHashMap<>();
    private static final Map<String, Long> VERIFICATION_RETRY_AFTER =
        new ConcurrentHashMap<>();
    private static final AtomicLong VERIFICATION_GENERATION = new AtomicLong();
    private static volatile boolean hooksReady;
    private static final Object MANIFEST_VERIFIER_LOCK = new Object();
    private static volatile String observedDocumentKey;
    private static final ThreadPoolExecutor MANIFEST_VERIFIER =
        new ThreadPoolExecutor(
            1,
            1,
            0L,
            TimeUnit.MILLISECONDS,
            new ArrayBlockingQueue<Runnable>(1)
        );
    private static final ThreadLocal<int[]> PAGE_BAR_VALUES =
        new ThreadLocal<>();
    private static final ThreadLocal<Boolean> REPLAYING_LINK =
        new ThreadLocal<>();
    private static final ThreadLocal<Boolean> PURE_LINK_DISPATCH =
        new ThreadLocal<>();
    private static final ThreadLocal<SaveObservation> SAVE_OBSERVATION =
        new ThreadLocal<>();
    private static final ThreadLocal<NativeViewportCompletion>
        NATIVE_VIEWPORT_COMPLETION = new ThreadLocal<>();
    private static final ThreadLocal<NativeViewportLoadBinding>
        NATIVE_VIEWPORT_LOAD_INVOCATION = new ThreadLocal<>();
    private static final Map<Object, NativeViewportLoadBinding>
        NATIVE_VIEWPORT_TASK_BINDINGS = new WeakHashMap<>();
    private static final Map<Object, NativeViewportLoadBinding>
        NATIVE_VIEWPORT_PAGE_INFO_BINDINGS = new WeakHashMap<>();
    private static final Object NATIVE_VIEWPORT_LOAD_BINDING_LOCK =
        new Object();
    private static final ThreadLocal<HistoryActionContext> HISTORY_ACTION =
        new ThreadLocal<>();
    private static final ReentrantLock HISTORY_SERIALIZATION =
        new ReentrantLock(true);
    private static final ThreadLocal<Integer> HISTORY_ACTION_LOCK_DEPTH =
        new ThreadLocal<>();
    private static volatile Class<?> backLinkClass;
    private static final Binder NATIVE_VIEWPORT_SESSION = new Binder();
    private static volatile boolean nativeViewportMayBePublished;

    private static final class Manifest {
        final String key;
        final String revision;
        final String schema;
        final String sourceAuthority;
        final String documentId;
        final String outputAuthority;
        final String layoutAuthority;
        final String linkAuthority;
        final String mappingAuthority;
        final String navigationAuthority;
        final String viewId;
        final String cacheBasename;
        final String generatorVersion;
        final int pageCount;
        final VirtualSpreadNavigation.Spread[] spreads;
        final double pageWidth;
        final double pageHeight;
        final VirtualSpreadNavigation.LinkTarget[] links;
        final VirtualSpreadNavigation.UriTarget[] uriLinks;
        final OutlineTarget[] outlines;

        Manifest(
            String key,
            String revision,
            String schema,
            String sourceAuthority,
            String documentId,
            String outputAuthority,
            String layoutAuthority,
            String linkAuthority,
            String mappingAuthority,
            String navigationAuthority,
            String viewId,
            String cacheBasename,
            String generatorVersion,
            int pageCount,
            VirtualSpreadNavigation.Spread[] spreads,
            double pageWidth,
            double pageHeight,
            VirtualSpreadNavigation.LinkTarget[] links,
            VirtualSpreadNavigation.UriTarget[] uriLinks,
            OutlineTarget[] outlines
        ) {
            this.key = key;
            this.revision = revision;
            this.schema = schema;
            this.sourceAuthority = sourceAuthority;
            this.documentId = documentId;
            this.outputAuthority = outputAuthority;
            this.layoutAuthority = layoutAuthority;
            this.linkAuthority = linkAuthority;
            this.mappingAuthority = mappingAuthority;
            this.navigationAuthority = navigationAuthority;
            this.viewId = viewId;
            this.cacheBasename = cacheBasename;
            this.generatorVersion = generatorVersion;
            this.pageCount = pageCount;
            this.spreads = spreads;
            this.pageWidth = pageWidth;
            this.pageHeight = pageHeight;
            this.links = links;
            this.uriLinks = uriLinks;
            this.outlines = outlines;
        }
    }

    private static final class OutlineTarget {
        final String title;
        final int virtualPage;
        final VirtualSpreadNavigation.Half half;
        final boolean resetLandscapeFit;

        OutlineTarget(
            String title,
            int virtualPage,
            VirtualSpreadNavigation.Half half,
            boolean resetLandscapeFit
        ) {
            this.title = title;
            this.virtualPage = virtualPage;
            this.half = half;
            this.resetLandscapeFit = resetLandscapeFit;
        }
    }

    private static final class NavigationData {
        final String authority;
        final boolean removeAdjacentPageLinks;
        final int removedLinkCount;
        final int retainedLinkCount;
        final OutlineTarget[] outlines;

        NavigationData(
            String authority,
            boolean removeAdjacentPageLinks,
            int removedLinkCount,
            int retainedLinkCount,
            OutlineTarget[] outlines
        ) {
            this.authority = authority;
            this.removeAdjacentPageLinks = removeAdjacentPageLinks;
            this.removedLinkCount = removedLinkCount;
            this.retainedLinkCount = retainedLinkCount;
            this.outlines = outlines;
        }
    }

    private static final class MappingRecord {
        final int sourcePageIndex;
        final int virtualPageIndex;
        final String side;
        final double[] destination;
        final String canonical;

        MappingRecord(
            int sourcePageIndex,
            int virtualPageIndex,
            String side,
            double[] destination,
            String canonical
        ) {
            this.sourcePageIndex = sourcePageIndex;
            this.virtualPageIndex = virtualPageIndex;
            this.side = side;
            this.destination = destination.clone();
            this.canonical = canonical;
        }
    }

    private static final class SaveObservation {
        final Object expectedNote;
        final int expectedPage;
        final String expectedMarkPath;
        boolean callbackObserved;
        boolean callbackSucceeded;
        boolean sameNote;
        int observedPage = -1;
        boolean sameMarkPath;

        SaveObservation(
            Object expectedNote,
            int expectedPage,
            String expectedMarkPath
        ) {
            this.expectedNote = expectedNote;
            this.expectedPage = expectedPage;
            this.expectedMarkPath = expectedMarkPath;
        }

        boolean accepted() {
            return VirtualSpreadNavigation.saveAcknowledgementMatches(
                true,
                callbackObserved,
                callbackSucceeded,
                sameNote,
                expectedPage,
                observedPage,
                sameMarkPath
            );
        }
    }

    private static final class HistoryActionContext {
        final Object expectedBackInfo;
        final Object viewModel;
        final Manifest manifest;
        boolean pageLoadAuthorized;

        HistoryActionContext(
            Object expectedBackInfo,
            Object viewModel,
            Manifest manifest
        ) {
            this.expectedBackInfo = expectedBackInfo;
            this.viewModel = viewModel;
            this.manifest = manifest;
        }
    }

    private static final class ManifestLookup {
        final Manifest manifest;
        final boolean verificationPending;
        final boolean nativeSnapshotBlocked;
        final String snapshotId;
        final long verificationGeneration;
        final String blockedReason;

        ManifestLookup(
            Manifest manifest,
            boolean verificationPending,
            boolean nativeSnapshotBlocked,
            String snapshotId
        ) {
            this(
                manifest,
                verificationPending,
                nativeSnapshotBlocked,
                snapshotId,
                0L,
                null
            );
        }

        ManifestLookup(
            Manifest manifest,
            boolean verificationPending,
            boolean nativeSnapshotBlocked,
            String snapshotId,
            long verificationGeneration
        ) {
            this(
                manifest,
                verificationPending,
                nativeSnapshotBlocked,
                snapshotId,
                verificationGeneration,
                null
            );
        }

        ManifestLookup(
            Manifest manifest,
            boolean verificationPending,
            boolean nativeSnapshotBlocked,
            String snapshotId,
            long verificationGeneration,
            String blockedReason
        ) {
            this.manifest = manifest;
            this.verificationPending = verificationPending;
            this.nativeSnapshotBlocked = nativeSnapshotBlocked;
            this.snapshotId = snapshotId;
            this.verificationGeneration = verificationGeneration;
            this.blockedReason = blockedReason;
        }

        boolean navigationBlocked() {
            return verificationPending || nativeSnapshotBlocked;
        }

        String navigationBlockReason() {
            if (blockedReason != null) {
                return blockedReason;
            }
            return nativeSnapshotBlocked
                ? "native_snapshot_mismatch"
                : "manifest_verification_pending";
        }
    }

    /**
     * The exact firmware opens a native action menu when a PDF link overlaps
     * a digest or annotation. Retain the link identity without claiming that
     * navigation occurred; the later jumpLink call is the user's actual Link
     * choice and is authenticated against this short-lived context.
     */
    private static final class MixedLinkCandidate {
        final String documentPath;
        final Object nativeDocument;
        final String nativeSourceAuthority;
        final String nativeLayoutAuthority;
        final String nativeLinkAuthority;
        final String nativeMappingAuthority;
        final String nativeViewId;
        final String nativeGeneratorVersion;
        final Object link;
        final int sourcePage;
        final int targetPage;
        final String uri;
        final Boolean external;
        final long verificationGeneration;
        final long pageLoadGeneration;
        final long createdAt;

        MixedLinkCandidate(
            String documentPath,
            Object nativeDocument,
            String nativeSourceAuthority,
            String nativeLayoutAuthority,
            String nativeLinkAuthority,
            String nativeMappingAuthority,
            String nativeViewId,
            String nativeGeneratorVersion,
            Object link,
            int sourcePage,
            int targetPage,
            String uri,
            Boolean external,
            long verificationGeneration,
            long pageLoadGeneration,
            long createdAt
        ) {
            this.documentPath = documentPath;
            this.nativeDocument = nativeDocument;
            this.nativeSourceAuthority = nativeSourceAuthority;
            this.nativeLayoutAuthority = nativeLayoutAuthority;
            this.nativeLinkAuthority = nativeLinkAuthority;
            this.nativeMappingAuthority = nativeMappingAuthority;
            this.nativeViewId = nativeViewId;
            this.nativeGeneratorVersion = nativeGeneratorVersion;
            this.link = link;
            this.sourcePage = sourcePage;
            this.targetPage = targetPage;
            this.uri = uri;
            this.external = external;
            this.verificationGeneration = verificationGeneration;
            this.pageLoadGeneration = pageLoadGeneration;
            this.createdAt = createdAt;
        }

        MixedLinkCandidate withPageLoadGeneration(long generation) {
            return new MixedLinkCandidate(
                documentPath,
                nativeDocument,
                nativeSourceAuthority,
                nativeLayoutAuthority,
                nativeLinkAuthority,
                nativeMappingAuthority,
                nativeViewId,
                nativeGeneratorVersion,
                link,
                sourcePage,
                targetPage,
                uri,
                external,
                verificationGeneration,
                generation,
                createdAt
            );
        }
    }

    private static final class FileIdentity {
        final long device;
        final long inode;
        final long size;
        final long modifiedSeconds;
        final long changedSeconds;
        final long changedNanos;

        FileIdentity(
            long device,
            long inode,
            long size,
            long modifiedSeconds,
            long changedSeconds,
            long changedNanos
        ) {
            this.device = device;
            this.inode = inode;
            this.size = size;
            this.modifiedSeconds = modifiedSeconds;
            this.changedSeconds = changedSeconds;
            this.changedNanos = changedNanos;
        }

        static FileIdentity captureRegularPath(File file) throws Exception {
            StructStat stat = Os.lstat(file.getPath());
            if (!OsConstants.S_ISREG(stat.st_mode)) {
                throw new IllegalArgumentException(
                    "manifest input is not a regular file"
                );
            }
            return fromStat(stat);
        }

        static FileIdentity capture(FileDescriptor descriptor) throws Exception {
            return fromStat(Os.fstat(descriptor));
        }

        private static FileIdentity fromStat(StructStat stat) {
            long changedNanos = stat.st_ctim == null
                ? 0L : stat.st_ctim.tv_nsec;
            return new FileIdentity(
                stat.st_dev,
                stat.st_ino,
                stat.st_size,
                stat.st_mtime,
                stat.st_ctime,
                changedNanos
            );
        }

        boolean matches(FileIdentity other) {
            return other != null
                && device == other.device
                && inode == other.inode
                && size == other.size
                && modifiedSeconds == other.modifiedSeconds
                && changedSeconds == other.changedSeconds
                && changedNanos == other.changedNanos;
        }

        String token() {
            return device + ":" + inode
                + ":" + size
                + ":" + modifiedSeconds
                + ":" + changedSeconds
                + ":" + changedNanos;
        }
    }

    private static final class CachedManifest {
        final FileIdentity pdfIdentity;
        final FileIdentity sidecarIdentity;
        final String sidecarDigest;
        final Manifest manifest;
        final Object nativeDocument;
        final String snapshotId;
        final long verificationGeneration;
        final long verifiedAtElapsed;

        CachedManifest(
            FileIdentity pdfIdentity,
            FileIdentity sidecarIdentity,
            String sidecarDigest,
            Manifest manifest,
            Object nativeDocument,
            String snapshotId,
            long verificationGeneration,
            long verifiedAtElapsed
        ) {
            this.pdfIdentity = pdfIdentity;
            this.sidecarIdentity = sidecarIdentity;
            this.sidecarDigest = sidecarDigest;
            this.manifest = manifest;
            this.nativeDocument = nativeDocument;
            this.snapshotId = snapshotId;
            this.verificationGeneration = verificationGeneration;
            this.verifiedAtElapsed = verifiedAtElapsed;
        }

        String snapshotId() {
            return snapshotId;
        }

        CachedManifest refreshed(long now) {
            return new CachedManifest(
                pdfIdentity,
                sidecarIdentity,
                sidecarDigest,
                manifest,
                nativeDocument,
                snapshotId,
                verificationGeneration,
                now
            );
        }
    }

    private static final class VerificationOwner {
        final String snapshotId;
        final long generation;
        final Object nativeDocument;

        VerificationOwner(
            String snapshotId,
            long generation,
            Object nativeDocument
        ) {
            this.snapshotId = snapshotId;
            this.generation = generation;
            this.nativeDocument = nativeDocument;
        }
    }

    private static final class ManifestVerificationTask implements Runnable {
        final File pdf;
        final File sidecar;
        final String key;
        final VerificationOwner owner;

        ManifestVerificationTask(
            File pdf,
            File sidecar,
            String key,
            VerificationOwner owner
        ) {
            this.pdf = pdf;
            this.sidecar = sidecar;
            this.key = key;
            this.owner = owner;
        }

        @Override
        public void run() {
            verifyManifestSnapshot(
                pdf,
                sidecar,
                key,
                owner
            );
        }

        void cancelBeforeRun() {
            VERIFYING.remove(key, owner);
            log("manifest_verification_superseded path=" + key);
        }
    }

    private static final class ManifestFreshnessTask implements Runnable {
        final File pdf;
        final File sidecar;
        final String key;
        final CachedManifest expected;
        final ManifestInvalidationToken invalidationToken;

        ManifestFreshnessTask(
            File pdf,
            File sidecar,
            String key,
            CachedManifest expected,
            ManifestInvalidationToken invalidationToken
        ) {
            this.pdf = pdf;
            this.sidecar = sidecar;
            this.key = key;
            this.expected = expected;
            this.invalidationToken = invalidationToken;
        }

        @Override
        public void run() {
            verifyManifestFreshness(
                pdf,
                sidecar,
                key,
                expected,
                invalidationToken
            );
        }

        void cancelBeforeRun() {
            FRESHNESS_CHECKING.remove(key, expected);
            log("manifest_freshness_superseded path=" + key);
        }
    }

    private static final class ManifestVerificationSuperseded
        extends Exception {
        private static final long serialVersionUID = 1L;
    }

    private static final class ManifestInvalidationToken {
        final Activity owner;
        final Object viewModel;
        final long intentGeneration;

        ManifestInvalidationToken(
            Activity owner,
            Object viewModel,
            long intentGeneration
        ) {
            this.owner = owner;
            this.viewModel = viewModel;
            this.intentGeneration = intentGeneration;
        }
    }

    private static final class ReaderState {
        Object nativeSnapshotDocument;
        String nativeSnapshotRevision;
        boolean nativeSnapshotAccepted;
        String documentKey;
        String manifestKey;
        String manifestRevision;
        long manifestVerificationGeneration;
        long intentGeneration;
        int lastPage = -1;
        int pendingPage = -1;
        VirtualSpreadNavigation.Half half =
            VirtualSpreadNavigation.Half.RIGHT;
        VirtualSpreadNavigation.Half pendingHalf;
        int pendingLinkSourcePage = -1;
        VirtualSpreadNavigation.Half pendingLinkSourceHalf;
        int pendingLinkPage = -1;
        VirtualSpreadNavigation.Half pendingLinkHalf;
        boolean pendingLinkResetLandscapeFit;
        long pendingLinkAt;
        Object[] queuedLinkArguments;
        String queuedLinkDocumentPath;
        String queuedLinkSnapshotId;
        long queuedLinkVerificationGeneration;
        long queuedLinkPageLoadGeneration = -1L;
        VirtualSpreadNavigation.LinkRouting queuedLinkRouting;
        Object queuedLinkNativeDocument;
        String queuedLinkNativeSourceAuthority;
        String queuedLinkNativeLayoutAuthority;
        String queuedLinkNativeLinkAuthority;
        String queuedLinkNativeMappingAuthority;
        String queuedLinkNativeViewId;
        String queuedLinkNativeGeneratorVersion;
        Object queuedLinkObject;
        int queuedLinkTargetPage = -1;
        boolean queuedLinkDirectJump;
        int queuedLinkSourcePage = -1;
        long queuedLinkAt;
        MixedLinkCandidate mixedLinkCandidate;
        int preservedLinkViewportPage = -1;
        VirtualSpreadNavigation.Half preservedLinkViewportHalf;
        int pendingHistoryPage = -1;
        VirtualSpreadNavigation.Half pendingHistoryHalf;
        long pendingHistoryAt;
        long pageLoadGeneration;
        long nativeViewportRequestSerial;
        final VirtualSpreadNavigation.BoundedCache<
            Integer,
            NativeViewportLoadBinding
        > nativeViewportLoadBindings =
            new VirtualSpreadNavigation.BoundedCache<>(8);
        boolean nativeViewportLoadPending;
        final VirtualSpreadNavigation.LinkHistory linkHistory =
            new VirtualSpreadNavigation.LinkHistory();
    }

    @Override
    public void handleLoadPackage(
        XC_LoadPackage.LoadPackageParam loadPackageParam
    ) throws Throwable {
        if (!TARGET_PACKAGE.equals(loadPackageParam.packageName)
            || !TARGET_PACKAGE.equals(loadPackageParam.processName)) {
            return;
        }
        if (!compatibleFirmware()) {
            log("disabled reason=firmware_mismatch fingerprint="
                + Build.FINGERPRINT);
            return;
        }

        hooksReady = false;
        try {
            hookActivity(loadPackageParam.classLoader);
            hookViewModel(loadPackageParam.classLoader);
            hookPageBar(loadPackageParam.classLoader);
            hookLinkTarget(loadPackageParam.classLoader);
            hookLinkHistory(loadPackageParam.classLoader);
            hookLinkHistoryActions(loadPackageParam.classLoader);
            hookOutlineTarget(loadPackageParam.classLoader);
            hookNativeSaveAcknowledgement(loadPackageParam.classLoader);
        } catch (Throwable throwable) {
            hooksReady = false;
            logFailure("disabled reason=required_hook_failed", throwable);
            return;
        }
        hooksReady = true;
        log("loaded version=" + VERSION);
    }

    private static void hookActivity(ClassLoader classLoader) {
        XposedHelpers.findAndHookMethod(
            TARGET_ACTIVITY,
            classLoader,
            "onCreate",
            Bundle.class,
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    Activity activity = (Activity) param.thisObject;
                    Activity previous = activeActivity.get();
                    if (NativeViewportLifecycleAuthority
                            .beginsReaderOwnership(activity, previous)) {
                        // DocumentActivity can synchronously construct its
                        // first page worker inside onCreate. Claim ownership
                        // and invalidate the previous descriptor before any of
                        // that replacement activity's page work can run.
                        clearNativeViewport(
                            activity,
                            "activity_creation_started"
                        );
                        activeActivity = new WeakReference<>(activity);
                        observeDocumentKey(null);
                        log("activity_ownership_started replacement="
                            + (previous != null));
                    }
                    CREATING_ACTIVITY.set(activity);
                }

                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    Activity activity = (Activity) param.thisObject;
                    try {
                        // Ownership already began in the before-hook. Never let
                        // a late/nested onCreate completion reclaim it from a
                        // newer activity.
                        log("activity_created active_owner="
                            + (activeActivity.get() == activity));
                    } finally {
                        if (CREATING_ACTIVITY.get() == activity) {
                            CREATING_ACTIVITY.remove();
                        }
                    }
                }
            }
        );

        XposedHelpers.findAndHookMethod(
            TARGET_ACTIVITY,
            classLoader,
            "screenChange",
            boolean.class,
            new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    Activity activity = (Activity) param.thisObject;
                    if (!NativeViewportLifecycleAuthority
                            .activityCallbackOwnsReader(
                                activity,
                                activeActivity.get()
                            )) {
                        log("activity_callback_rejected "
                            + "reason=inactive_screen_change");
                        return;
                    }
                    Object viewModel = objectField(
                        activity,
                        "documentViewModel"
                    );
                    if (isPortrait(activity)) {
                        if (hasPreservedLinkViewport(viewModel)) {
                            log("portrait_focus_skipped "
                                + "reason=preserved_link_viewport "
                                + "stage=screen_change");
                        } else {
                            schedulePortraitFocus(
                                viewModel,
                                "screen_change"
                            );
                        }
                    }
                }
            }
        );

        XposedHelpers.findAndHookMethod(
            TARGET_ACTIVITY,
            classLoader,
            "onConfigurationChanged",
            Configuration.class,
            new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    Activity activity = (Activity) param.thisObject;
                    if (!NativeViewportLifecycleAuthority
                            .activityCallbackOwnsReader(
                                activity,
                                activeActivity.get()
                            )) {
                        log("activity_callback_rejected "
                            + "reason=inactive_configuration_change");
                        return;
                    }
                    Object viewModel = objectField(
                        activity,
                        "documentViewModel"
                    );
                    scheduleConfigurationRefresh(
                        activity,
                        viewModel,
                        "configuration_changed"
                    );
                }
            }
        );

        XposedHelpers.findAndHookMethod(
            TARGET_ACTIVITY,
            classLoader,
            "onDestroy",
            new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    Activity activity = (Activity) param.thisObject;
                    Activity current = activeActivity.get();
                    Object viewModel = objectField(
                        activity,
                        "documentViewModel"
                    );
                    Object activeViewModel = current == null ? null
                        : objectField(current, "documentViewModel");
                    boolean activeOwner = NativeViewportLifecycleAuthority
                        .mayClearForDestroyedActivity(activity, current);
                    if (activeOwner) {
                        clearNativeViewport(activity, "activity_destroyed");
                        activeActivity = new WeakReference<>(null);
                        observeDocumentKey(null);
                    }
                    boolean stateReleased = NativeViewportLifecycleAuthority
                        .mayReleaseDestroyedViewModel(
                            viewModel,
                            activeViewModel,
                            activeOwner
                        );
                    if (stateReleased) {
                        releaseNativeViewportReaderState(viewModel);
                    }
                    log("activity_destroyed active_owner=" + activeOwner
                        + " state_released=" + stateReleased);
                }
            }
        );
    }

    private static void hookLinkTarget(ClassLoader classLoader) {
        XposedHelpers.findAndHookMethod(
            TARGET_ACTIVITY,
            classLoader,
            "showLinkJumpView",
            android.graphics.Point.class,
            "com.supernote.document.document.bean.SuperNoteLink",
            int.class,
            "com.supernote.document.digest.Knowledge",
            "com.supernote.document.document.bean.AnnotationContentBean",
            "com.artifex.mupdf.fitz.Point",
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    if (!Boolean.TRUE.equals(REPLAYING_LINK.get())) {
                        if (immediateLinkArguments(param.args)) {
                            PURE_LINK_DISPATCH.set(Boolean.TRUE);
                        }
                        handleLinkTarget(param);
                    }
                }

                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    PURE_LINK_DISPATCH.remove();
                }
            }
        );
        XposedHelpers.findAndHookMethod(
            TARGET_ACTIVITY,
            classLoader,
            "jumpLink",
            int.class,
            String.class,
            boolean.class,
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    if (!Boolean.TRUE.equals(REPLAYING_LINK.get())
                        && !Boolean.TRUE.equals(PURE_LINK_DISPATCH.get())) {
                        handleMixedLinkJump(param);
                    }
                }
            }
        );
    }

    private static void hookLinkHistory(ClassLoader classLoader) {
        backLinkClass = XposedHelpers.findClass(
            TARGET_BACK_LINK,
            classLoader
        );
        hookBackLinkSerialization();
        XposedHelpers.findAndHookMethod(
            TARGET_BACK_LINK,
            classLoader,
            "getFirstBack",
            new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    captureHistoryReturn(param, false);
                }
            }
        );
        XposedHelpers.findAndHookMethod(
            TARGET_BACK_LINK,
            classLoader,
            "getLastBack",
            new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    captureHistoryReturn(param, true);
                }
            }
        );
    }

    private static void hookBackLinkSerialization() {
        int hooked = 0;
        for (Method method : backLinkClass.getDeclaredMethods()) {
            int modifiers = method.getModifiers();
            if (!Modifier.isStatic(modifiers)
                || Modifier.isAbstract(modifiers)
                || Modifier.isNative(modifiers)) {
                continue;
            }
            XposedBridge.hookMethod(method, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    HISTORY_SERIALIZATION.lock();
                }

                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    HISTORY_SERIALIZATION.unlock();
                }
            });
            hooked++;
        }
        if (hooked == 0) {
            throw new IllegalStateException(
                "BackLinkUtils serialization hooks are unavailable"
            );
        }
        log("link_history_serialization_ready methods=" + hooked);
    }

    private static void hookLinkHistoryActions(ClassLoader classLoader) {
        XposedHelpers.findAndHookMethod(
            TARGET_BACK_LISTENER,
            classLoader,
            "onBackClick",
            historyActionGuard(false)
        );
        XposedHelpers.findAndHookMethod(
            TARGET_BACK_LISTENER,
            classLoader,
            "onOriginalBackClick",
            historyActionGuard(true)
        );

        // This is a defensive second boundary for a native history list that
        // changes between our non-mutating preflight and the firmware getter.
        // The ordinary loadPage path is untouched when no history action is
        // active, and external-document Back never calls this overload.
        XposedHelpers.findAndHookMethod(
            TARGET_VIEW_MODEL,
            classLoader,
            "loadPage",
            int.class,
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    HistoryActionContext context = HISTORY_ACTION.get();
                    if (context != null && !context.pageLoadAuthorized) {
                        param.setResult(null);
                        log("link_history_page_load_blocked "
                            + "reason=preflight_changed");
                    }
                }
            }
        );
    }

    private static XC_MethodHook historyActionGuard(
        final boolean original
    ) {
        return new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) {
                lockHistoryAction();
                try {
                    HISTORY_ACTION.remove();
                    Activity activity = (Activity) objectField(
                        param.thisObject,
                        "this$0"
                    );
                    Object viewModel = objectField(
                        activity,
                        "documentViewModel"
                    );
                    // A concrete Back action supersedes every older queued or
                    // mixed-menu link. HISTORY_SERIALIZATION remains held until
                    // the listener returns, so its getter, list mutation, and
                    // same/external-document branch are one native transaction.
                    clearQueuedLinkInvocation(viewModel);
                    clearMixedLinkCandidate(viewModel);
                    ManifestLookup lookup = manifestLookupFor(viewModel);
                    // As with a turn, let a freshness lookup capture the prior
                    // token, then claim Back before any blocked/native return.
                    noteReaderIntent(viewModel);
                    if (lookup.navigationBlocked()) {
                        blockHistoryAction(
                            param,
                            lookup.navigationBlockReason(),
                            original
                        );
                        return;
                    }
                    Manifest manifest = lookup.manifest;
                    if (manifest == null) {
                        return;
                    }
                    Object backInfo = peekNativeBackInfo(original);
                    if (backInfo == null) {
                        blockHistoryAction(
                            param,
                            "native_history_unavailable",
                            original
                        );
                        return;
                    }
                    String sourcePath = stringMethod(
                        backInfo,
                        "getFromUrl"
                    );
                    if (sourcePath != null
                        && !sameCanonicalPath(manifest.key, sourcePath)) {
                        // A Back target in another document stays wholly
                        // native, but remains inside the same serialized action.
                        log("link_history_action_native_external original="
                            + original);
                        return;
                    }
                    if (!preflightSameDocumentHistory(
                            viewModel,
                            manifest,
                            backInfo,
                            original
                        )) {
                        blockHistoryAction(
                            param,
                            "unresolved_same_document_history",
                            original
                        );
                        return;
                    }
                    // Bind this already-authenticated manifest for the
                    // duration of the one synchronous native action. The
                    // firmware getter mutates its history list, so capture
                    // must not perform a second lookup that could cross a
                    // freshness-lease boundary after the native history entry
                    // has already been consumed.
                    HISTORY_ACTION.set(new HistoryActionContext(
                        backInfo,
                        viewModel,
                        manifest
                    ));
                } catch (Throwable throwable) {
                    blockHistoryAction(param, "guard_failed", original);
                    unlockHistoryAction();
                    logFailure("link_history_action_guard_failed", throwable);
                }
            }

            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                try {
                    HISTORY_ACTION.remove();
                } finally {
                    unlockHistoryAction();
                }
            }
        };
    }

    private static void lockHistoryAction() {
        HISTORY_SERIALIZATION.lock();
        Integer depth = HISTORY_ACTION_LOCK_DEPTH.get();
        HISTORY_ACTION_LOCK_DEPTH.set(Integer.valueOf(
            depth == null ? 1 : depth.intValue() + 1
        ));
    }

    private static void unlockHistoryAction() {
        Integer depth = HISTORY_ACTION_LOCK_DEPTH.get();
        if (depth == null || depth.intValue() <= 0) {
            return;
        }
        if (depth.intValue() == 1) {
            HISTORY_ACTION_LOCK_DEPTH.remove();
        } else {
            HISTORY_ACTION_LOCK_DEPTH.set(Integer.valueOf(
                depth.intValue() - 1
            ));
        }
        HISTORY_SERIALIZATION.unlock();
    }

    private static void blockHistoryAction(
        XC_MethodHook.MethodHookParam param,
        String reason,
        boolean original
    ) {
        // Block at the void action boundary. Never replace the firmware
        // getter's non-null BackLinkInfo with null: its caller dereferences it.
        param.setResult(null);
        HISTORY_ACTION.remove();
        log("link_history_action_blocked reason=" + reason
            + " original=" + original);
    }

    private static Object peekNativeBackInfo(boolean original) {
        try {
            Object value = XposedHelpers.getStaticObjectField(
                backLinkClass,
                "backList"
            );
            if (!(value instanceof List)) {
                return null;
            }
            List<?> backList = (List<?>) value;
            if (backList.isEmpty()) {
                return null;
            }
            return original
                ? backList.get(backList.size() - 1)
                : backList.get(0);
        } catch (Throwable throwable) {
            logFailure("link_history_preflight_failed", throwable);
            return null;
        }
    }

    private static boolean preflightSameDocumentHistory(
        Object viewModel,
        Manifest manifest,
        Object backInfo,
        boolean original
    ) {
        try {
            int sourcePage = intMethod(backInfo, "getFromPage", -1);
            int targetPage = intMethod(backInfo, "getToPage", -1);
            String sourcePath = stringMethod(backInfo, "getFromUrl");
            String targetPath = stringMethod(backInfo, "getToUrl");
            int currentPage = intField(viewModel, "currentPage", -1);
            if (sourcePage < 0 || sourcePage >= manifest.pageCount
                || targetPage < 0 || targetPage >= manifest.pageCount
                || currentPage < 0 || currentPage >= manifest.pageCount
                || (!original && currentPage != targetPage)
                || !sameCanonicalPath(manifest.key, sourcePath)
                || !sameCanonicalPath(manifest.key, targetPath)) {
                return false;
            }
            ReaderState state = stateFor(viewModel, manifest);
            boolean hasRuntimeHistory = state.linkHistory.size() > 0;
            VirtualSpreadNavigation.LinkVisit visit = original
                ? state.linkHistory.peekOriginal(
                    sourcePage, targetPage, currentPage
                )
                : state.linkHistory.peekBack(
                    sourcePage, targetPage, currentPage
                );
            if (hasRuntimeHistory) {
                return visit != null;
            }
            return VirtualSpreadNavigation.inferLinkSourceHalf(
                manifest.links,
                sourcePage,
                targetPage
            ) != null;
        } catch (Throwable throwable) {
            logFailure("link_history_preflight_failed", throwable);
            return false;
        }
    }

    private static void hookNativeSaveAcknowledgement(
        ClassLoader classLoader
    ) {
        XposedHelpers.findAndHookMethod(
            TARGET_SUPER_NOTE,
            classLoader,
            "saveMarkData",
            String.class,
            String.class,
            int.class,
            boolean.class,
            new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    SaveObservation observation = SAVE_OBSERVATION.get();
                    if (observation == null) {
                        return;
                    }
                    observation.callbackObserved = true;
                    observation.callbackSucceeded = Boolean.TRUE.equals(
                        param.getResult()
                    );
                    observation.sameNote = param.thisObject
                        == observation.expectedNote;
                    observation.observedPage = param.args[2] instanceof Integer
                        ? ((Integer) param.args[2]).intValue() : -1;
                    observation.sameMarkPath = sameText(
                        observation.expectedMarkPath,
                        param.args[0] instanceof String
                            ? (String) param.args[0] : null
                    );
                }
            }
        );
    }

    private static void captureHistoryReturn(
        XC_MethodHook.MethodHookParam param,
        boolean original
    ) {
        Object backInfo = param.getResult();
        if (backInfo == null) {
            return;
        }
        HistoryActionContext action = HISTORY_ACTION.get();
        if (action == null) {
            return;
        }
        if (action.expectedBackInfo != backInfo) {
            log("link_history_unmatched reason=preflight_changed");
            return;
        }
        Activity activity = activeActivity.get();
        if (activity == null || objectField(
                activity,
                "documentViewModel"
            ) != action.viewModel) {
            log("link_history_unmatched reason=view_model_changed");
            return;
        }
        Object viewModel = action.viewModel;
        Manifest manifest = action.manifest;
        try {
            int sourcePage = intMethod(backInfo, "getFromPage", -1);
            int targetPage = intMethod(backInfo, "getToPage", -1);
            String sourcePath = stringMethod(backInfo, "getFromUrl");
            String targetPath = stringMethod(backInfo, "getToUrl");
            int currentPage = intField(viewModel, "currentPage", -1);
            if (sourcePage < 0 || sourcePage >= manifest.pageCount
                || targetPage < 0 || targetPage >= manifest.pageCount
                || currentPage < 0 || currentPage >= manifest.pageCount
                || (!original && currentPage != targetPage)
                || !sameCanonicalPath(manifest.key, sourcePath)
                || !sameCanonicalPath(manifest.key, targetPath)) {
                log("link_history_ignored original=" + original
                    + " source=" + sourcePage
                    + " target=" + targetPage
                    + " current=" + currentPage);
                return;
            }

            ReaderState state = stateFor(viewModel, manifest);
            boolean hadRuntimeHistory = state.linkHistory.size() > 0;
            VirtualSpreadNavigation.LinkVisit visit = original
                ? state.linkHistory.takeOriginal(
                    sourcePage, targetPage, currentPage
                )
                : state.linkHistory.takeBack(
                    sourcePage, targetPage, currentPage
                );
            if (hadRuntimeHistory && visit == null) {
                clearPendingHistory(state);
                log("link_history_unmatched original=" + original
                    + " source=" + sourcePage
                    + " target=" + targetPage
                    + " current=" + currentPage
                    + " origin=runtime");
                return;
            }
            VirtualSpreadNavigation.Half sourceHalf = visit == null
                ? VirtualSpreadNavigation.inferLinkSourceHalf(
                    manifest.links,
                    sourcePage,
                    targetPage
                )
                : visit.sourceHalf;
            if (sourceHalf == null) {
                clearPendingHistory(state);
                log("link_history_unmatched original=" + original
                    + " source=" + sourcePage
                    + " target=" + targetPage);
                return;
            }
            clearPendingLink(state);
            state.pendingHistoryPage = sourcePage;
            state.pendingHistoryHalf = sourceHalf;
            state.pendingHistoryAt = System.currentTimeMillis();
            noteReaderIntent(state);
            if (action != null) {
                action.pageLoadAuthorized = true;
            }
            log("link_history_captured original=" + original
                + " source=" + sourcePage
                + " target=" + targetPage
                + " half=" + sourceHalf
                + " origin=" + (visit == null ? "manifest" : "runtime"));
        } catch (Throwable throwable) {
            logFailure("link_history_capture_failed", throwable);
        }
    }

    private static void handleLinkTarget(
        XC_MethodHook.MethodHookParam param
    ) {
        Activity activity = (Activity) param.thisObject;
        Object viewModel = objectField(activity, "documentViewModel");
        Object superNoteLink = param.args[1];
        if (superNoteLink == null) {
            // showLinkJumpView is also Supernote's annotation/digest menu
            // callback. It is not document navigation and must stay native,
            // but this newer action supersedes an older cold-link replay.
            clearQueuedLinkInvocation(viewModel);
            clearMixedLinkCandidate(viewModel);
            return;
        }
        boolean immediate = immediateLinkArguments(param.args);
        if (!immediate) {
            // A mixed hit opens DocumentLinkJumpView2. Highlight, underline,
            // digest, copy, and delete actions must remain completely native.
            // Merely showing that menu is not a link traversal; retain only a
            // short-lived candidate for the later jumpLink callback.
            rememberMixedLinkCandidate(
                viewModel,
                superNoteLink,
                ((Integer) param.args[2]).intValue()
            );
            return;
        }
        clearMixedLinkCandidate(viewModel);
        ManifestLookup lookup = manifestLookupFor(viewModel);
        if (lookup.manifest == null && !lookup.navigationBlocked()) {
            // An ordinary PDF with explicit native non-spread authority must
            // remain completely untouched by this companion.
            return;
        }
        int targetPage = ((Integer) param.args[2]).intValue();
        VirtualSpreadNavigation.LinkRouting routing =
            classifyLinkInvocation(superNoteLink, targetPage);
        if (routing == VirtualSpreadNavigation.LinkRouting.NON_LINK) {
            return;
        }
        if (routing == VirtualSpreadNavigation.LinkRouting.BLOCKED) {
            // An uninspectable current link must not allow an older queued
            // link to replay after manifest verification completes. The
            // firmware method returns primitive boolean, so every blocked
            // invocation must return a non-null value. TRUE also consumes the
            // tap in DocumentActivity$2; FALSE would fall through and turn a
            // page even though link navigation was blocked.
            clearQueuedLinkInvocation(viewModel);
            param.setResult(Boolean.TRUE);
            log("link_jump_blocked reason=uninspectable_link_kind");
            return;
        }
        if (lookup.manifest != null) {
            // Any newly authenticated link action supersedes an invocation
            // queued by an older cold-verification callback. Clear it before
            // either native external handling or internal capture can return.
            clearQueuedLinkInvocation(viewModel);
            if (routing == VirtualSpreadNavigation.LinkRouting.EXTERNAL) {
                if (!authenticatedExternalLink(
                        viewModel,
                        lookup.manifest,
                        superNoteLink
                    )) {
                    param.setResult(Boolean.TRUE);
                    log("link_jump_blocked reason=unmatched_authenticated_uri");
                    return;
                }
                log("link_jump_passthrough kind=external authority=matched");
                return;
            }
            if (!captureLinkTarget(
                viewModel,
                lookup.manifest,
                superNoteLink,
                targetPage
            )) {
                param.setResult(Boolean.TRUE);
                log("link_jump_blocked reason=unmatched_authenticated_link");
            }
            return;
        }
        if (lookup.verificationPending) {
            queueLinkInvocation(
                viewModel,
                param.args,
                superNoteLink,
                targetPage,
                false,
                lookup.snapshotId,
                lookup.verificationGeneration,
                routing
            );
            param.setResult(Boolean.TRUE);
            log("link_jump_blocked reason=manifest_verification_pending");
            return;
        }
        if (lookup.navigationBlocked()) {
            clearQueuedLinkInvocation(viewModel);
            param.setResult(Boolean.TRUE);
            log("link_jump_blocked reason="
                + lookup.navigationBlockReason());
        }
    }

    private static boolean immediateLinkArguments(Object[] arguments) {
        return arguments != null
            && arguments.length == 6
            && VirtualSpreadNavigation.isImmediateLinkInvocation(
                arguments[1] != null,
                arguments[3] != null,
                arguments[4] != null
            );
    }

    private static void rememberMixedLinkCandidate(
        Object viewModel,
        Object superNoteLink,
        int targetPage
    ) {
        ManifestLookup lookup = manifestLookupFor(viewModel);
        if (lookup.manifest == null && !lookup.navigationBlocked()) {
            clearMixedLinkCandidate(viewModel);
            return;
        }
        // Opening a new native action menu supersedes any older cold-start
        // navigation replay. The menu itself remains visible and native.
        clearQueuedLinkInvocation(viewModel);
        Object nativeDocument = nativePdfDocument(viewModel);
        Boolean external = null;
        try {
            Object value = XposedHelpers.callMethod(
                superNoteLink,
                "isExternal"
            );
            if (value instanceof Boolean) {
                external = (Boolean) value;
            }
        } catch (Throwable throwable) {
            logFailure("mixed_link_kind_inspection_failed", throwable);
        }
        String documentPath = documentPath(viewModel);
        String uri = stringMethod(superNoteLink, "getUrl");
        int sourcePage = intField(viewModel, "currentPage", -1);
        synchronized (STATES) {
            ReaderState state = readerStateLocked(viewModel);
            state.mixedLinkCandidate = new MixedLinkCandidate(
                documentPath,
                nativeDocument,
                nativePdfMetadata(
                    nativeDocument,
                    "SNVirtualSpreadSourceSHA256"
                ),
                nativePdfMetadata(
                    nativeDocument,
                    "SNVirtualSpreadLayoutSHA256"
                ),
                nativePdfMetadata(
                    nativeDocument,
                    "SNVirtualSpreadLinksSHA256"
                ),
                nativePdfMetadata(
                    nativeDocument,
                    "SNVirtualSpreadMappingSHA256"
                ),
                nativePdfMetadata(
                    nativeDocument,
                    "SNVirtualSpreadViewID"
                ),
                nativePdfMetadata(
                    nativeDocument,
                    "SNVirtualSpreadGeneratorVersion"
                ),
                superNoteLink,
                sourcePage,
                targetPage,
                uri,
                external,
                lookup.verificationGeneration,
                state.pageLoadGeneration,
                System.currentTimeMillis()
            );
            noteReaderIntent(state);
        }
        log("mixed_link_menu_observed source=" + sourcePage
            + " target=" + targetPage);
    }

    private static void handleMixedLinkJump(
        XC_MethodHook.MethodHookParam param
    ) {
        Activity activity = (Activity) param.thisObject;
        Object viewModel = objectField(activity, "documentViewModel");
        ManifestLookup lookup = manifestLookupFor(viewModel);
        if (lookup.manifest == null && !lookup.navigationBlocked()) {
            clearMixedLinkCandidate(viewModel);
            return;
        }
        MixedLinkCandidate candidate;
        long currentPageLoadGeneration;
        synchronized (STATES) {
            ReaderState state = STATES.get(viewModel);
            candidate = state == null ? null : state.mixedLinkCandidate;
            currentPageLoadGeneration = state == null
                ? -1L : state.pageLoadGeneration;
            if (state != null) {
                state.mixedLinkCandidate = null;
            }
        }
        if (candidate == null) {
            // Pure-link calls are explicitly marked by the surrounding
            // showLinkJumpView hook. On a generated document, every other
            // direct jumpLink call must have a fresh mixed-menu candidate.
            param.setResult(null);
            log("mixed_link_jump_blocked reason=missing_menu_context");
            return;
        }
        int targetPage = param.args[0] instanceof Integer
            ? ((Integer) param.args[0]).intValue() : -1;
        String uri = param.args[1] instanceof String
            ? (String) param.args[1] : null;
        Boolean external = param.args[2] instanceof Boolean
            ? (Boolean) param.args[2] : null;
        Object currentNativeDocument = nativePdfDocument(viewModel);
        long age = System.currentTimeMillis() - candidate.createdAt;
        boolean current = currentPageLoadGeneration >= 0L
            && candidate.link != null
            && VirtualSpreadNavigation
                .mixedLinkSurvivesVerificationBinding(
                    candidate.verificationGeneration,
                    lookup.verificationGeneration
                )
            && targetPage == candidate.targetPage
            && sameText(uri, candidate.uri)
            && external != null
            && external.equals(candidate.external)
            && candidate.sourcePage >= 0
            && candidate.sourcePage == intField(viewModel, "currentPage", -1)
            && candidate.pageLoadGeneration == currentPageLoadGeneration
            && sameCanonicalPath(
                candidate.documentPath,
                documentPath(viewModel)
            )
            && currentNativeDocument != null
            && currentNativeDocument == candidate.nativeDocument
            && sameText(
                candidate.nativeSourceAuthority,
                nativePdfMetadata(
                    currentNativeDocument,
                    "SNVirtualSpreadSourceSHA256"
                )
            )
            && sameText(
                candidate.nativeLayoutAuthority,
                nativePdfMetadata(
                    currentNativeDocument,
                    "SNVirtualSpreadLayoutSHA256"
                )
            )
            && sameText(
                candidate.nativeLinkAuthority,
                nativePdfMetadata(
                    currentNativeDocument,
                    "SNVirtualSpreadLinksSHA256"
                )
            )
            && sameText(
                candidate.nativeMappingAuthority,
                nativePdfMetadata(
                    currentNativeDocument,
                    "SNVirtualSpreadMappingSHA256"
                )
            )
            && sameText(
                candidate.nativeViewId,
                nativePdfMetadata(
                    currentNativeDocument,
                    "SNVirtualSpreadViewID"
                )
            )
            && sameText(
                candidate.nativeGeneratorVersion,
                nativePdfMetadata(
                    currentNativeDocument,
                    "SNVirtualSpreadGeneratorVersion"
                )
            )
            && age >= 0L
            && age <= PENDING_LINK_MAX_AGE_MS;
        if (!current) {
            clearQueuedLinkInvocation(viewModel);
            param.setResult(null);
            log("mixed_link_jump_blocked reason=stale_or_invalid_context");
            return;
        }
        VirtualSpreadNavigation.LinkRouting routing =
            classifyLinkInvocation(candidate.link, targetPage);
        if (routing == VirtualSpreadNavigation.LinkRouting.BLOCKED
            || routing == VirtualSpreadNavigation.LinkRouting.NON_LINK) {
            clearQueuedLinkInvocation(viewModel);
            param.setResult(null);
            log("mixed_link_jump_blocked reason=uninspectable_link_kind");
            return;
        }
        if (lookup.manifest != null) {
            clearQueuedLinkInvocation(viewModel);
            if (routing == VirtualSpreadNavigation.LinkRouting.EXTERNAL) {
                if (!authenticatedExternalLink(
                        viewModel,
                        lookup.manifest,
                        candidate.link
                    )) {
                    param.setResult(null);
                    log("mixed_link_jump_blocked reason="
                        + "unmatched_authenticated_uri");
                    return;
                }
                log("mixed_link_jump_passthrough kind=external"
                    + " authority=matched");
                return;
            }
            if (!captureLinkTarget(
                    viewModel,
                    lookup.manifest,
                    candidate.link,
                    targetPage
                )) {
                param.setResult(null);
                log("mixed_link_jump_blocked reason="
                    + "unmatched_authenticated_link");
            }
            return;
        }
        if (lookup.verificationPending) {
            queueLinkInvocation(
                viewModel,
                param.args,
                candidate.link,
                targetPage,
                true,
                lookup.snapshotId,
                lookup.verificationGeneration,
                routing
            );
            param.setResult(null);
            log("mixed_link_jump_blocked reason="
                + "manifest_verification_pending");
            return;
        }
        if (lookup.navigationBlocked()) {
            clearQueuedLinkInvocation(viewModel);
            param.setResult(null);
            log("mixed_link_jump_blocked reason="
                + lookup.navigationBlockReason());
        }
    }

    private static String documentPath(Object viewModel) {
        Uri uri = viewModel == null ? null
            : (Uri) objectField(viewModel, "uri");
        return uri == null ? null : uri.getPath();
    }

    private static VirtualSpreadNavigation.LinkRouting classifyLinkInvocation(
        Object superNoteLink,
        int targetPage
    ) {
        Boolean external = null;
        if (superNoteLink != null) {
            try {
                Object value = XposedHelpers.callMethod(
                    superNoteLink,
                    "isExternal"
                );
                if (value instanceof Boolean) {
                    external = (Boolean) value;
                }
            } catch (Throwable throwable) {
                logFailure("link_kind_inspection_failed", throwable);
            }
        }
        return VirtualSpreadNavigation.classifyLinkInvocation(
            superNoteLink != null,
            external,
            targetPage
        );
    }

    private static boolean captureLinkTarget(
        Object viewModel,
        Manifest manifest,
        Object superNoteLink,
        int targetPage
    ) {
        ReaderState state = stateFor(viewModel, manifest);
        clearPendingLink(state);
        if (superNoteLink == null || targetPage < 0) {
            return false;
        }
        try {
            Object nativeLink = XposedHelpers.callMethod(
                superNoteLink,
                "getLink"
            );
            Object bounds = nativeLink == null ? null
                : XposedHelpers.callMethod(nativeLink, "getBounds");
            if (bounds == null) {
                return false;
            }
            int sourcePage = intField(viewModel, "currentPage", -1);
            float x0 = floatField(bounds, "x0", Float.NaN);
            float y0 = floatField(bounds, "y0", Float.NaN);
            float x1 = floatField(bounds, "x1", Float.NaN);
            float y1 = floatField(bounds, "y1", Float.NaN);
            VirtualSpreadNavigation.LinkTarget matched =
                VirtualSpreadNavigation.matchLink(
                    manifest.links,
                    sourcePage,
                    targetPage,
                    x0,
                    y0,
                    x1,
                    y1,
                    (float) manifest.pageHeight,
                    2.0f
                );
            if (matched == null) {
                log("link_target_unmatched source=" + sourcePage
                    + " target=" + targetPage
                    + " rect=" + x0 + "," + y0 + "," + x1 + "," + y1);
                return false;
            }
            VirtualSpreadNavigation.Half sourceHalf =
                matched.sourceHalf == null
                    ? detectHalf(viewModel, state.half)
                    : matched.sourceHalf;
            state.pendingLinkSourcePage = sourcePage;
            state.pendingLinkSourceHalf = sourceHalf;
            state.pendingLinkPage = targetPage;
            state.pendingLinkHalf = matched.targetHalf;
            state.pendingLinkResetLandscapeFit =
                matched.resetLandscapeFit;
            state.pendingLinkAt = System.currentTimeMillis();
            noteReaderIntent(state);
            log("link_target_captured source=" + sourcePage
                + " source_half=" + sourceHalf
                + " target=" + targetPage
                + " target_half=" + matched.targetHalf
                + " reset_landscape_fit="
                + matched.resetLandscapeFit);
            return true;
        } catch (Throwable throwable) {
            clearPendingLink(state);
            logFailure("link_target_capture_failed", throwable);
            return false;
        }
    }

    private static boolean authenticatedExternalLink(
        Object viewModel,
        Manifest manifest,
        Object superNoteLink
    ) {
        if (manifest == null || superNoteLink == null) {
            return false;
        }
        try {
            String uri = stringMethod(superNoteLink, "getUrl");
            Object nativeLink = XposedHelpers.callMethod(
                superNoteLink,
                "getLink"
            );
            Object bounds = nativeLink == null ? null
                : XposedHelpers.callMethod(nativeLink, "getBounds");
            if (uri == null || bounds == null) {
                return false;
            }
            int sourcePage = intField(viewModel, "currentPage", -1);
            VirtualSpreadNavigation.UriTarget matched =
                VirtualSpreadNavigation.matchUriLink(
                    manifest.uriLinks,
                    sourcePage,
                    uri,
                    floatField(bounds, "x0", Float.NaN),
                    floatField(bounds, "y0", Float.NaN),
                    floatField(bounds, "x1", Float.NaN),
                    floatField(bounds, "y1", Float.NaN),
                    (float) manifest.pageHeight,
                    2.0f
                );
            if (matched == null) {
                log("uri_link_unmatched source=" + sourcePage
                    + " uri=" + uri);
                return false;
            }
            return true;
        } catch (Throwable throwable) {
            logFailure("uri_link_match_failed", throwable);
            return false;
        }
    }

    private static void queueLinkInvocation(
        Object viewModel,
        Object[] arguments,
        Object linkObject,
        int targetPage,
        boolean directJump,
        String snapshotId,
        long verificationGeneration,
        VirtualSpreadNavigation.LinkRouting routing
    ) {
        if (viewModel == null || arguments == null || arguments.length < 3
            || linkObject == null
            || snapshotId == null
            || verificationGeneration <= 0L
            || (routing != VirtualSpreadNavigation.LinkRouting.EXTERNAL
                && routing != VirtualSpreadNavigation.LinkRouting.INTERNAL)
            || (routing == VirtualSpreadNavigation.LinkRouting.INTERNAL
                && targetPage < 0)) {
            clearQueuedLinkInvocation(viewModel);
            log("link_jump_not_queued reason=invalid_invocation");
            return;
        }
        String documentPath = documentPath(viewModel);
        int sourcePage = intField(viewModel, "currentPage", -1);
        Object nativeDocument = nativePdfDocument(viewModel);
        String nativeSourceAuthority = nativePdfMetadata(
            nativeDocument, "SNVirtualSpreadSourceSHA256"
        );
        String nativeLayoutAuthority = nativePdfMetadata(
            nativeDocument, "SNVirtualSpreadLayoutSHA256"
        );
        String nativeLinkAuthority = nativePdfMetadata(
            nativeDocument, "SNVirtualSpreadLinksSHA256"
        );
        String nativeMappingAuthority = nativePdfMetadata(
            nativeDocument, "SNVirtualSpreadMappingSHA256"
        );
        String nativeViewId = nativePdfMetadata(
            nativeDocument, "SNVirtualSpreadViewID"
        );
        String nativeGeneratorVersion = nativePdfMetadata(
            nativeDocument, "SNVirtualSpreadGeneratorVersion"
        );
        if (documentPath == null || sourcePage < 0 || nativeDocument == null
            || !isSha256(nativeSourceAuthority)
            || !isSha256(nativeLayoutAuthority)
            || !isSha256(nativeLinkAuthority)
            || !isSha256(nativeMappingAuthority)
            || nativeViewId == null
            || !nativeViewId.startsWith(VIEW_ID_PREFIX)
            || !(GENERATOR_VERSION.equals(nativeGeneratorVersion)
                || NAVIGATION_GENERATOR_VERSION.equals(
                    nativeGeneratorVersion))) {
            clearQueuedLinkInvocation(viewModel);
            log("link_jump_not_queued reason=missing_native_source_state");
            return;
        }
        synchronized (STATES) {
            ReaderState state = readerStateLocked(viewModel);
            state.queuedLinkArguments = arguments.clone();
            state.queuedLinkDocumentPath = documentPath;
            state.queuedLinkSnapshotId = snapshotId;
            state.queuedLinkVerificationGeneration = verificationGeneration;
            state.queuedLinkPageLoadGeneration = state.pageLoadGeneration;
            state.queuedLinkRouting = routing;
            state.queuedLinkNativeDocument = nativeDocument;
            state.queuedLinkNativeSourceAuthority = nativeSourceAuthority;
            state.queuedLinkNativeLayoutAuthority = nativeLayoutAuthority;
            state.queuedLinkNativeLinkAuthority = nativeLinkAuthority;
            state.queuedLinkNativeMappingAuthority = nativeMappingAuthority;
            state.queuedLinkNativeViewId = nativeViewId;
            state.queuedLinkNativeGeneratorVersion = nativeGeneratorVersion;
            state.queuedLinkObject = linkObject;
            state.queuedLinkTargetPage = targetPage;
            state.queuedLinkDirectJump = directJump;
            state.queuedLinkSourcePage = sourcePage;
            state.queuedLinkAt = System.currentTimeMillis();
            noteReaderIntent(state);
        }
        log("link_jump_queued source=" + sourcePage
            + " target=" + targetPage
            + " dispatch=" + (directJump ? "jumpLink" : "showLinkJumpView")
            + " kind=" + routing);
    }

    private static VirtualSpreadNavigation.LinkRouting replayQueuedLink(
        Activity activity,
        Object viewModel,
        Manifest manifest,
        VerificationOwner verificationOwner
    ) {
        Object[] arguments;
        String documentPath;
        String snapshotId;
        VirtualSpreadNavigation.LinkRouting queuedRouting;
        int sourcePage;
        long queuedAt;
        long queuedVerificationGeneration;
        long queuedPageLoadGeneration;
        long currentPageLoadGeneration;
        Object queuedNativeDocument;
        String queuedNativeSourceAuthority;
        String queuedNativeLayoutAuthority;
        String queuedNativeLinkAuthority;
        String queuedNativeMappingAuthority;
        String queuedNativeViewId;
        String queuedNativeGeneratorVersion;
        Object queuedLinkObject;
        int queuedTargetPage;
        boolean queuedDirectJump;
        synchronized (STATES) {
            ReaderState state = STATES.get(viewModel);
            if (state == null || state.queuedLinkArguments == null) {
                return VirtualSpreadNavigation.LinkRouting.NON_LINK;
            }
            if (!VirtualSpreadNavigation.queuedLinkBelongsToVerification(
                    state.queuedLinkVerificationGeneration,
                    verificationOwner.generation
                )) {
                log("link_jump_replay_deferred reason=verification_generation"
                    + " queued=" + state.queuedLinkVerificationGeneration
                    + " activation=" + verificationOwner.generation);
                return VirtualSpreadNavigation.LinkRouting.BLOCKED;
            }
            arguments = state.queuedLinkArguments;
            documentPath = state.queuedLinkDocumentPath;
            snapshotId = state.queuedLinkSnapshotId;
            queuedRouting = state.queuedLinkRouting;
            sourcePage = state.queuedLinkSourcePage;
            queuedAt = state.queuedLinkAt;
            queuedVerificationGeneration =
                state.queuedLinkVerificationGeneration;
            queuedPageLoadGeneration = state.queuedLinkPageLoadGeneration;
            currentPageLoadGeneration = state.pageLoadGeneration;
            queuedNativeDocument = state.queuedLinkNativeDocument;
            queuedNativeSourceAuthority =
                state.queuedLinkNativeSourceAuthority;
            queuedNativeLayoutAuthority =
                state.queuedLinkNativeLayoutAuthority;
            queuedNativeLinkAuthority = state.queuedLinkNativeLinkAuthority;
            queuedNativeMappingAuthority =
                state.queuedLinkNativeMappingAuthority;
            queuedNativeViewId = state.queuedLinkNativeViewId;
            queuedNativeGeneratorVersion =
                state.queuedLinkNativeGeneratorVersion;
            queuedLinkObject = state.queuedLinkObject;
            queuedTargetPage = state.queuedLinkTargetPage;
            queuedDirectJump = state.queuedLinkDirectJump;
            clearQueuedLinkInvocation(state);
        }
        long age = System.currentTimeMillis() - queuedAt;
        int currentPage = intField(viewModel, "currentPage", -1);
        Object currentNativeDocument = nativePdfDocument(viewModel);
        boolean sameNativeDocument = currentNativeDocument != null
            && currentNativeDocument == queuedNativeDocument
            && queuedNativeSourceAuthority != null
            && queuedNativeSourceAuthority.equals(nativePdfMetadata(
                currentNativeDocument,
                "SNVirtualSpreadSourceSHA256"
            ))
            && queuedNativeLayoutAuthority != null
            && queuedNativeLayoutAuthority.equals(nativePdfMetadata(
                currentNativeDocument,
                "SNVirtualSpreadLayoutSHA256"
            ))
            && queuedNativeLinkAuthority != null
            && queuedNativeLinkAuthority.equals(nativePdfMetadata(
                currentNativeDocument,
                "SNVirtualSpreadLinksSHA256"
            ))
            && queuedNativeMappingAuthority != null
            && queuedNativeMappingAuthority.equals(nativePdfMetadata(
                currentNativeDocument,
                "SNVirtualSpreadMappingSHA256"
            ))
            && queuedNativeViewId != null
            && queuedNativeViewId.equals(nativePdfMetadata(
                currentNativeDocument,
                "SNVirtualSpreadViewID"
            ))
            && queuedNativeGeneratorVersion != null
            && queuedNativeGeneratorVersion.equals(nativePdfMetadata(
                currentNativeDocument,
                "SNVirtualSpreadGeneratorVersion"
            ));
        if (!VirtualSpreadNavigation.pendingLinkReplayIsCurrent(
                sameCanonicalPath(manifest.key, documentPath),
                snapshotId != null
                    && snapshotId.equals(verificationOwner.snapshotId),
                sameNativeDocument
                    && verificationOwner.generation > 0L
                    && queuedVerificationGeneration
                        == verificationOwner.generation,
                queuedPageLoadGeneration >= 0L
                    && queuedPageLoadGeneration == currentPageLoadGeneration,
                sourcePage,
                currentPage,
                age,
                PENDING_LINK_MAX_AGE_MS
            ) || queuedLinkObject == null
            || !queuedReplayArgumentsAreValid(
                arguments,
                queuedLinkObject,
                queuedTargetPage,
                queuedDirectJump
            )) {
            log("link_jump_discarded reason=stale_or_invalid");
            return VirtualSpreadNavigation.LinkRouting.BLOCKED;
        }
        try {
            VirtualSpreadNavigation.LinkRouting currentRouting =
                classifyLinkInvocation(queuedLinkObject, queuedTargetPage);
            if (queuedRouting == null || currentRouting != queuedRouting
                || (currentRouting != VirtualSpreadNavigation.LinkRouting.EXTERNAL
                    && currentRouting
                        != VirtualSpreadNavigation.LinkRouting.INTERNAL)) {
                log("link_jump_discarded reason=link_kind_changed");
                return VirtualSpreadNavigation.LinkRouting.BLOCKED;
            }
            if (queuedDirectJump && !directJumpArgumentsMatchLink(
                    arguments,
                    queuedLinkObject,
                    currentRouting
                )) {
                log("link_jump_discarded reason=direct_arguments_changed");
                return VirtualSpreadNavigation.LinkRouting.BLOCKED;
            }
            if (currentRouting == VirtualSpreadNavigation.LinkRouting.INTERNAL
                && !captureLinkTarget(
                    viewModel,
                    manifest,
                    queuedLinkObject,
                    queuedTargetPage
                )) {
                log("link_jump_discarded reason=unmatched_authenticated_link");
                return VirtualSpreadNavigation.LinkRouting.BLOCKED;
            }
            if (currentRouting == VirtualSpreadNavigation.LinkRouting.EXTERNAL
                && !authenticatedExternalLink(
                    viewModel,
                    manifest,
                    queuedLinkObject
                )) {
                log("link_jump_discarded reason=unmatched_authenticated_uri");
                return VirtualSpreadNavigation.LinkRouting.BLOCKED;
            }
            REPLAYING_LINK.set(Boolean.TRUE);
            XposedHelpers.callMethod(
                activity,
                queuedDirectJump ? "jumpLink" : "showLinkJumpView",
                arguments
            );
            log("link_jump_replayed source=" + sourcePage
                + " target=" + queuedTargetPage
                + " dispatch="
                + (queuedDirectJump ? "jumpLink" : "showLinkJumpView")
                + " kind=" + currentRouting);
            return currentRouting;
        } catch (Throwable throwable) {
            clearPendingLink(stateFor(viewModel, manifest));
            logFailure("link_jump_replay_failed", throwable);
            return VirtualSpreadNavigation.LinkRouting.BLOCKED;
        } finally {
            REPLAYING_LINK.remove();
        }
    }

    private static boolean queuedReplayArgumentsAreValid(
        Object[] arguments,
        Object linkObject,
        int targetPage,
        boolean directJump
    ) {
        if (arguments == null) {
            return false;
        }
        if (directJump) {
            return arguments.length == 3
                && arguments[0] instanceof Integer
                && ((Integer) arguments[0]).intValue() == targetPage
                && arguments[2] instanceof Boolean;
        }
        return arguments.length == 6
            && arguments[1] == linkObject
            && arguments[2] instanceof Integer
            && ((Integer) arguments[2]).intValue() == targetPage;
    }

    private static boolean directJumpArgumentsMatchLink(
        Object[] arguments,
        Object linkObject,
        VirtualSpreadNavigation.LinkRouting routing
    ) {
        if (arguments == null || arguments.length != 3
            || !(arguments[2] instanceof Boolean)) {
            return false;
        }
        boolean expectedExternal = routing
            == VirtualSpreadNavigation.LinkRouting.EXTERNAL;
        if (((Boolean) arguments[2]).booleanValue() != expectedExternal) {
            return false;
        }
        if (arguments[1] != null && !(arguments[1] instanceof String)) {
            return false;
        }
        return sameText(
            (String) arguments[1],
            stringMethod(linkObject, "getUrl")
        );
    }

    private static void hookViewModel(ClassLoader classLoader)
        throws Exception {
        Class<?> viewModelClass = XposedHelpers.findClass(
            TARGET_VIEW_MODEL,
            classLoader
        );
        Class<?> pageInfoClass = XposedHelpers.findClass(
            TARGET_PAGE_INFO,
            classLoader
        );
        Class<?> loadPageTaskClass = XposedHelpers.findClass(
            TARGET_LOAD_PAGE_TASK,
            classLoader
        );
        XposedBridge.hookMethod(
            loadPageTaskClass.getDeclaredConstructor(
                viewModelClass,
                int.class,
                int.class
            ),
            new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    NativeViewportLoadBinding binding =
                        NATIVE_VIEWPORT_LOAD_INVOCATION.get();
                    Object viewModel = objectField(
                        param.thisObject,
                        "this$0"
                    );
                    int page = intField(param.thisObject, "val$page", -1);
                    if (!nativeViewportCallbackOwnsActiveReader(
                            activeActivity.get(),
                            viewModel
                        )) {
                        return;
                    }
                    // Initial open and fit/orientation refresh can construct
                    // workers outside DocumentViewModel.loadPage(). A worker
                    // for the live page must synchronously invalidate the old
                    // descriptor at construction; adjacent prefetch workers
                    // receive an identity only and cannot disturb authority.
                    if (binding == null && viewModel != null && page >= 0) {
                        int livePage = intField(
                            viewModel,
                            "currentPage",
                            -1
                        );
                        binding = NativeViewportCompletionAuthority
                            .isCurrentWorkerPage(page, livePage)
                                ? beginNativeViewportLoadInvocation(
                                    viewModel,
                                    page,
                                    "current_page_worker"
                                )
                                : bindNativeViewportTask(
                                    viewModel,
                                    page
                                );
                    }
                    if (binding == null
                        || viewModel != binding.viewModel
                        || page != binding.page) {
                        return;
                    }
                    synchronized (STATES) {
                        NATIVE_VIEWPORT_TASK_BINDINGS.put(
                            param.thisObject,
                            binding
                        );
                    }
                }
            }
        );
        XposedBridge.hookMethod(
            loadPageTaskClass.getDeclaredMethod(
                "mainThreadCall",
                pageInfoClass
            ),
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    Object pageInfo = param.args == null
                        || param.args.length == 0 ? null : param.args[0];
                    if (pageInfo == null) {
                        return;
                    }
                    synchronized (STATES) {
                        NativeViewportLoadBinding binding =
                            NATIVE_VIEWPORT_TASK_BINDINGS.get(
                                param.thisObject
                            );
                        if (binding != null
                            && nativeViewportCallbackOwnsActiveReader(
                                activeActivity.get(),
                                binding.viewModel
                            )) {
                            NATIVE_VIEWPORT_PAGE_INFO_BINDINGS.put(
                                pageInfo,
                                binding
                            );
                        }
                    }
                }
            }
        );

        XposedHelpers.findAndHookMethod(
            TARGET_VIEW_MODEL,
            classLoader,
            "turnPage",
            int.class,
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    handleTurn(param);
                }
            }
        );

        XposedHelpers.findAndHookMethod(
            TARGET_VIEW_MODEL,
            classLoader,
            "loadPage",
            int.class,
            Integer.class,
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    NATIVE_VIEWPORT_LOAD_INVOCATION.remove();
                    int requestedPage = normalizedRequestedPage(
                        param.thisObject,
                        ((Integer) param.args[0]).intValue()
                    );
                    NativeViewportLoadBinding binding =
                        beginNativeViewportLoadInvocation(
                            param.thisObject,
                            requestedPage,
                            "load_page"
                        );
                    if (binding != null) {
                        NATIVE_VIEWPORT_LOAD_INVOCATION.set(binding);
                    }
                }

                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    NATIVE_VIEWPORT_LOAD_INVOCATION.remove();
                }
            }
        );

        XposedHelpers.findAndHookMethod(
            TARGET_VIEW_MODEL,
            classLoader,
            "onPageLoaded",
            TARGET_PAGE_INFO,
            Integer.class,
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    NATIVE_VIEWPORT_COMPLETION.remove();
                    Object pageInfo = param.args == null
                        || param.args.length == 0 ? null : param.args[0];
                    NativeViewportLoadBinding binding =
                        completionBindingFor(
                            param.thisObject,
                            pageInfo
                        );
                    if (binding != null
                        && binding.pageLoadGeneration >= 0L) {
                        NATIVE_VIEWPORT_COMPLETION.set(
                            new NativeViewportCompletion(
                                param.thisObject,
                                pageInfo,
                                binding.pageLoadGeneration
                            )
                        );
                    }
                }

                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    NATIVE_VIEWPORT_COMPLETION.remove();
                }
            }
        );

        XposedHelpers.findAndHookMethod(
            TARGET_VIEW_MODEL,
            classLoader,
            "onPageLoadedPart2",
            Integer.class,
            new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    handlePageLoaded(
                        param.thisObject,
                        NATIVE_VIEWPORT_COMPLETION.get()
                    );
                }
            }
        );
    }

    private static void hookPageBar(ClassLoader classLoader) {
        XposedHelpers.findAndHookMethod(
            TARGET_PAGE_BAR,
            classLoader,
            "setPageInfo",
            int.class,
            int.class,
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    PAGE_BAR_VALUES.remove();
                    Activity activity = activeActivity.get();
                    Object viewModel = objectField(
                        activity,
                        "documentViewModel"
                    );
                    Manifest manifest = manifestFor(viewModel);
                    if (manifest == null) {
                        return;
                    }
                    int current = ((Integer) param.args[0]).intValue();
                    int total = ((Integer) param.args[1]).intValue();
                    if (current < 1 || total != manifest.pageCount) {
                        return;
                    }
                    ReaderState state = stateFor(viewModel, manifest);
                    VirtualSpreadNavigation.Half half = detectHalf(
                        viewModel,
                        state.half
                    );
                    VirtualSpreadNavigation.PageBarState buttons =
                        VirtualSpreadNavigation.pageBarState(
                            manifest.spreads,
                            current - 1,
                            half,
                            isPortrait(activity)
                        );
                    int originalSplit = intField(
                        param.thisObject,
                        "mSplit",
                        -1
                    );
                    PAGE_BAR_VALUES.set(new int[] {
                        current,
                        total,
                        originalSplit
                    });

                    // Feed Supernote a synthetic page/split combination that
                    // produces the desired native clickable state and icons.
                    // The real label, total and split are restored afterward.
                    if (buttons.previousEnabled && buttons.nextEnabled) {
                        param.args[0] = Integer.valueOf(1);
                        param.args[1] = Integer.valueOf(2);
                        XposedHelpers.setIntField(
                            param.thisObject,
                            "mSplit",
                            2
                        );
                    } else if (buttons.previousEnabled) {
                        param.args[0] = Integer.valueOf(2);
                        param.args[1] = Integer.valueOf(2);
                        XposedHelpers.setIntField(
                            param.thisObject,
                            "mSplit",
                            -1
                        );
                    } else if (buttons.nextEnabled) {
                        param.args[0] = Integer.valueOf(1);
                        param.args[1] = Integer.valueOf(2);
                        XposedHelpers.setIntField(
                            param.thisObject,
                            "mSplit",
                            -1
                        );
                    } else {
                        param.args[0] = Integer.valueOf(1);
                        param.args[1] = Integer.valueOf(1);
                        XposedHelpers.setIntField(
                            param.thisObject,
                            "mSplit",
                            -1
                        );
                    }
                    log("page_bar current=" + current
                        + " total=" + total
                        + " portrait=" + isPortrait(activity)
                        + " half=" + half
                        + " previous_enabled="
                        + buttons.previousEnabled
                        + " next_enabled=" + buttons.nextEnabled);
                }

                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    int[] values = PAGE_BAR_VALUES.get();
                    PAGE_BAR_VALUES.remove();
                    if (values == null) {
                        return;
                    }
                    try {
                        XposedHelpers.setIntField(
                            param.thisObject,
                            "mSplit",
                            values[2]
                        );
                        XposedHelpers.setIntField(
                            param.thisObject,
                            "mTotalPageNumber",
                            values[1]
                        );
                        XposedHelpers.callMethod(
                            param.thisObject,
                            "setPageInfo",
                            values[0] + " / " + values[1]
                        );
                    } catch (Throwable throwable) {
                        logFailure("page_bar_restore_failed", throwable);
                    }
                }
            }
        );
    }

    private static void handleTurn(XC_MethodHook.MethodHookParam param) {
        int nativeOffset = ((Integer) param.args[0]).intValue();
        if (nativeOffset == 0) {
            return;
        }
        Object viewModel = param.thisObject;
        // A manual turn is newer user intent even while manifest authority is
        // still pending or blocked. Discard older queued and mixed-menu link
        // intent before any fail-closed return. This also covers portrait
        // same-spread half changes, which do not advance pageLoadGeneration.
        clearQueuedLinkInvocation(viewModel);
        clearMixedLinkCandidate(viewModel);
        ManifestLookup lookup = manifestLookupFor(viewModel);
        // A lookup may schedule freshness and capture its invalidation token.
        // Claim this turn only afterward, before any return or state mutation,
        // so that worker invalidation cannot erase the turn it just observed.
        noteReaderIntent(viewModel);
        Manifest manifest = lookup.manifest;
        if (manifest == null && lookup.navigationBlocked()) {
            param.setResult(null);
            log("turn_blocked reason=" + lookup.navigationBlockReason());
            return;
        }
        if (manifest == null) {
            return;
        }
        Activity activity = activeActivity.get();
        if (activity == null) {
            param.setResult(null);
            log("turn_blocked reason=no_activity");
            return;
        }
        int orientation = activity.getResources()
            .getConfiguration().orientation;
        if (orientation != Configuration.ORIENTATION_PORTRAIT
            && orientation != Configuration.ORIENTATION_LANDSCAPE) {
            param.setResult(null);
            log("turn_blocked reason=orientation_unavailable");
            return;
        }

        int currentPage = intField(viewModel, "currentPage", -1);
        ReaderState state = stateFor(viewModel, manifest);
        clearPendingLink(state);
        if (orientation == Configuration.ORIENTATION_LANDSCAPE) {
            int adjusted = VirtualSpreadNavigation.reverseLandscapeOffset(
                nativeOffset
            );
            param.args[0] = Integer.valueOf(adjusted);
            state.lastPage = currentPage;
            state.half = firstHalf(manifest, currentPage);
            log("landscape_turn current=" + currentPage
                + " native_offset=" + nativeOffset
                + " adjusted_offset=" + adjusted);
            return;
        }

        VirtualSpreadNavigation.Half currentHalf = detectHalf(
            viewModel,
            state.half
        );
        VirtualSpreadNavigation.Plan plan =
            VirtualSpreadNavigation.planPortrait(
                manifest.spreads,
                currentPage,
                currentHalf,
                nativeOffset
            );
        if (plan.kind == VirtualSpreadNavigation.Kind.BOUNDARY) {
            param.setResult(null);
            log("portrait_turn_boundary page=" + currentPage
                + " half=" + currentHalf
                + " native_offset=" + nativeOffset);
            return;
        }

        if (plan.kind == VirtualSpreadNavigation.Kind.SAME_SPREAD) {
            clearPreservedLinkViewport(state);
            state.half = plan.targetHalf;
            state.lastPage = plan.targetPage;
            int adjusted = plan.targetHalf == VirtualSpreadNavigation.Half.LEFT
                ? -1 : 1;
            param.args[0] = Integer.valueOf(adjusted);
            log("portrait_turn_same page=" + currentPage
                + " from=" + currentHalf
                + " to=" + plan.targetHalf
                + " adjusted_offset=" + adjusted);
            return;
        }

        if (!saveNativeTrails(activity)) {
            param.setResult(null);
            log("portrait_turn_blocked reason=native_save_failed");
            return;
        }
        state.pendingPage = plan.targetPage;
        state.pendingHalf = plan.targetHalf;
        int resetOffset = plan.targetHalf
            == VirtualSpreadNavigation.Half.RIGHT ? -1 : 1;
        // Once a manual cross-page transition begins, fail closed. Resuming
        // the original call after a reflection failure would turn the page in
        // Supernote's opposite, LTR direction.
        param.setResult(null);
        try {
            XposedHelpers.callMethod(
                viewModel,
                "setTurnPage",
                Integer.valueOf(resetOffset)
            );
            XposedHelpers.callMethod(
                viewModel,
                "loadPage",
                Integer.valueOf(plan.targetPage),
                Integer.valueOf(resetOffset)
            );
            log("portrait_turn_other from_page=" + currentPage
                + " from_half=" + currentHalf
                + " to_page=" + plan.targetPage
                + " to_half=" + plan.targetHalf
                + " load_hint=" + resetOffset);
        } catch (Throwable throwable) {
            state.pendingPage = -1;
            state.pendingHalf = null;
            logFailure("portrait_turn_failed", throwable);
        }
    }

    private static void handlePageLoaded(
        Object viewModel,
        NativeViewportCompletion completion
    ) {
        handlePageLoaded(viewModel, false, completion);
    }

    private static void handleManifestActivationInitialization(
        Object viewModel
    ) {
        long generation = beginNativeViewportPageLoad(
            viewModel,
            "manifest_activation",
            true
        );
        Object pageInfo = objectField(viewModel, "pageInfo");
        NativeViewportCompletion completion = generation < 0L
            || pageInfo == null ? null : new NativeViewportCompletion(
                viewModel,
                pageInfo,
                generation
            );
        handlePageLoaded(viewModel, true, completion);
    }

    private static final class NativeViewportCompletion {
        final Object viewModel;
        final Object pageInfo;
        final long pageLoadGeneration;

        NativeViewportCompletion(
            Object viewModel,
            Object pageInfo,
            long pageLoadGeneration
        ) {
            this.viewModel = viewModel;
            this.pageInfo = pageInfo;
            this.pageLoadGeneration = pageLoadGeneration;
        }
    }

    private static final class NativeViewportLoadBinding {
        final Object viewModel;
        final Object nativeMupdf;
        final int page;
        final long requestSerial;
        final long pageLoadGeneration;

        NativeViewportLoadBinding(
            Object viewModel,
            Object nativeMupdf,
            int page,
            long requestSerial,
            long pageLoadGeneration
        ) {
            this.viewModel = viewModel;
            this.nativeMupdf = nativeMupdf;
            this.page = page;
            this.requestSerial = requestSerial;
            this.pageLoadGeneration = pageLoadGeneration;
        }

        NativeViewportLoadBinding withGeneration(long generation) {
            return new NativeViewportLoadBinding(
                viewModel,
                nativeMupdf,
                page,
                requestSerial,
                generation
            );
        }
    }

    private static int normalizedRequestedPage(
        Object viewModel,
        int requestedPage
    ) {
        if (viewModel == null || requestedPage < 0) {
            return -1;
        }
        int pageCount = intField(viewModel, "pageCount", -1);
        if (pageCount > 0 && requestedPage >= pageCount) {
            return pageCount - 1;
        }
        return requestedPage;
    }

    private static NativeViewportLoadBinding
        beginNativeViewportLoadInvocation(
            Object viewModel,
            int page,
            String reason
        ) {
        synchronized (NATIVE_VIEWPORT_LOAD_BINDING_LOCK) {
            return beginNativeViewportLoadInvocationLocked(
                viewModel,
                page,
                reason
            );
        }
    }

    private static NativeViewportLoadBinding
        beginNativeViewportLoadInvocationLocked(
            Object viewModel,
            int page,
            String reason
        ) {
        Activity activity = activeActivity.get();
        if (!nativeViewportCallbackOwnsActiveReader(activity, viewModel)) {
            log("native_viewport_load_rejected "
                + "reason=inactive_view_model");
            return null;
        }
        if (page < 0) {
            clearNativeViewport(activity, "page_load_identity_unavailable");
            return null;
        }
        Object nativeMupdf = objectField(viewModel, "mupdf");
        if (nativeMupdf == null) {
            clearNativeViewport(activity, "page_load_identity_unavailable");
            return null;
        }
        final long requestSerial;
        synchronized (STATES) {
            ReaderState state = readerStateLocked(viewModel);
            // Never reuse an in-flight identity. Two overlapping requests for
            // the same logical page can carry different native fit/translation
            // geometry, so only the most recently initiated request may
            // publish its completion.
            state.nativeViewportRequestSerial++;
            requestSerial = state.nativeViewportRequestSerial;
        }
        long generation = beginNativeViewportPageLoad(
            viewModel,
            reason,
            false
        );
        NativeViewportLoadBinding binding =
            new NativeViewportLoadBinding(
                viewModel,
                nativeMupdf,
                page,
                requestSerial,
                generation
            );
        synchronized (STATES) {
            ReaderState state = readerStateLocked(viewModel);
            if (state.nativeViewportRequestSerial != requestSerial
                || objectField(viewModel, "mupdf") != nativeMupdf) {
                return null;
            }
            state.nativeViewportLoadBindings.put(
                Integer.valueOf(page),
                binding
            );
        }
        return binding;
    }

    private static NativeViewportLoadBinding bindNativeViewportTask(
        Object viewModel,
        int page
    ) {
        synchronized (NATIVE_VIEWPORT_LOAD_BINDING_LOCK) {
            return bindNativeViewportTaskLocked(viewModel, page);
        }
    }

    private static NativeViewportLoadBinding bindNativeViewportTaskLocked(
        Object viewModel,
        int page
    ) {
        if (viewModel == null || page < 0) {
            return null;
        }
        Object nativeMupdf = objectField(viewModel, "mupdf");
        if (nativeMupdf == null) {
            return null;
        }
        synchronized (STATES) {
            ReaderState state = readerStateLocked(viewModel);
            state.nativeViewportRequestSerial++;
            NativeViewportLoadBinding binding =
                new NativeViewportLoadBinding(
                    viewModel,
                    nativeMupdf,
                    page,
                    state.nativeViewportRequestSerial,
                    -1L
                );
            state.nativeViewportLoadBindings.put(
                Integer.valueOf(page),
                binding
            );
            return binding;
        }
    }

    private static NativeViewportLoadBinding completionBindingFor(
        Object viewModel,
        Object pageInfo
    ) {
        synchronized (NATIVE_VIEWPORT_LOAD_BINDING_LOCK) {
            return completionBindingForLocked(viewModel, pageInfo);
        }
    }

    private static NativeViewportLoadBinding completionBindingForLocked(
        Object viewModel,
        Object pageInfo
    ) {
        if (viewModel == null || pageInfo == null) {
            return null;
        }
        if (!nativeViewportCallbackOwnsActiveReader(
                activeActivity.get(),
                viewModel
            )) {
            return null;
        }
        NativeViewportLoadBinding binding =
            NATIVE_VIEWPORT_LOAD_INVOCATION.get();
        synchronized (STATES) {
            if (binding == null || binding.viewModel != viewModel) {
                binding = NATIVE_VIEWPORT_PAGE_INFO_BINDINGS.get(pageInfo);
            }
            ReaderState state = readerStateLocked(viewModel);
            Object liveNativeMupdf = objectField(viewModel, "mupdf");
            int livePage = intField(viewModel, "currentPage", -1);
            NativeViewportLoadBinding latest = binding == null ? null
                : state.nativeViewportLoadBindings.get(
                    Integer.valueOf(binding.page)
                );
            if (binding == null
                || latest == null
                || !NativeViewportCompletionAuthority.isCurrentRequest(
                    binding.viewModel,
                    binding.nativeMupdf,
                    binding.page,
                    binding.requestSerial,
                    viewModel,
                    liveNativeMupdf,
                    livePage,
                    latest.requestSerial
                )) {
                log("native_viewport_completion_rejected "
                    + "reason=unmatched_load_request");
                return null;
            }
            if (latest.pageLoadGeneration >= 0L) {
                return latest;
            }
        }

        // A load may have started before its manifest was verified. Only the
        // exact task/request binding may acquire the first provider generation
        // after verification; an older same-page callback cannot adopt it.
        long generation = beginNativeViewportPageLoad(
            viewModel,
            "verified_load_completion",
            false
        );
        if (generation < 0L) {
            // This callback was already proven to belong to the latest load
            // request. If verification has not published its manifest yet,
            // record only that this exact load finished. Do not grant provider
            // authority here. The verified manifest activation may then
            // synthesize one completion from the live PageInfo, while any
            // newer request restores the pending marker before activation.
            synchronized (STATES) {
                ReaderState state = readerStateLocked(viewModel);
                NativeViewportLoadBinding latest =
                    state.nativeViewportLoadBindings.get(
                        Integer.valueOf(binding.page)
                    );
                boolean exactCurrentRequest = latest != null
                    && NativeViewportCompletionAuthority.isCurrentRequest(
                        binding.viewModel,
                        binding.nativeMupdf,
                        binding.page,
                        binding.requestSerial,
                        viewModel,
                        objectField(viewModel, "mupdf"),
                        intField(viewModel, "currentPage", -1),
                        latest.requestSerial
                    );
                state.nativeViewportLoadPending =
                    NativeViewportLifecycleAuthority
                        .pendingAfterUnpublishedCompletion(
                            state.nativeViewportLoadPending,
                            exactCurrentRequest
                        );
                if (exactCurrentRequest) {
                    log("native_viewport_completion_deferred "
                        + "reason=manifest_verification_pending page="
                        + binding.page
                        + " request=" + binding.requestSerial);
                }
            }
            return null;
        }
        NativeViewportLoadBinding rebound = binding.withGeneration(generation);
        synchronized (STATES) {
            ReaderState state = readerStateLocked(viewModel);
            NativeViewportLoadBinding latest =
                state.nativeViewportLoadBindings.get(
                    Integer.valueOf(rebound.page)
                );
            if (!NativeViewportCompletionAuthority.isCurrentRequest(
                    rebound.viewModel,
                    rebound.nativeMupdf,
                    rebound.page,
                    rebound.requestSerial,
                    viewModel,
                    objectField(viewModel, "mupdf"),
                    intField(viewModel, "currentPage", -1),
                    latest == null ? -1L : latest.requestSerial
                )) {
                clearNativeViewportGeneration(
                    activeActivity.get(),
                    viewModel,
                    rebound.pageLoadGeneration,
                    "load_request_changed_before_binding"
                );
                return null;
            }
            state.nativeViewportLoadBindings.put(
                Integer.valueOf(rebound.page),
                rebound
            );
            NATIVE_VIEWPORT_PAGE_INFO_BINDINGS.put(pageInfo, rebound);
        }
        return rebound;
    }

    private static long beginNativeViewportPageLoad(
        Object viewModel,
        String reason,
        boolean manifestActivationInitialization
    ) {
        if (viewModel == null) {
            log("native_viewport_load_rejected "
                + "reason=page_load_view_model_unavailable");
            return -1L;
        }
        Activity activity = activeActivity.get();
        if (!nativeViewportCallbackOwnsActiveReader(activity, viewModel)) {
            log("native_viewport_load_rejected "
                + "reason=inactive_view_model");
            return -1L;
        }
        ReaderState state;
        synchronized (STATES) {
            state = readerStateLocked(viewModel);
            state.pageLoadGeneration++;
            state.nativeViewportLoadPending = true;
            boolean preserveDeferredLinkIntent = VirtualSpreadNavigation
                .pageLoadPreservesDeferredLinkIntent(
                    manifestActivationInitialization
                );
            if (!preserveDeferredLinkIntent) {
                clearQueuedLinkInvocation(state);
                state.mixedLinkCandidate = null;
            } else if (state.mixedLinkCandidate != null) {
                state.mixedLinkCandidate = state.mixedLinkCandidate
                    .withPageLoadGeneration(state.pageLoadGeneration);
            }
        }
        // Invalidate the provider record before manifest lookup can rebind
        // state or wait for replacement page geometry.
        clearNativeViewport(activity, "page_load_started");
        Manifest manifest = manifestFor(viewModel);
        if (manifest == null) {
            return -1L;
        }
        if (activity == null) {
            return -1L;
        }
        // Bind the verified manifest before choosing the publication
        // generation. A first activation can advance state while attaching
        // its verification generation; that intermediate value must never be
        // sent to the provider.
        stateFor(viewModel, manifest);
        final long generation;
        synchronized (STATES) {
            state = readerStateLocked(viewModel);
            state.pageLoadGeneration++;
            state.nativeViewportLoadPending = true;
            generation = state.pageLoadGeneration;
            boolean preserveDeferredLinkIntent = VirtualSpreadNavigation
                .pageLoadPreservesDeferredLinkIntent(
                    manifestActivationInitialization
                );
            if (!preserveDeferredLinkIntent) {
                clearQueuedLinkInvocation(state);
                state.mixedLinkCandidate = null;
            } else if (state.mixedLinkCandidate != null) {
                state.mixedLinkCandidate = state.mixedLinkCandidate
                    .withPageLoadGeneration(generation);
            }
        }
        try {
            Bundle request = new Bundle();
            request.putBinder("sessionToken", NATIVE_VIEWPORT_SESSION);
            request.putLong("pageLoadGeneration", generation);
            // The provider clears the prior record before acknowledging this
            // generation. Mark first so a lost Binder response is followed by
            // a best-effort clear instead of leaving ambiguous authority.
            nativeViewportMayBePublished = true;
            Bundle response = activity.getContentResolver().call(
                NativeViewportProvider.CONTENT_URI,
                NativeViewportProvider.METHOD_BEGIN_LOAD,
                null,
                request
            );
            if (response == null
                || !"begun".equals(response.getString("status"))
                || response.getLong("pageLoadGeneration", -1L)
                    != generation) {
                throw new IllegalStateException(
                    "viewport provider rejected page-load fence"
                );
            }
            log("native_viewport_load_begun generation=" + generation
                + " reason=" + reason);
        } catch (Throwable throwable) {
            clearNativeViewportGeneration(
                activity,
                viewModel,
                generation,
                "page_load_fence_failed"
            );
            logFailure("native_viewport_load_begin_failed", throwable);
        }
        return generation;
    }

    private static void handlePageLoaded(
        Object viewModel,
        boolean manifestActivationInitialization,
        NativeViewportCompletion completion
    ) {
        // An unbound callback is either stale or from a worker whose load
        // identity could not be proven. It must not clear a newer load's
        // pending flag or provider generation.
        if (completion == null) {
            log("native_viewport_completion_rejected "
                + "reason=unmatched_before_state");
            return;
        }
        Activity callbackOwner = activeActivity.get();
        if (!nativeViewportCallbackOwnsActiveReader(
                callbackOwner,
                viewModel
            )) {
            log("native_viewport_completion_rejected "
                + "reason=inactive_view_model");
            return;
        }
        ReaderState state;
        final long completedPageLoadGeneration;
        Object livePageInfo = objectField(viewModel, "pageInfo");
        synchronized (STATES) {
            state = readerStateLocked(viewModel);
            if (completion != null
                && !NativeViewportCompletionAuthority.isCurrent(
                    completion.viewModel,
                    completion.pageInfo,
                    completion.pageLoadGeneration,
                    viewModel,
                    livePageInfo,
                    state.pageLoadGeneration
                )) {
                log("native_viewport_completion_rejected reason=stale "
                    + "completion_generation="
                    + completion.pageLoadGeneration
                    + " current_generation="
                    + state.pageLoadGeneration);
                return;
            }
            state.nativeViewportLoadPending = false;
            completedPageLoadGeneration = completion.pageLoadGeneration;
            boolean preserveDeferredLinkIntent = VirtualSpreadNavigation
                .pageLoadPreservesDeferredLinkIntent(
                    manifestActivationInitialization
                );
            if (!preserveDeferredLinkIntent) {
                clearQueuedLinkInvocation(state);
                state.mixedLinkCandidate = null;
            } else if (state.mixedLinkCandidate != null) {
                state.mixedLinkCandidate = state.mixedLinkCandidate
                    .withPageLoadGeneration(state.pageLoadGeneration);
            }
        }
        Manifest manifest = manifestFor(viewModel);
        if (manifest == null) {
            clearNativeViewportGeneration(
                callbackOwner,
                viewModel,
                completedPageLoadGeneration,
                "manifest_unavailable"
            );
            return;
        }
        state = stateFor(viewModel, manifest);
        int currentPage = intField(viewModel, "currentPage", -1);
        long now = System.currentTimeMillis();
        long linkAge = now - state.pendingLinkAt;
        boolean hasLinkTarget = state.pendingLinkPage == currentPage
            && state.pendingLinkHalf != null
            && linkAge >= 0L
            && linkAge <= 60000L;
        boolean resetLandscapeFit = hasLinkTarget
            && state.pendingLinkResetLandscapeFit;
        long historyAge = now - state.pendingHistoryAt;
        boolean hasHistoryTarget = state.pendingHistoryPage == currentPage
            && state.pendingHistoryHalf != null
            && historyAge >= 0L
            && historyAge <= 60000L;
        VirtualSpreadNavigation.Half target;
        String targetReason;
        if (state.pendingPage == currentPage && state.pendingHalf != null) {
            target = state.pendingHalf;
            targetReason = "page_turn";
        } else if (hasHistoryTarget) {
            target = state.pendingHistoryHalf;
            targetReason = "native_link_history";
        } else if (hasLinkTarget) {
            target = state.pendingLinkHalf;
            targetReason = "internal_link";
        } else if (state.lastPage != currentPage) {
            target = firstHalf(manifest, currentPage);
            targetReason = "new_page";
        } else {
            target = state.half;
            targetReason = "existing_state";
        }
        if (hasLinkTarget
            && state.pendingLinkSourcePage >= 0
            && state.pendingLinkSourceHalf != null) {
            state.linkHistory.record(
                state.pendingLinkSourcePage,
                state.pendingLinkSourceHalf,
                currentPage
            );
            log("link_history_recorded source="
                + state.pendingLinkSourcePage
                + " target=" + currentPage
                + " half=" + state.pendingLinkSourceHalf);
        }
        state.pendingPage = -1;
        state.pendingHalf = null;
        clearPendingLink(state);
        clearPendingHistory(state);
        state.lastPage = currentPage;
        state.half = target;

        Activity activity = activeActivity.get();
        boolean portrait = isPortrait(activity);
        boolean internalLinkTarget = "internal_link".equals(targetReason);
        boolean retainedLinkViewport = "existing_state".equals(targetReason)
            && state.preservedLinkViewportPage == currentPage
            && state.preservedLinkViewportHalf == target;
        if (internalLinkTarget && !resetLandscapeFit) {
            state.preservedLinkViewportPage = currentPage;
            state.preservedLinkViewportHalf = target;
            retainedLinkViewport = true;
        } else if (!"existing_state".equals(targetReason)) {
            clearPreservedLinkViewport(state);
            retainedLinkViewport = false;
        }
        boolean preserveLinkViewport =
            VirtualSpreadNavigation.shouldPreservePortraitLinkViewport(
                internalLinkTarget,
                resetLandscapeFit,
                retainedLinkViewport
            );
        boolean resetSelectedLinkLandscapeFit =
            internalLinkTarget && resetLandscapeFit;
        if (portrait) {
            if (preserveLinkViewport) {
                log("portrait_link_view_preserved page=" + currentPage
                    + " half=" + target);
            } else {
                focusHalf(viewModel, target, "page_loaded");
                schedulePortraitFocus(viewModel, "page_loaded_retry");
            }
        } else if (resetSelectedLinkLandscapeFit) {
            scheduleConfigurationRefresh(
                activity,
                viewModel,
                "internal_link_fit_reset"
            );
        }
        log("page_loaded page=" + currentPage + " portrait="
            + portrait + " target_half=" + target
            + " reason=" + targetReason
            + " reset_landscape_fit=" + resetSelectedLinkLandscapeFit
            + " preserve_link_viewport=" + preserveLinkViewport);
        synchronized (STATES) {
            ReaderState currentState = readerStateLocked(viewModel);
            if (!NativeViewportCompletionAuthority.isCurrent(
                    completion.viewModel,
                    completion.pageInfo,
                    completion.pageLoadGeneration,
                    viewModel,
                    objectField(viewModel, "pageInfo"),
                    currentState.pageLoadGeneration
                )) {
                log("native_viewport_completion_rejected "
                    + "reason=changed_before_publication");
                return;
            }
        }
        publishNativeViewport(
            viewModel,
            manifest,
            state,
            currentPage,
            completedPageLoadGeneration,
            completion.pageInfo
        );
    }

    private static void publishNativeViewport(
        Object viewModel,
        Manifest manifest,
        ReaderState state,
        int currentPage,
        long completedPageLoadGeneration,
        Object completedPageInfo
    ) {
        Activity activity = activeActivity.get();
        if (activity == null || viewModel == null || manifest == null
            || state == null || currentPage < 0
            || currentPage >= manifest.pageCount) {
            clearNativeViewportGeneration(
                activity,
                viewModel,
                completedPageLoadGeneration,
                "publication_identity_unavailable"
            );
            return;
        }
        if (!nativeViewportCallbackOwnsActiveReader(activity, viewModel)) {
            log("native_viewport_publication_rejected "
                + "reason=inactive_view_model");
            return;
        }
        try {
            CachedManifest cached = MANIFESTS.get(manifest.key);
            Object nativeDocument = nativePdfDocument(viewModel);
            if (cached == null || cached.manifest != manifest
                || cached.nativeDocument != nativeDocument
                || cached.pdfIdentity == null
                || cached.sidecarIdentity == null
                || cached.verificationGeneration
                    != state.manifestVerificationGeneration) {
                throw new IllegalStateException(
                    "authenticated activation snapshot is unavailable"
                );
            }
            Object pageInfo = objectField(viewModel, "pageInfo");
            Object originBitmap = pageInfo == null ? null
                : XposedHelpers.callMethod(pageInfo, "getOriginBitmap");
            Object ctm = pageInfo == null ? null
                : XposedHelpers.callMethod(pageInfo, "getCtm");
            int loadedPage = intMethod(pageInfo, "getPage", -1);
            if (pageInfo == null || pageInfo != completedPageInfo
                || originBitmap == null || ctm == null
                || loadedPage != currentPage) {
                throw new IllegalStateException(
                    "native page geometry is not current"
                );
            }
            int width = ((Number) XposedHelpers.callMethod(
                originBitmap, "getWidth"
            )).intValue();
            int height = ((Number) XposedHelpers.callMethod(
                originBitmap, "getHeight"
            )).intValue();
            double[] pdfToOrigin = new double[] {
                floatField(ctm, "a", Float.NaN),
                floatField(ctm, "b", Float.NaN),
                floatField(ctm, "c", Float.NaN),
                floatField(ctm, "d", Float.NaN),
                floatField(ctm, "e", Float.NaN),
                floatField(ctm, "f", Float.NaN)
            };
            double offsetX = NativeViewportAuthority
                .requireNumericRenderOffset(
                    XposedHelpers.callMethod(pageInfo, "getOffsetX"),
                    "offsetX"
                );
            double offsetY = NativeViewportAuthority
                .requireNumericRenderOffset(
                    XposedHelpers.callMethod(pageInfo, "getOffsetY"),
                    "offsetY"
                );
            NativeViewportAuthority.Descriptor descriptor =
                NativeViewportAuthority.fromNativeRender(
                    manifest.documentId,
                    manifest.viewId,
                    currentPage,
                    manifest.pageWidth,
                    manifest.pageHeight,
                    width,
                    height,
                    width,
                    height,
                    pdfToOrigin,
                    offsetX,
                    offsetY
                );
            Bundle publication = new Bundle();
            publication.putString("documentId", descriptor.documentId);
            publication.putString("viewId", descriptor.viewId);
            publication.putInt(
                "virtualPageIndex", descriptor.virtualPageIndex
            );
            publication.putInt("nativeWidth", descriptor.nativeWidth);
            publication.putInt("nativeHeight", descriptor.nativeHeight);
            publication.putDoubleArray(
                "spreadToNative", descriptor.spreadToNative.clone()
            );
            publication.putString("documentPath", manifest.key);
            publication.putString("sidecarPath", manifest.key + ".json");
            publication.putString(
                "generatedPdfSha256", manifest.outputAuthority
            );
            publication.putString("sidecarSha256", manifest.revision);
            publication.putString(
                "mappingAuthoritySha256", manifest.mappingAuthority
            );
            int viewportProtocol = NativeViewportProtocol
                .versionForRepresentation(
                    manifest.schema,
                    manifest.generatorVersion,
                    manifest.navigationAuthority
                );
            if (viewportProtocol < 0) {
                throw new IllegalStateException(
                    "verified manifest has no viewport protocol"
                );
            }
            boolean navigationViewport = viewportProtocol == 2;
            if (navigationViewport) {
                publication.putString("manifestSchema", manifest.schema);
                publication.putString(
                    "generatorVersion", manifest.generatorVersion
                );
                publication.putString(
                    "navigationAuthoritySha256",
                    manifest.navigationAuthority
                );
            }
            publication.putString("snapshotId", cached.snapshotId());
            publication.putString(
                "pdfIdentity", cached.pdfIdentity.token()
            );
            publication.putString(
                "sidecarIdentity", cached.sidecarIdentity.token()
            );
            publication.putLong(
                "verificationGeneration", cached.verificationGeneration
            );
            publication.putLong(
                "pageLoadGeneration", completedPageLoadGeneration
            );
            publication.putBinder(
                "sessionToken", NATIVE_VIEWPORT_SESSION
            );
            // Mark before crossing the process boundary. If the provider
            // commits and the Binder response is lost, the failure path must
            // still attempt to clear that possibly published record.
            nativeViewportMayBePublished = true;
            Bundle response = activity.getContentResolver().call(
                navigationViewport
                    ? NativeViewportProvider.CONTENT_URI_V2
                    : NativeViewportProvider.CONTENT_URI,
                navigationViewport
                    ? NativeViewportProvider.METHOD_PUBLISH_V2
                    : NativeViewportProvider.METHOD_PUBLISH,
                null,
                publication
            );
            if (response == null
                || response.getInt("protocolVersion", -1)
                    != viewportProtocol
                || !"published".equals(response.getString("status"))) {
                throw new IllegalStateException(
                    "viewport provider rejected publication"
                );
            }
            log("native_viewport_published page=" + currentPage
                + " size=" + width + "x" + height
                + " descriptor_sha256="
                + response.getString("descriptorSha256")
                + " snapshot=" + cached.snapshotId()
                + " descriptor=" + descriptor.canonicalJson());
        } catch (Throwable throwable) {
            clearNativeViewportGeneration(
                activity,
                viewModel,
                completedPageLoadGeneration,
                "publication_failed"
            );
            logFailure("native_viewport_publish_failed", throwable);
        }
    }

    private static boolean nativeViewportCallbackOwnsActiveReader(
        Activity activity,
        Object viewModel
    ) {
        Object activeViewModel = activity == null ? null
            : objectField(activity, "documentViewModel");
        return NativeViewportLifecycleAuthority.callbackOwnsActiveReader(
            viewModel,
            activity,
            activeViewModel,
            activity != null && CREATING_ACTIVITY.get() == activity
        );
    }

    private static void releaseNativeViewportReaderState(Object viewModel) {
        if (viewModel == null) {
            return;
        }
        synchronized (NATIVE_VIEWPORT_LOAD_BINDING_LOCK) {
            synchronized (STATES) {
                STATES.remove(viewModel);
                removeNativeViewportBindingsForViewModel(
                    NATIVE_VIEWPORT_TASK_BINDINGS,
                    viewModel
                );
                removeNativeViewportBindingsForViewModel(
                    NATIVE_VIEWPORT_PAGE_INFO_BINDINGS,
                    viewModel
                );
            }
        }
        NativeViewportLoadBinding invocation =
            NATIVE_VIEWPORT_LOAD_INVOCATION.get();
        if (invocation != null && invocation.viewModel == viewModel) {
            NATIVE_VIEWPORT_LOAD_INVOCATION.remove();
        }
        NativeViewportCompletion completion =
            NATIVE_VIEWPORT_COMPLETION.get();
        if (completion != null && completion.viewModel == viewModel) {
            NATIVE_VIEWPORT_COMPLETION.remove();
        }
    }

    private static void removeNativeViewportBindingsForViewModel(
        Map<Object, NativeViewportLoadBinding> bindings,
        Object viewModel
    ) {
        Iterator<Map.Entry<Object, NativeViewportLoadBinding>> iterator =
            bindings.entrySet().iterator();
        while (iterator.hasNext()) {
            NativeViewportLoadBinding binding = iterator.next().getValue();
            if (binding != null && binding.viewModel == viewModel) {
                iterator.remove();
            }
        }
    }

    private static void clearNativeViewportGeneration(
        Activity activity,
        Object viewModel,
        long pageLoadGeneration,
        String reason
    ) {
        if (!nativeViewportCallbackOwnsActiveReader(activity, viewModel)) {
            log("native_viewport_generation_clear_skipped reason=" + reason
                + " ownership=inactive_view_model generation="
                + pageLoadGeneration);
            return;
        }
        if (pageLoadGeneration < 0L || !nativeViewportMayBePublished) {
            return;
        }
        try {
            Bundle request = new Bundle();
            request.putBinder("sessionToken", NATIVE_VIEWPORT_SESSION);
            request.putLong("pageLoadGeneration", pageLoadGeneration);
            Bundle response = activity.getContentResolver().call(
                NativeViewportProvider.CONTENT_URI,
                NativeViewportProvider.METHOD_CLEAR_GENERATION,
                null,
                request
            );
            if (response == null) {
                throw new IllegalStateException(
                    "viewport provider returned no generation-clear result"
                );
            }
            String status = response.getString("status");
            if ("cleared".equals(status)) {
                nativeViewportMayBePublished = false;
                log("native_viewport_cleared reason=" + reason
                    + " generation=" + pageLoadGeneration);
            } else if ("not_generation_owner".equals(status)) {
                log("native_viewport_generation_clear_skipped reason="
                    + reason + " ownership=newer_generation generation="
                    + pageLoadGeneration);
            } else {
                throw new IllegalStateException(
                    "viewport provider rejected generation clear"
                );
            }
        } catch (Throwable throwable) {
            logFailure(
                "native_viewport_generation_clear_failed reason=" + reason,
                throwable
            );
        }
    }

    private static void clearNativeViewport(
        Activity activity,
        String reason
    ) {
        if (activity == null || !nativeViewportMayBePublished) {
            return;
        }
        try {
            Bundle request = new Bundle();
            request.putBinder("sessionToken", NATIVE_VIEWPORT_SESSION);
            Bundle response = activity.getContentResolver().call(
                NativeViewportProvider.CONTENT_URI,
                NativeViewportProvider.METHOD_CLEAR,
                null,
                request
            );
            if (response == null
                || !"cleared".equals(response.getString("status"))) {
                throw new IllegalStateException(
                    "viewport provider rejected clear"
                );
            }
            nativeViewportMayBePublished = false;
            log("native_viewport_cleared reason=" + reason);
        } catch (Throwable throwable) {
            logFailure(
                "native_viewport_clear_failed reason=" + reason,
                throwable
            );
        }
    }

    private static void schedulePortraitFocus(
        final Object viewModel,
        final String reason
    ) {
        if (viewModel == null) {
            return;
        }
        if (hasPreservedLinkViewport(viewModel)) {
            log("portrait_focus_skipped "
                + "reason=preserved_link_viewport stage=schedule");
            return;
        }
        final Activity owner = activeActivity.get();
        if (owner == null) {
            return;
        }
        final Manifest scheduledManifest = manifestFor(viewModel);
        if (scheduledManifest == null) {
            return;
        }
        final ReaderState scheduledState = stateFor(
            viewModel,
            scheduledManifest
        );
        final long scheduledGeneration =
            scheduledState.pageLoadGeneration;
        final Handler handler = new Handler(owner.getMainLooper());
        final long[] delays = new long[] {0L, 120L, 360L};
        for (final long delay : delays) {
            handler.postDelayed(new Runnable() {
                @Override
                public void run() {
                    Activity activity = activeActivity.get();
                    if (activity != owner || !isPortrait(activity)) {
                        return;
                    }
                    Manifest manifest = manifestFor(viewModel);
                    if (manifest == null) {
                        return;
                    }
                    ReaderState state = stateFor(viewModel, manifest);
                    if (state != scheduledState
                        || state.pageLoadGeneration
                            != scheduledGeneration) {
                        log("portrait_focus_skipped reason=native_reload");
                        return;
                    }
                    int currentPage = intField(viewModel, "currentPage", -1);
                    if (hasPreservedLinkViewport(state, currentPage)) {
                        log("portrait_focus_skipped "
                            + "reason=preserved_link_viewport stage=retry");
                        return;
                    }
                    if (state.lastPage != currentPage) {
                        state.lastPage = currentPage;
                        state.half = firstHalf(manifest, currentPage);
                    }
                    focusHalf(
                        viewModel,
                        state.half,
                        reason + ":" + delay
                    );
                }
            }, delay);
        }
    }

    private static void scheduleConfigurationRefresh(
        final Activity owner,
        final Object viewModel,
        final String reason
    ) {
        if (owner == null || viewModel == null) {
            return;
        }
        final Manifest scheduledManifest = manifestFor(viewModel);
        if (scheduledManifest == null) {
            return;
        }
        final ReaderState scheduledState = stateFor(
            viewModel,
            scheduledManifest
        );
        final long scheduledGeneration =
            scheduledState.pageLoadGeneration;
        new Handler(owner.getMainLooper()).postDelayed(new Runnable() {
            @Override
            public void run() {
                Activity activity = activeActivity.get();
                if (activity != owner
                    || objectField(activity, "documentViewModel")
                        != viewModel) {
                    return;
                }
                Manifest currentManifest = manifestFor(viewModel);
                if (currentManifest == null) {
                    return;
                }
                ReaderState currentState = stateFor(
                    viewModel,
                    currentManifest
                );
                if (currentState != scheduledState
                    || currentState.pageLoadGeneration
                        != scheduledGeneration) {
                    log("orientation_refresh_skipped reason=native_reload");
                    return;
                }
                try {
                    XposedHelpers.callMethod(
                        owner,
                        "screenChange",
                        Boolean.TRUE
                    );
                    log("orientation_refresh orientation="
                        + (isPortrait(owner) ? "portrait" : "landscape")
                        + " page="
                        + intField(viewModel, "currentPage", -1)
                        + " reason=" + reason);
                } catch (Throwable throwable) {
                    logFailure(
                        "orientation_refresh_failed reason=" + reason,
                        throwable
                    );
                }
            }
        }, 180L);
    }

    private static boolean focusHalf(
        Object viewModel,
        VirtualSpreadNavigation.Half target,
        String reason
    ) {
        try {
            RectF showRect = (RectF) XposedHelpers.getObjectField(
                viewModel,
                "showRect"
            );
            Object pageInfo = XposedHelpers.getObjectField(
                viewModel,
                "pageInfo"
            );
            Object bitmap = pageInfo == null ? null
                : XposedHelpers.callMethod(pageInfo, "getOriginBitmap");
            if (showRect == null || bitmap == null) {
                return false;
            }
            int width = ((Integer) XposedHelpers.callMethod(
                bitmap,
                "getWidth"
            )).intValue();
            float dx = target == VirtualSpreadNavigation.Half.RIGHT
                ? width - showRect.right
                : -showRect.left;
            if (Math.abs(dx) < 0.5f) {
                return true;
            }
            XposedHelpers.callMethod(
                viewModel,
                "offsetShowRect",
                Float.valueOf(dx),
                Float.valueOf(0.0f)
            );
            log("portrait_focus page="
                + intField(viewModel, "currentPage", -1)
                + " half=" + target
                + " dx=" + dx
                + " reason=" + reason);
            return true;
        } catch (Throwable throwable) {
            logFailure("portrait_focus_failed reason=" + reason, throwable);
            return false;
        }
    }

    private static VirtualSpreadNavigation.Half detectHalf(
        Object viewModel,
        VirtualSpreadNavigation.Half fallback
    ) {
        try {
            RectF showRect = (RectF) XposedHelpers.getObjectField(
                viewModel,
                "showRect"
            );
            Object pageInfo = XposedHelpers.getObjectField(
                viewModel,
                "pageInfo"
            );
            Object bitmap = pageInfo == null ? null
                : XposedHelpers.callMethod(pageInfo, "getOriginBitmap");
            if (showRect == null || bitmap == null) {
                return fallback;
            }
            int width = ((Integer) XposedHelpers.callMethod(
                bitmap,
                "getWidth"
            )).intValue();
            return showRect.centerX() >= width / 2.0f
                ? VirtualSpreadNavigation.Half.RIGHT
                : VirtualSpreadNavigation.Half.LEFT;
        } catch (Throwable throwable) {
            return fallback;
        }
    }

    private static boolean saveNativeTrails(Activity activity) {
        Object presenter = null;
        try {
            presenter = XposedHelpers.getObjectField(
                activity,
                "handWritePresenter"
            );
            if (presenter == null) {
                return false;
            }
            boolean hadTrails = XposedHelpers.getBooleanField(
                presenter,
                "hasTrails"
            );
            if (!hadTrails) {
                return true;
            }
            Object note = objectField(presenter, "superNoteNote");
            int expectedPage = intField(presenter, "currentPage", -1);
            Object markPathValue = objectField(presenter, "markPath");
            String markPath = markPathValue instanceof String
                ? (String) markPathValue : null;
            if (note == null || expectedPage <= 0 || markPath == null) {
                log("native_save_rejected reason=missing_page_identity");
                return false;
            }
            SaveObservation observation = new SaveObservation(
                note,
                expectedPage,
                markPath
            );
            SAVE_OBSERVATION.set(observation);
            XposedHelpers.callMethod(
                presenter,
                "saveTrails",
                Boolean.FALSE,
                Boolean.FALSE
            );
            if (!observation.accepted()) {
                // saveTrails clears hasTrails even when native saveMarkData
                // reports failure. Restore dirty state so the user's ink is
                // not silently discarded by a later page load.
                XposedHelpers.setBooleanField(presenter, "hasTrails", true);
                log("native_save_rejected reason=missing_or_failed_ack"
                    + " expected_page=" + expectedPage
                    + " observed_page=" + observation.observedPage
                    + " callback=" + observation.callbackObserved
                    + " success=" + observation.callbackSucceeded);
                return false;
            }
            log("native_save_acknowledged page=" + expectedPage);
            return true;
        } catch (Throwable throwable) {
            if (presenter != null) {
                try {
                    XposedHelpers.setBooleanField(
                        presenter,
                        "hasTrails",
                        true
                    );
                } catch (Throwable ignored) {
                    // Preserve the original failure as the useful diagnostic.
                }
            }
            logFailure("native_save_failed", throwable);
            return false;
        } finally {
            SAVE_OBSERVATION.remove();
        }
    }

    private static void clearPendingLink(ReaderState state) {
        state.pendingLinkSourcePage = -1;
        state.pendingLinkSourceHalf = null;
        state.pendingLinkPage = -1;
        state.pendingLinkHalf = null;
        state.pendingLinkResetLandscapeFit = false;
        state.pendingLinkAt = 0L;
    }

    private static void clearQueuedLinkInvocation(Object viewModel) {
        if (viewModel == null) {
            return;
        }
        synchronized (STATES) {
            ReaderState state = STATES.get(viewModel);
            if (state != null) {
                clearQueuedLinkInvocation(state);
            }
        }
    }

    private static void clearQueuedLinkInvocation(ReaderState state) {
        state.queuedLinkArguments = null;
        state.queuedLinkDocumentPath = null;
        state.queuedLinkSnapshotId = null;
        state.queuedLinkVerificationGeneration = 0L;
        state.queuedLinkPageLoadGeneration = -1L;
        state.queuedLinkRouting = null;
        state.queuedLinkNativeDocument = null;
        state.queuedLinkNativeSourceAuthority = null;
        state.queuedLinkNativeLayoutAuthority = null;
        state.queuedLinkNativeLinkAuthority = null;
        state.queuedLinkNativeMappingAuthority = null;
        state.queuedLinkNativeViewId = null;
        state.queuedLinkNativeGeneratorVersion = null;
        state.queuedLinkObject = null;
        state.queuedLinkTargetPage = -1;
        state.queuedLinkDirectJump = false;
        state.queuedLinkSourcePage = -1;
        state.queuedLinkAt = 0L;
    }

    private static void clearMixedLinkCandidate(Object viewModel) {
        if (viewModel == null) {
            return;
        }
        synchronized (STATES) {
            ReaderState state = STATES.get(viewModel);
            if (state != null) {
                state.mixedLinkCandidate = null;
            }
        }
    }

    private static void noteReaderIntent(Object viewModel) {
        if (viewModel == null) {
            return;
        }
        synchronized (STATES) {
            noteReaderIntent(readerStateLocked(viewModel));
        }
    }

    private static void noteReaderIntent(ReaderState state) {
        synchronized (STATES) {
            state.intentGeneration++;
        }
    }

    private static void clearPendingHistory(ReaderState state) {
        state.pendingHistoryPage = -1;
        state.pendingHistoryHalf = null;
        state.pendingHistoryAt = 0L;
    }

    private static void clearPreservedLinkViewport(ReaderState state) {
        state.preservedLinkViewportPage = -1;
        state.preservedLinkViewportHalf = null;
    }

    private static boolean hasPreservedLinkViewport(Object viewModel) {
        Manifest manifest = manifestFor(viewModel);
        if (manifest == null) {
            return false;
        }
        ReaderState state = stateFor(viewModel, manifest);
        return hasPreservedLinkViewport(
            state,
            intField(viewModel, "currentPage", -1)
        );
    }

    private static boolean hasPreservedLinkViewport(
        ReaderState state,
        int currentPage
    ) {
        return currentPage >= 0
            && state.preservedLinkViewportPage == currentPage
            && state.preservedLinkViewportHalf != null
            && state.preservedLinkViewportHalf == state.half;
    }

    private static ReaderState readerStateLocked(Object viewModel) {
        ReaderState state = STATES.get(viewModel);
        if (state == null) {
            state = new ReaderState();
            STATES.put(viewModel, state);
        }
        return state;
    }

    private static String nativePdfMetadata(Object document, String key) {
        if (document == null) {
            return null;
        }
        try {
            Object value = XposedHelpers.callMethod(
                document,
                "getMetaData",
                "info:" + key
            );
            return value instanceof String ? (String) value : null;
        } catch (Throwable throwable) {
            return null;
        }
    }

    private static Object nativePdfDocument(Object viewModel) {
        Object nativeMupdf = objectField(viewModel, "mupdf");
        Object nativePdfMupdf = objectField(nativeMupdf, "pdfMupdf");
        return objectField(nativePdfMupdf, "document");
    }

    private static Boolean nativeSnapshotClaimsVirtualSpread(
        Object viewModel
    ) {
        Object nativeDocument = nativePdfDocument(viewModel);
        if (nativeDocument == null) {
            return null;
        }
        try {
            Object nativeSchema = XposedHelpers.callMethod(
                nativeDocument,
                "getMetaData",
                "info:SNVirtualSpreadSchema"
            );
            Object nativeSource = XposedHelpers.callMethod(
                nativeDocument,
                "getMetaData",
                "info:SNVirtualSpreadSourceSHA256"
            );
            Object nativeLayout = XposedHelpers.callMethod(
                nativeDocument,
                "getMetaData",
                "info:SNVirtualSpreadLayoutSHA256"
            );
            Object nativeLinks = XposedHelpers.callMethod(
                nativeDocument,
                "getMetaData",
                "info:SNVirtualSpreadLinksSHA256"
            );
            Object nativeMapping = XposedHelpers.callMethod(
                nativeDocument,
                "getMetaData",
                "info:SNVirtualSpreadMappingSHA256"
            );
            Object nativeNavigation = XposedHelpers.callMethod(
                nativeDocument,
                "getMetaData",
                "info:SNVirtualSpreadNavigationSHA256"
            );
            Object nativeViewId = XposedHelpers.callMethod(
                nativeDocument,
                "getMetaData",
                "info:SNVirtualSpreadViewID"
            );
            Object nativeGenerator = XposedHelpers.callMethod(
                nativeDocument,
                "getMetaData",
                "info:SNVirtualSpreadGeneratorVersion"
            );
            return Boolean.valueOf(
                VirtualSpreadNavigation.nativeMetadataClaimsVirtualSpread(
                    nativeSchema,
                    nativeSource,
                    nativeLayout,
                    nativeLinks,
                    nativeMapping,
                    nativeNavigation,
                    nativeViewId,
                    nativeGenerator
                )
            );
        } catch (Throwable throwable) {
            logFailure("native_snapshot_metadata_probe_failed", throwable);
            return null;
        }
    }

    private static Manifest validateNativeSnapshot(
        Object viewModel,
        Manifest manifest
    ) {
        if (manifest == null) {
            return null;
        }
        Object nativeMupdf = objectField(viewModel, "mupdf");
        if (nativeMupdf == null) {
            return null;
        }
        Object nativePdfMupdf = objectField(nativeMupdf, "pdfMupdf");
        Object nativeDocument = objectField(nativePdfMupdf, "document");
        if (nativeDocument == null) {
            return null;
        }
        synchronized (STATES) {
            ReaderState state = readerStateLocked(viewModel);
            if (state.nativeSnapshotDocument == nativeDocument
                && manifest.revision.equals(
                    state.nativeSnapshotRevision
                )) {
                return state.nativeSnapshotAccepted ? manifest : null;
            }
        }

        String nativeSchema = nativePdfMetadata(
            nativeDocument,
            "SNVirtualSpreadSchema"
        );
        String nativeSource = nativePdfMetadata(
            nativeDocument,
            "SNVirtualSpreadSourceSHA256"
        );
        String nativeLayout = nativePdfMetadata(
            nativeDocument,
            "SNVirtualSpreadLayoutSHA256"
        );
        String nativeLinks = nativePdfMetadata(
            nativeDocument,
            "SNVirtualSpreadLinksSHA256"
        );
        String nativeMapping = nativePdfMetadata(
            nativeDocument,
            "SNVirtualSpreadMappingSHA256"
        );
        String nativeNavigation = nativePdfMetadata(
            nativeDocument,
            "SNVirtualSpreadNavigationSHA256"
        );
        String nativeViewId = nativePdfMetadata(
            nativeDocument,
            "SNVirtualSpreadViewID"
        );
        String nativeGenerator = nativePdfMetadata(
            nativeDocument,
            "SNVirtualSpreadGeneratorVersion"
        );
        if (!manifest.schema.equals(nativeSchema)
            || !isSha256(nativeSource)
            || !isSha256(nativeLayout)
            || !isSha256(nativeLinks)
            || !isSha256(nativeMapping)
            || (manifest.navigationAuthority == null
                ? (nativeNavigation != null
                    && !nativeNavigation.trim().isEmpty())
                : !manifest.navigationAuthority.equals(nativeNavigation))
            || !manifest.viewId.equals(nativeViewId)
            || !manifest.generatorVersion.equals(nativeGenerator)) {
            log("manifest_rejected reason=native_snapshot_metadata path="
                + manifest.key);
            return null;
        }
        boolean accepted = VirtualSpreadNavigation
            .manifestMatchesNativeSnapshot(
                manifest.schema,
                manifest.sourceAuthority,
                manifest.layoutAuthority,
                manifest.linkAuthority,
                manifest.mappingAuthority,
                manifest.navigationAuthority,
                manifest.viewId,
                manifest.generatorVersion,
                nativeSchema,
                nativeSource,
                nativeLayout,
                nativeLinks,
                nativeMapping,
                nativeNavigation,
                nativeViewId,
                nativeGenerator
            );
        Object currentMupdf = objectField(viewModel, "mupdf");
        Object currentPdfMupdf = objectField(currentMupdf, "pdfMupdf");
        if (currentMupdf != nativeMupdf
            || objectField(currentPdfMupdf, "document") != nativeDocument) {
            return null;
        }
        synchronized (STATES) {
            ReaderState state = readerStateLocked(viewModel);
            state.nativeSnapshotDocument = nativeDocument;
            state.nativeSnapshotRevision = manifest.revision;
            state.nativeSnapshotAccepted = accepted;
        }
        log((accepted ? "native_snapshot_accepted" :
            "manifest_rejected reason=native_snapshot")
            + " path=" + manifest.key);
        return accepted ? manifest : null;
    }

    private static ReaderState stateFor(
        Object viewModel,
        Manifest manifest
    ) {
        bindReaderStateToDocument(viewModel, manifest.key);
        CachedManifest cached = MANIFESTS.get(manifest.key);
        long verificationGeneration = cached != null
            && cached.manifest == manifest
            && cached.nativeDocument == nativePdfDocument(viewModel)
                ? cached.verificationGeneration : 0L;
        synchronized (STATES) {
            ReaderState state = readerStateLocked(viewModel);
            if (!manifest.key.equals(state.manifestKey)
                || !manifest.revision.equals(state.manifestRevision)
                || state.manifestVerificationGeneration
                    != verificationGeneration) {
                state.manifestKey = manifest.key;
                state.manifestRevision = manifest.revision;
                state.manifestVerificationGeneration =
                    verificationGeneration;
                state.nativeViewportLoadPending =
                    NativeViewportLifecycleAuthority
                        .pendingAfterStateBinding(
                            state.nativeViewportLoadPending,
                            false
                        );
                clearManifestTransientState(
                    state,
                    false,
                    verificationGeneration
                );
            }
            return state;
        }
    }

    private static void clearManifestTransientState(
        ReaderState state,
        boolean clearQueuedLink,
        long bindingVerificationGeneration
    ) {
        MixedLinkCandidate retainedMixedLink = !clearQueuedLink
            && state.mixedLinkCandidate != null
            && VirtualSpreadNavigation
                .mixedLinkSurvivesVerificationBinding(
                    state.mixedLinkCandidate.verificationGeneration,
                    bindingVerificationGeneration
                )
                    ? state.mixedLinkCandidate : null;
        boolean rebindQueuedLink = !clearQueuedLink
            && state.queuedLinkArguments != null
            && VirtualSpreadNavigation
                .queuedLinkSurvivesVerificationBinding(
                    state.queuedLinkVerificationGeneration,
                    bindingVerificationGeneration
                );
        state.lastPage = -1;
        state.pendingPage = -1;
        state.pendingHalf = null;
        clearPendingLink(state);
        state.mixedLinkCandidate = null;
        clearPendingHistory(state);
        clearPreservedLinkViewport(state);
        if (clearQueuedLink) {
            clearQueuedLinkInvocation(state);
        }
        state.linkHistory.clear();
        state.half = VirtualSpreadNavigation.Half.RIGHT;
        // Never reset this counter: delayed work compares it to reject stale
        // callbacks, so reusing an earlier value would create an ABA window.
        state.pageLoadGeneration++;
        if (rebindQueuedLink) {
            state.queuedLinkPageLoadGeneration = state.pageLoadGeneration;
        }
        if (retainedMixedLink != null) {
            // Verification activation resets manifest-scoped state without a
            // native page change. Preserve the already-visible native menu,
            // but bind it to the new generation; all document/page/native-PDF
            // identity checks still run when Link is actually chosen.
            state.mixedLinkCandidate = retainedMixedLink
                .withPageLoadGeneration(state.pageLoadGeneration);
        }
    }

    private static void bindReaderStateToDocument(
        Object viewModel,
        String key
    ) {
        if (viewModel == null) {
            return;
        }
        synchronized (STATES) {
            ReaderState state = readerStateLocked(viewModel);
            if (sameDocumentKey(key, state.documentKey)) {
                return;
            }
            String previous = state.documentKey;
            state.documentKey = key;
            state.manifestKey = null;
            state.manifestRevision = null;
            state.manifestVerificationGeneration = 0L;
            state.nativeSnapshotDocument = null;
            state.nativeSnapshotRevision = null;
            state.nativeSnapshotAccepted = false;
            state.nativeViewportLoadPending =
                NativeViewportLifecycleAuthority.pendingAfterStateBinding(
                    state.nativeViewportLoadPending,
                    true
                );
            clearManifestTransientState(state, true, 0L);
            log("reader_state_document_changed from=" + previous
                + " to=" + key);
        }
    }

    private static VirtualSpreadNavigation.Half firstHalf(
        Manifest manifest,
        int page
    ) {
        if (page < 0 || page >= manifest.spreads.length) {
            return VirtualSpreadNavigation.Half.RIGHT;
        }
        return VirtualSpreadNavigation.firstReadableHalf(
            manifest.spreads[page]
        );
    }

    private static Manifest manifestFor(Object viewModel) {
        return manifestLookupFor(viewModel).manifest;
    }

    private static ManifestLookup unavailableManifestLookup(
        Object viewModel,
        String reason,
        String key
    ) {
        Boolean nativeAuthority = nativeSnapshotClaimsVirtualSpread(viewModel);
        boolean generatedDocumentBlocked = nativeAuthority == null
            || nativeAuthority.booleanValue();
        if (generatedDocumentBlocked) {
            log("manifest_unavailable reason=" + reason
                + " native_authority="
                + (nativeAuthority == null ? "unknown" : "present")
                + (key == null ? "" : " path=" + key));
        }
        return new ManifestLookup(
            null,
            false,
            generatedDocumentBlocked,
            null
        );
    }

    private static ManifestLookup supersededManifestLookup(String reason) {
        log("manifest_lookup_blocked reason=" + reason);
        return new ManifestLookup(
            null,
            false,
            true,
            null,
            0L,
            reason
        );
    }

    private static ManifestLookup rejectedManifestLookup(
        Object viewModel,
        String key,
        CachedManifest rejected,
        String reason
    ) {
        Boolean nativeAuthority = nativeSnapshotClaimsVirtualSpread(viewModel);
        boolean generatedDocumentBlocked = nativeAuthority == null
            || nativeAuthority.booleanValue();
        log("manifest_rejected_cached reason=" + reason
            + " native_authority="
            + (nativeAuthority == null ? "unknown" : "present")
            + " path=" + key);
        return new ManifestLookup(
            null,
            false,
            generatedDocumentBlocked,
            rejected.snapshotId()
        );
    }

    private static ManifestLookup manifestLookupFor(Object viewModel) {
        if (!hooksReady) {
            return new ManifestLookup(null, false, false, null);
        }
        if (viewModel == null) {
            Activity current = activeActivity.get();
            if (current == null
                || objectField(current, "documentViewModel") == null) {
                observeDocumentKey(null);
            }
            return new ManifestLookup(null, false, false, null);
        }
        try {
            Activity activity = activeActivity.get();
            if (activity != null
                && !nativeViewportCallbackOwnsActiveReader(
                    activity,
                    viewModel
                )) {
                log("manifest_lookup_skipped reason=stale_view_model");
                return supersededManifestLookup("stale_view_model");
            }
            Uri uri = (Uri) XposedHelpers.getObjectField(viewModel, "uri");
            if (uri == null || uri.getPath() == null) {
                bindReaderStateToDocument(viewModel, null);
                ManifestLookup unavailable = unavailableManifestLookup(
                    viewModel,
                    "missing_uri",
                    null
                );
                observeDocumentKey(null);
                return unavailable;
            }
            String key = lexicalAbsolutePath(uri.getPath());
            File pdf = new File(key);
            File sidecar = new File(pdf.getPath() + ".json");
            observeDocumentKey(key);
            bindReaderStateToDocument(viewModel, key);
            Object nativeDocument = nativePdfDocument(viewModel);
            Boolean nativeAuthority = nativeSnapshotClaimsVirtualSpread(
                viewModel
            );
            if (Boolean.FALSE.equals(nativeAuthority)) {
                // The live MuPDF object definitively has no virtual-spread
                // authority. Do not probe storage or consume the first native
                // turn/link/Back action of an ordinary PDF.
                MANIFESTS.remove(key);
                VERIFICATION_RETRY_AFTER.remove(key);
                return new ManifestLookup(null, false, false, null);
            }
            CachedManifest cached = MANIFESTS.get(key);
            if (cached != null && cached.nativeDocument == nativeDocument) {
                long freshnessAge = SystemClock.elapsedRealtime()
                    - cached.verifiedAtElapsed;
                if (freshnessAge < 0L
                    || freshnessAge > MAX_MANIFEST_FRESHNESS_AGE_MS) {
                    if (!MANIFESTS.remove(key, cached)) {
                        return supersededManifestLookup(
                            "manifest_cache_changed"
                        );
                    }
                    invalidateManifestState(
                        viewModel,
                        key,
                        cached,
                        -1L,
                        "freshness_lease_expired"
                    );
                    cached = null;
                    log("manifest_cache_expired path=" + key);
                } else if (freshnessAge
                        >= MANIFEST_FRESHNESS_INTERVAL_MS) {
                    scheduleManifestFreshness(
                        pdf,
                        sidecar,
                        key,
                        cached
                    );
                }
            }
            if (cached != null && cached.nativeDocument == nativeDocument) {
                if (cached.manifest == null) {
                    return rejectedManifestLookup(
                        viewModel,
                        key,
                        cached,
                        "stable_snapshot"
                    );
                }
                Manifest validated = validatePageCount(
                    viewModel,
                    validateNativeSnapshot(viewModel, cached.manifest)
                );
                // A valid sidecar/PDF pair must remain fail-closed when the
                // live MuPDF document still represents an older same-path
                // snapshot (or has not yet exposed a matching page count).
                return new ManifestLookup(
                    validated,
                    false,
                    validated == null,
                    cached.snapshotId(),
                    cached.verificationGeneration
                );
            }
            if (cached != null) {
                MANIFESTS.remove(key, cached);
            }
            Long retryAfter = VERIFICATION_RETRY_AFTER.get(key);
            long now = SystemClock.elapsedRealtime();
            if (retryAfter != null && retryAfter.longValue() > now) {
                return new ManifestLookup(
                    null,
                    true,
                    false,
                    "retry:" + retryAfter + ":" + key,
                    0L,
                    "manifest_retry_backoff"
                );
            }
            if (retryAfter != null) {
                VERIFICATION_RETRY_AFTER.remove(key, retryAfter);
            }
            VerificationOwner verificationOwner = scheduleManifestVerification(
                    pdf,
                    sidecar,
                    key,
                    nativeDocument
                );
            boolean verificationPending = verificationOwner != null;
            if (verificationPending) {
                discardQueuedLinkForDifferentSnapshot(
                    viewModel,
                    key,
                    verificationOwner.snapshotId
                );
                log("manifest_verification_pending path=" + key);
            } else {
                return supersededManifestLookup(
                    "manifest_verification_superseded"
                );
            }
            // Fail closed until the background verifier publishes a stable
            // PDF + sidecar snapshot into MANIFESTS.
            return new ManifestLookup(
                null,
                verificationPending,
                false,
                verificationOwner == null
                    ? null : verificationOwner.snapshotId,
                verificationOwner == null
                    ? 0L : verificationOwner.generation
            );
        } catch (Throwable throwable) {
            bindReaderStateToDocument(viewModel, null);
            ManifestLookup unavailable = unavailableManifestLookup(
                viewModel,
                "lookup_failed",
                null
            );
            observeDocumentKey(null);
            logFailure("manifest_read_failed", throwable);
            return unavailable;
        }
    }

    private static void discardQueuedLinkForDifferentSnapshot(
        Object viewModel,
        String key,
        String snapshotId
    ) {
        synchronized (STATES) {
            ReaderState state = STATES.get(viewModel);
            if (state != null && state.queuedLinkArguments != null
                && sameCanonicalPath(key, state.queuedLinkDocumentPath)
                && (state.queuedLinkSnapshotId == null
                    || !state.queuedLinkSnapshotId.equals(snapshotId))) {
                clearQueuedLinkInvocation(state);
                log("link_jump_discarded reason=document_snapshot_changed");
            }
        }
    }

    private static boolean sameDocumentKey(String first, String second) {
        return first == null ? second == null : first.equals(second);
    }

    private static void observeDocumentKey(String key) {
        synchronized (MANIFEST_VERIFIER_LOCK) {
            if (sameDocumentKey(key, observedDocumentKey)) {
                return;
            }
            observedDocumentKey = key;
            cancelManifestVerificationLocked();
            log("manifest_document_observed path=" + key);
        }
    }

    private static void cancelManifestVerificationLocked() {
        VERIFYING.clear();
        LATEST_VERIFICATION_OWNER.clear();
        FRESHNESS_CHECKING.clear();
        VERIFICATION_RETRY_AFTER.clear();
        Runnable stale;
        while ((stale = MANIFEST_VERIFIER.getQueue().poll()) != null) {
            if (stale instanceof ManifestVerificationTask) {
                ((ManifestVerificationTask) stale).cancelBeforeRun();
            } else if (stale instanceof ManifestFreshnessTask) {
                ((ManifestFreshnessTask) stale).cancelBeforeRun();
            }
        }
    }

    private static void scheduleManifestFreshnessWakeup(
        final String key,
        final CachedManifest expected
    ) {
        final Activity owner = activeActivity.get();
        if (owner == null) {
            return;
        }
        new Handler(owner.getMainLooper()).postDelayed(new Runnable() {
            @Override
            public void run() {
                Activity activity = activeActivity.get();
                if (activity != owner || owner.isFinishing()
                    || owner.isDestroyed()
                    || !sameDocumentKey(key, observedDocumentKey)
                    || MANIFESTS.get(key) != expected) {
                    return;
                }
                Object viewModel = objectField(
                    owner,
                    "documentViewModel"
                );
                if (nativePdfDocument(viewModel)
                    != expected.nativeDocument) {
                    return;
                }
                File pdf = new File(key);
                scheduleManifestFreshness(
                    pdf,
                    new File(key + ".json"),
                    key,
                    expected
                );
            }
        }, MANIFEST_FRESHNESS_INTERVAL_MS);
    }

    private static void scheduleManifestFreshness(
        File pdf,
        File sidecar,
        String key,
        CachedManifest expected
    ) {
        if (expected == null || expected.pdfIdentity == null
            || expected.sidecarIdentity == null
            || FRESHNESS_CHECKING.putIfAbsent(key, expected) != null) {
            return;
        }
        ManifestInvalidationToken invalidationToken =
            captureManifestInvalidationToken(key, expected);
        try {
            MANIFEST_VERIFIER.execute(new ManifestFreshnessTask(
                pdf,
                sidecar,
                key,
                expected,
                invalidationToken
            ));
        } catch (RuntimeException exception) {
            FRESHNESS_CHECKING.remove(key, expected);
            logFailure("manifest_freshness_schedule_failed", exception);
        }
    }

    private static void verifyManifestFreshness(
        File pdf,
        File sidecar,
        String key,
        CachedManifest expected,
        ManifestInvalidationToken invalidationToken
    ) {
        boolean invalidated = false;
        try {
            if (MANIFESTS.get(key) != expected
                || !sameDocumentKey(key, observedDocumentKey)) {
                return;
            }
            if (!key.equals(pdf.getCanonicalPath())
                || !(key + ".json").equals(sidecar.getCanonicalPath())) {
                throw new IllegalArgumentException(
                    "manifest paths must not use aliases"
                );
            }
            FileIdentity pdfCurrent = FileIdentity.captureRegularPath(pdf);
            FileIdentity sidecarCurrent =
                FileIdentity.captureRegularPath(sidecar);
            if (!expected.pdfIdentity.matches(pdfCurrent)
                || !expected.sidecarIdentity.matches(sidecarCurrent)) {
                throw new IllegalStateException(
                    "manifest filesystem generation changed"
                );
            }
            CachedManifest refreshed = expected.refreshed(
                SystemClock.elapsedRealtime()
            );
            if (MANIFESTS.replace(key, expected, refreshed)) {
                log("manifest_freshness_accepted path=" + key
                    + " snapshot=" + expected.snapshotId());
                if (refreshed.manifest != null) {
                    scheduleManifestFreshnessWakeup(key, refreshed);
                }
            }
        } catch (Throwable throwable) {
            invalidated = MANIFESTS.remove(key, expected);
            if (invalidated) {
                scheduleManifestStateInvalidation(
                    key,
                    expected,
                    invalidationToken,
                    "filesystem_generation_changed"
                );
                deferManifestRetry(key);
                logFailure("manifest_freshness_failed path=" + key, throwable);
            }
        } finally {
            FRESHNESS_CHECKING.remove(key, expected);
        }
    }

    private static void scheduleManifestStateInvalidation(
        final String key,
        final CachedManifest expected,
        final ManifestInvalidationToken token,
        final String reason
    ) {
        if (token == null || expected == null) {
            return;
        }
        new Handler(token.owner.getMainLooper()).post(new Runnable() {
            @Override
            public void run() {
                if (activeActivity.get() != token.owner) {
                    return;
                }
                Object viewModel = objectField(
                    token.owner,
                    "documentViewModel"
                );
                if (viewModel != token.viewModel) {
                    return;
                }
                invalidateManifestState(
                    viewModel,
                    key,
                    expected,
                    token.intentGeneration,
                    reason
                );
            }
        });
    }

    private static ManifestInvalidationToken
        captureManifestInvalidationToken(
            String key,
            CachedManifest expected
        ) {
        Activity owner = activeActivity.get();
        if (owner == null || expected == null) {
            return null;
        }
        Object viewModel = objectField(owner, "documentViewModel");
        synchronized (STATES) {
            ReaderState state = STATES.get(viewModel);
            if (state == null
                || !VirtualSpreadNavigation.manifestInvalidationMayClear(
                    sameDocumentKey(key, state.documentKey),
                    state.nativeSnapshotDocument == expected.nativeDocument,
                    state.manifestVerificationGeneration,
                    expected.verificationGeneration,
                    state.intentGeneration,
                    -1L
                )) {
                return null;
            }
            return new ManifestInvalidationToken(
                owner,
                viewModel,
                state.intentGeneration
            );
        }
    }

    private static boolean invalidateManifestState(
        Object viewModel,
        String key,
        CachedManifest expected,
        long expectedIntentGeneration,
        String reason
    ) {
        synchronized (STATES) {
            ReaderState state = STATES.get(viewModel);
            if (state == null
                || expected == null
                || !VirtualSpreadNavigation.manifestInvalidationMayClear(
                    sameDocumentKey(key, state.documentKey),
                    state.nativeSnapshotDocument == expected.nativeDocument,
                    state.manifestVerificationGeneration,
                    expected.verificationGeneration,
                    state.intentGeneration,
                    expectedIntentGeneration
                )) {
                log("manifest_state_invalidation_superseded reason=" + reason
                    + " snapshot="
                    + (expected == null ? "none" : expected.snapshotId())
                    + " path=" + key);
                return false;
            }
            state.manifestKey = null;
            state.manifestRevision = null;
            state.manifestVerificationGeneration = 0L;
            state.nativeSnapshotDocument = null;
            state.nativeSnapshotRevision = null;
            state.nativeSnapshotAccepted = false;
            clearManifestTransientState(state, true, 0L);
        }
        clearNativeViewport(activeActivity.get(), reason);
        log("manifest_state_invalidated reason=" + reason
            + " snapshot=" + expected.snapshotId()
            + " path=" + key);
        return true;
    }

    private static void deferManifestRetry(
        final String key
    ) {
        final long retryAt = SystemClock.elapsedRealtime()
            + MANIFEST_RETRY_BACKOFF_MS;
        final Activity owner = activeActivity.get();
        if (owner == null) {
            return;
        }
        final Long retryToken = Long.valueOf(retryAt);
        VERIFICATION_RETRY_AFTER.put(key, retryToken);
        new Handler(owner.getMainLooper()).postDelayed(new Runnable() {
            @Override
            public void run() {
                // Always retire this exact token first. Lifecycle or document
                // changes must not strand a path in the retry map. Retrying is
                // deliberately demand-driven: a later real reader action may
                // schedule verification after this short cooldown, while a
                // stable missing/denied sidecar cannot create an autonomous
                // verifier/logging loop.
                if (!VERIFICATION_RETRY_AFTER.remove(key, retryToken)) {
                    return;
                }
                if (activeActivity.get() != owner
                    || owner.isFinishing()
                    || owner.isDestroyed()
                    || !sameDocumentKey(key, observedDocumentKey)) {
                    return;
                }
                log("manifest_retry_ready path=" + key);
            }
        }, MANIFEST_RETRY_BACKOFF_MS);
    }

    /**
     * Returns the exact queued/running snapshot identity, or null when this
     * document no longer owns verification. A caller can therefore bind a
     * deferred native action to the same PDF/sidecar bytes without racing a
     * duplicate scheduling attempt that performs no additional work.
     */
    private static VerificationOwner scheduleManifestVerification(
        final File pdf,
        final File sidecar,
        final String key,
        final Object nativeDocument
    ) {
        synchronized (MANIFEST_VERIFIER_LOCK) {
            if (!key.equals(observedDocumentKey)) {
                return null;
            }
            VerificationOwner existing = VERIFYING.get(key);
            if (existing != null
                && existing.nativeDocument == nativeDocument) {
                return existing;
            }
            // Only the document most recently requested by the native reader
            // may remain current. Invalidate an active older verification and
            // retain at most one pending task behind it.
            cancelManifestVerificationLocked();
            long generation = VERIFICATION_GENERATION.incrementAndGet();
            VerificationOwner owner = new VerificationOwner(
                "request:" + generation + ":" + key,
                generation,
                nativeDocument
            );
            VERIFYING.put(key, owner);
            LATEST_VERIFICATION_OWNER.put(key, owner);
            try {
                MANIFEST_VERIFIER.execute(new ManifestVerificationTask(
                    pdf,
                    sidecar,
                    key,
                    owner
                ));
                return owner;
            } catch (RuntimeException exception) {
                VERIFYING.remove(key, owner);
                LATEST_VERIFICATION_OWNER.remove(key, owner);
                throw exception;
            }
        }
    }

    private static void requireCurrentVerification(
        String key,
        VerificationOwner owner
    ) throws ManifestVerificationSuperseded {
        if (VERIFYING.get(key) != owner) {
            throw new ManifestVerificationSuperseded();
        }
    }

    private static void verifyManifestSnapshot(
        File pdf,
        File sidecar,
        String key,
        VerificationOwner owner
    ) {
        try {
            requireCurrentVerification(key, owner);
            if (!key.equals(pdf.getCanonicalPath())
                || !(key + ".json").equals(sidecar.getCanonicalPath())) {
                throw new IllegalArgumentException(
                    "manifest paths must not use aliases"
                );
            }
            FileIdentity pdfBefore = FileIdentity.captureRegularPath(pdf);
            FileIdentity sidecarBefore = FileIdentity.captureRegularPath(
                sidecar
            );
            if (sidecarBefore.size < 0L
                || sidecarBefore.size > MAX_MANIFEST_BYTES) {
                throw new IllegalArgumentException("manifest is too large");
            }
            try (
                FileInputStream pdfInput = openRegularFile(
                    pdf,
                    pdfBefore
                );
                FileInputStream sidecarInput = openRegularFile(
                    sidecar,
                    sidecarBefore
                )
            ) {
                FileIdentity pdfOpened = FileIdentity.capture(pdfInput.getFD());
                FileIdentity sidecarOpened = FileIdentity.capture(
                    sidecarInput.getFD()
                );
                if (!pdfBefore.matches(pdfOpened)
                    || !sidecarBefore.matches(sidecarOpened)) {
                    scheduleQueuedLinkDiscard(
                        key,
                        owner,
                        "snapshot_changed_before_read"
                    );
                    log("manifest_rejected reason=snapshot_changed_before_read path="
                        + key);
                    return;
                }
                byte[] sidecarData = readBytes(
                    sidecarInput,
                    sidecarOpened.size
                );
                String sidecarDigest = sha256(sidecarData);
                String sidecarJson =
                    VirtualSpreadNavigation.decodeStrictUtf8(sidecarData);
                Manifest parsed;
                Throwable deterministicParseFailure = null;
                if (sidecarJson == null) {
                    log("manifest_rejected reason=invalid_utf8 path=" + key);
                    parsed = null;
                } else {
                    try {
                        parsed = parseManifest(
                            pdfInput,
                            pdfOpened.size,
                            sidecarJson,
                            key,
                            sidecarDigest,
                            owner
                        );
                    } catch (
                        org.json.JSONException | IllegalArgumentException error
                    ) {
                        // These exceptions are determined entirely by the
                        // authenticated JSON/authority bytes. Finish all
                        // descriptor and pathname checks below before caching
                        // the rejection for this exact stable snapshot.
                        deterministicParseFailure = error;
                        parsed = null;
                    }
                }
                String currentSidecarDigest = sha256(readBytes(
                    sidecarInput,
                    sidecarOpened.size
                ));
                FileIdentity pdfAfter = FileIdentity.capture(pdfInput.getFD());
                FileIdentity sidecarAfter = FileIdentity.capture(
                    sidecarInput.getFD()
                );
                FileIdentity pdfPathAfter = FileIdentity.captureRegularPath(
                    pdf
                );
                FileIdentity sidecarPathAfter =
                    FileIdentity.captureRegularPath(sidecar);
                if (!pdfOpened.matches(pdfAfter)
                    || !sidecarOpened.matches(sidecarAfter)
                    || !pdfAfter.matches(pdfPathAfter)
                    || !sidecarAfter.matches(sidecarPathAfter)
                    || !sidecarDigest.equals(currentSidecarDigest)
                    || !key.equals(pdf.getCanonicalPath())
                    || !(key + ".json").equals(sidecar.getCanonicalPath())) {
                    if (VERIFYING.get(key) == owner) {
                        MANIFESTS.remove(key);
                    }
                    scheduleQueuedLinkDiscard(
                        key,
                        owner,
                        "snapshot_changed_during_read"
                    );
                    log("manifest_rejected reason=snapshot_changed_during_read path="
                        + key);
                    return;
                }
                if (VERIFYING.get(key) == owner) {
                    CachedManifest published = new CachedManifest(
                        pdfAfter,
                        sidecarAfter,
                        sidecarDigest,
                        parsed,
                        owner.nativeDocument,
                        pdfAfter.token() + ":" + sidecarAfter.token(),
                        owner.generation,
                        SystemClock.elapsedRealtime()
                    );
                    MANIFESTS.put(key, published);
                    if (VERIFYING.get(key) != owner) {
                        MANIFESTS.remove(key, published);
                        return;
                    }
                    if (deterministicParseFailure != null) {
                        logFailure(
                            "manifest_rejected reason=deterministic_parse path="
                                + key,
                            deterministicParseFailure
                        );
                    }
                    if (parsed != null) {
                        VERIFICATION_RETRY_AFTER.remove(key);
                        log("manifest_accepted path=" + key
                            + " pages=" + parsed.pageCount);
                        scheduleManifestFreshnessWakeup(key, published);
                        scheduleManifestActivation(
                            key,
                            parsed.revision,
                            owner
                        );
                    } else {
                        scheduleQueuedLinkDiscard(
                            key,
                            owner,
                            "manifest_rejected"
                        );
                    }
                }
            }
        } catch (ManifestVerificationSuperseded superseded) {
            log("manifest_verification_superseded path=" + key);
        } catch (Throwable throwable) {
            if (VERIFYING.get(key) == owner) {
                // Availability and I/O failures are not authenticated
                // negative evidence. Leave them retryable instead of pinning
                // the native document to a synthetic rejected snapshot.
                MANIFESTS.remove(key);
                deferManifestRetry(key);
                scheduleQueuedLinkDiscard(
                    key,
                    owner,
                    "verification_failed"
                );
                logFailure("manifest_verification_failed", throwable);
            }
        } finally {
            VERIFYING.remove(key, owner);
        }
    }

    private static FileInputStream openRegularFile(
        File file,
        FileIdentity expected
    ) throws Exception {
        FileDescriptor descriptor = null;
        try {
            descriptor = Os.open(
                file.getPath(),
                OsConstants.O_RDONLY
                    | OsConstants.O_CLOEXEC
                    | OsConstants.O_NOFOLLOW
                    | OsConstants.O_NONBLOCK,
                0
            );
            StructStat opened = Os.fstat(descriptor);
            if (!OsConstants.S_ISREG(opened.st_mode)) {
                throw new IllegalArgumentException(
                    "manifest input is not a regular file"
                );
            }
            FileIdentity openedIdentity = FileIdentity.fromStat(opened);
            if (expected == null || !expected.matches(openedIdentity)) {
                throw new IllegalStateException(
                    "manifest input changed before opening"
                );
            }
            FileInputStream stream = new FileInputStream(descriptor);
            descriptor = null;
            return stream;
        } finally {
            if (descriptor != null) {
                Os.close(descriptor);
            }
        }
    }

    private static void scheduleManifestActivation(
        final String key,
        final String revision,
        final VerificationOwner verificationOwner
    ) {
        final Activity owner = activeActivity.get();
        if (owner == null) {
            return;
        }
        new Handler(owner.getMainLooper()).post(new Runnable() {
            @Override
            public void run() {
                Activity activity = activeActivity.get();
                if (activity != owner
                    || owner.isFinishing()
                    || owner.isDestroyed()) {
                    return;
                }
                Object viewModel = objectField(
                    owner,
                    "documentViewModel"
                );
                Manifest current = manifestFor(viewModel);
                if (current == null
                    || !key.equals(current.key)
                    || !revision.equals(current.revision)) {
                    return;
                }
                VerificationOwner latestOwner =
                    LATEST_VERIFICATION_OWNER.get(key);
                if (!VirtualSpreadNavigation
                    .manifestActivationBelongsToVerification(
                        latestOwner == null ? 0L : latestOwner.generation,
                        verificationOwner.generation,
                        latestOwner == verificationOwner
                            && latestOwner.nativeDocument
                                == verificationOwner.nativeDocument
                            && nativePdfDocument(viewModel)
                                == verificationOwner.nativeDocument
                    )) {
                    log("manifest_activation_superseded path=" + key
                        + " generation=" + verificationOwner.generation);
                    return;
                }
                VirtualSpreadNavigation.LinkRouting replayedRouting =
                    replayQueuedLink(
                        owner,
                        viewModel,
                        current,
                        verificationOwner
                    );
                boolean requiresInitialization =
                    manifestActivationRequiresInitialization(
                        viewModel,
                        current,
                        verificationOwner.generation
                    );
                if (VirtualSpreadNavigation
                        .replayRequiresImmediateInitialization(replayedRouting)
                    && requiresInitialization) {
                    handleManifestActivationInitialization(viewModel);
                    scheduleConfigurationRefresh(
                        owner,
                        viewModel,
                        "manifest_verified"
                    );
                } else if (replayedRouting
                        != VirtualSpreadNavigation.LinkRouting.INTERNAL
                    && !requiresInitialization) {
                    // MANIFESTS is published before this main-thread task is
                    // posted. A newer turn, link, or link-history action can
                    // bind the manifest and begin native loading first. Never
                    // synthesize page-loaded over that newer state.
                    log("manifest_activation_deferred reason="
                        + "newer_reader_state path=" + key);
                }
                if (replayedRouting
                        == VirtualSpreadNavigation.LinkRouting.EXTERNAL
                    || replayedRouting
                        == VirtualSpreadNavigation.LinkRouting.INTERNAL) {
                    log("manifest_activated path=" + key
                        + " revision=" + revision
                        + " queued_link=" + replayedRouting);
                    return;
                }
                log("manifest_activated path=" + key
                    + " revision=" + revision);
            }
        });
    }

    private static boolean manifestActivationRequiresInitialization(
        Object viewModel,
        Manifest manifest,
        long activationVerificationGeneration
    ) {
        synchronized (STATES) {
            ReaderState state = STATES.get(viewModel);
            boolean sameManifestKeyAndRevision = state != null
                && manifest != null
                && manifest.key.equals(state.manifestKey)
                && manifest.revision.equals(state.manifestRevision);
            return VirtualSpreadNavigation
                .manifestActivationRequiresInitialization(
                    sameManifestKeyAndRevision,
                    state == null ? 0L
                        : state.manifestVerificationGeneration,
                    activationVerificationGeneration,
                    state == null ? -1 : state.lastPage,
                    state == null ? -1 : state.pendingPage,
                    state != null && state.pendingHalf != null,
                    state == null ? -1 : state.pendingLinkPage,
                    state != null && state.pendingLinkHalf != null,
                    state == null ? -1 : state.pendingHistoryPage,
                    state != null && state.pendingHistoryHalf != null,
                    nativeViewportMayBePublished,
                    state != null && state.nativeViewportLoadPending
                );
        }
    }

    private static void scheduleQueuedLinkDiscard(
        final String key,
        final VerificationOwner verificationOwner,
        final String reason
    ) {
        final Activity owner = activeActivity.get();
        if (owner == null) {
            return;
        }
        new Handler(owner.getMainLooper()).post(new Runnable() {
            @Override
            public void run() {
                Activity activity = activeActivity.get();
                if (activity != owner) {
                    return;
                }
                Object viewModel = objectField(
                    owner,
                    "documentViewModel"
                );
                synchronized (STATES) {
                    ReaderState state = STATES.get(viewModel);
                    if (state == null || state.queuedLinkArguments == null
                        || !sameCanonicalPath(
                            key,
                            state.queuedLinkDocumentPath
                        )
                        || verificationOwner == null
                        || !verificationOwner.snapshotId.equals(
                            state.queuedLinkSnapshotId
                        )
                        || verificationOwner.generation
                            != state.queuedLinkVerificationGeneration) {
                        return;
                    }
                    clearQueuedLinkInvocation(state);
                }
                log("link_jump_discarded reason=" + reason);
            }
        });
    }

    private static Manifest validatePageCount(
        Object viewModel,
        Manifest manifest
    ) {
        if (manifest == null) {
            return null;
        }
        int nativePageCount = intField(viewModel, "pageCount", 0);
        if (nativePageCount <= 0
            || nativePageCount != manifest.pageCount) {
            log("manifest_rejected reason=page_count expected="
                + manifest.pageCount + " actual=" + nativePageCount);
            return null;
        }
        return manifest;
    }

    private static int expectedSourcePage(
        int virtualPage,
        boolean left,
        boolean coverSeparate,
        int sourcePageCount
    ) {
        if (coverSeparate && virtualPage == 0) {
            return left ? -1 : 0;
        }
        int firstVirtualPage = coverSeparate ? 1 : 0;
        int firstSourcePage = coverSeparate ? 1 : 0;
        int sourcePage = firstSourcePage
            + (virtualPage - firstVirtualPage) * 2
            + (left ? 1 : 0);
        return sourcePage >= 0 && sourcePage < sourcePageCount
            ? sourcePage : -1;
    }

    private static Integer exactManifestInteger(
        JSONObject object,
        String key
    ) {
        return object == null ? null
            : VirtualSpreadNavigation.exactJsonInteger(object.opt(key));
    }

    private static String exactManifestString(
        JSONObject object,
        String key
    ) {
        return VirtualSpreadNavigation.exactJsonString(
            object == null ? null : object.opt(key)
        );
    }

    private static boolean objectHasExactKeys(
        JSONObject object,
        String... expected
    ) {
        if (object == null) {
            return false;
        }
        Set<String> keys = new HashSet<>();
        Iterator<String> iterator = object.keys();
        while (iterator.hasNext()) {
            keys.add(iterator.next());
        }
        if (keys.size() != expected.length) {
            return false;
        }
        for (String key : expected) {
            if (!keys.contains(key)) {
                return false;
            }
        }
        return true;
    }

    private static double[] exactFiniteArray(
        JSONObject object,
        String key,
        int length
    ) {
        JSONArray values = object == null ? null : object.optJSONArray(key);
        if (values == null || values.length() != length) {
            return null;
        }
        double[] result = new double[length];
        for (int index = 0; index < length; index++) {
            Double value = VirtualSpreadNavigation.exactFiniteJsonNumber(
                values.opt(index)
            );
            if (value == null) {
                return null;
            }
            result[index] = value.doubleValue();
        }
        return result;
    }

    private static boolean unitColor(double[] values) {
        if (values == null || values.length != 3) {
            return false;
        }
        for (double value : values) {
            if (!Double.isFinite(value) || value < 0.0 || value > 1.0) {
                return false;
            }
        }
        return true;
    }

    private static void hookOutlineTarget(ClassLoader classLoader) {
        Class<?> outlineItemClass = XposedHelpers.findClass(
            "com.supernote.document.document.DocumentOutlineItem",
            classLoader
        );
        XposedHelpers.findAndHookMethod(
            TARGET_VIEW_MODEL,
            classLoader,
            "loadPage",
            outlineItemClass,
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    Object viewModel = param.thisObject;
                    Object item = param.args[0];
                    if (item == null) {
                        return;
                    }
                    // The outline tap is newer user intent than any link that
                    // was queued while manifest verification was cold. Clear
                    // those older actions before the lookup captures an
                    // invalidation token, then advance intent generation after
                    // lookup so a pending worker cannot erase this decision.
                    clearQueuedLinkInvocation(viewModel);
                    clearMixedLinkCandidate(viewModel);
                    ManifestLookup lookup = manifestLookupFor(viewModel);
                    if (lookup.manifest != null
                        || lookup.navigationBlocked()) {
                        noteReaderIntent(viewModel);
                    }
                    if (lookup.manifest == null) {
                        if (lookup.navigationBlocked()) {
                            param.setResult(null);
                            log("outline_jump_blocked reason=manifest_unavailable");
                        }
                        return;
                    }
                    int page = intMethod(item, "getPage", -1);
                    Object nativeOutline = XposedHelpers.callMethod(
                        item, "getOutline"
                    );
                    Object titleValue = nativeOutline == null ? null
                        : objectField(nativeOutline, "title");
                    String title = titleValue instanceof String
                        ? (String) titleValue : null;
                    OutlineTarget selected = null;
                    for (OutlineTarget target : lookup.manifest.outlines) {
                        if (target.virtualPage != page
                            || !sameText(target.title, title)) {
                            continue;
                        }
                        if (selected != null
                            && (selected.half != target.half
                                || selected.resetLandscapeFit
                                    != target.resetLandscapeFit)) {
                            param.setResult(null);
                            log("outline_jump_blocked reason=ambiguous_target"
                                + " page=" + page);
                            return;
                        }
                        selected = target;
                    }
                    if (selected == null) {
                        param.setResult(null);
                        log("outline_jump_blocked reason=unmatched_target"
                            + " page=" + page);
                        return;
                    }
                    ReaderState state = stateFor(viewModel, lookup.manifest);
                    clearPendingLink(state);
                    state.pendingLinkPage = selected.virtualPage;
                    state.pendingLinkHalf = selected.half;
                    state.pendingLinkResetLandscapeFit =
                        selected.resetLandscapeFit;
                    state.pendingLinkAt = System.currentTimeMillis();
                    noteReaderIntent(state);
                    log("outline_jump_captured page=" + selected.virtualPage
                        + " half=" + selected.half
                        + " fit=" + selected.resetLandscapeFit);
                }
            }
        );
    }

    private static NavigationData parseNavigation(
        JSONObject navigation,
        JSONObject output,
        int sourcePageCount,
        int outputPageCount,
        int retainedLinks,
        MappingRecord[] sourceMappings
    ) throws Exception {
        if (!objectHasExactKeys(
                navigation,
                "authority",
                "authoritySha256",
                "removeAdjacentPageLinks",
                "removedAdjacentPageLinkCount",
                "retainedLinkCount",
                "outlines"
            )
            || !"techrebbe.supernote.virtual-spread-navigation/v1".equals(
                exactManifestString(navigation, "authority")
            )) {
            return null;
        }
        String expected = exactManifestString(
            navigation, "authoritySha256"
        );
        String outputExpected = exactManifestString(
            output, "navigationAuthoritySha256"
        );
        Object removeValue = navigation.opt("removeAdjacentPageLinks");
        Integer removed = exactManifestInteger(
            navigation, "removedAdjacentPageLinkCount"
        );
        Integer retained = exactManifestInteger(
            navigation, "retainedLinkCount"
        );
        JSONArray array = navigation.optJSONArray("outlines");
        if (!isSha256(expected) || !expected.equals(outputExpected)
            || !(removeValue instanceof Boolean)
            || removed == null || retained == null || array == null
            || removed.intValue() < 0 || retained.intValue() < 0
            || (!((Boolean) removeValue).booleanValue()
                && removed.intValue() != 0)
            || retained.intValue() != retainedLinks) {
            return null;
        }
        ArrayList<String> records = new ArrayList<>();
        ArrayList<OutlineTarget> targets = new ArrayList<>();
        Map<String, Map<Integer, OutlineTarget>> outlineRoutes =
            new HashMap<>();
        for (int index = 0; index < array.length(); index++) {
            JSONObject item = array.optJSONObject(index);
            if (!objectHasExactKeys(
                    item,
                    "outlineIndex", "parentOutlineIndex", "title", "isOpen",
                    "bold", "italic", "color", "destination"
                )) {
                return null;
            }
            Integer outlineIndex = exactManifestInteger(item, "outlineIndex");
            Object parentValue = item.opt("parentOutlineIndex");
            Integer parent = parentValue == JSONObject.NULL
                ? null : VirtualSpreadNavigation.exactJsonInteger(parentValue);
            String title = exactManifestString(item, "title");
            Object openValue = item.opt("isOpen");
            Object boldValue = item.opt("bold");
            Object italicValue = item.opt("italic");
            double[] color = exactFiniteArray(item, "color", 3);
            if (outlineIndex == null || outlineIndex.intValue() != index
                || (parentValue != JSONObject.NULL && parent == null)
                || title == null || title.indexOf('\0') >= 0
                || !(openValue instanceof Boolean)
                || !(boldValue instanceof Boolean)
                || !(italicValue instanceof Boolean)
                || color == null
                || !unitColor(color)
                || (parent != null
                    && (parent.intValue() < 0
                        || parent.intValue() >= index))) {
                return null;
            }
            Object destinationValue = item.opt("destination");
            Integer sourcePage = null;
            Integer virtualPage = null;
            String side = null;
            String targetView = null;
            String mode = null;
            Double[] operands = null;
            if (destinationValue != JSONObject.NULL) {
                JSONObject destination = item.optJSONObject("destination");
                if (!objectHasExactKeys(
                        destination,
                        "sourcePageIndex", "virtualPageIndex", "side",
                        "targetView", "mode", "operands"
                    )) {
                    return null;
                }
                sourcePage = exactManifestInteger(
                    destination, "sourcePageIndex"
                );
                virtualPage = exactManifestInteger(
                    destination, "virtualPageIndex"
                );
                side = exactManifestString(destination, "side");
                targetView = exactManifestString(
                    destination, "targetView"
                );
                mode = exactManifestString(destination, "mode");
                JSONArray operandArray = destination.optJSONArray("operands");
                if (sourcePage == null || sourcePage.intValue() < 0
                    || sourcePage.intValue() >= sourcePageCount
                    || virtualPage == null
                    || virtualPage.intValue() < 0
                    || virtualPage.intValue() >= outputPageCount
                    || !("left".equals(side) || "right".equals(side))
                    || !"fit-source-page".equals(targetView)
                    || !"/FitR".equals(mode)
                    || operandArray == null) {
                    return null;
                }
                operands = new Double[operandArray.length()];
                for (int operand = 0; operand < operands.length; operand++) {
                    Object raw = operandArray.opt(operand);
                    if (raw == JSONObject.NULL) {
                        return null;
                    }
                    operands[operand] = VirtualSpreadNavigation
                        .exactFiniteJsonNumber(raw);
                    if (operands[operand] == null) {
                        return null;
                    }
                }
                if (operands.length != 4) {
                    return null;
                }
                if (sourcePage.intValue() >= sourceMappings.length) {
                    return null;
                }
                MappingRecord mapping = sourceMappings[
                    sourcePage.intValue()
                ];
                if (mapping == null
                    || !VirtualSpreadNavigation.outlineTargetMatchesMapping(
                        mapping.sourcePageIndex,
                        mapping.virtualPageIndex,
                        mapping.side,
                        mapping.destination,
                        sourcePage.intValue(),
                        virtualPage.intValue(),
                        side,
                        operands
                    )) {
                    return null;
                }
                VirtualSpreadNavigation.Half targetHalf =
                    "left".equals(side)
                        ? VirtualSpreadNavigation.Half.LEFT
                        : VirtualSpreadNavigation.Half.RIGHT;
                boolean resetLandscapeFit =
                    "fit-source-page".equals(targetView);
                Map<Integer, OutlineTarget> routesForTitle =
                    outlineRoutes.get(title);
                if (routesForTitle == null) {
                    routesForTitle = new HashMap<>();
                    outlineRoutes.put(title, routesForTitle);
                }
                OutlineTarget existing = routesForTitle.get(virtualPage);
                if (existing != null
                    && VirtualSpreadNavigation.outlineRouteConflicts(
                        existing.title,
                        existing.virtualPage,
                        existing.half,
                        existing.resetLandscapeFit,
                        title,
                        virtualPage.intValue(),
                        targetHalf,
                        resetLandscapeFit
                    )) {
                    return null;
                }
                OutlineTarget target = new OutlineTarget(
                    title,
                    virtualPage.intValue(),
                    targetHalf,
                    resetLandscapeFit
                );
                if (existing == null) {
                    routesForTitle.put(virtualPage, target);
                }
                targets.add(target);
            }
            records.add(VirtualSpreadNavigationAuthority.record(
                index,
                parent,
                title,
                ((Boolean) openValue).booleanValue(),
                ((Boolean) boldValue).booleanValue(),
                ((Boolean) italicValue).booleanValue(),
                color,
                sourcePage,
                virtualPage,
                side,
                targetView,
                mode,
                operands
            ));
        }
        if (!expected.equals(VirtualSpreadNavigationAuthority.digest(
            records.toArray(new String[records.size()]),
            ((Boolean) removeValue).booleanValue(),
            removed.intValue(),
            retained.intValue()
        ))) {
            return null;
        }
        return new NavigationData(
            expected,
            ((Boolean) removeValue).booleanValue(),
            removed.intValue(),
            retained.intValue(),
            targets.toArray(new OutlineTarget[targets.size()])
        );
    }

    private static boolean mappingHasFrozenFieldSet(JSONObject mapping) {
        String[] required = new String[] {
            "sourcePageIndex",
            "virtualPageIndex",
            "side",
            "sourceRotation",
            "sourceBox",
            "normalizedSourceBox",
            "slot",
            "destination",
            "scale",
            "transform"
        };
        if (mapping == null) {
            return false;
        }
        Set<String> allowed = new HashSet<>();
        for (String key : required) {
            allowed.add(key);
            if (!mapping.has(key)) {
                return false;
            }
        }
        allowed.add("sourcePageNumber");
        allowed.add("virtualPageNumber");
        Iterator<String> iterator = mapping.keys();
        while (iterator.hasNext()) {
            if (!allowed.contains(iterator.next())) {
                return false;
            }
        }
        return true;
    }

    private static boolean mappingPlacementMatches(
        int sourcePage,
        int virtualPage,
        String side,
        boolean coverSeparate
    ) {
        if (coverSeparate && sourcePage == 0) {
            return virtualPage == 0 && "right".equals(side);
        }
        int firstSourcePage = coverSeparate ? 1 : 0;
        int firstVirtualPage = coverSeparate ? 1 : 0;
        int offset = sourcePage - firstSourcePage;
        return offset >= 0
            && virtualPage == firstVirtualPage + offset / 2
            && (offset % 2 == 0 ? "right" : "left").equals(side);
    }

    private static MappingRecord parseMappingRecord(
        JSONObject mapping,
        int expectedSourcePage,
        boolean coverSeparate,
        double pageWidth,
        double pageHeight,
        double gutter
    ) {
        if (!mappingHasFrozenFieldSet(mapping)) {
            return null;
        }
        Integer sourcePageValue = exactManifestInteger(
            mapping, "sourcePageIndex"
        );
        Integer sourcePageNumber = mapping.has("sourcePageNumber")
            ? exactManifestInteger(mapping, "sourcePageNumber") : null;
        Integer virtualPageValue = exactManifestInteger(
            mapping, "virtualPageIndex"
        );
        Integer virtualPageNumber = mapping.has("virtualPageNumber")
            ? exactManifestInteger(mapping, "virtualPageNumber") : null;
        Integer rotationValue = exactManifestInteger(
            mapping, "sourceRotation"
        );
        Object sideValue = mapping.opt("side");
        if (sourcePageValue == null
            || (mapping.has("sourcePageNumber") && sourcePageNumber == null)
            || virtualPageValue == null
            || (mapping.has("virtualPageNumber") && virtualPageNumber == null)
            || rotationValue == null || !(sideValue instanceof String)) {
            return null;
        }
        int sourcePage = sourcePageValue.intValue();
        int virtualPage = virtualPageValue.intValue();
        int rotation = rotationValue.intValue();
        String side = (String) sideValue;
        if (sourcePage != expectedSourcePage
            || (sourcePageNumber != null
                && sourcePageNumber.intValue() != sourcePage + 1)
            || virtualPage < 0
            || (virtualPageNumber != null
                && virtualPageNumber.intValue() != virtualPage + 1)
            || !(rotation == 0 || rotation == 90
                || rotation == 180 || rotation == 270)
            || !("left".equals(side) || "right".equals(side))
            || !mappingPlacementMatches(
                sourcePage, virtualPage, side, coverSeparate)) {
            return null;
        }

        double[] sourceBox = exactFiniteArray(mapping, "sourceBox", 4);
        double[] normalizedSourceBox = exactFiniteArray(
            mapping, "normalizedSourceBox", 4
        );
        double[] slot = exactFiniteArray(mapping, "slot", 4);
        double[] destination = exactFiniteArray(
            mapping, "destination", 4
        );
        double[] transform = exactFiniteArray(mapping, "transform", 6);
        Double scaleValue = VirtualSpreadNavigation.exactFiniteJsonNumber(
            mapping.opt("scale")
        );
        if (scaleValue == null) {
            return null;
        }
        double scale = scaleValue.doubleValue();
        if (!VirtualSpreadNavigation.mappingGeometryIsValid(
                side,
                rotation,
                sourceBox,
                normalizedSourceBox,
                slot,
                destination,
                scale,
                transform,
                pageWidth,
                pageHeight,
                gutter
            )) {
            return null;
        }
        String canonical;
        try {
            canonical = VirtualSpreadLinkAuthority.mapping(
                sourcePage,
                virtualPage,
                side,
                rotation,
                sourceBox,
                normalizedSourceBox,
                slot,
                destination,
                scale,
                transform
            );
        } catch (RuntimeException error) {
            return null;
        }
        return new MappingRecord(
            sourcePage, virtualPage, side, destination, canonical
        );
    }

    private static boolean spreadEntryMatches(
        JSONObject spread,
        String side,
        int expectedSourcePage,
        int virtualPage,
        MappingRecord[] mappings,
        boolean coverSeparate,
        double pageWidth,
        double pageHeight,
        double gutter
    ) {
        if (!spread.has(side)) {
            return false;
        }
        if (expectedSourcePage < 0) {
            return spread.isNull(side);
        }
        MappingRecord parsed = parseMappingRecord(
            spread.optJSONObject(side),
            expectedSourcePage,
            coverSeparate,
            pageWidth,
            pageHeight,
            gutter
        );
        return parsed != null
            && parsed.virtualPageIndex == virtualPage
            && side.equals(parsed.side)
            && expectedSourcePage < mappings.length
            && mappings[expectedSourcePage] != null
            && parsed.canonical.equals(
                mappings[expectedSourcePage].canonical
            );
    }

    private static boolean linkEndpointMatches(
        MappingRecord[] sourcePages,
        int sourcePageIndex,
        int virtualPageIndex,
        String side
    ) {
        if (sourcePageIndex < 0
            || sourcePageIndex >= sourcePages.length
            || virtualPageIndex < 0
            || !("left".equals(side) || "right".equals(side))) {
            return false;
        }
        MappingRecord mapping = sourcePages[sourcePageIndex];
        return mapping != null
            && sourcePageIndex == mapping.sourcePageIndex
            && virtualPageIndex == mapping.virtualPageIndex
            && side.equals(mapping.side);
    }

    private static Manifest parseManifest(
        FileInputStream pdfInput,
        long pdfLength,
        String sidecarJson,
        String key,
        String sidecarDigest,
        VerificationOwner owner
    ) throws Exception {
        requireCurrentVerification(key, owner);
        if (!VirtualSpreadNavigation.jsonObjectHasUniqueKeys(sidecarJson)) {
            log("manifest_rejected reason=duplicate_or_invalid_json path="
                + key);
            return null;
        }
        JSONObject root = new JSONObject(sidecarJson);
        String manifestSchema = exactManifestString(root, "schema");
        String manifestGenerator = exactManifestString(
            root, "generatorVersion"
        );
        boolean navigationFormat = NAVIGATION_SCHEMA.equals(manifestSchema)
            && NAVIGATION_GENERATOR_VERSION.equals(manifestGenerator);
        boolean legacyFormat = SCHEMA.equals(manifestSchema)
            && GENERATOR_VERSION.equals(manifestGenerator);
        if (!(legacyFormat || navigationFormat)
            || !"rtl".equals(exactManifestString(root, "direction"))) {
            return null;
        }
        if (navigationFormat && !objectHasExactKeys(
                root,
                "schema", "source", "output", "generatorVersion",
                "direction", "coverSeparate", "spreads", "sourcePages",
                "links", "navigation"
            )) {
            log("manifest_rejected reason=navigation_root_fields path=" + key);
            return null;
        }
        Object coverValue = root.opt("coverSeparate");
        JSONObject source = root.optJSONObject("source");
        JSONObject output = root.optJSONObject("output");
        JSONArray spreadsJson = root.optJSONArray("spreads");
        JSONArray sourcePagesJson = root.optJSONArray("sourcePages");
        JSONArray linksJson = root.optJSONArray("links");
        if (!(coverValue instanceof Boolean)
            || source == null || output == null
            || spreadsJson == null || sourcePagesJson == null
            || linksJson == null) {
            log("manifest_rejected reason=manifest_shape path=" + key);
            return null;
        }
        boolean coverSeparate = ((Boolean) coverValue).booleanValue();
        Integer sourcePageCountValue = exactManifestInteger(
            source, "pageCount"
        );
        Integer pageCountValue = exactManifestInteger(output, "pageCount");
        Long expectedSizeValue = VirtualSpreadNavigation
            .exactNonnegativeJsonLong(output.opt("size"));
        if (sourcePageCountValue == null || pageCountValue == null
            || expectedSizeValue == null) {
            log("manifest_rejected reason=manifest_integer path=" + key);
            return null;
        }
        int sourcePageCount = sourcePageCountValue.intValue();
        int pageCount = pageCountValue.intValue();
        String expectedSourceAuthority = exactManifestString(source, "sha256");
        String expectedDocumentId = exactManifestString(source, "documentId");
        long expectedSize = expectedSizeValue.longValue();
        String expectedHash = exactManifestString(output, "sha256");
        if (expectedSize != pdfLength
            || pageCount <= 0
            || spreadsJson.length() != pageCount) {
            log("manifest_rejected reason=output_identity path=" + key);
            return null;
        }
        if (!isSha256(expectedHash)
            || !expectedHash.equals(
                sha256File(pdfInput, key, owner)
            )) {
            log("manifest_rejected reason=output_hash path=" + key);
            return null;
        }
        try {
            if (!VirtualSpreadLinkAuthority.documentId(
                    expectedSourceAuthority
                ).equals(expectedDocumentId)) {
                log("manifest_rejected reason=document_identity path=" + key);
                return null;
            }
        } catch (RuntimeException error) {
            log("manifest_rejected reason=document_identity path=" + key);
            return null;
        }
        requireCurrentVerification(key, owner);
        String embeddedSourceAuthority =
            VirtualSpreadLinkAuthority.readPdfSourceDigest(pdfInput);
        if (!isSha256(expectedSourceAuthority)
            || !expectedSourceAuthority.equals(
                embeddedSourceAuthority
            )) {
            log("manifest_rejected reason=source_authority path="
                + key);
            return null;
        }
        String expectedLinkAuthority = exactManifestString(
            output, "linkAuthoritySha256"
        );
        requireCurrentVerification(key, owner);
        String embeddedLinkAuthority =
            VirtualSpreadLinkAuthority.readPdfDigest(pdfInput);
        if (!isSha256(expectedLinkAuthority)
            || !expectedLinkAuthority.equals(embeddedLinkAuthority)) {
            log("manifest_rejected reason=link_authority path=" + key);
            return null;
        }
        String expectedLayoutAuthority = exactManifestString(
            output, "layoutAuthoritySha256"
        );
        requireCurrentVerification(key, owner);
        String embeddedLayoutAuthority =
            VirtualSpreadLinkAuthority.readPdfLayoutDigest(pdfInput);
        if (!isSha256(expectedLayoutAuthority)
            || !expectedLayoutAuthority.equals(embeddedLayoutAuthority)) {
            log("manifest_rejected reason=layout_authority path=" + key);
            return null;
        }
        String expectedMappingAuthority = exactManifestString(
            output, "mappingAuthoritySha256"
        );
        requireCurrentVerification(key, owner);
        String embeddedMappingAuthority =
            VirtualSpreadLinkAuthority.readPdfMappingDigest(pdfInput);
        if (!isSha256(expectedMappingAuthority)
            || !expectedMappingAuthority.equals(
                embeddedMappingAuthority
            )) {
            log("manifest_rejected reason=mapping_authority path=" + key);
            return null;
        }
        if (navigationFormat && (
                !objectHasExactKeys(
                    source,
                    "name", "path", "size", "sha256", "pageCount",
                    "documentId"
                )
                || !objectHasExactKeys(
                    output,
                    "name", "path", "size", "sha256", "pageCount",
                    "spreadSize", "gutter", "layoutAuthoritySha256",
                    "linkAuthoritySha256", "mappingAuthoritySha256",
                    "navigationAuthoritySha256", "viewId", "cacheBasename"
                ))) {
            log("manifest_rejected reason=navigation_identity_fields path="
                + key);
            return null;
        }
        JSONObject navigationJson = root.optJSONObject("navigation");
        String expectedNavigationAuthority = navigationFormat
            ? exactManifestString(output, "navigationAuthoritySha256")
            : null;
        requireCurrentVerification(key, owner);
        String embeddedNavigationAuthority =
            VirtualSpreadLinkAuthority.readPdfNavigationDigest(pdfInput);
        if (navigationFormat) {
            if (!isSha256(expectedNavigationAuthority)
                || !expectedNavigationAuthority.equals(
                    embeddedNavigationAuthority
                ) || navigationJson == null) {
                log("manifest_rejected reason=navigation_authority path=" + key);
                return null;
            }
        } else if (navigationJson != null
            || embeddedNavigationAuthority != null
            || output.has("navigationAuthoritySha256")) {
            log("manifest_rejected reason=legacy_navigation_state path=" + key);
            return null;
        }
        String expectedViewId = exactManifestString(output, "viewId");
        String expectedCacheBasename = exactManifestString(
            output, "cacheBasename"
        );
        if (expectedCacheBasename == null) {
            log("manifest_rejected reason=cache_basename path=" + key);
            return null;
        }
        requireCurrentVerification(key, owner);
        String embeddedViewDigest =
            VirtualSpreadLinkAuthority.readPdfViewDigest(pdfInput);
        if (expectedViewId == null
            || !expectedViewId.startsWith(VIEW_ID_PREFIX)
            || !isSha256(embeddedViewDigest)
            || !expectedViewId.substring(VIEW_ID_PREFIX.length()).equals(
                embeddedViewDigest
            )) {
            log("manifest_rejected reason=view_authority path=" + key);
            return null;
        }
        int firstSourcePage = coverSeparate ? 1 : 0;
        long expectedPageCount = (coverSeparate ? 1L : 0L)
            + (sourcePageCount - (long) firstSourcePage + 1L) / 2L;
        if (sourcePageCount <= 0
            || sourcePagesJson.length() != sourcePageCount
            || pageCount != expectedPageCount) {
            log("manifest_rejected reason=cover_layout path=" + key);
            return null;
        }
        JSONArray spreadSize = output.optJSONArray("spreadSize");
        if (spreadSize == null || spreadSize.length() != 2) {
            log("manifest_rejected reason=output_geometry path=" + key);
            return null;
        }
        Double pageWidthValue = VirtualSpreadNavigation
            .exactFiniteJsonNumber(spreadSize.opt(0));
        Double pageHeightValue = VirtualSpreadNavigation
            .exactFiniteJsonNumber(spreadSize.opt(1));
        Double gutterValue = VirtualSpreadNavigation
            .exactFiniteJsonNumber(output.opt("gutter"));
        if (pageWidthValue == null || pageHeightValue == null
            || gutterValue == null) {
            log("manifest_rejected reason=output_geometry path=" + key);
            return null;
        }
        double pageWidth = pageWidthValue.doubleValue();
        double pageHeight = pageHeightValue.doubleValue();
        double gutter = gutterValue.doubleValue();
        if (!VirtualSpreadNavigation.runtimeGeometryIsRepresentable(
                pageWidth, pageHeight, gutter)
            || !VirtualSpreadNavigation.nomadSpreadAspectIsSupported(
                pageWidth, pageHeight)) {
            log("manifest_rejected reason=output_geometry path=" + key);
            return null;
        }
        String actualLayoutAuthority = VirtualSpreadLinkAuthority.layoutDigest(
            VirtualSpreadLinkAuthority.layout(
                "rtl",
                coverSeparate,
                sourcePageCount,
                pageCount,
                pageWidth,
                pageHeight,
                gutter
            )
        );
        if (!expectedLayoutAuthority.equals(actualLayoutAuthority)) {
            log("manifest_rejected reason=layout_authority_records path=" + key);
            return null;
        }
        MappingRecord[] sourceMappings = new MappingRecord[sourcePageCount];
        ArrayList<String> mappingAuthorityRecords = new ArrayList<>();
        for (int index = 0; index < sourcePageCount; index++) {
            requireCurrentVerification(key, owner);
            MappingRecord mapping = parseMappingRecord(
                sourcePagesJson.optJSONObject(index),
                index,
                coverSeparate,
                pageWidth,
                pageHeight,
                gutter
            );
            if (mapping == null) {
                log("manifest_rejected reason=source_mapping index=" + index);
                return null;
            }
            sourceMappings[index] = mapping;
            mappingAuthorityRecords.add(mapping.canonical);
        }
        String actualMappingAuthority = VirtualSpreadLinkAuthority.mappingDigest(
            mappingAuthorityRecords.toArray(
                new String[mappingAuthorityRecords.size()]
            ));
        if (!expectedMappingAuthority.equals(actualMappingAuthority)) {
            log("manifest_rejected reason=mapping_authority_records path="
                + key);
            return null;
        }
        NavigationData navigationData = navigationFormat
            ? parseNavigation(
                navigationJson,
                output,
                sourcePageCount,
                pageCount,
                linksJson.length(),
                sourceMappings
            )
            : new NavigationData(
                null, false, 0, linksJson.length(), new OutlineTarget[0]
            );
        if (navigationData == null
            || (navigationFormat && !expectedNavigationAuthority.equals(
                navigationData.authority
            ))) {
            log("manifest_rejected reason=navigation_records path=" + key);
            return null;
        }
        String actualViewId;
        String actualCacheBasename;
        try {
            actualViewId = navigationFormat
                ? VirtualSpreadLinkAuthority.navigationViewId(
                    expectedSourceAuthority,
                    NAVIGATION_SCHEMA,
                    NAVIGATION_GENERATOR_VERSION,
                    "rtl",
                    coverSeparate,
                    pageWidth,
                    pageHeight,
                    gutter,
                    actualMappingAuthority,
                    navigationData.authority,
                    navigationData.removeAdjacentPageLinks
                )
                : VirtualSpreadLinkAuthority.viewId(
                    expectedSourceAuthority,
                    SCHEMA,
                    GENERATOR_VERSION,
                    "rtl",
                    coverSeparate,
                    pageWidth,
                    pageHeight,
                    gutter,
                    actualMappingAuthority
                );
            actualCacheBasename = VirtualSpreadLinkAuthority.outputBasename(
                expectedSourceAuthority,
                actualViewId
            );
        } catch (RuntimeException error) {
            log("manifest_rejected reason=view_identity path=" + key);
            return null;
        }
        if (!expectedViewId.equals(actualViewId)
            || !expectedCacheBasename.equals(actualCacheBasename)) {
            log("manifest_rejected reason=view_identity path=" + key);
            return null;
        }
        if (!expectedCacheBasename.equals(new File(key).getName())) {
            log("manifest_rejected reason=cache_basename_path path=" + key);
            return null;
        }
        VirtualSpreadNavigation.Spread[] spreads =
            new VirtualSpreadNavigation.Spread[pageCount];
        for (int index = 0; index < pageCount; index++) {
            requireCurrentVerification(key, owner);
            JSONObject spread = spreadsJson.optJSONObject(index);
            Integer spreadIndex = exactManifestInteger(
                spread, "virtualPageIndex"
            );
            Integer spreadNumber = exactManifestInteger(
                spread, "virtualPageNumber"
            );
            if (spreadIndex == null
                || spreadNumber == null
                || spreadIndex.intValue() != index
                || spreadNumber.intValue() != index + 1
                || !objectHasExactKeys(
                    spread,
                    "virtualPageIndex",
                    "virtualPageNumber",
                    "left",
                    "right"
                )) {
                log("manifest_rejected reason=spread_index index=" + index);
                return null;
            }
            int expectedLeft = expectedSourcePage(
                index, true, coverSeparate, sourcePageCount
            );
            int expectedRight = expectedSourcePage(
                index, false, coverSeparate, sourcePageCount
            );
            if (!spreadEntryMatches(
                    spread,
                    "left",
                    expectedLeft,
                    index,
                    sourceMappings,
                    coverSeparate,
                    pageWidth,
                    pageHeight,
                    gutter
                ) || !spreadEntryMatches(
                    spread,
                    "right",
                    expectedRight,
                    index,
                    sourceMappings,
                    coverSeparate,
                    pageWidth,
                    pageHeight,
                    gutter
                )) {
                log("manifest_rejected reason=cover_layout index=" + index);
                return null;
            }
            spreads[index] = new VirtualSpreadNavigation.Spread(
                expectedLeft >= 0,
                expectedRight >= 0
            );
        }
        ArrayList<VirtualSpreadNavigation.LinkTarget> links =
            new ArrayList<>();
        ArrayList<VirtualSpreadNavigation.UriTarget> uriLinks =
            new ArrayList<>();
        ArrayList<String> linkAuthorityRecords = new ArrayList<>();
        for (int index = 0; index < linksJson.length(); index++) {
            requireCurrentVerification(key, owner);
            JSONObject link = linksJson.optJSONObject(index);
            if (link == null) {
                log("manifest_rejected reason=link_record index=" + index);
                return null;
            }
            String kind = exactManifestString(link, "kind");
            if (!("internal".equals(kind) || "uri".equals(kind))) {
                log("manifest_rejected reason=link_record index=" + index);
                return null;
            }
            Integer sourceSourcePageValue = exactManifestInteger(
                link, "sourcePage"
            );
            Integer sourceOutputPageValue = exactManifestInteger(
                link, "outputPage"
            );
            if (sourceSourcePageValue == null
                || sourceOutputPageValue == null) {
                log("manifest_rejected reason=manifest_integer index=" + index);
                return null;
            }
            int sourceSourcePage = sourceSourcePageValue.intValue();
            int sourceOutputPage = sourceOutputPageValue.intValue();
            String sourceSide = exactManifestString(link, "sourceSide");
            JSONArray rect = link.optJSONArray("rect");
            if (sourceOutputPage < 0 || sourceOutputPage >= pageCount
                || rect == null || rect.length() != 4) {
                log("manifest_rejected reason=link_record index=" + index);
                return null;
            }
            if (!linkEndpointMatches(
                    sourceMappings,
                    sourceSourcePage,
                    sourceOutputPage,
                    sourceSide
                )) {
                log("manifest_rejected reason=link_mapping index=" + index);
                return null;
            }
            Double x0Value = VirtualSpreadNavigation
                .exactFiniteJsonNumber(rect.opt(0));
            Double y0Value = VirtualSpreadNavigation
                .exactFiniteJsonNumber(rect.opt(1));
            Double x1Value = VirtualSpreadNavigation
                .exactFiniteJsonNumber(rect.opt(2));
            Double y1Value = VirtualSpreadNavigation
                .exactFiniteJsonNumber(rect.opt(3));
            if (x0Value == null || y0Value == null
                || x1Value == null || y1Value == null) {
                log("manifest_rejected reason=link_rect index=" + index);
                return null;
            }
            double x0 = x0Value.doubleValue();
            double y0 = y0Value.doubleValue();
            double x1 = x1Value.doubleValue();
            double y1 = y1Value.doubleValue();
            if (!VirtualSpreadNavigation.runtimeRectIsRepresentable(
                    pageHeight, x0, y0, x1, y1)) {
                log("manifest_rejected reason=link_rect index=" + index);
                return null;
            }
            if ("uri".equals(kind)) {
                if (!(link.opt("uri") instanceof String)) {
                    log("manifest_rejected reason=link_record index=" + index);
                    return null;
                }
                String targetUri = (String) link.opt("uri");
                linkAuthorityRecords.add(VirtualSpreadLinkAuthority.uri(
                    sourceSourcePage,
                    sourceSide,
                    sourceOutputPage,
                    x0,
                    y0,
                    x1,
                    y1,
                    targetUri
                ));
                uriLinks.add(new VirtualSpreadNavigation.UriTarget(
                    sourceOutputPage,
                    "left".equals(sourceSide)
                        ? VirtualSpreadNavigation.Half.LEFT
                        : VirtualSpreadNavigation.Half.RIGHT,
                    targetUri,
                    (float) x0,
                    (float) y0,
                    (float) x1,
                    (float) y1
                ));
                continue;
            }
            Integer targetSourcePageValue = exactManifestInteger(
                link, "targetSourcePage"
            );
            Integer targetOutputPageValue = exactManifestInteger(
                link, "targetOutputPage"
            );
            if (targetSourcePageValue == null
                || targetOutputPageValue == null) {
                log("manifest_rejected reason=manifest_integer index=" + index);
                return null;
            }
            int targetSourcePage = targetSourcePageValue.intValue();
            int targetOutputPage = targetOutputPageValue.intValue();
            String targetSide = exactManifestString(link, "targetSide");
            Object targetViewValue = link.opt("targetView");
            if (!(targetViewValue instanceof String)) {
                log("manifest_rejected reason=link_record index=" + index);
                return null;
            }
            String targetView = (String) targetViewValue;
            if (!("preserve".equals(targetView)
                || "fit-source-page".equals(targetView))) {
                log("manifest_rejected reason=link_record index=" + index);
                return null;
            }
            if (targetOutputPage < 0 || targetOutputPage >= pageCount) {
                log("manifest_rejected reason=link_record index=" + index);
                return null;
            }
            if (!linkEndpointMatches(
                    sourceMappings,
                    targetSourcePage,
                    targetOutputPage,
                    targetSide
                )) {
                log("manifest_rejected reason=link_mapping index=" + index);
                return null;
            }
            linkAuthorityRecords.add(VirtualSpreadLinkAuthority.internal(
                sourceSourcePage,
                sourceSide,
                sourceOutputPage,
                x0,
                y0,
                x1,
                y1,
                targetSourcePage,
                targetOutputPage,
                targetSide,
                targetView
            ));
            VirtualSpreadNavigation.Half sourceHalf = "left".equals(
                sourceSide
            ) ? VirtualSpreadNavigation.Half.LEFT
                : VirtualSpreadNavigation.Half.RIGHT;
            links.add(new VirtualSpreadNavigation.LinkTarget(
                sourceOutputPage,
                targetOutputPage,
                sourceHalf,
                "left".equals(targetSide)
                    ? VirtualSpreadNavigation.Half.LEFT
                    : VirtualSpreadNavigation.Half.RIGHT,
                "fit-source-page".equals(targetView),
                (float) x0,
                (float) y0,
                (float) x1,
                (float) y1
            ));
        }
        String actualLinkAuthority = VirtualSpreadLinkAuthority.digest(
            linkAuthorityRecords.toArray(
                new String[linkAuthorityRecords.size()]
            )
        );
        if (!expectedLinkAuthority.equals(actualLinkAuthority)) {
            log("manifest_rejected reason=link_authority_records path=" + key);
            return null;
        }
        requireCurrentVerification(key, owner);
        return new Manifest(
            key,
            sidecarDigest,
            manifestSchema,
            expectedSourceAuthority,
            expectedDocumentId,
            expectedHash,
            expectedLayoutAuthority,
            expectedLinkAuthority,
            expectedMappingAuthority,
            navigationData.authority,
            expectedViewId,
            expectedCacheBasename,
            manifestGenerator,
            pageCount,
            spreads,
            pageWidth,
            pageHeight,
            links.toArray(new VirtualSpreadNavigation.LinkTarget[links.size()]),
            uriLinks.toArray(
                new VirtualSpreadNavigation.UriTarget[uriLinks.size()]
            ),
            navigationData.outlines
        );
    }


    private static byte[] readBytes(
        FileInputStream input,
        long length
    ) throws Exception {
        if (length < 0L || length > MAX_MANIFEST_BYTES) {
            throw new IllegalArgumentException("manifest is too large");
        }
        byte[] data = new byte[(int) length];
        input.getChannel().position(0L);
        try {
            int offset = 0;
            while (offset < data.length) {
                int count = input.read(data, offset, data.length - offset);
                if (count < 0) {
                    break;
                }
                offset += count;
            }
            if (offset != data.length) {
                throw new IllegalStateException("short manifest read");
            }
            if (input.read() >= 0) {
                throw new IllegalStateException("long manifest read");
            }
        } finally {
            input.getChannel().position(0L);
        }
        return data;
    }

    private static String sha256(byte[] data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(data);
        return toHex(digest.digest());
    }

    private static String sha256File(
        FileInputStream input,
        String key,
        VerificationOwner owner
    ) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        FileChannel channel = input.getChannel();
        long originalPosition = channel.position();
        long expectedSize = channel.size();
        try {
            channel.position(0L);
            byte[] buffer = new byte[64 * 1024];
            long remaining = expectedSize;
            while (remaining > 0L) {
                requireCurrentVerification(key, owner);
                int count = input.read(
                    buffer,
                    0,
                    (int) Math.min((long) buffer.length, remaining)
                );
                if (count < 0) {
                    throw new IllegalStateException("short PDF read");
                }
                if (count > 0) {
                    digest.update(buffer, 0, count);
                    remaining -= count;
                }
            }
            if (input.read() >= 0) {
                throw new IllegalStateException("long PDF read");
            }
        } finally {
            channel.position(originalPosition);
        }
        return toHex(digest.digest());
    }

    private static String toHex(byte[] value) {
        final char[] digits = "0123456789abcdef".toCharArray();
        char[] output = new char[value.length * 2];
        for (int index = 0; index < value.length; index++) {
            int current = value[index] & 0xff;
            output[index * 2] = digits[current >>> 4];
            output[index * 2 + 1] = digits[current & 0x0f];
        }
        return new String(output);
    }

    private static boolean isSha256(String value) {
        if (value == null || value.length() != 64) {
            return false;
        }
        for (int index = 0; index < value.length(); index++) {
            char current = value.charAt(index);
            if (!((current >= '0' && current <= '9')
                    || (current >= 'a' && current <= 'f'))) {
                return false;
            }
        }
        return true;
    }

    private static boolean isPortrait(Activity activity) {
        return activity != null
            && activity.getResources().getConfiguration().orientation
                == Configuration.ORIENTATION_PORTRAIT;
    }

    private static boolean compatibleFirmware() {
        return TARGET_FINGERPRINT.equals(Build.FINGERPRINT)
            && new File(TARGET_DOCUMENT_APK).length()
                == TARGET_DOCUMENT_APK_LENGTH;
    }

    private static Object objectField(Object owner, String name) {
        if (owner == null) {
            return null;
        }
        try {
            return XposedHelpers.getObjectField(owner, name);
        } catch (Throwable throwable) {
            return null;
        }
    }

    private static int intField(Object owner, String name, int fallback) {
        try {
            return XposedHelpers.getIntField(owner, name);
        } catch (Throwable throwable) {
            return fallback;
        }
    }

    private static float floatField(
        Object owner,
        String name,
        float fallback
    ) {
        try {
            Object value = XposedHelpers.getObjectField(owner, name);
            return value instanceof Number
                ? ((Number) value).floatValue()
                : fallback;
        } catch (Throwable throwable) {
            return fallback;
        }
    }

    private static int intMethod(
        Object owner,
        String name,
        int fallback
    ) {
        try {
            Object value = XposedHelpers.callMethod(owner, name);
            return value instanceof Number
                ? ((Number) value).intValue() : fallback;
        } catch (Throwable throwable) {
            return fallback;
        }
    }

    private static String stringMethod(Object owner, String name) {
        try {
            Object value = XposedHelpers.callMethod(owner, name);
            return value instanceof String ? (String) value : null;
        } catch (Throwable throwable) {
            return null;
        }
    }

    private static boolean sameCanonicalPath(
        String expected,
        String candidate
    ) {
        if (expected == null || candidate == null) {
            return false;
        }
        try {
            // Reader callbacks may run on the UI thread. Keep comparison
            // lexical here; the verifier separately rejects aliases and
            // symlinks after opening exact descriptors on its worker.
            return lexicalAbsolutePath(expected).equals(
                lexicalAbsolutePath(candidate)
            );
        } catch (Throwable throwable) {
            return false;
        }
    }

    private static String lexicalAbsolutePath(String path) {
        return new File(path)
            .getAbsoluteFile()
            .toPath()
            .normalize()
            .toString();
    }

    private static boolean sameText(String first, String second) {
        return first == null ? second == null : first.equals(second);
    }

    private static void log(String message) {
        Log.i(TAG, message);
        XposedBridge.log(TAG + " " + message);
    }

    private static void logFailure(String prefix, Throwable throwable) {
        log(prefix + " " + throwable);
        XposedBridge.log(throwable);
    }
}
