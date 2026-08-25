package com.techrebbe.supernote.virtualspread;

import android.app.Activity;
import android.content.res.Configuration;
import android.graphics.RectF;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.system.Os;
import android.system.StructStat;
import android.util.Log;

import java.io.File;
import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.RandomAccessFile;
import java.lang.ref.WeakReference;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Map;
import java.util.WeakHashMap;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

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
    private static final String TARGET_PAGE_BAR =
        "com.ratta.supernote.supernotetoolbarlib.PageBarView";
    private static final String TARGET_BACK_LINK =
        "com.supernote.document.utils.BackLinkUtils";
    private static final String TARGET_FINGERPRINT =
        "Supernote/Supernote/Supernote:11/RQ2A.210505.003/eng.supern.20260616.100032:user/release-keys";
    private static final String TARGET_DOCUMENT_APK =
        "/system_ext/app/SupernoteDocument/SupernoteDocument.apk";
    private static final long TARGET_DOCUMENT_APK_LENGTH = 138486560L;
    private static final String SCHEMA =
        "techrebbe.supernote.virtual-spread/v1";
    private static final String TAG = "SN_VIRTUAL_SPREAD";
    private static final String VERSION = "0.0.23";
    private static final long MAX_MANIFEST_BYTES = 8L * 1024L * 1024L;
    private static final int MAX_CACHED_MANIFESTS = 4;

    private static volatile WeakReference<Activity> activeActivity =
        new WeakReference<>(null);
    private static final Map<Object, ReaderState> STATES =
        new WeakHashMap<>();
    private static final VirtualSpreadNavigation.BoundedCache<
        String,
        CachedManifest
    > MANIFESTS = new VirtualSpreadNavigation.BoundedCache<>(
        MAX_CACHED_MANIFESTS
    );
    private static final Map<String, String> VERIFYING =
        new ConcurrentHashMap<>();
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

    private static final class Manifest {
        final String key;
        final String revision;
        final String sourceAuthority;
        final String layoutAuthority;
        final String linkAuthority;
        final int pageCount;
        final VirtualSpreadNavigation.Spread[] spreads;
        final float pageHeight;
        final VirtualSpreadNavigation.LinkTarget[] links;

        Manifest(
            String key,
            String revision,
            String sourceAuthority,
            String layoutAuthority,
            String linkAuthority,
            int pageCount,
            VirtualSpreadNavigation.Spread[] spreads,
            float pageHeight,
            VirtualSpreadNavigation.LinkTarget[] links
        ) {
            this.key = key;
            this.revision = revision;
            this.sourceAuthority = sourceAuthority;
            this.layoutAuthority = layoutAuthority;
            this.linkAuthority = linkAuthority;
            this.pageCount = pageCount;
            this.spreads = spreads;
            this.pageHeight = pageHeight;
            this.links = links;
        }
    }

    private static final class ManifestLookup {
        final Manifest manifest;
        final boolean verificationPending;

        ManifestLookup(Manifest manifest, boolean verificationPending) {
            this.manifest = manifest;
            this.verificationPending = verificationPending;
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

        static FileIdentity capture(File file) throws Exception {
            return fromStat(Os.stat(file.getPath()));
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

        CachedManifest(
            FileIdentity pdfIdentity,
            FileIdentity sidecarIdentity,
            String sidecarDigest,
            Manifest manifest
        ) {
            this.pdfIdentity = pdfIdentity;
            this.sidecarIdentity = sidecarIdentity;
            this.sidecarDigest = sidecarDigest;
            this.manifest = manifest;
        }

        boolean matches(FileIdentity pdf, FileIdentity sidecar) {
            return pdfIdentity.matches(pdf)
                && sidecarIdentity.matches(sidecar);
        }
    }

    private static final class ManifestVerificationTask implements Runnable {
        final File pdf;
        final File sidecar;
        final String key;
        final FileIdentity pdfBefore;
        final FileIdentity sidecarBefore;
        final String verificationId;

        ManifestVerificationTask(
            File pdf,
            File sidecar,
            String key,
            FileIdentity pdfBefore,
            FileIdentity sidecarBefore,
            String verificationId
        ) {
            this.pdf = pdf;
            this.sidecar = sidecar;
            this.key = key;
            this.pdfBefore = pdfBefore;
            this.sidecarBefore = sidecarBefore;
            this.verificationId = verificationId;
        }

        @Override
        public void run() {
            verifyManifestSnapshot(
                pdf,
                sidecar,
                key,
                pdfBefore,
                sidecarBefore,
                verificationId
            );
        }

        void cancelBeforeRun() {
            VERIFYING.remove(key, verificationId);
            log("manifest_verification_superseded path=" + key);
        }
    }

    private static final class ManifestVerificationSuperseded
        extends Exception {
        private static final long serialVersionUID = 1L;
    }

    private static final class ReaderState {
        Object nativeSnapshotDocument;
        String nativeSnapshotRevision;
        boolean nativeSnapshotAccepted;
        String manifestKey;
        String manifestRevision;
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
        int pendingHistoryPage = -1;
        VirtualSpreadNavigation.Half pendingHistoryHalf;
        long pendingHistoryAt;
        long pageLoadGeneration;
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

        hookActivity(loadPackageParam.classLoader);
        hookViewModel(loadPackageParam.classLoader);
        hookPageBar(loadPackageParam.classLoader);
        try {
            hookLinkTarget(loadPackageParam.classLoader);
        } catch (Throwable throwable) {
            logFailure("link_target_hook_failed", throwable);
        }
        try {
            hookLinkHistory(loadPackageParam.classLoader);
        } catch (Throwable throwable) {
            logFailure("link_history_hook_failed", throwable);
        }
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
                protected void afterHookedMethod(MethodHookParam param) {
                    Activity activity = (Activity) param.thisObject;
                    activeActivity = new WeakReference<>(activity);
                    log("activity_created");
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
                    activeActivity = new WeakReference<>(activity);
                    Object viewModel = objectField(
                        activity,
                        "documentViewModel"
                    );
                    if (isPortrait(activity)) {
                        schedulePortraitFocus(viewModel, "screen_change");
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
                    activeActivity = new WeakReference<>(activity);
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
                    Object viewModel = objectField(
                        activity,
                        "documentViewModel"
                    );
                    synchronized (STATES) {
                        STATES.remove(viewModel);
                    }
                    Activity current = activeActivity.get();
                    if (current == activity) {
                        activeActivity = new WeakReference<>(null);
                        observeDocumentKey(null);
                    }
                    log("activity_destroyed");
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
                    captureLinkTarget(
                        (Activity) param.thisObject,
                        param.args[1],
                        ((Integer) param.args[2]).intValue()
                    );
                }
            }
        );
    }

    private static void hookLinkHistory(ClassLoader classLoader) {
        XposedHelpers.findAndHookMethod(
            TARGET_BACK_LINK,
            classLoader,
            "getFirstBack",
            new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    captureHistoryReturn(param.getResult(), false);
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
                    captureHistoryReturn(param.getResult(), true);
                }
            }
        );
    }

    private static void captureHistoryReturn(
        Object backInfo,
        boolean original
    ) {
        Activity activity = activeActivity.get();
        Object viewModel = objectField(activity, "documentViewModel");
        Manifest manifest = manifestFor(viewModel);
        if (backInfo == null || manifest == null) {
            return;
        }
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
            log("link_history_captured original=" + original
                + " source=" + sourcePage
                + " target=" + targetPage
                + " half=" + sourceHalf
                + " origin=" + (visit == null ? "manifest" : "runtime"));
        } catch (Throwable throwable) {
            logFailure("link_history_capture_failed", throwable);
        }
    }

    private static void captureLinkTarget(
        Activity activity,
        Object superNoteLink,
        int targetPage
    ) {
        Object viewModel = objectField(activity, "documentViewModel");
        Manifest manifest = manifestFor(viewModel);
        if (manifest == null) {
            return;
        }
        ReaderState state = stateFor(viewModel, manifest);
        clearPendingLink(state);
        if (superNoteLink == null || targetPage < 0) {
            return;
        }
        try {
            Object nativeLink = XposedHelpers.callMethod(
                superNoteLink,
                "getLink"
            );
            Object bounds = nativeLink == null ? null
                : XposedHelpers.callMethod(nativeLink, "getBounds");
            if (bounds == null) {
                return;
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
                    manifest.pageHeight,
                    2.0f
                );
            if (matched == null) {
                log("link_target_unmatched source=" + sourcePage
                    + " target=" + targetPage
                    + " rect=" + x0 + "," + y0 + "," + x1 + "," + y1);
                return;
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
            log("link_target_captured source=" + sourcePage
                + " source_half=" + sourceHalf
                + " target=" + targetPage
                + " target_half=" + matched.targetHalf
                + " reset_landscape_fit="
                + matched.resetLandscapeFit);
        } catch (Throwable throwable) {
            clearPendingLink(state);
            logFailure("link_target_capture_failed", throwable);
        }
    }

    private static void hookViewModel(ClassLoader classLoader) {
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
            "onPageLoadedPart2",
            Integer.class,
            new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    handlePageLoaded(param.thisObject);
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
        ManifestLookup lookup = manifestLookupFor(viewModel);
        Manifest manifest = lookup.manifest;
        if (manifest == null && lookup.verificationPending) {
            param.setResult(null);
            log("turn_blocked reason=manifest_verification_pending");
            return;
        }
        if (manifest == null) {
            return;
        }
        Activity activity = activeActivity.get();
        if (activity == null) {
            log("turn_passthrough reason=no_activity");
            return;
        }

        int currentPage = intField(viewModel, "currentPage", -1);
        ReaderState state = stateFor(viewModel, manifest);
        clearPendingLink(state);
        if (!isPortrait(activity)) {
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

    private static void handlePageLoaded(Object viewModel) {
        Manifest manifest = manifestFor(viewModel);
        if (manifest == null) {
            return;
        }
        ReaderState state = stateFor(viewModel, manifest);
        state.pageLoadGeneration++;
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
        boolean preserveLinkViewport =
            VirtualSpreadNavigation.shouldPreservePortraitLinkViewport(
                internalLinkTarget,
                resetLandscapeFit
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
    }

    private static void schedulePortraitFocus(
        final Object viewModel,
        final String reason
    ) {
        if (viewModel == null) {
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
        try {
            Object presenter = XposedHelpers.getObjectField(
                activity,
                "handWritePresenter"
            );
            if (presenter == null) {
                return false;
            }
            XposedHelpers.callMethod(
                presenter,
                "saveTrails",
                Boolean.FALSE,
                Boolean.FALSE
            );
            return true;
        } catch (Throwable throwable) {
            logFailure("native_save_failed", throwable);
            return false;
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

    private static void clearPendingHistory(ReaderState state) {
        state.pendingHistoryPage = -1;
        state.pendingHistoryHalf = null;
        state.pendingHistoryAt = 0L;
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
        if (!isSha256(nativeSource)
            || !isSha256(nativeLayout)
            || !isSha256(nativeLinks)) {
            log("manifest_rejected reason=native_snapshot_metadata path="
                + manifest.key);
            return null;
        }
        boolean accepted = VirtualSpreadNavigation
            .manifestMatchesNativeSnapshot(
                manifest.sourceAuthority,
                manifest.layoutAuthority,
                manifest.linkAuthority,
                nativeSource,
                nativeLayout,
                nativeLinks
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
        synchronized (STATES) {
            ReaderState state = readerStateLocked(viewModel);
            if (!manifest.key.equals(state.manifestKey)
                || !manifest.revision.equals(state.manifestRevision)) {
                state.manifestKey = manifest.key;
                state.manifestRevision = manifest.revision;
                state.lastPage = -1;
                state.pendingPage = -1;
                state.pendingHalf = null;
                clearPendingLink(state);
                clearPendingHistory(state);
                state.linkHistory.clear();
                state.half = VirtualSpreadNavigation.Half.RIGHT;
                state.pageLoadGeneration = 0L;
            }
            return state;
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

    private static ManifestLookup manifestLookupFor(Object viewModel) {
        if (viewModel == null) {
            Activity current = activeActivity.get();
            if (current == null
                || objectField(current, "documentViewModel") == null) {
                observeDocumentKey(null);
            }
            return new ManifestLookup(null, false);
        }
        try {
            Activity activity = activeActivity.get();
            if (activity != null
                && objectField(activity, "documentViewModel") != viewModel) {
                log("manifest_lookup_skipped reason=stale_view_model");
                return new ManifestLookup(null, false);
            }
            Uri uri = (Uri) XposedHelpers.getObjectField(viewModel, "uri");
            if (uri == null || uri.getPath() == null) {
                observeDocumentKey(null);
                return new ManifestLookup(null, false);
            }
            File pdf = new File(uri.getPath());
            File sidecar = new File(pdf.getPath() + ".json");
            String key = pdf.getCanonicalPath();
            observeDocumentKey(key);
            if (!pdf.isFile() || !sidecar.isFile()) {
                cancelManifestVerificationForKey(key);
                return new ManifestLookup(null, false);
            }
            FileIdentity pdfIdentity = FileIdentity.capture(pdf);
            FileIdentity sidecarIdentity = FileIdentity.capture(sidecar);
            CachedManifest cached = MANIFESTS.get(key);
            if (cached != null
                && cached.matches(pdfIdentity, sidecarIdentity)) {
                return new ManifestLookup(validatePageCount(
                    viewModel,
                    validateNativeSnapshot(viewModel, cached.manifest)
                ), false);
            }
            if (cached != null) {
                MANIFESTS.remove(key, cached);
            }
            boolean verificationPending = scheduleManifestVerification(
                    pdf,
                    sidecar,
                    key,
                    pdfIdentity,
                    sidecarIdentity
                );
            if (verificationPending) {
                log("manifest_verification_pending path=" + key);
            }
            // Fail closed until the background verifier publishes a stable
            // PDF + sidecar snapshot into MANIFESTS.
            return new ManifestLookup(null, verificationPending);
        } catch (Throwable throwable) {
            observeDocumentKey(null);
            logFailure("manifest_read_failed", throwable);
            return new ManifestLookup(null, false);
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

    private static void cancelManifestVerificationForKey(String key) {
        synchronized (MANIFEST_VERIFIER_LOCK) {
            if (sameDocumentKey(key, observedDocumentKey)) {
                cancelManifestVerificationLocked();
            }
        }
    }

    private static void cancelManifestVerificationLocked() {
        VERIFYING.clear();
        Runnable stale;
        while ((stale = MANIFEST_VERIFIER.getQueue().poll()) != null) {
            if (stale instanceof ManifestVerificationTask) {
                ((ManifestVerificationTask) stale).cancelBeforeRun();
            }
        }
    }

    /**
     * Returns true while this exact PDF/sidecar snapshot is queued or running.
     * A caller can therefore block native navigation without racing a duplicate
     * scheduling attempt that correctly performs no additional work.
     */
    private static boolean scheduleManifestVerification(
        final File pdf,
        final File sidecar,
        final String key,
        final FileIdentity pdfBefore,
        final FileIdentity sidecarBefore
    ) {
        final String verificationId = pdfBefore.token()
            + ":" + sidecarBefore.token();
        synchronized (MANIFEST_VERIFIER_LOCK) {
            if (!key.equals(observedDocumentKey)) {
                return false;
            }
            if (verificationId.equals(VERIFYING.get(key))) {
                return true;
            }
            // Only the document most recently requested by the native reader
            // may remain current. Invalidate an active older verification and
            // retain at most one pending task behind it.
            cancelManifestVerificationLocked();
            VERIFYING.put(key, verificationId);
            try {
                MANIFEST_VERIFIER.execute(new ManifestVerificationTask(
                    pdf,
                    sidecar,
                    key,
                    pdfBefore,
                    sidecarBefore,
                    verificationId
                ));
                return true;
            } catch (RuntimeException exception) {
                VERIFYING.remove(key, verificationId);
                throw exception;
            }
        }
    }

    private static void requireCurrentVerification(
        String key,
        String verificationId
    ) throws ManifestVerificationSuperseded {
        if (!verificationId.equals(VERIFYING.get(key))) {
            throw new ManifestVerificationSuperseded();
        }
    }

    private static void verifyManifestSnapshot(
        File pdf,
        File sidecar,
        String key,
        FileIdentity pdfBefore,
        FileIdentity sidecarBefore,
        String verificationId
    ) {
        try {
            if (!verificationId.equals(VERIFYING.get(key))) {
                return;
            }
            try (
                RandomAccessFile pdfInput = new RandomAccessFile(pdf, "r");
                FileInputStream sidecarInput = new FileInputStream(sidecar)
            ) {
                FileIdentity pdfOpened = FileIdentity.capture(pdfInput.getFD());
                FileIdentity sidecarOpened = FileIdentity.capture(
                    sidecarInput.getFD()
                );
                if (!pdfBefore.matches(pdfOpened)
                    || !sidecarBefore.matches(sidecarOpened)) {
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
                if (sidecarJson == null) {
                    log("manifest_rejected reason=invalid_utf8 path=" + key);
                    parsed = null;
                } else {
                    parsed = parseManifest(
                        pdfInput,
                        pdfOpened.size,
                        sidecarJson,
                        key,
                        sidecarDigest,
                        verificationId
                    );
                }
                String currentSidecarDigest = sha256(readBytes(
                    sidecarInput,
                    sidecarOpened.size
                ));
                FileIdentity pdfAfter = FileIdentity.capture(pdfInput.getFD());
                FileIdentity sidecarAfter = FileIdentity.capture(
                    sidecarInput.getFD()
                );
                FileIdentity pdfPathAfter = FileIdentity.capture(pdf);
                FileIdentity sidecarPathAfter = FileIdentity.capture(sidecar);
                if (!pdfOpened.matches(pdfAfter)
                    || !sidecarOpened.matches(sidecarAfter)
                    || !pdfAfter.matches(pdfPathAfter)
                    || !sidecarAfter.matches(sidecarPathAfter)
                    || !sidecarDigest.equals(currentSidecarDigest)) {
                    if (verificationId.equals(VERIFYING.get(key))) {
                        MANIFESTS.remove(key);
                    }
                    log("manifest_rejected reason=snapshot_changed_during_read path="
                        + key);
                    return;
                }
                if (verificationId.equals(VERIFYING.get(key))) {
                    CachedManifest published = new CachedManifest(
                        pdfAfter,
                        sidecarAfter,
                        sidecarDigest,
                        parsed
                    );
                    MANIFESTS.put(key, published);
                    if (!verificationId.equals(VERIFYING.get(key))) {
                        MANIFESTS.remove(key, published);
                        return;
                    }
                    if (parsed != null) {
                        log("manifest_accepted path=" + key
                            + " pages=" + parsed.pageCount);
                        scheduleManifestActivation(key, parsed.revision);
                    }
                }
            }
        } catch (Throwable throwable) {
            if (verificationId.equals(VERIFYING.get(key))) {
                MANIFESTS.remove(key);
                logFailure("manifest_verification_failed", throwable);
            }
        } finally {
            VERIFYING.remove(key, verificationId);
        }
    }

    private static void scheduleManifestActivation(
        final String key,
        final String revision
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
                handlePageLoaded(viewModel);
                scheduleConfigurationRefresh(
                    owner,
                    viewModel,
                    "manifest_verified"
                );
                log("manifest_activated path=" + key
                    + " revision=" + revision);
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
        if (nativePageCount > 0 && nativePageCount != manifest.pageCount) {
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

    private static boolean spreadEntryMatches(
        JSONObject spread,
        String side,
        int expectedSourcePage,
        int virtualPage
    ) {
        if (!spread.has(side)) {
            return false;
        }
        if (expectedSourcePage < 0) {
            return spread.isNull(side);
        }
        JSONObject mapping = spread.optJSONObject(side);
        Integer mappedSourcePage = exactManifestInteger(
            mapping, "sourcePageIndex"
        );
        Integer mappedVirtualPage = exactManifestInteger(
            mapping, "virtualPageIndex"
        );
        return mappedSourcePage != null
            && mappedVirtualPage != null
            && expectedSourcePage == mappedSourcePage.intValue()
            && virtualPage == mappedVirtualPage.intValue()
            && side.equals(mapping.optString("side"));
    }

    private static boolean sourceEntryMatches(
        JSONObject mapping,
        int sourcePage,
        boolean coverSeparate
    ) {
        Integer mappedSourcePage = exactManifestInteger(
            mapping, "sourcePageIndex"
        );
        Integer mappedVirtualPage = exactManifestInteger(
            mapping, "virtualPageIndex"
        );
        if (mappedSourcePage == null || mappedVirtualPage == null
            || sourcePage != mappedSourcePage.intValue()) {
            return false;
        }
        if (coverSeparate && sourcePage == 0) {
            return mappedVirtualPage.intValue() == 0
                && "right".equals(mapping.optString("side"));
        }
        int firstSourcePage = coverSeparate ? 1 : 0;
        int firstVirtualPage = coverSeparate ? 1 : 0;
        int offset = sourcePage - firstSourcePage;
        if (offset < 0) {
            return false;
        }
        return mappedVirtualPage.intValue()
                == firstVirtualPage + offset / 2
            && (offset % 2 == 0 ? "right" : "left").equals(
                mapping.optString("side")
            );
    }

    private static boolean linkEndpointMatches(
        JSONArray sourcePages,
        int sourcePageIndex,
        int virtualPageIndex,
        String side
    ) {
        if (sourcePageIndex < 0
            || sourcePageIndex >= sourcePages.length()
            || virtualPageIndex < 0
            || !("left".equals(side) || "right".equals(side))) {
            return false;
        }
        JSONObject mapping = sourcePages.optJSONObject(sourcePageIndex);
        Integer mappedSourcePage = exactManifestInteger(
            mapping, "sourcePageIndex"
        );
        Integer mappedVirtualPage = exactManifestInteger(
            mapping, "virtualPageIndex"
        );
        return mappedSourcePage != null
            && mappedVirtualPage != null
            && sourcePageIndex == mappedSourcePage.intValue()
            && virtualPageIndex == mappedVirtualPage.intValue()
            && side.equals(mapping.optString("side"));
    }

    private static Manifest parseManifest(
        RandomAccessFile pdfInput,
        long pdfLength,
        String sidecarJson,
        String key,
        String sidecarDigest,
        String verificationId
    ) throws Exception {
        requireCurrentVerification(key, verificationId);
        if (!VirtualSpreadNavigation.jsonObjectHasUniqueKeys(sidecarJson)) {
            log("manifest_rejected reason=duplicate_or_invalid_json path="
                + key);
            return null;
        }
        JSONObject root = new JSONObject(sidecarJson);
        if (!SCHEMA.equals(root.optString("schema"))
            || !"rtl".equalsIgnoreCase(root.optString("direction"))) {
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
        String expectedSourceAuthority = source.optString(
            "sha256",
            ""
        );
        long expectedSize = expectedSizeValue.longValue();
        String expectedHash = output.optString("sha256", "");
        if (expectedSize != pdfLength
            || pageCount <= 0
            || spreadsJson.length() != pageCount) {
            log("manifest_rejected reason=output_identity path=" + key);
            return null;
        }
        if (!isSha256(expectedHash)
            || !expectedHash.equalsIgnoreCase(
                sha256File(pdfInput, key, verificationId)
            )) {
            log("manifest_rejected reason=output_hash path=" + key);
            return null;
        }
        requireCurrentVerification(key, verificationId);
        String embeddedSourceAuthority =
            VirtualSpreadLinkAuthority.readPdfSourceDigest(pdfInput);
        if (!isSha256(expectedSourceAuthority)
            || !expectedSourceAuthority.equalsIgnoreCase(
                embeddedSourceAuthority
            )) {
            log("manifest_rejected reason=source_authority path="
                + key);
            return null;
        }
        String expectedLinkAuthority = output.optString(
            "linkAuthoritySha256",
            ""
        );
        requireCurrentVerification(key, verificationId);
        String embeddedLinkAuthority =
            VirtualSpreadLinkAuthority.readPdfDigest(pdfInput);
        if (!isSha256(expectedLinkAuthority)
            || !expectedLinkAuthority.equalsIgnoreCase(embeddedLinkAuthority)) {
            log("manifest_rejected reason=link_authority path=" + key);
            return null;
        }
        String expectedLayoutAuthority = output.optString(
            "layoutAuthoritySha256",
            ""
        );
        requireCurrentVerification(key, verificationId);
        String embeddedLayoutAuthority =
            VirtualSpreadLinkAuthority.readPdfLayoutDigest(pdfInput);
        if (!isSha256(expectedLayoutAuthority)
            || !expectedLayoutAuthority.equalsIgnoreCase(embeddedLayoutAuthority)) {
            log("manifest_rejected reason=layout_authority path=" + key);
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
        if (!expectedLayoutAuthority.equalsIgnoreCase(actualLayoutAuthority)) {
            log("manifest_rejected reason=layout_authority_records path=" + key);
            return null;
        }
        VirtualSpreadNavigation.Spread[] spreads =
            new VirtualSpreadNavigation.Spread[pageCount];
        for (int index = 0; index < pageCount; index++) {
            requireCurrentVerification(key, verificationId);
            JSONObject spread = spreadsJson.optJSONObject(index);
            Integer spreadIndex = exactManifestInteger(
                spread, "virtualPageIndex"
            );
            if (spreadIndex == null
                || spreadIndex.intValue() != index) {
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
                    spread, "left", expectedLeft, index
                ) || !spreadEntryMatches(
                    spread, "right", expectedRight, index
                )) {
                log("manifest_rejected reason=cover_layout index=" + index);
                return null;
            }
            spreads[index] = new VirtualSpreadNavigation.Spread(
                expectedLeft >= 0,
                expectedRight >= 0
            );
        }
        for (int index = 0; index < sourcePageCount; index++) {
            requireCurrentVerification(key, verificationId);
            if (!sourceEntryMatches(
                    sourcePagesJson.optJSONObject(index),
                    index,
                    coverSeparate
                )) {
                log("manifest_rejected reason=source_layout index=" + index);
                return null;
            }
        }
        ArrayList<VirtualSpreadNavigation.LinkTarget> links =
            new ArrayList<>();
        ArrayList<String> linkAuthorityRecords = new ArrayList<>();
        for (int index = 0; index < linksJson.length(); index++) {
            requireCurrentVerification(key, verificationId);
            JSONObject link = linksJson.optJSONObject(index);
            if (link == null) {
                log("manifest_rejected reason=link_record index=" + index);
                return null;
            }
            String kind = link.optString("kind");
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
            String sourceSide = link.optString("sourceSide");
            JSONArray rect = link.optJSONArray("rect");
            if (sourceOutputPage < 0 || sourceOutputPage >= pageCount
                || rect == null || rect.length() != 4) {
                log("manifest_rejected reason=link_record index=" + index);
                return null;
            }
            if (!linkEndpointMatches(
                    sourcePagesJson,
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
                linkAuthorityRecords.add(VirtualSpreadLinkAuthority.uri(
                    sourceSourcePage,
                    sourceSide,
                    sourceOutputPage,
                    x0,
                    y0,
                    x1,
                    y1,
                    (String) link.opt("uri")
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
            String targetSide = link.optString("targetSide");
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
                    sourcePagesJson,
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
        if (!expectedLinkAuthority.equalsIgnoreCase(actualLinkAuthority)) {
            log("manifest_rejected reason=link_authority_records path=" + key);
            return null;
        }
        requireCurrentVerification(key, verificationId);
        return new Manifest(
            key,
            sidecarDigest,
            expectedSourceAuthority,
            expectedLayoutAuthority,
            expectedLinkAuthority,
            pageCount,
            spreads,
            (float) pageHeight,
            links.toArray(new VirtualSpreadNavigation.LinkTarget[links.size()])
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
        RandomAccessFile input,
        String key,
        String verificationId
    ) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        long originalPosition = input.getFilePointer();
        try {
            input.seek(0L);
            byte[] buffer = new byte[64 * 1024];
            while (true) {
                requireCurrentVerification(key, verificationId);
                int count = input.read(buffer);
                if (count < 0) {
                    break;
                }
                if (count > 0) {
                    digest.update(buffer, 0, count);
                }
            }
        } finally {
            input.seek(originalPosition);
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
            if (Character.digit(value.charAt(index), 16) < 0) {
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
            return expected.equals(new File(candidate).getCanonicalPath());
        } catch (Throwable throwable) {
            return false;
        }
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
