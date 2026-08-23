package com.techrebbe.supernote.virtualspread;

import android.app.Activity;
import android.content.res.Configuration;
import android.graphics.RectF;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.util.Log;

import java.io.File;
import java.io.FileInputStream;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Map;
import java.util.WeakHashMap;
import java.util.concurrent.ConcurrentHashMap;

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
    private static final String VERSION = "0.0.8";

    private static volatile WeakReference<Activity> activeActivity =
        new WeakReference<>(null);
    private static final Map<Object, ReaderState> STATES =
        new WeakHashMap<>();
    private static final Map<String, CachedManifest> MANIFESTS =
        new ConcurrentHashMap<>();
    private static final ThreadLocal<int[]> PAGE_BAR_VALUES =
        new ThreadLocal<>();

    private static final class Manifest {
        final String key;
        final int pageCount;
        final VirtualSpreadNavigation.Spread[] spreads;
        final float pageHeight;
        final VirtualSpreadNavigation.LinkTarget[] links;

        Manifest(
            String key,
            int pageCount,
            VirtualSpreadNavigation.Spread[] spreads,
            float pageHeight,
            VirtualSpreadNavigation.LinkTarget[] links
        ) {
            this.key = key;
            this.pageCount = pageCount;
            this.spreads = spreads;
            this.pageHeight = pageHeight;
            this.links = links;
        }
    }

    private static final class CachedManifest {
        final long pdfLength;
        final long pdfModified;
        final long sidecarLength;
        final long sidecarModified;
        final Manifest manifest;

        CachedManifest(
            long pdfLength,
            long pdfModified,
            long sidecarLength,
            long sidecarModified,
            Manifest manifest
        ) {
            this.pdfLength = pdfLength;
            this.pdfModified = pdfModified;
            this.sidecarLength = sidecarLength;
            this.sidecarModified = sidecarModified;
            this.manifest = manifest;
        }

        boolean matches(File pdf, File sidecar) {
            return pdfLength == pdf.length()
                && pdfModified == pdf.lastModified()
                && sidecarLength == sidecar.length()
                && sidecarModified == sidecar.lastModified();
        }
    }

    private static final class ReaderState {
        String manifestKey;
        int lastPage = -1;
        int pendingPage = -1;
        VirtualSpreadNavigation.Half half =
            VirtualSpreadNavigation.Half.RIGHT;
        VirtualSpreadNavigation.Half pendingHalf;
        int pendingLinkSourcePage = -1;
        VirtualSpreadNavigation.Half pendingLinkSourceHalf;
        int pendingLinkPage = -1;
        VirtualSpreadNavigation.Half pendingLinkHalf;
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
                || currentPage != targetPage
                || !sameCanonicalPath(manifest.key, sourcePath)
                || !sameCanonicalPath(manifest.key, targetPath)) {
                log("link_history_ignored original=" + original
                    + " source=" + sourcePage
                    + " target=" + targetPage
                    + " current=" + currentPage);
                return;
            }

            ReaderState state = stateFor(viewModel, manifest);
            VirtualSpreadNavigation.LinkVisit visit = original
                ? state.linkHistory.takeOriginal(sourcePage, targetPage)
                : state.linkHistory.takeBack(sourcePage, targetPage);
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
            state.pendingLinkAt = System.currentTimeMillis();
            log("link_target_captured source=" + sourcePage
                + " source_half=" + sourceHalf
                + " target=" + targetPage
                + " target_half=" + matched.targetHalf);
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
        Manifest manifest = manifestFor(viewModel);
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

        state.half = plan.targetHalf;
        state.lastPage = plan.targetPage;
        if (plan.kind == VirtualSpreadNavigation.Kind.SAME_SPREAD) {
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
        if (isPortrait(activity)) {
            focusHalf(viewModel, target, "page_loaded");
            schedulePortraitFocus(viewModel, "page_loaded_retry");
        }
        log("page_loaded page=" + currentPage + " portrait="
            + isPortrait(activity) + " target_half=" + target
            + " reason=" + targetReason);
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
        final Handler handler = new Handler(owner.getMainLooper());
        final long[] delays = new long[] {0L, 120L, 360L};
        for (final long delay : delays) {
            handler.postDelayed(new Runnable() {
                @Override
                public void run() {
                    Activity activity = activeActivity.get();
                    if (!isPortrait(activity)) {
                        return;
                    }
                    Manifest manifest = manifestFor(viewModel);
                    if (manifest == null) {
                        return;
                    }
                    ReaderState state = stateFor(viewModel, manifest);
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
                Manifest currentManifest = manifestFor(viewModel);
                if (activity != owner || currentManifest == null) {
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
        state.pendingLinkAt = 0L;
    }

    private static void clearPendingHistory(ReaderState state) {
        state.pendingHistoryPage = -1;
        state.pendingHistoryHalf = null;
        state.pendingHistoryAt = 0L;
    }

    private static ReaderState stateFor(
        Object viewModel,
        Manifest manifest
    ) {
        synchronized (STATES) {
            ReaderState state = STATES.get(viewModel);
            if (state == null) {
                state = new ReaderState();
                STATES.put(viewModel, state);
            }
            if (!manifest.key.equals(state.manifestKey)) {
                state.manifestKey = manifest.key;
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
        if (viewModel == null) {
            return null;
        }
        try {
            Uri uri = (Uri) XposedHelpers.getObjectField(viewModel, "uri");
            if (uri == null || uri.getPath() == null) {
                return null;
            }
            File pdf = new File(uri.getPath());
            File sidecar = new File(pdf.getPath() + ".json");
            String key = pdf.getCanonicalPath();
            CachedManifest cached = MANIFESTS.get(key);
            if (cached != null && cached.matches(pdf, sidecar)) {
                return validatePageCount(viewModel, cached.manifest);
            }
            Manifest parsed = parseManifest(pdf, sidecar, key);
            MANIFESTS.put(
                key,
                new CachedManifest(
                    pdf.length(),
                    pdf.lastModified(),
                    sidecar.length(),
                    sidecar.lastModified(),
                    parsed
                )
            );
            return validatePageCount(viewModel, parsed);
        } catch (Throwable throwable) {
            logFailure("manifest_read_failed", throwable);
            return null;
        }
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

    private static Manifest parseManifest(
        File pdf,
        File sidecar,
        String key
    ) throws Exception {
        if (!pdf.isFile() || !sidecar.isFile()) {
            return null;
        }
        JSONObject root = new JSONObject(readUtf8(sidecar));
        if (!SCHEMA.equals(root.optString("schema"))
            || !"rtl".equalsIgnoreCase(root.optString("direction"))) {
            return null;
        }
        JSONObject output = root.optJSONObject("output");
        JSONArray spreadsJson = root.optJSONArray("spreads");
        if (output == null || spreadsJson == null) {
            return null;
        }
        long expectedSize = output.optLong("size", -1L);
        int pageCount = output.optInt("pageCount", -1);
        if (expectedSize != pdf.length()
            || pageCount <= 0
            || spreadsJson.length() != pageCount) {
            log("manifest_rejected reason=output_identity path=" + key);
            return null;
        }
        JSONArray spreadSize = output.optJSONArray("spreadSize");
        if (spreadSize == null || spreadSize.length() != 2) {
            log("manifest_rejected reason=output_geometry path=" + key);
            return null;
        }
        double pageWidth = spreadSize.optDouble(0, Double.NaN);
        double pageHeight = spreadSize.optDouble(1, Double.NaN);
        if (Double.isNaN(pageWidth) || Double.isInfinite(pageWidth)
            || Double.isNaN(pageHeight) || Double.isInfinite(pageHeight)
            || pageWidth <= 0.0 || pageHeight <= 0.0) {
            log("manifest_rejected reason=output_geometry path=" + key);
            return null;
        }
        VirtualSpreadNavigation.Spread[] spreads =
            new VirtualSpreadNavigation.Spread[pageCount];
        for (int index = 0; index < pageCount; index++) {
            JSONObject spread = spreadsJson.optJSONObject(index);
            if (spread == null
                || spread.optInt("virtualPageIndex", -1) != index) {
                log("manifest_rejected reason=spread_index index=" + index);
                return null;
            }
            boolean hasLeft = spread.has("left") && !spread.isNull("left");
            boolean hasRight = spread.has("right") && !spread.isNull("right");
            if (!hasLeft && !hasRight) {
                log("manifest_rejected reason=empty_spread index=" + index);
                return null;
            }
            spreads[index] = new VirtualSpreadNavigation.Spread(
                hasLeft,
                hasRight
            );
        }
        ArrayList<VirtualSpreadNavigation.LinkTarget> links =
            new ArrayList<>();
        JSONArray linksJson = root.optJSONArray("links");
        if (linksJson != null) {
            for (int index = 0; index < linksJson.length(); index++) {
                JSONObject link = linksJson.optJSONObject(index);
                if (link == null || !"internal".equals(link.optString("kind"))) {
                    continue;
                }
                int sourcePage = link.optInt("outputPage", -1);
                int targetPage = link.optInt("targetOutputPage", -1);
                String sourceSide = link.optString("sourceSide");
                String side = link.optString("targetSide");
                JSONArray rect = link.optJSONArray("rect");
                if (sourcePage < 0 || sourcePage >= pageCount
                    || targetPage < 0 || targetPage >= pageCount
                    || rect == null || rect.length() != 4
                    || !("left".equals(side) || "right".equals(side))) {
                    log("manifest_rejected reason=link_record index=" + index);
                    return null;
                }
                double x0 = rect.optDouble(0, Double.NaN);
                double y0 = rect.optDouble(1, Double.NaN);
                double x1 = rect.optDouble(2, Double.NaN);
                double y1 = rect.optDouble(3, Double.NaN);
                if (Double.isNaN(x0) || Double.isInfinite(x0)
                    || Double.isNaN(y0) || Double.isInfinite(y0)
                    || Double.isNaN(x1) || Double.isInfinite(x1)
                    || Double.isNaN(y1) || Double.isInfinite(y1)) {
                    log("manifest_rejected reason=link_rect index=" + index);
                    return null;
                }
                VirtualSpreadNavigation.Half sourceHalf;
                if ("left".equals(sourceSide)) {
                    sourceHalf = VirtualSpreadNavigation.Half.LEFT;
                } else if ("right".equals(sourceSide)) {
                    sourceHalf = VirtualSpreadNavigation.Half.RIGHT;
                } else if (x1 <= pageWidth / 2.0) {
                    sourceHalf = VirtualSpreadNavigation.Half.LEFT;
                } else if (x0 >= pageWidth / 2.0) {
                    sourceHalf = VirtualSpreadNavigation.Half.RIGHT;
                } else {
                    sourceHalf = null;
                }
                links.add(new VirtualSpreadNavigation.LinkTarget(
                    sourcePage,
                    targetPage,
                    sourceHalf,
                    "left".equals(side)
                        ? VirtualSpreadNavigation.Half.LEFT
                        : VirtualSpreadNavigation.Half.RIGHT,
                    (float) x0,
                    (float) y0,
                    (float) x1,
                    (float) y1
                ));
            }
        }
        log("manifest_accepted path=" + key + " pages=" + pageCount);
        return new Manifest(
            key,
            pageCount,
            spreads,
            (float) pageHeight,
            links.toArray(new VirtualSpreadNavigation.LinkTarget[links.size()])
        );
    }

    private static String readUtf8(File file) throws Exception {
        if (file.length() > 8L * 1024L * 1024L) {
            throw new IllegalArgumentException("manifest is too large");
        }
        byte[] data = new byte[(int) file.length()];
        FileInputStream input = new FileInputStream(file);
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
        } finally {
            input.close();
        }
        return new String(data, "UTF-8");
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
