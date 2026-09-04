package com.techrebbe.supernote.spreadprobe.v2android;

import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.res.Configuration;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.Process;
import android.os.SystemClock;
import android.util.Log;
import android.view.InputDevice;
import android.view.MotionEvent;

import com.techrebbe.supernote.spreadprobe.v2.PointD;
import com.techrebbe.supernote.spreadprobe.v2.RectD;
import com.techrebbe.supernote.spreadprobe.v2.NativeReaderV2MarkerClaim;
import com.techrebbe.supernote.spreadprobe.v2.NativeHandshakeSingleFlight;

import java.io.File;
import java.lang.reflect.Method;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;

/** Exact-firmware hook shell for Native Reader v2. */
public final class NativeReaderV2Hooks {
    private static final String TAG = "SN_NATIVE_READER_V2";
    private static final String ACTIVITY =
        "com.supernote.document.document.DocumentActivity";
    private static final String VIEW_MODEL =
        "com.supernote.document.document.DocumentViewModel";
    private static final String IMAGE_VIEW =
        "com.supernote.document.utils.view.DocumentImageView";
    private static final String HAND_WRITE_VIEW =
        "com.supernote.document.handwrite.HandWriteView";
    private static final String PRESENTER =
        "com.supernote.document.handwrite.HandWritePresenter";
    private static final String NOTE =
        "com.example.libsupernote.SuperNoteNote";
    private static final String NATIVE_CALLBACK = ACTIVITY + "$6";
    private static final String PLUGIN_HOST_PACKAGE =
        "com.ratta.supernote.pluginhost";
    private static final String HANDSHAKE_REQUEST =
        "com.techrebbe.supernote.spreadprobe.HANDSHAKE_REQUEST";
    private static final String HANDSHAKE_RESPONSE =
        "com.techrebbe.supernote.spreadprobe.HANDSHAKE_RESPONSE";
    private static final int HANDSHAKE_PROTOCOL = 4;
    private static final long HANDSHAKE_PROVIDER_EXPIRY_MS = 2_500L;
    private static final long NATIVE_PEN_TERMINAL_GRACE_MS = 250L;

    private static final ConcurrentHashMap<Object, Entry> BY_ACTIVITY =
        new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<Object, Entry> BY_COMPONENT =
        new ConcurrentHashMap<>();
    private static final AtomicLong ACTIVITY_GENERATIONS = new AtomicLong(1L);
    private static final NativeHandshakeSingleFlight HANDSHAKE_SINGLE_FLIGHT =
        new NativeHandshakeSingleFlight();
    private static final Handler MAIN_HANDLER = new Handler(Looper.getMainLooper());
    private static final ExecutorService ADMISSION =
        Executors.newSingleThreadExecutor();
    private static final ThreadLocal<Boolean> INTERNAL_PRESENTATION =
        new ThreadLocal<>();
    private static final ThreadLocal<Boolean> REPLAY_BYPASS =
        new ThreadLocal<>();
    private static final ThreadLocal<Boolean> DOCUMENT_OPEN_BYPASS =
        new ThreadLocal<>();
    private static final ThreadLocal<ArrayDeque<Boolean>> SAME_PAGE_RELOADS =
        new ThreadLocal<>();
    private static final ThreadLocal<ArrayDeque<Boolean>> SCALE_CHANGES =
        new ThreadLocal<>();
    private static volatile NativeReaderV2FirmwareAccess firmware;
    private static volatile BroadcastReceiver handshakeReceiver;
    private static volatile boolean handshakeReceiverRegistered;
    private static volatile boolean installed;

    private NativeReaderV2Hooks() {}

    public static synchronized void install(ClassLoader loader) {
        if (installed) return;
        ArrayList<XC_MethodHook.Unhook> hooks = new ArrayList<>();
        try {
            firmware = new NativeReaderV2FirmwareAccess(loader);
            installLifecycle(loader, hooks);
            installPresentation(loader, hooks);
            installNavigation(loader, hooks);
            installNativeChromeMasks(loader, hooks);
            installInput(loader, hooks);
            installSaveWitness(loader, hooks);
            installed = true;
            Log.i(TAG, "exact Native Reader v2 hooks installed count="
                + hooks.size());
        } catch (Throwable failure) {
            for (int index = hooks.size() - 1; index >= 0; index--) {
                try {
                    hooks.get(index).unhook();
                } catch (Throwable cleanupFailure) {
                    failure.addSuppressed(cleanupFailure);
                }
            }
            firmware = null;
            throw new IllegalStateException(
                "Native Reader v2 hook installation rolled back",
                failure
            );
        }
    }

    static void runInternalPresentation(Runnable action) {
        if (action == null) return;
        Boolean previous = INTERNAL_PRESENTATION.get();
        INTERNAL_PRESENTATION.set(Boolean.TRUE);
        try {
            action.run();
        } finally {
            if (previous == null) INTERNAL_PRESENTATION.remove();
            else INTERNAL_PRESENTATION.set(previous);
        }
    }

    private static void hook(
        List<XC_MethodHook.Unhook> hooks,
        String className,
        ClassLoader loader,
        String methodName,
        Object... parameterTypesAndCallback
    ) {
        hooks.add(XposedHelpers.findAndHookMethod(
            className,
            loader,
            methodName,
            parameterTypesAndCallback
        ));
    }

    private static void installLifecycle(
        ClassLoader loader,
        List<XC_MethodHook.Unhook> hooks
    ) {
        hook(hooks,
            ACTIVITY, loader, "onCreate", Bundle.class,
            new XC_MethodHook() {
                @Override protected void afterHookedMethod(MethodHookParam param) {
                    Activity activity = (Activity) param.thisObject;
                    Entry entry = new Entry(
                        activity,
                        ACTIVITY_GENERATIONS.getAndIncrement()
                    );
                    Entry replaced = BY_ACTIVITY.put(activity, entry);
                    if (replaced != null) retire(replaced, "activity_replaced");
                    registerHandshakeReceiver(activity);
                }
            }
        );
        hook(hooks,
            ACTIVITY, loader, "onResume",
            new XC_MethodHook() {
                @Override protected void afterHookedMethod(MethodHookParam param) {
                    Entry entry = entry(param.thisObject);
                    if (entry == null) return;
                    entry.resumed = true;
                    entry.lifecycleGeneration++;
                    // The companion writes the v2 marker while PluginHost is
                    // in front of this Activity. A resumed reader must retry
                    // an earlier marker-missing admission without making
                    // every image callback rehash the PDF.
                    maybeAdmit(entry, true);
                }
            }
        );
        hook(hooks,
            ACTIVITY, loader, "onPause",
            new XC_MethodHook() {
                @Override protected void beforeHookedMethod(MethodHookParam param) {
                    Entry entry = entry(param.thisObject);
                    if (entry != null) {
                        entry.resumed = false;
                        entry.lifecycleGeneration++;
                    }
                    if (entry != null && entry.runtime != null) {
                        entry.runtime.beforeLifecyclePause();
                    }
                }

                @Override protected void afterHookedMethod(MethodHookParam param) {
                    Entry entry = entry(param.thisObject);
                    if (entry != null && entry.runtime != null) {
                        entry.runtime.afterLifecyclePause();
                        // Stock onPause is the terminal boundary for both pen
                        // transports even when the hardware omits an explicit
                        // UP sample after disabling DrawPath.
                        clearStylusContact(entry);
                        entry.runtime.postPhysicalContactFenceReleased();
                    }
                }
            }
        );
        hook(hooks,
            ACTIVITY, loader, "onDestroy",
            new XC_MethodHook() {
                @Override protected void afterHookedMethod(MethodHookParam param) {
                    Entry entry = BY_ACTIVITY.remove(param.thisObject);
                    if (entry != null) {
                        releaseDestroyedEntry(entry, "activity_destroyed");
                    }
                    if (BY_ACTIVITY.isEmpty() && firmware != null) {
                        try {
                            firmware.releaseProjectionReader();
                        } catch (RuntimeException failure) {
                            Log.e(
                                TAG,
                                "read-only projection reader cleanup failed",
                                failure
                            );
                        }
                    }
                }
            }
        );
        hook(hooks,
            ACTIVITY, loader, "onConfigurationChanged", Configuration.class,
            new XC_MethodHook() {
                @Override protected void beforeHookedMethod(MethodHookParam param) {
                    Entry entry = entry(param.thisObject);
                    if (entry != null && entry.runtime != null) {
                        entry.runtime.beforeConfigurationChange();
                    }
                }

                @Override protected void afterHookedMethod(MethodHookParam param) {
                    Entry entry = entry(param.thisObject);
                    if (entry != null && entry.runtime != null) {
                        entry.runtime.afterConfigurationChange();
                    }
                }
            }
        );

        XC_MethodHook readySignal = new XC_MethodHook() {
            @Override protected void afterHookedMethod(MethodHookParam param) {
                Entry entry = entry(param.thisObject);
                if (entry == null) return;
                maybeAdmit(entry, false);
                reindex(entry);
                if (entry.runtime != null && !entry.admitting) {
                    String signalName =
                        ((java.lang.reflect.Method) param.method).getName();
                    entry.runtime.onNativeStockPageReady(
                        param.thisObject,
                        signalName
                    );
                    entry.runtime.onNativePresentationChanged(
                        signalName
                    );
                }
            }
        };
        hook(hooks,
            ACTIVITY, loader, "setImage", android.graphics.Bitmap.class,
            readySignal
        );
        hook(hooks,
            ACTIVITY, loader, "updateImage", android.graphics.Bitmap.class,
            readySignal
        );
        hook(hooks,
            ACTIVITY, loader, "displayChanged",
            "com.supernote.document.document.bean.DisplayResult",
            readySignal
        );
        hook(hooks,
            ACTIVITY, loader, "loadPageChanged",
            "com.supernote.document.document.bean.LoadPageResult",
            readySignal
        );
        hook(hooks,
            ACTIVITY, loader, "setDigestImage", android.graphics.Bitmap.class,
            new XC_MethodHook() {
                @Override protected void beforeHookedMethod(MethodHookParam param) {
                    if (Boolean.TRUE.equals(INTERNAL_PRESENTATION.get())) return;
                    Entry entry = entry(param.thisObject);
                    if (entry != null && entry.runtime != null
                        && entry.runtime.suppressNativePresentation()) {
                        param.setResult(null);
                    }
                }

                @Override protected void afterHookedMethod(MethodHookParam param) {
                    Entry entry = entry(param.thisObject);
                    if (entry != null && entry.runtime != null
                        && !Boolean.TRUE.equals(INTERNAL_PRESENTATION.get())) {
                        if (param.getThrowable() == null) {
                            entry.runtime.onNativeStockDigestPresented(
                                param.thisObject,
                                (android.graphics.Bitmap) param.args[0]
                            );
                        }
                        entry.runtime.onNativePresentationChanged("setDigestImage");
                    }
                }
            }
        );
    }

    private static void installPresentation(
        ClassLoader loader,
        List<XC_MethodHook.Unhook> hooks
    ) {
        hook(hooks,
            IMAGE_VIEW, loader, "setImageBitmap", android.graphics.Bitmap.class,
            new XC_MethodHook() {
                @Override protected void beforeHookedMethod(MethodHookParam param) {
                    if (Boolean.TRUE.equals(INTERNAL_PRESENTATION.get())) return;
                    Entry entry = BY_COMPONENT.get(param.thisObject);
                    if (entry != null && entry.runtime != null
                        && entry.runtime.suppressNativePresentation()) {
                        param.setResult(null);
                        entry.runtime.onNativePresentationChanged(
                            "native_background_suppressed"
                        );
                    }
                }

                @Override protected void afterHookedMethod(MethodHookParam param) {
                    if (Boolean.TRUE.equals(INTERNAL_PRESENTATION.get())
                        || param.getThrowable() != null) return;
                    Entry entry = BY_COMPONENT.get(param.thisObject);
                    if (entry != null && entry.runtime != null) {
                        entry.runtime.onNativeStockBackgroundPresented(
                            param.thisObject,
                            (android.graphics.Bitmap) param.args[0]
                        );
                    }
                }
            }
        );
        hook(hooks,
            HAND_WRITE_VIEW, loader, "setBitmap", android.graphics.Bitmap.class,
            new XC_MethodHook() {
                @Override protected void beforeHookedMethod(MethodHookParam param) {
                    if (Boolean.TRUE.equals(INTERNAL_PRESENTATION.get())) return;
                    Entry entry = BY_COMPONENT.get(param.thisObject);
                    if (entry != null && entry.runtime != null
                        && entry.runtime.suppressNativePresentation()) {
                        param.setResult(null);
                        entry.runtime.onNativePresentationChanged(
                            "native_ink_presentation_suppressed"
                        );
                    }
                }

                @Override protected void afterHookedMethod(MethodHookParam param) {
                    if (Boolean.TRUE.equals(INTERNAL_PRESENTATION.get())
                        || param.getThrowable() != null) return;
                    Entry entry = BY_COMPONENT.get(param.thisObject);
                    if (entry != null && entry.runtime != null) {
                        entry.runtime.onNativeStockInkPresented(
                            param.thisObject,
                            (android.graphics.Bitmap) param.args[0]
                        );
                    }
                }
            }
        );
    }

    private static void installNavigation(
        ClassLoader loader,
        List<XC_MethodHook.Unhook> hooks
    ) {
        hook(hooks,
            VIEW_MODEL, loader, "openDocument",
            android.net.Uri.class,
            Integer.TYPE, Integer.TYPE, Integer.TYPE,
            Integer.TYPE, Integer.TYPE, Boolean.TYPE,
            new XC_MethodHook() {
                @Override protected void beforeHookedMethod(MethodHookParam param) {
                    if (Boolean.TRUE.equals(DOCUMENT_OPEN_BYPASS.get())) return;
                    Entry entry = BY_COMPONENT.get(param.thisObject);
                    if (entry == null) return;
                    if (entry.runtime == null) {
                        if (entry.admissionFence) {
                            // Last request wins while the old document is
                            // fenced. A later user navigation must not be
                            // silently discarded in favor of an older queued
                            // link/open action.
                            entry.pendingNativeOpen = new PendingNativeOpen(
                                (Method) param.method,
                                param.thisObject,
                                param.args.clone()
                            );
                            // Admission is inspecting the old document. Keep
                            // this exact open until that worker returns; never
                            // silently drop the user's cross-document action.
                            param.setResult(null);
                        }
                        return;
                    }
                    if (entry.pendingNativeOpen != null) {
                        entry.pendingNativeOpen = new PendingNativeOpen(
                            (Method) param.method,
                            param.thisObject,
                            param.args.clone()
                        );
                        param.setResult(null);
                        return;
                    }
                    PendingNativeOpen pending = new PendingNativeOpen(
                        (Method) param.method,
                        param.thisObject,
                        param.args.clone()
                    );
                    entry.pendingNativeOpen = pending;
                    boolean prepared = entry.runtime.prepareNativeDocumentOpen();
                    if (!prepared) {
                        // The old document remains the writer authority until
                        // its source save and restoration complete. Never let
                        // openDocument mutate the URI underneath that state.
                        param.setResult(null);
                        return;
                    }
                    entry.pendingNativeOpen = null;
                    if (!resetRuntime(entry, "native_document_open")) {
                        entry.pendingNativeOpen = pending;
                        param.setResult(null);
                        return;
                    }
                    // This may be a reload of the same canonical path. The
                    // old attempted-path suppression must not prevent fresh
                    // marker and document admission after the stock open.
                    entry.attemptedPath = null;
                }
            }
        );
        hook(hooks,
            VIEW_MODEL, loader, "turnPage", Integer.TYPE,
            new XC_MethodHook() {
                @Override protected void beforeHookedMethod(MethodHookParam param) {
                    Entry entry = BY_COMPONENT.get(param.thisObject);
                    if (entry == null) return;
                    if (entry.runtime == null) {
                        if (entry.admissionFence) param.setResult(null);
                        return;
                    }
                    int offset = (Integer) param.args[0];
                    if (!entry.runtime.isLandscapeActive()) {
                        param.args[0] = entry.runtime.adjustPortraitTurnOffset(offset);
                        return;
                    }
                    if (!entry.runtime.requestNativeTurn(offset)) {
                        entry.runtime.disableNativeReaderV2(
                            "native_turn_could_not_be_preserved"
                        );
                    }
                    param.setResult(null);
                }
            }
        );
        hook(hooks,
            VIEW_MODEL, loader, "loadPage", Integer.TYPE,
            new XC_MethodHook() {
                @Override protected void beforeHookedMethod(MethodHookParam param) {
                    ArrayDeque<Boolean> reloads = SAME_PAGE_RELOADS.get();
                    if (reloads == null) {
                        reloads = new ArrayDeque<>();
                        SAME_PAGE_RELOADS.set(reloads);
                    }
                    reloads.push(Boolean.FALSE);
                    Entry entry = BY_COMPONENT.get(param.thisObject);
                    if (entry == null) return;
                    if (entry.runtime == null) {
                        if (entry.admissionFence) param.setResult(null);
                        return;
                    }
                    if (entry.runtime.isInternalPageLoad()
                        || !entry.runtime.isLandscapeActive()) return;
                    int target = (Integer) param.args[0];
                    if (Boolean.TRUE.equals(REPLAY_BYPASS.get())) {
                        if (!entry.runtime.deferNativeLoadDuringReplay(target)) {
                            entry.runtime.disableNativeReaderV2(
                                "replayed_link_load_not_authorized"
                            );
                        }
                        param.setResult(null);
                        return;
                    }
                    if (entry.runtime.isCurrentNativePage(target)) {
                        if (entry.runtime.prepareSamePageReload()) {
                            reloads.pop();
                            reloads.push(Boolean.TRUE);
                        } else {
                            // A same-page reload may not bypass an active
                            // transfer. Suppress it until v2 reaches a stable
                            // ownership boundary or retires fail-closed.
                            param.setResult(null);
                        }
                        return;
                    }
                    if (!entry.runtime.requestNavigation(target)) {
                        entry.runtime.disableNativeReaderV2(
                            "native_load_could_not_be_preserved"
                        );
                    }
                    param.setResult(null);
                }

                @Override protected void afterHookedMethod(MethodHookParam param) {
                    ArrayDeque<Boolean> reloads = SAME_PAGE_RELOADS.get();
                    boolean prepared = reloads != null && !reloads.isEmpty()
                        && Boolean.TRUE.equals(reloads.pop());
                    if (reloads != null && reloads.isEmpty()) {
                        SAME_PAGE_RELOADS.remove();
                    }
                    if (!prepared) {
                        return;
                    }
                    Entry entry = BY_COMPONENT.get(param.thisObject);
                    if (entry == null || entry.runtime == null) return;
                    if (param.getThrowable() != null) {
                        entry.runtime.disableNativeReaderV2(
                            "same_page_reload_firmware_failed"
                        );
                    } else {
                        entry.runtime.scheduleRefresh("same_page_reload");
                    }
                }
            }
        );
        hook(hooks,
            VIEW_MODEL, loader, "setScaleRect", android.graphics.RectF.class,
            new XC_MethodHook() {
                @Override protected void beforeHookedMethod(MethodHookParam param) {
                    ArrayDeque<Boolean> changes = SCALE_CHANGES.get();
                    if (changes == null) {
                        changes = new ArrayDeque<>();
                        SCALE_CHANGES.set(changes);
                    }
                    changes.push(Boolean.FALSE);
                    Entry entry = BY_COMPONENT.get(param.thisObject);
                    if (entry == null || entry.runtime == null
                        || entry.runtime.isInternalPageLoad()
                        || !entry.runtime.isLandscapeActive()) return;
                    if (!entry.runtime.prepareNativeScaleChange()) {
                        param.setResult(null);
                        return;
                    }
                    changes.pop();
                    changes.push(Boolean.TRUE);
                }

                @Override protected void afterHookedMethod(MethodHookParam param) {
                    ArrayDeque<Boolean> changes = SCALE_CHANGES.get();
                    boolean prepared = changes != null && !changes.isEmpty()
                        && Boolean.TRUE.equals(changes.pop());
                    if (changes != null && changes.isEmpty()) {
                        SCALE_CHANGES.remove();
                    }
                    if (!prepared) return;
                    Entry entry = BY_COMPONENT.get(param.thisObject);
                    if (entry != null && entry.runtime != null) {
                        entry.runtime.completeNativeScaleChange(
                            param.getThrowable() == null
                        );
                    }
                }
            }
        );
    }

    private static void installInput(
        ClassLoader loader,
        List<XC_MethodHook.Unhook> hooks
    ) {
        hook(hooks,
            ACTIVITY, loader, "dispatchTouchEvent", MotionEvent.class,
            new XC_MethodHook() {
                @Override protected void beforeHookedMethod(MethodHookParam param) {
                    if (Boolean.TRUE.equals(REPLAY_BYPASS.get())) return;
                    MotionEvent event = (MotionEvent) param.args[0];
                    if (event == null || event.getPointerCount() == 0) {
                        return;
                    }
                    Entry entry = entry(param.thisObject);
                    if (entry == null) return;
                    if (entry.runtime == null
                        || admissionFenceContactActive(entry)) {
                        if (entry.admissionFence
                            || admissionFenceContactActive(entry)) {
                            List<RectD> chrome = chromeSnapshot(entry);
                            if (chrome == null || routeAdmissionFenceAndroidContact(
                                entry, event, chrome
                            )) {
                                param.setResult(Boolean.TRUE);
                            }
                        }
                        return;
                    }
                    NativeReaderV2Runtime runtime = entry.runtime;
                    int tool = event.getToolType(event.getActionIndex());
                    // Input dispatch consumes only the immutable rectangles
                    // published by layout/pre-draw. Never walk the Android
                    // view hierarchy while a contact is being dispatched.
                    List<RectD> chrome = chromeSnapshot(entry);
                    if (chrome == null || entry.runtime != runtime) {
                        // Chrome discovery failure retires the runtime. The
                        // triggering contact must not leak into stock writer
                        // handling after its authority disappeared.
                        param.setResult(Boolean.TRUE);
                        return;
                    }
                    boolean consume;
                    if (tool == MotionEvent.TOOL_TYPE_FINGER) {
                        synchronized (entry.stylusRouteLock) {
                            if (event.getActionMasked() == MotionEvent.ACTION_DOWN) {
                                entry.fingerPhysicalContact = true;
                            }
                        }
                        consume = runtime.routeFinger(event, chrome);
                        if (event.getActionMasked() == MotionEvent.ACTION_UP
                            || event.getActionMasked()
                                == MotionEvent.ACTION_CANCEL) {
                            synchronized (entry.stylusRouteLock) {
                                entry.fingerPhysicalContact = false;
                            }
                        }
                    } else if (tool == MotionEvent.TOOL_TYPE_STYLUS
                        || tool == MotionEvent.TOOL_TYPE_ERASER
                        || entry.androidPenContact) {
                        consume = routeAndroidPen(entry, runtime, event, chrome);
                    } else {
                        consume = false;
                    }
                    if (consume) {
                        param.setResult(Boolean.TRUE);
                    }
                }
            }
        );
        hook(hooks,
            NATIVE_CALLBACK, loader, "onDigitalPosition",
            Integer.TYPE, Integer.TYPE,
            new XC_MethodHook() {
                @Override protected void beforeHookedMethod(MethodHookParam param) {
                    NativeReaderV2FirmwareAccess.NativePenSignal signal;
                    try {
                        signal = firmware.inspectNativePenCallback(
                            param.thisObject
                        );
                    } catch (RuntimeException failure) {
                        Log.e(
                            TAG,
                            "native pen callback inspection failed",
                            failure
                        );
                        param.setResult(null);
                        return;
                    }
                    Entry entry = BY_ACTIVITY.get(signal.activity);
                    if (entry == null) return;
                    if (BY_COMPONENT.get(signal.eventCallback) != entry) {
                        if (entry.admissionFence || entry.runtime != null) {
                            param.setResult(null);
                        }
                        return;
                    }
                    if (entry.runtime == null
                        || admissionFenceContactActive(entry)) {
                        if (entry.admissionFence
                            || admissionFenceContactActive(entry)) {
                            List<RectD> chrome = chromeSnapshot(entry);
                            if (chrome == null || routeAdmissionFenceNativePen(
                                entry,
                                (Integer) param.args[0],
                                (Integer) param.args[1],
                                signal.pressure,
                                chrome
                            )) {
                                param.setResult(null);
                            }
                        }
                        return;
                    }
                    NativeReaderV2Runtime runtime = entry.runtime;
                    int x = (Integer) param.args[0];
                    int y = (Integer) param.args[1];
                    int pressure = signal.pressure;
                    boolean contactStart = pressure > 0 && !entry.penContact;
                    List<RectD> chrome = chromeSnapshot(entry);
                    if (chrome == null || entry.runtime != runtime) {
                        // Retiring on chrome failure is fail-closed for the
                        // sample that discovered it as well as future input.
                        param.setResult(null);
                        return;
                    }
                    boolean pass;
                    synchronized (entry.stylusRouteLock) {
                        if (entry.suppressNativeUntilTerminal) {
                            if (pressure <= 0) {
                                entry.suppressNativeUntilTerminal = false;
                                entry.penContact = false;
                                entry.penPass = false;
                                releaseStylusRouteIfComplete(entry);
                            }
                            param.setResult(null);
                            return;
                        }
                    }
                    if (contactStart) {
                        synchronized (entry.stylusRouteLock) {
                            if (!entry.penContact) {
                                entry.penContact = true;
                                entry.penPass = beginStylusRoute(
                                    entry,
                                    runtime,
                                    x,
                                    y,
                                    chrome
                                );
                            }
                        }
                    }
                    if (entry.penContact) {
                        pass = entry.penPass;
                        // The firmware callback is also the authoritative
                        // contact-lifecycle signal. Passing the sample to
                        // Supernote must not make the contact invisible to
                        // v2: presentation callbacks emitted while a native
                        // pen/lasso/eraser/highlighter gesture is live must be
                        // deferred until the matching terminal sample.
                        postOrRoutePen(entry, runtime, x, y, pressure, chrome);
                        if (pressure <= 0) {
                            entry.penContact = false;
                            entry.penPass = false;
                            releaseStylusRouteIfComplete(entry);
                        }
                    } else {
                        pass = runtime.mayPassNativePenImmediately(
                            x, y, chrome
                        );
                        if (!pass) {
                            postOrRoutePen(
                                entry, runtime, x, y, pressure, chrome
                            );
                        }
                    }
                    if (!pass) param.setResult(null);
                }
            }
        );
    }

    private static void installNativeChromeMasks(
        ClassLoader loader,
        List<XC_MethodHook.Unhook> hooks
    ) {
        XC_MethodHook maskChanged = new XC_MethodHook() {
            @Override protected void afterHookedMethod(MethodHookParam param) {
                Entry entry = entry(param.thisObject);
                if (entry != null && entry.runtime != null) {
                    entry.runtime.onNativeDisableAreasChanged();
                }
            }
        };
        hook(hooks,
            ACTIVITY, loader, "sendDisableWriteArea", maskChanged
        );
        hook(hooks,
            ACTIVITY, loader, "sendDisableWriteAreaNotRefreshBitmap", maskChanged
        );
    }

    private static void installSaveWitness(
        ClassLoader loader,
        List<XC_MethodHook.Unhook> hooks
    ) {
        hook(hooks,
            PRESENTER, loader, "sendWriteInfo",
            new XC_MethodHook() {
                @Override protected void afterHookedMethod(MethodHookParam param) {
                    Entry entry = BY_COMPONENT.get(param.thisObject);
                    if (entry == null || entry.runtime == null) return;
                    entry.runtime.onNativeWriterEnableCompleted(
                        param.thisObject,
                        param.getThrowable() == null
                    );
                }
            }
        );
        hook(hooks,
            PRESENTER, loader, "disableHandWrite", String.class,
            new XC_MethodHook() {
                @Override protected void afterHookedMethod(MethodHookParam param) {
                    Entry entry = BY_COMPONENT.get(param.thisObject);
                    if (entry == null || entry.runtime == null) return;
                    entry.runtime.onNativeWriterDisableCompleted(
                        param.thisObject,
                        param.getThrowable() == null
                    );
                }
            }
        );
        hook(hooks,
            NOTE, loader, "screenRotation",
            Integer.TYPE, Integer.TYPE, Integer.TYPE,
            new XC_MethodHook() {
                @Override protected void afterHookedMethod(MethodHookParam param) {
                    Entry entry = BY_COMPONENT.get(param.thisObject);
                    if (entry == null || entry.runtime == null) return;
                    entry.runtime.onNativeWriterGeometryCompleted(
                        param.thisObject,
                        (Integer) param.args[0],
                        (Integer) param.args[1],
                        (Integer) param.args[2],
                        param.getThrowable() == null
                            && Boolean.TRUE.equals(param.getResult())
                    );
                }
            }
        );
        hook(hooks,
            NOTE, loader, "saveMarkData",
            String.class, String.class, Integer.TYPE, Boolean.TYPE,
            new XC_MethodHook() {
                @Override protected void afterHookedMethod(MethodHookParam param) {
                    Entry entry = BY_COMPONENT.get(param.thisObject);
                    if (entry == null || entry.runtime == null) return;
                    entry.runtime.onNativeSaveMarkData(
                        param.thisObject,
                        (String) param.args[0],
                        (Integer) param.args[2],
                        (Boolean) param.args[3],
                        Boolean.TRUE.equals(param.getResult())
                    );
                }
            }
        );
    }

    private static void maybeAdmit(Entry entry, boolean forceRetry) {
        if (entry == null || entry.retired || entry.admitting
            || !entry.resumed) return;
        if (entry.retryAdmissionAfterAuthorityOff) {
            entry.retryAdmissionAfterAuthorityOff = false;
            entry.attemptedPath = null;
            forceRetry = true;
        }
        NativeReaderV2FirmwareAccess.Components components;
        try {
            components = firmware.inspect(entry.activity);
        } catch (RuntimeException notReady) {
            return;
        }
        final String path = components.documentPath;
        if (entry.runtime != null) {
            if (path != null && path.equals(
                entry.runtime.admittedDocumentPath()
            )) {
                if (forceRetry) {
                    revalidateExistingRuntime(entry, path);
                }
                return;
            }
            if (!resetRuntime(entry, "document_changed", false, true)) return;
        }
        if (path == null || !forceRetry && path.equals(entry.attemptedPath)) {
            return;
        }
        // Fence first without touching storage on this hook/UI callback. The
        // serialized worker decides whether a marker candidate exists and
        // releases the fence for ordinary PDFs only after that lookup.
        entry.admissionFence = true;
        entry.admissionFencePath = path;
        indexAdmissionComponents(entry, components);
        ensureChromeTracker(entry);
        entry.attemptedPath = path;
        entry.admitting = true;
        final long admissionLifecycleGeneration = entry.lifecycleGeneration;
        ADMISSION.execute(new Runnable() {
            @Override public void run() {
                NativeReaderV2DocumentGate.Evidence evidence = null;
                Throwable failure = null;
                boolean candidate = true;
                try {
                    candidate = NativeReaderV2DocumentGate
                        .candidateMarkerPresent(path);
                    if (candidate) {
                        evidence = NativeReaderV2DocumentGate.admit(path);
                        if (!NativeReaderV2DocumentGate
                            .evidenceStillCurrent(evidence)) {
                            throw new IllegalStateException(
                                "admission evidence changed before publication"
                            );
                        }
                    }
                } catch (Throwable caught) {
                    if (evidence != null) {
                        evidence.close();
                        evidence = null;
                    }
                    failure = caught;
                }
                final NativeReaderV2DocumentGate.Evidence accepted = evidence;
                final Throwable rejected = failure;
                final boolean markerCandidate = candidate;
                entry.activity.runOnUiThread(guardedHookContinuation(
                    entry,
                    "document_admission",
                    new Runnable() {
                    @Override public void run() {
                        entry.admitting = false;
                        if (entry.retired || BY_ACTIVITY.get(entry.activity) != entry) {
                            releaseEvidence(accepted);
                            return;
                        }
                        if (entry.retryAdmissionAfterAuthorityOff
                            && entry.resumed) {
                            releaseEvidence(accepted);
                            maybeAdmit(entry, true);
                            return;
                        }
                        PendingNativeOpen pendingOpen = entry.pendingNativeOpen;
                        if (pendingOpen != null && entry.runtime == null) {
                            releaseEvidence(accepted);
                            entry.pendingNativeOpen = null;
                            entry.admissionFence = false;
                            entry.admissionFencePath = null;
                            entry.attemptedPath = null;
                            replayNativeDocumentOpen(entry, pendingOpen);
                            return;
                        }
                        if (!entry.resumed || entry.lifecycleGeneration !=
                            admissionLifecycleGeneration) {
                            releaseEvidence(accepted);
                            if (entry.resumed) maybeAdmit(entry, true);
                            return;
                        }
                        if (!path.equals(currentPath(entry))) {
                            releaseEvidence(accepted);
                            return;
                        }
                        if (accepted == null) {
                            Log.i(TAG, "document not admitted path=" + path
                                + " reason=" + (rejected == null
                                    ? "unknown" : rejected.getClass().getSimpleName())
                                + " detail=" + (rejected == null
                                    || rejected.getMessage() == null
                                    ? "none" : rejected.getMessage()));
                            if (!markerCandidate && rejected == null) {
                                entry.admissionFence = false;
                                entry.admissionFencePath = null;
                                retireChromeTrackerWhenUnfenced(entry);
                            }
                            return;
                        }
                        try {
                            entry.runtime = new NativeReaderV2Runtime(
                                entry.activity,
                                accepted,
                                firmware,
                                entry.generation,
                                new NativeReaderV2Runtime.FingerReplayInjector() {
                                    @Override public void replayFingerTap(
                                        Activity activity,
                                        PointD point
                                    ) {
                                        replayFinger(activity, point);
                                    }
                                },
                                new NativeReaderV2Runtime.PhysicalContactFence() {
                                    @Override public boolean stylusContactActive() {
                                        synchronized (entry.stylusRouteLock) {
                                            return entry.penContact
                                                || entry.androidPenContact
                                                || entry.stylusRouteActive;
                                        }
                                    }

                                    @Override public boolean runWhenStylusIdle(
                                        Runnable publication
                                    ) {
                                        synchronized (entry.stylusRouteLock) {
                                            if (entry.penContact
                                                || entry.androidPenContact
                                                || entry.stylusRouteActive) {
                                                return false;
                                            }
                                            publication.run();
                                            return true;
                                        }
                                    }
                                },
                                new NativeReaderV2Runtime.ActivationListener() {
                                    @Override public void
                                        onRuntimeInputAuthorityReady(
                                            NativeReaderV2Runtime readyRuntime
                                        ) {
                                        if (entry.runtime == readyRuntime
                                            && path.equals(currentPath(entry))) {
                                            entry.admissionFence = false;
                                            entry.admissionFencePath = null;
                                        }
                                    }
                                },
                                new NativeReaderV2Runtime.DetachmentListener() {
                                    @Override public void
                                        onRuntimeDetachmentReady(
                                            NativeReaderV2Runtime readyRuntime,
                                            String reason
                                        ) {
                                            if (entry.runtime == readyRuntime) {
                                                PendingNativeOpen pendingOpen =
                                                    entry.pendingNativeOpen;
                                                boolean retireEntry =
                                                    entry.retireAfterDetachment;
                                                boolean retryAdmission =
                                                    entry.retryAdmissionAfterDetachment;
                                                entry.retireAfterDetachment = false;
                                                entry.retryAdmissionAfterDetachment = false;
                                                if (resetRuntime(entry, reason)) {
                                                    if (retireEntry) {
                                                        entry.retired = true;
                                                    } else if (pendingOpen != null
                                                        && "native_document_open"
                                                            .equals(reason)) {
                                                        entry.pendingNativeOpen = null;
                                                        entry.attemptedPath = null;
                                                        replayNativeDocumentOpen(
                                                            entry,
                                                            pendingOpen
                                                        );
                                                    } else if (retryAdmission
                                                        && entry.resumed) {
                                                        maybeAdmit(entry, true);
                                                    }
                                                }
                                            }
                                        }
                                }
                            );
                            final NativeReaderV2Runtime admittedRuntime =
                                entry.runtime;
                            ensureChromeTracker(entry);
                            admittedRuntime.onTrackedNativeChromeChanged(
                                chromeSnapshot(entry)
                            );
                            reindex(entry);
                            entry.runtime.start();
                            Log.i(TAG, "document admitted path=" + path);
                        } catch (Throwable activationFailure) {
                            Log.e(TAG, "document activation failed", activationFailure);
                            if (entry.runtime == null) {
                                releaseEvidence(accepted);
                            } else {
                                retire(entry, "activation_failed");
                            }
                        }
                    }
                }));
            }
        });
    }

    private static void revalidateExistingRuntime(
        Entry entry,
        String path
    ) {
        if (entry == null || entry.retired || entry.admitting
            || entry.runtime == null || path == null) {
            return;
        }
        final NativeReaderV2Runtime expectedRuntime = entry.runtime;
        entry.admitting = true;
        final long admissionLifecycleGeneration = entry.lifecycleGeneration;
        ADMISSION.execute(new Runnable() {
            @Override public void run() {
                boolean verified = false;
                Throwable verificationFailure = null;
                try {
                    verified = expectedRuntime.admissionEvidenceStillCurrent();
                } catch (Throwable failure) {
                    verificationFailure = failure;
                }
                final boolean current = verified;
                final Throwable rejected = verificationFailure;
                entry.activity.runOnUiThread(guardedHookContinuation(
                    entry,
                    "resume_revalidation",
                    new Runnable() {
                    @Override public void run() {
                        entry.admitting = false;
                        if (entry.retired
                            || BY_ACTIVITY.get(entry.activity) != entry
                            || entry.runtime != expectedRuntime) {
                            return;
                        }
                        if (!entry.resumed || entry.lifecycleGeneration !=
                            admissionLifecycleGeneration) {
                            if (entry.resumed) maybeAdmit(entry, true);
                            return;
                        }
                        if (!path.equals(currentPath(entry))) return;
                        if (rejected != null) {
                            Log.e(TAG, "resume authority revalidation failed",
                                rejected);
                        }
                        if (current) {
                            expectedRuntime.onLifecycleResumeRevalidated();
                            return;
                        }
                        if (!resetRuntime(
                                entry,
                                "resume_authority_changed",
                                false,
                                true
                            )) {
                            return;
                        }
                        maybeAdmit(entry, true);
                    }
                }));
            }
        });
    }

    /**
     * Minimal v2-only capability handshake. It deliberately does not depend
     * on legacy Native Spread ownership, JNI interception, or trace state.
     */
    private static synchronized void registerHandshakeReceiver(
        Activity activity
    ) {
        if (handshakeReceiverRegistered || activity == null) return;
        Context context = activity.getApplicationContext();
        if (context == null) {
            throw new IllegalStateException(
                "Native Reader v2 has no application context"
            );
        }
        BroadcastReceiver receiver = new BroadcastReceiver() {
            @Override public void onReceive(
                Context receiverContext,
                Intent request
            ) {
                if (Looper.myLooper() != Looper.getMainLooper()) {
                    Log.e(TAG, "v2 handshake rejected outside main snapshot looper");
                    return;
                }
                if (request == null
                    || !HANDSHAKE_REQUEST.equals(request.getAction())) {
                    return;
                }
                String nonce = request.getStringExtra("nonce");
                String requestedPath = request.getStringExtra("rawDocumentPath");
                int protocol = request.getIntExtra("protocol", -1);
                String expectedJournalPath = request.getStringExtra(
                    "expectedJournalPath"
                );
                long expectedJournalGeneration = request.getLongExtra(
                    "expectedJournalGeneration",
                    -1L
                );
                String expectedJournalAuthoritySha256 = request.getStringExtra(
                    "expectedJournalAuthoritySha256"
                );
                String expectedJournalState = request.getStringExtra(
                    "expectedJournalState"
                );
                String expectedActivationToken = request.getStringExtra(
                    "expectedActivationToken"
                );
                boolean authorityAckRequested = expectedJournalPath != null
                    || expectedJournalGeneration >= 0L
                    || expectedJournalAuthoritySha256 != null
                    || expectedJournalState != null
                    || expectedActivationToken != null;
                if (nonce == null || nonce.length() < 16
                    || protocol != HANDSHAKE_PROTOCOL
                    || requestedPath == null
                    || requestedPath.indexOf('\0') >= 0
                    || authorityAckRequested && (
                        expectedJournalPath == null
                        || expectedJournalPath.indexOf('\0') >= 0
                        || expectedJournalGeneration <= 0L
                        || expectedJournalAuthoritySha256 == null
                        || expectedJournalAuthoritySha256.length() != 64
                        || expectedJournalState == null
                        || expectedActivationToken == null
                    )) {
                    Log.w(TAG, "v2 handshake rejected protocol=" + protocol);
                    return;
                }
                final long handshakeToken = HANDSHAKE_SINGLE_FLIGHT.tryBegin();
                if (handshakeToken == 0L) {
                    Log.w(TAG, "v2 handshake rejected while another request is pending");
                    return;
                }
                final long handshakeDeadlineUptimeMs =
                    SystemClock.uptimeMillis() + HANDSHAKE_PROVIDER_EXPIRY_MS;
                final AtomicReference<Thread> authorityObservationWorker =
                    new AtomicReference<>();
                final Runnable handshakeExpiry = new Runnable() {
                    @Override public void run() {
                        if (HANDSHAKE_SINGLE_FLIGHT.finish(handshakeToken)) {
                            Thread worker = authorityObservationWorker
                                .getAndSet(null);
                            if (worker != null) worker.interrupt();
                            Log.w(TAG, "v2 handshake admission expired");
                        }
                    }
                };
                if (!MAIN_HANDLER.postAtTime(
                        handshakeExpiry,
                        handshakeDeadlineUptimeMs
                    )) {
                    HANDSHAKE_SINGLE_FLIGHT.finish(handshakeToken);
                    Log.w(TAG, "v2 handshake rejected without expiry scheduling");
                    return;
                }
                boolean asynchronousAck = false;
                try {
                    HandshakeSnapshot snapshot = captureHandshakeSnapshot();
                    if (snapshot == null) {
                        Log.w(TAG, "v2 handshake snapshot rejected");
                        return;
                    }
                    HandshakeResolution resolution = resolveHandshake(
                        snapshot,
                        requestedPath
                    );
                    if (resolution == null) {
                        Log.w(TAG, "v2 handshake rejected path authority");
                        return;
                    }
                    if (authorityAckRequested) {
                        final HandshakeExpectation expectation =
                            new HandshakeExpectation(
                                expectedJournalPath,
                                expectedJournalGeneration,
                                expectedJournalAuthoritySha256,
                                expectedJournalState,
                                expectedActivationToken
                            );
                        Thread worker = new Thread(new Runnable() {
                            @Override public void run() {
                                NativeReaderV2DocumentGate.AuthorityObservation
                                    observation = null;
                                try {
                                    NativeReaderV2DocumentGate.AuthorityObservation
                                        candidate = NativeReaderV2DocumentGate
                                            .observeAuthority(requestedPath);
                                    if (expectation.matches(candidate)) {
                                        observation = candidate;
                                    } else {
                                        Log.w(TAG,
                                            "v2 authority ACK rejected exact record");
                                    }
                                } catch (Throwable failure) {
                                    Log.w(TAG,
                                        "v2 authority ACK observation failed closed",
                                        failure);
                                }
                                final NativeReaderV2DocumentGate
                                    .AuthorityObservation acceptedObservation =
                                        observation;
                                boolean posted = MAIN_HANDLER.post(new Runnable() {
                                        @Override public void run() {
                                            try {
                                                if (acceptedObservation != null) {
                                                    publishHandshakeResponse(
                                                        receiverContext,
                                                        nonce,
                                                        snapshot,
                                                        resolution,
                                                        handshakeToken,
                                                        handshakeDeadlineUptimeMs,
                                                        acceptedObservation
                                                    );
                                                }
                                            } finally {
                                                finishHandshake(
                                                    handshakeToken,
                                                    handshakeExpiry
                                                );
                                            }
                                        }
                                    });
                                if (!posted) {
                                    finishHandshake(
                                        handshakeToken,
                                        handshakeExpiry
                                    );
                                    Log.w(TAG,
                                        "v2 authority ACK rejected without main publication");
                                }
                                authorityObservationWorker.compareAndSet(
                                    Thread.currentThread(),
                                    null
                                );
                            }
                        }, "sn-v2-authority-ack-" + handshakeToken);
                        worker.setDaemon(true);
                        if (!authorityObservationWorker.compareAndSet(
                                null,
                                worker
                            )) {
                            throw new IllegalStateException(
                                "authority observation worker already exists"
                            );
                        }
                        worker.start();
                        asynchronousAck = true;
                    } else {
                        publishHandshakeResponse(
                            receiverContext,
                            nonce,
                            snapshot,
                            resolution,
                            handshakeToken,
                            handshakeDeadlineUptimeMs,
                            null
                        );
                    }
                } catch (Throwable failure) {
                    Log.w(TAG, "v2 handshake failed closed", failure);
                } finally {
                    if (!asynchronousAck) {
                        finishHandshake(handshakeToken, handshakeExpiry);
                    }
                }
            }
        };
        try {
            context.registerReceiver(
                receiver,
                new IntentFilter(HANDSHAKE_REQUEST)
            );
        } catch (RuntimeException | Error failure) {
            throw failure;
        }
        handshakeReceiver = receiver;
        handshakeReceiverRegistered = true;
        Log.i(TAG, "v2 handshake receiver registered with in-memory path binding");
    }

    private static void finishHandshake(long token, Runnable expiry) {
        MAIN_HANDLER.removeCallbacks(expiry);
        HANDSHAKE_SINGLE_FLIGHT.finish(token);
    }

    private static HandshakeSnapshot captureHandshakeSnapshot() {
        if (Looper.myLooper() != Looper.getMainLooper()) return null;
        ArrayList<HandshakeCandidate> candidates = new ArrayList<>();
        for (Entry candidate : BY_ACTIVITY.values()) {
            if (candidate == null || candidate.retired
                || candidate.activity.isFinishing()
                || candidate.activity.isDestroyed()) {
                continue;
            }
            NativeReaderV2FirmwareAccess.Components components;
            try {
                components = firmware.inspect(candidate.activity);
            } catch (RuntimeException failure) {
                Log.w(TAG, "v2 handshake snapshot inspection failed", failure);
                return null;
            }
            candidates.add(new HandshakeCandidate(
                candidate,
                candidate.generation,
                candidate.lifecycleGeneration,
                candidate.resumed,
                components.documentPath,
                components
            ));
        }
        return new HandshakeSnapshot(candidates);
    }

    private static HandshakeResolution resolveHandshake(
        HandshakeSnapshot snapshot,
        String requestedPath
    ) {
        if (snapshot == null || requestedPath == null) return null;
        HandshakeCandidate match = null;
        for (HandshakeCandidate candidate : snapshot.candidates) {
            if (candidate.rawPath == null) continue;
            if (!requestedPath.equals(candidate.rawPath)) continue;
            if (match != null && match.entry != candidate.entry) return null;
            match = candidate;
        }
        return match == null
            ? null
            : new HandshakeResolution(match, match.rawPath);
    }

    private static void publishHandshakeResponse(
        Context receiverContext,
        String nonce,
        HandshakeSnapshot snapshot,
        HandshakeResolution resolution,
        long handshakeToken,
        long handshakeDeadlineUptimeMs,
        NativeReaderV2DocumentGate.AuthorityObservation observation
    ) {
        if (Looper.myLooper() != Looper.getMainLooper()
            || receiverContext == null
            || nonce == null
            || resolution == null
            || !handshakeSnapshotStillCurrent(snapshot)
            || !snapshot.candidates.contains(resolution.candidate)) {
            Log.w(TAG, "v2 handshake authority changed before send");
            return;
        }
        Intent response = new Intent(HANDSHAKE_RESPONSE);
        response.setPackage(PLUGIN_HOST_PACKAGE);
        response.putExtra("nonce", nonce);
        response.putExtra("rawDocumentPath", resolution.rawPath);
        response.putExtra("protocol", HANDSHAKE_PROTOCOL);
        response.putExtra("hooksReady", true);
        response.putExtra(
            "moduleVersionCode",
            NativeReaderV2MarkerClaim.MINIMUM_COMPANION_MODULE_VERSION
        );
        response.putExtra(
            "documentApkLength",
            NativeReaderV2PackageAdmission.EXPECTED_APK_LENGTH
        );
        response.putExtra("processId", Process.myPid());
        if (observation != null) {
            response.putExtra("journalPath", observation.journalPath);
            response.putExtra("journalGeneration", observation.generation);
            response.putExtra(
                "journalAuthoritySha256",
                observation.authoritySha256
            );
            response.putExtra("journalState", observation.state);
            response.putExtra(
                "activationToken",
                observation.activationToken
            );
        }
        if (!HANDSHAKE_SINGLE_FLIGHT.currentBefore(
                handshakeToken,
                SystemClock.uptimeMillis(),
                handshakeDeadlineUptimeMs
            )) {
            Log.w(TAG, "v2 handshake publication expired");
            return;
        }
        try {
            receiverContext.sendBroadcast(response);
            Log.i(TAG, "v2 handshake response path="
                + resolution.rawPath);
            if (observation != null && "off".equals(observation.state)) {
                Entry entry = resolution.candidate.entry;
                if (entry != null && !entry.retired
                    && resolution.rawPath.equals(currentPath(entry))) {
                    entry.retryAdmissionAfterAuthorityOff = true;
                    if (!entry.admitting && entry.resumed) {
                        maybeAdmit(entry, true);
                    }
                }
            }
        } catch (RuntimeException failure) {
            Log.w(TAG, "v2 handshake response send failed", failure);
        }
    }

    private static boolean handshakeSnapshotStillCurrent(
        HandshakeSnapshot expected
    ) {
        HandshakeSnapshot actual = captureHandshakeSnapshot();
        if (expected == null || actual == null
            || expected.candidates.size() != actual.candidates.size()) {
            return false;
        }
        for (HandshakeCandidate expectedCandidate : expected.candidates) {
            HandshakeCandidate actualCandidate = null;
            for (HandshakeCandidate candidate : actual.candidates) {
                if (candidate.entry == expectedCandidate.entry) {
                    actualCandidate = candidate;
                    break;
                }
            }
            if (actualCandidate == null
                || expectedCandidate.entryGeneration !=
                    actualCandidate.entryGeneration
                || expectedCandidate.lifecycleGeneration !=
                    actualCandidate.lifecycleGeneration
                || expectedCandidate.resumed != actualCandidate.resumed
                || !sameHandshakePath(
                    expectedCandidate.rawPath,
                    actualCandidate.rawPath
                )
                || !sameHandshakeComponents(
                    expectedCandidate.components,
                    actualCandidate.components
                )) {
                return false;
            }
        }
        return true;
    }

    private static boolean sameHandshakePath(String expected, String actual) {
        return expected == null ? actual == null : expected.equals(actual);
    }

    private static boolean sameHandshakeComponents(
        NativeReaderV2FirmwareAccess.Components expected,
        NativeReaderV2FirmwareAccess.Components actual
    ) {
        return expected != null && actual != null
            && expected.activity == actual.activity
            && expected.viewModel == actual.viewModel
            && expected.presenter == actual.presenter
            && expected.handWriteView == actual.handWriteView
            && expected.eventCallback == actual.eventCallback
            && expected.image == actual.image
            && expected.digestImage == actual.digestImage
            && expected.documentLayout == actual.documentLayout
            && expected.note == actual.note
            && expected.client == actual.client
            && expected.binder == actual.binder
            && expected.documentPath != null
            && expected.documentPath.equals(actual.documentPath);
    }

    private static final class HandshakeCandidate {
        final Entry entry;
        final long entryGeneration;
        final long lifecycleGeneration;
        final boolean resumed;
        final String rawPath;
        final NativeReaderV2FirmwareAccess.Components components;

        HandshakeCandidate(
            Entry entry,
            long entryGeneration,
            long lifecycleGeneration,
            boolean resumed,
            String rawPath,
            NativeReaderV2FirmwareAccess.Components components
        ) {
            this.entry = entry;
            this.entryGeneration = entryGeneration;
            this.lifecycleGeneration = lifecycleGeneration;
            this.resumed = resumed;
            this.rawPath = rawPath;
            this.components = components;
        }
    }

    private static final class HandshakeSnapshot {
        final List<HandshakeCandidate> candidates;

        HandshakeSnapshot(List<HandshakeCandidate> candidates) {
            this.candidates = Collections.unmodifiableList(
                new ArrayList<>(candidates)
            );
        }
    }

    private static final class HandshakeResolution {
        final HandshakeCandidate candidate;
        final String rawPath;

        HandshakeResolution(
            HandshakeCandidate candidate,
            String rawPath
        ) {
            this.candidate = candidate;
            this.rawPath = rawPath;
        }
    }

    private static final class HandshakeExpectation {
        final String journalPath;
        final long generation;
        final String authoritySha256;
        final String state;
        final String activationToken;

        HandshakeExpectation(
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

        boolean matches(
            NativeReaderV2DocumentGate.AuthorityObservation observation
        ) {
            return observation != null
                && generation == observation.generation
                && journalPath.equals(observation.journalPath)
                && authoritySha256.equals(observation.authoritySha256)
                && state.equals(observation.state)
                && activationToken.equals(observation.activationToken);
        }
    }

    private static void releaseEvidence(
        NativeReaderV2DocumentGate.Evidence evidence
    ) {
        if (evidence == null) return;
        try {
            ADMISSION.execute(evidence::close);
        } catch (RuntimeException rejected) {
            // This path runs only while the process is already losing its
            // admission executor. Release the lease rather than leak writer
            // authority into a future Activity generation.
            evidence.close();
        }
    }

    private static void postOrRoutePen(
        Entry entry,
        NativeReaderV2Runtime runtime,
        int x,
        int y,
        int pressure,
        List<RectD> chrome
    ) {
        long now = SystemClock.uptimeMillis();
        if (Looper.myLooper() == entry.activity.getMainLooper()) {
            runtime.routeNativePenPosition(x, y, pressure, now, chrome);
        } else {
            runtime.postNativePenPosition(x, y, pressure, now, chrome);
        }
    }

    /**
     * Mirrors the native callback's one-decision-per-contact invariant for
     * Android's parallel stylus stream. The native callback remains the
     * authority for activation; this path merely prevents leaked UI effects.
     */
    private static boolean routeAndroidPen(
        Entry entry,
        NativeReaderV2Runtime runtime,
        MotionEvent event,
        List<RectD> chrome
    ) {
        int action = event.getActionMasked();
        if (action == MotionEvent.ACTION_DOWN) {
            int index = event.getActionIndex();
            synchronized (entry.stylusRouteLock) {
                entry.androidPenContact = true;
                entry.nativeTerminalGeneration++;
                entry.androidPenPointerId = event.getPointerId(index);
                entry.androidPenPass = beginStylusRoute(
                    entry,
                    runtime,
                    event.getX(index),
                    event.getY(index),
                    chrome
                );
            }
            return !entry.androidPenPass;
        }
        if (!entry.androidPenContact) return false;
        boolean consume = !entry.androidPenPass;
        if (action == MotionEvent.ACTION_UP
            || action == MotionEvent.ACTION_CANCEL) {
            entry.androidPenContact = false;
            entry.androidPenPass = false;
            entry.androidPenPointerId = -1;
            releaseStylusRouteIfComplete(entry);
            scheduleNativeTerminalGuard(entry, runtime);
            return consume;
        }
        if (event.findPointerIndex(entry.androidPenPointerId) < 0) {
            entry.androidPenContact = false;
            entry.androidPenPass = false;
            entry.androidPenPointerId = -1;
            releaseStylusRouteIfComplete(entry);
            return true;
        }
        return consume;
    }

    /**
     * Android dispatch and the native digital-position callback describe the
     * same physical stylus contact. Whichever stream observes DOWN first owns
     * this single immutable decision until every participating stream ends.
     */
    private static boolean beginStylusRoute(
        Entry entry,
        NativeReaderV2Runtime runtime,
        double x,
        double y,
        List<RectD> chrome
    ) {
        synchronized (entry.stylusRouteLock) {
            if (!entry.stylusRouteActive) {
                entry.stylusRoutePass = !entry.fingerPhysicalContact
                    && runtime.beginNativePenContactImmediately(x, y, chrome);
                entry.stylusRouteActive = true;
            }
            return entry.stylusRoutePass;
        }
    }

    private static void scheduleNativeTerminalGuard(
        Entry entry,
        NativeReaderV2Runtime runtime
    ) {
        final long generation = ++entry.nativeTerminalGeneration;
        entry.activity.getWindow().getDecorView().postDelayed(
            guardedHookContinuation(
                entry,
                "native_terminal_guard",
                new Runnable() {
                @Override public void run() {
                    if (entry.retired || entry.runtime != runtime
                        || entry.nativeTerminalGeneration != generation) {
                        return;
                    }
                    synchronized (entry.stylusRouteLock) {
                        if (!entry.penContact || entry.androidPenContact) return;
                        entry.suppressNativeUntilTerminal = true;
                        entry.penPass = false;
                        entry.stylusRoutePass = false;
                    }
                    runtime.cancelMissingNativePenTerminal();
                    Log.w(TAG,
                        "native pen pressure-zero terminal missing; "
                            + "contact cancelled fail-closed");
                }
            }),
            NATIVE_PEN_TERMINAL_GRACE_MS
        );
    }

    private static void releaseStylusRouteIfComplete(Entry entry) {
        boolean released = false;
        synchronized (entry.stylusRouteLock) {
            if (!entry.penContact && !entry.androidPenContact) {
                entry.stylusRouteActive = false;
                entry.stylusRoutePass = false;
                released = true;
            }
        }
        NativeReaderV2Runtime runtime = entry.runtime;
        if (released && runtime != null) {
            runtime.postPhysicalContactFenceReleased();
        }
    }

    private static boolean stylusRouteDecisionActive(Entry entry) {
        synchronized (entry.stylusRouteLock) {
            return entry.stylusRouteActive;
        }
    }

    private static void clearStylusContact(Entry entry) {
        synchronized (entry.stylusRouteLock) {
            entry.penContact = false;
            entry.penPass = false;
            entry.androidPenContact = false;
            entry.androidPenPass = false;
            entry.androidPenPointerId = -1;
            entry.stylusRouteActive = false;
            entry.stylusRoutePass = false;
            entry.suppressNativeUntilTerminal = false;
            entry.fingerPhysicalContact = false;
            entry.fenceAndroidContact = false;
            entry.fenceAndroidPass = false;
            entry.fenceAndroidPointerId = -1;
            entry.fenceNativePenContact = false;
            entry.fenceNativePenPass = false;
            entry.nativeTerminalGeneration++;
        }
    }

    private static void replayFinger(Activity activity, PointD point) {
        if (Looper.myLooper() != activity.getMainLooper()) {
            throw new IllegalStateException("finger replay must run on owner thread");
        }
        long downTime = SystemClock.uptimeMillis();
        MotionEvent down = MotionEvent.obtain(
            downTime, downTime, MotionEvent.ACTION_DOWN,
            (float) point.x, (float) point.y, 0
        );
        MotionEvent up = MotionEvent.obtain(
            downTime, downTime + 16L, MotionEvent.ACTION_UP,
            (float) point.x, (float) point.y, 0
        );
        down.setSource(InputDevice.SOURCE_TOUCHSCREEN);
        up.setSource(InputDevice.SOURCE_TOUCHSCREEN);
        Boolean previous = REPLAY_BYPASS.get();
        REPLAY_BYPASS.set(Boolean.TRUE);
        try {
            if (!activity.dispatchTouchEvent(down)
                || !activity.dispatchTouchEvent(up)) {
                throw new IllegalStateException("native finger replay was rejected");
            }
        } finally {
            down.recycle();
            up.recycle();
            if (previous == null) REPLAY_BYPASS.remove();
            else REPLAY_BYPASS.set(previous);
        }
    }

    private static String currentPath(Entry entry) {
        try {
            return firmware.inspect(entry.activity).documentPath;
        } catch (RuntimeException failure) {
            return null;
        }
    }

    private static void reindex(Entry entry) {
        if (entry == null || entry.retired || entry.runtime == null) return;
        try {
            NativeReaderV2FirmwareAccess.Components components =
                firmware.inspect(entry.activity);
            ArrayList<Object> current = new ArrayList<>();
            addIdentity(current, entry.activity);
            addIdentity(current, components.viewModel);
            addIdentity(current, components.presenter);
            addIdentity(current, components.handWriteView);
            addIdentity(current, components.eventCallback);
            addIdentity(current, components.image);
            addIdentity(current, components.note);
            for (Object previous : entry.indexed) {
                if (!containsIdentity(current, previous)) {
                    BY_COMPONENT.remove(previous, entry);
                    entry.indexed.remove(previous);
                }
            }
            for (Object component : current) index(entry, component);
        } catch (RuntimeException failure) {
            retire(entry, "component_reindex_failed");
        }
    }

    private static void indexAdmissionComponents(
        Entry entry,
        NativeReaderV2FirmwareAccess.Components components
    ) {
        if (entry == null || components == null || !entry.admissionFence) return;
        index(entry, entry.activity);
        index(entry, components.viewModel);
        index(entry, components.presenter);
        index(entry, components.handWriteView);
        index(entry, components.eventCallback);
        index(entry, components.image);
        index(entry, components.note);
    }

    private static void addIdentity(List<Object> values, Object candidate) {
        if (candidate != null && !containsIdentity(values, candidate)) {
            values.add(candidate);
        }
    }

    private static boolean containsIdentity(
        List<Object> values,
        Object candidate
    ) {
        for (Object value : values) {
            if (value == candidate) return true;
        }
        return false;
    }

    private static void index(Entry entry, Object component) {
        if (component != null) {
            Entry previous = BY_COMPONENT.putIfAbsent(component, entry);
            if (previous != null && previous != entry) {
                throw new IllegalStateException(
                    "native component is claimed by another live activity"
                );
            }
            entry.indexed.add(component);
        }
    }

    private static List<RectD> chromeSnapshot(Entry entry) {
        NativeReaderV2ChromeTracker tracker = entry == null ? null : entry.chrome;
        return tracker == null ? Collections.<RectD>emptyList() : tracker.snapshot();
    }

    private static void ensureChromeTracker(final Entry entry) {
        if (entry == null || entry.retired || entry.chrome != null) return;
        try {
            entry.chrome = new NativeReaderV2ChromeTracker(
                entry.activity,
                new Runnable() {
                    @Override public void run() {
                        entry.admissionFence = true;
                        entry.chrome = null;
                        NativeReaderV2Runtime runtime = entry.runtime;
                        if (runtime != null) {
                            retire(entry, "native_chrome_discovery_failed");
                        } else {
                            Log.e(TAG,
                                "native chrome discovery failed while admission fenced");
                        }
                    }
                },
                new Runnable() {
                    @Override public void run() {
                        NativeReaderV2Runtime runtime = entry.runtime;
                        NativeReaderV2ChromeTracker tracker = entry.chrome;
                        if (runtime != null && tracker != null) {
                            runtime.onTrackedNativeChromeChanged(tracker.snapshot());
                        }
                    }
                }
            );
        } catch (RuntimeException failure) {
            entry.chrome = null;
            entry.admissionFence = true;
            Log.e(TAG, "native chrome tracker could not start", failure);
        }
    }

    private static void retireChromeTracker(Entry entry) {
        if (entry == null) return;
        NativeReaderV2ChromeTracker tracker = entry.chrome;
        entry.chrome = null;
        if (tracker != null) tracker.retire();
    }

    private static boolean admissionFenceContactActive(Entry entry) {
        if (entry == null) return false;
        synchronized (entry.stylusRouteLock) {
            return entry.fenceAndroidContact || entry.fenceNativePenContact;
        }
    }

    private static void retireChromeTrackerWhenUnfenced(final Entry entry) {
        if (entry == null || entry.admissionFence || entry.runtime != null
            || admissionFenceContactActive(entry)) return;
        if (Looper.myLooper() == entry.activity.getMainLooper()) {
            retireChromeTracker(entry);
            return;
        }
        entry.activity.getWindow().getDecorView().post(
            guardedHookContinuation(
                entry,
                "retire_unfenced_chrome_tracker",
                new Runnable() {
                    @Override public void run() {
                        if (!entry.admissionFence && entry.runtime == null
                            && !admissionFenceContactActive(entry)) {
                            retireChromeTracker(entry);
                        }
                    }
                }
            )
        );
    }

    private static boolean pointInsideChrome(
        double x,
        double y,
        List<RectD> chrome
    ) {
        if (chrome == null) return false;
        for (RectD rect : chrome) {
            if (rect != null && rect.contains(x, y)) return true;
        }
        return false;
    }

    /**
     * A rejected marker must fence the document without making the native
     * recovery controls unreachable. Classify once at DOWN and retain that
     * decision through the matching terminal event.
     */
    private static boolean routeAdmissionFenceAndroidContact(
        Entry entry,
        MotionEvent event,
        List<RectD> chrome
    ) {
        int action = event.getActionMasked();
        synchronized (entry.stylusRouteLock) {
            if (action == MotionEvent.ACTION_DOWN) {
                int index = event.getActionIndex();
                entry.fenceAndroidContact = true;
                entry.fenceAndroidPointerId = event.getPointerId(index);
                entry.fenceAndroidPass = pointInsideChrome(
                    event.getX(index), event.getY(index), chrome
                );
                Log.i(TAG, "admission fence contact route="
                    + (entry.fenceAndroidPass
                        ? "native_chrome" : "blocked_document"));
            }
            if (!entry.fenceAndroidContact) return true;
            boolean consume = !entry.fenceAndroidPass;
            if (action == MotionEvent.ACTION_UP
                || action == MotionEvent.ACTION_CANCEL
                || event.findPointerIndex(entry.fenceAndroidPointerId) < 0) {
                entry.fenceAndroidContact = false;
                entry.fenceAndroidPass = false;
                entry.fenceAndroidPointerId = -1;
            }
            if (!entry.fenceAndroidContact) {
                retireChromeTrackerWhenUnfenced(entry);
            }
            return consume;
        }
    }

    private static boolean routeAdmissionFenceNativePen(
        Entry entry,
        int x,
        int y,
        int pressure,
        List<RectD> chrome
    ) {
        synchronized (entry.stylusRouteLock) {
            if (pressure > 0 && !entry.fenceNativePenContact) {
                entry.fenceNativePenContact = true;
                entry.fenceNativePenPass = pointInsideChrome(x, y, chrome);
            }
            boolean consume = !entry.fenceNativePenContact
                || !entry.fenceNativePenPass;
            if (pressure <= 0) {
                entry.fenceNativePenContact = false;
                entry.fenceNativePenPass = false;
            }
            if (!entry.fenceNativePenContact) {
                retireChromeTrackerWhenUnfenced(entry);
            }
            return consume;
        }
    }

    private static Entry entry(Object activity) {
        return activity == null ? null : BY_ACTIVITY.get(activity);
    }

    private static Runnable guardedHookContinuation(
        Entry entry,
        String label,
        Runnable action
    ) {
        if (action == null) {
            throw new IllegalArgumentException("hook continuation is required");
        }
        return new Runnable() {
            @Override public void run() {
                if (entry == null || entry.retired) return;
                try {
                    action.run();
                } catch (Throwable failure) {
                    Log.e(TAG, "hook continuation failed label=" + label,
                        failure);
                    entry.admissionFence = true;
                    NativeReaderV2Runtime runtime = entry.runtime;
                    if (runtime != null) {
                        runtime.disableNativeReaderV2(
                            "hook_continuation_failed:" + label
                        );
                    }
                }
            }
        };
    }

    private static void retire(Entry entry, String reason) {
        if (entry == null || entry.retired) return;
        if (resetRuntime(entry, reason, true, false)) entry.retired = true;
    }

    private static boolean resetRuntime(Entry entry, String reason) {
        return resetRuntime(entry, reason, false, false);
    }

    private static boolean resetRuntime(
        Entry entry,
        String reason,
        boolean retireAfterDetachment,
        boolean retryAdmissionAfterDetachment
    ) {
        if (entry == null) return true;
        NativeReaderV2Runtime runtime = entry.runtime;
        NativeReaderV2ChromeTracker chrome = entry.chrome;
        if (runtime != null && !runtime.retire(reason)) {
            entry.retireAfterDetachment |= retireAfterDetachment;
            entry.retryAdmissionAfterDetachment |= retryAdmissionAfterDetachment;
            Log.e(TAG, "runtime reset deferred by fail-closed containment reason="
                + reason);
            return false;
        }
        entry.runtime = null;
        entry.chrome = null;
        if (chrome != null) chrome.retire();
        for (Object component : entry.indexed) {
            BY_COMPONENT.remove(component, entry);
        }
        entry.indexed.clear();
        clearStylusContact(entry);
        return true;
    }

    private static void releaseDestroyedEntry(Entry entry, String reason) {
        if (entry == null) return;
        entry.retired = true;
        NativeReaderV2Runtime runtime = entry.runtime;
        NativeReaderV2ChromeTracker chrome = entry.chrome;
        entry.runtime = null;
        entry.chrome = null;
        entry.pendingNativeOpen = null;
        if (runtime != null) runtime.retireAfterNativeDestroy(reason);
        if (chrome != null) chrome.retire();
        for (Object component : entry.indexed) {
            BY_COMPONENT.remove(component, entry);
        }
        entry.indexed.clear();
        clearStylusContact(entry);
    }

    private static void replayNativeDocumentOpen(
        Entry entry,
        PendingNativeOpen pending
    ) {
        Boolean previous = DOCUMENT_OPEN_BYPASS.get();
        DOCUMENT_OPEN_BYPASS.set(Boolean.TRUE);
        try {
            // This Xposed API level does not expose invokeOriginalMethod.
            // Invoke the exact captured overload reflectively; the hook is
            // entered again, but DOCUMENT_OPEN_BYPASS makes that one replay
            // pass through without scheduling a second restoration.
            pending.method.setAccessible(true);
            pending.method.invoke(pending.receiver, pending.arguments);
            Log.i(TAG, "queued native document open replayed after stock restore");
        } catch (Throwable failure) {
            entry.admissionFence = true;
            Log.e(TAG, "queued native document open replay failed", failure);
            retire(entry, "native_document_open_replay_failed");
        } finally {
            if (previous == null) DOCUMENT_OPEN_BYPASS.remove();
            else DOCUMENT_OPEN_BYPASS.set(previous);
        }
    }

    private static final class Entry {
        final Activity activity;
        final long generation;
        final java.util.Set<Object> indexed =
            Collections.newSetFromMap(new ConcurrentHashMap<Object, Boolean>());
        volatile NativeReaderV2Runtime runtime;
        volatile NativeReaderV2ChromeTracker chrome;
        volatile String attemptedPath;
        volatile boolean admitting;
        volatile boolean retired;
        volatile boolean resumed;
        volatile boolean admissionFence;
        volatile String admissionFencePath;
        volatile boolean retryAdmissionAfterAuthorityOff;
        volatile PendingNativeOpen pendingNativeOpen;
        volatile boolean retireAfterDetachment;
        volatile boolean retryAdmissionAfterDetachment;
        volatile long lifecycleGeneration;
        volatile boolean penContact;
        volatile boolean penPass;
        volatile boolean androidPenContact;
        volatile boolean androidPenPass;
        int androidPenPointerId = -1;
        final Object stylusRouteLock = new Object();
        boolean stylusRouteActive;
        boolean stylusRoutePass;
        boolean suppressNativeUntilTerminal;
        boolean fingerPhysicalContact;
        boolean fenceAndroidContact;
        boolean fenceAndroidPass;
        int fenceAndroidPointerId = -1;
        boolean fenceNativePenContact;
        boolean fenceNativePenPass;
        long nativeTerminalGeneration;

        Entry(Activity activity, long generation) {
            this.activity = activity;
            this.generation = generation;
        }
    }

    private static final class PendingNativeOpen {
        final Method method;
        final Object receiver;
        final Object[] arguments;

        PendingNativeOpen(Method method, Object receiver, Object[] arguments) {
            if (method == null || receiver == null || arguments == null) {
                throw new IllegalArgumentException(
                    "pending native document open is incomplete"
                );
            }
            this.method = method;
            this.receiver = receiver;
            this.arguments = arguments;
        }
    }
}
