package com.techrebbe.supernote.spreadprobe.v2android;

import android.app.Activity;
import android.graphics.Rect;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewTreeObserver;

import com.techrebbe.supernote.spreadprobe.v2.RectD;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;

/**
 * Owner-thread producer of immutable native-chrome rectangles. Pen callbacks
 * only read {@link #snapshot()}; they never traverse Android views.
 */
public final class NativeReaderV2ChromeTracker {
    private static final int MAX_DECOR_AREA_PERCENT = 45;

    private final Activity activity;
    private final View decor;
    private final Runnable failureHandler;
    private final Runnable changeHandler;
    private final ViewTreeObserver.OnGlobalLayoutListener listener;
    private final ViewTreeObserver.OnPreDrawListener preDrawListener;
    private volatile List<RectD> published = Collections.emptyList();
    private volatile String signature = "";
    private boolean retired;

    private static volatile Object windowManagerGlobal;
    private static volatile Method windowManagerGetWindowViews;
    private static volatile Field windowManagerViewsField;
    public NativeReaderV2ChromeTracker(
        Activity activity,
        Runnable failureHandler,
        Runnable changeHandler
    ) {
        if (activity == null || activity.getWindow() == null
            || failureHandler == null || changeHandler == null) {
            throw new IllegalArgumentException("activity window is required");
        }
        this.activity = activity;
        this.failureHandler = failureHandler;
        this.changeHandler = changeHandler;
        this.decor = activity.getWindow().getDecorView();
        if (decor == null) {
            throw new IllegalArgumentException("activity decor is required");
        }
        listener = new ViewTreeObserver.OnGlobalLayoutListener() {
            @Override public void onGlobalLayout() {
                refresh();
            }
        };
        preDrawListener = new ViewTreeObserver.OnPreDrawListener() {
            @Override public boolean onPreDraw() {
                // Translation-only toolbar/menu movement need not produce a
                // global-layout callback. Publish the final rectangles before
                // that frame is drawable, never from an input callback.
                refresh();
                return true;
            }
        };
        ViewTreeObserver observer = decor.getViewTreeObserver();
        observer.addOnGlobalLayoutListener(listener);
        observer.addOnPreDrawListener(preDrawListener);
        decor.post(new Runnable() {
            @Override public void run() {
                refresh();
            }
        });
    }

    /** Constant-time immutable publication for input routing. */
    public List<RectD> snapshot() {
        return published;
    }

    public void refresh() {
        assertOwnerThread();
        if (retired || decor.getWidth() <= 0 || decor.getHeight() <= 0) return;
        try {
            TreeMap<String, RectD> captured = new TreeMap<>();
            long decorArea = (long) decor.getWidth() * (long) decor.getHeight();
            collect(decor, false, decorArea, captured);
            collectAdditionalWindows(decorArea, captured);
            if (retired) return;
            StringBuilder nextSignature = new StringBuilder();
            for (Map.Entry<String, RectD> entry : captured.entrySet()) {
                nextSignature.append(entry.getKey()).append(';');
            }
            String encoded = nextSignature.toString();
            if (encoded.equals(signature)) return;
            signature = encoded;
            published = Collections.unmodifiableList(
                new ArrayList<>(captured.values())
            );
            changeHandler.run();
        } catch (Throwable failure) {
            failClosed();
        }
    }

    public void retire() {
        assertOwnerThread();
        retired = true;
        published = Collections.emptyList();
        ViewTreeObserver observer = decor.getViewTreeObserver();
        if (observer.isAlive()) {
            observer.removeOnGlobalLayoutListener(listener);
            observer.removeOnPreDrawListener(preDrawListener);
        }
    }

    private void collectAdditionalWindows(
        long decorArea,
        TreeMap<String, RectD> captured
    ) {
        try {
            Object global = windowManagerGlobal;
            Method viewsMethod = windowManagerGetWindowViews;
            Field viewsField = windowManagerViewsField;
            if (global == null || viewsMethod == null && viewsField == null) {
                synchronized (NativeReaderV2ChromeTracker.class) {
                    global = windowManagerGlobal;
                    viewsMethod = windowManagerGetWindowViews;
                    viewsField = windowManagerViewsField;
                    if (global == null || viewsMethod == null && viewsField == null) {
                        Class<?> type = Class.forName(
                            "android.view.WindowManagerGlobal"
                        );
                        Method getInstance = type.getDeclaredMethod("getInstance");
                        getInstance.setAccessible(true);
                        global = getInstance.invoke(null);
                        try {
                            viewsMethod = type.getDeclaredMethod("getWindowViews");
                            viewsMethod.setAccessible(true);
                        } catch (NoSuchMethodException missing) {
                            viewsField = type.getDeclaredField("mViews");
                            viewsField.setAccessible(true);
                        }
                        windowManagerGlobal = global;
                        windowManagerGetWindowViews = viewsMethod;
                        windowManagerViewsField = viewsField;
                    }
                }
            }
            Object windows = viewsMethod != null
                ? viewsMethod.invoke(global) : viewsField.get(global);
            if (!(windows instanceof Iterable<?>)) {
                throw new IllegalStateException(
                    "native window inventory is not iterable"
                );
            }
            for (Object candidate : (Iterable<?>) windows) {
                if (!(candidate instanceof View) || candidate == decor) continue;
                View root = (View) candidate;
                boolean chromeWindow = containerMarker(
                    resourceName(root),
                    description(root),
                    root.getClass().getName()
                );
                collect(root, chromeWindow, decorArea, captured);
            }
        } catch (Throwable failure) {
            // The EMR stream can bypass ordinary Android window dispatch.
            // Continuing without popover geometry could therefore route a
            // toolbar/lasso contact into the active document writer. Retire
            // the entire feature rather than silently weakening authority.
            failClosed();
        }
    }

    private void failClosed() {
        if (retired) return;
        published = Collections.emptyList();
        retired = true;
        try {
            failureHandler.run();
        } catch (Throwable ignored) {
            // The caller's runtime fence remains installed. Never propagate a
            // queued layout/predraw failure into the document UI thread.
        }
    }

    private static void collect(
        View view,
        boolean insideChrome,
        long decorArea,
        TreeMap<String, RectD> captured
    ) {
        if (view == null || view.getVisibility() != View.VISIBLE
            || !view.isShown() || view.getAlpha() <= 0.0f) return;
        String resource = resourceName(view);
        String description = description(view);
        String className = view.getClass().getName();
        boolean container = insideChrome
            || containerMarker(resource, description, className);
        Rect visible = new Rect();
        boolean hasRect = view.getGlobalVisibleRect(visible)
            && visible.width() > 0 && visible.height() > 0;
        long area = hasRect ? (long) visible.width() * visible.height() : 0L;
        boolean bounded = decorArea > 0L
            && area * 100L <= decorArea * MAX_DECOR_AREA_PERCENT;
        boolean described = !description.isEmpty()
            && !"TODO".equalsIgnoreCase(description)
            && !"pageBar".equalsIgnoreCase(description);
        if (hasRect && bounded && container
            && (described || resourceMarker(resource)
                || classMarker(className))) {
            String source = !resource.isEmpty() ? resource
                : (!description.isEmpty() ? "desc:" + description
                    : "class:" + className);
            String key = visible.left + "," + visible.top + ","
                + visible.right + "," + visible.bottom + ":" + source;
            captured.put(key, new RectD(
                visible.left,
                visible.top,
                visible.right,
                visible.bottom
            ));
        }
        if (view instanceof ViewGroup) {
            ViewGroup group = (ViewGroup) view;
            for (int index = 0; index < group.getChildCount(); index++) {
                collect(group.getChildAt(index), container, decorArea, captured);
            }
        }
    }

    private static String resourceName(View view) {
        if (view == null || view.getId() == View.NO_ID) return "";
        try {
            return view.getResources().getResourceEntryName(view.getId());
        } catch (Throwable ignored) {
            return "";
        }
    }

    private static String description(View view) {
        CharSequence value = view == null ? null : view.getContentDescription();
        return value == null ? "" : value.toString().trim();
    }

    private static boolean containerMarker(
        String resourceName,
        String description,
        String className
    ) {
        String resource = lower(resourceName);
        String desc = lower(description);
        return resource.contains("tool_bar")
            || resource.contains("toolbar")
            || resource.contains("pagebar")
            || resource.contains("page_bar")
            || resource.contains("menu")
            || resource.contains("popup")
            || resource.contains("popover")
            || resource.contains("selection")
            || resource.contains("select_panel")
            || resource.contains("lasso")
            || classMarker(className)
            || "pagebar".equals(desc);
    }

    private static boolean classMarker(String className) {
        String type = lower(className);
        return type.contains("toolbar") || type.contains("menuview")
            || type.contains("popup") || type.contains("popover");
    }

    private static boolean resourceMarker(String resourceName) {
        String resource = lower(resourceName);
        return resource.contains("tool_bar")
            || resource.contains("toolbar")
            || resource.contains("pagebar")
            || resource.contains("page_bar")
            || resource.contains("menu")
            || resource.contains("popup")
            || resource.contains("popover")
            || resource.contains("selection")
            || resource.contains("select_panel")
            || resource.contains("lasso")
            || resource.equals("side_pagebar")
            || resource.startsWith("btn_")
            || resource.startsWith("btv_");
    }

    private static String lower(String value) {
        return value == null ? "" : value.toLowerCase(Locale.ROOT);
    }

    private void assertOwnerThread() {
        if (Thread.currentThread() != activity.getMainLooper().getThread()) {
            throw new IllegalStateException("chrome tracker used off owner thread");
        }
    }
}
