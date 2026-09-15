package com.techrebbe.supernote.viewportdisplayprobe;

import android.app.Activity;
import android.content.pm.PackageManager;
import android.content.res.Configuration;
import android.graphics.Color;
import android.hardware.display.DisplayManager;
import android.hardware.display.VirtualDisplay;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.DisplayMetrics;
import android.util.Log;
import android.view.Gravity;
import android.view.MotionEvent;
import android.view.SurfaceHolder;
import android.view.SurfaceView;
import android.view.View;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TextView;
import com.techrebbe.supernote.viewportprobe.DisplayProbeLayout;
import com.techrebbe.supernote.viewportprobe.DisplayProbeLifecycle;
import java.util.UUID;
import java.lang.ref.WeakReference;

/**
 * Isolated DISPLAY-ONLY experiment. Never opens Document, injects input, or
 * programs the singleton pen service. Consuming MotionEvent here is NOT a
 * safety barrier for Supernote's separate direct-pen path.
 */
public final class DisplayProbeActivity extends Activity implements SurfaceHolder.Callback {
    private static final String TAG = "NATIVE_VIEWPORT_DISPLAY";
    private static WeakReference<DisplayProbeActivity> owner = new WeakReference<>(null);
    private final Handler main = new Handler(Looper.getMainLooper());
    private final String instance = UUID.randomUUID().toString();
    private FrameLayout root;
    private SurfaceView surface;
    private TextView status;
    private LinearLayout controls;
    private DisplayProbeLifecycle lifecycle;
    private VirtualDisplay display;
    private DisplayProbeLayout.Placement requested = DisplayProbeLayout.Placement.LEFT;
    private long generation;
    private String failure;
    private boolean calibrationLaunched;
    private boolean closing;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        lifecycle = new DisplayProbeLifecycle(state != null);
        if (state != null) failure = "restored instance stopped; close and reopen probe to restart";
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_FULLSCREEN);
        getWindow().getDecorView().setSystemUiVisibility(View.SYSTEM_UI_FLAG_FULLSCREEN
                | View.SYSTEM_UI_FLAG_HIDE_NAVIGATION | View.SYSTEM_UI_FLAG_IMMERSIVE_STICKY);
        root = new FrameLayout(this);
        root.setBackgroundColor(Color.LTGRAY);
        status = new TextView(this);
        status.setTextColor(Color.BLACK);
        status.setBackgroundColor(Color.WHITE);
        status.setTextSize(16);
        status.setPadding(8, 8, 8, 8);
        setContentView(root);
        if (Build.VERSION.SDK_INT != 30 || !"Supernote Nomad".equals(Build.MODEL)
                || !getPackageManager().hasSystemFeature(PackageManager.FEATURE_ACTIVITIES_ON_SECONDARY_DISPLAYS)) {
            root.addView(status);
            fail("pinned Nomad Android 11 / secondary-display capability required");
            return;
        }
        owner = new WeakReference<>(this);
        surface = new SurfaceView(this);
        surface.getHolder().setFixedSize(DisplayProbeLayout.BUFFER_WIDTH, DisplayProbeLayout.BUFFER_HEIGHT);
        surface.getHolder().addCallback(this);
        surface.setOnTouchListener((view, event) -> {
            if (event.getActionMasked() == MotionEvent.ACTION_UP && event.getPointerCount() == 1
                    && controls != null && failure == null) {
                controls.setVisibility(controls.getVisibility() == View.VISIBLE ? View.GONE : View.VISIBLE);
            }
            return true; // no forwarding/injection
        });
        root.addView(surface, new FrameLayout.LayoutParams(3, 4));
        controls = new LinearLayout(this);
        controls.setOrientation(LinearLayout.VERTICAL);
        controls.setBackgroundColor(Color.WHITE);
        controls.addView(status);
        LinearLayout buttons = new LinearLayout(this);
        for (DisplayProbeLayout.Placement placement : DisplayProbeLayout.Placement.values()) {
            Button button = new Button(this);
            button.setText(placement.name());
            button.setOnClickListener(view -> { requested = placement; layoutSurface(); });
            buttons.addView(button);
        }
        Button close = new Button(this);
        close.setText("Close probe");
        close.setOnClickListener(view -> finish());
        buttons.addView(close);
        controls.addView(buttons);
        Button hide = new Button(this);
        hide.setText("Hide controls — finger-tap image to show");
        hide.setOnClickListener(view -> { if (failure == null) controls.setVisibility(View.GONE); });
        controls.addView(hide);
        FrameLayout.LayoutParams chrome = new FrameLayout.LayoutParams(-2, -2, Gravity.TOP | Gravity.RIGHT);
        root.addView(controls, chrome);
        root.addOnLayoutChangeListener((v, l, t, r, b, ol, ot, or, ob) -> layoutSurface());
        root.post(this::layoutSurface);
        log("START", "display-only=true pen-ready=false");
    }

    // Ignore stylus input at the host, including its controls. This prevents
    // accidental host commands, NOT independent DrawPath activity. Use finger.
    @Override public boolean dispatchTouchEvent(MotionEvent event) {
        for (int i = 0; i < event.getPointerCount(); i++) {
            int tool = event.getToolType(i);
            if (tool == MotionEvent.TOOL_TYPE_STYLUS || tool == MotionEvent.TOOL_TYPE_ERASER) return true;
        }
        return super.dispatchTouchEvent(event);
    }

    private void layoutSurface() {
        if (surface == null || closing || root.getWidth() < 4 || root.getHeight() < 4) return;
        DisplayProbeLayout frame = DisplayProbeLayout.fit(root.getWidth(), root.getHeight(), requested);
        FrameLayout.LayoutParams lp = (FrameLayout.LayoutParams) surface.getLayoutParams();
        if (lp.width != frame.width || lp.height != frame.height
                || lp.leftMargin != frame.left || lp.topMargin != frame.top) {
            lp.width = frame.width; lp.height = frame.height;
            lp.leftMargin = frame.left; lp.topMargin = frame.top;
            surface.setLayoutParams(lp);
            log("FRAME", "host=" + root.getWidth() + "x" + root.getHeight()
                    + " placement=" + frame.effectivePlacement + " rect=" + frame.left + ","
                    + frame.top + "," + frame.width + "," + frame.height);
        }
        showStatus();
    }

    @Override public void onConfigurationChanged(Configuration configuration) {
        super.onConfigurationChanged(configuration);
        // Only the physical presentation changes. Do not resize the native
        // display, re-open its activity, or synthesize a native rotation.
        lifecycle.onConfigurationChanged();
        root.post(this::layoutSurface);
    }

    @Override public void surfaceCreated(SurfaceHolder holder) { /* wait for fixed-size confirmation */ }

    @Override public void surfaceChanged(SurfaceHolder holder, int format, int width, int height) {
        if (closing || failure != null || display != null) return;
        if (width != DisplayProbeLayout.BUFFER_WIDTH || height != DisplayProbeLayout.BUFFER_HEIGHT
                || !holder.getSurface().isValid()) {
            log("WAIT_SURFACE", "size=" + width + "x" + height);
            return;
        }
        if (!lifecycle.onSurfaceReady()) return;
        try {
            DisplayMetrics metrics = new DisplayMetrics();
            getWindowManager().getDefaultDisplay().getRealMetrics(metrics);
            if (metrics.densityDpi <= 0) throw new IllegalStateException("missing physical density");
            final long captured = ++generation;
            DisplayManager manager = getSystemService(DisplayManager.class);
            // Explicit OWN_CONTENT_ONLY prevents a blank display from silently
            // mirroring the physical screen and masquerading as a native task.
            display = manager.createVirtualDisplay("NativeViewportProbe-" + instance + "-" + captured,
                    width, height, metrics.densityDpi, holder.getSurface(),
                    DisplayManager.VIRTUAL_DISPLAY_FLAG_PUBLIC | DisplayManager.VIRTUAL_DISPLAY_FLAG_OWN_CONTENT_ONLY,
                    new VirtualDisplay.Callback() {
                        @Override public void onStopped() {
                            if (!closing && generation == captured) {
                                releaseDisplay();
                                fail("virtual display stopped");
                            }
                        }
                    }, main);
            if (display == null || display.getDisplay().getDisplayId() <= 0) {
                throw new IllegalStateException("non-default display allocation failed");
            }
            int id = display.getDisplay().getDisplayId();
            lifecycle.onDisplayCreated();
            log("CREATED", "display=" + id + " buffer=" + width + "x" + height
                    + " density=" + metrics.densityDpi + " generation=" + captured);
            // Nomad rejects an ordinary app launch on this untrusted display.
            // Keep the live lease for an explicit host-side root launch of ONLY
            // our non-exported CalibrationActivity. Never execute su in this app,
            // weaken Android policy, or launch a native reader automatically.
            log("WAIT_ROOT_CALIBRATION", "display=" + id + " generation=" + captured);
            showStatus();
        } catch (RuntimeException exception) {
            lifecycle.onDisplayCreateFailed();
            releaseDisplay();
            fail(exception.getClass().getSimpleName() + ": " + exception.getMessage());
        }
    }

    @Override public void surfaceDestroyed(SurfaceHolder holder) {
        lifecycle.onSurfaceDestroyed();
        releaseDisplay();
        if (!closing) fail("surface lost; restart display-only probe explicitly");
    }

    private void releaseDisplay() {
        if (lifecycle != null) lifecycle.onDisplayReleased();
        generation++;
        VirtualDisplay old = display;
        display = null;
        calibrationLaunched = false;
        // Close our task before removing the display. Some Android builds move
        // tasks from a removed display back to the physical screen by default.
        CalibrationActivity.closeOwned(instance);
        if (old != null) old.release();
    }

    static boolean ownsDisplay(String instance, int id) {
        DisplayProbeActivity activity = owner.get();
        return activity != null && !activity.closing && activity.failure == null
                && activity.lifecycle != null && activity.lifecycle.isActive()
                && activity.instance.equals(instance) && activity.display != null
                && activity.display.getDisplay().getDisplayId() == id;
    }

    static boolean calibrationAttached(String instance, int id) {
        if (!ownsDisplay(instance, id)) return false;
        DisplayProbeActivity activity = owner.get();
        if (activity == null || !activity.lifecycle.onCalibrationAttached()) return false;
        activity.calibrationLaunched = true;
        activity.log("CALIBRATION_ATTACHED", "display=" + id + " pen-ready=false");
        activity.showStatus();
        return true;
    }

    static void calibrationEnded(String instance, int id) {
        if (!ownsDisplay(instance, id)) return;
        DisplayProbeActivity activity = owner.get();
        if (activity == null) return;
        activity.lifecycle.onCalibrationEnded();
        activity.releaseDisplay();
        activity.fail("calibration ended; close and reopen probe to restart");
    }

    private void fail(String reason) {
        failure = reason;
        if (lifecycle != null) lifecycle.onFailure();
        if (controls != null) controls.setVisibility(View.VISIBLE);
        log("UNAVAILABLE", reason);
        showStatus();
    }

    private void showStatus() {
        status.setText("DISPLAY-ONLY • DO NOT USE PEN\n"
                + (failure != null ? "Unavailable: " + failure : display == null ? "Waiting for surface"
                : "Display " + display.getDisplay().getDisplayId() + " • 1404 × 1872\n"
                    + requested + (calibrationLaunched ? " • calibration attached"
                    : " • awaiting explicit root calibration launch"))
                + "\nNot native-reader or handwriting validation.");
    }

    private void log(String event, String detail) {
        Log.i(TAG, event + " instance=" + instance + " " + detail);
    }

    @Override protected void onDestroy() {
        closing = true;
        if (lifecycle != null) lifecycle.onActivityDestroyed();
        releaseDisplay();
        super.onDestroy();
    }

    @Override protected void onSaveInstanceState(Bundle state) {
        super.onSaveInstanceState(state);
        lifecycle.onStateSaved();
        state.putBoolean("displayProbeExisted", true);
        // Never persist authority to create a replacement display automatically.
    }
}
