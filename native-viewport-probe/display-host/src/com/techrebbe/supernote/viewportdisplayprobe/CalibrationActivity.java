package com.techrebbe.supernote.viewportdisplayprobe;

import android.app.Activity;
import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.os.Bundle;
import android.util.Log;
import android.view.MotionEvent;
import android.view.View;
import android.view.WindowManager;
import com.techrebbe.supernote.viewportprobe.DisplayProbeLayout;
import java.lang.ref.WeakReference;

/** Independent activity/display proof, not a PDF renderer or native reader substitute. */
public final class CalibrationActivity extends Activity {
    private static WeakReference<CalibrationActivity> current = new WeakReference<>(null);
    private String ownerInstance;
    private int actualDisplay;
    private boolean admitted;
    @Override public void onCreate(Bundle saved) {
        super.onCreate(saved);
        int expected = getIntent().getIntExtra("expectedDisplay", -1);
        int actual = getWindowManager().getDefaultDisplay().getDisplayId();
        actualDisplay = actual;
        ownerInstance = getIntent().getStringExtra("instance");
        if (expected <= 0 || actual != expected || !DisplayProbeActivity.calibrationAttached(ownerInstance, actual)) {
            Log.e("NATIVE_VIEWPORT_DISPLAY", "CALIBRATION_REJECTED expected=" + expected + " actual=" + actual);
            finishAndRemoveTask();
            return;
        }
        current = new WeakReference<>(this);
        admitted = true;
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_FULLSCREEN);
        getWindow().getDecorView().setSystemUiVisibility(View.SYSTEM_UI_FLAG_FULLSCREEN
                | View.SYSTEM_UI_FLAG_HIDE_NAVIGATION | View.SYSTEM_UI_FLAG_IMMERSIVE_STICKY);
        setContentView(new Target(this));
    }

    @Override public boolean dispatchTouchEvent(MotionEvent event) { return true; }

    @Override protected void onDestroy() {
        if (current.get() == this) current.clear();
        // Rejected duplicate/stale launches must not stop the accepted task.
        if (admitted) {
            admitted = false;
            DisplayProbeActivity.calibrationEnded(ownerInstance, actualDisplay);
        }
        super.onDestroy();
    }

    static void closeOwned(String instance) {
        CalibrationActivity activity = current.get();
        if (activity != null && instance.equals(activity.ownerInstance)) {
            current.clear();
            activity.finishAndRemoveTask();
        }
    }

    private static final class Target extends View {
        private final Paint ink = new Paint();
        Target(Context context) { super(context); }
        @Override protected void onSizeChanged(int w, int h, int oldw, int oldh) {
            Log.i("NATIVE_VIEWPORT_DISPLAY", "CALIBRATION_SIZE actual=" + w + "x" + h
                    + " canonical=" + (w == DisplayProbeLayout.BUFFER_WIDTH && h == DisplayProbeLayout.BUFFER_HEIGHT));
        }
        @Override protected void onDraw(Canvas canvas) {
            canvas.drawColor(Color.WHITE);
            ink.setColor(Color.BLACK);
            ink.setStrokeWidth(4);
            ink.setStyle(Paint.Style.STROKE);
            canvas.drawRect(8, 8, getWidth() - 8, getHeight() - 8, ink);
            canvas.drawRect(140, 187, 1264, 1685, ink);
            canvas.drawLine(702, 8, 702, getHeight() - 8, ink);
            canvas.drawLine(8, 936, getWidth() - 8, 936, ink);
            canvas.drawCircle(702, 936, 160, ink);
            ink.setStyle(Paint.Style.FILL);
            ink.setTextSize(42);
            canvas.drawText("DISPLAY CALIBRATION — NOT A PDF", 80, 100, ink);
            canvas.drawText("1404 × 1872 canonical pixels", 80, 155, ink);
            canvas.drawText("TOP LEFT", 160, 250, ink);
            canvas.drawText("BOTTOM RIGHT", 850, 1640, ink);
            canvas.drawText("No pen input / no saved annotations", 100, 1800, ink);
        }
    }
}
