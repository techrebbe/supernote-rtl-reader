package com.techrebbe.supernote.shadowpageoverlay;

import android.app.Service;
import android.content.Intent;
import android.content.res.Configuration;
import android.graphics.Bitmap;
import android.graphics.Color;
import android.graphics.Matrix;
import android.graphics.PixelFormat;
import android.graphics.Point;
import android.graphics.Rect;
import android.graphics.pdf.PdfRenderer;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.ParcelFileDescriptor;
import android.provider.Settings;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructStat;
import android.util.Log;
import android.view.Display;
import android.view.Gravity;
import android.view.View;
import android.view.ViewTreeObserver;
import android.view.WindowManager;
import android.widget.ImageView;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/** One owned, non-interactive overlay. This is a visual probe, not hardware admission. */
public final class ShadowPageOverlayService extends Service {
    public static final String ACTION_SHOW_FULL =
            "com.techrebbe.supernote.shadowpageoverlay.SHOW_FULL";
    public static final String ACTION_SHOW_LEFT =
            "com.techrebbe.supernote.shadowpageoverlay.SHOW_LEFT";
    public static final String ACTION_SHOW_RIGHT =
            "com.techrebbe.supernote.shadowpageoverlay.SHOW_RIGHT";
    public static final String ACTION_BASELINE =
            "com.techrebbe.supernote.shadowpageoverlay.BASELINE";
    public static final String ACTION_TEARDOWN =
            "com.techrebbe.supernote.shadowpageoverlay.TEARDOWN";

    // Disposable, independently confirmed printed PAGE 1: zero-based PdfRenderer page 0.
    // A later, separately authorized host gate must seed this exact private file
    // from the pinned original. No shared-storage fallback or caller path exists.
    private static final String FIXTURE_FILENAME = "RTL_DISPLAY0_CAPTURE_20260927.pdf";
    private static final String FIXTURE_SHA256 =
            "28b126627dd5966e8975ae1bf48385d65e1f8189e8aa32ddc0eab778904859c9";
    private static final long FIXTURE_BYTES = 2419L;
    private static final int FIXTURE_PAGE_COUNT = 2;
    private static final int SOURCE_PAGE_INDEX = 0;
    private static final int SOURCE_PAGE_WIDTH = 612;
    private static final int SOURCE_PAGE_HEIGHT = 792;
    private static final long MAX_OVERLAY_LIFETIME_MS = 30_000L;
    private static final String TAG = "ShadowPageOverlay";

    private final Handler main = new Handler(Looper.getMainLooper());
    private final ShadowOverlayGeneration generation = new ShadowOverlayGeneration();
    private WindowManager windowManager;
    private ImageView ownedView;
    private Bitmap ownedBitmap;
    private int activeStartId;
    private Runnable lifetimeTimeout;
    private ViewTreeObserver.OnGlobalLayoutListener frameListener;

    @Override public IBinder onBind(Intent intent) { return null; }

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        activeStartId = startId;
        String action = intent == null ? null : intent.getAction();
        String mode = modeForAction(action);
        // Deliberate blank baseline before any new FD admission/render. Switching
        // modes can briefly reveal the stock page; no atomic visual swap is claimed.
        removeOwnedOverlay();
        if (mode == null) {
            // Baseline, teardown, null, and unknown commands all leave no overlay.
            stopSelfResult(startId);
            return START_NOT_STICKY;
        }
        try {
            show(mode, startId);
        } catch (IOException | ErrnoException | RuntimeException failure) {
            Log.e(TAG, "visual-only overlay refused: " + failure.getClass().getSimpleName(),
                    failure);
            removeOwnedOverlay();
            stopSelfResult(startId);
        }
        return START_NOT_STICKY;
    }

    private static String modeForAction(String action) {
        if (ACTION_SHOW_FULL.equals(action)) return "FULL";
        if (ACTION_SHOW_LEFT.equals(action)) return "LEFT";
        if (ACTION_SHOW_RIGHT.equals(action)) return "RIGHT";
        return null;
    }

    private void show(String mode, int startId) throws IOException, ErrnoException {
        if (!Settings.canDrawOverlays(this)) {
            throw new SecurityException("overlay AppOp was not independently granted");
        }
        WindowManager manager = (WindowManager) getSystemService(WINDOW_SERVICE);
        if (manager == null) throw new IllegalStateException("window manager unavailable");
        Display display = manager.getDefaultDisplay();
        if (display == null || display.getDisplayId() != Display.DEFAULT_DISPLAY) {
            throw new IllegalStateException("physical display 0 unavailable");
        }
        Point realSize = new Point();
        display.getRealSize(realSize);
        ShadowPageGeometry.Placement placement =
                ShadowPageGeometry.placement(mode, realSize.x, realSize.y);

        // The only input path is this exact app-private copy. Pin its lstat
        // identity around a read-only open; retain that FD while PdfRenderer
        // consumes a duplicate, then recheck the original FD and path.
        Bitmap bitmap;
        File fixture = new File(getFilesDir(), FIXTURE_FILENAME);
        StructStat pinnedPath = Os.lstat(fixture.getAbsolutePath());
        verifyRegularFixture(pinnedPath);
        try (ParcelFileDescriptor sourceDescriptor = ParcelFileDescriptor.open(
                fixture, ParcelFileDescriptor.MODE_READ_ONLY)) {
            verifyFixtureIdentity(fixture, pinnedPath, sourceDescriptor);
            verifyOpenedBytes(sourceDescriptor);
            try (ParcelFileDescriptor renderDescriptor =
                         ParcelFileDescriptor.dup(sourceDescriptor.getFileDescriptor())) {
                try (PdfRenderer renderer = new PdfRenderer(renderDescriptor)) {
                    if (renderer.getPageCount() != FIXTURE_PAGE_COUNT) {
                        throw new IOException("fixture page count changed");
                    }
                    try (PdfRenderer.Page page = renderer.openPage(SOURCE_PAGE_INDEX)) {
                        if (page.getWidth() != SOURCE_PAGE_WIDTH
                                || page.getHeight() != SOURCE_PAGE_HEIGHT) {
                            throw new IOException("fixture page geometry changed");
                        }
                        bitmap = Bitmap.createBitmap(ShadowPageGeometry.CANVAS_WIDTH,
                                ShadowPageGeometry.CANVAS_HEIGHT, Bitmap.Config.ARGB_8888);
                        boolean rendered = false;
                        try {
                            bitmap.eraseColor(Color.WHITE);
                            float scale = Math.min(
                                    (float) ShadowPageGeometry.CANVAS_WIDTH / page.getWidth(),
                                    (float) ShadowPageGeometry.CANVAS_HEIGHT / page.getHeight());
                            float left = (ShadowPageGeometry.CANVAS_WIDTH
                                    - page.getWidth() * scale) / 2.0f;
                            float top = (ShadowPageGeometry.CANVAS_HEIGHT
                                    - page.getHeight() * scale) / 2.0f;
                            Matrix fit = new Matrix();
                            fit.setValues(new float[] {scale, 0, left, 0, scale, top, 0, 0, 1});
                            page.render(bitmap, new Rect(0, 0, ShadowPageGeometry.CANVAS_WIDTH,
                                    ShadowPageGeometry.CANVAS_HEIGHT), fit,
                                    PdfRenderer.Page.RENDER_MODE_FOR_DISPLAY);
                            rendered = true;
                            // Own the bitmap before any later close/recheck/view failure.
                            ownedBitmap = bitmap;
                        } finally {
                            if (!rendered) bitmap.recycle();
                        }
                    }
                }
            }
            verifyOpenedBytes(sourceDescriptor);
            verifyFixtureIdentity(fixture, pinnedPath, sourceDescriptor);
        } catch (FileNotFoundException denied) {
            throw new IOException("pinned private fixture absent or unreadable", denied);
        }

        ImageView view = new ImageView(this);
        view.setScaleType(ImageView.ScaleType.FIT_XY); // exact 3:4 canvas-to-window scaling
        view.setImageBitmap(bitmap);
        view.setFocusable(false);
        view.setClickable(false);
        view.setLongClickable(false);
        view.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO_HIDE_DESCENDANTS);

        int overlayFlags = WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE
                | WindowManager.LayoutParams.FLAG_NOT_TOUCHABLE
                | WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN;
        WindowManager.LayoutParams params = new WindowManager.LayoutParams(
                placement.width, placement.height,
                WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY,
                overlayFlags, PixelFormat.OPAQUE);
        params.gravity = Gravity.TOP | Gravity.LEFT;
        params.x = placement.x;
        params.y = placement.y;
        params.setTitle("Shadow Page Overlay - Visual Only");

        windowManager = manager;
        ownedView = view;
        manager.addView(view, params);
        final long admittedGeneration = generation.begin(view);
        frameListener = () -> {
            if (!generation.owns(view, admittedGeneration)) return;
            // An actual layout event, not a queued post, is the placement boundary.
            clearFrameListener();
            verifyAttachedFrameOrTeardown(view, placement, startId, admittedGeneration);
        };
        view.getViewTreeObserver().addOnGlobalLayoutListener(frameListener);
        lifetimeTimeout = () -> {
            if (!generation.owns(view, admittedGeneration)) return;
            Log.i(TAG, "bounded visual-only overlay lifetime expired");
            removeOwnedOverlay();
            stopSelfResult(startId);
        };
        if (!main.postDelayed(lifetimeTimeout, MAX_OVERLAY_LIFETIME_MS)) {
            throw new IllegalStateException("could not arm bounded overlay lifetime");
        }
    }

    private static void verifyRegularFixture(StructStat stat) throws IOException {
        if (!OsConstants.S_ISREG(stat.st_mode) || stat.st_size != FIXTURE_BYTES) {
            throw new IOException("private fixture is not the pinned regular file size");
        }
    }

    private static void verifyFixtureIdentity(File fixture, StructStat pinnedPath,
            ParcelFileDescriptor descriptor) throws IOException, ErrnoException {
        StructStat pathNow = Os.lstat(fixture.getAbsolutePath());
        StructStat opened = Os.fstat(descriptor.getFileDescriptor());
        verifyRegularFixture(pathNow);
        verifyRegularFixture(opened);
        if (pathNow.st_dev != pinnedPath.st_dev || pathNow.st_ino != pinnedPath.st_ino
                || opened.st_dev != pinnedPath.st_dev || opened.st_ino != pinnedPath.st_ino) {
            throw new IOException("private fixture path and opened FD identity diverged");
        }
    }

    private static void verifyOpenedBytes(ParcelFileDescriptor descriptor)
            throws IOException, ErrnoException {
        StructStat stat = Os.fstat(descriptor.getFileDescriptor());
        verifyRegularFixture(stat);
        MessageDigest digest;
        try { digest = MessageDigest.getInstance("SHA-256"); }
        catch (NoSuchAlgorithmException impossible) { throw new IOException(impossible); }
        Os.lseek(descriptor.getFileDescriptor(), 0, OsConstants.SEEK_SET);
        byte[] buffer = new byte[4096];
        long read = 0;
        for (;;) {
            int count = Os.read(descriptor.getFileDescriptor(), buffer, 0, buffer.length);
            if (count == 0) break;
            read += count;
            if (read > FIXTURE_BYTES) throw new IOException("fixture grew during FD hash");
            digest.update(buffer, 0, count);
        }
        // The renderer duplicate refers to this opened inode. Verify it again
        // after rendering so an ordinary persistent rewrite fails closed.
        if (read != FIXTURE_BYTES || !FIXTURE_SHA256.equals(hex(digest.digest()))) {
            throw new IOException("opened fixture SHA-256 differs from build pin");
        }
        verifyRegularFixture(Os.fstat(descriptor.getFileDescriptor()));
        if (Os.lseek(descriptor.getFileDescriptor(), 0, OsConstants.SEEK_SET) != 0) {
            throw new IOException("could not rewind admitted fixture descriptor");
        }
    }

    private static String hex(byte[] bytes) {
        char[] digits = "0123456789abcdef".toCharArray();
        char[] result = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            result[2 * i] = digits[(bytes[i] >>> 4) & 15];
            result[2 * i + 1] = digits[bytes[i] & 15];
        }
        return new String(result);
    }

    private void verifyAttachedFrameOrTeardown(ImageView expected,
            ShadowPageGeometry.Placement placement, int startId, long expectedGeneration) {
        if (!generation.owns(expected, expectedGeneration)) return;
        Point size = new Point();
        Display display = expected.getDisplay();
        if (display == null || display.getDisplayId() != Display.DEFAULT_DISPLAY) {
            failFrame(expected, startId, expectedGeneration);
            return;
        }
        display.getRealSize(size);
        int[] origin = new int[2];
        expected.getLocationOnScreen(origin);
        if (size.x != ShadowPageGeometry.DISPLAY_WIDTH
                || size.y != ShadowPageGeometry.DISPLAY_HEIGHT
                || origin[0] != placement.x || origin[1] != placement.y
                || expected.getWidth() != placement.width
                || expected.getHeight() != placement.height) {
            failFrame(expected, startId, expectedGeneration);
        }
    }

    private void failFrame(ImageView expected, int startId, long expectedGeneration) {
        if (!generation.owns(expected, expectedGeneration)) return;
        Log.e(TAG, "overlay frame differed from pinned display-0 placement");
        removeOwnedOverlay();
        stopSelfResult(startId);
    }

    private void removeOwnedOverlay() {
        // Invalidates both the lifetime timer and any delayed frame callback
        // from an earlier SHOW generation, even if callback removal races.
        generation.clear();
        if (lifetimeTimeout != null) {
            main.removeCallbacks(lifetimeTimeout);
            lifetimeTimeout = null;
        }
        ImageView view = ownedView;
        if (view != null) {
            clearFrameListener();
            if (view.getParent() != null) {
                try {
                    // Only this Service's own view is ever removed. A failure kills this
                    // isolated process so Android tears down the remaining owned window.
                    windowManager.removeViewImmediate(view);
                } catch (RuntimeException removalFailure) {
                    Log.e(TAG, "could not remove owned overlay; ending owner process", removalFailure);
                    android.os.Process.killProcess(android.os.Process.myPid());
                    return;
                }
            }
            view.setImageDrawable(null);
            ownedView = null;
        }
        if (ownedBitmap != null) {
            ownedBitmap.recycle();
            ownedBitmap = null;
        }
        windowManager = null;
    }

    private void clearFrameListener() {
        if (frameListener == null || ownedView == null) return;
        ViewTreeObserver observer = ownedView.getViewTreeObserver();
        if (observer.isAlive()) observer.removeOnGlobalLayoutListener(frameListener);
        frameListener = null;
    }

    @Override public void onConfigurationChanged(Configuration configuration) {
        super.onConfigurationChanged(configuration);
        removeOwnedOverlay();
        stopSelfResult(activeStartId);
    }

    @Override public void onDestroy() {
        removeOwnedOverlay();
        super.onDestroy();
    }
}
