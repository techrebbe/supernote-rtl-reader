package com.techrebbe.supernote.disposableleasehost;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.os.Looper;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewParent;

import com.techrebbe.supernote.viewportprobe.TargetOwnedVisualLeaseCore;

/**
 * One disposable diagnostic child. PREPARED has no pixel path: the entire
 * View.draw call returns before Android can draw a background, foreground,
 * onDraw body, or ViewOverlay. It is not a pen/input surface.
 */
public final class AndroidLeaseVisualView extends View {
    private final Paint paint = new Paint();
    private TargetOwnedVisualLeaseCore lease;

    public AndroidLeaseVisualView(Context context) {
        super(context);
        setBackground(null);
        setForeground(null);
        setElevation(0f);
        setTranslationZ(0f);
        setOutlineProvider(null);
        setClickable(false);
        setLongClickable(false);
        setFocusable(false);
        setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);
        setWillNotDraw(false);
        paint.setColor(0xff8d1e91);
        paint.setStyle(Paint.Style.FILL);
    }

    public void bindLease(TargetOwnedVisualLeaseCore lease) {
        requireMain();
        if (lease == null || this.lease != null || lease.ownedChild() != this) {
            throw new IllegalStateException("only the exact owned lease may bind");
        }
        ViewParent parent = getParent();
        if (parent instanceof AndroidLeasePaintRoot) {
            ((AndroidLeasePaintRoot) parent).beforeEvidenceMutation();
        }
        this.lease = lease;
    }

    public boolean hasBoundLease() { return lease != null; }

    @Override public void draw(Canvas canvas) {
        requireMain();
        if (lease == null || !lease.mayDraw()) return;
        super.draw(canvas);
    }

    @Override protected void onDraw(Canvas canvas) {
        canvas.drawRect(0, 0, getWidth(), getHeight(), paint);
    }

    @Override public boolean onTouchEvent(MotionEvent event) { return false; }

    private static void requireMain() {
        if (Looper.myLooper() != Looper.getMainLooper()) {
            throw new IllegalStateException("lease visual requires main Looper");
        }
    }
}
