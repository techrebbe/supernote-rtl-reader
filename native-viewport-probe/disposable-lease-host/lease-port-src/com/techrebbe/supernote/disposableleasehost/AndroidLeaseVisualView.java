package com.techrebbe.supernote.disposableleasehost;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.os.Looper;
import android.view.MotionEvent;
import android.view.View;

import com.techrebbe.supernote.viewportprobe.TargetOwnedVisualLeaseCore;

/**
 * One disposable diagnostic child. PREPARED has no pixel path: the entire
 * View.draw call returns before Android can draw a background, foreground,
 * onDraw body, or ViewOverlay. It is not a pen/input surface.
 */
public final class AndroidLeaseVisualView extends View {
    private final Paint paint = new Paint();
    private final TargetOwnedVisualLeaseCore.DrawGate drawGate;
    private boolean claimedForAdd;

    public AndroidLeaseVisualView(Context context, TargetOwnedVisualLeaseCore.DrawGate drawGate) {
        super(context);
        if (drawGate == null) throw new IllegalArgumentException("prebound draw gate required");
        this.drawGate = drawGate;
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

    /** One-shot use prevents a previously removed view from being reinserted. */
    void claimForAdd() {
        requireMain();
        if (claimedForAdd || getParent() != null) {
            throw new IllegalStateException("owned child already used");
        }
        claimedForAdd = true;
    }

    boolean wasClaimedForAdd() { return claimedForAdd; }

    boolean usesDrawGate(TargetOwnedVisualLeaseCore.DrawGate expected) {
        return expected != null && drawGate == expected;
    }

    @Override public void draw(Canvas canvas) {
        requireMain();
        if (!drawGate.mayDraw()) return;
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
