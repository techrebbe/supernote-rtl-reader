package com.techrebbe.supernote.layoutfencetrial;

import android.content.Context;
import android.view.View;
import android.widget.FrameLayout;

/** Sole synthetic parent; pre-signals only its own calls into root.layout. */
final class TrialParent extends FrameLayout {
    interface Host {
        void beforeParentRootLayout(TrialEvidence.Bounds target);
        void afterParentRootLayout();
        void onParentAnomaly(String reason);
        void onParentDetached();
    }

    private final TrialRoot root;
    private final Host host;
    private final int insetPx;
    private int desiredDelta;

    TrialParent(Context context, TrialRoot root, Host host, int insetPx) {
        super(context);
        if (root == null || host == null || insetPx < 1) {
            throw new IllegalArgumentException("exact root, host and inset required");
        }
        this.root = root;
        this.host = host;
        this.insetPx = insetPx;
    }

    void setDesiredDelta(int value) {
        if (value < -1 || value > 1) throw new IllegalArgumentException("delta must be ±1");
        desiredDelta = value;
    }

    int desiredDelta() { return desiredDelta; }

    TrialEvidence.Bounds baseBounds() {
        int right = getWidth() - insetPx;
        int bottom = getHeight();
        if (right <= 1 || bottom <= 0) throw new IllegalStateException("parent not laid out");
        return new TrialEvidence.Bounds(0, 0, right, bottom);
    }

    boolean exactSoleChild() {
        return getChildCount() == 1 && getChildAt(0) == root && root.getParent() == this;
    }

    @Override protected void onLayout(boolean changed,
            int left, int top, int right, int bottom) {
        if (!exactSoleChild()) {
            host.onParentAnomaly("PARENT_NOT_SOLE_OWNER");
            return;
        }
        layoutRootAtDeltaNow(desiredDelta);
    }

    @Override protected void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        host.onParentDetached();
    }

    /** ABA control invokes this twice synchronously, with no intervening paint. */
    void layoutRootAtDeltaNow(int delta) {
        if (!exactSoleChild() || !isAttachedToWindow()) {
            host.onParentAnomaly("PARENT_ROOT_NOT_ATTACHED");
            return;
        }
        TrialEvidence.Bounds target = baseBounds().withRightDelta(delta);
        host.beforeParentRootLayout(target);
        root.enterParentCall();
        try {
            root.layout(target.left, target.top, target.right, target.bottom);
        } finally {
            root.leaveParentCall();
        }
        host.afterParentRootLayout();
    }

    @Override public void onViewAdded(View child) {
        super.onViewAdded(child);
        if (child != root) host.onParentAnomaly("FOREIGN_PARENT_CHILD");
    }

    @Override public void onViewRemoved(View child) {
        super.onViewRemoved(child);
        host.onParentAnomaly("PARENT_CHILD_REMOVED");
    }
}
