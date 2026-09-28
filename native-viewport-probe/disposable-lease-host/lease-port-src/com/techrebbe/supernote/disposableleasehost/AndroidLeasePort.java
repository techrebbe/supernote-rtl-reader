package com.techrebbe.supernote.disposableleasehost;

import android.app.Activity;
import android.os.Handler;
import android.os.Looper;
import android.os.Process;
import android.os.SystemClock;
import android.view.View;
import android.view.ViewParent;
import android.widget.FrameLayout;

import com.techrebbe.supernote.viewportprobe.TargetOwnedVisualLeaseCore;

/**
 * Android side of the disposable visual-lease model. This is deliberately
 * unconnected to ProbeActivity and cannot run there until its root/lifecycle
 * integration is independently reviewed. It is not a Nomad adapter.
 */
public final class AndroidLeasePort implements TargetOwnedVisualLeaseCore.Port {
    /**
     * The activity owner, not this adapter, must establish the process/root
     * incarnation and atomically subscribe to pause, detach and scene drift.
     * It must signal drift before a changed scene may paint. A null/throw from
     * armLifecycle must leave no callback registration behind. A true mutation
     * coverage declaration requires every scene/child/draw-policy setter to
     * call root.beforeEvidenceMutation() BEFORE its change. No implementation
     * in the existing disposable host makes that declaration yet.
     */
    public interface Authority {
        boolean processIncarnationCurrent();
        boolean isCurrentRoot(Activity activity, AndroidLeasePaintRoot root);
        boolean hasCompleteSynchronousEvidenceMutationCoverage();
        TargetOwnedVisualLeaseCore.Registration armLifecycle(
                Runnable onPause, Runnable onRootLoss, Runnable onPageOrLayoutDrift);
    }

    private final Activity activity;
    private final AndroidLeasePaintRoot root;
    private final Authority authority;
    private final boolean mutationCoverageCertified;
    private final Handler main = new Handler(Looper.getMainLooper());
    private final int originalPid = Process.myPid();

    public AndroidLeasePort(Activity activity, AndroidLeasePaintRoot root, Authority authority) {
        if (activity == null || root == null || authority == null) {
            throw new IllegalArgumentException("activity, controlled root and authority required");
        }
        if (root.getContext() != activity) {
            throw new IllegalArgumentException("root must belong to exact activity");
        }
        this.activity = activity;
        this.root = root;
        this.authority = authority;
        this.mutationCoverageCertified = authority.hasCompleteSynchronousEvidenceMutationCoverage();
    }

    @Override public void requireMainThread() {
        if (Looper.myLooper() != Looper.getMainLooper()) {
            throw new IllegalStateException("lease Port requires main Looper");
        }
    }

    @Override public long elapsedRealtimeMillis() { return SystemClock.elapsedRealtime(); }

    @Override public long evidenceMutationRevision() {
        // Pure local field read: do not invoke an owner callback at the
        // core's final commit fence. Uncertified coverage never yields proof.
        return mutationCoverageCertified ? root.evidenceMutationRevision() : -1;
    }

    @Override public long startedPaintRevision() {
        requireMainThread();
        return root.startedPaintRevision();
    }

    @Override public TargetOwnedVisualLeaseCore.PaintFrame lastCompletedPaintFrame() {
        requireMainThread();
        return root.lastCompletedPaintFrame();
    }

    @Override public boolean processAlive() {
        requireMainThread();
        return Process.myPid() == originalPid && authority.processIncarnationCurrent();
    }

    @Override public boolean rootAlive() {
        requireMainThread();
        return mutationCoverageCertified && !activity.isFinishing() && !activity.isDestroyed()
                && root.isAttachedToWindow() && authority.isCurrentRoot(activity, root);
    }

    @Override public Object root() {
        requireMainThread();
        return root;
    }

    @Override public TargetOwnedVisualLeaseCore.Snapshot snapshot() {
        requireMainThread();
        return root.currentSnapshot();
    }

    @Override public Object parentOf(Object child) {
        requireMainThread();
        if (!(child instanceof View)) throw new IllegalArgumentException("owned child must be View");
        return ((View) child).getParent();
    }

    @Override public void add(Object child, int provenSlot) {
        requireMainThread();
        if (!(child instanceof AndroidLeaseVisualView) || provenSlot < 0 || provenSlot > 9
                || root.getChildCount() != 9 || !rootAlive()) {
            throw new IllegalStateException("unproved disposable insertion");
        }
        AndroidLeaseVisualView owned = (AndroidLeaseVisualView) child;
        if (owned.getParent() != null || owned.hasBoundLease()) {
            throw new IllegalStateException("child already used");
        }
        FrameLayout.LayoutParams params = new FrameLayout.LayoutParams(64, 64);
        root.beforeEvidenceMutation();
        root.addView(owned, provenSlot, params);
        root.invalidate();
    }

    @Override public void remove(Object child) {
        requireMainThread();
        if (!(child instanceof AndroidLeaseVisualView)) {
            throw new IllegalArgumentException("owned visual required");
        }
        AndroidLeaseVisualView owned = (AndroidLeaseVisualView) child;
        ViewParent parent = owned.getParent();
        if (parent != root) throw new IllegalStateException("exact original root no longer owns child");
        root.beforeEvidenceMutation();
        root.removeView(owned); // Exact reference only; never index, tag or ID.
        root.invalidate();
    }

    @Override public void requestDraw(Object child) {
        requireMainThread();
        if (!(child instanceof AndroidLeaseVisualView)
                || ((View) child).getParent() != root
                || !((AndroidLeaseVisualView) child).hasBoundLease()) {
            throw new IllegalStateException("unbound or detached visual");
        }
        ((View) child).invalidate();
        root.invalidate();
    }

    @Override public void dispatch(Runnable callback) {
        if (callback == null || !main.post(callback)) {
            throw new IllegalStateException("main Handler rejected cleanup dispatch");
        }
    }

    @Override public void schedule(Runnable callback, long delayMillis) {
        if (callback == null || delayMillis < 0 || !main.postDelayed(callback, delayMillis)) {
            throw new IllegalStateException("main Handler rejected bounded callback");
        }
    }

    @Override public void cancel(Runnable callback) {
        requireMainThread();
        main.removeCallbacks(callback);
    }

    @Override public TargetOwnedVisualLeaseCore.Registration armLifecycle(
            Runnable onPause, Runnable onRootLoss, Runnable onPageOrLayoutDrift) {
        requireMainThread();
        TargetOwnedVisualLeaseCore.Registration registration = authority.armLifecycle(
                onPause, onRootLoss, onPageOrLayoutDrift);
        if (registration == null) throw new IllegalStateException("lifecycle authority unavailable");
        return registration;
    }
}
