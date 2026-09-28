package com.techrebbe.supernote.disposableleasehost;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Matrix;
import android.graphics.Rect;
import android.os.Looper;
import android.os.SystemClock;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;

import com.techrebbe.supernote.viewportprobe.TargetOwnedVisualLeaseCore;

import java.util.ArrayList;
import java.util.IdentityHashMap;

/**
 * Disposable-emulator-only root for a future lease trial. Unlike a pre-draw
 * listener, this observes each actual drawChild call and publishes a frame
 * only after dispatchDraw finishes with an unchanged direct hierarchy.
 * It is deliberately not wired into ProbeActivity or the Nomad reader.
 */
public final class AndroidLeasePaintRoot extends FrameLayout {
    public interface SceneAuthority { String sceneStamp(); }

    private static final class PaintedChild {
        final View view;
        final int indexAtPaint;
        final String evidenceAtPaint;

        PaintedChild(View view, int indexAtPaint, String evidenceAtPaint) {
            this.view = view;
            this.indexAtPaint = indexAtPaint;
            this.evidenceAtPaint = evidenceAtPaint;
        }
    }

    private static final class DirectCut {
        final View[] children;
        final Object[] parents;
        final String[] evidence;
        final String policy;
        final String scene;
        final long mutationRevision;

        DirectCut(View[] children, Object[] parents, String[] evidence,
                String policy, String scene, long mutationRevision) {
            this.children = children;
            this.parents = parents;
            this.evidence = evidence;
            this.policy = policy;
            this.scene = scene;
            this.mutationRevision = mutationRevision;
        }

        boolean same(DirectCut other) {
            if (other == null || children.length != other.children.length
                    || mutationRevision != other.mutationRevision
                    || !policy.equals(other.policy) || !scene.equals(other.scene)) return false;
            for (int i = 0; i < children.length; i++) {
                if (children[i] != other.children[i] || parents[i] != other.parents[i]
                        || !evidence[i].equals(other.evidence[i])) return false;
            }
            return true;
        }
    }

    private final SceneAuthority sceneAuthority;
    private final LeasePaintPassLedger passes = new LeasePaintPassLedger();
    private final LeaseEvidenceMutationLedger mutations = new LeaseEvidenceMutationLedger();
    private final ArrayList<PaintedChild> drawing = new ArrayList<>();
    private TargetOwnedVisualLeaseCore.PaintFrame lastCompleted;
    private long completedMutationRevision = -1;
    private boolean drawingActive;

    public AndroidLeasePaintRoot(Context context, SceneAuthority sceneAuthority) {
        super(context);
        if (sceneAuthority == null) throw new IllegalArgumentException("scene authority required");
        this.sceneAuthority = sceneAuthority;
        setChildrenDrawingOrderEnabled(false);
    }

    public long startedPaintRevision() {
        requireMain();
        return passes.begunRevision();
    }

    /** Pure, non-reentrant read for the core's final restoration fence. */
    public long evidenceMutationRevision() {
        requireMain();
        return mutations.revision();
    }

    /** Call synchronously before a controlled scene/evidence mutation. */
    public void beforeEvidenceMutation() {
        requireMain();
        mutations.beforeMutation();
    }

    public TargetOwnedVisualLeaseCore.PaintFrame lastCompletedPaintFrame() {
        requireMain();
        return mutations.isCurrent(completedMutationRevision) ? lastCompleted : null;
    }

    /** A current hierarchy cut paired with the last actual completed paint order. */
    public TargetOwnedVisualLeaseCore.Snapshot currentSnapshot() {
        requireMain();
        if (lastCompleted == null || !mutations.isCurrent(completedMutationRevision)) {
            throw new IllegalStateException("no stable completed paint pass");
        }
        DirectCut cut = captureDirect();
        Object[] order = lastCompletedOrder();
        if (cut.children.length != order.length) {
            throw new IllegalStateException("paint order does not cover current hierarchy");
        }
        return snapshot(cut, order);
    }

    @Override protected void dispatchDraw(Canvas canvas) {
        requireMain();
        if (drawingActive) throw new IllegalStateException("nested paint pass");
        DirectCut before = captureDirect();
        long revision = passes.begin();
        drawingActive = true;
        drawing.clear();
        try {
            super.dispatchDraw(canvas);
            DirectCut after = captureDirect();
            Object[] order = verifiedPaintOrder(before, after);
            if (order != null) {
                TargetOwnedVisualLeaseCore.Snapshot cut = snapshot(after, order);
                TargetOwnedVisualLeaseCore.PaintFrame frame =
                        new TargetOwnedVisualLeaseCore.PaintFrame(revision,
                                SystemClock.elapsedRealtime(), cut);
                passes.complete(revision);
                completedOrder = order.clone();
                completedMutationRevision = after.mutationRevision;
                lastCompleted = frame;
            }
            // An incomplete/changed pass is never promoted to evidence.
        } finally {
            drawing.clear();
            drawingActive = false;
        }
    }

    @Override protected boolean drawChild(Canvas canvas, View child, long drawingTime) {
        requireMain();
        if (!drawingActive) throw new IllegalStateException("drawChild outside paint pass");
        drawing.add(new PaintedChild(child, indexOfChild(child), childEvidence(child)));
        return super.drawChild(canvas, child, drawingTime);
    }

    private Object[] verifiedPaintOrder(DirectCut before, DirectCut after) {
        if (!before.same(after) || drawing.size() != after.children.length) return null;
        IdentityHashMap<View, Boolean> seen = new IdentityHashMap<>();
        Object[] order = new Object[drawing.size()];
        for (int i = 0; i < drawing.size(); i++) {
            PaintedChild painted = drawing.get(i);
            if (painted.indexAtPaint < 0 || painted.indexAtPaint >= after.children.length
                    || after.children[painted.indexAtPaint] != painted.view
                    || !painted.evidenceAtPaint.equals(after.evidence[painted.indexAtPaint])
                    || seen.put(painted.view, true) != null) return null;
            order[i] = painted.view;
        }
        return order;
    }

    private Object[] lastCompletedOrder() {
        // Snapshot intentionally has no public arrays. The root owns the
        // paint-order witness directly, alongside the immutable core frame.
        if (completedOrder == null) throw new IllegalStateException("no paint order");
        return completedOrder.clone();
    }

    private Object[] completedOrder;

    private TargetOwnedVisualLeaseCore.Snapshot snapshot(DirectCut cut, Object[] order) {
        return new TargetOwnedVisualLeaseCore.Snapshot(this, cut.children, cut.parents,
                cut.evidence, order, cut.policy, cut.scene);
    }

    private DirectCut captureDirect() {
        requireMain();
        long revisionAtStart = mutations.revision();
        int count = getChildCount();
        View[] children = new View[count];
        Object[] parents = new Object[count];
        String[] evidence = new String[count];
        for (int i = 0; i < count; i++) {
            View child = getChildAt(i);
            if (child == null) throw new IllegalStateException("null child");
            children[i] = child;
            parents[i] = child.getParent();
            evidence[i] = childEvidence(child);
        }
        String sceneStamp = sceneAuthority.sceneStamp();
        if (sceneStamp == null || sceneStamp.isEmpty()) {
            throw new IllegalStateException("missing scene stamp");
        }
        String policy = "customOrder=" + isChildrenDrawingOrderEnabled()
                + ":clipChildren=" + getClipChildren()
                + ":clipPadding=" + getClipToPadding();
        String scene = sceneStamp + ":root=" + System.identityHashCode(this)
                + ":bounds=" + getLeft() + "," + getTop() + ","
                + getRight() + "," + getBottom()
                + ":padding=" + getPaddingLeft() + "," + getPaddingTop()
                + "," + getPaddingRight() + "," + getPaddingBottom();
        if (!mutations.isCurrent(revisionAtStart)) {
            throw new IllegalStateException("evidence changed during hierarchy snapshot");
        }
        return new DirectCut(children, parents, evidence, policy, scene, revisionAtStart);
    }

    @Override protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
        // Layout changes child geometry. This is before FrameLayout lays out
        // its children, so a previous completed frame becomes stale first.
        beforeEvidenceMutation();
        super.onLayout(changed, left, top, right, bottom);
    }

    private static String childEvidence(View child) {
        StringBuilder out = new StringBuilder();
        out.append(child.getClass().getName()).append(':').append(child.getId())
                .append(':').append(child.getVisibility())
                .append(':').append(child.getLeft()).append(',').append(child.getTop())
                .append(',').append(child.getRight()).append(',').append(child.getBottom())
                .append(':').append(Float.floatToRawIntBits(child.getAlpha()))
                .append(':').append(Float.floatToRawIntBits(child.getElevation()))
                .append(':').append(Float.floatToRawIntBits(child.getTranslationX()))
                .append(':').append(Float.floatToRawIntBits(child.getTranslationY()))
                .append(':').append(Float.floatToRawIntBits(child.getTranslationZ()))
                .append(':').append(Float.floatToRawIntBits(child.getScaleX()))
                .append(':').append(Float.floatToRawIntBits(child.getScaleY()))
                .append(':').append(Float.floatToRawIntBits(child.getRotation()))
                .append(':').append(Float.floatToRawIntBits(child.getRotationX()))
                .append(':').append(Float.floatToRawIntBits(child.getRotationY()))
                .append(':').append(Float.floatToRawIntBits(child.getPivotX()))
                .append(':').append(Float.floatToRawIntBits(child.getPivotY()))
                .append(':').append(child.getScrollX()).append(',').append(child.getScrollY())
                .append(':').append(child.getLayerType());
        Matrix matrix = child.getMatrix();
        float[] matrixValues = new float[9];
        matrix.getValues(matrixValues);
        for (float value : matrixValues) out.append(':').append(Float.floatToRawIntBits(value));
        Rect clip = child.getClipBounds();
        if (clip == null) out.append(":no-clip");
        else out.append(":clip=").append(clip.left).append(',').append(clip.top)
                .append(',').append(clip.right).append(',').append(clip.bottom);
        ViewGroup.LayoutParams params = child.getLayoutParams();
        if (params == null) out.append(":no-layout");
        else {
            out.append(':').append(params.getClass().getName())
                    .append(':').append(params.width).append(':').append(params.height);
            if (params instanceof FrameLayout.LayoutParams) {
                FrameLayout.LayoutParams frame = (FrameLayout.LayoutParams) params;
                out.append(':').append(frame.gravity)
                        .append(':').append(frame.leftMargin).append(',').append(frame.topMargin)
                        .append(',').append(frame.rightMargin).append(',').append(frame.bottomMargin);
            }
        }
        return out.toString();
    }

    private static void requireMain() {
        if (Looper.myLooper() != Looper.getMainLooper()) {
            throw new IllegalStateException("paint root requires main Looper");
        }
    }
}
