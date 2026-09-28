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
        final boolean[] paintExpected;
        final String policy;
        final String scene;
        final long mutationRevision;

        DirectCut(View[] children, Object[] parents, String[] evidence,
                boolean[] paintExpected,
                String policy, String scene, long mutationRevision) {
            this.children = children;
            this.parents = parents;
            this.evidence = evidence;
            this.paintExpected = paintExpected;
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
                        || paintExpected[i] != other.paintExpected[i]
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
    private DirectCut completedCut;
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

    /** A current hierarchy cut. Its order is empty until this cut has actually painted. */
    public TargetOwnedVisualLeaseCore.Snapshot currentSnapshot() {
        requireMain();
        DirectCut cut = captureDirect();
        // Cleanup needs the structural cut immediately after exact removal.
        // A stale order must not masquerade as a freshly completed frame.
        boolean paintCurrent = lastCompleted != null
                && mutations.isCurrent(completedMutationRevision)
                && cut.same(completedCut);
        return snapshot(cut, snapshotOrder(paintCurrent, completedOrder));
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
                completedCut = after;
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
        drawing.add(new PaintedChild(child, indexOfChild(child),
                childEvidence(child, child.getVisibility())));
        return super.drawChild(canvas, child, drawingTime);
    }

    private Object[] verifiedPaintOrder(DirectCut before, DirectCut after) {
        if (!before.same(after)) return null;
        Object[] order = new Object[drawing.size()];
        for (int i = 0; i < drawing.size(); i++) {
            PaintedChild painted = drawing.get(i);
            if (painted.indexAtPaint < 0 || painted.indexAtPaint >= after.children.length
                    || after.children[painted.indexAtPaint] != painted.view
                    || !painted.evidenceAtPaint.equals(after.evidence[painted.indexAtPaint])) {
                return null;
            }
            order[i] = painted.view;
        }
        return paintParticipantsMatch(after.children, after.paintExpected, order) ? order : null;
    }

    // Pure identity check shared by the Android pass and offline contract test.
    // The expectation comes from visibility, not from the observed draws.
    static boolean paintParticipantsMatch(Object[] children, boolean[] expected,
            Object[] observed) {
        if (children == null || expected == null || observed == null
                || children.length != expected.length) return false;
        IdentityHashMap<Object, Boolean> participants = new IdentityHashMap<>();
        int expectedCount = 0;
        for (int i = 0; i < children.length; i++) {
            if (children[i] == null || participants.put(children[i], expected[i]) != null) {
                return false;
            }
            if (expected[i]) expectedCount++;
        }
        if (observed.length != expectedCount) return false;
        IdentityHashMap<Object, Boolean> seen = new IdentityHashMap<>();
        for (Object child : observed) {
            if (participants.get(child) != Boolean.TRUE || seen.put(child, true) != null) {
                return false;
            }
        }
        return true;
    }

    static Object[] snapshotOrder(boolean completedPaintCurrent, Object[] completedOrder) {
        return completedPaintCurrent && completedOrder != null
                ? completedOrder.clone() : new Object[0];
    }

    static boolean expectsDrawChild(int visibility) {
        return visibility == View.VISIBLE;
    }

    private Object[] completedOrder;

    private TargetOwnedVisualLeaseCore.Snapshot snapshot(DirectCut cut, Object[] order) {
        return new TargetOwnedVisualLeaseCore.Snapshot(this, cut.children, cut.parents,
                cut.evidence, cut.paintExpected, order, cut.policy, cut.scene);
    }

    private DirectCut captureDirect() {
        requireMain();
        long revisionAtStart = mutations.revision();
        int count = getChildCount();
        View[] children = new View[count];
        Object[] parents = new Object[count];
        String[] evidence = new String[count];
        boolean[] paintExpected = new boolean[count];
        for (int i = 0; i < count; i++) {
            View child = getChildAt(i);
            if (child == null) throw new IllegalStateException("null child");
            children[i] = child;
            parents[i] = child.getParent();
            int visibility = child.getVisibility();
            evidence[i] = childEvidence(child, visibility);
            // Android's ordinary dispatch policy calls drawChild for visible
            // direct children. Hidden children remain structural evidence;
            // animation-driven or other unexpected draws fail verification.
            paintExpected[i] = expectsDrawChild(visibility);
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
        return new DirectCut(children, parents, evidence, paintExpected,
                policy, scene, revisionAtStart);
    }

    @Override protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
        // Layout changes child geometry. This is before FrameLayout lays out
        // its children, so a previous completed frame becomes stale first.
        beforeEvidenceMutation();
        super.onLayout(changed, left, top, right, bottom);
    }

    private static String childEvidence(View child, int visibility) {
        StringBuilder out = new StringBuilder();
        out.append(child.getClass().getName()).append(':').append(child.getId())
                .append(':').append(visibility)
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
