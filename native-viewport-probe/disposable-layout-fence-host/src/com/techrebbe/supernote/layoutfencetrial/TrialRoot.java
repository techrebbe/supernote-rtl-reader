package com.techrebbe.supernote.layoutfencetrial;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import android.os.Looper;
import android.os.SystemClock;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.TextView;

import java.util.ArrayList;

/** Exact synthetic nine-child root. Its revision covers parent pre-calls only. */
public final class TrialRoot extends FrameLayout {
    interface Host {
        String sceneStamp();
        void onRootHierarchyChanged();
        void onUnfencedRootLayout();
        void onRootDetached();
        void onCompletedFrame(TrialEvidence.Cut frame);
        void onPaintInvalid(String reason);
    }

    private final Host host;
    private final String rootToken;
    private final ArrayList<View> drawing = new ArrayList<>();
    private TrialEvidence.Cut lastFrame;
    private long parentPreCallRevision;
    private long observedWriteOrdinal;
    private long layoutCalls;
    private long startedPaintRevision;
    private long paintStartedElapsedMs;
    private long paintStartParentRevision;
    private long paintStartWriteOrdinal;
    private long completedPaintCount;
    private boolean parentCallActive;
    private boolean drawingActive;

    TrialRoot(Context context, String rootToken, Host host) {
        super(context);
        if (rootToken == null || rootToken.isEmpty() || host == null) {
            throw new IllegalArgumentException("root identity and host required");
        }
        this.rootToken = rootToken;
        this.host = host;
        setChildrenDrawingOrderEnabled(false);
    }

    /** Stable per-root token; observers must also compare the actual Java root object. */
    public String getRootToken() { return rootToken; }

    /** Monotonic only for calls owned by TrialParent; not complete mutation authority. */
    public long getParentPreCallRevision() { return parentPreCallRevision; }

    /** Observational write sequence, including deliberately unfenced direct controls. */
    public long getObservedWriteOrdinal() { return observedWriteOrdinal; }

    public long getLayoutCallCount() { return layoutCalls; }
    public long getCompletedPaintCount() { return completedPaintCount; }
    public long getStartedPaintRevision() { return startedPaintRevision; }
    public boolean customDrawingOrderEnabled() { return isChildrenDrawingOrderEnabled(); }

    long beforeParentRootLayout() {
        requireMain();
        if (parentCallActive || parentPreCallRevision == Long.MAX_VALUE
                || observedWriteOrdinal == Long.MAX_VALUE) {
            throw new IllegalStateException("parent fence cannot advance");
        }
        parentPreCallRevision++;
        observedWriteOrdinal++;
        return parentPreCallRevision;
    }

    void enterParentCall() {
        requireMain();
        if (parentCallActive) throw new IllegalStateException("nested parent root call");
        parentCallActive = true;
    }

    void leaveParentCall() {
        requireMain();
        parentCallActive = false;
    }

    void noteDirectOffsetAfterWrite() {
        requireMain();
        if (observedWriteOrdinal == Long.MAX_VALUE) {
            throw new IllegalStateException("write ordinal exhausted");
        }
        observedWriteOrdinal++;
    }

    @Override public void onViewAdded(View child) {
        super.onViewAdded(child);
        host.onRootHierarchyChanged();
    }

    @Override public void onViewRemoved(View child) {
        super.onViewRemoved(child);
        host.onRootHierarchyChanged();
    }

    @Override protected void onLayout(boolean changed,
            int left, int top, int right, int bottom) {
        layoutCalls++;
        if (!parentCallActive) {
            // ViewGroup.layout is final. This observation is AFTER its frame write.
            if (observedWriteOrdinal == Long.MAX_VALUE) {
                throw new IllegalStateException("write ordinal exhausted");
            }
            observedWriteOrdinal++;
            host.onUnfencedRootLayout();
        }
        super.onLayout(changed, left, top, right, bottom);
    }

    @Override protected void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        host.onRootDetached();
    }

    @Override protected void dispatchDraw(Canvas canvas) {
        requireMain();
        if (drawingActive) {
            host.onPaintInvalid("NESTED_PAINT");
            super.dispatchDraw(canvas);
            return;
        }
        TrialEvidence.Cut before = captureLive();
        if (startedPaintRevision == Long.MAX_VALUE) {
            host.onPaintInvalid("PAINT_REVISION_OVERFLOW");
            return;
        }
        startedPaintRevision++;
        paintStartedElapsedMs = SystemClock.elapsedRealtime();
        paintStartParentRevision = parentPreCallRevision;
        paintStartWriteOrdinal = observedWriteOrdinal;
        drawingActive = true;
        drawing.clear();
        try {
            super.dispatchDraw(canvas);
            TrialEvidence.Cut after = captureLive();
            if (!before.sameOriginals(after)
                    || !before.bounds.equals(after.bounds)
                    || before.parentPreCallRevision != after.parentPreCallRevision
                    || before.observedWriteOrdinal != after.observedWriteOrdinal
                    || before.rootLayoutCalls != after.rootLayoutCalls
                    || drawing.size() != TrialEvidence.ORIGINAL_COUNT) {
                host.onPaintInvalid("PAINT_STATE_CHANGED_OR_CHILD_SKIPPED");
                return;
            }
            Object[] painted = drawing.toArray(new Object[drawing.size()]);
            TrialEvidence.Cut complete = new TrialEvidence.Cut(this, rootToken,
                    after.scene, after.bounds, after.childCount, after.childrenCopy(),
                    after.parentsCopy(), after.childEvidenceCopy(), painted,
                    parentPreCallRevision, observedWriteOrdinal, layoutCalls,
                    startedPaintRevision, paintStartedElapsedMs,
                    paintStartParentRevision, paintStartWriteOrdinal,
                    startedPaintRevision, SystemClock.elapsedRealtime());
            if (!complete.exactNinePainted()) {
                host.onPaintInvalid("PAINT_ORDER_OR_NINE_MISMATCH");
                return;
            }
            lastFrame = complete;
            completedPaintCount++;
            host.onCompletedFrame(complete);
        } finally {
            drawing.clear();
            drawingActive = false;
        }
    }

    @Override protected boolean drawChild(Canvas canvas, View child, long drawingTime) {
        if (drawingActive) drawing.add(child);
        return super.drawChild(canvas, child, drawingTime);
    }

    TrialEvidence.Cut lastCompletedFrame() { return lastFrame; }

    TrialEvidence.Cut captureLive() {
        requireMain();
        Object[] children = new Object[TrialEvidence.ORIGINAL_COUNT];
        Object[] parents = new Object[TrialEvidence.ORIGINAL_COUNT];
        String[] childEvidence = new String[TrialEvidence.ORIGINAL_COUNT];
        Object[] painted = new Object[TrialEvidence.ORIGINAL_COUNT];
        for (int i = 0; i < TrialEvidence.ORIGINAL_COUNT; i++) {
            View child = i < getChildCount() ? getChildAt(i) : null;
            children[i] = child;
            parents[i] = child == null ? null : child.getParent();
            childEvidence[i] = child == null ? "MISSING" : childEvidence(child);
            painted[i] = lastFrame == null ? null : lastFrame.paintedAt(i);
        }
        return new TrialEvidence.Cut(this, rootToken, host.sceneStamp(),
                new TrialEvidence.Bounds(getLeft(), getTop(), getRight(), getBottom()),
                getChildCount(), children, parents, childEvidence, painted,
                parentPreCallRevision, observedWriteOrdinal, layoutCalls,
                startedPaintRevision, paintStartedElapsedMs,
                paintStartParentRevision, paintStartWriteOrdinal,
                lastFrame == null ? 0 : lastFrame.completedPaintRevision,
                lastFrame == null ? 0 : lastFrame.completedPaintElapsedMs);
    }

    boolean originalsHavePendingLayout(View[] originals) {
        for (View child : originals) if (child == null || child.isLayoutRequested()) return true;
        return false;
    }

    private static String childEvidence(View child) {
        StringBuilder out = new StringBuilder();
        out.append(child.getClass().getName()).append(':').append(child.getId())
                .append(':').append(child.getVisibility())
                .append(':').append(child.getMeasuredWidth()).append(',')
                .append(child.getMeasuredHeight())
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
                .append(':').append(String.valueOf(child.getContentDescription()));
        Drawable background = child.getBackground();
        out.append(":background=").append(background == null ? "none"
                : background.getClass().getName() + "@"
                    + System.identityHashCode(background));
        if (background instanceof ColorDrawable) {
            out.append(':').append(((ColorDrawable) background).getColor());
        }
        if (child instanceof TextView) {
            TextView text = (TextView) child;
            out.append(":text=").append(String.valueOf(text.getText()))
                    .append(":textColor=").append(text.getCurrentTextColor());
        }
        ViewGroup.LayoutParams params = child.getLayoutParams();
        if (params == null) out.append(":no-layout");
        else {
            out.append(':').append(params.getClass().getName())
                    .append(':').append(params.width).append(':').append(params.height);
            if (params instanceof FrameLayout.LayoutParams) {
                FrameLayout.LayoutParams frame = (FrameLayout.LayoutParams) params;
                out.append(':').append(frame.gravity)
                        .append(':').append(frame.leftMargin).append(',')
                        .append(frame.topMargin).append(',')
                        .append(frame.rightMargin).append(',').append(frame.bottomMargin);
            }
        }
        return out.toString();
    }

    private static void requireMain() {
        if (Looper.myLooper() != Looper.getMainLooper()) {
            throw new IllegalStateException("root evidence requires main Looper");
        }
    }
}
