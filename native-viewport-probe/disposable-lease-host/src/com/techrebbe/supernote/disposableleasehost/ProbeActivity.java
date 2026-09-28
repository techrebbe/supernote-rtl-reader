package com.techrebbe.supernote.disposableleasehost;

import android.app.Activity;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.content.res.Configuration;
import android.graphics.Canvas;
import android.os.Bundle;
import android.os.Looper;
import android.os.SystemClock;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewTreeObserver;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.TextView;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.lang.ref.WeakReference;
import java.util.ArrayList;

/** The nine original views are never replaced, removed, or reordered by this app. */
public final class ProbeActivity extends Activity {
    public static final class ProbeRoot extends FrameLayout {
        public static final class PaintEntry {
            public final int identityHash;
            public final int childIndexAtPaint;
            public final WeakReference<View> view;

            PaintEntry(View child, int index) {
                identityHash = System.identityHashCode(child);
                childIndexAtPaint = index;
                view = new WeakReference<>(child);
            }
        }

        private final ArrayList<View> drawingFrame = new ArrayList<>();
        private PaintEntry[] lastPaintOrder = new PaintEntry[0];
        private long lastPaintElapsedRealtimeMs;
        private long currentLayoutPass;
        private long lastPaintLayoutPass;
        private final PaintEpoch paintEpoch = new PaintEpoch();

        public ProbeRoot(Activity activity) {
            super(activity);
            setChildrenDrawingOrderEnabled(false);
        }

        public boolean customDrawingOrderEnabled() {
            return isChildrenDrawingOrderEnabled();
        }

        public int rawDrawingChildIndex(int position) {
            if (!customDrawingOrderEnabled()) return position;
            return getChildDrawingOrder(getChildCount(), position);
        }

        @Override protected void dispatchDraw(Canvas canvas) {
            long frameRevision = paintEpoch.beginFrame();
            drawingFrame.clear();
            super.dispatchDraw(canvas);
            PaintEntry[] observed = new PaintEntry[drawingFrame.size()];
            for (int i = 0; i < observed.length; i++) {
                View child = drawingFrame.get(i);
                observed[i] = new PaintEntry(child, indexOfChild(child));
            }
            lastPaintOrder = observed;
            drawingFrame.clear();
            lastPaintElapsedRealtimeMs = SystemClock.elapsedRealtime();
            lastPaintLayoutPass = currentLayoutPass;
            paintEpoch.completeFrame(frameRevision);
        }

        @Override protected boolean drawChild(Canvas canvas, View child, long drawingTime) {
            drawingFrame.add(child);
            return super.drawChild(canvas, child, drawingTime);
        }

        @Override public void onViewAdded(View child) {
            super.onViewAdded(child);
            invalidatePaintEvidence();
            ProbeState.get().record("ROOT_CHILD_ADDED", "id=" + child.getId()
                    + " identity=" + System.identityHashCode(child)
                    + " count=" + getChildCount());
        }

        @Override public void onViewRemoved(View child) {
            super.onViewRemoved(child);
            invalidatePaintEvidence();
            ProbeState.get().record("ROOT_CHILD_REMOVED", "id=" + child.getId()
                    + " identity=" + System.identityHashCode(child)
                    + " count=" + getChildCount());
        }

        public PaintEntry[] lastPaintOrder() { return lastPaintOrder.clone(); }
        public long lastPaintElapsedRealtimeMs() { return lastPaintElapsedRealtimeMs; }
        public long lastPaintLayoutPass() { return lastPaintLayoutPass; }
        public void markLayoutPass(long pass) {
            currentLayoutPass = pass;
            invalidatePaintEvidence();
        }
        public void invalidatePaintEvidence() {
            paintEpoch.invalidate();
            invalidate();
        }
        public boolean paintFreshForRevision() { return paintEpoch.fresh(); }
        public long requiredPaintRevision() { return paintEpoch.requiredRevision(); }
        public long lastPaintRevision() { return paintEpoch.observedRevision(); }
    }

    private final ProbeModel model = new ProbeModel();
    private final View[] originals = new View[ProbeContract.childCount()];
    private final String[] baselineSignatures = new String[ProbeContract.childCount()];
    private ProbeRoot root;
    private ImageView pdfSurrogate;
    private TextView digestSurrogate;
    private TextView inkSurrogate;
    private Object renderIdentity = new Object();
    private String lifecycle = "NEW";
    private String baselineRootSignature;
    private long actualLayoutPasses;
    private long activitySerial;
    private boolean admitted;

    @Override public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        root = new ProbeRoot(this);
        activitySerial = ProbeState.get().register(this, root);
        if (activitySerial < 0) {
            ProbeState.get().record("ACTIVITY_REJECTED", "second live instance");
            finish();
            return;
        }
        admitted = true;
        root.setId(ProbeContract.ROOT_ID);
        root.setContentDescription("disposable_nine_child_root");
        root.setBackgroundColor(0xfff7f7f2);
        for (int i = 0; i < originals.length; i++) {
            ProbeContract.ChildSpec spec = ProbeContract.childAt(i);
            View child;
            if (spec.image) {
                ImageView image = new ImageView(this);
                image.setBackgroundColor(spec.color);
                pdfSurrogate = image;
                child = image;
            } else {
                TextView label = new TextView(this);
                label.setText(spec.name);
                label.setGravity(Gravity.CENTER);
                label.setTextColor(0xff202020);
                label.setBackgroundColor(spec.color);
                if (i == 1) digestSurrogate = label;
                if (i == 2) inkSurrogate = label;
                child = label;
            }
            child.setId(spec.id);
            child.setContentDescription(spec.name);
            child.setFocusable(false);
            child.setClickable(false);
            FrameLayout.LayoutParams params = new FrameLayout.LayoutParams(dp(96), dp(56));
            params.gravity = Gravity.TOP | Gravity.LEFT;
            params.leftMargin = dp(8 + 104 * spec.column);
            params.topMargin = dp(8 + 64 * spec.row);
            root.addView(child, params);
            originals[i] = child;
        }
        if (root.getChildCount() != 9) throw new AssertionError("nine originals required");
        root.getViewTreeObserver().addOnGlobalLayoutListener(
                new ViewTreeObserver.OnGlobalLayoutListener() {
                    @Override public void onGlobalLayout() {
                        actualLayoutPasses++;
                        root.markLayoutPass(actualLayoutPasses);
                        if (baselineRootSignature == null && root.isAttachedToWindow()
                                && root.getWidth() > 0 && root.getHeight() > 0
                                && originalsAtExactIndices()) {
                            for (int i = 0; i < originals.length; i++) {
                                baselineSignatures[i] = structuralSignature(originals[i]);
                            }
                            baselineRootSignature = rootSignature();
                            ProbeState.get().record("BASELINE_CAPTURED", "nine laid-out originals");
                        }
                        ProbeState.get().record("LAYOUT_PASS", Long.toString(actualLayoutPasses));
                    }
                });
        setContentView(root);
        lifecycle = "CREATED";
        ProbeState.get().record("ACTIVITY_CREATE", "serial=" + activitySerial);
    }

    @Override protected void onStart() {
        super.onStart();
        if (!admitted) return;
        lifecycle = "STARTED";
        ProbeState.get().record("ACTIVITY_START", "serial=" + activitySerial);
    }

    @Override protected void onResume() {
        super.onResume();
        if (!admitted) return;
        root.invalidatePaintEvidence();
        lifecycle = "RESUMED";
        ProbeState.get().record("ACTIVITY_RESUME", "serial=" + activitySerial);
    }

    @Override protected void onPause() {
        if (!admitted) { super.onPause(); return; }
        root.invalidatePaintEvidence();
        lifecycle = "PAUSED";
        ProbeState.get().record("ACTIVITY_PAUSE", "serial=" + activitySerial);
        super.onPause();
    }

    @Override protected void onStop() {
        if (!admitted) { super.onStop(); return; }
        root.invalidatePaintEvidence();
        lifecycle = "STOPPED";
        ProbeState.get().record("ACTIVITY_STOP", "serial=" + activitySerial);
        super.onStop();
    }

    @Override protected void onDestroy() {
        if (!admitted) { super.onDestroy(); return; }
        root.invalidatePaintEvidence();
        lifecycle = "DESTROYED";
        ProbeState.get().record("ACTIVITY_DESTROY", "serial=" + activitySerial);
        ProbeState.get().unregister(this);
        super.onDestroy();
    }

    @Override public void onConfigurationChanged(Configuration configuration) {
        super.onConfigurationChanged(configuration);
        if (!admitted) return;
        root.invalidatePaintEvidence();
        model.apply("layout");
        applyLayoutPadding();
        ProbeState.get().record("CONFIGURATION_CHANGE",
                "orientation=" + configuration.orientation + " layoutEpoch=" + model.layoutEpoch());
    }

    @Override public void onWindowFocusChanged(boolean focused) {
        super.onWindowFocusChanged(focused);
        if (!admitted) return;
        root.invalidatePaintEvidence();
        ProbeState.get().record("WINDOW_FOCUS", Boolean.toString(focused));
    }

    @Override protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        if (!admitted) return;
        root.invalidatePaintEvidence();
        ProbeState.get().record("ACTIVITY_REUSED", "serial=" + activitySerial);
    }

    /** Called only by the provider's bounded main-thread dispatch. */
    public boolean applyCommand(String command) {
        requireMainThread();
        if (!admitted) return false;
        if (model.apply(command)) {
            root.invalidatePaintEvidence();
            if ("render".equals(command)) {
                renderIdentity = new Object();
                pdfSurrogate.setBackgroundColor(
                        (model.renderEpoch() & 1L) == 0L ? 0xff6d8caf : 0xff466381);
            } else if ("layout".equals(command)) {
                applyLayoutPadding();
            }
            ProbeState.get().record("TOGGLE_" + command.toUpperCase(),
                    "page=" + model.page() + " uri=" + model.uri()
                    + " render=" + model.renderEpoch() + " layout=" + model.layoutEpoch());
            return true;
        }
        if ("orientation".equals(command)) {
            root.invalidatePaintEvidence();
            int next = getResources().getConfiguration().orientation
                    == Configuration.ORIENTATION_LANDSCAPE
                    ? ActivityInfo.SCREEN_ORIENTATION_PORTRAIT
                    : ActivityInfo.SCREEN_ORIENTATION_LANDSCAPE;
            setRequestedOrientation(next);
            ProbeState.get().record("ORIENTATION_REQUEST", Integer.toString(next));
            return true;
        }
        if ("cover".equals(command)) {
            root.invalidatePaintEvidence();
            return ProbeState.get().requestCover(this);
        }
        if ("uncover".equals(command)) {
            root.invalidatePaintEvidence();
            return ProbeState.get().uncover();
        }
        if ("finish".equals(command)) {
            root.invalidatePaintEvidence();
            ProbeState.get().record("FINISH_REQUEST", "");
            finish();
            return true;
        }
        return false;
    }

    private void applyLayoutPadding() {
        int inset = model.alternateLayout() ? dp(12) : 0;
        root.setPadding(inset, inset, 0, 0);
        root.requestLayout();
    }

    public ProbeRoot getProbeRoot() { return root; }
    public ImageView getPdfSurrogate() { return pdfSurrogate; }
    public TextView getDigestSurrogate() { return digestSurrogate; }
    public TextView getInkSurrogate() { return inkSurrogate; }
    public Object getRenderIdentity() { return renderIdentity; }
    public int getSyntheticPage() { return model.page(); }
    public String getSyntheticUri() { return model.uri(); }
    public long getSyntheticRenderEpoch() { return model.renderEpoch(); }
    public long getSyntheticLayoutEpoch() { return model.layoutEpoch(); }

    /** No source file, page bitmap, or mark file is opened to produce this JSON. */
    public String snapshotOnMainThread() {
        requireMainThread();
        if (!admitted || ProbeState.get().activity() != this) {
            throw new IllegalStateException("not the admitted activity/root");
        }
        try {
            JSONObject result = new JSONObject();
            result.put("schema", "disposable-lease-host-state-v1");
            result.put("process", ProbeState.get().identityJson());
            result.put("sampleElapsedRealtimeMs", SystemClock.elapsedRealtime());
            result.put("activitySerial", activitySerial);
            result.put("activityIdentityHash", System.identityHashCode(this));
            result.put("lifecycle", lifecycle);
            result.put("taskId", getTaskId());
            result.put("displayId", getDisplay() == null ? -1 : getDisplay().getDisplayId());
            result.put("orientation", getResources().getConfiguration().orientation);
            result.put("rootIdentityHash", System.identityHashCode(root));
            result.put("rootAttached", root.isAttachedToWindow());
            result.put("rootWidth", root.getWidth());
            result.put("rootHeight", root.getHeight());
            result.put("rootPaddingLeft", root.getPaddingLeft());
            result.put("rootPaddingTop", root.getPaddingTop());
            result.put("baselineCaptured", baselineRootSignature != null);
            result.put("actualLayoutPasses", actualLayoutPasses);
            result.put("page", model.page());
            result.put("uri", model.uri());
            result.put("renderEpoch", model.renderEpoch());
            result.put("renderIdentityHash", System.identityHashCode(renderIdentity));
            result.put("layoutEpoch", model.layoutEpoch());
            result.put("childCount", root.getChildCount());
            result.put("customDrawingOrderEnabled", root.customDrawingOrderEnabled());

            ProbeRoot.PaintEntry[] paintOrder = root.lastPaintOrder();
            JSONArray paint = new JSONArray();
            boolean paintMatchesOriginals = paintOrder.length == originals.length;
            for (int i = 0; i < paintOrder.length; i++) {
                JSONObject entry = new JSONObject();
                entry.put("paintPosition", i);
                View paintedView = paintOrder[i].view.get();
                entry.put("childIndexAtPaint", paintOrder[i].childIndexAtPaint);
                entry.put("currentChildIndex", paintedView == null
                        ? -1 : root.indexOfChild(paintedView));
                entry.put("originalIndex", paintedView == null
                        ? -1 : originalIndexOf(paintedView));
                entry.put("identityHash", paintOrder[i].identityHash);
                entry.put("referenceStillLive", paintedView != null);
                paint.put(entry);
                if (i >= originals.length || paintedView != originals[i]) {
                    paintMatchesOriginals = false;
                }
            }
            result.put("lastPaintOrder", paint);
            result.put("lastPaintElapsedRealtimeMs", root.lastPaintElapsedRealtimeMs());
            result.put("lastPaintLayoutPass", root.lastPaintLayoutPass());
            result.put("paintOrderMatchesOriginals", paintMatchesOriginals);
            boolean paintFreshForLayout = root.lastPaintElapsedRealtimeMs() > 0
                    && root.lastPaintLayoutPass() == actualLayoutPasses;
            result.put("paintFreshForLayout", paintFreshForLayout);
            result.put("requiredPaintRevision", root.requiredPaintRevision());
            result.put("lastPaintRevision", root.lastPaintRevision());
            result.put("paintFreshForRevision", root.paintFreshForRevision());

            JSONArray current = new JSONArray();
            for (int i = 0; i < root.getChildCount(); i++) {
                current.put(childJson(root.getChildAt(i), i));
            }
            result.put("children", current);
            JSONArray original = new JSONArray();
            boolean present = true;
            boolean relativeOrder = true;
            boolean originalGeometryAndParams = baselineRootSignature != null
                    && baselineRootSignature.equals(rootSignature());
            int previousIndex = -1;
            for (int i = 0; i < originals.length; i++) {
                View child = originals[i];
                int currentIndex = root.indexOfChild(child);
                JSONObject entry = childJson(child, currentIndex);
                entry.put("originalIndex", i);
                entry.put("present", currentIndex >= 0 && child.getParent() == root);
                entry.put("baselineSignatureMatches", baselineSignatures[i] != null
                        && baselineSignatures[i].equals(structuralSignature(child)));
                original.put(entry);
                if (currentIndex < 0 || child.getParent() != root) present = false;
                if (currentIndex <= previousIndex) relativeOrder = false;
                if (baselineSignatures[i] == null
                        || !baselineSignatures[i].equals(structuralSignature(child))) {
                    originalGeometryAndParams = false;
                }
                previousIndex = currentIndex;
            }
            result.put("originals", original);
            result.put("originalsPresent", present);
            result.put("originalRelativeOrder", relativeOrder);
            result.put("originalsAtExactIndices", originalsAtExactIndices());
            result.put("originalGeometryAndParams", originalGeometryAndParams);
            boolean exactNineBaseline = baselineRootSignature != null
                    && root.getChildCount() == 9 && originalsAtExactIndices()
                    && originalGeometryAndParams && !root.customDrawingOrderEnabled();
            result.put("exactNineBaseline", exactNineBaseline);
            result.put("liveNineBaselineCandidate", exactNineBaseline
                    && "RESUMED".equals(lifecycle) && root.isAttachedToWindow()
                    && paintMatchesOriginals && paintFreshForLayout
                    && root.paintFreshForRevision());
            JSONObject bindings = new JSONObject();
            bindings.put("pdfOriginal", pdfSurrogate == originals[0]);
            bindings.put("digestOriginal", digestSurrogate == originals[1]);
            bindings.put("inkOriginal", inkSurrogate == originals[2]);
            bindings.put("pdfIdentityHash", System.identityHashCode(pdfSurrogate));
            bindings.put("digestIdentityHash", System.identityHashCode(digestSurrogate));
            bindings.put("inkIdentityHash", System.identityHashCode(inkSurrogate));
            result.put("fieldBindings", bindings);
            return result.toString();
        } catch (JSONException exception) {
            throw new IllegalStateException("snapshot JSON failed", exception);
        }
    }

    private JSONObject childJson(View child, int index) throws JSONException {
        JSONObject value = new JSONObject();
        int originalIndex = originalIndexOf(child);
        value.put("index", index);
        value.put("originalIndex", originalIndex);
        value.put("name", originalIndex >= 0
                ? ProbeContract.childAt(originalIndex).name : "foreign_child");
        value.put("identityHash", System.identityHashCode(child));
        value.put("class", child.getClass().getName());
        value.put("id", child.getId());
        value.put("parentIsRoot", child.getParent() == root);
        value.put("parentIdentityHash", child.getParent() == null ? 0
                : System.identityHashCode(child.getParent()));
        value.put("visibility", child.getVisibility());
        value.put("left", child.getLeft());
        value.put("top", child.getTop());
        value.put("right", child.getRight());
        value.put("bottom", child.getBottom());
        int[] screen = new int[2];
        child.getLocationOnScreen(screen);
        value.put("screenLeft", screen[0]);
        value.put("screenTop", screen[1]);
        value.put("screenRight", screen[0] + child.getWidth());
        value.put("screenBottom", screen[1] + child.getHeight());
        value.put("elevation", child.getElevation());
        value.put("translationZ", child.getTranslationZ());
        value.put("z", child.getZ());
        value.put("alpha", child.getAlpha());
        value.put("rawDrawingPosition", index >= 0 ? drawingPositionOf(index) : -1);
        ViewGroup.LayoutParams params = child.getLayoutParams();
        JSONObject layout = new JSONObject();
        layout.put("class", params == null ? JSONObject.NULL : params.getClass().getName());
        layout.put("width", params == null ? JSONObject.NULL : params.width);
        layout.put("height", params == null ? JSONObject.NULL : params.height);
        if (params instanceof FrameLayout.LayoutParams) {
            FrameLayout.LayoutParams frame = (FrameLayout.LayoutParams) params;
            layout.put("gravity", frame.gravity);
            layout.put("leftMargin", frame.leftMargin);
            layout.put("topMargin", frame.topMargin);
            layout.put("rightMargin", frame.rightMargin);
            layout.put("bottomMargin", frame.bottomMargin);
        }
        value.put("layout", layout);
        return value;
    }

    private int drawingPositionOf(int index) {
        for (int position = 0; position < root.getChildCount(); position++) {
            if (root.rawDrawingChildIndex(position) == index) return position;
        }
        return -1;
    }

    private int originalIndexOf(View view) {
        for (int i = 0; i < originals.length; i++) if (originals[i] == view) return i;
        return -1;
    }

    private boolean originalsAtExactIndices() {
        if (root.getChildCount() != originals.length) return false;
        for (int i = 0; i < originals.length; i++) {
            if (root.getChildAt(i) != originals[i] || originals[i].getParent() != root) {
                return false;
            }
        }
        return true;
    }

    private String rootSignature() {
        return root.getWidth() + ":" + root.getHeight() + ":"
                + root.getLeft() + ":" + root.getTop() + ":"
                + root.getPaddingLeft() + ":" + root.getPaddingTop() + ":"
                + root.getPaddingRight() + ":" + root.getPaddingBottom();
    }

    private String structuralSignature(View view) {
        StringBuilder value = new StringBuilder();
        value.append(view.getId()).append(':').append(view.getClass().getName())
                .append(':').append(view.getVisibility()).append(':')
                .append(view.getLeft()).append(':').append(view.getTop()).append(':')
                .append(view.getRight()).append(':').append(view.getBottom()).append(':')
                .append(view.getElevation()).append(':').append(view.getTranslationZ())
                .append(':').append(view.getZ()).append(':').append(view.getAlpha());
        ViewGroup.LayoutParams params = view.getLayoutParams();
        if (params != null) {
            value.append(':').append(params.getClass().getName()).append(':')
                    .append(params.width).append(':').append(params.height);
            if (params instanceof FrameLayout.LayoutParams) {
                FrameLayout.LayoutParams frame = (FrameLayout.LayoutParams) params;
                value.append(':').append(frame.gravity).append(':')
                        .append(frame.leftMargin).append(':').append(frame.topMargin)
                        .append(':').append(frame.rightMargin).append(':')
                        .append(frame.bottomMargin);
            }
        }
        return value.toString();
    }

    private int dp(int value) {
        return (int) (value * getResources().getDisplayMetrics().density + 0.5f);
    }

    private static void requireMainThread() {
        if (Looper.myLooper() != Looper.getMainLooper()) {
            throw new IllegalStateException("probe hierarchy requires main Looper");
        }
    }
}
