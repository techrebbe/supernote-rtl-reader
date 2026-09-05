package com.techrebbe.supernote.spreadprobe.v2android;

import android.app.Activity;
import android.graphics.Color;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.TextView;

import com.techrebbe.supernote.spreadprobe.v2.PageSlot;
import com.techrebbe.supernote.spreadprobe.v2.RectD;
import com.techrebbe.supernote.spreadprobe.v2.SpreadSnapshot;

import java.util.Collections;
import java.util.List;

/** Cosmetic, non-interactive active-page status owned only by v2. */
final class NativeReaderV2StatusOverlay {
    private static final int TOP_MARGIN_PX = 8;
    private static final int HEIGHT_PX = 52;
    private static final String TAG =
        "com.techrebbe.supernote.spreadprobe.v2.status";

    private final Activity activity;

    NativeReaderV2StatusOverlay(Activity activity) {
        if (activity == null) {
            throw new IllegalArgumentException("status activity is required");
        }
        this.activity = activity;
    }

    void update(
        SpreadSnapshot snapshot,
        boolean visible,
        String readingDirection
    ) {
        assertOwnerThread();
        if (!visible || snapshot == null
            || snapshot.mode != SpreadSnapshot.Mode.SPREAD) {
            remove();
            return;
        }
        PageSlot active = snapshot.slotForPage(snapshot.activePageIndex);
        if (active == null || active.isBlank()
            || active.side == PageSlot.Side.FULL) {
            throw new IllegalStateException(
                "status overlay lacks active spread authority"
            );
        }
        if (!"RTL".equals(readingDirection)
            && !"LTR".equals(readingDirection)) {
            throw new IllegalArgumentException(
                "status overlay reading direction is invalid"
            );
        }
        ViewGroup root = activity.findViewById(android.R.id.content);
        if (root == null) {
            throw new IllegalStateException("status overlay root is missing");
        }
        View existing = root.findViewWithTag(TAG);
        TextView label;
        if (existing instanceof TextView) {
            label = (TextView) existing;
        } else {
            if (existing != null) root.removeView(existing);
            label = new TextView(activity);
            label.setTag(TAG);
            label.setTextColor(Color.WHITE);
            label.setTextSize(14.0f);
            label.setGravity(Gravity.CENTER);
            label.setBackgroundColor(Color.rgb(120, 0, 0));
            label.setClickable(false);
            label.setFocusable(false);
            label.setImportantForAccessibility(
                View.IMPORTANT_FOR_ACCESSIBILITY_NO
            );
            FrameLayout.LayoutParams layout = new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                HEIGHT_PX,
                Gravity.TOP | Gravity.CENTER_HORIZONTAL
            );
            layout.topMargin = TOP_MARGIN_PX;
            root.addView(label, layout);
        }
        label.setText(
            readingDirection + " SPREAD: ACTIVE " + active.side.name()
                + " page " + (snapshot.activePageIndex + 1)
        );
        label.bringToFront();
    }

    /**
     * The cosmetic header overlays document pixels, so its full physical
     * strip must also be excluded from DrawPath and classified once as
     * chrome. Returning an empty list when hidden makes the former area
     * immediately writable again.
     */
    List<RectD> protectedAreas(
        SpreadSnapshot snapshot,
        boolean visible,
        int viewWidth,
        int viewHeight
    ) {
        assertOwnerThread();
        if (!visible || snapshot == null
            || snapshot.mode != SpreadSnapshot.Mode.SPREAD) {
            return Collections.emptyList();
        }
        if (viewWidth <= 0 || viewHeight <= 0) {
            throw new IllegalArgumentException(
                "status overlay canvas is unavailable"
            );
        }
        return Collections.singletonList(new RectD(
            0.0,
            0.0,
            viewWidth,
            Math.min(viewHeight, TOP_MARGIN_PX + HEIGHT_PX)
        ));
    }

    void remove() {
        assertOwnerThread();
        ViewGroup root = activity.findViewById(android.R.id.content);
        if (root == null) return;
        View existing = root.findViewWithTag(TAG);
        if (existing != null) root.removeView(existing);
    }

    private void assertOwnerThread() {
        if (Thread.currentThread() != activity.getMainLooper().getThread()) {
            throw new IllegalStateException(
                "status overlay used off its owner thread"
            );
        }
    }
}
