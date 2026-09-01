package com.techrebbe.supernote.spreadprobe.v2android;

import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Matrix;
import android.graphics.Paint;
import android.graphics.RectF;

import com.techrebbe.supernote.spreadprobe.v2.Affine2D;
import com.techrebbe.supernote.spreadprobe.v2.PageSlot;
import com.techrebbe.supernote.spreadprobe.v2.RectD;
import com.techrebbe.supernote.spreadprobe.v2.SpreadSnapshot;

/** Renders the PDF spread and the separate native handwriting projection. */
public final class NativeReaderV2Compositor {
    private static final Paint PAGE_PAINT = new Paint(
        Paint.ANTI_ALIAS_FLAG | Paint.FILTER_BITMAP_FLAG
    );
    private static final Paint INK_PAINT = new Paint(
        Paint.ANTI_ALIAS_FLAG | Paint.FILTER_BITMAP_FLAG
    );

    private final NativeReaderV2FirmwareAccess firmware;

    public NativeReaderV2Compositor(NativeReaderV2FirmwareAccess firmware) {
        if (firmware == null) {
            throw new IllegalArgumentException("firmware access is required");
        }
        this.firmware = firmware;
    }

    /** Caller owns and must eventually recycle the returned bitmaps. */
    public Result compose(
        NativeReaderV2FirmwareAccess.Components components,
        SpreadSnapshot snapshot,
        Bitmap activeNativeInk
    ) {
        if (components == null || snapshot == null || !snapshot.writerReady
            || components.readerPage != snapshot.activePageIndex) {
            throw new IllegalArgumentException(
                "complete writer-owned spread authority is required"
            );
        }
        int width = components.documentLayout.getWidth();
        int height = components.documentLayout.getHeight();
        if (width <= 0 || height <= 0) {
            throw new IllegalStateException("native document canvas has no size");
        }
        Bitmap background = Bitmap.createBitmap(
            width,
            height,
            Bitmap.Config.ARGB_8888
        );
        Bitmap ink = Bitmap.createBitmap(
            width,
            height,
            Bitmap.Config.ARGB_8888
        );
        boolean success = false;
        try {
            Canvas pageCanvas = new Canvas(background);
            pageCanvas.drawColor(Color.WHITE);
            Canvas inkCanvas = new Canvas(ink);
            drawSlot(
                components,
                snapshot,
                snapshot.leftOrFull,
                pageCanvas,
                inkCanvas,
                activeNativeInk
            );
            if (snapshot.right != null) {
                drawSlot(
                    components,
                    snapshot,
                    snapshot.right,
                    pageCanvas,
                    inkCanvas,
                    activeNativeInk
                );
            }
            success = true;
            return new Result(snapshot, background, ink);
        } finally {
            if (!success) {
                background.recycle();
                ink.recycle();
            }
        }
    }

    private void drawSlot(
        NativeReaderV2FirmwareAccess.Components components,
        SpreadSnapshot snapshot,
        PageSlot slot,
        Canvas pageCanvas,
        Canvas inkCanvas,
        Bitmap activeNativeInk
    ) {
        if (slot.isBlank()) return;
        Bitmap page = firmware.originBitmap(
            components,
            slot.sourcePageIndex
        );
        if (!usable(page)
            || page.getWidth() != Math.round(slot.sourceBox.width())
            || page.getHeight() != Math.round(slot.sourceBox.height())) {
            throw new IllegalStateException(
                "page cache bitmap disagrees with spread geometry"
            );
        }
        drawMapped(pageCanvas, page, slot.sourceToScreen, slot.screenBounds,
            PAGE_PAINT);

        if (slot.sourcePageIndex == snapshot.activePageIndex) {
            requirePageInkGeometry(activeNativeInk, page);
            drawMapped(
                inkCanvas,
                activeNativeInk,
                slot.sourceToScreen,
                slot.screenBounds,
                INK_PAINT
            );
            return;
        }

        NativeReaderV2FirmwareAccess.CanonicalInk committed =
            firmware.committedCanonicalHandwriting(
            components,
            slot.sourcePageIndex,
            page
        );
        if (committed.empty) {
            return;
        }
        try {
            if (!usable(committed.bitmap)
                || committed.bitmap.getWidth() != page.getWidth()
                || committed.bitmap.getHeight() != page.getHeight()) {
                throw new IllegalStateException(
                    "inactive mark bitmap geometry changed"
                );
            }
            drawMapped(
                inkCanvas,
                committed.bitmap,
                slot.sourceToScreen,
                slot.screenBounds,
                INK_PAINT
            );
        } finally {
            committed.recycle();
        }
    }

    private static void drawMapped(
        Canvas canvas,
        Bitmap bitmap,
        Affine2D transform,
        RectD clip,
        Paint paint
    ) {
        int save = canvas.save();
        try {
            canvas.clipRect(new RectF(
                (float) clip.left,
                (float) clip.top,
                (float) clip.right,
                (float) clip.bottom
            ));
            canvas.drawBitmap(bitmap, androidMatrix(transform), paint);
        } finally {
            canvas.restoreToCount(save);
        }
    }

    private static Matrix androidMatrix(Affine2D transform) {
        Matrix matrix = new Matrix();
        matrix.setValues(new float[] {
            (float) transform.a,
            (float) transform.c,
            (float) transform.e,
            (float) transform.b,
            (float) transform.d,
            (float) transform.f,
            0.0f,
            0.0f,
            1.0f,
        });
        return matrix;
    }

    private static void requirePageInkGeometry(
        Bitmap bitmap,
        Bitmap page
    ) {
        if (!usable(bitmap) || !usable(page)
            || bitmap.getWidth() != page.getWidth()
            || bitmap.getHeight() != page.getHeight()) {
            throw new IllegalStateException(
                "active native ink bitmap does not match its source page"
            );
        }
    }

    private static boolean usable(Bitmap bitmap) {
        return bitmap != null && !bitmap.isRecycled()
            && bitmap.getWidth() > 0 && bitmap.getHeight() > 0;
    }

    public static final class Result {
        public final SpreadSnapshot snapshot;
        public final Bitmap background;
        public final Bitmap ink;
        private boolean recycled;

        private Result(
            SpreadSnapshot snapshot,
            Bitmap background,
            Bitmap ink
        ) {
            this.snapshot = snapshot;
            this.background = background;
            this.ink = ink;
        }

        public synchronized void recycle() {
            if (recycled) return;
            recycled = true;
            if (!background.isRecycled()) background.recycle();
            if (!ink.isRecycled()) ink.recycle();
        }
    }
}
