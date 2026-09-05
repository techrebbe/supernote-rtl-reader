package com.techrebbe.supernote.spreadprobe.v2android;

import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Matrix;
import android.graphics.Paint;
import android.graphics.RectF;

import com.techrebbe.supernote.spreadprobe.v2.Affine2D;
import com.techrebbe.supernote.spreadprobe.v2.NativeDisplayTransform;
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
    private static final Paint DIVIDER_PAINT = new Paint();

    static {
        DIVIDER_PAINT.setColor(Color.BLACK);
        DIVIDER_PAINT.setStyle(Paint.Style.FILL);
    }

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
        Bitmap digest = Bitmap.createBitmap(
            width,
            height,
            Bitmap.Config.ARGB_8888
        );
        boolean success = false;
        try {
            Canvas pageCanvas = new Canvas(background);
            pageCanvas.drawColor(Color.WHITE);
            Canvas inkCanvas = new Canvas(ink);
            Canvas digestCanvas = new Canvas(digest);
            drawSlot(
                components,
                snapshot,
                snapshot.leftOrFull,
                pageCanvas,
                inkCanvas,
                digestCanvas,
                activeNativeInk
            );
            if (snapshot.right != null) {
                drawSlot(
                    components,
                    snapshot,
                    snapshot.right,
                    pageCanvas,
                    inkCanvas,
                    digestCanvas,
                    activeNativeInk
                );
                drawDivider(pageCanvas, snapshot);
            }
            success = true;
            return new Result(snapshot, background, ink, digest);
        } finally {
            if (!success) {
                background.recycle();
                ink.recycle();
                digest.recycle();
            }
        }
    }

    private void drawSlot(
        NativeReaderV2FirmwareAccess.Components components,
        SpreadSnapshot snapshot,
        PageSlot slot,
        Canvas pageCanvas,
        Canvas inkCanvas,
        Canvas digestCanvas,
        Bitmap activeNativeInk
    ) {
        if (slot.isBlank()) return;
        Bitmap page = firmware.originBitmap(
            components,
            slot.sourcePageIndex
        );
        RectD fullSource = usable(page) ? new RectD(
            0,
            0,
            page.getWidth(),
            page.getHeight()
        ) : null;
        if (!usable(page) || !contains(fullSource, slot.sourceBox)) {
            throw new IllegalStateException(
                "page cache bitmap disagrees with spread geometry"
            );
        }
        RectD contentClip = intersection(
            slot.screenBounds,
            slot.contentBounds
        );
        drawMapped(pageCanvas, page, slot.sourceToScreen, contentClip,
            PAGE_PAINT);
        drawDigest(components, slot, page, fullSource, contentClip, digestCanvas);

        if (slot.sourcePageIndex == snapshot.activePageIndex) {
            drawActiveInk(
                components,
                slot,
                page,
                fullSource,
                contentClip,
                inkCanvas,
                activeNativeInk
            );
            return;
        }

        drawCommittedInk(
            components,
            slot,
            page,
            contentClip,
            inkCanvas
        );
    }

    private void drawDigest(
        NativeReaderV2FirmwareAccess.Components components,
        PageSlot slot,
        Bitmap page,
        RectD fullSource,
        RectD contentClip,
        Canvas digestCanvas
    ) {
        Bitmap digest = firmware.digestBitmap(
            components,
            slot.sourcePageIndex
        );
        if (!usable(digest)) return;
        Affine2D digestToScreen;
        if (digest.getWidth() == page.getWidth()
            && digest.getHeight() == page.getHeight()) {
            digestToScreen = NativeDisplayTransform.displayToOrigin(
                slot.sourceBox,
                fullSource
            ).then(slot.sourceToScreen);
        } else {
            digestToScreen = NativeDisplayTransform.croppedBitmapToOrigin(
                digest.getWidth(),
                digest.getHeight(),
                slot.sourceBox,
                fullSource
            ).then(slot.sourceToScreen);
        }
        drawMapped(
            digestCanvas,
            digest,
            digestToScreen,
            contentClip,
            INK_PAINT
        );
    }

    private void drawActiveInk(
        NativeReaderV2FirmwareAccess.Components components,
        PageSlot slot,
        Bitmap page,
        RectD fullSource,
        RectD contentClip,
        Canvas inkCanvas,
        Bitmap activeNativeInk
    ) {
        if (!usable(activeNativeInk)) {
            drawCommittedInk(
                components,
                slot,
                page,
                contentClip,
                inkCanvas
            );
            return;
        }
        if (activeNativeInk.getWidth() == inkCanvas.getWidth()
            && activeNativeInk.getHeight() == inkCanvas.getHeight()) {
            // Once v2 owns DrawPath, the exact firmware presenter exposes its
            // live layer in native display coordinates (1872x1404 on the
            // Nomad landscape canvas), not in the origin page's portrait
            // coordinates.  Preserve those pixels under the authoritative
            // active-slot clip instead of applying the source-page transform
            // a second time.
            drawMapped(
                inkCanvas,
                activeNativeInk,
                Affine2D.identity(),
                contentClip,
                INK_PAINT
            );
            return;
        }
        requireOriginInkGeometry(activeNativeInk, page);
        Affine2D activeInkToScreen = NativeDisplayTransform.displayToOrigin(
            slot.sourceBox,
            fullSource
        ).then(slot.sourceToScreen);
        drawMapped(
            inkCanvas,
            activeNativeInk,
            activeInkToScreen,
            contentClip,
            INK_PAINT
        );
    }

    private void drawCommittedInk(
        NativeReaderV2FirmwareAccess.Components components,
        PageSlot slot,
        Bitmap page,
        RectD contentClip,
        Canvas inkCanvas
    ) {
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
                contentClip,
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

    private static void drawDivider(
        Canvas canvas,
        SpreadSnapshot snapshot
    ) {
        double left = snapshot.leftOrFull.screenBounds.right;
        double right = snapshot.right.screenBounds.left;
        if (!(right > left)) return;
        double top = Math.min(
            snapshot.leftOrFull.screenBounds.top,
            snapshot.right.screenBounds.top
        );
        double bottom = Math.max(
            snapshot.leftOrFull.screenBounds.bottom,
            snapshot.right.screenBounds.bottom
        );
        canvas.drawRect(
            (float) left,
            (float) top,
            (float) right,
            (float) bottom,
            DIVIDER_PAINT
        );
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

    private static void requireOriginInkGeometry(
        Bitmap bitmap,
        Bitmap page
    ) {
        if (!usable(bitmap) || !usable(page)
            || bitmap.getWidth() != page.getWidth()
            || bitmap.getHeight() != page.getHeight()) {
            throw new IllegalStateException(
                "active native ink display does not match its source page"
            );
        }
    }

    private static boolean usable(Bitmap bitmap) {
        return bitmap != null && !bitmap.isRecycled()
            && bitmap.getWidth() > 0 && bitmap.getHeight() > 0;
    }

    private static boolean contains(RectD outer, RectD inner) {
        if (outer == null || inner == null) return false;
        double tolerance = 0.501;
        return inner.left >= outer.left - tolerance
            && inner.top >= outer.top - tolerance
            && inner.right <= outer.right + tolerance
            && inner.bottom <= outer.bottom + tolerance;
    }

    private static RectD intersection(RectD first, RectD second) {
        double left = Math.max(first.left, second.left);
        double top = Math.max(first.top, second.top);
        double right = Math.min(first.right, second.right);
        double bottom = Math.min(first.bottom, second.bottom);
        if (!(right > left && bottom > top)) {
            throw new IllegalStateException(
                "page content has no visible physical intersection"
            );
        }
        return new RectD(left, top, right, bottom);
    }

    public static final class Result {
        public final SpreadSnapshot snapshot;
        public final Bitmap background;
        public final Bitmap ink;
        public final Bitmap digest;
        private boolean recycled;

        private Result(
            SpreadSnapshot snapshot,
            Bitmap background,
            Bitmap ink,
            Bitmap digest
        ) {
            this.snapshot = snapshot;
            this.background = background;
            this.ink = ink;
            this.digest = digest;
        }

        public synchronized void recycle() {
            if (recycled) return;
            recycled = true;
            if (!background.isRecycled()) background.recycle();
            if (!ink.isRecycled()) ink.recycle();
            if (!digest.isRecycled()) digest.recycle();
        }
    }
}
