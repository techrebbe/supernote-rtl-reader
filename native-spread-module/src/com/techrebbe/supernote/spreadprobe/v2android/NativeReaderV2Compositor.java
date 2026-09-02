package com.techrebbe.supernote.spreadprobe.v2android;

import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Matrix;
import android.graphics.Paint;
import android.graphics.PorterDuff;
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

    /**
     * Refreshes only the active page's ink/digest halves in the already
     * installed spread. Page pixels and the inactive projection are immutable
     * for an ordinary completed stroke, so rebuilding three full-screen
     * bitmaps (and rereading the inactive mark page) would be wasteful.
     */
    public void refreshActiveLayers(
        NativeReaderV2FirmwareAccess.Components components,
        Result current,
        Bitmap activeNativeInk
    ) {
        if (components == null || current == null || current.recycled
            || current.snapshot == null || !current.snapshot.writerReady
            || components.readerPage != current.snapshot.activePageIndex
            || !usable(current.ink) || !usable(current.digest)) {
            throw new IllegalArgumentException(
                "live writer-owned spread layers are required"
            );
        }
        SpreadSnapshot snapshot = current.snapshot;
        PageSlot slot = snapshot.slotForPage(snapshot.activePageIndex);
        if (slot == null || slot.isBlank()) {
            throw new IllegalStateException("active spread slot is unavailable");
        }
        Bitmap page = firmware.originBitmap(components, slot.sourcePageIndex);
        RectD fullSource = usable(page) ? new RectD(
            0,
            0,
            page.getWidth(),
            page.getHeight()
        ) : null;
        if (!usable(page) || !contains(fullSource, slot.sourceBox)) {
            throw new IllegalStateException(
                "active page cache bitmap disagrees with spread geometry"
            );
        }
        RectD contentClip = intersection(slot.screenBounds, slot.contentBounds);
        int scratchLeft = Math.max(0, (int) Math.floor(slot.screenBounds.left));
        int scratchTop = Math.max(0, (int) Math.floor(slot.screenBounds.top));
        int scratchRight = Math.min(
            current.ink.getWidth(),
            (int) Math.ceil(slot.screenBounds.right)
        );
        int scratchBottom = Math.min(
            current.ink.getHeight(),
            (int) Math.ceil(slot.screenBounds.bottom)
        );
        if (scratchRight <= scratchLeft || scratchBottom <= scratchTop) {
            throw new IllegalStateException("active spread slot has no pixels");
        }
        current.ensureActiveLayerScratch(
            scratchRight - scratchLeft,
            scratchBottom - scratchTop
        );
        Canvas inkScratch = new Canvas(current.activeInkScratch);
        Canvas digestScratch = new Canvas(current.activeDigestScratch);
        inkScratch.drawColor(Color.TRANSPARENT, PorterDuff.Mode.CLEAR);
        digestScratch.drawColor(Color.TRANSPARENT, PorterDuff.Mode.CLEAR);
        inkScratch.translate(-scratchLeft, -scratchTop);
        digestScratch.translate(-scratchLeft, -scratchTop);

        // Build both replacement layers off-screen. The installed bitmaps are
        // not touched until every native read, geometry check, and draw has
        // succeeded, so a failed refresh leaves the last coherent spread up.
        drawDigest(components, slot, page, fullSource, contentClip, digestScratch);
        drawActiveInk(
            components,
            slot,
            page,
            fullSource,
            contentClip,
            inkScratch,
            activeNativeInk
        );

        Canvas inkCanvas = new Canvas(current.ink);
        Canvas digestCanvas = new Canvas(current.digest);
        clearSlot(inkCanvas, slot.screenBounds);
        clearSlot(digestCanvas, slot.screenBounds);
        inkCanvas.drawBitmap(
            current.activeInkScratch,
            scratchLeft,
            scratchTop,
            null
        );
        digestCanvas.drawBitmap(
            current.activeDigestScratch,
            scratchLeft,
            scratchTop,
            null
        );
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
        requireDisplayInkGeometry(activeNativeInk, page);
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

    private static void clearSlot(Canvas canvas, RectD bounds) {
        int save = canvas.save();
        try {
            canvas.clipRect(new RectF(
                (float) bounds.left,
                (float) bounds.top,
                (float) bounds.right,
                (float) bounds.bottom
            ));
            canvas.drawColor(Color.TRANSPARENT, PorterDuff.Mode.CLEAR);
        } finally {
            canvas.restoreToCount(save);
        }
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

    private static void requireDisplayInkGeometry(
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
        private Bitmap activeInkScratch;
        private Bitmap activeDigestScratch;
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

        private void ensureActiveLayerScratch(int width, int height) {
            if (recycled || width <= 0 || height <= 0) {
                throw new IllegalStateException("active layer scratch is invalid");
            }
            if (usable(activeInkScratch) && usable(activeDigestScratch)
                && activeInkScratch.getWidth() == width
                && activeInkScratch.getHeight() == height
                && activeDigestScratch.getWidth() == width
                && activeDigestScratch.getHeight() == height) {
                return;
            }
            Bitmap nextInk = null;
            Bitmap nextDigest = null;
            try {
                nextInk = Bitmap.createBitmap(
                    width,
                    height,
                    Bitmap.Config.ARGB_8888
                );
                nextDigest = Bitmap.createBitmap(
                    width,
                    height,
                    Bitmap.Config.ARGB_8888
                );
            } finally {
                if (nextInk != null && nextDigest == null
                    && !nextInk.isRecycled()) {
                    nextInk.recycle();
                }
            }
            recycleScratch();
            activeInkScratch = nextInk;
            activeDigestScratch = nextDigest;
        }

        private void recycleScratch() {
            if (activeInkScratch != null && !activeInkScratch.isRecycled()) {
                activeInkScratch.recycle();
            }
            if (activeDigestScratch != null
                && !activeDigestScratch.isRecycled()) {
                activeDigestScratch.recycle();
            }
            activeInkScratch = null;
            activeDigestScratch = null;
        }

        public synchronized void recycle() {
            if (recycled) return;
            recycled = true;
            recycleScratch();
            if (!background.isRecycled()) background.recycle();
            if (!ink.isRecycled()) ink.recycle();
            if (!digest.isRecycled()) digest.recycle();
        }
    }
}
