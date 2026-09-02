package com.techrebbe.supernote.spreadprobe.v2android;

import android.graphics.Bitmap;
import android.graphics.Rect;
import android.graphics.RectF;
import android.net.Uri;
import android.os.IBinder;
import android.os.Parcel;
import android.view.View;
import android.widget.ImageView;

import com.techrebbe.supernote.spreadprobe.v2.NativeAuthority;
import com.techrebbe.supernote.spreadprobe.v2.NativeMarkPageInventory;
import com.techrebbe.supernote.spreadprobe.v2.Affine2D;
import com.techrebbe.supernote.spreadprobe.v2.NativePageTransform;
import com.techrebbe.supernote.spreadprobe.v2.NativeDisplayTransform;
import com.techrebbe.supernote.spreadprobe.v2.NativeWriterGeometry;
import com.techrebbe.supernote.spreadprobe.v2.RectD;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Constructor;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Cached reflection bridge for the exact admitted SupernoteDocument build. */
public final class NativeReaderV2FirmwareAccess {
    private static final String ACTIVITY =
        "com.supernote.document.document.DocumentActivity";
    private static final String VIEW_MODEL =
        "com.supernote.document.document.DocumentViewModel";
    private static final String PAGE_INFO =
        "com.supernote.document.document.PageInfo";
    private static final String PRESENTER =
        "com.supernote.document.handwrite.HandWritePresenter";
    private static final String HAND_WRITE_CLIENT =
        "com.supernote.document.handwrite.HandWriteClient";
    private static final String DOCUMENT_CONSTANTS =
        "com.ratta.supernote.documentlib.constants.DocumentConstants";

    // Firmware access is process-scoped, while Activity component graphs are
    // not. Weak identity entries prevent a retired reader from being retained
    // merely because it once participated in an authority observation.
    private final ArrayList<ComponentIdentity> componentIds = new ArrayList<>();
    private long nextComponentId = 1L;
    private final Object projectionNoteLock = new Object();

    private final Field activityViewModel;
    private final Field activityPresenter;
    private final Field activityHandWriteView;
    private final Field activityImage;
    private final Field activityDigestImage;
    private final Field activityDocumentLayout;
    private final Field activityEventCallback;
    private final Field activityImageReady;
    private final Field activityHandWriteReady;
    private final Method activitySendDisableWriteArea;
    private final Method activityGetDisableRectList;
    private final Field viewModelCurrentPage;
    private final Field viewModelPageCount;
    private final Field viewModelPageInfoMap;
    private final Field viewModelAnnotationMap;
    private final Field viewModelUri;
    private final Field viewModelPortraitScaleRect;
    private final Field viewModelLandscapeScaleRect;
    private final Field viewModelPortraitTrimmingRect;
    private final Field viewModelLandscapeTrimmingRect;
    private final Field pageInfoCtm;
    private final Field pageInfoRevertCtm;
    private final Field pageInfoOffsetX;
    private final Field pageInfoOffsetY;
    private final Field presenterCurrentPage;
    private final Field presenterMarkPath;
    private final Field presenterScreenRotation;
    private final Field presenterBitmap;
    private final Field presenterExistNoteFile;
    private final Field presenterHasTrails;
    private final Field presenterNote;
    private final Field presenterClient;
    private final Field clientBinder;
    private final Method pageInfoOrigin;
    private final Method pageInfoDisplay;
    private final Method pageInfoDigest;
    private final Method pageInfoTrimmingRect;
    private final Method viewModelLoadPage;
    private final Method viewModelReloadPage;
    private final Method viewModelShowRect;
    private final Method viewModelTrimmingRect;
    private final Method viewModelSetAnnotationMap;
    private final Method viewModelUpdateDigestBitmap;
    private final Method presenterSave;
    private final Method presenterDisable;
    private final Method presenterLoadPage;
    private final Method presenterGetHandwriting;
    private final Method presenterSendWriteInfo;
    private final Method presenterSetDisabledAreas;
    private final Method presenterRefresh;
    private final Method handWriteViewSetBitmap;
    private final Method handWriteViewCancelSelection;
    private final Method noteScreenRotation;
    private final Method noteFetchPagesOfMark;
    private final Method noteLoadMarkPageBitmap;
    private final Method noteCreate;
    private final Method noteMarkInitProcess;
    private final Method noteChangeDirtyFlag;
    private final Method noteFreeCommon;
    private final Method documentGetDeviceType;
    private final Constructor<?> matrixConstructor;
    private final Method matrixInvert;
    private final Field matrixA;
    private final Field matrixB;
    private final Field matrixC;
    private final Field matrixD;
    private final Field matrixE;
    private final Field matrixF;

    public NativeReaderV2FirmwareAccess(ClassLoader loader) {
        try {
            Class<?> activity = Class.forName(ACTIVITY, false, loader);
            Class<?> viewModel = Class.forName(VIEW_MODEL, false, loader);
            Class<?> pageInfo = Class.forName(PAGE_INFO, false, loader);
            Class<?> presenter = Class.forName(PRESENTER, false, loader);
            Class<?> client = Class.forName(HAND_WRITE_CLIENT, false, loader);
            Class<?> documentConstants = Class.forName(
                DOCUMENT_CONSTANTS,
                false,
                loader
            );
            Class<?> matrix = Class.forName(
                "com.artifex.mupdf.fitz.Matrix",
                false,
                loader
            );
            Class<?> noteClass = Class.forName(
                "com.example.libsupernote.SuperNoteNote",
                false,
                loader
            );

            activityViewModel = field(activity, "documentViewModel");
            activityPresenter = field(activity, "handWritePresenter");
            activityHandWriteView = field(activity, "handWriteView");
            activityImage = field(activity, "mImage");
            activityDigestImage = field(activity, "digestImage");
            activityDocumentLayout = field(activity, "documentViewLayout");
            activityEventCallback = field(activity, "eventCallBack");
            activityImageReady = field(activity, "documentImageReady");
            activityHandWriteReady = field(activity, "handWriteInitReady");
            activitySendDisableWriteArea = method(
                activity,
                "sendDisableWriteArea"
            );
            activityGetDisableRectList = method(
                activity,
                "getDisableRectList"
            );
            viewModelCurrentPage = field(viewModel, "currentPage");
            viewModelPageCount = field(viewModel, "pageCount");
            viewModelPageInfoMap = field(viewModel, "pageInfoHashMap");
            viewModelAnnotationMap = field(viewModel, "documentAnnotationMap");
            viewModelUri = field(viewModel, "uri");
            viewModelPortraitScaleRect = field(viewModel, "portraitScaleRect");
            viewModelLandscapeScaleRect = field(
                viewModel,
                "landscapeScaleRect"
            );
            viewModelPortraitTrimmingRect = field(viewModel, "trimmingRect");
            viewModelLandscapeTrimmingRect = field(
                viewModel,
                "landscapeTrimmingRect"
            );
            pageInfoCtm = field(pageInfo, "ctm");
            pageInfoRevertCtm = field(pageInfo, "revertCtm");
            pageInfoOffsetX = field(pageInfo, "offsetX");
            pageInfoOffsetY = field(pageInfo, "offsetY");
            presenterCurrentPage = field(presenter, "currentPage");
            presenterMarkPath = field(presenter, "markPath");
            presenterScreenRotation = field(presenter, "screenRotation");
            presenterBitmap = field(presenter, "bitmap");
            presenterExistNoteFile = field(presenter, "existNoteFile");
            presenterHasTrails = field(presenter, "hasTrails");
            presenterNote = field(presenter, "superNoteNote");
            presenterClient = field(presenter, "handWriteClient");
            clientBinder = field(client, "iBinder");

            pageInfoOrigin = method(pageInfo, "getOriginBitmap");
            pageInfoDisplay = method(pageInfo, "getDisplayBitmap");
            pageInfoDigest = method(pageInfo, "getDigestBitmap");
            pageInfoTrimmingRect = method(pageInfo, "getTrimmingRect");
            viewModelLoadPage = method(viewModel, "loadPage", Integer.TYPE);
            viewModelReloadPage = method(viewModel, "reloadPage");
            viewModelShowRect = method(viewModel, "getShowRect");
            viewModelTrimmingRect = method(
                viewModel,
                "getDisplayTrimmingRect"
            );
            viewModelSetAnnotationMap = method(
                viewModel,
                "setDocumentAnnotationMap",
                HashMap.class
            );
            viewModelUpdateDigestBitmap = method(
                viewModel,
                "updateDigestBitmap",
                pageInfo
            );
            presenterSave = method(presenter, "saveTrails", Boolean.TYPE);
            presenterDisable = method(
                presenter,
                "disableHandWrite",
                String.class
            );
            presenterLoadPage = method(
                presenter,
                "loadPage",
                Integer.TYPE,
                RectF.class
            );
            presenterGetHandwriting = method(
                presenter,
                "getHandWriteOriginBitmap",
                Integer.TYPE
            );
            presenterSendWriteInfo = method(presenter, "sendWriteInfo");
            presenterSetDisabledAreas = method(
                presenter,
                "setDisableAreaList",
                String.class,
                List.class
            );
            presenterRefresh = method(presenter, "refreshBitmap");

            Class<?> handWriteView = activityHandWriteView.getType();
            handWriteViewSetBitmap = method(
                handWriteView,
                "setBitmap",
                Bitmap.class
            );
            handWriteViewCancelSelection = method(
                handWriteView,
                "cancelAreaSelect"
            );
            noteScreenRotation = method(
                noteClass,
                "screenRotation",
                Integer.TYPE,
                Integer.TYPE,
                Integer.TYPE
            );
            noteFetchPagesOfMark = method(
                noteClass,
                "fetchPagesOfMark",
                String.class
            );
            noteLoadMarkPageBitmap = method(
                noteClass,
                "loadMarkPageBitmap",
                String.class,
                Integer.TYPE,
                Bitmap.class
            );
            noteCreate = method(noteClass, "createSuperNoteNote");
            noteMarkInitProcess = method(
                noteClass,
                "markInitProcess",
                Integer.TYPE
            );
            noteChangeDirtyFlag = method(
                noteClass,
                "changeDirtyFlag",
                Boolean.TYPE
            );
            noteFreeCommon = method(noteClass, "freeCommon");
            documentGetDeviceType = method(
                documentConstants,
                "getDeviceType"
            );
            matrixConstructor = matrix.getDeclaredConstructor(
                Float.TYPE,
                Float.TYPE,
                Float.TYPE,
                Float.TYPE,
                Float.TYPE,
                Float.TYPE
            );
            matrixConstructor.setAccessible(true);
            matrixInvert = method(matrix, "invert");
            matrixA = field(matrix, "a");
            matrixB = field(matrix, "b");
            matrixC = field(matrix, "c");
            matrixD = field(matrix, "d");
            matrixE = field(matrix, "e");
            matrixF = field(matrix, "f");
        } catch (ReflectiveOperationException exception) {
            throw new IllegalStateException(
                "admitted firmware reflection cache could not be created",
                exception
            );
        }
    }

    public Components inspect(Object activity) {
        try {
            Object viewModel = activityViewModel.get(activity);
            Object presenter = activityPresenter.get(activity);
            Object handWriteView = activityHandWriteView.get(activity);
            Object eventCallback = activityEventCallback.get(activity);
            ImageView image = (ImageView) activityImage.get(activity);
            ImageView digestImage = (ImageView) activityDigestImage.get(activity);
            View layout = (View) activityDocumentLayout.get(activity);
            if (viewModel == null || presenter == null || handWriteView == null
                || eventCallback == null
                || image == null || digestImage == null || layout == null) {
                throw new IllegalStateException("native reader components missing");
            }
            Object note = presenterNote.get(presenter);
            Object client = presenterClient.get(presenter);
            IBinder binder = client == null
                ? null : (IBinder) clientBinder.get(client);
            Uri uri = (Uri) viewModelUri.get(viewModel);
            return new Components(
                activity,
                viewModel,
                presenter,
                handWriteView,
                eventCallback,
                image,
                digestImage,
                layout,
                note,
                client,
                binder,
                uri == null ? null : uri.getPath(),
                viewModelCurrentPage.getInt(viewModel),
                viewModelPageCount.getInt(viewModel),
                presenterCurrentPage.getInt(presenter),
                presenterScreenRotation.getInt(presenter),
                activityImageReady.getBoolean(activity),
                activityHandWriteReady.getBoolean(activity),
                (String) presenterMarkPath.get(presenter)
            );
        } catch (ReflectiveOperationException exception) {
            throw new IllegalStateException(
                "native reader component inspection failed",
                exception
            );
        }
    }

    @SuppressWarnings("unchecked")
    public Object pageInfo(Components components, int zeroBasedPage) {
        try {
            Map<Integer, Object> pages = (Map<Integer, Object>)
                viewModelPageInfoMap.get(components.viewModel);
            return pages == null ? null : pages.get(zeroBasedPage);
        } catch (IllegalAccessException exception) {
            throw new IllegalStateException("page cache inspection failed", exception);
        }
    }

    public Bitmap originBitmap(Components components, int zeroBasedPage) {
        return bitmap(pageInfoOrigin, pageInfo(components, zeroBasedPage));
    }

    public Bitmap displayBitmap(Components components, int zeroBasedPage) {
        return bitmap(pageInfoDisplay, pageInfo(components, zeroBasedPage));
    }

    public Bitmap digestBitmap(Components components, int zeroBasedPage) {
        return bitmap(pageInfoDigest, pageInfo(components, zeroBasedPage));
    }

    public RectF showRect(Components components) {
        return copyRect(invoke(viewModelShowRect, components.viewModel));
    }

    public RectF trimmingRect(Components components) {
        return copyRect(invoke(viewModelTrimmingRect, components.viewModel));
    }

    /**
     * Returns the exact per-orientation crop the stock reader applies to the
     * requested cached source page. A zero rectangle is the firmware's
     * explicit no-crop sentinel and is normalized to the full bitmap.
     */
    public RectD displaySourceBox(Components components, int zeroBasedPage) {
        Object info = pageInfo(components, zeroBasedPage);
        Bitmap origin = bitmap(pageInfoOrigin, info);
        if (origin == null) {
            throw new IllegalStateException("source page bitmap is unavailable");
        }
        RectD full = new RectD(0, 0, origin.getWidth(), origin.getHeight());
        try {
            boolean landscape = origin.getWidth() > origin.getHeight();
            RectF scale = copyRect((landscape
                ? viewModelLandscapeScaleRect
                : viewModelPortraitScaleRect).get(components.viewModel));
            if (scale != null) {
                if (!positive(scale)) {
                    throw new IllegalStateException(
                        "native scale rectangle is invalid"
                    );
                }
                return validatedSourceBox(scale, full);
            }
            RectF configured = copyRect((landscape
                ? viewModelLandscapeTrimmingRect
                : viewModelPortraitTrimmingRect).get(components.viewModel));
            RectF pageTrim = copyRect(invoke(pageInfoTrimmingRect, info));
            if (configured == null) return full;
            RectF portraitConfigured = copyRect(
                viewModelPortraitTrimmingRect.get(components.viewModel)
            );
            RectF landscapeConfigured = copyRect(
                viewModelLandscapeTrimmingRect.get(components.viewModel)
            );
            // Match DocumentViewModel.getDisplayTrimmingRect() exactly: its
            // automatic-trim sentinel is global across the two page-shape
            // stores, not merely the rectangle selected for this page.
            if (zero(portraitConfigured) || zero(landscapeConfigured)) {
                if (pageTrim == null || zero(pageTrim)) return full;
                if (!positive(pageTrim)) {
                    throw new IllegalStateException(
                        "native page trimming rectangle is invalid"
                    );
                }
                return validatedSourceBox(pageTrim, full);
            }
            if (!positive(configured)) {
                throw new IllegalStateException(
                    "native trimming rectangle is invalid"
                );
            }
            return validatedSourceBox(configured, full);
        } catch (IllegalAccessException failure) {
            throw new IllegalStateException(
                "native display crop could not be inspected",
                failure
            );
        }
    }

    public void saveSource(Components components) {
        // The transfer boundary must flush and drain DrawPath's live trail;
        // retaining it would let the old page's samples survive into the
        // next writer page.
        invoke(presenterSave, components.presenter, Boolean.TRUE);
    }

    public boolean sourceHasTrails(Components components) {
        try {
            if (!presenterExistNoteFile.getBoolean(components.presenter)) {
                throw new IllegalStateException(
                    "native mark document is not ready for saving"
                );
            }
            return presenterHasTrails.getBoolean(components.presenter);
        } catch (IllegalAccessException exception) {
            throw new IllegalStateException(
                "native trail state inspection failed",
                exception
            );
        }
    }

    public void disableWriter(Components components, String reason) {
        invoke(presenterDisable, components.presenter, reason);
    }

    public void loadDocumentPage(Components components, int zeroBasedPage) {
        invoke(viewModelLoadPage, components.viewModel, zeroBasedPage);
    }

    public void reloadDocumentPage(Components components) {
        invoke(viewModelReloadPage, components.viewModel);
    }

    public void loadHandwritingPage(
        Components components,
        int zeroBasedPage,
        RectF trimming
    ) {
        invoke(
            presenterLoadPage,
            components.presenter,
            zeroBasedPage + 1,
            trimming == null ? null : new RectF(trimming)
        );
    }

    public Bitmap committedHandwriting(
        Components components,
        int zeroBasedPage
    ) {
        return bitmap(
            presenterGetHandwriting,
            components.presenter,
            zeroBasedPage + 1
        );
    }

    public Bitmap liveHandwritingBitmap(Components components) {
        try {
            Object value = presenterBitmap.get(components.presenter);
            if (!(value instanceof Bitmap)) return null;
            Bitmap bitmap = (Bitmap) value;
            return bitmap.isRecycled() ? null : bitmap;
        } catch (IllegalAccessException exception) {
            throw new IllegalStateException(
                "live handwriting bitmap inspection failed",
                exception
            );
        }
    }

    /**
     * Loads one committed inactive mark page in the source PDF bitmap's
     * canonical portrait geometry.
     *
     * This must never borrow the live presenter's SuperNoteNote. Both
     * screenRotation() and loadMarkPageBitmap() mutate native instance state;
     * doing either on the writer object can invalidate dirty trails, undo, or
     * the current lasso. The exact firmware itself uses separately initialized
     * SuperNoteNote instances for export and conflict bitmap rendering, so v2
     * follows that established isolation boundary for its read-only projector.
     */
    public CanonicalInk committedCanonicalHandwriting(
        Components components,
        int zeroBasedPage,
        Bitmap pageOrigin
    ) {
        if (components.markPath == null || pageOrigin == null
            || pageOrigin.isRecycled()) {
            throw new IllegalStateException(
                "canonical handwriting authority is incomplete"
            );
        }
        if (zeroBasedPage < 0 || zeroBasedPage >= components.pageCount) {
            throw new IllegalArgumentException("mark page is out of range");
        }
        int nativePage = zeroBasedPage + 1;
        synchronized (projectionNoteLock) {
            Object reader = createProjectionNoteLocked();
            RuntimeException projectionFailure = null;
            try {
                Object fetched = invoke(
                    noteFetchPagesOfMark,
                    reader,
                    components.markPath
                );
                if (!(fetched instanceof List<?>)) {
                    throw new IllegalStateException(
                        "native mark page inventory is unavailable"
                    );
                }
                boolean present;
                try {
                    present = NativeMarkPageInventory.contains(
                        (List<?>) fetched,
                        components.pageCount,
                        zeroBasedPage
                    );
                } catch (IllegalArgumentException invalidInventory) {
                    throw new IllegalStateException(
                        "native mark page inventory is invalid",
                        invalidInventory
                    );
                }
                if (!present) return CanonicalInk.empty();

                Bitmap result = Bitmap.createBitmap(
                    pageOrigin.getWidth(),
                    pageOrigin.getHeight(),
                    Bitmap.Config.ARGB_8888
                );
                boolean loaded = false;
                try {
                    if (!Boolean.TRUE.equals(invoke(
                        noteScreenRotation,
                        reader,
                        1000,
                        0,
                        0
                    ))) {
                        throw new IllegalStateException(
                            "canonical mark rotation was rejected"
                        );
                    }
                    if (!Boolean.TRUE.equals(invoke(
                        noteLoadMarkPageBitmap,
                        reader,
                        components.markPath,
                        nativePage,
                        result
                    ))) {
                        throw new IllegalStateException(
                            "known mark page could not be rendered"
                        );
                    }
                    loaded = true;
                    return CanonicalInk.loaded(result);
                } finally {
                    if (!loaded && !result.isRecycled()) result.recycle();
                }
            } catch (RuntimeException failure) {
                projectionFailure = failure;
                throw failure;
            } finally {
                // The exact firmware's conflict/export paths create and free
                // a separate SuperNoteNote for every committed snapshot.
                // Match that boundary: a long-lived native reader may retain
                // page inventory or rendered mark state after the live writer
                // saves, making an adjacent projection silently stale.
                try {
                    invoke(noteFreeCommon, reader);
                } catch (RuntimeException cleanupFailure) {
                    if (projectionFailure != null) {
                        projectionFailure.addSuppressed(cleanupFailure);
                    } else {
                        throw cleanupFailure;
                    }
                }
            }
        }
    }

    /**
     * Kept as a lifecycle no-op: projection readers are snapshot-scoped and
     * are always freed by committedCanonicalHandwriting().
     */
    public void releaseProjectionReader() {
        synchronized (projectionNoteLock) {
            // Synchronize with an in-flight projection before teardown.
        }
    }

    private Object createProjectionNoteLocked() {
        Object candidate = invoke(noteCreate, null);
        if (candidate == null) {
            throw new IllegalStateException(
                "read-only native projection note could not be created"
            );
        }
        try {
            Object deviceType = invoke(documentGetDeviceType, null);
            if (!(deviceType instanceof Integer)) {
                throw new IllegalStateException(
                    "native device type is unavailable for projection"
                );
            }
            if (!Boolean.TRUE.equals(invoke(
                noteMarkInitProcess,
                candidate,
                ((Integer) deviceType).intValue() + 2
            ))) {
                throw new IllegalStateException(
                    "read-only native projection note initialization failed"
                );
            }
            // Match the firmware's ConflictPageBitmaps setup. This flag is
            // instance-local and the projector never receives writer input.
            invoke(noteChangeDirtyFlag, candidate, true);
            return candidate;
        } catch (RuntimeException failure) {
            try {
                invoke(noteFreeCommon, candidate);
            } catch (RuntimeException cleanupFailure) {
                failure.addSuppressed(cleanupFailure);
            }
            throw failure;
        }
    }

    public void setBackground(Components components, Bitmap bitmap) {
        components.image.setScaleType(ImageView.ScaleType.FIT_XY);
        components.image.setImageBitmap(bitmap);
    }

    public void setLiveInkBitmap(Components components, Bitmap bitmap) {
        invoke(handWriteViewSetBitmap, components.handWriteView, bitmap);
    }

    public void setDigestBitmap(Components components, Bitmap bitmap) {
        components.digestImage.setScaleType(ImageView.ScaleType.FIT_XY);
        components.digestImage.setImageBitmap(bitmap);
    }

    public PresentationScaleLease capturePresentationScale(
        Components components
    ) {
        if (components == null || components.image == null
            || components.digestImage == null) {
            throw new IllegalArgumentException(
                "native presentation views are required"
            );
        }
        return new PresentationScaleLease(
            components.image,
            components.image.getScaleType(),
            components.digestImage,
            components.digestImage.getScaleType()
        );
    }

    public void restorePresentationScale(PresentationScaleLease lease) {
        if (lease == null || lease.restored) return;
        lease.image.setScaleType(lease.imageScaleType);
        lease.digestImage.setScaleType(lease.digestScaleType);
        lease.restored = true;
    }

    /**
     * Makes native PDF hit testing use the exact same active-half transform
     * as the compositor and DrawPath writer. The returned lease must be
     * restored before page ownership or orientation changes.
     */
    public PageGeometryLease programPageGeometry(
        Components components,
        com.techrebbe.supernote.spreadprobe.v2.PageSlot slot
    ) {
        if (components == null || slot == null || slot.isBlank()
            || slot.sourcePageIndex != components.readerPage) {
            throw new IllegalArgumentException(
                "active page geometry requires the writer-owned slot"
            );
        }
        Object info = pageInfo(components, components.readerPage);
        if (info == null) {
            throw new IllegalStateException("active PageInfo is unavailable");
        }
        Bitmap activeOrigin = bitmap(pageInfoOrigin, info);
        if (activeOrigin == null) {
            throw new IllegalStateException(
                "active source bitmap is unavailable for PageInfo geometry"
            );
        }
        try {
            Object originalCtm = pageInfoCtm.get(info);
            Object originalRevert = pageInfoRevertCtm.get(info);
            int originalOffsetX = pageInfoOffsetX.getInt(info);
            int originalOffsetY = pageInfoOffsetY.getInt(info);
            if (originalCtm == null || originalRevert == null) {
                throw new IllegalStateException("native page matrices are missing");
            }
            NativePageTransform transformed = NativePageTransform.from(
                new Affine2D(
                    matrixA.getFloat(originalCtm),
                    matrixB.getFloat(originalCtm),
                    matrixC.getFloat(originalCtm),
                    matrixD.getFloat(originalCtm),
                    matrixE.getFloat(originalCtm),
                    matrixF.getFloat(originalCtm)
                ),
                originalOffsetX,
                originalOffsetY,
                slot,
                NativeDisplayTransform.displayToOrigin(
                    slot.sourceBox,
                    new RectD(
                        0,
                        0,
                        activeOrigin.getWidth(),
                        activeOrigin.getHeight()
                    )
                )
            );
            Object installedCtm = newMatrix(
                (float) transformed.ctm.a,
                (float) transformed.ctm.b,
                (float) transformed.ctm.c,
                (float) transformed.ctm.d,
                (float) transformed.ctm.e,
                (float) transformed.ctm.f
            );
            Object installedRevert = newMatrix(
                (float) transformed.revertCtm.a,
                (float) transformed.revertCtm.b,
                (float) transformed.revertCtm.c,
                (float) transformed.revertCtm.d,
                (float) transformed.revertCtm.e,
                (float) transformed.revertCtm.f
            );
            int installedOffsetX = transformed.offsetX;
            int installedOffsetY = transformed.offsetY;
            PageGeometryLease lease = new PageGeometryLease(
                components.readerPage,
                info,
                originalCtm,
                originalRevert,
                originalOffsetX,
                originalOffsetY,
                installedCtm,
                installedRevert,
                matrixValues(installedCtm),
                matrixValues(installedRevert),
                installedOffsetX,
                installedOffsetY
            );
            try {
                pageInfoCtm.set(info, installedCtm);
                pageInfoRevertCtm.set(info, installedRevert);
                pageInfoOffsetX.setInt(info, installedOffsetX);
                pageInfoOffsetY.setInt(info, installedOffsetY);
                recalculateAnnotationRects(components);
                return lease;
            } catch (Throwable failure) {
                try {
                    pageInfoCtm.set(info, originalCtm);
                    pageInfoRevertCtm.set(info, originalRevert);
                    pageInfoOffsetX.setInt(info, originalOffsetX);
                    pageInfoOffsetY.setInt(info, originalOffsetY);
                    recalculateAnnotationRects(components);
                } catch (Throwable rollbackFailure) {
                    failure.addSuppressed(rollbackFailure);
                }
                if (failure instanceof RuntimeException) {
                    throw (RuntimeException) failure;
                }
                throw new IllegalStateException(
                    "native PageInfo geometry publication failed",
                    failure
                );
            }
        } catch (IllegalAccessException failure) {
            throw new IllegalStateException(
                "native PageInfo geometry could not be programmed",
                failure
            );
        }
    }

    @SuppressWarnings("unchecked")
    private void recalculateAnnotationRects(Components components) {
        try {
            Object value = viewModelAnnotationMap.get(components.viewModel);
            if (!(value instanceof HashMap<?, ?>)) {
                throw new IllegalStateException(
                    "native annotation authority map is unavailable"
                );
            }
            HashMap<Integer, Object> annotations = new HashMap<>(
                (HashMap<Integer, Object>) value
            );
            invoke(
                viewModelSetAnnotationMap,
                components.viewModel,
                annotations
            );
        } catch (IllegalAccessException failure) {
            throw new IllegalStateException(
                "native annotation rectangles could not be recalculated",
                failure
            );
        }
    }

    @SuppressWarnings("unchecked")
    public void restorePageGeometry(
        Components components,
        PageGeometryLease lease
    ) {
        if (lease == null || lease.restored) return;
        if (components == null || components.viewModel == null) {
            throw new IllegalArgumentException(
                "components are required to restore PageInfo geometry"
            );
        }
        try {
            if (components.readerPage != lease.pageIndex
                || pageInfo(components, lease.pageIndex) != lease.pageInfo) {
                throw new IllegalStateException(
                    "native PageInfo identity changed while v2 held its lease"
                );
            }
            if (!lease.matricesRestored) {
                if (pageInfoCtm.get(lease.pageInfo) != lease.installedCtm
                    || pageInfoRevertCtm.get(lease.pageInfo)
                        != lease.installedRevert
                    || !sameMatrixValues(
                        lease.installedCtm,
                        lease.installedCtmValues
                    )
                    || !sameMatrixValues(
                        lease.installedRevert,
                        lease.installedRevertValues
                    )
                    || pageInfoOffsetX.getInt(lease.pageInfo)
                        != lease.installedOffsetX
                    || pageInfoOffsetY.getInt(lease.pageInfo)
                        != lease.installedOffsetY) {
                    throw new IllegalStateException(
                        "native PageInfo changed while v2 owned its geometry"
                    );
                }
                pageInfoCtm.set(lease.pageInfo, lease.originalCtm);
                pageInfoRevertCtm.set(lease.pageInfo, lease.originalRevert);
                pageInfoOffsetX.setInt(lease.pageInfo, lease.originalOffsetX);
                pageInfoOffsetY.setInt(lease.pageInfo, lease.originalOffsetY);
                lease.matricesRestored = true;
            }
            recalculateAnnotationRects(components);
            invoke(
                viewModelUpdateDigestBitmap,
                components.viewModel,
                lease.pageInfo
            );
            // A failed rectangle/digest rebuild remains retryable after the
            // matrices have been restored. Only the complete native contract
            // closes the lease.
            lease.restored = true;
        } catch (IllegalAccessException failure) {
            throw new IllegalStateException(
                "native PageInfo geometry could not be restored",
                failure
            );
        }
    }

    /**
     * Commits or dismisses the native floating lasso before a page transfer.
     *
     * This intentionally matches DocumentActivity's stock onRegionClick(2)
     * ordering. AreaSelectionView.close() commits a pending move/scale through
     * onTransition(); refreshBitmap() then settles the live page before the
     * caller witnesses saveTrails(true). clearAreaSelectionView() is a view
     * teardown operation and must not run at an ordinary page boundary.
     */
    public void prepareSourceForTransfer(Components components) {
        invoke(handWriteViewCancelSelection, components.handWriteView);
        invoke(presenterRefresh, components.presenter);
    }

    public void enableWriterForAreas(
        Components components,
        List<Rect> disabledAreas
    ) {
        invoke(
            presenterSetDisabledAreas,
            components.presenter,
            "SN_NATIVE_READER_V2 active page",
            disabledAreas
        );
        invoke(presenterSendWriteInfo, components.presenter);
    }

    /**
     * Programs DrawPath, mark rendering, and the native writable region from
     * one already-validated geometry. Partial acknowledgement is a failure;
     * the caller must keep the writer disabled.
     */
    public void programWriterGeometry(
        Components components,
        NativeWriterGeometry geometry,
        List<com.techrebbe.supernote.spreadprobe.v2.RectD> overlayMasks
    ) {
        if (components == null || geometry == null
            || !components.writerReady()
            || components.presenterRotation != geometry.rotation
            || components.documentLayout.getWidth() != geometry.viewWidth
            || components.documentLayout.getHeight() != geometry.viewHeight
            || components.binder == null
            || !components.binder.isBinderAlive()) {
            throw new IllegalStateException(
                "native writer geometry authority is incomplete"
            );
        }
        // Native sendWriteInfo() must run first: it primes DrawPath and can
        // overwrite geometry. The exact v2 Binder transaction is the final
        // geometry authority, never the other way around.
        enableWriterForAreas(components, writerDisabledAreas(
            components,
            geometry,
            overlayMasks
        ));

        Parcel request = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            request.writeInterfaceToken("android.demo.IMyService");
            request.writeString("superNoteDocument");
            request.writeInt(geometry.rotation);
            request.writeInt(geometry.viewWidth);
            request.writeInt(geometry.viewHeight);
            request.writeInt(geometry.virtualWidth);
            request.writeInt(geometry.virtualHeight);
            request.writeInt(geometry.originX);
            request.writeInt(geometry.originY);
            request.writeFloat(1.0f);
            boolean accepted = components.binder.transact(
                10,
                request,
                reply,
                0
            );
            String response = reply.readString();
            if (!accepted || !"realTimeHandWriting".equals(response)) {
                throw new IllegalStateException(
                    "DrawPath rejected the exact writer geometry"
                );
            }
        } catch (android.os.RemoteException exception) {
            throw new IllegalStateException(
                "DrawPath writer geometry transaction failed",
                exception
            );
        } finally {
            request.recycle();
            reply.recycle();
        }

        synchronized (components.note) {
            if (!Boolean.TRUE.equals(invoke(
                noteScreenRotation,
                components.note,
                geometry.rotation + 2000,
                geometry.originX,
                geometry.originY
            ))) {
                throw new IllegalStateException(
                    "native mark geometry was rejected"
                );
            }
        }
    }

    /** Restores the stock writer contract before v2 relinquishes ownership. */
    public void restoreNativeWriterGeometry(Components components) {
        if (components == null || components.note == null) {
            throw new IllegalArgumentException(
                "native writer components are required for restoration"
            );
        }
        synchronized (components.note) {
            if (!Boolean.TRUE.equals(invoke(
                noteScreenRotation,
                components.note,
                components.presenterRotation + 1000,
                0,
                0
            ))) {
                throw new IllegalStateException(
                    "stock native mark geometry could not be restored"
                );
            }
        }
        invoke(presenterSendWriteInfo, components.presenter);
        invoke(activitySendDisableWriteArea, components.activity);
    }

    /** Reasserts the inactive half without discarding native chrome masks. */
    public void refreshWriterDisabledAreas(
        Components components,
        NativeWriterGeometry geometry,
        List<com.techrebbe.supernote.spreadprobe.v2.RectD> overlayMasks
    ) {
        if (components == null || geometry == null) {
            throw new IllegalArgumentException(
                "writer mask authority is required"
            );
        }
        invoke(
            presenterSetDisabledAreas,
            components.presenter,
            "SN_NATIVE_READER_V2 native chrome refresh",
            writerDisabledAreas(components, geometry, overlayMasks)
        );
    }

    /** Exact firmware-owned visible/write-blocked native chrome snapshot. */
    public List<com.techrebbe.supernote.spreadprobe.v2.RectD>
        nativeChromeDisabledAreas(Components components) {
        ArrayList<com.techrebbe.supernote.spreadprobe.v2.RectD> result =
            new ArrayList<>();
        for (Rect rect : nativeDisabledRects(components)) {
            result.add(new com.techrebbe.supernote.spreadprobe.v2.RectD(
                rect.left,
                rect.top,
                rect.right,
                rect.bottom
            ));
        }
        return java.util.Collections.unmodifiableList(result);
    }

    @SuppressWarnings("unchecked")
    private List<Rect> writerDisabledAreas(
        Components components,
        NativeWriterGeometry geometry,
        List<com.techrebbe.supernote.spreadprobe.v2.RectD> overlayMasks
    ) {
        ArrayList<Rect> combined = nativeDisabledRects(components);
        if (overlayMasks != null) {
            for (com.techrebbe.supernote.spreadprobe.v2.RectD mask
                : overlayMasks) {
                if (mask == null || mask.left < 0.0 || mask.top < 0.0
                    || mask.right > geometry.viewWidth
                    || mask.bottom > geometry.viewHeight) {
                    throw new IllegalArgumentException(
                        "overlay writer mask lies outside the current canvas"
                    );
                }
                combined.add(new Rect(
                    (int) Math.floor(mask.left),
                    (int) Math.floor(mask.top),
                    (int) Math.ceil(mask.right),
                    (int) Math.ceil(mask.bottom)
                ));
            }
        }
        combined.addAll(disabledOutside(geometry));
        return combined;
    }

    private ArrayList<Rect> nativeDisabledRects(Components components) {
        if (components == null || components.activity == null) {
            throw new IllegalArgumentException(
                "native chrome authority requires the current activity"
            );
        }
        Object value = invoke(activityGetDisableRectList, components.activity);
        if (!(value instanceof List<?>)) {
            throw new IllegalStateException(
                "native chrome writer mask is unavailable"
            );
        }
        ArrayList<Rect> combined = new ArrayList<>();
        for (Object item : (List<?>) value) {
            if (!(item instanceof Rect)) {
                throw new IllegalStateException(
                    "native chrome writer mask contains an invalid rectangle"
                );
            }
            Rect rect = new Rect((Rect) item);
            if (rect.left > rect.right || rect.top > rect.bottom) {
                throw new IllegalStateException(
                    "native chrome writer mask rectangle is inverted"
                );
            }
            combined.add(rect);
        }
        return combined;
    }

    private static List<Rect> disabledOutside(
        NativeWriterGeometry geometry
    ) {
        int left = (int) geometry.writableBounds.left;
        int top = (int) geometry.writableBounds.top;
        int right = (int) geometry.writableBounds.right;
        int bottom = (int) geometry.writableBounds.bottom;
        ArrayList<Rect> disabled = new ArrayList<>();
        if (left > 0) {
            disabled.add(new Rect(0, 0, left, geometry.viewHeight));
        }
        if (top > 0 && right > left) {
            disabled.add(new Rect(left, 0, right, top));
        }
        if (bottom < geometry.viewHeight && right > left) {
            disabled.add(new Rect(
                left,
                bottom,
                right,
                geometry.viewHeight
            ));
        }
        if (right < geometry.viewWidth) {
            disabled.add(new Rect(
                right,
                0,
                geometry.viewWidth,
                geometry.viewHeight
            ));
        }
        if (disabled.isEmpty()) {
            disabled.add(new Rect(0, 0, 0, 0));
        }
        return disabled;
    }

    public NativeAuthority authority(
        Components components,
        String documentId,
        long activityGeneration,
        long layoutGeneration
    ) {
        if (!components.writerReady()) {
            return null;
        }
        return new NativeAuthority(
            documentId,
            activityGeneration,
            layoutGeneration,
            components.readerPage,
            componentId(components.viewModel),
            componentId(components.presenter),
            componentId(components.note),
            componentId(components.binder),
            components.readerPage
        );
    }

    public synchronized long componentId(Object component) {
        if (component == null) {
            throw new IllegalArgumentException("native component is missing");
        }
        for (int index = componentIds.size() - 1; index >= 0; index--) {
            ComponentIdentity entry = componentIds.get(index);
            Object existing = entry.component.get();
            if (existing == null) {
                componentIds.remove(index);
            } else if (existing == component) {
                return entry.id;
            }
        }
        if (nextComponentId <= 0L) {
            throw new IllegalStateException("component identity exhausted");
        }
        long assigned = nextComponentId++;
        componentIds.add(new ComponentIdentity(component, assigned));
        return assigned;
    }

    public synchronized void releaseComponentIds(Components components) {
        if (components == null) return;
        for (int index = componentIds.size() - 1; index >= 0; index--) {
            Object component = componentIds.get(index).component.get();
            if (component == null || component == components.viewModel
                || component == components.presenter
                || component == components.note
                || component == components.binder) {
                componentIds.remove(index);
            }
        }
    }

    private static final class ComponentIdentity {
        final WeakReference<Object> component;
        final long id;

        ComponentIdentity(Object component, long id) {
            this.component = new WeakReference<>(component);
            this.id = id;
        }
    }

    private static Field field(Class<?> owner, String name)
        throws ReflectiveOperationException {
        Field field = owner.getDeclaredField(name);
        field.setAccessible(true);
        return field;
    }

    private static Method method(
        Class<?> owner,
        String name,
        Class<?>... parameters
    ) throws ReflectiveOperationException {
        Method method = owner.getDeclaredMethod(name, parameters);
        method.setAccessible(true);
        return method;
    }

    private static Object invoke(Method method, Object owner, Object... args) {
        try {
            return method.invoke(owner, args);
        } catch (ReflectiveOperationException exception) {
            throw new IllegalStateException(
                "native firmware call failed: " + method.getName(),
                exception
            );
        }
    }

    private Object newMatrix(float... values) {
        try {
            return matrixConstructor.newInstance(
                values[0], values[1], values[2],
                values[3], values[4], values[5]
            );
        } catch (ReflectiveOperationException failure) {
            throw new IllegalStateException(
                "native PDF matrix could not be constructed",
                failure
            );
        }
    }

    private float[] matrixValues(Object matrix) {
        if (matrix == null) {
            throw new IllegalArgumentException("native matrix is missing");
        }
        try {
            return new float[] {
                matrixA.getFloat(matrix),
                matrixB.getFloat(matrix),
                matrixC.getFloat(matrix),
                matrixD.getFloat(matrix),
                matrixE.getFloat(matrix),
                matrixF.getFloat(matrix),
            };
        } catch (IllegalAccessException failure) {
            throw new IllegalStateException(
                "native matrix values could not be witnessed",
                failure
            );
        }
    }

    private boolean sameMatrixValues(Object matrix, float[] expected) {
        float[] actual = matrixValues(matrix);
        if (expected == null || expected.length != actual.length) return false;
        for (int index = 0; index < actual.length; index++) {
            if (Float.floatToIntBits(actual[index])
                != Float.floatToIntBits(expected[index])) {
                return false;
            }
        }
        return true;
    }

    private static Bitmap bitmap(Method method, Object owner, Object... args) {
        if (owner == null) return null;
        Object result = invoke(method, owner, args);
        if (result == null) return null;
        Bitmap bitmap = (Bitmap) result;
        return bitmap.isRecycled() ? null : bitmap;
    }

    private static RectF copyRect(Object value) {
        return value instanceof RectF ? new RectF((RectF) value) : null;
    }

    private static boolean positive(RectF rect) {
        return rect != null
            && Float.isFinite(rect.left) && Float.isFinite(rect.top)
            && Float.isFinite(rect.right) && Float.isFinite(rect.bottom)
            && rect.right > rect.left && rect.bottom > rect.top;
    }

    private static boolean zero(RectF rect) {
        return rect != null && rect.left == 0.0f && rect.top == 0.0f
            && rect.right == 0.0f && rect.bottom == 0.0f;
    }

    private static RectD validatedSourceBox(RectF rect, RectD full) {
        RectD candidate = new RectD(
            rect.left,
            rect.top,
            rect.right,
            rect.bottom
        );
        double tolerance = 0.501;
        if (candidate.left < full.left - tolerance
            || candidate.top < full.top - tolerance
            || candidate.right > full.right + tolerance
            || candidate.bottom > full.bottom + tolerance) {
            throw new IllegalStateException(
                "native display crop escapes the source page"
            );
        }
        return candidate;
    }

    public static final class Components {
        public final Object activity;
        public final Object viewModel;
        public final Object presenter;
        public final Object handWriteView;
        public final Object eventCallback;
        public final ImageView image;
        public final ImageView digestImage;
        public final View documentLayout;
        public final Object note;
        public final Object client;
        public final IBinder binder;
        public final String documentPath;
        public final int readerPage;
        public final int pageCount;
        public final int presenterMarkPage;
        public final int presenterRotation;
        public final boolean documentImageReady;
        public final boolean handWriteReady;
        public final String markPath;

        private Components(
            Object activity,
            Object viewModel,
            Object presenter,
            Object handWriteView,
            Object eventCallback,
            ImageView image,
            ImageView digestImage,
            View documentLayout,
            Object note,
            Object client,
            IBinder binder,
            String documentPath,
            int readerPage,
            int pageCount,
            int presenterMarkPage,
            int presenterRotation,
            boolean documentImageReady,
            boolean handWriteReady,
            String markPath
        ) {
            this.activity = activity;
            this.viewModel = viewModel;
            this.presenter = presenter;
            this.handWriteView = handWriteView;
            this.eventCallback = eventCallback;
            this.image = image;
            this.digestImage = digestImage;
            this.documentLayout = documentLayout;
            this.note = note;
            this.client = client;
            this.binder = binder;
            this.documentPath = documentPath;
            this.readerPage = readerPage;
            this.pageCount = pageCount;
            this.presenterMarkPage = presenterMarkPage;
            this.presenterRotation = presenterRotation;
            this.documentImageReady = documentImageReady;
            this.handWriteReady = handWriteReady;
            this.markPath = markPath;
        }

        public boolean writerReady() {
            return readerPage >= 0 && readerPage < pageCount
                && presenterMarkPage == readerPage + 1
                // DocumentActivity.tryHideWaitView() clears
                // documentImageReady only after the document bitmap and the
                // handwriting layer have converged. handWriteInitReady stays
                // asserted. Requiring both booleans true observes a transient
                // pre-publication state and can bind the writer too early.
                && !documentImageReady && handWriteReady
                && note != null && client != null && binder != null
                && documentPath != null && markPath != null
                && documentLayout.getWidth() > 0
                && documentLayout.getHeight() > 0
                && canvasUsesPhysicalScreenOrigin();
        }

        private boolean canvasUsesPhysicalScreenOrigin() {
            int[] location = new int[2];
            documentLayout.getLocationOnScreen(location);
            // Activity.dispatchTouchEvent coordinates and Supernote's
            // onDigitalPosition callback are combined with global chrome
            // rectangles and DrawPath's physical canvas. This exact-firmware
            // adapter may proceed only when all four spaces share (0,0).
            return location[0] == 0 && location[1] == 0;
        }
    }

    public static final class PageGeometryLease {
        final int pageIndex;
        final Object pageInfo;
        final Object originalCtm;
        final Object originalRevert;
        final int originalOffsetX;
        final int originalOffsetY;
        final Object installedCtm;
        final Object installedRevert;
        final float[] installedCtmValues;
        final float[] installedRevertValues;
        final int installedOffsetX;
        final int installedOffsetY;
        boolean matricesRestored;
        boolean restored;

        PageGeometryLease(
            int pageIndex,
            Object pageInfo,
            Object originalCtm,
            Object originalRevert,
            int originalOffsetX,
            int originalOffsetY,
            Object installedCtm,
            Object installedRevert,
            float[] installedCtmValues,
            float[] installedRevertValues,
            int installedOffsetX,
            int installedOffsetY
        ) {
            this.pageIndex = pageIndex;
            this.pageInfo = pageInfo;
            this.originalCtm = originalCtm;
            this.originalRevert = originalRevert;
            this.originalOffsetX = originalOffsetX;
            this.originalOffsetY = originalOffsetY;
            this.installedCtm = installedCtm;
            this.installedRevert = installedRevert;
            this.installedCtmValues = installedCtmValues.clone();
            this.installedRevertValues = installedRevertValues.clone();
            this.installedOffsetX = installedOffsetX;
            this.installedOffsetY = installedOffsetY;
        }
    }

    public static final class PresentationScaleLease {
        final ImageView image;
        final ImageView.ScaleType imageScaleType;
        final ImageView digestImage;
        final ImageView.ScaleType digestScaleType;
        boolean restored;

        PresentationScaleLease(
            ImageView image,
            ImageView.ScaleType imageScaleType,
            ImageView digestImage,
            ImageView.ScaleType digestScaleType
        ) {
            this.image = image;
            this.imageScaleType = imageScaleType;
            this.digestImage = digestImage;
            this.digestScaleType = digestScaleType;
        }
    }

    public static final class CanonicalInk {
        public final boolean empty;
        public final Bitmap bitmap;

        private CanonicalInk(boolean empty, Bitmap bitmap) {
            this.empty = empty;
            this.bitmap = bitmap;
        }

        private static CanonicalInk empty() {
            return new CanonicalInk(true, null);
        }

        private static CanonicalInk loaded(Bitmap bitmap) {
            if (bitmap == null || bitmap.isRecycled()) {
                throw new IllegalArgumentException("loaded mark bitmap is invalid");
            }
            return new CanonicalInk(false, bitmap);
        }

        public void recycle() {
            if (bitmap != null && !bitmap.isRecycled()) bitmap.recycle();
        }
    }
}
