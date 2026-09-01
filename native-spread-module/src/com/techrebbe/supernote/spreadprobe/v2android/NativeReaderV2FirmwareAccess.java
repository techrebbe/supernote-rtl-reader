package com.techrebbe.supernote.spreadprobe.v2android;

import android.graphics.Bitmap;
import android.graphics.Rect;
import android.graphics.RectF;
import android.net.Uri;
import android.os.IBinder;
import android.view.View;
import android.widget.ImageView;

import com.techrebbe.supernote.spreadprobe.v2.NativeAuthority;
import com.techrebbe.supernote.spreadprobe.v2.NativeMarkPageInventory;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.IdentityHashMap;
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

    private final IdentityHashMap<Object, Long> componentIds =
        new IdentityHashMap<>();
    private long nextComponentId = 1L;

    private final Field activityViewModel;
    private final Field activityPresenter;
    private final Field activityHandWriteView;
    private final Field activityImage;
    private final Field activityDocumentLayout;
    private final Field activityImageReady;
    private final Field activityHandWriteReady;
    private final Field viewModelCurrentPage;
    private final Field viewModelPageCount;
    private final Field viewModelPageInfoMap;
    private final Field viewModelUri;
    private final Field presenterCurrentPage;
    private final Field presenterMarkPath;
    private final Field presenterScreenRotation;
    private final Field presenterBitmap;
    private final Field presenterNote;
    private final Field presenterClient;
    private final Field clientBinder;
    private final Method pageInfoOrigin;
    private final Method pageInfoDisplay;
    private final Method viewModelLoadPage;
    private final Method viewModelReloadPage;
    private final Method viewModelShowRect;
    private final Method viewModelTrimmingRect;
    private final Method presenterSave;
    private final Method presenterDisable;
    private final Method presenterLoadPage;
    private final Method presenterGetHandwriting;
    private final Method presenterSendWriteInfo;
    private final Method presenterSetDisabledAreas;
    private final Method handWriteViewSetBitmap;
    private final Method handWriteViewCancelSelection;
    private final Method handWriteViewClearSelection;
    private final Method noteScreenRotation;
    private final Method noteFetchPagesOfMark;
    private final Method noteLoadMarkPageBitmap;

    public NativeReaderV2FirmwareAccess(ClassLoader loader) {
        try {
            Class<?> activity = Class.forName(ACTIVITY, false, loader);
            Class<?> viewModel = Class.forName(VIEW_MODEL, false, loader);
            Class<?> pageInfo = Class.forName(PAGE_INFO, false, loader);
            Class<?> presenter = Class.forName(PRESENTER, false, loader);
            Class<?> client = Class.forName(HAND_WRITE_CLIENT, false, loader);
            Class<?> noteClass = Class.forName(
                "com.example.libsupernote.SuperNoteNote",
                false,
                loader
            );

            activityViewModel = field(activity, "documentViewModel");
            activityPresenter = field(activity, "handWritePresenter");
            activityHandWriteView = field(activity, "handWriteView");
            activityImage = field(activity, "mImage");
            activityDocumentLayout = field(activity, "documentViewLayout");
            activityImageReady = field(activity, "documentImageReady");
            activityHandWriteReady = field(activity, "handWriteInitReady");
            viewModelCurrentPage = field(viewModel, "currentPage");
            viewModelPageCount = field(viewModel, "pageCount");
            viewModelPageInfoMap = field(viewModel, "pageInfoHashMap");
            viewModelUri = field(viewModel, "uri");
            presenterCurrentPage = field(presenter, "currentPage");
            presenterMarkPath = field(presenter, "markPath");
            presenterScreenRotation = field(presenter, "screenRotation");
            presenterBitmap = field(presenter, "bitmap");
            presenterNote = field(presenter, "superNoteNote");
            presenterClient = field(presenter, "handWriteClient");
            clientBinder = field(client, "iBinder");

            pageInfoOrigin = method(pageInfo, "getOriginBitmap");
            pageInfoDisplay = method(pageInfo, "getDisplayBitmap");
            viewModelLoadPage = method(viewModel, "loadPage", Integer.TYPE);
            viewModelReloadPage = method(viewModel, "reloadPage");
            viewModelShowRect = method(viewModel, "getShowRect");
            viewModelTrimmingRect = method(
                viewModel,
                "getDisplayTrimmingRect"
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
            handWriteViewClearSelection = method(
                handWriteView,
                "clearAreaSelectionView"
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
            ImageView image = (ImageView) activityImage.get(activity);
            View layout = (View) activityDocumentLayout.get(activity);
            if (viewModel == null || presenter == null || handWriteView == null
                || image == null || layout == null) {
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
                image,
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

    public RectF showRect(Components components) {
        return copyRect(invoke(viewModelShowRect, components.viewModel));
    }

    public RectF trimmingRect(Components components) {
        return copyRect(invoke(viewModelTrimmingRect, components.viewModel));
    }

    public void saveSource(Components components) {
        // The transfer boundary must flush and drain DrawPath's live trail;
        // retaining it would let the old page's samples survive into the
        // next writer page.
        invoke(presenterSave, components.presenter, Boolean.TRUE);
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
     * canonical portrait geometry. The caller must reapply live writer
     * geometry before releasing document input.
     */
    public CanonicalInk committedCanonicalHandwriting(
        Components components,
        int zeroBasedPage,
        Bitmap pageOrigin
    ) {
        if (components.note == null || components.markPath == null
            || pageOrigin == null || pageOrigin.isRecycled()) {
            throw new IllegalStateException(
                "canonical handwriting authority is incomplete"
            );
        }
        if (zeroBasedPage < 0 || zeroBasedPage >= components.pageCount) {
            throw new IllegalArgumentException("mark page is out of range");
        }
        int nativePage = zeroBasedPage + 1;
        synchronized (components.note) {
            Object fetched = invoke(
                noteFetchPagesOfMark,
                components.note,
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
            RuntimeException failure = null;
            CanonicalInk loaded = null;
            try {
                if (!Boolean.TRUE.equals(invoke(
                    noteScreenRotation,
                    components.note,
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
                    components.note,
                    components.markPath,
                    nativePage,
                    result
                ))) {
                    throw new IllegalStateException(
                        "known mark page could not be rendered"
                    );
                }
                loaded = CanonicalInk.loaded(result);
            } catch (RuntimeException caught) {
                failure = caught;
            }
            try {
                if (!Boolean.TRUE.equals(invoke(
                    noteScreenRotation,
                    components.note,
                    components.presenterRotation + 1000,
                    0,
                    0
                ))) {
                    throw new IllegalStateException(
                        "native writer rotation could not be restored"
                    );
                }
            } catch (RuntimeException restoreFailure) {
                if (failure == null) {
                    failure = restoreFailure;
                } else {
                    failure.addSuppressed(restoreFailure);
                }
            }
            if (failure != null) {
                if (!result.isRecycled()) result.recycle();
                throw failure;
            }
            return loaded;
        }
    }

    public void setBackground(Components components, Bitmap bitmap) {
        components.image.setScaleType(ImageView.ScaleType.FIT_XY);
        components.image.setImageBitmap(bitmap);
    }

    public void setLiveInkBitmap(Components components, Bitmap bitmap) {
        invoke(handWriteViewSetBitmap, components.handWriteView, bitmap);
    }

    public void cancelSelection(Components components) {
        invoke(handWriteViewCancelSelection, components.handWriteView);
        invoke(handWriteViewClearSelection, components.handWriteView);
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
        Long existing = componentIds.get(component);
        if (existing != null) return existing;
        if (nextComponentId <= 0L) {
            throw new IllegalStateException("component identity exhausted");
        }
        long assigned = nextComponentId++;
        componentIds.put(component, assigned);
        return assigned;
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

    public static final class Components {
        public final Object activity;
        public final Object viewModel;
        public final Object presenter;
        public final Object handWriteView;
        public final ImageView image;
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
            ImageView image,
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
            this.image = image;
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
                && documentImageReady && handWriteReady
                && note != null && client != null && binder != null
                && documentPath != null && markPath != null
                && documentLayout.getWidth() > 0
                && documentLayout.getHeight() > 0;
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
