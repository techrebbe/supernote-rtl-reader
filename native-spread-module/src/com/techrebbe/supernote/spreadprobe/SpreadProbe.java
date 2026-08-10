package com.techrebbe.supernote.spreadprobe;

import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.res.Configuration;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.Point;
import android.graphics.PointF;
import android.graphics.PorterDuff;
import android.graphics.Rect;
import android.graphics.RectF;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.FileObserver;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.Parcel;
import android.os.Process;
import android.os.SystemClock;
import android.system.Os;
import android.system.StructStat;
import android.util.Log;
import android.util.Size;
import android.view.Gravity;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.TextView;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.lang.ref.WeakReference;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;
import java.util.WeakHashMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import org.json.JSONArray;
import org.json.JSONObject;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public final class SpreadProbe implements IXposedHookLoadPackage {
    private static final String TARGET_PACKAGE = "com.supernote.document";
    private static final String TARGET_ACTIVITY =
        "com.supernote.document.document.DocumentActivity";
    private static final String TARGET_FINGERPRINT =
        "Supernote/Supernote/Supernote:11/RQ2A.210505.003/eng.supern.20260616.100032:user/release-keys";
    private static final String TARGET_DOCUMENT_APK =
        "/system_ext/app/SupernoteDocument/SupernoteDocument.apk";
    private static final long TARGET_DOCUMENT_APK_LENGTH = 138486560L;
    private static final String TARGET_FILE =
        "/storage/emulated/0/Document/SupernoteNativeSpreadCalibration.pdf";
    private static final String SIDECAR_SUFFIX = ".snspread";
    private static final String TAG = "SN_SPREAD_PROBE";
    private static final String PLUGIN_HOST_PACKAGE =
        "com.ratta.supernote.pluginhost";
    private static final String HANDSHAKE_REQUEST_ACTION =
        "com.techrebbe.supernote.spreadprobe.HANDSHAKE_REQUEST";
    private static final String HANDSHAKE_RESPONSE_ACTION =
        "com.techrebbe.supernote.spreadprobe.HANDSHAKE_RESPONSE";
    private static final String HANDSHAKE_EXTRA_NONCE = "nonce";
    private static final String HANDSHAKE_EXTRA_DOCUMENT_PATH = "documentPath";
    private static final String HANDSHAKE_EXTRA_PROTOCOL = "protocol";
    private static final String HANDSHAKE_EXTRA_HOOKS_READY = "hooksReady";
    private static final String HANDSHAKE_EXTRA_MODULE_VERSION_CODE =
        "moduleVersionCode";
    private static final String HANDSHAKE_EXTRA_DOCUMENT_APK_LENGTH =
        "documentApkLength";
    private static final String HANDSHAKE_EXTRA_PROCESS_ID = "processId";
    private static final String TRACE_CONTROL_ACTION =
        "com.techrebbe.supernote.spreadprobe.TRACE_CONTROL";
    private static final String TRACE_EXTRA_COMMAND = "command";
    private static final String TRACE_EXTRA_LABEL = "label";
    private static final String TRACE_CONTROL_PERMISSION =
        "android.permission.DUMP";
    private static final String TRACE_ROOT =
        "/storage/emulated/0/Download/SupernoteNativeSpreadTrace";
    private static final int TRACE_SCHEMA_VERSION = 1;
    private static final int TRACE_TRAIL_LIMIT = 256;
    private static final long TRACE_MAX_SNAPSHOT_BYTES = 64L * 1024L * 1024L;
    private static final int TRACE_FINAL_SNAPSHOT_ATTEMPTS = 5;
    private static final long TRACE_FINAL_SNAPSHOT_RETRY_MS = 120L;
    private static final int HANDSHAKE_PROTOCOL = 1;
    private static final long MODULE_VERSION_CODE = 118L;
    private static final String OVERLAY_TAG = "sn-spread-probe-overlay";
    private static final int CANONICAL_PAGE_WIDTH = 1872;
    private static final int CANONICAL_PAGE_HEIGHT = 2496;
    private static final int DOCUMENT_PAGE_WIDTH = 1404;
    private static final int DOCUMENT_PAGE_HEIGHT = 1872;
    private static final int SPREAD_PAGE_WIDTH = 932;
    private static final int SPREAD_PAGE_HEIGHT = 1243;
    private static final float SPREAD_OUTER_EDGE_FRACTION = 0.14f;
    private static final int NATIVE_TOP_CHROME_TOUCH_EXCLUSION_PX = 112;
    private static final int NATIVE_BOTTOM_CHROME_TOUCH_EXCLUSION_PX = 96;
    private static final long NON_EDGE_TAP_SUPPRESSION_MS = 400L;
    private static final long PAGE_ACTIVATION_TIMEOUT_MS = 3000L;
    private static final int PAGE_ACTIVATION_ROLLBACK_MAX_ATTEMPTS = 2;
    private static final long PAGE_ACTIVATION_ROLLBACK_RETRY_MS = 180L;
    private static final long DEFERRED_SPREAD_TURN_RETRY_MS = 80L;
    private static final long DEFERRED_SPREAD_TURN_SLOW_RETRY_MS = 250L;
    private static final long DEFERRED_SPREAD_TURN_NOTICE_MS = 3000L;
    private static final long PAGE_ACTIVATION_PEN_SETTLE_MS = 160L;
    private static final int PEN_CONTACT_BLOCKED_PAGE = Integer.MIN_VALUE;
    private static final long TRACE_SNAPSHOT_DEBOUNCE_MS = 80L;
    private static final AtomicInteger GENERATION = new AtomicInteger();
    private static final AtomicLong TRACE_TRANSACTION_COUNTER =
        new AtomicLong();
    private static final AtomicLong PAGE_ACTIVATION_COUNTER =
        new AtomicLong();
    private static final AtomicLong DEFERRED_SPREAD_TURN_COUNTER =
        new AtomicLong();
    private static final ScheduledExecutorService LOW_LATENCY_LOG_EXECUTOR =
        Executors.newSingleThreadScheduledExecutor(new ThreadFactory() {
            @Override
            public Thread newThread(Runnable runnable) {
                Thread thread = new Thread(
                    runnable,
                    "SNSpreadLowLatencyLog"
                );
                thread.setDaemon(true);
                return thread;
            }
        });
    private static final Object TRACE_LOCK = new Object();
    private static final Object PAGE_ACTIVATION_OWNERSHIP_LOCK = new Object();
    private static final Map<Activity, Bitmap> COMPOSITES = new WeakHashMap<>();
    private static final Map<Activity, RectF> LEFT_DESTINATIONS = new WeakHashMap<>();
    private static final Map<Activity, RectF> RIGHT_DESTINATIONS = new WeakHashMap<>();
    private static final Map<Activity, RectF> LEFT_VISIBLE_BOUNDS = new WeakHashMap<>();
    private static final Map<Activity, RectF> RIGHT_VISIBLE_BOUNDS = new WeakHashMap<>();
    private static final Map<Object, RectF> AUTO_TRIMMING_RECTS =
        new WeakHashMap<>();
    private static final Map<Activity, Bitmap> COMMITTED_INK_COMPOSITES =
        new WeakHashMap<>();
    private static final Map<Activity, Bitmap> FULL_INK_BITMAPS =
        new WeakHashMap<>();
    private static final Map<Activity, Boolean> REPLACE_ACTIVE_INK_MODES =
        new WeakHashMap<>();
    private static final Map<Activity, Boolean> CANONICAL_ONLY_INK_MODES =
        new WeakHashMap<>();
    private static final Map<Activity, Bitmap> DIGEST_COMPOSITES =
        new WeakHashMap<>();
    private static final Map<Activity, Integer> ACTIVATION_TOUCH_TARGETS =
        new WeakHashMap<>();
    private static final Map<Activity, Point> ACTIVATION_TOUCH_STARTS =
        new WeakHashMap<>();
    private static final Map<Activity, Boolean>
        PAGE_ACTIVATION_BLOCKED_TOUCHES = new WeakHashMap<>();
    private static final Map<Activity, PageActivationTransaction>
        PAGE_ACTIVATION_TRANSACTIONS = new ConcurrentHashMap<>();
    private static final Map<Activity, DeferredSpreadTurn>
        DEFERRED_SPREAD_TURNS = new ConcurrentHashMap<>();
    private static final Map<Activity, Integer> PEN_CONTACT_START_PAGES =
        new ConcurrentHashMap<>();
    private static final Map<Activity, Integer> PEN_ACTIVATION_TARGETS =
        new WeakHashMap<>();
    private static final Map<Activity, Integer> PEN_ACTIVATION_ORIGINAL_PAGES =
        new WeakHashMap<>();
    private static final Map<Activity, List<Object>> PEN_ACTIVATION_TRAILS =
        new WeakHashMap<>();
    private static final Map<Activity, List<Object>> PEN_ACTIVATION_ERASERS =
        new WeakHashMap<>();
    private static final Map<Activity, Boolean>
        PEN_ACTIVATION_STALE_SAVE_PENDING =
        new WeakHashMap<>();
    private static final Map<Activity, PageEditHistory>
        PENDING_PAGE_EDIT_HISTORY = new WeakHashMap<>();
    private static final Map<Object, PageEditHistory>
        PAGE_EDIT_HISTORY_ACTIONS = new WeakHashMap<>();
    private static final Map<Activity, Point> FINGER_TOUCH_STARTS =
        new WeakHashMap<>();
    private static final Map<Activity, Long> NON_EDGE_TAP_SUPPRESS_UNTIL =
        new WeakHashMap<>();
    private static final Map<Activity, Integer> TRACE_LAST_PRESSURES =
        new ConcurrentHashMap<>();
    private static final Map<Activity, Long> TRACE_TRANSACTION_IDS =
        new ConcurrentHashMap<>();
    private static final Map<Activity, String> TRACE_TOOLS =
        new WeakHashMap<>();
    private static final Map<Activity, PenInputSnapshot> PEN_INPUT_SNAPSHOTS =
        new ConcurrentHashMap<>();
    private static final Map<Activity, String> PEN_INPUT_BLOCK_LOG_STATES =
        new ConcurrentHashMap<>();
    private static final Map<Activity, SpreadConfig> SPREAD_CONFIGS =
        new WeakHashMap<>();
    private static final Map<Activity, ProtectedVerification>
        PROTECTED_VERIFICATIONS = new WeakHashMap<>();
    private static final ThreadLocal<Boolean> LINK_SPLIT_ORIGINAL =
        new ThreadLocal<>();
    private static final ThreadLocal<List<Rect>> SELECT_POP_RECT_ORIGINALS =
        new ThreadLocal<>();
    private static final ThreadLocal<Bitmap> SET_IMAGE_ACTIVE_BITMAP =
        new ThreadLocal<>();
    private static final ThreadLocal<Boolean> SET_IMAGE_VIEW_SUPPRESSED =
        new ThreadLocal<>();
    private static final ThreadLocal<Boolean> COMMITTED_INK_ALREADY_SPREAD =
        new ThreadLocal<>();
    private static final ThreadLocal<Boolean> PEN_ACTIVATION_MARK_PRIMING =
        new ThreadLocal<>();
    private static final ThreadLocal<Boolean> FORCE_CANONICAL_ACTIVE_INK =
        new ThreadLocal<>();
    private static final ThreadLocal<Boolean> EXPLICIT_CANONICAL_TRAIL_SAVE =
        new ThreadLocal<>();
    private static final ThreadLocal<Boolean> PEN_ACTIVATION_STALE_SAVE_SCOPE =
        new ThreadLocal<>();
    private static final ThreadLocal<Boolean> PAGE_ACTIVATION_SOURCE_SAVE_SCOPE =
        new ThreadLocal<>();
    private static final ThreadLocal<Boolean>
        PAGE_ACTIVATION_RECEIVE_BLOCKED = new ThreadLocal<>();
    private static final ThreadLocal<Boolean>
        PAGE_ACTIVATION_HISTORY_BLOCKED = new ThreadLocal<>();
    private static final ThreadLocal<Activity>
        ACTIVE_PAGE_STROKE_TERMINAL_CLEANUP = new ThreadLocal<>();
    private static Activity activeActivity;
    private static boolean nativeBridgeLoaded;
    private static volatile boolean hooksReady;
    private static BroadcastReceiver handshakeReceiver;
    private static boolean handshakeReceiverRegistered;
    private static BroadcastReceiver traceControlReceiver;
    private static boolean traceControlReceiverRegistered;
    private static volatile TraceSession traceSession;
    private static boolean spreadLassoActive;
    private static boolean spreadLassoOriginZero;
    private static boolean spreadLassoCanonicalSelection;
    private static boolean spreadLassoOperationOriginZero;
    private static boolean spreadLassoToolArmed;
    private static Bitmap spreadLassoCorrectedPreview;

    private static final class FileIdentity {
        final long modified;
        final long length;
        final long device;
        final long inode;
        final long changeSeconds;
        final long changeNanos;

        FileIdentity(
            long modified,
            long length,
            long device,
            long inode,
            long changeSeconds,
            long changeNanos
        ) {
            this.modified = modified;
            this.length = length;
            this.device = device;
            this.inode = inode;
            this.changeSeconds = changeSeconds;
            this.changeNanos = changeNanos;
        }

        static FileIdentity missing() {
            return new FileIdentity(-1L, -1L, -1L, -1L, -1L, -1L);
        }

        static FileIdentity capture(File file) throws Exception {
            if (file == null || !file.isFile()) {
                return missing();
            }
            StructStat stat = Os.stat(file.getAbsolutePath());
            return new FileIdentity(
                file.lastModified(),
                file.length(),
                stat.st_dev,
                stat.st_ino,
                stat.st_ctim.tv_sec,
                stat.st_ctim.tv_nsec
            );
        }

        boolean sameAs(FileIdentity other) {
            return other != null
                && modified == other.modified
                && length == other.length
                && device == other.device
                && inode == other.inode
                && changeSeconds == other.changeSeconds
                && changeNanos == other.changeNanos;
        }
    }

    private static final class TraceSession {
        final String id;
        final String documentPath;
        final String markPath;
        final File rootDirectory;
        final File sessionDirectory;
        final File eventFile;
        final File snapshotDirectory;
        final long startedAtMillis;
        final WeakReference<Activity> activity;
        long sequence;
        String lastSnapshotHash;
        FileIdentity lastSnapshotIdentity;
        FileObserver markObserver;
        final ScheduledExecutorService snapshotExecutor;
        final ScheduledExecutorService eventExecutor;
        ScheduledFuture<?> pendingSnapshot;
        long snapshotGeneration;
        boolean stopping;
        volatile String eventWriteFailure;

        TraceSession(
            String id,
            String documentPath,
            String markPath,
            File rootDirectory,
            File sessionDirectory,
            File eventFile,
            File snapshotDirectory,
            long startedAtMillis,
            Activity activity
        ) {
            this.id = id;
            this.documentPath = documentPath;
            this.markPath = markPath;
            this.rootDirectory = rootDirectory;
            this.sessionDirectory = sessionDirectory;
            this.eventFile = eventFile;
            this.snapshotDirectory = snapshotDirectory;
            this.startedAtMillis = startedAtMillis;
            this.activity = new WeakReference<>(activity);
            this.snapshotExecutor = Executors.newSingleThreadScheduledExecutor(
                new ThreadFactory() {
                    @Override
                    public Thread newThread(Runnable runnable) {
                        Thread thread = new Thread(
                            runnable,
                            "SNSpreadTraceSnapshot-" + id
                        );
                        thread.setDaemon(true);
                        return thread;
                    }
                }
            );
            this.eventExecutor = Executors.newSingleThreadScheduledExecutor(
                new ThreadFactory() {
                    @Override
                    public Thread newThread(Runnable runnable) {
                        Thread thread = new Thread(
                            runnable,
                            "SNSpreadTraceEvent-" + id
                        );
                        thread.setDaemon(true);
                        return thread;
                    }
                }
            );
        }
    }

    private static final class TraceEventContext {
        final int readerPage;
        final int markPage;
        final int orientation;
        final Long transaction;
        final String tool;
        final Integer pendingActivationPage;
        final Boolean editable;
        final Boolean coverSeparate;

        TraceEventContext(
            int readerPage,
            int markPage,
            int orientation,
            Long transaction,
            String tool,
            Integer pendingActivationPage,
            Boolean editable,
            Boolean coverSeparate
        ) {
            this.readerPage = readerPage;
            this.markPage = markPage;
            this.orientation = orientation;
            this.transaction = transaction;
            this.tool = tool;
            this.pendingActivationPage = pendingActivationPage;
            this.editable = editable;
            this.coverSeparate = coverSeparate;
        }

        static TraceEventContext capture(Activity activity) {
            if (activity == null) {
                return new TraceEventContext(
                    -1, -1, -1, null, null, null, null, null
                );
            }
            int orientation = -1;
            try {
                orientation = activity.getResources()
                    .getConfiguration().orientation;
            } catch (Throwable ignored) {
            }
            SpreadConfig config = SPREAD_CONFIGS.get(activity);
            return new TraceEventContext(
                traceCurrentDocumentPage(activity),
                traceCurrentMarkPage(activity),
                orientation,
                TRACE_TRANSACTION_IDS.get(activity),
                TRACE_TOOLS.get(activity),
                pendingPageActivationTarget(activity),
                config == null ? null : Boolean.valueOf(config.editable),
                config == null ? null : Boolean.valueOf(config.coverSeparate)
            );
        }

        void writeTo(JSONObject entry) throws Exception {
            if (readerPage >= 0) {
                entry.put("readerPage", readerPage);
                entry.put("visibleReaderPage", readerPage + 1);
            }
            if (markPage >= 0) {
                entry.put("markPage", markPage);
            }
            if (orientation >= 0) {
                entry.put("orientation", orientation);
            }
            if (transaction != null) {
                entry.put("transaction", transaction.longValue());
            }
            if (tool != null) {
                entry.put("tool", tool);
            }
            if (pendingActivationPage != null) {
                entry.put(
                    "pendingActivationPage",
                    pendingActivationPage.intValue()
                );
            }
            if (editable != null) {
                entry.put("editable", editable.booleanValue());
            }
            if (coverSeparate != null) {
                entry.put("coverSeparate", coverSeparate.booleanValue());
            }
        }
    }

    private static final class TraceTrailCapture {
        final boolean nullValue;
        final String error;
        final int page;
        final int trail;
        final int inPage;
        final int pen;
        final int penColor;
        final int thickness;
        final int emrType;
        final int flagDraw;
        final int flagPenup;
        final int flagSpecial;
        final int layer;
        final int recMod;
        final int emrPointAxis;
        final int trailType;
        final int drawVersion;
        final int recognTrailType;
        final int status;
        final int process;
        final int rotation;
        final int redrawWidth;
        final int redrawHeight;
        final int maxX;
        final int maxY;
        final TraceValueCapture rrdRect;
        final TraceValueCapture refreshRect;
        final TraceValueCapture beforeShiftRect;
        final TraceValueCapture afterShiftRect;
        final TraceValueCapture contours;
        final int[] pointXs;
        final int[] pointYs;
        final boolean[] pointPresent;
        final String erased;
        final TraceValueCapture writeAppName;
        final TraceValueCapture pressures;
        final TraceValueCapture angles;
        final TraceValueCapture timestamp;

        TraceTrailCapture(
            boolean nullValue,
            String error,
            int page,
            int trail,
            int inPage,
            int pen,
            int penColor,
            int thickness,
            int emrType,
            int flagDraw,
            int flagPenup,
            int flagSpecial,
            int layer,
            int recMod,
            int emrPointAxis,
            int trailType,
            int drawVersion,
            int recognTrailType,
            int status,
            int process,
            int rotation,
            int redrawWidth,
            int redrawHeight,
            int maxX,
            int maxY,
            TraceValueCapture rrdRect,
            TraceValueCapture refreshRect,
            TraceValueCapture beforeShiftRect,
            TraceValueCapture afterShiftRect,
            TraceValueCapture contours,
            int[] pointXs,
            int[] pointYs,
            boolean[] pointPresent,
            String erased,
            TraceValueCapture writeAppName,
            TraceValueCapture pressures,
            TraceValueCapture angles,
            TraceValueCapture timestamp
        ) {
            this.nullValue = nullValue;
            this.error = error;
            this.page = page;
            this.trail = trail;
            this.inPage = inPage;
            this.pen = pen;
            this.penColor = penColor;
            this.thickness = thickness;
            this.emrType = emrType;
            this.flagDraw = flagDraw;
            this.flagPenup = flagPenup;
            this.flagSpecial = flagSpecial;
            this.layer = layer;
            this.recMod = recMod;
            this.emrPointAxis = emrPointAxis;
            this.trailType = trailType;
            this.drawVersion = drawVersion;
            this.recognTrailType = recognTrailType;
            this.status = status;
            this.process = process;
            this.rotation = rotation;
            this.redrawWidth = redrawWidth;
            this.redrawHeight = redrawHeight;
            this.maxX = maxX;
            this.maxY = maxY;
            this.rrdRect = rrdRect;
            this.refreshRect = refreshRect;
            this.beforeShiftRect = beforeShiftRect;
            this.afterShiftRect = afterShiftRect;
            this.contours = contours;
            this.pointXs = pointXs;
            this.pointYs = pointYs;
            this.pointPresent = pointPresent;
            this.erased = erased;
            this.writeAppName = writeAppName;
            this.pressures = pressures;
            this.angles = angles;
            this.timestamp = timestamp;
        }
    }

    private static final class TraceValueCapture {
        final boolean sequence;
        final Object value;

        TraceValueCapture(boolean sequence, Object value) {
            this.sequence = sequence;
            this.value = value;
        }
    }

    private static final class TraceTrailListCapture {
        final boolean missing;
        final TraceTrailCapture[] trails;

        TraceTrailListCapture(boolean missing, TraceTrailCapture[] trails) {
            this.missing = missing;
            this.trails = trails;
        }
    }

    private static final class PageEditHistory {
        final Activity activity;
        final String markPath;
        final int markPage;
        final ArrayList<Object> beforeTrails;
        final ArrayList<Object> afterTrails;

        PageEditHistory(
            Activity activity,
            String markPath,
            int markPage,
            List<Object> beforeTrails,
            List<Object> afterTrails
        ) {
            this.activity = activity;
            this.markPath = markPath;
            this.markPage = markPage;
            this.beforeTrails = new ArrayList<>(beforeTrails);
            this.afterTrails = new ArrayList<>(afterTrails);
        }
    }

    /**
     * One fail-closed ownership transfer for Supernote's single native
     * handwriting page.  The spread may display two pages, but only targetPage
     * is allowed to own HandWritePresenter, DrawPath, Undo/Redo, and .mark I/O
     * after this transaction commits.
     */
    private static final class PageActivationTransaction {
        final long id;
        final int sourcePage;
        final int targetPage;
        final String trigger;
        final long startedAt;
        volatile boolean triggerContactObserved;
        volatile boolean triggerPenLifted;
        volatile boolean geometryCommitted;
        volatile boolean rollbackPending;
        volatile String abortReason;
        int loadAttempts;
        int rollbackAttempts;

        PageActivationTransaction(
            long id,
            int sourcePage,
            int targetPage,
            String trigger,
            boolean triggerContactObserved
        ) {
            this.id = id;
            this.sourcePage = sourcePage;
            this.targetPage = targetPage;
            this.trigger = trigger;
            this.startedAt = SystemClock.uptimeMillis();
            this.triggerContactObserved = triggerContactObserved;
            this.triggerPenLifted = !triggerContactObserved;
        }
    }

    private static final class DeferredSpreadTurn {
        final long id;
        final String documentPath;
        final int sourcePage;
        final int targetPage;
        final long startedAt;
        volatile boolean noticeShown;

        DeferredSpreadTurn(
            long id,
            String documentPath,
            int sourcePage,
            int targetPage
        ) {
            this.id = id;
            this.documentPath = documentPath;
            this.sourcePage = sourcePage;
            this.targetPage = targetPage;
            this.startedAt = SystemClock.uptimeMillis();
        }
    }

    private static final class SpreadConfig {
        final String documentPath;
        final long documentModified;
        final long documentLength;
        final long documentDevice;
        final long documentInode;
        final long documentChangeSeconds;
        final long documentChangeNanos;
        final String markerPath;
        final FileIdentity markerIdentity;
        final FileIdentity backupIdentity;
        final FileIdentity snapshotIdentity;
        final boolean enabled;
        final boolean coverSeparate;
        final boolean showDivider;
        final boolean showHeader;
        final boolean nativeFill;
        final boolean editable;
        final boolean calibration;

        SpreadConfig(
            String documentPath,
            long documentModified,
            long documentLength,
            long documentDevice,
            long documentInode,
            long documentChangeSeconds,
            long documentChangeNanos,
            String markerPath,
            FileIdentity markerIdentity,
            FileIdentity backupIdentity,
            FileIdentity snapshotIdentity,
            boolean enabled,
            boolean coverSeparate,
            boolean showDivider,
            boolean showHeader,
            boolean nativeFill,
            boolean editable,
            boolean calibration
        ) {
            this.documentPath = documentPath;
            this.documentModified = documentModified;
            this.documentLength = documentLength;
            this.documentDevice = documentDevice;
            this.documentInode = documentInode;
            this.documentChangeSeconds = documentChangeSeconds;
            this.documentChangeNanos = documentChangeNanos;
            this.markerPath = markerPath;
            this.markerIdentity = markerIdentity;
            this.backupIdentity = backupIdentity;
            this.snapshotIdentity = snapshotIdentity;
            this.enabled = enabled;
            this.coverSeparate = coverSeparate;
            this.showDivider = showDivider;
            this.showHeader = showHeader;
            this.nativeFill = nativeFill;
            this.editable = editable;
            this.calibration = calibration;
        }
    }

    private static final class ProtectedVerification {
        final String documentPath;
        final long documentModified;
        final long documentLength;
        final long documentDevice;
        final long documentInode;
        final long documentChangeSeconds;
        final long documentChangeNanos;
        final String markerPath;
        final FileIdentity markerIdentity;
        final FileIdentity backupIdentity;
        final FileIdentity snapshotIdentity;
        boolean complete;
        boolean valid;

        ProtectedVerification(
            String documentPath,
            long documentModified,
            long documentLength,
            long documentDevice,
            long documentInode,
            long documentChangeSeconds,
            long documentChangeNanos,
            String markerPath,
            FileIdentity markerIdentity,
            FileIdentity backupIdentity,
            FileIdentity snapshotIdentity
        ) {
            this.documentPath = documentPath;
            this.documentModified = documentModified;
            this.documentLength = documentLength;
            this.documentDevice = documentDevice;
            this.documentInode = documentInode;
            this.documentChangeSeconds = documentChangeSeconds;
            this.documentChangeNanos = documentChangeNanos;
            this.markerPath = markerPath;
            this.markerIdentity = markerIdentity;
            this.backupIdentity = backupIdentity;
            this.snapshotIdentity = snapshotIdentity;
        }

        boolean matches(
            String nextDocumentPath,
            long nextDocumentModified,
            long nextDocumentLength,
            long nextDocumentDevice,
            long nextDocumentInode,
            long nextDocumentChangeSeconds,
            long nextDocumentChangeNanos,
            String nextMarkerPath,
            FileIdentity nextMarkerIdentity,
            FileIdentity nextBackupIdentity,
            FileIdentity nextSnapshotIdentity
        ) {
            return documentPath.equals(nextDocumentPath)
                && documentModified == nextDocumentModified
                && documentLength == nextDocumentLength
                && documentDevice == nextDocumentDevice
                && documentInode == nextDocumentInode
                && documentChangeSeconds == nextDocumentChangeSeconds
                && documentChangeNanos == nextDocumentChangeNanos
                && markerPath.equals(nextMarkerPath)
                && markerIdentity.sameAs(nextMarkerIdentity)
                && backupIdentity.sameAs(nextBackupIdentity)
                && snapshotIdentity.sameAs(nextSnapshotIdentity);
        }
    }

    private static final class SpreadPair {
        final int rightPage;
        final int leftPage;

        SpreadPair(int rightPage, int leftPage) {
            this.rightPage = rightPage;
            this.leftPage = leftPage;
        }

        boolean contains(int page) {
            return page >= 0 && (page == rightPage || page == leftPage);
        }
    }

    /**
     * Immutable, UI-thread-published state used by the native pen callback.
     *
     * The callback runs in front of Supernote's low-latency writer and must
     * never validate marker files or document metadata. The UI composition
     * path performs that validation once, copies the page geometry here, and
     * atomically replaces this snapshot when the document or spread changes.
     */
    private static final class PenInputSnapshot {
        final SpreadConfig config;
        final String documentPath;
        final int currentPage;
        final int pageCount;
        final int rightPage;
        final int leftPage;
        final RectF rightVisibleBounds;
        final RectF leftVisibleBounds;
        final boolean editable;
        final boolean geometryReady;

        PenInputSnapshot(
            SpreadConfig config,
            int currentPage,
            int pageCount,
            int rightPage,
            int leftPage,
            RectF rightVisibleBounds,
            RectF leftVisibleBounds,
            boolean geometryReady
        ) {
            this.config = config;
            this.documentPath = config.documentPath;
            this.currentPage = currentPage;
            this.pageCount = pageCount;
            this.rightPage = rightPage;
            this.leftPage = leftPage;
            this.rightVisibleBounds = rightVisibleBounds == null
                ? null : new RectF(rightVisibleBounds);
            this.leftVisibleBounds = leftVisibleBounds == null
                ? null : new RectF(leftVisibleBounds);
            this.editable = config.enabled && config.editable;
            this.geometryReady = geometryReady;
        }

        int pageAt(float x, float y) {
            if (leftPage >= 0 && leftVisibleBounds != null
                && leftVisibleBounds.contains(x, y)) {
                return leftPage;
            }
            if (rightPage >= 0 && rightVisibleBounds != null
                && rightVisibleBounds.contains(x, y)) {
                return rightPage;
            }
            return -1;
        }
    }

    private static final class SpreadPageLayout {
        final RectF destination;
        final RectF visibleBounds;

        SpreadPageLayout(RectF destination, RectF visibleBounds) {
            this.destination = destination;
            this.visibleBounds = visibleBounds;
        }
    }

    private static final class PluginLassoGeometry {
        final Rect pageBounds;
        final List<Point> emrPoints;
        final int pageWidth;
        final int pageHeight;
        final int maxX;
        final int maxY;
        final int page;
        final int orientation;
        final int device;

        PluginLassoGeometry(
            Rect pageBounds,
            List<Point> emrPoints,
            int pageWidth,
            int pageHeight,
            int maxX,
            int maxY,
            int page,
            int orientation,
            int device
        ) {
            this.pageBounds = pageBounds;
            this.emrPoints = emrPoints;
            this.pageWidth = pageWidth;
            this.pageHeight = pageHeight;
            this.maxX = maxX;
            this.maxY = maxY;
            this.page = page;
            this.orientation = orientation;
            this.device = device;
        }
    }

    private static final class SelectionGeometry {
        final RectF destination;
        final Bitmap originBitmap;
        final float nativeOutputScale;
        final float nativeOffsetX;
        final float nativeOffsetY;

        SelectionGeometry(
            RectF destination,
            Bitmap originBitmap,
            float nativeOutputScale,
            float nativeOffsetX,
            float nativeOffsetY
        ) {
            this.destination = destination;
            this.originBitmap = originBitmap;
            this.nativeOutputScale = nativeOutputScale;
            this.nativeOffsetX = nativeOffsetX;
            this.nativeOffsetY = nativeOffsetY;
        }
    }

    private static native void nativeSetCalibrationEnabled(boolean enabled);
    private static native int nativeGetHookState();

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam loadPackageParam)
        throws Throwable {
        if (!TARGET_PACKAGE.equals(loadPackageParam.packageName)
            || !TARGET_PACKAGE.equals(loadPackageParam.processName)) {
            return;
        }

        if (!TARGET_FINGERPRINT.equals(Build.FINGERPRINT)) {
            log("disabled fingerprint=" + Build.FINGERPRINT);
            return;
        }

        File documentApk = new File(TARGET_DOCUMENT_APK);
        long installedApkLength = documentApk.isFile()
            ? documentApk.length() : -1L;
        if (installedApkLength != TARGET_DOCUMENT_APK_LENGTH) {
            log("disabled document_package_mismatch apk_length="
                + installedApkLength + " source=" + TARGET_DOCUMENT_APK);
            return;
        }

        try {
            System.loadLibrary("spreadprobe");
            nativeBridgeLoaded = true;
            nativeSetCalibrationEnabled(false);
            log("native_bridge_loaded hook_state=" + nativeGetHookState());
        } catch (Throwable throwable) {
            nativeBridgeLoaded = false;
            log("native_bridge_failed " + throwable);
            XposedBridge.log(throwable);
        }

        log("loaded compatibility_ok=true process="
            + loadPackageParam.processName + " document_version=1.02.446"
            + " apk_length=" + installedApkLength);

        XposedHelpers.findAndHookMethod(
            "com.supernote.document.utils.view.DocumentImageView",
            loadPackageParam.classLoader,
            "setImageBitmap",
            Bitmap.class,
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    if (!Boolean.TRUE.equals(
                        SET_IMAGE_VIEW_SUPPRESSED.get()
                    )) {
                        return;
                    }
                    Activity activity = activeActivity;
                    if (activity == null
                        || !isCalibrationLandscape(activity)) {
                        return;
                    }
                    Object documentImage = XposedHelpers.getObjectField(
                        activity,
                        "mImage"
                    );
                    if (param.thisObject != documentImage) {
                        return;
                    }
                    param.setResult(null);
                    log("transition_native_image_submission_suppressed");
                }
            }
        );

        XposedHelpers.findAndHookMethod(
            TARGET_ACTIVITY,
            loadPackageParam.classLoader,
            "onCreate",
            Bundle.class,
            new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    activeActivity = (Activity) param.thisObject;
                    SPREAD_CONFIGS.remove(activeActivity);
                    registerHandshakeReceiver(activeActivity);
                    registerTraceControlReceiver(activeActivity);
                    updateNativeEraserGate(activeActivity, "activity_created");
                    log("activity_created");
                }
            }
        );

        XposedHelpers.findAndHookMethod(
            TARGET_ACTIVITY,
            loadPackageParam.classLoader,
            "onConfigurationChanged",
            Configuration.class,
            new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    Activity activity = (Activity) param.thisObject;
                    Configuration configuration =
                        (Configuration) param.args[0];
                    traceEvent(
                        activity,
                        "configuration_changed",
                        "newOrientation",
                        configuration.orientation
                    );
                    if (configuration.orientation
                            != Configuration.ORIENTATION_LANDSCAPE
                        && PAGE_ACTIVATION_TRANSACTIONS.get(activity) != null) {
                        abortPageActivationTransaction(
                            activity,
                            "orientation_changed",
                            true
                        );
                    }
                    if (!isCalibrationFile(activity)) {
                        updateNativeEraserGate(
                            activity,
                            "configuration_non_calibration"
                        );
                        return;
                    }
                    updateNativeEraserGate(
                        activity,
                        "configuration_changed"
                    );
                    scheduleConfigurationRefresh(
                        activity,
                        configuration.orientation,
                        0
                    );
                }
            }
        );

        XposedHelpers.findAndHookMethod(
            TARGET_ACTIVITY,
            loadPackageParam.classLoader,
            "dispatchTouchEvent",
            MotionEvent.class,
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    Activity activity = (Activity) param.thisObject;
                    MotionEvent event = (MotionEvent) param.args[0];
                    traceTouchEvent(activity, event);
                    if (blockPageActivationUiInput(activity, event)) {
                        param.setResult(true);
                        return;
                    }
                    SpreadConfig config = spreadConfig(activity);
                    if (isCalibrationLandscape(activity)
                        && config != null
                        && !config.editable
                        && event != null
                        && event.getPointerCount() > 0
                        && (event.getToolType(0) == MotionEvent.TOOL_TYPE_STYLUS
                            || event.getToolType(0)
                                == MotionEvent.TOOL_TYPE_ERASER)) {
                        param.setResult(true);
                        return;
                    }
                    if (isEditableSpreadLandscape(activity)
                        && event != null
                        && event.getPointerCount() > 0
                        && event.getToolType(0) == MotionEvent.TOOL_TYPE_STYLUS
                        && event.getActionMasked() == MotionEvent.ACTION_DOWN
                        && XposedHelpers.getIntField(activity, "selectModel") >= 0) {
                        setTextSelectionHardwareGate(
                            activity,
                            true,
                            "stylus_down"
                        );
                    }
                    trackFingerTapNavigation(activity, event);
                    if (handlePageActivationTouch(activity, event)) {
                        param.setResult(true);
                    }
                }
            }
        );

        /*
         * The low-latency writer receives pen input outside
         * Activity.dispatchTouchEvent(), but NativeEventCallBack still reports
         * the physical pen position while the stylus is hovering and again on
         * the first contact frame. Activate the page under the pen from that
         * native signal so receiveTrials() commits the stroke to the page the
         * user actually wrote on rather than to the previously active page.
         */
        XposedHelpers.findAndHookMethod(
            "com.supernote.document.document.DocumentActivity$6",
            loadPackageParam.classLoader,
            "onDigitalPosition",
            int.class,
            int.class,
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    ACTIVE_PAGE_STROKE_TERMINAL_CLEANUP.remove();
                    Activity activity = activeActivity;
                    if (activity == null) {
                        return;
                    }
                    int pressure = -1;
                    try {
                        Object callback = XposedHelpers.getObjectField(
                            activity,
                            "eventCallBack"
                        );
                        pressure = XposedHelpers.getIntField(
                            callback,
                            "mPressure"
                        );
                    } catch (Throwable ignored) {
                    }
                    PenInputSnapshot inputSnapshot =
                        penInputSnapshot(activity);
                    if (pressure > 0) {
                        synchronized (PAGE_ACTIVATION_OWNERSHIP_LOCK) {
                            PageActivationTransaction ownershipTransaction =
                                PAGE_ACTIVATION_TRANSACTIONS.get(activity);
                            if (ownershipTransaction != null) {
                                // Latch the held contact under the same lock
                                // used by final commit/removal. The later
                                // interceptor repeats this defensively, but
                                // commit can never miss this first frame.
                                ownershipTransaction.triggerContactObserved =
                                    true;
                                ownershipTransaction.triggerPenLifted = false;
                            }
                            if (inputSnapshot != null
                                && inputSnapshot.editable
                                && inputSnapshot.geometryReady
                                && PEN_CONTACT_START_PAGES.get(activity)
                                    == null) {
                                int mappedContactPage = pageAt(
                                    inputSnapshot,
                                    ((Integer) param.args[0]).intValue(),
                                    ((Integer) param.args[1]).intValue()
                                );
                                // A contact may begin in the divider or a
                                // cropped margin. Do not permanently latch
                                // that unmapped -1; keep watching until the
                                // held gesture first reaches a real page so
                                // cross-divider ownership stays bound to that
                                // page through pen-up.
                                if (mappedContactPage >= 0) {
                                    PEN_CONTACT_START_PAGES.put(
                                        activity,
                                        Integer.valueOf(mappedContactPage)
                                    );
                                }
                            } else if (PEN_CONTACT_START_PAGES.get(activity)
                                    == null
                                && publishedEditablePenInputLandscape(
                                    activity
                                )) {
                                // Geometry/config publication is between
                                // verified states. Bind this entire physical
                                // gesture to a fail-closed sentinel so a later
                                // ready snapshot cannot admit only its tail.
                                PEN_CONTACT_START_PAGES.put(
                                    activity,
                                    Integer.valueOf(PEN_CONTACT_BLOCKED_PAGE)
                                );
                                queueLowLatencyLog(
                                    "pen_contact_guard_latched"
                                        + " start=blocked_pending_geometry"
                                );
                            }
                        }
                    }
                    Integer contactStartPage =
                        PEN_CONTACT_START_PAGES.get(activity);
                    boolean completingActivePageStroke =
                        isCompletingActivePageStroke(
                            activity,
                            inputSnapshot,
                            pressure
                        );
                    tracePenPosition(
                        activity,
                        inputSnapshot,
                        ((Integer) param.args[0]).intValue(),
                        ((Integer) param.args[1]).intValue(),
                        pressure
                    );
                    if (interceptPenPageActivation(
                            activity,
                            ((Integer) param.args[0]).intValue(),
                            ((Integer) param.args[1]).intValue(),
                            pressure,
                            inputSnapshot
                        )) {
                        // The native callback must not see any point belonging
                        // to a gesture that initiated or overlaps an ownership
                        // transfer.  The user lifts and starts a fresh stroke
                        // only after the target page owns the writer.
                        param.setResult(null);
                    }
                    if (completingActivePageStroke) {
                        ACTIVE_PAGE_STROKE_TERMINAL_CLEANUP.set(activity);
                        queueLowLatencyLog(
                            "page_activation_active_stroke_terminal_preserved"
                                + " page=" + contactStartPage
                                + " point=" + param.args[0]
                                + "," + param.args[1]
                        );
                    } else {
                        handlePenPageActivation(
                            activity,
                            ((Integer) param.args[0]).intValue(),
                            ((Integer) param.args[1]).intValue(),
                            pressure,
                            inputSnapshot
                        );
                    }
                    if (pressure == 0 && !completingActivePageStroke) {
                        clearPenContactStartPage(
                            activity,
                            "position_pressure_zero"
                        );
                    }
                }

                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    Activity activity =
                        ACTIVE_PAGE_STROKE_TERMINAL_CLEANUP.get();
                    ACTIVE_PAGE_STROKE_TERMINAL_CLEANUP.remove();
                    if (activity != null) {
                        clearPenContactStartPage(
                            activity,
                            "position_pressure_zero_after_native"
                        );
                    }
                }
            }
        );

        XposedHelpers.findAndHookMethod(
            "com.supernote.document.document.DocumentActivity$6",
            loadPackageParam.classLoader,
            "onDigital",
            int.class,
            new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    int state = ((Integer) param.args[0]).intValue();
                    if (state == 1) {
                        return;
                    }
                    Activity activity = activeActivity;
                    tracePenLeftScreen(activity, state);
                    if (activity != null) {
                        activity.runOnUiThread(new Runnable() {
                            @Override
                            public void run() {
                                markPageActivationPenLifted(
                                    activity,
                                    "digital_state:" + state
                                );
                                clearPenContactStartPage(
                                    activity,
                                    "digital_state:" + state
                                );
                                cancelPendingPenPageActivation(
                                    activity,
                                    "pen_left_screen"
                                );
                            }
                        });
                    }
                }
            }
        );

        /*
         * DocumentActivity performs a one-shot writable-area refresh on the
         * first pen-down after opening a document. During deferred inactive-
         * page activation its DocumentViewModel still intentionally points at
         * the visible original page, so that refresh replaces the target-page
         * geometry prepared from the preceding hover frame and drops the
         * stroke. Keep the prepared region intact for this one narrow state;
         * returning true preserves the caller's normal sendWritable(true).
         */
        XposedHelpers.findAndHookMethod(
            "com.supernote.document.document.DocumentActivity",
            loadPackageParam.classLoader,
            "sendDisableWriteAreaNotRefreshBitmap",
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    Activity activity = activeActivity;
                    Integer target = activity == null
                        ? null
                        : PEN_ACTIVATION_TARGETS.get(activity);
                    if (target == null
                        || !isEditableSpreadLandscape(activity)) {
                        return;
                    }
                    param.setResult(Boolean.TRUE);
                    log("pen_activation_disable_area_refresh_bypassed target="
                        + target);
                }
            }
        );

        /*
         * The Nomad's low-latency pen service does not consistently route
         * stylus events through Activity.dispatchTouchEvent().  In read-only
         * mode, enforce the disabled region at the HandWriteClient boundary
         * instead.  This also prevents toolbar state changes from silently
         * replacing the full-screen disabled rectangle with a writable one.
         */
        XposedHelpers.findAndHookMethod(
            "com.supernote.document.handwrite.HandWriteClient",
            loadPackageParam.classLoader,
            "sendDisableAreaInfo",
            List.class,
            boolean.class,
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    Activity activity = activeActivity;
                    if (!isReadOnlyNativeMode(activity)) {
                        return;
                    }
                    ArrayList<Rect> disabled = new ArrayList<>();
                    disabled.add(new Rect(
                        0,
                        0,
                        CANONICAL_PAGE_WIDTH,
                        CANONICAL_PAGE_HEIGHT
                    ));
                    param.args[0] = disabled;
                    param.args[1] = Boolean.TRUE;
                    log("read_only_disable_area_forced size="
                        + CANONICAL_PAGE_WIDTH + "x"
                        + CANONICAL_PAGE_HEIGHT);
                }
            }
        );

        /*
         * Persistence fail-safe. If firmware or the native writer ever lets
         * a low-latency trail through despite the disabled region, do not let
         * HandWritePresenter create or mutate the document's .mark file.
         */
        XposedHelpers.findAndHookMethod(
            "com.supernote.document.handwrite.HandWritePresenter",
            loadPackageParam.classLoader,
            "receiveTrials",
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    if (!isReadOnlyNativeMode(activeActivity)) {
                        return;
                    }
                    param.setResult(null);
                    log("read_only_receive_trials_blocked");
                }
            }
        );

        /*
         * A full-screen disabled rectangle is normally enough to suppress the
         * low-latency pen trail while selecting PDF text. In the probe's
         * half-page DrawPath geometry that rectangle is interpreted in the
         * virtual page coordinate space, leaving part of the physical screen
         * writable. Suspend the hardware writer outright during text
         * selection; the correctly mapped Java overlay remains available.
         */
        XposedHelpers.findAndHookMethod(
            TARGET_ACTIVITY,
            loadPackageParam.classLoader,
            "changeSelectTextModel",
            int.class,
            new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    Activity activity = (Activity) param.thisObject;
                    if (!isEditableSpreadLandscape(activity)) {
                        return;
                    }
                    int model = ((Integer) param.args[0]).intValue();
                    setTextSelectionHardwareGate(
                        activity,
                        model >= 0,
                        "model_changed:" + model
                    );
                }
            }
        );

        XposedHelpers.findAndHookMethod(
            "com.supernote.document.document.DocumentViewModel",
            loadPackageParam.classLoader,
            "turnPage",
            int.class,
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    Activity activity = activeActivity;
                    if (activity == null || !isCalibrationFile(activity)) {
                        return;
                    }
                    int offset = ((Integer) param.args[0]).intValue();
                    if (isCalibrationLandscape(activity)) {
                        if (offset != 0
                            && shouldSuppressNonEdgeTapTurn(activity)) {
                            log("rtl_spread_turn_suppressed reason=non_edge_tap"
                                + " current="
                                + currentDocumentPage(activity));
                            param.setResult(null);
                            return;
                        }
                        if (handleRtlSpreadTurn(
                            activity,
                            param.thisObject,
                            offset
                        )) {
                            param.setResult(null);
                        }
                        return;
                    }
                    if (activity.getResources().getConfiguration().orientation
                        == Configuration.ORIENTATION_PORTRAIT
                        && offset != 0) {
                        param.args[0] = -offset;
                        log("rtl_portrait_turn_reversed native_offset="
                            + offset + " adjusted_offset=" + (-offset)
                            + " current=" + currentDocumentPage(activity));
                    }
                }
            }
        );

        XposedHelpers.findAndHookMethod(
            "com.supernote.document.document.DocumentViewModel",
            loadPackageParam.classLoader,
            "checkLink",
            Point.class,
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    Activity activity = activeActivity;
                    Point input = (Point) param.args[0];
                    if (activity == null || input == null
                        || !isCalibrationLandscape(activity)) {
                        return;
                    }
                    try {
                        RectF destination = activePageDestination(activity);
                        RectF visibleBounds = activePageVisibleBounds(activity);
                        if (destination == null
                            || visibleBounds == null
                            || !visibleBounds.contains(input.x, input.y)) {
                            log("link_remap_skipped point="
                                + pointDescription(input)
                                + " destination="
                                + rectDescription(destination)
                                + " visible="
                                + rectDescription(visibleBounds));
                            return;
                        }
                        Object pageInfo = XposedHelpers.getObjectField(
                            param.thisObject,
                            "pageInfo"
                        );
                        Bitmap originBitmap = pageInfo == null
                            ? null
                            : (Bitmap) XposedHelpers.callMethod(
                                pageInfo,
                                "getOriginBitmap"
                            );
                        if (!usable(originBitmap)) {
                            log("link_remap_skipped unusable_origin");
                            return;
                        }
                        int mappedX = Math.round(
                            (input.x - destination.left)
                                * originBitmap.getWidth()
                                / destination.width()
                        );
                        int mappedY = Math.round(
                            (input.y - destination.top)
                                * originBitmap.getHeight()
                                / destination.height()
                        );
                        Class<?> baseApplication = Class.forName(
                            "com.supernote.document.BaseApplication",
                            false,
                            activity.getClassLoader()
                        );
                        java.lang.reflect.Field splitField =
                            baseApplication.getDeclaredField("isSplit");
                        splitField.setAccessible(true);
                        boolean wasSplit = splitField.getBoolean(null);
                        LINK_SPLIT_ORIGINAL.set(Boolean.valueOf(wasSplit));
                        splitField.setBoolean(null, false);
                        param.args[0] = new Point(mappedX, mappedY);
                        log("link_remapped page="
                            + currentDocumentPage(activity)
                            + " from=" + pointDescription(input)
                            + " to=" + mappedX + "," + mappedY
                            + " destination="
                            + rectDescription(destination)
                            + " origin="
                            + originBitmap.getWidth() + "x"
                            + originBitmap.getHeight()
                            + " split_was=" + wasSplit);
                    } catch (Throwable throwable) {
                        log("link_remap_failed " + throwable);
                        XposedBridge.log(throwable);
                    }
                }

                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    Boolean wasSplit = LINK_SPLIT_ORIGINAL.get();
                    LINK_SPLIT_ORIGINAL.remove();
                    Activity activity = activeActivity;
                    if (activity != null && wasSplit != null) {
                        try {
                            Class<?> baseApplication = Class.forName(
                                "com.supernote.document.BaseApplication",
                                false,
                                activity.getClassLoader()
                            );
                            java.lang.reflect.Field splitField =
                                baseApplication.getDeclaredField("isSplit");
                            splitField.setAccessible(true);
                            splitField.setBoolean(
                                null,
                                wasSplit.booleanValue()
                            );
                        } catch (Throwable throwable) {
                            log("link_split_restore_failed " + throwable);
                            XposedBridge.log(throwable);
                        }
                    }
                    try {
                        Object result = param.getResult();
                        if (result != null) {
                            log("link_result have_link="
                                + XposedHelpers.callMethod(
                                    result,
                                    "isHaveLink"
                                )
                                + " target_page="
                                + XposedHelpers.callMethod(
                                    result,
                                    "getLinkPage"
                                ));
                        }
                    } catch (Throwable throwable) {
                        log("link_result_log_failed " + throwable);
                    }
                }
            }
        );

        /*
         * Supernote's text-selection path assumes that landscape always
         * displays one page zoomed to screen width.  In our spread that
         * scales stylus points by 1404/1872 before asking MuPDF for the
         * nearest structured-text characters, so the hit test lands well
         * above the visible text.  Recover the physical stylus coordinates
         * and map them through the active spread destination into the
         * untouched page-origin bitmap.  The returned MuPDF and Supernote
         * rectangles remain canonical; later hooks only adapt the transient
         * on-screen preview and menu geometry.
         */
        XposedHelpers.findAndHookMethod(
            "com.supernote.document.document.DocumentViewModel",
            loadPackageParam.classLoader,
            "highlightSelect",
            Point.class,
            Point.class,
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    Activity activity = activeActivity;
                    if (activity == null
                        || !isEditableSpreadLandscape(activity)) {
                        return;
                    }
                    try {
                        Point start = (Point) param.args[0];
                        Point end = (Point) param.args[1];
                        RectF destination = activePageDestination(activity);
                        Object pageInfo = XposedHelpers.getObjectField(
                            param.thisObject,
                            "pageInfo"
                        );
                        Bitmap originBitmap = pageInfo == null
                            ? null
                            : (Bitmap) XposedHelpers.callMethod(
                                pageInfo,
                                "getOriginBitmap"
                            );
                        ImageView imageView = (ImageView) XposedHelpers
                            .getObjectField(activity, "mImage");
                        if (start == null || end == null
                            || destination == null || !usable(originBitmap)
                            || imageView == null || imageView.getWidth() <= 0
                            || imageView.getHeight() <= 0) {
                            log("highlight_remap_skipped start="
                                + pointDescription(start)
                                + " end=" + pointDescription(end)
                                + " destination="
                                + rectDescription(destination)
                                + " origin="
                                + bitmapDescription(originBitmap));
                            return;
                        }

                        float nativeInputScale =
                            (float) imageView.getHeight()
                                / (float) imageView.getWidth();
                        RectF showRect = (RectF) XposedHelpers.callMethod(
                            param.thisObject,
                            "getShowRect"
                        );
                        float nativeOffsetX = 0.0f;
                        float nativeOffsetY = 0.0f;
                        if (showRect != null) {
                            if (originBitmap.getWidth()
                                > originBitmap.getHeight()) {
                                nativeOffsetX = showRect.left;
                            } else {
                                nativeOffsetY = showRect.top;
                            }
                        }

                        Point mappedStart = mapNativeSplitSelectionPoint(
                            start,
                            nativeInputScale,
                            nativeOffsetX,
                            nativeOffsetY,
                            destination,
                            originBitmap.getWidth(),
                            originBitmap.getHeight()
                        );
                        Point mappedEnd = mapNativeSplitSelectionPoint(
                            end,
                            nativeInputScale,
                            nativeOffsetX,
                            nativeOffsetY,
                            destination,
                            originBitmap.getWidth(),
                            originBitmap.getHeight()
                        );
                        param.args[0] = mappedStart;
                        param.args[1] = mappedEnd;
                        log("highlight_remapped page="
                            + currentDocumentPage(activity)
                            + " start=" + pointDescription(start)
                            + "->" + pointDescription(mappedStart)
                            + " end=" + pointDescription(end)
                            + "->" + pointDescription(mappedEnd)
                            + " destination="
                            + rectDescription(destination)
                            + " origin=" + originBitmap.getWidth() + "x"
                            + originBitmap.getHeight()
                            + " native_scale=" + nativeInputScale
                            + " native_offset=" + nativeOffsetX + ","
                            + nativeOffsetY);
                    } catch (Throwable throwable) {
                        log("highlight_remap_failed " + throwable);
                        XposedBridge.log(throwable);
                    }
                }

                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    if (activeActivity == null
                        || !isEditableSpreadLandscape(activeActivity)) {
                        return;
                    }
                    try {
                        Object bean = param.getResult();
                        Object rects = bean == null
                            ? null
                            : XposedHelpers.callMethod(bean, "getRectList");
                        Object mupdfRects = bean == null
                            ? null
                            : XposedHelpers.callMethod(
                                bean,
                                "getMupdfRectList"
                            );
                        log("highlight_result page="
                            + currentDocumentPage(activeActivity)
                            + " rect_count=" + listSize(rects)
                            + " mupdf_count=" + listSize(mupdfRects));
                    } catch (Throwable throwable) {
                        log("highlight_result_log_failed " + throwable);
                    }
                }
            }
        );

        /* Map the live native selection frame into the active spread slot. */
        XposedHelpers.findAndHookMethod(
            TARGET_ACTIVITY,
            loadPackageParam.classLoader,
            "handWriteSelectText",
            int.class,
            List.class,
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    Activity activity = (Activity) param.thisObject;
                    int state = ((Integer) param.args[0]).intValue();
                    if (!isEditableSpreadLandscape(activity)) {
                        return;
                    }
                    try {
                        ImageView documentImage = (ImageView) XposedHelpers
                            .getObjectField(activity, "mImage");
                        if (state == 0 || state == 1) {
                            if (documentImage != null) {
                                setPublicField(
                                    documentImage,
                                    "highlightRectList",
                                    new ArrayList<Rect>()
                                );
                                documentImage.invalidate();
                            }
                            param.setResult(null);
                            log("highlight_hardware_protocol_suppressed state="
                                + state + " page="
                                + currentDocumentPage(activity));
                            return;
                        }
                        if (state == 3) {
                            /*
                             * Supernote's low-latency selectPdfText protocol
                             * keeps its own rotation/slot transform.  Its
                             * DOWN/MOVE/UP preview cannot represent two page
                             * destinations at once, so suppress the whole
                             * protocol in spread mode.  The Java selection
                             * overlay and canonical MuPDF/SN rectangles still
                             * drive the final menu and persisted annotation.
                             */
                            param.setResult(null);
                            log("highlight_hardware_protocol_suppressed state=3"
                                + " page=" + currentDocumentPage(activity));
                            return;
                        }
                        if (state != 2) {
                            return;
                        }
                        @SuppressWarnings("unchecked")
                        List<Rect> displaySource = (List<Rect>) XposedHelpers
                            .getObjectField(
                                activity,
                                "mImageDisplayHighlightList"
                            );
                        List<Rect> previewRects = copyRects(displaySource);
                        Rect sourceFirst = previewRects.isEmpty()
                            ? null : new Rect(previewRects.get(0));
                        /*
                         * The state-2 argument has already been rotated for
                         * HandWriteClient and is therefore unsuitable for an
                         * Android Canvas overlay.  The final, known-good
                         * DocumentImageView path instead starts from
                         * mImageDisplayHighlightList, applies Supernote's
                         * split-mode 4/3 expansion on pen-up, and then reaches
                         * our invalidateHighlight hook. Reproduce that same
                         * pipeline for each live MOVE frame.
                         */
                        scaleRects(previewRects, 1.3333334f);
                        Rect expandedFirst = previewRects.isEmpty()
                            ? null : new Rect(previewRects.get(0));
                        if (mapNativeDisplayRectsToSpread(
                            activity,
                            previewRects
                        )) {
                            /*
                             * HandWriteClient applies the active handwriting
                             * slot transform a second time.  That made the
                             * right-page live preview flash on the left even
                             * though the final Java overlay was correct. Draw
                             * the already-mapped rectangles in DocumentImageView
                             * and skip the native hardware-preview protocol.
                             * Supernote's canonical text-selection data and
                             * final menu remain untouched.
                             */
                            if (documentImage != null) {
                                setPublicField(
                                    documentImage,
                                    "highlightRectList",
                                    previewRects
                                );
                                documentImage.invalidate();
                            }
                            param.setResult(null);
                            log("highlight_preview_drawn_by_probe page="
                                + currentDocumentPage(activity)
                                + " rect_count=" + previewRects.size()
                                + " source=" + rectDescription(sourceFirst)
                                + " expanded="
                                + rectDescription(expandedFirst)
                                + " display=" + rectDescription(
                                    previewRects.isEmpty()
                                        ? null : previewRects.get(0)
                                ));
                        } else {
                            param.setResult(null);
                            log("highlight_preview_suppressed_no_geometry page="
                                + currentDocumentPage(activity)
                                + " rect_count=" + previewRects.size());
                        }
                    } catch (Throwable throwable) {
                        log("highlight_preview_remap_failed " + throwable);
                        XposedBridge.log(throwable);
                    }
                }

                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    Activity activity = (Activity) param.thisObject;
                    int state = ((Integer) param.args[0]).intValue();
                    if (state == 0 && isEditableSpreadLandscape(activity)
                        && XposedHelpers.getIntField(activity, "selectModel") >= 0) {
                        setTextSelectionHardwareGate(
                            activity,
                            true,
                            "selection_down"
                        );
                    }
                }
            }
        );

        /*
         * The text-selection menu computes its anchor from the canonical
         * Supernote rectangles and then applies the same full-width split
         * transform.  Temporarily pre-compensate only while the menu is laid
         * out, then restore the canonical rectangles before any native
         * highlight/underline action can persist them.
         */
        XposedHelpers.findAndHookMethod(
            TARGET_ACTIVITY,
            loadPackageParam.classLoader,
            "showSelectTextPopView",
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    Activity activity = (Activity) param.thisObject;
                    if (!isEditableSpreadLandscape(activity)) {
                        return;
                    }
                    try {
                        @SuppressWarnings("unchecked")
                        List<Rect> rects = (List<Rect>) XposedHelpers
                            .getObjectField(
                                activity,
                                "snRectListBySelectText"
                            );
                        List<Rect> originals = copyRects(rects);
                        if (precompensateSelectMenuRects(activity, rects)) {
                            SELECT_POP_RECT_ORIGINALS.set(originals);
                            log("highlight_menu_anchor_remapped page="
                                + currentDocumentPage(activity)
                                + " rect_count=" + rects.size());
                        }
                    } catch (Throwable throwable) {
                        SELECT_POP_RECT_ORIGINALS.remove();
                        log("highlight_menu_anchor_failed " + throwable);
                        XposedBridge.log(throwable);
                    }
                }

                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    List<Rect> originals =
                        SELECT_POP_RECT_ORIGINALS.get();
                    SELECT_POP_RECT_ORIGINALS.remove();
                    if (originals == null) {
                        return;
                    }
                    try {
                        @SuppressWarnings("unchecked")
                        List<Rect> rects = (List<Rect>) XposedHelpers
                            .getObjectField(
                                param.thisObject,
                                "snRectListBySelectText"
                            );
                        replaceRects(rects, originals);
                        log("highlight_menu_canonical_restored rect_count="
                            + rects.size());
                    } catch (Throwable throwable) {
                        log("highlight_menu_restore_failed " + throwable);
                        XposedBridge.log(throwable);
                    }
                }
            }
        );

        /* Correct the dark selection overlay drawn by DocumentImageView. */
        XposedHelpers.findAndHookMethod(
            "com.supernote.document.utils.view.DocumentImageView",
            loadPackageParam.classLoader,
            "invalidateHighlight",
            List.class,
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    Activity activity = activeActivity;
                    if (activity == null
                        || !isEditableSpreadLandscape(activity)) {
                        return;
                    }
                    try {
                        @SuppressWarnings("unchecked")
                        List<Rect> rects = (List<Rect>) param.args[0];
                        if (mapNativeDisplayRectsToSpread(activity, rects)) {
                            log("highlight_overlay_remapped page="
                                + currentDocumentPage(activity)
                                + " rect_count=" + rects.size());
                        }
                    } catch (Throwable throwable) {
                        log("highlight_overlay_remap_failed " + throwable);
                        XposedBridge.log(throwable);
                    }
                }
            }
        );

        /*
         * Native highlights and underlines are drawn in a separate digest
         * ImageView.  Supernote trims that bitmap to its ordinary landscape
         * half-page viewport, which makes annotations in the lower half of
         * our full-page spread disappear after the selection overlay closes.
         * Rebuild the digest layer from the native annotation beans for both
         * visible pages and map their canonical RN rectangles into the two
         * spread destinations.  The stored annotation/MuPDF data is never
         * modified.
         */
        XposedHelpers.findAndHookMethod(
            TARGET_ACTIVITY,
            loadPackageParam.classLoader,
            "setDigestImage",
            Bitmap.class,
            new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    Activity activity = (Activity) param.thisObject;
                    if (!isCalibrationLandscape(activity)) {
                        releaseDigestComposite(activity);
                        return;
                    }
                    applySpreadDigestOverlay(
                        activity,
                        "native_set_digest"
                    );
                }
            }
        );

        XposedHelpers.findAndHookMethod(
            TARGET_ACTIVITY,
            loadPackageParam.classLoader,
            "setImage",
            Bitmap.class,
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    SET_IMAGE_ACTIVE_BITMAP.remove();
                    SET_IMAGE_VIEW_SUPPRESSED.remove();
                    Activity activity = (Activity) param.thisObject;
                    if (!isCalibrationLandscape(activity)) {
                        return;
                    }
                    Bitmap activeBitmap = (Bitmap) param.args[0];
                    SET_IMAGE_ACTIVE_BITMAP.set(activeBitmap);
                    Bitmap previousComposite = COMPOSITES.get(activity);
                    if (!usable(previousComposite)) {
                        return;
                    }
                    SET_IMAGE_VIEW_SUPPRESSED.set(Boolean.TRUE);
                    log("transition_native_frame_held source="
                        + bitmapDescription(activeBitmap)
                        + " previous="
                        + bitmapDescription(previousComposite));
                }

                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    Activity activity = (Activity) param.thisObject;
                    Bitmap activeBitmap = SET_IMAGE_ACTIVE_BITMAP.get();
                    boolean nativeImageSuppressed = Boolean.TRUE.equals(
                        SET_IMAGE_VIEW_SUPPRESSED.get()
                    );
                    SET_IMAGE_ACTIVE_BITMAP.remove();
                    SET_IMAGE_VIEW_SUPPRESSED.remove();
                    if (activeBitmap == null) {
                        activeBitmap = (Bitmap) param.args[0];
                    }
                    if (!isCalibrationLandscape(activity)) {
                        finishPageActivationRollbackIfConverged(
                            activity,
                            "set_image_non_landscape"
                        );
                        updateNativeEraserGate(
                            activity,
                            "set_image_non_calibration_landscape"
                        );
                        restorePortraitPresentation(activity);
                        removeOverlay(activity);
                        return;
                    }
                    updateNativeEraserGate(activity, "set_image_landscape");
                    int generation = GENERATION.incrementAndGet();
                    log("set_image generation=" + generation + " active="
                        + bitmapDescription(activeBitmap));
                    Bitmap previousComposite = COMPOSITES.get(activity);
                    if (usable(previousComposite)) {
                        if (!nativeImageSuppressed) {
                            ImageView imageView = (ImageView) XposedHelpers
                                .getObjectField(activity, "mImage");
                            imageView.setScaleType(ImageView.ScaleType.FIT_XY);
                            imageView.setImageBitmap(previousComposite);
                            imageView.invalidate();
                        }
                        log("transition_spread_preserved generation="
                            + generation + " previous="
                            + bitmapDescription(previousComposite)
                            + " native_submission_suppressed="
                            + nativeImageSuppressed);
                    }
                    scheduleCompose(activity, activeBitmap, generation, 0);
                }
            }
        );

        XposedHelpers.findAndHookMethod(
            TARGET_ACTIVITY,
            loadPackageParam.classLoader,
            "onDestroy",
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    Activity activity = (Activity) param.thisObject;
                    updateNativeEraserGate(
                        activity,
                        "activity_destroyed",
                        false
                    );
                }

                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    Activity activity = (Activity) param.thisObject;
                    releaseActivityResources(activity);
                }
            }
        );

        XposedHelpers.findAndHookMethod(
            "com.supernote.document.handwrite.HandWritePresenter",
            loadPackageParam.classLoader,
            "resetShowRect",
            Bitmap.class,
            RectF.class,
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    Activity tracedActivity = activeActivity;
                    Bitmap tracedSource = (Bitmap) param.args[0];
                    traceEvent(
                        tracedActivity,
                        "handwrite_bitmap_submitted",
                        "source",
                        bitmapDescription(tracedSource),
                        "replaceActiveSlot",
                        tracedActivity != null
                            && shouldReplaceActiveInkSlot(tracedActivity),
                        "canonicalOnly",
                        tracedActivity != null && Boolean.TRUE.equals(
                            CANONICAL_ONLY_INK_MODES.get(tracedActivity)
                        )
                    );
                    if (Boolean.TRUE.equals(
                        PEN_ACTIVATION_MARK_PRIMING.get()
                    )) {
                        return;
                    }
                    Activity activity = activeActivity;
                    Bitmap fullBitmap = (Bitmap) param.args[0];
                    if (activity == null || !isCalibrationLandscape(activity)
                        || !usable(fullBitmap)) {
                        return;
                    }
                    Bitmap copy = Bitmap.createBitmap(fullBitmap);
                    Bitmap previous = FULL_INK_BITMAPS.put(activity, copy);
                    if (previous != null && previous != copy
                        && !previous.isRecycled()) {
                        previous.recycle();
                    }
                    log("full_ink_captured_before_trim source="
                        + bitmapDescription(fullBitmap)
                        + " copy=" + bitmapDescription(copy));
                }
            }
        );

        XposedHelpers.findAndHookMethod(
            "com.supernote.document.handwrite.HandWriteView",
            loadPackageParam.classLoader,
            "setBitmap",
            Bitmap.class,
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    if (Boolean.TRUE.equals(
                        PEN_ACTIVATION_MARK_PRIMING.get()
                    )) {
                        param.setResult(null);
                        log("pen_activation_mark_bitmap_suppressed");
                        return;
                    }
                    if (Boolean.TRUE.equals(
                        COMMITTED_INK_ALREADY_SPREAD.get()
                    )) {
                        return;
                    }
                    Activity activity = activeActivity;
                    Bitmap source = (Bitmap) param.args[0];
                    if (activity == null || source == null
                        || !isCalibrationLandscape(activity)) {
                        return;
                    }
                    RectF destination = activePageDestination(activity);
                    if (destination == null || !usable(source)) {
                        log("committed_ink_waiting destination="
                            + rectDescription(destination)
                            + " source=" + bitmapDescription(source));
                        return;
                    }

                    boolean readOnly = isReadOnlyNativeMode(activity);
                    boolean replaceActiveSlot = shouldReplaceActiveInkSlot(
                        activity
                    );
                    boolean canonicalOnly = !readOnly
                        && (Boolean.TRUE.equals(
                            CANONICAL_ONLY_INK_MODES.get(activity)
                        ) || Boolean.TRUE.equals(
                            FORCE_CANONICAL_ACTIVE_INK.get()
                        ));
                    Bitmap transformed = readOnly || canonicalOnly
                        ? renderCanonicalCommittedInk(activity)
                        : renderCombinedCommittedInk(
                            activity,
                            replaceActiveSlot
                        );
                    if (canonicalOnly && transformed != null) {
                        log("committed_ink_canonical_only reason=eraser"
                            + " active_page="
                            + (currentDocumentPage(activity) + 1));
                    }
                    if (transformed == null && !readOnly) {
                        transformed = transformCommittedInkFallback(
                            source,
                            destination,
                            activity
                        );
                    }
                    if (transformed == null) {
                        return;
                    }
                    param.args[0] = transformed;
                    Bitmap previous = COMMITTED_INK_COMPOSITES.put(
                        activity,
                        transformed
                    );
                    if (previous != null && previous != transformed
                        && !previous.isRecycled()) {
                        previous.recycle();
                    }
                }
            }
        );

        XposedHelpers.findAndHookMethod(
            "com.supernote.document.handwrite.HandWritePresenter",
            loadPackageParam.classLoader,
            "setHandWriteRotation",
            String.class,
            new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    Activity activity = activeActivity;
                    if (activity == null
                        || !isEditableSpreadLandscape(activity)) {
                        return;
                    }
                    applySpreadMarkGeometry(
                        activity,
                        param.thisObject,
                        "before_mark_load:" + param.args[0]
                    );
                }
            }
        );

        XposedHelpers.findAndHookMethod(
            "com.supernote.document.handwrite.HandWritePresenter",
            loadPackageParam.classLoader,
            "setAreaSelection",
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    if (activeActivity != null) {
                        TRACE_TOOLS.put(activeActivity, "lasso");
                    }
                    setReplaceActiveInkMode(
                        activeActivity,
                        true,
                        "area_selection"
                    );
                }

                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    Activity activity = activeActivity;
                    if (activity == null
                        || !isEditableSpreadLandscape(activity)) {
                        return;
                    }
                    Object presenter = param.thisObject;
                    RectF writable = resolveActivePageDestination(
                        activity,
                        presenter
                    );
                    ImageView imageView = (ImageView) XposedHelpers
                        .getObjectField(activity, "mImage");
                    int outputWidth = imageView == null
                        ? 0
                        : imageView.getWidth();
                    int outputHeight = imageView == null
                        ? 0
                        : imageView.getHeight();
                    spreadLassoToolArmed = writable != null
                        && sendCalibrationGeometry(
                            presenter,
                            writable,
                            outputWidth,
                            outputHeight
                        );
                    log("lasso_native_armed page="
                        + XposedHelpers.getIntField(
                            presenter,
                            "currentPage"
                        ) + " half_page_geometry="
                        + spreadLassoToolArmed);
                }
            }
        );

        XposedHelpers.findAndHookMethod(
            "com.supernote.document.handwrite.HandWritePresenter",
            loadPackageParam.classLoader,
            "setPen",
            int.class,
            int.class,
            int.class,
            new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    if (activeActivity != null) {
                        TRACE_TOOLS.put(
                            activeActivity,
                            "pen:" + param.args[0] + ":" + param.args[2]
                        );
                    }
                    setReplaceActiveInkMode(
                        activeActivity,
                        false,
                        "pen"
                    );
                    traceEvent(
                        activeActivity,
                        "tool_selected",
                        "tool",
                        "pen",
                        "penType",
                        param.args[0],
                        "color",
                        param.args[1],
                        "thickness",
                        param.args[2]
                    );
                }
            }
        );

        XposedHelpers.findAndHookMethod(
            "com.supernote.document.handwrite.HandWritePresenter",
            loadPackageParam.classLoader,
            "sendEraserInfo",
            int.class,
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    Activity activity = activeActivity;
                    int eraserType = (Integer) param.args[0];
                    if (activity != null) {
                        TRACE_TOOLS.put(
                            activity,
                            "eraser:" + eraserType
                        );
                    }
                    setReplaceActiveInkMode(
                        activity,
                        true,
                        "eraser:" + eraserType
                    );
                    traceEvent(
                        activity,
                        "tool_selected",
                        "tool",
                        "eraser",
                        "eraserType",
                        eraserType
                    );
                    if (activity == null || eraserType == 2
                        || !isEditableSpreadLandscape(activity)) {
                        return;
                    }
                    prepareSpreadEraser(
                        activity,
                        param.thisObject,
                        eraserType
                    );
                }
            }
        );

        for (String methodName : new String[] {"undo", "redo"}) {
            final String mutationName = methodName;
            XposedHelpers.findAndHookMethod(
                "com.supernote.document.handwrite.HandWritePresenter",
                loadPackageParam.classLoader,
                methodName,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        PAGE_ACTIVATION_HISTORY_BLOCKED.remove();
                        Activity activity = activeActivity;
                        PageActivationTransaction transaction = activity == null
                            ? null : PAGE_ACTIVATION_TRANSACTIONS.get(activity);
                        if (transaction != null) {
                            PAGE_ACTIVATION_HISTORY_BLOCKED.set(Boolean.TRUE);
                            param.setResult(null);
                            log("page_activation_history_blocked id="
                                + transaction.id + " target="
                                + transaction.targetPage + " action="
                                + mutationName);
                            return;
                        }
                        FORCE_CANONICAL_ACTIVE_INK.set(true);
                        traceEvent(
                            activity,
                            "history_action_started",
                            "action",
                            mutationName
                        );
                        traceAnnotationBoundary(
                            activity,
                            param.thisObject,
                            mutationName + "_before",
                            false
                        );
                        log("ink_composition_force_canonical reason="
                            + mutationName);
                        if (activity != null
                            && applyPageEditHistory(
                                activity,
                                param.thisObject,
                                mutationName
                            )) {
                            param.setResult(null);
                        }
                    }

                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        if (Boolean.TRUE.equals(
                                PAGE_ACTIVATION_HISTORY_BLOCKED.get()
                            )) {
                            PAGE_ACTIVATION_HISTORY_BLOCKED.remove();
                            return;
                        }
                        try {
                            Activity activity = activeActivity;
                            if (activity != null
                                && isEditableSpreadLandscape(activity)) {
                                int markPage = XposedHelpers.getIntField(
                                    param.thisObject,
                                    "currentPage"
                                );
                                saveTrailsForCanonicalReload(
                                    param.thisObject,
                                    "undo_redo:" + mutationName
                                );
                                XposedHelpers.callMethod(
                                    param.thisObject,
                                    "loadHandWrite",
                                    markPage
                                );
                                log("undo_redo_saved_before_canonical_reload"
                                    + " action=" + mutationName
                                    + " mark_page=" + markPage);
                            }
                            traceAnnotationBoundary(
                                activity,
                                param.thisObject,
                                mutationName + "_after",
                                true
                            );
                        } catch (Throwable throwable) {
                            log("undo_redo_canonical_reload_failed action="
                                + mutationName + " " + throwable);
                            XposedBridge.log(throwable);
                        } finally {
                            FORCE_CANONICAL_ACTIVE_INK.remove();
                        }
                    }
                }
            );
        }

        XposedHelpers.findAndHookMethod(
            "com.supernote.document.handwrite.HandWritePresenter",
            loadPackageParam.classLoader,
            "loadHandWrite",
            int.class,
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    if (traceSession == null) {
                        return;
                    }
                    traceEvent(
                        activeActivity,
                        "load_handwrite_started",
                        "requestedMarkPage",
                        param.args[0]
                    );
                }

                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    Activity activity = activeActivity;
                    if (activity != null) {
                        registerPendingPageEditHistory(
                            activity,
                            param.thisObject,
                            ((Integer) param.args[0]).intValue()
                        );
                        traceAnnotationBoundary(
                            activity,
                            param.thisObject,
                            "load_handwrite_after",
                            false
                        );
                    }
                }
            }
        );

        /*
         * Diagnostic-only trail snapshots for the disposable calibration PDF.
         * They let us compare the coordinates loaded from the .mark file with
         * the eraser gesture returned by DrawPath.  No trail is modified.
         */
        XposedHelpers.findAndHookMethod(
            "com.example.libsupernote.SuperNoteNote",
            loadPackageParam.classLoader,
            "loadMarkData",
            String.class,
            int.class,
            Bitmap.class,
            boolean.class,
            new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    Activity activity = activeActivity;
                    if (activity == null
                        || !isEditableSpreadLandscape(activity)) {
                        return;
                    }
                    dumpTrailState(
                        activity,
                        param.thisObject,
                        "after_load_mark_data",
                        (Integer) param.args[1],
                        null
                    );
                    Object presenter = XposedHelpers.getObjectField(
                        activity,
                        "handWritePresenter"
                    );
                    traceAnnotationBoundary(
                        activity,
                        presenter,
                        "load_mark_data_after",
                        false
                    );
                }
            }
        );

        XposedHelpers.findAndHookMethod(
            "com.example.libsupernote.SuperNoteNote",
            loadPackageParam.classLoader,
            "getTrailContainer",
            String.class,
            String.class,
            String.class,
            String.class,
            int.class,
            int.class,
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    Activity activity = activeActivity;
                    if (!spreadLassoToolArmed || activity == null
                        || !isEditableSpreadLandscape(activity)) {
                        return;
                    }
                    spreadLassoOriginZero = false;
                    log("lasso_native_before_get armed=true"
                        + " half_page_input=true canonical_resubmit=true page="
                        + param.args[4]);
                }

                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    Activity activity = activeActivity;
                    if (activity == null
                        || !isEditableSpreadLandscape(activity)) {
                        return;
                    }
                    Object result = param.getResult();
                    boolean prepared = false;
                    if (result instanceof List) {
                        traceOperationTrails(
                            activity,
                            "trail_container_returned",
                            (List<?>) result
                        );
                        capturePendingPenActivationTrails(
                            activity,
                            (Integer) param.args[4],
                            (List<?>) result
                        );
                        prepared = prepareNativeSpreadLasso(
                            param.thisObject,
                            (List<?>) result
                        );
                    }
                    if (!prepared && spreadLassoOriginZero) {
                        restoreSpreadLassoOrigin(
                            param.thisObject,
                            "lasso_native_no_operation"
                        );
                    }
                    dumpTrailState(
                        activity,
                        param.thisObject,
                        "after_get_trail_container",
                        (Integer) param.args[4],
                        result instanceof List ? (List<?>) result : null
                    );
                }
            }
        );

        XposedHelpers.findAndHookMethod(
            "com.example.libsupernote.SuperNoteNote",
            loadPackageParam.classLoader,
            "modifyPageTrailsFromFile",
            String.class,
            int.class,
            List.class,
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    if (traceSession == null) {
                        return;
                    }
                    traceOperationTrails(
                        activeActivity,
                        "modify_page_trails_started",
                        "replacementTrails",
                        (List<?>) param.args[2],
                        "markPath",
                        param.args[0],
                        "markPage",
                        param.args[1]
                    );
                }

                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    Activity activity = activeActivity;
                    traceEvent(
                        activity,
                        "modify_page_trails_finished",
                        "markPath",
                        param.args[0],
                        "markPage",
                        param.args[1],
                        "result",
                        param.getResult(),
                        "throwable",
                        String.valueOf(param.getThrowable())
                    );
                    Object presenter = activity == null ? null
                        : XposedHelpers.getObjectField(
                            activity,
                            "handWritePresenter"
                        );
                    traceAnnotationBoundary(
                        activity,
                        presenter,
                        "modify_page_trails_after",
                        true
                    );
                }
            }
        );

        XposedHelpers.findAndHookMethod(
            "com.example.libsupernote.SuperNoteNote",
            loadPackageParam.classLoader,
            "getRegionTrailRect",
            new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    repairSpreadLassoDisplayRect(
                        param.getResult(),
                        "region"
                    );
                }
            }
        );

        XposedHelpers.findAndHookMethod(
            "com.example.libsupernote.SuperNoteNote",
            loadPackageParam.classLoader,
            "getShiftBodyPosition",
            new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    if (spreadLassoCanonicalSelection) {
                        log("lasso_shift_body_preserved rect="
                            + jniRectDescription(param.getResult()));
                        return;
                    }
                    repairSpreadLassoDisplayRect(param.getResult(), "shift_body");
                }
            }
        );

        XposedHelpers.findAndHookMethod(
            "com.supernote.document.handwrite.HandWriteView",
            loadPackageParam.classLoader,
            "showAreaSelection",
            Bitmap.class,
            Rect.class,
            int.class,
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    if (!spreadLassoCanonicalSelection) {
                        return;
                    }
                    Rect original = (Rect) param.args[1];
                    Rect display = canonicalLassoRectToDisplay(original);
                    if (display == null) {
                        return;
                    }
                    Bitmap nativePreview = (Bitmap) param.args[0];
                    Bitmap correctedPreview = usable(
                        spreadLassoCorrectedPreview
                    )
                        ? Bitmap.createBitmap(spreadLassoCorrectedPreview)
                        : capturedLassoPreview(original);
                    if (usable(correctedPreview)) {
                        // AreaSelectionView.redrawBitmap() only pads a small
                        // selection to its 180 px minimum; it does not scale
                        // the source. Match the spread-space rectangle first
                        // so that padding cannot clip the canonical preview.
                        param.args[0] = correctedPreview.getWidth()
                            == display.width()
                            && correctedPreview.getHeight()
                            == display.height()
                            ? correctedPreview
                            : Bitmap.createScaledBitmap(
                                correctedPreview,
                                display.width(),
                                display.height(),
                                true
                            );
                    }
                    param.args[1] = display;
                    log("lasso_selection_ui_repaired rect="
                        + rectDescription(original) + "->"
                        + rectDescription(display) + " native_bitmap="
                        + bitmapDescription(nativePreview)
                        + " corrected_bitmap="
                        + bitmapDescription((Bitmap) param.args[0]));
                }
            }
        );

        XposedHelpers.findAndHookMethod(
            "com.example.libsupernote.SuperNoteNote",
            loadPackageParam.classLoader,
            "loadShiftData",
            Bitmap.class,
            int.class,
            new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    Activity activity = activeActivity;
                    if (!spreadLassoActive || activity == null
                        || !isEditableSpreadLandscape(activity)) {
                        return;
                    }
                    Object lassoInfo = param.getResult();
                    log("lasso_shift_data " + lassoInfo);
                    prepareSelectedTrailPreview(
                        param.thisObject,
                        lassoInfo,
                        (Bitmap) param.args[0]
                    );
                    restoreSpreadLassoOrigin(
                        param.thisObject,
                        "after_shift_data"
                    );
                }
            }
        );

        XposedHelpers.findAndHookMethod(
            "com.supernote.document.handwrite.HandWritePresenter",
            loadPackageParam.classLoader,
            "saveTrails",
            boolean.class,
            boolean.class,
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    Activity activity = activeActivity;
                    traceEvent(
                        activity,
                        "save_trails_started",
                        "arg0",
                        param.args[0],
                        "arg1",
                        param.args[1],
                        "explicitCanonical",
                        Boolean.TRUE.equals(
                            EXPLICIT_CANONICAL_TRAIL_SAVE.get()
                        ),
                        "staleActivationScope",
                        Boolean.TRUE.equals(
                            PEN_ACTIVATION_STALE_SAVE_SCOPE.get()
                        ),
                        "activationSourceSaveScope",
                        Boolean.TRUE.equals(
                            PAGE_ACTIVATION_SOURCE_SAVE_SCOPE.get()
                        )
                    );
                    traceAnnotationBoundary(
                        activity,
                        param.thisObject,
                        "save_trails_before",
                        false
                    );
                    boolean activationSourceSave = Boolean.TRUE.equals(
                        PAGE_ACTIVATION_SOURCE_SAVE_SCOPE.get()
                    );
                    if (shouldBlockPageActivationSave(activity)
                        && !activationSourceSave) {
                        param.setResult(null);
                        PageActivationTransaction transaction =
                            PAGE_ACTIVATION_TRANSACTIONS.get(activity);
                        log("page_activation_save_blocked id="
                            + (transaction == null ? -1L : transaction.id)
                            + " target="
                            + (transaction == null
                                ? -1 : transaction.targetPage));
                        return;
                    }
                    if (activationSourceSave) {
                        log("page_activation_source_save_allowed");
                    }
                    boolean explicitCanonicalSave = Boolean.TRUE.equals(
                        EXPLICIT_CANONICAL_TRAIL_SAVE.get()
                    );
                    boolean staleActivationSave = activity != null
                        && Boolean.TRUE.equals(
                            PEN_ACTIVATION_STALE_SAVE_PENDING.get(activity)
                        )
                        && Boolean.TRUE.equals(
                            PEN_ACTIVATION_STALE_SAVE_SCOPE.get()
                        );
                    if (staleActivationSave && !explicitCanonicalSave) {
                        PEN_ACTIVATION_STALE_SAVE_PENDING.remove(activity);
                        param.setResult(null);
                        log("pen_activation_stale_save_bypassed"
                            + " scope=deferred_load_page");
                        return;
                    }
                    if (staleActivationSave) {
                        log("pen_activation_stale_save_preserved"
                            + " reason=explicit_canonical");
                    }
                    List<Object> captured = activity == null
                        ? null
                        : PEN_ACTIVATION_TRAILS.get(activity);
                    List<Object> erasers = activity == null
                        ? null
                        : PEN_ACTIVATION_ERASERS.get(activity);
                    if (activity == null
                        || PEN_ACTIVATION_TARGETS.get(activity) == null
                        || ((captured == null || captured.isEmpty())
                            && (erasers == null || erasers.isEmpty()))) {
                        return;
                    }
                    param.setResult(null);
                    log("pen_activation_native_save_bypassed trails="
                        + (captured == null ? 0 : captured.size())
                        + " erasers="
                        + (erasers == null ? 0 : erasers.size()));
                }

                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    Activity activity = activeActivity;
                    if (activity != null) {
                        persistPendingPenActivationTrails(
                            activity,
                            param.thisObject,
                            false
                        );
                    }
                    traceEvent(
                        activity,
                        "save_trails_finished",
                        "result",
                        param.getResult(),
                        "throwable",
                        String.valueOf(param.getThrowable())
                    );
                    traceAnnotationBoundary(
                        activity,
                        param.thisObject,
                        "save_trails_after",
                        true
                    );
                }
            }
        );

        XposedHelpers.findAndHookMethod(
            "com.supernote.document.handwrite.HandWritePresenter",
            loadPackageParam.classLoader,
            "receiveTrials",
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    PAGE_ACTIVATION_RECEIVE_BLOCKED.remove();
                    traceEvent(activeActivity, "receive_trials_started");
                    traceAnnotationBoundary(
                        activeActivity,
                        param.thisObject,
                        "receive_trials_before",
                        false
                    );
                    Activity activity = activeActivity;
                    if (shouldBlockPageActivationGesture(activity)) {
                        PAGE_ACTIVATION_RECEIVE_BLOCKED.set(Boolean.TRUE);
                        param.setResult(null);
                        PageActivationTransaction transaction =
                            PAGE_ACTIVATION_TRANSACTIONS.get(activity);
                        log("page_activation_receive_blocked id="
                            + (transaction == null ? -1L : transaction.id)
                            + " target="
                            + (transaction == null
                                ? -1 : transaction.targetPage));
                    }
                }

                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    boolean activationGestureBlocked = Boolean.TRUE.equals(
                        PAGE_ACTIVATION_RECEIVE_BLOCKED.get()
                    );
                    PAGE_ACTIVATION_RECEIVE_BLOCKED.remove();
                    if (spreadLassoOriginZero) {
                        Object superNoteNote = XposedHelpers.getObjectField(
                            param.thisObject,
                            "superNoteNote"
                        );
                        restoreSpreadLassoOrigin(
                            superNoteNote,
                            "receive_trials_fallback"
                        );
                    }
                    Activity activity = activeActivity;
                    clearPenContactStartPage(
                        activity,
                        "receive_trials_finished"
                    );
                    if (activationGestureBlocked) {
                        if (activity != null) {
                            markPageActivationPenLifted(
                                activity,
                                "receive_trials_blocked"
                            );
                            traceEvent(
                                activity,
                                "page_activation_trigger_gesture_discarded"
                            );
                            TRACE_TRANSACTION_IDS.remove(activity);
                        }
                        return;
                    }
                    if (activity != null) {
                        persistActiveEraserBeforeCanonicalRefresh(
                            activity,
                            param.thisObject
                        );
                        /*
                         * receiveTrials() fetches the completed native trail,
                         * but it does not call saveTrails(). Persist the
                         * page-local transaction here before the deferred page
                         * activation checks its fail-closed guard. Waiting for
                         * a later lifecycle save makes completion race ahead of
                         * persistence and cancel otherwise valid inactive-page
                         * ink.
                         */
                        persistPendingPenActivationTrails(
                            activity,
                            param.thisObject,
                            true
                        );
                        activity.runOnUiThread(new Runnable() {
                            @Override
                            public void run() {
                                completePendingPenPageActivation(
                                    activity,
                                    "pen_up"
                                );
                            }
                        });
                        traceAnnotationBoundary(
                            activity,
                            param.thisObject,
                            "receive_trials_after",
                            true
                        );
                        traceEvent(
                            activity,
                            "receive_trials_finished",
                            "result",
                            param.getResult(),
                            "throwable",
                            String.valueOf(param.getThrowable())
                        );
                        TRACE_TRANSACTION_IDS.remove(activity);
                    }
                }
            }
        );

        XposedHelpers.findAndHookMethod(
            "com.supernote.document.handwrite.HandWritePresenter",
            loadPackageParam.classLoader,
            "areaSelectionTransition",
            int.class,
            int.class,
            int.class,
            int.class,
            int.class,
            int.class,
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    beginCanonicalLassoOperation(
                        param.thisObject,
                        "transition"
                    );
                    repairSpreadLassoTransition(param);
                }

                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    endCanonicalLassoOperation(
                        param.thisObject,
                        "transition"
                    );
                }
            }
        );

        XposedHelpers.findAndHookMethod(
            "com.supernote.document.handwrite.HandWritePresenter",
            loadPackageParam.classLoader,
            "reWriteTrails",
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    beginCanonicalLassoOperation(
                        param.thisObject,
                        "rewrite"
                    );
                }

                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    endCanonicalLassoOperation(
                        param.thisObject,
                        "rewrite"
                    );
                }
            }
        );
        hooksReady = true;
        log("hooks_ready handshake_protocol=" + HANDSHAKE_PROTOCOL
            + " module_version_code=" + MODULE_VERSION_CODE);
    }

    private static synchronized void registerHandshakeReceiver(
        Activity activity
    ) {
        if (handshakeReceiverRegistered || activity == null || !hooksReady) {
            return;
        }
        final Context context = activity.getApplicationContext();
        if (context == null) {
            log("handshake_receiver_failed reason=no_application_context");
            return;
        }

        BroadcastReceiver receiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context receiverContext, Intent request) {
                if (request == null
                    || !HANDSHAKE_REQUEST_ACTION.equals(request.getAction())) {
                    return;
                }
                String nonce = request.getStringExtra(HANDSHAKE_EXTRA_NONCE);
                String requestedPath = request.getStringExtra(
                    HANDSHAKE_EXTRA_DOCUMENT_PATH
                );
                int requestedProtocol = request.getIntExtra(
                    HANDSHAKE_EXTRA_PROTOCOL,
                    -1
                );
                Activity current = activeActivity;
                String actualPath = currentDocumentPath(current);
                boolean activityReady = current != null
                    && !current.isFinishing()
                    && !current.isDestroyed();
                boolean pathMatches = sameCanonicalPath(
                    requestedPath,
                    actualPath
                );
                if (!hooksReady || !activityReady || nonce == null
                    || nonce.length() < 16
                    || requestedProtocol != HANDSHAKE_PROTOCOL
                    || !pathMatches) {
                    log("handshake_rejected hooks_ready=" + hooksReady
                        + " activity_ready=" + activityReady
                        + " protocol=" + requestedProtocol
                        + " path_matches=" + pathMatches);
                    return;
                }

                Intent response = new Intent(HANDSHAKE_RESPONSE_ACTION);
                response.setPackage(PLUGIN_HOST_PACKAGE);
                response.putExtra(HANDSHAKE_EXTRA_NONCE, nonce);
                response.putExtra(
                    HANDSHAKE_EXTRA_DOCUMENT_PATH,
                    actualPath
                );
                response.putExtra(
                    HANDSHAKE_EXTRA_PROTOCOL,
                    HANDSHAKE_PROTOCOL
                );
                response.putExtra(HANDSHAKE_EXTRA_HOOKS_READY, true);
                response.putExtra(
                    HANDSHAKE_EXTRA_MODULE_VERSION_CODE,
                    MODULE_VERSION_CODE
                );
                response.putExtra(
                    HANDSHAKE_EXTRA_DOCUMENT_APK_LENGTH,
                    TARGET_DOCUMENT_APK_LENGTH
                );
                response.putExtra(
                    HANDSHAKE_EXTRA_PROCESS_ID,
                    Process.myPid()
                );
                receiverContext.sendBroadcast(response);
                log("handshake_response protocol=" + HANDSHAKE_PROTOCOL
                    + " process_id=" + Process.myPid()
                    + " path=" + actualPath);
            }
        };

        try {
            context.registerReceiver(
                receiver,
                new IntentFilter(HANDSHAKE_REQUEST_ACTION)
            );
            handshakeReceiver = receiver;
            handshakeReceiverRegistered = true;
            log("handshake_receiver_registered");
        } catch (Throwable throwable) {
            handshakeReceiver = null;
            handshakeReceiverRegistered = false;
            log("handshake_receiver_failed " + throwable);
            XposedBridge.log(throwable);
        }
    }

    private static synchronized void registerTraceControlReceiver(
        Activity activity
    ) {
        if (traceControlReceiverRegistered || activity == null || !hooksReady) {
            return;
        }
        final Context context = activity.getApplicationContext();
        if (context == null) {
            log("trace_control_receiver_failed reason=no_application_context");
            return;
        }

        BroadcastReceiver receiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context receiverContext, Intent request) {
                if (request == null
                    || !TRACE_CONTROL_ACTION.equals(request.getAction())) {
                    return;
                }
                String command = request.getStringExtra(TRACE_EXTRA_COMMAND);
                String label = request.getStringExtra(TRACE_EXTRA_LABEL);
                Activity current = activeActivity;
                if ("start".equalsIgnoreCase(command)) {
                    startAnnotationTrace(current, label);
                } else if ("checkpoint".equalsIgnoreCase(command)) {
                    checkpointAnnotationTrace(current, label);
                } else if ("stop".equalsIgnoreCase(command)) {
                    stopAnnotationTrace(current, "adb_stop");
                } else {
                    log("trace_control_rejected command=" + command);
                }
            }
        };

        try {
            context.registerReceiver(
                receiver,
                new IntentFilter(TRACE_CONTROL_ACTION),
                TRACE_CONTROL_PERMISSION,
                null
            );
            traceControlReceiver = receiver;
            traceControlReceiverRegistered = true;
            log("trace_control_receiver_registered permission="
                + TRACE_CONTROL_PERMISSION);
        } catch (Throwable throwable) {
            traceControlReceiver = null;
            traceControlReceiverRegistered = false;
            log("trace_control_receiver_failed " + throwable);
            XposedBridge.log(throwable);
        }
    }

    private static void startAnnotationTrace(Activity activity, String label) {
        if (activity == null || activity.isFinishing()
            || activity.isDestroyed()) {
            log("trace_start_rejected reason=no_active_document");
            return;
        }
        SpreadConfig config = spreadConfig(activity);
        if (config == null || !config.enabled || !config.editable) {
            log("trace_start_rejected reason=editable_native_spread_required");
            showOverlay(
                activity,
                "SPREAD TRACE: enable editable Native Spread first"
            );
            return;
        }
        if (traceSession != null) {
            stopAnnotationTrace(activity, "restarted");
            log("trace_start_deferred reason=previous_session_stopping");
            showStatusOverlay(
                activity,
                "SPREAD TRACE: previous session stopping; start again"
            );
            return;
        }

        TraceSession started = null;
        try {
            String documentPath = currentDocumentPath(activity);
            Object presenter = XposedHelpers.getObjectField(
                activity,
                "handWritePresenter"
            );
            String markPath = (String) XposedHelpers.getObjectField(
                presenter,
                "markPath"
            );
            long startedAt = System.currentTimeMillis();
            String timestamp = new SimpleDateFormat(
                "yyyyMMdd-HHmmss-SSS",
                Locale.US
            ).format(new Date(startedAt));
            String documentName = documentPath == null
                ? "document"
                : new File(documentPath).getName();
            String sessionId = timestamp + "-p" + Process.myPid() + "-"
                + traceSanitize(documentName);
            File root = new File(TRACE_ROOT);
            File directory = new File(root, sessionId);
            File snapshots = new File(directory, "mark-snapshots");
            if ((!root.isDirectory() && !root.mkdirs())
                || (!directory.isDirectory() && !directory.mkdirs())
                || (!snapshots.isDirectory() && !snapshots.mkdirs())) {
                throw new IllegalStateException(
                    "could not create trace directory " + directory
                );
            }

            started = new TraceSession(
                sessionId,
                documentPath,
                markPath,
                root,
                directory,
                new File(directory, "events.jsonl"),
                snapshots,
                startedAt,
                activity
            );
            synchronized (TRACE_LOCK) {
                traceSession = started;
            }

            Properties metadata = new Properties();
            metadata.setProperty("schema", String.valueOf(TRACE_SCHEMA_VERSION));
            metadata.setProperty("session", sessionId);
            metadata.setProperty("moduleVersionCode", String.valueOf(
                MODULE_VERSION_CODE
            ));
            metadata.setProperty("fingerprint", Build.FINGERPRINT);
            metadata.setProperty("documentPath", String.valueOf(documentPath));
            metadata.setProperty("markPath", String.valueOf(markPath));
            metadata.setProperty("processId", String.valueOf(Process.myPid()));
            metadata.setProperty("startedAtMillis", String.valueOf(startedAt));
            metadata.setProperty("label", label == null ? "" : label);
            try (FileOutputStream output = new FileOutputStream(
                    new File(directory, "session.properties")
                )) {
                metadata.store(output, "Native Spread annotation trace");
                output.getFD().sync();
            }
            writeTraceText(new File(root, "active.txt"), sessionId + "\n");
            startTraceMarkObserver(started);
            traceEvent(
                activity,
                "trace_session_started",
                "label",
                label,
                "directory",
                directory.getAbsolutePath(),
                "markPath",
                markPath
            );
            traceAnnotationBoundary(
                activity,
                presenter,
                "trace_start",
                true
            );
            log("trace_session_started id=" + sessionId
                + " dir=" + directory.getAbsolutePath());
            showStatusOverlay(activity, "SPREAD TRACE: recording");
        } catch (Throwable throwable) {
            FileObserver failedObserver = null;
            synchronized (TRACE_LOCK) {
                if (traceSession == started) {
                    traceSession = null;
                }
                if (started != null) {
                    started.stopping = true;
                    failedObserver = started.markObserver;
                    started.markObserver = null;
                    if (started.pendingSnapshot != null) {
                        started.pendingSnapshot.cancel(false);
                        started.pendingSnapshot = null;
                    }
                    started.snapshotGeneration++;
                }
            }
            if (failedObserver != null) {
                try {
                    failedObserver.stopWatching();
                } catch (Throwable ignored) {
                }
            }
            if (started != null) {
                started.snapshotExecutor.shutdownNow();
                started.eventExecutor.shutdownNow();
                try {
                    File active = new File(
                        started.rootDirectory,
                        "active.txt"
                    );
                    if (active.isFile() && !active.delete()) {
                        log("trace_start_active_pointer_delete_failed path="
                            + active.getAbsolutePath());
                    }
                } catch (Throwable cleanupError) {
                    log("trace_start_pointer_cleanup_failed " + cleanupError);
                }
            }
            log("trace_start_failed " + throwable);
            XposedBridge.log(throwable);
            showOverlay(activity, "SPREAD TRACE: unable to start");
        }
    }

    private static void checkpointAnnotationTrace(
        Activity activity,
        String label
    ) {
        TraceSession session = traceSession;
        if (session == null) {
            log("trace_checkpoint_rejected reason=no_active_session");
            return;
        }
        try {
            Object presenter = activity == null ? null
                : XposedHelpers.getObjectField(
                    activity,
                    "handWritePresenter"
                );
            traceEvent(
                activity,
                "trace_checkpoint",
                "label",
                label == null ? "checkpoint" : label
            );
            traceAnnotationBoundary(
                activity,
                presenter,
                "checkpoint_" + traceSanitize(label),
                true
            );
            log("trace_checkpoint label=" + label);
        } catch (Throwable throwable) {
            log("trace_checkpoint_failed " + throwable);
            XposedBridge.log(throwable);
        }
    }

    private static void stopAnnotationTrace(Activity activity, String reason) {
        final TraceSession session;
        final FileObserver observer;
        final ScheduledFuture<?> pendingSnapshot;
        synchronized (TRACE_LOCK) {
            session = traceSession;
            if (session == null || session.stopping) {
                return;
            }
            session.stopping = true;
            observer = session.markObserver;
            session.markObserver = null;
            pendingSnapshot = session.pendingSnapshot;
            session.pendingSnapshot = null;
            session.snapshotGeneration++;
        }
        if (observer != null) {
            try {
                observer.stopWatching();
            } catch (Throwable ignored) {
            }
        }
        if (pendingSnapshot != null) {
            pendingSnapshot.cancel(false);
        }
        try {
            Object presenter = activity == null ? null
                : XposedHelpers.getObjectField(
                    activity,
                    "handWritePresenter"
                );
            traceAnnotationBoundary(
                activity,
                presenter,
                "trace_stop",
                false
            );
        } catch (Throwable throwable) {
            traceEvent(
                activity,
                "trace_stop_failed",
                "error",
                String.valueOf(throwable)
            );
        }
        try {
            session.snapshotExecutor.execute(
                new Runnable() {
                    @Override
                    public void run() {
                        boolean stableFinalSnapshot =
                            captureStableFinalTraceMarkSnapshot(session);
                        if (!stableFinalSnapshot) {
                            traceEvent(
                                activity,
                                "trace_session_incomplete",
                                "reason",
                                "final_snapshot_unstable",
                                "attempts",
                                TRACE_FINAL_SNAPSHOT_ATTEMPTS
                            );
                            finishTraceSession(
                                session,
                                activity,
                                reason,
                                false
                            );
                            return;
                        }
                        traceEvent(
                            activity,
                            "trace_session_stopped",
                            "reason",
                            reason,
                            "durationMs",
                            System.currentTimeMillis()
                                - session.startedAtMillis
                        );
                        finishTraceSession(
                            session,
                            activity,
                            reason,
                            true
                        );
                    }
                }
            );
        } catch (Throwable throwable) {
            traceEvent(
                activity,
                "mark_snapshot_failed",
                "reason",
                "trace_stop",
                "error",
                String.valueOf(throwable)
            );
            traceEvent(
                activity,
                "trace_session_incomplete",
                "reason",
                "final_snapshot_worker_failed"
            );
            finishTraceSession(session, activity, reason, false);
        }
    }

    private static boolean captureStableFinalTraceMarkSnapshot(
        TraceSession session
    ) {
        for (int attempt = 1;
             attempt <= TRACE_FINAL_SNAPSHOT_ATTEMPTS;
             attempt++) {
            if (captureTraceMarkSnapshot(
                    session,
                    "trace_stop_attempt_" + attempt
                )) {
                return true;
            }
            if (!isTraceSessionActive(session)
                || attempt >= TRACE_FINAL_SNAPSHOT_ATTEMPTS) {
                break;
            }
            SystemClock.sleep(TRACE_FINAL_SNAPSHOT_RETRY_MS);
        }
        return false;
    }

    private static void finishTraceSession(
        TraceSession session,
        Activity activity,
        String reason,
        boolean requestedCompleted
    ) {
        boolean owned;
        synchronized (TRACE_LOCK) {
            owned = traceSession == session;
            if (owned) {
                traceSession = null;
            }
        }
        boolean eventLogComplete = drainTraceEventWriter(session);
        boolean completed = requestedCompleted && eventLogComplete;
        Throwable publicationFailure = null;
        if (owned) {
            File active = new File(session.rootDirectory, "active.txt");
            try {
                File incomplete = new File(
                    session.rootDirectory,
                    "incomplete.txt"
                );
                File failed = new File(
                    session.rootDirectory,
                    "publication-failed.txt"
                );
                if (completed) {
                    writeTraceText(
                        new File(session.rootDirectory, "last.txt"),
                        session.id + "\n"
                    );
                    if (incomplete.isFile() && !incomplete.delete()) {
                        throw new IllegalStateException(
                            "could not clear " + incomplete
                        );
                    }
                } else {
                    writeTraceText(incomplete, session.id + "\n");
                }
                if (failed.isFile() && !failed.delete()) {
                    throw new IllegalStateException(
                        "could not clear " + failed
                    );
                }
            } catch (Throwable throwable) {
                publicationFailure = throwable;
                preserveTracePublicationFailure(
                    session,
                    active,
                    throwable
                );
            } finally {
                if (active.isFile() && !active.delete()) {
                    IllegalStateException cleanupFailure =
                        new IllegalStateException(
                            "could not clear " + active
                        );
                    if (publicationFailure == null) {
                        publicationFailure = cleanupFailure;
                    }
                    preserveTracePublicationFailure(
                        session,
                        active,
                        cleanupFailure
                    );
                }
            }
        }
        session.snapshotExecutor.shutdown();
        TRACE_LAST_PRESSURES.remove(activity);
        TRACE_TRANSACTION_IDS.remove(activity);
        log("trace_session_stopped id=" + session.id
            + " reason=" + reason
            + " completed=" + completed
            + " eventLogComplete=" + eventLogComplete
            + " publicationFailure=" + String.valueOf(publicationFailure));
    }

    private static boolean drainTraceEventWriter(TraceSession session) {
        session.eventExecutor.shutdown();
        boolean terminated = false;
        try {
            terminated = session.eventExecutor.awaitTermination(
                30L,
                TimeUnit.SECONDS
            );
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            session.eventWriteFailure = String.valueOf(interrupted);
        }
        if (!terminated) {
            session.eventExecutor.shutdownNow();
            if (session.eventWriteFailure == null) {
                session.eventWriteFailure = "event_writer_timeout";
            }
        }
        if (session.eventWriteFailure != null) {
            Log.e(
                TAG,
                "trace_event_writer_incomplete id=" + session.id
                    + " error=" + session.eventWriteFailure
            );
            return false;
        }
        return terminated;
    }

    private static void preserveTracePublicationFailure(
        TraceSession session,
        File active,
        Throwable failure
    ) {
        File failed = new File(
            session.rootDirectory,
            "publication-failed.txt"
        );
        boolean preserved = false;
        try {
            if (failed.isFile() && !failed.delete()) {
                Log.e(TAG, "trace_publication_old_failure_delete_failed");
            }
            if (active.isFile()) {
                preserved = active.renameTo(failed);
            }
            if (!preserved) {
                writeTraceText(failed, session.id + "\n");
                preserved = true;
            }
        } catch (Throwable pointerFailure) {
            Log.e(
                TAG,
                "trace_publication_failure_pointer_failed id=" + session.id,
                pointerFailure
            );
        }
        try {
            writeTraceText(
                new File(
                    session.sessionDirectory,
                    "publication-failure.txt"
                ),
                String.valueOf(failure) + "\n"
            );
        } catch (Throwable detailFailure) {
            Log.e(
                TAG,
                "trace_publication_failure_detail_failed id=" + session.id,
                detailFailure
            );
        }
        Log.e(
            TAG,
            "trace_publication_failed id=" + session.id
                + " preserved=" + preserved,
            failure
        );
    }

    private static void startTraceMarkObserver(final TraceSession session) {
        if (session == null || session.markPath == null) {
            return;
        }
        final File mark = new File(session.markPath);
        final File parent = mark.getParentFile();
        if (parent == null) {
            return;
        }
        final String expectedName = mark.getName();
        int mask = FileObserver.CLOSE_WRITE | FileObserver.MOVED_TO
            | FileObserver.CREATE | FileObserver.DELETE
            | FileObserver.MODIFY | FileObserver.ATTRIB;
        FileObserver observer = new FileObserver(parent.getAbsolutePath(), mask) {
            @Override
            public void onEvent(int event, String path) {
                if (path == null || !expectedName.equals(path)
                    || traceSession != session) {
                    return;
                }
                final int normalized = event & FileObserver.ALL_EVENTS;
                Activity activity = session.activity.get();
                traceEvent(
                    activity,
                    "mark_file_event",
                    "mask",
                    normalized,
                    "name",
                    path
                );
                scheduleTraceMarkSnapshot(
                    session,
                    "file_event_" + normalized,
                    TRACE_SNAPSHOT_DEBOUNCE_MS
                );
            }
        };
        observer.startWatching();
        session.markObserver = observer;
        traceEvent(
            session.activity.get(),
            "mark_observer_started",
            "path",
            mark.getAbsolutePath(),
            "mask",
            mask
        );
    }

    private static void traceTouchEvent(Activity activity, MotionEvent event) {
        if (traceSession == null || event == null
            || event.getPointerCount() == 0) {
            return;
        }
        int action = event.getActionMasked();
        if (action != MotionEvent.ACTION_DOWN
            && action != MotionEvent.ACTION_UP
            && action != MotionEvent.ACTION_CANCEL) {
            return;
        }
        traceEvent(
            activity,
            "activity_touch",
            "action",
            action,
            "tool",
            event.getToolType(0),
            "x",
            event.getX(),
            "y",
            event.getY(),
            "resolvedPage",
            pageAt(activity, event.getX(), event.getY()),
            "pointerCount",
            event.getPointerCount()
        );
    }

    private static void tracePenPosition(
        Activity activity,
        PenInputSnapshot inputSnapshot,
        int x,
        int y,
        int pressure
    ) {
        final TraceSession expected = traceSession;
        if (expected == null || activity == null) {
            return;
        }
        Integer previous = TRACE_LAST_PRESSURES.put(activity, pressure);
        boolean contactStarted = pressure > 0
            && (previous == null || previous.intValue() <= 0);
        boolean contactEnded = pressure <= 0
            && previous != null && previous.intValue() > 0;
        if (!contactStarted && !contactEnded) {
            return;
        }
        if (contactStarted) {
            TRACE_TRANSACTION_IDS.put(
                activity,
                TRACE_TRANSACTION_COUNTER.incrementAndGet()
            );
        }
        final String event = contactStarted
            ? "pen_contact_started" : "pen_contact_ended";
        final int capturedX = x;
        final int capturedY = y;
        final int capturedPressure = pressure;
        final Integer capturedPrevious = previous;
        final int capturedResolvedPage = pageAt(inputSnapshot, x, y);
        final int capturedCurrentPage = inputSnapshot == null
            ? -1 : inputSnapshot.currentPage;
        final Long capturedTransactionId = TRACE_TRANSACTION_IDS.get(activity);
        try {
            expected.eventExecutor.execute(new Runnable() {
                @Override
                public void run() {
                    if (!isTraceSessionActive(expected)) {
                        return;
                    }
                    traceEvent(
                        expected,
                        null,
                        event,
                        "x",
                        capturedX,
                        "y",
                        capturedY,
                        "pressure",
                        capturedPressure,
                        "previousPressure",
                        capturedPrevious,
                        "resolvedPage",
                        capturedResolvedPage,
                        "currentPage",
                        capturedCurrentPage,
                        "transactionId",
                        capturedTransactionId
                    );
                }
            });
        } catch (Throwable throwable) {
            expected.eventWriteFailure = String.valueOf(throwable);
        }
    }

    private static void tracePenLeftScreen(Activity activity, int state) {
        if (traceSession == null || activity == null) {
            return;
        }
        traceEvent(activity, "pen_left_screen", "state", state);
        TRACE_LAST_PRESSURES.remove(activity);
    }

    private static void traceOperationTrails(
        Activity activity,
        String event,
        List<?> trails
    ) {
        traceOperationTrails(
            activity,
            event,
            "operationTrails",
            trails,
            new Object[0]
        );
    }

    private static void traceOperationTrails(
        Activity activity,
        String event,
        String summaryKey,
        List<?> trails,
        Object... metadata
    ) {
        final TraceSession session = traceSession;
        if (session == null) {
            return;
        }
        final TraceEventContext context = TraceEventContext.capture(activity);
        final TraceTrailListCapture captured = captureTraceTrailList(trails);
        final Object[] capturedMetadata = metadata == null
            ? new Object[0] : metadata.clone();
        scheduleTraceWorkerTask(
            session,
            event,
            new Runnable() {
                @Override
                public void run() {
                    Object[] values = new Object[capturedMetadata.length + 2];
                    System.arraycopy(
                        capturedMetadata,
                        0,
                        values,
                        0,
                        capturedMetadata.length
                    );
                    values[capturedMetadata.length] = summaryKey;
                    values[capturedMetadata.length + 1] =
                        traceTrailList(captured);
                    traceEvent(session, context, event, values);
                }
            }
        );
    }

    private static void traceAnnotationBoundary(
        Activity activity,
        Object presenter,
        String boundary,
        boolean snapshotMark
    ) {
        TraceSession session = traceSession;
        if (session == null || activity == null || presenter == null) {
            return;
        }
        try {
            Object superNoteNote = XposedHelpers.getObjectField(
                presenter,
                "superNoteNote"
            );
            String markPath = (String) XposedHelpers.getObjectField(
                presenter,
                "markPath"
            );
            int markPage = XposedHelpers.getIntField(
                presenter,
                "currentPage"
            );
            Object fileResult = XposedHelpers.callMethod(
                superNoteNote,
                "getFilePageTrails",
                markPath,
                markPage
            );
            Object currentResult = XposedHelpers.callMethod(
                superNoteNote,
                "getCurPageTrails",
                markPath
            );
            File mark = markPath == null ? null : new File(markPath);
            final boolean markExists = mark != null && mark.isFile();
            final long markLength = markExists ? mark.length() : -1L;
            final String markHash = traceLastSnapshotHash(session, mark);
            final TraceEventContext context =
                TraceEventContext.capture(activity);
            final TraceTrailListCapture fileTrails = captureTraceTrailList(
                fileResult instanceof List ? (List<?>) fileResult : null
            );
            final TraceTrailListCapture currentTrails = captureTraceTrailList(
                currentResult instanceof List ? (List<?>) currentResult : null
            );
            final int capturedInactiveInk = traceListSize(
                PEN_ACTIVATION_TRAILS.get(activity)
            );
            final int capturedInactiveErasers = traceListSize(
                PEN_ACTIVATION_ERASERS.get(activity)
            );
            scheduleTraceWorkerTask(
                session,
                "annotation_boundary_" + boundary,
                "trace_stop".equals(boundary),
                new Runnable() {
                    @Override
                    public void run() {
                        traceEvent(
                            session,
                            context,
                            "annotation_boundary",
                            "boundary",
                            boundary,
                            "markPath",
                            markPath,
                            "markPage",
                            markPage,
                            "markExists",
                            markExists,
                            "markLength",
                            markLength,
                            "markSha256",
                            markHash,
                            "fileTrails",
                            traceTrailList(fileTrails),
                            "currentTrails",
                            traceTrailList(currentTrails),
                            "capturedInactiveInk",
                            capturedInactiveInk,
                            "capturedInactiveErasers",
                            capturedInactiveErasers
                        );
                    }
                }
            );
            if (snapshotMark) {
                scheduleTraceMarkSnapshot(
                    session,
                    boundary,
                    TRACE_SNAPSHOT_DEBOUNCE_MS
                );
            }
        } catch (Throwable throwable) {
            traceEvent(
                activity,
                "annotation_boundary_failed",
                "boundary",
                boundary,
                "error",
                String.valueOf(throwable)
            );
        }
    }

    private static int traceListSize(List<?> list) {
        return list == null ? 0 : list.size();
    }

    private static TraceTrailListCapture captureTraceTrailList(List<?> trails) {
        if (trails == null) {
            return new TraceTrailListCapture(true, new TraceTrailCapture[0]);
        }
        TraceTrailCapture[] captured = new TraceTrailCapture[trails.size()];
        for (int index = 0; index < trails.size(); index++) {
            captured[index] = captureTraceTrail(trails.get(index));
        }
        return new TraceTrailListCapture(false, captured);
    }

    private static TraceTrailCapture captureTraceTrail(Object trail) {
        if (trail == null) {
            return failedTraceTrailCapture(true, null);
        }
        try {
            @SuppressWarnings("unchecked")
            List<Point> points = (List<Point>) XposedHelpers.callMethod(
                trail,
                "get_m_points"
            );
            int pointCount = points == null ? 0 : points.size();
            int[] pointXs = new int[pointCount];
            int[] pointYs = new int[pointCount];
            boolean[] pointPresent = new boolean[pointCount];
            for (int index = 0; index < pointCount; index++) {
                Point point = points.get(index);
                if (point != null) {
                    pointPresent[index] = true;
                    pointXs[index] = point.x;
                    pointYs[index] = point.y;
                }
            }
            Object erased = XposedHelpers.callMethod(
                trail,
                "get_erase_line_trail_num"
            );
            Object rrd = traceCall(trail, "get_rrd");
            return new TraceTrailCapture(
                false,
                null,
                traceInt(trail, "get_page_num"),
                traceInt(trail, "get_trail_num"),
                traceInt(trail, "get_m_trail_num_in_page"),
                traceInt(trail, "get_pen_type"),
                traceInt(trail, "get_pen_color"),
                traceInt(trail, "get_m_thickness"),
                traceInt(trail, "get_walcom_emr_type"),
                traceInt(trail, "get_flag_draw"),
                traceInt(trail, "get_flag_penup"),
                traceInt(trail, "get_flag_special"),
                traceInt(trail, "get_layer_num"),
                traceInt(trail, "get_rec_mod"),
                traceInt(trail, "get_m_emr_point_axis"),
                traceInt(trail, "get_m_trail_type"),
                traceInt(trail, "get_m_draw_version"),
                traceInt(trail, "get_recogn_trail_type"),
                traceInt(trail, "get_m_trail_status"),
                traceInt(trail, "get_process_mod"),
                traceInt(trail, "get_m_rotate_angle"),
                traceInt(trail, "get_m_redraw_width"),
                traceInt(trail, "get_m_redraw_height"),
                traceInt(trail, "get_max_x"),
                traceInt(trail, "get_max_y"),
                captureTraceRect(rrd == null ? null : traceCall(rrd, "getRect")),
                captureTraceRect(traceCall(trail, "get_refresh_rect")),
                captureTraceRect(traceCall(trail, "get_m_before_shift_rect")),
                captureTraceRect(traceCall(trail, "get_m_after_shift_rect")),
                captureTraceContours(traceCall(trail, "get_m_contours_src")),
                pointXs,
                pointYs,
                pointPresent,
                String.valueOf(erased),
                captureTraceValue(traceCall(trail, "get_write_app_name")),
                captureTraceValue(traceCall(trail, "get_pressures")),
                captureTraceValue(traceCall(trail, "get_angles")),
                captureTraceValue(traceCall(trail, "get_timestamp"))
            );
        } catch (Throwable throwable) {
            return failedTraceTrailCapture(false, String.valueOf(throwable));
        }
    }

    private static TraceTrailCapture failedTraceTrailCapture(
        boolean nullValue,
        String error
    ) {
        return new TraceTrailCapture(
            nullValue,
            error,
            Integer.MIN_VALUE,
            Integer.MIN_VALUE,
            Integer.MIN_VALUE,
            Integer.MIN_VALUE,
            Integer.MIN_VALUE,
            Integer.MIN_VALUE,
            Integer.MIN_VALUE,
            Integer.MIN_VALUE,
            Integer.MIN_VALUE,
            Integer.MIN_VALUE,
            Integer.MIN_VALUE,
            Integer.MIN_VALUE,
            Integer.MIN_VALUE,
            Integer.MIN_VALUE,
            Integer.MIN_VALUE,
            Integer.MIN_VALUE,
            Integer.MIN_VALUE,
            Integer.MIN_VALUE,
            Integer.MIN_VALUE,
            Integer.MIN_VALUE,
            Integer.MIN_VALUE,
            Integer.MIN_VALUE,
            Integer.MIN_VALUE,
            captureTraceValue(null),
            captureTraceValue(null),
            captureTraceValue(null),
            captureTraceValue(null),
            captureTraceValue(null),
            new int[0],
            new int[0],
            new boolean[0],
            "null",
            captureTraceValue(null),
            captureTraceValue(null),
            captureTraceValue(null),
            captureTraceValue(null)
        );
    }

    private static JSONObject traceTrailList(TraceTrailListCapture captured) {
        JSONObject summary = new JSONObject();
        try {
            if (captured == null || captured.missing) {
                summary.put("count", -1);
                summary.put("items", JSONObject.NULL);
                return summary;
            }
            summary.put("count", captured.trails.length);
            JSONArray items = new JSONArray();
            StringBuilder ordered = new StringBuilder();
            int limit = Math.min(
                captured.trails.length,
                TRACE_TRAIL_LIMIT
            );
            for (int index = 0; index < captured.trails.length; index++) {
                TraceTrailCapture trail = captured.trails[index];
                String fingerprint = traceTrailFingerprint(trail);
                if (index < limit) {
                    items.put(traceTrail(trail, index, fingerprint));
                }
                ordered.append(fingerprint).append(';');
            }
            summary.put("items", items);
            summary.put(
                "truncated",
                Math.max(0, captured.trails.length - limit)
            );
            summary.put(
                "orderedFingerprint",
                sha256Text(ordered.toString())
            );
        } catch (Throwable throwable) {
            try {
                summary.put("error", String.valueOf(throwable));
            } catch (Throwable ignored) {
            }
        }
        return summary;
    }

    private static JSONObject traceTrail(
        TraceTrailCapture trail,
        int index,
        String fingerprint
    ) {
        JSONObject item = new JSONObject();
        try {
            item.put("index", index);
            if (trail == null || trail.nullValue) {
                item.put("value", JSONObject.NULL);
                item.put("fingerprint", "null");
                return item;
            }
            if (trail.error != null) {
                item.put("error", trail.error);
                item.put("fingerprint", "error");
                return item;
            }
            int pointCount = trail.pointXs.length;
            item.put("page", trail.page);
            item.put("trail", trail.trail);
            item.put("inPage", trail.inPage);
            item.put("pen", trail.pen);
            item.put("penColor", trail.penColor);
            item.put("thickness", trail.thickness);
            item.put("emrType", trail.emrType);
            item.put("flagDraw", trail.flagDraw);
            item.put("flagPenup", trail.flagPenup);
            item.put("flagSpecial", trail.flagSpecial);
            item.put("layer", trail.layer);
            item.put("recMod", trail.recMod);
            item.put("emrPointAxis", trail.emrPointAxis);
            item.put("trailType", trail.trailType);
            item.put("drawVersion", trail.drawVersion);
            item.put("recognTrailType", trail.recognTrailType);
            item.put("status", trail.status);
            item.put("process", trail.process);
            item.put("rotation", trail.rotation);
            item.put("redrawWidth", trail.redrawWidth);
            item.put("redrawHeight", trail.redrawHeight);
            item.put("maxX", trail.maxX);
            item.put("maxY", trail.maxY);
            item.put("rrdRect", traceValueDescription(trail.rrdRect));
            item.put("refreshRect", traceValueDescription(trail.refreshRect));
            item.put(
                "beforeShiftRect",
                traceValueDescription(trail.beforeShiftRect)
            );
            item.put(
                "afterShiftRect",
                traceValueDescription(trail.afterShiftRect)
            );
            item.put("contours", traceValueDescription(trail.contours));
            item.put("pointCount", pointCount);
            item.put("first", capturedPointDescription(trail, 0));
            item.put(
                "middle",
                capturedPointDescription(trail, pointCount / 2)
            );
            item.put(
                "last",
                capturedPointDescription(trail, pointCount - 1)
            );
            item.put("bounds", rectDescription(capturedPointBounds(trail)));
            item.put("erased", trail.erased);
            item.put(
                "writeAppName",
                traceValueDescription(trail.writeAppName)
            );
            item.put(
                "pressures",
                traceValueDescription(trail.pressures)
            );
            item.put("angles", traceValueDescription(trail.angles));
            item.put("timestamp", traceValueDescription(trail.timestamp));
            item.put("fingerprint", fingerprint);
        } catch (Throwable throwable) {
            try {
                item.put("error", String.valueOf(throwable));
                item.put("fingerprint", "error");
            } catch (Throwable ignored) {
            }
        }
        return item;
    }

    private static String traceTrailFingerprint(TraceTrailCapture trail) {
        if (trail == null || trail.nullValue) {
            return "null";
        }
        if (trail.error != null) {
            return "error";
        }
        try {
            StringBuilder canonical = new StringBuilder();
            canonical.append(trail.page).append('|')
                .append(trail.trail).append('|')
                .append(trail.inPage).append('|')
                .append(trail.pen).append('|')
                .append(trail.penColor).append('|')
                .append(trail.thickness).append('|')
                .append(trail.emrType).append('|')
                .append(trail.flagDraw).append('|')
                .append(trail.flagPenup).append('|')
                .append(trail.flagSpecial).append('|')
                .append(trail.layer).append('|')
                .append(trail.recMod).append('|')
                .append(trail.emrPointAxis).append('|')
                .append(trail.trailType).append('|')
                .append(trail.drawVersion).append('|')
                .append(trail.recognTrailType).append('|')
                .append(trail.status).append('|')
                .append(trail.process).append('|')
                .append(trail.rotation).append('|')
                .append(trail.redrawWidth).append('|')
                .append(trail.redrawHeight).append('|')
                .append(trail.maxX).append('|')
                .append(trail.maxY).append('|')
                .append(traceValueDescription(trail.rrdRect)).append('|')
                .append(traceValueDescription(trail.refreshRect)).append('|')
                .append(traceValueDescription(trail.beforeShiftRect)).append('|')
                .append(traceValueDescription(trail.afterShiftRect)).append('|')
                .append(traceValueDescription(trail.contours)).append('|')
                .append(trail.erased).append('|')
                .append(traceValueDescription(trail.writeAppName)).append('|')
                .append(traceValueDescription(trail.pressures)).append('|')
                .append(traceValueDescription(trail.angles)).append('|')
                .append(traceValueDescription(trail.timestamp)).append('|');
            for (int index = 0; index < trail.pointXs.length; index++) {
                if (!trail.pointPresent[index]) {
                    canonical.append("null;");
                } else {
                    canonical.append(trail.pointXs[index]).append(',')
                        .append(trail.pointYs[index]).append(';');
                }
            }
            return sha256Text(canonical.toString());
        } catch (Throwable throwable) {
            return "error";
        }
    }

    private static String capturedPointDescription(
        TraceTrailCapture trail,
        int index
    ) {
        if (trail == null || index < 0 || index >= trail.pointXs.length
            || !trail.pointPresent[index]) {
            return "null";
        }
        return trail.pointXs[index] + "," + trail.pointYs[index];
    }

    private static Rect capturedPointBounds(TraceTrailCapture trail) {
        if (trail == null) {
            return null;
        }
        int left = Integer.MAX_VALUE;
        int top = Integer.MAX_VALUE;
        int right = Integer.MIN_VALUE;
        int bottom = Integer.MIN_VALUE;
        for (int index = 0; index < trail.pointXs.length; index++) {
            if (!trail.pointPresent[index]) {
                continue;
            }
            left = Math.min(left, trail.pointXs[index]);
            top = Math.min(top, trail.pointYs[index]);
            right = Math.max(right, trail.pointXs[index]);
            bottom = Math.max(bottom, trail.pointYs[index]);
        }
        return left == Integer.MAX_VALUE
            ? null : new Rect(left, top, right + 1, bottom + 1);
    }

    private static int traceInt(Object target, String methodName) {
        try {
            return callInt(target, methodName);
        } catch (Throwable throwable) {
            return Integer.MIN_VALUE;
        }
    }

    private static Object traceCall(Object target, String methodName) {
        try {
            return XposedHelpers.callMethod(target, methodName);
        } catch (Throwable throwable) {
            return null;
        }
    }

    private static TraceValueCapture captureTraceRect(Object value) {
        if (value == null) {
            return captureTraceValue(null);
        }
        if (!(value instanceof Rect)) {
            return captureTraceValue(new Object[] {
                "unexpected",
                value.getClass().getName()
            });
        }
        Rect rect = (Rect) value;
        return captureTraceValue(new int[] {
            rect.left,
            rect.top,
            rect.right,
            rect.bottom
        });
    }

    private static TraceValueCapture captureTraceContours(Object value) {
        if (value == null) {
            return captureTraceValue(null);
        }
        if (!(value instanceof List)) {
            return captureTraceValue(new Object[] {
                "unexpected",
                value.getClass().getName()
            });
        }
        ArrayList<Object> flattened = new ArrayList<>();
        List<?> contours = (List<?>) value;
        flattened.add("contours");
        flattened.add(Integer.valueOf(contours.size()));
        for (Object contourValue : contours) {
            if (!(contourValue instanceof List)) {
                flattened.add("unexpected-contour");
                flattened.add(
                    contourValue == null
                        ? "null"
                        : contourValue.getClass().getName()
                );
                continue;
            }
            List<?> contour = (List<?>) contourValue;
            flattened.add("contour");
            flattened.add(Integer.valueOf(contour.size()));
            for (Object pointValue : contour) {
                if (!(pointValue instanceof PointF)) {
                    flattened.add("unexpected-point");
                    flattened.add(
                        pointValue == null
                            ? "null"
                            : pointValue.getClass().getName()
                    );
                    continue;
                }
                PointF point = (PointF) pointValue;
                flattened.add(Integer.valueOf(Float.floatToRawIntBits(point.x)));
                flattened.add(Integer.valueOf(Float.floatToRawIntBits(point.y)));
            }
        }
        return captureTraceValue(flattened);
    }

    private static TraceValueCapture captureTraceValue(Object value) {
        if (value == null) {
            return new TraceValueCapture(false, null);
        }
        try {
            Class<?> type = value.getClass();
            if (type.isArray()) {
                int length = java.lang.reflect.Array.getLength(value);
                if (type.getComponentType().isPrimitive()) {
                    Object copy = java.lang.reflect.Array.newInstance(
                        type.getComponentType(),
                        length
                    );
                    System.arraycopy(value, 0, copy, 0, length);
                    return new TraceValueCapture(true, copy);
                }
                Object[] copy = new Object[length];
                for (int index = 0; index < length; index++) {
                    copy[index] = captureTraceScalar(
                        java.lang.reflect.Array.get(value, index)
                    );
                }
                return new TraceValueCapture(true, copy);
            }
            if (value instanceof Iterable) {
                ArrayList<Object> copy = new ArrayList<>();
                for (Object item : (Iterable<?>) value) {
                    copy.add(captureTraceScalar(item));
                }
                return new TraceValueCapture(true, copy.toArray());
            }
            return new TraceValueCapture(false, captureTraceScalar(value));
        } catch (Throwable throwable) {
            return new TraceValueCapture(false, "unavailable");
        }
    }

    private static Object captureTraceScalar(Object value) {
        if (value == null || value instanceof String
            || value instanceof Number || value instanceof Boolean
            || value instanceof Character || value instanceof Enum) {
            return value;
        }
        return String.valueOf(value);
    }

    private static String traceValueDescription(TraceValueCapture captured) {
        if (captured == null || captured.value == null) {
            return "null";
        }
        try {
            if (captured.sequence) {
                int length = java.lang.reflect.Array.getLength(
                    captured.value
                );
                StringBuilder result = new StringBuilder();
                result.append('[');
                for (int index = 0; index < length; index++) {
                    if (index > 0) {
                        result.append(',');
                    }
                    result.append(String.valueOf(
                        java.lang.reflect.Array.get(captured.value, index)
                    ));
                }
                return result.append(']').toString();
            }
            return String.valueOf(captured.value);
        } catch (Throwable throwable) {
            return "unavailable";
        }
    }

    private static String traceLastSnapshotHash(
        TraceSession expected,
        File mark
    ) {
        if (mark == null || !mark.isFile()) {
            return "missing";
        }
        FileIdentity currentIdentity;
        try {
            currentIdentity = FileIdentity.capture(mark);
        } catch (Throwable throwable) {
            return "pending";
        }
        synchronized (TRACE_LOCK) {
            if (expected == null || traceSession != expected
                || expected.lastSnapshotHash == null
                || expected.lastSnapshotIdentity == null
                || !expected.lastSnapshotIdentity.sameAs(currentIdentity)) {
                return "pending";
            }
            return expected.lastSnapshotHash;
        }
    }

    private static void scheduleTraceWorkerTask(
        final TraceSession expected,
        final String label,
        final Runnable task
    ) {
        scheduleTraceWorkerTask(expected, label, false, task);
    }

    private static void scheduleTraceWorkerTask(
        final TraceSession expected,
        final String label,
        final boolean allowWhenStopping,
        final Runnable task
    ) {
        synchronized (TRACE_LOCK) {
            if (expected == null || traceSession != expected
                || (expected.stopping && !allowWhenStopping)
                || expected.snapshotExecutor.isShutdown()) {
                return;
            }
            try {
                expected.snapshotExecutor.execute(
                    new Runnable() {
                        @Override
                        public void run() {
                            if (!isTraceSessionActive(expected)) {
                                return;
                            }
                            try {
                                task.run();
                            } catch (Throwable throwable) {
                                traceEvent(
                                    expected,
                                    null,
                                    "trace_worker_failed",
                                    "label",
                                    label,
                                    "error",
                                    String.valueOf(throwable)
                                );
                            }
                        }
                    }
                );
            } catch (Throwable throwable) {
                traceEvent(
                    expected,
                    null,
                    "trace_worker_failed",
                    "label",
                    label,
                    "error",
                    String.valueOf(throwable)
                );
            }
        }
    }

    private static void scheduleTraceMarkSnapshot(
        final TraceSession expected,
        final String reason,
        long delayMillis
    ) {
        synchronized (TRACE_LOCK) {
            if (expected == null || traceSession != expected
                || expected.markPath == null
                || expected.stopping
                || expected.snapshotExecutor.isShutdown()) {
                return;
            }
            if (expected.pendingSnapshot != null) {
                expected.pendingSnapshot.cancel(false);
            }
            final long generation = ++expected.snapshotGeneration;
            expected.pendingSnapshot = expected.snapshotExecutor.schedule(
                new Runnable() {
                    @Override
                    public void run() {
                        synchronized (TRACE_LOCK) {
                            if (traceSession != expected
                                || generation
                                    != expected.snapshotGeneration) {
                                return;
                            }
                            expected.pendingSnapshot = null;
                        }
                        captureTraceMarkSnapshot(expected, reason);
                    }
                },
                Math.max(0L, delayMillis),
                TimeUnit.MILLISECONDS
            );
        }
    }

    private static boolean isTraceSessionActive(TraceSession expected) {
        synchronized (TRACE_LOCK) {
            return expected != null && traceSession == expected;
        }
    }

    private static boolean captureTraceMarkSnapshot(
        TraceSession expected,
        String reason
    ) {
        if (!isTraceSessionActive(expected) || expected.markPath == null) {
            return false;
        }
        Activity activity = expected.activity.get();
        File mark = new File(expected.markPath);
        try {
            if (!mark.isFile()) {
                FileIdentity missingBefore = FileIdentity.capture(mark);
                boolean changed;
                synchronized (TRACE_LOCK) {
                    if (traceSession != expected) {
                        return false;
                    }
                    changed = traceSession == expected
                        && !"missing".equals(expected.lastSnapshotHash);
                }
                FileIdentity missingAfter = FileIdentity.capture(mark);
                if (!FileIdentity.missing().sameAs(missingBefore)
                    || !missingBefore.sameAs(missingAfter)) {
                    traceEvent(
                        activity,
                        "mark_snapshot_unstable",
                        "reason",
                        reason,
                        "phase",
                        "missing_recheck"
                    );
                    return false;
                }
                synchronized (TRACE_LOCK) {
                    if (traceSession != expected) {
                        return false;
                    }
                    expected.lastSnapshotHash = "missing";
                    expected.lastSnapshotIdentity = missingAfter;
                }
                if (changed) {
                    traceEvent(
                        activity,
                        "mark_snapshot",
                        "reason",
                        reason,
                        "exists",
                        false
                    );
                }
                return true;
            }
            if (mark.length() > TRACE_MAX_SNAPSHOT_BYTES) {
                traceEvent(
                    activity,
                    "mark_snapshot_skipped",
                    "reason",
                    reason,
                    "length",
                    mark.length(),
                    "limit",
                    TRACE_MAX_SNAPSHOT_BYTES
                );
                return false;
            }
            FileIdentity before = FileIdentity.capture(mark);
            String hash = sha256(mark);
            FileIdentity after = FileIdentity.capture(mark);
            if (!before.sameAs(after)) {
                traceEvent(
                    activity,
                    "mark_snapshot_unstable",
                    "reason",
                    reason,
                    "lengthBefore",
                    before.length,
                    "lengthAfter",
                    after.length
                );
                return false;
            }
            boolean unchanged;
            synchronized (TRACE_LOCK) {
                if (traceSession != expected) {
                    return false;
                }
                unchanged = hash.equals(expected.lastSnapshotHash);
            }
            if (unchanged) {
                FileIdentity unchangedVerified = FileIdentity.capture(mark);
                if (!after.sameAs(unchangedVerified)) {
                    traceEvent(
                        activity,
                        "mark_snapshot_unstable",
                        "reason",
                        reason,
                        "phase",
                        "unchanged_recheck",
                        "lengthBefore",
                        after.length,
                        "lengthAfter",
                        unchangedVerified.length
                    );
                    return false;
                }
                synchronized (TRACE_LOCK) {
                    if (traceSession != expected
                        || !hash.equals(expected.lastSnapshotHash)) {
                        return false;
                    }
                    expected.lastSnapshotIdentity = unchangedVerified;
                }
                traceEvent(
                    activity,
                    "mark_snapshot_unchanged",
                    "reason",
                    reason,
                    "sha256",
                    hash,
                    "length",
                    unchangedVerified.length
                );
                return true;
            }
            long sequenceHint;
            synchronized (TRACE_LOCK) {
                sequenceHint = expected.sequence + 1L;
            }
            String fileName = String.format(
                Locale.US,
                "%06d-%s-p%d-%s.mark",
                sequenceHint,
                traceSanitize(reason),
                traceCurrentMarkPage(activity),
                hash.substring(0, Math.min(12, hash.length()))
            );
            File snapshot = new File(expected.snapshotDirectory, fileName);
            copyTraceFile(mark, snapshot);
            FileIdentity publishedSource = FileIdentity.capture(mark);
            String publishedHash = sha256(snapshot);
            FileIdentity verifiedSource = FileIdentity.capture(mark);
            if (!after.sameAs(publishedSource)
                || !publishedSource.sameAs(verifiedSource)
                || !hash.equals(publishedHash)) {
                snapshot.delete();
                traceEvent(
                    activity,
                    "mark_snapshot_unstable",
                    "reason",
                    reason,
                    "phase",
                    "copy",
                    "expectedSha256",
                    hash,
                    "snapshotSha256",
                    publishedHash
                );
                return false;
            }
            FileIdentity acceptedSource = FileIdentity.capture(mark);
            if (!verifiedSource.sameAs(acceptedSource)) {
                snapshot.delete();
                traceEvent(
                    activity,
                    "mark_snapshot_unstable",
                    "reason",
                    reason,
                    "phase",
                    "acceptance_recheck",
                    "lengthBefore",
                    verifiedSource.length,
                    "lengthAfter",
                    acceptedSource.length
                );
                return false;
            }
            synchronized (TRACE_LOCK) {
                if (traceSession != expected) {
                    snapshot.delete();
                    return false;
                }
                expected.lastSnapshotHash = hash;
                expected.lastSnapshotIdentity = acceptedSource;
            }
            traceEvent(
                activity,
                "mark_snapshot",
                "reason",
                reason,
                "exists",
                true,
                "sha256",
                hash,
                "length",
                acceptedSource.length,
                "snapshot",
                snapshot.getName()
            );
            return true;
        } catch (Throwable throwable) {
            traceEvent(
                activity,
                "mark_snapshot_failed",
                "reason",
                reason,
                "error",
                String.valueOf(throwable)
            );
            return false;
        }
    }

    private static void traceEvent(
        Activity activity,
        String event,
        Object... values
    ) {
        TraceSession expected = traceSession;
        if (expected == null) {
            return;
        }
        traceEvent(
            expected,
            TraceEventContext.capture(activity),
            event,
            values
        );
    }

    private static void traceEvent(
        TraceSession expected,
        TraceEventContext context,
        String event,
        Object... values
    ) {
        synchronized (TRACE_LOCK) {
            if (expected == null || traceSession != expected) {
                return;
            }
            try {
                JSONObject entry = new JSONObject();
                entry.put("schema", TRACE_SCHEMA_VERSION);
                entry.put("session", expected.id);
                entry.put("seq", ++expected.sequence);
                entry.put("wallMs", System.currentTimeMillis());
                entry.put("uptimeMs", SystemClock.uptimeMillis());
                entry.put("pid", Process.myPid());
                entry.put("tid", Process.myTid());
                entry.put("thread", Thread.currentThread().getName());
                entry.put("event", event);
                if (context != null) {
                    context.writeTo(entry);
                }
                if (values != null) {
                    for (int index = 0; index + 1 < values.length; index += 2) {
                        String key = String.valueOf(values[index]);
                        Object value = values[index + 1];
                        entry.put(key, value == null ? JSONObject.NULL : value);
                    }
                }
                final String record = entry.toString() + "\n";
                queueTraceEventRecord(expected, event, record);
            } catch (Throwable throwable) {
                Log.e(TAG, "trace_event_failed event=" + event, throwable);
            }
        }
    }

    private static void queueTraceEventRecord(
        final TraceSession expected,
        final String event,
        final String record
    ) {
        try {
            expected.eventExecutor.execute(
                new Runnable() {
                    @Override
                    public void run() {
                        try {
                            appendTraceRecord(expected.eventFile, record);
                        } catch (Throwable throwable) {
                            expected.eventWriteFailure = String.valueOf(
                                throwable
                            );
                            Log.e(
                                TAG,
                                "trace_event_write_failed event=" + event,
                                throwable
                            );
                        }
                    }
                }
            );
        } catch (Throwable throwable) {
            expected.eventWriteFailure = String.valueOf(throwable);
            Log.e(
                TAG,
                "trace_event_queue_failed event=" + event,
                throwable
            );
        }
    }

    private static void traceLogMessage(String message) {
        TraceSession expected = traceSession;
        if (expected == null) {
            return;
        }
        traceEvent(expected, null, "module_log", "message", message);
    }

    private static int traceCurrentDocumentPage(Activity activity) {
        try {
            return currentDocumentPage(activity);
        } catch (Throwable throwable) {
            return -1;
        }
    }

    private static int traceCurrentMarkPage(Activity activity) {
        try {
            Object presenter = XposedHelpers.getObjectField(
                activity,
                "handWritePresenter"
            );
            return XposedHelpers.getIntField(presenter, "currentPage");
        } catch (Throwable throwable) {
            return -1;
        }
    }

    private static void appendTraceRecord(File file, String record)
        throws Exception {
        byte[] bytes = record.getBytes("UTF-8");
        try (FileOutputStream output = new FileOutputStream(file, true)) {
            output.write(bytes);
            output.flush();
        }
    }

    private static void writeTraceText(File file, String value)
        throws Exception {
        File parent = file.getParentFile();
        if (parent != null && !parent.isDirectory() && !parent.mkdirs()) {
            throw new IllegalStateException("could not create " + parent);
        }
        try (FileOutputStream output = new FileOutputStream(file, false)) {
            output.write(value.getBytes("UTF-8"));
            output.flush();
            output.getFD().sync();
        }
    }

    private static void copyTraceFile(File source, File destination)
        throws Exception {
        File parent = destination.getParentFile();
        if (parent != null && !parent.isDirectory() && !parent.mkdirs()) {
            throw new IllegalStateException("could not create " + parent);
        }
        File temporary = new File(
            parent,
            destination.getName() + ".tmp"
        );
        byte[] buffer = new byte[64 * 1024];
        try (FileInputStream input = new FileInputStream(source);
             FileOutputStream output = new FileOutputStream(temporary)) {
            int count;
            while ((count = input.read(buffer)) >= 0) {
                if (count > 0) {
                    output.write(buffer, 0, count);
                }
            }
            output.flush();
            output.getFD().sync();
        }
        if (destination.isFile() && !destination.delete()) {
            throw new IllegalStateException(
                "could not replace " + destination
            );
        }
        if (!temporary.renameTo(destination)) {
            throw new IllegalStateException(
                "could not publish " + destination
            );
        }
    }

    private static String sha256Text(String value) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(value.getBytes("UTF-8"));
        StringBuilder result = new StringBuilder(hash.length * 2);
        for (byte item : hash) {
            result.append(String.format("%02x", item & 0xff));
        }
        return result.toString();
    }

    private static String traceSanitize(String value) {
        if (value == null || value.length() == 0) {
            return "untitled";
        }
        String sanitized = value.replaceAll("[^A-Za-z0-9._-]", "_");
        if (sanitized.length() > 72) {
            sanitized = sanitized.substring(0, 72);
        }
        return sanitized.length() == 0 ? "untitled" : sanitized;
    }

    private static String currentDocumentPath(Activity activity) {
        if (activity == null) {
            return null;
        }
        try {
            Object viewModel = XposedHelpers.getObjectField(
                activity,
                "documentViewModel"
            );
            Uri uri = (Uri) XposedHelpers.getObjectField(viewModel, "uri");
            return uri == null ? null : uri.getPath();
        } catch (Throwable throwable) {
            log("handshake_document_path_failed " + throwable);
            return null;
        }
    }

    private static boolean sameCanonicalPath(String first, String second) {
        if (first == null || second == null) {
            return false;
        }
        try {
            return new File(first).getCanonicalPath().equals(
                new File(second).getCanonicalPath()
            );
        } catch (Throwable throwable) {
            return false;
        }
    }

    private static boolean protectedEditableBackupValid(
        File document,
        Properties markerProperties
    ) {
        try {
            if (!"supernote-rtl-reader".equals(
                    markerProperties.getProperty("managedBy", "").trim()
                )
                || !"protected-editable-pilot".equals(
                    markerProperties.getProperty("mode", "").trim()
                )
                || !"true".equalsIgnoreCase(
                    markerProperties.getProperty("backupVerified", "false").trim()
                )
                || !sameCanonicalPath(
                    markerProperties.getProperty("documentPath"),
                    document.getCanonicalPath()
                )) {
                log("protected_editable_backup_rejected reason=marker_attestation");
                return false;
            }

            File parent = document.getParentFile();
            if (parent == null) {
                return false;
            }
            File expectedManifest = new File(
                parent,
                "." + document.getName() + ".snspread-backup.properties"
            );
            String markerManifestPath = markerProperties.getProperty(
                "backupManifestPath",
                ""
            );
            if (!expectedManifest.isFile()
                || !sameCanonicalPath(
                    markerManifestPath,
                    expectedManifest.getCanonicalPath()
                )) {
                log("protected_editable_backup_rejected reason=manifest_path");
                return false;
            }
            String expectedManifestHash = markerProperties.getProperty(
                "backupManifestSha256",
                ""
            ).trim();
            if (expectedManifestHash.length() != 64
                || !expectedManifestHash.equals(sha256(expectedManifest))) {
                log("protected_editable_backup_rejected reason=manifest_hash");
                return false;
            }

            Properties backup = new Properties();
            try (FileInputStream input = new FileInputStream(expectedManifest)) {
                backup.load(input);
            }
            if (!"1".equals(backup.getProperty("version", "").trim())
                || !"supernote-rtl-reader".equals(
                    backup.getProperty("managedBy", "").trim()
                )
                || !sameCanonicalPath(
                    backup.getProperty("documentPath"),
                    document.getCanonicalPath()
                )
                || Long.parseLong(backup.getProperty("documentLength", "-1"))
                    != document.length()
                || !backup.getProperty("documentSha256", "").trim().equals(
                    sha256(document)
                )) {
                log("protected_editable_backup_rejected reason=document_identity");
                return false;
            }

            long backedUpModified = Long.parseLong(
                backup.getProperty("documentModified", "-1")
            );
            if (backedUpModified != document.lastModified()) {
                log("protected_editable_document_mtime_changed original="
                    + backedUpModified + " current=" + document.lastModified()
                    + " content_sha256_verified=true");
            }

            File expectedMark = new File(document.getAbsolutePath() + ".mark");
            File expectedSnapshot = new File(
                parent,
                "." + document.getName() + ".snspread-backup.mark"
            );
            if (!sameCanonicalPath(
                    backup.getProperty("markPath"),
                    expectedMark.getCanonicalPath()
                )
                || !sameCanonicalPath(
                    backup.getProperty("snapshotPath"),
                    expectedSnapshot.getCanonicalPath()
                )) {
                log("protected_editable_backup_rejected reason=annotation_path");
                return false;
            }

            boolean originalPresent = "true".equalsIgnoreCase(
                backup.getProperty("originalMarkPresent", "false").trim()
            );
            long markLength = Long.parseLong(
                backup.getProperty("markLength", "-1")
            );
            String markHash = backup.getProperty("markSha256", "").trim();
            if (originalPresent) {
                if (!expectedSnapshot.isFile()
                    || expectedSnapshot.length() != markLength
                    || !markHash.equals(sha256(expectedSnapshot))) {
                    log("protected_editable_backup_rejected reason=snapshot_bytes");
                    return false;
                }
            } else if (markLength != 0L
                || !"ABSENT".equals(markHash)
                || expectedSnapshot.exists()) {
                log("protected_editable_backup_rejected reason=absent_snapshot");
                return false;
            }
            log("protected_editable_backup_verified manifest="
                + expectedManifest.getAbsolutePath()
                + " original_mark_present=" + originalPresent);
            return true;
        } catch (Throwable throwable) {
            log("protected_editable_backup_rejected reason=exception " + throwable);
            return false;
        }
    }

    private static ProtectedVerification startProtectedEditableVerification(
        Activity activity,
        File document,
        Properties markerProperties,
        String documentPath,
        long documentModified,
        long documentLength,
        long documentDevice,
        long documentInode,
        long documentChangeSeconds,
        long documentChangeNanos,
        String markerPath,
        FileIdentity markerIdentity,
        FileIdentity backupIdentity,
        FileIdentity snapshotIdentity
    ) {
        ProtectedVerification verification = new ProtectedVerification(
            documentPath,
            documentModified,
            documentLength,
            documentDevice,
            documentInode,
            documentChangeSeconds,
            documentChangeNanos,
            markerPath,
            markerIdentity,
            backupIdentity,
            snapshotIdentity
        );
        PROTECTED_VERIFICATIONS.put(activity, verification);

        Properties verificationProperties = new Properties();
        verificationProperties.putAll(markerProperties);
        File verificationDocument = new File(document.getAbsolutePath());
        WeakReference<Activity> activityReference =
            new WeakReference<>(activity);
        Handler mainHandler = new Handler(activity.getMainLooper());
        Thread worker = new Thread(() -> {
            boolean valid = protectedEditableBackupValid(
                verificationDocument,
                verificationProperties
            );
            mainHandler.post(() -> {
                Activity currentActivity = activityReference.get();
                if (currentActivity == null
                    || currentActivity.isFinishing()
                    || (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1
                        && currentActivity.isDestroyed())
                    || PROTECTED_VERIFICATIONS.get(currentActivity)
                        != verification) {
                    return;
                }
                verification.complete = true;
                verification.valid = valid;
                SPREAD_CONFIGS.remove(currentActivity);
                log("protected_editable_backup_verification_complete valid="
                    + valid + " path=" + verification.documentPath);
                updateNativeEraserGate(
                    currentActivity,
                    "protected_backup_verified"
                );
                if (valid && currentActivity.getResources()
                        .getConfiguration().orientation
                        == Configuration.ORIENTATION_LANDSCAPE) {
                    log("protected_editable_backup_refresh_scheduled path="
                        + verification.documentPath);
                    scheduleConfigurationRefresh(
                        currentActivity,
                        Configuration.ORIENTATION_LANDSCAPE,
                        0
                    );
                }
            });
        }, "SNSpreadBackupVerify");
        worker.setDaemon(true);
        try {
            worker.start();
            log("protected_editable_backup_verification_started path="
                + verification.documentPath);
        } catch (Throwable throwable) {
            verification.complete = true;
            verification.valid = false;
            log("protected_editable_backup_verification_failed_to_start "
                + throwable);
        }
        return verification;
    }

    private static String sha256(File file) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] buffer = new byte[64 * 1024];
        try (FileInputStream input = new FileInputStream(file)) {
            int count;
            while ((count = input.read(buffer)) >= 0) {
                if (count > 0) {
                    digest.update(buffer, 0, count);
                }
            }
        }
        StringBuilder value = new StringBuilder(64);
        for (byte item : digest.digest()) {
            value.append(String.format("%02x", item & 0xff));
        }
        return value.toString();
    }

    private static boolean prepareNativeSpreadLasso(
        Object superNoteNote,
        List<?> operationTrails
    ) {
        for (Object trail : operationTrails) {
            if (trail == null) {
                continue;
            }
            try {
                int penType = (Integer) XposedHelpers.callMethod(
                    trail,
                    "get_pen_type"
                );
                int processMode = (Integer) XposedHelpers.callMethod(
                    trail,
                    "get_process_mod"
                );
                int redrawWidth = (Integer) XposedHelpers.callMethod(
                    trail,
                    "get_m_redraw_width"
                );
                int redrawHeight = (Integer) XposedHelpers.callMethod(
                    trail,
                    "get_m_redraw_height"
                );
                boolean halfPageGeometry =
                    redrawWidth == SPREAD_PAGE_WIDTH
                    && redrawHeight == SPREAD_PAGE_HEIGHT;
                if (penType != 4 || processMode != 1
                    || !halfPageGeometry) {
                    continue;
                }
                Object recognitionBounds = XposedHelpers.callMethod(
                    trail,
                    "get_rrd"
                );
                Rect before = recognitionBounds == null
                    ? null
                    : (Rect) XposedHelpers.callMethod(
                        recognitionBounds,
                        "getRect"
                    );
                Rect after = scaleRect(
                    before,
                    redrawWidth,
                    redrawHeight,
                    CANONICAL_PAGE_WIDTH,
                    CANONICAL_PAGE_HEIGHT
                );
                PluginLassoGeometry pageGeometry =
                    buildPluginLassoGeometry(superNoteNote, after);
                if (after == null || pageGeometry == null) {
                    log("lasso_native_resubmit_failed geometry_null");
                    continue;
                }

                int originalFlagPenup = (Integer) XposedHelpers.callMethod(
                    trail,
                    "get_flag_penup"
                );
                int originalLayer = (Integer) XposedHelpers.callMethod(
                    trail,
                    "get_layer_num"
                );
                int originalRecognitionMode =
                    (Integer) XposedHelpers.callMethod(
                        trail,
                        "get_rec_mod"
                    );
                int originalThickness = (Integer) XposedHelpers.callMethod(
                    trail,
                    "get_m_thickness"
                );
                int originalWalcomType = (Integer) XposedHelpers.callMethod(
                    trail,
                    "get_walcom_emr_type"
                );
                int originalPointAxis = (Integer) XposedHelpers.callMethod(
                    trail,
                    "get_m_emr_point_axis"
                );
                String originalAppName = (String) XposedHelpers.callMethod(
                    trail,
                    "get_write_app_name"
                );
                int originalPage = (Integer) XposedHelpers.callMethod(
                    trail,
                    "get_page_num"
                );
                int originalMaxX = (Integer) XposedHelpers.callMethod(
                    trail,
                    "get_max_x"
                );
                int originalMaxY = (Integer) XposedHelpers.callMethod(
                    trail,
                    "get_max_y"
                );
                Object originalPoints = XposedHelpers.callMethod(
                    trail,
                    "get_m_points"
                );
                ArrayList<Point> scaledPoints = scaleLassoPoints(
                    originalPoints,
                    originalMaxX,
                    originalMaxY,
                    pageGeometry.maxX,
                    pageGeometry.maxY
                );
                if (scaledPoints == null || scaledPoints.size() < 3) {
                    log("lasso_native_resubmit_failed points_unavailable");
                    continue;
                }

                boolean originAccepted = setSpreadMarkOrigin(
                    superNoteNote,
                    0,
                    "lasso_native_resubmit"
                );
                if (!originAccepted) {
                    log("lasso_native_resubmit_failed origin_zero_rejected");
                    continue;
                }
                spreadLassoOriginZero = true;

                Object result;
                try {
                    XposedHelpers.callMethod(trail, "set_flag_penup", -1);
                    XposedHelpers.callMethod(trail, "set_layer_num", 0);
                    XposedHelpers.callMethod(trail, "set_rec_mod", 10);
                    XposedHelpers.callMethod(trail, "set_m_thickness", 200);
                    XposedHelpers.callMethod(
                        trail,
                        "set_walcom_emr_type",
                        26
                    );
                    XposedHelpers.callMethod(
                        trail,
                        "set_m_emr_point_axis",
                        1
                    );
                    XposedHelpers.callMethod(
                        trail,
                        "set_write_app_name",
                        "superNoteNote"
                    );
                    XposedHelpers.callMethod(trail, "set_process_mod", 0);
                    XposedHelpers.callMethod(
                        trail,
                        "set_m_redraw_width",
                        CANONICAL_PAGE_WIDTH
                    );
                    XposedHelpers.callMethod(
                        trail,
                        "set_m_redraw_height",
                        CANONICAL_PAGE_HEIGHT
                    );
                    XposedHelpers.callMethod(recognitionBounds, "setRect", after);
                    XposedHelpers.callMethod(
                        trail,
                        "set_m_points",
                        scaledPoints
                    );
                    XposedHelpers.callMethod(
                        trail,
                        "set_max_x",
                        pageGeometry.maxX
                    );
                    XposedHelpers.callMethod(
                        trail,
                        "set_max_y",
                        pageGeometry.maxY
                    );
                    result = XposedHelpers.callMethod(
                        superNoteNote,
                        "lassoTrailsByTrail",
                        "MAINLAYER",
                        trail
                    );
                } finally {
                    XposedHelpers.callMethod(
                        trail,
                        "set_flag_penup",
                        originalFlagPenup
                    );
                    XposedHelpers.callMethod(
                        trail,
                        "set_layer_num",
                        originalLayer
                    );
                    XposedHelpers.callMethod(
                        trail,
                        "set_rec_mod",
                        originalRecognitionMode
                    );
                    XposedHelpers.callMethod(
                        trail,
                        "set_m_thickness",
                        originalThickness
                    );
                    XposedHelpers.callMethod(
                        trail,
                        "set_walcom_emr_type",
                        originalWalcomType
                    );
                    XposedHelpers.callMethod(
                        trail,
                        "set_m_emr_point_axis",
                        originalPointAxis
                    );
                    XposedHelpers.callMethod(
                        trail,
                        "set_write_app_name",
                        originalAppName
                    );
                    XposedHelpers.callMethod(
                        trail,
                        "set_process_mod",
                        processMode
                    );
                    XposedHelpers.callMethod(
                        trail,
                        "set_page_num",
                        originalPage
                    );
                    XposedHelpers.callMethod(
                        trail,
                        "set_m_redraw_width",
                        redrawWidth
                    );
                    XposedHelpers.callMethod(
                        trail,
                        "set_m_redraw_height",
                        redrawHeight
                    );
                    XposedHelpers.callMethod(
                        recognitionBounds,
                        "setRect",
                        before
                    );
                    XposedHelpers.callMethod(
                        trail,
                        "set_m_points",
                        originalPoints
                    );
                    XposedHelpers.callMethod(
                        trail,
                        "set_max_x",
                        originalMaxX
                    );
                    XposedHelpers.callMethod(
                        trail,
                        "set_max_y",
                        originalMaxY
                    );
                }

                boolean accepted = Boolean.TRUE.equals(result);
                spreadLassoToolArmed = false;
                spreadLassoActive = accepted;
                spreadLassoCanonicalSelection = accepted;
                if (!accepted) {
                    restoreSpreadLassoOrigin(
                        superNoteNote,
                        "lasso_native_resubmit_rejected"
                    );
                }
                log("lasso_native_resubmitted accepted=" + accepted
                    + " redraw=" + redrawWidth + "x" + redrawHeight
                    + "->" + CANONICAL_PAGE_WIDTH + "x"
                    + CANONICAL_PAGE_HEIGHT + " rrd="
                    + rectDescription(before) + "->"
                    + rectDescription(after) + " points="
                    + scaledPoints.size() + " max=" + originalMaxX + "x"
                    + originalMaxY + "->" + pageGeometry.maxX + "x"
                    + pageGeometry.maxY + " origin_zero="
                    + spreadLassoOriginZero);
                return accepted;
            } catch (Throwable throwable) {
                log("lasso_native_prepare_failed " + throwable);
                XposedBridge.log(throwable);
            }
        }
        return false;
    }

    private static ArrayList<Point> scaleLassoPoints(
        Object pointsObject,
        int sourceMaxX,
        int sourceMaxY,
        int targetMaxX,
        int targetMaxY
    ) {
        if (!(pointsObject instanceof List) || sourceMaxX <= 0
            || sourceMaxY <= 0 || targetMaxX <= 0 || targetMaxY <= 0) {
            return null;
        }
        ArrayList<Point> scaled = new ArrayList<>();
        for (Object item : (List<?>) pointsObject) {
            if (!(item instanceof Point)) {
                continue;
            }
            Point point = (Point) item;
            scaled.add(new Point(
                Math.round(point.x * targetMaxX / (float) sourceMaxX),
                Math.round(point.y * targetMaxY / (float) sourceMaxY)
            ));
        }
        return scaled;
    }

    /*
     * DrawPath reports a landscape-spread lasso in the visible half-page
     * coordinate system.  The document annotation layer remains a canonical
     * 1872x2496 page, so the native selection engine otherwise compares the
     * half-page polygon with full-page trails and returns a negative/empty
     * region.  Re-submit only the exact lasso operation after scaling its
     * redraw metadata and recognition bounds to the canonical page.
     */
    private static void repairSpreadLasso(
        Object superNoteNote,
        List<?> operationTrails
    ) {
        for (Object trail : operationTrails) {
            if (trail == null) {
                continue;
            }
            try {
                int penType = (Integer) XposedHelpers.callMethod(
                    trail,
                    "get_pen_type"
                );
                int processMode = (Integer) XposedHelpers.callMethod(
                    trail,
                    "get_process_mod"
                );
                int redrawWidth = (Integer) XposedHelpers.callMethod(
                    trail,
                    "get_m_redraw_width"
                );
                int redrawHeight = (Integer) XposedHelpers.callMethod(
                    trail,
                    "get_m_redraw_height"
                );
                if (penType != 4 || processMode != 1
                    || redrawWidth != SPREAD_PAGE_WIDTH
                    || redrawHeight != SPREAD_PAGE_HEIGHT) {
                    continue;
                }

                Object recognitionBounds = XposedHelpers.callMethod(
                    trail,
                    "get_rrd"
                );
                Rect before = recognitionBounds == null
                    ? null
                    : (Rect) XposedHelpers.callMethod(
                        recognitionBounds,
                        "getRect"
                    );
                Rect after = scaleRect(
                    before,
                    redrawWidth,
                    redrawHeight,
                    CANONICAL_PAGE_WIDTH,
                    CANONICAL_PAGE_HEIGHT
                );
                PluginLassoGeometry pluginGeometry =
                    buildPluginLassoGeometry(superNoteNote, after);
                if (pluginGeometry == null) {
                    log("lasso_geometry_repair_failed plugin_geometry_null");
                    continue;
                }

                XposedHelpers.callMethod(
                    trail,
                    "set_m_redraw_width",
                    CANONICAL_PAGE_WIDTH
                );
                XposedHelpers.callMethod(
                    trail,
                    "set_m_redraw_height",
                    CANONICAL_PAGE_HEIGHT
                );
                if (recognitionBounds != null && after != null) {
                    XposedHelpers.callMethod(
                        recognitionBounds,
                        "setRect",
                        after
                    );
                }

                boolean originAccepted = setSpreadMarkOrigin(
                    superNoteNote,
                    0,
                    "lasso_select"
                );
                if (!originAccepted) {
                    log("lasso_geometry_repair_failed origin_zero_rejected");
                    continue;
                }
                spreadLassoOriginZero = true;
                int originalFlagPenup = (Integer) XposedHelpers.callMethod(
                    trail,
                    "get_flag_penup"
                );
                int originalLayer = (Integer) XposedHelpers.callMethod(
                    trail,
                    "get_layer_num"
                );
                int originalRecognitionMode =
                    (Integer) XposedHelpers.callMethod(
                        trail,
                        "get_rec_mod"
                    );
                int originalThickness = (Integer) XposedHelpers.callMethod(
                    trail,
                    "get_m_thickness"
                );
                int originalWalcomType = (Integer) XposedHelpers.callMethod(
                    trail,
                    "get_walcom_emr_type"
                );
                int originalPointAxis = (Integer) XposedHelpers.callMethod(
                    trail,
                    "get_m_emr_point_axis"
                );
                String originalAppName = (String) XposedHelpers.callMethod(
                    trail,
                    "get_write_app_name"
                );
                int originalProcessMode = (Integer) XposedHelpers.callMethod(
                    trail,
                    "get_process_mod"
                );
                int originalPage = (Integer) XposedHelpers.callMethod(
                    trail,
                    "get_page_num"
                );
                int originalMaxX = (Integer) XposedHelpers.callMethod(
                    trail,
                    "get_max_x"
                );
                int originalMaxY = (Integer) XposedHelpers.callMethod(
                    trail,
                    "get_max_y"
                );
                Object originalPoints = XposedHelpers.callMethod(
                    trail,
                    "get_m_points"
                );
                Object result;
                try {
                    XposedHelpers.callMethod(
                        trail,
                        "set_flag_penup",
                        -1
                    );
                    XposedHelpers.callMethod(trail, "set_layer_num", 0);
                    XposedHelpers.callMethod(trail, "set_rec_mod", 10);
                    XposedHelpers.callMethod(
                        trail,
                        "set_m_thickness",
                        200
                    );
                    XposedHelpers.callMethod(
                        trail,
                        "set_walcom_emr_type",
                        26
                    );
                    XposedHelpers.callMethod(
                        trail,
                        "set_m_emr_point_axis",
                        1
                    );
                    XposedHelpers.callMethod(
                        trail,
                        "set_write_app_name",
                        "superNoteNote"
                    );
                    XposedHelpers.callMethod(
                        trail,
                        "set_process_mod",
                        0
                    );
                    XposedHelpers.callMethod(
                        trail,
                        "set_page_num",
                        pluginGeometry.page
                    );
                    XposedHelpers.callMethod(
                        trail,
                        "set_m_redraw_width",
                        pluginGeometry.pageWidth
                    );
                    XposedHelpers.callMethod(
                        trail,
                        "set_m_redraw_height",
                        pluginGeometry.pageHeight
                    );
                    XposedHelpers.callMethod(
                        recognitionBounds,
                        "setRect",
                        pluginGeometry.pageBounds
                    );
                    XposedHelpers.callMethod(
                        trail,
                        "set_m_points",
                        pluginGeometry.emrPoints
                    );
                    XposedHelpers.callMethod(
                        trail,
                        "set_max_x",
                        pluginGeometry.maxX
                    );
                    XposedHelpers.callMethod(
                        trail,
                        "set_max_y",
                        pluginGeometry.maxY
                    );
                    result = XposedHelpers.callMethod(
                        superNoteNote,
                        "lassoTrailsByTrail",
                        "MAINLAYER",
                        trail
                    );
                } finally {
                    XposedHelpers.callMethod(
                        trail,
                        "set_flag_penup",
                        originalFlagPenup
                    );
                    XposedHelpers.callMethod(
                        trail,
                        "set_layer_num",
                        originalLayer
                    );
                    XposedHelpers.callMethod(
                        trail,
                        "set_rec_mod",
                        originalRecognitionMode
                    );
                    XposedHelpers.callMethod(
                        trail,
                        "set_m_thickness",
                        originalThickness
                    );
                    XposedHelpers.callMethod(
                        trail,
                        "set_walcom_emr_type",
                        originalWalcomType
                    );
                    XposedHelpers.callMethod(
                        trail,
                        "set_m_emr_point_axis",
                        originalPointAxis
                    );
                    XposedHelpers.callMethod(
                        trail,
                        "set_write_app_name",
                        originalAppName
                    );
                    XposedHelpers.callMethod(
                        trail,
                        "set_process_mod",
                        originalProcessMode
                    );
                    XposedHelpers.callMethod(
                        trail,
                        "set_page_num",
                        originalPage
                    );
                    XposedHelpers.callMethod(
                        trail,
                        "set_m_redraw_width",
                        CANONICAL_PAGE_WIDTH
                    );
                    XposedHelpers.callMethod(
                        trail,
                        "set_m_redraw_height",
                        CANONICAL_PAGE_HEIGHT
                    );
                    if (recognitionBounds != null && after != null) {
                        XposedHelpers.callMethod(
                            recognitionBounds,
                            "setRect",
                            after
                        );
                    }
                    XposedHelpers.callMethod(
                        trail,
                        "set_m_points",
                        originalPoints
                    );
                    XposedHelpers.callMethod(
                        trail,
                        "set_max_x",
                        originalMaxX
                    );
                    XposedHelpers.callMethod(
                        trail,
                        "set_max_y",
                        originalMaxY
                    );
                }
                spreadLassoActive = Boolean.TRUE.equals(result);
                spreadLassoCanonicalSelection = spreadLassoActive;
                if (!spreadLassoActive) {
                    restoreSpreadLassoOrigin(
                        superNoteNote,
                        "lasso_rejected"
                    );
                }
                log("lasso_geometry_repaired redraw="
                    + redrawWidth + "x" + redrawHeight
                    + "->" + CANONICAL_PAGE_WIDTH + "x"
                    + CANONICAL_PAGE_HEIGHT
                    + " rrd=" + rectDescription(before)
                    + "->" + rectDescription(after)
                    + " plugin_metadata=true"
                    + " plugin_page_bounds="
                    + rectDescription(pluginGeometry.pageBounds)
                    + " orientation=" + pluginGeometry.orientation
                    + " device=" + pluginGeometry.device
                    + " accepted=" + result);
            } catch (Throwable throwable) {
                log("lasso_geometry_repair_failed " + throwable);
                XposedBridge.log(throwable);
            }
        }
    }

    private static void repairSpreadLassoDisplayRect(
        Object jniRect,
        String reason
    ) {
        Activity activity = activeActivity;
        if (!spreadLassoActive || jniRect == null || activity == null
            || !isEditableSpreadLandscape(activity)) {
            return;
        }
        try {
            int x = (Integer) XposedHelpers.callMethod(jniRect, "get_x");
            int y = (Integer) XposedHelpers.callMethod(jniRect, "get_y");
            int width = (Integer) XposedHelpers.callMethod(
                jniRect,
                "get_width"
            );
            int height = (Integer) XposedHelpers.callMethod(
                jniRect,
                "get_height"
            );
            Object presenter =
                XposedHelpers.getObjectField(activity, "handWritePresenter");
            RectF writable = resolveActivePageDestination(
                activity,
                presenter
            );
            ImageView imageView =
                (ImageView) XposedHelpers.getObjectField(activity, "mImage");
            int outputWidth = imageView == null
                ? 0
                : imageView.getWidth();
            if (writable == null || outputWidth <= 0) {
                return;
            }
            int slotOffset = Math.round(outputWidth - writable.right);
            float scaleX = writable.width() / CANONICAL_PAGE_WIDTH;
            float scaleY = writable.height() / CANONICAL_PAGE_HEIGHT;
            int canonicalX = spreadLassoOriginZero
                ? x
                : x + slotOffset;
            int repairedX = Math.round(
                writable.left + canonicalX * scaleX
            );
            int repairedY = Math.round(writable.top + y * scaleY);
            int repairedWidth = Math.max(1, Math.round(width * scaleX));
            int repairedHeight = Math.max(1, Math.round(height * scaleY));
            XposedHelpers.callMethod(jniRect, "set_x", repairedX);
            XposedHelpers.callMethod(jniRect, "set_y", repairedY);
            XposedHelpers.callMethod(
                jniRect,
                "set_width",
                repairedWidth
            );
            XposedHelpers.callMethod(
                jniRect,
                "set_height",
                repairedHeight
            );
            log("lasso_display_rect_repaired reason=" + reason
                + " rect=[" + x + "," + y + " "
                + width + "x" + height + "]->["
                + repairedX + "," + repairedY + " "
                + repairedWidth + "x" + repairedHeight + "]"
                + " slot_offset=" + slotOffset
                + " origin_zero=" + spreadLassoOriginZero
                + " scale=" + scaleX + "," + scaleY);
        } catch (Throwable throwable) {
            log("lasso_display_rect_repair_failed reason=" + reason
                + " " + throwable);
            XposedBridge.log(throwable);
        }
    }

    private static Rect canonicalLassoRectToDisplay(Rect source) {
        Activity activity = activeActivity;
        if (source == null || activity == null
            || !isEditableSpreadLandscape(activity)) {
            return null;
        }
        try {
            Object presenter =
                XposedHelpers.getObjectField(activity, "handWritePresenter");
            RectF writable = resolveActivePageDestination(
                activity,
                presenter
            );
            if (writable == null) {
                return null;
            }
            float scaleX = writable.width() / CANONICAL_PAGE_WIDTH;
            float scaleY = writable.height() / CANONICAL_PAGE_HEIGHT;
            return new Rect(
                Math.round(writable.left + source.left * scaleX),
                Math.round(writable.top + source.top * scaleY),
                Math.round(writable.left + source.right * scaleX),
                Math.round(writable.top + source.bottom * scaleY)
            );
        } catch (Throwable throwable) {
            log("lasso_selection_ui_repair_failed " + throwable);
            XposedBridge.log(throwable);
            return null;
        }
    }

    private static Bitmap capturedLassoPreview(Rect canonicalRect) {
        Activity activity = activeActivity;
        if (activity == null || canonicalRect == null) {
            return null;
        }
        try {
            Bitmap fullInk = FULL_INK_BITMAPS.get(activity);
            if (!usable(fullInk)) {
                log("lasso_preview_capture_unavailable");
                return null;
            }
            int left = Math.max(0, Math.min(
                fullInk.getWidth() - 1,
                canonicalRect.left
            ));
            int top = Math.max(0, Math.min(
                fullInk.getHeight() - 1,
                canonicalRect.top
            ));
            int right = Math.max(
                left + 1,
                Math.min(fullInk.getWidth(), canonicalRect.right)
            );
            int bottom = Math.max(
                top + 1,
                Math.min(fullInk.getHeight(), canonicalRect.bottom)
            );
            Bitmap preview = Bitmap.createBitmap(
                fullInk,
                left,
                top,
                right - left,
                bottom - top
            );
            log("lasso_preview_captured source="
                + bitmapDescription(fullInk) + " rect=[" + left + ","
                + top + "-" + right + "," + bottom + "] preview="
                + bitmapDescription(preview));
            return preview;
        } catch (Throwable throwable) {
            log("lasso_preview_capture_failed " + throwable);
            XposedBridge.log(throwable);
            return null;
        }
    }

    /*
     * loadShiftData identifies every selected native trail correctly, but on
     * a spread it sometimes rasterizes only one of two crossing strokes into
     * the floating selection bitmap.  Repaint the selected handwriting from
     * its original EMR points onto that bitmap.  This changes only the preview;
     * native selection, movement, and persistence continue to use the original
     * Supernote trail objects and control numbers.
     */
    private static void prepareSelectedTrailPreview(
        Object superNoteNote,
        Object lassoInfo,
        Bitmap nativePreview
    ) {
        if (spreadLassoCorrectedPreview != null
            && !spreadLassoCorrectedPreview.isRecycled()) {
            spreadLassoCorrectedPreview.recycle();
        }
        spreadLassoCorrectedPreview = null;
        Activity activity = activeActivity;
        if (activity == null || superNoteNote == null || lassoInfo == null
            || !usable(nativePreview)) {
            return;
        }
        try {
            Object controlResult = XposedHelpers.callMethod(
                lassoInfo,
                "getControlnums"
            );
            if (!(controlResult instanceof List)) {
                log("lasso_preview_rebuild_unavailable controls="
                    + controlResult);
                return;
            }
            List<?> controlNumbers = (List<?>) controlResult;
            if (controlNumbers.isEmpty()) {
                return;
            }

            Object presenter = XposedHelpers.getObjectField(
                activity,
                "handWritePresenter"
            );
            String markPath = (String) XposedHelpers.getObjectField(
                presenter,
                "markPath"
            );
            Object trailResult = XposedHelpers.callMethod(
                superNoteNote,
                "getCurPageTrails",
                markPath
            );
            if (!(trailResult instanceof List)) {
                log("lasso_preview_rebuild_unavailable trails="
                    + trailResult);
                return;
            }
            Object shiftBody = XposedHelpers.callMethod(
                superNoteNote,
                "getShiftBodyPosition"
            );
            int shiftX = ((Number) XposedHelpers.callMethod(
                shiftBody,
                "get_x"
            )).intValue();
            int shiftY = ((Number) XposedHelpers.callMethod(
                shiftBody,
                "get_y"
            )).intValue();

            int nonTrailSelections = callInt(lassoInfo, "getLassolinknum")
                + callInt(lassoInfo, "getPnglinknum")
                + callInt(lassoInfo, "getTextlinknum")
                + callInt(lassoInfo, "getTodolinknum")
                + callInt(lassoInfo, "getTitlenum")
                + callInt(lassoInfo, "getBitmapnum")
                + callInt(lassoInfo, "getPlaintextboxnum")
                + callInt(lassoInfo, "getQuotetextboxnum")
                + callInt(lassoInfo, "getCreatetextboxnum")
                + callInt(lassoInfo, "getGeometrynum");
            boolean trailsOnly = callInt(lassoInfo, "getTrailnum") > 0
                && nonTrailSelections == 0;
            Bitmap corrected = trailsOnly
                ? Bitmap.createBitmap(
                    nativePreview.getWidth(),
                    nativePreview.getHeight(),
                    Bitmap.Config.ARGB_8888
                )
                : Bitmap.createBitmap(nativePreview);
            Canvas canvas = new Canvas(corrected);
            Paint paint = new Paint(Paint.ANTI_ALIAS_FLAG);
            paint.setColor(Color.BLACK);
            paint.setStyle(Paint.Style.STROKE);
            paint.setStrokeCap(Paint.Cap.ROUND);
            paint.setStrokeJoin(Paint.Join.ROUND);
            paint.setStrokeWidth(5.0f);

            int drawnTrails = 0;
            for (Object trail : (List<?>) trailResult) {
                if (trail == null) {
                    continue;
                }
                int trailNumber = callInt(
                    trail,
                    "get_m_trail_num_in_page"
                );
                boolean selected = false;
                for (Object control : controlNumbers) {
                    if (control instanceof Number
                        && ((Number) control).intValue() == trailNumber) {
                        selected = true;
                        break;
                    }
                }
                if (!selected) {
                    continue;
                }

                @SuppressWarnings("unchecked")
                List<Point> points = (List<Point>) XposedHelpers.callMethod(
                    trail,
                    "get_m_points"
                );
                int maxX = callInt(trail, "get_max_x");
                int maxY = callInt(trail, "get_max_y");
                if (points == null || points.size() < 2
                    || maxX <= 0 || maxY <= 0) {
                    continue;
                }

                Path path = new Path();
                boolean started = false;
                for (Point point : points) {
                    if (point == null) {
                        continue;
                    }
                    // Orientation 1000 rotates the EMR axes: page X is the
                    // inverse of EMR Y, while page Y follows EMR X.
                    float pageX = CANONICAL_PAGE_WIDTH
                        - point.y * CANONICAL_PAGE_WIDTH / (float) maxY;
                    float pageY = point.x * CANONICAL_PAGE_HEIGHT
                        / (float) maxX;
                    float localX = pageX - shiftX;
                    float localY = pageY - shiftY;
                    if (!started) {
                        path.moveTo(localX, localY);
                        started = true;
                    } else {
                        path.lineTo(localX, localY);
                    }
                }
                if (started) {
                    canvas.drawPath(path, paint);
                    drawnTrails++;
                }
            }

            if (drawnTrails > 0) {
                spreadLassoCorrectedPreview = corrected;
                log("lasso_preview_rebuilt controls=" + controlNumbers
                    + " trails=" + drawnTrails
                    + " trails_only=" + trailsOnly
                    + " shift=" + shiftX + "," + shiftY
                    + " bitmap=" + bitmapDescription(corrected));
            } else {
                corrected.recycle();
                log("lasso_preview_rebuild_empty controls="
                    + controlNumbers);
            }
        } catch (Throwable throwable) {
            log("lasso_preview_rebuild_failed " + throwable);
            XposedBridge.log(throwable);
        }
    }

    private static String jniRectDescription(Object jniRect) {
        if (jniRect == null) {
            return "null";
        }
        try {
            int x = (Integer) XposedHelpers.callMethod(jniRect, "get_x");
            int y = (Integer) XposedHelpers.callMethod(jniRect, "get_y");
            int width = (Integer) XposedHelpers.callMethod(
                jniRect,
                "get_width"
            );
            int height = (Integer) XposedHelpers.callMethod(
                jniRect,
                "get_height"
            );
            return "[" + x + "," + y + " " + width + "x" + height + "]";
        } catch (Throwable throwable) {
            return String.valueOf(jniRect);
        }
    }

    private static boolean setSpreadMarkOrigin(
        Object superNoteNote,
        int originX,
        String reason
    ) {
        Activity activity = activeActivity;
        if (superNoteNote == null || activity == null) {
            return false;
        }
        try {
            Object presenter =
                XposedHelpers.getObjectField(activity, "handWritePresenter");
            int rotation =
                XposedHelpers.getIntField(presenter, "screenRotation");
            boolean accepted = (Boolean) XposedHelpers.callMethod(
                superNoteNote,
                "screenRotation",
                rotation + 2000,
                originX,
                0
            );
            log("lasso_mark_origin reason=" + reason
                + " rotation=" + rotation
                + " origin=" + originX + ",0"
                + " accepted=" + accepted);
            return accepted;
        } catch (Throwable throwable) {
            log("lasso_mark_origin_failed reason=" + reason
                + " " + throwable);
            XposedBridge.log(throwable);
            return false;
        }
    }

    private static void restoreSpreadLassoOrigin(
        Object superNoteNote,
        String reason
    ) {
        if (!spreadLassoOriginZero) {
            return;
        }
        Activity activity = activeActivity;
        try {
            if (activity == null || !isEditableSpreadLandscape(activity)) {
                return;
            }
            Object presenter =
                XposedHelpers.getObjectField(activity, "handWritePresenter");
            RectF writable = resolveActivePageDestination(
                activity,
                presenter
            );
            ImageView imageView =
                (ImageView) XposedHelpers.getObjectField(activity, "mImage");
            int outputWidth = imageView == null
                ? 0
                : imageView.getWidth();
            if (writable == null || outputWidth <= 0) {
                return;
            }
            int slotOffset = Math.round(outputWidth - writable.right);
            setSpreadMarkOrigin(superNoteNote, slotOffset, reason);
        } finally {
            spreadLassoOriginZero = false;
        }
    }

    private static void repairSpreadLassoTransition(
        XC_MethodHook.MethodHookParam param
    ) {
        Activity activity = activeActivity;
        if (!spreadLassoActive || activity == null
            || !isEditableSpreadLandscape(activity)) {
            return;
        }
        try {
            int x = (Integer) param.args[1];
            int y = (Integer) param.args[2];
            int width = (Integer) param.args[3];
            int height = (Integer) param.args[4];
            int mode = (Integer) param.args[5];
            Object presenter =
                XposedHelpers.getObjectField(activity, "handWritePresenter");
            RectF writable = resolveActivePageDestination(
                activity,
                presenter
            );
            ImageView imageView =
                (ImageView) XposedHelpers.getObjectField(activity, "mImage");
            int outputWidth = imageView == null
                ? 0
                : imageView.getWidth();
            if (writable == null || outputWidth <= 0) {
                return;
            }

            int slotOffset = Math.round(outputWidth - writable.right);
            float scaleX = writable.width() / CANONICAL_PAGE_WIDTH;
            float scaleY = writable.height() / CANONICAL_PAGE_HEIGHT;
            int nativeX = Math.round(
                (x - writable.left) / scaleX
            ) - (spreadLassoCanonicalSelection ? 0 : slotOffset);
            int nativeY = Math.round((y - writable.top) / scaleY);
            // The native selection model keeps its canonical dimensions while
            // AreaSelectionView reports a move using the padded native preview
            // size. Only the translated origin is in spread-display space.
            // Applying the inverse half-page scale to the width and height a
            // second time makes a pure move enlarge the selected trails ~2x.
            boolean preserveCanonicalSize =
                spreadLassoCanonicalSelection && mode == 1;
            int nativeWidth = preserveCanonicalSize
                ? width
                : Math.max(1, Math.round(width / scaleX));
            int nativeHeight = preserveCanonicalSize
                ? height
                : Math.max(1, Math.round(height / scaleY));

            param.args[1] = nativeX;
            param.args[2] = nativeY;
            param.args[3] = nativeWidth;
            param.args[4] = nativeHeight;
            log("lasso_transition_repaired mode=" + mode
                + " rect=[" + x + "," + y + " "
                + width + "x" + height + "]->["
                + nativeX + "," + nativeY + " "
                + nativeWidth + "x" + nativeHeight + "]"
                + " slot_offset=" + slotOffset
                + " canonical=" + spreadLassoCanonicalSelection
                + " preserve_size=" + preserveCanonicalSize
                + " scale=" + scaleX + "," + scaleY);
        } catch (Throwable throwable) {
            log("lasso_transition_repair_failed " + throwable);
            XposedBridge.log(throwable);
        }
    }

    private static void beginCanonicalLassoOperation(
        Object presenter,
        String reason
    ) {
        if (!spreadLassoCanonicalSelection
            || spreadLassoOperationOriginZero) {
            return;
        }
        try {
            Object superNoteNote =
                XposedHelpers.getObjectField(presenter, "superNoteNote");
            if (setSpreadMarkOrigin(
                superNoteNote,
                0,
                "operation_" + reason
            )) {
                spreadLassoOriginZero = true;
                spreadLassoOperationOriginZero = true;
            }
        } catch (Throwable throwable) {
            log("lasso_operation_origin_failed reason=" + reason
                + " " + throwable);
            XposedBridge.log(throwable);
        }
    }

    private static void endCanonicalLassoOperation(
        Object presenter,
        String reason
    ) {
        if (!spreadLassoOperationOriginZero) {
            return;
        }
        try {
            Object superNoteNote =
                XposedHelpers.getObjectField(presenter, "superNoteNote");
            restoreSpreadLassoOrigin(
                superNoteNote,
                "operation_" + reason + "_done"
            );
        } catch (Throwable throwable) {
            log("lasso_operation_restore_failed reason=" + reason
                + " " + throwable);
            XposedBridge.log(throwable);
        } finally {
            spreadLassoOperationOriginZero = false;
        }
    }

    private static Rect scaleRect(
        Rect source,
        int sourceWidth,
        int sourceHeight,
        int targetWidth,
        int targetHeight
    ) {
        if (source == null || sourceWidth <= 0 || sourceHeight <= 0) {
            return null;
        }
        return new Rect(
            Math.round(source.left * targetWidth / (float) sourceWidth),
            Math.round(source.top * targetHeight / (float) sourceHeight),
            Math.round(source.right * targetWidth / (float) sourceWidth),
            Math.round(source.bottom * targetHeight / (float) sourceHeight)
        );
    }

    private static PluginLassoGeometry buildPluginLassoGeometry(
        Object superNoteNote,
        Rect canonicalBounds
    ) {
        Activity activity = activeActivity;
        if (activity == null || canonicalBounds == null) {
            return null;
        }
        try {
            Object presenter =
                XposedHelpers.getObjectField(activity, "handWritePresenter");
            String markPath =
                (String) XposedHelpers.getObjectField(presenter, "markPath");
            int page = XposedHelpers.getIntField(presenter, "currentPage");
            int device = (Integer) XposedHelpers.callMethod(
                superNoteNote,
                "getFileCreateDevice",
                markPath
            );
            int orientation = (Integer) XposedHelpers.callMethod(
                superNoteNote,
                "fetchPageOrientation",
                markPath,
                page
            );
            Class<?> pointUtilsClass = Class.forName(
                "com.ratta.supernote.plugincommon.utils.PointUtils",
                true,
                activity.getClassLoader()
            );
            Object pointUtils = pointUtilsClass
                .getDeclaredMethod("getInstance")
                .invoke(null);
            Size pageSize = (Size) XposedHelpers.callMethod(
                pointUtils,
                "getNotePageSize",
                orientation,
                device
            );
            Rect pageBounds = scaleRect(
                canonicalBounds,
                CANONICAL_PAGE_WIDTH,
                CANONICAL_PAGE_HEIGHT,
                pageSize.getWidth(),
                pageSize.getHeight()
            );
            ArrayList<Point> emrPoints = new ArrayList<>();
            emrPoints.add(pluginPointToEmr(
                pointUtils,
                new Point(pageBounds.left, pageBounds.top),
                orientation,
                device
            ));
            emrPoints.add(pluginPointToEmr(
                pointUtils,
                new Point(pageBounds.right, pageBounds.top),
                orientation,
                device
            ));
            emrPoints.add(pluginPointToEmr(
                pointUtils,
                new Point(pageBounds.right, pageBounds.bottom),
                orientation,
                device
            ));
            emrPoints.add(pluginPointToEmr(
                pointUtils,
                new Point(pageBounds.left, pageBounds.bottom),
                orientation,
                device
            ));
            emrPoints.add(pluginPointToEmr(
                pointUtils,
                new Point(pageBounds.left, pageBounds.top),
                orientation,
                device
            ));
            int maxX = (Integer) XposedHelpers.callMethod(
                pointUtils,
                "getRealMaxX",
                device,
                orientation
            );
            int maxY = (Integer) XposedHelpers.callMethod(
                pointUtils,
                "getRealMaxY",
                device,
                orientation
            );
            log("lasso_plugin_points page=" + page
                + " mark=" + markPath
                + " canonical=" + rectDescription(canonicalBounds)
                + " page_bounds=" + rectDescription(pageBounds)
                + " page_size=" + pageSize.getWidth() + "x"
                + pageSize.getHeight()
                + " orientation=" + orientation
                + " device=" + device
                + " max=" + maxX + "x" + maxY
                + " points=" + emrPoints);
            return new PluginLassoGeometry(
                pageBounds,
                emrPoints,
                pageSize.getWidth(),
                pageSize.getHeight(),
                maxX,
                maxY,
                page,
                orientation,
                device
            );
        } catch (Throwable throwable) {
            log("lasso_plugin_points_failed " + throwable);
            XposedBridge.log(throwable);
            return null;
        }
    }

    private static Point pluginPointToEmr(
        Object pointUtils,
        Point point,
        int orientation,
        int device
    ) {
        return (Point) XposedHelpers.callMethod(
            pointUtils,
            "androidPoint2Emr",
            point,
            orientation,
            device
        );
    }

    private static void dumpTrailState(
        Activity activity,
        Object superNoteNote,
        String reason,
        int page,
        List<?> operationTrails
    ) {
        try {
            Object presenter =
                XposedHelpers.getObjectField(activity, "handWritePresenter");
            String markPath =
                (String) XposedHelpers.getObjectField(presenter, "markPath");
            ImageView imageView =
                (ImageView) XposedHelpers.getObjectField(activity, "mImage");
            RectF destination = resolveActivePageDestination(
                activity,
                presenter
            );
            int outputWidth = imageView == null ? 0 : imageView.getWidth();
            int outputHeight = imageView == null ? 0 : imageView.getHeight();
            log("trail_state reason=" + reason
                + " page=" + page
                + " output=" + outputWidth + "x" + outputHeight
                + " destination=" + rectDescription(destination));

            if (operationTrails != null) {
                dumpTrailList(reason + ":operation", operationTrails);
            }

            Object fileResult = XposedHelpers.callMethod(
                superNoteNote,
                "getFilePageTrails",
                markPath,
                page
            );
            dumpTrailList(
                reason + ":file",
                fileResult instanceof List ? (List<?>) fileResult : null
            );

            Object currentResult = XposedHelpers.callMethod(
                superNoteNote,
                "getCurPageTrails",
                markPath
            );
            dumpTrailList(
                reason + ":current",
                currentResult instanceof List ? (List<?>) currentResult : null
            );
        } catch (Throwable throwable) {
            log("trail_state_failed reason=" + reason + " " + throwable);
            XposedBridge.log(throwable);
        }
    }

    private static void dumpTrailList(String reason, List<?> trails) {
        if (trails == null) {
            log("trail_list reason=" + reason + " value=null");
            return;
        }
        log("trail_list reason=" + reason + " count=" + trails.size());
        int limit = Math.min(trails.size(), 32);
        for (int index = 0; index < limit; index++) {
            Object trail = trails.get(index);
            if (trail == null) {
                log("trail reason=" + reason + " index=" + index
                    + " value=null");
                continue;
            }
            try {
                @SuppressWarnings("unchecked")
                List<Point> points = (List<Point>) XposedHelpers.callMethod(
                    trail,
                    "get_m_points"
                );
                Rect pointBounds = pointBounds(points);
                Point first = points == null || points.isEmpty()
                    ? null : points.get(0);
                Point last = points == null || points.isEmpty()
                    ? null : points.get(points.size() - 1);
                Object rrd = XposedHelpers.callMethod(trail, "get_rrd");
                Rect recognitionBounds = null;
                if (rrd != null) {
                    recognitionBounds =
                        (Rect) XposedHelpers.callMethod(rrd, "getRect");
                }
                log("trail reason=" + reason
                    + " index=" + index
                    + " page=" + callInt(trail, "get_page_num")
                    + " trail=" + callInt(trail, "get_trail_num")
                    + " in_page="
                    + callInt(trail, "get_m_trail_num_in_page")
                    + " pen=" + callInt(trail, "get_pen_type")
                    + " status=" + callInt(trail, "get_m_trail_status")
                    + " process=" + callInt(trail, "get_process_mod")
                    + " erased=" + String.valueOf(
                        XposedHelpers.callMethod(
                            trail,
                            "get_erase_line_trail_num"
                        )
                    )
                    + " rotation=" + callInt(trail, "get_m_rotate_angle")
                    + " redraw=" + callInt(trail, "get_m_redraw_width")
                    + "x" + callInt(trail, "get_m_redraw_height")
                    + " emr_axis="
                    + callInt(trail, "get_m_emr_point_axis")
                    + " max=" + callInt(trail, "get_max_x")
                    + "," + callInt(trail, "get_max_y")
                    + " points=" + (points == null ? -1 : points.size())
                    + " first=" + pointDescription(first)
                    + " last=" + pointDescription(last)
                    + " bounds=" + rectDescription(pointBounds)
                    + " rrd=" + rectDescription(recognitionBounds));
            } catch (Throwable throwable) {
                log("trail_failed reason=" + reason + " index=" + index
                    + " " + throwable);
                XposedBridge.log(throwable);
            }
        }
        if (trails.size() > limit) {
            log("trail_list_truncated reason=" + reason
                + " remaining=" + (trails.size() - limit));
        }
    }

    private static int callInt(Object target, String methodName) {
        return ((Number) XposedHelpers.callMethod(
            target,
            methodName
        )).intValue();
    }

    private static Rect pointBounds(List<Point> points) {
        if (points == null || points.isEmpty()) {
            return null;
        }
        int left = Integer.MAX_VALUE;
        int top = Integer.MAX_VALUE;
        int right = Integer.MIN_VALUE;
        int bottom = Integer.MIN_VALUE;
        for (Point point : points) {
            if (point == null) {
                continue;
            }
            left = Math.min(left, point.x);
            top = Math.min(top, point.y);
            right = Math.max(right, point.x);
            bottom = Math.max(bottom, point.y);
        }
        if (left == Integer.MAX_VALUE) {
            return null;
        }
        return new Rect(left, top, right + 1, bottom + 1);
    }

    private static String pointDescription(Point point) {
        return point == null ? "null" : point.x + "," + point.y;
    }

    private static boolean isCalibrationLandscape(Activity activity) {
        return activity.getResources().getConfiguration().orientation
            == Configuration.ORIENTATION_LANDSCAPE
            && isCalibrationFile(activity);
    }

    private static boolean isReadOnlyNativeMode(Activity activity) {
        if (activity == null) {
            return false;
        }
        SpreadConfig config = spreadConfig(activity);
        return config != null && config.enabled && !config.editable;
    }

    private static boolean isEditableSpreadLandscape(Activity activity) {
        if (!isCalibrationLandscape(activity)) {
            return false;
        }
        SpreadConfig config = spreadConfig(activity);
        return config != null && config.editable;
    }

    private static void releaseActivityResources(Activity activity) {
        if (activity == null) {
            return;
        }
        stopAnnotationTrace(activity, "activity_destroyed");
        boolean activeCleared = activeActivity == activity;
        if (activeCleared) {
            activeActivity = null;
        }

        resetSpreadEditingState("activity_destroyed");
        int recycled = 0;
        recycled += recycleRemovedBitmap(COMPOSITES, activity);
        recycled += recycleRemovedBitmap(
            COMMITTED_INK_COMPOSITES,
            activity
        );
        recycled += recycleRemovedBitmap(FULL_INK_BITMAPS, activity);
        recycled += recycleRemovedBitmap(DIGEST_COMPOSITES, activity);
        REPLACE_ACTIVE_INK_MODES.remove(activity);
        CANONICAL_ONLY_INK_MODES.remove(activity);
        LEFT_DESTINATIONS.remove(activity);
        RIGHT_DESTINATIONS.remove(activity);
        LEFT_VISIBLE_BOUNDS.remove(activity);
        RIGHT_VISIBLE_BOUNDS.remove(activity);
        ACTIVATION_TOUCH_TARGETS.remove(activity);
        ACTIVATION_TOUCH_STARTS.remove(activity);
        PAGE_ACTIVATION_BLOCKED_TOUCHES.remove(activity);
        PAGE_ACTIVATION_TRANSACTIONS.remove(activity);
        DEFERRED_SPREAD_TURNS.remove(activity);
        PEN_CONTACT_START_PAGES.remove(activity);
        PEN_ACTIVATION_TARGETS.remove(activity);
        PEN_ACTIVATION_ORIGINAL_PAGES.remove(activity);
        PEN_ACTIVATION_TRAILS.remove(activity);
        PEN_ACTIVATION_ERASERS.remove(activity);
        PEN_ACTIVATION_STALE_SAVE_PENDING.remove(activity);
        clearPageEditHistory(activity);
        FINGER_TOUCH_STARTS.remove(activity);
        NON_EDGE_TAP_SUPPRESS_UNTIL.remove(activity);
        TRACE_LAST_PRESSURES.remove(activity);
        TRACE_TRANSACTION_IDS.remove(activity);
        TRACE_TOOLS.remove(activity);
        PEN_INPUT_SNAPSHOTS.remove(activity);
        PEN_INPUT_BLOCK_LOG_STATES.remove(activity);
        SPREAD_CONFIGS.remove(activity);
        PROTECTED_VERIFICATIONS.remove(activity);
        log("activity_resources_released active_cleared=" + activeCleared
            + " recycled_bitmaps=" + recycled);
    }

    private static int recycleRemovedBitmap(
        Map<Activity, Bitmap> cache,
        Activity activity
    ) {
        Bitmap bitmap = cache.remove(activity);
        if (bitmap == null || bitmap.isRecycled()) {
            return 0;
        }
        bitmap.recycle();
        return 1;
    }

    private static void resetSpreadEditingState(String reason) {
        spreadLassoActive = false;
        spreadLassoOriginZero = false;
        spreadLassoCanonicalSelection = false;
        spreadLassoOperationOriginZero = false;
        spreadLassoToolArmed = false;
        if (spreadLassoCorrectedPreview != null
            && !spreadLassoCorrectedPreview.isRecycled()) {
            spreadLassoCorrectedPreview.recycle();
        }
        spreadLassoCorrectedPreview = null;
        log("spread_editing_state_reset reason=" + reason);
    }

    private static boolean isCalibrationFile(Activity activity) {
        SpreadConfig config = spreadConfig(activity);
        return config != null && config.enabled;
    }

    private static SpreadConfig spreadConfig(Activity activity) {
        try {
            Object viewModel = XposedHelpers.getObjectField(
                activity,
                "documentViewModel"
            );
            Uri uri = (Uri) XposedHelpers.getObjectField(viewModel, "uri");
            String path = uri == null ? null : uri.getPath();
            if (path == null || path.length() == 0) {
                return null;
            }

            if (TARGET_FILE.equals(path)) {
                SpreadConfig calibration = new SpreadConfig(
                    path,
                    0L,
                    0L,
                    0L,
                    0L,
                    0L,
                    0L,
                    null,
                    FileIdentity.missing(),
                    FileIdentity.missing(),
                    FileIdentity.missing(),
                    true,
                    false,
                    true,
                    true,
                    false,
                    true,
                    true
                );
                SPREAD_CONFIGS.put(activity, calibration);
                return calibration;
            }

            File document = new File(path);
            long documentModified = document.isFile()
                ? document.lastModified() : -1L;
            long documentLength = document.isFile()
                ? document.length() : -1L;
            StructStat documentStat = Os.stat(document.getAbsolutePath());
            long documentDevice = documentStat.st_dev;
            long documentInode = documentStat.st_ino;
            long documentChangeSeconds = documentStat.st_ctim.tv_sec;
            long documentChangeNanos = documentStat.st_ctim.tv_nsec;
            File parent = document.getParentFile();
            if (parent == null) {
                return null;
            }
            File marker = new File(
                parent,
                "." + document.getName() + SIDECAR_SUFFIX
            );
            File backupManifest = new File(
                parent,
                "." + document.getName() + ".snspread-backup.properties"
            );
            File backupSnapshot = new File(
                parent,
                "." + document.getName() + ".snspread-backup.mark"
            );
            FileIdentity markerIdentity = FileIdentity.capture(marker);
            FileIdentity backupIdentity = FileIdentity.capture(backupManifest);
            FileIdentity snapshotIdentity = FileIdentity.capture(backupSnapshot);
            SpreadConfig cached = SPREAD_CONFIGS.get(activity);
            if (cached != null && path.equals(cached.documentPath)
                && cached.documentModified == documentModified
                && cached.documentLength == documentLength
                && cached.documentDevice == documentDevice
                && cached.documentInode == documentInode
                && cached.documentChangeSeconds == documentChangeSeconds
                && cached.documentChangeNanos == documentChangeNanos
                && marker.getAbsolutePath().equals(cached.markerPath)
                && cached.markerIdentity.sameAs(markerIdentity)
                && cached.backupIdentity.sameAs(backupIdentity)
                && cached.snapshotIdentity.sameAs(snapshotIdentity)) {
                return cached;
            }

            if (!marker.isFile()) {
                SpreadConfig disabled = new SpreadConfig(
                    path,
                    documentModified,
                    documentLength,
                    documentDevice,
                    documentInode,
                    documentChangeSeconds,
                    documentChangeNanos,
                    marker.getAbsolutePath(),
                    markerIdentity,
                    backupIdentity,
                    snapshotIdentity,
                    false,
                    false,
                    true,
                    true,
                    false,
                    false,
                    false
                );
                SPREAD_CONFIGS.put(activity, disabled);
                return disabled;
            }

            Properties properties = new Properties();
            try (FileInputStream input = new FileInputStream(marker)) {
                properties.load(input);
            }
            boolean enabled = "true".equalsIgnoreCase(
                properties.getProperty("enabled", "false").trim()
            ) && "rtl".equalsIgnoreCase(
                properties.getProperty("direction", "").trim()
            );
            boolean coverSeparate = "true".equalsIgnoreCase(
                properties.getProperty("coverSeparate", "false").trim()
            );
            boolean showDivider = !"false".equalsIgnoreCase(
                properties.getProperty("showDivider", "true").trim()
            );
            boolean showHeader = !"false".equalsIgnoreCase(
                properties.getProperty("showHeader", "true").trim()
            );
            boolean nativeFill = "native_fill".equalsIgnoreCase(
                properties.getProperty("spreadSizing", "fit").trim()
            );
            boolean disposable = "true".equalsIgnoreCase(
                properties.getProperty("disposable", "false").trim()
            );
            boolean requestedEditable = "true".equalsIgnoreCase(
                properties.getProperty("editable", "false").trim()
            );
            boolean protectedEditable = false;
            if (enabled && requestedEditable && !disposable) {
                ProtectedVerification verification =
                    PROTECTED_VERIFICATIONS.get(activity);
                if (verification == null || !verification.matches(
                        path,
                        documentModified,
                        documentLength,
                        documentDevice,
                        documentInode,
                        documentChangeSeconds,
                        documentChangeNanos,
                        marker.getAbsolutePath(),
                        markerIdentity,
                        backupIdentity,
                        snapshotIdentity
                    )) {
                    verification = startProtectedEditableVerification(
                        activity,
                        document,
                        properties,
                        path,
                        documentModified,
                        documentLength,
                        documentDevice,
                        documentInode,
                        documentChangeSeconds,
                        documentChangeNanos,
                        marker.getAbsolutePath(),
                        markerIdentity,
                        backupIdentity,
                        snapshotIdentity
                    );
                }
                protectedEditable = verification.complete
                    && verification.valid;
            } else {
                PROTECTED_VERIFICATIONS.remove(activity);
            }
            boolean editable = enabled && requestedEditable
                && (disposable || protectedEditable);
            SpreadConfig loaded = new SpreadConfig(
                path,
                documentModified,
                documentLength,
                documentDevice,
                documentInode,
                documentChangeSeconds,
                documentChangeNanos,
                marker.getAbsolutePath(),
                markerIdentity,
                backupIdentity,
                snapshotIdentity,
                enabled,
                coverSeparate,
                showDivider,
                showHeader,
                nativeFill,
                editable,
                false
            );
            SPREAD_CONFIGS.put(activity, loaded);
            log("spread_config_loaded path=" + path
                + " marker=" + marker.getAbsolutePath()
                + " enabled=" + enabled
                + " cover_separate=" + coverSeparate
                + " show_divider=" + showDivider
                + " show_header=" + showHeader
                + " sizing=" + (nativeFill ? "native_fill" : "fit")
                + " editable=" + editable
                + " requested_editable=" + requestedEditable
                + " protected_editable=" + protectedEditable
                + " disposable=" + disposable);
            return loaded;
        } catch (Throwable throwable) {
            log("gate_failed " + throwable);
            return null;
        }
    }

    private static void publishPendingPenInputSnapshot(
        Activity activity,
        SpreadConfig config,
        String reason
    ) {
        if (activity == null) {
            return;
        }
        if (Looper.myLooper() != activity.getMainLooper()) {
            PEN_INPUT_SNAPSHOTS.remove(activity);
            log("pen_input_snapshot_rejected reason=not_ui_thread source="
                + reason);
            return;
        }
        if (config == null) {
            PEN_INPUT_SNAPSHOTS.remove(activity);
            log("pen_input_snapshot_cleared reason=" + reason);
            return;
        }
        try {
            Object viewModel = XposedHelpers.getObjectField(
                activity,
                "documentViewModel"
            );
            int currentPage = XposedHelpers.getIntField(
                viewModel,
                "currentPage"
            );
            int pageCount = XposedHelpers.getIntField(viewModel, "pageCount");
            PEN_INPUT_SNAPSHOTS.put(
                activity,
                new PenInputSnapshot(
                    config,
                    currentPage,
                    pageCount,
                    -1,
                    -1,
                    null,
                    null,
                    false
                )
            );
            log("pen_input_snapshot_pending current=" + currentPage
                + " editable=" + (config.enabled && config.editable)
                + " reason=" + reason);
        } catch (Throwable throwable) {
            PEN_INPUT_SNAPSHOTS.remove(activity);
            log("pen_input_snapshot_failed reason=" + reason + " "
                + throwable);
        }
    }

    private static void publishPenInputGeometrySnapshot(
        Activity activity,
        SpreadConfig config,
        int currentPage,
        int pageCount,
        SpreadPair pair,
        RectF rightVisibleBounds,
        RectF leftVisibleBounds,
        boolean geometryReady,
        String reason
    ) {
        if (activity == null || config == null || pair == null) {
            if (activity != null) {
                PEN_INPUT_SNAPSHOTS.remove(activity);
            }
            return;
        }
        if (Looper.myLooper() != activity.getMainLooper()) {
            PEN_INPUT_SNAPSHOTS.remove(activity);
            log("pen_input_geometry_rejected reason=not_ui_thread source="
                + reason);
            return;
        }
        boolean ready = geometryReady
            && config.enabled
            && config.editable
            && pair.contains(currentPage)
            && rightVisibleBounds != null
            && (pair.leftPage < 0 || leftVisibleBounds != null);
        PEN_INPUT_SNAPSHOTS.put(
            activity,
            new PenInputSnapshot(
                config,
                currentPage,
                pageCount,
                pair.rightPage,
                pair.leftPage,
                rightVisibleBounds,
                leftVisibleBounds,
                ready
            )
        );
        log("pen_input_geometry_published current=" + currentPage
            + " right=" + pair.rightPage
            + " left=" + pair.leftPage
            + " editable=" + (config.enabled && config.editable)
            + " ready=" + ready
            + " reason=" + reason);
    }

    private static void invalidatePenInputGeometrySnapshot(
        Activity activity,
        String reason
    ) {
        if (activity == null) {
            return;
        }
        PenInputSnapshot published = PEN_INPUT_SNAPSHOTS.get(activity);
        if (published == null) {
            return;
        }
        PEN_INPUT_SNAPSHOTS.put(
            activity,
            new PenInputSnapshot(
                published.config,
                published.currentPage,
                published.pageCount,
                published.rightPage,
                published.leftPage,
                published.rightVisibleBounds,
                published.leftVisibleBounds,
                false
            )
        );
        log("pen_input_geometry_invalidated current="
            + published.currentPage + " reason=" + reason);
    }

    private static boolean publishReadyPenInputGeometryAfterActivation(
        Activity activity,
        PageActivationTransaction transaction,
        String reason
    ) {
        PenInputSnapshot pending = penInputSnapshot(activity);
        if (pending == null || transaction == null || !pending.editable
            || pending.currentPage != transaction.targetPage
            || pending.rightPage < 0
            || pending.rightVisibleBounds == null
            || (pending.leftPage >= 0
                && pending.leftVisibleBounds == null)) {
            log("pen_input_geometry_activation_publish_rejected id="
                + (transaction == null ? -1L : transaction.id)
                + " reason=" + reason);
            return false;
        }
        publishPenInputGeometrySnapshot(
            activity,
            pending.config,
            pending.currentPage,
            pending.pageCount,
            new SpreadPair(pending.rightPage, pending.leftPage),
            pending.rightVisibleBounds,
            pending.leftVisibleBounds,
            true,
            reason
        );
        PenInputSnapshot ready = penInputSnapshot(activity);
        return ready != null && ready.geometryReady && ready.editable
            && ready.currentPage == transaction.targetPage;
    }

    private static PenInputSnapshot penInputSnapshot(Activity activity) {
        if (activity == null || activity != activeActivity
            || activity.isFinishing()
            || (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1
                && activity.isDestroyed())) {
            return null;
        }
        PenInputSnapshot snapshot = PEN_INPUT_SNAPSHOTS.get(activity);
        if (snapshot == null) {
            return null;
        }
        try {
            if (activity.getResources().getConfiguration().orientation
                    != Configuration.ORIENTATION_LANDSCAPE
                || !snapshot.documentPath.equals(currentDocumentPath(activity))) {
                return null;
            }
            Object viewModel = XposedHelpers.getObjectField(
                activity,
                "documentViewModel"
            );
            int currentPage = XposedHelpers.getIntField(
                viewModel,
                "currentPage"
            );
            int pageCount = XposedHelpers.getIntField(viewModel, "pageCount");
            return currentPage == snapshot.currentPage
                    && pageCount == snapshot.pageCount
                ? snapshot : null;
        } catch (Throwable throwable) {
            return null;
        }
    }

    private static boolean publishedEditablePenInputLandscape(
        Activity activity
    ) {
        PenInputSnapshot published = activity == null
            ? null : PEN_INPUT_SNAPSHOTS.get(activity);
        if (published == null || !published.editable) {
            return false;
        }
        try {
            return activity.getResources().getConfiguration().orientation
                == Configuration.ORIENTATION_LANDSCAPE;
        } catch (Throwable throwable) {
            return true;
        }
    }

    private static boolean editablePenInputReady(Activity activity) {
        PenInputSnapshot snapshot = penInputSnapshot(activity);
        return snapshot != null && snapshot.editable
            && snapshot.geometryReady;
    }

    private static int pageAt(
        PenInputSnapshot snapshot,
        float x,
        float y
    ) {
        return snapshot == null ? -1 : snapshot.pageAt(x, y);
    }

    private static SpreadPair spreadPair(
        SpreadConfig config,
        int currentPage,
        int pageCount
    ) {
        if (currentPage < 0 || currentPage >= pageCount || pageCount <= 0) {
            return new SpreadPair(-1, -1);
        }
        if (config != null && config.coverSeparate) {
            if (currentPage == 0) {
                return new SpreadPair(0, -1);
            }
            int right = currentPage - ((currentPage - 1) & 1);
            int left = right + 1;
            return new SpreadPair(right, left < pageCount ? left : -1);
        }
        int right = currentPage - (currentPage & 1);
        int left = right + 1;
        return new SpreadPair(right, left < pageCount ? left : -1);
    }

    private static void updateNativeEraserGate(
        Activity activity,
        String reason
    ) {
        SpreadConfig config = spreadConfig(activity);
        publishPendingPenInputSnapshot(activity, config, reason);
        updateNativeEraserGate(
            activity,
            reason,
            activity != null
                && activity.getResources().getConfiguration().orientation
                    == Configuration.ORIENTATION_LANDSCAPE
                && config != null
                && config.enabled
                && config.editable
        );
    }

    private static void updateNativeEraserGate(
        Activity activity,
        String reason,
        boolean enabled
    ) {
        if (!nativeBridgeLoaded) {
            return;
        }
        try {
            nativeSetCalibrationEnabled(enabled);
            log("native_eraser_gate enabled=" + enabled
                + " reason=" + reason
                + " hook_state=" + nativeGetHookState());
        } catch (Throwable throwable) {
            nativeBridgeLoaded = false;
            log("native_eraser_gate_failed reason=" + reason
                + " " + throwable);
            XposedBridge.log(throwable);
        }
    }

    private static void scheduleConfigurationRefresh(
        final Activity activity,
        final int orientation,
        final int attempt
    ) {
        new Handler(activity.getMainLooper()).postDelayed(new Runnable() {
            @Override
            public void run() {
                if (activity.isFinishing() || !isCalibrationFile(activity)) {
                    return;
                }
                try {
                    Object viewModel = XposedHelpers.getObjectField(
                        activity,
                        "documentViewModel"
                    );
                    Bitmap originBitmap = (Bitmap) XposedHelpers.callMethod(
                        viewModel,
                        "getOriginBitmap"
                    );
                    if (!usable(originBitmap)) {
                        if (attempt < 20) {
                            scheduleConfigurationRefresh(
                                activity,
                                orientation,
                                attempt + 1
                            );
                        } else {
                            log("configuration_refresh_abandoned orientation="
                                + orientation);
                        }
                        return;
                    }

                    ImageView imageView = (ImageView) XposedHelpers
                        .getObjectField(activity, "mImage");
                    int viewWidth = imageView == null ? 0 : imageView.getWidth();
                    int viewHeight = imageView == null ? 0 : imageView.getHeight();
                    boolean viewMatchesOrientation = orientation
                        == Configuration.ORIENTATION_LANDSCAPE
                            ? viewWidth > viewHeight
                            : orientation == Configuration.ORIENTATION_PORTRAIT
                                && viewHeight > viewWidth;
                    if (!viewMatchesOrientation) {
                        if (attempt < 20) {
                            log("configuration_refresh_waiting_for_layout orientation="
                                + orientation + " attempt=" + attempt
                                + " view=" + viewWidth + "x" + viewHeight);
                            scheduleConfigurationRefresh(
                                activity,
                                orientation,
                                attempt + 1
                            );
                        } else {
                            log("configuration_refresh_layout_abandoned orientation="
                                + orientation + " view=" + viewWidth + "x"
                                + viewHeight);
                        }
                        return;
                    }

                    if (orientation == Configuration.ORIENTATION_PORTRAIT) {
                        log("configuration_refresh_native_reload orientation="
                            + orientation + " attempt=" + attempt
                            + " view=" + viewWidth + "x" + viewHeight);
                        XposedHelpers.callMethod(viewModel, "reloadPage");
                        return;
                    }

                    // DocumentActivity.setImage() mutates the bitmap it receives
                    // when Supernote's native half-page mode is active: it draws
                    // the pointing-hand split indicators directly into that
                    // bitmap.  Never give it PageInfo's canonical originBitmap.
                    // A disposable copy prevents the landscape guide icons from
                    // becoming part of the cached page and reappearing after the
                    // device returns to portrait.
                    Bitmap refreshBitmap = Bitmap.createBitmap(originBitmap);
                    log("configuration_refresh orientation=" + orientation
                        + " attempt=" + attempt
                        + " view=" + viewWidth + "x" + viewHeight
                        + " source=" + bitmapDescription(originBitmap)
                        + " disposable=" + bitmapDescription(refreshBitmap));
                    XposedHelpers.callMethod(
                        activity,
                        "setImage",
                        refreshBitmap
                    );
                } catch (Throwable throwable) {
                    log("configuration_refresh_failed orientation="
                        + orientation + " " + throwable);
                    XposedBridge.log(throwable);
                }
            }
        }, attempt == 0 ? 400L : 150L);
    }

    private static void restorePortraitPresentation(Activity activity) {
        try {
            ImageView imageView =
                (ImageView) XposedHelpers.getObjectField(activity, "mImage");
            if (imageView != null
                && imageView.getScaleType() != ImageView.ScaleType.MATRIX) {
                imageView.setScaleType(ImageView.ScaleType.MATRIX);
                imageView.invalidate();
                log("portrait_presentation_restored scale_type=MATRIX");
            }
            LEFT_DESTINATIONS.remove(activity);
            RIGHT_DESTINATIONS.remove(activity);
            LEFT_VISIBLE_BOUNDS.remove(activity);
            RIGHT_VISIBLE_BOUNDS.remove(activity);
            PEN_INPUT_SNAPSHOTS.remove(activity);
        } catch (Throwable throwable) {
            log("portrait_presentation_restore_failed " + throwable);
            XposedBridge.log(throwable);
        }
    }

    private static void scheduleCompose(
        final Activity activity,
        final Bitmap activeBitmap,
        final int generation,
        final int attempt
    ) {
        new Handler(activity.getMainLooper()).postDelayed(new Runnable() {
            @Override
            public void run() {
                if (generation != GENERATION.get() || activity.isFinishing()) {
                    return;
                }
                try {
                    if (compose(activity, activeBitmap, generation)) {
                        return;
                    }
                    if (attempt < 20) {
                        scheduleCompose(activity, activeBitmap, generation, attempt + 1);
                    } else {
                        showOverlay(activity, "SPREAD PROBE: adjacent page unavailable");
                        log("compose_abandoned generation=" + generation);
                    }
                } catch (Throwable throwable) {
                    showOverlay(activity, "SPREAD PROBE FAILED - writing disabled");
                    log("compose_failed " + throwable);
                    XposedBridge.log(throwable);
                }
            }
        }, attempt == 0 ? 300L : 150L);
    }

    @SuppressWarnings("unchecked")
    private static boolean compose(
        Activity activity,
        Bitmap activeBitmap,
        int generation
    ) {
        Object viewModel = XposedHelpers.getObjectField(activity, "documentViewModel");
        int currentPage = XposedHelpers.getIntField(viewModel, "currentPage");
        int pageCount = XposedHelpers.getIntField(viewModel, "pageCount");
        Map<Integer, Object> pageMap =
            (Map<Integer, Object>) XposedHelpers.getObjectField(viewModel, "pageInfoHashMap");

        SpreadConfig config = spreadConfig(activity);
        SpreadPair pair = spreadPair(config, currentPage, pageCount);
        int rightPage = pair.rightPage;
        int leftPage = pair.leftPage;
        if (rightPage < 0) {
            return false;
        }

        Object rightInfo = rightPage >= 0 ? pageMap.get(rightPage) : null;
        Object leftInfo = leftPage >= 0 ? pageMap.get(leftPage) : null;
        if ((rightPage >= 0 && rightInfo == null)
            || (leftPage >= 0 && leftInfo == null)) {
            log("waiting generation=" + generation + " current=" + currentPage
                + " map_right=" + (rightInfo != null) + " map_left=" + (leftInfo != null));
            return false;
        }

        // setImage() receives Supernote's already-rotated display bitmap for the
        // active page.  A spread needs both pages in the same source coordinate
        // system, so always compose from PageInfo's portrait-oriented originals.
        Bitmap rightBitmap = rightInfo == null ? null
            : (Bitmap) XposedHelpers.callMethod(rightInfo, "getOriginBitmap");
        Bitmap leftBitmap = leftInfo == null ? null
            : (Bitmap) XposedHelpers.callMethod(leftInfo, "getOriginBitmap");

        if ((rightPage >= 0 && !usable(rightBitmap))
            || (leftPage >= 0 && !usable(leftBitmap))) {
            log("waiting_bitmaps generation=" + generation + " right="
                + bitmapDescription(rightBitmap) + " left=" + bitmapDescription(leftBitmap));
            return false;
        }

        ImageView imageView = (ImageView) XposedHelpers.getObjectField(activity, "mImage");
        int outputWidth = imageView.getWidth();
        int outputHeight = imageView.getHeight();
        if (outputWidth <= 0 || outputHeight <= 0) {
            log("waiting_view generation=" + generation + " size="
                + outputWidth + "x" + outputHeight);
            return false;
        }

        Object presenter = XposedHelpers.getObjectField(
            activity,
            "handWritePresenter"
        );
        int presenterRotation = XposedHelpers.getIntField(
            presenter,
            "screenRotation"
        );
        if (outputWidth <= outputHeight
            || (presenterRotation != 90 && presenterRotation != 270)) {
            log("waiting_landscape_state generation=" + generation
                + " size=" + outputWidth + "x" + outputHeight
                + " presenter_rotation=" + presenterRotation);
            return false;
        }

        Bitmap composite = Bitmap.createBitmap(
            outputWidth,
            outputHeight,
            Bitmap.Config.ARGB_8888
        );
        Canvas canvas = new Canvas(composite);
        canvas.drawColor(Color.WHITE);

        Paint bitmapPaint = new Paint(Paint.ANTI_ALIAS_FLAG | Paint.FILTER_BITMAP_FLAG);
        boolean showDivider = config == null || config.showDivider;
        boolean nativeFill = config != null && config.nativeFill;
        float gutter = showDivider ? 8.0f : 0.0f;
        float half = outputWidth / 2.0f;
        RectF leftSlot = new RectF(0.0f, 0.0f, half - gutter / 2.0f, outputHeight);
        RectF rightSlot = new RectF(half + gutter / 2.0f, 0.0f, outputWidth, outputHeight);
        Bitmap geometryBitmap = usable(rightBitmap) ? rightBitmap : leftBitmap;
        RectF leftTrimmingRect = nativeTrimmingRect(
            activity,
            leftPage,
            leftInfo,
            leftBitmap,
            nativeFill
        );
        RectF rightTrimmingRect = nativeTrimmingRect(
            activity,
            rightPage,
            rightInfo,
            rightBitmap,
            nativeFill
        );
        SpreadPageLayout leftLayout = pageLayout(
            usable(leftBitmap) ? leftBitmap.getWidth() : geometryBitmap.getWidth(),
            usable(leftBitmap) ? leftBitmap.getHeight() : geometryBitmap.getHeight(),
            leftSlot,
            nativeFill,
            leftTrimmingRect
        );
        SpreadPageLayout rightLayout = pageLayout(
            usable(rightBitmap) ? rightBitmap.getWidth() : geometryBitmap.getWidth(),
            usable(rightBitmap) ? rightBitmap.getHeight() : geometryBitmap.getHeight(),
            rightSlot,
            nativeFill,
            rightTrimmingRect
        );
        RectF leftDestination = leftLayout.destination;
        RectF rightDestination = rightLayout.destination;

        if (usable(leftBitmap)) {
            drawPageBitmap(canvas, leftBitmap, leftLayout, bitmapPaint);
        }
        if (usable(rightBitmap)) {
            drawPageBitmap(canvas, rightBitmap, rightLayout, bitmapPaint);
        }
        LEFT_DESTINATIONS.put(activity, new RectF(leftDestination));
        RIGHT_DESTINATIONS.put(activity, new RectF(rightDestination));
        LEFT_VISIBLE_BOUNDS.put(activity, new RectF(leftLayout.visibleBounds));
        RIGHT_VISIBLE_BOUNDS.put(activity, new RectF(rightLayout.visibleBounds));
        publishPenInputGeometrySnapshot(
            activity,
            config,
            currentPage,
            pageCount,
            pair,
            rightLayout.visibleBounds,
            leftLayout.visibleBounds,
            false,
            "compose_geometry_pending"
        );

        if (showDivider) {
            Paint dividerPaint = new Paint();
            dividerPaint.setColor(Color.DKGRAY);
            canvas.drawRect(
                half - gutter / 2.0f,
                0.0f,
                half + gutter / 2.0f,
                outputHeight,
                dividerPaint
            );
        }

        imageView.setScaleType(ImageView.ScaleType.FIT_XY);
        imageView.setImageBitmap(composite);

        Bitmap activeOrigin = currentPage == leftPage
            ? leftBitmap : rightBitmap;
        RectF activeDestination =
            currentPage == leftPage ? leftDestination : rightDestination;
        RectF activeVisibleBounds = currentPage == leftPage
            ? leftLayout.visibleBounds : rightLayout.visibleBounds;
        String activeSide =
            currentPage == leftPage ? "LEFT" : "RIGHT";
        boolean calibrationSpreadWriteEnabled = config != null
            && config.editable
            && pair.contains(currentPage)
            && editableSpreadGeometrySupported(
                activeOrigin,
                activeDestination,
                activeVisibleBounds,
                outputWidth,
                outputHeight
            );
        updateNativeEraserGate(
            activity,
            "compose_geometry",
            calibrationSpreadWriteEnabled
        );
        if (calibrationSpreadWriteEnabled) {
            ArrayList<Rect> disabledAreas = activePageDisabledAreas(
                activeVisibleBounds,
                outputWidth,
                outputHeight
            );
            XposedHelpers.callMethod(
                presenter,
                "setDisableAreaList",
                "SN_SPREAD_PROBE disposable active-page pen trace",
                disabledAreas
            );
            XposedHelpers.callMethod(presenter, "sendWriteInfo");
            if (sendCalibrationGeometry(
                presenter,
                activeDestination,
                outputWidth,
                outputHeight
            )) {
                boolean activationReady = commitPageActivationGeometry(
                    activity,
                    presenter,
                    currentPage
                );
                if (activationReady) {
                    publishPenInputGeometrySnapshot(
                        activity,
                        config,
                        currentPage,
                        pageCount,
                        pair,
                        rightLayout.visibleBounds,
                        leftLayout.visibleBounds,
                        true,
                        "compose_geometry_committed"
                    );
                    showStatusOverlay(
                        activity,
                        "RTL SPREAD: ACTIVE " + activeSide
                            + " page " + (currentPage + 1)
                            + " - tap or hover over the other page to activate it"
                    );
                }
            } else {
                XposedHelpers.callMethod(
                    presenter,
                    "disableHandWrite",
                    "SN_SPREAD_PROBE geometry transaction failed"
                );
                showOverlay(
                    activity,
                    "RTL SPREAD: geometry failed - writing disabled"
                );
            }
        } else {
            resetSpreadEditingState("compose_read_only");
            XposedHelpers.callMethod(
                presenter,
                "disableHandWrite",
                "SN_SPREAD_PROBE read-only opt-in spread"
            );
            showStatusOverlay(
                activity,
                "RTL SPREAD: READ ONLY - writing geometry not approved"
            );
        }

        Bitmap previous = COMPOSITES.put(activity, composite);
        if (previous != null && previous != composite && !previous.isRecycled()) {
            previous.recycle();
        }

        log("composed generation=" + generation
            + " current=" + currentPage
            + " right_page=" + rightPage
            + " left_page=" + leftPage
            + " output=" + outputWidth + "x" + outputHeight
            + " right_source=" + bitmapDescription(rightBitmap)
            + " left_source=" + bitmapDescription(leftBitmap)
            + " right_dest=" + rectDescription(rightDestination)
            + " left_dest=" + rectDescription(leftDestination)
            + " right_trim=" + rectDescription(rightTrimmingRect)
            + " left_trim=" + rectDescription(leftTrimmingRect)
            + " active_side=" + activeSide
            + " show_divider=" + showDivider
            + " sizing=" + (nativeFill ? "native_fill" : "fit")
            + " spread_write_enabled=" + calibrationSpreadWriteEnabled
            + " cover_separate="
            + (config != null && config.coverSeparate)
            + " handwrite_view=" + viewDescription(
                (View) XposedHelpers.getObjectField(activity, "handWriteView")
            )
            + " presenter_bitmap=" + bitmapDescription(
                (Bitmap) XposedHelpers.getObjectField(presenter, "bitmap")
            )
            + " presenter_rotation=" + XposedHelpers.getIntField(presenter, "screenRotation"));

        // The active page's presenter bitmap can be null even when the other
        // page in the spread has saved ink. Rebuild the committed overlay
        // from both pages after every composition instead of relying on the
        // newly active page's bitmap.
        Object handWriteView =
            XposedHelpers.getObjectField(activity, "handWriteView");
        reapplyCanonicalCommittedInk(activity, handWriteView);
        applySpreadDigestOverlay(activity, "spread_composed");
        return true;
    }

    private static void reapplyCanonicalCommittedInk(
        Activity activity,
        Object handWriteView
    ) {
        if (handWriteView == null || !isCalibrationLandscape(activity)) {
            return;
        }
        Bitmap transformed = renderCanonicalCommittedInk(activity);
        if (transformed == null) {
            log("committed_ink_reapply_skipped reason=canonical_unavailable");
            return;
        }

        Bitmap previous = COMMITTED_INK_COMPOSITES.put(activity, transformed);
        COMMITTED_INK_ALREADY_SPREAD.set(true);
        try {
            XposedHelpers.callMethod(handWriteView, "setBitmap", transformed);
            log("committed_ink_reapplied_after_compose source="
                + bitmapDescription(transformed));
        } finally {
            COMMITTED_INK_ALREADY_SPREAD.remove();
            if (previous != null && previous != transformed
                && !previous.isRecycled()) {
                previous.recycle();
            }
        }
    }

    private static boolean blockPageActivationUiInput(
        Activity activity,
        MotionEvent event
    ) {
        if (activity == null || event == null) {
            return false;
        }
        boolean blockedGesture = Boolean.TRUE.equals(
            PAGE_ACTIVATION_BLOCKED_TOUCHES.get(activity)
        );
        PageActivationTransaction transaction =
            PAGE_ACTIVATION_TRANSACTIONS.get(activity);
        if (!blockedGesture && transaction == null) {
            return false;
        }

        int action = event.getActionMasked();
        if (action == MotionEvent.ACTION_UP
            || action == MotionEvent.ACTION_CANCEL
            || action == MotionEvent.ACTION_HOVER_EXIT) {
            PAGE_ACTIVATION_BLOCKED_TOUCHES.remove(activity);
        } else if (blockedGesture
            || action == MotionEvent.ACTION_DOWN
            || action == MotionEvent.ACTION_MOVE
            || action == MotionEvent.ACTION_POINTER_DOWN
            || action == MotionEvent.ACTION_POINTER_UP) {
            // Latch only a real contact gesture. A hover event may request the
            // transfer, but must not keep all later UI input blocked after the
            // transaction commits while the pen remains in sensing range.
            PAGE_ACTIVATION_BLOCKED_TOUCHES.put(activity, Boolean.TRUE);
        }
        log("page_activation_ui_input_blocked id="
            + (transaction == null ? -1L : transaction.id)
            + " target="
            + (transaction == null ? -1 : transaction.targetPage)
            + " action=" + action
            + " tool=" + (event.getPointerCount() <= 0
                ? -1 : event.getToolType(0)));
        return true;
    }

    private static boolean handlePageActivationTouch(
        Activity activity,
        MotionEvent event
    ) {
        if (event == null || !isCalibrationLandscape(activity)
            || event.getPointerCount() <= 0
            || event.getToolType(0) != MotionEvent.TOOL_TYPE_FINGER) {
            return false;
        }
        PageActivationTransaction transaction =
            PAGE_ACTIVATION_TRANSACTIONS.get(activity);
        if (transaction != null) {
            log("page_activation_touch_blocked id=" + transaction.id
                + " target=" + transaction.targetPage
                + " action=" + event.getActionMasked());
            return true;
        }

        int action = event.getActionMasked();
        Integer trackedTarget = ACTIVATION_TOUCH_TARGETS.get(activity);
        if (action == MotionEvent.ACTION_DOWN) {
            ACTIVATION_TOUCH_TARGETS.remove(activity);
            ACTIVATION_TOUCH_STARTS.remove(activity);
            if (isNativeChromeTouch(activity, event.getY())) {
                log("activation_touch_ignored_native_chrome point="
                    + Math.round(event.getX()) + ","
                    + Math.round(event.getY()));
                return false;
            }
            int target = pageAt(activity, event.getX(), event.getY());
            int current = currentDocumentPage(activity);
            if (target >= 0 && target != current
                && !isOuterEdgeTap(activity, event.getX())) {
                ACTIVATION_TOUCH_TARGETS.put(activity, target);
                ACTIVATION_TOUCH_STARTS.put(
                    activity,
                    new Point(
                        Math.round(event.getX()),
                        Math.round(event.getY())
                    )
                );
                log("activation_touch_down current=" + current
                    + " target=" + target
                    + " point=" + Math.round(event.getX()) + ","
                    + Math.round(event.getY()));
            }
            return false;
        }

        if (trackedTarget == null) {
            return false;
        }

        if (isNativeChromeTouch(activity, event.getY())) {
            ACTIVATION_TOUCH_TARGETS.remove(activity);
            ACTIVATION_TOUCH_STARTS.remove(activity);
            log("activation_touch_cancelled_native_chrome target="
                + trackedTarget + " point=" + Math.round(event.getX())
                + "," + Math.round(event.getY()));
            return false;
        }

        Point start = ACTIVATION_TOUCH_STARTS.get(activity);
        if (action == MotionEvent.ACTION_MOVE && start != null) {
            float deltaX = event.getX() - start.x;
            float deltaY = event.getY() - start.y;
            if (deltaX * deltaX + deltaY * deltaY > 64.0f * 64.0f) {
                ACTIVATION_TOUCH_TARGETS.remove(activity);
                ACTIVATION_TOUCH_STARTS.remove(activity);
                log("activation_touch_released_to_swipe target="
                    + trackedTarget + " delta=" + Math.round(deltaX)
                    + "," + Math.round(deltaY));
            }
            return false;
        }

        if (action == MotionEvent.ACTION_UP) {
            ACTIVATION_TOUCH_TARGETS.remove(activity);
            ACTIVATION_TOUCH_STARTS.remove(activity);
            int releasedTarget = pageAt(
                activity,
                event.getX(),
                event.getY()
            );
            if (releasedTarget == trackedTarget.intValue()) {
                if (!beginPageActivationTransaction(
                        activity,
                        releasedTarget,
                        "finger_tap",
                        false
                    )) {
                    activateDocumentPage(activity, releasedTarget);
                }
            } else {
                log("activation_touch_cancelled expected=" + trackedTarget
                    + " released=" + releasedTarget);
            }
            return true;
        }

        if (action == MotionEvent.ACTION_CANCEL) {
            ACTIVATION_TOUCH_TARGETS.remove(activity);
            ACTIVATION_TOUCH_STARTS.remove(activity);
            log("activation_touch_cancelled action=CANCEL");
            return false;
        }

        return false;
    }

    private static boolean isNativeChromeTouch(Activity activity, float y) {
        if (y <= NATIVE_TOP_CHROME_TOUCH_EXCLUSION_PX) {
            return true;
        }
        try {
            View decor = activity == null || activity.getWindow() == null
                ? null
                : activity.getWindow().getDecorView();
            int height = decor == null ? 0 : decor.getHeight();
            return height > 0
                && y >= height - NATIVE_BOTTOM_CHROME_TOUCH_EXCLUSION_PX;
        } catch (Throwable throwable) {
            queueLowLatencyLog(
                "native_chrome_touch_check_failed " + throwable
            );
            return false;
        }
    }

    private static void queueLowLatencyLog(final String message) {
        if (message == null) {
            return;
        }
        try {
            LOW_LATENCY_LOG_EXECUTOR.execute(new Runnable() {
                @Override
                public void run() {
                    log(message);
                }
            });
        } catch (Throwable ignored) {
            // Logging is diagnostic. Never perturb the native pen callback if
            // its background queue is unavailable.
        }
    }

    private static void notePenInputBlock(
        Activity activity,
        String state,
        int x,
        int y,
        int pressure,
        long transactionId,
        int currentPage,
        int targetPage,
        int contactStartPage
    ) {
        if (activity == null || state == null || pressure <= 0) {
            return;
        }
        String previous = PEN_INPUT_BLOCK_LOG_STATES.put(activity, state);
        if (state.equals(previous)) {
            return;
        }
        final String captured = "page_activation_pen_input_blocked"
            + " state=" + state + " phase=contact"
            + " transaction=" + transactionId
            + " current=" + currentPage + " target=" + targetPage
            + " start=" + contactStartPage + " point=" + x + "," + y
            + " pressure=" + pressure;
        queueLowLatencyLog(captured);
    }

    private static void finishPenInputBlock(
        Activity activity,
        int x,
        int y,
        int pressure
    ) {
        if (activity == null || pressure > 0) {
            return;
        }
        String previous = PEN_INPUT_BLOCK_LOG_STATES.remove(activity);
        if (previous == null) {
            return;
        }
        final String captured = "page_activation_pen_input_blocked"
            + " state=" + previous + " phase=lift point=" + x + "," + y
            + " pressure=" + pressure;
        queueLowLatencyLog(captured);
    }

    private static void clearPenContactStartPage(
        Activity activity,
        String reason
    ) {
        if (activity == null) {
            return;
        }
        Integer startPage = PEN_CONTACT_START_PAGES.remove(activity);
        if (startPage != null) {
            queueLowLatencyLog(
                "pen_contact_guard_cleared start=" + startPage
                    + " reason=" + reason
            );
        }
    }

    private static void handlePenPageActivation(
        Activity activity,
        int x,
        int y,
        int pressure,
        PenInputSnapshot inputSnapshot
    ) {
        if (activity == null) {
            return;
        }
        final int requestedX = x;
        final int requestedY = y;
        final int requestedPressure = pressure;
        final int requestedTarget = pageAt(inputSnapshot, x, y);
        activity.runOnUiThread(new Runnable() {
            @Override
            public void run() {
                PageActivationTransaction transaction =
                    PAGE_ACTIVATION_TRANSACTIONS.get(activity);
                if (transaction != null) {
                    if (requestedPressure > 0) {
                        transaction.triggerContactObserved = true;
                        transaction.triggerPenLifted = false;
                        log("page_activation_trigger_contact id="
                            + transaction.id + " target="
                            + transaction.targetPage + " point_page="
                            + requestedTarget);
                    } else if (requestedPressure <= 0
                        && transaction.triggerContactObserved) {
                        markPageActivationPenLifted(
                            activity,
                            "position_pressure_zero"
                        );
                    }
                    return;
                }
                PenInputSnapshot currentSnapshot =
                    penInputSnapshot(activity);
                if (inputSnapshot == null
                    || currentSnapshot != inputSnapshot
                    || !inputSnapshot.editable
                    || !inputSnapshot.geometryReady) {
                    abortPageActivationTransaction(
                        activity,
                        "pen_snapshot_stale",
                        true
                    );
                    return;
                }
                if (isNativeChromeTouch(activity, requestedY)) {
                    log("page_activation_pen_ignored_native_chrome point="
                        + requestedX + "," + requestedY
                        + " pressure=" + requestedPressure);
                    return;
                }
                int current = inputSnapshot.currentPage;
                Integer contactStartPage =
                    PEN_CONTACT_START_PAGES.get(activity);
                if (contactStartPage != null
                    && contactStartPage.intValue()
                        == PEN_CONTACT_BLOCKED_PAGE) {
                    log("page_activation_ignored_blocked_contact"
                        + " point_page=" + requestedTarget
                        + " pressure=" + requestedPressure);
                    return;
                }
                if (requestedTarget < 0 || requestedTarget == current) {
                    return;
                }
                if (requestedPressure > 0
                    && contactStartPage != null
                    && contactStartPage.intValue() == current) {
                    log("page_activation_ignored_cross_page_stroke current="
                        + current + " target=" + requestedTarget
                        + " start=" + contactStartPage);
                    return;
                }

                String trigger = requestedPressure > 0
                    ? "pen_contact" : "pen_hover";
                log("page_activation_requested current="
                    + current
                    + " target=" + requestedTarget
                    + " point=" + requestedX + "," + requestedY
                    + " trigger=" + trigger
                    + " pressure=" + requestedPressure);
                beginPageActivationTransaction(
                    activity,
                    requestedTarget,
                    trigger,
                    requestedPressure > 0
                );
            }
        });
    }

    private static boolean interceptPenPageActivation(
        Activity activity,
        int x,
        int y,
        int pressure,
        PenInputSnapshot inputSnapshot
    ) {
        if (activity == null) {
            return false;
        }
        finishPenInputBlock(activity, x, y, pressure);
        Integer contactStartPage = PEN_CONTACT_START_PAGES.get(activity);
        int capturedContactStart = contactStartPage == null
            ? -1 : contactStartPage.intValue();
        PageActivationTransaction transaction =
            PAGE_ACTIVATION_TRANSACTIONS.get(activity);
        if (transaction != null) {
            if (pressure > 0) {
                transaction.triggerContactObserved = true;
                transaction.triggerPenLifted = false;
            }
            notePenInputBlock(
                activity,
                "transaction",
                x,
                y,
                pressure,
                transaction.id,
                inputSnapshot == null ? -1 : inputSnapshot.currentPage,
                transaction.targetPage,
                capturedContactStart
            );
            return true;
        }
        if (inputSnapshot == null) {
            if (publishedEditablePenInputLandscape(activity)) {
                notePenInputBlock(
                    activity,
                    "stale_snapshot",
                    x,
                    y,
                    pressure,
                    -1L,
                    -1,
                    -1,
                    capturedContactStart
                );
                return true;
            }
            return false;
        }
        if (!inputSnapshot.editable) {
            return false;
        }
        if (!inputSnapshot.geometryReady) {
            notePenInputBlock(
                activity,
                "geometry_pending",
                x,
                y,
                pressure,
                -1L,
                inputSnapshot.currentPage,
                -1,
                capturedContactStart
            );
            return true;
        }
        boolean completingActivePageStroke =
            isCompletingActivePageStroke(
                activity,
                inputSnapshot,
                pressure
            );
        if (isNativeChromeTouch(activity, y)) {
            if (completingActivePageStroke) {
                return false;
            }
            // The toolbar and bottom page bar consume ordinary Android stylus
            // events.  Suppress only the parallel low-latency DrawPath point,
            // so selecting a native control with the pen cannot ink or activate
            // the page visually underneath that control.
            notePenInputBlock(
                activity,
                "native_chrome",
                x,
                y,
                pressure,
                -1L,
                inputSnapshot.currentPage,
                pageAt(inputSnapshot, x, y),
                capturedContactStart
            );
            return true;
        }
        int target = pageAt(inputSnapshot, x, y);
        int current = inputSnapshot.currentPage;
        if (contactStartPage != null
            && contactStartPage.intValue() != current) {
            // The contact began where the writer did not own the page. Keep
            // every frame in that physical gesture, including its terminal
            // pen-up, out of the native writer. This also covers a fast move
            // back onto the current page before the UI thread has published
            // the requested ownership transaction.
            notePenInputBlock(
                activity,
                "nonwritable_contact",
                x,
                y,
                pressure,
                -1L,
                current,
                target,
                capturedContactStart
            );
            return true;
        }
        if (target < 0 || target == current) {
            return false;
        }
        if (contactStartPage != null
            && contactStartPage.intValue() == current) {
            if (pressure > 0) {
                // A stroke that began on the active page remains an active-page
                // stroke. Block ink-bearing points that cross the divider, but
                // never turn that continuation into an ownership transfer.
                notePenInputBlock(
                    activity,
                    "active_stroke_cross_page",
                    x,
                    y,
                    pressure,
                    -1L,
                    current,
                    target,
                    capturedContactStart
                );
                return true;
            }
            if (completingActivePageStroke) {
                // The source page must receive its ordinary terminal callback
                // even when the lift coordinate is over the other half. The
                // caller skips hover activation for this same frame and clears
                // the guard only after the native callback is preserved.
                return false;
            }
        }
        // handlePenPageActivation runs the native save/load transition on the
        // UI thread.  Return true immediately so this initiating coordinate
        // can never enter the source page's DrawPath while that work is queued.
        notePenInputBlock(
            activity,
            "activation_trigger",
            x,
            y,
            pressure,
            -1L,
            current,
            target,
            capturedContactStart
        );
        return true;
    }

    private static boolean isCompletingActivePageStroke(
        Activity activity,
        PenInputSnapshot inputSnapshot,
        int pressure
    ) {
        if (activity == null || pressure != 0
            || PAGE_ACTIVATION_TRANSACTIONS.get(activity) != null
            || inputSnapshot == null
            || !inputSnapshot.editable
            || !inputSnapshot.geometryReady) {
            return false;
        }
        Integer contactStartPage = PEN_CONTACT_START_PAGES.get(activity);
        if (contactStartPage == null) {
            return false;
        }
        return contactStartPage.intValue() == inputSnapshot.currentPage;
    }

    private static Integer pendingPageActivationTarget(Activity activity) {
        PageActivationTransaction transaction = activity == null
            ? null : PAGE_ACTIVATION_TRANSACTIONS.get(activity);
        if (transaction != null) {
            return Integer.valueOf(transaction.targetPage);
        }
        return activity == null ? null : PEN_ACTIVATION_TARGETS.get(activity);
    }

    private static boolean beginPageActivationTransaction(
        Activity activity,
        int targetPage,
        String trigger,
        boolean triggerContactObserved
    ) {
        if (activity == null || !editablePenInputReady(activity)) {
            return false;
        }
        PageActivationTransaction transaction = null;
        try {
            Object viewModel = XposedHelpers.getObjectField(
                activity,
                "documentViewModel"
            );
            int sourcePage = XposedHelpers.getIntField(viewModel, "currentPage");
            int pageCount = XposedHelpers.getIntField(viewModel, "pageCount");
            if (targetPage < 0 || targetPage >= pageCount
                || targetPage == sourcePage) {
                log("page_activation_rejected reason=invalid_target"
                    + " source=" + sourcePage + " target=" + targetPage
                    + " count=" + pageCount + " trigger=" + trigger);
                return false;
            }

            Object presenter = XposedHelpers.getObjectField(
                activity,
                "handWritePresenter"
            );

            long id = PAGE_ACTIVATION_COUNTER.incrementAndGet();
            synchronized (PAGE_ACTIVATION_OWNERSHIP_LOCK) {
                // Contact-start recording uses this same lock. Therefore a
                // non-contact activation either observes an existing native
                // stroke and rejects, or publishes its transaction before a
                // new low-latency contact can be admitted.
                if (!triggerContactObserved
                    && PEN_CONTACT_START_PAGES.get(activity) != null) {
                    log("page_activation_rejected reason=pen_contact_active"
                        + " requested_target=" + targetPage
                        + " trigger=" + trigger);
                    return false;
                }
                PageActivationTransaction currentTransaction =
                    PAGE_ACTIVATION_TRANSACTIONS.get(activity);
                if (currentTransaction != null) {
                    if (currentTransaction.targetPage == targetPage
                        && triggerContactObserved) {
                        currentTransaction.triggerContactObserved = true;
                        currentTransaction.triggerPenLifted = false;
                    }
                    log("page_activation_rejected"
                        + " reason=transaction_in_progress"
                        + " active_id=" + currentTransaction.id
                        + " active_target=" + currentTransaction.targetPage
                        + " requested_target=" + targetPage
                        + " trigger=" + trigger);
                    return currentTransaction.targetPage == targetPage;
                }
                transaction = new PageActivationTransaction(
                    id,
                    sourcePage,
                    targetPage,
                    trigger,
                    triggerContactObserved
                );
                PAGE_ACTIVATION_TRANSACTIONS.put(activity, transaction);
            }

            // The ownership/input guard is already visible. Permit exactly
            // this call stack to perform the intentional source flush while
            // all concurrent lifecycle saves and pen/UI input remain blocked.
            PAGE_ACTIVATION_SOURCE_SAVE_SCOPE.set(Boolean.TRUE);
            try {
                XposedHelpers.callMethod(
                    presenter,
                    "saveTrails",
                    false,
                    false
                );
            } finally {
                PAGE_ACTIVATION_SOURCE_SAVE_SCOPE.remove();
            }
            XposedHelpers.callMethod(
                presenter,
                "disableHandWrite",
                "SN_SPREAD_PROBE transactional page activation"
            );
            showStatusOverlay(
                activity,
                "RTL SPREAD: switching active page to " + (targetPage + 1)
            );
            traceEvent(
                activity,
                "page_activation_transaction_started",
                "id",
                id,
                "sourcePage",
                sourcePage,
                "targetPage",
                targetPage,
                "trigger",
                trigger,
                "discardTriggerGesture",
                triggerContactObserved
            );
            requestPageActivationLoad(activity, transaction, viewModel);
            schedulePageActivationTimeout(activity, id);
            return true;
        } catch (Throwable throwable) {
            log("page_activation_start_failed target=" + targetPage
                + " trigger=" + trigger + " " + throwable);
            XposedBridge.log(throwable);
            if (transaction != null
                && PAGE_ACTIVATION_TRANSACTIONS.get(activity) == transaction) {
                // loadPage(target) may have changed reader or presenter state
                // before throwing. Preserve the ownership/save guard and use
                // the same identity-verified source rollback as a timeout.
                abortPageActivationTransaction(
                    activity,
                    "start_failed",
                    true
                );
            } else {
                failClosedPageActivation(activity, "start_failed");
            }
            return false;
        }
    }

    private static void requestPageActivationLoad(
        Activity activity,
        PageActivationTransaction transaction,
        Object viewModel
    ) throws Exception {
        transaction.loadAttempts++;
        XposedHelpers.callMethod(
            viewModel,
            "loadPage",
            transaction.targetPage
        );
        log("page_activation_load_requested id=" + transaction.id
            + " source=" + transaction.sourcePage
            + " target=" + transaction.targetPage
            + " attempt=" + transaction.loadAttempts
            + " trigger=" + transaction.trigger);
    }

    private static void schedulePageActivationTimeout(
        final Activity activity,
        final long transactionId
    ) {
        new Handler(activity.getMainLooper()).postDelayed(new Runnable() {
            @Override
            public void run() {
                PageActivationTransaction transaction =
                    PAGE_ACTIVATION_TRANSACTIONS.get(activity);
                if (transaction == null || transaction.id != transactionId) {
                    return;
                }
                if (transaction.rollbackPending) {
                    return;
                }
                if (transaction.geometryCommitted
                    && transaction.triggerContactObserved
                    && !transaction.triggerPenLifted) {
                    // A held pen is not a failed page load.  Continue blocking
                    // the trigger gesture until the writer reports pen-up.
                    schedulePageActivationTimeout(activity, transactionId);
                    return;
                }
                if (!transaction.geometryCommitted
                    && transaction.loadAttempts < 2) {
                    try {
                        Object viewModel = XposedHelpers.getObjectField(
                            activity,
                            "documentViewModel"
                        );
                        log("page_activation_retry id=" + transaction.id
                            + " target=" + transaction.targetPage);
                        requestPageActivationLoad(
                            activity,
                            transaction,
                            viewModel
                        );
                        schedulePageActivationTimeout(activity, transactionId);
                        return;
                    } catch (Throwable throwable) {
                        log("page_activation_retry_failed id="
                            + transaction.id + " " + throwable);
                        XposedBridge.log(throwable);
                    }
                }
                abortPageActivationTransaction(
                    activity,
                    "timeout",
                    true
                );
            }
        }, PAGE_ACTIVATION_TIMEOUT_MS);
    }

    private static boolean commitPageActivationGeometry(
        Activity activity,
        Object presenter,
        int currentPage
    ) {
        PageActivationTransaction transaction =
            PAGE_ACTIVATION_TRANSACTIONS.get(activity);
        if (transaction == null) {
            return true;
        }
        try {
            int presenterMarkPage = XposedHelpers.getIntField(
                presenter,
                "currentPage"
            );
            if (transaction.rollbackPending) {
                if (currentPage != transaction.sourcePage
                    || presenterMarkPage != transaction.sourcePage + 1) {
                    log("page_activation_rollback_waiting id="
                        + transaction.id + " source="
                        + transaction.sourcePage + " reader_page="
                        + currentPage + " mark_page=" + presenterMarkPage);
                    XposedHelpers.callMethod(
                        presenter,
                        "disableHandWrite",
                        "SN_SPREAD_PROBE rollback identity mismatch"
                    );
                    return false;
                }
                finishPageActivationRollback(
                    activity,
                    presenter,
                    transaction,
                    "source_identity_reconverged"
                );
                return false;
            }
            if (currentPage != transaction.targetPage
                || presenterMarkPage != transaction.targetPage + 1) {
                log("page_activation_commit_waiting id=" + transaction.id
                    + " target=" + transaction.targetPage
                    + " reader_page=" + currentPage
                    + " mark_page=" + presenterMarkPage);
                XposedHelpers.callMethod(
                    presenter,
                    "disableHandWrite",
                    "SN_SPREAD_PROBE activation identity mismatch"
                );
                return false;
            }
            transaction.geometryCommitted = true;
            if (transaction.triggerContactObserved
                && !transaction.triggerPenLifted) {
                XposedHelpers.callMethod(
                    presenter,
                    "disableHandWrite",
                    "SN_SPREAD_PROBE discard activation gesture"
                );
                showStatusOverlay(
                    activity,
                    "RTL SPREAD: page " + (currentPage + 1)
                        + " active - lift pen, then write"
                );
                log("page_activation_waiting_for_pen_lift id="
                    + transaction.id + " target=" + transaction.targetPage);
                return false;
            }
            if (!finishPageActivationTransaction(
                activity,
                transaction,
                "geometry_committed"
            )) {
                PageActivationTransaction current =
                    PAGE_ACTIVATION_TRANSACTIONS.get(activity);
                if (current == transaction
                    && current.triggerContactObserved
                    && !current.triggerPenLifted) {
                    XposedHelpers.callMethod(
                        presenter,
                        "disableHandWrite",
                        "SN_SPREAD_PROBE commit/contact race"
                    );
                    showStatusOverlay(
                        activity,
                        "RTL SPREAD: page " + (currentPage + 1)
                            + " active - lift pen, then write"
                    );
                    log("page_activation_commit_contact_race id="
                        + transaction.id + " target="
                        + transaction.targetPage);
                }
                return false;
            }
            return true;
        } catch (Throwable throwable) {
            log("page_activation_commit_failed id=" + transaction.id
                + " " + throwable);
            XposedBridge.log(throwable);
            failClosedPageActivation(activity, "commit_failed");
            return false;
        }
    }

    private static void markPageActivationPenLifted(
        final Activity activity,
        String reason
    ) {
        final PageActivationTransaction transaction =
            PAGE_ACTIVATION_TRANSACTIONS.get(activity);
        if (transaction == null || !transaction.triggerContactObserved
            || transaction.triggerPenLifted || transaction.rollbackPending) {
            return;
        }
        transaction.triggerPenLifted = true;
        log("page_activation_pen_lifted id=" + transaction.id
            + " target=" + transaction.targetPage
            + " reason=" + reason
            + " geometry=" + transaction.geometryCommitted);
        if (!transaction.geometryCommitted) {
            return;
        }
        new Handler(activity.getMainLooper()).postDelayed(new Runnable() {
            @Override
            public void run() {
                PageActivationTransaction current =
                    PAGE_ACTIVATION_TRANSACTIONS.get(activity);
                if (current == null || current.id != transaction.id
                    || current.rollbackPending
                    || !current.geometryCommitted
                    || !current.triggerPenLifted) {
                    return;
                }
                try {
                    Object presenter = XposedHelpers.getObjectField(
                        activity,
                        "handWritePresenter"
                    );
                    if (!restoreTransactionalActivePageGeometry(
                            activity,
                            presenter,
                            current
                        )) {
                        failClosedPageActivation(
                            activity,
                            "pen_lift_geometry_failed"
                        );
                        return;
                    }
                    if (!publishReadyPenInputGeometryAfterActivation(
                            activity,
                            current,
                            "pen_lift_geometry_committed"
                        )) {
                        failClosedPageActivation(
                            activity,
                            "pen_lift_snapshot_publish_failed"
                        );
                        return;
                    }
                    if (!finishPageActivationTransaction(
                        activity,
                        current,
                        "trigger_gesture_discarded"
                    )) {
                        log("page_activation_pen_lift_finish_deferred id="
                            + current.id + " target=" + current.targetPage);
                    }
                } catch (Throwable throwable) {
                    log("page_activation_pen_lift_failed id=" + current.id
                        + " " + throwable);
                    XposedBridge.log(throwable);
                    failClosedPageActivation(activity, "pen_lift_failed");
                }
            }
        }, PAGE_ACTIVATION_PEN_SETTLE_MS);
    }

    private static boolean restoreTransactionalActivePageGeometry(
        Activity activity,
        Object presenter,
        PageActivationTransaction transaction
    ) {
        RectF writable = activePageDestination(activity);
        ImageView imageView = (ImageView) XposedHelpers.getObjectField(
            activity,
            "mImage"
        );
        int outputWidth = imageView == null ? 0 : imageView.getWidth();
        int outputHeight = imageView == null ? 0 : imageView.getHeight();
        if (writable == null || outputWidth <= outputHeight
            || outputHeight <= 0) {
            log("page_activation_geometry_restore_rejected id="
                + transaction.id + " destination="
                + rectDescription(writable) + " output=" + outputWidth
                + "x" + outputHeight);
            return false;
        }
        XposedHelpers.callMethod(
            presenter,
            "setDisableAreaList",
            "SN_SPREAD_PROBE transactional active page",
            activePageDisabledAreas(
                visibleBoundsOrDestination(activity, writable),
                outputWidth,
                outputHeight
            )
        );
        XposedHelpers.callMethod(presenter, "sendWriteInfo");
        return applySpreadMarkGeometry(
            activity,
            presenter,
            "transaction_commit"
        );
    }

    private static boolean finishPageActivationTransaction(
        Activity activity,
        PageActivationTransaction transaction,
        String reason
    ) {
        PageActivationTransaction current;
        synchronized (PAGE_ACTIVATION_OWNERSHIP_LOCK) {
            current = PAGE_ACTIVATION_TRANSACTIONS.get(activity);
            if (current == null || current.id != transaction.id
                || current.rollbackPending) {
                return false;
            }
            if (current.triggerContactObserved
                && !current.triggerPenLifted) {
                log("page_activation_commit_retained_for_contact id="
                    + current.id + " target=" + current.targetPage);
                return false;
            }
            if (!PAGE_ACTIVATION_TRANSACTIONS.remove(activity, current)) {
                return false;
            }
        }
        long elapsed = SystemClock.uptimeMillis() - transaction.startedAt;
        log("page_activation_committed id=" + transaction.id
            + " source=" + transaction.sourcePage
            + " target=" + transaction.targetPage
            + " trigger=" + transaction.trigger
            + " reason=" + reason
            + " discarded=" + transaction.triggerContactObserved
            + " elapsed_ms=" + elapsed);
        traceEvent(
            activity,
            "page_activation_transaction_committed",
            "id",
            transaction.id,
            "sourcePage",
            transaction.sourcePage,
            "targetPage",
            transaction.targetPage,
            "trigger",
            transaction.trigger,
            "triggerGestureDiscarded",
            transaction.triggerContactObserved,
            "elapsedMs",
            elapsed
        );
        if ("trigger_gesture_discarded".equals(reason)) {
            try {
                Object viewModel = XposedHelpers.getObjectField(
                    activity,
                    "documentViewModel"
                );
                int pageCount = XposedHelpers.getIntField(
                    viewModel,
                    "pageCount"
                );
                SpreadPair pair = spreadPair(
                    spreadConfig(activity),
                    transaction.targetPage,
                    pageCount
                );
                String activeSide = transaction.targetPage == pair.leftPage
                    ? "LEFT" : "RIGHT";
                showStatusOverlay(
                    activity,
                    "RTL SPREAD: ACTIVE " + activeSide
                        + " page " + (transaction.targetPage + 1)
                        + " - tap or hover over the other page to activate it"
                );
            } catch (Throwable throwable) {
                log("page_activation_status_refresh_failed id="
                    + transaction.id + " " + throwable);
            }
        }
        return true;
    }

    private static boolean shouldBlockPageActivationGesture(Activity activity) {
        PageActivationTransaction transaction = activity == null
            ? null : PAGE_ACTIVATION_TRANSACTIONS.get(activity);
        return transaction != null && transaction.triggerContactObserved;
    }

    private static boolean shouldBlockPageActivationSave(Activity activity) {
        return activity != null
            && PAGE_ACTIVATION_TRANSACTIONS.get(activity) != null;
    }

    private static void abortPageActivationTransaction(
        Activity activity,
        String reason,
        boolean restoreSourcePage
    ) {
        if (activity == null) {
            return;
        }
        PageActivationTransaction transaction =
            PAGE_ACTIVATION_TRANSACTIONS.get(activity);
        if (transaction == null) {
            return;
        }
        if (transaction.rollbackPending) {
            log("page_activation_abort_ignored id=" + transaction.id
                + " reason=rollback_pending requested_reason=" + reason);
            return;
        }
        transaction.rollbackPending = true;
        transaction.abortReason = reason;
        try {
            log("page_activation_aborted id=" + transaction.id
                + " source=" + transaction.sourcePage
                + " target=" + transaction.targetPage
                + " reason=" + reason
                + " restore_source=" + restoreSourcePage);
            traceEvent(
                activity,
                "page_activation_transaction_aborted",
                "id",
                transaction.id,
                "sourcePage",
                transaction.sourcePage,
                "targetPage",
                transaction.targetPage,
                "reason",
                reason
            );
            failClosedPageActivation(activity, reason);
            if (!restoreSourcePage || activity.isFinishing()) {
                PAGE_ACTIVATION_TRANSACTIONS.remove(activity, transaction);
                return;
            }
            // Always reload the source, even if the reader field already says
            // source: the presenter may still own the target mark page.  The
            // transaction remains published after this asynchronous request
            // and is released only when composition verifies both identities.
            requestPageActivationRollback(
                activity,
                transaction,
                "abort_" + reason
            );
        } catch (Throwable throwable) {
            log("page_activation_abort_failed id=" + transaction.id
                + " " + throwable);
            XposedBridge.log(throwable);
            schedulePageActivationRollbackRetry(
                activity,
                transaction,
                "abort_exception"
            );
        }
    }

    private static void requestPageActivationRollback(
        final Activity activity,
        final PageActivationTransaction transaction,
        final String reason
    ) {
        if (activity == null || transaction == null) {
            return;
        }
        if (Looper.myLooper() != activity.getMainLooper()) {
            new Handler(activity.getMainLooper()).post(new Runnable() {
                @Override
                public void run() {
                    requestPageActivationRollback(
                        activity,
                        transaction,
                        reason + "_main"
                    );
                }
            });
            return;
        }

        PageActivationTransaction current =
            PAGE_ACTIVATION_TRANSACTIONS.get(activity);
        if (current != transaction || !transaction.rollbackPending) {
            return;
        }
        if (activity.isFinishing()
            || transaction.rollbackAttempts
                >= PAGE_ACTIVATION_ROLLBACK_MAX_ATTEMPTS) {
            releaseFailedPageActivationRollback(
                activity,
                transaction,
                reason + "_attempts_exhausted"
            );
            return;
        }

        int attempt = ++transaction.rollbackAttempts;
        try {
            Object viewModel = XposedHelpers.getObjectField(
                activity,
                "documentViewModel"
            );
            XposedHelpers.callMethod(
                viewModel,
                "loadPage",
                transaction.sourcePage
            );
            log("page_activation_rollback_requested id="
                + transaction.id + " page=" + transaction.sourcePage
                + " attempt=" + attempt + " reason=" + reason);
            schedulePageActivationRollbackTimeout(
                activity,
                transaction,
                attempt
            );
        } catch (Throwable throwable) {
            log("page_activation_rollback_failed id=" + transaction.id
                + " attempt=" + attempt + " reason=" + reason
                + " " + throwable);
            XposedBridge.log(throwable);
            failClosedPageActivation(
                activity,
                "rollback_load_failed_" + attempt
            );
            schedulePageActivationRollbackRetry(
                activity,
                transaction,
                "load_exception"
            );
        }
    }

    private static void schedulePageActivationRollbackRetry(
        final Activity activity,
        final PageActivationTransaction transaction,
        final String reason
    ) {
        if (activity == null || transaction == null) {
            return;
        }
        new Handler(activity.getMainLooper()).postDelayed(new Runnable() {
            @Override
            public void run() {
                PageActivationTransaction current =
                    PAGE_ACTIVATION_TRANSACTIONS.get(activity);
                if (current != transaction || !transaction.rollbackPending) {
                    return;
                }
                if (transaction.rollbackAttempts
                    >= PAGE_ACTIVATION_ROLLBACK_MAX_ATTEMPTS) {
                    releaseFailedPageActivationRollback(
                        activity,
                        transaction,
                        reason + "_attempts_exhausted"
                    );
                    return;
                }
                requestPageActivationRollback(
                    activity,
                    transaction,
                    reason + "_retry"
                );
            }
        }, PAGE_ACTIVATION_ROLLBACK_RETRY_MS);
    }

    private static void schedulePageActivationRollbackTimeout(
        final Activity activity,
        final PageActivationTransaction transaction,
        final int attempt
    ) {
        new Handler(activity.getMainLooper()).postDelayed(new Runnable() {
            @Override
            public void run() {
                PageActivationTransaction current =
                    PAGE_ACTIVATION_TRANSACTIONS.get(activity);
                if (current != transaction || !transaction.rollbackPending
                    || transaction.rollbackAttempts != attempt) {
                    return;
                }
                if (finishPageActivationRollbackIfConverged(
                        activity,
                        "rollback_timeout_check"
                    )) {
                    return;
                }
                if (transaction.rollbackAttempts
                    < PAGE_ACTIVATION_ROLLBACK_MAX_ATTEMPTS) {
                    requestPageActivationRollback(
                        activity,
                        transaction,
                        "convergence_timeout"
                    );
                    return;
                }
                releaseFailedPageActivationRollback(
                    activity,
                    transaction,
                    "convergence_timeout_attempts_exhausted"
                );
            }
        }, PAGE_ACTIVATION_TIMEOUT_MS);
    }

    private static void releaseFailedPageActivationRollback(
        Activity activity,
        PageActivationTransaction transaction,
        String reason
    ) {
        if (activity == null || transaction == null) {
            return;
        }
        PageActivationTransaction current =
            PAGE_ACTIVATION_TRANSACTIONS.get(activity);
        if (current != transaction || !transaction.rollbackPending) {
            return;
        }

        // Release the global transaction/save guard only after the native
        // writer has been disabled again.  Page ownership remains uncertain,
        // so subsequent pen input continues to fail closed until a normal
        // page/configuration refresh publishes a new ready snapshot.
        if (!failClosedPageActivation(activity, reason)) {
            log("page_activation_rollback_guard_retained id="
                + transaction.id + " reason=" + reason
                + " writer_disabled=false");
            return;
        }
        invalidatePenInputGeometrySnapshot(
            activity,
            "rollback_released_fail_closed"
        );
        synchronized (PAGE_ACTIVATION_OWNERSHIP_LOCK) {
            current = PAGE_ACTIVATION_TRANSACTIONS.get(activity);
            if (current != transaction || !transaction.rollbackPending
                || !PAGE_ACTIVATION_TRANSACTIONS.remove(
                    activity,
                    transaction
                )) {
                return;
            }
        }
        long elapsed = SystemClock.uptimeMillis() - transaction.startedAt;
        log("page_activation_rollback_released_fail_closed id="
            + transaction.id + " source=" + transaction.sourcePage
            + " target=" + transaction.targetPage + " attempts="
            + transaction.rollbackAttempts + " reason=" + reason
            + " elapsed_ms=" + elapsed);
        traceEvent(
            activity,
            "page_activation_transaction_rollback_released_fail_closed",
            "id",
            transaction.id,
            "sourcePage",
            transaction.sourcePage,
            "targetPage",
            transaction.targetPage,
            "attempts",
            transaction.rollbackAttempts,
            "reason",
            reason,
            "elapsedMs",
            elapsed
        );
    }

    private static void finishPageActivationRollback(
        Activity activity,
        Object presenter,
        PageActivationTransaction transaction,
        String reason
    ) {
        PageActivationTransaction current = activity == null
            ? null : PAGE_ACTIVATION_TRANSACTIONS.get(activity);
        if (current == null || current.id != transaction.id
            || !current.rollbackPending) {
            return;
        }
        try {
            // loadPage() may re-enable the writer.  Disable it again after both
            // identities have reconverged, before releasing mutation guards.
            XposedHelpers.callMethod(
                presenter,
                "disableHandWrite",
                "SN_SPREAD_PROBE rollback completed fail closed"
            );
        } catch (Throwable throwable) {
            log("page_activation_rollback_disable_failed id="
                + transaction.id + " " + throwable);
            XposedBridge.log(throwable);
            return;
        }
        if (!PAGE_ACTIVATION_TRANSACTIONS.remove(activity, current)) {
            return;
        }
        long elapsed = SystemClock.uptimeMillis() - transaction.startedAt;
        log("page_activation_rollback_completed id=" + transaction.id
            + " source=" + transaction.sourcePage
            + " target=" + transaction.targetPage
            + " abort_reason=" + transaction.abortReason
            + " reason=" + reason
            + " elapsed_ms=" + elapsed);
        traceEvent(
            activity,
            "page_activation_transaction_rolled_back",
            "id",
            transaction.id,
            "sourcePage",
            transaction.sourcePage,
            "targetPage",
            transaction.targetPage,
            "abortReason",
            transaction.abortReason,
            "reason",
            reason,
            "elapsedMs",
            elapsed
        );
    }

    private static boolean finishPageActivationRollbackIfConverged(
        Activity activity,
        String reason
    ) {
        PageActivationTransaction transaction = activity == null
            ? null : PAGE_ACTIVATION_TRANSACTIONS.get(activity);
        if (transaction == null || !transaction.rollbackPending) {
            return false;
        }
        try {
            Object viewModel = XposedHelpers.getObjectField(
                activity,
                "documentViewModel"
            );
            Object presenter = XposedHelpers.getObjectField(
                activity,
                "handWritePresenter"
            );
            int readerPage = XposedHelpers.getIntField(
                viewModel,
                "currentPage"
            );
            int presenterMarkPage = XposedHelpers.getIntField(
                presenter,
                "currentPage"
            );
            if (readerPage != transaction.sourcePage
                || presenterMarkPage != transaction.sourcePage + 1) {
                log("page_activation_rollback_waiting id="
                    + transaction.id + " source="
                    + transaction.sourcePage + " reader_page="
                    + readerPage + " mark_page=" + presenterMarkPage
                    + " reason=" + reason);
                XposedHelpers.callMethod(
                    presenter,
                    "disableHandWrite",
                    "SN_SPREAD_PROBE rollback identity mismatch"
                );
                return false;
            }
            finishPageActivationRollback(
                activity,
                presenter,
                transaction,
                reason
            );
            return PAGE_ACTIVATION_TRANSACTIONS.get(activity) != transaction;
        } catch (Throwable throwable) {
            log("page_activation_rollback_convergence_failed id="
                + transaction.id + " reason=" + reason + " " + throwable);
            XposedBridge.log(throwable);
            return false;
        }
    }

    private static boolean failClosedPageActivation(
        Activity activity,
        String reason
    ) {
        if (activity == null) {
            return false;
        }
        boolean writerDisabled = false;
        try {
            Object presenter = XposedHelpers.getObjectField(
                activity,
                "handWritePresenter"
            );
            XposedHelpers.callMethod(
                presenter,
                "disableHandWrite",
                "SN_SPREAD_PROBE transaction failure: " + reason
            );
            writerDisabled = true;
        } catch (Throwable throwable) {
            log("page_activation_fail_closed_error reason=" + reason
                + " " + throwable);
        }
        showOverlay(
            activity,
            "RTL SPREAD: page switch failed - writing disabled"
        );
        return writerDisabled;
    }

    private static void activateDocumentPageFromPen(
        Activity activity,
        int targetPage
    ) {
        try {
            Object viewModel = XposedHelpers.getObjectField(
                activity,
                "documentViewModel"
            );
            int currentPage = XposedHelpers.getIntField(
                viewModel,
                "currentPage"
            );
            if (targetPage == currentPage) {
                return;
            }
            if (isEditableSpreadLandscape(activity)) {
                beginPageActivationTransaction(
                    activity,
                    targetPage,
                    "explicit_activation",
                    false
                );
                return;
            }

            Object presenter = XposedHelpers.getObjectField(
                activity,
                "handWritePresenter"
            );
            SpreadConfig config = spreadConfig(activity);
            if (config != null && config.editable) {
                XposedHelpers.callMethod(
                    presenter,
                    "saveTrails",
                    false,
                    false
                );
            }

            /*
             * Prime the writer for the target page before the ordinary page
             * load starts. DocumentViewModel.loadPage() can spend close to a
             * second loading the bitmap/mark layer; disabling handwriting for
             * that interval drops a stroke made immediately after hover. The
             * low-latency writer is independent, so update its page and slot
             * geometry first and leave it enabled throughout the transition.
             */
            XposedHelpers.setIntField(viewModel, "currentPage", targetPage);
            int targetMarkPage = targetPage + 1;
            XposedHelpers.setIntField(
                presenter,
                "currentPage",
                targetMarkPage
            );
            /*
             * Merely changing HandWritePresenter.currentPage and the DrawPath
             * geometry does not make libsupernote's trail container current
             * for a page that has not been loaded. Prime the target mark page
             * through the native load path, but suppress HandWriteView's
             * bitmap submission so the visible two-page spread never changes
             * before pen-up completes the deferred activation.
             */
            PEN_ACTIVATION_MARK_PRIMING.set(true);
            try {
                XposedHelpers.callMethod(
                    presenter,
                    "loadHandWrite",
                    targetMarkPage
                );
            } finally {
                PEN_ACTIVATION_MARK_PRIMING.remove();
            }
            log("pen_activation_mark_primed mark_page=" + targetMarkPage);
            RectF writable = activePageDestination(activity);
            ImageView imageView = (ImageView) XposedHelpers.getObjectField(
                activity,
                "mImage"
            );
            int outputWidth = imageView == null ? 0 : imageView.getWidth();
            int outputHeight = imageView == null ? 0 : imageView.getHeight();
            boolean prepared = writable != null
                && outputWidth > outputHeight
                && outputHeight > 0;
            if (prepared) {
                XposedHelpers.callMethod(
                    presenter,
                    "setDisableAreaList",
                    "SN_SPREAD_PROBE pen page activation",
                    activePageDisabledAreas(
                        visibleBoundsOrDestination(activity, writable),
                        outputWidth,
                        outputHeight
                    )
                );
                XposedHelpers.callMethod(presenter, "sendWriteInfo");
                prepared = applySpreadMarkGeometry(
                    activity,
                    presenter,
                    "pen_page_activation"
                );
            }
            log("pen_page_activation_prearmed from=" + currentPage
                + " to=" + targetPage
                + " prepared=" + prepared
                + " destination=" + rectDescription(writable));

            if (!prepared) {
                XposedHelpers.setIntField(
                    presenter,
                    "currentPage",
                    currentPage + 1
                );
                XposedHelpers.setIntField(
                    viewModel,
                    "currentPage",
                    currentPage
                );
                XposedHelpers.callMethod(
                    presenter,
                    "disableHandWrite",
                    "SN_SPREAD_PROBE pen activation preparation failed"
                );
                activateDocumentPage(activity, targetPage);
                return;
            }

            // Keep the displayed spread stable while the pen is down. The
            // presenter and low-latency writer now target the intended page,
            // but the visual DocumentViewModel remains on the original page
            // until receiveTrials() has committed the stroke on pen-up.
            XposedHelpers.setIntField(
                viewModel,
                "currentPage",
                currentPage
            );
            PEN_ACTIVATION_TARGETS.put(activity, targetPage);
            PEN_ACTIVATION_ORIGINAL_PAGES.put(activity, currentPage);
            log("pen_activation_deferred from=" + currentPage
                + " to=" + targetPage
                + " writer_prepared=true");
        } catch (Throwable throwable) {
            log("pen_activation_failed target=" + targetPage + " "
                + throwable);
            XposedBridge.log(throwable);
            activateDocumentPage(activity, targetPage);
        }
    }

    private static void completePendingPenPageActivation(
        Activity activity,
        String reason
    ) {
        Integer target = PEN_ACTIVATION_TARGETS.get(activity);
        Integer original = PEN_ACTIVATION_ORIGINAL_PAGES.get(activity);
        if (target == null) {
            return;
        }
        if (hasPendingPenActivationEdits(activity)) {
            log("pen_activation_aborted reason=persistence_failed target="
                + target);
            showOverlay(
                activity,
                "SPREAD PROBE: annotation save failed - edit not applied"
            );
            cancelPendingPenPageActivation(activity, "persistence_failed");
            return;
        }
        try {
            Object viewModel = XposedHelpers.getObjectField(
                activity,
                "documentViewModel"
            );
            showStatusOverlay(
                activity,
                "SPREAD PROBE: switching active page to "
                    + (target.intValue() + 1)
            );
            boolean staleSavePending = Boolean.TRUE.equals(
                PEN_ACTIVATION_STALE_SAVE_PENDING.get(activity)
            );
            if (staleSavePending) {
                PEN_ACTIVATION_STALE_SAVE_SCOPE.set(Boolean.TRUE);
            }
            try {
                XposedHelpers.callMethod(
                    viewModel,
                    "loadPage",
                    target.intValue()
                );
            } finally {
                PEN_ACTIVATION_STALE_SAVE_SCOPE.remove();
                if (staleSavePending
                    && PEN_ACTIVATION_STALE_SAVE_PENDING.remove(activity)
                        != null) {
                    log("pen_activation_stale_save_not_observed"
                        + " scope=deferred_load_page");
                }
            }
            log("pen_activation_completed reason=" + reason
                + " from=" + original
                + " to=" + target);
        } catch (Throwable throwable) {
            log("pen_activation_completion_failed reason=" + reason
                + " target=" + target + " " + throwable);
            XposedBridge.log(throwable);
            activateDocumentPage(activity, target.intValue());
        } finally {
            PEN_ACTIVATION_TARGETS.remove(activity);
            PEN_ACTIVATION_ORIGINAL_PAGES.remove(activity);
        }
    }

    private static boolean hasPendingPenActivationEdits(Activity activity) {
        List<Object> trails = PEN_ACTIVATION_TRAILS.get(activity);
        List<Object> erasers = PEN_ACTIVATION_ERASERS.get(activity);
        return (trails != null && !trails.isEmpty())
            || (erasers != null && !erasers.isEmpty());
    }

    /*
     * A pen-down that begins on the inactive half reaches getTrailContainer()
     * before the visual page switch. Supernote associates that operation with
     * the target page, but its later save pass still serializes the combined
     * spread buffer. Preserve completed ink (process 0) and stroke-eraser paths
     * (processes 6 and 7), normalize the spread writer's 4/3 EMR scale to the
     * document mark geometry, and apply only that page-local transaction after
     * bypassing the unsafe native save.
     */
    private static void capturePendingPenActivationTrails(
        Activity activity,
        int operationPage,
        List<?> operationTrails
    ) {
        Integer target = PEN_ACTIVATION_TARGETS.get(activity);
        int targetMarkPage = target == null ? -1 : target.intValue() + 1;
        if (target == null || targetMarkPage != operationPage
            || operationTrails == null || operationTrails.isEmpty()) {
            return;
        }

        ArrayList<Object> captured = new ArrayList<>();
        ArrayList<Object> erasers = new ArrayList<>();
        for (Object source : operationTrails) {
            if (source == null) {
                continue;
            }
            try {
                int process = callInt(source, "get_process_mod");
                if (callInt(source, "get_page_num") != targetMarkPage
                    || (process != 0 && process != 6 && process != 7)
                    || (process == 0
                        && callInt(source, "get_pen_type") == 4)) {
                    continue;
                }
                @SuppressWarnings("unchecked")
                List<Point> points = (List<Point>) XposedHelpers.callMethod(
                    source,
                    "get_m_points"
                );
                if (points == null || points.isEmpty()) {
                    continue;
                }
                Object copy = copyObjectFields(source);
                normalizePendingPenTrail(copy, targetMarkPage);
                if (process == 6 || process == 7) {
                    erasers.add(copy);
                } else {
                    captured.add(copy);
                }
                log(((process == 6 || process == 7)
                        ? "pen_activation_eraser_captured reader_page="
                        : "pen_activation_trail_captured reader_page=")
                    + target
                    + " mark_page=" + targetMarkPage
                    + " in_page="
                    + callInt(source, "get_m_trail_num_in_page")
                    + " process=" + process
                    + " points=" + points.size()
                    + " redraw="
                    + callInt(source, "get_m_redraw_width") + "x"
                    + callInt(source, "get_m_redraw_height")
                    + " max=" + callInt(source, "get_max_x") + "x"
                    + callInt(source, "get_max_y"));
            } catch (Throwable throwable) {
                log("pen_activation_trail_capture_failed " + throwable);
                XposedBridge.log(throwable);
            }
        }
        if (!captured.isEmpty()) {
            PEN_ACTIVATION_TRAILS.put(activity, captured);
        }
        if (!erasers.isEmpty()) {
            PEN_ACTIVATION_ERASERS.put(activity, erasers);
        }
    }

    private static void normalizePendingPenTrail(
        Object trail,
        int targetPage
    ) throws Exception {
        float emrXScale = DOCUMENT_PAGE_HEIGHT
            / (float) CANONICAL_PAGE_HEIGHT;
        float emrYScale = DOCUMENT_PAGE_WIDTH
            / (float) CANONICAL_PAGE_WIDTH;
        float pageXScale = DOCUMENT_PAGE_WIDTH
            / (float) CANONICAL_PAGE_WIDTH;
        float pageYScale = DOCUMENT_PAGE_HEIGHT
            / (float) CANONICAL_PAGE_HEIGHT;

        @SuppressWarnings("unchecked")
        List<Point> sourcePoints = (List<Point>) XposedHelpers.callMethod(
            trail,
            "get_m_points"
        );
        ArrayList<Point> scaledPoints = new ArrayList<>();
        if (sourcePoints != null) {
            for (Point point : sourcePoints) {
                if (point != null) {
                    scaledPoints.add(new Point(
                        Math.round(point.x * emrXScale),
                        Math.round(point.y * emrYScale)
                    ));
                }
            }
        }
        XposedHelpers.callMethod(trail, "set_m_points", scaledPoints);
        XposedHelpers.callMethod(
            trail,
            "set_max_x",
            Math.round(callInt(trail, "get_max_x") * emrXScale)
        );
        XposedHelpers.callMethod(
            trail,
            "set_max_y",
            Math.round(callInt(trail, "get_max_y") * emrYScale)
        );
        XposedHelpers.callMethod(
            trail,
            "set_m_redraw_width",
            DOCUMENT_PAGE_WIDTH
        );
        XposedHelpers.callMethod(
            trail,
            "set_m_redraw_height",
            DOCUMENT_PAGE_HEIGHT
        );
        XposedHelpers.callMethod(trail, "set_page_num", targetPage);

        Object sourceRrd = XposedHelpers.callMethod(trail, "get_rrd");
        if (sourceRrd != null) {
            Object copiedRrd = copyObjectFields(sourceRrd);
            Rect bounds = (Rect) XposedHelpers.callMethod(
                sourceRrd,
                "getRect"
            );
            Rect scaled = scaleUsableRect(
                bounds,
                pageXScale,
                pageYScale
            );
            if (scaled != null) {
                XposedHelpers.callMethod(copiedRrd, "setRect", scaled);
            }
            XposedHelpers.callMethod(trail, "set_rrd", copiedRrd);
        }

        scaleOptionalTrailRect(
            trail,
            "get_refresh_rect",
            "set_refresh_rect",
            pageXScale,
            pageYScale
        );
        scaleOptionalTrailRect(
            trail,
            "get_m_before_shift_rect",
            "set_m_before_shift_rect",
            pageXScale,
            pageYScale
        );
        scaleOptionalTrailRect(
            trail,
            "get_m_after_shift_rect",
            "set_m_after_shift_rect",
            pageXScale,
            pageYScale
        );

        Object contoursObject = XposedHelpers.callMethod(
            trail,
            "get_m_contours_src"
        );
        if (contoursObject instanceof List) {
            ArrayList<List<PointF>> contours = new ArrayList<>();
            for (Object contourObject : (List<?>) contoursObject) {
                ArrayList<PointF> contour = new ArrayList<>();
                if (contourObject instanceof List) {
                    for (Object pointObject : (List<?>) contourObject) {
                        if (pointObject instanceof PointF) {
                            PointF point = (PointF) pointObject;
                            contour.add(new PointF(
                                point.x * pageXScale,
                                point.y * pageYScale
                            ));
                        }
                    }
                }
                contours.add(contour);
            }
            XposedHelpers.callMethod(
                trail,
                "set_m_contours_src",
                contours
            );
        }
    }

    private static Object copyObjectFields(Object source) throws Exception {
        Object copy = source.getClass().getDeclaredConstructor().newInstance();
        Class<?> type = source.getClass();
        while (type != null && type != Object.class) {
            for (java.lang.reflect.Field field : type.getDeclaredFields()) {
                if (java.lang.reflect.Modifier.isStatic(field.getModifiers())) {
                    continue;
                }
                field.setAccessible(true);
                field.set(copy, field.get(source));
            }
            type = type.getSuperclass();
        }
        return copy;
    }

    private static Rect scaleUsableRect(
        Rect source,
        float scaleX,
        float scaleY
    ) {
        if (source == null
            || source.left == Integer.MAX_VALUE
            || source.top == Integer.MAX_VALUE
            || source.right < 0
            || source.bottom < 0) {
            return null;
        }
        return new Rect(
            Math.round(source.left * scaleX),
            Math.round(source.top * scaleY),
            Math.round(source.right * scaleX),
            Math.round(source.bottom * scaleY)
        );
    }

    private static void scaleOptionalTrailRect(
        Object trail,
        String getter,
        String setter,
        float scaleX,
        float scaleY
    ) {
        try {
            Rect source = (Rect) XposedHelpers.callMethod(trail, getter);
            Rect scaled = scaleUsableRect(source, scaleX, scaleY);
            if (scaled != null) {
                XposedHelpers.callMethod(trail, setter, scaled);
            }
        } catch (Throwable ignored) {
        }
    }

    private static void persistPendingPenActivationTrails(
        Activity activity,
        Object presenter,
        boolean armPostActivationSaveBypass
    ) {
        Integer target = PEN_ACTIVATION_TARGETS.get(activity);
        List<Object> captured = PEN_ACTIVATION_TRAILS.get(activity);
        List<Object> erasers = PEN_ACTIVATION_ERASERS.get(activity);
        if (target == null
            || ((captured == null || captured.isEmpty())
                && (erasers == null || erasers.isEmpty()))) {
            return;
        }
        try {
            Object superNoteNote = XposedHelpers.getObjectField(
                presenter,
                "superNoteNote"
            );
            String markPath = (String) XposedHelpers.getObjectField(
                presenter,
                "markPath"
            );
            int targetMarkPage = target.intValue() + 1;
            Object existingResult = XposedHelpers.callMethod(
                superNoteNote,
                "getFilePageTrails",
                markPath,
                targetMarkPage
            );
            ArrayList<Object> fileTrails = new ArrayList<>();
            if (existingResult instanceof List) {
                fileTrails.addAll((List<?>) existingResult);
            }
            ArrayList<Object> beforeTrails = new ArrayList<>(fileTrails);

            int erased = 0;
            if (erasers != null && !erasers.isEmpty()) {
                for (int index = fileTrails.size() - 1; index >= 0; index--) {
                    Object existing = fileTrails.get(index);
                    if (existing == null
                        || callInt(existing, "get_page_num") != targetMarkPage
                        || callInt(existing, "get_process_mod") != 0) {
                        continue;
                    }
                    boolean intersects = false;
                    for (Object eraser : erasers) {
                        if (eraserIntersectsTrail(eraser, existing)) {
                            intersects = true;
                            break;
                        }
                    }
                    if (intersects) {
                        fileTrails.remove(index);
                        erased++;
                    }
                }
            }

            int nextTrailNumber = 0;
            for (Object existing : fileTrails) {
                if (existing != null) {
                    nextTrailNumber = Math.max(
                        nextTrailNumber,
                        callInt(existing, "get_m_trail_num_in_page")
                    );
                }
            }

            int appended = 0;
            int alreadyPresent = 0;
            if (captured != null) {
                for (Object trail : captured) {
                    if (matchingTrailExists(fileTrails, trail)) {
                        alreadyPresent++;
                        continue;
                    }
                    nextTrailNumber++;
                    XposedHelpers.callMethod(
                        trail,
                        "set_m_trail_num_in_page",
                        nextTrailNumber
                    );
                    XposedHelpers.callMethod(
                        trail,
                        "set_page_num",
                        targetMarkPage
                    );
                    fileTrails.add(trail);
                    appended++;
                }
            }

            boolean saved = (appended == 0 && erased == 0)
                || Boolean.TRUE.equals(
                XposedHelpers.callMethod(
                    superNoteNote,
                    "modifyPageTrailsFromFile",
                    markPath,
                    targetMarkPage,
                    fileTrails
                )
            );
            log("pen_activation_trails_persisted reader_page=" + target
                + " mark_page=" + targetMarkPage
                + " appended=" + appended
                + " erased=" + erased
                + " already_present=" + alreadyPresent
                + " total=" + fileTrails.size()
                + " saved=" + saved);
            if (saved) {
                PEN_ACTIVATION_TRAILS.remove(activity);
                PEN_ACTIVATION_ERASERS.remove(activity);
                if (appended > 0 || erased > 0) {
                    PENDING_PAGE_EDIT_HISTORY.put(
                        activity,
                        new PageEditHistory(
                            activity,
                            markPath,
                            targetMarkPage,
                            beforeTrails,
                            fileTrails
                        )
                    );
                    log("page_edit_history_pending mark_page="
                        + targetMarkPage
                        + " before=" + beforeTrails.size()
                        + " after=" + fileTrails.size());
                }
                if (armPostActivationSaveBypass && erased > 0) {
                    PEN_ACTIVATION_STALE_SAVE_PENDING.put(
                        activity,
                        Boolean.TRUE
                    );
                    log("pen_activation_stale_save_armed"
                        + " scope=deferred_load_page");
                }
            }
        } catch (Throwable throwable) {
            log("pen_activation_trail_persist_failed target=" + target
                + " " + throwable);
            XposedBridge.log(throwable);
        }
    }

    private static void persistActiveEraserBeforeCanonicalRefresh(
        Activity activity,
        Object presenter
    ) {
        if (!isEditableSpreadLandscape(activity)
            || PEN_ACTIVATION_TARGETS.get(activity) != null
            || !Boolean.TRUE.equals(CANONICAL_ONLY_INK_MODES.get(activity))) {
            return;
        }
        try {
            int markPage = XposedHelpers.getIntField(
                presenter,
                "currentPage"
            );
            /*
             * Native area erasing updates Supernote's in-memory trail state in
             * receiveTrials(), but the ordinary writer defers the .mark write.
             * The first spread refresh has already run against the pre-erase
             * file by the time receiveTrials() returns. Flush the completed
             * transaction, then explicitly reload the same mark page so the
             * active committed-ink layer is rebuilt from the updated canonical
             * file instead of retaining those stale pixels until a page switch.
             */
            saveTrailsForCanonicalReload(
                presenter,
                "active_eraser"
            );
            log("active_eraser_saved_before_canonical_refresh page="
                + currentDocumentPage(activity));
            XposedHelpers.callMethod(
                presenter,
                "loadHandWrite",
                markPage
            );
            log("active_eraser_canonical_reloaded mark_page=" + markPage
                + " document_page=" + currentDocumentPage(activity));
            traceAnnotationBoundary(
                activity,
                presenter,
                "active_eraser_canonical_reload",
                true
            );
        } catch (Throwable throwable) {
            log("active_eraser_save_before_refresh_failed " + throwable);
            XposedBridge.log(throwable);
        }
    }

    private static void saveTrailsForCanonicalReload(
        Object presenter,
        String reason
    ) {
        EXPLICIT_CANONICAL_TRAIL_SAVE.set(Boolean.TRUE);
        try {
            XposedHelpers.callMethod(
                presenter,
                "saveTrails",
                false,
                false
            );
            log("explicit_canonical_trail_save reason=" + reason);
        } finally {
            EXPLICIT_CANONICAL_TRAIL_SAVE.remove();
        }
    }

    private static void registerPendingPageEditHistory(
        Activity activity,
        Object presenter,
        int loadedMarkPage
    ) {
        PageEditHistory history = PENDING_PAGE_EDIT_HISTORY.get(activity);
        if (history == null || history.markPage != loadedMarkPage) {
            return;
        }
        try {
            String currentMarkPath = (String) XposedHelpers.getObjectField(
                presenter,
                "markPath"
            );
            if (!Objects.equals(history.markPath, currentMarkPath)) {
                PENDING_PAGE_EDIT_HISTORY.remove(activity);
                log("page_edit_history_discarded reason=mark_changed");
                return;
            }
            Object stack = XposedHelpers.getObjectField(
                presenter,
                "handWriteRedoUndoStack"
            );
            XposedHelpers.callMethod(stack, "appendTrail");
            Object undoObject = XposedHelpers.getObjectField(
                stack,
                "undoList"
            );
            if (!(undoObject instanceof List)
                || ((List<?>) undoObject).isEmpty()) {
                throw new IllegalStateException(
                    "native undo stack did not accept page edit"
                );
            }
            Object action = ((List<?>) undoObject).get(0);
            java.lang.reflect.Field isTrailField = action.getClass()
                .getDeclaredField("isTrail");
            isTrailField.setAccessible(true);
            isTrailField.setBoolean(action, false);
            PAGE_EDIT_HISTORY_ACTIONS.put(action, history);
            PENDING_PAGE_EDIT_HISTORY.remove(activity);
            log("page_edit_history_registered mark_page="
                + history.markPage
                + " before=" + history.beforeTrails.size()
                + " after=" + history.afterTrails.size());
        } catch (Throwable throwable) {
            log("page_edit_history_register_failed mark_page="
                + history.markPage + " " + throwable);
            XposedBridge.log(throwable);
        }
    }

    private static boolean applyPageEditHistory(
        Activity activity,
        Object presenter,
        String actionName
    ) {
        try {
            boolean undo = "undo".equals(actionName);
            String listField = undo ? "undoList" : "redoList";
            Object stack = XposedHelpers.getObjectField(
                presenter,
                "handWriteRedoUndoStack"
            );
            Object actionsObject = XposedHelpers.getObjectField(
                stack,
                listField
            );
            if (!(actionsObject instanceof List)
                || ((List<?>) actionsObject).isEmpty()) {
                return false;
            }
            Object action = ((List<?>) actionsObject).get(0);
            PageEditHistory history = PAGE_EDIT_HISTORY_ACTIONS.get(action);
            if (history == null) {
                return false;
            }
            String currentMarkPath = (String) XposedHelpers.getObjectField(
                presenter,
                "markPath"
            );
            int currentMarkPage = XposedHelpers.getIntField(
                presenter,
                "currentPage"
            );
            if (history.activity != activity
                || history.markPage != currentMarkPage
                || !Objects.equals(history.markPath, currentMarkPath)) {
                log("page_edit_history_rejected action=" + actionName
                    + " expected_page=" + history.markPage
                    + " current_page=" + currentMarkPage
                    + " mark_match="
                    + Objects.equals(history.markPath, currentMarkPath));
                showOverlay(
                    activity,
                    "SPREAD PROBE: Undo/Redo page changed"
                );
                return true;
            }

            Object superNoteNote = XposedHelpers.getObjectField(
                presenter,
                "superNoteNote"
            );
            List<Object> snapshot = undo
                ? history.beforeTrails
                : history.afterTrails;
            boolean restored = Boolean.TRUE.equals(
                XposedHelpers.callMethod(
                    superNoteNote,
                    "modifyPageTrailsFromFile",
                    history.markPath,
                    history.markPage,
                    new ArrayList<>(snapshot)
                )
            );
            if (!restored) {
                log("page_edit_history_apply_failed action=" + actionName
                    + " mark_page=" + history.markPage);
                showOverlay(
                    activity,
                    "SPREAD PROBE: Undo/Redo save failed"
                );
                return true;
            }

            XposedHelpers.callMethod(stack, actionName);
            XposedHelpers.callMethod(
                presenter,
                "loadHandWrite",
                history.markPage
            );
            log("page_edit_history_applied action=" + actionName
                + " mark_page=" + history.markPage
                + " trails=" + snapshot.size());
            return true;
        } catch (Throwable throwable) {
            log("page_edit_history_apply_failed action=" + actionName
                + " " + throwable);
            XposedBridge.log(throwable);
            showOverlay(
                activity,
                "SPREAD PROBE: Undo/Redo failed"
            );
            return true;
        }
    }

    private static void clearPageEditHistory(Activity activity) {
        PENDING_PAGE_EDIT_HISTORY.remove(activity);
        ArrayList<Object> remove = new ArrayList<>();
        for (Map.Entry<Object, PageEditHistory> entry
            : PAGE_EDIT_HISTORY_ACTIONS.entrySet()) {
            PageEditHistory history = entry.getValue();
            if (history != null && history.activity == activity) {
                remove.add(entry.getKey());
            }
        }
        for (Object action : remove) {
            PAGE_EDIT_HISTORY_ACTIONS.remove(action);
        }
    }

    private static boolean matchingTrailExists(
        List<Object> existingTrails,
        Object candidate
    ) {
        try {
            @SuppressWarnings("unchecked")
            List<Point> candidatePoints = (List<Point>) XposedHelpers.callMethod(
                candidate,
                "get_m_points"
            );
            if (candidatePoints == null || candidatePoints.isEmpty()) {
                return false;
            }
            for (Object existing : existingTrails) {
                if (existing == null
                    || callInt(existing, "get_page_num")
                        != callInt(candidate, "get_page_num")
                    || callInt(existing, "get_pen_type")
                        != callInt(candidate, "get_pen_type")
                    || callInt(existing, "get_process_mod")
                        != callInt(candidate, "get_process_mod")) {
                    continue;
                }
                @SuppressWarnings("unchecked")
                List<Point> points = (List<Point>) XposedHelpers.callMethod(
                    existing,
                    "get_m_points"
                );
                if (points == null || points.size() != candidatePoints.size()) {
                    continue;
                }
                if (matchingTrailPoints(points, candidatePoints, 6)
                    && matchingTrailInkAttributes(existing, candidate)
                    && matchingTrailValue(existing, candidate, "get_pressures")
                    && matchingTrailValue(existing, candidate, "get_angles")
                    && matchingTrailValue(existing, candidate, "get_flag_draw")
                    && matchingTrailValue(existing, candidate, "get_timestamp")) {
                    return true;
                }
            }
        } catch (Throwable throwable) {
            log("pen_activation_trail_match_failed " + throwable);
        }
        return false;
    }

    private static boolean matchingTrailPoints(
        List<Point> existing,
        List<Point> candidate,
        int tolerance
    ) {
        if (existing == null || candidate == null
            || existing.size() != candidate.size()) {
            return false;
        }
        for (int index = 0; index < existing.size(); index++) {
            Point existingPoint = existing.get(index);
            Point candidatePoint = candidate.get(index);
            if (existingPoint == null || candidatePoint == null) {
                if (existingPoint != candidatePoint) {
                    return false;
                }
            } else if (!pointsNear(
                existingPoint,
                candidatePoint,
                tolerance
            )) {
                return false;
            }
        }
        return true;
    }

    private static boolean matchingTrailInkAttributes(
        Object existing,
        Object candidate
    ) {
        String[] integerGetters = new String[] {
            "get_flag_penup",
            "get_flag_special",
            "get_layer_num",
            "get_pen_color",
            "get_pen_type",
            "get_rec_mod",
            "get_m_thickness",
            "get_walcom_emr_type",
            "get_max_x",
            "get_max_y",
            "get_m_emr_point_axis",
            "get_m_trail_status",
            "get_m_rotate_angle",
            "get_m_redraw_width",
            "get_m_redraw_height",
            "get_m_trail_type",
            "get_m_draw_version",
            "get_recogn_trail_type",
            "get_process_mod"
        };
        for (String getter : integerGetters) {
            if (callInt(existing, getter) != callInt(candidate, getter)) {
                return false;
            }
        }
        return matchingTrailValue(
            existing,
            candidate,
            "get_write_app_name"
        );
    }

    private static boolean matchingTrailValue(
        Object existing,
        Object candidate,
        String getter
    ) {
        return Objects.equals(
            XposedHelpers.callMethod(existing, getter),
            XposedHelpers.callMethod(candidate, getter)
        );
    }

    private static boolean eraserIntersectsTrail(
        Object eraser,
        Object trail
    ) {
        final int radius = 225;
        try {
            List<Point> eraserPoints = normalizedTrailMatchPoints(eraser);
            List<Point> trailPoints = normalizedTrailMatchPoints(trail);
            if (eraserPoints == null || eraserPoints.isEmpty()
                || trailPoints == null || trailPoints.isEmpty()) {
                return false;
            }

            Rect eraserBounds = pointBounds(eraserPoints);
            Rect trailBounds = pointBounds(trailPoints);
            if (eraserBounds == null || trailBounds == null) {
                return false;
            }
            eraserBounds.inset(-radius, -radius);
            if (!Rect.intersects(eraserBounds, trailBounds)) {
                return false;
            }

            double radiusSquared = (double) radius * radius;
            if (polylinePointsNearSegments(
                eraserPoints,
                trailPoints,
                radiusSquared
            )) {
                return true;
            }
            return polylinePointsNearSegments(
                trailPoints,
                eraserPoints,
                radiusSquared
            );
        } catch (Throwable throwable) {
            log("pen_activation_eraser_match_failed " + throwable);
            return false;
        }
    }

    private static List<Point> normalizedTrailMatchPoints(Object trail) {
        @SuppressWarnings("unchecked")
        List<Point> source = (List<Point>) XposedHelpers.callMethod(
            trail,
            "get_m_points"
        );
        ArrayList<Point> normalized = new ArrayList<>();
        if (source == null || source.isEmpty()) {
            return normalized;
        }
        int maxX = Math.max(1, Math.abs(callInt(trail, "get_max_x")));
        int maxY = Math.max(1, Math.abs(callInt(trail, "get_max_y")));
        for (Point point : source) {
            if (point != null) {
                normalized.add(new Point(
                    Math.round(point.x * 10000.0f / maxX),
                    Math.round(point.y * 10000.0f / maxY)
                ));
            }
        }
        return normalized;
    }

    private static boolean polylinePointsNearSegments(
        List<Point> probes,
        List<Point> polyline,
        double radiusSquared
    ) {
        if (polyline.size() == 1) {
            Point only = polyline.get(0);
            for (Point probe : probes) {
                if (probe != null && only != null
                    && pointDistanceSquared(probe, only) <= radiusSquared) {
                    return true;
                }
            }
            return false;
        }
        for (Point probe : probes) {
            if (probe == null) {
                continue;
            }
            for (int index = 1; index < polyline.size(); index++) {
                Point start = polyline.get(index - 1);
                Point end = polyline.get(index);
                if (start != null && end != null
                    && pointSegmentDistanceSquared(probe, start, end)
                        <= radiusSquared) {
                    return true;
                }
            }
        }
        return false;
    }

    private static double pointDistanceSquared(Point first, Point second) {
        double dx = first.x - (double) second.x;
        double dy = first.y - (double) second.y;
        return dx * dx + dy * dy;
    }

    private static double pointSegmentDistanceSquared(
        Point point,
        Point start,
        Point end
    ) {
        double dx = end.x - (double) start.x;
        double dy = end.y - (double) start.y;
        if (dx == 0.0 && dy == 0.0) {
            return pointDistanceSquared(point, start);
        }
        double projection = ((point.x - start.x) * dx
            + (point.y - start.y) * dy) / (dx * dx + dy * dy);
        projection = Math.max(0.0, Math.min(1.0, projection));
        double closestX = start.x + projection * dx;
        double closestY = start.y + projection * dy;
        double offsetX = point.x - closestX;
        double offsetY = point.y - closestY;
        return offsetX * offsetX + offsetY * offsetY;
    }

    private static boolean pointsNear(Point first, Point second, int tolerance) {
        return first != null && second != null
            && Math.abs(first.x - second.x) <= tolerance
            && Math.abs(first.y - second.y) <= tolerance;
    }

    private static void cancelPendingPenPageActivation(
        Activity activity,
        String reason
    ) {
        Integer target = PEN_ACTIVATION_TARGETS.remove(activity);
        Integer original = PEN_ACTIVATION_ORIGINAL_PAGES.remove(activity);
        PEN_ACTIVATION_TRAILS.remove(activity);
        PEN_ACTIVATION_ERASERS.remove(activity);
        PEN_ACTIVATION_STALE_SAVE_PENDING.remove(activity);
        PENDING_PAGE_EDIT_HISTORY.remove(activity);
        if (target == null || original == null) {
            return;
        }
        try {
            Object presenter = XposedHelpers.getObjectField(
                activity,
                "handWritePresenter"
            );
            XposedHelpers.setIntField(
                presenter,
                "currentPage",
                original.intValue() + 1
            );
            RectF writable = activePageDestination(activity);
            ImageView imageView = (ImageView) XposedHelpers.getObjectField(
                activity,
                "mImage"
            );
            int outputWidth = imageView == null ? 0 : imageView.getWidth();
            int outputHeight = imageView == null ? 0 : imageView.getHeight();
            if (writable != null && outputWidth > outputHeight
                && outputHeight > 0) {
                XposedHelpers.callMethod(
                    presenter,
                    "setDisableAreaList",
                    "SN_SPREAD_PROBE cancel pen page activation",
                    activePageDisabledAreas(
                        visibleBoundsOrDestination(activity, writable),
                        outputWidth,
                        outputHeight
                    )
                );
                XposedHelpers.callMethod(presenter, "sendWriteInfo");
                applySpreadMarkGeometry(
                    activity,
                    presenter,
                    "pen_page_activation_cancelled"
                );
            }
            log("pen_activation_cancelled reason=" + reason
                + " target=" + target
                + " restored=" + original);
        } catch (Throwable throwable) {
            log("pen_activation_cancel_failed reason=" + reason + " "
                + throwable);
            XposedBridge.log(throwable);
        }
    }

    private static void trackFingerTapNavigation(
        Activity activity,
        MotionEvent event
    ) {
        if (event == null || !isCalibrationLandscape(activity)
            || event.getPointerCount() <= 0
            || event.getToolType(0) != MotionEvent.TOOL_TYPE_FINGER) {
            return;
        }

        int action = event.getActionMasked();
        if (action == MotionEvent.ACTION_DOWN) {
            NON_EDGE_TAP_SUPPRESS_UNTIL.remove(activity);
            FINGER_TOUCH_STARTS.put(
                activity,
                new Point(
                    Math.round(event.getX()),
                    Math.round(event.getY())
                )
            );
            return;
        }

        Point start = FINGER_TOUCH_STARTS.get(activity);
        if (action == MotionEvent.ACTION_MOVE && start != null) {
            float deltaX = event.getX() - start.x;
            float deltaY = event.getY() - start.y;
            if (deltaX * deltaX + deltaY * deltaY > 64.0f * 64.0f) {
                FINGER_TOUCH_STARTS.remove(activity);
                NON_EDGE_TAP_SUPPRESS_UNTIL.remove(activity);
            }
            return;
        }

        if (action == MotionEvent.ACTION_UP) {
            FINGER_TOUCH_STARTS.remove(activity);
            if (start == null) {
                return;
            }
            float deltaX = event.getX() - start.x;
            float deltaY = event.getY() - start.y;
            boolean tap = deltaX * deltaX + deltaY * deltaY
                <= 64.0f * 64.0f;
            if (tap && !isOuterEdgeTap(activity, event.getX())) {
                NON_EDGE_TAP_SUPPRESS_UNTIL.put(
                    activity,
                    System.currentTimeMillis()
                        + NON_EDGE_TAP_SUPPRESSION_MS
                );
            }
            return;
        }

        if (action == MotionEvent.ACTION_CANCEL) {
            FINGER_TOUCH_STARTS.remove(activity);
            NON_EDGE_TAP_SUPPRESS_UNTIL.remove(activity);
        }
    }

    private static boolean shouldSuppressNonEdgeTapTurn(Activity activity) {
        Long suppressUntil = NON_EDGE_TAP_SUPPRESS_UNTIL.remove(activity);
        return suppressUntil != null
            && suppressUntil.longValue() >= System.currentTimeMillis();
    }

    private static boolean isOuterEdgeTap(Activity activity, float x) {
        try {
            ImageView imageView = (ImageView) XposedHelpers.getObjectField(
                activity,
                "mImage"
            );
            int width = imageView == null ? 0 : imageView.getWidth();
            if (width <= 0 && activity.getWindow() != null
                && activity.getWindow().getDecorView() != null) {
                width = activity.getWindow().getDecorView().getWidth();
            }
            if (width <= 0) {
                return false;
            }
            float edgeWidth = width * SPREAD_OUTER_EDGE_FRACTION;
            return x <= edgeWidth || x >= width - edgeWidth;
        } catch (Throwable throwable) {
            log("edge_tap_detection_failed " + throwable);
            return false;
        }
    }

    @SuppressWarnings("unchecked")
    private static boolean applySpreadDigestOverlay(
        Activity activity,
        String reason
    ) {
        try {
            RectF leftDestination = LEFT_DESTINATIONS.get(activity);
            RectF rightDestination = RIGHT_DESTINATIONS.get(activity);
            if (leftDestination == null || rightDestination == null) {
                log("digest_spread_waiting reason=" + reason
                    + " left=" + rectDescription(leftDestination)
                    + " right=" + rectDescription(rightDestination));
                return false;
            }

            Object viewModel = XposedHelpers.getObjectField(
                activity,
                "documentViewModel"
            );
            int currentPage = XposedHelpers.getIntField(
                viewModel,
                "currentPage"
            );
            int pageCount = XposedHelpers.getIntField(viewModel, "pageCount");
            SpreadPair pair = spreadPair(
                spreadConfig(activity),
                currentPage,
                pageCount
            );
            int rightPage = pair.rightPage;
            int leftPage = pair.leftPage;
            Map<Integer, Object> pageMap =
                (Map<Integer, Object>) XposedHelpers.getObjectField(
                    viewModel,
                    "pageInfoHashMap"
                );
            Object rightInfo = rightPage >= 0 ? pageMap.get(rightPage) : null;
            Object leftInfo = leftPage >= 0 ? pageMap.get(leftPage) : null;
            if ((rightPage >= 0 && rightInfo == null)
                || (leftPage >= 0 && leftInfo == null)) {
                log("digest_spread_waiting reason=" + reason
                    + " right_info=" + (rightInfo != null)
                    + " left_info=" + (leftInfo != null));
                return false;
            }

            ImageView digestImage = (ImageView) XposedHelpers.getObjectField(
                activity,
                "digestImage"
            );
            ImageView documentImage = (ImageView) XposedHelpers
                .getObjectField(activity, "mImage");
            int outputWidth = documentImage == null
                ? 0 : documentImage.getWidth();
            int outputHeight = documentImage == null
                ? 0 : documentImage.getHeight();
            if (digestImage == null || outputWidth <= 0
                || outputHeight <= 0) {
                log("digest_spread_waiting reason=" + reason
                    + " output=" + outputWidth + "x" + outputHeight
                    + " view=" + (digestImage != null));
                return false;
            }

            Bitmap overlay = Bitmap.createBitmap(
                outputWidth,
                outputHeight,
                Bitmap.Config.ARGB_8888
            );
            Canvas canvas = new Canvas(overlay);
            int leftCount = leftInfo == null ? 0 : drawPageAnnotations(
                canvas,
                leftInfo,
                leftDestination,
                LEFT_VISIBLE_BOUNDS.get(activity)
            );
            int rightCount = rightInfo == null ? 0 : drawPageAnnotations(
                canvas,
                rightInfo,
                rightDestination,
                RIGHT_VISIBLE_BOUNDS.get(activity)
            );

            digestImage.setScaleType(ImageView.ScaleType.FIT_XY);
            digestImage.setImageBitmap(overlay);
            digestImage.invalidate();
            Bitmap previous = DIGEST_COMPOSITES.put(activity, overlay);
            if (previous != null && previous != overlay
                && !previous.isRecycled()) {
                previous.recycle();
            }
            log("digest_spread_composed reason=" + reason
                + " right_page=" + rightPage
                + " right_annotations=" + rightCount
                + " left_page=" + leftPage
                + " left_annotations=" + leftCount
                + " output=" + outputWidth + "x" + outputHeight);
            return true;
        } catch (Throwable throwable) {
            log("digest_spread_failed reason=" + reason + " " + throwable);
            XposedBridge.log(throwable);
            return false;
        }
    }

    @SuppressWarnings("unchecked")
    private static int drawPageAnnotations(
        Canvas canvas,
        Object pageInfo,
        RectF destination,
        RectF visibleBounds
    ) {
        Bitmap originBitmap = (Bitmap) XposedHelpers.callMethod(
            pageInfo,
            "getOriginBitmap"
        );
        List<Object> annotations = (List<Object>) XposedHelpers.callMethod(
            pageInfo,
            "getAnnotationRectList"
        );
        if (!usable(originBitmap) || annotations == null
            || annotations.isEmpty()) {
            return 0;
        }

        float scaleX = destination.width() / originBitmap.getWidth();
        float scaleY = destination.height() / originBitmap.getHeight();
        int saveCount = canvas.save();
        if (visibleBounds != null) {
            canvas.clipRect(visibleBounds);
        }
        Paint paint = new Paint(Paint.ANTI_ALIAS_FLAG);
        int drawn = 0;
        for (Object annotation : annotations) {
            if (annotation == null) {
                continue;
            }
            int annotationType = ((Number) XposedHelpers.callMethod(
                annotation,
                "getAnnotationType"
            )).intValue();
            if (annotationType != 0 && annotationType != 1
                && annotationType != 6 && annotationType != 10
                && annotationType != 11) {
                continue;
            }
            int colorType = ((Number) XposedHelpers.callMethod(
                annotation,
                "getColorType"
            )).intValue();
            paint.setColor(Color.BLACK);
            if (annotationType == 0 || annotationType == 6
                || annotationType == 11) {
                if (colorType == 2) {
                    paint.setAlpha(87);
                } else if (colorType == 3) {
                    paint.setAlpha(109);
                } else {
                    paint.setAlpha(63);
                }
            } else {
                paint.setColor(Color.RED);
                paint.setAlpha(255);
            }

            List<Rect> rects = (List<Rect>) XposedHelpers.callMethod(
                annotation,
                "getRnRectList"
            );
            if (rects == null) {
                continue;
            }
            for (Rect rect : rects) {
                if (rect == null) {
                    continue;
                }
                float left = destination.left + rect.left * scaleX;
                float top = destination.top + rect.top * scaleY;
                float right = destination.left + rect.right * scaleX;
                float bottom = destination.top + rect.bottom * scaleY;
                canvas.drawRect(left, top, right, bottom, paint);
            }
            drawn++;
        }
        canvas.restoreToCount(saveCount);
        return drawn;
    }

    private static void releaseDigestComposite(Activity activity) {
        Bitmap previous = DIGEST_COMPOSITES.remove(activity);
        if (previous != null && !previous.isRecycled()) {
            previous.recycle();
        }
    }

    private static int pageAt(Activity activity, float x, float y) {
        return pageAt(penInputSnapshot(activity), x, y);
    }

    private static int currentDocumentPage(Activity activity) {
        Object viewModel =
            XposedHelpers.getObjectField(activity, "documentViewModel");
        return XposedHelpers.getIntField(viewModel, "currentPage");
    }

    private static boolean deferRtlSpreadTurn(
        Activity activity,
        SpreadConfig config,
        int sourcePage,
        int targetPage
    ) {
        if (activity == null || config == null || !config.editable
            || activity.isFinishing()) {
            return false;
        }
        DeferredSpreadTurn deferred = new DeferredSpreadTurn(
            DEFERRED_SPREAD_TURN_COUNTER.incrementAndGet(),
            config.documentPath,
            sourcePage,
            targetPage
        );
        DeferredSpreadTurn replaced = DEFERRED_SPREAD_TURNS.put(
            activity,
            deferred
        );
        log("rtl_spread_turn_deferred id=" + deferred.id
            + " source=" + sourcePage + " target=" + targetPage
            + " replaced=" + (replaced == null ? -1L : replaced.id));
        scheduleDeferredRtlSpreadTurn(activity, deferred);
        return true;
    }

    private static void scheduleDeferredRtlSpreadTurn(
        final Activity activity,
        final DeferredSpreadTurn deferred
    ) {
        long elapsed = SystemClock.uptimeMillis() - deferred.startedAt;
        long delay = elapsed < DEFERRED_SPREAD_TURN_NOTICE_MS
            ? DEFERRED_SPREAD_TURN_RETRY_MS
            : DEFERRED_SPREAD_TURN_SLOW_RETRY_MS;
        new Handler(activity.getMainLooper()).postDelayed(new Runnable() {
            @Override
            public void run() {
                DeferredSpreadTurn current =
                    DEFERRED_SPREAD_TURNS.get(activity);
                if (current != deferred) {
                    return;
                }
                if (activity.isFinishing()
                    || (Build.VERSION.SDK_INT
                            >= Build.VERSION_CODES.JELLY_BEAN_MR1
                        && activity.isDestroyed())) {
                    DEFERRED_SPREAD_TURNS.remove(activity, deferred);
                    return;
                }
                try {
                    if (activity.getResources().getConfiguration().orientation
                            != Configuration.ORIENTATION_LANDSCAPE
                        || !deferred.documentPath.equals(
                            currentDocumentPath(activity)
                        )) {
                        DEFERRED_SPREAD_TURNS.remove(activity, deferred);
                        log("rtl_spread_turn_deferred_cancelled id="
                            + deferred.id + " reason=context_changed");
                        return;
                    }

                    int currentPage = currentDocumentPage(activity);
                    if (currentPage == deferred.targetPage) {
                        DEFERRED_SPREAD_TURNS.remove(activity, deferred);
                        log("rtl_spread_turn_deferred_satisfied id="
                            + deferred.id + " target="
                            + deferred.targetPage);
                        return;
                    }
                    if (currentPage != deferred.sourcePage) {
                        DEFERRED_SPREAD_TURNS.remove(activity, deferred);
                        log("rtl_spread_turn_deferred_cancelled id="
                            + deferred.id + " reason=source_changed"
                            + " expected=" + deferred.sourcePage
                            + " current=" + currentPage);
                        return;
                    }

                    if (editablePenInputReady(activity)
                        && beginPageActivationTransaction(
                            activity,
                            deferred.targetPage,
                            "deferred_spread_turn",
                            false
                        )) {
                        DEFERRED_SPREAD_TURNS.remove(activity, deferred);
                        log("rtl_spread_turn_deferred_started id="
                            + deferred.id + " source="
                            + deferred.sourcePage + " target="
                            + deferred.targetPage);
                        return;
                    }

                    long waiting = SystemClock.uptimeMillis()
                        - deferred.startedAt;
                    if (!deferred.noticeShown
                        && waiting >= DEFERRED_SPREAD_TURN_NOTICE_MS) {
                        deferred.noticeShown = true;
                        showStatusOverlay(
                            activity,
                            "RTL SPREAD: page turn waiting for pen/page state"
                        );
                        log("rtl_spread_turn_deferred_waiting id="
                            + deferred.id + " elapsed_ms=" + waiting);
                    }
                    scheduleDeferredRtlSpreadTurn(activity, deferred);
                } catch (Throwable throwable) {
                    log("rtl_spread_turn_deferred_retry_failed id="
                        + deferred.id + " " + throwable);
                    scheduleDeferredRtlSpreadTurn(activity, deferred);
                }
            }
        }, delay);
    }

    private static boolean handleRtlSpreadTurn(
        Activity activity,
        Object viewModel,
        int nativeOffset
    ) {
        if (nativeOffset == 0) {
            return false;
        }
        try {
            int currentPage = XposedHelpers.getIntField(
                viewModel,
                "currentPage"
            );
            int pageCount = XposedHelpers.getIntField(viewModel, "pageCount");
            SpreadConfig config = spreadConfig(activity);
            SpreadPair pair = spreadPair(config, currentPage, pageCount);
            if (pair.rightPage < 0) {
                return false;
            }

            // Supernote's physical rightward page-turn gesture arrives as -1.
            // In an RTL book that gesture advances to the next spread.
            boolean forward = nativeOffset < 0;
            boolean preserveLeftSide = currentPage == pair.leftPage;
            int target;
            if (forward) {
                if (config != null && config.coverSeparate
                    && pair.rightPage == 0 && pair.leftPage < 0) {
                    target = 1;
                } else {
                    target = pair.rightPage + 2
                        + (preserveLeftSide ? 1 : 0);
                }
            } else if (config != null && config.coverSeparate
                && pair.rightPage == 1) {
                target = 0;
            } else {
                target = pair.rightPage - 2
                    + (preserveLeftSide ? 1 : 0);
            }

            if (target < 0 || target >= pageCount) {
                log("rtl_spread_turn_boundary current=" + currentPage
                    + " right=" + pair.rightPage
                    + " left=" + pair.leftPage
                    + " native_offset=" + nativeOffset
                    + " forward=" + forward);
                return true;
            }

            if (config != null && config.editable) {
                boolean started = beginPageActivationTransaction(
                    activity,
                    target,
                    "spread_turn",
                    false
                );
                log("rtl_spread_turn_transaction current=" + currentPage
                    + " target=" + target + " started=" + started
                    + " forward=" + forward
                    + " preserve_side="
                    + (preserveLeftSide ? "LEFT" : "RIGHT"));
                boolean deferred = !started && deferRtlSpreadTurn(
                    activity,
                    config,
                    currentPage,
                    target
                );
                return started || deferred;
            }

            Object presenter = XposedHelpers.getObjectField(
                activity,
                "handWritePresenter"
            );
            XposedHelpers.callMethod(
                presenter,
                "disableHandWrite",
                "SN_SPREAD_PROBE RTL spread turn"
            );
            if (config != null && config.editable) {
                XposedHelpers.callMethod(
                    presenter,
                    "saveTrails",
                    false,
                    false
                );
            }
            XposedHelpers.callMethod(viewModel, "loadPage", target);
            log("rtl_spread_turn current=" + currentPage
                + " right=" + pair.rightPage
                + " left=" + pair.leftPage
                + " native_offset=" + nativeOffset
                + " forward=" + forward
                + " preserve_side="
                + (preserveLeftSide ? "LEFT" : "RIGHT")
                + " target=" + target);
            return true;
        } catch (Throwable throwable) {
            log("rtl_spread_turn_failed offset=" + nativeOffset
                + " " + throwable);
            XposedBridge.log(throwable);
            return false;
        }
    }

    private static void activateDocumentPage(
        Activity activity,
        int targetPage
    ) {
        try {
            Object viewModel =
                XposedHelpers.getObjectField(activity, "documentViewModel");
            int currentPage =
                XposedHelpers.getIntField(viewModel, "currentPage");
            if (targetPage == currentPage) {
                return;
            }
            if (isEditableSpreadLandscape(activity)) {
                beginPageActivationTransaction(
                    activity,
                    targetPage,
                    "explicit_activation",
                    false
                );
                return;
            }

            Object presenter = XposedHelpers.getObjectField(
                activity,
                "handWritePresenter"
            );
            XposedHelpers.callMethod(
                presenter,
                "disableHandWrite",
                "SN_SPREAD_PROBE switching active spread page"
            );
            SpreadConfig config = spreadConfig(activity);
            if (config != null && config.editable) {
                XposedHelpers.callMethod(
                    presenter,
                    "saveTrails",
                    false,
                    false
                );
            }
            showStatusOverlay(
                activity,
                "SPREAD PROBE: switching active page to "
                    + (targetPage + 1)
            );

            // loadPage(int) bypasses Supernote's native half-page
            // turnShowRect() state machine while preserving the normal page
            // observer, mark-page load, toolbar, and annotation lifecycle.
            XposedHelpers.callMethod(viewModel, "loadPage", targetPage);
            log("activation_requested from=" + currentPage
                + " to=" + targetPage);
        } catch (Throwable throwable) {
            log("activation_failed target=" + targetPage + " " + throwable);
            XposedBridge.log(throwable);
            showOverlay(
                activity,
                "SPREAD PROBE: page activation failed - writing disabled"
            );
            try {
                Object presenter = XposedHelpers.getObjectField(
                    activity,
                    "handWritePresenter"
                );
                XposedHelpers.callMethod(
                    presenter,
                    "disableHandWrite",
                    "SN_SPREAD_PROBE activation failure"
                );
            } catch (Throwable ignored) {
            }
        }
    }

    private static void setReplaceActiveInkMode(
        Activity activity,
        boolean replace,
        String reason
    ) {
        if (activity == null) {
            return;
        }
        REPLACE_ACTIVE_INK_MODES.put(activity, replace);
        if (replace && reason != null && reason.startsWith("eraser:")) {
            CANONICAL_ONLY_INK_MODES.put(activity, true);
        } else {
            CANONICAL_ONLY_INK_MODES.remove(activity);
        }
        log("ink_composition_mode mode=" + (replace ? "replace" : "add")
            + " canonical_only="
            + Boolean.TRUE.equals(CANONICAL_ONLY_INK_MODES.get(activity))
            + " reason=" + reason);
    }

    private static boolean shouldReplaceActiveInkSlot(Activity activity) {
        return Boolean.TRUE.equals(REPLACE_ACTIVE_INK_MODES.get(activity));
    }

    private static Bitmap renderCapturedFullInk(Activity activity) {
        try {
            Bitmap fullBitmap = FULL_INK_BITMAPS.get(activity);
            RectF activeDestination = activePageDestination(activity);
            if (!usable(fullBitmap) || activeDestination == null) {
                return null;
            }
            RectF activeVisibleBounds = activePageVisibleBounds(activity);
            if (activeVisibleBounds == null) {
                activeVisibleBounds = new RectF(activeDestination);
            }
            ImageView imageView =
                (ImageView) XposedHelpers.getObjectField(activity, "mImage");
            Bitmap transformed = Bitmap.createBitmap(
                imageView.getWidth(),
                imageView.getHeight(),
                Bitmap.Config.ARGB_8888
            );
            Canvas canvas = new Canvas(transformed);
            Paint paint = new Paint(
                Paint.ANTI_ALIAS_FLAG | Paint.FILTER_BITMAP_FLAG
            );
            int saveCount = canvas.save();
            canvas.clipRect(activeVisibleBounds);
            canvas.drawBitmap(
                fullBitmap,
                null,
                activeDestination,
                paint
            );
            canvas.restoreToCount(saveCount);
            log("full_ink_transformed source="
                + bitmapDescription(fullBitmap)
                + " active_dest=" + rectDescription(activeDestination)
                + " visible=" + rectDescription(activeVisibleBounds)
                + " active_page=" + (currentDocumentPage(activity) + 1));
            return transformed;
        } catch (Throwable throwable) {
            log("full_ink_failed " + throwable);
            XposedBridge.log(throwable);
            return null;
        }
    }

    private static Bitmap renderCombinedCommittedInk(
        Activity activity,
        boolean replaceActiveSlot
    ) {
        Bitmap canonical = renderCanonicalCommittedInk(activity);
        Bitmap active = renderCapturedFullInk(activity);
        if (canonical == null) {
            return active;
        }
        if (active == null) {
            return canonical;
        }
        boolean recycleActive = true;
        try {
            Canvas canvas = new Canvas(canonical);
            Paint paint = new Paint(
                Paint.ANTI_ALIAS_FLAG | Paint.FILTER_BITMAP_FLAG
            );
            // A normal pen refresh can contain only the newest live trail while
            // the canonical mark bitmap still contains the previously saved
            // trails. Compose those additively so settling a new stroke cannot
            // hide earlier ink. Eraser, lasso, undo, and redo refreshes are
            // replacement operations: transparent pixels in their captured
            // bitmap must remove stale ink from the active slot.
            RectF activeDestination = activePageDestination(activity);
            if (replaceActiveSlot && activeDestination != null) {
                int saveCount = canvas.save();
                canvas.clipRect(
                    visibleBoundsOrDestination(activity, activeDestination)
                );
                canvas.drawColor(Color.TRANSPARENT, PorterDuff.Mode.CLEAR);
                canvas.restoreToCount(saveCount);
            }
            canvas.drawBitmap(active, 0.0f, 0.0f, paint);
            log("combined_ink_composed canonical="
                + bitmapDescription(canonical)
                + " active=" + bitmapDescription(active)
                + " active_dest=" + rectDescription(activeDestination)
                + " mode=" + (replaceActiveSlot ? "replace" : "add")
                + " active_page=" + (currentDocumentPage(activity) + 1));
            return canonical;
        } catch (Throwable throwable) {
            log("combined_ink_failed " + throwable);
            XposedBridge.log(throwable);
            if (!canonical.isRecycled()) {
                canonical.recycle();
            }
            recycleActive = false;
            return active;
        } finally {
            if (recycleActive && active != null && active != canonical
                && !active.isRecycled()) {
                active.recycle();
            }
        }
    }

    private static RectF activePageDestination(Activity activity) {
        try {
            Object viewModel = XposedHelpers.getObjectField(
                activity,
                "documentViewModel"
            );
            int currentPage = XposedHelpers.getIntField(
                viewModel,
                "currentPage"
            );
            int pageCount = XposedHelpers.getIntField(viewModel, "pageCount");
            SpreadPair pair = spreadPair(
                spreadConfig(activity),
                currentPage,
                pageCount
            );
            RectF destination = currentPage == pair.leftPage
                ? LEFT_DESTINATIONS.get(activity)
                : RIGHT_DESTINATIONS.get(activity);
            return destination == null ? null : new RectF(destination);
        } catch (Throwable throwable) {
            log("active_destination_failed " + throwable);
            return null;
        }
    }

    private static RectF activePageVisibleBounds(Activity activity) {
        try {
            Object viewModel = XposedHelpers.getObjectField(
                activity,
                "documentViewModel"
            );
            int currentPage = XposedHelpers.getIntField(
                viewModel,
                "currentPage"
            );
            int pageCount = XposedHelpers.getIntField(viewModel, "pageCount");
            SpreadPair pair = spreadPair(
                spreadConfig(activity),
                currentPage,
                pageCount
            );
            RectF visible = currentPage == pair.leftPage
                ? LEFT_VISIBLE_BOUNDS.get(activity)
                : RIGHT_VISIBLE_BOUNDS.get(activity);
            return visible == null ? null : new RectF(visible);
        } catch (Throwable throwable) {
            log("active_visible_bounds_failed " + throwable);
            return null;
        }
    }

    private static Point mapNativeSplitSelectionPoint(
        Point input,
        float nativeInputScale,
        float nativeOffsetX,
        float nativeOffsetY,
        RectF destination,
        int originWidth,
        int originHeight
    ) {
        float physicalX =
            (input.x - nativeOffsetX) / nativeInputScale;
        float physicalY =
            (input.y - nativeOffsetY) / nativeInputScale;
        int mappedX = Math.round(
            (physicalX - destination.left)
                * originWidth / destination.width()
        );
        int mappedY = Math.round(
            (physicalY - destination.top)
                * originHeight / destination.height()
        );
        mappedX = Math.max(0, Math.min(originWidth - 1, mappedX));
        mappedY = Math.max(0, Math.min(originHeight - 1, mappedY));
        return new Point(mappedX, mappedY);
    }

    private static SelectionGeometry selectionGeometry(Activity activity) {
        try {
            RectF destination = activePageDestination(activity);
            Object viewModel = XposedHelpers.getObjectField(
                activity,
                "documentViewModel"
            );
            Object pageInfo = XposedHelpers.getObjectField(
                viewModel,
                "pageInfo"
            );
            Bitmap originBitmap = pageInfo == null
                ? null
                : (Bitmap) XposedHelpers.callMethod(
                    pageInfo,
                    "getOriginBitmap"
                );
            ImageView imageView = (ImageView) XposedHelpers.getObjectField(
                activity,
                "mImage"
            );
            if (destination == null || !usable(originBitmap)
                || imageView == null || imageView.getWidth() <= 0
                || imageView.getHeight() <= 0) {
                return null;
            }
            float nativeOutputScale =
                (float) imageView.getWidth()
                    / (float) imageView.getHeight();
            RectF showRect = (RectF) XposedHelpers.callMethod(
                viewModel,
                "getShowRect"
            );
            float nativeOffsetX = 0.0f;
            float nativeOffsetY = 0.0f;
            if (showRect != null) {
                if (originBitmap.getWidth() > originBitmap.getHeight()) {
                    nativeOffsetX = showRect.left;
                } else {
                    nativeOffsetY = showRect.top;
                }
            }
            return new SelectionGeometry(
                destination,
                originBitmap,
                nativeOutputScale,
                nativeOffsetX,
                nativeOffsetY
            );
        } catch (Throwable throwable) {
            log("highlight_geometry_failed " + throwable);
            XposedBridge.log(throwable);
            return null;
        }
    }

    private static boolean mapNativeDisplayRectsToSpread(
        Activity activity,
        List<Rect> rects
    ) {
        if (rects == null || rects.isEmpty()) {
            return false;
        }
        SelectionGeometry geometry = selectionGeometry(activity);
        if (geometry == null || geometry.nativeOutputScale <= 0.0f) {
            return false;
        }
        float pageScaleX = geometry.destination.width()
            / geometry.originBitmap.getWidth();
        float pageScaleY = geometry.destination.height()
            / geometry.originBitmap.getHeight();
        for (Rect rect : rects) {
            if (rect == null) {
                continue;
            }
            float originLeft = rect.left / geometry.nativeOutputScale
                + geometry.nativeOffsetX;
            float originTop = rect.top / geometry.nativeOutputScale
                + geometry.nativeOffsetY;
            float originRight = rect.right / geometry.nativeOutputScale
                + geometry.nativeOffsetX;
            float originBottom = rect.bottom / geometry.nativeOutputScale
                + geometry.nativeOffsetY;
            rect.left = Math.round(
                geometry.destination.left + originLeft * pageScaleX
            );
            rect.top = Math.round(
                geometry.destination.top + originTop * pageScaleY
            );
            rect.right = Math.round(
                geometry.destination.left + originRight * pageScaleX
            );
            rect.bottom = Math.round(
                geometry.destination.top + originBottom * pageScaleY
            );
        }
        return true;
    }

    private static boolean precompensateSelectMenuRects(
        Activity activity,
        List<Rect> rects
    ) {
        if (rects == null || rects.isEmpty()) {
            return false;
        }
        SelectionGeometry geometry = selectionGeometry(activity);
        if (geometry == null || geometry.nativeOutputScale <= 0.0f) {
            return false;
        }
        float pageScaleX = geometry.destination.width()
            / geometry.originBitmap.getWidth();
        float pageScaleY = geometry.destination.height()
            / geometry.originBitmap.getHeight();
        for (Rect rect : rects) {
            if (rect == null) {
                continue;
            }
            float displayLeft = geometry.destination.left
                + rect.left * pageScaleX;
            float displayTop = geometry.destination.top
                + rect.top * pageScaleY;
            float displayRight = geometry.destination.left
                + rect.right * pageScaleX;
            float displayBottom = geometry.destination.top
                + rect.bottom * pageScaleY;
            rect.left = Math.round(
                displayLeft / geometry.nativeOutputScale
                    + geometry.nativeOffsetX
            );
            rect.top = Math.round(
                displayTop / geometry.nativeOutputScale
                    + geometry.nativeOffsetY
            );
            rect.right = Math.round(
                displayRight / geometry.nativeOutputScale
                    + geometry.nativeOffsetX
            );
            rect.bottom = Math.round(
                displayBottom / geometry.nativeOutputScale
                    + geometry.nativeOffsetY
            );
        }
        return true;
    }

    private static List<Rect> copyRects(List<Rect> rects) {
        ArrayList<Rect> copies = new ArrayList<>();
        if (rects == null) {
            return copies;
        }
        for (Rect rect : rects) {
            if (rect != null) {
                copies.add(new Rect(rect));
            }
        }
        return copies;
    }

    private static void scaleRects(List<Rect> rects, float scale) {
        if (rects == null) {
            return;
        }
        for (Rect rect : rects) {
            if (rect == null) {
                continue;
            }
            rect.left = Math.round(rect.left * scale);
            rect.top = Math.round(rect.top * scale);
            rect.right = Math.round(rect.right * scale);
            rect.bottom = Math.round(rect.bottom * scale);
        }
    }

    private static void replaceRects(
        List<Rect> destination,
        List<Rect> source
    ) {
        if (destination == null) {
            return;
        }
        destination.clear();
        if (source == null) {
            return;
        }
        for (Rect rect : source) {
            if (rect != null) {
                destination.add(new Rect(rect));
            }
        }
    }

    private static int listSize(Object value) {
        return value instanceof List ? ((List<?>) value).size() : -1;
    }

    private static void setPublicField(
        Object target,
        String name,
        Object value
    ) throws Exception {
        java.lang.reflect.Field field = target.getClass().getField(name);
        field.setAccessible(true);
        field.set(target, value);
    }

    private static void prepareSpreadEraser(
        Activity activity,
        Object presenter,
        int eraserType
    ) {
        try {
            updateNativeEraserGate(
                activity,
                "prepare_spread_eraser",
                editablePenInputReady(activity)
            );
            RectF writable = resolveActivePageDestination(
                activity,
                presenter
            );
            ImageView imageView =
                (ImageView) XposedHelpers.getObjectField(activity, "mImage");
            int outputWidth = imageView == null ? 0 : imageView.getWidth();
            int outputHeight = imageView == null ? 0 : imageView.getHeight();
            if (writable == null || outputWidth <= 0 || outputHeight <= 0) {
                log("eraser_prepare_skipped type=" + eraserType
                    + " destination=" + rectDescription(writable)
                    + " output=" + outputWidth + "x" + outputHeight);
                return;
            }

            ArrayList<Rect> disabledAreas = activePageDisabledAreas(
                visibleBoundsOrDestination(activity, writable),
                outputWidth,
                outputHeight
            );
            XposedHelpers.callMethod(
                presenter,
                "setDisableAreaList",
                "SN_SPREAD_PROBE disposable active-page eraser",
                disabledAreas
            );
            if (!sendCalibrationGeometry(
                presenter,
                writable,
                outputWidth,
                outputHeight
            )) {
                log("eraser_prepare_failed type=" + eraserType
                    + " reason=drawpath_geometry");
                return;
            }

            /*
             * Toolbar interaction can resend Supernote's ordinary full-page
             * state. Reapply the mark-side slot offset immediately before the
             * eraser gesture, but do not reload layers here: doing so would
             * discard any live, not-yet-flushed trail. Existing layers are
             * instead loaded under this geometry by the
             * setHandWriteRotation hook above.
             */
            int rotation =
                XposedHelpers.getIntField(presenter, "screenRotation");
            int markOriginX =
                Math.round(outputWidth - writable.right);
            Object superNoteNote =
                XposedHelpers.getObjectField(presenter, "superNoteNote");
            boolean rotationAccepted = (Boolean) XposedHelpers.callMethod(
                superNoteNote,
                "screenRotation",
                rotation + 2000,
                markOriginX,
                0
            );
            int currentPage =
                XposedHelpers.getIntField(presenter, "currentPage");
            log("eraser_prepared type=" + eraserType
                + " page=" + currentPage
                + " rotation=" + rotation
                + " mark_origin=" + markOriginX + ",0"
                + " rotation_accepted=" + rotationAccepted
                + " destination=" + rectDescription(writable));
        } catch (Throwable throwable) {
            log("eraser_prepare_failed type=" + eraserType + " " + throwable);
            XposedBridge.log(throwable);
        }
    }

    private static void setTextSelectionHardwareGate(
        Activity activity,
        boolean disabled,
        String reason
    ) {
        try {
            Object presenter = XposedHelpers.getObjectField(
                activity,
                "handWritePresenter"
            );
            if (presenter == null) {
                log("text_selection_hardware_gate_skipped reason=" + reason
                    + " presenter=false");
                return;
            }

            if (disabled) {
                XposedHelpers.callMethod(
                    presenter,
                    "disableHandWrite",
                    "SN_SPREAD_PROBE text-selection hardware trail"
                );
                log("text_selection_hardware_disabled reason=" + reason
                    + " page=" + currentDocumentPage(activity));
                return;
            }

            RectF writable = resolveActivePageDestination(activity, presenter);
            ImageView imageView = (ImageView) XposedHelpers.getObjectField(
                activity,
                "mImage"
            );
            int outputWidth = imageView == null ? 0 : imageView.getWidth();
            int outputHeight = imageView == null ? 0 : imageView.getHeight();
            if (writable == null || outputWidth <= outputHeight
                || outputHeight <= 0) {
                log("text_selection_hardware_restore_skipped reason=" + reason
                    + " destination=" + rectDescription(writable)
                    + " output=" + outputWidth + "x" + outputHeight);
                return;
            }

            ArrayList<Rect> disabledAreas = activePageDisabledAreas(
                visibleBoundsOrDestination(activity, writable),
                outputWidth,
                outputHeight
            );
            XposedHelpers.callMethod(
                presenter,
                "setDisableAreaList",
                "SN_SPREAD_PROBE restore active page after text selection",
                disabledAreas
            );
            XposedHelpers.callMethod(presenter, "sendWriteInfo");
            boolean geometryRestored = applySpreadMarkGeometry(
                activity,
                presenter,
                "text_selection_closed"
            );
            log("text_selection_hardware_restored reason=" + reason
                + " page=" + currentDocumentPage(activity)
                + " geometry=" + geometryRestored
                + " destination=" + rectDescription(writable));
        } catch (Throwable throwable) {
            log("text_selection_hardware_gate_failed reason=" + reason
                + " disabled=" + disabled + " " + throwable);
            XposedBridge.log(throwable);
        }
    }

    private static boolean applySpreadMarkGeometry(
        Activity activity,
        Object presenter,
        String reason
    ) {
        try {
            RectF writable = resolveActivePageDestination(
                activity,
                presenter
            );
            ImageView imageView =
                (ImageView) XposedHelpers.getObjectField(activity, "mImage");
            int outputWidth = imageView == null ? 0 : imageView.getWidth();
            int outputHeight = imageView == null ? 0 : imageView.getHeight();
            if (writable == null || outputWidth <= outputHeight) {
                log("preload_geometry_skipped reason=" + reason
                    + " destination=" + rectDescription(writable)
                    + " output=" + outputWidth + "x" + outputHeight);
                return false;
            }

            if (!sendCalibrationGeometry(
                presenter,
                writable,
                outputWidth,
                outputHeight
            )) {
                log("preload_geometry_failed reason=" + reason
                    + " stage=drawpath");
                return false;
            }

            int rotation =
                XposedHelpers.getIntField(presenter, "screenRotation");
            int markOriginX =
                Math.round(outputWidth - writable.right);
            Object superNoteNote =
                XposedHelpers.getObjectField(presenter, "superNoteNote");
            boolean rotationAccepted = (Boolean) XposedHelpers.callMethod(
                superNoteNote,
                "screenRotation",
                rotation + 2000,
                markOriginX,
                0
            );
            int currentPage =
                XposedHelpers.getIntField(presenter, "currentPage");
            log("preload_geometry_applied reason=" + reason
                + " page=" + currentPage
                + " rotation=" + rotation
                + " mark_origin=" + markOriginX + ",0"
                + " rotation_accepted=" + rotationAccepted
                + " destination=" + rectDescription(writable));
            return rotationAccepted;
        } catch (Throwable throwable) {
            log("preload_geometry_failed reason=" + reason + " " + throwable);
            XposedBridge.log(throwable);
            return false;
        }
    }

    private static RectF resolveActivePageDestination(
        Activity activity,
        Object presenter
    ) {
        RectF destination = activePageDestination(activity);
        if (destination != null) {
            return destination;
        }

        try {
            ImageView imageView =
                (ImageView) XposedHelpers.getObjectField(activity, "mImage");
            int outputWidth = imageView == null ? 0 : imageView.getWidth();
            int outputHeight = imageView == null ? 0 : imageView.getHeight();
            if (outputWidth <= outputHeight || outputHeight <= 0) {
                return null;
            }

            float sourceWidth = ((Number) XposedHelpers.callMethod(
                presenter,
                "getOriginBitmapWidth"
            )).floatValue();
            float sourceHeight = ((Number) XposedHelpers.callMethod(
                presenter,
                "getOriginBitmapHeight"
            )).floatValue();
            if (sourceWidth <= 0.0f || sourceHeight <= 0.0f) {
                return null;
            }

            SpreadConfig config = spreadConfig(activity);
            boolean showDivider = config == null || config.showDivider;
            boolean nativeFill = config != null && config.nativeFill;
            float gutter = showDivider ? 8.0f : 0.0f;
            float half = outputWidth / 2.0f;
            RectF leftSlot = new RectF(
                0.0f,
                0.0f,
                half - gutter / 2.0f,
                outputHeight
            );
            RectF rightSlot = new RectF(
                half + gutter / 2.0f,
                0.0f,
                outputWidth,
                outputHeight
            );
            int currentPage = currentDocumentPage(activity);
            Object viewModel = XposedHelpers.getObjectField(
                activity,
                "documentViewModel"
            );
            int pageCount = XposedHelpers.getIntField(viewModel, "pageCount");
            SpreadPair pair = spreadPair(
                config,
                currentPage,
                pageCount
            );
            Map<Integer, Object> pageMap =
                (Map<Integer, Object>) XposedHelpers.getObjectField(
                    viewModel,
                    "pageInfoHashMap"
                );
            Object currentPageInfo = pageMap.get(currentPage);
            Bitmap currentOrigin = currentPageInfo == null ? null
                : (Bitmap) XposedHelpers.callMethod(
                    currentPageInfo,
                    "getOriginBitmap"
                );
            RectF currentTrimmingRect = nativeTrimmingRect(
                activity,
                currentPage,
                currentPageInfo,
                currentOrigin,
                nativeFill
            );
            SpreadPageLayout provisionalLayout = pageLayout(
                sourceWidth,
                sourceHeight,
                currentPage == pair.leftPage ? leftSlot : rightSlot,
                nativeFill,
                currentTrimmingRect
            );
            RectF provisional = provisionalLayout.destination;
            log("provisional_active_destination page=" + currentPage
                + " source=" + sourceWidth + "x" + sourceHeight
                + " destination=" + rectDescription(provisional));
            return provisional;
        } catch (Throwable throwable) {
            log("provisional_destination_failed " + throwable);
            XposedBridge.log(throwable);
            return null;
        }
    }

    @SuppressWarnings("unchecked")
    private static Bitmap renderCanonicalCommittedInk(Activity activity) {
        Bitmap rightCanonical = null;
        Bitmap leftCanonical = null;
        boolean rotationChanged = false;
        Object superNoteNote = null;
        Object presenter = null;
        int originalRotation = 0;
        try {
            RectF rightDestination = RIGHT_DESTINATIONS.get(activity);
            RectF leftDestination = LEFT_DESTINATIONS.get(activity);
            if (rightDestination == null || leftDestination == null) {
                return null;
            }

            Object viewModel =
                XposedHelpers.getObjectField(activity, "documentViewModel");
            int currentPage = XposedHelpers.getIntField(viewModel, "currentPage");
            int pageCount = XposedHelpers.getIntField(viewModel, "pageCount");
            SpreadPair pair = spreadPair(
                spreadConfig(activity),
                currentPage,
                pageCount
            );
            int rightPage = pair.rightPage;
            int leftPage = pair.leftPage;
            Map<Integer, Object> pageMap =
                (Map<Integer, Object>) XposedHelpers.getObjectField(
                    viewModel,
                    "pageInfoHashMap"
                );
            Object rightInfo = rightPage >= 0 ? pageMap.get(rightPage) : null;
            Object leftInfo = leftPage >= 0 ? pageMap.get(leftPage) : null;
            if ((rightPage >= 0 && rightInfo == null)
                || (leftPage >= 0 && leftInfo == null)) {
                log("canonical_ink_failed missing_page_info right="
                    + (rightInfo != null) + " left=" + (leftInfo != null));
                return null;
            }

            Bitmap rightPageBitmap = rightInfo == null ? null
                : (Bitmap) XposedHelpers.callMethod(
                    rightInfo,
                    "getOriginBitmap"
                );
            Bitmap leftPageBitmap = leftInfo == null ? null
                : (Bitmap) XposedHelpers.callMethod(
                    leftInfo,
                    "getOriginBitmap"
                );
            if ((rightPage >= 0 && !usable(rightPageBitmap))
                || (leftPage >= 0 && !usable(leftPageBitmap))) {
                log("canonical_ink_failed unusable_page_bitmap");
                return null;
            }

            Bitmap geometryBitmap = usable(rightPageBitmap)
                ? rightPageBitmap : leftPageBitmap;
            int canonicalWidth = geometryBitmap.getWidth();
            int canonicalHeight = geometryBitmap.getHeight();
            if (rightPage >= 0) {
                rightCanonical = Bitmap.createBitmap(
                    rightPageBitmap.getWidth(),
                    rightPageBitmap.getHeight(),
                    Bitmap.Config.ARGB_8888
                );
            }
            if (leftPage >= 0) {
                leftCanonical = Bitmap.createBitmap(
                    leftPageBitmap.getWidth(),
                    leftPageBitmap.getHeight(),
                    Bitmap.Config.ARGB_8888
                );
            }

            presenter = XposedHelpers.getObjectField(
                activity,
                "handWritePresenter"
            );
            superNoteNote =
                XposedHelpers.getObjectField(presenter, "superNoteNote");
            String markPath =
                (String) XposedHelpers.getObjectField(presenter, "markPath");
            originalRotation =
                XposedHelpers.getIntField(presenter, "screenRotation");

            // Load the mark pages in their canonical portrait orientation,
            // then immediately restore Supernote's active landscape rotation.
            XposedHelpers.callMethod(
                superNoteNote,
                "screenRotation",
                1000,
                0,
                0
            );
            rotationChanged = true;
            boolean rightLoaded = rightPage >= 0 && (Boolean) XposedHelpers
                .callMethod(
                    superNoteNote,
                    "loadMarkPageBitmap",
                    markPath,
                    rightPage + 1,
                    rightCanonical
                );
            boolean leftLoaded = leftPage >= 0 && (Boolean) XposedHelpers
                .callMethod(
                    superNoteNote,
                    "loadMarkPageBitmap",
                    markPath,
                    leftPage + 1,
                    leftCanonical
                );

            ImageView imageView =
                (ImageView) XposedHelpers.getObjectField(activity, "mImage");
            Bitmap transformed = Bitmap.createBitmap(
                imageView.getWidth(),
                imageView.getHeight(),
                Bitmap.Config.ARGB_8888
            );
            Canvas canvas = new Canvas(transformed);
            Paint paint = new Paint(
                Paint.ANTI_ALIAS_FLAG | Paint.FILTER_BITMAP_FLAG
            );
            if (leftLoaded) {
                int saveCount = canvas.save();
                RectF visible = LEFT_VISIBLE_BOUNDS.get(activity);
                if (visible != null) canvas.clipRect(visible);
                canvas.drawBitmap(leftCanonical, null, leftDestination, paint);
                canvas.restoreToCount(saveCount);
            }
            if (rightLoaded) {
                int saveCount = canvas.save();
                RectF visible = RIGHT_VISIBLE_BOUNDS.get(activity);
                if (visible != null) canvas.clipRect(visible);
                canvas.drawBitmap(rightCanonical, null, rightDestination, paint);
                canvas.restoreToCount(saveCount);
            }
            log("canonical_ink_transformed right_page=" + rightPage
                + " right_loaded=" + rightLoaded
                + " left_page=" + leftPage
                + " left_loaded=" + leftLoaded
                + " canonical=" + canonicalWidth + "x" + canonicalHeight
                + " right_dest=" + rectDescription(rightDestination)
                + " left_dest=" + rectDescription(leftDestination));
            return transformed;
        } catch (Throwable throwable) {
            log("canonical_ink_failed " + throwable);
            XposedBridge.log(throwable);
            return null;
        } finally {
            if (rotationChanged && superNoteNote != null) {
                boolean restored = false;
                if (presenter != null
                    && isEditableSpreadLandscape(activity)) {
                    restored = applySpreadMarkGeometry(
                        activity,
                        presenter,
                        "canonical_ink_restore"
                    );
                }
                try {
                    if (!restored) {
                        XposedHelpers.callMethod(
                            superNoteNote,
                            "screenRotation",
                            originalRotation + 1000,
                            0,
                            0
                        );
                    }
                } catch (Throwable throwable) {
                    log("canonical_ink_rotation_restore_failed " + throwable);
                    XposedBridge.log(throwable);
                }
            }
            if (rightCanonical != null && !rightCanonical.isRecycled()) {
                rightCanonical.recycle();
            }
            if (leftCanonical != null && !leftCanonical.isRecycled()) {
                leftCanonical.recycle();
            }
        }
    }

    private static Bitmap transformCommittedInkFallback(
        Bitmap source,
        RectF destination,
        Activity activity
    ) {
        try {
            ImageView imageView =
                (ImageView) XposedHelpers.getObjectField(activity, "mImage");
            int outputWidth = imageView.getWidth();
            int outputHeight = imageView.getHeight();
            if (outputWidth <= 0 || outputHeight <= 0) {
                log("committed_ink_failed output=" + outputWidth + "x"
                    + outputHeight);
                return null;
            }

            // In ordinary landscape mode Supernote rasterizes the portrait
            // mark page into a 1872-wide virtual canvas.  The on-screen bitmap
            // contains the top 1404 rows of that approximately 2496-row
            // virtual page.  Map those rows with the page-slot's horizontal
            // scale instead of stretching the clipped bitmap to the slot
            // height.  This is a display-only proof; it does not modify mark
            // data or draw-path input coordinates.
            float scale = destination.width() / source.getWidth();
            RectF visibleDestination = new RectF(
                destination.left,
                destination.top,
                destination.right,
                destination.top + source.getHeight() * scale
            );

            Bitmap transformed = Bitmap.createBitmap(
                outputWidth,
                outputHeight,
                Bitmap.Config.ARGB_8888
            );
            Canvas canvas = new Canvas(transformed);
            Paint paint = new Paint(
                Paint.ANTI_ALIAS_FLAG | Paint.FILTER_BITMAP_FLAG
            );
            canvas.clipRect(visibleBoundsOrDestination(activity, destination));
            canvas.drawBitmap(source, null, visibleDestination, paint);
            log("committed_ink_transformed source="
                + bitmapDescription(source)
                + " scale=" + scale
                + " destination=" + rectDescription(visibleDestination));
            return transformed;
        } catch (Throwable throwable) {
            log("committed_ink_failed " + throwable);
            XposedBridge.log(throwable);
            return null;
        }
    }

    private static boolean sendCalibrationGeometry(
        Object presenter,
        RectF writable,
        int outputWidth,
        int outputHeight
    ) {
        Parcel request = null;
        Parcel reply = null;
        try {
            Object client = XposedHelpers.getObjectField(presenter, "handWriteClient");
            IBinder binder = (IBinder) XposedHelpers.getObjectField(client, "iBinder");
            if (binder == null || !binder.isBinderAlive()) {
                binder = (IBinder) XposedHelpers.callMethod(client, "getBinder");
            }
            if (binder == null || !binder.isBinderAlive()) {
                log("geometry_failed binder_unavailable");
                return false;
            }

            // DrawPath expects the physical full-screen view first. The
            // rendered half-page slot is the virtual coordinate extent.
            //
            // Android exposes two distinct landscape rotations on the Nomad.
            // The earlier proof hard-coded 270, which was correct only while
            // HandWritePresenter.screenRotation was also 270. When the user
            // rotated through the opposite landscape direction, the presenter
            // switched to 90 and the same physical slot was transformed into
            // the wrong native coordinate system. Use the presenter's live
            // rotation so both orientations share the same slot geometry.
            int rotation =
                XposedHelpers.getIntField(presenter, "screenRotation");
            if (rotation != 90 && rotation != 270) {
                log("geometry_failed unsupported_landscape_rotation="
                    + rotation);
                return false;
            }

            // For rotation 90 the native transform computes canonical Y from
            // physical X after first adding originX in physical-screen units.
            // The right slot already starts at the native anchor and needs 0.
            // The left slot must be translated right by the distance from its
            // right edge to the physical screen's right edge (+940 for the
            // current calibration geometry).  Using the negative value pushes
            // the saved trail beyond the canonical page boundary.
            int originX =
                Math.round(outputWidth - writable.right);
            int originY = -Math.round(writable.top);
            int viewWidth = outputWidth;
            int viewHeight = outputHeight;
            int virtualWidth = Math.round(writable.width());
            int virtualHeight = Math.round(writable.height());

            request = Parcel.obtain();
            reply = Parcel.obtain();
            request.writeInterfaceToken("android.demo.IMyService");
            request.writeString("superNoteDocument");
            request.writeInt(rotation);
            request.writeInt(viewWidth);
            request.writeInt(viewHeight);
            request.writeInt(virtualWidth);
            request.writeInt(virtualHeight);
            request.writeInt(originX);
            request.writeInt(originY);
            request.writeFloat(1.0f);

            boolean accepted = binder.transact(10, request, reply, 0);
            String response = reply.readString();
            log("geometry_sent accepted=" + accepted
                + " response=" + response
                + " rotation=" + rotation
                + " view=" + viewWidth + "x" + viewHeight
                + " virtual=" + virtualWidth + "x" + virtualHeight
                + " origin=" + originX + "," + originY);
            return accepted;
        } catch (Throwable throwable) {
            log("geometry_failed " + throwable);
            XposedBridge.log(throwable);
            return false;
        } finally {
            if (request != null) {
                request.recycle();
            }
            if (reply != null) {
                reply.recycle();
            }
        }
    }

    private static boolean sendCalibrationLassoGeometry(
        Object presenter,
        RectF writable,
        int outputWidth,
        int outputHeight
    ) {
        Parcel request = null;
        Parcel reply = null;
        try {
            Object client = XposedHelpers.getObjectField(
                presenter,
                "handWriteClient"
            );
            IBinder binder = (IBinder) XposedHelpers.getObjectField(
                client,
                "iBinder"
            );
            if (binder == null || !binder.isBinderAlive()) {
                binder = (IBinder) XposedHelpers.callMethod(
                    client,
                    "getBinder"
                );
            }
            if (binder == null || !binder.isBinderAlive()) {
                log("lasso_geometry_failed binder_unavailable");
                return false;
            }
            int rotation = XposedHelpers.getIntField(
                presenter,
                "screenRotation"
            );
            if (rotation != 90 && rotation != 270) {
                log("lasso_geometry_failed unsupported_rotation="
                    + rotation);
                return false;
            }
            int originX = Math.round(outputWidth - writable.right);
            int originY = -Math.round(writable.top);
            request = Parcel.obtain();
            reply = Parcel.obtain();
            request.writeInterfaceToken("android.demo.IMyService");
            request.writeString("superNoteDocument");
            request.writeInt(rotation);
            request.writeInt(outputWidth);
            request.writeInt(outputHeight);
            request.writeInt(CANONICAL_PAGE_WIDTH);
            request.writeInt(CANONICAL_PAGE_HEIGHT);
            request.writeInt(originX);
            request.writeInt(originY);
            request.writeFloat(1.0f);
            boolean accepted = binder.transact(10, request, reply, 0);
            String response = reply.readString();
            log("lasso_geometry_sent accepted=" + accepted
                + " response=" + response
                + " rotation=" + rotation
                + " view=" + outputWidth + "x" + outputHeight
                + " virtual=" + CANONICAL_PAGE_WIDTH + "x"
                + CANONICAL_PAGE_HEIGHT
                + " origin=" + originX + "," + originY);
            return accepted;
        } catch (Throwable throwable) {
            log("lasso_geometry_failed " + throwable);
            XposedBridge.log(throwable);
            return false;
        } finally {
            if (request != null) {
                request.recycle();
            }
            if (reply != null) {
                reply.recycle();
            }
        }
    }

    private static RectF visibleBoundsOrDestination(
        Activity activity,
        RectF destination
    ) {
        RectF visible = activePageVisibleBounds(activity);
        if (visible != null) {
            return visible;
        }
        try {
            ImageView imageView = (ImageView) XposedHelpers.getObjectField(
                activity,
                "mImage"
            );
            int outputWidth = imageView == null ? 0 : imageView.getWidth();
            int outputHeight = imageView == null ? 0 : imageView.getHeight();
            if (outputWidth <= outputHeight || outputHeight <= 0) {
                return destination;
            }
            SpreadConfig config = spreadConfig(activity);
            float gutter = config == null || config.showDivider ? 8.0f : 0.0f;
            float half = outputWidth / 2.0f;
            int currentPage = currentDocumentPage(activity);
            Object viewModel = XposedHelpers.getObjectField(
                activity,
                "documentViewModel"
            );
            int pageCount = XposedHelpers.getIntField(viewModel, "pageCount");
            SpreadPair pair = spreadPair(config, currentPage, pageCount);
            RectF slot = currentPage == pair.leftPage
                ? new RectF(0.0f, 0.0f, half - gutter / 2.0f, outputHeight)
                : new RectF(
                    half + gutter / 2.0f,
                    0.0f,
                    outputWidth,
                    outputHeight
                );
            RectF clipped = new RectF(destination);
            clipped.intersect(slot);
            return clipped;
        } catch (Throwable throwable) {
            log("visible_bounds_fallback_failed " + throwable);
            return destination;
        }
    }

    private static ArrayList<Rect> activePageDisabledAreas(
        RectF writable,
        int outputWidth,
        int outputHeight
    ) {
        int left = Math.max(0, Math.min(outputWidth, (int) Math.floor(writable.left)));
        int top = Math.max(0, Math.min(outputHeight, (int) Math.floor(writable.top)));
        int right = Math.max(0, Math.min(outputWidth, (int) Math.ceil(writable.right)));
        int bottom = Math.max(0, Math.min(outputHeight, (int) Math.ceil(writable.bottom)));

        ArrayList<Rect> disabled = new ArrayList<>();
        if (left > 0) {
            disabled.add(new Rect(0, 0, left, outputHeight));
        }
        if (top > 0 && right > left) {
            disabled.add(new Rect(left, 0, right, top));
        }
        if (bottom < outputHeight && right > left) {
            disabled.add(new Rect(left, bottom, right, outputHeight));
        }
        if (right < outputWidth) {
            disabled.add(new Rect(right, 0, outputWidth, outputHeight));
        }
        if (disabled.isEmpty()) {
            // Supernote treats a single zero-sized rectangle as "no disabled
            // region", while an empty list is not transmitted.
            disabled.add(new Rect(0, 0, 0, 0));
        }
        return disabled;
    }

    private static boolean editableSpreadGeometrySupported(
        Bitmap originBitmap,
        RectF destination,
        RectF visibleBounds,
        int outputWidth,
        int outputHeight
    ) {
        if (!usable(originBitmap) || destination == null
            || visibleBounds == null) {
            return false;
        }
        boolean supported = outputWidth == CANONICAL_PAGE_WIDTH
            && outputHeight == 1404
            && originBitmap.getWidth() == 1404
            && originBitmap.getHeight() == 1872
            && destination.width() > 0.0f
            && destination.height() > 0.0f
            && visibleBounds.width() >= SPREAD_PAGE_WIDTH - 1
            && visibleBounds.width() <= outputWidth / 2.0f + 1.0f
            && visibleBounds.height() <= outputHeight + 1.0f
            && Math.abs(
                destination.width() / destination.height()
                    - (float) originBitmap.getWidth()
                        / (float) originBitmap.getHeight()
            ) <= 0.002f;
        if (!supported) {
            log("editable_geometry_rejected origin="
                + bitmapDescription(originBitmap)
                + " destination=" + rectDescription(destination)
                + " visible=" + rectDescription(visibleBounds)
                + " output=" + outputWidth + "x" + outputHeight);
        }
        return supported;
    }

    private static RectF fit(Bitmap bitmap, RectF slot) {
        return fit(bitmap.getWidth(), bitmap.getHeight(), slot);
    }

    private static SpreadPageLayout pageLayout(
        float sourceWidth,
        float sourceHeight,
        RectF slot,
        boolean nativeFill
    ) {
        return pageLayout(
            sourceWidth,
            sourceHeight,
            slot,
            nativeFill,
            null
        );
    }

    private static SpreadPageLayout pageLayout(
        float sourceWidth,
        float sourceHeight,
        RectF slot,
        boolean nativeFill,
        RectF trimmingRect
    ) {
        RectF destination;
        if (nativeFill && validTrimmingRect(
            trimmingRect,
            sourceWidth,
            sourceHeight
        )) {
            // Mirror Supernote's BitmapUtil.trimming() transform without
            // creating a second bitmap. The detected content rectangle is
            // fitted into the half-screen, while its asymmetric placement in
            // the original page is retained. Keeping destination in original
            // page coordinates also keeps pen, eraser, lasso, highlights and
            // links on the same canonical geometry.
            float scale = Math.min(
                slot.width() / trimmingRect.width(),
                slot.height() / trimmingRect.height()
            );
            float horizontalRoom = slot.width()
                - trimmingRect.width() * scale;
            float verticalRoom = slot.height()
                - trimmingRect.height() * scale;
            float horizontalMargin = sourceWidth - trimmingRect.width();
            float verticalMargin = sourceHeight - trimmingRect.height();
            float horizontalAnchor = horizontalMargin > 0.0f
                ? trimmingRect.left / horizontalMargin : 0.5f;
            float verticalAnchor = verticalMargin > 0.0f
                ? trimmingRect.top / verticalMargin : 0.5f;
            horizontalAnchor = Math.max(0.0f, Math.min(1.0f, horizontalAnchor));
            verticalAnchor = Math.max(0.0f, Math.min(1.0f, verticalAnchor));
            float trimmedLeft = slot.left + horizontalRoom * horizontalAnchor;
            float trimmedTop = slot.top + verticalRoom * verticalAnchor;
            float left = trimmedLeft - trimmingRect.left * scale;
            float top = trimmedTop - trimmingRect.top * scale;
            destination = new RectF(
                left,
                top,
                left + sourceWidth * scale,
                top + sourceHeight * scale
            );
        } else {
            destination = nativeFill
                ? fill(sourceWidth, sourceHeight, slot)
                : fit(sourceWidth, sourceHeight, slot);
        }
        RectF visibleBounds = new RectF(destination);
        if (nativeFill) {
            visibleBounds.intersect(slot);
        }
        return new SpreadPageLayout(destination, visibleBounds);
    }

    private static RectF nativeTrimmingRect(
        Activity activity,
        int page,
        Object pageInfo,
        Bitmap originBitmap,
        boolean nativeFill
    ) {
        if (!nativeFill || pageInfo == null || !usable(originBitmap)) {
            return null;
        }
        float sourceWidth = originBitmap.getWidth();
        float sourceHeight = originBitmap.getHeight();
        try {
            RectF nativeRect = (RectF) XposedHelpers.callMethod(
                pageInfo,
                "getTrimmingRect"
            );
            if (validTrimmingRect(nativeRect, sourceWidth, sourceHeight)) {
                RectF copy = new RectF(nativeRect);
                AUTO_TRIMMING_RECTS.put(pageInfo, copy);
                return copy;
            }

            RectF cached = AUTO_TRIMMING_RECTS.get(pageInfo);
            if (validTrimmingRect(cached, sourceWidth, sourceHeight)) {
                return new RectF(cached);
            }

            Class<?> trimmingUtil = activity.getClassLoader().loadClass(
                "com.supernote.document.utils.TrimmingUtil"
            );
            RectF detected = (RectF) trimmingUtil
                .getMethod("getTrimmingRect", Bitmap.class)
                .invoke(null, originBitmap);
            if (validTrimmingRect(detected, sourceWidth, sourceHeight)) {
                RectF copy = new RectF(detected);
                AUTO_TRIMMING_RECTS.put(pageInfo, copy);
                log("native_fill_trim_detected page=" + page
                    + " source=" + bitmapDescription(originBitmap)
                    + " rect=" + rectDescription(copy));
                return copy;
            }
            log("native_fill_trim_unavailable page=" + page
                + " source=" + bitmapDescription(originBitmap)
                + " rect=" + rectDescription(detected));
        } catch (Throwable throwable) {
            log("native_fill_trim_failed page=" + page + " " + throwable);
            XposedBridge.log(throwable);
        }
        return null;
    }

    private static boolean validTrimmingRect(
        RectF rect,
        float sourceWidth,
        float sourceHeight
    ) {
        return rect != null
            && rect.left >= 0.0f
            && rect.top >= 0.0f
            && rect.right <= sourceWidth + 1.0f
            && rect.bottom <= sourceHeight + 1.0f
            && rect.width() > 1.0f
            && rect.height() > 1.0f;
    }

    private static void drawPageBitmap(
        Canvas canvas,
        Bitmap bitmap,
        SpreadPageLayout layout,
        Paint paint
    ) {
        int saveCount = canvas.save();
        canvas.clipRect(layout.visibleBounds);
        canvas.drawBitmap(bitmap, null, layout.destination, paint);
        canvas.restoreToCount(saveCount);
    }

    private static RectF fit(
        float sourceWidth,
        float sourceHeight,
        RectF slot
    ) {
        float scale = Math.min(
            slot.width() / sourceWidth,
            slot.height() / sourceHeight
        );
        float width = sourceWidth * scale;
        float height = sourceHeight * scale;
        float left = slot.left + (slot.width() - width) / 2.0f;
        float top = slot.top + (slot.height() - height) / 2.0f;
        return new RectF(left, top, left + width, top + height);
    }

    private static RectF fill(
        float sourceWidth,
        float sourceHeight,
        RectF slot
    ) {
        float scale = Math.max(
            slot.width() / sourceWidth,
            slot.height() / sourceHeight
        );
        float width = sourceWidth * scale;
        float height = sourceHeight * scale;
        float left = slot.left + (slot.width() - width) / 2.0f;
        float top = slot.top + (slot.height() - height) / 2.0f;
        return new RectF(left, top, left + width, top + height);
    }

    private static boolean usable(Bitmap bitmap) {
        return bitmap != null && !bitmap.isRecycled()
            && bitmap.getWidth() > 0 && bitmap.getHeight() > 0;
    }

    private static void showOverlay(Activity activity, String text) {
        ViewGroup root = activity.findViewById(android.R.id.content);
        View existing = root.findViewWithTag(OVERLAY_TAG);
        TextView label;
        if (existing instanceof TextView) {
            label = (TextView) existing;
        } else {
            label = new TextView(activity);
            label.setTag(OVERLAY_TAG);
            label.setTextColor(Color.WHITE);
            label.setTextSize(14.0f);
            label.setGravity(Gravity.CENTER);
            label.setBackgroundColor(Color.rgb(120, 0, 0));
            FrameLayout.LayoutParams layoutParams = new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                52,
                Gravity.TOP | Gravity.CENTER_HORIZONTAL
            );
            layoutParams.topMargin = 8;
            root.addView(label, layoutParams);
        }
        label.setText(text);
        label.bringToFront();
    }

    private static void showStatusOverlay(Activity activity, String text) {
        SpreadConfig config = spreadConfig(activity);
        if (config != null && !config.showHeader) {
            removeOverlay(activity);
            return;
        }
        showOverlay(activity, text);
    }

    private static void removeOverlay(Activity activity) {
        try {
            ViewGroup root = activity.findViewById(android.R.id.content);
            View existing = root.findViewWithTag(OVERLAY_TAG);
            if (existing != null) {
                root.removeView(existing);
            }
        } catch (Throwable ignored) {
        }
    }

    private static String bitmapDescription(Bitmap bitmap) {
        if (bitmap == null) {
            return "null";
        }
        return bitmap.getWidth() + "x" + bitmap.getHeight()
            + ":recycled=" + bitmap.isRecycled();
    }

    private static String viewDescription(View view) {
        if (view == null) {
            return "null";
        }
        return view.getWidth() + "x" + view.getHeight()
            + "@(" + view.getX() + "," + view.getY() + ")"
            + ":scale=(" + view.getScaleX() + "," + view.getScaleY() + ")";
    }

    private static String rectDescription(RectF rect) {
        if (rect == null) {
            return "null";
        }
        return "[" + Math.round(rect.left) + "," + Math.round(rect.top)
            + "-" + Math.round(rect.right) + "," + Math.round(rect.bottom) + "]";
    }

    private static String rectDescription(Rect rect) {
        if (rect == null) {
            return "null";
        }
        return "[" + rect.left + "," + rect.top
            + "-" + rect.right + "," + rect.bottom + "]";
    }

    private static void log(String message) {
        Log.i(TAG, message);
        XposedBridge.log(TAG + " " + message);
        traceLogMessage(message);
    }
}
