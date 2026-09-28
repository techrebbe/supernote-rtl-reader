package com.techrebbe.supernote.layoutfencetrial;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.Binder;
import android.os.Bundle;
import android.os.Process;

import org.json.JSONException;
import org.json.JSONObject;

/** Shell/own-UID diagnostics; pinned one-shot commands only. */
public final class TrialProvider extends ContentProvider {
    @Override public boolean onCreate() {
        TrialProcess.get();
        return true;
    }

    @Override public Cursor query(Uri uri, String[] projection, String selection,
            String[] selectionArgs, String sortOrder) {
        enforceCaller();
        if ("/events".equals(uri.getPath())) {
            long after = 0;
            String raw = uri.getQueryParameter("after");
            if (raw != null) after = Long.parseLong(raw);
            TrialProcess.Window window = TrialProcess.get().window(after);
            MatrixCursor rows = new MatrixCursor(new String[] { "pid", "incarnation",
                    "firstRetained", "lastSequence", "sequence", "elapsedMs",
                    "name", "detail" });
            for (TrialProcess.Event event : window.events) {
                rows.addRow(new Object[] { window.pid, window.incarnation,
                        window.firstRetained, window.lastSequence, event.sequence,
                        event.elapsedMs, event.name, event.detail });
            }
            return rows;
        }
        if ("/identity".equals(uri.getPath()) || "/state".equals(uri.getPath())) {
            MatrixCursor rows = new MatrixCursor(new String[] { "json" }, 1);
            rows.addRow(new Object[] { "/identity".equals(uri.getPath())
                    ? identityJson() : stateJson() });
            return rows;
        }
        throw new IllegalArgumentException("unknown disposable path");
    }

    @Override public Bundle call(String method, String arg, Bundle extras) {
        enforceCaller();
        Bundle result = new Bundle();
        boolean refreshClaimed = false;
        try {
            if ("identity".equals(method)) {
                result.putString("json", identityJson());
                result.putBoolean("ok", true);
            } else if ("state".equals(method)) {
                result.putString("json", stateJson());
                result.putBoolean("ok", true);
            } else if ("prearm".equals(method)) {
                TrialProcess.ArmInfo arm = TrialProcess.get().prearm(extras);
                result.putBoolean("ok", arm != null);
                if (arm != null) {
                    result.putString("armToken", arm.token);
                    result.putLong("armDeadlineElapsedMs", arm.deadlineElapsedMs);
                }
                result.putString("json", identityJson());
            } else if ("refresh".equals(method)) {
                final Bundle pins = extras == null ? null : new Bundle(extras);
                if (!TrialProcess.get().claimRefresh(pins)) {
                    result.putBoolean("ok", false);
                    result.putString("error", "refresh requires unused arm and exact pins/token");
                    return result;
                }
                refreshClaimed = true;
                TrialActivity.RefreshResult request = TrialProcess.get().onMain(
                        new TrialProcess.MainWork<TrialActivity.RefreshResult>() {
                    @Override public TrialActivity.RefreshResult run() {
                        TrialActivity activity = TrialProcess.get().activity();
                        return activity == null ? null : activity.requestRefresh(pins);
                    }
                });
                boolean completed = TrialProcess.get().completeRefresh(pins,
                        request == null ? null : request.token);
                result.putBoolean("ok", completed);
                if (completed) {
                    result.putString("refreshToken", request.token);
                    result.putLong("paintFloorRevision", request.paintFloorRevision);
                    result.putLong("completedPaintCountFloor",
                            request.completedPaintCountFloor);
                    result.putLong("requestedElapsedMs", request.requestedElapsedMs);
                } else {
                    result.putString("error", "refresh ambiguous or rejected; no retry");
                }
                result.putString("json", identityJson());
            } else if ("command".equals(method)) {
                final TrialEvidence.Command command = TrialEvidence.Command.fromWire(arg);
                final Bundle pins = extras == null ? null : new Bundle(extras);
                if (!TrialProcess.get().claimArmedCommand(pins)) {
                    result.putBoolean("ok", false);
                    result.putString("error", "not armed or exact pins/token rejected");
                    return result;
                }
                boolean accepted = TrialProcess.get().onMain(new TrialProcess.MainWork<Boolean>() {
                    @Override public Boolean run() {
                        TrialActivity activity = TrialProcess.get().activity();
                        return activity != null && activity.applyCommand(command, pins);
                    }
                });
                result.putBoolean("ok", accepted);
                result.putString("command", command.wire);
                result.putString("json", stateJson());
            } else if ("sentinel".equals(method)) {
                final String stage = arg;
                final Bundle pins = extras == null ? null : new Bundle(extras);
                if (!TrialProcess.get().claimSentinel(stage, pins)) {
                    result.putBoolean("ok", false);
                    result.putString("error", "sentinel out of order or pins/token rejected");
                    return result;
                }
                TrialActivity.SentinelResult witness = TrialProcess.get().onMain(
                        new TrialProcess.MainWork<TrialActivity.SentinelResult>() {
                    @Override public TrialActivity.SentinelResult run() {
                        TrialActivity activity = TrialProcess.get().activity();
                        return activity == null ? null : activity.performSentinel(stage, pins);
                    }
                });
                boolean unchanged = witness != null && witness.unchanged;
                boolean completed = TrialProcess.get().completeSentinel(stage, pins, unchanged);
                result.putBoolean("ok", completed && unchanged);
                result.putBoolean("unchanged", unchanged);
                result.putString("stage", stage);
                result.putString("json", witness == null ? null : witness.json);
            } else if ("finish".equals(method)) {
                final Bundle pins = extras == null ? null : new Bundle(extras);
                boolean finished = TrialProcess.get().onMain(
                        new TrialProcess.MainWork<Boolean>() {
                    @Override public Boolean run() {
                        TrialActivity activity = TrialProcess.get().activity();
                        return activity != null && activity.finishAfterSentinels(pins);
                    }
                });
                result.putBoolean("ok", finished);
                result.putString("json", identityJson());
            } else if ("abort".equals(method)) {
                if (!TrialProcess.get().abort(extras)) {
                    result.putBoolean("ok", false);
                    result.putString("error", "abort pins/token rejected or terminal");
                    return result;
                }
                // No response is promised: independent Binder-thread self-kill.
                Process.killProcess(Process.myPid());
                result.putBoolean("ok", true);
            } else {
                throw new IllegalArgumentException("unknown provider method");
            }
        } catch (RuntimeException exception) {
            if (refreshClaimed) TrialProcess.get().failRefresh();
            result.putBoolean("ok", false);
            result.putBoolean("outcomeUnknown", exception.getMessage() != null
                    && exception.getMessage().contains("outcome unknown"));
            result.putString("error", exception.getClass().getSimpleName() + ": "
                    + exception.getMessage());
        }
        return result;
    }

    private static String identityJson() {
        try { return TrialProcess.get().identityJson().toString(); }
        catch (JSONException exception) { throw new IllegalStateException(exception); }
    }

    private static String stateJson() {
        return TrialProcess.get().onMain(new TrialProcess.MainWork<String>() {
            @Override public String run() {
                TrialActivity activity = TrialProcess.get().activity();
                if (activity != null) return activity.snapshotJson();
                try {
                    JSONObject state = new JSONObject();
                    state.put("schema", TrialContract.SCHEMA);
                    state.put("process", TrialProcess.get().identityJson());
                    state.put("activityPresent", false);
                    return state.toString();
                } catch (JSONException exception) {
                    throw new IllegalStateException(exception);
                }
            }
        });
    }

    private static void enforceCaller() {
        int uid = Binder.getCallingUid();
        if (uid != Process.myUid() && uid != Process.SHELL_UID && uid != Process.ROOT_UID) {
            throw new SecurityException("disposable diagnostics accept only own/shell/root UID");
        }
    }

    @Override public String getType(Uri uri) {
        return "vnd.android.cursor.item/vnd.layoutfencetrial";
    }
    @Override public Uri insert(Uri uri, ContentValues values) {
        throw new UnsupportedOperationException("no writes");
    }
    @Override public int delete(Uri uri, String selection, String[] selectionArgs) {
        throw new UnsupportedOperationException("no deletes");
    }
    @Override public int update(Uri uri, ContentValues values, String selection,
            String[] selectionArgs) {
        throw new UnsupportedOperationException("no updates");
    }
}
