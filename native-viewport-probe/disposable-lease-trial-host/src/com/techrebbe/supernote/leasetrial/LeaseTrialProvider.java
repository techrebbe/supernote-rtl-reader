package com.techrebbe.supernote.leasetrial;

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

/** Shell/app-UID-only diagnostic channel for the disposable emulator package. */
public final class LeaseTrialProvider extends ContentProvider {
    @Override public boolean onCreate() {
        LeaseTrialState.get().record("PROVIDER_CREATE", "");
        return true;
    }

    @Override public Cursor query(Uri uri, String[] projection, String selection,
            String[] selectionArgs, String sortOrder) {
        enforceTestCaller();
        if ("/events".equals(uri.getPath())) {
            long after = 0;
            String raw = uri.getQueryParameter("after");
            if (raw != null) {
                try { after = Long.parseLong(raw); }
                catch (NumberFormatException exception) {
                    throw new IllegalArgumentException("after must be integer");
                }
                if (after < 0) throw new IllegalArgumentException("after must be nonnegative");
            }
            LeaseTrialState.Window window = LeaseTrialState.get().window(after);
            MatrixCursor rows = new MatrixCursor(new String[] {
                    "pid", "incarnation", "firstRetained", "lastSequence",
                    "sequence", "elapsedMs", "name", "detail"
            });
            for (LeaseTrialState.Event event : window.events) {
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
        throw new IllegalArgumentException("unknown trial path");
    }

    @Override public Bundle call(String method, String arg, Bundle extras) {
        enforceTestCaller();
        Bundle result = new Bundle();
        try {
            if ("identity".equals(method)) {
                result.putString("json", identityJson());
                result.putBoolean("ok", true);
            } else if ("state".equals(method)) {
                result.putString("json", stateJson());
                result.putBoolean("ok", true);
            } else if ("command".equals(method)) {
                if (!"preflight-noop-layout".equals(arg) && !"finish".equals(arg)) {
                    throw new IllegalArgumentException("unsupported no-child command");
                }
                final String command = arg;
                boolean accepted = LeaseTrialState.get().onMain(
                        new LeaseTrialState.MainWork<Boolean>() {
                    @Override public Boolean run() {
                        LeaseTrialActivity activity = LeaseTrialState.get().activity();
                        return activity != null && activity.applyCommand(command);
                    }
                });
                result.putBoolean("ok", accepted);
                result.putString("command", command);
                result.putString("json", stateJson());
            } else {
                throw new IllegalArgumentException("unknown provider method");
            }
        } catch (RuntimeException exception) {
            result.putBoolean("ok", false);
            result.putString("error", exception.getClass().getSimpleName() + ": "
                    + exception.getMessage());
        }
        return result;
    }

    private static String identityJson() {
        try { return LeaseTrialState.get().identityJson().toString(); }
        catch (JSONException exception) { throw new IllegalStateException(exception); }
    }

    private static String stateJson() {
        return LeaseTrialState.get().onMain(new LeaseTrialState.MainWork<String>() {
            @Override public String run() {
                LeaseTrialActivity activity = LeaseTrialState.get().activity();
                if (activity != null) return activity.snapshotJson();
                try {
                    JSONObject state = new JSONObject();
                    state.put("schema", LeaseTrialContract.STATE_SCHEMA);
                    state.put("process", LeaseTrialState.get().identityJson());
                    state.put("activityPresent", false);
                    return state.toString();
                } catch (JSONException exception) {
                    throw new IllegalStateException(exception);
                }
            }
        });
    }

    private static void enforceTestCaller() {
        int uid = Binder.getCallingUid();
        if (uid != Process.myUid() && uid != Process.SHELL_UID && uid != Process.ROOT_UID) {
            throw new SecurityException("disposable trial accepts only own/shell/root UID");
        }
    }

    @Override public String getType(Uri uri) { return "vnd.android.cursor.item/vnd.leasetrial"; }
    @Override public Uri insert(Uri uri, ContentValues values) {
        throw new UnsupportedOperationException("no file writes");
    }
    @Override public int delete(Uri uri, String selection, String[] selectionArgs) {
        throw new UnsupportedOperationException("no file deletes");
    }
    @Override public int update(Uri uri, ContentValues values, String selection,
            String[] selectionArgs) {
        throw new UnsupportedOperationException("no file updates");
    }
}
