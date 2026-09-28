package com.techrebbe.supernote.leasetiletrial;

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
public final class TileTrialProvider extends ContentProvider {
    @Override public boolean onCreate() {
        TileTrialState.get().record("PROVIDER_CREATE", "");
        return true;
    }

    @Override public Cursor query(Uri uri, String[] projection, String selection,
            String[] selectionArgs, String sortOrder) {
        enforceTestCaller();
        String path = uri.getPath();
        if ("/events".equals(path)) {
            long after = 0;
            String raw = uri.getQueryParameter("after");
            if (raw != null) {
                try { after = Long.parseLong(raw); }
                catch (NumberFormatException exception) {
                    throw new IllegalArgumentException("after must be an integer");
                }
                if (after < 0) throw new IllegalArgumentException("after must be nonnegative");
            }
            TileTrialState.Window window = TileTrialState.get().window(after);
            MatrixCursor rows = new MatrixCursor(new String[] {
                    "pid", "incarnation", "firstRetained", "lastSequence",
                    "sequence", "elapsedMs", "name", "detail"
            });
            for (TileTrialState.Event event : window.events) {
                rows.addRow(new Object[] { window.pid, window.incarnation,
                        window.firstRetained, window.lastSequence, event.sequence,
                        event.elapsedMs, event.name, event.detail });
            }
            return rows;
        }
        if ("/state".equals(path) || "/identity".equals(path)) {
            MatrixCursor rows = new MatrixCursor(new String[] { "json" }, 1);
            rows.addRow(new Object[] { "/identity".equals(path)
                    ? identityJson() : stateJson() });
            return rows;
        }
        throw new IllegalArgumentException("unknown tile trial path");
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
                if (!"start-tile".equals(arg) && !"stop-tile".equals(arg)) {
                    throw new IllegalArgumentException("unsupported tile command");
                }
                if (extras == null || !extras.containsKey("expectedPid")
                        || !extras.containsKey("expectedIncarnation")
                        || !extras.containsKey("expectedActivityToken")
                        || !extras.containsKey("expectedRootToken")) {
                    throw new IllegalArgumentException("expected identity extras required");
                }
                final String command = arg;
                final int expectedPid = extras.getInt("expectedPid", -1);
                final String expectedIncarnation = extras.getString("expectedIncarnation");
                final String expectedActivityToken = extras.getString("expectedActivityToken");
                final String expectedRootToken = extras.getString("expectedRootToken");
                boolean accepted = TileTrialState.get().onMain(
                        new TileTrialState.MainWork<Boolean>() {
                    @Override public Boolean run() {
                        if (!TileTrialState.get().matchesProcess(expectedPid,
                                expectedIncarnation)) return false;
                        TileTrialActivity activity = TileTrialState.get().activity();
                        return activity != null && activity.command(command,
                                expectedActivityToken, expectedRootToken);
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
        try { return TileTrialState.get().identityJson().toString(); }
        catch (JSONException exception) { throw new IllegalStateException(exception); }
    }

    private static String stateJson() {
        return TileTrialState.get().onMain(new TileTrialState.MainWork<String>() {
            @Override public String run() {
                TileTrialActivity activity = TileTrialState.get().activity();
                if (activity != null) return activity.stateJson();
                try {
                    JSONObject value = new JSONObject();
                    value.put("schema", "disposable-lease-tile-trial-state-v1");
                    value.put("process", TileTrialState.get().identityJson());
                    value.put("activityPresent", false);
                    return value.toString();
                } catch (JSONException exception) {
                    throw new IllegalStateException(exception);
                }
            }
        });
    }

    private static void enforceTestCaller() {
        int caller = Binder.getCallingUid();
        if (caller != Process.myUid() && caller != Process.SHELL_UID
                && caller != Process.ROOT_UID) {
            throw new SecurityException("disposable tile trial accepts only own/shell/root UID");
        }
    }

    @Override public String getType(Uri uri) {
        return "vnd.android.cursor.item/vnd.disposableleasetiletrial";
    }
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
