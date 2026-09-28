package com.techrebbe.supernote.disposableleasehost;

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

/** Test-only shell/app-UID channel that remains available after Frida detaches. */
public final class ProbeProvider extends ContentProvider {
    @Override public boolean onCreate() {
        ProbeState.get().record("PROVIDER_CREATE", "");
        return true;
    }

    @Override public Cursor query(Uri uri, String[] projection, String selection,
            String[] selectionArgs, String sortOrder) {
        enforceTestCaller();
        String path = uri.getPath();
        if ("/events".equals(path)) {
            long after = 0;
            String value = uri.getQueryParameter("after");
            if (value != null) {
                try { after = Long.parseLong(value); }
                catch (NumberFormatException exception) {
                    throw new IllegalArgumentException("after must be a sequence number");
                }
                if (after < 0) throw new IllegalArgumentException("after must be nonnegative");
            }
            MatrixCursor cursor = new MatrixCursor(new String[] {
                    "pid", "incarnation", "windowFirstSequence", "windowLastSequence",
                    "sequence", "elapsedRealtimeMs", "name", "detail"
            });
            ProbeState.EvidenceWindow window = ProbeState.get().evidenceWindow(after);
            for (EventRing.Event event : window.ledger.events) {
                cursor.addRow(new Object[] { window.pid, window.incarnation,
                        window.ledger.firstRetainedSequence, window.ledger.lastSequence,
                        event.sequence,
                        event.elapsedMs, event.name, event.detail });
            }
            return cursor;
        }
        if ("/state".equals(path) || "/identity".equals(path)) {
            MatrixCursor cursor = new MatrixCursor(new String[] { "json" }, 1);
            String json = "/identity".equals(path) ? identityJson() : stateJson();
            cursor.addRow(new Object[] { json });
            return cursor;
        }
        throw new IllegalArgumentException("unknown probe path");
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
                if (arg == null) throw new IllegalArgumentException("command arg required");
                final String command = arg;
                Boolean accepted = ProbeState.get().onMain(new ProbeState.MainWork<Boolean>() {
                    @Override public Boolean run() {
                        ProbeActivity activity = ProbeState.get().activity();
                        return activity != null && activity.applyCommand(command);
                    }
                });
                result.putBoolean("ok", accepted);
                result.putString("command", command);
                result.putString("json", stateJson());
            } else {
                throw new IllegalArgumentException("unknown method");
            }
        } catch (RuntimeException exception) {
            result.putBoolean("ok", false);
            result.putString("error", exception.getClass().getSimpleName() + ": "
                    + exception.getMessage());
        }
        return result;
    }

    private static String identityJson() {
        try { return ProbeState.get().identityJson().toString(); }
        catch (JSONException exception) { throw new IllegalStateException(exception); }
    }

    private static String stateJson() {
        return ProbeState.get().onMain(new ProbeState.MainWork<String>() {
            @Override public String run() {
                ProbeActivity activity = ProbeState.get().activity();
                if (activity != null) return activity.snapshotOnMainThread();
                try {
                    JSONObject result = new JSONObject();
                    result.put("schema", "disposable-lease-host-state-v1");
                    result.put("process", ProbeState.get().identityJson());
                    result.put("activityPresent", false);
                    return result.toString();
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
            throw new SecurityException("disposable host accepts only own/shell/root UID");
        }
    }

    @Override public String getType(Uri uri) { return "vnd.android.cursor.item/vnd.probe"; }
    @Override public Uri insert(Uri uri, ContentValues values) {
        throw new UnsupportedOperationException("read-only provider");
    }
    @Override public int delete(Uri uri, String selection, String[] selectionArgs) {
        throw new UnsupportedOperationException("read-only provider");
    }
    @Override public int update(Uri uri, ContentValues values, String selection,
            String[] selectionArgs) {
        throw new UnsupportedOperationException("read-only provider");
    }
}
