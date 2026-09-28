package com.techrebbe.supernote.disposableleasehost;

import android.app.Application;

/** Forces the process-local ledger and app-primary lease slot to exist first. */
public final class ProbeApplication extends Application {
    @Override public void onCreate() {
        super.onCreate();
        ProbeState.get().record("APPLICATION_CREATE", "primary-loader-root-ready");
    }
}
