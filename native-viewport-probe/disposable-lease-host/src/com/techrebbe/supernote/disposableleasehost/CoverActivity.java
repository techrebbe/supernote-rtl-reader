package com.techrebbe.supernote.disposableleasehost;

import android.app.Activity;
import android.os.Bundle;
import android.widget.TextView;

/** Ordinary foreground cover to drive pause/stop/resume of ProbeActivity. */
public final class CoverActivity extends Activity {
    private long generation;

    @Override public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        generation = getIntent().getLongExtra(ProbeState.COVER_GENERATION_EXTRA, -1);
        TextView label = new TextView(this);
        label.setText("Disposable lifecycle cover");
        setContentView(label);
        CoverGate.Activation activation = ProbeState.get().registerCover(this, generation);
        ProbeState.get().record("COVER_CREATE", "generation=" + generation
                + " activation=" + activation);
        if (activation != CoverGate.Activation.ACTIVE) finish();
    }

    @Override protected void onResume() {
        super.onResume();
        ProbeState.get().record("COVER_RESUME", "");
    }

    @Override protected void onDestroy() {
        ProbeState.get().record("COVER_ACTIVITY_DESTROY", "generation=" + generation);
        ProbeState.get().unregisterCover(this, generation);
        super.onDestroy();
    }
}
