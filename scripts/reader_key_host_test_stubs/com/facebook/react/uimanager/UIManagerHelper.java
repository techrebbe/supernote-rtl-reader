package com.facebook.react.uimanager;
import android.view.View;
import com.facebook.react.uimanager.events.EventDispatcher;
public final class UIManagerHelper {
    public static EventDispatcher dispatcher;
    public static EventDispatcher getEventDispatcherForReactTag(ThemedReactContext context,int tag) { return dispatcher; }
    public static ThemedReactContext getReactContext(View view) { return new ThemedReactContext(); }
    public static int getSurfaceId(View view) { return 1; }
}
