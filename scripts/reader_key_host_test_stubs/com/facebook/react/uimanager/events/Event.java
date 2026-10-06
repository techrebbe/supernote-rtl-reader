package com.facebook.react.uimanager.events;
import com.facebook.react.bridge.WritableMap;
/** Queue model only: no RN runtime delivery proof. */
public abstract class Event<T extends Event> {
    protected Event(int surface,int tag) {}
    public abstract String getEventName();
    public boolean canCoalesce() { return true; }
    protected WritableMap getEventData() { return null; }
}
