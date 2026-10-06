package com.facebook.react.views.view;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.uimanager.ThemedReactContext;
import java.util.HashMap;
import java.util.Map;
/** Only callback transaction and command delegation, not Android layout. */
public class ReactViewManager {
    public int delegatedCommands, droppedViews;
    public String getName() { return "RCTView"; }
    public ReactViewGroup createViewInstance(ThemedReactContext context) { return new ReactViewGroup(context); }
    protected void onAfterUpdateTransaction(ReactViewGroup view) {}
    public Map<String,Integer> getCommandsMap() { Map<String,Integer> map=new HashMap<>(); map.put("stock",1); return map; }
    public void receiveCommand(ReactViewGroup view,int command,ReadableArray args) { delegatedCommands++; }
    public void receiveCommand(ReactViewGroup view,String command,ReadableArray args) { delegatedCommands++; }
    public Map<String,Object> getExportedCustomDirectEventTypeConstants() { return new HashMap<>(); }
    public void onDropViewInstance(ReactViewGroup view) { droppedViews++; }
}
