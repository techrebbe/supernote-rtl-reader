package t014;

import android.os.SystemClock;
import android.view.KeyEvent;
import android.view.View;
import com.facebook.react.bridge.*;
import com.facebook.react.uimanager.ThemedReactContext;
import com.facebook.react.uimanager.UIManagerHelper;
import java.util.*;

/** Actual bridge source under transaction/event-queue doubles. NOT RN/HID proof. */
public final class ReaderKeyBridgeTests {
    private static int assertions;
    private static final String NAMESPACE="d1a05000-0000-4000-8000-000000000001";
    private static final ArrayList<ReaderKeyEvent> queue=new ArrayList<>();
    private static void check(boolean value,String why) { assertions++; if(!value) throw new AssertionError(why); }
    private static ReadableType type(Object value) {
        if(value==null) return ReadableType.Null;
        if(value instanceof String) return ReadableType.String;
        if(value instanceof Boolean) return ReadableType.Boolean;
        if(value instanceof Number) return ReadableType.Number;
        if(value instanceof ReadableArray) return ReadableType.Array;
        return ReadableType.Map;
    }
    private static final class ArrayValue implements ReadableArray {
        final Object[] values;
        ArrayValue(Object... values) { this.values=values; }
        public int size() { return values.length; }
        public ReadableType getType(int index) { return type(values[index]); }
        public double getDouble(int index) { return ((Number)values[index]).doubleValue(); }
        public String getString(int index) { return (String)values[index]; }
    }
    private static final class MapValue extends LinkedHashMap<String,Object> implements ReadableMap {
        public ReadableMapKeySetIterator keySetIterator() {
            Iterator<String> keys=keySet().iterator();
            return new ReadableMapKeySetIterator() {
                public boolean hasNextKey() { return keys.hasNext(); }
                public String nextKey() { return keys.next(); }
            };
        }
        public ReadableType getType(String key) { return type(get(key)); }
        public String getString(String key) { return (String)get(key); }
        public boolean getBoolean(String key) { return (Boolean)get(key); }
        public ReadableArray getArray(String key) { return (ReadableArray)get(key); }
    }
    private static MapValue spec(int counter,String document,boolean enabled,Object... keys) {
        MapValue value=new MapValue();
        value.put("requestId",NAMESPACE+":"+counter); value.put("documentId",document);
        value.put("enabled",enabled); value.put("keyCodes",new ArrayValue(keys));
        return value;
    }
    private static Map<String,Object> data(int index) { return (Arguments.MapValue)queue.get(index).getEventData(); }
    private static ReaderKeyHost host(ReaderKeyHostManager manager) {
        queue.clear(); UIManagerHelper.dispatcher=event -> queue.add((ReaderKeyEvent)event);
        SystemClock.now+=10;
        ReaderKeyHost host=(ReaderKeyHost)manager.createViewInstance(new ThemedReactContext());
        host.onAttachedToWindow(); return host;
    }
    private static void atomicConfigAndFrozenStream() {
        ReaderKeyHostManager manager=new ReaderKeyHostManager(); ReaderKeyHost host=host(manager);
        manager.setRouteSpec(host,spec(1,"one",true,93));
        check(queue.isEmpty(),"Prop setter cannot arm/publish before entire transaction");
        check(!host.dispatchKeyEvent(new KeyEvent(0,93,++SystemClock.now,0)),"Pending configuration cannot consume");
        manager.onAfterUpdateTransaction(host);
        check(queue.size()==1 && data(0).get("requestId").equals(NAMESPACE+":1"),"Complete config committed/stamped once");
        manager.receiveCommand(host,"requestReaderKeyFocus",new ArrayValue(NAMESPACE+":0"));
        check(!host.isFocused(),"Stale focus command rejected");
        manager.receiveCommand(host,100,new ArrayValue(NAMESPACE+":1"));
        check(host.isFocused() && queue.size()==2 && data(1).get("eligible").equals(true),"Current config requests unclaimed focus");
        long down=++SystemClock.now;
        host.dispatchKeyEvent(new KeyEvent(0,93,down,0)); host.dispatchKeyEvent(new KeyEvent(1,93,down,0));
        check(queue.size()==4,"State/DOWN/UP share one queue, no repeat coalescing");
        for(int index=0;index<queue.size();index++) {
            check(!queue.get(index).canCoalesce() && queue.get(index).getEventName().equals("topReaderKey"),"Every envelope is noncoalescing single-event transport");
            check(((Number)data(index).get("sequence")).longValue()==index+1,"Native sequence stamped in publication order");
        }
        Map<String,Object> queued=data(2); Object oldActivation=queued.get("activationId");
        manager.setRouteSpec(host,spec(2,"two",true,92));
        check(queued.get("documentId").equals("one"),"Pending next props cannot restamp queued payload");
        manager.onAfterUpdateTransaction(host);
        check(data(4).get("requestId").equals(NAMESPACE+":2") && data(4).get("documentId").equals("two"),"New document/keys/ID one atomic commit");
        check(queued.get("documentId").equals("one") && queued.get("activationId").equals(oldActivation),"Later config cannot restamp dispatched event");
        int count=queue.size(); manager.setRouteSpec(host,spec(2,"two",true,92)); manager.onAfterUpdateTransaction(host);
        check(queue.size()==count,"Identical props do not cancel held contacts/change activation");
        check(!host.dispatchKeyEvent(new KeyEvent(0,93,++SystemClock.now,0)),"Removed key no longer owned");
        manager.receiveCommand(host,"stock",null); check(manager.delegatedCommands==1,"Ordinary ReactViewManager command retained");
        host.clearFocus(); host.otherFocus=new View();
        manager.receiveCommand(host,100,new ArrayValue(NAMESPACE+":2"));
        check(!host.isFocused(),"Focus command cannot steal a control/text field");
        manager.onDropViewInstance(host);
        check(data(queue.size()-1).get("disposed").equals(true) && manager.droppedViews==1,"Drop publishes terminal state and releases manager ownership");
        check(!host.dispatchKeyEvent(new KeyEvent(0,92,++SystemClock.now,0)),"Drop leaves no live key listener");
    }
    private static void malformedAndReplay() {
        for(int variant=0;variant<10;variant++) {
            ReaderKeyHostManager manager=new ReaderKeyHostManager(); ReaderKeyHost host=host(manager);
            manager.setRouteSpec(host,spec(1,"one",true,93)); manager.onAfterUpdateTransaction(host);
            manager.receiveCommand(host,100,new ArrayValue(NAMESPACE+":1"));
            MapValue invalid=spec(2,"two",true,92);
            switch(variant) {
                case 0: invalid.put("extra",1); break;
                case 1: invalid.put("enabled",1); break;
                case 2: invalid.put("keyCodes",new ArrayValue(92.5)); break;
                case 3: invalid.put("keyCodes",new ArrayValue("92")); break;
                case 4: invalid.put("keyCodes",new ArrayValue(92,92)); break;
                case 5: invalid.put("keyCodes",new ArrayValue(Double.NaN)); break;
                case 6: invalid.put("requestId",NAMESPACE+":1"); break;
                case 7: invalid.put("requestId","d1a05000-0000-4000-8000-000000000003:2"); break;
                case 8: invalid.remove("documentId"); break;
                case 9: invalid.put("keyCodes",new ArrayValue(20)); break;
            }
            manager.setRouteSpec(host,invalid); manager.onAfterUpdateTransaction(host);
            check(data(queue.size()-1).get("disposed").equals(true),"Invalid/reused request terminally revokes old routing variant"+variant);
            check(!host.dispatchKeyEvent(new KeyEvent(0,93,++SystemClock.now,0)),"Invalid props cannot leave old route active");
            manager.onDropViewInstance(host);
        }
        ReaderKeyHostManager manager=new ReaderKeyHostManager(); ReaderKeyHost host=host(manager);
        UIManagerHelper.dispatcher=null;
        manager.setRouteSpec(host,spec(1,"one",true,93)); manager.onAfterUpdateTransaction(host);
        check(!host.requestReaderKeyFocus() && !host.dispatchKeyEvent(new KeyEvent(0,93,++SystemClock.now,0)),"Missing event dispatcher revokes rather than consuming invisibly");
        manager.onDropViewInstance(host);
    }
    private static void defensiveConfig() {
        int[] keys={93,21}; ReaderKeyConfiguration config=new ReaderKeyConfiguration(NAMESPACE+":1","one",keys,true);
        keys[0]=92; int[] copy=config.keyCodes(); copy[0]=92;
        check(Arrays.equals(config.keyCodes(),new int[]{21,93}),"Config validates/clones both ingress and egress key arrays");
        for(String request:new String[]{NAMESPACE+":01",NAMESPACE+":0",NAMESPACE+":9007199254740992","bad:1"}) {
            boolean rejected=false; try { new ReaderKeyConfiguration(request,"one",new int[]{93},true); }
            catch(IllegalArgumentException expected) { rejected=true; }
            check(rejected,"Request namespace/counter invalid case rejected");
        }
    }
    public static void main(String[] args) {
        atomicConfigAndFrozenStream(); malformedAndReplay(); defensiveConfig();
        System.out.println("Reader key atomic RN bridge model: PASS "+assertions+" assertions; actual RN/device delivery NOT TESTED");
    }
}
