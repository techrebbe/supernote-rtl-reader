package t014;
import android.os.SystemClock;
import android.util.Log;
import android.view.KeyEvent;
import android.view.View;
import com.facebook.react.uimanager.ThemedReactContext;

/** Execute ACTUAL Host source with narrow callback-order doubles.
 * This does not establish native focus ownership, RN event delivery or HID.
 */
public final class ReaderKeyHostTests {
    private static int assertions;
    private static void check(boolean value,String why) { assertions++; if(!value) throw new AssertionError(why); }
    private static final class Sink implements ReaderKeyHost.Sink {
        boolean failState, failKey, failTerminal;
        int keys;
        ReaderKeyRouteCore.State latest;
        public void state(ReaderKeyRouteCore.State state) {
            latest=state;
            if (failState || (failTerminal && state.disposed)) throw new IllegalStateException("state failure");
        }
        public void key(ReaderKeyRouteCore.Packet packet) { keys++; if(failKey) throw new IllegalStateException("key failure"); }
    }
    private static ReaderKeyHost host(Sink sink) {
        SystemClock.now+=10;
        ReaderKeyHost host=new ReaderKeyHost(new ThemedReactContext());
        host.onAttachedToWindow();
        host.configure("document-one",new int[]{93},true,sink);
        SystemClock.now++;
        check(host.requestReaderKeyFocus(),"Bound current route can request unclaimed focus");
        return host;
    }
    private static void callbacksFailClosed() {
        Sink sink=new Sink(); sink.failState=true;
        ReaderKeyHost host=new ReaderKeyHost(new ThemedReactContext());
        host.onAttachedToWindow();
        host.configure("doc",new int[]{93},true,sink);
        check(sink.latest.disposed,"Failed configuration publication terminally revokes");
        check(!host.requestReaderKeyFocus(),"Failed Sink cannot acquire focus");
        check(!host.dispatchKeyEvent(new KeyEvent(0,93,++SystemClock.now,0)),"Failed Sink cannot consume key");
        boolean rejected=false;
        try { host.configure("doc",new int[]{93},true,new Sink()); } catch(IllegalStateException expected) { rejected=true; }
        check(rejected,"Dropped host cannot rearm");
        sink=new Sink(); host=host(sink);
        ReaderKeyRouteCore.State before=sink.latest;
        sink.failState=true;
        host.windowFocused=false; SystemClock.now++;
        host.onWindowFocusChanged(false);
        check(sink.latest.disposed && !host.validate(before),"Lifecycle state failure revokes and does not escape");
        sink=new Sink(); host=host(sink);
        sink.failKey=true; sink.failTerminal=true;
        check(host.dispatchKeyEvent(new KeyEvent(0,93,++SystemClock.now,0)),"Key plus terminal-state failure remains consumed");
        check(sink.latest.disposed && sink.keys==1,"Key failure delivers once and releases Sink");
        check(!host.dispatchKeyEvent(new KeyEvent(0,93,++SystemClock.now,0)),"No later key survives terminal failure");
        host.drop();
    }
    private static void lifecycleAbaAndFocus() {
        Sink sink=new Sink(); ReaderKeyHost host=host(sink);
        ReaderKeyRouteCore.State before=sink.latest;
        check(before.eligible && host.validate(before),"Initial native stamps current");
        SystemClock.now++;
        host.onDetachedFromWindow(); // frameworkAttached deliberately still TRUE
        check(!sink.latest.eligible && sink.latest.generation>before.generation,"Detach explicitly fences before framework attachment clears");
        check(!host.validate(before),"Immediate detach validation rejects old packet");
        check(!host.requestReaderKeyFocus(),"Cannot refocus during incomplete outer detach");
        SystemClock.now++;
        host.onAttachedToWindow();
        check(sink.latest.eligible && sink.latest.generation>before.generation,"Reattach creates distinct authority even with identical live flags");
        check(!host.validate(before),"Attachment ABA never revives old packet");
        long down=++SystemClock.now;
        check(host.dispatchKeyEvent(new KeyEvent(0,93,down,0)),"Fresh contact handled");
        check(host.dispatchKeyEvent(new KeyEvent(0,93,down,256)),"Native long hold ownership retained");
        check(host.dispatchKeyEvent(new KeyEvent(0,93,down,Integer.MAX_VALUE)),"Maximum-int hold retained");
        check(sink.keys==1 && host.delegated==0,"Neither repeat turns or falls through");
        check(host.dispatchKeyEvent(new KeyEvent(1,93,down,0)),"Exact UP completes owned contact");
        host.clearFocus();
        check(!host.dispatchKeyEvent(new KeyEvent(0,93,++SystemClock.now,0)),"No route when a child/other control owns focus");
        host.otherFocus=new View();
        check(!host.requestReaderKeyFocus(),"Do not steal focus from another control");
        host.otherFocus=null;
        host.configure("doc",new int[]{93},false,sink);
        check(!host.requestReaderKeyFocus(),"Disabled route cannot request focus");
        host.drop();
    }
    private static void offReleasesFocus() {
        Sink sink=new Sink();
        ReaderKeyHost fresh=new ReaderKeyHost(new ThemedReactContext());
        check(!fresh.focusable && !fresh.focusableInTouchMode,"Unconfigured host is non-focusable");
        check(!fresh.requestFocus(),"Unconfigured ordinary framework request cannot focus");
        ReaderKeyHost host=host(sink);
        long generation=sink.latest.generation;
        host.configure("document-one",new int[]{93},false,sink);
        check(!host.focusable && !host.focusableInTouchMode && !host.focused,"OFF releases focus and cannot capture controls");
        check(!sink.latest.eligible && sink.latest.generation>generation,"OFF leaves the latest published generation inactive");
        check(!host.dispatchKeyEvent(new KeyEvent(0,93,++SystemClock.now,0)),"OFF delegates ordinary key");
        host.configure("document-one",new int[]{93},true,sink);
        check(host.focusable && !host.focused,"ON does not automatically steal focus");
        host.drop();
        check(!host.focusable && !host.focusableInTouchMode,"Drop leaves no focus target");
    }
    private static void diagnosticBoundary() {
        Log.lines.clear();
        Sink sink=new Sink(); ReaderKeyHost host=host(sink);
        long down=++SystemClock.now;
        check(host.dispatchKeyEvent(new KeyEvent(0,93,-1,down,0)),"ADB virtual keyboard accepted by actual Host");
        check(Log.lines.stream().anyMatch(line -> line.contains("device=-1") && line.contains("result=pressed") && line.contains("packet=true")),"Native arrival/decision witnessed");
        check(sink.keys==1,"Diagnostics do not add delivery");
        check(host.dispatchKeyEvent(new KeyEvent(1,93,-1,down,0)),"Exact virtual-keyboard UP handled");
        int count=Log.lines.size();
        host.dispatchKeyEvent(new KeyEvent(0,29,-1,++SystemClock.now,0));
        check(Log.lines.size()==count,"Unrelated text keys are not logged");
        Log.fail=true;
        check(host.dispatchKeyEvent(new KeyEvent(0,93,-1,++SystemClock.now,0)),"Logger failure cannot block dispatch");
        check(sink.keys==3 && sink.latest.eligible,"Logger failure cannot revoke authority");
        Log.fail=false;
        for(int index=0;index<200;index++) host.dispatchKeyEvent(new KeyEvent(0,93,-1,++SystemClock.now,0));
        check(sink.keys==203,"Observation saturation does not stop fresh contacts");
        check(Log.lines.size()<=128,"Native diagnostics bounded per Host");
        host.clearFocus(); count=Log.lines.size();
        check(!host.dispatchKeyEvent(new KeyEvent(0,93,-1,++SystemClock.now,0)),"Saturated diagnostics do not change focus bypass");
        check(Log.lines.size()==count,"Saturation stays bounded");
        host.drop();
        Log.lines.clear(); sink=new Sink(); host=host(sink); host.clearFocus();
        check(!host.dispatchKeyEvent(new KeyEvent(0,93,-1,++SystemClock.now,0)),"Unfocused candidate bypasses");
        check(Log.lines.stream().anyMatch(line -> line.contains("result=bypass focused=false")),"Unfocused native boundary distinguishable");
        host.drop();
    }
    private static void verticalDiagnostics() {
        Log.lines.clear();
        Sink sink=new Sink(); ReaderKeyHost host=host(sink);
        host.configure("vertical",new int[]{19,20},true,sink);
        for(int key:new int[]{19,20}) {
            long down=++SystemClock.now;
            check(host.dispatchKeyEvent(new KeyEvent(0,key,3,down,0)),"Configured vertical key is accepted");
            check(Log.lines.stream().anyMatch(line -> line.contains("dispatch key="+key+" action=0") &&
                    line.contains("result=pressed") && line.contains("packet=true")),"Vertical Android dispatch is observable");
            check(host.dispatchKeyEvent(new KeyEvent(1,key,3,down,0)),"Vertical UP closes contact");
        }
        host.clearFocus();
        check(!host.dispatchKeyEvent(new KeyEvent(0,20,3,++SystemClock.now,0)),"Unfocused vertical input delegates");
        check(Log.lines.stream().anyMatch(line -> line.contains("dispatch key=20") && line.contains("result=bypass focused=false")),
                "Vertical bypass is distinguishable from absent upstream input");
        host.drop();
    }
    public static void main(String[] args) {
        callbacksFailClosed(); lifecycleAbaAndFocus(); offReleasesFocus(); diagnosticBoundary(); verticalDiagnostics();
        System.out.println("Reader key Host callback model: PASS "+assertions+" assertions; actual device delivery NOT TESTED");
    }
}
