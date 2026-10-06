package t014;
import android.os.SystemClock;
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
    public static void main(String[] args) {
        callbacksFailClosed(); lifecycleAbaAndFocus(); offReleasesFocus();
        System.out.println("Reader key Host callback model: PASS "+assertions+" assertions; actual device delivery NOT TESTED");
    }
}
