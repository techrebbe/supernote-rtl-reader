package android.view;
import android.graphics.Rect;
/** Bounded callback-order model only, NOT Android/HID runtime evidence. */
public class View {
    public boolean frameworkAttached=true, windowFocused=true, focused=false, shown=true;
    public int delegated;
    public View otherFocus;
    public int getId() { return 42; }
    public boolean isAttachedToWindow() { return frameworkAttached; }
    public boolean hasWindowFocus() { return windowFocused; }
    public boolean isFocused() { return focused; }
    public boolean isShown() { return shown; }
    public void setFocusable(boolean value) {}
    public void setFocusableInTouchMode(boolean value) {}
    public View getRootView() { return this; }
    public View findFocus() { return otherFocus != null ? otherFocus : focused ? this : null; }
    public boolean requestFocus() { focused=true; onFocusChanged(true,0,null); return true; }
    public void clearFocus() { focused=false; onFocusChanged(false,0,null); }
    public boolean dispatchKeyEvent(KeyEvent event) { delegated++; return false; }
    protected void onAttachedToWindow() {}
    // Deliberately leave frameworkAttached TRUE through the whole callback:
    // the actual framework clears attachment information AFTER it returns.
    protected void onDetachedFromWindow() {}
    public void onWindowFocusChanged(boolean value) {}
    protected void onFocusChanged(boolean value,int direction,Rect rect) {}
    protected void onVisibilityChanged(View changed,int visibility) {}
}
