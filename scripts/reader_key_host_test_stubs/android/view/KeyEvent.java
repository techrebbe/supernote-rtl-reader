package android.view;
public final class KeyEvent {
    private final int action, key, repeat, device;
    private final long down;
    public KeyEvent(int action, int key, long down, int repeat) { this(action,key,2,down,repeat); }
    public KeyEvent(int action, int key, int device, long down, int repeat) { this.action=action; this.key=key; this.device=device; this.down=down; this.repeat=repeat; }
    public int getAction() { return action; }
    public int getKeyCode() { return key; }
    public int getDeviceId() { return device; }
    public long getDownTime() { return down; }
    public int getRepeatCount() { return repeat; }
}
