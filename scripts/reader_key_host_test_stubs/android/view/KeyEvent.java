package android.view;
public final class KeyEvent {
    private final int action, key, repeat;
    private final long down;
    public KeyEvent(int action, int key, long down, int repeat) { this.action=action; this.key=key; this.down=down; this.repeat=repeat; }
    public int getAction() { return action; }
    public int getKeyCode() { return key; }
    public int getDeviceId() { return 2; }
    public long getDownTime() { return down; }
    public int getRepeatCount() { return repeat; }
}
