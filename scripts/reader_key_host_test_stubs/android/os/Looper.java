package android.os;
public final class Looper {
    private static final Thread OWNER = Thread.currentThread();
    private static final Looper MAIN = new Looper();
    public static Looper myLooper() { return Thread.currentThread() == OWNER ? MAIN : null; }
    public static Looper getMainLooper() { return MAIN; }
}
