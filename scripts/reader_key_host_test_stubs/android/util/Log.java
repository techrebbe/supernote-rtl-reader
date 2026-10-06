package android.util;
import java.util.ArrayList;
import java.util.List;
/** Observation double only; no Android logger or device delivery claim. */
public final class Log {
    public static final List<String> lines = new ArrayList<>();
    public static boolean fail;
    public static int i(String tag, String detail) {
        if (fail) throw new IllegalStateException("diagnostic failure");
        lines.add(tag + " " + detail);
        return 0;
    }
}
