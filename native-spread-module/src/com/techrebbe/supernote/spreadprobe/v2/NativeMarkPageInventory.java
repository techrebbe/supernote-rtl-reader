package com.techrebbe.supernote.spreadprobe.v2;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Strictly classifies one page against the native one-based mark inventory. */
public final class NativeMarkPageInventory {
    private NativeMarkPageInventory() {}

    public static boolean contains(
        List<?> nativePages,
        int pageCount,
        int zeroBasedPage
    ) {
        if (nativePages == null) {
            throw new IllegalArgumentException("mark page inventory is missing");
        }
        if (pageCount <= 0 || zeroBasedPage < 0 || zeroBasedPage >= pageCount) {
            throw new IllegalArgumentException("requested mark page is invalid");
        }
        int requested = zeroBasedPage + 1;
        boolean present = false;
        Set<Integer> unique = new HashSet<>();
        for (Object raw : nativePages) {
            if (!(raw instanceof Integer)) {
                throw new IllegalArgumentException(
                    "mark page inventory contains a non-integer"
                );
            }
            Integer boxed = (Integer) raw;
            int page = boxed.intValue();
            if (page <= 0 || page > pageCount) {
                throw new IllegalArgumentException(
                    "mark page inventory contains an out-of-range page"
                );
            }
            if (!unique.add(boxed)) {
                throw new IllegalArgumentException(
                    "mark page inventory contains a duplicate page"
                );
            }
            present |= page == requested;
        }
        return present;
    }
}
