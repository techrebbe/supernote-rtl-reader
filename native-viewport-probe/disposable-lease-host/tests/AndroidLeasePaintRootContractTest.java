package com.techrebbe.supernote.disposableleasehost;

/** Pure offline checks for the Android root's paint-participant decision. */
public final class AndroidLeasePaintRootContractTest {
    private static int checks;

    private static void check(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }

    public static void main(String[] args) {
        check(AndroidLeasePaintRoot.expectsDrawChild(0), "VISIBLE expected to dispatch");
        check(!AndroidLeasePaintRoot.expectsDrawChild(4), "INVISIBLE remains structural");
        check(!AndroidLeasePaintRoot.expectsDrawChild(8), "GONE remains structural");

        Object[] nine = new Object[9];
        boolean[] expected = new boolean[9];
        Object[] eight = new Object[8];
        for (int i = 0; i < nine.length; i++) {
            nine[i] = new Object();
            expected[i] = i != 7;
            if (i < 7) eight[i] = nine[i];
            else if (i > 7) eight[i - 1] = nine[i];
        }
        check(AndroidLeasePaintRoot.paintParticipantsMatch(nine, expected, eight),
                "nine structural children and eight actual draw calls accepted");

        Object[] missing = eight.clone();
        missing[2] = nine[7];
        check(!AndroidLeasePaintRoot.paintParticipantsMatch(nine, expected, missing),
                "hidden child's unexpected draw cannot replace a visible draw");
        missing[2] = nine[3];
        check(!AndroidLeasePaintRoot.paintParticipantsMatch(nine, expected, missing),
                "duplicate draw cannot conceal a visible omission");
        Object[] seven = new Object[7];
        System.arraycopy(eight, 0, seven, 0, seven.length);
        check(!AndroidLeasePaintRoot.paintParticipantsMatch(nine, expected, seven),
                "visible omission rejected");
        Object[] extra = new Object[9];
        System.arraycopy(eight, 0, extra, 0, eight.length);
        extra[8] = nine[7];
        check(!AndroidLeasePaintRoot.paintParticipantsMatch(nine, expected, extra),
                "extra hidden draw rejected");

        Object owned = new Object();
        Object[] ten = new Object[10];
        boolean[] tenExpected = new boolean[10];
        System.arraycopy(nine, 0, ten, 0, 4);
        ten[4] = owned;
        System.arraycopy(nine, 4, ten, 5, 5);
        for (int i = 0; i < 10; i++) tenExpected[i] = i != 8;
        Object[] nineDraws = new Object[9];
        System.arraycopy(eight, 0, nineDraws, 0, 4);
        nineDraws[4] = owned;
        System.arraycopy(eight, 4, nineDraws, 5, 4);
        check(AndroidLeasePaintRoot.paintParticipantsMatch(ten, tenExpected, nineDraws),
                "owned insertion has ten structural and nine painted children");

        Object[] current = AndroidLeasePaintRoot.snapshotOrder(true, eight);
        check(current.length == 8 && current != eight && current[0] == eight[0],
                "current completed order is copied");
        check(AndroidLeasePaintRoot.snapshotOrder(false, eight).length == 0,
                "post-mutation structural cut cannot borrow stale paint order");
        check(AndroidLeasePaintRoot.snapshotOrder(true, null).length == 0,
                "no completed pass means no paint order");
        System.out.println("ANDROID_LEASE_PAINT_ROOT_CONTRACT PASS checks=" + checks);
    }
}
