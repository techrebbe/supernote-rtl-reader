import com.techrebbe.supernote.virtualspread.VirtualSpreadNavigationAuthority;

public final class VirtualSpreadNavigationAuthorityTest {
    private static int assertions;

    public static void main(String[] args) throws Exception {
        String structural = VirtualSpreadNavigationAuthority.record(
            0,
            null,
            "שער ראשון",
            true,
            true,
            false,
            new double[] {0.0, 0.0, -0.0},
            null,
            null,
            null,
            null,
            null,
            null
        );
        String destination = VirtualSpreadNavigationAuthority.record(
            1,
            Integer.valueOf(0),
            "תפילת שחרית",
            true,
            false,
            false,
            new double[] {0.0, 0.0, 0.0},
            Integer.valueOf(142),
            Integer.valueOf(71),
            "right",
            "fit-source-page",
            "/FitR",
            new Double[] {432.0, 0.0, 864.0, 648.0}
        );
        String[] records = new String[] {structural, destination};
        assertEquals(
            "cross-language navigation digest",
            "7fbaa18d9b6c14ac6e1d5ea3062dccdb82c4092de9b56150676d19cc9695c172",
            VirtualSpreadNavigationAuthority.digest(records, true, 3, 7)
        );
        assertNotEquals(
            "filter state is authenticated",
            VirtualSpreadNavigationAuthority.digest(records, true, 3, 7),
            VirtualSpreadNavigationAuthority.digest(records, false, 0, 7)
        );
        assertNotEquals(
            "removed count is authenticated",
            VirtualSpreadNavigationAuthority.digest(records, true, 3, 7),
            VirtualSpreadNavigationAuthority.digest(records, true, 4, 7)
        );
        assertNotEquals(
            "retained count is authenticated",
            VirtualSpreadNavigationAuthority.digest(records, true, 3, 7),
            VirtualSpreadNavigationAuthority.digest(records, true, 3, 8)
        );
        assertRejected(
            "removed count requires filter",
            new CheckedAction() {
                @Override
                public void run() throws Exception {
                    VirtualSpreadNavigationAuthority.digest(
                        records, false, 1, 7
                    );
                }
            }
        );
        assertRejected(
            "color outside unit interval",
            new CheckedAction() {
                @Override
                public void run() throws Exception {
                    VirtualSpreadNavigationAuthority.record(
                        0, null, "title", true, false, false,
                        new double[] {1.1, 0.0, 0.0},
                        null, null, null, null, null, null
                    );
                }
            }
        );
        assertRejected(
            "unpaired title surrogate",
            new CheckedAction() {
                @Override
                public void run() throws Exception {
                    VirtualSpreadNavigationAuthority.record(
                        0, null, "bad\uD800", true, false, false,
                        new double[] {0.0, 0.0, 0.0},
                        null, null, null, null, null, null
                    );
                }
            }
        );
        System.out.println(
            "VirtualSpreadNavigationAuthorityTest PASS assertions="
                + assertions
        );
    }

    private static void assertEquals(
        String label,
        String expected,
        String actual
    ) {
        assertions++;
        if (!expected.equals(actual)) {
            throw new AssertionError(
                label + " expected=" + expected + " actual=" + actual
            );
        }
    }

    private static void assertNotEquals(
        String label,
        String first,
        String second
    ) {
        assertions++;
        if (first.equals(second)) {
            throw new AssertionError(label + " values unexpectedly match");
        }
    }

    private static void assertRejected(
        String label,
        CheckedAction action
    ) throws Exception {
        assertions++;
        try {
            action.run();
        } catch (IllegalArgumentException expected) {
            return;
        }
        throw new AssertionError(label + " expected rejection");
    }

    private interface CheckedAction {
        void run() throws Exception;
    }
}
