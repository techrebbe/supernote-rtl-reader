import com.techrebbe.supernote.virtualspread.VirtualSpreadNavigation;
import com.techrebbe.supernote.virtualspread.VirtualSpreadNavigation.Half;
import com.techrebbe.supernote.virtualspread.VirtualSpreadNavigation.Kind;
import com.techrebbe.supernote.virtualspread.VirtualSpreadNavigation.PageBarState;
import com.techrebbe.supernote.virtualspread.VirtualSpreadNavigation.Plan;
import com.techrebbe.supernote.virtualspread.VirtualSpreadNavigation.Spread;

public final class VirtualSpreadNavigationExhaustiveTest {
    private static int assertions;

    public static void main(String[] args) {
        for (int pageCount = 1; pageCount <= 5; pageCount++) {
            int combinations = 1;
            for (int index = 0; index < pageCount; index++) {
                combinations *= 3;
            }
            for (int encoded = 0; encoded < combinations; encoded++) {
                checkLayout(pageCount, encoded);
            }
        }
        System.out.println(
            "VirtualSpreadNavigationExhaustiveTest PASS assertions="
                + assertions
        );
    }

    private static void checkLayout(int pageCount, int encoded) {
        Spread[] spreads = new Spread[pageCount];
        int value = encoded;
        int positionCount = 0;
        for (int page = 0; page < pageCount; page++) {
            int mask = (value % 3) + 1;
            value /= 3;
            spreads[page] = new Spread(
                (mask & 1) != 0,
                (mask & 2) != 0
            );
            positionCount += spreads[page].hasLeft ? 1 : 0;
            positionCount += spreads[page].hasRight ? 1 : 0;
        }

        int[] pages = new int[positionCount];
        Half[] halves = new Half[positionCount];
        int cursor = 0;
        for (int page = 0; page < pageCount; page++) {
            if (spreads[page].hasRight) {
                pages[cursor] = page;
                halves[cursor++] = Half.RIGHT;
            }
            if (spreads[page].hasLeft) {
                pages[cursor] = page;
                halves[cursor++] = Half.LEFT;
            }
        }

        for (int position = 0; position < positionCount; position++) {
            assertAdjacent(
                spreads, pages, halves, position, -1, position + 1
            );
            assertAdjacent(
                spreads, pages, halves, position, 1, position - 1
            );
        }
    }

    private static void assertAdjacent(
        Spread[] spreads,
        int[] pages,
        Half[] halves,
        int current,
        int offset,
        int expected
    ) {
        Plan actual = VirtualSpreadNavigation.planPortrait(
            spreads,
            pages[current],
            halves[current],
            offset
        );
        if (expected < 0 || expected >= pages.length) {
            if (actual.kind != Kind.BOUNDARY
                || actual.targetPage != pages[current]
                || actual.targetHalf != halves[current]) {
                throw new AssertionError("boundary mismatch");
            }
        } else {
            Kind expectedKind = pages[expected] == pages[current]
                ? Kind.SAME_SPREAD : Kind.OTHER_SPREAD;
            if (actual.kind != expectedKind
                || actual.targetPage != pages[expected]
                || actual.targetHalf != halves[expected]) {
                throw new AssertionError("adjacency mismatch");
            }
        }
        assertions++;

        PageBarState buttons = VirtualSpreadNavigation.pageBarState(
            spreads,
            pages[current],
            halves[current],
            true
        );
        boolean expectedPrevious = current + 1 < pages.length;
        boolean expectedNext = current > 0;
        if (buttons.previousEnabled != expectedPrevious
            || buttons.nextEnabled != expectedNext) {
            throw new AssertionError("page-bar state mismatch");
        }
        assertions++;
    }
}
