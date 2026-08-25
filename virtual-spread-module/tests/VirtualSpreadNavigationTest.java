import com.techrebbe.supernote.virtualspread.VirtualSpreadNavigation;
import com.techrebbe.supernote.virtualspread.VirtualSpreadNavigation.Half;
import com.techrebbe.supernote.virtualspread.VirtualSpreadNavigation.Kind;
import com.techrebbe.supernote.virtualspread.VirtualSpreadNavigation.LinkHistory;
import com.techrebbe.supernote.virtualspread.VirtualSpreadNavigation.LinkTarget;
import com.techrebbe.supernote.virtualspread.VirtualSpreadNavigation.LinkVisit;
import com.techrebbe.supernote.virtualspread.VirtualSpreadNavigation.PageBarState;
import com.techrebbe.supernote.virtualspread.VirtualSpreadNavigation.Plan;
import com.techrebbe.supernote.virtualspread.VirtualSpreadNavigation.Spread;

public final class VirtualSpreadNavigationTest {
    private static int assertions;

    public static void main(String[] args) {
        Spread[] coverBook = new Spread[] {
            new Spread(false, true),
            new Spread(true, true),
            new Spread(true, true),
            new Spread(true, true)
        };

        assertPlan(
            "cover skips virtual blank",
            VirtualSpreadNavigation.planPortrait(
                coverBook, 0, Half.RIGHT, -1
            ),
            Kind.OTHER_SPREAD, 1, Half.RIGHT
        );
        assertPlan(
            "right advances to left on same spread",
            VirtualSpreadNavigation.planPortrait(
                coverBook, 1, Half.RIGHT, -1
            ),
            Kind.SAME_SPREAD, 1, Half.LEFT
        );
        assertPlan(
            "left advances to next spread right",
            VirtualSpreadNavigation.planPortrait(
                coverBook, 1, Half.LEFT, -1
            ),
            Kind.OTHER_SPREAD, 2, Half.RIGHT
        );
        assertPlan(
            "right goes back to previous spread left",
            VirtualSpreadNavigation.planPortrait(
                coverBook, 2, Half.RIGHT, 1
            ),
            Kind.OTHER_SPREAD, 1, Half.LEFT
        );
        assertPlan(
            "left goes back to right on same spread",
            VirtualSpreadNavigation.planPortrait(
                coverBook, 1, Half.LEFT, 1
            ),
            Kind.SAME_SPREAD, 1, Half.RIGHT
        );
        assertPlan(
            "start boundary",
            VirtualSpreadNavigation.planPortrait(
                coverBook, 0, Half.RIGHT, 1
            ),
            Kind.BOUNDARY, 0, Half.RIGHT
        );
        assertPlan(
            "end boundary",
            VirtualSpreadNavigation.planPortrait(
                coverBook, 3, Half.LEFT, -1
            ),
            Kind.BOUNDARY, 3, Half.LEFT
        );

        Spread[] partialLast = new Spread[] {
            new Spread(true, true),
            new Spread(false, true)
        };
        assertPlan(
            "partial last spread chooses right",
            VirtualSpreadNavigation.planPortrait(
                partialLast, 0, Half.LEFT, -1
            ),
            Kind.OTHER_SPREAD, 1, Half.RIGHT
        );
        assertPlan(
            "partial last spread has forward boundary",
            VirtualSpreadNavigation.planPortrait(
                partialLast, 1, Half.RIGHT, -1
            ),
            Kind.BOUNDARY, 1, Half.RIGHT
        );
        assertEquals(
            "landscape rightward gesture advances",
            1,
            VirtualSpreadNavigation.reverseLandscapeOffset(-1)
        );
        assertEquals(
            "landscape leftward gesture goes back",
            -1,
            VirtualSpreadNavigation.reverseLandscapeOffset(1)
        );
        assertPageBar(
            "landscape start",
            VirtualSpreadNavigation.pageBarState(
                coverBook, 0, Half.RIGHT, false
            ),
            true,
            false
        );
        assertPageBar(
            "landscape end",
            VirtualSpreadNavigation.pageBarState(
                coverBook, 3, Half.LEFT, false
            ),
            false,
            true
        );
        assertPageBar(
            "portrait cover start",
            VirtualSpreadNavigation.pageBarState(
                coverBook, 0, Half.RIGHT, true
            ),
            true,
            false
        );
        assertPageBar(
            "portrait middle has both directions",
            VirtualSpreadNavigation.pageBarState(
                coverBook, 1, Half.RIGHT, true
            ),
            true,
            true
        );
        assertPageBar(
            "portrait final half",
            VirtualSpreadNavigation.pageBarState(
                coverBook, 3, Half.LEFT, true
            ),
            false,
            true
        );
        assertBoolean(
            "normal runtime geometry is representable",
            true,
            VirtualSpreadNavigation.runtimeGeometryIsRepresentable(
                864.0, 648.0, 0.0
            )
        );
        assertBoolean(
            "overflowing runtime geometry fails closed",
            false,
            VirtualSpreadNavigation.runtimeGeometryIsRepresentable(
                864.0, 1e40, 0.0
            )
        );
        assertBoolean(
            "underflowing runtime geometry fails closed",
            false,
            VirtualSpreadNavigation.runtimeGeometryIsRepresentable(
                864.0, 1e-50, 0.0
            )
        );
        assertBoolean(
            "positive gutter cannot collapse to zero",
            false,
            VirtualSpreadNavigation.runtimeGeometryIsRepresentable(
                864.0, 648.0, 1e-50
            )
        );
        assertBoolean(
            "slot width cannot collapse to zero",
            false,
            VirtualSpreadNavigation.runtimeGeometryIsRepresentable(
                2e-40, 1.0, 1.999999999e-40
            )
        );
        assertBoolean(
            "runtime width and gutter cannot collapse together",
            false,
            VirtualSpreadNavigation.runtimeGeometryIsRepresentable(
                1.0, 1.0, 1.0 - 1e-16
            )
        );
        assertBoolean(
            "runtime slot arithmetic rounds after every float operation",
            false,
            VirtualSpreadNavigation.runtimeGeometryIsRepresentable(
                2.49 * Math.scalb(1.0, -149),
                1.0,
                0.51 * Math.scalb(1.0, -149)
            )
        );
        assertBoolean(
            "normal runtime link rectangle is representable",
            true,
            VirtualSpreadNavigation.runtimeRectIsRepresentable(
                648.0, 10.0, 20.0, 100.0, 50.0
            )
        );
        assertBoolean(
            "overflowing runtime link rectangle fails closed",
            false,
            VirtualSpreadNavigation.runtimeRectIsRepresentable(
                648.0, 10.0, 20.0, 1e40, 50.0
            )
        );
        assertBoolean(
            "collapsing runtime link rectangle fails closed",
            false,
            VirtualSpreadNavigation.runtimeRectIsRepresentable(
                648.0, 1e-50, 20.0, 2e-50, 50.0
            )
        );
        assertBoolean(
            "zero-width runtime link rectangle fails closed",
            false,
            VirtualSpreadNavigation.runtimeRectIsRepresentable(
                648.0, 10.0, 20.0, 10.0, 50.0
            )
        );
        assertBoolean(
            "zero-height runtime link rectangle fails closed",
            false,
            VirtualSpreadNavigation.runtimeRectIsRepresentable(
                648.0, 10.0, 20.0, 100.0, 20.0
            )
        );
        assertBoolean(
            "tall-page link retains top-down float ordering",
            true,
            VirtualSpreadNavigation.runtimeRectIsRepresentable(
                Math.scalb(1.0, 27), 0.0, 10.0, 100.0, 20.0
            )
        );
        assertBoolean(
            "tall-page link collapsing top-down fails closed",
            false,
            VirtualSpreadNavigation.runtimeRectIsRepresentable(
                Math.scalb(1.0, 27), 0.0, 10.0, 100.0, 11.0
            )
        );

        LinkTarget[] linkTargets = new LinkTarget[] {
            new LinkTarget(
                1,
                3,
                Half.RIGHT,
                Half.RIGHT,
                486.0f,
                60.0f,
                810.0f,
                102.0f
            ),
            new LinkTarget(
                1,
                3,
                Half.RIGHT,
                Half.LEFT,
                486.0f,
                120.0f,
                810.0f,
                162.0f
            )
        };
        LinkTarget fitLinkTarget = new LinkTarget(
            1,
            3,
            Half.RIGHT,
            Half.LEFT,
            true,
            10.0f,
            20.0f,
            30.0f,
            40.0f
        );
        assertBoolean(
            "Fit link retains authenticated landscape reset",
            true,
            fitLinkTarget.resetLandscapeFit
        );
        assertBoolean(
            "ordinary link defaults to preserving destination view",
            false,
            linkTargets[0].resetLandscapeFit
        );
        assertHalf(
            "right link target",
            Half.RIGHT,
            VirtualSpreadNavigation.matchLinkTarget(
                linkTargets,
                1,
                3,
                486.0f,
                546.0f,
                810.0f,
                588.0f,
                648.0f,
                0.5f
            )
        );
        assertHalf(
            "left link target with native rounding",
            Half.LEFT,
            VirtualSpreadNavigation.matchLinkTarget(
                linkTargets,
                1,
                3,
                486.4f,
                485.7f,
                810.2f,
                528.3f,
                648.0f,
                0.5f
            )
        );
        assertHalf(
            "unmatched link fails closed",
            null,
            VirtualSpreadNavigation.matchLinkTarget(
                linkTargets,
                1,
                3,
                480.0f,
                546.0f,
                810.0f,
                588.0f,
                648.0f,
                0.5f
            )
        );
        LinkTarget[] observedFixtureTarget = new LinkTarget[] {
            new LinkTarget(
                1,
                3,
                Half.RIGHT,
                Half.LEFT,
                502.2f,
                59.4f,
                680.4f,
                100.44f
            )
        };
        assertHalf(
            "MuPDF top-left bounds normalize to manifest coordinates",
            Half.LEFT,
            VirtualSpreadNavigation.matchLinkTarget(
                observedFixtureTarget,
                1,
                3,
                502.2f,
                547.56f,
                680.4f,
                588.6f,
                648.0f,
                0.01f
            )
        );
        float tallPageHeight = Math.scalb(1.0f, 27);
        LinkTarget[] tallPageTargets = new LinkTarget[] {
            new LinkTarget(
                1,
                3,
                Half.RIGHT,
                Half.LEFT,
                10.0f,
                10.0f,
                100.0f,
                20.0f
            )
        };
        assertHalf(
            "tall-page link matches directly in top-down coordinates",
            Half.LEFT,
            VirtualSpreadNavigation.matchLinkTarget(
                tallPageTargets,
                1,
                3,
                10.0f,
                tallPageHeight - 20.0f,
                100.0f,
                tallPageHeight - 10.0f,
                tallPageHeight,
                2.0f
            )
        );
        assertHalf(
            "non-finite tolerance fails closed",
            null,
            VirtualSpreadNavigation.matchLinkTarget(
                linkTargets,
                1,
                3,
                486.0f,
                546.0f,
                810.0f,
                588.0f,
                648.0f,
                Float.NaN
            )
        );
        assertHalf(
            "non-finite manifest target fails closed",
            null,
            VirtualSpreadNavigation.matchLinkTarget(
                new LinkTarget[] {
                    new LinkTarget(
                        1, 3, Half.RIGHT, Half.LEFT,
                        10.0f, Float.NaN, 100.0f, 20.0f
                    )
                },
                1,
                3,
                10.0f,
                628.0f,
                100.0f,
                638.0f,
                648.0f,
                2.0f
            )
        );
        assertHalf(
            "non-finite bounds fail closed",
            null,
            VirtualSpreadNavigation.matchLinkTarget(
                linkTargets,
                1,
                3,
                Float.NaN,
                60.0f,
                810.0f,
                588.0f,
                648.0f,
                0.5f
            )
        );
        assertHalf(
            "invalid page height fails closed",
            null,
            VirtualSpreadNavigation.matchLinkTarget(
                linkTargets,
                1,
                3,
                486.0f,
                546.0f,
                810.0f,
                588.0f,
                Float.NaN,
                0.5f
            )
        );
        assertHalf(
            "zero-area observed link fails closed",
            null,
            VirtualSpreadNavigation.matchLinkTarget(
                linkTargets,
                1,
                3,
                486.0f,
                546.0f,
                486.0f,
                588.0f,
                648.0f,
                400.0f
            )
        );
        assertHalf(
            "zero-area manifest target fails closed",
            null,
            VirtualSpreadNavigation.matchLinkTarget(
                new LinkTarget[] {
                    new LinkTarget(
                        1, 3, Half.RIGHT, Half.LEFT,
                        10.0f, 20.0f, 10.0f, 50.0f
                    )
                },
                1, 3, 9.0f, 598.0f, 11.0f, 628.0f, 648.0f, 2.0f
            )
        );
        LinkTarget[] conflictingTargetViews = new LinkTarget[] {
            new LinkTarget(
                1, 3, Half.RIGHT, Half.LEFT, false,
                10.0f, 20.0f, 30.0f, 40.0f
            ),
            new LinkTarget(
                1, 3, Half.RIGHT, Half.LEFT, true,
                10.25f, 20.25f, 30.25f, 40.25f
            )
        };
        assertHalf(
            "indistinguishable conflicting target views fail closed",
            null,
            VirtualSpreadNavigation.matchLinkTarget(
                conflictingTargetViews,
                1, 3, 10.0f, 608.0f, 30.0f, 628.0f, 648.0f, 0.5f
            )
        );
        LinkTarget[] duplicateFitTargetViews = new LinkTarget[] {
            new LinkTarget(
                1, 3, Half.RIGHT, Half.LEFT, true,
                10.0f, 20.0f, 30.0f, 40.0f
            ),
            new LinkTarget(
                1, 3, Half.RIGHT, Half.LEFT, true,
                10.25f, 20.25f, 30.25f, 40.25f
            )
        };
        assertHalf(
            "indistinguishable matching target views remain deterministic",
            Half.LEFT,
            VirtualSpreadNavigation.matchLinkTarget(
                duplicateFitTargetViews,
                1, 3, 10.0f, 608.0f, 30.0f, 628.0f, 648.0f, 0.5f
            )
        );
        assertHalf(
            "native history source half inferred",
            Half.RIGHT,
            VirtualSpreadNavigation.inferLinkSourceHalf(
                linkTargets,
                1,
                3
            )
        );
        LinkTarget[] ambiguousHistoryTargets = new LinkTarget[] {
            new LinkTarget(
                1,
                3,
                Half.LEFT,
                Half.RIGHT,
                10.0f,
                10.0f,
                20.0f,
                20.0f
            ),
            new LinkTarget(
                1,
                3,
                Half.RIGHT,
                Half.LEFT,
                500.0f,
                10.0f,
                510.0f,
                20.0f
            )
        };
        assertHalf(
            "ambiguous native history source fails closed",
            null,
            VirtualSpreadNavigation.inferLinkSourceHalf(
                ambiguousHistoryTargets,
                1,
                3
            )
        );

        String sourceAuthority =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        String layoutAuthority =
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        String linkAuthority =
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        assertBoolean(
            "matching native document authorities are accepted",
            true,
            VirtualSpreadNavigation.manifestMatchesNativeSnapshot(
                sourceAuthority,
                layoutAuthority,
                linkAuthority,
                sourceAuthority.toUpperCase(),
                layoutAuthority,
                linkAuthority
            )
        );
        assertBoolean(
            "replaced native source fails closed",
            false,
            VirtualSpreadNavigation.manifestMatchesNativeSnapshot(
                sourceAuthority,
                layoutAuthority,
                linkAuthority,
                linkAuthority,
                layoutAuthority,
                linkAuthority
            )
        );
        assertBoolean(
            "stale native layout fails closed",
            false,
            VirtualSpreadNavigation.manifestMatchesNativeSnapshot(
                sourceAuthority,
                layoutAuthority,
                linkAuthority,
                sourceAuthority,
                linkAuthority,
                linkAuthority
            )
        );
        assertBoolean(
            "stale native links fail closed",
            false,
            VirtualSpreadNavigation.manifestMatchesNativeSnapshot(
                sourceAuthority,
                layoutAuthority,
                linkAuthority,
                sourceAuthority,
                layoutAuthority,
                sourceAuthority
            )
        );
        assertBoolean(
            "missing native authority fails closed",
            false,
            VirtualSpreadNavigation.manifestMatchesNativeSnapshot(
                sourceAuthority,
                layoutAuthority,
                linkAuthority,
                null,
                layoutAuthority,
                linkAuthority
            )
        );

        LinkHistory history = new LinkHistory();
        history.record(1, Half.RIGHT, 3);
        history.record(3, Half.LEFT, 1);
        assertEquals("history records two visits", 2, history.size());
        assertVisit(
            "Back restores latest link source",
            history.takeBack(3, 1),
            3,
            Half.LEFT,
            1
        );
        assertEquals("Back consumes one visit", 1, history.size());
        assertVisit(
            "Original Back restores oldest link source",
            history.takeOriginal(1, 3),
            1,
            Half.RIGHT,
            3
        );
        assertEquals("Original Back clears history", 0, history.size());

        history.record(1, Half.RIGHT, 3);
        assertVisit(
            "mismatched native history fails closed",
            history.takeBack(2, 3),
            -1,
            null,
            -1
        );
        assertEquals("mismatch clears stale mirror", 0, history.size());
        history.record(-1, Half.RIGHT, 3);
        history.record(1, null, 3);
        assertEquals("invalid visits are ignored", 0, history.size());
        System.out.println(
            "VirtualSpreadNavigationTest PASS assertions=" + assertions
        );
    }

    private static void assertPlan(
        String name,
        Plan actual,
        Kind kind,
        int page,
        Half half
    ) {
        if (actual.kind != kind
            || actual.targetPage != page
            || actual.targetHalf != half) {
            throw new AssertionError(
                name + ": expected " + kind + " " + page + " " + half
                    + " but got " + actual.kind + " "
                    + actual.targetPage + " " + actual.targetHalf
            );
        }
        assertions++;
    }

    private static void assertEquals(
        String name,
        int expected,
        int actual
    ) {
        if (expected != actual) {
            throw new AssertionError(
                name + ": expected " + expected + " but got " + actual
            );
        }
        assertions++;
    }

    private static void assertPageBar(
        String name,
        PageBarState actual,
        boolean previousEnabled,
        boolean nextEnabled
    ) {
        if (actual.previousEnabled != previousEnabled
            || actual.nextEnabled != nextEnabled) {
            throw new AssertionError(
                name + ": expected previous=" + previousEnabled
                    + " next=" + nextEnabled
                    + " but got previous=" + actual.previousEnabled
                    + " next=" + actual.nextEnabled
            );
        }
        assertions++;
    }

    private static void assertBoolean(
        String name,
        boolean expected,
        boolean actual
    ) {
        if (expected != actual) {
            throw new AssertionError(
                name + ": expected " + expected + " but got " + actual
            );
        }
        assertions++;
    }

    private static void assertHalf(
        String name,
        Half expected,
        Half actual
    ) {
        if (actual != expected) {
            throw new AssertionError(
                name + ": expected " + expected + " but got " + actual
            );
        }
        assertions++;
    }

    private static void assertVisit(
        String name,
        LinkVisit actual,
        int sourcePage,
        Half sourceHalf,
        int targetPage
    ) {
        if (sourceHalf == null) {
            if (actual != null) {
                throw new AssertionError(name + ": expected null visit");
            }
        } else if (actual == null
            || actual.sourcePage != sourcePage
            || actual.sourceHalf != sourceHalf
            || actual.targetPage != targetPage) {
            throw new AssertionError(
                name + ": expected " + sourcePage + " " + sourceHalf
                    + " -> " + targetPage + " but got "
                    + (actual == null ? "null" : actual.sourcePage + " "
                        + actual.sourceHalf + " -> " + actual.targetPage)
            );
        }
        assertions++;
    }
}
