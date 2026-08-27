import com.techrebbe.supernote.virtualspread.VirtualSpreadNavigation;
import com.techrebbe.supernote.virtualspread.VirtualSpreadNavigation.BoundedCache;
import com.techrebbe.supernote.virtualspread.VirtualSpreadNavigation.Half;
import com.techrebbe.supernote.virtualspread.VirtualSpreadNavigation.Kind;
import com.techrebbe.supernote.virtualspread.VirtualSpreadNavigation.LinkHistory;
import com.techrebbe.supernote.virtualspread.VirtualSpreadNavigation.LinkRouting;
import com.techrebbe.supernote.virtualspread.VirtualSpreadNavigation.LinkTarget;
import com.techrebbe.supernote.virtualspread.VirtualSpreadNavigation.LinkVisit;
import com.techrebbe.supernote.virtualspread.VirtualSpreadNavigation.PageBarState;
import com.techrebbe.supernote.virtualspread.VirtualSpreadNavigation.Plan;
import com.techrebbe.supernote.virtualspread.VirtualSpreadNavigation.Spread;
import com.techrebbe.supernote.virtualspread.VirtualSpreadNavigation.UriTarget;

import java.nio.charset.StandardCharsets;

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
        assertLinkRouting(
            "annotation callback bypasses link routing",
            LinkRouting.NON_LINK,
            VirtualSpreadNavigation.classifyLinkInvocation(
                false, null, -1
            )
        );
        assertLinkRouting(
            "external URI uses authenticated native handling",
            LinkRouting.EXTERNAL,
            VirtualSpreadNavigation.classifyLinkInvocation(
                true, Boolean.TRUE, -1
            )
        );
        assertLinkRouting(
            "internal page link requires target capture",
            LinkRouting.INTERNAL,
            VirtualSpreadNavigation.classifyLinkInvocation(
                true, Boolean.FALSE, 4
            )
        );
        assertLinkRouting(
            "uninspectable link fails closed",
            LinkRouting.BLOCKED,
            VirtualSpreadNavigation.classifyLinkInvocation(
                true, null, 4
            )
        );
        assertLinkRouting(
            "negative internal target fails closed",
            LinkRouting.BLOCKED,
            VirtualSpreadNavigation.classifyLinkInvocation(
                true, Boolean.FALSE, -1
            )
        );
        assertBoolean(
            "pure link hit navigates immediately",
            true,
            VirtualSpreadNavigation.isImmediateLinkInvocation(
                true, false, false
            )
        );
        assertBoolean(
            "link plus digest remains a native action menu",
            false,
            VirtualSpreadNavigation.isImmediateLinkInvocation(
                true, true, false
            )
        );
        assertBoolean(
            "link plus annotation remains a native action menu",
            false,
            VirtualSpreadNavigation.isImmediateLinkInvocation(
                true, false, true
            )
        );
        assertBoolean(
            "annotation-only hit is not link navigation",
            false,
            VirtualSpreadNavigation.isImmediateLinkInvocation(
                false, false, true
            )
        );
        assertBoolean(
            "external replay initializes the verified spread immediately",
            true,
            VirtualSpreadNavigation.replayRequiresImmediateInitialization(
                LinkRouting.EXTERNAL
            )
        );
        assertBoolean(
            "blocked replay initializes the verified spread immediately",
            true,
            VirtualSpreadNavigation.replayRequiresImmediateInitialization(
                LinkRouting.BLOCKED
            )
        );
        assertBoolean(
            "no queued link initializes the verified spread immediately",
            true,
            VirtualSpreadNavigation.replayRequiresImmediateInitialization(
                LinkRouting.NON_LINK
            )
        );
        assertBoolean(
            "internal replay waits for its native page-load callback",
            false,
            VirtualSpreadNavigation.replayRequiresImmediateInitialization(
                LinkRouting.INTERNAL
            )
        );
        assertBoolean(
            "unbound manifest activation initializes the current spread",
            true,
            VirtualSpreadNavigation.manifestActivationRequiresInitialization(
                false, 8L, 8L, -1, -1, false, -1, false, -1, false
            )
        );
        assertBoolean(
            "fresh bound manifest activation initializes the current spread",
            true,
            VirtualSpreadNavigation.manifestActivationRequiresInitialization(
                true, 8L, 8L, -1, -1, false, -1, false, -1, false
            )
        );
        assertBoolean(
            "same key and revision from an older generation reinitializes",
            true,
            VirtualSpreadNavigation.manifestActivationRequiresInitialization(
                true, 7L, 8L, 3, -1, false, -1, false, -1, false
            )
        );
        assertBoolean(
            "initialized page wins the publish-to-activation race",
            false,
            VirtualSpreadNavigation.manifestActivationRequiresInitialization(
                true, 8L, 8L, 3, -1, false, -1, false, -1, false
            )
        );
        assertBoolean(
            "pending manual page wins the publish-to-activation race",
            false,
            VirtualSpreadNavigation.manifestActivationRequiresInitialization(
                true, 8L, 8L, -1, 3, true, -1, false, -1, false
            )
        );
        assertBoolean(
            "partial manual pending state fails closed",
            false,
            VirtualSpreadNavigation.manifestActivationRequiresInitialization(
                true, 8L, 8L, -1, -1, true, -1, false, -1, false
            )
        );
        assertBoolean(
            "pending internal link wins the publish-to-activation race",
            false,
            VirtualSpreadNavigation.manifestActivationRequiresInitialization(
                true, 8L, 8L, -1, -1, false, 3, true, -1, false
            )
        );
        assertBoolean(
            "partial link pending state fails closed",
            false,
            VirtualSpreadNavigation.manifestActivationRequiresInitialization(
                true, 8L, 8L, -1, -1, false, -1, true, -1, false
            )
        );
        assertBoolean(
            "pending link-history load wins the publish-to-activation race",
            false,
            VirtualSpreadNavigation.manifestActivationRequiresInitialization(
                true, 8L, 8L, -1, -1, false, -1, false, 3, true
            )
        );
        assertBoolean(
            "partial link-history pending state fails closed",
            false,
            VirtualSpreadNavigation.manifestActivationRequiresInitialization(
                true, 8L, 8L, -1, -1, false, -1, false, -1, true
            )
        );
        assertBoolean(
            "exact verification owner may activate",
            true,
            VirtualSpreadNavigation.manifestActivationBelongsToVerification(
                8L, 8L, true
            )
        );
        assertBoolean(
            "older same-revision verification may not activate",
            false,
            VirtualSpreadNavigation.manifestActivationBelongsToVerification(
                9L, 8L, true
            )
        );
        assertBoolean(
            "same generation on another native document may not activate",
            false,
            VirtualSpreadNavigation.manifestActivationBelongsToVerification(
                8L, 8L, false
            )
        );
        assertBoolean(
            "missing latest verification owner may not activate",
            false,
            VirtualSpreadNavigation.manifestActivationBelongsToVerification(
                0L, 8L, true
            )
        );
        assertBoolean(
            "synchronous lease expiry clears its exact bound state",
            true,
            VirtualSpreadNavigation.manifestInvalidationMayClear(
                true, true, 8L, 8L, 12L, -1L
            )
        );
        assertBoolean(
            "new queued link survives an older posted invalidation",
            false,
            VirtualSpreadNavigation.manifestInvalidationMayClear(
                true, true, 8L, 8L, 13L, 12L
            )
        );
        assertBoolean(
            "new mixed-menu candidate survives an older posted invalidation",
            false,
            VirtualSpreadNavigation.manifestInvalidationMayClear(
                true, true, 8L, 8L, 23L, 22L
            )
        );
        assertBoolean(
            "pre-removal token rejects intent created after cache removal",
            false,
            VirtualSpreadNavigation.manifestInvalidationMayClear(
                true, true, 8L, 8L, 31L, 30L
            )
        );
        assertBoolean(
            "freshness token cannot clear a later same-spread turn",
            false,
            VirtualSpreadNavigation.manifestInvalidationMayClear(
                true, true, 8L, 8L, 41L, 40L
            )
        );
        assertBoolean(
            "freshness token cannot clear a later cross-page turn",
            false,
            VirtualSpreadNavigation.manifestInvalidationMayClear(
                true, true, 8L, 8L, 51L, 50L
            )
        );
        assertBoolean(
            "new verification state survives an older invalidation",
            false,
            VirtualSpreadNavigation.manifestInvalidationMayClear(
                true, true, 9L, 8L, 12L, 12L
            )
        );
        assertBoolean(
            "new native document survives an older invalidation",
            false,
            VirtualSpreadNavigation.manifestInvalidationMayClear(
                true, false, 8L, 8L, 12L, 12L
            )
        );
        assertBoolean(
            "passive state binding retains its verification queue",
            true,
            VirtualSpreadNavigation.queuedLinkSurvivesVerificationBinding(
                8L, 8L
            )
        );
        assertBoolean(
            "passive state binding rejects an older verification queue",
            false,
            VirtualSpreadNavigation.queuedLinkSurvivesVerificationBinding(
                7L, 8L
            )
        );
        assertBoolean(
            "passive state binding retains its verification menu",
            true,
            VirtualSpreadNavigation.mixedLinkSurvivesVerificationBinding(
                8L, 8L
            )
        );
        assertBoolean(
            "passive state binding rejects an older verification menu",
            false,
            VirtualSpreadNavigation.mixedLinkSurvivesVerificationBinding(
                7L, 8L
            )
        );
        assertBoolean(
            "unbound mixed menu cannot enter a verified generation",
            false,
            VirtualSpreadNavigation.mixedLinkSurvivesVerificationBinding(
                0L, 8L
            )
        );
        assertBoolean(
            "synthetic manifest initialization preserves deferred link intent",
            true,
            VirtualSpreadNavigation.pageLoadPreservesDeferredLinkIntent(true)
        );
        assertBoolean(
            "real native page load invalidates queued link intent",
            false,
            VirtualSpreadNavigation.pageLoadPreservesDeferredLinkIntent(false)
        );
        assertBoolean(
            "real native page load invalidates a mixed-menu candidate",
            false,
            VirtualSpreadNavigation.pageLoadPreservesDeferredLinkIntent(false)
        );
        assertBoolean(
            "clean page needs no save callback",
            true,
            VirtualSpreadNavigation.saveAcknowledgementMatches(
                false, false, false, false, -1, -1, false
            )
        );
        assertBoolean(
            "dirty page requires matching successful native save callback",
            true,
            VirtualSpreadNavigation.saveAcknowledgementMatches(
                true, true, true, true, 17, 17, true
            )
        );
        assertBoolean(
            "normal saveTrails return without callback fails closed",
            false,
            VirtualSpreadNavigation.saveAcknowledgementMatches(
                true, false, false, false, 17, -1, false
            )
        );
        assertBoolean(
            "failed native save callback fails closed",
            false,
            VirtualSpreadNavigation.saveAcknowledgementMatches(
                true, true, false, true, 17, 17, true
            )
        );
        assertBoolean(
            "save callback for another page fails closed",
            false,
            VirtualSpreadNavigation.saveAcknowledgementMatches(
                true, true, true, true, 17, 18, true
            )
        );
        assertBoolean(
            "pending link replays on its original page",
            true,
            VirtualSpreadNavigation.pendingLinkReplayIsCurrent(
                true, true, true, true, 4, 4, 1000L, 60000L
            )
        );
        assertBoolean(
            "pending link cannot cross documents",
            false,
            VirtualSpreadNavigation.pendingLinkReplayIsCurrent(
                false, true, true, true, 4, 4, 1000L, 60000L
            )
        );
        assertBoolean(
            "pending link cannot cross document snapshots",
            false,
            VirtualSpreadNavigation.pendingLinkReplayIsCurrent(
                true, false, true, true, 4, 4, 1000L, 60000L
            )
        );
        assertBoolean(
            "pending link cannot cross native document instances",
            false,
            VirtualSpreadNavigation.pendingLinkReplayIsCurrent(
                true, true, false, true, 4, 4, 1000L, 60000L
            )
        );
        assertBoolean(
            "pending link cannot survive an intervening page load",
            false,
            VirtualSpreadNavigation.pendingLinkReplayIsCurrent(
                true, true, true, false, 4, 4, 1000L, 60000L
            )
        );
        assertBoolean(
            "pending link cannot cross pages",
            false,
            VirtualSpreadNavigation.pendingLinkReplayIsCurrent(
                true, true, true, true, 4, 5, 1000L, 60000L
            )
        );
        assertBoolean(
            "expired pending link is discarded",
            false,
            VirtualSpreadNavigation.pendingLinkReplayIsCurrent(
                true, true, true, true, 4, 4, 60001L, 60000L
            )
        );
        assertBoolean(
            "queued link belongs to its verifier generation",
            true,
            VirtualSpreadNavigation.queuedLinkBelongsToVerification(9L, 9L)
        );
        assertBoolean(
            "stale verifier cannot consume a newer queued link",
            false,
            VirtualSpreadNavigation.queuedLinkBelongsToVerification(10L, 9L)
        );
        assertBoolean(
            "unowned verifier generation cannot consume a queued link",
            false,
            VirtualSpreadNavigation.queuedLinkBelongsToVerification(0L, 0L)
        );
        assertBoolean(
            "explicit portrait link viewport is preserved",
            true,
            VirtualSpreadNavigation.shouldPreservePortraitLinkViewport(
                true,
                false,
                false
            )
        );
        assertBoolean(
            "source-fit portrait link viewport is normalized",
            false,
            VirtualSpreadNavigation.shouldPreservePortraitLinkViewport(
                true,
                true,
                false
            )
        );
        assertBoolean(
            "ordinary page loads retain normal half focus",
            false,
            VirtualSpreadNavigation.shouldPreservePortraitLinkViewport(
                false,
                false,
                false
            )
        );
        assertBoolean(
            "explicit portrait link viewport survives native reload",
            true,
            VirtualSpreadNavigation.shouldPreservePortraitLinkViewport(
                false,
                false,
                true
            )
        );

        Object cacheA = new Object();
        Object cacheB = new Object();
        Object cacheC = new Object();
        BoundedCache<String, Object> cache = new BoundedCache<>(2);
        cache.put("a", cacheA);
        cache.put("b", cacheB);
        assertBoolean(
            "manifest cache lookup returns exact value",
            true,
            cache.get("a") == cacheA
        );
        cache.put("c", cacheC);
        assertBoolean(
            "manifest cache refresh protects recent entry",
            true,
            cache.get("a") == cacheA
        );
        assertBoolean(
            "manifest cache evicts least-recent entry",
            true,
            cache.get("b") == null
        );
        assertBoolean(
            "manifest cache retains newest entry",
            true,
            cache.get("c") == cacheC
        );
        assertEquals("manifest cache remains bounded", 2, cache.size());
        assertBoolean(
            "conditional cache removal rejects stale value",
            false,
            cache.remove("a", cacheB)
        );
        assertBoolean(
            "conditional cache removal preserves live value",
            true,
            cache.get("a") == cacheA
        );
        assertBoolean(
            "conditional cache removal accepts exact value",
            true,
            cache.remove("a", cacheA)
        );
        assertEquals("conditional removal updates cache size", 1, cache.size());
        assertBoolean(
            "conditional cache replacement rejects stale value",
            false,
            cache.replace("c", cacheA, cacheB)
        );
        assertBoolean(
            "conditional cache replacement accepts exact value",
            true,
            cache.replace("c", cacheC, cacheB)
        );
        assertBoolean(
            "conditional cache replacement publishes replacement",
            true,
            cache.get("c") == cacheB
        );
        boolean rejectedZeroCapacity = false;
        try {
            new BoundedCache<String, Object>(0);
        } catch (IllegalArgumentException expected) {
            rejectedZeroCapacity = true;
        }
        assertBoolean(
            "manifest cache rejects zero capacity",
            true,
            rejectedZeroCapacity
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
            "oversized PDF page geometry fails closed",
            false,
            VirtualSpreadNavigation.runtimeGeometryIsRepresentable(
                20000.0, 15000.0, 0.0
            )
        );
        assertBoolean(
            "undersized PDF page geometry fails closed",
            false,
            VirtualSpreadNavigation.runtimeGeometryIsRepresentable(
                3.9, 2.925, 0.0
            )
        );
        assertBoolean(
            "maximum PDF page geometry is accepted",
            true,
            VirtualSpreadNavigation.runtimeGeometryIsRepresentable(
                14400.0, 10800.0, 0.0
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
            "default Nomad spread aspect is supported",
            true,
            VirtualSpreadNavigation.nomadSpreadAspectIsSupported(
                864.0, 648.0
            )
        );
        assertBoolean(
            "scaled Nomad spread aspect is supported",
            true,
            VirtualSpreadNavigation.nomadSpreadAspectIsSupported(
                1728.0, 1296.0
            )
        );
        assertBoolean(
            "non-Nomad spread aspect is rejected",
            false,
            VirtualSpreadNavigation.nomadSpreadAspectIsSupported(
                864.0, 864.0
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
        UriTarget[] uriTargets = new UriTarget[] {
            new UriTarget(
                1,
                Half.RIGHT,
                "https://example.test/chapter",
                486.0f,
                60.0f,
                810.0f,
                102.0f
            )
        };
        assertBoolean(
            "authenticated external URI and bounds match",
            true,
            VirtualSpreadNavigation.matchUriLink(
                uriTargets,
                1,
                "https://example.test/chapter",
                486.0f,
                546.0f,
                810.0f,
                588.0f,
                648.0f,
                0.5f
            ) != null
        );
        assertBoolean(
            "external URI callback with another URL fails closed",
            true,
            VirtualSpreadNavigation.matchUriLink(
                uriTargets,
                1,
                "https://attacker.invalid/",
                486.0f,
                546.0f,
                810.0f,
                588.0f,
                648.0f,
                0.5f
            ) == null
        );
        assertBoolean(
            "external URI callback with unauthenticated bounds fails closed",
            true,
            VirtualSpreadNavigation.matchUriLink(
                uriTargets,
                1,
                "https://example.test/chapter",
                480.0f,
                546.0f,
                810.0f,
                588.0f,
                648.0f,
                0.5f
            ) == null
        );
        assertBoolean(
            "ambiguous external URI halves fail closed",
            true,
            VirtualSpreadNavigation.matchUriLink(
                new UriTarget[] {
                    uriTargets[0],
                    new UriTarget(
                        1,
                        Half.LEFT,
                        "https://example.test/chapter",
                        486.25f,
                        60.25f,
                        810.25f,
                        102.25f
                    )
                },
                1,
                "https://example.test/chapter",
                486.0f,
                546.0f,
                810.0f,
                588.0f,
                648.0f,
                0.5f
            ) == null
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

        assertNullableInteger(
            "JSON Integer token is accepted",
            Integer.valueOf(17),
            VirtualSpreadNavigation.exactJsonInteger(Integer.valueOf(17))
        );
        assertNullableInteger(
            "in-range JSON Long token is accepted",
            Integer.valueOf(17),
            VirtualSpreadNavigation.exactJsonInteger(Long.valueOf(17L))
        );
        assertNullableInteger(
            "numeric JSON string is rejected",
            null,
            VirtualSpreadNavigation.exactJsonInteger("17")
        );
        assertNullableInteger(
            "fractional JSON number is rejected",
            null,
            VirtualSpreadNavigation.exactJsonInteger(Double.valueOf(17.5))
        );
        assertNullableInteger(
            "integral JSON double is rejected",
            null,
            VirtualSpreadNavigation.exactJsonInteger(Double.valueOf(17.0))
        );
        assertNullableInteger(
            "overflowing JSON long is rejected",
            null,
            VirtualSpreadNavigation.exactJsonInteger(
                Long.valueOf((long) Integer.MAX_VALUE + 1L)
            )
        );
        assertNullableInteger(
            "underflowing JSON long is rejected",
            null,
            VirtualSpreadNavigation.exactJsonInteger(
                Long.valueOf((long) Integer.MIN_VALUE - 1L)
            )
        );
        assertNullableInteger(
            "missing JSON integer is rejected",
            null,
            VirtualSpreadNavigation.exactJsonInteger(null)
        );
        assertNullableLong(
            "JSON Integer size is accepted",
            Long.valueOf(17L),
            VirtualSpreadNavigation.exactNonnegativeJsonLong(
                Integer.valueOf(17)
            )
        );
        assertNullableLong(
            "JSON Long size is accepted",
            Long.valueOf(Long.MAX_VALUE),
            VirtualSpreadNavigation.exactNonnegativeJsonLong(
                Long.valueOf(Long.MAX_VALUE)
            )
        );
        assertNullableLong(
            "numeric JSON size string is rejected",
            null,
            VirtualSpreadNavigation.exactNonnegativeJsonLong("17")
        );
        assertNullableLong(
            "fractional JSON size is rejected",
            null,
            VirtualSpreadNavigation.exactNonnegativeJsonLong(
                Double.valueOf(17.9)
            )
        );
        assertNullableLong(
            "integral JSON size double is rejected",
            null,
            VirtualSpreadNavigation.exactNonnegativeJsonLong(
                Double.valueOf(17.0)
            )
        );
        assertNullableLong(
            "negative JSON Integer size is rejected",
            null,
            VirtualSpreadNavigation.exactNonnegativeJsonLong(
                Integer.valueOf(-1)
            )
        );
        assertNullableLong(
            "negative JSON Long size is rejected",
            null,
            VirtualSpreadNavigation.exactNonnegativeJsonLong(
                Long.valueOf(-1L)
            )
        );
        assertNullableLong(
            "missing JSON size is rejected",
            null,
            VirtualSpreadNavigation.exactNonnegativeJsonLong(null)
        );
        assertNullableDouble(
            "JSON Integer geometry is accepted",
            Double.valueOf(17.0),
            VirtualSpreadNavigation.exactFiniteJsonNumber(
                Integer.valueOf(17)
            )
        );
        assertNullableDouble(
            "JSON Long geometry is accepted",
            Double.valueOf(17.0),
            VirtualSpreadNavigation.exactFiniteJsonNumber(
                Long.valueOf(17L)
            )
        );
        assertNullableDouble(
            "JSON Double geometry is accepted",
            Double.valueOf(17.5),
            VirtualSpreadNavigation.exactFiniteJsonNumber(
                Double.valueOf(17.5)
            )
        );
        assertNullableDouble(
            "numeric JSON geometry string is rejected",
            null,
            VirtualSpreadNavigation.exactFiniteJsonNumber("17.5")
        );
        assertNullableDouble(
            "boolean JSON geometry is rejected",
            null,
            VirtualSpreadNavigation.exactFiniteJsonNumber(Boolean.TRUE)
        );
        assertNullableDouble(
            "NaN JSON geometry is rejected",
            null,
            VirtualSpreadNavigation.exactFiniteJsonNumber(Double.NaN)
        );
        assertNullableDouble(
            "positive infinite JSON geometry is rejected",
            null,
            VirtualSpreadNavigation.exactFiniteJsonNumber(
                Double.POSITIVE_INFINITY
            )
        );
        assertNullableDouble(
            "negative infinite JSON geometry is rejected",
            null,
            VirtualSpreadNavigation.exactFiniteJsonNumber(
                Double.NEGATIVE_INFINITY
            )
        );
        assertNullableDouble(
            "missing JSON geometry is rejected",
            null,
            VirtualSpreadNavigation.exactFiniteJsonNumber(null)
        );
        String validUtf8 = "{\"label\":\"שלום \uFFFD\"}";
        assertBoolean(
            "valid UTF-8 including a literal replacement character is exact",
            true,
            validUtf8.equals(VirtualSpreadNavigation.decodeStrictUtf8(
                validUtf8.getBytes(StandardCharsets.UTF_8)
            ))
        );
        assertBoolean(
            "malformed UTF-8 in an ignored field is rejected",
            true,
            VirtualSpreadNavigation.decodeStrictUtf8(new byte[] {
                '{', '"', 'e', 'x', 't', 'r', 'a', '"', ':', '"',
                (byte) 0x80, '"', '}'
            }) == null
        );
        assertBoolean(
            "overlong UTF-8 is rejected",
            true,
            VirtualSpreadNavigation.decodeStrictUtf8(new byte[] {
                (byte) 0xC0, (byte) 0xAF
            }) == null
        );
        assertBoolean(
            "truncated UTF-8 is rejected",
            true,
            VirtualSpreadNavigation.decodeStrictUtf8(new byte[] {
                (byte) 0xE2, (byte) 0x82
            }) == null
        );
        assertBoolean(
            "UTF-8 encoded surrogate is rejected",
            true,
            VirtualSpreadNavigation.decodeStrictUtf8(new byte[] {
                (byte) 0xED, (byte) 0xA0, (byte) 0x80
            }) == null
        );
        assertBoolean(
            "missing UTF-8 bytes are rejected",
            true,
            VirtualSpreadNavigation.decodeStrictUtf8(null) == null
        );
        assertBoolean(
            "unique nested JSON object keys are accepted",
            true,
            VirtualSpreadNavigation.jsonObjectHasUniqueKeys(
                "{\"root\":{\"value\":1},"
                    + "\"items\":[{\"value\":2}],"
                    + "\"flag\":true,\"none\":null}"
            )
        );
        assertBoolean(
            "duplicate root JSON key is rejected",
            false,
            VirtualSpreadNavigation.jsonObjectHasUniqueKeys(
                "{\"a\":1,\"a\":2}"
            )
        );
        assertBoolean(
            "duplicate nested JSON key is rejected",
            false,
            VirtualSpreadNavigation.jsonObjectHasUniqueKeys(
                "{\"root\":{\"a\":1,\"a\":2}}"
            )
        );
        assertBoolean(
            "duplicate JSON key inside array is rejected",
            false,
            VirtualSpreadNavigation.jsonObjectHasUniqueKeys(
                "{\"items\":[{\"a\":1,\"a\":2}]}"
            )
        );
        String escapedDuplicate = "{\"a\":1,\""
            + ((char) 92) + "u0061\":2}";
        assertBoolean(
            "escape-equivalent duplicate JSON key is rejected",
            false,
            VirtualSpreadNavigation.jsonObjectHasUniqueKeys(escapedDuplicate)
        );
        assertBoolean(
            "malformed JSON is rejected before JSONObject",
            false,
            VirtualSpreadNavigation.jsonObjectHasUniqueKeys(
                "{\"a\":1,}"
            )
        );
        assertBoolean(
            "trailing JSON content is rejected",
            false,
            VirtualSpreadNavigation.jsonObjectHasUniqueKeys(
                "{\"a\":1}{}"
            )
        );
        assertBoolean(
            "non-object JSON root is rejected",
            false,
            VirtualSpreadNavigation.jsonObjectHasUniqueKeys(
                "[{\"a\":1}]"
            )
        );

        String sourceAuthority =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        String layoutAuthority =
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        String linkAuthority =
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        String mappingAuthority =
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
        String viewId = "inkbridge-view-v1-"
            + "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
        String generatorVersion =
            "techrebbe.supernote.virtual-spread-generator/v1";
        assertBoolean(
            "matching native document authorities are accepted",
            true,
            VirtualSpreadNavigation.manifestMatchesNativeSnapshot(
                sourceAuthority,
                layoutAuthority,
                linkAuthority,
                mappingAuthority,
                viewId,
                generatorVersion,
                sourceAuthority,
                layoutAuthority,
                linkAuthority,
                mappingAuthority,
                viewId,
                generatorVersion
            )
        );
        assertBoolean(
            "uppercase native authority fails closed",
            false,
            VirtualSpreadNavigation.manifestMatchesNativeSnapshot(
                sourceAuthority,
                layoutAuthority,
                linkAuthority,
                mappingAuthority,
                viewId,
                generatorVersion,
                sourceAuthority,
                layoutAuthority,
                linkAuthority,
                mappingAuthority.toUpperCase(),
                viewId,
                generatorVersion
            )
        );
        assertBoolean(
            "replaced native source fails closed",
            false,
            VirtualSpreadNavigation.manifestMatchesNativeSnapshot(
                sourceAuthority,
                layoutAuthority,
                linkAuthority,
                mappingAuthority,
                viewId,
                generatorVersion,
                linkAuthority,
                layoutAuthority,
                linkAuthority,
                mappingAuthority,
                viewId,
                generatorVersion
            )
        );
        assertBoolean(
            "stale native layout fails closed",
            false,
            VirtualSpreadNavigation.manifestMatchesNativeSnapshot(
                sourceAuthority,
                layoutAuthority,
                linkAuthority,
                mappingAuthority,
                viewId,
                generatorVersion,
                sourceAuthority,
                linkAuthority,
                linkAuthority,
                mappingAuthority,
                viewId,
                generatorVersion
            )
        );
        assertBoolean(
            "stale native links fail closed",
            false,
            VirtualSpreadNavigation.manifestMatchesNativeSnapshot(
                sourceAuthority,
                layoutAuthority,
                linkAuthority,
                mappingAuthority,
                viewId,
                generatorVersion,
                sourceAuthority,
                layoutAuthority,
                sourceAuthority,
                mappingAuthority,
                viewId,
                generatorVersion
            )
        );
        assertBoolean(
            "missing native authority fails closed",
            false,
            VirtualSpreadNavigation.manifestMatchesNativeSnapshot(
                sourceAuthority,
                layoutAuthority,
                linkAuthority,
                mappingAuthority,
                viewId,
                generatorVersion,
                null,
                layoutAuthority,
                linkAuthority,
                mappingAuthority,
                viewId,
                generatorVersion
            )
        );
        assertBoolean(
            "stale native mapping fails closed",
            false,
            VirtualSpreadNavigation.manifestMatchesNativeSnapshot(
                sourceAuthority,
                layoutAuthority,
                linkAuthority,
                mappingAuthority,
                viewId,
                generatorVersion,
                sourceAuthority,
                layoutAuthority,
                linkAuthority,
                sourceAuthority,
                viewId,
                generatorVersion
            )
        );
        assertBoolean(
            "stale native view identity fails closed",
            false,
            VirtualSpreadNavigation.manifestMatchesNativeSnapshot(
                sourceAuthority,
                layoutAuthority,
                linkAuthority,
                mappingAuthority,
                viewId,
                generatorVersion,
                sourceAuthority,
                layoutAuthority,
                linkAuthority,
                mappingAuthority,
                "inkbridge-view-v1-" + sourceAuthority,
                generatorVersion
            )
        );
        assertBoolean(
            "stale native generator fails closed",
            false,
            VirtualSpreadNavigation.manifestMatchesNativeSnapshot(
                sourceAuthority,
                layoutAuthority,
                linkAuthority,
                mappingAuthority,
                viewId,
                generatorVersion,
                sourceAuthority,
                layoutAuthority,
                linkAuthority,
                mappingAuthority,
                viewId,
                "older-generator"
            )
        );
        assertBoolean(
            "null native metadata is ordinary",
            false,
            VirtualSpreadNavigation.nativeMetadataClaimsVirtualSpread(
                null,
                null,
                null,
                null,
                null,
                null
            )
        );
        assertBoolean(
            "MuPDF empty native metadata is ordinary",
            false,
            VirtualSpreadNavigation.nativeMetadataClaimsVirtualSpread(
                "",
                "   ",
                "\t",
                "",
                " ",
                null
            )
        );
        assertBoolean(
            "one generated authority claims Virtual Spread",
            true,
            VirtualSpreadNavigation.nativeMetadataClaimsVirtualSpread(
                sourceAuthority,
                "",
                null,
                null,
                null,
                null
            )
        );
        assertBoolean(
            "malformed nonblank authority remains fail closed",
            true,
            VirtualSpreadNavigation.nativeMetadataClaimsVirtualSpread(
                "malformed",
                null,
                null,
                null,
                null,
                null
            )
        );
        assertBoolean(
            "unexpected typed authority remains fail closed",
            true,
            VirtualSpreadNavigation.nativeMetadataClaimsVirtualSpread(
                Integer.valueOf(1),
                null,
                null,
                null,
                null,
                null
            )
        );

        LinkHistory history = new LinkHistory();
        history.record(1, Half.RIGHT, 3);
        history.record(3, Half.LEFT, 1);
        assertEquals("history records two visits", 2, history.size());
        assertVisit(
            "Back preflight validates without consuming",
            history.peekBack(3, 1, 1),
            3,
            Half.LEFT,
            1
        );
        assertEquals("Back preflight preserves visits", 2, history.size());
        assertVisit(
            "Back restores latest link source",
            history.takeBack(3, 1, 1),
            3,
            Half.LEFT,
            1
        );
        assertEquals("Back consumes one visit", 1, history.size());
        assertVisit(
            "Original Back restores oldest link source",
            history.takeOriginal(1, 3, 3),
            1,
            Half.RIGHT,
            3
        );
        assertEquals("Original Back clears history", 0, history.size());

        history.record(1, Half.RIGHT, 3);
        assertVisit(
            "mismatched native history fails closed",
            history.takeBack(2, 3, 3),
            -1,
            null,
            -1
        );
        assertEquals("mismatch clears stale mirror", 0, history.size());

        history.record(1, Half.RIGHT, 3);
        history.record(3, Half.LEFT, 5);
        assertVisit(
            "Original Back preflight validates without consuming",
            history.peekOriginal(1, 3, 5),
            1,
            Half.RIGHT,
            3
        );
        assertEquals(
            "Original Back preflight preserves complete history",
            2,
            history.size()
        );
        assertVisit(
            "direct Original Back validates newest destination",
            history.takeOriginal(1, 3, 5),
            1,
            Half.RIGHT,
            3
        );
        assertEquals(
            "direct Original Back clears complete history",
            0,
            history.size()
        );

        history.record(1, Half.RIGHT, 3);
        assertVisit(
            "mismatched Back preflight is non-mutating",
            history.peekBack(2, 3, 3),
            -1,
            null,
            -1
        );
        assertEquals(
            "mismatched Back preflight preserves mirror",
            1,
            history.size()
        );
        assertVisit(
            "stale current page clears native history",
            history.takeBack(1, 3, 2),
            -1,
            null,
            -1
        );
        assertEquals("stale current page clears mirror", 0, history.size());
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

    private static void assertNullableInteger(
        String name,
        Integer expected,
        Integer actual
    ) {
        if (expected == null ? actual != null : !expected.equals(actual)) {
            throw new AssertionError(
                name + ": expected " + expected + " but got " + actual
            );
        }
        assertions++;
    }

    private static void assertNullableLong(
        String name,
        Long expected,
        Long actual
    ) {
        if (expected == null ? actual != null : !expected.equals(actual)) {
            throw new AssertionError(
                name + ": expected " + expected + " but got " + actual
            );
        }
        assertions++;
    }

    private static void assertNullableDouble(
        String name,
        Double expected,
        Double actual
    ) {
        if (expected == null ? actual != null : !expected.equals(actual)) {
            throw new AssertionError(
                name + ": expected " + expected + " but got " + actual
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

    private static void assertLinkRouting(
        String name,
        LinkRouting expected,
        LinkRouting actual
    ) {
        if (actual != expected) {
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
