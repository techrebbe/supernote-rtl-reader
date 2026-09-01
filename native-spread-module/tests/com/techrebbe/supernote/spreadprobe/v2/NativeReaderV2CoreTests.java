package com.techrebbe.supernote.spreadprobe.v2;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Random;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

public final class NativeReaderV2CoreTests {
    private static int assertions;

    public static void main(String[] args) throws Exception {
        testAffineRoundTrips();
        testNativeProjectionGeometry();
        testPairingMatrix();
        testSnapshotAuthority();
        testGestureRouting();
        testGestureBuffer();
        testActivationHappyPaths();
        testActivationRollbackAndStaleEvents();
        testActivationConcurrency();
        testSessionPublication();
        System.out.println("NativeReaderV2CoreTests PASS assertions=" + assertions);
    }

    private static void testAffineRoundTrips() {
        Random random = new Random(0x5eed5eedL);
        for (int index = 0; index < 10000; index++) {
            double angle = random.nextDouble() * Math.PI * 2.0;
            double scaleX = 0.1 + random.nextDouble() * 4.0;
            double scaleY = 0.1 + random.nextDouble() * 4.0;
            double cos = Math.cos(angle);
            double sin = Math.sin(angle);
            Affine2D transform = new Affine2D(
                cos * scaleX,
                sin * scaleX,
                -sin * scaleY,
                cos * scaleY,
                random.nextDouble() * 10000.0 - 5000.0,
                random.nextDouble() * 10000.0 - 5000.0
            );
            double x = random.nextDouble() * 2000.0 - 1000.0;
            double y = random.nextDouble() * 2000.0 - 1000.0;
            PointD mapped = transform.map(x, y);
            PointD roundTrip = transform.derivedInverse().map(mapped.x, mapped.y);
            near(x, roundTrip.x, 1.0e-8, "affine x round trip");
            near(y, roundTrip.y, 1.0e-8, "affine y round trip");
        }
        expectThrows(() -> new Affine2D(
            Double.NaN, 0, 0, 1, 0, 0
        ), "non-finite affine");
        expectThrows(() -> new Affine2D(
            1, 1, 2, 2, 0, 0
        ), "singular affine");
        Affine2D android = Affine2D.fromAndroidMatrix(
            new double[] { 2, 0.5, 7, -0.25, 3, 11, 0, 0, 1 }
        );
        PointD androidPoint = android.map(4, 5);
        near(17.5, androidPoint.x, 1.0e-12, "Android matrix x");
        near(25.0, androidPoint.y, 1.0e-12, "Android matrix y");
        expectThrows(() -> Affine2D.fromAndroidMatrix(
            new double[] { 1, 0, 0, 0, 1, 0, 0.1, 0, 1 }
        ), "perspective matrix rejected");
        expectThrows(() -> new PageSlot(
            0,
            PageSlot.Side.FULL,
            new RectD(0, 0, 100, 100),
            new RectD(0, 0, 100, 100),
            new Affine2D(1, 0, 0, 1, 1, 0)
        ), "escaping page transform");
    }

    private static void testNativeProjectionGeometry() {
        RectD source = new RectD(10, 20, 1010, 1420);
        RectD canvas = new RectD(0, 0, 1872, 1404);
        Affine2D rotatedNative = new Affine2D(
            0, -1, 1, 0, -20, 1010
        );
        PageSlot portrait = PageProjectionFactory.portrait(
            4, source, canvas, rotatedNative
        );
        equal(PageSlot.Side.FULL, portrait.side, "native portrait retained");
        PointD sourceRoundTrip = portrait.mapToSource(
            portrait.mapToScreen(417, 999).x,
            portrait.mapToScreen(417, 999).y
        );
        near(417, sourceRoundTrip.x, 1.0e-9, "portrait rotation round-trip x");
        near(999, sourceRoundTrip.y, 1.0e-9, "portrait rotation round-trip y");

        RectD left = new RectD(0, 0, 936, 1404);
        PageSlot projected = PageProjectionFactory.landscapeSlot(
            4, PageSlot.Side.LEFT, source, canvas, rotatedNative, left
        );
        RectD projectedBounds = projected.sourceToScreen.mapBounds(source);
        near(936, projectedBounds.width(), 1.0e-9,
            "wide rotated page uses full half width");
        near(668.5714285714286, projectedBounds.height(), 1.0e-9,
            "wide rotated page preserves aspect");
        near(0, projectedBounds.left, 1.0e-9, "wide page centered x");
        near((1404 - projectedBounds.height()) / 2.0,
            projectedBounds.top, 1.0e-9, "wide page centered y");

        RectD narrowSource = new RectD(0, 0, 400, 2000);
        Affine2D narrowNative = new Affine2D(
            0.6, 0, 0, 0.6, 816, 102
        );
        PageSlot narrow = PageProjectionFactory.landscapeSlot(
            5, PageSlot.Side.RIGHT, narrowSource, canvas, narrowNative,
            new RectD(936, 0, 1872, 1404)
        );
        RectD narrowBounds = narrow.sourceToScreen.mapBounds(narrowSource);
        near(1404, narrowBounds.height(), 1.0e-9,
            "narrow page uses full half height");
        near(280.8, narrowBounds.width(), 1.0e-9,
            "narrow page preserves aspect");
        near(936 + (936 - 280.8) / 2.0, narrowBounds.left, 1.0e-9,
            "narrow page centered");

        expectThrows(() -> PageProjectionFactory.landscapeSlot(
            0,
            PageSlot.Side.LEFT,
            new RectD(0, 0, 100, 100),
            new RectD(0, 0, 100, 100),
            new Affine2D(1, 0, 0, 1, 20, 20),
            new RectD(0, 0, 50, 100)
        ), "cropped native source fails closed");

        Random random = new Random(0x51a7f17L);
        for (int index = 0; index < 5000; index++) {
            double sourceLeft = random.nextDouble() * 200.0 - 100.0;
            double sourceTop = random.nextDouble() * 200.0 - 100.0;
            double width = 10.0 + random.nextDouble() * 3000.0;
            double height = 10.0 + random.nextDouble() * 3000.0;
            RectD randomSource = new RectD(
                sourceLeft,
                sourceTop,
                sourceLeft + width,
                sourceTop + height
            );
            double angle = random.nextDouble() * Math.PI * 2.0;
            Affine2D rotation = new Affine2D(
                Math.cos(angle),
                Math.sin(angle),
                -Math.sin(angle),
                Math.cos(angle),
                0,
                0
            );
            RectD rotated = rotation.mapBounds(randomSource);
            double nativeScale = Math.min(
                canvas.width() / rotated.width(),
                canvas.height() / rotated.height()
            ) * (0.5 + random.nextDouble() * 0.5);
            Affine2D toCanvas = new Affine2D(
                nativeScale,
                0,
                0,
                nativeScale,
                canvas.left + (canvas.width() - rotated.width() * nativeScale)
                    / 2.0 - rotated.left * nativeScale,
                canvas.top + (canvas.height() - rotated.height() * nativeScale)
                    / 2.0 - rotated.top * nativeScale
            );
            Affine2D nativeTransform = rotation.then(toCanvas);
            PageSlot randomSlot = PageProjectionFactory.landscapeSlot(
                index,
                PageSlot.Side.LEFT,
                randomSource,
                canvas,
                nativeTransform,
                left
            );
            RectD result = randomSlot.sourceToScreen.mapBounds(randomSource);
            near(left.left + left.width() / 2.0,
                result.left + result.width() / 2.0, 1.0e-7,
                "random projection centered x");
            near(left.top + left.height() / 2.0,
                result.top + result.height() / 2.0, 1.0e-7,
                "random projection centered y");
            check(result.width() <= left.width() + 1.0e-7
                && result.height() <= left.height() + 1.0e-7,
                "random projection fits slot");
            double sourceX = randomSource.left + random.nextDouble() * width;
            double sourceY = randomSource.top + random.nextDouble() * height;
            PointD screen = randomSlot.mapToScreen(sourceX, sourceY);
            PointD back = randomSlot.mapToSource(screen.x, screen.y);
            near(sourceX, back.x, 1.0e-7, "random projection inverse x");
            near(sourceY, back.y, 1.0e-7, "random projection inverse y");
        }
    }

    private static void testPairingMatrix() {
        for (int pageCount = 1; pageCount <= 40; pageCount++) {
            for (int page = 0; page < pageCount; page++) {
                for (SpreadPairing.Direction direction
                    : SpreadPairing.Direction.values()) {
                    for (boolean cover : new boolean[] { false, true }) {
                        SpreadPairing.Pair pair = SpreadPairing.forPage(
                            page,
                            pageCount,
                            direction,
                            cover
                        );
                        check(pair.contains(page), "pair must contain focus");
                        check(pair.leftPage < pageCount, "left bound");
                        check(pair.rightPage < pageCount, "right bound");
                        check(pair.leftPage >= -1 && pair.rightPage >= -1,
                            "blank sentinel only");
                        if (pair.leftPage >= 0 && pair.rightPage >= 0) {
                            check(Math.abs(pair.leftPage - pair.rightPage) == 1,
                                "paired pages must be adjacent");
                        }
                        if (direction == SpreadPairing.Direction.RTL
                            && pair.leftPage >= 0 && pair.rightPage >= 0) {
                            check(pair.leftPage > pair.rightPage,
                                "RTL physical order");
                        }
                        if (direction == SpreadPairing.Direction.LTR
                            && pair.leftPage >= 0 && pair.rightPage >= 0) {
                            check(pair.leftPage < pair.rightPage,
                                "LTR physical order");
                        }
                    }
                }
            }
        }
        SpreadPairing.Pair cover = SpreadPairing.forPage(
            0, 10, SpreadPairing.Direction.RTL, true
        );
        equal(-1, cover.leftPage, "RTL cover blank on left");
        equal(0, cover.rightPage, "RTL cover on right");
        SpreadPairing.Pair next = SpreadPairing.forPage(
            1, 10, SpreadPairing.Direction.RTL, true
        );
        equal(2, next.leftPage, "page 3 on left");
        equal(1, next.rightPage, "page 2 on right");
    }

    private static void testSnapshotAuthority() {
        SpreadSnapshot spread = spread(1, 1, 1, true);
        check(spread.writerReady, "fixture writer ready");
        equal(1, spread.slotAt(100, 500).sourcePageIndex, "left hit");
        equal(0, spread.slotAt(1200, 500).sourcePageIndex, "right hit");
        check(spread.slotAt(935.999, 500).sourcePageIndex == 1,
            "divider boundary remains left");
        check(spread.slotAt(936.0, 500).sourcePageIndex == 0,
            "half-open boundary becomes right");
        expectThrows(() -> new SpreadSnapshot(
            "doc", 1, 1, 10, 1, SpreadSnapshot.Mode.SPREAD,
            leftSlot(1), rightSlot(0), authority(0, 1, 1), true
        ), "stale writer page");
        expectThrows(() -> new SpreadSnapshot(
            "doc", 1, 1, 10, 1, SpreadSnapshot.Mode.SPREAD,
            leftSlot(1), leftSlot(0), authority(1, 1, 1), true
        ), "duplicate physical side");
        SpreadSnapshot cover = new SpreadSnapshot(
            "doc", 1, 2, 10, 0, SpreadSnapshot.Mode.SPREAD,
            PageSlot.blank(PageSlot.Side.LEFT, new RectD(0, 0, 936, 1404)),
            rightSlot(0), authority(0, 1, 2), true
        );
        check(cover.leftOrFull.isBlank(), "cover blank is explicit");
        check(cover.slotAt(100, 500).isBlank(), "blank occupies physical slot");
        expectThrows(() -> cover.leftOrFull.mapToSource(100, 500),
            "blank has no inverse transform");
        expectThrows(() -> new SpreadSnapshot(
            "doc", 1, 2, 10, 0, SpreadSnapshot.Mode.SPREAD,
            PageSlot.blank(PageSlot.Side.LEFT, new RectD(0, 0, 936, 1404)),
            rightSlot(0), authority(0, 1, 2), false
        ), "unready authority rejected");
    }

    private static void testGestureRouting() {
        SpreadSnapshot spread = spread(1, 1, 1, true);
        GestureRouter router = new GestureRouter();
        List<RectD> chrome = Collections.singletonList(
            new RectD(0, 0, 1872, 100)
        );
        GestureRouter.Token toolbar = router.begin(
            spread, 0, 100, 50, GestureRouter.Tool.STYLUS, chrome
        );
        equal(GestureRouter.Route.NATIVE_CHROME, toolbar.route,
            "chrome wins at DOWN");
        check(router.current(toolbar.id, 0) == toolbar,
            "route remains latched while moving out of chrome");
        check(router.finish(toolbar.id, 0), "finish chrome gesture");

        GestureRouter.Token active = router.begin(
            spread, 0, 100, 500, GestureRouter.Tool.STYLUS, chrome
        );
        equal(GestureRouter.Route.ACTIVE_DOCUMENT, active.route,
            "active pen native");
        check(router.finish(active.id, 0), "finish active gesture");

        GestureRouter.Token inactiveFinger = router.begin(
            spread, 0, 1200, 500, GestureRouter.Tool.FINGER, chrome
        );
        equal(GestureRouter.Route.ACTIVATE_AND_REPLAY_HIT,
            inactiveFinger.route, "inactive finger activation");
        check(router.finish(inactiveFinger.id, 0), "finish inactive finger");

        GestureRouter.Token inactivePen = router.begin(
            spread, 0, 1200, 500, GestureRouter.Tool.STYLUS, chrome
        );
        equal(GestureRouter.Route.ACTIVATE_AND_BUFFER_PEN,
            inactivePen.route, "inactive pen activation");
        SpreadSnapshot newer = spread(1, 1, 2, true);
        check(!router.authorityCurrent(inactivePen, newer),
            "layout replacement invalidates gesture authority");
        check(!router.finish(inactivePen.id, 1), "wrong pointer cannot finish");
        check(router.finish(inactivePen.id, 0), "right pointer finishes");

        GestureRouter.Token hiddenToolbar = router.begin(
            spread, 0, 100, 50, GestureRouter.Tool.STYLUS,
            Collections.<RectD>emptyList()
        );
        equal(GestureRouter.Route.ACTIVE_DOCUMENT, hiddenToolbar.route,
            "hidden toolbar rectangle is document again");
        check(router.finish(hiddenToolbar.id, 0), "finish hidden-toolbar pen");

        SpreadSnapshot blocked = spread(1, 1, 1, false);
        GestureRouter.Token noWriter = router.begin(
            blocked, 0, 100, 500, GestureRouter.Tool.STYLUS, chrome
        );
        equal(GestureRouter.Route.BLOCKED, noWriter.route,
            "unverified active writer fails closed");
        router.retire();
        GestureRouter.Token blockedInactive = router.begin(
            blocked, 0, 1200, 500, GestureRouter.Tool.STYLUS, chrome
        );
        equal(GestureRouter.Route.BLOCKED, blockedInactive.route,
            "unverified source cannot activate inactive page");
        router.retire();
        SpreadSnapshot cover = new SpreadSnapshot(
            "doc", 1, 2, 10, 0, SpreadSnapshot.Mode.SPREAD,
            PageSlot.blank(PageSlot.Side.LEFT, new RectD(0, 0, 936, 1404)),
            rightSlot(0), authority(0, 1, 2), true
        );
        GestureRouter.Token blank = router.begin(
            cover, 0, 100, 500, GestureRouter.Tool.STYLUS, chrome
        );
        equal(GestureRouter.Route.BLOCKED, blank.route,
            "blank page never owns input");
        router.retire();
        equal(GestureRouter.Route.ACTIVATE_AND_BUFFER_PEN,
            router.classifyHover(spread, 1200, 500,
                GestureRouter.Tool.STYLUS, chrome),
            "inactive hover preactivates");
    }

    private static void testGestureBuffer() {
        GestureBuffer buffer = new GestureBuffer(7, 4, 4 * 48, 100);
        check(buffer.append(7, sample(10, GestureBuffer.Action.DOWN)),
            "buffer down");
        check(buffer.append(7, sample(20, GestureBuffer.Action.MOVE)),
            "buffer move");
        check(buffer.append(7, sample(30, GestureBuffer.Action.UP)),
            "buffer up");
        check(buffer.isReplayable(), "complete pen gesture replayable");
        check(!buffer.append(7, sample(40, GestureBuffer.Action.MOVE)),
            "terminal rejects append");
        expectThrows(() -> buffer.immutableSamples().clear(),
            "buffer snapshot immutable");

        GestureBuffer wrongToken = new GestureBuffer(8, 4, 192, 100);
        check(!wrongToken.append(9, sample(0, GestureBuffer.Action.DOWN)),
            "wrong token rejected without mutation");
        check(wrongToken.append(8, sample(0, GestureBuffer.Action.DOWN)),
            "correct token still accepted");

        GestureBuffer overflow = new GestureBuffer(9, 2, 96, 100);
        check(overflow.append(9, sample(0, GestureBuffer.Action.DOWN)),
            "overflow fixture down");
        check(overflow.append(9, sample(1, GestureBuffer.Action.MOVE)),
            "overflow fixture move");
        check(!overflow.append(9, sample(2, GestureBuffer.Action.UP)),
            "sample overflow fails");
        check(overflow.isFailed(), "overflow latched failed");
        equal(0, overflow.immutableSamples().size(), "failed buffer clears data");

        GestureBuffer timeout = new GestureBuffer(10, 4, 192, 10);
        check(timeout.append(10, sample(0, GestureBuffer.Action.DOWN)),
            "timeout fixture down");
        check(!timeout.append(10, sample(11, GestureBuffer.Action.UP)),
            "duration overflow fails");
    }

    private static void testActivationHappyPaths() {
        SpreadSnapshot spread = spread(1, 1, 1, true);
        ActivationMachine machine = new ActivationMachine();
        machine.initialize(spread);
        ActivationMachine.Token token = machine.begin(spread, 0, true);
        check(token != null, "activation begins");
        status(machine, ActivationMachine.State.SOURCE_SAVING, 1, false);
        check(machine.sourceSaved(token), "source save accepted");
        check(!machine.targetLoaded(token, 1), "wrong load page rejected");
        check(machine.targetLoaded(token, 0), "target load accepted");
        check(!machine.targetVerified(token, authority(0, 1, 1)),
            "same-generation target authority rejected");
        check(!machine.targetVerified(token, authority(1, 1, 2)),
            "wrong writer page rejected");
        check(machine.targetVerified(token, authority(0, 1, 2)),
            "target authority verified");
        status(machine, ActivationMachine.State.TARGET_PUBLISHING, 0, false);
        SpreadSnapshot targetSnapshot = spread(0, 1, 2, true);
        check(machine.targetPublished(token, targetSnapshot),
            "target snapshot published atomically");
        status(machine, ActivationMachine.State.REPLAYING, 0, false);
        check(machine.replayComplete(token, authority(0, 1, 2)),
            "replay completion accepted");
        status(machine, ActivationMachine.State.ACTIVE, 0, true);

        ActivationMachine.Token noReplay = machine.begin(
            targetSnapshot, 1, false
        );
        check(noReplay != null, "second activation begins");
        check(machine.sourceSaved(noReplay), "second source saved");
        check(machine.targetLoaded(noReplay, 1), "second target loaded");
        check(machine.targetVerified(noReplay, authority(1, 1, 3)),
            "no-replay target verifies");
        check(machine.targetPublished(noReplay, spread(1, 1, 3, true)),
            "no-replay activation publishes");
        status(machine, ActivationMachine.State.ACTIVE, 1, true);
    }

    private static void testActivationRollbackAndStaleEvents() {
        SpreadSnapshot spread = spread(1, 2, 5, true);
        ActivationMachine machine = new ActivationMachine();
        machine.initialize(spread);
        ActivationMachine.Token token = machine.begin(spread, 0, false);
        check(machine.sourceSaved(token), "rollback source saved");
        check(machine.fail(token), "failure starts rollback");
        check(!machine.rollbackVerified(token, authority(1, 2, 4)),
            "stale layout rollback rejected");
        check(machine.rollbackVerified(token, authority(1, 2, 6)),
            "source rollback verified");
        status(machine, ActivationMachine.State.ROLLBACK_PUBLISHING, 1, false);
        SpreadSnapshot recovered = spread(1, 2, 6, true);
        check(machine.rollbackPublished(token, recovered),
            "rollback snapshot published atomically");
        status(machine, ActivationMachine.State.ACTIVE, 1, true);
        check(!machine.sourceSaved(token), "retired callback rejected");

        ActivationMachine.Token doomed = machine.begin(recovered, 0, false);
        check(doomed != null && machine.fail(doomed), "second failure");
        check(machine.rollbackFailed(doomed), "rollback failure disables");
        status(machine, ActivationMachine.State.DISABLED, 1, false);
        check(machine.begin(spread, 0, false) == null,
            "disabled machine cannot reactivate silently");
    }

    private static void testActivationConcurrency() throws Exception {
        SpreadSnapshot spread = spread(1, 3, 1, true);
        ActivationMachine machine = new ActivationMachine();
        machine.initialize(spread);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger winners = new AtomicInteger();
        Thread[] threads = new Thread[16];
        for (int index = 0; index < threads.length; index++) {
            threads[index] = new Thread(() -> {
                try {
                    start.await();
                    if (machine.begin(spread, 0, false) != null) {
                        winners.incrementAndGet();
                    }
                } catch (InterruptedException exception) {
                    throw new AssertionError(exception);
                }
            });
            threads[index].start();
        }
        start.countDown();
        for (Thread thread : threads) {
            thread.join();
        }
        equal(1, winners.get(), "exactly one activation owns writer");
    }

    private static void testSessionPublication() {
        SpreadSession session = new SpreadSession();
        SpreadSnapshot first = spread(1, 1, 1, true);
        check(session.publish(first), "first snapshot publishes");
        GestureRouter.Token token = session.gestures().begin(
            first, 0, 100, 500, GestureRouter.Tool.STYLUS,
            Collections.<RectD>emptyList()
        );
        check(session.gestures().authorityCurrent(token, first),
            "published gesture current");
        check(!session.publish(spread(1, 1, 1, true)),
            "same generation rejected");
        SpreadSnapshot second = spread(1, 1, 2, true);
        check(session.publish(second), "newer layout publishes");
        check(session.gestures().current(token.id, 0) == null,
            "layout publication retires contact");
        check(!session.publish(spread(1, 1, 1, true)),
            "older layout rejected");
        status(session.activation(), ActivationMachine.State.ACTIVE, 1, true);
        SpreadSnapshot wrongDocument = new SpreadSnapshot(
            "other", 1, 3, 10, 1, SpreadSnapshot.Mode.SPREAD,
            leftSlot(1), rightSlot(0),
            new NativeAuthority("other", 1, 3, 1, 11, 12, 13, 14, 1),
            true
        );
        check(!session.publish(wrongDocument),
            "session rejects document replacement");
        SpreadSnapshot wrongActivity = new SpreadSnapshot(
            "doc", 2, 3, 10, 1, SpreadSnapshot.Mode.SPREAD,
            leftSlot(1), rightSlot(0), authority(1, 2, 3), true
        );
        check(!session.publish(wrongActivity),
            "session rejects activity replacement");
        session.retire();
        check(session.snapshot() == null, "retire clears snapshot");
        status(session.activation(), ActivationMachine.State.DISABLED, -1, false);

        SpreadSession activationSession = new SpreadSession();
        SpreadSnapshot activationStart = spread(1, 7, 1, true);
        check(activationSession.publish(activationStart),
            "activation session initialized");
        ActivationMachine.Token activation = activationSession.activation()
            .begin(activationStart, 0, true);
        check(activationSession.activation().sourceSaved(activation),
            "session activation source saved");
        check(activationSession.activation().targetLoaded(activation, 0),
            "session activation target loaded");
        check(activationSession.activation().targetVerified(
            activation, authority(0, 7, 2)
        ), "session target verified");
        check(!activationSession.publish(spread(0, 7, 2, true)),
            "ordinary publication cannot bypass transaction");
        SpreadSnapshot activated = spread(0, 7, 2, true);
        check(activationSession.publishActivated(activation, activated),
            "transaction publishes exact verified snapshot");
        equal(0, activationSession.snapshot().activePageIndex,
            "activated source is published");
        status(activationSession.activation(),
            ActivationMachine.State.REPLAYING, 0, false);
        check(activationSession.activation().replayComplete(
            activation, authority(0, 7, 2)
        ), "session buffered replay finishes");
        status(activationSession.activation(),
            ActivationMachine.State.ACTIVE, 0, true);
    }

    private static SpreadSnapshot spread(
        int active,
        long activityGeneration,
        long layoutGeneration,
        boolean writerReady
    ) {
        return new SpreadSnapshot(
            "doc",
            activityGeneration,
            layoutGeneration,
            10,
            active,
            SpreadSnapshot.Mode.SPREAD,
            leftSlot(1),
            rightSlot(0),
            writerReady
                ? authority(active, activityGeneration, layoutGeneration)
                : null,
            writerReady
        );
    }

    private static PageSlot leftSlot(int page) {
        return new PageSlot(
            page,
            PageSlot.Side.LEFT,
            new RectD(0, 0, 1000, 1400),
            new RectD(0, 0, 936, 1404),
            new Affine2D(0.936, 0, 0, 0.936, 0, 46.8)
        );
    }

    private static PageSlot rightSlot(int page) {
        return new PageSlot(
            page,
            PageSlot.Side.RIGHT,
            new RectD(0, 0, 1000, 1400),
            new RectD(936, 0, 1872, 1404),
            new Affine2D(0.936, 0, 0, 0.936, 936, 46.8)
        );
    }

    private static NativeAuthority authority(
        int page,
        long activityGeneration,
        long layoutGeneration
    ) {
        return new NativeAuthority(
            "doc",
            activityGeneration,
            layoutGeneration,
            page,
            11,
            12,
            13,
            14,
            page
        );
    }

    private static GestureBuffer.Sample sample(
        long time,
        GestureBuffer.Action action
    ) {
        return new GestureBuffer.Sample(time, action, 10, 20, 0.5);
    }

    private static void status(
        ActivationMachine machine,
        ActivationMachine.State state,
        int page,
        boolean writer
    ) {
        ActivationMachine.Status status = machine.status();
        equal(state, status.state, "activation state");
        equal(page, status.activePage, "activation page");
        equal(writer, status.writerEnabled, "writer state");
    }

    private static void check(boolean condition, String message) {
        assertions++;
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    private static void equal(Object expected, Object actual, String message) {
        check(expected == null ? actual == null : expected.equals(actual),
            message + ": expected=" + expected + " actual=" + actual);
    }

    private static void near(
        double expected,
        double actual,
        double tolerance,
        String message
    ) {
        check(Math.abs(expected - actual) <= tolerance,
            message + ": expected=" + expected + " actual=" + actual);
    }

    private static void expectThrows(Runnable action, String message) {
        assertions++;
        try {
            action.run();
        } catch (RuntimeException expected) {
            return;
        }
        throw new AssertionError(message + ": expected exception");
    }
}
