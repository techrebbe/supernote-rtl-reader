package com.techrebbe.supernote.disposableleasehost;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;

import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

public final class HostContractTest {
    private static int checks;

    private static void check(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }

    private static void testNineChildContract() {
        check(ProbeContract.childCount() == 9, "exactly nine specs");
        Set<Integer> ids = new HashSet<>();
        Set<String> names = new HashSet<>();
        for (int i = 0; i < 9; i++) {
            ProbeContract.ChildSpec child = ProbeContract.childAt(i);
            check(child.id == 0x71000100 + i, "stable ordered ID " + i);
            check(ids.add(child.id), "unique ID");
            check(names.add(child.name), "unique name");
            check(child.column == i % 3 && child.row == i / 3, "grid position");
            check(child.image == (i == 0), "one image surrogate");
        }
        check("pdf_surrogate".equals(ProbeContract.childAt(0).name), "PDF role");
        check("digest_surrogate".equals(ProbeContract.childAt(1).name), "digest role");
        check("ink_surrogate".equals(ProbeContract.childAt(2).name), "ink role");
    }

    private static void testIndependentToggles() {
        ProbeModel model = new ProbeModel();
        check(model.page() == 1 && model.renderEpoch() == 0 && model.layoutEpoch() == 0,
                "initial epochs");
        String sourceA = model.uri();
        check(model.apply("page") && model.page() == 2, "page toggle");
        check(sourceA.equals(model.uri()) && model.renderEpoch() == 0
                && model.layoutEpoch() == 0, "page independent");
        check(model.apply("uri") && !sourceA.equals(model.uri()), "URI toggle");
        check(model.page() == 2 && model.renderEpoch() == 0, "URI independent");
        check(model.apply("render") && model.renderEpoch() == 1, "render toggle");
        check(model.page() == 2 && model.layoutEpoch() == 0, "render independent");
        check(model.apply("layout") && model.layoutEpoch() == 1
                && model.alternateLayout(), "layout toggle");
        check(model.apply("layout") && model.layoutEpoch() == 2
                && !model.alternateLayout(), "layout reversible");
        check(!model.apply("unknown"), "unknown command rejected");
        check(model.page() == 2 && model.renderEpoch() == 1
                && model.layoutEpoch() == 2, "unknown no-op");
    }

    private static void testBoundedEvents() {
        EventRing ring = new EventRing(3);
        check(ring.size() == 0 && ring.firstRetainedSequence() == 1, "empty ring");
        ring.append(10, "A", "one");
        ring.append(11, "B", "two");
        ring.append(12, "C", "three");
        ring.append(13, "D", "four");
        check(ring.size() == 3 && ring.firstRetainedSequence() == 2
                && ring.lastSequence() == 4, "bounded overwrite");
        EventRing.Event[] all = ring.after(0);
        check(all.length == 3 && all[0].sequence == 2 && all[2].sequence == 4,
                "retained event order");
        EventRing.Event[] tail = ring.after(3);
        check(tail.length == 1 && "D".equals(tail[0].name), "cursor query");
        StringBuilder detail = new StringBuilder();
        for (int i = 0; i < 300; i++) detail.append('x');
        check(ring.append(14, "E", detail.toString()).detail.length() == 160,
                "bounded event text");
    }

    private static void testPrimarySlot() {
        LeaseSlot slot = new LeaseSlot();
        Object first = new Object();
        Object second = new Object();
        check(slot.claim(first), "first owner admitted");
        check(!slot.claim(first) && !slot.claim(second), "no second start");
        check(!slot.release(second) && slot.occupied(), "foreign release rejected");
        check(slot.release(first) && !slot.occupied(), "exact owner release");
        check(!slot.release(first), "idempotent no-op after release");
        check(slot.claim(second) && slot.claims() == 2, "new owner after release");
    }

    private static void testSecondActivityRejected() {
        ActivityAdmission gate = new ActivityAdmission();
        Object first = new Object();
        Object firstRoot = new Object();
        Object second = new Object();
        Object secondRoot = new Object();
        check(gate.claim(first, firstRoot) == 1, "first activity admitted");
        check(gate.claim(second, secondRoot) == -1, "second activity rejected");
        check(gate.liveCount() == 1 && gate.activity() == first
                && gate.root() == firstRoot && gate.collisions() == 1,
                "collision cannot replace first root");
        check(!gate.release(second) && gate.activity() == first,
                "rejected activity cannot clear first");
        check(gate.release(first) && gate.liveCount() == 0,
                "exact first release");
        check(gate.claim(second, secondRoot) == 2 && gate.root() == secondRoot,
                "later activity gets new serial and root");
    }

    private static void testPaintRequiresPostEventFrame() {
        PaintEpoch paint = new PaintEpoch();
        check(!paint.fresh(), "no frame is not fresh");
        paint.completeFrame(paint.beginFrame());
        check(paint.fresh(), "initial completed frame");
        paint.invalidate(); // synthetic command without a layout pass
        check(!paint.fresh(), "pre-command frame is stale");
        long started = paint.beginFrame();
        paint.invalidate(); // resume or cleanup during a frame
        paint.completeFrame(started);
        check(!paint.fresh(), "mid-frame invalidation rejects that frame");
        paint.completeFrame(paint.beginFrame());
        check(paint.fresh(), "only subsequent complete frame is fresh");
        paint.invalidate(); // view removal with the same layout pass
        check(!paint.fresh(), "pre-cleanup frame is stale");
        paint.completeFrame(paint.beginFrame());
        check(paint.fresh(), "post-cleanup frame required");
    }

    private static void testCoverRequestRaces() {
        CoverGate gate = new CoverGate();
        long first = gate.requestCover();
        check(first > 0 && gate.requestCover() == -1, "repeated cover rejected");
        check(gate.requestUncover() == CoverGate.Uncover.DEFERRED,
                "immediate uncover deferred");
        check(gate.activate(first + 1) == CoverGate.Activation.REJECTED,
                "stale cover cannot activate");
        check(gate.activate(first) == CoverGate.Activation.FINISH_IMMEDIATELY,
                "deferred uncover finishes arriving cover");
        check(gate.requestCover() == -1, "no new cover until old destroyed");
        check(gate.requestUncover() == CoverGate.Uncover.ALREADY_FINISHING,
                "repeated uncover idempotent");
        check(!gate.destroyed(first + 1) && gate.destroyed(first),
                "only matching cover ends request");
        long second = gate.requestCover();
        check(second > first && gate.activate(second) == CoverGate.Activation.ACTIVE,
                "new generation after cleanup");
        check(gate.requestUncover() == CoverGate.Uncover.FINISH_ACTIVE,
                "active cover requested to finish");
        check(gate.destroyed(second) && "IDLE".equals(gate.state()),
                "cover returns idle only after destroy");
        check(gate.requestUncover() == CoverGate.Uncover.REJECTED,
                "idle uncover rejected");
    }

    private static void testCoherentConcurrentLedger() throws Exception {
        final ProbeLedger ledger = new ProbeLedger(64);
        final Object owner = new Object();
        final AtomicReference<Throwable> failure = new AtomicReference<>();
        final CountDownLatch go = new CountDownLatch(1);
        Thread writer = new Thread(new Runnable() {
            @Override public void run() {
                try {
                    go.await();
                    for (int i = 0; i < 1000; i++) {
                        if (!ledger.claim(i * 2L, owner)
                                || !ledger.release(i * 2L + 1L, owner)) {
                            throw new AssertionError("writer slot cycle failed");
                        }
                    }
                } catch (Throwable error) { failure.compareAndSet(null, error); }
            }
        });
        Thread reader = new Thread(new Runnable() {
            @Override public void run() {
                try {
                    go.await();
                    for (int i = 0; i < 1000; i++) {
                        ProbeLedger.Snapshot cut = ledger.snapshot(0);
                        long expected = cut.slotClaimCount * 2
                                - (cut.slotOccupied ? 1 : 0);
                        if (cut.lastSequence != expected) {
                            throw new AssertionError("torn slot/event cut");
                        }
                        if (cut.events.length > 64) {
                            throw new AssertionError("unbounded event window");
                        }
                        if (cut.events.length > 0) {
                            if (cut.events[0].sequence != cut.firstRetainedSequence
                                    || cut.events[cut.events.length - 1].sequence
                                            != cut.lastSequence) {
                                throw new AssertionError("torn event bounds");
                            }
                        }
                    }
                } catch (Throwable error) { failure.compareAndSet(null, error); }
            }
        });
        writer.start();
        reader.start();
        go.countDown();
        writer.join(10000);
        reader.join(10000);
        check(!writer.isAlive() && !reader.isAlive(), "concurrency test completed");
        check(failure.get() == null, "coherent slot/event snapshots under concurrency"
                + (failure.get() == null ? "" : ": " + failure.get()));
        ProbeLedger.Snapshot finalCut = ledger.snapshot(0);
        check(finalCut.lastSequence == 2000 && !finalCut.slotOccupied
                && finalCut.slotClaimCount == 1000, "final coherent ledger");
    }

    private static void testManifestAndConstruction(String manifestPath, String activityPath)
            throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        Document document = factory.newDocumentBuilder().parse(manifestPath);
        Element manifest = document.getDocumentElement();
        check("com.techrebbe.supernote.disposableleasehost".equals(
                manifest.getAttribute("package")), "isolated package");
        check(document.getElementsByTagName("uses-permission").getLength() == 0,
                "no Android permissions");
        Element sdk = (Element) document.getElementsByTagName("uses-sdk").item(0);
        check("30".equals(sdk.getAttribute("android:minSdkVersion"))
                && "30".equals(sdk.getAttribute("android:targetSdkVersion")),
                "API30 contract");
        Element app = (Element) document.getElementsByTagName("application").item(0);
        check(".ProbeApplication".equals(app.getAttribute("android:name")),
                "primary application root");
        Element activity = (Element) document.getElementsByTagName("activity").item(0);
        check("singleTask".equals(activity.getAttribute("android:launchMode")),
                "second launcher intent reuses live activity");
        String source = new String(Files.readAllBytes(Paths.get(activityPath)),
                StandardCharsets.UTF_8);
        check(source.contains("root.addView(child, params);")
                && !source.contains("root.removeView")
                && !source.contains("root.removeAllViews"),
                "host only adds original views");
        int configuration = source.indexOf("onConfigurationChanged(Configuration configuration)");
        int focus = source.indexOf("onWindowFocusChanged", configuration);
        check(configuration >= 0 && focus > configuration
                && source.substring(configuration, focus).contains("applyLayoutPadding();"),
                "orientation applies layout-epoch padding parity");
        check(source.contains("paintFreshForRevision()")
                && source.contains("onViewRemoved(View child)")
                && source.contains("ROOT_CHILD_REMOVED"),
                "cleanup invalidates paint freshness");
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 2) throw new IllegalArgumentException("manifest and activity paths");
        testNineChildContract();
        testIndependentToggles();
        testBoundedEvents();
        testPrimarySlot();
        testSecondActivityRejected();
        testPaintRequiresPostEventFrame();
        testCoverRequestRaces();
        testCoherentConcurrentLedger();
        testManifestAndConstruction(args[0], args[1]);
        System.out.println("HOST_CONTRACT_PASS checks=" + checks);
    }
}
