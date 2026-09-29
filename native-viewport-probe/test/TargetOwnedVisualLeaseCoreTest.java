package com.techrebbe.supernote.viewportprobe;

import com.techrebbe.supernote.viewportprobe.TargetOwnedVisualLeaseCore.Port;
import com.techrebbe.supernote.viewportprobe.TargetOwnedVisualLeaseCore.DrawGate;
import com.techrebbe.supernote.viewportprobe.TargetOwnedVisualLeaseCore.PaintFrame;
import com.techrebbe.supernote.viewportprobe.TargetOwnedVisualLeaseCore.PageWriterWitness;
import com.techrebbe.supernote.viewportprobe.TargetOwnedVisualLeaseCore.Reason;
import com.techrebbe.supernote.viewportprobe.TargetOwnedVisualLeaseCore.Registration;
import com.techrebbe.supernote.viewportprobe.TargetOwnedVisualLeaseCore.Result;
import com.techrebbe.supernote.viewportprobe.TargetOwnedVisualLeaseCore.Slot;
import com.techrebbe.supernote.viewportprobe.TargetOwnedVisualLeaseCore.Snapshot;
import com.techrebbe.supernote.viewportprobe.TargetOwnedVisualLeaseCore.State;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.IdentityHashMap;
import java.util.Iterator;
import java.util.List;

public final class TargetOwnedVisualLeaseCoreTest {
    private static int checks;

    // Deliberately hostile: equality cannot identify any child or its parent.
    private static class Identity {
        final String name;
        Identity(String name) { this.name = name; }
        @Override public boolean equals(Object other) { return other instanceof Identity; }
        @Override public int hashCode() { return 1; }
        @Override public String toString() { return name; }
    }

    private static final class GateBoundChild extends Identity {
        final DrawGate drawGate;
        GateBoundChild(DrawGate drawGate) {
            super("owned");
            this.drawGate = drawGate;
        }
    }

    private static final class Event {
        final long due;
        final long order;
        final Runnable callback;
        Event(long due, long order, Runnable callback) {
            this.due = due;
            this.order = order;
            this.callback = callback;
        }
    }

    private static final class FakePort implements Port {
        final Identity root = new Identity("root");
        final Identity foreignParent = new Identity("foreign parent");
        final Identity[] original = new Identity[9];
        final List<Object> children = new ArrayList<Object>();
        final List<Object> effectiveDrawOrder = new ArrayList<Object>();
        final IdentityHashMap<Object, Object> parents = new IdentityHashMap<Object, Object>();
        final IdentityHashMap<Object, String> evidence = new IdentityHashMap<Object, String>();
        final IdentityHashMap<Object, Boolean> paintExpected =
                new IdentityHashMap<Object, Boolean>();
        final List<Event> events = new ArrayList<Event>();
        long now = 100;
        long evidenceMutationRevision = 1;
        long pageWriterRevision = 1;
        long startedPaintRevision = 1;
        PaintFrame lastCompletedPaintFrame;
        long nextOrder;
        long dispatchDelay;
        boolean processAlive = true;
        boolean rootAlive = true;
        boolean onMainThread = true;
        boolean useLegacyAllVisibleSnapshot;
        boolean inlineDispatch;
        boolean lossChangesHostState;
        Reason lossOnCancel;
        Reason lossOnRelease;
        Reason lossOnPostReleaseRootRead;
        int signalOnPostReleaseRootRead;
        int rootReadsAfterRelease;
        boolean callbacksReleased;
        boolean beginUnfinishedPaintOnRelease;
        boolean driftSceneOnReleasePaintRead;
        boolean driftSceneOnFinalSnapshot;
        boolean pageWriterWitnessAvailable = true;
        boolean pageWriterRevisionAvailable = true;
        boolean useDefaultPageWriterMethods;
        boolean writerAbaDuringAdd;
        boolean writerAbaOnRelease;
        boolean stopOnPostReleaseWriterRead;
        boolean abaAfterSecondReleasedWriterRead;
        boolean abaOnNextClockRead;
        int pageWriterReadsAfterRelease;
        Runnable afterNextPageWriterWitnessRead;
        int snapshotsUntilSceneDrift;
        TargetOwnedVisualLeaseCore activeLease;
        boolean armed;
        boolean addSawDeadline;
        long deadlineDelay = -1;
        long armAdvance;
        long scheduleAdvance;
        long snapshotAdvance;
        long nextCompletedPaintReadAdvance;
        long addAdvance;
        boolean nullRegistration;
        boolean firePauseWhileArming;
        boolean driftWhileArming;
        boolean changeSceneWhileArming;
        boolean reorderWhileArming;
        boolean loseRootWhileArming;
        boolean loseProcessWhileArming;
        boolean detachRootAfterAdd;
        boolean snapshotFailure;
        Runnable afterNextSnapshot;
        Runnable afterNextCompletedPaintRead;
        int removeCalls;
        int addCalls;
        DrawGate gateSeenAtAdd;
        boolean throwBeforeAdd;
        boolean throwAfterAttach;
        boolean sceneAbaDuringAdd;
        int paintInsertSlot = 1;
        boolean autoAddPaint = true;
        boolean autoRemovePaint = true;
        boolean dropPaintOrderAfterRemove;
        boolean paintOrderUnavailable;
        int snapshotsWithoutPaintOrder;
        boolean beginPaintDuringAdd;
        boolean beginPaintBeforeRemove;
        boolean failPaintScheduleAfterAdd;
        boolean failPaintScheduleAfterRemove;
        boolean failNextSchedule;
        boolean failNextDispatch;
        Runnable lastScheduledCallback;
        int drawRequests;
        boolean throwBeforeRemove;
        boolean throwAfterRemove;
        long removeAdvance;
        String scene = "page A|uri A|render A|root 1404x1872|epoch 1";
        Identity pageIdentity = new Identity("page A");
        Identity writerIdentity = new Identity("native writer A");
        boolean writerEnabled = true;
        String drawPolicy = "default child order|no transient children|all Z zero";
        Runnable pause;
        Runnable rootLoss;
        Runnable drift;

        FakePort() {
            for (int i = 0; i < 9; i++) {
                original[i] = new Identity("stock " + i);
                children.add(original[i]);
                effectiveDrawOrder.add(original[i]);
                parents.put(original[i], root);
                evidence.put(original[i], "class|id|visibility|bounds|z|layout " + i);
                paintExpected.put(original[i], true);
            }
            lastCompletedPaintFrame = new PaintFrame(startedPaintRevision, now, snapshot());
        }

        void setStockSevenVisible(boolean visible) {
            Object stockSeven = original[7];
            if (paintExpected.get(stockSeven) == Boolean.valueOf(visible)) {
                throw new AssertionError("stock seven visibility did not change");
            }
            evidenceMutationRevision++;
            paintExpected.put(stockSeven, visible);
            evidence.put(stockSeven, "class|id|visibility="
                    + (visible ? "VISIBLE" : "GONE") + "|bounds|z|layout 7");
            if (visible) {
                effectiveDrawOrder.add(effectiveDrawOrder.indexOf(original[8]), stockSeven);
            } else {
                for (Iterator<Object> iter = effectiveDrawOrder.iterator(); iter.hasNext();) {
                    if (iter.next() == stockSeven) { iter.remove(); break; }
                }
            }
        }

        void completeFreshPaintNow() {
            long revision = ++startedPaintRevision;
            lastCompletedPaintFrame = new PaintFrame(revision, now, snapshot());
        }

        void useCustomPaintOrder() {
            // The controlled root exposes this actual non-default order; it
            // is not inferred from direct-child indices or an inserted child.
            evidenceMutationRevision++;
            Object stockOne = effectiveDrawOrder.remove(1);
            effectiveDrawOrder.add(2, stockOne);
            drawPolicy = "custom stable sibling order|no transients|all Z zero";
            paintInsertSlot = 2;
            lastCompletedPaintFrame = new PaintFrame(startedPaintRevision, now, snapshot());
        }

        @Override public long evidenceMutationRevision() {
            return evidenceMutationRevision;
        }
        @Override public long pageWriterMutationRevision() {
            if (useDefaultPageWriterMethods) return Port.super.pageWriterMutationRevision();
            return pageWriterRevisionAvailable ? pageWriterRevision : -1;
        }
        @Override public PageWriterWitness pageWriterWitness() {
            if (useDefaultPageWriterMethods) return Port.super.pageWriterWitness();
            if (!pageWriterWitnessAvailable) return null;
            PageWriterWitness captured = new PageWriterWitness(
                    pageIdentity, writerIdentity, writerEnabled, pageWriterRevision);
            if (afterNextPageWriterWitnessRead != null) {
                Runnable hook = afterNextPageWriterWitnessRead;
                afterNextPageWriterWitnessRead = null;
                hook.run();
            }
            if (callbacksReleased && stopOnPostReleaseWriterRead) {
                stopOnPostReleaseWriterRead = false;
                activeLease.requestCleanup(Reason.DRIFT);
            }
            if (callbacksReleased && ++pageWriterReadsAfterRelease == 2
                    && abaAfterSecondReleasedWriterRead) {
                abaOnNextClockRead = true;
            }
            return captured;
        }
        void abaWriterEnablement() {
            pageWriterRevision++;
            writerEnabled = !writerEnabled;
            pageWriterRevision++;
            writerEnabled = !writerEnabled;
        }
        @Override public void requireMainThread() {
            if (!onMainThread) throw new IllegalStateException("not on main thread");
        }
        @Override public long elapsedRealtimeMillis() {
            if (abaOnNextClockRead) {
                abaOnNextClockRead = false;
                abaWriterEnablement();
            }
            return now;
        }
        @Override public long startedPaintRevision() { return startedPaintRevision; }
        @Override public PaintFrame lastCompletedPaintFrame() {
            now += nextCompletedPaintReadAdvance;
            nextCompletedPaintReadAdvance = 0;
            PaintFrame completed = lastCompletedPaintFrame;
            if (afterNextCompletedPaintRead != null) {
                Runnable hook = afterNextCompletedPaintRead;
                afterNextCompletedPaintRead = null;
                hook.run();
            }
            return completed;
        }
        @Override public boolean processAlive() { return processAlive; }
        @Override public boolean rootAlive() { return rootAlive; }
        @Override public Object root() {
            if (callbacksReleased && lossOnPostReleaseRootRead != null) {
                rootReadsAfterRelease++;
                if (rootReadsAfterRelease == signalOnPostReleaseRootRead) {
                    activeLease.requestCleanup(lossOnPostReleaseRootRead);
                }
            }
            return root;
        }
        @Override public Snapshot snapshot() {
            if (snapshotFailure) throw new IllegalStateException("snapshot unavailable");
            now += snapshotAdvance;
            Object[] seen = children.toArray(new Object[children.size()]);
            Object[] seenParents = new Object[seen.length];
            String[] seenEvidence = new String[seen.length];
            boolean[] seenPaintExpected = new boolean[seen.length];
            for (int i = 0; i < seen.length; i++) {
                seenParents[i] = parents.get(seen[i]);
                seenEvidence[i] = evidence.get(seen[i]);
                seenPaintExpected[i] = paintExpected.get(seen[i]) == Boolean.TRUE;
            }
            if (paintOrderUnavailable) snapshotsWithoutPaintOrder++;
            Object[] painted = paintOrderUnavailable ? new Object[0]
                    : effectiveDrawOrder.toArray(new Object[effectiveDrawOrder.size()]);
            Snapshot captured = useLegacyAllVisibleSnapshot
                    ? new Snapshot(root, seen, seenParents, seenEvidence,
                            painted, drawPolicy, scene)
                    : new Snapshot(root, seen, seenParents, seenEvidence,
                            seenPaintExpected, painted, drawPolicy, scene);
            if (afterNextSnapshot != null) {
                Runnable hook = afterNextSnapshot;
                afterNextSnapshot = null;
                hook.run();
            }
            if (snapshotsUntilSceneDrift > 0 && --snapshotsUntilSceneDrift == 0) {
                evidenceMutationRevision++;
                scene = "page B|uri B|render B|root 1404x1872|epoch 2";
            }
            return captured;
        }
        @Override public Object parentOf(Object child) { return parents.get(child); }
        @Override public void add(Object child, int provenSlot, DrawGate drawGate) {
            addCalls++;
            require(armed, "lifecycle callbacks were not armed before add");
            require(addSawDeadline, "target deadline was not armed before add");
            if (!(child instanceof GateBoundChild)
                    || ((GateBoundChild) child).drawGate != drawGate) {
                throw new IllegalStateException("factory child lacks exact draw gate");
            }
            gateSeenAtAdd = drawGate;
            require(!gateSeenAtAdd.mayDraw(),
                    "factory child lacked a closed draw gate before add");
            if (throwBeforeAdd) throw new IllegalStateException("before add");
            evidenceMutationRevision++;
            children.add(provenSlot, child);
            effectiveDrawOrder.add(paintInsertSlot, child);
            parents.put(child, root);
            evidence.put(child, "owned visual only");
            paintExpected.put(child, true);
            if (writerAbaDuringAdd) abaWriterEnablement();
            if (sceneAbaDuringAdd) {
                String originalScene = scene;
                evidenceMutationRevision++;
                scene = "page B|uri B|render B|root 1404x1872|epoch 2";
                evidenceMutationRevision++;
                scene = originalScene;
            }
            if (beginPaintDuringAdd) {
                final long staleRevision = ++startedPaintRevision;
                schedulePaintCompletion(staleRevision, 1);
            } else if (autoAddPaint) {
                scheduleFreshPaint(1);
            }
            now += addAdvance;
            if (failPaintScheduleAfterAdd) failNextSchedule = true;
            if (detachRootAfterAdd) rootAlive = false;
            if (throwAfterAttach) throw new IllegalStateException("attached then threw");
        }
        @Override public void remove(Object child) {
            removeCalls++;
            if (throwBeforeRemove) throw new IllegalStateException("before remove");
            evidenceMutationRevision++;
            final long staleRevision = beginPaintBeforeRemove ? ++startedPaintRevision : -1;
            boolean found = false;
            for (Iterator<Object> iter = children.iterator(); iter.hasNext();) {
                if (iter.next() == child) {
                    iter.remove();
                    found = true;
                    break;
                }
            }
            if (found) parents.remove(child);
            if (found) paintExpected.remove(child);
            for (Iterator<Object> iter = effectiveDrawOrder.iterator(); iter.hasNext();) {
                if (iter.next() == child) {
                    iter.remove();
                    break;
                }
            }
            if (dropPaintOrderAfterRemove) {
                paintOrderUnavailable = true;
                lastCompletedPaintFrame = null;
            }
            now += removeAdvance;
            if (staleRevision > 0) schedulePaintCompletion(staleRevision, 1);
            else if (autoRemovePaint) scheduleFreshPaint(1);
            if (failPaintScheduleAfterRemove) failNextSchedule = true;
            if (throwAfterRemove) throw new IllegalStateException("after remove");
        }
        @Override public void requestDraw(Object child) {
            require(parents.get(child) == root, "requestDraw on detached child");
            drawRequests++;
        }
        void scheduleFreshPaint(long delay) {
            events.add(new Event(now + delay, nextOrder++, new Runnable() {
                @Override public void run() {
                    long begun = ++startedPaintRevision;
                    paintOrderUnavailable = false;
                    lastCompletedPaintFrame = new PaintFrame(begun, now, snapshot());
                }
            }));
        }
        void schedulePaintCompletion(final long begunRevision, long delay) {
            events.add(new Event(now + delay, nextOrder++, new Runnable() {
                @Override public void run() {
                    lastCompletedPaintFrame = new PaintFrame(begunRevision, now, snapshot());
                }
            }));
        }
        @Override public void dispatch(Runnable callback) {
            if (failNextDispatch) {
                failNextDispatch = false;
                throw new IllegalStateException("injected Handler dispatch failure");
            }
            if (inlineDispatch) callback.run();
            else schedule(callback, dispatchDelay);
        }
        @Override public void schedule(Runnable callback, long delayMillis) {
            require(delayMillis >= 0, "negative delay");
            if (failNextSchedule) {
                failNextSchedule = false;
                throw new IllegalStateException("injected Handler post failure");
            }
            events.add(new Event(now + delayMillis, nextOrder++, callback));
            lastScheduledCallback = callback;
            if (armed && !addSawDeadline && delayMillis > 0) {
                addSawDeadline = true;
                deadlineDelay = delayMillis;
                now += scheduleAdvance;
            }
        }
        @Override public void cancel(Runnable callback) {
            if (lossOnCancel != null) signalLoss(lossOnCancel);
            for (Iterator<Event> iter = events.iterator(); iter.hasNext();) {
                if (iter.next().callback == callback) iter.remove();
            }
        }
        @Override public Registration armLifecycle(Runnable onPause, Runnable onRootLoss,
                Runnable onPageOrLayoutDrift) {
            if (nullRegistration) return null;
            armed = true;
            pause = onPause;
            rootLoss = onRootLoss;
            drift = onPageOrLayoutDrift;
            now += armAdvance;
            if (changeSceneWhileArming) {
                evidenceMutationRevision++;
                scene = "page B|uri B|render B|epoch 2";
            }
            if (reorderWhileArming) {
                evidenceMutationRevision++;
                Object first = children.get(0);
                children.set(0, children.get(1));
                children.set(1, first);
            }
            if (loseRootWhileArming) rootAlive = false;
            if (loseProcessWhileArming) processAlive = false;
            if (firePauseWhileArming) pause.run();
            if (driftWhileArming) drift.run();
            return new Registration() {
                @Override public void release() {
                    if (lossOnRelease != null) signalLoss(lossOnRelease);
                    if (beginUnfinishedPaintOnRelease) startedPaintRevision++;
                    if (driftSceneOnReleasePaintRead) {
                        afterNextCompletedPaintRead = new Runnable() {
                            @Override public void run() {
                                evidenceMutationRevision++;
                                scene = "page B|uri B|render B|root 1404x1872|epoch 2";
                            }
                        };
                    }
                    if (driftSceneOnFinalSnapshot) snapshotsUntilSceneDrift = 2;
                    if (writerAbaOnRelease) abaWriterEnablement();
                    armed = false;
                    pause = null;
                    rootLoss = null;
                    drift = null;
                    callbacksReleased = true;
                }
            };
        }

        private void signalLoss(Reason loss) {
            if (loss == Reason.ROOT_LOSS) {
                if (lossChangesHostState) rootAlive = false;
                rootLoss.run();
            } else if (loss == Reason.PROCESS_LOSS) {
                if (lossChangesHostState) processAlive = false;
                activeLease.requestCleanup(Reason.PROCESS_LOSS);
            } else {
                throw new AssertionError("not a loss signal");
            }
        }

        void runReady() {
            for (int steps = 0; steps < 100; steps++) {
                Event next = null;
                for (Event candidate : events) {
                    if (candidate.due <= now && (next == null || candidate.due < next.due
                            || (candidate.due == next.due && candidate.order < next.order))) {
                        next = candidate;
                    }
                }
                if (next == null) return;
                events.remove(next);
                next.callback.run();
            }
            throw new AssertionError("callback loop did not settle");
        }
        void advance(long millis) {
            long target = now + millis;
            for (int steps = 0; steps < 100; steps++) {
                Event next = null;
                for (Event candidate : events) {
                    if (candidate.due <= target && (next == null
                            || candidate.due < next.due
                            || (candidate.due == next.due && candidate.order < next.order))) {
                        next = candidate;
                    }
                }
                if (next == null) break;
                now = Math.max(now, next.due);
                events.remove(next);
                next.callback.run();
            }
            now = Math.max(now, target);
            runReady();
        }
        void exactNine() {
            require(children.size() == 9, "wrong child count");
            require(effectiveDrawOrder.size() == 9, "wrong effective draw count");
            for (int i = 0; i < 9; i++) {
                require(children.get(i) == original[i], "wrong child identity/order at " + i);
                require(effectiveDrawOrder.get(i) == original[i],
                        "wrong effective draw identity/order at " + i);
                require(parents.get(original[i]) == root, "stock child moved");
            }
        }
        void exactNineWithGoneSeven() {
            require(children.size() == 9, "wrong structural child count after GONE rollback");
            require(effectiveDrawOrder.size() == 8, "wrong GONE paint count");
            for (int i = 0; i < 9; i++) {
                require(children.get(i) == original[i], "GONE structural order at " + i);
                require(parents.get(original[i]) == root, "GONE structural parent at " + i);
                require(paintExpected.get(original[i]) == Boolean.valueOf(i != 7),
                        "GONE paint expectation at " + i);
                if (i != 7) {
                    int paintAt = i < 7 ? i : i - 1;
                    require(effectiveDrawOrder.get(paintAt) == original[i],
                            "GONE paint order at " + i);
                }
            }
        }
        void removeOwnedExternally(Object owned) {
            evidenceMutationRevision++;
            for (Iterator<Object> iter = children.iterator(); iter.hasNext();) {
                if (iter.next() == owned) { iter.remove(); break; }
            }
            for (Iterator<Object> iter = effectiveDrawOrder.iterator(); iter.hasNext();) {
                if (iter.next() == owned) { iter.remove(); break; }
            }
            parents.remove(owned);
            paintExpected.remove(owned);
        }
        boolean containsIdentity(Object child) {
            for (Object candidate : children) if (candidate == child) return true;
            return false;
        }
    }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }

    private static void requirePaintOrder(FakePort port, Object[] expected, String message) {
        require(port.effectiveDrawOrder.size() == expected.length, message + " length");
        for (int i = 0; i < expected.length; i++) {
            require(port.effectiveDrawOrder.get(i) == expected[i], message + " at " + i);
        }
    }

    private static void requireCapturedTenChildFrame(PaintFrame frame, Object owned,
            Object stockFour, String stockFourEvidence, String message) {
        if (frame == null) throw new AssertionError(message + ": no completed frame");
        try {
            Field childrenField = Snapshot.class.getDeclaredField("children");
            Field evidenceField = Snapshot.class.getDeclaredField("childEvidence");
            childrenField.setAccessible(true);
            evidenceField.setAccessible(true);
            Object[] capturedChildren = (Object[]) childrenField.get(frame.snapshot);
            String[] capturedEvidence = (String[]) evidenceField.get(frame.snapshot);
            require(capturedChildren.length == 10 && capturedEvidence.length == 10
                    && capturedChildren[1] == owned && capturedChildren[5] == stockFour
                    && stockFourEvidence.equals(capturedEvidence[5]), message);
        } catch (ReflectiveOperationException reflectionFailure) {
            throw new AssertionError(message, reflectionFailure);
        }
    }

    private static TargetOwnedVisualLeaseCore start(Slot slot, FakePort port) {
        return start(slot, port,
                new TargetOwnedVisualLeaseCore.Factory() {
                    @Override public Object create(DrawGate drawGate) { return new GateBoundChild(drawGate); }
                });
    }

    private static TargetOwnedVisualLeaseCore start(Slot slot, FakePort port,
            TargetOwnedVisualLeaseCore.Factory factory) {
        TargetOwnedVisualLeaseCore lease = TargetOwnedVisualLeaseCore.startForTest(
                slot, port, factory, 1, 1, 50, 10, 10, 40);
        if (lease.state() == State.PREPARED && port.autoAddPaint) port.advance(1);
        return lease;
    }

    private static void testPreboundDrawGate() {
        FakePort port = new FakePort();
        port.autoAddPaint = false;
        Slot slot = new Slot();
        final DrawGate[] supplied = new DrawGate[1];
        final GateBoundChild[] created = new GateBoundChild[1];
        TargetOwnedVisualLeaseCore lease = start(slot, port,
                new TargetOwnedVisualLeaseCore.Factory() {
                    @Override public Object create(DrawGate drawGate) {
                        require(drawGate != null && slot.occupied()
                                && port.addCalls == 0 && port.children.size() == 9,
                                "draw gate was not supplied before child construction/add");
                        require(!drawGate.mayDraw(),
                                "newly supplied factory gate permitted pending pixels");
                        supplied[0] = drawGate;
                        created[0] = new GateBoundChild(drawGate);
                        return created[0];
                    }
                });
        require(lease.ownedChild() == created[0]
                && port.gateSeenAtAdd == supplied[0]
                && created[0].drawGate == supplied[0]
                && lease.state() == State.PREPARED
                && !supplied[0].mayDraw() && port.drawRequests == 0,
                "add did not receive the exact prebound, pixel-silent gate");
        port.scheduleFreshPaint(1);
        port.advance(2);
        require(lease.state() == State.INSERTED && supplied[0].mayDraw(),
                "prebound gate did not open after completed-paint admission");
        lease.requestCleanup(Reason.HOST_STOP);
        require(!supplied[0].mayDraw(), "queued stop left prebound gate drawable");
        port.runReady();
        port.advance(2);
        require(lease.state() == State.REMOVED
                && lease.result() == Result.LIVE_STRUCTURE_RESTORED
                && !supplied[0].mayDraw(),
                "prebound gate reopened after verified rollback");
    }

    private static void testPortRejectsWrongDrawGate() {
        FakePort anchorPort = new FakePort();
        final DrawGate[] oldGate = new DrawGate[1];
        TargetOwnedVisualLeaseCore anchor = start(new Slot(), anchorPort,
                new TargetOwnedVisualLeaseCore.Factory() {
                    @Override public Object create(DrawGate drawGate) {
                        oldGate[0] = drawGate;
                        return new GateBoundChild(drawGate);
                    }
                });
        anchor.requestCleanup(Reason.HOST_STOP);
        anchorPort.runReady();
        anchorPort.advance(2);
        require(oldGate[0] != null && !oldGate[0].mayDraw()
                && anchor.result() == Result.LIVE_STRUCTURE_RESTORED,
                "wrong-gate fixture did not retire its first gate");

        FakePort unboundPort = new FakePort();
        Slot unboundSlot = new Slot();
        TargetOwnedVisualLeaseCore unbound = start(unboundSlot, unboundPort,
                new TargetOwnedVisualLeaseCore.Factory() {
                    @Override public Object create(DrawGate drawGate) {
                        return new GateBoundChild(null);
                    }
                });
        require(unbound.state() == State.REMOVING
                && unboundPort.addCalls == 1 && unboundPort.removeCalls == 0
                && unboundPort.children.size() == 9 && unboundPort.gateSeenAtAdd == null,
                "Port.add accepted a child without the supplied gate");
        unboundPort.advance(1);
        require(unbound.state() == State.REMOVED && unbound.result() == Result.UNKNOWN
                && unbound.failure() != null && !unboundSlot.occupied(),
                "unbound child failure escaped safe unattached cleanup");
        unboundPort.exactNine();

        FakePort wrongPort = new FakePort();
        Slot wrongSlot = new Slot();
        final DrawGate[] offeredGate = new DrawGate[1];
        TargetOwnedVisualLeaseCore wrong = start(wrongSlot, wrongPort,
                new TargetOwnedVisualLeaseCore.Factory() {
                    @Override public Object create(DrawGate drawGate) {
                        offeredGate[0] = drawGate;
                        return new GateBoundChild(oldGate[0]);
                    }
                });
        require(offeredGate[0] != null && offeredGate[0] != oldGate[0]
                && wrong.state() == State.REMOVING
                && wrongPort.addCalls == 1 && wrongPort.removeCalls == 0
                && wrongPort.children.size() == 9 && wrongPort.gateSeenAtAdd == null,
                "Port.add accepted a child bound to a foreign gate");
        wrongPort.advance(1);
        require(wrong.state() == State.REMOVED && wrong.result() == Result.UNKNOWN
                && wrong.failure() != null && !wrongSlot.occupied(),
                "foreign gate failure escaped safe unattached cleanup");
        wrongPort.exactNine();
    }

    private static void testNormalAndCollision() {
        Slot slot = new Slot();
        FakePort port = new FakePort();
        TargetOwnedVisualLeaseCore lease = start(slot, port);
        require(lease.state() == State.INSERTED, "not inserted");
        require(port.children.size() == 10 && port.children.get(1) == lease.ownedChild(),
                "wrong insertion slot");
        require(port.effectiveDrawOrder.size() == 10
                && port.effectiveDrawOrder.get(1) == lease.ownedChild()
                && port.effectiveDrawOrder.get(2) == port.original[1],
                "effective paint insertion did not shift the original rank");
        require(lease.mayDraw(), "live draw denied");
        try {
            start(slot, new FakePort());
            throw new AssertionError("second lease admitted");
        } catch (IllegalStateException expected) { checks++; }
        lease.requestCleanup(Reason.HOST_STOP);
        lease.requestCleanup(Reason.HOST_STOP);
        port.runReady();
        require(lease.state() == State.REMOVING, "verification was not deferred");
        require(port.removeCalls == 1, "duplicate removal");
        port.advance(2);
        require(lease.state() == State.REMOVED, "not removed");
        require(lease.result() == Result.LIVE_STRUCTURE_RESTORED,
                "live structure not verified");
        require(!slot.occupied() && !port.armed, "slot/listeners retained after verification");
        port.exactNine();
        lease.requestCleanup(Reason.DEADLINE);
        port.runReady();
        require(port.removeCalls == 1, "terminal cleanup repeated removal");
    }

    private static void testProductionSlot() {
        TargetOwnedVisualLeaseCore.Factory factory = new TargetOwnedVisualLeaseCore.Factory() {
            @Override public Object create(DrawGate drawGate) { return new GateBoundChild(drawGate); }
        };
        FakePort first = new FakePort();
        TargetOwnedVisualLeaseCore lease = TargetOwnedVisualLeaseCore.start(first, factory, 1, 1, 50, 10, 10, 40);
        first.advance(1);
        try {
            TargetOwnedVisualLeaseCore.start(new FakePort(), factory, 1, 1, 50, 10, 10, 40);
            throw new AssertionError("production slot admitted a second lease");
        } catch (IllegalStateException expected) { checks++; }
        lease.requestCleanup(Reason.HOST_STOP);
        first.runReady();
        first.advance(2);
        require(lease.state() == State.REMOVED, "production slot did not release");
        FakePort second = new FakePort();
        TargetOwnedVisualLeaseCore next = TargetOwnedVisualLeaseCore.start(second, factory, 1, 1, 50, 10, 10, 40);
        second.advance(1);
        require(next.state() == State.INSERTED, "production slot did not admit safe next lease");
        next.requestCleanup(Reason.HOST_STOP);
        second.runReady();
        second.advance(2);
        require(next.state() == State.REMOVED, "next production lease did not finish");
    }

    private static void testAttachThenThrow() {
        Slot slot = new Slot();
        FakePort port = new FakePort();
        port.throwAfterAttach = true;
        TargetOwnedVisualLeaseCore lease = start(slot, port);
        require(lease.state() == State.REMOVING, "attached throw was not cleaned");
        require(port.removeCalls == 1 && port.parentOf(lease.ownedChild()) == null,
                "exact attached object remained");
        port.advance(2);
        require(lease.state() == State.REMOVED && lease.result() == Result.UNKNOWN,
                "insertion failure was silently passed");
        require(lease.failure() != null && !slot.occupied(), "failure not recorded");
        port.exactNine();

        FakePort beforeAdd = new FakePort();
        beforeAdd.throwBeforeAdd = true;
        TargetOwnedVisualLeaseCore early = start(new Slot(), beforeAdd);
        beforeAdd.advance(1);
        require(early.state() == State.REMOVED && beforeAdd.removeCalls == 0,
                "unattached child was removed");
        beforeAdd.exactNine();
    }

    private static void testPreInsertionReauthentication() {
        FakePort factoryTime = new FakePort();
        TargetOwnedVisualLeaseCore timeLease = start(new Slot(), factoryTime,
                new TargetOwnedVisualLeaseCore.Factory() {
                    @Override public Object create(DrawGate drawGate) {
                        factoryTime.now += 20;
                        return new GateBoundChild(drawGate);
                    }
                });
        require(timeLease.state() == State.INSERTED && factoryTime.deadlineDelay == 30,
                "factory time was not deducted from elapsed deadline");
        timeLease.requestCleanup(Reason.HOST_STOP);
        factoryTime.runReady();
        factoryTime.advance(1);

        FakePort expiredFactory = new FakePort();
        Slot expiredSlot = new Slot();
        TargetOwnedVisualLeaseCore expired = start(expiredSlot, expiredFactory,
                new TargetOwnedVisualLeaseCore.Factory() {
                    @Override public Object create(DrawGate drawGate) {
                        expiredFactory.now += 60;
                        return new GateBoundChild(drawGate);
                    }
                });
        require(expired.state() == State.REMOVING && expiredFactory.addCalls == 0,
                "expired factory admitted add");
        expiredFactory.advance(1);
        require(expired.state() == State.REMOVED && expired.result() == Result.UNKNOWN
                && !expiredSlot.occupied(), "expired prepared lease was not released safely");
        expiredFactory.exactNine();

        FakePort slowArm = new FakePort();
        slowArm.armAdvance = 60;
        TargetOwnedVisualLeaseCore armedTooLate = start(new Slot(), slowArm);
        require(armedTooLate.state() == State.REMOVING && slowArm.addCalls == 0,
                "expired arming admitted add");
        slowArm.advance(1);
        require(armedTooLate.state() == State.REMOVED && armedTooLate.result() == Result.UNKNOWN,
                "expired arming produced live pass");

        FakePort slowSchedule = new FakePort();
        slowSchedule.scheduleAdvance = 60;
        TargetOwnedVisualLeaseCore scheduledTooLate = start(new Slot(), slowSchedule);
        require(scheduledTooLate.state() == State.REMOVING && slowSchedule.addCalls == 0,
                "expired schedule admitted add");
        slowSchedule.runReady();
        slowSchedule.advance(1);
        require(scheduledTooLate.state() == State.REMOVED
                && scheduledTooLate.result() == Result.UNKNOWN,
                "expired prepared schedule produced live pass");

        FakePort changedScene = new FakePort();
        changedScene.changeSceneWhileArming = true;
        TargetOwnedVisualLeaseCore sceneLease = start(new Slot(), changedScene);
        require(sceneLease.state() == State.QUARANTINED && changedScene.addCalls == 0,
                "changed page/URI before add was admitted");

        FakePort changedOrder = new FakePort();
        changedOrder.reorderWhileArming = true;
        TargetOwnedVisualLeaseCore orderLease = start(new Slot(), changedOrder);
        require(orderLease.state() == State.QUARANTINED && changedOrder.addCalls == 0,
                "changed stock order before add was admitted");

        FakePort pausedWhileArming = new FakePort();
        pausedWhileArming.firePauseWhileArming = true;
        Slot pausedSlot = new Slot();
        TargetOwnedVisualLeaseCore pausedLease = start(pausedSlot, pausedWhileArming);
        require(pausedLease.state() == State.REMOVING && pausedWhileArming.addCalls == 0,
                "queued lifecycle callback did not block add");
        pausedWhileArming.runReady();
        pausedWhileArming.advance(1);
        require(pausedLease.state() == State.REMOVED && pausedLease.result() == Result.UNKNOWN
                && !pausedSlot.occupied(), "pre-add pause was not verified and released");

        FakePort rootGone = new FakePort();
        rootGone.loseRootWhileArming = true;
        TargetOwnedVisualLeaseCore rootLease = start(new Slot(), rootGone);
        require(rootLease.state() == State.QUARANTINED && rootGone.addCalls == 0,
                "lost root before add was admitted");

        FakePort processGone = new FakePort();
        processGone.loseProcessWhileArming = true;
        TargetOwnedVisualLeaseCore processLease = start(new Slot(), processGone);
        require(processLease.state() == State.QUARANTINED && processGone.addCalls == 0,
                "lost process before add was admitted");

        FakePort detachedByAdd = new FakePort();
        detachedByAdd.detachRootAfterAdd = true;
        TargetOwnedVisualLeaseCore detachedLease = start(new Slot(), detachedByAdd);
        require(detachedLease.state() == State.QUARANTINED && detachedByAdd.addCalls == 1
                && detachedByAdd.removeCalls == 1,
                "add-time root detach did not remove the exact child");
        detachedByAdd.exactNine();

        FakePort slowAdd = new FakePort();
        Slot slowAddSlot = new Slot();
        slowAdd.addAdvance = 70;
        TargetOwnedVisualLeaseCore slowAddLease = start(slowAddSlot, slowAdd);
        require(slowAddLease.state() == State.REMOVING && slowAdd.addCalls == 1
                && slowAdd.removeCalls == 1 && slowAddLease.deadlineLatenessExceeded(),
                "late attached-but-PREPARED child was not removed and flagged");
        slowAdd.advance(2);
        require(slowAddLease.state() == State.QUARANTINED && slowAddSlot.occupied(),
                "late add produced a live restoration or released its slot");
        slowAdd.exactNine();
    }

    private static void testUnattachedPreparationFailures() {
        FakePort nullChild = new FakePort();
        Slot childSlot = new Slot();
        TargetOwnedVisualLeaseCore childLease = start(childSlot, nullChild,
                new TargetOwnedVisualLeaseCore.Factory() {
                    @Override public Object create(DrawGate drawGate) { return null; }
                });
        require(childLease.state() == State.REMOVING && nullChild.addCalls == 0,
                "null factory child was not verified");
        nullChild.advance(1);
        require(childLease.state() == State.REMOVED && childLease.result() == Result.UNKNOWN
                && !childSlot.occupied(), "null factory child leaked slot");
        nullChild.exactNine();

        FakePort failedFactory = new FakePort();
        Slot failedSlot = new Slot();
        final DrawGate[] gateBeforeFactoryThrow = new DrawGate[1];
        TargetOwnedVisualLeaseCore failedLease = start(failedSlot, failedFactory,
                new TargetOwnedVisualLeaseCore.Factory() {
                    @Override public Object create(DrawGate drawGate) {
                        gateBeforeFactoryThrow[0] = drawGate;
                        throw new IllegalStateException("factory failure");
                    }
                });
        failedFactory.advance(1);
        require(gateBeforeFactoryThrow[0] != null
                && !gateBeforeFactoryThrow[0].mayDraw()
                && failedFactory.addCalls == 0
                && failedLease.state() == State.REMOVED && failedLease.failure() != null
                && !failedSlot.occupied(), "factory exception leaked an unattached lease");

        FakePort noRegistration = new FakePort();
        noRegistration.nullRegistration = true;
        Slot registrationSlot = new Slot();
        TargetOwnedVisualLeaseCore registrationLease = start(registrationSlot, noRegistration);
        require(registrationLease.state() == State.REMOVING && noRegistration.addCalls == 0,
                "null registration admitted add");
        noRegistration.advance(1);
        require(registrationLease.state() == State.REMOVED && !registrationSlot.occupied(),
                "null registration leaked an unattached lease");

        FakePort badBaseline = new FakePort();
        badBaseline.children.remove(0);
        TargetOwnedVisualLeaseCore invalid = start(new Slot(), badBaseline);
        require(invalid.state() == State.QUARANTINED && badBaseline.addCalls == 0,
                "invalid original nine was not quarantined");

        FakePort foreignFactory = new FakePort();
        Slot foreignSlot = new Slot();
        Identity foreignChild = new Identity("borrowed from foreign hierarchy");
        foreignFactory.parents.put(foreignChild, foreignFactory.foreignParent);
        final DrawGate[] gateBeforeForeignChild = new DrawGate[1];
        TargetOwnedVisualLeaseCore borrowed = start(foreignSlot, foreignFactory,
                new TargetOwnedVisualLeaseCore.Factory() {
                    @Override public Object create(DrawGate drawGate) {
                        gateBeforeForeignChild[0] = drawGate;
                        return foreignChild;
                    }
                });
        require(borrowed.state() == State.QUARANTINED
                && borrowed.reason() == Reason.INSERTION_FAILURE
                && gateBeforeForeignChild[0] != null
                && !gateBeforeForeignChild[0].mayDraw()
                && foreignFactory.addCalls == 0 && foreignFactory.removeCalls == 0
                && foreignFactory.parentOf(foreignChild) == foreignFactory.foreignParent
                && foreignSlot.occupied(),
                "foreign-parented factory child was reparented or treated as owned");
        foreignFactory.exactNine();

        FakePort lostRoot = new FakePort();
        lostRoot.rootAlive = false;
        TargetOwnedVisualLeaseCore rootLoss = start(new Slot(), lostRoot);
        require(lostRoot.processAlive && rootLoss.state() == State.QUARANTINED
                && rootLoss.reason() == Reason.ROOT_LOSS && lostRoot.addCalls == 0,
                "live-process root loss before insertion was misclassified");

        FakePort deadProcess = new FakePort();
        deadProcess.processAlive = false;
        TargetOwnedVisualLeaseCore processLoss = start(new Slot(), deadProcess);
        require(processLoss.state() == State.QUARANTINED
                && processLoss.reason() == Reason.PROCESS_LOSS && deadProcess.addCalls == 0,
                "process loss before insertion was misclassified");
    }

    private static void testDrawPathDrift() {
        FakePort scene = new FakePort();
        TargetOwnedVisualLeaseCore sceneLease = start(new Slot(), scene);
        scene.scene = "page changed without callback";
        require(!sceneLease.mayDraw(), "page drift painted before callback");
        scene.runReady();
        require(sceneLease.state() == State.QUARANTINED,
                "draw-path page drift was not quarantined");

        FakePort layout = new FakePort();
        TargetOwnedVisualLeaseCore layoutLease = start(new Slot(), layout);
        layout.evidence.put(layout.original[4], "layout changed without callback");
        require(!layoutLease.mayDraw(), "layout drift painted before callback");
        layout.runReady();
        require(layoutLease.state() == State.QUARANTINED,
                "draw-path layout drift was not quarantined");

        FakePort signaled = new FakePort();
        TargetOwnedVisualLeaseCore signaledLease = start(new Slot(), signaled);
        signaled.drift.run();
        require(!signaledLease.mayDraw(), "signaled drift painted while cleanup queued");
        signaled.runReady();
        signaled.advance(2);
        require(signaledLease.state() == State.REMOVED
                && signaledLease.result() == Result.UNKNOWN,
                "drift callback produced a live rollback claim");
        signaled.exactNine();

        FakePort failedWitness = new FakePort();
        TargetOwnedVisualLeaseCore failedWitnessLease = start(new Slot(), failedWitness);
        failedWitness.snapshotFailure = true;
        require(!failedWitnessLease.mayDraw(), "failed draw witness allowed painting");
        failedWitness.runReady();
        require(failedWitnessLease.state() == State.QUARANTINED
                && failedWitnessLease.failure() != null,
                "failed draw witness did not remain UNKNOWN");

        FakePort slowWitness = new FakePort();
        TargetOwnedVisualLeaseCore slowLease = start(new Slot(), slowWitness);
        slowWitness.snapshotAdvance = 59; // start's separate paint pass cost one millisecond
        require(!slowLease.mayDraw(), "draw crossed deadline inside witness capture");
        slowWitness.snapshotAdvance = 0;
        slowWitness.runReady();
        slowWitness.advance(2);
        require(slowLease.state() == State.REMOVED,
                "slow witness did not schedule expired cleanup");

        FakePort ownedChanged = new FakePort();
        TargetOwnedVisualLeaseCore ownedLease = start(new Slot(), ownedChanged);
        ownedChanged.evidence.put(ownedLease.ownedChild(), "owned Z/geometry changed");
        require(!ownedLease.mayDraw(), "owned child drift painted after insertion");
        ownedChanged.runReady();
        ownedChanged.advance(2);
        require(ownedLease.state() == State.REMOVED && ownedLease.result() == Result.UNKNOWN,
                "owned child drift was reported as live restoration");
        ownedChanged.exactNine();
    }

    private static void testBoundedVerificationGap() {
        FakePort onBound = new FakePort();
        TargetOwnedVisualLeaseCore timely = start(new Slot(), onBound);
        timely.requestCleanup(Reason.HOST_STOP);
        onBound.runReady();
        onBound.advance(1); // Fresh post-removal frame establishes sample one.
        onBound.now += 10; // Inclusive ten-millisecond verification gap.
        onBound.runReady();
        require(timely.state() == State.REMOVED
                && timely.result() == Result.LIVE_STRUCTURE_RESTORED,
                "second sample at predeclared bound was rejected");

        FakePort stalled = new FakePort();
        Slot stalledSlot = new Slot();
        TargetOwnedVisualLeaseCore delayed = start(stalledSlot, stalled);
        delayed.requestCleanup(Reason.HOST_STOP);
        stalled.runReady();
        stalled.advance(1); // Fresh nine-child paint, then pending second sample.
        require(delayed.state() == State.REMOVING && stalled.removeCalls == 1,
                "first restoration sample was not taken");
        stalled.now += 100; // UI loop stalls before the queued second sample.
        stalled.runReady();
        require(delayed.state() == State.QUARANTINED && delayed.result() == Result.UNKNOWN
                && stalledSlot.occupied(),
                "late second sample manufactured live restoration");
        stalled.exactNine();

        FakePort slowSecondSnapshot = new FakePort();
        TargetOwnedVisualLeaseCore slow = start(new Slot(), slowSecondSnapshot);
        slow.requestCleanup(Reason.HOST_STOP);
        slowSecondSnapshot.runReady();
        slowSecondSnapshot.advance(1);
        slowSecondSnapshot.snapshotAdvance = 20;
        slowSecondSnapshot.advance(1);
        require(slow.state() == State.QUARANTINED && slow.result() == Result.UNKNOWN,
                "second sample exceeding gap during capture passed");
        slowSecondSnapshot.exactNine();
    }

    private static void testFinalizationSignals() {
        Reason[] losses = { Reason.ROOT_LOSS, Reason.PROCESS_LOSS,
                Reason.ROOT_LOSS, Reason.PROCESS_LOSS };
        for (int i = 0; i < losses.length; i++) {
            FakePort port = new FakePort();
            Slot slot = new Slot();
            TargetOwnedVisualLeaseCore lease = start(slot, port);
            port.activeLease = lease;
            lease.requestCleanup(Reason.HOST_STOP);
            port.runReady();
            port.advance(1); // Fresh nine-child frame; verifier is still queued.
            port.inlineDispatch = i == 0 || i == 2;
            port.lossChangesHostState = i == 0 || i == 3;
            if (i < 2) port.lossOnCancel = losses[i];
            else port.lossOnRelease = losses[i];
            port.advance(1);
            require(lease.state() == State.QUARANTINED && lease.result() == Result.UNKNOWN
                    && slot.occupied() && port.removeCalls == 1,
                    "cancel/release loss overwrote quarantine in case " + i);
            port.exactNine();
        }

        FakePort queued = new FakePort();
        Slot queuedSlot = new Slot();
        TargetOwnedVisualLeaseCore queuedLease = start(queuedSlot, queued);
        queuedLease.requestCleanup(Reason.HOST_STOP);
        queued.runReady();
        queued.advance(1);
        queued.dispatchDelay = 2;
        queuedLease.requestCleanup(Reason.ROOT_LOSS); // Signal now; dispatch after verifier.
        queued.advance(1);
        require(queuedLease.state() == State.QUARANTINED
                && queuedLease.result() == Result.UNKNOWN && queuedSlot.occupied(),
                "queued loss signal was ignored by verifier");
        queued.advance(1);
        queued.exactNine();

        FakePort commitSeam = new FakePort();
        Slot seamSlot = new Slot();
        TargetOwnedVisualLeaseCore seamLease = start(seamSlot, commitSeam);
        commitSeam.activeLease = seamLease;
        seamLease.requestCleanup(Reason.HOST_STOP);
        commitSeam.runReady();
        commitSeam.advance(1);
        commitSeam.lossOnPostReleaseRootRead = Reason.ROOT_LOSS;
        commitSeam.signalOnPostReleaseRootRead = 3;
        commitSeam.advance(1);
        require(commitSeam.rootReadsAfterRelease >= 3
                && seamLease.state() == State.QUARANTINED
                && seamLease.result() == Result.UNKNOWN && seamSlot.occupied(),
                "loss at terminal check/commit seam released the slot");
        commitSeam.exactNine();
    }

    private static void testDeadlineAndLifecycle() {
        FakePort stalled = new FakePort();
        TargetOwnedVisualLeaseCore expired = start(new Slot(), stalled);
        stalled.now = 151; // Deadline callback is intentionally still queued.
        require(!expired.mayDraw(), "expired draw painted before callback");
        require(stalled.children.size() == 10, "draw guard hid callback ordering");
        stalled.runReady();
        stalled.advance(2);
        require(expired.state() == State.REMOVED && !expired.mayDraw()
                && expired.result() == Result.LIVE_STRUCTURE_RESTORED
                && !expired.deadlineLatenessExceeded(),
                "deadline cleanup failed");
        stalled.exactNine();

        FakePort boundary = new FakePort();
        TargetOwnedVisualLeaseCore onBound = start(new Slot(), boundary);
        boundary.now = 160; // Deadline 150; lateness bound 10 is inclusive.
        boundary.runReady();
        boundary.advance(2);
        require(onBound.state() == State.REMOVED && !onBound.deadlineLatenessExceeded(),
                "on-bound callback was treated as late");

        FakePort stalledTooLong = new FakePort();
        Slot stalledSlot = new Slot();
        TargetOwnedVisualLeaseCore late = start(stalledSlot, stalledTooLong);
        stalledTooLong.now = 170; // Main-loop stall beyond the declared bound.
        stalledTooLong.runReady();
        stalledTooLong.advance(2);
        require(late.state() == State.QUARANTINED && late.result() == Result.UNKNOWN
                && late.deadlineLatenessExceeded() && stalledSlot.occupied()
                && stalledTooLong.removeCalls == 1,
                "late callback manufactured a live rollback PASS");
        stalledTooLong.exactNine();

        FakePort resumed = new FakePort();
        Slot resumedSlot = new Slot();
        TargetOwnedVisualLeaseCore afterSleep = start(resumedSlot, resumed);
        resumed.now = 170; // Elapsed time includes suspend; callback is still queued.
        require(!afterSleep.mayDraw() && resumed.children.size() == 10
                && afterSleep.deadlineLatenessExceeded(),
                "sleep-resume draw ignored elapsed-realtime lateness");
        resumed.runReady();
        resumed.advance(2);
        require(afterSleep.state() == State.QUARANTINED
                && afterSleep.result() == Result.UNKNOWN && resumedSlot.occupied(),
                "sleep-resume late cleanup reported live restoration");
        resumed.exactNine();

        FakePort slowRemoval = new FakePort();
        TargetOwnedVisualLeaseCore removalCrossedBound = start(new Slot(), slowRemoval);
        slowRemoval.now = 149;
        slowRemoval.removeAdvance = 20;
        removalCrossedBound.requestCleanup(Reason.HOST_STOP);
        slowRemoval.runReady();
        slowRemoval.advance(2);
        require(removalCrossedBound.state() == State.QUARANTINED
                && removalCrossedBound.deadlineLatenessExceeded(),
                "slow exact removal crossed bound but reported live restoration");

        FakePort paused = new FakePort();
        TargetOwnedVisualLeaseCore activity = start(new Slot(), paused);
        paused.pause.run();
        activity.requestCleanup(Reason.HOST_STOP);
        paused.runReady();
        paused.advance(2);
        require(activity.state() == State.REMOVED && activity.result() == Result.UNKNOWN,
                "lifecycle abort reported a live rollback");
        require(paused.removeCalls == 1, "pause/host-stop were not idempotent");
        paused.exactNine();
    }

    private static void testMovedMissingAndImpostor() {
        FakePort moved = new FakePort();
        Slot movedSlot = new Slot();
        TargetOwnedVisualLeaseCore movedLease = start(movedSlot, moved);
        moved.removeOwnedExternally(movedLease.ownedChild());
        moved.parents.put(movedLease.ownedChild(), moved.foreignParent);
        movedLease.requestCleanup(Reason.HOST_STOP);
        moved.runReady();
        require(movedLease.state() == State.QUARANTINED && moved.removeCalls == 0
                && movedSlot.occupied(), "moved child was touched or slot released");

        FakePort missing = new FakePort();
        TargetOwnedVisualLeaseCore absent = start(new Slot(), missing);
        missing.removeOwnedExternally(absent.ownedChild());
        absent.requestCleanup(Reason.HOST_STOP);
        missing.runReady();
        require(absent.state() == State.QUARANTINED && missing.removeCalls == 0,
                "missing child was treated as restored");

        FakePort replaced = new FakePort();
        TargetOwnedVisualLeaseCore lease = start(new Slot(), replaced);
        replaced.removeOwnedExternally(lease.ownedChild());
        Identity impostor = new Identity("impostor");
        replaced.children.add(1, impostor);
        replaced.parents.put(impostor, replaced.root);
        replaced.evidence.put(impostor, "impostor");
        lease.requestCleanup(Reason.HOST_STOP);
        replaced.runReady();
        require(lease.state() == State.QUARANTINED && replaced.removeCalls == 0
                && replaced.children.get(1) == impostor,
                "impostor was removed using slot/equality authority");

        FakePort extra = new FakePort();
        TargetOwnedVisualLeaseCore extraLease = start(new Slot(), extra);
        Identity extraImpostor = new Identity("extra");
        extra.children.add(extraImpostor);
        extra.parents.put(extraImpostor, extra.root);
        extra.evidence.put(extraImpostor, "extra");
        extraLease.requestCleanup(Reason.HOST_STOP);
        extra.runReady();
        require(extraLease.state() == State.QUARANTINED && extra.removeCalls == 1
                && extra.containsIdentity(extraImpostor),
                "post-removal impostor escaped structural check");
    }

    private static void testNineChildAndEvidenceVerification() {
        FakePort reordered = new FakePort();
        TargetOwnedVisualLeaseCore lease = start(new Slot(), reordered);
        lease.requestCleanup(Reason.HOST_STOP);
        reordered.runReady();
        Object first = reordered.children.get(0);
        reordered.children.set(0, reordered.children.get(1));
        reordered.children.set(1, first);
        reordered.advance(1);
        require(lease.state() == State.QUARANTINED && lease.result() == Result.UNKNOWN,
                "nine-child order change passed second sample");

        FakePort metadata = new FakePort();
        TargetOwnedVisualLeaseCore metadataLease = start(new Slot(), metadata);
        metadataLease.requestCleanup(Reason.HOST_STOP);
        metadata.runReady();
        metadata.evidence.put(metadata.original[4], "changed layout parameters");
        metadata.advance(1);
        require(metadataLease.state() == State.QUARANTINED,
                "stock child evidence change passed second sample");

        FakePort replaced = new FakePort();
        TargetOwnedVisualLeaseCore replacedLease = start(new Slot(), replaced);
        replacedLease.requestCleanup(Reason.HOST_STOP);
        replaced.runReady();
        Identity lookalike = new Identity("same equals and hash as every stock child");
        replaced.children.set(3, lookalike);
        replaced.parents.remove(replaced.original[3]);
        replaced.parents.put(lookalike, replaced.root);
        replaced.evidence.put(lookalike, replaced.evidence.get(replaced.original[3]));
        replaced.advance(1);
        require(replacedLease.state() == State.QUARANTINED,
                "equal-looking replacement passed exact identity check");

        FakePort scene = new FakePort();
        TargetOwnedVisualLeaseCore drifted = start(new Slot(), scene);
        scene.scene = "page B|uri B|render B|root 1404x1872|epoch 2";
        drifted.requestCleanup(Reason.DRIFT);
        scene.runReady();
        require(drifted.state() == State.QUARANTINED,
                "changed page/scene evidence passed restoration");
    }

    private static void testEffectiveDrawingOrderEvidence() {
        TargetOwnedVisualLeaseCore.Factory factory = new TargetOwnedVisualLeaseCore.Factory() {
            @Override public Object create(DrawGate drawGate) { return new GateBoundChild(drawGate); }
        };

        FakePort independentlyProvenSlot = new FakePort();
        independentlyProvenSlot.useCustomPaintOrder();
        Object[] customBaseline = independentlyProvenSlot.original.clone();
        customBaseline[1] = independentlyProvenSlot.original[2];
        customBaseline[2] = independentlyProvenSlot.original[1];
        requirePaintOrder(independentlyProvenSlot, customBaseline,
                "custom-order stock baseline");
        require(independentlyProvenSlot.children.get(1) == independentlyProvenSlot.original[1]
                && independentlyProvenSlot.drawPolicy.startsWith("custom"),
                "custom-order fixture did not establish a distinct baseline permutation");
        TargetOwnedVisualLeaseCore differentSlots = TargetOwnedVisualLeaseCore.startForTest(
                new Slot(), independentlyProvenSlot, factory, 1, 2, 50, 10, 10, 40);
        independentlyProvenSlot.advance(1);
        require(differentSlots.state() == State.INSERTED
                && independentlyProvenSlot.children.get(1) == differentSlots.ownedChild()
                && independentlyProvenSlot.effectiveDrawOrder.get(2) == differentSlots.ownedChild()
                && independentlyProvenSlot.effectiveDrawOrder.get(3)
                    == independentlyProvenSlot.original[1],
                "separately proven direct and paint slots were conflated");
        Object[] customInserted = new Object[10];
        for (int i = 0; i < 9; i++) {
            customInserted[i < 2 ? i : i + 1] = customBaseline[i];
        }
        customInserted[2] = differentSlots.ownedChild();
        requirePaintOrder(independentlyProvenSlot, customInserted,
                "custom-order inserted permutation");
        differentSlots.requestCleanup(Reason.HOST_STOP);
        independentlyProvenSlot.runReady();
        independentlyProvenSlot.advance(2);
        require(differentSlots.result() == Result.LIVE_STRUCTURE_RESTORED,
                "separately proven paint slot failed exact restoration");
        requirePaintOrder(independentlyProvenSlot, customBaseline,
                "custom-order restored permutation");
        require(independentlyProvenSlot.children.size() == 9
                && independentlyProvenSlot.drawPolicy.startsWith("custom"),
                "custom paint permutation was not preserved on restoration");

        FakePort wrongRank = new FakePort();
        wrongRank.paintInsertSlot = 2;
        Slot wrongRankSlot = new Slot();
        TargetOwnedVisualLeaseCore wrongRankLease = start(wrongRankSlot, wrongRank);
        wrongRank.runReady();
        wrongRank.advance(2);
        require(wrongRankLease.state() == State.REMOVED
                && wrongRankLease.result() == Result.UNKNOWN
                && wrongRank.removeCalls == 1 && !wrongRankSlot.occupied(),
                "unproven paint rank was not rejected and exactly removed");
        wrongRank.exactNine();

        FakePort paintDrift = new FakePort();
        TargetOwnedVisualLeaseCore paintDriftLease = start(new Slot(), paintDrift);
        Object firstPaint = paintDrift.effectiveDrawOrder.get(0);
        paintDrift.effectiveDrawOrder.set(0, paintDrift.effectiveDrawOrder.get(2));
        paintDrift.effectiveDrawOrder.set(2, firstPaint);
        require(!paintDriftLease.mayDraw(), "paint-order drift allowed drawing");
        paintDrift.runReady();
        require(paintDriftLease.state() == State.REMOVING,
                "paint-order drift bypassed the fresh restoration-frame fence");
        paintDrift.advance(2);
        require(paintDriftLease.state() == State.QUARANTINED,
                "paint-order drift was reported as restoration");

        FakePort policyDrift = new FakePort();
        TargetOwnedVisualLeaseCore policyDriftLease = start(new Slot(), policyDrift);
        policyDrift.drawPolicy = "custom child drawing order enabled";
        require(!policyDriftLease.mayDraw(), "draw-policy drift allowed drawing");
        policyDrift.runReady();
        require(policyDriftLease.state() == State.QUARANTINED,
                "draw-policy drift was reported as restoration");

        FakePort duplicatePaint = new FakePort();
        duplicatePaint.effectiveDrawOrder.set(4, duplicatePaint.original[3]);
        Slot duplicateSlot = new Slot();
        TargetOwnedVisualLeaseCore duplicateLease = start(duplicateSlot, duplicatePaint);
        require(duplicateLease.state() == State.QUARANTINED
                && duplicateLease.result() == Result.UNKNOWN
                && duplicatePaint.addCalls == 0 && duplicateSlot.occupied(),
                "duplicate paint identity passed the nine-child baseline");

        FakePort missingPaint = new FakePort();
        missingPaint.effectiveDrawOrder.set(4, missingPaint.foreignParent);
        TargetOwnedVisualLeaseCore missingLease = start(new Slot(), missingPaint);
        require(missingLease.state() == State.QUARANTINED
                && missingLease.result() == Result.UNKNOWN && missingPaint.addCalls == 0,
                "foreign paint identity passed the nine-child baseline");

        FakePort ownedEvidence = new FakePort();
        TargetOwnedVisualLeaseCore ownedLease = start(new Slot(), ownedEvidence);
        ownedEvidence.evidence.put(ownedLease.ownedChild(), "owned geometry/Z drift");
        require(!ownedLease.mayDraw(), "changed owned evidence allowed drawing");
        ownedEvidence.runReady();
        ownedEvidence.advance(2);
        require(ownedLease.state() == State.REMOVED
                && ownedLease.result() == Result.UNKNOWN && ownedEvidence.removeCalls == 1,
                "changed owned evidence escaped exact-object cleanup");
    }

    private static void testGoneChildPaintRepresentation() {
        TargetOwnedVisualLeaseCore.Factory factory = new TargetOwnedVisualLeaseCore.Factory() {
            @Override public Object create(DrawGate drawGate) {
                return new GateBoundChild(drawGate);
            }
        };

        FakePort gone = new FakePort();
        gone.setStockSevenVisible(false);
        gone.completeFreshPaintNow();
        gone.exactNineWithGoneSeven();
        Object[] legacyParents = new Object[9];
        String[] legacyEvidence = new String[9];
        for (int i = 0; i < 9; i++) {
            legacyParents[i] = gone.root;
            legacyEvidence[i] = gone.evidence.get(gone.original[i]);
        }
        try {
            new Snapshot(gone.root, gone.original, legacyParents, legacyEvidence,
                    gone.effectiveDrawOrder.toArray(new Object[8]),
                    gone.drawPolicy, gone.scene);
            throw new AssertionError("legacy all-visible constructor accepted omitted child");
        } catch (IllegalArgumentException expected) { checks++; }
        gone.paintInsertSlot = 7;
        Slot goneSlot = new Slot();
        TargetOwnedVisualLeaseCore lease = TargetOwnedVisualLeaseCore.startForTest(
                goneSlot, gone, factory, 8, 7, 50, 10, 10, 40);
        gone.advance(1);
        require(lease.state() == State.INSERTED && lease.mayDraw()
                && gone.children.size() == 10 && gone.children.get(8) == lease.ownedChild(),
                "nine-structural/eight-painted baseline did not admit exact owned child");
        Object[] insertedOrder = new Object[9];
        for (int i = 0; i < 7; i++) insertedOrder[i] = gone.original[i];
        insertedOrder[7] = lease.ownedChild();
        insertedOrder[8] = gone.original[8];
        requirePaintOrder(gone, insertedOrder, "GONE baseline owned paint order");
        lease.requestCleanup(Reason.HOST_STOP);
        gone.runReady();
        gone.advance(2);
        require(lease.state() == State.REMOVED
                && lease.result() == Result.LIVE_STRUCTURE_RESTORED
                && gone.removeCalls == 1 && !goneSlot.occupied(),
                "eight-painted rollback did not restore exact nine-child structure");
        gone.exactNineWithGoneSeven();

        FakePort impossibleRank = new FakePort();
        impossibleRank.setStockSevenVisible(false);
        impossibleRank.completeFreshPaintNow();
        Slot impossibleSlot = new Slot();
        TargetOwnedVisualLeaseCore impossible = TargetOwnedVisualLeaseCore.startForTest(
                impossibleSlot, impossibleRank, factory, 8, 9, 50, 10, 10, 40);
        require(impossible.state() == State.QUARANTINED
                && impossible.result() == Result.UNKNOWN
                && impossibleRank.addCalls == 0 && impossibleSlot.occupied(),
                "paint slot beyond eight original dispatches reached insertion");

        FakePort wrongRank = new FakePort();
        wrongRank.setStockSevenVisible(false);
        wrongRank.completeFreshPaintNow();
        wrongRank.paintInsertSlot = 8;
        Slot wrongRankSlot = new Slot();
        TargetOwnedVisualLeaseCore misplaced = TargetOwnedVisualLeaseCore.startForTest(
                wrongRankSlot, wrongRank, factory, 8, 7, 50, 10, 10, 40);
        wrongRank.advance(3);
        require(misplaced.state() == State.REMOVED
                && misplaced.result() == Result.UNKNOWN
                && wrongRank.drawRequests == 0 && wrongRank.removeCalls == 1
                && !wrongRankSlot.occupied(),
                "unproven owned paint rank was admitted with a GONE sibling: state="
                        + misplaced.state() + " result=" + misplaced.result()
                        + " draws=" + wrongRank.drawRequests
                        + " removes=" + wrongRank.removeCalls);
        wrongRank.exactNineWithGoneSeven();
    }

    private static void testLegacyAllVisibleSnapshotCompatibility() {
        FakePort legacy = new FakePort();
        legacy.useLegacyAllVisibleSnapshot = true;
        legacy.completeFreshPaintNow();
        TargetOwnedVisualLeaseCore lease = start(new Slot(), legacy);
        require(lease.state() == State.INSERTED && lease.mayDraw()
                && legacy.effectiveDrawOrder.size() == 10,
                "legacy all-visible Snapshot did not admit the unchanged host shape");
        lease.requestCleanup(Reason.HOST_STOP);
        legacy.runReady();
        legacy.advance(2);
        require(lease.state() == State.REMOVED
                && lease.result() == Result.LIVE_STRUCTURE_RESTORED,
                "legacy all-visible Snapshot failed exact rollback");
        legacy.exactNine();
    }

    private static void testGoneChildWithCustomPaintOrder() {
        FakePort custom = new FakePort();
        custom.useCustomPaintOrder();
        custom.setStockSevenVisible(false);
        custom.completeFreshPaintNow();
        Object[] baselineOrder = new Object[] {
                custom.original[0], custom.original[2], custom.original[1],
                custom.original[3], custom.original[4], custom.original[5],
                custom.original[6], custom.original[8]
        };
        requirePaintOrder(custom, baselineOrder, "GONE custom-order baseline");
        TargetOwnedVisualLeaseCore lease = TargetOwnedVisualLeaseCore.startForTest(
                new Slot(), custom, new TargetOwnedVisualLeaseCore.Factory() {
                    @Override public Object create(DrawGate drawGate) {
                        return new GateBoundChild(drawGate);
                    }
                }, 8, 2, 50, 10, 10, 40);
        custom.advance(1);
        Object[] insertedOrder = new Object[] {
                custom.original[0], custom.original[2], lease.ownedChild(),
                custom.original[1], custom.original[3], custom.original[4],
                custom.original[5], custom.original[6], custom.original[8]
        };
        require(lease.state() == State.INSERTED && lease.mayDraw()
                && custom.children.size() == 10
                && custom.children.get(8) == lease.ownedChild(),
                "GONE custom paint order did not admit distinct direct/paint slots");
        requirePaintOrder(custom, insertedOrder, "GONE custom-order owned paint");
        lease.requestCleanup(Reason.HOST_STOP);
        custom.runReady();
        custom.advance(2);
        require(lease.state() == State.REMOVED
                && lease.result() == Result.LIVE_STRUCTURE_RESTORED
                && custom.children.size() == 9,
                "GONE custom paint order failed exact restoration");
        requirePaintOrder(custom, baselineOrder, "GONE custom-order restored paint");
        for (int i = 0; i < 9; i++) {
            require(custom.children.get(i) == custom.original[i]
                    && custom.parents.get(custom.original[i]) == custom.root,
                    "GONE custom-order structural restoration at " + i);
        }
    }

    private static void testGoneVisibilityAndUnexpectedOmissions() {
        FakePort omittedVisible = new FakePort();
        omittedVisible.effectiveDrawOrder.remove(omittedVisible.original[4]);
        omittedVisible.completeFreshPaintNow();
        Slot omittedSlot = new Slot();
        TargetOwnedVisualLeaseCore missing = start(omittedSlot, omittedVisible);
        require(missing.state() == State.QUARANTINED
                && missing.result() == Result.UNKNOWN
                && omittedVisible.addCalls == 0 && omittedSlot.occupied(),
                "unexpected omitted visible child passed baseline admission");

        FakePort paintedGone = new FakePort();
        paintedGone.setStockSevenVisible(false);
        paintedGone.effectiveDrawOrder.set(4, paintedGone.original[7]);
        paintedGone.completeFreshPaintNow();
        TargetOwnedVisualLeaseCore extraPaint = start(new Slot(), paintedGone);
        require(extraPaint.state() == State.QUARANTINED
                && paintedGone.addCalls == 0,
                "GONE child appearing in actual paint order passed baseline admission");

        FakePort missingAfterAdd = new FakePort();
        missingAfterAdd.setStockSevenVisible(false);
        missingAfterAdd.completeFreshPaintNow();
        missingAfterAdd.autoAddPaint = false;
        TargetOwnedVisualLeaseCore pending = start(new Slot(), missingAfterAdd);
        require(pending.state() == State.PREPARED, "missing-after-add fixture not pending");
        missingAfterAdd.effectiveDrawOrder.remove(missingAfterAdd.original[4]);
        missingAfterAdd.scheduleFreshPaint(1);
        missingAfterAdd.advance(3);
        require(pending.result() == Result.UNKNOWN
                && missingAfterAdd.drawRequests == 0
                && missingAfterAdd.removeCalls == 1,
                "post-add omitted visible child authorized owned pixels: state="
                        + pending.state() + " result=" + pending.result()
                        + " draws=" + missingAfterAdd.drawRequests
                        + " removes=" + missingAfterAdd.removeCalls);

        FakePort newlyVisible = new FakePort();
        newlyVisible.setStockSevenVisible(false);
        newlyVisible.completeFreshPaintNow();
        newlyVisible.paintInsertSlot = 7;
        TargetOwnedVisualLeaseCore shown = TargetOwnedVisualLeaseCore.startForTest(
                new Slot(), newlyVisible, new TargetOwnedVisualLeaseCore.Factory() {
                    @Override public Object create(DrawGate drawGate) {
                        return new GateBoundChild(drawGate);
                    }
                }, 8, 7, 50, 10, 10, 40);
        newlyVisible.advance(1);
        require(shown.state() == State.INSERTED, "newly-visible fixture did not admit");
        newlyVisible.setStockSevenVisible(true);
        newlyVisible.completeFreshPaintNow();
        require(!shown.mayDraw(), "newly visible stock child retained draw authority");
        newlyVisible.runReady();
        newlyVisible.advance(2);
        require(shown.result() == Result.UNKNOWN
                && newlyVisible.removeCalls == 1,
                "newly visible transition produced live rollback PASS");

        FakePort newlyHidden = new FakePort();
        TargetOwnedVisualLeaseCore hidden = start(new Slot(), newlyHidden);
        newlyHidden.setStockSevenVisible(false);
        newlyHidden.completeFreshPaintNow();
        require(!hidden.mayDraw(), "newly GONE stock child retained draw authority");
        newlyHidden.runReady();
        newlyHidden.advance(2);
        require(hidden.result() == Result.UNKNOWN
                && newlyHidden.removeCalls == 1,
                "newly hidden transition produced live rollback PASS");
    }

    private static void testCompletedPaintAdmission() {
        FakePort deferredLayout = new FakePort();
        deferredLayout.autoAddPaint = false;
        Slot deferredLayoutSlot = new Slot();
        TargetOwnedVisualLeaseCore deferredLayoutLease = start(deferredLayoutSlot,
                deferredLayout);
        require(deferredLayoutLease.state() == State.PREPARED
                && deferredLayout.children.size() == 10
                && deferredLayout.removeCalls == 0 && deferredLayout.drawRequests == 0
                && !deferredLayoutLease.mayDraw(),
                "deferred-layout fixture was not pending after owned add");
        deferredLayout.evidenceMutationRevision++; // Before stock geometry changes.
        String changedGeometry = "class|id|visibility|bounds 12,24,72,84|z|layout 4";
        deferredLayout.evidence.put(deferredLayout.original[4], changedGeometry);
        deferredLayout.scheduleFreshPaint(0);
        deferredLayout.runReady(); // Complete ten-child paint before the t+1 admission poll.
        requireCapturedTenChildFrame(deferredLayout.lastCompletedPaintFrame,
                deferredLayoutLease.ownedChild(), deferredLayout.original[4], changedGeometry,
                "deferred layout frame omitted owned child or changed stock geometry");
        require(deferredLayoutLease.state() == State.PREPARED
                && deferredLayout.drawRequests == 0 && deferredLayout.removeCalls == 0,
                "completed deferred-layout frame admitted or removed owned child early");
        deferredLayout.advance(1);
        require(!deferredLayoutLease.mayDraw() && deferredLayout.drawRequests == 0
                && deferredLayout.removeCalls == 1
                && deferredLayout.parentOf(deferredLayoutLease.ownedChild()) == null
                && !deferredLayout.containsIdentity(deferredLayoutLease.ownedChild())
                && deferredLayoutLease.state() == State.QUARANTINED
                && deferredLayoutLease.result() == Result.UNKNOWN
                && deferredLayoutLease.reason() == Reason.DRIFT
                && deferredLayoutSlot.occupied(),
                "deferred stock layout admitted pixels or certified uncertain restoration");
        deferredLayout.exactNine();

        FakePort layoutAba = new FakePort();
        layoutAba.autoAddPaint = false;
        Slot layoutAbaSlot = new Slot();
        TargetOwnedVisualLeaseCore layoutAbaLease = start(layoutAbaSlot, layoutAba);
        require(layoutAbaLease.state() == State.PREPARED
                && layoutAba.children.size() == 10
                && layoutAba.removeCalls == 0 && layoutAba.drawRequests == 0
                && !layoutAbaLease.mayDraw(),
                "layout ABA fixture was not pending after owned add");
        String originalGeometry = layoutAba.evidence.get(layoutAba.original[4]);
        layoutAba.evidenceMutationRevision++; // Outbound deferred layout.
        layoutAba.evidence.put(layoutAba.original[4],
                "class|id|visibility|bounds 12,24,72,84|z|layout 4");
        layoutAba.evidenceMutationRevision++; // Inverse layout is another mutation.
        layoutAba.evidence.put(layoutAba.original[4], originalGeometry);
        layoutAba.scheduleFreshPaint(0); // Frame and live metadata now match baseline.
        layoutAba.runReady(); // Complete ten-child paint before the t+1 admission poll.
        requireCapturedTenChildFrame(layoutAba.lastCompletedPaintFrame,
                layoutAbaLease.ownedChild(), layoutAba.original[4], originalGeometry,
                "layout ABA frame omitted owned child or failed to restore metadata");
        require(layoutAbaLease.state() == State.PREPARED
                && layoutAba.drawRequests == 0 && layoutAba.removeCalls == 0,
                "completed layout ABA frame admitted or removed owned child early");
        layoutAba.advance(1);
        require(layoutAba.drawRequests == 0 && layoutAba.removeCalls == 1
                && layoutAba.parentOf(layoutAbaLease.ownedChild()) == null
                && !layoutAba.containsIdentity(layoutAbaLease.ownedChild())
                && !layoutAbaLease.mayDraw()
                && layoutAbaLease.state() == State.REMOVING
                && layoutAbaLease.result() == Result.PENDING
                && layoutAbaLease.reason() == Reason.DRIFT,
                "deferred layout ABA bypassed the admission revision fence");
        layoutAba.advance(2);
        require(layoutAbaLease.state() == State.REMOVED
                && layoutAbaLease.result() == Result.UNKNOWN
                && layoutAbaLease.reason() == Reason.DRIFT
                && !layoutAbaSlot.occupied(),
                "restored stock metadata promoted an ABA lease to a live pass");
        layoutAba.exactNine();

        FakePort betweenAddAndPollAba = new FakePort();
        Slot abaSlot = new Slot();
        TargetOwnedVisualLeaseCore abaLease = TargetOwnedVisualLeaseCore.startForTest(
                abaSlot, betweenAddAndPollAba, new TargetOwnedVisualLeaseCore.Factory() {
                    @Override public Object create(DrawGate drawGate) { return new GateBoundChild(drawGate); }
                }, 1, 1, 50, 10, 10, 40);
        require(abaLease.state() == State.PREPARED
                && betweenAddAndPollAba.drawRequests == 0,
                "ABA fixture painted before completed frame");
        String originalScene = betweenAddAndPollAba.scene;
        betweenAddAndPollAba.evidenceMutationRevision++;
        betweenAddAndPollAba.scene = "page B|uri B|render B|root 1404x1872|epoch 2";
        betweenAddAndPollAba.evidenceMutationRevision++;
        betweenAddAndPollAba.scene = originalScene;
        betweenAddAndPollAba.advance(1); // Frame and live snapshot both look unchanged.
        require(betweenAddAndPollAba.drawRequests == 0
                && betweenAddAndPollAba.removeCalls == 1
                && !abaLease.mayDraw(),
                "scene ABA between add and paint poll was adopted as baseline");
        betweenAddAndPollAba.advance(2);
        require(abaLease.result() == Result.UNKNOWN,
                "admission ABA produced a live rollback claim");

        FakePort insideAddAba = new FakePort();
        insideAddAba.sceneAbaDuringAdd = true;
        TargetOwnedVisualLeaseCore insideAddLease = start(new Slot(), insideAddAba);
        require(insideAddAba.addCalls == 1 && insideAddAba.removeCalls == 1
                && insideAddAba.drawRequests == 0 && !insideAddLease.mayDraw(),
                "unrelated reentrant ABA inside add passed exact-one-revision contract");
        insideAddAba.advance(2);
        require(insideAddLease.result() == Result.UNKNOWN,
                "inside-add scene ABA produced a live rollback claim");

        FakePort delayed = new FakePort();
        delayed.autoAddPaint = false;
        TargetOwnedVisualLeaseCore delayedLease = start(new Slot(), delayed);
        require(delayedLease.state() == State.PREPARED && delayed.children.size() == 10
                && delayed.drawRequests == 0 && !delayedLease.mayDraw(),
                "attached child painted before a completed ten-child frame");
        delayed.scheduleFreshPaint(5);
        delayed.advance(4);
        require(delayedLease.state() == State.PREPARED && !delayedLease.mayDraw()
                && delayed.drawRequests == 0,
                "pending admission painted before its delayed frame");
        delayed.advance(1);
        require(delayedLease.state() == State.INSERTED && delayed.drawRequests == 1
                && delayedLease.mayDraw(),
                "fresh completed ten-child frame did not admit drawing");

        FakePort noFrame = new FakePort();
        noFrame.autoAddPaint = false;
        Slot noFrameSlot = new Slot();
        TargetOwnedVisualLeaseCore noFrameLease = start(noFrameSlot, noFrame);
        require(noFrameLease.state() == State.PREPARED && !noFrameLease.mayDraw(),
                "missing paint frame was admitted");
        noFrame.advance(40);
        require(noFrameLease.state() == State.REMOVING && noFrame.removeCalls == 1
                && noFrame.drawRequests == 0,
                "paint-wait timeout retained an attached pending child");
        noFrame.advance(2);
        require(noFrameLease.state() == State.REMOVED
                && noFrameLease.result() == Result.UNKNOWN && !noFrameSlot.occupied(),
                "missing admission frame produced a live rollback claim");

        FakePort staleBegin = new FakePort();
        staleBegin.autoAddPaint = false;
        staleBegin.beginPaintDuringAdd = true;
        TargetOwnedVisualLeaseCore staleLease = start(new Slot(), staleBegin);
        staleBegin.advance(1); // Completes a frame begun before the post-add fence.
        require(staleLease.state() == State.PREPARED && !staleLease.mayDraw()
                && staleBegin.drawRequests == 0,
                "pre-add-begun frame was mistaken for fresh admission");
        staleBegin.scheduleFreshPaint(1);
        staleBegin.advance(2);
        require(staleLease.state() == State.INSERTED && staleBegin.drawRequests == 1,
                "later genuinely begun frame did not admit after stale frame");

        FakePort staleBaseline = new FakePort();
        staleBaseline.now = 141; // Completed nine-child frame is 41 ms old.
        TargetOwnedVisualLeaseCore baselineLease = start(new Slot(), staleBaseline);
        require(staleBaseline.addCalls == 0 && !baselineLease.mayDraw(),
                "stale pre-add nine-child paint frame admitted mutation");
        staleBaseline.advance(1);
        require(baselineLease.result() == Result.UNKNOWN,
                "stale pre-add frame was reported as a live pass");

        FakePort wrongPaintSlot = new FakePort();
        wrongPaintSlot.paintInsertSlot = 2;
        TargetOwnedVisualLeaseCore wrongPaintLease = start(new Slot(), wrongPaintSlot);
        require(!wrongPaintLease.mayDraw() && wrongPaintSlot.drawRequests == 0,
                "completed frame at wrong paint rank admitted pixels");
        wrongPaintSlot.advance(2);
        require(wrongPaintLease.result() == Result.UNKNOWN
                && wrongPaintSlot.removeCalls == 1,
                "wrong paint rank escaped exact-object cleanup");

        FakePort sceneDrift = new FakePort();
        sceneDrift.autoAddPaint = false;
        TargetOwnedVisualLeaseCore sceneLease = start(new Slot(), sceneDrift);
        sceneDrift.scene = "page B|uri B|render B|root 1404x1872|epoch 2";
        sceneDrift.scheduleFreshPaint(1);
        sceneDrift.advance(2);
        require(sceneLease.state() == State.QUARANTINED
                && sceneLease.result() == Result.UNKNOWN && sceneDrift.drawRequests == 0,
                "pending scene drift admitted a completed frame");

        FakePort metadataDrift = new FakePort();
        metadataDrift.autoAddPaint = false;
        TargetOwnedVisualLeaseCore metadataLease = start(new Slot(), metadataDrift);
        metadataDrift.evidence.put(metadataDrift.original[4], "stock layout changed");
        metadataDrift.scheduleFreshPaint(1);
        metadataDrift.advance(2);
        require(metadataLease.state() == State.QUARANTINED
                && metadataLease.result() == Result.UNKNOWN
                && metadataDrift.drawRequests == 0,
                "pending metadata drift admitted a completed frame");

        FakePort pausedPending = new FakePort();
        pausedPending.autoAddPaint = false;
        TargetOwnedVisualLeaseCore pausedLease = start(new Slot(), pausedPending);
        pausedPending.pause.run();
        require(!pausedLease.mayDraw(), "pending child painted after pause signal");
        pausedPending.runReady();
        pausedPending.advance(2);
        require(pausedLease.state() == State.REMOVED
                && pausedLease.result() == Result.UNKNOWN
                && pausedPending.removeCalls == 1 && pausedPending.drawRequests == 0,
                "pause during pending admission escaped exact-object cleanup");

        FakePort rootLostPending = new FakePort();
        rootLostPending.autoAddPaint = false;
        TargetOwnedVisualLeaseCore rootLostLease = start(new Slot(), rootLostPending);
        rootLostPending.rootAlive = false;
        rootLostPending.rootLoss.run();
        rootLostPending.runReady();
        require(rootLostLease.state() == State.QUARANTINED
                && rootLostLease.result() == Result.UNKNOWN
                && rootLostPending.removeCalls == 1 && rootLostPending.drawRequests == 0,
                "pending root loss admitted pixels or a live pass");

        FakePort processLostPending = new FakePort();
        processLostPending.autoAddPaint = false;
        TargetOwnedVisualLeaseCore processLostLease = start(new Slot(), processLostPending);
        processLostPending.processAlive = false;
        processLostLease.requestCleanup(Reason.PROCESS_LOSS);
        processLostPending.runReady();
        require(processLostLease.state() == State.QUARANTINED
                && processLostLease.result() == Result.UNKNOWN
                && processLostPending.drawRequests == 0,
                "pending process loss admitted pixels or a live pass");

        FakePort preAddReentry = new FakePort();
        preAddReentry.inlineDispatch = true;
        TargetOwnedVisualLeaseCore preAddLease = start(new Slot(), preAddReentry,
                new TargetOwnedVisualLeaseCore.Factory() {
                    @Override public Object create(DrawGate drawGate) {
                        preAddReentry.afterNextSnapshot = new Runnable() {
                            @Override public void run() { preAddReentry.pause.run(); }
                        };
                        return new GateBoundChild(drawGate);
                    }
                });
        require(preAddLease.state() == State.REMOVING && preAddReentry.addCalls == 0,
                "pre-add snapshot reentry bypassed the terminal-state check");
        preAddReentry.advance(1);
        require(preAddLease.result() == Result.UNKNOWN,
                "pre-add reentrant pause manufactured live restoration");

        FakePort admissionReentry = new FakePort();
        admissionReentry.autoAddPaint = false;
        admissionReentry.inlineDispatch = true;
        TargetOwnedVisualLeaseCore reentrantLease = start(new Slot(), admissionReentry);
        admissionReentry.scheduleFreshPaint(1);
        admissionReentry.advance(1); // Poll precedes the completed frame.
        admissionReentry.afterNextSnapshot = new Runnable() {
            @Override public void run() { reentrantLease.requestCleanup(Reason.HOST_STOP); }
        };
        admissionReentry.advance(1);
        require(reentrantLease.state() == State.REMOVING
                && admissionReentry.drawRequests == 0 && !reentrantLease.mayDraw(),
                "post-paint snapshot reentry resurrected admission after stop");
        admissionReentry.advance(2);
        require(reentrantLease.state() == State.REMOVED
                && reentrantLease.result() == Result.UNKNOWN,
                "reentrant stop during admission produced a live pass");

        FakePort addThrow = new FakePort();
        addThrow.throwAfterAttach = true;
        TargetOwnedVisualLeaseCore addThrowLease = start(new Slot(), addThrow);
        require(!addThrowLease.mayDraw() && addThrow.drawRequests == 0
                && addThrow.removeCalls == 1,
                "add-then-throw admitted pixels before cleanup");

        FakePort failedPost = new FakePort();
        failedPost.failPaintScheduleAfterAdd = true;
        TargetOwnedVisualLeaseCore failedPostLease = start(new Slot(), failedPost);
        failedPost.advance(2);
        require(failedPostLease.state() == State.REMOVED
                && failedPostLease.result() == Result.UNKNOWN
                && failedPostLease.failure() != null
                && failedPost.removeCalls == 1 && failedPost.drawRequests == 0,
                "failed admission callback post left a drawable child");

        FakePort lateCallback = new FakePort();
        lateCallback.autoAddPaint = false;
        TargetOwnedVisualLeaseCore lateLease = start(new Slot(), lateCallback);
        Runnable oldPoll = lateCallback.lastScheduledCallback;
        lateLease.requestCleanup(Reason.HOST_STOP);
        lateCallback.runReady();
        lateCallback.advance(2);
        require(lateLease.state() == State.REMOVED, "explicit stop did not settle");
        oldPoll.run(); // A queued poll can arrive after terminal cleanup.
        require(lateLease.state() == State.REMOVED && lateCallback.removeCalls == 1
                && lateCallback.drawRequests == 0,
                "late paint callback re-admitted or re-removed the child");
    }

    private static void testCompletedPaintRestoration() {
        FakePort noRemovalFrame = new FakePort();
        noRemovalFrame.autoRemovePaint = false;
        Slot noRemovalSlot = new Slot();
        TargetOwnedVisualLeaseCore noRemovalLease = start(noRemovalSlot, noRemovalFrame);
        noRemovalLease.requestCleanup(Reason.HOST_STOP);
        noRemovalFrame.runReady();
        require(noRemovalFrame.children.size() == 9
                && noRemovalLease.state() == State.REMOVING,
                "structural nine was mistaken for a painted restoration");
        noRemovalFrame.advance(39);
        require(noRemovalLease.state() == State.REMOVING,
                "post-removal paint wait was not bounded correctly");
        noRemovalFrame.advance(1);
        require(noRemovalLease.state() == State.QUARANTINED
                && noRemovalLease.result() == Result.UNKNOWN
                && noRemovalSlot.occupied(),
                "missing fresh nine-child frame manufactured live restoration");

        FakePort staleRemoval = new FakePort();
        staleRemoval.beginPaintBeforeRemove = true;
        staleRemoval.autoRemovePaint = false;
        TargetOwnedVisualLeaseCore staleRemovalLease = start(new Slot(), staleRemoval);
        staleRemovalLease.requestCleanup(Reason.HOST_STOP);
        staleRemoval.runReady();
        staleRemoval.advance(1); // Frame begun before remove, completed afterward.
        require(staleRemovalLease.state() == State.REMOVING,
                "pre-removal-begun frame was mistaken for restoration");
        staleRemoval.scheduleFreshPaint(1);
        staleRemoval.advance(3);
        require(staleRemovalLease.state() == State.REMOVED
                && staleRemovalLease.result() == Result.LIVE_STRUCTURE_RESTORED,
                "later fresh nine-child frame was not accepted");

        FakePort failedPost = new FakePort();
        failedPost.failPaintScheduleAfterRemove = true;
        Slot failedPostSlot = new Slot();
        TargetOwnedVisualLeaseCore failedPostLease = start(failedPostSlot, failedPost);
        failedPostLease.requestCleanup(Reason.HOST_STOP);
        failedPost.runReady();
        require(failedPostLease.state() == State.QUARANTINED
                && failedPostLease.result() == Result.UNKNOWN
                && failedPostSlot.occupied() && failedPost.removeCalls == 1
                && failedPost.parentOf(failedPostLease.ownedChild()) == null,
                "failed post-removal callback post reported restoration");
    }

    private static void testPostRemoveStructureBeforeFreshPaint() {
        FakePort delayed = new FakePort();
        delayed.setStockSevenVisible(false);
        delayed.completeFreshPaintNow();
        delayed.paintInsertSlot = 7;
        delayed.dropPaintOrderAfterRemove = true;
        delayed.autoRemovePaint = false;
        Slot delayedSlot = new Slot();
        TargetOwnedVisualLeaseCore lease = TargetOwnedVisualLeaseCore.startForTest(
                delayedSlot, delayed, new TargetOwnedVisualLeaseCore.Factory() {
                    @Override public Object create(DrawGate drawGate) {
                        return new GateBoundChild(drawGate);
                    }
                }, 8, 7, 50, 10, 10, 40);
        delayed.advance(1);
        require(lease.state() == State.INSERTED, "post-remove fixture not admitted");
        lease.requestCleanup(Reason.HOST_STOP);
        delayed.runReady();
        long beforeFreshPaint = delayed.startedPaintRevision;
        require(lease.state() == State.REMOVING && lease.result() == Result.PENDING
                && delayed.removeCalls == 1 && delayed.children.size() == 9
                && delayed.paintOrderUnavailable && delayed.lastCompletedPaintFrame == null
                && delayed.snapshotsWithoutPaintOrder > 0 && delayedSlot.occupied(),
                "immediate structural cut required or fabricated a completed paint order");
        delayed.advance(3);
        require(lease.state() == State.REMOVING && lease.result() == Result.PENDING,
                "structural-only post-remove cut produced a live rollback claim");
        delayed.scheduleFreshPaint(1);
        delayed.advance(3);
        require(delayed.startedPaintRevision > beforeFreshPaint
                && delayed.lastCompletedPaintFrame != null
                && lease.state() == State.REMOVED
                && lease.result() == Result.LIVE_STRUCTURE_RESTORED
                && !delayedSlot.occupied(),
                "fresh eight-painted restoration frame was not required and accepted");
        delayed.exactNineWithGoneSeven();

        FakePort reordered = new FakePort();
        reordered.dropPaintOrderAfterRemove = true;
        reordered.autoRemovePaint = false;
        Slot reorderedSlot = new Slot();
        TargetOwnedVisualLeaseCore reorderedLease = start(reorderedSlot, reordered);
        reorderedLease.requestCleanup(Reason.HOST_STOP);
        reordered.runReady();
        require(reorderedLease.state() == State.REMOVING
                && reordered.paintOrderUnavailable,
                "reordered-paint fixture did not pass the immediate structural cut");
        Object firstVisible = reordered.effectiveDrawOrder.get(1);
        reordered.effectiveDrawOrder.set(1, reordered.effectiveDrawOrder.get(2));
        reordered.effectiveDrawOrder.set(2, firstVisible);
        reordered.scheduleFreshPaint(1);
        reordered.advance(3);
        require(reordered.lastCompletedPaintFrame != null
                && reorderedLease.state() == State.QUARANTINED
                && reorderedLease.result() == Result.UNKNOWN
                && reorderedSlot.occupied(),
                "fresh frame with reordered visible siblings passed restoration");

        FakePort sceneDrift = new FakePort();
        sceneDrift.dropPaintOrderAfterRemove = true;
        sceneDrift.autoRemovePaint = false;
        Slot sceneSlot = new Slot();
        TargetOwnedVisualLeaseCore driftedLease = start(sceneSlot, sceneDrift);
        driftedLease.requestCleanup(Reason.HOST_STOP);
        sceneDrift.runReady();
        require(driftedLease.state() == State.REMOVING,
                "scene-drift fixture did not pass the immediate structural cut");
        sceneDrift.evidenceMutationRevision++;
        sceneDrift.scene = "page B|uri B|render B|root 1404x1872|epoch 2";
        sceneDrift.scheduleFreshPaint(1);
        sceneDrift.advance(3);
        require(sceneDrift.lastCompletedPaintFrame != null
                && driftedLease.state() == State.QUARANTINED
                && driftedLease.result() == Result.UNKNOWN && sceneSlot.occupied(),
                "fresh frame after scene drift passed restoration");
    }

    private static void testSlowPaintReadsAndQueuedStop() {
        FakePort slowPreAdd = new FakePort();
        slowPreAdd.nextCompletedPaintReadAdvance = 50;
        TargetOwnedVisualLeaseCore preAddLease = start(new Slot(), slowPreAdd);
        require(slowPreAdd.addCalls == 0 && preAddLease.result() == Result.PENDING,
                "pre-add paint read crossed the deadline but still attached a child");
        slowPreAdd.advance(1);
        require(preAddLease.state() == State.REMOVED
                && preAddLease.result() == Result.UNKNOWN,
                "expired pre-add frame produced a live rollback claim");

        FakePort agedPreAddPaint = new FakePort();
        agedPreAddPaint.nextCompletedPaintReadAdvance = 30;
        TargetOwnedVisualLeaseCore agedLease = TargetOwnedVisualLeaseCore.startForTest(
                new Slot(), agedPreAddPaint, new TargetOwnedVisualLeaseCore.Factory() {
                    @Override public Object create(DrawGate drawGate) { return new GateBoundChild(drawGate); }
                }, 1, 1, 50, 10, 10, 25);
        require(agedPreAddPaint.now == 130 && agedPreAddPaint.addCalls == 0
                && agedLease.reason() == Reason.DRIFT,
                "paint aged past pre-add freshness bound before a live deadline");
        agedPreAddPaint.advance(1);
        require(agedLease.state() == State.REMOVED
                && agedLease.result() == Result.UNKNOWN,
                "stale pre-add paint produced a live rollback claim");

        FakePort preAddMutation = new FakePort();
        TargetOwnedVisualLeaseCore preAddMutationLease = start(new Slot(), preAddMutation,
                new TargetOwnedVisualLeaseCore.Factory() {
                    @Override public Object create(DrawGate drawGate) {
                        preAddMutation.afterNextSnapshot = new Runnable() {
                            @Override public void run() {
                                preAddMutation.evidenceMutationRevision++;
                                preAddMutation.scene = "page B";
                            }
                        };
                        return new GateBoundChild(drawGate);
                    }
                });
        require(preAddMutation.addCalls == 0
                && preAddMutationLease.result() != Result.LIVE_STRUCTURE_RESTORED,
                "pre-add snapshot mutation escaped the evidence fence");

        FakePort slowAdmission = new FakePort();
        slowAdmission.autoAddPaint = false;
        TargetOwnedVisualLeaseCore admissionLease = start(new Slot(), slowAdmission);
        slowAdmission.scheduleFreshPaint(1);
        slowAdmission.advance(1); // Frame completes after the first poll.
        slowAdmission.afterNextSnapshot = new Runnable() {
            @Override public void run() { slowAdmission.now += 40; }
        };
        slowAdmission.advance(1);
        require(admissionLease.state() == State.REMOVING
                && slowAdmission.drawRequests == 0 && slowAdmission.removeCalls == 1,
                "admission snapshot crossed paint-wait bound and requested pixels");
        slowAdmission.advance(2);
        require(admissionLease.result() == Result.UNKNOWN,
                "late admission read produced a live rollback claim");

        FakePort admissionMutation = new FakePort();
        admissionMutation.autoAddPaint = false;
        TargetOwnedVisualLeaseCore mutatedAdmissionLease = start(new Slot(),
                admissionMutation);
        admissionMutation.scheduleFreshPaint(1);
        admissionMutation.advance(1);
        admissionMutation.afterNextSnapshot = new Runnable() {
            @Override public void run() {
                admissionMutation.evidenceMutationRevision++;
                admissionMutation.scene = "page B";
            }
        };
        admissionMutation.advance(1);
        require(admissionMutation.drawRequests == 0
                && admissionMutation.removeCalls == 1
                && mutatedAdmissionLease.result() == Result.UNKNOWN,
                "admission snapshot mutation promoted a drawable child");

        FakePort queuedStop = new FakePort();
        queuedStop.autoAddPaint = false;
        TargetOwnedVisualLeaseCore queuedLease = start(new Slot(), queuedStop);
        queuedStop.scheduleFreshPaint(1);
        queuedStop.advance(1);
        queuedStop.dispatchDelay = 10;
        queuedStop.afterNextSnapshot = new Runnable() {
            @Override public void run() { queuedLease.requestCleanup(Reason.HOST_STOP); }
        };
        queuedStop.advance(1);
        require(queuedLease.state() == State.REMOVING
                && queuedStop.drawRequests == 0 && queuedStop.removeCalls == 1
                && !queuedLease.mayDraw(),
                "queued HOST_STOP during admission snapshot promoted pending child");
        queuedStop.advance(2);
        require(queuedLease.result() == Result.UNKNOWN,
                "queued stop during pending admission produced a live pass");

        FakePort drawStop = new FakePort();
        TargetOwnedVisualLeaseCore drawLease = start(new Slot(), drawStop);
        drawStop.dispatchDelay = 10;
        drawStop.afterNextSnapshot = new Runnable() {
            @Override public void run() { drawLease.requestCleanup(Reason.HOST_STOP); }
        };
        require(!drawLease.mayDraw() && drawLease.failure() == null,
                "queued HOST_STOP during draw witness escaped the draw guard");
        drawStop.advance(12);
        require(drawLease.state() == State.REMOVED
                && drawLease.result() == Result.LIVE_STRUCTURE_RESTORED,
                "queued draw-stop changed successful exact-object rollback");

        FakePort drawMutation = new FakePort();
        TargetOwnedVisualLeaseCore mutatedDrawLease = start(new Slot(), drawMutation);
        drawMutation.afterNextSnapshot = new Runnable() {
            @Override public void run() {
                drawMutation.evidenceMutationRevision++;
                drawMutation.scene = "page B";
            }
        };
        require(!mutatedDrawLease.mayDraw(),
                "draw witness captured before scene mutation still authorized pixels");
        drawMutation.runReady();
        require(mutatedDrawLease.result() == Result.UNKNOWN,
                "draw-time scene mutation produced a live rollback claim");

        FakePort slowRestoration = new FakePort();
        Slot slowRestorationSlot = new Slot();
        TargetOwnedVisualLeaseCore restorationLease = start(slowRestorationSlot,
                slowRestoration);
        restorationLease.requestCleanup(Reason.HOST_STOP);
        slowRestoration.runReady();
        slowRestoration.afterNextSnapshot = new Runnable() {
            @Override public void run() { slowRestoration.snapshotAdvance = 40; }
        };
        slowRestoration.advance(1);
        require(restorationLease.state() == State.QUARANTINED
                && restorationLease.result() == Result.UNKNOWN
                && slowRestorationSlot.occupied(),
                "restoration snapshot crossed paint-wait bound and accepted sample");
    }

    private static void testFinalPaintProofAndDispatchFailure() {
        FakePort expiredFrame = new FakePort();
        Slot expiredSlot = new Slot();
        TargetOwnedVisualLeaseCore expiredLease = TargetOwnedVisualLeaseCore.startForTest(
                expiredSlot, expiredFrame, new TargetOwnedVisualLeaseCore.Factory() {
                    @Override public Object create(DrawGate drawGate) { return new GateBoundChild(drawGate); }
                }, 1, 1, 50, 10, 100, 5);
        expiredFrame.advance(1);
        expiredLease.requestCleanup(Reason.HOST_STOP);
        expiredFrame.runReady();
        expiredFrame.advance(1); // Accept fresh nine-child frame.
        require(expiredLease.state() == State.REMOVING,
                "expired-frame fixture did not reach two-sample restoration");
        expiredFrame.now += 5; // Verification gap is 100; paint age alone fails.
        expiredFrame.runReady();
        require(expiredLease.state() == State.QUARANTINED
                && expiredLease.result() == Result.UNKNOWN && expiredSlot.occupied(),
                "expired paint proof passed the final sample");

        FakePort unfinished = new FakePort();
        Slot unfinishedSlot = new Slot();
        TargetOwnedVisualLeaseCore unfinishedLease = start(unfinishedSlot, unfinished);
        unfinishedLease.requestCleanup(Reason.HOST_STOP);
        unfinished.runReady();
        unfinished.advance(1);
        unfinished.startedPaintRevision++; // A newer paint began but did not finish.
        unfinished.advance(1);
        require(unfinishedLease.state() == State.QUARANTINED
                && unfinishedLease.result() == Result.UNKNOWN && unfinishedSlot.occupied(),
                "unfinished newer paint was ignored at final restoration proof");

        FakePort superseded = new FakePort();
        Slot supersededSlot = new Slot();
        TargetOwnedVisualLeaseCore supersededLease = start(supersededSlot, superseded);
        supersededLease.requestCleanup(Reason.HOST_STOP);
        superseded.runReady();
        superseded.advance(1);
        long newRevision = ++superseded.startedPaintRevision;
        superseded.lastCompletedPaintFrame = new PaintFrame(newRevision,
                superseded.now, superseded.snapshot());
        superseded.advance(1);
        require(supersededLease.state() == State.QUARANTINED
                && supersededLease.result() == Result.UNKNOWN && supersededSlot.occupied(),
                "superseded nine-child paint was accepted as the original proof");

        FakePort commitSeam = new FakePort();
        Slot commitSlot = new Slot();
        TargetOwnedVisualLeaseCore commitLease = start(commitSlot, commitSeam);
        commitLease.requestCleanup(Reason.HOST_STOP);
        commitSeam.runReady();
        commitSeam.advance(1);
        commitSeam.beginUnfinishedPaintOnRelease = true;
        commitSeam.advance(1);
        require(commitLease.state() == State.QUARANTINED
                && commitLease.result() == Result.UNKNOWN && commitSlot.occupied(),
                "new paint during callback release escaped terminal proof");

        FakePort sceneDuringProof = new FakePort();
        Slot sceneSlot = new Slot();
        TargetOwnedVisualLeaseCore sceneLease = start(sceneSlot, sceneDuringProof);
        sceneLease.requestCleanup(Reason.HOST_STOP);
        sceneDuringProof.runReady();
        sceneDuringProof.advance(1);
        sceneDuringProof.driftSceneOnReleasePaintRead = true;
        sceneDuringProof.advance(1);
        require(sceneLease.state() == State.QUARANTINED
                && sceneLease.result() == Result.UNKNOWN && sceneSlot.occupied(),
                "scene drift during paint-proof read escaped terminal nine-child check");

        FakePort finalSnapshotDrift = new FakePort();
        Slot finalSnapshotSlot = new Slot();
        TargetOwnedVisualLeaseCore finalSnapshotLease = start(finalSnapshotSlot,
                finalSnapshotDrift);
        finalSnapshotLease.requestCleanup(Reason.HOST_STOP);
        finalSnapshotDrift.runReady();
        finalSnapshotDrift.advance(1);
        finalSnapshotDrift.driftSceneOnFinalSnapshot = true;
        finalSnapshotDrift.advance(1);
        require(finalSnapshotLease.state() == State.QUARANTINED
                && finalSnapshotLease.result() == Result.UNKNOWN
                && finalSnapshotSlot.occupied()
                && finalSnapshotDrift.snapshotsUntilSceneDrift == 0,
                "final snapshot mutated scene after capture without tripping revision fence");

        FakePort rejectedDispatch = new FakePort();
        Slot rejectedSlot = new Slot();
        TargetOwnedVisualLeaseCore rejectedLease = start(rejectedSlot, rejectedDispatch);
        rejectedDispatch.failNextDispatch = true;
        rejectedLease.requestCleanup(Reason.HOST_STOP);
        require(rejectedLease.state() == State.QUARANTINED
                && rejectedLease.result() == Result.UNKNOWN
                && rejectedDispatch.removeCalls == 1 && !rejectedLease.mayDraw(),
                "rejected cleanup dispatch left a drawable child");
        rejectedDispatch.advance(2);
        require(rejectedLease.failure() != null && rejectedSlot.occupied()
                && rejectedDispatch.children.size() == 9,
                "rejected cleanup dispatch released authority or skipped exact removal");

        FakePort rejectedOffMain = new FakePort();
        Slot offMainSlot = new Slot();
        TargetOwnedVisualLeaseCore offMainLease = start(offMainSlot, rejectedOffMain);
        rejectedOffMain.onMainThread = false;
        rejectedOffMain.failNextDispatch = true;
        offMainLease.requestCleanup(Reason.HOST_STOP);
        rejectedOffMain.onMainThread = true;
        require(offMainLease.state() == State.QUARANTINED
                && offMainLease.result() == Result.UNKNOWN
                && rejectedOffMain.children.size() == 10
                && rejectedOffMain.removeCalls == 0 && offMainSlot.occupied()
                && !offMainLease.mayDraw(),
                "off-main rejected dispatch mutated hierarchy or allowed drawing");
    }

    private static void testRootProcessLossAndRemoveFailures() {
        FakePort rootLost = new FakePort();
        TargetOwnedVisualLeaseCore rootLease = start(new Slot(), rootLost);
        rootLost.rootAlive = false;
        rootLost.rootLoss.run();
        rootLost.runReady();
        require(rootLease.state() == State.QUARANTINED
                && rootLease.result() != Result.LIVE_STRUCTURE_RESTORED
                && rootLost.removeCalls == 1, "lost root did not remove exact owned child");
        rootLost.exactNine();

        FakePort movedOnRootLoss = new FakePort();
        TargetOwnedVisualLeaseCore movedRootLease = start(new Slot(), movedOnRootLoss);
        movedOnRootLoss.removeOwnedExternally(movedRootLease.ownedChild());
        movedOnRootLoss.parents.put(movedRootLease.ownedChild(), movedOnRootLoss.foreignParent);
        movedOnRootLoss.rootAlive = false;
        movedOnRootLoss.rootLoss.run();
        movedOnRootLoss.runReady();
        require(movedRootLease.state() == State.QUARANTINED
                && movedOnRootLoss.removeCalls == 0
                && movedOnRootLoss.parentOf(movedRootLease.ownedChild())
                        == movedOnRootLoss.foreignParent,
                "root loss touched an unrelated parent");

        FakePort rootLostDuringVerification = new FakePort();
        TargetOwnedVisualLeaseCore pending = start(new Slot(), rootLostDuringVerification);
        pending.requestCleanup(Reason.HOST_STOP);
        rootLostDuringVerification.runReady();
        rootLostDuringVerification.children.add(1, pending.ownedChild());
        rootLostDuringVerification.parents.put(pending.ownedChild(),
                rootLostDuringVerification.root);
        rootLostDuringVerification.rootAlive = false;
        rootLostDuringVerification.rootLoss.run();
        rootLostDuringVerification.runReady();
        require(pending.state() == State.QUARANTINED
                && rootLostDuringVerification.removeCalls == 2,
                "root loss during verification left reattached owned child");
        rootLostDuringVerification.exactNine();

        FakePort processLost = new FakePort();
        TargetOwnedVisualLeaseCore processLease = start(new Slot(), processLost);
        processLost.processAlive = false;
        processLease.requestCleanup(Reason.PROCESS_LOSS);
        processLost.runReady();
        require(processLease.state() == State.QUARANTINED
                && processLease.result() != Result.LIVE_STRUCTURE_RESTORED,
                "process loss produced live rollback PASS");

        FakePort lossBetweenSamples = new FakePort();
        TargetOwnedVisualLeaseCore between = start(new Slot(), lossBetweenSamples);
        between.requestCleanup(Reason.HOST_STOP);
        lossBetweenSamples.runReady();
        lossBetweenSamples.processAlive = false;
        lossBetweenSamples.advance(1);
        require(between.state() == State.QUARANTINED
                && between.result() != Result.LIVE_STRUCTURE_RESTORED,
                "process loss during verification produced live rollback PASS");

        FakePort movedAfterRemoval = new FakePort();
        TargetOwnedVisualLeaseCore movedAfter = start(new Slot(), movedAfterRemoval);
        movedAfter.requestCleanup(Reason.HOST_STOP);
        movedAfterRemoval.runReady();
        movedAfterRemoval.parents.put(movedAfter.ownedChild(), movedAfterRemoval.foreignParent);
        movedAfterRemoval.advance(1);
        require(movedAfter.state() == State.QUARANTINED,
                "owned child moved after removal passed verification");

        FakePort failedRemove = new FakePort();
        failedRemove.throwBeforeRemove = true;
        TargetOwnedVisualLeaseCore removeLease = start(new Slot(), failedRemove);
        removeLease.requestCleanup(Reason.HOST_STOP);
        failedRemove.runReady();
        require(removeLease.state() == State.QUARANTINED && removeLease.failure() != null,
                "remove exception was silently passed");

        FakePort detachedThenThrow = new FakePort();
        detachedThenThrow.throwAfterRemove = true;
        TargetOwnedVisualLeaseCore detachedLease = start(new Slot(), detachedThenThrow);
        detachedLease.requestCleanup(Reason.HOST_STOP);
        detachedThenThrow.runReady();
        require(detachedLease.state() == State.QUARANTINED && detachedLease.failure() != null,
                "post-remove exception was silently passed");
        detachedThenThrow.exactNine();
    }

    private static void testPageWriterWitnessAdmission() {
        FakePort inheritedDefaults = new FakePort();
        Slot defaultSlot = new Slot();
        inheritedDefaults.useDefaultPageWriterMethods = true;
        TargetOwnedVisualLeaseCore defaultLease = start(defaultSlot, inheritedDefaults);
        require(defaultLease.state() == State.QUARANTINED
                && inheritedDefaults.addCalls == 0 && defaultSlot.occupied(),
                "unwired Port defaults admitted a visual child");

        FakePort missing = new FakePort();
        Slot missingSlot = new Slot();
        missing.pageWriterWitnessAvailable = false;
        TargetOwnedVisualLeaseCore missingLease = start(missingSlot, missing);
        require(missingLease.state() == State.QUARANTINED && missing.addCalls == 0
                && missingSlot.occupied(),
                "missing typed page/writer authority admitted a visual child");

        FakePort unknownRevision = new FakePort();
        unknownRevision.pageWriterRevisionAvailable = false;
        TargetOwnedVisualLeaseCore unknownLease = start(new Slot(), unknownRevision);
        require(unknownLease.state() == State.QUARANTINED
                && unknownRevision.addCalls == 0,
                "unknown page/writer revision admitted a visual child");

        FakePort preAddAba = new FakePort();
        long unchangedSceneRevision = preAddAba.evidenceMutationRevision;
        TargetOwnedVisualLeaseCore preAddLease = start(new Slot(), preAddAba,
                new TargetOwnedVisualLeaseCore.Factory() {
                    @Override public Object create(DrawGate drawGate) {
                        preAddAba.abaWriterEnablement();
                        return new GateBoundChild(drawGate);
                    }
                });
        require(preAddLease.state() == State.QUARANTINED && preAddAba.addCalls == 0
                && preAddAba.writerEnabled
                && preAddAba.evidenceMutationRevision == unchangedSceneRevision,
                "pre-add writer enablement ABA escaped the typed revision fence");

        FakePort addAba = new FakePort();
        addAba.writerAbaDuringAdd = true;
        TargetOwnedVisualLeaseCore addLease = start(new Slot(), addAba);
        require(addLease.state() == State.QUARANTINED && addAba.addCalls == 1
                && addAba.removeCalls == 1 && addAba.writerEnabled,
                "writer ABA inside add escaped exact-child cleanup");
        addAba.exactNine();

        FakePort admissionAba = new FakePort();
        admissionAba.autoAddPaint = false;
        TargetOwnedVisualLeaseCore admissionLease = start(new Slot(), admissionAba);
        admissionAba.scheduleFreshPaint(1);
        admissionAba.afterNextPageWriterWitnessRead = new Runnable() {
            @Override public void run() { admissionAba.abaWriterEnablement(); }
        };
        admissionAba.advance(2);
        require(admissionLease.state() == State.QUARANTINED
                && admissionAba.drawRequests == 0 && admissionAba.removeCalls == 1
                && admissionAba.writerEnabled,
                "reentrant writer ABA during admission requested pixels");
        admissionAba.exactNine();
    }

    private static void testPageWriterWitnessDrawAndRollback() {
        for (int changed = 0; changed < 3; changed++) {
            FakePort port = new FakePort();
            Slot slot = new Slot();
            TargetOwnedVisualLeaseCore lease = start(slot, port);
            require(lease.state() == State.INSERTED && lease.mayDraw()
                    && port.writerEnabled,
                    "stable enabled native writer should not itself block a visual lease");
            long unchangedSceneRevision = port.evidenceMutationRevision;
            long unchangedWriterRevision = port.pageWriterRevision;
            // Deliberately violate the Port's revision promise as well:
            // typed identity/enablement must not collapse to an epoch check.
            if (changed == 0) {
                port.pageIdentity = new Identity("page A"); // equals() lies.
            } else if (changed == 1) {
                port.writerIdentity = new Identity("native writer A");
            } else {
                port.writerEnabled = false;
            }
            require(!lease.mayDraw() && port.evidenceMutationRevision == unchangedSceneRevision
                    && port.pageWriterRevision == unchangedWriterRevision,
                    "typed page/writer drift allowed drawing in case " + changed);
            port.runReady();
            require(lease.state() == State.QUARANTINED
                    && lease.result() == Result.UNKNOWN && slot.occupied()
                    && port.removeCalls == 1,
                    "typed drift made a live rollback claim in case " + changed);
            port.exactNine();
        }

        FakePort drawAba = new FakePort();
        Slot drawSlot = new Slot();
        TargetOwnedVisualLeaseCore drawLease = start(drawSlot, drawAba);
        drawAba.afterNextPageWriterWitnessRead = new Runnable() {
            @Override public void run() { drawAba.abaWriterEnablement(); }
        };
        require(!drawLease.mayDraw(),
                "reentrant writer ABA during draw witness authorized pixels");
        drawAba.runReady();
        require(drawLease.state() == State.QUARANTINED
                && drawLease.result() == Result.UNKNOWN && drawSlot.occupied()
                && drawAba.removeCalls == 1,
                "reentrant draw ABA produced a live rollback claim");
        drawAba.exactNine();

        FakePort restorationAba = new FakePort();
        Slot restorationSlot = new Slot();
        TargetOwnedVisualLeaseCore restorationLease = start(restorationSlot, restorationAba);
        restorationLease.requestCleanup(Reason.HOST_STOP);
        restorationAba.runReady();
        restorationAba.abaWriterEnablement();
        restorationAba.advance(2);
        require(restorationLease.state() == State.QUARANTINED
                && restorationLease.result() == Result.UNKNOWN
                && restorationSlot.occupied(),
                "writer ABA after exact removal passed restoration frame");
        restorationAba.exactNine();

        FakePort releaseAba = new FakePort();
        Slot releaseSlot = new Slot();
        TargetOwnedVisualLeaseCore releaseLease = start(releaseSlot, releaseAba);
        releaseLease.requestCleanup(Reason.HOST_STOP);
        releaseAba.runReady();
        releaseAba.advance(1);
        releaseAba.writerAbaOnRelease = true;
        releaseAba.advance(1);
        require(releaseLease.state() == State.QUARANTINED
                && releaseLease.result() == Result.UNKNOWN && releaseSlot.occupied()
                && releaseAba.writerEnabled && releaseAba.removeCalls == 1,
                "writer ABA during callback release passed the terminal commit");
        releaseAba.exactNine();

        FakePort lateClockAba = new FakePort();
        Slot lateClockSlot = new Slot();
        TargetOwnedVisualLeaseCore lateClockLease = start(lateClockSlot, lateClockAba);
        lateClockLease.requestCleanup(Reason.HOST_STOP);
        lateClockAba.runReady();
        lateClockAba.advance(1);
        lateClockAba.abaAfterSecondReleasedWriterRead = true;
        lateClockAba.advance(1);
        require(lateClockAba.pageWriterReadsAfterRelease >= 2
                && !lateClockAba.abaOnNextClockRead
                && lateClockAba.pageWriterRevision == 3 && lateClockAba.writerEnabled
                && lateClockLease.state() == State.QUARANTINED
                && lateClockLease.result() == Result.UNKNOWN && lateClockSlot.occupied(),
                "writer ABA after final typed read escaped the pure commit fence");
        lateClockAba.exactNine();

        FakePort reentrant = new FakePort();
        Slot reentrantSlot = new Slot();
        TargetOwnedVisualLeaseCore reentrantLease = start(reentrantSlot, reentrant);
        reentrant.activeLease = reentrantLease;
        reentrantLease.requestCleanup(Reason.HOST_STOP);
        reentrant.runReady();
        reentrant.advance(1);
        reentrant.stopOnPostReleaseWriterRead = true;
        reentrant.advance(1);
        require(reentrantLease.state() == State.QUARANTINED
                && !reentrant.stopOnPostReleaseWriterRead
                && reentrantLease.result() == Result.UNKNOWN && reentrantSlot.occupied()
                && reentrant.removeCalls == 1,
                "reentrant stop from terminal page/writer read released the slot");
        reentrant.exactNine();
    }

    public static void main(String[] args) {
        testPreboundDrawGate();
        testPortRejectsWrongDrawGate();
        testNormalAndCollision();
        testProductionSlot();
        testAttachThenThrow();
        testPreInsertionReauthentication();
        testUnattachedPreparationFailures();
        testDeadlineAndLifecycle();
        testDrawPathDrift();
        testBoundedVerificationGap();
        testFinalizationSignals();
        testMovedMissingAndImpostor();
        testNineChildAndEvidenceVerification();
        testEffectiveDrawingOrderEvidence();
        testGoneChildPaintRepresentation();
        testLegacyAllVisibleSnapshotCompatibility();
        testGoneChildWithCustomPaintOrder();
        testGoneVisibilityAndUnexpectedOmissions();
        testCompletedPaintAdmission();
        testCompletedPaintRestoration();
        testPostRemoveStructureBeforeFreshPaint();
        testSlowPaintReadsAndQueuedStop();
        testFinalPaintProofAndDispatchFailure();
        testRootProcessLossAndRemoveFailures();
        testPageWriterWitnessAdmission();
        testPageWriterWitnessDrawAndRollback();
        System.out.println("TARGET_OWNED_VISUAL_LEASE_CORE_PASS checks=" + checks);
    }
}
