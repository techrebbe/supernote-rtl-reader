package com.techrebbe.supernote.viewportprobe;

import com.techrebbe.supernote.viewportprobe.TargetOwnedVisualLeaseCore.Port;
import com.techrebbe.supernote.viewportprobe.TargetOwnedVisualLeaseCore.Reason;
import com.techrebbe.supernote.viewportprobe.TargetOwnedVisualLeaseCore.Registration;
import com.techrebbe.supernote.viewportprobe.TargetOwnedVisualLeaseCore.Result;
import com.techrebbe.supernote.viewportprobe.TargetOwnedVisualLeaseCore.Slot;
import com.techrebbe.supernote.viewportprobe.TargetOwnedVisualLeaseCore.Snapshot;
import com.techrebbe.supernote.viewportprobe.TargetOwnedVisualLeaseCore.State;
import java.util.ArrayList;
import java.util.IdentityHashMap;
import java.util.Iterator;
import java.util.List;

public final class TargetOwnedVisualLeaseCoreTest {
    private static int checks;

    // Deliberately hostile: equality cannot identify any child or its parent.
    private static final class Identity {
        final String name;
        Identity(String name) { this.name = name; }
        @Override public boolean equals(Object other) { return other instanceof Identity; }
        @Override public int hashCode() { return 1; }
        @Override public String toString() { return name; }
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
        final IdentityHashMap<Object, Object> parents = new IdentityHashMap<Object, Object>();
        final IdentityHashMap<Object, String> evidence = new IdentityHashMap<Object, String>();
        final List<Event> events = new ArrayList<Event>();
        long now = 100;
        long nextOrder;
        long dispatchDelay;
        boolean processAlive = true;
        boolean rootAlive = true;
        boolean inlineDispatch;
        boolean lossChangesHostState;
        Reason lossOnCancel;
        Reason lossOnRelease;
        Reason lossOnPostReleaseRootRead;
        int signalOnPostReleaseRootRead;
        int rootReadsAfterRelease;
        boolean callbacksReleased;
        TargetOwnedVisualLeaseCore activeLease;
        boolean armed;
        boolean addSawDeadline;
        long deadlineDelay = -1;
        long armAdvance;
        long scheduleAdvance;
        long snapshotAdvance;
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
        int removeCalls;
        int addCalls;
        boolean throwBeforeAdd;
        boolean throwAfterAttach;
        boolean throwBeforeRemove;
        boolean throwAfterRemove;
        long removeAdvance;
        String scene = "page A|uri A|render A|root 1404x1872|epoch 1";
        Runnable pause;
        Runnable rootLoss;
        Runnable drift;

        FakePort() {
            for (int i = 0; i < 9; i++) {
                original[i] = new Identity("stock " + i);
                children.add(original[i]);
                parents.put(original[i], root);
                evidence.put(original[i], "class|id|draw|visibility|bounds|z|layout " + i);
            }
        }

        @Override public void requireMainThread() { /* deterministic one-thread executor */ }
        @Override public long elapsedRealtimeMillis() { return now; }
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
            for (int i = 0; i < seen.length; i++) {
                seenParents[i] = parents.get(seen[i]);
                seenEvidence[i] = evidence.get(seen[i]);
            }
            return new Snapshot(root, seen, seenParents, seenEvidence, scene);
        }
        @Override public Object parentOf(Object child) { return parents.get(child); }
        @Override public void add(Object child, int provenSlot) {
            addCalls++;
            require(armed, "lifecycle callbacks were not armed before add");
            require(addSawDeadline, "target deadline was not armed before add");
            if (throwBeforeAdd) throw new IllegalStateException("before add");
            children.add(provenSlot, child);
            parents.put(child, root);
            evidence.put(child, "owned visual only");
            now += addAdvance;
            if (detachRootAfterAdd) rootAlive = false;
            if (throwAfterAttach) throw new IllegalStateException("attached then threw");
        }
        @Override public void remove(Object child) {
            removeCalls++;
            if (throwBeforeRemove) throw new IllegalStateException("before remove");
            boolean found = false;
            for (Iterator<Object> iter = children.iterator(); iter.hasNext();) {
                if (iter.next() == child) {
                    iter.remove();
                    found = true;
                    break;
                }
            }
            if (found) parents.remove(child);
            now += removeAdvance;
            if (throwAfterRemove) throw new IllegalStateException("after remove");
        }
        @Override public void dispatch(Runnable callback) {
            if (inlineDispatch) callback.run();
            else schedule(callback, dispatchDelay);
        }
        @Override public void schedule(Runnable callback, long delayMillis) {
            require(delayMillis >= 0, "negative delay");
            events.add(new Event(now + delayMillis, nextOrder++, callback));
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
            if (changeSceneWhileArming) scene = "page B|uri B|render B|epoch 2";
            if (reorderWhileArming) {
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
        void advance(long millis) { now += millis; runReady(); }
        void exactNine() {
            require(children.size() == 9, "wrong child count");
            for (int i = 0; i < 9; i++) {
                require(children.get(i) == original[i], "wrong child identity/order at " + i);
                require(parents.get(original[i]) == root, "stock child moved");
            }
        }
        void removeOwnedExternally(Object owned) {
            for (Iterator<Object> iter = children.iterator(); iter.hasNext();) {
                if (iter.next() == owned) { iter.remove(); break; }
            }
            parents.remove(owned);
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

    private static TargetOwnedVisualLeaseCore start(Slot slot, FakePort port) {
        return start(slot, port,
                new TargetOwnedVisualLeaseCore.Factory() {
                    @Override public Object create() { return new Identity("owned"); }
                });
    }

    private static TargetOwnedVisualLeaseCore start(Slot slot, FakePort port,
            TargetOwnedVisualLeaseCore.Factory factory) {
        return TargetOwnedVisualLeaseCore.startForTest(slot, port, factory, 1, 50, 10, 10);
    }

    private static void testNormalAndCollision() {
        Slot slot = new Slot();
        FakePort port = new FakePort();
        TargetOwnedVisualLeaseCore lease = start(slot, port);
        require(lease.state() == State.INSERTED, "not inserted");
        require(port.children.size() == 10 && port.children.get(1) == lease.ownedChild(),
                "wrong insertion slot");
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
        port.advance(1);
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
            @Override public Object create() { return new Identity("owned"); }
        };
        FakePort first = new FakePort();
        TargetOwnedVisualLeaseCore lease = TargetOwnedVisualLeaseCore.start(first, factory, 1, 50, 10, 10);
        try {
            TargetOwnedVisualLeaseCore.start(new FakePort(), factory, 1, 50, 10, 10);
            throw new AssertionError("production slot admitted a second lease");
        } catch (IllegalStateException expected) { checks++; }
        lease.requestCleanup(Reason.HOST_STOP);
        first.runReady();
        first.advance(1);
        require(lease.state() == State.REMOVED, "production slot did not release");
        FakePort second = new FakePort();
        TargetOwnedVisualLeaseCore next = TargetOwnedVisualLeaseCore.start(second, factory, 1, 50, 10, 10);
        require(next.state() == State.INSERTED, "production slot did not admit safe next lease");
        next.requestCleanup(Reason.HOST_STOP);
        second.runReady();
        second.advance(1);
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
        port.advance(1);
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
                    @Override public Object create() {
                        factoryTime.now += 20;
                        return new Identity("owned");
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
                    @Override public Object create() {
                        expiredFactory.now += 60;
                        return new Identity("owned");
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
        slowAdd.advance(1);
        require(slowAddLease.state() == State.QUARANTINED && slowAddSlot.occupied(),
                "late add produced a live restoration or released its slot");
        slowAdd.exactNine();
    }

    private static void testUnattachedPreparationFailures() {
        FakePort nullChild = new FakePort();
        Slot childSlot = new Slot();
        TargetOwnedVisualLeaseCore childLease = start(childSlot, nullChild,
                new TargetOwnedVisualLeaseCore.Factory() {
                    @Override public Object create() { return null; }
                });
        require(childLease.state() == State.REMOVING && nullChild.addCalls == 0,
                "null factory child was not verified");
        nullChild.advance(1);
        require(childLease.state() == State.REMOVED && childLease.result() == Result.UNKNOWN
                && !childSlot.occupied(), "null factory child leaked slot");
        nullChild.exactNine();

        FakePort failedFactory = new FakePort();
        Slot failedSlot = new Slot();
        TargetOwnedVisualLeaseCore failedLease = start(failedSlot, failedFactory,
                new TargetOwnedVisualLeaseCore.Factory() {
                    @Override public Object create() {
                        throw new IllegalStateException("factory failure");
                    }
                });
        failedFactory.advance(1);
        require(failedLease.state() == State.REMOVED && failedLease.failure() != null
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
        TargetOwnedVisualLeaseCore borrowed = start(foreignSlot, foreignFactory,
                new TargetOwnedVisualLeaseCore.Factory() {
                    @Override public Object create() { return foreignChild; }
                });
        require(borrowed.state() == State.QUARANTINED
                && borrowed.reason() == Reason.INSERTION_FAILURE
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
        signaled.advance(1);
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
        slowWitness.snapshotAdvance = 60;
        require(!slowLease.mayDraw(), "draw crossed deadline inside witness capture");
        slowWitness.snapshotAdvance = 0;
        slowWitness.runReady();
        slowWitness.advance(1);
        require(slowLease.state() == State.REMOVED,
                "slow witness did not schedule expired cleanup");

        FakePort ownedChanged = new FakePort();
        TargetOwnedVisualLeaseCore ownedLease = start(new Slot(), ownedChanged);
        ownedChanged.evidence.put(ownedLease.ownedChild(), "owned Z/geometry changed");
        require(!ownedLease.mayDraw(), "owned child drift painted after insertion");
        ownedChanged.runReady();
        ownedChanged.advance(1);
        require(ownedLease.state() == State.REMOVED && ownedLease.result() == Result.UNKNOWN,
                "owned child drift was reported as live restoration");
        ownedChanged.exactNine();
    }

    private static void testBoundedVerificationGap() {
        FakePort onBound = new FakePort();
        TargetOwnedVisualLeaseCore timely = start(new Slot(), onBound);
        timely.requestCleanup(Reason.HOST_STOP);
        onBound.runReady();
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
            port.runReady(); // First sample; the verifier is still queued.
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
        stalled.advance(1);
        require(expired.state() == State.REMOVED && !expired.mayDraw()
                && expired.result() == Result.LIVE_STRUCTURE_RESTORED
                && !expired.deadlineLatenessExceeded(),
                "deadline cleanup failed");
        stalled.exactNine();

        FakePort boundary = new FakePort();
        TargetOwnedVisualLeaseCore onBound = start(new Slot(), boundary);
        boundary.now = 160; // Deadline 150; lateness bound 10 is inclusive.
        boundary.runReady();
        boundary.advance(1);
        require(onBound.state() == State.REMOVED && !onBound.deadlineLatenessExceeded(),
                "on-bound callback was treated as late");

        FakePort stalledTooLong = new FakePort();
        Slot stalledSlot = new Slot();
        TargetOwnedVisualLeaseCore late = start(stalledSlot, stalledTooLong);
        stalledTooLong.now = 170; // Main-loop stall beyond the declared bound.
        stalledTooLong.runReady();
        stalledTooLong.advance(1);
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
        resumed.advance(1);
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
        slowRemoval.advance(1);
        require(removalCrossedBound.state() == State.QUARANTINED
                && removalCrossedBound.deadlineLatenessExceeded(),
                "slow exact removal crossed bound but reported live restoration");

        FakePort paused = new FakePort();
        TargetOwnedVisualLeaseCore activity = start(new Slot(), paused);
        paused.pause.run();
        activity.requestCleanup(Reason.HOST_STOP);
        paused.runReady();
        paused.advance(1);
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

    public static void main(String[] args) {
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
        testRootProcessLossAndRemoveFailures();
        System.out.println("TARGET_OWNED_VISUAL_LEASE_CORE_PASS checks=" + checks);
    }
}
