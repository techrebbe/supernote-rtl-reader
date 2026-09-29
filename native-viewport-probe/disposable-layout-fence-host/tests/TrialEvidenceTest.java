package com.techrebbe.supernote.layoutfencetrial;

/** Deterministic Java-8 checks; no Android runtime, Frida, ADB or device. */
public final class TrialEvidenceTest {
    private static int checks;
    private static final TrialEvidence.Command[] RESTORING_COMMANDS = {
        TrialEvidence.Command.PARENT_PLUS, TrialEvidence.Command.PARENT_MINUS,
        TrialEvidence.Command.DIRECT_LAYOUT, TrialEvidence.Command.DIRECT_OFFSET
    };

    private static void check(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }

    private static final class Fixture {
        final Object root = new Object();
        final Object[] children = new Object[TrialEvidence.ORIGINAL_COUNT];
        final Object[] parents = new Object[TrialEvidence.ORIGINAL_COUNT];
        final String[] metadata = new String[TrialEvidence.ORIGINAL_COUNT];
        final TrialEvidence.Bounds base = new TrialEvidence.Bounds(0, 0, 100, 100);

        Fixture() {
            for (int i = 0; i < children.length; i++) {
                children[i] = new Object();
                parents[i] = root;
                metadata[i] = "child-" + i;
            }
        }

        TrialEvidence.Cut cut(TrialEvidence.Bounds bounds, long parentRevision,
                long write, long layout, long started, long paintParent,
                long paintWrite, long completed, long completedAt) {
            return cut(bounds, parentRevision, write, layout, started, paintParent,
                    paintWrite, completed, completedAt, children.clone(), "scene");
        }

        TrialEvidence.Cut cut(TrialEvidence.Bounds bounds, long parentRevision,
                long write, long layout, long started, long paintParent,
                long paintWrite, long completed, long completedAt,
                Object[] order, String scene) {
            return cutAt(bounds, parentRevision, write, layout, started,
                    Math.max(0, completedAt - 1), paintParent, paintWrite,
                    completed, completedAt, order, scene);
        }

        TrialEvidence.Cut cutAt(TrialEvidence.Bounds bounds, long parentRevision,
                long write, long layout, long started, long paintStartedAt,
                long paintParent, long paintWrite, long completed, long completedAt) {
            return cutAt(bounds, parentRevision, write, layout, started,
                    paintStartedAt, paintParent, paintWrite, completed, completedAt,
                    children.clone(), "scene");
        }

        TrialEvidence.Cut cutAt(TrialEvidence.Bounds bounds, long parentRevision,
                long write, long layout, long started, long paintStartedAt,
                long paintParent, long paintWrite, long completed, long completedAt,
                Object[] order, String scene) {
            return new TrialEvidence.Cut(root,
                    TrialContract.rootToken("process", "one"), scene, bounds, 9,
                    children, parents, metadata, order, parentRevision, write,
                    layout, started, paintStartedAt, paintParent, paintWrite,
                    completed, completedAt);
        }

        TrialEvidence.Cut baseline() {
            return cut(base, 10, 20, 3, 5, 10, 20, 5, 1000);
        }

        TrialEvidence.Cut firstAfter(TrialEvidence.Bounds bounds,
                long parentRevision, long write, long layout) {
            return cut(bounds, parentRevision, write, layout, 5, 10, 20, 5, 1000);
        }

        TrialEvidence.Cut firstFrame(TrialEvidence.Bounds bounds,
                long parentRevision, long write, long layout) {
            return cut(bounds, parentRevision, write, layout, 6,
                    parentRevision, write, 6, 1020);
        }

        TrialEvidence.Cut restoreAfter(long parentRevision, long write,
                long layout, TrialEvidence.Cut firstFrame) {
            return cut(base, parentRevision, write, layout,
                    firstFrame.startedPaintRevision,
                    firstFrame.paintStartParentRevision,
                    firstFrame.paintStartWriteOrdinal,
                    firstFrame.completedPaintRevision,
                    firstFrame.completedPaintElapsedMs);
        }

        TrialEvidence.Cut restoredFrame(long parentRevision, long write, long layout) {
            return cut(base, parentRevision, write, layout, 7,
                    parentRevision, write, 7, 1040);
        }
    }

    private static void parentPulse(TrialEvidence.Command command, int delta) {
        Fixture f = new Fixture();
        TrialEvidence.Cut baseline = f.baseline();
        TrialEvidence.Trial proof = TrialEvidence.Trial.begin(command, baseline, 1005);
        TrialEvidence.Bounds target = f.base.withRightDelta(delta);
        check(proof.onParentPreCall(baseline, target, 11, 1010), "parent pre-call");
        check(proof.state() == TrialEvidence.State.WAIT_FIRST_CALL,
                "pre-call cannot claim changed root yet");
        TrialEvidence.Cut after = f.firstAfter(target, 11, 21, 4);
        proof.onParentLayoutAfter(after, 1011);
        check(proof.state() == TrialEvidence.State.WAIT_FIRST_PAINT,
                "layout alone cannot pass");
        TrialEvidence.Cut firstFrame = f.firstFrame(target, 11, 21, 4);
        proof.onCompletedPaint(firstFrame, 1021);
        check(proof.state() == TrialEvidence.State.WAIT_RESTORE_CALL,
                "changed frame requires restore");
        check(proof.onParentPreCall(firstFrame, f.base, 12, 1030),
                "restoration pre-call");
        proof.onParentLayoutAfter(f.restoreAfter(12, 22, 5, firstFrame), 1031);
        check(proof.state() == TrialEvidence.State.WAIT_RESTORE_PAINT,
                "restored bounds require fresh paint");
        TrialEvidence.Cut restored = f.restoredFrame(12, 22, 5);
        proof.onCompletedPaint(restored, 1041);
        check(proof.state() == TrialEvidence.State.WAIT_SECOND_PAINT_REQUEST,
                "one restored frame is not enough");
        check(proof.requestSecondPaint(restored, restored, 1070),
                "explicit spaced second-paint request");
        TrialEvidence.Cut second = f.cutAt(f.base, 12, 22, 5, 8, 1075,
                12, 22, 8, 1080);
        proof.onCompletedPaint(second, 1081);
        check(proof.state() == TrialEvidence.State.WAIT_FINAL_SAMPLE,
                "second actual paint required before final sample");
        proof.onSecondSample(second, second, 1082);
        check(proof.state() == TrialEvidence.State.PASS, "two-sample restore");
        check(proof.rollbackVerified(), "rollback verified");
        check(!proof.completeMutationCoverage(), "path proof is never complete authority");
        check(!proof.bypassObserved(), "parent call not bypass");
        check(proof.abaAway() == null, "non-ABA parent JSON cut is null");
        check(proof.restoreEntryDrift() == null,
                "successful restoration has no failure-only entry diagnostic");
    }

    private static TrialEvidence.Trial waitingForRestore(Fixture f,
            TrialEvidence.Cut firstFrame) {
        TrialEvidence.Cut baseline = f.baseline();
        TrialEvidence.Trial proof = TrialEvidence.Trial.begin(
                TrialEvidence.Command.PARENT_PLUS, baseline, 1005);
        TrialEvidence.Bounds target = f.base.withRightDelta(1);
        check(proof.onParentPreCall(baseline, target, 11, 1010),
                "diagnostic fixture first pre-call");
        proof.onParentLayoutAfter(f.firstAfter(target, 11, 21, 4), 1011);
        proof.onCompletedPaint(firstFrame, 1021);
        check(proof.state() == TrialEvidence.State.WAIT_RESTORE_CALL,
                "diagnostic fixture reached restore entry");
        check(proof.restoreEntryDrift() == null,
                "diagnostic absent before a failed restore comparison");
        return proof;
    }

    private static TrialEvidence.Trial waitingForSecondPaintRequest(Fixture f) {
        return waitingForSecondPaintRequest(f, TrialEvidence.Command.PARENT_PLUS);
    }

    private static TrialEvidence.Trial waitingForSecondPaintRequest(Fixture f,
            TrialEvidence.Command command) {
        boolean direct = command == TrialEvidence.Command.DIRECT_LAYOUT
                || command == TrialEvidence.Command.DIRECT_OFFSET;
        TrialEvidence.Bounds target = command == TrialEvidence.Command.PARENT_MINUS
                ? f.base.withRightDelta(-1)
                : command == TrialEvidence.Command.DIRECT_OFFSET
                    ? f.base.shiftedRight(1) : f.base.withRightDelta(1);
        long firstRevision = direct ? 10 : 11;
        long firstLayout = command == TrialEvidence.Command.DIRECT_OFFSET ? 3 : 4;
        TrialEvidence.Cut baseline = f.baseline();
        TrialEvidence.Trial proof = TrialEvidence.Trial.begin(command, baseline, 1005);
        TrialEvidence.Cut after = f.firstAfter(target, firstRevision, 21, firstLayout);
        if (direct) proof.onDirectAfter(baseline, after, 1010);
        else {
            check(proof.onParentPreCall(baseline, target, 11, 1010),
                    "restoring command first pre-call");
            proof.onParentLayoutAfter(after, 1011);
        }
        check(!proof.claimUnchangedFirstPaintRequest(after),
                command.wire + " cannot claim an unchanged-control first paint");
        TrialEvidence.Cut firstFrame = f.firstFrame(target, firstRevision, 21,
                firstLayout);
        proof.onCompletedPaint(firstFrame, 1021);
        check(proof.state() == TrialEvidence.State.WAIT_RESTORE_CALL,
                "restoring command has a distinct restore phase");
        long restoreRevision = firstRevision + 1;
        check(proof.onParentPreCall(firstFrame, f.base, restoreRevision, 1030),
                "restore entry remains the first changed frame");
        TrialEvidence.Cut restoreAfter = f.restoreAfter(restoreRevision, 22,
                firstLayout + 1, firstFrame);
        proof.onParentLayoutAfter(restoreAfter, 1031);
        check(proof.shouldRequestRestorePaint(restoreAfter)
                        == (command == TrialEvidence.Command.DIRECT_OFFSET),
                command.wire + " post-restore redraw remains command-specific");
        check(!proof.claimUnchangedFirstPaintRequest(restoreAfter),
                command.wire + " restore cannot claim an unchanged-control first paint");
        proof.onCompletedPaint(f.restoredFrame(restoreRevision, 22,
                firstLayout + 1), 1041);
        check(proof.state() == TrialEvidence.State.WAIT_SECOND_PAINT_REQUEST,
                "first restored paint waits for an explicit second request");
        return proof;
    }

    private static TrialEvidence.Cut interveningFrame(Fixture f,
            TrialEvidence.Trial proof) {
        TrialEvidence.Cut restored = proof.restoredFrame();
        long revision = restored.startedPaintRevision + 1;
        return f.cutAt(f.base, restored.parentPreCallRevision,
                restored.observedWriteOrdinal, restored.rootLayoutCalls,
                revision, restored.completedPaintElapsedMs + 5,
                restored.parentPreCallRevision, restored.observedWriteOrdinal,
                revision, restored.completedPaintElapsedMs + 6);
    }

    private static void oneInterveningRestoredPaint() {
        Fixture f = new Fixture();
        TrialEvidence.Trial proof = waitingForSecondPaintRequest(f);
        TrialEvidence.Cut firstRestored = proof.restoredFrame();
        TrialEvidence.Cut intervening = f.cutAt(f.base, 12, 22, 5,
                8, 1045, 12, 22, 8, 1046);
        proof.onCompletedPaint(intervening, 1047);
        check(proof.state() == TrialEvidence.State.WAIT_SECOND_PAINT_REQUEST
                        && proof.interveningRestoredFrame() == intervening
                        && proof.restoredFrame() == firstRestored
                        && proof.secondPaintAnchor() == intervening
                        && !proof.rollbackVerified(),
                "one exact intervening frame remains non-voting");
    }

    private static void interveningThenRequestedPaint() {
        Fixture f = new Fixture();
        TrialEvidence.Trial proof = waitingForSecondPaintRequest(f);
        TrialEvidence.Cut firstRestored = proof.restoredFrame();
        TrialEvidence.Cut intervening = f.cutAt(f.base, 12, 22, 5,
                8, 1045, 12, 22, 8, 1046);
        proof.onCompletedPaint(intervening, 1047);
        check(proof.state() == TrialEvidence.State.WAIT_SECOND_PAINT_REQUEST
                        && proof.restoredFrame() == firstRestored,
                "first restored frame remains immutable");
        check(proof.requestSecondPaint(intervening, intervening, 1075),
                "later explicit request uses intervening frame as quiet anchor");
        check(proof.secondPaintRequestElapsedMs() == 1075
                        && proof.secondPaintStartRevisionFloor() == 8,
                "request time and paint floor retained for independent host proof");
        TrialEvidence.Cut second = f.cutAt(f.base, 12, 22, 5,
                9, 1076, 12, 22, 9, 1077);
        proof.onCompletedPaint(second, 1078);
        check(proof.state() == TrialEvidence.State.WAIT_FINAL_SAMPLE,
                "intervening frame did not substitute for requested frame");
        proof.onSecondSample(second, second, 1079);
        check(proof.state() == TrialEvidence.State.PASS && proof.rollbackVerified(),
                "fresh requested frame plus stable final sample verifies rollback");
        check(!proof.currentlyValid(intervening, intervening, 1080, 30000),
                "superseded intervening frame cannot serve as live PASS");
    }

    private static void oneExtraAcrossRestoringCommands() {
        for (TrialEvidence.Command command : RESTORING_COMMANDS) {
            Fixture f = new Fixture();
            TrialEvidence.Trial proof = waitingForSecondPaintRequest(f, command);
            TrialEvidence.Cut restored = proof.restoredFrame();
            TrialEvidence.Cut extra = interveningFrame(f, proof);
            proof.onCompletedPaint(extra, 1047);
            check(proof.state() == TrialEvidence.State.WAIT_SECOND_PAINT_REQUEST
                            && proof.restoredFrame() == restored
                            && proof.interveningRestoredFrame() == extra
                            && proof.secondPaintAnchor() == extra
                            && !proof.rollbackVerified(),
                    command.wire + " extra frame is non-voting and leaves restore immutable");
            check(proof.requestSecondPaint(extra, extra, 1075),
                    command.wire + " requires a later explicit paint request");
            check(proof.secondPaintStartRevisionFloor() == extra.startedPaintRevision,
                    command.wire + " request floor is the extra frame");
            TrialEvidence.Cut second = f.cutAt(f.base,
                    extra.parentPreCallRevision, extra.observedWriteOrdinal,
                    extra.rootLayoutCalls, extra.startedPaintRevision + 1, 1076,
                    extra.parentPreCallRevision, extra.observedWriteOrdinal,
                    extra.startedPaintRevision + 1, 1077);
            proof.onCompletedPaint(second, 1078);
            check(proof.state() == TrialEvidence.State.WAIT_FINAL_SAMPLE,
                    command.wire + " extra cannot replace requested paint");
            proof.onSecondSample(second, second, 1079);
            check(proof.state() == TrialEvidence.State.PASS
                            && proof.rollbackVerified()
                            && !proof.completeMutationCoverage(),
                    command.wire + " distinct requested paint verifies scoped rollback");
        }
    }

    private static void extraFrameDriftAcrossRestoringCommands() {
        for (TrialEvidence.Command command : RESTORING_COMMANDS) {
            for (int mutation = 0; mutation < 7; mutation++) {
                Fixture f = new Fixture();
                TrialEvidence.Trial proof = waitingForSecondPaintRequest(f, command);
                TrialEvidence.Cut restored = proof.restoredFrame();
                TrialEvidence.Cut extra = interveningFrame(f, proof);
                TrialEvidence.Cut changed;
                if (mutation == 0) {
                    changed = f.cutAt(f.base, extra.parentPreCallRevision,
                            extra.observedWriteOrdinal + 1, extra.rootLayoutCalls,
                            extra.startedPaintRevision, 1045,
                            extra.parentPreCallRevision, extra.observedWriteOrdinal + 1,
                            extra.completedPaintRevision, 1046);
                } else if (mutation == 1) {
                    changed = f.cutAt(f.base.withRightDelta(1),
                            extra.parentPreCallRevision, extra.observedWriteOrdinal,
                            extra.rootLayoutCalls, extra.startedPaintRevision, 1045,
                            extra.parentPreCallRevision, extra.observedWriteOrdinal,
                            extra.completedPaintRevision, 1046);
                } else if (mutation == 2) {
                    changed = f.cutAt(f.base, extra.parentPreCallRevision,
                            extra.observedWriteOrdinal, extra.rootLayoutCalls,
                            restored.startedPaintRevision + 2, 1045,
                            extra.parentPreCallRevision, extra.observedWriteOrdinal,
                            restored.startedPaintRevision + 2, 1046);
                } else if (mutation == 3) {
                    changed = f.cutAt(f.base, extra.parentPreCallRevision,
                            extra.observedWriteOrdinal, extra.rootLayoutCalls,
                            extra.startedPaintRevision,
                            restored.completedPaintElapsedMs - 1,
                            extra.parentPreCallRevision, extra.observedWriteOrdinal,
                            extra.completedPaintRevision, 1046);
                } else if (mutation == 4) {
                    Fixture other = new Fixture();
                    changed = other.cutAt(other.base, extra.parentPreCallRevision,
                            extra.observedWriteOrdinal, extra.rootLayoutCalls,
                            extra.startedPaintRevision, 1045,
                            extra.parentPreCallRevision, extra.observedWriteOrdinal,
                            extra.completedPaintRevision, 1046);
                } else if (mutation == 5) {
                    Object[] wrongOrder = f.children.clone();
                    wrongOrder[0] = wrongOrder[1];
                    changed = f.cutAt(f.base, extra.parentPreCallRevision,
                            extra.observedWriteOrdinal, extra.rootLayoutCalls,
                            extra.startedPaintRevision, 1045,
                            extra.parentPreCallRevision, extra.observedWriteOrdinal,
                            extra.completedPaintRevision, 1046, wrongOrder, "scene");
                } else {
                    changed = f.cutAt(f.base, extra.parentPreCallRevision,
                            extra.observedWriteOrdinal, extra.rootLayoutCalls,
                            extra.startedPaintRevision, 1045,
                            extra.parentPreCallRevision, extra.observedWriteOrdinal,
                            extra.completedPaintRevision, 2041);
                }
                proof.onCompletedPaint(changed, mutation == 6 ? 2042 : 1047);
                check(proof.state() == TrialEvidence.State.UNKNOWN
                                && "UNREQUESTED_SECOND_PAINT".equals(proof.reason()),
                        command.wire + " extra mutation " + mutation + " rejected");
            }
            Fixture f = new Fixture();
            TrialEvidence.Trial duplicate = waitingForSecondPaintRequest(f, command);
            duplicate.onCompletedPaint(interveningFrame(f, duplicate), 1047);
            TrialEvidence.Cut anchor = duplicate.interveningRestoredFrame();
            duplicate.onCompletedPaint(f.cutAt(f.base,
                    anchor.parentPreCallRevision, anchor.observedWriteOrdinal,
                    anchor.rootLayoutCalls, anchor.startedPaintRevision + 1, 1048,
                    anchor.parentPreCallRevision, anchor.observedWriteOrdinal,
                    anchor.startedPaintRevision + 1, 1049), 1050);
            check(duplicate.state() == TrialEvidence.State.UNKNOWN
                            && "UNREQUESTED_SECOND_PAINT".equals(duplicate.reason()),
                    command.wire + " second unsolicited frame rejected");

            Fixture earlyFixture = new Fixture();
            TrialEvidence.Trial early = waitingForSecondPaintRequest(
                    earlyFixture, command);
            TrialEvidence.Cut earlyExtra = interveningFrame(earlyFixture, early);
            early.onCompletedPaint(earlyExtra, 1047);
            check(!early.requestSecondPaint(earlyExtra, earlyExtra, 1070)
                            && early.state() == TrialEvidence.State.UNKNOWN,
                    command.wire + " request before the extra-frame quiet gap rejected");

            Fixture staleFixture = new Fixture();
            TrialEvidence.Trial stale = waitingForSecondPaintRequest(
                    staleFixture, command);
            TrialEvidence.Cut staleExtra = interveningFrame(staleFixture, stale);
            stale.onCompletedPaint(staleExtra, 1047);
            check(stale.requestSecondPaint(staleExtra, staleExtra, 1075),
                    command.wire + " setup later request");
            stale.onCompletedPaint(staleExtra, 1078);
            check(stale.state() == TrialEvidence.State.UNKNOWN
                            && "SECOND_COMPLETED_PAINT_MISMATCH".equals(stale.reason()),
                    command.wire + " extra frame cannot impersonate requested paint");
        }
    }

    private static void noRestoreCommandsRejectExtra() {
        for (TrialEvidence.Command command : new TrialEvidence.Command[] {
                TrialEvidence.Command.UNCHANGED, TrialEvidence.Command.ABA}) {
            Fixture f = new Fixture();
            TrialEvidence.Cut baseline = f.baseline();
            TrialEvidence.Trial proof = TrialEvidence.Trial.begin(command, baseline, 1005);
            if (command == TrialEvidence.Command.UNCHANGED) {
                check(proof.onParentPreCall(baseline, f.base, 11, 1010),
                        "unchanged setup pre-call");
                proof.onParentLayoutAfter(f.firstAfter(f.base, 11, 21, 3), 1011);
                proof.onCompletedPaint(f.firstFrame(f.base, 11, 21, 3), 1021);
            } else {
                TrialEvidence.Bounds away = f.base.withRightDelta(1);
                check(proof.onParentPreCall(baseline, away, 11, 1010),
                        "ABA setup away pre-call");
                TrialEvidence.Cut awayAfter = f.firstAfter(away, 11, 21, 4);
                proof.onParentLayoutAfter(awayAfter, 1011);
                check(proof.onParentPreCall(awayAfter, f.base, 12, 1012),
                        "ABA setup return pre-call");
                proof.onParentLayoutAfter(f.firstAfter(f.base, 12, 22, 5), 1013);
                proof.onCompletedPaint(f.cut(f.base, 12, 22, 5,
                        6, 12, 22, 6, 1020), 1021);
            }
            TrialEvidence.Cut first = proof.restoredFrame();
            check(proof.state() == TrialEvidence.State.WAIT_SECOND_PAINT_REQUEST
                            && proof.restoreAfter() == null
                            && proof.firstFrame() == first,
                    command.wire + " has no separate restored-frame phase");
            proof.onCompletedPaint(f.cutAt(f.base,
                    first.parentPreCallRevision, first.observedWriteOrdinal,
                    first.rootLayoutCalls, first.startedPaintRevision + 1, 1045,
                    first.parentPreCallRevision, first.observedWriteOrdinal,
                    first.startedPaintRevision + 1, 1046), 1047);
            check(proof.state() == TrialEvidence.State.UNKNOWN
                            && "UNREQUESTED_SECOND_PAINT".equals(proof.reason()),
                    command.wire + " unsolicited frame remains rejected");
        }
    }

    private static void rejectedInterveningRestoredPaints() {
        Fixture f = new Fixture();
        TrialEvidence.Trial duplicate = waitingForSecondPaintRequest(f);
        TrialEvidence.Cut first = f.cutAt(f.base, 12, 22, 5,
                8, 1045, 12, 22, 8, 1046);
        duplicate.onCompletedPaint(first, 1047);
        duplicate.onCompletedPaint(f.cutAt(f.base, 12, 22, 5,
                9, 1048, 12, 22, 9, 1049), 1050);
        check(duplicate.state() == TrialEvidence.State.UNKNOWN
                        && "UNREQUESTED_SECOND_PAINT".equals(duplicate.reason()),
                "second intervening frame is never silently accepted");

        TrialEvidence.Trial altered = waitingForSecondPaintRequest(new Fixture());
        Fixture alteredFixture = new Fixture();
        // This different fixture has different child identities despite matching numbers.
        altered.onCompletedPaint(alteredFixture.cutAt(alteredFixture.base, 12, 22, 5,
                8, 1045, 12, 22, 8, 1046), 1047);
        check(altered.state() == TrialEvidence.State.UNKNOWN,
                "different root and children rejected");

        Fixture changed = new Fixture();
        TrialEvidence.Trial revisionDrift = waitingForSecondPaintRequest(changed);
        revisionDrift.onCompletedPaint(changed.cutAt(changed.base, 12, 23, 5,
                8, 1045, 12, 23, 8, 1046), 1047);
        check(revisionDrift.state() == TrialEvidence.State.UNKNOWN,
                "extra write ordinal rejected");

        Fixture wrongOrder = new Fixture();
        TrialEvidence.Trial orderDrift = waitingForSecondPaintRequest(wrongOrder);
        Object[] painted = wrongOrder.children.clone();
        painted[0] = painted[1];
        orderDrift.onCompletedPaint(wrongOrder.cutAt(wrongOrder.base,
                12, 22, 5, 8, 1045, 12, 22, 8, 1046,
                painted, "scene"), 1047);
        check(orderDrift.state() == TrialEvidence.State.UNKNOWN,
                "wrong painted order rejected");

        Fixture shortGap = new Fixture();
        TrialEvidence.Trial early = waitingForSecondPaintRequest(shortGap);
        TrialEvidence.Cut quiet = shortGap.cutAt(shortGap.base, 12, 22, 5,
                8, 1045, 12, 22, 8, 1046);
        early.onCompletedPaint(quiet, 1047);
        check(!early.requestSecondPaint(quiet, quiet, 1070)
                        && early.state() == TrialEvidence.State.UNKNOWN,
                "request less than 25 ms after extra frame remains UNKNOWN");

    }

    private static void restoreEntryDiagnostic() {
        Fixture repeated = new Fixture();
        TrialEvidence.Bounds repeatedTarget = repeated.base.withRightDelta(1);
        TrialEvidence.Cut repeatedFirst = repeated.firstFrame(repeatedTarget, 11, 21, 4);
        TrialEvidence.Trial repeatedProof = waitingForRestore(repeated, repeatedFirst);
        TrialEvidence.Cut repeatedPaint = repeated.cutAt(repeatedTarget, 11, 21, 4,
                7, 1025, 11, 21, 7, 1026);
        check(!repeatedProof.onParentPreCall(repeatedPaint, repeated.base, 12, 1030)
                        && repeatedProof.state() == TrialEvidence.State.UNKNOWN
                        && "RESTORE_ENTRY_DRIFT".equals(repeatedProof.reason())
                        && !repeatedProof.rollbackVerified(),
                "intervening same-state paint cannot become restore proof");
        TrialEvidence.RestoreEntryDiff repeatedDiff = repeatedProof.restoreEntryDrift();
        check(repeatedDiff != null && repeatedDiff.sameRoot
                        && repeatedDiff.firstBounds.equals(repeatedDiff.entryBounds)
                        && repeatedDiff.parentPreCallRevision.firstFrame
                                == repeatedDiff.parentPreCallRevision.entry
                        && repeatedDiff.observedWriteOrdinal.firstFrame
                                == repeatedDiff.observedWriteOrdinal.entry
                        && repeatedDiff.rootLayoutCalls.firstFrame
                                == repeatedDiff.rootLayoutCalls.entry
                        && repeatedDiff.completedPaintRevision.firstFrame == 6
                        && repeatedDiff.completedPaintRevision.entry == 7,
                "duplicate-paint diagnostic isolates paint revision drift");

        Fixture f = new Fixture();
        TrialEvidence.Bounds target = f.base.withRightDelta(1);
        TrialEvidence.Cut firstFrame = f.firstFrame(target, 11, 21, 4);
        TrialEvidence.Trial proof = waitingForRestore(f, firstFrame);
        TrialEvidence.Cut oneChangedField = f.cutAt(target, 11, 21, 4,
                6, 1019, 11, 21, 6, 1021);
        check(!firstFrame.sameLiveFrame(oneChangedField),
                "one changed completion time fails original exact guard");
        check(!proof.onParentPreCall(oneChangedField, f.base, 12, 1030),
                "restore entry with one changed field rejected");
        check(proof.state() == TrialEvidence.State.UNKNOWN
                        && "RESTORE_ENTRY_DRIFT".equals(proof.reason()),
                "diagnostic cannot turn rejected restore into admission");
        TrialEvidence.RestoreEntryDiff diff = proof.restoreEntryDrift();
        check(diff != null && diff.sameRoot && diff.sameRootToken && diff.sameScene,
                "unchanged identities represented only by equality booleans");
        check(diff.firstChildCount == 9 && diff.entryChildCount == 9
                        && diff.firstBounds.equals(target) && diff.entryBounds.equals(target),
                "unchanged count and bounds retained as numeric pairs");
        check(diff.childIdentityMismatchIndices().length == 0
                        && diff.parentIdentityMismatchIndices().length == 0
                        && diff.childEvidenceMismatchIndices().length == 0,
                "one scalar drift has no child identity or evidence mismatch");
        check(diff.completedPaintElapsedMs.firstFrame == 1020
                        && diff.completedPaintElapsedMs.entry == 1021,
                "failed pre-bump completion-time pair retained exactly");
        check(diff.parentPreCallRevision.firstFrame == diff.parentPreCallRevision.entry
                        && diff.observedWriteOrdinal.firstFrame == diff.observedWriteOrdinal.entry
                        && diff.rootLayoutCalls.firstFrame == diff.rootLayoutCalls.entry
                        && diff.startedPaintRevision.firstFrame == diff.startedPaintRevision.entry
                        && diff.paintStartedElapsedMs.firstFrame == diff.paintStartedElapsedMs.entry
                        && diff.paintStartParentRevision.firstFrame
                                == diff.paintStartParentRevision.entry
                        && diff.paintStartWriteOrdinal.firstFrame
                                == diff.paintStartWriteOrdinal.entry
                        && diff.completedPaintRevision.firstFrame
                                == diff.completedPaintRevision.entry,
                "all other exact-cut numeric fields agree");
        check(!proof.onParentPreCall(firstFrame, f.base, 12, 1031)
                        && proof.state() == TrialEvidence.State.UNKNOWN
                        && proof.restoreEntryDrift() == diff,
                "UNKNOWN and first diagnostic remain sticky after later input");

        Fixture changed = new Fixture();
        TrialEvidence.Bounds changedTarget = changed.base.withRightDelta(1);
        TrialEvidence.Cut changedFirst = changed.firstFrame(changedTarget, 11, 21, 4);
        TrialEvidence.Trial multi = waitingForRestore(changed, changedFirst);
        Object[] children = changed.children.clone();
        Object[] parents = changed.parents.clone();
        String[] metadata = changed.metadata.clone();
        children[2] = new Object();
        parents[3] = new Object();
        metadata[4] = "private child text must not be retained in diagnostic";
        TrialEvidence.Cut changedEntry = new TrialEvidence.Cut(changed.root,
                TrialContract.rootToken("process", "one"), "other scene",
                changedTarget, 9, children, parents, metadata,
                changed.children.clone(), 11, 21, 4, 6, 1019,
                11, 21, 6, 1020);
        check(!multi.onParentPreCall(changedEntry, changed.base, 12, 1030),
                "multi-field restore drift also rejected");
        TrialEvidence.RestoreEntryDiff multiDiff = multi.restoreEntryDrift();
        check(multi.state() == TrialEvidence.State.UNKNOWN && multiDiff != null
                        && !multiDiff.sameScene,
                "scene mismatch exposes equality only and keeps UNKNOWN");
        check(multiDiff.childIdentityMismatchIndices().length == 1
                        && multiDiff.childIdentityMismatchIndices()[0] == 2
                        && multiDiff.parentIdentityMismatchIndices().length == 1
                        && multiDiff.parentIdentityMismatchIndices()[0] == 3
                        && multiDiff.childEvidenceMismatchIndices().length == 1
                        && multiDiff.childEvidenceMismatchIndices()[0] == 4,
                "bounded mismatch indices identify changed slots without payload");

        Fixture missing = new Fixture();
        TrialEvidence.Bounds missingTarget = missing.base.withRightDelta(1);
        TrialEvidence.Trial missingEntry = waitingForRestore(missing,
                missing.firstFrame(missingTarget, 11, 21, 4));
        check(!missingEntry.onParentPreCall(null, missing.base, 12, 1030),
                "null restore entry rejected before diagnostic construction");
        check(missingEntry.state() == TrialEvidence.State.UNKNOWN
                        && "PARENT_PRECALL_NOT_EXCLUSIVE".equals(missingEntry.reason())
                        && missingEntry.restoreEntryDrift() == null,
                "null entry preserves original unknown path with no diagnostic");
    }

    private static void unchangedControl() {
        Fixture f = new Fixture();
        TrialEvidence.Cut baseline = f.baseline();
        TrialEvidence.Trial proof = TrialEvidence.Trial.begin(
                TrialEvidence.Command.UNCHANGED, baseline, 1005);
        check(proof.onParentPreCall(baseline, f.base, 11, 1010), "noop pre-call");
        TrialEvidence.Cut after = f.firstAfter(f.base, 11, 21, 4);
        proof.onParentLayoutAfter(after, 1011);
        check(!proof.shouldRequestRestorePaint(after),
                "unchanged control does not request a restore redraw");
        TrialEvidence.Cut frame = f.firstFrame(f.base, 11, 21, 4);
        proof.onCompletedPaint(frame, 1021);
        check(proof.state() == TrialEvidence.State.WAIT_SECOND_PAINT_REQUEST,
                "noop still needs second completed paint");
        check(proof.requestSecondPaint(frame, frame, 1050), "noop second request");
        TrialEvidence.Cut second = f.cutAt(f.base, 11, 21, 4, 7, 1055,
                11, 21, 7, 1060);
        proof.onCompletedPaint(second, 1061);
        proof.onSecondSample(second, second, 1062);
        check(proof.state() == TrialEvidence.State.PASS, "noop control pass");
        check(proof.reason().equals("PARENT_PATH_RESTORED"), "scoped result label");
        check(proof.abaAway() == null, "unchanged JSON ABA cut is null");
    }

    private static void unchangedFirstPaintGate() {
        Fixture f = new Fixture();
        TrialEvidence.Cut baseline = f.baseline();
        TrialEvidence.Trial proof = TrialEvidence.Trial.begin(
                TrialEvidence.Command.UNCHANGED, baseline, 1005);
        check(!proof.claimUnchangedFirstPaintRequest(baseline),
                "unchanged control cannot request paint before a parent return");
        check(proof.onParentPreCall(baseline, f.base, 11, 1010),
                "unchanged control pre-call admitted");
        TrialEvidence.Cut after = f.firstAfter(f.base, 11, 21, 3);
        check(!proof.claimUnchangedFirstPaintRequest(after),
                "pending unchanged parent call cannot request paint");
        proof.onParentLayoutAfter(after, 1011);
        check(proof.state() == TrialEvidence.State.WAIT_FIRST_PAINT
                        && proof.firstAfter() == after
                        && proof.firstFrame() == null,
                "same-bounds parent return is verified but still awaits paint");
        check(!proof.claimUnchangedFirstPaintRequest(f.firstAfter(f.base, 11, 21, 3)),
                "lookalike parent-return cut cannot request paint");
        check(proof.claimUnchangedFirstPaintRequest(after),
                "exact verified unchanged return requests first paint");
        check(!proof.claimUnchangedFirstPaintRequest(after),
                "unchanged first-paint request can be claimed only once");
        proof.onCompletedPaint(f.firstFrame(f.base, 11, 21, 3), 1021);
        check(!proof.claimUnchangedFirstPaintRequest(after),
                "completed first paint cannot request another first paint");

        Fixture rejectedFixture = new Fixture();
        TrialEvidence.Cut rejectedBaseline = rejectedFixture.baseline();
        TrialEvidence.Trial rejected = TrialEvidence.Trial.begin(
                TrialEvidence.Command.UNCHANGED, rejectedBaseline, 1005);
        check(rejected.onParentPreCall(rejectedBaseline, rejectedFixture.base, 11, 1010),
                "rejected unchanged fixture pre-call admitted");
        TrialEvidence.Cut wrongGeometry = rejectedFixture.firstAfter(
                rejectedFixture.base.withRightDelta(1), 11, 21, 4);
        rejected.onParentLayoutAfter(wrongGeometry, 1011);
        check(rejected.state() == TrialEvidence.State.UNKNOWN
                        && rejected.firstAfter() == null
                        && !rejected.claimUnchangedFirstPaintRequest(wrongGeometry),
                "rejected unchanged geometry must never request paint");
    }

    private static void directBypass(TrialEvidence.Command command) {
        Fixture f = new Fixture();
        TrialEvidence.Cut baseline = f.baseline();
        TrialEvidence.Trial proof = TrialEvidence.Trial.begin(command, baseline, 1005);
        TrialEvidence.Bounds target = command == TrialEvidence.Command.DIRECT_OFFSET
                ? f.base.shiftedRight(1) : f.base.withRightDelta(1);
        long layout = command == TrialEvidence.Command.DIRECT_LAYOUT ? 4 : 3;
        TrialEvidence.Cut after = f.firstAfter(target, 10, 21, layout);
        proof.onDirectAfter(baseline, after, 1010);
        check(proof.bypassObserved(), "unfenced direct writer observed");
        check(proof.state() == TrialEvidence.State.WAIT_FIRST_PAINT,
                "direct write not a pass");
        TrialEvidence.Cut firstFrame = f.firstFrame(target, 10, 21, layout);
        proof.onCompletedPaint(firstFrame, 1021);
        check(proof.state() == TrialEvidence.State.WAIT_RESTORE_CALL,
                "direct control still restores");
        check(proof.onParentPreCall(firstFrame, f.base, 11, 1030),
                "parent restores direct control");
        proof.onParentLayoutAfter(f.restoreAfter(11, 22, layout + 1, firstFrame), 1031);
        TrialEvidence.Cut restored = f.restoredFrame(11, 22, layout + 1);
        proof.onCompletedPaint(restored, 1041);
        check(proof.requestSecondPaint(restored, restored, 1070),
                "direct control second request");
        TrialEvidence.Cut second = f.cutAt(f.base, 11, 22, layout + 1,
                8, 1075, 11, 22, 8, 1080);
        proof.onCompletedPaint(second, 1081);
        proof.onSecondSample(second, second, 1082);
        check(proof.state() == TrialEvidence.State.PASS, "direct control completed");
        check(proof.reason().equals("BYPASS_CONTROL_RESTORED"),
                "never labeled covered");
        check(!proof.completeMutationCoverage(), "bypass blocks complete authority");
        check(proof.abaAway() == null, "direct JSON ABA cut is null");
    }

    private static TrialEvidence.Trial offsetWaitingForRestore(Fixture f) {
        TrialEvidence.Cut baseline = f.baseline();
        TrialEvidence.Trial proof = TrialEvidence.Trial.begin(
                TrialEvidence.Command.DIRECT_OFFSET, baseline, 1005);
        TrialEvidence.Bounds shifted = f.base.shiftedRight(1);
        TrialEvidence.Cut after = f.firstAfter(shifted, 10, 21, 3);
        proof.onDirectAfter(baseline, after, 1010);
        check(!proof.shouldRequestRestorePaint(after),
                "direct offset write is not a verified restore");
        TrialEvidence.Cut firstFrame = f.firstFrame(shifted, 10, 21, 3);
        proof.onCompletedPaint(firstFrame, 1021);
        check(proof.state() == TrialEvidence.State.WAIT_RESTORE_CALL
                        && !proof.shouldRequestRestorePaint(firstFrame),
                "changed paint alone does not request the restore redraw");
        check(proof.onParentPreCall(firstFrame, f.base, 11, 1030),
                "direct offset restore pre-call admitted");
        return proof;
    }

    private static void directOffsetRestorePaintGate() {
        Fixture f = new Fixture();
        TrialEvidence.Trial proof = offsetWaitingForRestore(f);
        TrialEvidence.Cut restored = f.restoreAfter(11, 22, 4, proof.firstFrame());
        check(!proof.shouldRequestRestorePaint(restored),
                "pending parent call has not verified restore geometry");
        proof.onParentLayoutAfter(restored, 1031);
        check(proof.state() == TrialEvidence.State.WAIT_RESTORE_PAINT
                        && proof.restoreAfter() == restored
                        && proof.shouldRequestRestorePaint(restored),
                "exact verified direct-offset parent return requests a redraw");
        check(!proof.shouldRequestRestorePaint(f.restoreAfter(11, 22, 4,
                        proof.firstFrame())),
                "a lookalike cut cannot authorize the redraw");
        proof.onCompletedPaint(f.restoredFrame(11, 22, 4), 1041);
        check(!proof.shouldRequestRestorePaint(restored),
                "completed restored paint closes the one-time request stage");

        Fixture rejectedFixture = new Fixture();
        TrialEvidence.Trial rejected = offsetWaitingForRestore(rejectedFixture);
        TrialEvidence.Cut wrongGeometry = rejectedFixture.cut(
                rejectedFixture.base.shiftedRight(1), 11, 22, 4,
                6, 10, 21, 6, 1020);
        rejected.onParentLayoutAfter(wrongGeometry, 1031);
        check(rejected.state() == TrialEvidence.State.UNKNOWN
                        && rejected.restoreAfter() == null
                        && !rejected.shouldRequestRestorePaint(wrongGeometry),
                "rejected restore geometry must never request a redraw");
    }

    private static void abaControl() {
        Fixture f = new Fixture();
        TrialEvidence.Cut baseline = f.baseline();
        TrialEvidence.Trial proof = TrialEvidence.Trial.begin(
                TrialEvidence.Command.ABA, baseline, 1005);
        TrialEvidence.Bounds away = f.base.withRightDelta(1);
        check(proof.onParentPreCall(baseline, away, 11, 1010), "ABA away pre-call");
        TrialEvidence.Cut awayAfter = f.firstAfter(away, 11, 21, 4);
        proof.onParentLayoutAfter(awayAfter, 1011);
        check(proof.state() == TrialEvidence.State.WAIT_ABA_RETURN, "ABA away seen");
        check(!proof.shouldRequestRestorePaint(awayAfter),
                "ABA away call does not request a restore redraw");
        check(!proof.claimUnchangedFirstPaintRequest(awayAfter),
                "ABA away call does not claim an unchanged first paint");
        check(proof.onParentPreCall(awayAfter, f.base, 12, 1012),
                "ABA return pre-call");
        TrialEvidence.Cut backAfter = f.firstAfter(f.base, 12, 22, 5);
        proof.onParentLayoutAfter(backAfter, 1013);
        check(proof.state() == TrialEvidence.State.WAIT_FIRST_PAINT,
                "same final bounds still need later paint");
        check(!proof.shouldRequestRestorePaint(backAfter),
                "ABA return does not request a direct-offset redraw");
        check(!proof.claimUnchangedFirstPaintRequest(backAfter),
                "ABA return does not claim an unchanged first paint");
        TrialEvidence.Cut frame = f.cut(f.base, 12, 22, 5, 6, 12, 22, 6, 1020);
        proof.onCompletedPaint(frame, 1021);
        check(proof.requestSecondPaint(frame, frame, 1050), "ABA second request");
        TrialEvidence.Cut second = f.cutAt(f.base, 12, 22, 5, 7, 1055,
                12, 22, 7, 1060);
        proof.onCompletedPaint(second, 1061);
        proof.onSecondSample(second, second, 1062);
        check(proof.state() == TrialEvidence.State.PASS, "ABA distinct revisions");
        check(proof.abaAway() == awayAfter, "ABA JSON cut is exact away evidence");
        check(proof.firstAfter().parentPreCallRevision == 12, "return revision retained");
    }

    private static void adversarial() {
        Fixture f = new Fixture();
        TrialEvidence.Cut baseline = f.baseline();
        Object[] wrongOrder = f.children.clone();
        wrongOrder[0] = wrongOrder[1];
        TrialEvidence.Cut duplicate = f.cut(f.base, 10, 20, 3, 5, 10, 20,
                5, 1000, wrongOrder, "scene");
        check(!duplicate.exactNinePainted(), "duplicate actual draw identity denied");
        check(!f.cut(f.base, 10, 20, 3, 5, 10, 20, 5, 1000,
                f.children.clone(), "other scene").sameOriginals(baseline),
                "scene identity matters");
        f.metadata[2] = "unexpected-metadata";
        check(!f.baseline().sameOriginals(baseline),
                "stable child metadata drift denied");
        f.metadata[2] = "child-2";
        TrialEvidence.Trial stale = TrialEvidence.Trial.begin(
                TrialEvidence.Command.PARENT_PLUS, baseline, 1005);
        check(stale.onParentPreCall(baseline, f.base.withRightDelta(1), 11, 1010),
                "fresh entry");
        stale.onParentLayoutAfter(f.firstAfter(f.base.withRightDelta(1), 11, 21, 4),
                1011);
        TrialEvidence.Cut begunBeforeWrite = f.cut(f.base.withRightDelta(1), 11,
                21, 4, 6, 10, 20, 6, 1020);
        stale.onCompletedPaint(begunBeforeWrite, 1021);
        check(stale.state() == TrialEvidence.State.UNKNOWN,
                "frame begun before write cannot authorize");
        stale.onCompletedPaint(f.firstFrame(f.base.withRightDelta(1), 11, 21, 4),
                1022);
        check(stale.state() == TrialEvidence.State.UNKNOWN, "UNKNOWN sticky");

        TrialEvidence.Trial wrongRank = TrialEvidence.Trial.begin(
                TrialEvidence.Command.PARENT_PLUS, baseline, 1005);
        check(wrongRank.onParentPreCall(baseline, f.base.withRightDelta(1), 11, 1010),
                "pre-call for wrong rank");
        wrongRank.onParentLayoutAfter(f.firstAfter(f.base.withRightDelta(1), 11, 21, 4),
                1011);
        TrialEvidence.Cut badPaint = f.cut(f.base.withRightDelta(1), 11, 21, 4,
                6, 11, 21, 6, 1020, wrongOrder, "scene");
        wrongRank.onCompletedPaint(badPaint, 1021);
        check(wrongRank.state() == TrialEvidence.State.UNKNOWN,
                "wrong effective draw order denied");

        TrialEvidence.Trial wrongTarget = TrialEvidence.Trial.begin(
                TrialEvidence.Command.PARENT_PLUS, baseline, 1005);
        check(!wrongTarget.onParentPreCall(baseline, f.base, 11, 1010),
                "wrong proposed bounds denied before call");
        check(wrongTarget.state() == TrialEvidence.State.UNKNOWN, "wrong target sticky");

        TrialEvidence.Trial timeout = TrialEvidence.Trial.begin(
                TrialEvidence.Command.PARENT_PLUS, baseline, 1005);
        timeout.expire(6005);
        check(timeout.state() == TrialEvidence.State.UNKNOWN, "deadline fail closed");

        TrialEvidence.Trial noFrame = TrialEvidence.Trial.begin(
                TrialEvidence.Command.PARENT_PLUS, baseline, 1005);
        check(noFrame.onParentPreCall(baseline, f.base.withRightDelta(1), 11, 1010),
                "no frame setup");
        noFrame.onParentLayoutAfter(f.firstAfter(f.base.withRightDelta(1), 11, 21, 4),
                1011);
        check(noFrame.state() != TrialEvidence.State.PASS, "no frame never passes");
        noFrame.expire(6005);
        check(noFrame.state() == TrialEvidence.State.UNKNOWN, "no frame times out");

        TrialEvidence.Trial superseded = TrialEvidence.Trial.begin(
                TrialEvidence.Command.UNCHANGED, baseline, 1005);
        check(superseded.onParentPreCall(baseline, f.base, 11, 1010),
                "superseded setup");
        superseded.onParentLayoutAfter(f.firstAfter(f.base, 11, 21, 4), 1011);
        TrialEvidence.Cut restored = f.firstFrame(f.base, 11, 21, 4);
        superseded.onCompletedPaint(restored, 1021);
        check(superseded.requestSecondPaint(restored, restored, 1050),
                "superseded second request");
        TrialEvidence.Cut second = f.cutAt(f.base, 11, 21, 4, 7, 1055,
                11, 21, 7, 1060);
        superseded.onCompletedPaint(second, 1061);
        TrialEvidence.Cut newer = f.cutAt(f.base, 11, 21, 4, 8, 1065,
                11, 21, 8, 1070);
        superseded.onSecondSample(newer, newer, 1071);
        check(superseded.state() == TrialEvidence.State.UNKNOWN,
                "superseding paint denies second-sample commit");

        TrialEvidence.Trial sameFrame = TrialEvidence.Trial.begin(
                TrialEvidence.Command.UNCHANGED, baseline, 1005);
        check(sameFrame.onParentPreCall(baseline, f.base, 11, 1010),
                "same frame setup");
        sameFrame.onParentLayoutAfter(f.firstAfter(f.base, 11, 21, 4), 1011);
        sameFrame.onCompletedPaint(restored, 1021);
        check(sameFrame.requestSecondPaint(restored, restored, 1050),
                "same frame second request");
        sameFrame.onCompletedPaint(restored, 1051);
        check(sameFrame.state() == TrialEvidence.State.UNKNOWN,
                "same completed frame cannot count twice");

        TrialEvidence.Trial staleSecond = TrialEvidence.Trial.begin(
                TrialEvidence.Command.UNCHANGED, baseline, 1005);
        check(staleSecond.onParentPreCall(baseline, f.base, 11, 1010),
                "stale second setup");
        staleSecond.onParentLayoutAfter(f.firstAfter(f.base, 11, 21, 4), 1011);
        staleSecond.onCompletedPaint(restored, 1021);
        check(staleSecond.requestSecondPaint(restored, restored, 1050),
                "stale second request");
        TrialEvidence.Cut begunBeforeRequest = f.cutAt(f.base, 11, 21, 4,
                7, 1040, 11, 21, 7, 1060);
        staleSecond.onCompletedPaint(begunBeforeRequest, 1061);
        check(staleSecond.state() == TrialEvidence.State.UNKNOWN,
                "second paint begun before request denied");

        TrialEvidence.Trial alternateSecond = TrialEvidence.Trial.begin(
                TrialEvidence.Command.UNCHANGED, baseline, 1005);
        check(alternateSecond.onParentPreCall(baseline, f.base, 11, 1010),
                "alternate second setup");
        alternateSecond.onParentLayoutAfter(f.firstAfter(f.base, 11, 21, 4), 1011);
        alternateSecond.onCompletedPaint(restored, 1021);
        check(alternateSecond.requestSecondPaint(restored, restored, 1050),
                "alternate second request");
        TrialEvidence.Cut alternate = f.cutAt(f.base, 11, 21, 4, 7, 1055,
                11, 21, 7, 1060, wrongOrder, "scene");
        alternateSecond.onCompletedPaint(alternate, 1061);
        check(alternateSecond.state() == TrialEvidence.State.UNKNOWN,
                "alternate draw-order frame denied");

        TrialEvidence.Trial duplicateLayout = TrialEvidence.Trial.begin(
                TrialEvidence.Command.PARENT_PLUS, baseline, 1005);
        check(duplicateLayout.onParentPreCall(baseline,
                f.base.withRightDelta(1), 11, 1010), "duplicate layout setup");
        duplicateLayout.onParentLayoutAfter(
                f.firstAfter(f.base.withRightDelta(1), 11, 21, 5), 1011);
        check(duplicateLayout.state() == TrialEvidence.State.UNKNOWN,
                "two root onLayout calls denied for one parent call");
    }

    private static void postPassArmValidity() {
        Fixture f = new Fixture();
        TrialEvidence.Cut baseline = f.baseline();
        TrialEvidence.Trial proof = TrialEvidence.Trial.begin(
                TrialEvidence.Command.UNCHANGED, baseline, 1005);
        check(proof.deadlineElapsedMs() == 6005, "pre-PASS trial deadline stays 5s");
        check(proof.onParentPreCall(baseline, f.base, 11, 1010),
                "post-PASS fixture pre-call");
        proof.onParentLayoutAfter(f.firstAfter(f.base, 11, 21, 4), 1011);
        TrialEvidence.Cut first = f.firstFrame(f.base, 11, 21, 4);
        proof.onCompletedPaint(first, 1021);
        check(proof.requestSecondPaint(first, first, 1050),
                "post-PASS fixture second paint request");
        TrialEvidence.Cut second = f.cutAt(f.base, 11, 21, 4, 7, 1055,
                11, 21, 7, 1060);
        proof.onCompletedPaint(second, 1061);
        proof.onSecondSample(second, second, 1062);
        check(proof.state() == TrialEvidence.State.PASS, "post-PASS fixture passed");

        check(!proof.currentlyValid(second, second, 6100, -1),
                "historical PASS without active arm rejected");
        check(proof.currentlyValid(second, second, 6100, 31000),
                "stable restored second frame remains current after 5s under arm");
        check(proof.currentlyValid(second, second, 30999, 31000),
                "bounded arm allows stable proof until its own deadline");
        check(!proof.currentlyValid(second, second, 31000, 31000),
                "arm deadline equality rejects current validity");

        TrialEvidence.Cut changedBounds = f.cutAt(
                f.base.withRightDelta(1), 11, 21, 4, 7, 1055,
                11, 21, 7, 1060);
        check(!proof.currentlyValid(changedBounds, second, 6100, 31000),
                "post-PASS geometry drift rejected");
        Object[] wrongOrder = f.children.clone();
        wrongOrder[0] = wrongOrder[1];
        TrialEvidence.Cut changedPaint = f.cutAt(f.base, 11, 21, 4, 7,
                1055, 11, 21, 7, 1060, wrongOrder, "scene");
        check(!proof.currentlyValid(second, changedPaint, 6100, 31000),
                "post-PASS latest painted identity drift rejected");
        TrialEvidence.Cut supersedingPaint = f.cutAt(f.base, 11, 21, 4, 8,
                6100, 11, 21, 8, 6101);
        check(!proof.currentlyValid(supersedingPaint, supersedingPaint,
                6102, 31000), "post-PASS superseding paint rejected");
    }

    private static void refreshBaselineEvidence() {
        Fixture f = new Fixture();
        TrialEvidence.Cut oldFrame = f.baseline();
        TrialEvidence.Cut refreshed = f.cutAt(f.base, 10, 20, 3, 6,
                18001, 10, 20, 6, 18020);
        check(TrialEvidence.refreshedBaseline(oldFrame, refreshed, refreshed,
                5, 18000, 18030),
                "app-owned invalidate can establish a later fresh completed nine frame");
        check(TrialEvidence.Trial.begin(TrialEvidence.Command.PARENT_PLUS,
                refreshed, 18030) != null, "command may begin on new fresh frame");
        check(!TrialEvidence.refreshedBaseline(oldFrame, oldFrame, oldFrame,
                5, 18000, 18030), "old completed frame cannot satisfy refresh");
        TrialEvidence.Cut startedBeforeRequest = f.cutAt(f.base, 10, 20, 3,
                6, 17999, 10, 20, 6, 18020);
        check(!TrialEvidence.refreshedBaseline(oldFrame, startedBeforeRequest,
                startedBeforeRequest, 5, 18000, 18030),
                "frame begun before invalidate cannot satisfy refresh");
        check(!TrialEvidence.refreshedBaseline(oldFrame, refreshed, refreshed,
                5, 18000, 20100), "new frame too old before command rejected");
        TrialEvidence.Cut changedBounds = f.cutAt(f.base.withRightDelta(1),
                10, 20, 3, 6, 18001, 10, 20, 6, 18020);
        check(!TrialEvidence.refreshedBaseline(oldFrame, changedBounds,
                changedBounds, 5, 18000, 18030),
                "refresh cannot hide geometry mutation");
        TrialEvidence.Cut changedRevision = f.cutAt(f.base, 11, 21, 4,
                6, 18001, 11, 21, 6, 18020);
        check(!TrialEvidence.refreshedBaseline(oldFrame, changedRevision,
                changedRevision, 5, 18000, 18030),
                "refresh cannot hide layout/write revision mutation");
        Object[] duplicatePaint = f.children.clone();
        duplicatePaint[0] = duplicatePaint[1];
        TrialEvidence.Cut wrongPaint = f.cutAt(f.base, 10, 20, 3, 6,
                18001, 10, 20, 6, 18020, duplicatePaint, "scene");
        check(!TrialEvidence.refreshedBaseline(oldFrame, wrongPaint,
                wrongPaint, 5, 18000, 18030),
                "refresh requires actual exact nine-child paint order");
        TrialEvidence.Cut changedScene = f.cutAt(f.base, 10, 20, 3, 6,
                18001, 10, 20, 6, 18020, f.children.clone(), "other scene");
        check(!TrialEvidence.refreshedBaseline(oldFrame, changedScene,
                changedScene, 5, 18000, 18030),
                "refresh cannot hide scene replacement");
    }

    private static void rootTokenWireSyntax() {
        String token = TrialContract.rootToken(
                "550e8400-e29b-41d4-a716-446655440000",
                "56e9b5c2-4422-45e2-bafc-3d58d96505f6");
        check(token.equals("550e8400-e29b-41d4-a716-446655440000-root-"
                + "56e9b5c2-4422-45e2-bafc-3d58d96505f6"),
                "root token uses exact colon-free construction");
        check(token.matches("[A-Za-z0-9_-]+"),
                "root token is safe for content call string binding");
        check(token.indexOf(':') < 0, "root token contains no binding delimiter");
        boolean rejected = false;
        try { TrialContract.rootToken("bad:incarnation", "safe"); }
        catch (IllegalArgumentException expected) { rejected = true; }
        check(rejected, "colon-bearing token component rejected");
    }

    public static void main(String[] args) {
        parentPulse(TrialEvidence.Command.PARENT_PLUS, 1);
        parentPulse(TrialEvidence.Command.PARENT_MINUS, -1);
        unchangedControl();
        unchangedFirstPaintGate();
        directBypass(TrialEvidence.Command.DIRECT_LAYOUT);
        directBypass(TrialEvidence.Command.DIRECT_OFFSET);
        directOffsetRestorePaintGate();
        abaControl();
        oneInterveningRestoredPaint();
        interveningThenRequestedPaint();
        oneExtraAcrossRestoringCommands();
        extraFrameDriftAcrossRestoringCommands();
        noRestoreCommandsRejectExtra();
        rejectedInterveningRestoredPaints();
        restoreEntryDiagnostic();
        adversarial();
        postPassArmValidity();
        refreshBaselineEvidence();
        rootTokenWireSyntax();
        System.out.println("PASS TrialEvidenceTest checks=" + checks);
    }
}
