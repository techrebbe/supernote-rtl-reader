package com.techrebbe.supernote.layoutfencetrial;

/** Deterministic Java-8 checks; no Android runtime, Frida, ADB or device. */
public final class TrialEvidenceTest {
    private static int checks;

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

    private static void unrequestedRestoredPaint() {
        Fixture f = new Fixture();
        TrialEvidence.Bounds target = f.base.withRightDelta(1);
        TrialEvidence.Cut firstFrame = f.firstFrame(target, 11, 21, 4);
        TrialEvidence.Trial proof = waitingForRestore(f, firstFrame);
        check(proof.onParentPreCall(firstFrame, f.base, 12, 1030),
                "restore entry remains the first changed frame");
        proof.onParentLayoutAfter(f.restoreAfter(12, 22, 5, firstFrame), 1031);
        TrialEvidence.Cut restored = f.restoredFrame(12, 22, 5);
        proof.onCompletedPaint(restored, 1041);
        check(proof.state() == TrialEvidence.State.WAIT_SECOND_PAINT_REQUEST,
                "first restored paint waits for an explicit second request");
        TrialEvidence.Cut unsolicited = f.cutAt(f.base, 12, 22, 5,
                8, 1045, 12, 22, 8, 1046);
        proof.onCompletedPaint(unsolicited, 1047);
        check(proof.state() == TrialEvidence.State.UNKNOWN
                        && "UNREQUESTED_SECOND_PAINT".equals(proof.reason())
                        && !proof.rollbackVerified(),
                "unsolicited restored paint cannot satisfy the two-paint proof");
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
        proof.onParentLayoutAfter(f.firstAfter(f.base, 11, 21, 4), 1011);
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
        check(proof.onParentPreCall(awayAfter, f.base, 12, 1012),
                "ABA return pre-call");
        TrialEvidence.Cut backAfter = f.firstAfter(f.base, 12, 22, 5);
        proof.onParentLayoutAfter(backAfter, 1013);
        check(proof.state() == TrialEvidence.State.WAIT_FIRST_PAINT,
                "same final bounds still need later paint");
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
        directBypass(TrialEvidence.Command.DIRECT_LAYOUT);
        directBypass(TrialEvidence.Command.DIRECT_OFFSET);
        abaControl();
        unrequestedRestoredPaint();
        restoreEntryDiagnostic();
        adversarial();
        postPassArmValidity();
        refreshBaselineEvidence();
        rootTokenWireSyntax();
        System.out.println("PASS TrialEvidenceTest checks=" + checks);
    }
}
