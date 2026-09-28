package com.techrebbe.supernote.disposableleasehost;

public final class LeaseEvidenceMutationLedgerTest {
    private static int checks;

    private static void check(boolean value, String message) {
        checks++;
        if (!value) throw new AssertionError(message);
    }

    public static void main(String[] args) {
        LeaseEvidenceMutationLedger ledger = new LeaseEvidenceMutationLedger();
        check(ledger.revision() == 1, "positive initial revision");
        long oldFrame = ledger.revision();
        check(ledger.isCurrent(oldFrame), "unchanged frame accepted");
        final String[] scene = {"source-a"};
        final long[] seenInsideMutation = new long[1];
        final String[] sceneAtBump = new String[1];
        long changed = ledger.beforeMutation();
        seenInsideMutation[0] = ledger.revision();
        sceneAtBump[0] = scene[0];
        scene[0] = "source-b";
        check(changed == 2 && seenInsideMutation[0] == 2
                && "source-a".equals(sceneAtBump[0])
                && "source-b".equals(scene[0]), "revision bumped before scene change");
        check(!ledger.isCurrent(oldFrame), "prior completed frame rejected as stale");
        long changedAgain = ledger.beforeMutation();
        scene[0] = "source-a";
        check(changedAgain > changed && !ledger.isCurrent(oldFrame),
                "change then revert cannot revive stale frame");
        check(ledger.isCurrent(changedAgain), "new frame may use latest revision");
        check(!ledger.isCurrent(0) && !ledger.isCurrent(-1),
                "invalid revisions are never current");

        LeaseEvidenceMutationLedger deferredLayout = new LeaseEvidenceMutationLedger();
        long baseline = deferredLayout.revision();
        long afterOwnedAdd = deferredLayout.beforeMutation();
        check(afterOwnedAdd == baseline + 1, "owned add is one authorized mutation");
        long afterLayout = deferredLayout.beforeMutation();
        check(afterLayout == baseline + 2 && !deferredLayout.isCurrent(afterOwnedAdd),
                "a deferred layout cannot be folded silently into the owned-add revision");
        System.out.println("LEASE_EVIDENCE_MUTATION_LEDGER PASS checks=" + checks);
    }
}
