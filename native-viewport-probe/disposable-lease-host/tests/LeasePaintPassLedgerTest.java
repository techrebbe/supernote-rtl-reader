package com.techrebbe.supernote.disposableleasehost;

public final class LeasePaintPassLedgerTest {
    private static int checks;

    private static void check(boolean value, String message) {
        checks++;
        if (!value) throw new AssertionError(message);
    }

    private static void reject(Runnable action, String message) {
        boolean rejected = false;
        try { action.run(); }
        catch (IllegalStateException expected) { rejected = true; }
        check(rejected, message);
    }

    public static void main(String[] args) {
        LeasePaintPassLedger ledger = new LeasePaintPassLedger();
        check(ledger.begunRevision() == 0 && ledger.completedRevision() == 0,
                "no fabricated initial frame");
        long first = ledger.begin();
        check(first == 1 && ledger.completedRevision() == 0,
                "first frame not complete at entry");
        ledger.complete(first);
        check(ledger.completedRevision() == 1, "first completed pass");
        reject(() -> ledger.complete(first), "duplicate completion rejected");
        long interrupted = ledger.begin();
        long next = ledger.begin();
        check(interrupted == 2 && next == 3 && ledger.completedRevision() == 1,
                "failed pass never becomes completed evidence");
        reject(() -> ledger.complete(interrupted), "stale completion rejected");
        ledger.complete(next);
        check(ledger.completedRevision() == 3, "new exact pass can complete");
        reject(() -> ledger.complete(0), "zero revision rejected");
        System.out.println("LEASE_PAINT_PASS_LEDGER PASS checks=" + checks);
    }
}
