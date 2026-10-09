package t014;

public final class ReaderKeyRouteCoreTests {
    private static int assertions;
    private static void check(boolean value, String message) {
        assertions++; if (!value) throw new AssertionError(message);
    }
    private static void rejects(Runnable action, String message) {
        boolean rejected = false;
        try { action.run(); } catch (IllegalArgumentException | IllegalStateException expected) { rejected = true; }
        check(rejected, message);
    }
    private static ReaderKeyRouteCore armed() {
        ReaderKeyRouteCore core = new ReaderKeyRouteCore("test");
        core.configure("document-one", new int[] {21, 22, 92, 93}, true, 10);
        core.eligibility(true, true, true, true, 11);
        return core;
    }
    private static void contactLifecycle() {
        ReaderKeyRouteCore core = armed();
        ReaderKeyRouteCore.State state = core.snapshot();
        ReaderKeyRouteCore.Decision down = core.dispatch(0, 93, 2, 12, 0);
        check(down.consume && down.packet != null, "One current DOWN accepted");
        check(down.packet.state.activationId.equals(state.activationId), "Dispatch stamps actual native activation");
        check(down.packet.state.documentId.equals("document-one"), "Dispatch stamps native document");
        for (int repeat = 1; repeat <= 512; repeat++) {
            ReaderKeyRouteCore.Decision held = core.dispatch(0, 93, 2, 12, repeat);
            check(held.consume && held.packet == null, "Hold never emits another turn");
        }
        check(core.dispatch(0, 93, 2, 12, Integer.MAX_VALUE).consume, "Long native hold retains ownership");
        check(core.dispatch(0, 93, 2, 12, Integer.MAX_VALUE).packet == null, "Long hold cannot emit navigation");
        check(core.dispatch(0, 93, 2, 12, 0).packet == null, "Duplicate DOWN has no turn");
        check(!core.dispatch(1, 93, 2, 13, 0).consume, "Different UP cannot release owned contact");
        ReaderKeyRouteCore.Decision up = core.dispatch(1, 93, 2, 12, 0);
        check(up.consume && up.packet != null && up.packet.action == 1, "Exact UP releases");
        check(!core.dispatch(1, 93, 2, 12, 0).consume, "Duplicate UP unowned");
        check(core.dispatch(0, 93, 2, 13, 0).packet != null, "New contact accepted");
        check(core.dispatch(0, 93, 2, 14, 0).packet != null, "Strictly newer contact recovers missing UP");
        check(!core.dispatch(1, 93, 2, 13, 0).consume, "Old UP cannot release newer contact");
        check(core.dispatch(1, 93, 2, 14, 0).consume, "New exact UP releases");
    }
    private static void epochsAndFocus() {
        for (int bit = 0; bit < 4; bit++) {
            ReaderKeyRouteCore core = armed();
            ReaderKeyRouteCore.State before = core.snapshot();
            core.dispatch(0, 21, 3, 12, 0);
            boolean[] flags = {true, true, true, true}; flags[bit] = false;
            ReaderKeyRouteCore.State lost = core.eligibility(flags[0], flags[1], flags[2], flags[3], 13);
            check(!lost.eligible && lost.generation > before.generation, "Every focus/attachment/visibility loss fences");
            check(!core.isCurrent(before), "Old accepted packet authority revoked");
            check(!core.dispatch(0, 21, 3, 14, 0).consume, "No navigation while ineligible");
            ReaderKeyRouteCore.State gained = core.eligibility(true, true, true, true, 15);
            check(gained.eligible && gained.generation > lost.generation, "Recovery creates new non-reused epoch");
            check(!core.isCurrent(before), "Focus ABA cannot revive original authority");
            check(core.dispatch(0, 21, 3, 14, 0).packet == null, "Delayed pre-recovery DOWN rejected");
            check(!core.dispatch(1, 21, 3, 12, 0).consume, "Canceled old contact never owns later UP");
            check(!core.dispatch(0, 21, 3, 16, 1).consume, "Held key entering new focus cannot trigger");
            check(core.dispatch(0, 21, 3, 17, 0).packet != null, "New fresh contact after recovery accepted");
            ReaderKeyRouteCore.State stable = core.eligibility(true, true, true, true, 18);
            check(stable.generation == gained.generation, "Repeated observation is not a fresh route");
        }
        ReaderKeyRouteCore core = armed();
        ReaderKeyRouteCore.State old = core.snapshot();
        int[] keys = {93};
        ReaderKeyRouteCore.State changed = core.configure("document-two", keys, true, 20);
        keys[0] = 24;
        check(!core.isCurrent(old) && changed.generation > old.generation, "Document/routing change fences");
        check(!core.dispatch(0, 24, 2, 21, 0).consume, "Bindings copied; external mutation has no authority");
        ReaderKeyRouteCore.Decision newer = core.dispatch(0, 93, 2, 22, 0);
        check(newer.packet != null && newer.packet.state.documentId.equals("document-two"), "New packet bound to new document");
        ReaderKeyRouteCore.State disabled = core.configure("document-two", new int[] {93}, false, 23);
        check(!disabled.eligible && !core.dispatch(0, 93, 2, 24, 0).consume, "Explicit disable never overridden by focus");
        ReaderKeyRouteCore.State enabled = core.configure("document-two", new int[] {93}, true, 25);
        check(enabled.generation > disabled.generation && !core.dispatch(0, 93, 2, 24, 0).consume, "Enable ABA rejects older contact");
        core.configure("document-two", new int[] {93}, true, 25);
        check(!core.isCurrent(enabled), "Same-tick configure still creates distinct epoch");
    }
    private static void malformed() {
        ReaderKeyRouteCore core = armed();
        ReaderKeyRouteCore.State before = core.snapshot();
        rejects(() -> core.configure(null, new int[]{93}, true, 20), "Null document rejected");
        rejects(() -> core.configure("", new int[]{93}, true, 20), "Empty document rejected");
        rejects(() -> core.configure("document", null, true, 20), "Null keys rejected");
        rejects(() -> core.configure("document", new int[]{93, 93}, true, 20), "Duplicate keys rejected");
        rejects(() -> core.configure("document", new int[]{4}, true, 20), "Back/system key never mapped");
        rejects(() -> core.configure("document", new int[]{93}, true, 9), "Backward native uptime rejected");
        rejects(() -> core.configure("document", new int[]{93}, true, 9007199254740992L), "Unsafe cutover rejected");
        check(core.isCurrent(before), "Rejected configuration leaves prior exact route unchanged");
        check(!core.dispatch(2, 93, 2, 15, 0).consume, "Multiple action rejected");
        check(!core.dispatch(0, 93, -2, 15, 0).consume, "Malformed device rejected");
        check(!core.dispatch(0, 93, 2, -1, 0).consume, "Malformed uptime rejected");
        check(!core.dispatch(0, 93, 2, 9007199254740992L, 0).consume, "Unsafe binary64 uptime rejected");
        check(!core.dispatch(0, 93, 2, 15, -1).consume, "Negative repeat rejected");
        check(!core.dispatch(0, 24, 2, 15, 0).consume, "Default does not intercept volume");
        check(core.contactCount() == 0, "Malformed/unmapped events do not create contacts");
        check(core.dispatch(0, 93, 2, 11, 0).packet == null, "Cutover equality conservatively rejects");
        core.configure("document", new int[]{24}, true, 30);
        check(core.dispatch(0, 24, -1, 31, 0).packet != null, "Opt-in volume/synthetic device can be scoped");
    }
    private static void verticalContacts() {
        ReaderKeyRouteCore core = new ReaderKeyRouteCore("vertical");
        core.configure("document-one", new int[]{19,20,21,22,92,93}, true, 10);
        core.eligibility(true,true,true,true,11);
        for (int key : new int[]{19,20}) {
            long down = 100 + key;
            ReaderKeyRouteCore.Decision press = core.dispatch(0,key,3,down,0);
            check(press.consume && press.packet != null && press.packet.keyCode == key,
                    "Vertical DOWN keeps its exact dispatch-time Android key");
            for (int repeat : new int[]{0,1,256,Integer.MAX_VALUE}) {
                ReaderKeyRouteCore.Decision held = core.dispatch(0,key,3,down,repeat);
                check(held.consume && held.packet == null,"Vertical hold cannot duplicate navigation");
            }
            check(core.dispatch(1,key,3,down,0).consume,"Vertical exact UP releases contact");
            check(!core.dispatch(1,key,3,down,0).consume,"Vertical duplicate UP is not owned");
        }
        core.configure("document-one",new int[]{24,25},true,200);
        check(!core.dispatch(0,19,3,201,0).consume && !core.dispatch(0,20,3,202,0).consume,
                "Volume-only configuration leaves vertical arrows ordinary");
        core.configure("document-one",new int[]{19,20},false,210);
        check(!core.dispatch(0,20,3,211,0).consume,"Explicit OFF does not claim vertical arrows");
        core.configure("document-one",new int[]{19,20},true,220);
        check(core.dispatch(0,20,3,211,0).packet == null,"OFF/ON ABA cannot replay old vertical input");
        core.eligibility(true,true,false,true,230);
        check(!core.dispatch(0,19,3,231,0).consume,"Vertical input cannot claim another control's focus");
        core.eligibility(true,true,true,true,240);
        check(core.dispatch(0,19,3,231,0).packet == null,"Focus recovery rejects pre-write contact");
        check(core.dispatch(0,19,3,241,0).packet != null,"Fresh post-focus vertical input accepted");
        core.dispose(250);
        check(!core.dispatch(0,20,3,251,0).consume,"Dropped owner never owns vertical input");
    }
    private static void boundedHistory() {
        ReaderKeyRouteCore core = armed();
        for (int id = 0; id < 32; id++) {
            check(core.dispatch(0, 93, id, 100 + id, 0).packet != null, "Bounded simultaneous press accepted");
        }
        check(core.contactCount() == 32, "History bounded at32");
        check(!core.dispatch(0, 93, 32, 132, 0).consume, "All-held capacity rejection unhandled");
        check(core.dispatch(1, 93, 0, 100, 0).consume, "Release opens capacity");
        check(core.dispatch(0, 93, 32, 132, 0).packet == null, "Capacity-rejected DOWN never replayed");
        check(core.dispatch(0, 93, 33, 133, 0).packet != null, "Fresh later contact can use capacity");
        check(core.dispatch(0, 93, 0, 100, 0).packet == null, "Evicted contact cannot replay");
        check(core.contactCount() == 32, "No history growth");
        core = armed();
        for (int id = 0; id < 500; id++) {
            long time = 100 + id;
            check(core.dispatch(0, 93, id, time, 0).packet != null, "Long run fresh contact accepted");
            check(core.dispatch(1, 93, id, time, 0).consume, "Long run exact UP accepted");
            check(core.contactCount() <= 32, "Long run history bounded");
        }
        check(core.dispatch(0, 93, 0, 100, 0).packet == null, "Oldest retired contact rejected");
    }
    private static void threadAndDispose() throws Exception {
        ReaderKeyRouteCore core = armed();
        boolean[] failed = {false};
        Thread other = new Thread(() -> {
            try { core.dispatch(0, 93, 2, 12, 0); } catch (IllegalStateException expected) { failed[0] = true; }
        });
        other.start(); other.join();
        check(failed[0] && core.contactCount() == 0, "Foreign thread cannot dispatch or mutate");
        ReaderKeyRouteCore.State before = core.snapshot();
        core.dispatch(0, 93, 2, 12, 0);
        ReaderKeyRouteCore.State terminal = core.dispose(20);
        check(terminal.disposed && !terminal.eligible && !core.isCurrent(before), "Dispose revokes authority");
        check(core.contactCount() == 0 && !core.dispatch(0, 93, 2, 21, 0).consume, "Dispose clears ownership");
        check(!core.dispatch(1, 93, 2, 12, 0).consume, "No owned UP after dispose");
        check(core.dispose(21).generation == terminal.generation, "Dispose idempotent");
        rejects(() -> core.configure("other", new int[]{93}, true, 22), "Disposed host cannot rearm");
    }
    public static void main(String[] args) throws Exception {
        contactLifecycle(); epochsAndFocus(); malformed(); verticalContacts(); boundedHistory(); threadAndDispose();
        System.out.println("Reader key route Core: PASS " + assertions + " assertions");
    }
}
