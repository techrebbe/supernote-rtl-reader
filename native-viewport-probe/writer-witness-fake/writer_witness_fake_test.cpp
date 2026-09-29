// OFFLINE HOST-ONLY MODEL. No Binder, JNI, firmware, input, or device access.
// This exercises a proposed witness contract; it does not establish that the
// stock writer has the required gate, generation, or lifecycle behavior.
#include <array>
#include <condition_variable>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <initializer_list>
#include <iostream>
#include <limits>
#include <mutex>
#include <new>
#include <new>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

namespace {

void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

struct WriterState {
    int page;
    int layer;
    std::vector<int> regions;
    bool writable;
};

bool operator==(const WriterState& a, const WriterState& b) {
    return a.page == b.page && a.layer == b.layer &&
           a.regions == b.regions && a.writable == b.writable;
}

constexpr auto kWaitLimit = std::chrono::seconds(10);

// An explicit scheduling point: predicate waits have a bounded watchdog and
// never infer correctness from an elapsed sleep.
class PausePoint {
public:
    explicit PausePoint(std::size_t expected = 1) : expected_(expected) {}

    bool arrive_and_wait() {
        std::unique_lock<std::mutex> lock(mutex_);
        ++arrivals_;
        cv_.notify_all();
        return cv_.wait_for(lock, kWaitLimit, [&] { return released_; });
    }

    bool wait_for_arrival() {
        std::unique_lock<std::mutex> lock(mutex_);
        return cv_.wait_for(lock, kWaitLimit,
                            [&] { return arrivals_ >= expected_; });
    }

    void announce() {
        std::lock_guard<std::mutex> lock(mutex_);
        ++arrivals_;
        cv_.notify_all();
    }

    void release() {
        std::lock_guard<std::mutex> lock(mutex_);
        released_ = true;
        cv_.notify_all();
    }

private:
    std::mutex mutex_;
    std::condition_variable cv_;
    const std::size_t expected_;
    std::size_t arrivals_ = 0;
    bool released_ = false;
};

// Releases every staged worker before joining it even if a test assertion
// throws. Threads are declared before this guard so they outlive its cleanup.
class ScopedReleaseJoin {
public:
    ScopedReleaseJoin(std::initializer_list<PausePoint*> points,
                      std::initializer_list<std::thread*> threads)
        : points_(points), threads_(threads) {}

    ~ScopedReleaseJoin() {
        for (PausePoint* point : points_) point->release();
        for (std::thread* worker : threads_) {
            if (worker->joinable()) worker->join();
        }
    }

private:
    std::vector<PausePoint*> points_;
    std::vector<std::thread*> threads_;
};

enum class SnapshotStatus { available, pending, incomplete };

struct Incarnation {
    std::uint64_t process = 0;
    std::uint64_t service = 0;
};

bool operator==(const Incarnation& a, const Incarnation& b) {
    return a.process == b.process && a.service == b.service;
}

class FakeProcess {
public:
    FakeProcess() : process_(next_process_incarnation()) {}
    FakeProcess(const FakeProcess&) = delete;
    FakeProcess& operator=(const FakeProcess&) = delete;
    FakeProcess(FakeProcess&&) = delete;
    FakeProcess& operator=(FakeProcess&&) = delete;

    Incarnation new_service() {
        std::uint64_t candidate = next_service_.load();
        for (;;) {
            if (candidate == std::numeric_limits<std::uint64_t>::max()) {
                throw std::runtime_error("service incarnation exhausted");
            }
            if (next_service_.compare_exchange_weak(candidate, candidate + 1)) {
                return {process_, candidate};
            }
        }
    }

private:
    static std::uint64_t next_process_incarnation() {
        static std::atomic<std::uint64_t> next{1};
        std::uint64_t candidate = next.load();
        for (;;) {
            if (candidate == std::numeric_limits<std::uint64_t>::max()) {
                throw std::runtime_error("process incarnation exhausted");
            }
            if (next.compare_exchange_weak(candidate, candidate + 1)) {
                return candidate;
            }
        }
    }

    const std::uint64_t process_;
    std::atomic<std::uint64_t> next_service_{1};
};

static_assert(!std::is_copy_constructible<FakeProcess>::value &&
              !std::is_copy_assignable<FakeProcess>::value &&
              !std::is_move_constructible<FakeProcess>::value &&
              !std::is_move_assignable<FakeProcess>::value,
              "process identity must not be duplicable");

FakeProcess& default_fake_process() {
    static FakeProcess process;
    return process;
}

struct Snapshot {
    SnapshotStatus status;
    Incarnation incarnation{};
    std::uint64_t epoch = 0;
    WriterState state{};
};

enum class FailureAt { none, after_page_layer, after_regions };

struct WritePlan {
    PausePoint* gate_attempt = nullptr; // signal after trying the state gate
    std::atomic<bool>* gate_probe_blocked = nullptr;
    PausePoint* after_epoch = nullptr;
    PausePoint* after_page_layer = nullptr;
    PausePoint* after_regions = nullptr;
    FailureAt failure = FailureAt::none;
    bool inject_region_allocation_failure = false;
};

struct PenTrail {
    Incarnation incarnation;
    std::uint64_t epoch;
    WriterState consumed_state;
};

class FakeWriterService {
public:
    explicit FakeWriterService(WriterState initial)
        : FakeWriterService(std::move(initial), default_fake_process()) {}

    FakeWriterService(WriterState initial, FakeProcess& process)
        : incarnation_(process.new_service()), state_(std::move(initial)) {}

    // These are deliberately separate entry paths, as Java and document JNI
    // can each reach the service independently. Both must use the same gate.
    bool java_set(WriterState next, WritePlan plan = {}) {
        return write(Entry::java, next, plan);
    }

    bool jni_set(WriterState next, WritePlan plan = {}) {
        return write(Entry::jni, next, plan);
    }

    Snapshot snapshot() const {
        std::lock_guard<std::mutex> lock(gate_);
        if (fail_next_snapshot_for_test_) {
            fail_next_snapshot_for_test_ = false;
            throw std::bad_alloc();
        }
        if (incomplete_) return {SnapshotStatus::incomplete};
        if (pending_) return {SnapshotStatus::pending};
        return {SnapshotStatus::available, incarnation_, epoch_, state_};
    }

    std::optional<Snapshot> begin_contact() const {
        const Snapshot sample = snapshot();
        if (sample.status != SnapshotStatus::available) return std::nullopt;
        return sample;
    }

    // The actual fake pen side effect (trail append) stays under the same gate
    // as the final identity check. There is no check-then-consume gap.
    bool consume_contact(const Snapshot& admitted,
                         PausePoint* before_effect = nullptr) {
        std::unique_lock<std::mutex> lock(gate_);
        if (admitted.status != SnapshotStatus::available || pending_ ||
            incomplete_ || !(incarnation_ == admitted.incarnation) ||
            epoch_ != admitted.epoch || !state_.writable ||
            !(state_ == admitted.state)) return false;
        if (before_effect && !before_effect->arrive_and_wait()) return false;
        trails_.push_back({incarnation_, epoch_, state_});
        return true;
    }

    // White-box inspection is test-only. An actual witness must never expose
    // partially changed service state as an available snapshot.
    Snapshot raw_for_test() const {
        std::lock_guard<std::mutex> lock(gate_);
        return {pending_ ? SnapshotStatus::pending :
                incomplete_ ? SnapshotStatus::incomplete :
                              SnapshotStatus::available,
                incarnation_, epoch_, state_};
    }

    int java_entries_for_test() const {
        std::lock_guard<std::mutex> lock(gate_);
        return java_entries_;
    }

    int jni_entries_for_test() const {
        std::lock_guard<std::mutex> lock(gate_);
        return jni_entries_;
    }

    std::vector<PenTrail> trails_for_test() const {
        std::lock_guard<std::mutex> lock(gate_);
        return trails_;
    }

    bool gate_acquirable_for_test() const {
        std::unique_lock<std::mutex> lock(gate_, std::try_to_lock);
        return lock.owns_lock();
    }

    void fail_next_snapshot_once_for_test() {
        std::lock_guard<std::mutex> lock(gate_);
        fail_next_snapshot_for_test_ = true;
    }

private:
    enum class Entry { java, jni };

    bool mark_incomplete() {
        std::lock_guard<std::mutex> lock(gate_);
        incomplete_ = true;
        pending_ = false;
        return false;
    }

    static bool checkpoint(PausePoint* point) {
        return !point || point->arrive_and_wait();
    }

    bool write(Entry entry, const WriterState& next, const WritePlan& plan) {
        // Writer entries serialize, but the state gate is released between
        // phases. Every intervening snapshot sees PENDING, never partial data.
        std::lock_guard<std::mutex> writer_lock(writer_serial_);
        if (plan.gate_attempt) {
            std::unique_lock<std::mutex> probe(gate_, std::try_to_lock);
            if (plan.gate_probe_blocked)
                plan.gate_probe_blocked->store(!probe.owns_lock());
            plan.gate_attempt->announce();
        }
        {
            std::lock_guard<std::mutex> lock(gate_);
            if (incomplete_) return false;
            if (epoch_ == std::numeric_limits<std::uint64_t>::max()) {
                incomplete_ = true; // Never wrap to a reusable generation.
                return false;
            }
            ++epoch_;             // Must precede page/layer and every later phase.
            pending_ = true;
            if (entry == Entry::java) ++java_entries_;
            else ++jni_entries_;
        }

        try {
            if (!checkpoint(plan.after_epoch)) return mark_incomplete();

            {
                std::lock_guard<std::mutex> lock(gate_);
                state_.page = next.page;
                state_.layer = next.layer;
            }
            if (!checkpoint(plan.after_page_layer)) return mark_incomplete();
            if (plan.failure == FailureAt::after_page_layer)
                return mark_incomplete();

            {
                std::lock_guard<std::mutex> lock(gate_);
                if (plan.inject_region_allocation_failure) throw std::bad_alloc();
                state_.regions = next.regions;
            }
            if (!checkpoint(plan.after_regions)) return mark_incomplete();
            if (plan.failure == FailureAt::after_regions)
                return mark_incomplete();

            {
                std::lock_guard<std::mutex> lock(gate_);
                state_.writable = next.writable;
                pending_ = false;
            }
            return true;
        } catch (...) {
            // A real allocation or other exception after epoch admission is
            // still an incomplete write, never a stranded PENDING or success.
            return mark_incomplete();
        }
    }

    mutable std::mutex gate_;
    std::mutex writer_serial_;
    const Incarnation incarnation_;
    std::uint64_t epoch_ = 1;
    WriterState state_;
    bool pending_ = false;
    bool incomplete_ = false;
    int java_entries_ = 0;
    int jni_entries_ = 0;
    std::vector<PenTrail> trails_;
    mutable bool fail_next_snapshot_for_test_ = false;
};

struct DetachPlan {
    PausePoint* joined_branch = nullptr;
    bool inject_drain_timeout = false;
};

class WitnessObserver {
public:
    explicit WitnessObserver(FakeWriterService& service) : service_(service) {}

    bool callback(PausePoint* in_flight = nullptr) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!accepting_) return false;
            ++active_callbacks_;
        }

        try {
            const bool reached = !in_flight || in_flight->arrive_and_wait();
            const Snapshot sample = reached ? service_.snapshot() :
                                              Snapshot{SnapshotStatus::incomplete};

            std::lock_guard<std::mutex> lock(mutex_);
            const bool accepted = reached && accepting_ &&
                                  sample.status == SnapshotStatus::available;
            if (accepted) cached_ = sample;
            --active_callbacks_;
            cv_.notify_all();
            return accepted;
        } catch (...) {
            // A callback-side copy/allocation failure cannot strand the drain
            // count or leave a success-shaped cached witness behind.
            std::lock_guard<std::mutex> lock(mutex_);
            accepting_ = false;
            detach_started_ = true;
            cached_.reset();
            --active_callbacks_;
            cv_.notify_all();
            return false;
        }
    }

    bool detach_and_flush(DetachPlan plan = {}) {
        std::unique_lock<std::mutex> lock(mutex_);
        if (detached_) return true;
        if (accepting_) {
            accepting_ = false; // Close new admission before waiting/flush.
            detach_started_ = true;
            cv_.notify_all();
        } else if (plan.joined_branch) {
            plan.joined_branch->announce(); // Proves the join path was entered.
        }

        if (!cv_.wait_for(lock, kWaitLimit,
                          [&] { return !detacher_active_ || detached_; }))
            return false;
        if (detached_) return true;
        detacher_active_ = true;

        if (plan.inject_drain_timeout ||
            !cv_.wait_for(lock, kWaitLimit,
                          [&] { return active_callbacks_ == 0; })) {
            // Remain closed, but permit a later caller to finish the flush.
            detacher_active_ = false;
            cv_.notify_all();
            return false;
        }
        cached_.reset();
        detached_ = true;
        ++flushes_;
        detacher_active_ = false;
        cv_.notify_all();
        return true;
    }

    bool wait_for_detach_start() {
        std::unique_lock<std::mutex> lock(mutex_);
        return cv_.wait_for(lock, kWaitLimit,
                            [&] { return detach_started_; });
    }

    bool flushed_for_test() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return detached_ && !cached_ && flushes_ == 1;
    }

    int flushes_for_test() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return flushes_;
    }

private:
    FakeWriterService& service_;
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    bool accepting_ = true;
    bool detach_started_ = false;
    bool detached_ = false;
    bool detacher_active_ = false;
    int active_callbacks_ = 0;
    int flushes_ = 0;
    std::optional<Snapshot> cached_;
};

void test_two_entries_and_aba() {
    const WriterState a{7, 42, {3, 9}, true};
    const WriterState b{8, 43, {4}, false};
    FakeWriterService service(a);
    const Snapshot first = service.snapshot();
    require(first.status == SnapshotStatus::available, "initial unavailable");
    require(service.java_set(b), "Java setter failed");
    const Snapshot middle = service.snapshot();
    require(middle.epoch == first.epoch + 1 && middle.state == b,
            "Java entry did not advance and apply");
    require(service.jni_set(a), "JNI setter failed");
    const Snapshot last = service.snapshot();
    require(last.state == first.state && last.epoch == first.epoch + 2,
            "A-B-A reused its old generation");
    require(!service.consume_contact(first), "stale A contact survived A-B-A");
    require(service.java_entries_for_test() == 1 &&
            service.jni_entries_for_test() == 1,
            "independent entry path was not exercised");
}

void test_service_restart_aba() {
    const WriterState a{7, 42, {3, 9}, true};
    FakeProcess original_process;
    Snapshot old{SnapshotStatus::incomplete};
    {
        FakeWriterService before_restart(a, original_process);
        old = before_restart.snapshot();
    }
    FakeWriterService replacement_service(a, original_process);
    const Snapshot same_process = replacement_service.snapshot();
    require(same_process.incarnation.process == old.incarnation.process &&
            same_process.incarnation.service != old.incarnation.service &&
            !replacement_service.consume_contact(old),
            "same-process service replacement reused old witness");

    FakeProcess restarted_process;
    FakeWriterService after_restart(a, restarted_process);
    const Snapshot fresh = after_restart.snapshot();
    require(old.state == fresh.state && old.epoch == fresh.epoch,
            "restart test did not recreate the ABA values");
    require(old.incarnation.process != fresh.incarnation.process &&
            old.incarnation.service == fresh.incarnation.service,
            "process restart did not reset local service id under a new process");
    require(!after_restart.consume_contact(old),
            "pre-restart witness authorized post-restart pen effect");
    require(after_restart.consume_contact(fresh),
            "fresh incarnation witness was rejected");
}

void test_concurrent_service_incarnations() {
    const WriterState a{7, 42, {3, 9}, true};
    FakeProcess process;
    PausePoint all_ready(4);
    std::array<Incarnation, 4> identities{};
    std::array<bool, 4> completed{};
    std::thread worker0, worker1, worker2, worker3;
    ScopedReleaseJoin cleanup({&all_ready},
                              {&worker0, &worker1, &worker2, &worker3});
    const auto construct = [&](std::size_t index) {
        if (!all_ready.arrive_and_wait()) return;
        FakeWriterService service(a, process);
        const Snapshot observed = service.snapshot();
        identities[index] = observed.incarnation;
        completed[index] = observed.status == SnapshotStatus::available;
    };
    worker0 = std::thread(construct, 0);
    worker1 = std::thread(construct, 1);
    worker2 = std::thread(construct, 2);
    worker3 = std::thread(construct, 3);
    require(all_ready.wait_for_arrival(),
            "concurrent constructors did not reach barrier");
    all_ready.release();
    worker0.join();
    worker1.join();
    worker2.join();
    worker3.join();
    for (std::size_t i = 0; i < identities.size(); ++i) {
        require(completed[i], "concurrent service construction failed");
        for (std::size_t j = 0; j < i; ++j) {
            require(identities[i].process == identities[j].process &&
                    identities[i].service != identities[j].service,
                    "concurrent service IDs collided or changed process");
        }
    }
}

void test_pending_and_incomplete() {
    const WriterState a{1, 2, {3, 4}, true};
    const WriterState b{5, 6, {7, 8, 9}, false};
    FakeWriterService service(a);
    const Snapshot initial = service.snapshot();
    PausePoint after_epoch;
    PausePoint after_page_layer;
    PausePoint after_regions;
    bool writer_succeeded = true;
    WritePlan plan;
    plan.after_epoch = &after_epoch;
    plan.after_page_layer = &after_page_layer;
    plan.after_regions = &after_regions;
    plan.failure = FailureAt::after_regions;
    std::thread writer;
    ScopedReleaseJoin cleanup({&after_epoch, &after_page_layer, &after_regions},
                              {&writer});
    writer = std::thread([&] {
        writer_succeeded = service.jni_set(b, plan);
    });
    require(after_epoch.wait_for_arrival(), "epoch checkpoint timed out");
    Snapshot raw = service.raw_for_test();
    require(raw.epoch == initial.epoch + 1 && raw.state == a,
            "epoch did not advance before state mutation");
    require(service.snapshot().status == SnapshotStatus::pending,
            "pre-mutation write looked available");
    require(!service.begin_contact(), "pen admitted during pending write");
    after_epoch.release();

    require(after_page_layer.wait_for_arrival(),
            "page/layer checkpoint timed out");
    raw = service.raw_for_test();
    require(raw.state.page == b.page && raw.state.layer == b.layer &&
            raw.state.regions == a.regions && raw.state.writable == a.writable,
            "page/layer phase was not isolated");
    require(service.snapshot().status == SnapshotStatus::pending,
            "partial page/layer leaked as a witness");
    after_page_layer.release();

    require(after_regions.wait_for_arrival(),
            "region checkpoint timed out");
    raw = service.raw_for_test();
    require(raw.state.page == b.page && raw.state.layer == b.layer &&
            raw.state.regions == b.regions && raw.state.writable == a.writable,
            "region phase was not isolated from writable flag");
    require(service.snapshot().status == SnapshotStatus::pending,
            "partial region vector leaked as a witness");
    after_regions.release();
    writer.join();
    require(!writer_succeeded, "mid-write failure reported success");
    require(service.snapshot().status == SnapshotStatus::incomplete,
            "incomplete write looked available");
    raw = service.raw_for_test();
    require(raw.state.regions == b.regions && raw.state.writable == a.writable,
            "mid-write failure did not preserve a partial fake state");
    require(!service.begin_contact(), "pen admitted after incomplete write");
    require(!service.java_set(a), "poisoned witness accepted another write");
}

void test_exception_after_pending_poison() {
    const WriterState a{1, 2, {3, 4}, true};
    const WriterState b{5, 6, {7, 8, 9}, false};
    FakeWriterService service(a);
    const Snapshot before = service.snapshot();
    WritePlan plan;
    plan.inject_region_allocation_failure = true;
    require(!service.java_set(b, plan),
            "injected region allocation exception reported success");
    const Snapshot raw = service.raw_for_test();
    require(raw.status == SnapshotStatus::incomplete &&
            raw.epoch == before.epoch + 1 &&
            raw.state.page == b.page && raw.state.layer == b.layer &&
            raw.state.regions == a.regions && raw.state.writable == a.writable,
            "exception did not clear pending and poison partial write");
    require(service.snapshot().status == SnapshotStatus::incomplete &&
            !service.begin_contact() && !service.jni_set(a),
            "exception exposed a success-shaped witness");
}

void test_disabled_writer_has_no_pen_effect() {
    const WriterState enabled{10, 20, {30}, true};
    const WriterState disabled{10, 20, {30}, false};
    FakeWriterService service(enabled);
    const Snapshot old = service.snapshot();
    require(service.java_set(disabled), "disable setter failed");
    const Snapshot current = service.snapshot();
    require(current.status == SnapshotStatus::available &&
            !current.state.writable && !service.consume_contact(old) &&
            !service.consume_contact(current) &&
            service.trails_for_test().empty(),
            "disabled writer appended a pen trail");
    require(service.jni_set(enabled), "re-enable setter failed");
    const Snapshot fresh = service.snapshot();
    require(service.consume_contact(fresh) &&
            service.trails_for_test().size() == 1,
            "re-enabled writer rejected fresh contact");
}

void test_concurrent_pen_worker() {
    const WriterState a{10, 20, {30}, true};
    const WriterState b{11, 20, {31}, true};
    FakeWriterService service(a);
    PausePoint pen_before_commit;
    PausePoint writer_after_epoch;
    bool pen_consumed = true;
    WritePlan plan;
    plan.after_epoch = &writer_after_epoch;
    std::thread pen;
    std::thread writer;
    ScopedReleaseJoin cleanup({&pen_before_commit, &writer_after_epoch},
                              {&pen, &writer});
    pen = std::thread([&] {
        const auto contact = service.begin_contact();
        const bool resumed = pen_before_commit.arrive_and_wait();
        pen_consumed = resumed && contact && service.consume_contact(*contact);
    });
    require(pen_before_commit.wait_for_arrival(),
            "pen admission checkpoint timed out");

    writer = std::thread([&] { service.jni_set(b, plan); });
    require(writer_after_epoch.wait_for_arrival(),
            "writer epoch checkpoint timed out");
    require(service.snapshot().status == SnapshotStatus::pending,
            "concurrent setter did not close witness availability");
    writer_after_epoch.release();
    writer.join();
    pen_before_commit.release();
    pen.join();
    require(!pen_consumed && service.trails_for_test().empty(),
            "pen worker consumed stale state after writer changed");
    const auto fresh = service.begin_contact();
    require(fresh && service.consume_contact(*fresh) &&
            service.trails_for_test().size() == 1,
            "stable post-write contact was rejected");
}

void test_pen_effect_atomic_with_writer_change() {
    const WriterState a{10, 20, {30}, true};
    const WriterState b{11, 21, {31, 32}, false};
    FakeWriterService service(a);
    const Snapshot admitted = service.snapshot();
    PausePoint pen_inside_gate;
    PausePoint writer_gate_attempt;
    bool pen_consumed = false;
    bool writer_succeeded = false;
    std::atomic<bool> writer_finished{false};
    std::atomic<bool> gate_probe_blocked{false};
    WritePlan plan;
    plan.gate_attempt = &writer_gate_attempt;
    plan.gate_probe_blocked = &gate_probe_blocked;
    std::thread pen;
    std::thread writer;
    ScopedReleaseJoin cleanup({&pen_inside_gate, &writer_gate_attempt},
                              {&pen, &writer});

    pen = std::thread([&] {
        pen_consumed = service.consume_contact(admitted, &pen_inside_gate);
    });
    require(pen_inside_gate.wait_for_arrival(),
            "pen effect checkpoint timed out");
    require(!service.gate_acquirable_for_test(),
            "pen released state gate between check and side effect");

    writer = std::thread([&] {
        writer_succeeded = service.java_set(b, plan);
        writer_finished.store(true);
    });
    require(writer_gate_attempt.wait_for_arrival(),
            "writer gate-attempt checkpoint timed out");
    require(gate_probe_blocked.load(),
            "writer did not encounter the pen-held state gate");
    require(!writer_finished.load(),
            "writer completed while pen side effect held the state gate");

    pen_inside_gate.release();
    pen.join();
    writer.join();
    const auto trails = service.trails_for_test();
    const Snapshot after = service.snapshot();
    require(pen_consumed && writer_succeeded && trails.size() == 1,
            "pen/writer interleaving did not complete");
    require(trails[0].incarnation == admitted.incarnation &&
            trails[0].epoch == admitted.epoch &&
            trails[0].consumed_state == a,
            "pen effect used state from after the writer change");
    require(after.state == b && after.epoch == admitted.epoch + 1,
            "writer change did not follow pen consumption");
}

void test_detach_flush_new_entry_race() {
    FakeWriterService service({1, 2, {3}, true});
    WitnessObserver observer(service);
    require(observer.callback(), "initial callback did not cache witness");

    PausePoint callback_in_flight;
    PausePoint second_detacher_started;
    DetachPlan second_plan;
    second_plan.joined_branch = &second_detacher_started;
    bool old_callback_accepted = true;
    bool first_detach_succeeded = false;
    bool second_detach_succeeded = false;
    std::thread callback;
    std::thread first_detacher;
    std::thread second_detacher;
    ScopedReleaseJoin cleanup({&callback_in_flight},
                              {&callback, &first_detacher, &second_detacher});
    callback = std::thread([&] {
        old_callback_accepted = observer.callback(&callback_in_flight);
    });
    require(callback_in_flight.wait_for_arrival(),
            "callback checkpoint timed out");
    first_detacher = std::thread([&] {
        first_detach_succeeded = observer.detach_and_flush();
    });
    require(observer.wait_for_detach_start(), "detach start timed out");
    second_detacher = std::thread([&] {
        second_detach_succeeded = observer.detach_and_flush(second_plan);
    });
    require(second_detacher_started.wait_for_arrival(),
            "second detach caller did not enter join branch");
    require(!observer.flushed_for_test(), "flush passed an active callback");
    require(!observer.callback(), "new callback entered after detach began");
    callback_in_flight.release();
    callback.join();
    first_detacher.join();
    second_detacher.join();
    require(!old_callback_accepted,
            "in-flight callback reported a witness after detach began");
    require(first_detach_succeeded && second_detach_succeeded,
            "concurrent detach caller did not join the first detach");
    require(observer.flushed_for_test(), "detach did not flush cached witness");
    require(!observer.callback(), "callback entered after flush");
    require(observer.detach_and_flush(), "repeat detach failed");
    require(observer.flushes_for_test() == 1, "detach flushed twice");
}

void test_detach_takeover_after_timeout() {
    FakeWriterService service({1, 2, {3}, true});
    WitnessObserver observer(service);
    require(observer.callback(), "initial callback did not cache witness");
    PausePoint callback_in_flight;
    bool old_callback_accepted = true;
    std::thread callback;
    ScopedReleaseJoin cleanup({&callback_in_flight}, {&callback});
    callback = std::thread([&] {
        old_callback_accepted = observer.callback(&callback_in_flight);
    });
    require(callback_in_flight.wait_for_arrival(),
            "callback timeout-checkpoint timed out");

    DetachPlan first_plan;
    first_plan.inject_drain_timeout = true;
    require(!observer.detach_and_flush(first_plan),
            "injected first detach timeout reported success");
    require(!observer.flushed_for_test() && !observer.callback(),
            "timed-out detach reopened admission or forged a flush");
    callback_in_flight.release();
    callback.join();
    require(!old_callback_accepted,
            "callback accepted after first detach closed admission");
    require(observer.detach_and_flush() && observer.flushed_for_test() &&
            observer.flushes_for_test() == 1,
            "later detach caller did not take over and flush once");
}

void test_callback_exception_drains() {
    FakeWriterService service({1, 2, {3}, true});
    WitnessObserver observer(service);
    require(observer.callback(), "initial callback did not cache witness");
    service.fail_next_snapshot_once_for_test();
    require(!observer.callback(), "snapshot exception escaped callback");
    require(!observer.callback(), "failed callback reopened admission");
    require(observer.detach_and_flush() && observer.flushed_for_test(),
            "snapshot exception stranded in-flight callback or cached witness");
}

} // namespace

int main() {
    try {
        std::cerr << "RUN: two entries and A-B-A\n";
        test_two_entries_and_aba();
        std::cerr << "RUN: service restart A-B-A\n";
        test_service_restart_aba();
        std::cerr << "RUN: concurrent service incarnations\n";
        test_concurrent_service_incarnations();
        std::cerr << "RUN: phased pending and incomplete\n";
        test_pending_and_incomplete();
        std::cerr << "RUN: exception after pending\n";
        test_exception_after_pending_poison();
        std::cerr << "RUN: disabled writer\n";
        test_disabled_writer_has_no_pen_effect();
        std::cerr << "RUN: concurrent pen worker\n";
        test_concurrent_pen_worker();
        std::cerr << "RUN: atomic pen side effect\n";
        test_pen_effect_atomic_with_writer_change();
        std::cerr << "RUN: concurrent detach, flush, and new entry\n";
        test_detach_flush_new_entry_race();
        std::cerr << "RUN: detach takeover after timeout\n";
        test_detach_takeover_after_timeout();
        std::cerr << "RUN: callback exception drains\n";
        test_callback_exception_drains();
        std::cout << "PASS: entries, incarnations, phased/exception failure, "
                     "writable pen effect, detach/flush takeover\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
