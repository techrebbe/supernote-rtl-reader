#ifndef PEN_INPUT_LEASE_CORE_H
#define PEN_INPUT_LEASE_CORE_H

#include <stdint.h>

/* Pure, failure-injectable control flow. Production callbacks must never read,
 * log, transform, or replay events from the evdev descriptor. */
#define PEN_INPUT_LEASE_MAX_HOLD_MS UINT64_C(300000)

enum pen_input_lease_end_reason {
    PEN_INPUT_LEASE_END_RELEASE = 0,
    PEN_INPUT_LEASE_END_TIMEOUT = 1,
    PEN_INPUT_LEASE_END_SIGNAL = 2,
    PEN_INPUT_LEASE_END_PARENT_LOST = 3,
    PEN_INPUT_LEASE_END_CONTROL_LOST = 4,
    PEN_INPUT_LEASE_END_REVALIDATION_FAILED = 5,
    PEN_INPUT_LEASE_END_ERROR = 6
};

struct pen_input_lease_end {
    enum pen_input_lease_end_reason reason;
    int release_received;
    int final_phase_proved;
};

enum pen_input_lease_idle_result {
    PEN_INPUT_LEASE_IDLE = 0,
    PEN_INPUT_LEASE_ACTIVE_AT_DEADLINE = 1,
    PEN_INPUT_LEASE_IDLE_ERROR = -1
};

struct pen_input_lease_ops {
    void *context;
    int (*admit_contract)(void *context);
    int64_t (*parent_id)(void *context);
    int (*install_cleanup_handlers)(void *context);
    /* 0 means no cleanup control is pending, 1 means a cleanup was consumed,
     * and -1 means the pending-signal state could not be inspected safely. */
    int (*termination_pending)(void *context);
    int (*arm_parent_death)(void *context);
    int (*open_device)(void *context);
    int (*verify_initial_device)(void *context, int fd);
    int (*revalidate_device)(void *context, int fd);
    int (*same_device)(void *context, int first, int second);
    /* idle: 0 idle, 1 contact/tool active, -1 inspection failure. */
    int (*idle)(void *context, int fd);
    /* grab: 0 acquired, 1 busy, -1 other failure. */
    int (*grab)(void *context, int fd);
    /* Bind the shared standby probe and prepare entropy before any grab. Both
     * descriptors stay open across fork and throughout a held quarantine. */
    int (*prepare_guardian)(void *context, int held_fd, int standby_fd);
    /* The guardian must retain the grabbed open-file description and complete
     * its authenticated worker handshake before this callback succeeds.
     * Return 0 when that proof exists, 1 only when no child was created and
     * the caller is demonstrably the sole grab holder, and -1 when guardian
     * ownership is ambiguous (which requires quarantine). */
    int (*start_guardian)(void *context, int held_fd,
        uint64_t absolute_deadline_ms, int64_t expected_parent);
    /* Before READY only, the authenticated guardian independently proves idle
     * state, releases its retained grab, acknowledges, and exits. */
    int (*abort_guardian_before_ready)(void *context, int held_fd,
        uint64_t absolute_deadline_ms, int64_t expected_parent);
    int (*release)(void *context, int fd);
    int (*close_device)(void *context, int fd);
    /* Android CLOCK_BOOTTIME domain: elapsed time includes suspend. */
    int (*boottime_ms)(void *context, uint64_t *value);
    /* Return 0 only while the dedicated status consumer is still attached and
     * the nonblocking result endpoint remains usable; nonzero means loss or
     * an inspection error. */
    int (*status_consumer_alive)(void *context);
    int (*emit_ready)(void *context, uint64_t absolute_deadline_ms);
    int (*wait_until)(void *context, int held_fd,
        uint64_t absolute_deadline_ms, int64_t expected_parent,
        struct pen_input_lease_end *outcome);
    enum pen_input_lease_idle_result (*wait_idle_until)(void *context,
        int held_fd, uint64_t absolute_deadline_ms, int64_t expected_parent);
    int (*prove_still_exclusive)(void *context, int held_fd);
    int (*emit_released)(void *context, enum pen_input_lease_end_reason reason);
    int (*emit_failed)(void *context, const char *stage, int held,
        int reboot_required);
    /* Production never returns. A host fake returns to expose held state. */
    void (*quarantine)(void *context, int first_fd, int second_fd);
};

static int pen_input_lease_ops_valid(const struct pen_input_lease_ops *ops) {
    return ops != 0 && ops->admit_contract != 0 && ops->parent_id != 0 &&
        ops->install_cleanup_handlers != 0 && ops->arm_parent_death != 0 &&
        ops->termination_pending != 0 &&
        ops->open_device != 0 && ops->verify_initial_device != 0 &&
        ops->revalidate_device != 0 && ops->same_device != 0 &&
        ops->idle != 0 && ops->grab != 0 && ops->prepare_guardian != 0 &&
        ops->start_guardian != 0 &&
        ops->abort_guardian_before_ready != 0 && ops->release != 0 &&
        ops->close_device != 0 && ops->boottime_ms != 0 &&
        ops->status_consumer_alive != 0 &&
        ops->emit_ready != 0 && ops->wait_until != 0 &&
        ops->wait_idle_until != 0 && ops->prove_still_exclusive != 0 &&
        ops->emit_released != 0 && ops->emit_failed != 0 &&
        ops->quarantine != 0;
}

static int pen_input_lease_before_deadline(
        const struct pen_input_lease_ops *ops, uint64_t deadline) {
    uint64_t now = 0;
    return ops->boottime_ms(ops->context, &now) == 0 && now < deadline;
}

/* Returns 0 after a safe idle handoff, 1 before acquisition or after a safe
 * but failed cleanup, and 2 only when a host-test quarantine callback returns.
 * Production quarantine never returns and deliberately retains EVIOCGRAB until
 * reboot/process teardown. */
static int pen_input_lease_run(
        const struct pen_input_lease_ops *ops, uint64_t hold_ms) {
    int first = -1;
    int second = -1;
    int first_held = 0;
    int second_held = 0;
    int guardian_started = 0;
    int64_t parent = -1;
    uint64_t start = 0;
    uint64_t deadline = 0;
    const char *stage = "invalid_contract";
    struct pen_input_lease_end end;
    void *context;

    if (!pen_input_lease_ops_valid(ops)) return 1;
    context = ops->context;
    end.reason = PEN_INPUT_LEASE_END_ERROR;
    end.release_received = 0;
    end.final_phase_proved = 0;
    if (hold_ms == 0 || hold_ms > PEN_INPUT_LEASE_MAX_HOLD_MS) {
        (void)ops->emit_failed(context, "invalid_timeout", 0, 0);
        return 1;
    }
    stage = "install_cleanup_handlers";
    if (ops->install_cleanup_handlers(context) != 0) goto fail_before_grab;
    stage = "admit_contract";
    if (ops->admit_contract(context) != 0) goto fail_before_grab;
    stage = "parent_before_arm";
    parent = ops->parent_id(context);
    if (parent <= 1) goto fail_before_grab;
    stage = "arm_parent_death";
    if (ops->arm_parent_death(context) != 0) goto fail_before_grab;
    stage = "parent_after_arm";
    if (ops->parent_id(context) != parent) goto fail_before_grab;
    stage = "open_first";
    first = ops->open_device(context);
    if (first < 0) goto fail_before_grab;
    stage = "verify_first";
    if (ops->verify_initial_device(context, first) != 0) goto fail_before_grab;
    stage = "idle_before_grab";
    if (ops->idle(context, first) != 0) goto fail_before_grab;
    stage = "open_second";
    second = ops->open_device(context);
    if (second < 0) goto fail_before_grab;
    if (second == first) {
        second = -1;
        goto fail_before_grab;
    }
    stage = "verify_second";
    if (ops->verify_initial_device(context, second) != 0) goto fail_before_grab;
    stage = "same_device";
    if (ops->same_device(context, first, second) != 0) goto fail_before_grab;
    stage = "prepare_guardian";
    if (ops->prepare_guardian(context, first, second) != 0) goto fail_before_grab;

    stage = "termination_before_grab";
    if (ops->termination_pending(context) != 0) goto fail_before_grab;

    /* The absolute normal-lease deadline is fixed before EVIOCGRAB. */
    stage = "clock_before_grab";
    if (ops->boottime_ms(context, &start) != 0 ||
            UINT64_MAX - start < hold_ms) goto fail_before_grab;
    deadline = start + hold_ms;
    stage = "grab_first";
    if (ops->grab(context, first) != 0) goto fail_before_grab;
    first_held = 1;
    stage = "start_guardian";
    {
        int guardian_result = ops->start_guardian(context, first, deadline, parent);
        if (guardian_result > 0) goto safe_no_guardian;
        if (guardian_result < 0) goto quarantine;
    }
    guardian_started = 1;
    stage = "idle_after_grab";
    if (!pen_input_lease_before_deadline(ops, deadline) ||
            ops->idle(context, first) != 0) goto quarantine;
    stage = "prove_second_excluded";
    {
        int second_grab = ops->grab(context, second);
        if (second_grab == 0) second_held = 1;
        if (second_grab != 1) goto quarantine;
    }
    /* The standby OFD is retained in both processes. If a later exclusivity
     * probe unexpectedly acquires it, guardian retirement still leaves a
     * worker alias retaining that emergency grab. */
    stage = "revalidate_before_ready";
    if (!pen_input_lease_before_deadline(ops, deadline) ||
            ops->revalidate_device(context, first) != 0 ||
            ops->parent_id(context) != parent) goto quarantine;
    stage = "termination_before_ready";
    if (ops->termination_pending(context) != 0) goto safe_pre_ready_abort;
    stage = "emit_ready";
    if (ops->status_consumer_alive(context) != 0 ||
            ops->emit_ready(context, deadline) != 0) goto quarantine;
    stage = "wait";
    if (ops->wait_until(context, first, deadline, parent, &end) != 0 ||
            end.reason < PEN_INPUT_LEASE_END_RELEASE ||
            end.reason > PEN_INPUT_LEASE_END_ERROR) goto quarantine;
    stage = "status_after_wait";
    if (ops->status_consumer_alive(context) != 0) goto quarantine;
    stage = "final_phase";
    if (!end.final_phase_proved) goto quarantine;
    stage = "final_idle";
    {
        int idle_now = ops->idle(context, first);
        if (idle_now < 0) goto quarantine;
        if (idle_now > 0) {
            if (end.reason != PEN_INPUT_LEASE_END_RELEASE &&
                    end.reason != PEN_INPUT_LEASE_END_TIMEOUT) goto quarantine;
            if (ops->wait_idle_until(context, first, deadline, parent) !=
                    PEN_INPUT_LEASE_IDLE) goto quarantine;
        }
    }
    stage = "final_revalidation";
    if (ops->revalidate_device(context, first) != 0 ||
            ops->prove_still_exclusive(context, first) != 0) goto quarantine;
    stage = "status_before_release";
    if (ops->status_consumer_alive(context) != 0) goto quarantine;
    stage = "idle_at_release";
    if (ops->idle(context, first) != 0) goto quarantine;

    stage = "release";
    /* A guardian release failure is ambiguous even after final authority.
     * Retain the worker's duplicate rather than falling back to a sole-worker
     * ungrab that would defeat independent crash containment. */
    if (ops->release(context, first) != 0) goto quarantine;
    first_held = 0;
    stage = "close_second";
    {
        int closing = second;
        second = -1;
        if (ops->close_device(context, closing) != 0) goto safe_cleanup_failed;
    }
    stage = "close_first";
    {
        int closing = first;
        first = -1;
        if (ops->close_device(context, closing) != 0) goto safe_cleanup_failed;
    }
    if (ops->emit_released(context, end.reason) != 0) return 1;
    return 0;

safe_pre_ready_abort:
    /* No foreign task/display has been admitted yet. Release is nevertheless
     * delegated to the already-authenticated guardian and is allowed only
     * after fresh idle, identity, and exclusivity proofs. */
    if (!guardian_started || ops->revalidate_device(context, first) != 0 ||
            ops->prove_still_exclusive(context, first) != 0 ||
            ops->idle(context, first) != 0 ||
            ops->abort_guardian_before_ready(context, first, deadline, parent) != 0)
        goto quarantine;
    first_held = 0;
    guardian_started = 0;
    {
        int closing = second;
        second = -1;
        if (ops->close_device(context, closing) != 0) goto safe_cleanup_failed;
    }
    {
        int closing = first;
        first = -1;
        if (ops->close_device(context, closing) != 0) goto safe_cleanup_failed;
    }
    (void)ops->emit_failed(context, stage, 0, 0);
    return 1;

safe_no_guardian:
    /* The adapter proved that no child inherited the grabbed OFD. The worker
     * may therefore unwind its sole grab, but only after fresh idle, identity,
     * and exclusivity proofs. A failed proof/release remains quarantined. */
    stage = "guardian_not_created";
    if (guardian_started || ops->revalidate_device(context, first) != 0 ||
            ops->prove_still_exclusive(context, first) != 0 ||
            !pen_input_lease_before_deadline(ops, deadline) ||
            ops->status_consumer_alive(context) != 0 ||
            ops->idle(context, first) != 0 ||
            ops->release(context, first) != 0) goto quarantine;
    first_held = 0;
    if (second >= 0) {
        int closing = second;
        second = -1;
        if (ops->close_device(context, closing) != 0) goto safe_cleanup_failed;
    }
    {
        int closing = first;
        first = -1;
        if (ops->close_device(context, closing) != 0) goto safe_cleanup_failed;
    }
    (void)ops->emit_failed(context, stage, 0, 0);
    return 1;

safe_cleanup_failed:
    /* Final idle + phase authority make descriptor close a safe backstop. */
    if (first_held) {
        (void)ops->release(context, first);
        first_held = 0;
    }
    if (first >= 0) {
        int closing = first;
        first = -1;
        (void)ops->close_device(context, closing);
    }
    (void)ops->emit_failed(context, stage, 0, 0);
    return 1;

fail_before_grab:
    if (second >= 0) {
        int closing = second;
        second = -1;
        (void)ops->close_device(context, closing);
    }
    if (first >= 0) {
        int closing = first;
        first = -1;
        (void)ops->close_device(context, closing);
    }
    (void)ops->emit_failed(context, stage, 0, 0);
    return 1;

quarantine:
    /* No release/close is permitted here. The retained descriptors are the
     * safety barrier. Manual device reboot is the recovery. */
    (void)ops->emit_failed(context, stage, 1, 1);
    ops->quarantine(context, first_held ? first : -1,
        second_held ? second : -1);
    return 2;
}

#endif
