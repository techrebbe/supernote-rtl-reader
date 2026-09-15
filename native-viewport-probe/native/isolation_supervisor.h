#ifndef VIEWPORT_ISOLATION_SUPERVISOR_H
#define VIEWPORT_ISOLATION_SUPERVISOR_H

/* Linux/Android diagnostic supervisor, shared with the actual kernel tests.
 * Never use an unbounded waitpid, including after a failed signal. */
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Consume exactly one bounded nonblocking pipe frame after the exact child has
 * been reaped. EOF is part of the frame: truncation, duplicates, trailing
 * bytes, a retained writer, and every read error are rejection outcomes. */
static inline int isolation_read_exact_eof(
        int fd, void *data, size_t expected, size_t already) {
    if (fd < 0 || already > expected || (expected && !data)) return -1;
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0 || !(flags & O_NONBLOCK)) return -1;
    unsigned char *bytes = data;
    while (already < expected) {
        ssize_t count = read(fd, bytes + already, expected - already);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return -1;
        already += (size_t)count;
    }
    unsigned char trailing;
    for (;;) {
        ssize_t count = read(fd, &trailing, 1);
        if (count < 0 && errno == EINTR) continue;
        return count == 0 ? 0 : -1;
    }
}

static inline int64_t isolation_clock_ms(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return -1;
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

/* Single-threaded supervisor only. Do not inherit automatic child reaping:
 * the exact child must remain waitable, reserving its PID until we reap it. */
static inline int isolation_prepare_parent(void) {
    struct sigaction action, observed;
    memset(&action, 0, sizeof(action));
    action.sa_handler = SIG_DFL;
    if (sigemptyset(&action.sa_mask) || sigaction(SIGCHLD, &action, NULL) ||
        sigaction(SIGCHLD, NULL, &observed)) return -1;
    return observed.sa_handler == SIG_DFL && !(observed.sa_flags & SA_NOCLDWAIT) ? 0 : -1;
}

/* Arm before mounts/credential changes. The later filter cannot cancel this
 * kernel timer, install a handler, or block SIGALRM. PDEATHSIG is independent. */
static inline int isolation_arm_watchdog(unsigned seconds) {
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = SIG_DFL;
    if (!seconds || sigemptyset(&action.sa_mask) || sigaction(SIGALRM, &action, NULL)) return -1;
    sigset_t unblocked;
    if (sigemptyset(&unblocked) || sigaddset(&unblocked, SIGALRM) ||
        sigprocmask(SIG_UNBLOCK, &unblocked, NULL)) return -1;
    alarm(seconds);
    return 0;
}

enum isolation_wait_outcome {
    ISO_WAIT_SUPERVISOR_ERROR = -1,
    ISO_WAIT_ELAPSED_TIMEOUT = 0,
    ISO_WAIT_TIMELY_EXIT = 1,
    ISO_WAIT_LATE_EXIT = 2
};

static inline int isolation_observed_exit_outcome(
        int64_t start_ms, int64_t observed_ms, unsigned timeout_ms) {
    if (start_ms < 0 || observed_ms < start_ms || timeout_ms > 10000)
        return ISO_WAIT_SUPERVISOR_ERROR;
    return (uint64_t)(observed_ms - start_ms) < timeout_ms
        ? ISO_WAIT_TIMELY_EXIT : ISO_WAIT_LATE_EXIT;
}

struct isolation_wait_ops {
    int64_t (*clock_ms)(void *opaque);
    pid_t (*wait_nohang)(pid_t child, int *status, void *opaque);
    int (*pause_ms)(uint64_t milliseconds, void *opaque);
    void *opaque;
};

static inline int64_t isolation_real_clock(void *opaque) {
    (void)opaque;
    return isolation_clock_ms();
}

static inline pid_t isolation_real_wait(pid_t child, int *status, void *opaque) {
    (void)opaque;
    return waitpid(child, status, WNOHANG);
}

static inline int isolation_real_pause(uint64_t milliseconds, void *opaque) {
    (void)opaque;
    struct timespec pause = {(time_t)(milliseconds / 1000),
                             (long)(milliseconds % 1000) * 1000000L};
    return nanosleep(&pause, NULL);
}

/* TIMELY_EXIT = exact child reaped, ELAPSED_TIMEOUT = deadline, and
 * SUPERVISOR_ERROR = clock/wait failure.  Callers must retain this provenance;
 * a later cleanup signal or reap must never relabel an error/late exit as the
 * expected timeout case.
 * LATE_EXIT means the exact child was reaped only after the deadline and is
 * never acceptable as a timely exit or a forced timeout. */
static inline int isolation_wait_exit_with_ops(
        pid_t child, int *status, unsigned timeout_ms,
        const struct isolation_wait_ops *ops) {
    if (!ops || !ops->clock_ms || !ops->wait_nohang || !ops->pause_ms)
        return ISO_WAIT_SUPERVISOR_ERROR;
    int64_t start = ops->clock_ms(ops->opaque);
    if (child <= 0 || !status || start < 0 || timeout_ms > 10000)
        return ISO_WAIT_SUPERVISOR_ERROR;
    for (;;) {
        int64_t before = ops->clock_ms(ops->opaque);
        if (before < start) return ISO_WAIT_SUPERVISOR_ERROR;
        if ((uint64_t)(before - start) >= timeout_ms) return ISO_WAIT_ELAPSED_TIMEOUT;
        pid_t ended = ops->wait_nohang(child, status, ops->opaque);
        if (ended < 0 && errno != EINTR) return ISO_WAIT_SUPERVISOR_ERROR;
        int64_t after = ops->clock_ms(ops->opaque);
        if (after < before) return ISO_WAIT_SUPERVISOR_ERROR;
        if (ended == child) return isolation_observed_exit_outcome(start, after, timeout_ms);
        if ((uint64_t)(after - start) >= timeout_ms) return ISO_WAIT_ELAPSED_TIMEOUT;
        uint64_t remaining = timeout_ms - (uint64_t)(after - start);
        uint64_t pause_ms = remaining < 10 ? remaining : 10;
        if (ops->pause_ms(pause_ms, ops->opaque) && errno != EINTR)
            return ISO_WAIT_SUPERVISOR_ERROR;
    }
}

static inline int isolation_wait_exit(pid_t child, int *status, unsigned timeout_ms) {
    const struct isolation_wait_ops ops = {
        isolation_real_clock, isolation_real_wait, isolation_real_pause, NULL};
    return isolation_wait_exit_with_ops(child, status, timeout_ms, &ops);
}

struct isolation_reap_result {
    int reaped;
    int signal_sent;
    int signal_error;
    int wait_error;
};

static inline int isolation_confirmed_forced_timeout(
        int wait_outcome, struct isolation_reap_result stopped, int status) {
    return wait_outcome == ISO_WAIT_ELAPSED_TIMEOUT && stopped.signal_sent &&
        stopped.reaped == ISO_WAIT_TIMELY_EXIT && WIFSIGNALED(status) &&
        WTERMSIG(status) == SIGKILL;
}

static inline struct isolation_reap_result isolation_stop_child(
        pid_t child, int *status, unsigned timeout_ms,
        int (*send_signal)(pid_t, int)) {
    struct isolation_reap_result out = {-1, 0, 0, 0};
    if (child <= 0 || !status || !send_signal) return out;
    /* ECHILD means we no longer own a waitable child. Never signal that PID.
     * With normalized SIGCHLD and no other reaper, an exit between this check
     * and kill retains the PID as a zombie, so it cannot target another task. */
    pid_t ended = waitpid(child, status, WNOHANG);
    if (ended == child) { out.reaped = 1; return out; }
    if (ended < 0) { out.wait_error = errno; return out; }
    errno = 0;
    out.signal_sent = send_signal(child, SIGKILL) == 0;
    out.signal_error = out.signal_sent ? 0 : errno;
    out.reaped = isolation_wait_exit(child, status, timeout_ms);
    if (out.reaped < 0) out.wait_error = errno;
    return out;
}
#endif
