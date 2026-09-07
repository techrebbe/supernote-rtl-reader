#ifndef VIEWPORT_ISOLATION_SUPERVISOR_H
#define VIEWPORT_ISOLATION_SUPERVISOR_H

/* Linux/Android diagnostic supervisor, shared with the actual kernel tests.
 * Never use an unbounded waitpid, including after a failed signal. */
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

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

/* 1 = exact child reaped, 0 = deadline, -1 = clock/wait error.
 * A finite poll budget also prevents repeated EINTR from removing the bound. */
static inline int isolation_wait_exit(pid_t child, int *status, unsigned timeout_ms) {
    int64_t start = isolation_clock_ms();
    if (child <= 0 || !status || start < 0 || timeout_ms > 10000) return -1;
    unsigned polls = timeout_ms / 10 + 2;
    while (polls--) {
        pid_t ended = waitpid(child, status, WNOHANG);
        if (ended == child) return 1;
        if (ended < 0 && errno != EINTR) return -1;
        int64_t now = isolation_clock_ms();
        if (now < start) return -1;
        if (now - start >= timeout_ms) return 0;
        const struct timespec pause = {0, 10000000};
        (void)nanosleep(&pause, NULL);
    }
    return 0;
}

struct isolation_reap_result {
    int reaped;
    int signal_sent;
    int signal_error;
    int wait_error;
};

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
