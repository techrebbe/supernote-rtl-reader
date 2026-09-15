/* Unprivileged Linux/x86-64 HOST test of kernel BPF acceptance/behavior.
 * It translates ONLY syscall numbers and audit architecture in the actual
 * AArch64 diagnostic filter. It does not claim Nomad/kernel/namespace readiness.
 * No root, mount, chroot, firmware, network connection, or tablet access. */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "isolation_filter.h"
#include "isolation_supervisor.h"

#if !defined(__linux__) || !defined(__x86_64__)
#error This is an unprivileged Linux x86-64 host test, not an Android package.
#endif

static int translate(uint32_t arm) {
    switch (arm) {
        case 63: return __NR_read; case 64: return __NR_write;
        case 57: return __NR_close; case 56: return __NR_openat;
        case 80: return __NR_fstat; case 79: return __NR_newfstatat;
        case 62: return __NR_lseek; case 173: return __NR_getppid;
        case 174: return __NR_getuid; case 175: return __NR_geteuid;
        case 176: return __NR_getgid; case 177: return __NR_getegid;
        case 148: return __NR_getresuid; case 150: return __NR_getresgid;
        case 158: return __NR_getgroups; case 90: return __NR_capget;
        case 93: return __NR_exit; case 94: return __NR_exit_group;
        case 139: return __NR_rt_sigreturn; default: return -1;
    }
}

static int make_host_program(struct sock_filter *out) {
    _Static_assert(sizeof(struct isolation_instruction) == sizeof(struct sock_filter), "BPF layout");
    /* Fail on changed structure, rather than reinterpret a future filter. */
    if (ISOLATION_FILTER_COUNT != 50 || isolation_filter[1].code != 0x15 ||
        isolation_filter[1].k != ISO_ARCH || isolation_filter[4].code != 0x15 ||
        isolation_filter[4].k != 167 || isolation_filter[4].jf != 6 ||
        isolation_filter[10].code != 0x06 || isolation_filter[10].k != ISO_ALLOW ||
        isolation_filter[49].code != 0x06 || isolation_filter[49].k != ISO_DENY) return -1;
    memcpy(out, isolation_filter, sizeof(isolation_filter));
    out[1].k = AUDIT_ARCH_X86_64;
    out[4].k = __NR_prctl;
    for (unsigned at = 11; at < 49; at += 2) {
        if (out[at].code != 0x15 || out[at].jt != 0 || out[at].jf != 1 ||
            out[at + 1].code != 0x06 || out[at + 1].k != ISO_ALLOW) return -1;
        int host = translate(out[at].k);
        if (host < 0) return -1;
        out[at].k = (uint32_t)host;
    }
    return 0;
}

static int denied(long value) { return value == -1 && errno == EPERM; }

static void child_test(int report_fd, pid_t expected_parent, struct sock_filter *code,
        int hang_after_report, int deny_kill) {
    int report[3] = {0, 0, 0};
    if (isolation_arm_watchdog(deny_kill ? 1 : 5) ||
        prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != expected_parent ||
        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) goto done;
    struct sock_fprog program = {ISOLATION_FILTER_COUNT, code};
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program)) goto done;
    report[0] = 1;
    int death_signal = 0;
    if (prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1 ||
        prctl(PR_GET_SECCOMP, 0, 0, 0, 0) != SECCOMP_MODE_FILTER ||
        prctl(PR_GET_PDEATHSIG, &death_signal) || death_signal != SIGKILL ||
        getppid() != expected_parent) goto done;
    report[1] += 4;
    /* Positive tests use only /dev/null and the owned parent report pipe. */
    int fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (fd < 0) goto done;
    struct stat info;
    char byte;
    int file_ok = fstat(fd, &info) == 0 && S_ISCHR(info.st_mode) && read(fd, &byte, 1) == 0;
    if (close(fd) || !file_ok) goto done;
    report[1] += 4;
    /* Harmless calls even if the filter regresses: no socket connection, no
     * valid ioctl descriptor, no nonzero namespace flags or usable clone. */
    errno = 0;
    if (!denied(syscall(__NR_getpid))) goto done;
    ++report[1];
    errno = 0;
    int socket_fd = (int)syscall(__NR_socket, 1, 1, 0);
    int socket_denied = denied(socket_fd);
    if (socket_fd >= 0) close(socket_fd);
    if (!socket_denied) goto done;
    ++report[1];
    errno = 0;
    if (!denied(syscall(__NR_ioctl, -1, 0, 0))) goto done;
    ++report[1];
    errno = 0;
    if (!denied(syscall(__NR_unshare, 0))) goto done;
    ++report[1];
    errno = 0;
    if (!denied(syscall(__NR_prctl, PR_SET_NAME, "unexpected-filter-regression", 0, 0, 0))) goto done;
    ++report[1];
    errno = 0;
    if (!denied(syscall(__NR_mmap, NULL, 0, 0, 0, -1, 0))) goto done;
    ++report[1];
    report[2] = 1;
done:
    if (write(report_fd, report, sizeof(report)) != sizeof(report)) _exit(72);
    if (hang_after_report) for (;;) { /* Exercises the parent's exit deadline. */ }
    close(report_fd);
    _exit(report[2] ? 0 : 71);
}

static int deny_signal(pid_t child, int signal) {
    (void)child; (void)signal;
    errno = EPERM;
    return -1;
}

static int poll_readable_until(int fd, unsigned timeout_ms) {
    int64_t start = isolation_clock_ms();
    if (start < 0) return -1;
    for (;;) {
        int64_t now = isolation_clock_ms();
        if (now < start) return -1;
        uint64_t elapsed = (uint64_t)(now - start);
        if (elapsed >= timeout_ms) return 0;
        int remaining = (int)(timeout_ms - elapsed);
        struct pollfd ready = {fd, POLLIN, 0};
        int result = poll(&ready, 1, remaining);
        if (result >= 0) return result;
        if (errno != EINTR) return -1;
    }
}

static int run_kernel_case(int hang_after_report, int deny_kill) {
    struct sock_filter code[ISOLATION_FILTER_COUNT];
    if (make_host_program(code)) return 2;
    int channel[2];
    if (pipe2(channel, O_CLOEXEC | O_NONBLOCK)) return 2;
    pid_t parent = getpid(), child = fork();
    if (child == 0) {
        close(channel[0]);
        child_test(channel[1], parent, code, hang_after_report, deny_kill);
    }
    close(channel[1]);
    if (child < 0) { close(channel[0]); return 2; }
    int report[3] = {0}, status = 0;
    int readable = poll_readable_until(channel[0], 3000);
    ssize_t count = readable > 0 ? read(channel[0], report, sizeof(report)) : -1;
    int killed = 0, signal_error = 0;
    int wait_outcome = ISO_WAIT_SUPERVISOR_ERROR;
    /* Receiving a complete report must NOT remove the child-exit deadline. */
    if (count == sizeof(report))
        wait_outcome = isolation_wait_exit(child, &status, hang_after_report ? 200 : 3000);
    int reaped = wait_outcome == ISO_WAIT_TIMELY_EXIT || wait_outcome == ISO_WAIT_LATE_EXIT;
    if (!reaped) {
        struct isolation_reap_result stopped = isolation_stop_child(child, &status, 2000,
            deny_kill ? deny_signal : kill);
        killed = stopped.signal_sent;
        signal_error = stopped.signal_error;
        if (stopped.reaped != 1) {
            /* Fail boundedly even if the watchdog test itself regresses. */
            (void)isolation_stop_child(child, &status, 1000, kill);
            _exit(73);
        }
        reaped = 1;
    }
    size_t used = count > 0 ? (size_t)count : 0u;
    int wire_ok = readable > 0 && count >= 0 &&
        isolation_read_exact_eof(channel[0], report, sizeof(report), used) == 0;
    close(channel[0]);
    int exit_ok = deny_kill ? wait_outcome == ISO_WAIT_ELAPSED_TIMEOUT &&
        !killed && signal_error == EPERM &&
        WIFSIGNALED(status) && WTERMSIG(status) == SIGALRM :
        hang_after_report ? wait_outcome == ISO_WAIT_ELAPSED_TIMEOUT && killed &&
            WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL :
        wait_outcome == ISO_WAIT_TIMELY_EXIT && WIFEXITED(status) && WEXITSTATUS(status) == 0;
    if (!reaped || !wire_ok || !exit_ok ||
        report[0] != 1 || report[1] != 14 || report[2] != 1) {
        fprintf(stderr, "LINUX_FILTER FAIL installed=%d checks=%d completed=%d\n", report[0], report[1], report[2]);
        return 1;
    }
    return 0;
}

static int descriptor_count(void) {
    DIR *directory = opendir("/proc/self/fd");
    if (!directory) return -1;
    int count = 0;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (!entry) {
            if (errno) count = -1;
            break;
        }
        if (entry->d_name[0] >= '0' && entry->d_name[0] <= '9') ++count;
    }
    if (closedir(directory)) return -1;
    return count;
}

static unsigned unexpected_signal_calls;
static int count_unexpected_signal(pid_t child, int signal) {
    (void)child; (void)signal;
    ++unexpected_signal_calls;
    errno = EPERM;
    return -1;
}

struct scripted_wait {
    int64_t clocks[4];
    unsigned clock_at;
    pid_t wait_result;
    int wait_errno;
};

static int64_t scripted_clock(void *opaque) {
    struct scripted_wait *script = opaque;
    return script->clocks[script->clock_at++];
}

static pid_t scripted_wait_nohang(pid_t child, int *status, void *opaque) {
    struct scripted_wait *script = opaque;
    if (script->wait_result == child) *status = 0;
    errno = script->wait_errno;
    return script->wait_result;
}

static int scripted_pause(uint64_t milliseconds, void *opaque) {
    (void)milliseconds; (void)opaque;
    return 0;
}

static int test_reaper_ownership(void) {
    /* Model launch from a shell which ignored SIGCHLD / enabled auto-reaping. */
    struct sigaction inherited;
    memset(&inherited, 0, sizeof(inherited));
    inherited.sa_handler = SIG_IGN;
    inherited.sa_flags = SA_NOCLDWAIT;
    if (sigemptyset(&inherited.sa_mask) || sigaction(SIGCHLD, &inherited, NULL) ||
        isolation_prepare_parent()) return 1;
    pid_t child = fork();
    if (child == 0) _exit(0);
    if (child < 0) return 1;
    int status = 0;
    if (isolation_wait_exit(child, &status, 2000) != 1 ||
        !WIFEXITED(status) || WEXITSTATUS(status) != 0) return 1;
    /* That child is already reaped. Its numeric PID is no longer authority. */
    struct isolation_reap_result lost = isolation_stop_child(child, &status, 50, count_unexpected_signal);
    return lost.reaped == -1 && lost.wait_error == ECHILD &&
        !lost.signal_sent && unexpected_signal_calls == 0 ? 0 : 1;
}

static int test_timeout_provenance(void) {
    struct isolation_reap_result forced = {ISO_WAIT_TIMELY_EXIT, 1, 0, 0};
    struct isolation_reap_result late_exit = {ISO_WAIT_TIMELY_EXIT, 0, 0, 0};
    int killed_status = SIGKILL;
    int exited_status = 0;
    struct scripted_wait late = {{100, 109, 110, 110}, 0, 77, 0};
    struct scripted_wait error = {{100, 101, 101, 101}, 0, -1, EIO};
    struct isolation_wait_ops late_ops = {
        scripted_clock, scripted_wait_nohang, scripted_pause, &late};
    struct isolation_wait_ops error_ops = {
        scripted_clock, scripted_wait_nohang, scripted_pause, &error};
    int late_status = 0, error_status = 0;
    int late_result = isolation_wait_exit_with_ops(77, &late_status, 10, &late_ops);
    int error_result = isolation_wait_exit_with_ops(77, &error_status, 10, &error_ops);
    return isolation_confirmed_forced_timeout(ISO_WAIT_ELAPSED_TIMEOUT, forced, killed_status) &&
        !isolation_confirmed_forced_timeout(ISO_WAIT_SUPERVISOR_ERROR, forced, killed_status) &&
        !isolation_confirmed_forced_timeout(ISO_WAIT_TIMELY_EXIT, forced, killed_status) &&
        !isolation_confirmed_forced_timeout(ISO_WAIT_ELAPSED_TIMEOUT, late_exit, exited_status) &&
        isolation_observed_exit_outcome(100, 109, 10) == ISO_WAIT_TIMELY_EXIT &&
        isolation_observed_exit_outcome(100, 110, 10) == ISO_WAIT_LATE_EXIT &&
        isolation_observed_exit_outcome(100, 99, 10) == ISO_WAIT_SUPERVISOR_ERROR &&
        late_result == ISO_WAIT_LATE_EXIT && error_result == ISO_WAIT_SUPERVISOR_ERROR &&
        !isolation_confirmed_forced_timeout(late_result, forced, killed_status) &&
        !isolation_confirmed_forced_timeout(error_result, forced, killed_status) ? 0 : 1;
}

static int exact_wire_case(size_t payload_size, size_t expected_size, size_t pre_read) {
    unsigned char payload[32], received[16] = {0};
    if (payload_size > sizeof(payload) || expected_size > sizeof(received) ||
        pre_read > expected_size || pre_read > payload_size) return 1;
    for (size_t i = 0; i < sizeof(payload); ++i) payload[i] = (unsigned char)(i + 1u);
    int channel[2];
    if (pipe2(channel, O_CLOEXEC | O_NONBLOCK)) return 1;
    size_t written = 0;
    while (written < payload_size) {
        ssize_t count = write(channel[1], payload + written, payload_size - written);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { close(channel[0]); close(channel[1]); return 1; }
        written += (size_t)count;
    }
    close(channel[1]);
    size_t used = 0;
    while (used < pre_read) {
        ssize_t count = read(channel[0], received + used, pre_read - used);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { close(channel[0]); return 1; }
        used += (size_t)count;
    }
    int accepted = isolation_read_exact_eof(
        channel[0], received, expected_size, used) == 0;
    close(channel[0]);
    int should_accept = payload_size == expected_size;
    return accepted == should_accept &&
        (!accepted || memcmp(payload, received, expected_size) == 0) ? 0 : 1;
}

static int test_exact_wire_framing(void) {
    int retained[2];
    if (pipe2(retained, O_CLOEXEC | O_NONBLOCK)) return 1;
    const unsigned char complete[4] = {1, 2, 3, 4};
    if (write(retained[1], complete, sizeof(complete)) != (ssize_t)sizeof(complete)) {
        close(retained[0]); close(retained[1]); return 1;
    }
    unsigned char received[4] = {0};
    int framed = isolation_read_exact_eof(retained[0], received, sizeof(received), 0);
    int retained_rejected = framed != 0;
    close(retained[0]); close(retained[1]);
    return !retained_rejected || exact_wire_case(12, 12, 0) || exact_wire_case(12, 12, 5) ||
        exact_wire_case(11, 12, 0) || exact_wire_case(13, 12, 0) ||
        exact_wire_case(24, 12, 12) || exact_wire_case(1, 0, 0);
}

static void interrupt_wait(int signal) { (void)signal; }

static int test_interrupted_wait_uses_actual_deadline(void) {
    pid_t child = fork();
    if (child == 0) for (;;) pause();
    if (child < 0) return 1;
    struct sigaction action, old;
    struct itimerval timer = {{0, 1000}, {0, 1000}}, stopped_timer = {{0, 0}, {0, 0}};
    int old_valid = 0, timer_started = 0, status = 0, outcome = ISO_WAIT_SUPERVISOR_ERROR;
    int64_t start = -1, elapsed = -1;
    memset(&action, 0, sizeof(action));
    action.sa_handler = interrupt_wait;
    if (!sigemptyset(&action.sa_mask) && !sigaction(SIGALRM, &action, &old)) {
        old_valid = 1;
        start = isolation_clock_ms();
        if (start >= 0 && !setitimer(ITIMER_REAL, &timer, NULL)) {
            timer_started = 1;
            outcome = isolation_wait_exit(child, &status, 50);
            elapsed = isolation_clock_ms() - start;
        }
    }
    if (timer_started) (void)setitimer(ITIMER_REAL, &stopped_timer, NULL);
    if (old_valid) (void)sigaction(SIGALRM, &old, NULL);
    struct isolation_reap_result cleanup = isolation_stop_child(child, &status, 1000, kill);
    return outcome == ISO_WAIT_ELAPSED_TIMEOUT && elapsed >= 50 && elapsed < 500 &&
        cleanup.reaped == ISO_WAIT_TIMELY_EXIT ? 0 : 1;
}

int main(void) {
    if (test_timeout_provenance() || test_exact_wire_framing() ||
        test_reaper_ownership() || isolation_prepare_parent() ||
        test_interrupted_wait_uses_actual_deadline()) return 2;
    int before = descriptor_count();
    if (before < 0) return 2;
    for (unsigned run = 0; run < 100; ++run) {
        if (run_kernel_case(0, 0) || descriptor_count() != before) return 1;
    }
    if (run_kernel_case(1, 0) || descriptor_count() != before) return 1;
    if (run_kernel_case(1, 1) || descriptor_count() != before) return 1;
    puts("LINUX_FILTER PASS runs=102 checks=1428 descriptor_leaks=0 exact_wire=PASS exit_deadline=PASS denied_kill_watchdog=PASS reaper_ownership=PASS profile=x86_64-host-translation nomad_tested=false");
    return 0;
}
