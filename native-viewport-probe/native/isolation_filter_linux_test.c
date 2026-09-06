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
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "isolation_filter.h"

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

static void child_test(int report_fd, pid_t expected_parent, struct sock_filter *code, int hang_after_report) {
    int report[3] = {0, 0, 0};
    if (prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != expected_parent ||
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

static int run_kernel_case(int hang_after_report) {
    struct sock_filter code[ISOLATION_FILTER_COUNT];
    if (make_host_program(code)) return 2;
    int channel[2];
    if (pipe2(channel, O_CLOEXEC)) return 2;
    pid_t parent = getpid(), child = fork();
    if (child == 0) {
        close(channel[0]);
        child_test(channel[1], parent, code, hang_after_report);
    }
    close(channel[1]);
    if (child < 0) { close(channel[0]); return 2; }
    int report[3] = {0}, status = 0;
    struct pollfd ready = {channel[0], POLLIN, 0};
    int readable;
    do { readable = poll(&ready, 1, 3000); } while (readable < 0 && errno == EINTR);
    ssize_t count = readable > 0 ? read(channel[0], report, sizeof(report)) : -1;
    close(channel[0]);
    int killed = 0;
    pid_t ended = 0;
    /* Receiving a complete report must NOT remove the child-exit deadline. */
    unsigned attempts = hang_after_report ? 20 : 300;
    while (count == sizeof(report) && attempts--) {
        ended = waitpid(child, &status, WNOHANG);
        if (ended == child || (ended < 0 && errno != EINTR)) break;
        const struct timespec pause = {0, 10000000};
        (void)nanosleep(&pause, NULL);
    }
    if (ended != child) {
        killed = kill(child, SIGKILL) == 0;
        do { ended = waitpid(child, &status, 0); } while (ended < 0 && errno == EINTR);
    }
    int exit_ok = hang_after_report ? killed && WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL :
        WIFEXITED(status) && WEXITSTATUS(status) == 0;
    if (ended != child || count != sizeof(report) || !exit_ok ||
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

int main(void) {
    int before = descriptor_count();
    if (before < 0) return 2;
    for (unsigned run = 0; run < 100; ++run) {
        if (run_kernel_case(0) || descriptor_count() != before) return 1;
    }
    if (run_kernel_case(1) || descriptor_count() != before) return 1;
    puts("LINUX_FILTER PASS runs=101 checks=1414 descriptor_leaks=0 exit_deadline=PASS profile=x86_64-host-translation nomad_tested=false");
    return 0;
}
