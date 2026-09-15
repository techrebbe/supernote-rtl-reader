/* Build only until independent exact-source review has approved a device run.
 * This file DOES NOT load DrawPath or modify a real device/service. It proves
 * child-only mount/chroot/credential/syscall isolation using ordinary canaries. */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/magic.h>
#include <linux/seccomp.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "isolation_core.h"
#include "isolation_filter.h"
#include "isolation_supervisor.h"

#if !defined(__aarch64__)
#error This Linux implementation is pinned to Android AArch64; use the pure core test on hosts.
#endif

#define REPORT_MAGIC 0x56504953u
#define WORKER_UID 65534
#define TMP_PREFIX "/data/local/tmp/native-viewport-isolation-"

struct report {
    uint32_t magic;
    int completed, failed, error, pass;
};
struct context {
    pid_t parent;
    int report_fd, crash_after, timeout_after;
    const char *root;
    struct stat parent_namespace, original_root;
};

static int same_node(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
        a->st_rdev == b->st_rdev && a->st_mode == b->st_mode;
}

static int write_exact(int fd, const void *data, size_t length) {
    const unsigned char *at = data;
    while (length) {
        ssize_t count = write(fd, at, length);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return -1;
        at += count;
        length -= (size_t)count;
    }
    return 0;
}

static void finish_child(struct context *ctx, struct isolation_result result) {
    struct report report = {REPORT_MAGIC, (int)result.completed,
        result.failed_step, errno, result.mechanism_pass};
    int sent = write_exact(ctx->report_fd, &report, sizeof(report));
    close(ctx->report_fd);
    _exit(sent == 0 && result.mechanism_pass ? 0 : 70);
}

static int create_canary(const char *name, const char *value) {
    int fd = open(name, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return -1;
    int result = write_exact(fd, value, strlen(value));
    if (result == 0) result = fchmod(fd, 0666);
    if (close(fd) != 0) result = -1;
    return result;
}

static int close_inherited_except(int allowed) {
    DIR *directory = opendir("/proc/self/fd");
    if (!directory) return -1;
    int directory_fd = dirfd(directory), result = 0;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (!entry) {
            if (errno) result = -1;
            break;
        }
        char *end = NULL;
        long number = strtol(entry->d_name, &end, 10);
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        if (end == entry->d_name || *end || number < 0 || number > 1048576) { result = -1; break; }
        int fd = (int)number;
        if (fd != allowed && fd != directory_fd && close(fd) != 0) result = -1;
    }
    if (closedir(directory) != 0) result = -1;
    return result;
}

static int empty_capabilities(void) {
    struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct caps[2] = {{0}};
    if (syscall(__NR_capget, &header, caps) != 0) return -1;
    return caps[0].effective || caps[0].permitted || caps[0].inheritable ||
        caps[1].effective || caps[1].permitted || caps[1].inheritable ? -1 : 0;
}

static int parent_can_signal(void) {
    struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct caps[2] = {{0}};
    return syscall(__NR_capget, &header, caps) == 0 &&
        (caps[CAP_KILL / 32].effective & (1u << (CAP_KILL % 32))) ? 1 : 0;
}

/* Only enough syscalls for this diagnostic. NOT a native worker allowlist.
 * No socket, binder ioctl, mount, namespace entry, device creation, process/thread
 * creation, exec, ptrace, file-handle opens, process_vm, kill, or seccomp updates. */
static int restrict_syscalls(void) {
    _Static_assert(sizeof(struct isolation_instruction) == sizeof(struct sock_filter), "BPF layout");
    _Static_assert(offsetof(struct isolation_instruction, k) == offsetof(struct sock_filter, k), "BPF operand layout");
    _Static_assert(offsetof(struct seccomp_data, arch) == 4 && offsetof(struct seccomp_data, nr) == 0 &&
        offsetof(struct seccomp_data, args) == 16, "seccomp data ABI");
    _Static_assert(AUDIT_ARCH_AARCH64 == ISO_ARCH && SECCOMP_RET_ALLOW == ISO_ALLOW &&
        (SECCOMP_RET_ERRNO | EPERM) == ISO_DENY && SECCOMP_RET_KILL_PROCESS == ISO_KILL, "seccomp actions");
    _Static_assert(__NR_read == 63 && __NR_write == 64 && __NR_close == 57 && __NR_openat == 56 &&
        __NR_fstat == 80 && __NR_newfstatat == 79 && __NR_lseek == 62 && __NR_prctl == 167 &&
        __NR_getppid == 173 && __NR_getuid == 174 && __NR_geteuid == 175 && __NR_getgid == 176 && __NR_getegid == 177 &&
        __NR_getresuid == 148 && __NR_getresgid == 150 && __NR_getgroups == 158 && __NR_capget == 90 &&
        __NR_exit == 93 && __NR_exit_group == 94 && __NR_rt_sigreturn == 139 &&
        PR_GET_PDEATHSIG == 2 && PR_GET_NO_NEW_PRIVS == 39 && PR_GET_SECCOMP == 21, "pinned AArch64 syscall ABI");
    struct sock_filter code[ISOLATION_FILTER_COUNT];
    memcpy(code, isolation_filter, sizeof(code));
    struct sock_fprog filter = {(unsigned short)(sizeof(code) / sizeof(code[0])), code};
    return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &filter);
}

static int forbidden_paths_absent(void) {
    const char *paths[] = {"/proc/self/fd", "/dev/binder", "/dev/hwbinder",
        "/dev/vndbinder", "/dev/socket/property_service", "/dev/input/event0",
        "/storage", "/data", "/system", "/system_ext", "/sys"};
    for (unsigned i = 0; i < sizeof(paths) / sizeof(paths[0]); ++i) {
        errno = 0;
        int fd = open(paths[i], O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (fd >= 0) { close(fd); return -1; }
        if (errno != ENOENT) return -1;
    }
    return 0;
}

static int expect_filter_denial(long result) { return result == -1 && errno == EPERM ? 0 : -1; }

static int owned_io_only(void) {
    const char *paths[] = {"/dev/ebc", "/dev/input/event7"};
    const char expected[] = "private-canary";
    for (unsigned i = 0; i < 2; ++i) {
        int fd = open(paths[i], O_RDWR | O_CLOEXEC | O_NOFOLLOW);
        if (fd < 0) return -1;
        struct stat info;
        char data[sizeof(expected)] = {0};
        int result = fstat(fd, &info) == 0 && S_ISREG(info.st_mode) &&
            read(fd, data, sizeof(expected) - 1) == sizeof(expected) - 1 &&
            memcmp(data, expected, sizeof(expected)) == 0 ? 0 : -1;
        if (result == 0 && (lseek(fd, 0, SEEK_SET) != 0 || write_exact(fd, "P", 1))) result = -1;
        if (result == 0 && (lseek(fd, 0, SEEK_SET) != 0 || read(fd, data, 1) != 1 || data[0] != 'P')) result = -1;
        errno = 0;
        if (result == 0 && expect_filter_denial(syscall(__NR_ioctl, fd, 0, 0))) result = -1;
        if (close(fd)) result = -1;
        if (result) return -1;
    }
    errno = 0;
    if (expect_filter_denial(syscall(__NR_socket, 1, 1, 0))) return -1;
    errno = 0;
    if (expect_filter_denial(syscall(__NR_mount, NULL, NULL, NULL, 0, NULL))) return -1;
    errno = 0;
    if (expect_filter_denial(syscall(__NR_unshare, CLONE_NEWNS))) return -1;
    errno = 0;
    if (expect_filter_denial(syscall(__NR_setns, -1, CLONE_NEWNS))) return -1;
    errno = 0;
    if (expect_filter_denial(syscall(__NR_clone, 0, 0, 0, 0, 0))) return -1;
    return 0;
}

static int perform(void *opaque, enum isolation_step step) {
    struct context *ctx = opaque;
    struct stat info;
    struct statfs fs;
    int result = -1;
    switch (step) {
        case ISO_CHILD_IDENTITY:
            result = getpid() != ctx->parent && getppid() == ctx->parent && getuid() == 0 &&
                lstat(ctx->root, &info) == 0 && same_node(&info, &ctx->original_root) ? 0 : -1;
            break;
        case ISO_PARENT_LIFELINE:
            if (isolation_arm_watchdog(5) || prctl(PR_SET_PDEATHSIG, SIGKILL) != 0) break;
            result = getppid() == ctx->parent ? 0 : -1;
            break;
        case ISO_PRIVATE_NAMESPACE:
            if (unshare(CLONE_NEWNS) != 0 || stat("/proc/self/ns/mnt", &info) != 0) break;
            result = info.st_dev == ctx->parent_namespace.st_dev &&
                info.st_ino != ctx->parent_namespace.st_ino ? 0 : -1;
            break;
        case ISO_PRIVATE_PROPAGATION:
            result = mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL);
            break;
        case ISO_PRIVATE_ROOT:
            if (mount("tmpfs", ctx->root, "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC,
                    "size=1m,mode=0755") != 0 || statfs(ctx->root, &fs) != 0 ||
                lstat(ctx->root, &info) != 0) break;
            result = fs.f_type == TMPFS_MAGIC && S_ISDIR(info.st_mode) &&
                info.st_dev != ctx->original_root.st_dev ? 0 : -1;
            break;
        case ISO_SEED_FIXTURES:
            if (chdir(ctx->root) || mkdir("dev", 0755) || chmod("dev", 0755) ||
                mkdir("dev/input", 0755) || chmod("dev/input", 0755) ||
                create_canary("dev/ebc", "private-canary") ||
                create_canary("dev/input/event7", "private-canary")) break;
            result = 0;
            break;
        case ISO_CLOSE_INHERITED_FDS:
            result = close_inherited_except(ctx->report_fd);
            break;
        case ISO_CHROOT_AND_CWD:
            if (chroot(".") != 0 || chdir("/") != 0) break;
            result = forbidden_paths_absent();
            break;
        case ISO_DROP_PRIVILEGES: {
            struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0};
            struct __user_cap_data_struct caps[2] = {{0}};
            if (prctl(PR_SET_KEEPCAPS, 0) || setgroups(0, NULL) ||
                setresgid(WORKER_UID, WORKER_UID, WORKER_UID) ||
                setresuid(WORKER_UID, WORKER_UID, WORKER_UID) ||
                syscall(__NR_capset, &header, caps)) break;
            /* Credential changes clear PDEATHSIG. Re-arm before proceeding and
             * detect a supervisor lost in the credential-change window. */
            if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || getppid() != ctx->parent) break;
            result = empty_capabilities();
            break;
        }
        case ISO_NO_NEW_PRIVILEGES:
            result = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
            break;
        case ISO_SYSCALL_FILTER:
            result = restrict_syscalls();
            break;
        case ISO_VERIFY_BOUNDARY: {
            uid_t real, effective, saved;
            gid_t greal, geffective, gsaved;
            int death_signal = 0;
            if (getresuid(&real, &effective, &saved) || getresgid(&greal, &geffective, &gsaved)) break;
            result = real == WORKER_UID && effective == WORKER_UID && saved == WORKER_UID &&
                greal == WORKER_UID && geffective == WORKER_UID && gsaved == WORKER_UID &&
                getgroups(0, NULL) == 0 && empty_capabilities() == 0 &&
                getppid() == ctx->parent && prctl(PR_GET_PDEATHSIG, &death_signal) == 0 && death_signal == SIGKILL &&
                prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1 &&
                prctl(PR_GET_SECCOMP, 0, 0, 0, 0) == SECCOMP_MODE_FILTER &&
                forbidden_paths_absent() == 0 ? 0 : -1;
            break;
        }
        case ISO_OWNED_IO_ONLY: result = owned_io_only(); break;
        default: break;
    }
    if (result == 0 && (int)step == ctx->crash_after) _exit(71);
    if (result == 0 && (int)step == ctx->timeout_after) {
        struct report ready = {REPORT_MAGIC, (int)step + 1, -1, 0, 0};
        if (write_exact(ctx->report_fd, &ready, sizeof(ready))) return -1;
        for (;;) { /* Parent kills only this child after a reported admission. */ }
    }
    return result;
}

static int64_t now_ms(void) {
    return isolation_clock_ms();
}

static void stop_owned_child(pid_t child, int *status, int *killed, const char *root) {
    struct isolation_reap_result stopped = isolation_stop_child(child, status, 6000, kill);
    if (stopped.signal_sent) *killed = 1;
    if (stopped.reaped == 1) return;
    /* Do not proceed to more cases or delete a directory while ownership is
     * uncertain. Parent exit triggers PDEATHSIG; the child's own timer remains
     * armed. Preserve only this fresh path for later inspection. */
    fprintf(stderr, "ISOLATION_CLEANUP_UNCERTAIN signal_errno=%d wait_errno=%d preserve=%s\n",
        stopped.signal_error, stopped.wait_error, root);
    fflush(stderr);
    _exit(74);
}

static int run_case(int crash, int timeout) {
    char root[] = TMP_PREFIX "XXXXXX";
    struct stat before_ebc, before_pen, before_ns, root_info, after;
    if (geteuid() != 0 || !parent_can_signal() || lstat("/dev/ebc", &before_ebc) ||
        lstat("/dev/input/event7", &before_pen) || !S_ISCHR(before_ebc.st_mode) ||
        !S_ISCHR(before_pen.st_mode) || stat("/proc/self/ns/mnt", &before_ns)) return -1;
    if (!mkdtemp(root)) return -1;
    int result = -1, pipe_fds[2] = {-1, -1};
    pid_t child = -1;
    if (lstat(root, &root_info) || !S_ISDIR(root_info.st_mode) || root_info.st_uid != 0 ||
        pipe2(pipe_fds, O_CLOEXEC | O_NONBLOCK)) goto done;
    struct context context = {getpid(), pipe_fds[1], crash, timeout, root, before_ns, root_info};
    child = fork();
    if (child == 0) {
        struct isolation_ops ops = {&context, perform};
        finish_child(&context, isolation_prove(&ops));
    }
    if (child < 0) goto done;
    close(pipe_fds[1]); pipe_fds[1] = -1;
    struct report report = {0};
    size_t used = 0;
    int status = 0, killed = 0;
    int wait_outcome = ISO_WAIT_SUPERVISOR_ERROR;
    int64_t start = now_ms();
    if (start < 0) goto reap;
    int64_t deadline = start + (timeout >= 0 ? 2500 : 10000);
    for (;;) {
        int64_t before = now_ms();
        if (before < start) { wait_outcome = ISO_WAIT_SUPERVISOR_ERROR; break; }
        if (before >= deadline) {
            wait_outcome = ISO_WAIT_ELAPSED_TIMEOUT;
            if (kill(child, SIGKILL) == 0) killed = 1;
            break;
        }
        ssize_t count = read(pipe_fds[0], (char *)&report + used, sizeof(report) - used);
        if (count > 0) used += (size_t)count;
        else if (count < 0 && errno != EAGAIN && errno != EINTR) break;
        pid_t ended = waitpid(child, &status, WNOHANG);
        if (ended < 0 && errno != EINTR) { wait_outcome = ISO_WAIT_SUPERVISOR_ERROR; break; }
        int64_t clock = now_ms();
        if (clock < before) { wait_outcome = ISO_WAIT_SUPERVISOR_ERROR; break; }
        if (ended == child) {
            wait_outcome = clock < deadline ? ISO_WAIT_TIMELY_EXIT : ISO_WAIT_LATE_EXIT;
            break;
        }
        if (clock >= deadline) {
            wait_outcome = ISO_WAIT_ELAPSED_TIMEOUT;
            if (kill(child, SIGKILL) == 0) killed = 1;
            break;
        }
        struct pollfd pfd = {pipe_fds[0], POLLIN, 0};
        int remaining = (int)(deadline - clock);
        int polled = poll(&pfd, 1, remaining < 10 ? remaining : 10);
        if (polled < 0 && errno != EINTR) { wait_outcome = ISO_WAIT_SUPERVISOR_ERROR; break; }
    }
reap:
    if (wait_outcome == ISO_WAIT_ELAPSED_TIMEOUT || wait_outcome == ISO_WAIT_SUPERVISOR_ERROR) {
        /* Covers parent-side failure without leaving a root child behind. */
        stop_owned_child(child, &status, &killed, root);
    }
    child = -1;
    size_t expected_wire = crash >= 0 ? 0u : sizeof(report);
    int wire_ok = isolation_read_exact_eof(
        pipe_fds[0], &report, expected_wire, used) == 0;
    if (crash >= 0) result = wait_outcome == ISO_WAIT_TIMELY_EXIT &&
        wire_ok && WIFEXITED(status) && WEXITSTATUS(status) == 71 ? 0 : -1;
    else if (timeout >= 0) result = wait_outcome == ISO_WAIT_ELAPSED_TIMEOUT && killed &&
        WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL &&
        wire_ok && report.magic == REPORT_MAGIC && report.completed == timeout + 1 &&
        report.failed == -1 && report.error == 0 && report.pass == 0 ? 0 : -1;
    else result = wait_outcome == ISO_WAIT_TIMELY_EXIT && WIFEXITED(status) &&
        WEXITSTATUS(status) == 0 && wire_ok &&
        report.magic == REPORT_MAGIC && report.completed == ISO_COUNT && report.failed == -1 && report.pass == 1 ? 0 : -1;
    if (result && wire_ok && expected_wire == sizeof(report) && report.magic == REPORT_MAGIC)
        fprintf(stderr, "ISOLATION_REJECTED step=%d completed=%d errno=%d\n", report.failed, report.completed, report.error);
    /* Verify the parent still sees its ORIGINAL namespace, root, and hardware
     * identities. No real device node has ever been opened by this executable. */
    if (stat("/proc/self/ns/mnt", &after) || !same_node(&before_ns, &after) ||
        lstat(root, &after) || !same_node(&root_info, &after) ||
        lstat("/dev/ebc", &after) || !same_node(&before_ebc, &after) ||
        lstat("/dev/input/event7", &after) || !same_node(&before_pen, &after)) result = -1;
    printf("ISOLATION_CASE crash=%d timeout=%d result=%s native_start_allowed=false\n",
        crash, timeout, result ? "FAIL" : "PASS");
done:
    if (child > 0) {
        int cleanup_status = 0, cleanup_killed = 0;
        stop_owned_child(child, &cleanup_status, &cleanup_killed, root);
    }
    if (pipe_fds[0] >= 0) close(pipe_fds[0]);
    if (pipe_fds[1] >= 0) close(pipe_fds[1]);
    /* Exact fresh empty directory only. Never recursive-delete a computed path. */
    if (rmdir(root) != 0) { fprintf(stderr, "Preserve for inspection: %s\n", root); result = -1; }
    return result;
}

int main(int argc, char **argv) {
    if (argc != 2 || strcmp(argv[1], "--prove-isolation")) {
        fputs("Use --prove-isolation after exact-source review. No firmware startup.\n", stderr);
        return 2;
    }
    if (isolation_prepare_parent()) return 2;
    if (run_case(-1, -1) || run_case(ISO_PRIVATE_ROOT, -1) ||
        run_case(ISO_CHROOT_AND_CWD, -1) || run_case(ISO_SYSCALL_FILTER, -1) ||
        run_case(-1, ISO_SYSCALL_FILTER)) return 1;
    puts("ISOLATION_MECHANISM PASS native_start_allowed=false firmware_loaded=false");
    return 0;
}
