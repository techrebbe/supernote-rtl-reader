/* S4 device broker. Standalone, no dependency on or edits to the frozen lease.
 * Caller is the authenticated stage observer: absence-proof hashes are opaque
 * capabilities, not independently established UI absence. Caller authenticates
 * this broker and excludes peer/worker/guardian from ALL generic cleanup.
 * Never signal either holder. Any unknown outcome retains this process and its
 * FDs indefinitely. Only authenticated RELEASED + drained status EOF + exact
 * child/guardian closure permits a normal exit; the caller then reaps the peer.
 */
#define _GNU_SOURCE 1
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define PEER_BYTES 2048
#define PEER_CLOCK "android-boottime-v1"
#define PIPEFS_MAGIC_VALUE 0x50495045
#define MAX_IMAGE (UINT64_C(64) * 1024 * 1024)
enum peer_state {
    PEER_NEW,
    PEER_ACQUIRED,
    PEER_CAPTURED,
    PEER_FINISHING,
    PEER_RELEASED,
    PEER_QUARANTINED
};
struct process_id {
    pid_t pid;
    uint64_t start;
};
struct peer;
struct peer_ops {
    int (*now)(void *, uint64_t *);
    int (*identity)(void *, struct process_id, pid_t, int);
    int (*record)(void *, int, char *, size_t, uint64_t);
    int (*write_record)(void *, int, const char *);
    int (*close_fd)(void *, int);
    int (*empty)(void *, int, int);
    int (*closure)(void *, struct peer *, uint64_t);
    int (*prepare_publication)(void *, int, size_t);
    int (*publish)(void *, int, const char *, size_t);
};
struct peer {
    enum peer_state state;
    char token[65], stage[65], guardian_session[65], authority_hash[65];
    uint64_t hold_ms, deadline, last_now, sequence;
    struct process_id self, owner, worker, guardian;
    int authority, executable, control, phase, status;
    const struct peer_ops *ops;
    void *opaque;
};

/* SHA-256 authenticates copied executable/authority bytes before sealing memfd.
 * The reviewed caller supplies the expected digests. No hash learns authority. */
struct hash256 {
    uint32_t h[8];
    uint64_t bytes;
    unsigned used;
    unsigned char block[64];
};
static uint32_t ror(uint32_t n, unsigned b) {
    return (n >> b) | (n << (32 - b));
}
static void hash_block(struct hash256 *s, const unsigned char *p) {
    static const uint32_t k[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2};
    uint32_t w[64], a, b, c, d, e, f, g, h;
    for (unsigned i = 0; i < 16; i++)
        w[i] = ((uint32_t)p[4 * i] << 24) | ((uint32_t)p[4 * i + 1] << 16) |
               ((uint32_t)p[4 * i + 2] << 8) | p[4 * i + 3];
    for (unsigned i = 16; i < 64; i++) {
        uint32_t x = w[i - 15], y = w[i - 2];
        w[i] = w[i - 16] + (ror(x, 7) ^ ror(x, 18) ^ (x >> 3)) + w[i - 7] +
               (ror(y, 17) ^ ror(y, 19) ^ (y >> 10));
    }
    a = s->h[0];
    b = s->h[1];
    c = s->h[2];
    d = s->h[3];
    e = s->h[4];
    f = s->h[5];
    g = s->h[6];
    h = s->h[7];
    for (unsigned i = 0; i < 64; i++) {
        uint32_t t = h + (ror(e, 6) ^ ror(e, 11) ^ ror(e, 25)) + ((e & f) ^ (~e & g)) + k[i] + w[i];
        uint32_t u = (ror(a, 2) ^ ror(a, 13) ^ ror(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        h = g;
        g = f;
        f = e;
        e = d + t;
        d = c;
        c = b;
        b = a;
        a = t + u;
    }
    s->h[0] += a;
    s->h[1] += b;
    s->h[2] += c;
    s->h[3] += d;
    s->h[4] += e;
    s->h[5] += f;
    s->h[6] += g;
    s->h[7] += h;
}
static void hash_init(struct hash256 *s) {
    *s = (struct hash256){{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
                           0x1f83d9ab, 0x5be0cd19},
                          0,
                          0,
                          {0}};
}
static void hash_add(struct hash256 *s, const unsigned char *p, size_t n) {
    s->bytes += n;
    while (n--) {
        s->block[s->used++] = *p++;
        if (s->used == 64) {
            hash_block(s, s->block);
            s->used = 0;
        }
    }
}
static void hash_end(struct hash256 *s, char out[65]) {
    static const char hex[] = "0123456789abcdef";
    uint64_t bits = s->bytes * 8;
    s->block[s->used++] = 128;
    if (s->used > 56) {
        memset(s->block + s->used, 0, 64 - s->used);
        hash_block(s, s->block);
        s->used = 0;
    }
    memset(s->block + s->used, 0, 56 - s->used);
    for (unsigned i = 0; i < 8; i++)
        s->block[63 - i] = (unsigned char)(bits >> (8 * i));
    hash_block(s, s->block);
    for (unsigned i = 0; i < 32; i++) {
        unsigned v = (s->h[i / 4] >> (24 - 8 * (i % 4))) & 255;
        out[2 * i] = hex[v >> 4];
        out[2 * i + 1] = hex[v & 15];
    }
    out[64] = 0;
}

static int hex64(const char *s) {
    if (s == NULL || strlen(s) != 64)
        return 0;
    for (unsigned i = 0; i < 64; i++)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')))
            return 0;
    return 1;
}
static int number(const char *s, uint64_t *out) {
    uint64_t n = 0;
    if (s == NULL || *s < '1' || *s > '9')
        return -1;
    for (; *s; s++) {
        if (*s < '0' || *s > '9' || n > (UINT64_MAX - (unsigned)(*s - '0')) / 10)
            return -1;
        n = n * 10 + (unsigned)(*s - '0');
    }
    *out = n;
    return 0;
}
static int real_now(void *unused, uint64_t *out) {
    struct timespec t;
    (void)unused;
    if (clock_gettime(CLOCK_BOOTTIME, &t) != 0 || t.tv_sec < 0 ||
        (uint64_t)t.tv_sec > UINT64_MAX / 1000)
        return -1;
    *out = (uint64_t)t.tv_sec * 1000 + (uint64_t)t.tv_nsec / 1000000;
    return 0;
}
static int fresh_now(struct peer *p, uint64_t *out) {
    if (p->ops->now(p->opaque, out) != 0 || *out == 0 || *out < p->last_now)
        return -1;
    p->last_now = *out;
    return 0;
}
static int snapshot(pid_t pid, uint64_t *start, pid_t *parent, char *state) {
    char path[64], buf[4096], *at, *end;
    int fd;
    ssize_t n;
    if (pid <= 1 || snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid) <= 0)
        return -1;
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return -1;
    n = read(fd, buf, sizeof(buf) - 1);
    int saved = errno;
    (void)close(fd);
    errno = saved;
    if (n <= 0 || (size_t)n >= sizeof(buf) - 1)
        return -1;
    buf[n] = 0;
    at = strrchr(buf, ')');
    if (at == NULL || at[1] != ' ' || at[2] == 0 || at[3] != ' ')
        return -1;
    *state = at[2];
    at += 4;
    errno = 0;
    long pp = strtol(at, &end, 10);
    if (errno || end == at || *end != ' ' || pp < 0 || pp > INT_MAX)
        return -1;
    *parent = (pid_t)pp;
    at = end + 1;
    for (unsigned field = 5; field < 22; field++) {
        at = strchr(at, ' ');
        if (at == NULL)
            return -1;
        at++;
    }
    end = strchr(at, ' ');
    if (end == NULL)
        return -1;
    *end = 0;
    return number(at, start);
}
static int real_identity(void *unused, struct process_id id, pid_t parent, int gone) {
    uint64_t start;
    pid_t pp;
    char state;
    (void)unused;
    if (snapshot(id.pid, &start, &pp, &state) != 0)
        return gone && errno == ENOENT ? 0 : -1;
    if (gone)
        return start != id.start ? 0 : -1;
    return start == id.start && (parent == 0 || pp == parent) && state != 'Z' && state != 'X' &&
                   state != 'T' && state != 't'
               ? 0
               : -1;
}
static int pipe_identity(int fd, int mode, struct stat *st) {
    struct statfs fs;
    int flags = fcntl(fd, F_GETFL);
    return fd >= 0 && flags >= 0 && (flags & O_ACCMODE) == mode && (flags & O_NONBLOCK) &&
                   fstat(fd, st) == 0 && S_ISFIFO(st->st_mode) && fstatfs(fd, &fs) == 0 &&
                   (unsigned long)fs.f_type == PIPEFS_MAGIC_VALUE
               ? 0
               : -1;
}
static int same_fd(struct stat a, struct stat b) {
    return a.st_dev == b.st_dev && a.st_ino == b.st_ino;
}
static int validate_contract(int authority, int control, int phase, int status) {
    struct stat a, c, p, s;
    int flags = fcntl(authority, F_GETFL);
    if (authority < 3 || control < 3 || phase < 3 || status < 3 || authority == control ||
        authority == phase || authority == status || control == phase || control == status ||
        phase == status || flags < 0 || (flags & O_ACCMODE) != O_RDONLY ||
        fstat(authority, &a) != 0 || !S_ISREG(a.st_mode) || a.st_size < 1 || a.st_size >= 512 ||
        pipe_identity(control, O_WRONLY, &c) || pipe_identity(phase, O_WRONLY, &p) ||
        pipe_identity(status, O_RDONLY, &s) || same_fd(c, p) || same_fd(c, s) || same_fd(p, s))
        return -1;
    return 0;
}
static int real_empty(void *unused, int fd, int mode) {
    struct stat st;
    struct pollfd p = {fd, mode == O_WRONLY ? POLLOUT : 0, 0};
    int n;
    (void)unused;
    if (pipe_identity(fd, mode, &st) || ioctl(fd, FIONREAD, &n) || n != 0 || poll(&p, 1, 0) < 0 ||
        (p.revents & (POLLHUP | POLLERR | POLLNVAL)))
        return -1;
    return 0;
}
static int output_alive(int fd) {
    struct stat st;
    struct pollfd p = {fd, 0, 0};
    return pipe_identity(fd, O_WRONLY, &st) || poll(&p, 1, 0) < 0 ||
                   (p.revents & (POLLHUP | POLLERR | POLLNVAL))
               ? -1
               : 0;
}
static int real_write(void *unused, int fd, const char *line) {
    struct pollfd p = {fd, POLLOUT, 0};
    size_t n = strlen(line);
    long cap = fpathconf(fd, _PC_PIPE_BUF);
    (void)unused;
    if (n == 0 || cap < 0 || n > (size_t)cap || poll(&p, 1, 0) != 1 ||
        (p.revents & (POLLERR | POLLHUP | POLLNVAL)) || !(p.revents & POLLOUT))
        return -1;
    return write(fd, line, n) == (ssize_t)n ? 0 : -1;
}
static int real_prepare_publication(void *unused, int fd, size_t maximum) {
    struct stat identity;
    struct pollfd endpoint = {fd, POLLOUT, 0};
    long capacity = fpathconf(fd, _PC_PIPE_BUF);
    (void)unused;
    return capacity < 0 || maximum > (size_t)capacity || pipe_identity(fd, O_WRONLY, &identity) ||
                   poll(&endpoint, 1, 0) != 1 ||
                   (endpoint.revents & (POLLHUP | POLLERR | POLLNVAL)) ||
                   !(endpoint.revents & POLLOUT)
               ? -1
               : 0;
}
static int real_publish(void *unused, int fd, const char *line, size_t length) {
    (void)unused;
    /* No metadata/channel/identity operation is allowed after the final clock sample. */
    return write(fd, line, length) == (ssize_t)length ? 0 : -1;
}
static int real_close(void *unused, int fd) {
    (void)unused;
    return close(fd);
}
static int real_record(void *unused, int fd, char *line, size_t cap, uint64_t deadline) {
    (void)unused;
    for (;;) {
        uint64_t now;
        struct pollfd p = {fd, POLLIN | POLLHUP, 0};
        int n;
        ssize_t got;
        if (real_now(NULL, &now) || now >= deadline || poll(&p, 1, 10) < 0 ||
            (p.revents & (POLLERR | POLLNVAL)))
            return -1;
        if (ioctl(fd, FIONREAD, &n) || n < 0 || (size_t)n >= cap)
            return -1;
        if (n == 0) {
            if (p.revents & POLLHUP)
                return -1;
            continue;
        }
        got = read(fd, line, (size_t)n);
        if (got != n)
            return -1;
        line[n] = 0;
        if (line[n - 1] != '\n' || memchr(line, 0, (size_t)n) || memchr(line, '\r', (size_t)n) ||
            memchr(line, '\n', (size_t)n - 1))
            return -1;
        if (ioctl(fd, FIONREAD, &n) || n != 0)
            return -1;
        return 0;
    }
}
static int owners_live(struct peer *p) {
    return p->ops->identity(p->opaque, p->self, 0, 0) ||
                   p->ops->identity(p->opaque, p->owner, 0, 0) ||
                   p->ops->identity(p->opaque, p->worker, p->self.pid, 0) ||
                   p->ops->identity(p->opaque, p->guardian, p->worker.pid, 0)
               ? -1
               : 0;
}
static int quarantine(struct peer *p) {
    p->state = PEER_QUARANTINED;
    return -1;
}
static int status_ready(struct peer *p, const char *line) {
    char token[65], session[65], canonical[512];
    unsigned long long hold, deadline, start;
    long pid;
    int used = 0;
    if (sscanf(line,
               "PEN_INPUT_LEASE_READY token=%64s device=/dev/input/event7 held=true "
               "timeout_ms=%llu deviceClockDomain=" PEER_CLOCK
               " deadline_boottime_ms=%llu guardian_pid=%ld guardian_starttime=%llu "
               "guardian_session=%64s\n%n",
               token, &hold, &deadline, &pid, &start, session, &used) != 6 ||
        used != (int)strlen(line) || !hex64(session) || pid <= 1 || pid > INT_MAX || start == 0 ||
        strcmp(token, p->token) || hold != p->hold_ms)
        return -1;
    int length = snprintf(
        canonical, sizeof(canonical),
        "PEN_INPUT_LEASE_READY token=%s device=/dev/input/event7 held=true timeout_ms=%llu "
        "deviceClockDomain=" PEER_CLOCK
        " deadline_boottime_ms=%llu guardian_pid=%ld guardian_starttime=%llu guardian_session=%s\n",
        p->token, hold, deadline, pid, start, session);
    if (length <= 0 || (size_t)length >= sizeof(canonical) || strcmp(line, canonical) ||
        pid == p->worker.pid || pid == p->self.pid)
        return -1;
    p->guardian = (struct process_id){(pid_t)pid, (uint64_t)start};
    memcpy(p->guardian_session, session, 65);
    p->deadline = (uint64_t)deadline;
    uint64_t now;
    if (fresh_now(p, &now) || now >= p->deadline || p->deadline - now > p->hold_ms ||
        p->deadline > UINT64_MAX - 1000 || owners_live(p))
        return -1;
    return 0;
}
static int peer_acquired(struct peer *p) {
    char line[512];
    uint64_t now;
    if (p->state != PEER_NEW || fresh_now(p, &now) || now > UINT64_MAX - p->hold_ms ||
        p->ops->record(p->opaque, p->status, line, sizeof(line), now + p->hold_ms) ||
        status_ready(p, line) || p->ops->empty(p->opaque, p->control, O_WRONLY) ||
        p->ops->empty(p->opaque, p->phase, O_WRONLY) ||
        p->ops->empty(p->opaque, p->status, O_RDONLY))
        return quarantine(p);
    p->state = PEER_ACQUIRED;
    p->sequence = 1;
    return 0;
}
static int peer_capture(struct peer *p, uint64_t seq) {
    uint64_t now;
    if ((p->state != PEER_ACQUIRED && p->state != PEER_CAPTURED) || p->sequence == UINT64_MAX ||
        seq != p->sequence + 1 || fresh_now(p, &now) || now >= p->deadline || owners_live(p) ||
        p->ops->empty(p->opaque, p->control, O_WRONLY) ||
        p->ops->empty(p->opaque, p->phase, O_WRONLY) ||
        p->ops->empty(p->opaque, p->status, O_RDONLY))
        return quarantine(p);
    p->state = PEER_CAPTURED;
    p->sequence = seq;
    return 0;
}
static int real_closure(void *unused, struct peer *p, uint64_t deadline) {
    int reaped = 0, eof = 0;
    (void)unused;
    for (;;) {
        uint64_t now;
        int status;
        char byte;
        struct pollfd endpoint = {p->status, POLLIN | POLLHUP, 0};
        if (real_now(NULL, &now) || now >= deadline || poll(&endpoint, 1, 10) < 0 ||
            (endpoint.revents & (POLLERR | POLLNVAL)))
            return -1;
        if (endpoint.revents & POLLIN)
            return -1; /* Any trailing/replayed terminal is invalid. */
        if (endpoint.revents & POLLHUP) {
            if (read(p->status, &byte, 1) != 0)
                return -1;
            eof = 1;
        }
        if (!reaped) {
            pid_t result = waitpid(p->worker.pid, &status, WNOHANG);
            if (result < 0)
                return -1;
            if (result == p->worker.pid) {
                if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
                    return -1;
                reaped = 1;
            }
        }
        if (reaped && eof && real_identity(NULL, p->guardian, 0, 1) == 0)
            return 0;
    }
}
static int peer_finish(struct peer *p, uint64_t seq) {
    char phase[512], release[512], expected[512], actual[512];
    uint64_t now;
    if (p->state != PEER_CAPTURED || p->sequence == UINT64_MAX || seq != p->sequence + 1 ||
        fresh_now(p, &now) || now >= p->deadline || owners_live(p) ||
        p->ops->empty(p->opaque, p->control, O_WRONLY) ||
        p->ops->empty(p->opaque, p->phase, O_WRONLY) ||
        p->ops->empty(p->opaque, p->status, O_RDONLY))
        return quarantine(p);
    int a = snprintf(
        phase, sizeof(phase),
        "PHASE DESTROYED FINAL %s guardian_pid=%ld guardian_starttime=%llu guardian_session=%s\n",
        p->token, (long)p->guardian.pid, (unsigned long long)p->guardian.start,
        p->guardian_session);
    int b = snprintf(release, sizeof(release),
                     "RELEASE %s guardian_pid=%ld guardian_starttime=%llu guardian_session=%s\n",
                     p->token, (long)p->guardian.pid, (unsigned long long)p->guardian.start,
                     p->guardian_session);
    int c = snprintf(expected, sizeof(expected),
                     "PEN_INPUT_LEASE_RELEASED token=%s reason=control_release held=false "
                     "safe_idle_handoff=true "
                     "guardian_pid=%ld guardian_starttime=%llu guardian_session=%s\n",
                     p->token, (long)p->guardian.pid, (unsigned long long)p->guardian.start,
                     p->guardian_session);
    if (a <= 0 || b <= 0 || c <= 0 || (size_t)a >= sizeof(phase) || (size_t)b >= sizeof(release) ||
        (size_t)c >= sizeof(expected))
        return quarantine(p);
    p->state = PEER_FINISHING;
    /* Exclusive nonleaked writers. Both complete atomic records precede close.
     * Closing here is REQUIRED by the frozen public protocol, not cleanup.
     * Retain status + process ownership through authenticated release/closure. */
    if (p->ops->write_record(p->opaque, p->phase, phase) ||
        p->ops->write_record(p->opaque, p->control, release))
        return quarantine(p);
    int phase_fd = p->phase;
    p->phase = -1;
    if (p->ops->close_fd(p->opaque, phase_fd))
        return quarantine(p);
    int control_fd = p->control;
    p->control = -1;
    if (p->ops->close_fd(p->opaque, control_fd))
        return quarantine(p);
    if (p->ops->record(p->opaque, p->status, actual, sizeof(actual), p->deadline + 1000) ||
        strcmp(actual, expected) || p->ops->closure(p->opaque, p, p->deadline + 1000) ||
        fresh_now(p, &now) || now > p->deadline + 1000)
        return quarantine(p);
    p->state = PEER_RELEASED;
    p->sequence = seq;
    return 0;
}
static const struct peer_ops system_ops = {
    real_now,    real_identity, real_record,  real_write,
    real_close,  real_empty,    real_closure, real_prepare_publication,
    real_publish};

static int sealed_copy(const char *path, const char *expected, uint64_t limit, int executable) {
    int source = -1, copy = -1, result = -1, readonly = -1;
    struct stat st;
    struct hash256 hash;
    char digest[65], reopen[64];
    unsigned char bytes[8192];
    uint64_t total = 0;
    if (path == NULL || path[0] != '/' || !hex64(expected))
        return -1;
    source = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (source < 0 || fstat(source, &st) || !S_ISREG(st.st_mode) || st.st_size < 1 ||
        (uint64_t)st.st_size > limit)
        goto done;
    copy = memfd_create(executable ? "pen-lease-image" : "pen-authority",
                        MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (copy < 0)
        goto done;
    hash_init(&hash);
    for (;;) {
        ssize_t n = read(source, bytes, sizeof(bytes));
        if (n < 0)
            goto done;
        if (n == 0)
            break;
        if (total + (uint64_t)n > limit)
            goto done;
        total += (uint64_t)n;
        hash_add(&hash, bytes, (size_t)n);
        if (write(copy, bytes, (size_t)n) != n)
            goto done;
    }
    hash_end(&hash, digest);
    if (strcmp(digest, expected) || total != (uint64_t)st.st_size ||
        fchmod(copy, executable ? 0500 : 0400) ||
        fcntl(copy, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL))
        goto done;
    if (snprintf(reopen, sizeof(reopen), "/proc/self/fd/%d", copy) <= 0)
        goto done;
    readonly = open(reopen, O_RDONLY | O_CLOEXEC);
    if (readonly < 0)
        goto done;
    result = readonly;
    readonly = -1;
done:
    if (source >= 0)
        (void)close(source);
    if (copy >= 0)
        (void)close(copy);
    if (readonly >= 0)
        (void)close(readonly);
    return result;
}
static int keep_only(const int *keep, size_t count) {
    DIR *directory = opendir("/proc/self/fd");
    struct dirent *entry;
    if (directory == NULL)
        return -1;
    int scan = dirfd(directory), failed = 0;
    errno = 0;
    while ((entry = readdir(directory)) != NULL) {
        char *end;
        long fd = strtol(entry->d_name, &end, 10);
        if (*end || fd < 0 || fd > INT_MAX || fd == scan)
            continue;
        int retained = 0;
        for (size_t i = 0; i < count; i++)
            if (fd == keep[i])
                retained = 1;
        if (!retained && close((int)fd) != 0) {
            failed = 1;
            break;
        }
        errno = 0;
    }
    if (errno)
        failed = 1;
    if (closedir(directory))
        failed = 1;
    return failed ? -1 : 0;
}
static int launch_worker(struct peer *p) {
    int control[2] = {-1, -1}, phase[2] = {-1, -1}, status[2] = {-1, -1};
    char before[128];
    if (pipe2(control, O_CLOEXEC | O_NONBLOCK) || pipe2(phase, O_CLOEXEC | O_NONBLOCK) ||
        pipe2(status, O_CLOEXEC | O_NONBLOCK))
        goto fail;
    if (validate_contract(p->authority, control[1], phase[1], status[0]) ||
        real_empty(NULL, control[1], O_WRONLY) || real_empty(NULL, phase[1], O_WRONLY) ||
        real_empty(NULL, status[0], O_RDONLY))
        goto fail;
    if (snprintf(before, sizeof(before), "PHASE DESTROYED BEFORE %s\n", p->token) <= 0 ||
        real_write(NULL, phase[1], before))
        goto fail;
    pid_t worker = fork();
    if (worker < 0)
        goto fail;
    if (worker == 0) {
        int keep[] = {p->executable, p->authority, control[0], phase[0], status[1]};
        if (keep_only(keep, sizeof(keep) / sizeof(keep[0])))
            _exit(125);
        int nullfd = open("/dev/null", O_RDWR | O_CLOEXEC);
        if (nullfd < 0)
            _exit(125);
        for (int fd = 0; fd < 3; fd++)
            if (dup2(nullfd, fd) < 0)
                _exit(125);
        if (nullfd > 2)
            (void)close(nullfd);
        for (unsigned i = 1; i < 5; i++)
            if (fcntl(keep[i], F_SETFD, 0))
                _exit(125);
        char hold[32], authority[32], ctrl[32], ph[32], out[32];
        (void)snprintf(hold, sizeof(hold), "%llu", (unsigned long long)p->hold_ms);
        (void)snprintf(authority, sizeof(authority), "%d", p->authority);
        (void)snprintf(ctrl, sizeof(ctrl), "%d", control[0]);
        (void)snprintf(ph, sizeof(ph), "%d", phase[0]);
        (void)snprintf(out, sizeof(out), "%d", status[1]);
        char *args[] = {"pen-input-lease",
                        "--hold-ms",
                        hold,
                        "--token",
                        p->token,
                        "--authority-fd",
                        authority,
                        "--authority-sha256",
                        p->authority_hash,
                        "--control-fd",
                        ctrl,
                        "--phase-fd",
                        ph,
                        "--status-fd",
                        out,
                        NULL};
        char *env[] = {"LC_ALL=C", "LANG=C", NULL};
        fexecve(p->executable, args, env);
        _exit(125);
    }
    /* Ownership transfers before any later fallible parent-side operation. */
    p->worker.pid = worker;
    p->control = control[1];
    p->phase = phase[1];
    p->status = status[0];
    (void)close(control[0]);
    (void)close(phase[0]);
    (void)close(status[1]);
    pid_t parent;
    char state;
    if (snapshot(worker, &p->worker.start, &parent, &state) || parent != p->self.pid)
        return quarantine(p);
    return 0;
fail:
    for (unsigned i = 0; i < 2; i++) {
        if (control[i] >= 0)
            (void)close(control[i]);
        if (phase[i] >= 0)
            (void)close(phase[i]);
        if (status[i] >= 0)
            (void)close(status[i]);
    }
    return -1;
}
static int receipt(struct peer *p, const char *kind, const char *proof) {
    char line[PEER_BYTES], suffix[256], reverse[20];
    int closed = p->state == PEER_RELEASED;
    int prefix = snprintf(
        line, sizeof(line),
        "PEN_PAGE_PEER %s stage_session=%s sequence=%llu token=%s peer_pid=%ld "
        "peer_starttime=%llu worker_pid=%ld worker_starttime=%llu guardian_pid=%ld "
        "guardian_starttime=%llu guardian_session=%s deviceClockDomain=" PEER_CLOCK
        " deadline_boottime_ms=%llu device_boottime_ms=",
        kind, p->stage, (unsigned long long)p->sequence, p->token, (long)p->self.pid,
        (unsigned long long)p->self.start, (long)p->worker.pid, (unsigned long long)p->worker.start,
        (long)p->guardian.pid, (unsigned long long)p->guardian.start, p->guardian_session,
        (unsigned long long)p->deadline);
    int tail =
        snprintf(suffix, sizeof(suffix), " proof_sha256=%s worker_closed=%s guardian_closed=%s\n",
                 proof, closed ? "true" : "false", closed ? "true" : "false");
    if (prefix <= 0 || tail <= 0 || (size_t)tail >= sizeof(suffix) ||
        (size_t)prefix + sizeof(reverse) + (size_t)tail >= sizeof(line) ||
        p->ops->prepare_publication(p->opaque, STDOUT_FILENO,
                                    (size_t)prefix + sizeof(reverse) + (size_t)tail))
        return quarantine(p);
    /* All fallible/delayable authority, endpoint, and output admission is above.
     * Re-sample BOOTTIME here, after those proofs, including output readiness.
     * Only bounded integer formatting/copies and the atomic write follow. The
     * sample-to-write scheduling window is irreducible without kernel support;
     * this is a fresh device-clock observation, not a future execution guarantee. */
    uint64_t now;
    if (fresh_now(p, &now) || (!closed && now >= p->deadline) ||
        (closed && (p->deadline > UINT64_MAX - 1000 || now > p->deadline + 1000)))
        return quarantine(p);
    uint64_t remaining = now;
    size_t digits = 0, length = (size_t)prefix;
    do {
        reverse[digits++] = (char)('0' + remaining % 10);
        remaining /= 10;
    } while (remaining);
    while (digits)
        line[length++] = reverse[--digits];
    memcpy(line + length, suffix, (size_t)tail + 1);
    length += (size_t)tail;
    return p->ops->publish(p->opaque, STDOUT_FILENO, line, length) ? quarantine(p) : 0;
}
static int exact_command(struct peer *p, const char *line, const char *kind, const char *proof_name,
                         char proof[65], uint64_t *sequence) {
    char canonical[512], stage[65], digest[65];
    unsigned long long seq = 0;
    int used = 0, count;
    if (strcmp(kind, "ACQUIRE") == 0) {
        count = sscanf(line, "ACQUIRE stage_session=%64s before_absence_proof=%64s\n%n", stage,
                       digest, &used);
        if (count != 2 || used != (int)strlen(line) || !hex64(digest))
            return -1;
        (void)snprintf(canonical, sizeof(canonical),
                       "ACQUIRE stage_session=%s before_absence_proof=%s\n", p->stage, digest);
    } else if (proof_name != NULL) {
        count = sscanf(line, "FINISH stage_session=%64s sequence=%llu final_absence_proof=%64s\n%n",
                       stage, &seq, digest, &used);
        if (count != 3 || used != (int)strlen(line) || !hex64(digest))
            return -1;
        (void)snprintf(canonical, sizeof(canonical),
                       "FINISH stage_session=%s sequence=%llu final_absence_proof=%s\n", p->stage,
                       seq, digest);
    } else {
        count = sscanf(line, "CAPTURE stage_session=%64s sequence=%llu\n%n", stage, &seq, &used);
        if (count != 2 || used != (int)strlen(line))
            return -1;
        memset(digest, '0', 64);
        digest[64] = 0;
        (void)snprintf(canonical, sizeof(canonical), "CAPTURE stage_session=%s sequence=%llu\n",
                       p->stage, seq);
    }
    if (strcmp(stage, p->stage) || strcmp(line, canonical))
        return -1;
    memcpy(proof, digest, 65);
    *sequence = (uint64_t)seq;
    return 0;
}
static int signal_policy(void) {
    sigset_t mask;
    struct sigaction ignore, defaults;
    sigfillset(&mask);
    if (sigprocmask(SIG_SETMASK, &mask, NULL))
        return -1;
    memset(&ignore, 0, sizeof(ignore));
    ignore.sa_handler = SIG_IGN;
    sigemptyset(&ignore.sa_mask);
    memset(&defaults, 0, sizeof(defaults));
    defaults.sa_handler = SIG_DFL;
    sigemptyset(&defaults.sa_mask);
    if (sigaction(SIGCHLD, &defaults, NULL) || sigaction(SIGTERM, &ignore, NULL) ||
        sigaction(SIGINT, &ignore, NULL) || sigaction(SIGHUP, &ignore, NULL) ||
        sigaction(SIGPIPE, &ignore, NULL))
        return -1;
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    return sigprocmask(SIG_SETMASK, &mask, NULL);
}
static int active_command(struct peer *p, char command[512]) {
    for (;;) {
        uint64_t now;
        struct pollfd input = {STDIN_FILENO, POLLIN | POLLHUP, 0};
        if (fresh_now(p, &now) || now >= p->deadline || owners_live(p) ||
            real_empty(NULL, p->status, O_RDONLY) || real_empty(NULL, p->control, O_WRONLY) ||
            real_empty(NULL, p->phase, O_WRONLY) || output_alive(STDOUT_FILENO) ||
            poll(&input, 1, 10) < 0 || (input.revents & (POLLERR | POLLHUP | POLLNVAL)))
            return -1;
        if (input.revents & POLLIN)
            return real_record(NULL, STDIN_FILENO, command, 512, p->deadline);
    }
}
static void hold_quarantine(struct peer *p) {
    char line[256];
    p->state = PEER_QUARANTINED;
    (void)snprintf(
        line, sizeof(line),
        "PEN_PAGE_PEER QUARANTINED stage_session=%s reason=unknown reboot_required=true\n",
        p->stage);
    (void)real_write(NULL, STDOUT_FILENO, line);
    for (;;)
        (void)poll(NULL, 0, 250); /* Never close a peer or signal a holder. */
}
#ifndef NATIVE_PAGE_PEN_PEER_TEST
int main(int argc, char **argv) {
    struct peer p = {0};
    const char *image = NULL, *authority = NULL, *image_hash = NULL;
    uint64_t now, seq;
    char command[512], proof[65];
    pid_t parent;
    char process_state;
    p.authority = p.executable = p.control = p.phase = p.status = -1;
    p.ops = &system_ops;
    if (argc != 15)
        return 2;
    for (int i = 1; i < argc; i += 2) {
        const char *key = argv[i], *value = argv[i + 1];
        if (!strcmp(key, "--lease")) {
            if (image)
                return 2;
            image = value;
        } else if (!strcmp(key, "--lease-sha256")) {
            if (image_hash)
                return 2;
            image_hash = value;
        } else if (!strcmp(key, "--authority")) {
            if (authority)
                return 2;
            authority = value;
        } else if (!strcmp(key, "--authority-sha256")) {
            if (p.authority_hash[0] || !hex64(value))
                return 2;
            memcpy(p.authority_hash, value, 65);
        } else if (!strcmp(key, "--token")) {
            if (p.token[0] || !hex64(value))
                return 2;
            memcpy(p.token, value, 65);
        } else if (!strcmp(key, "--stage-session")) {
            if (p.stage[0] || !hex64(value))
                return 2;
            memcpy(p.stage, value, 65);
        } else if (!strcmp(key, "--hold-ms")) {
            if (p.hold_ms || number(value, &p.hold_ms) || p.hold_ms > 300000)
                return 2;
        } else
            return 2;
    }
    if (!image || !image_hash || !authority || !p.authority_hash[0] || !p.token[0] || !p.stage[0] ||
        !p.hold_ms || signal_policy())
        return 2;
    p.self.pid = getpid();
    p.owner.pid = getppid();
    if (snapshot(p.self.pid, &p.self.start, &parent, &process_state) ||
        snapshot(p.owner.pid, &p.owner.start, &parent, &process_state))
        return 2;
    /* Require exclusive caller command/output anonymous pipes, not a TTY/FIFO. */
    for (int fd = 0; fd < 2; fd++) {
        int flags = fcntl(fd, F_GETFL);
        if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK))
            return 2;
    }
    struct stat in, out;
    if (pipe_identity(0, O_RDONLY, &in) || pipe_identity(1, O_WRONLY, &out) || same_fd(in, out) ||
        real_empty(NULL, 1, O_WRONLY))
        return 2;
    p.authority = sealed_copy(authority, p.authority_hash, 511, 0);
    p.executable = sealed_copy(image, image_hash, MAX_IMAGE, 1);
    if (p.authority < 3 || p.executable < 3)
        return 2;
    int keep[] = {0, 1, 2, p.authority, p.executable};
    if (keep_only(keep, sizeof(keep) / sizeof(keep[0])))
        return 2;
    if (fresh_now(&p, &now) || now > UINT64_MAX - 5000 ||
        real_record(NULL, 0, command, sizeof(command), now + 5000) ||
        exact_command(&p, command, "ACQUIRE", "before_absence_proof", proof, &seq) ||
        real_empty(NULL, 0, O_RDONLY))
        return 2;
    if (launch_worker(&p) || peer_acquired(&p) || receipt(&p, "ACQUIRED", proof))
        hold_quarantine(&p);
    while (p.state != PEER_RELEASED) {
        if (active_command(&p, command))
            hold_quarantine(&p);
        if (!strncmp(command, "CAPTURE ", 8)) {
            if (exact_command(&p, command, "CAPTURE", NULL, proof, &seq) || peer_capture(&p, seq) ||
                receipt(&p, "CAPTURED", proof))
                hold_quarantine(&p);
        } else if (!strncmp(command, "FINISH ", 7)) {
            if (exact_command(&p, command, "FINISH", "final_absence_proof", proof, &seq) ||
                peer_finish(&p, seq))
                hold_quarantine(&p);
            /* All resource closure precedes the final receipt. Peer stays alive
             * until the receipt write completes; caller must then verify exit. */
            if (close(p.status) || close(p.authority) || close(p.executable) ||
                receipt(&p, "RELEASED", proof))
                hold_quarantine(&p);
        } else
            hold_quarantine(&p);
    }
    return 0;
}
#endif
