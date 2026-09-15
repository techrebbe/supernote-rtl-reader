#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/input.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/random.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "pen_input_lease_core.h"

#define PEN_NODE "/dev/input/event7"
#define TOKEN_HEX_LENGTH 64
#define HASH_LENGTH 32
#define AUTHORITY_MAX_BYTES 512
#define NAME_BYTES 128
#define PHYS_BYTES 256
#define UNIQ_BYTES 256
#define EVENT_BYTES ((EV_MAX / 8) + 1)
#define KEY_BYTES ((KEY_MAX / 8) + 1)
#define ABS_BYTES ((ABS_MAX / 8) + 1)
#define PROP_BYTES ((INPUT_PROP_MAX / 8) + 1)
#define GUARDIAN_RECORD_BYTES 512
#define GUARDIAN_PROTOCOL_GRACE_MS UINT64_C(1000)
#define GUARDIAN_SILENCE_MS UINT64_C(500)
#define GUARDIAN_PROGRESS_MS UINT64_C(100)
#ifndef PIPEFS_MAGIC
#define PIPEFS_MAGIC 0x50495045
#endif

struct sha256_state {
    uint32_t state[8];
    uint64_t bits;
    unsigned char block[64];
    size_t used;
};

struct pen_authority {
    uint64_t node_dev;
    uint64_t node_ino;
    uint64_t node_rdev;
    uint32_t node_mode;
    unsigned char identity_hash[HASH_LENGTH];
    unsigned char snapshot_hash[HASH_LENGTH];
};

struct captured_abs {
    uint8_t present;
    struct input_absinfo info;
};

struct captured_device {
    struct stat node;
    struct input_id id;
    unsigned char name[NAME_BYTES];
    unsigned char phys[PHYS_BYTES];
    unsigned char uniq[UNIQ_BYTES];
    unsigned char events[EVENT_BYTES];
    unsigned char keys[KEY_BYTES];
    unsigned char axes[ABS_BYTES];
    unsigned char properties[PROP_BYTES];
    struct captured_abs absolute[ABS_MAX + 1];
};

/* Narrow evdev syscall seam. Production binds this to the real kernel calls;
 * host tests bind it to a stateful fake device while exercising the exact
 * production descriptor/admission/grab/revalidation/release code. */
struct pen_device_io {
    int (*open_node)(void *opaque, const char *path, int flags);
    int (*lstat_node)(void *opaque, const char *path, struct stat *value);
    int (*fstat_fd)(void *opaque, int fd, struct stat *value);
    int (*ioctl_ptr)(void *opaque, int fd, unsigned long request, void *value);
    int (*ioctl_int)(void *opaque, int fd, unsigned long request, int value);
    int (*close_fd)(void *opaque, int fd);
};

struct lease_context {
    char token[TOKEN_HEX_LENGTH + 1];
    unsigned char authority_file_hash[HASH_LENGTH];
    struct pen_authority authority;
    uint64_t hold_ms;
    int authority_fd;
    int control_fd;
    int phase_fd;
    int status_fd;
    long status_pipe_buf;
    struct stat control_identity;
    struct stat phase_identity;
    struct stat status_identity;
    struct stat authority_identity;
    int status_admitted;
    int initial_phase_proved;
    int guardian_fd;
    int standby_fd;
    int standby_acquired;
    int guardian_session_prepared;
    int guardian_started;
    int guardian_ready;
    int guardian_terminal;
    pid_t guardian_pid;
    uint64_t guardian_starttime;
    uint64_t worker_starttime;
    uint64_t guardian_deadline_boottime;
    uint64_t guardian_handshake_deadline_boottime;
    enum pen_input_lease_end_reason guardian_end_reason;
    char guardian_session[TOKEN_HEX_LENGTH + 1];
    const struct pen_device_io *device_io;
    void *device_opaque;
};

static volatile sig_atomic_t cleanup_signal = 0;

#ifdef PEN_INPUT_LEASE_ADAPTER_TEST
/* Deterministic test-only process-boundary hooks. They are absent from the
 * production binary and never observe or replay evdev coordinates. */
static int pen_input_lease_test_kill_worker_handshake_stage;
static unsigned pen_input_lease_test_guardian_contact_ms;
static void (*pen_input_lease_test_before_guardian_release)(void *,unsigned);
static int pen_input_lease_test_close_worker_ready_peer_fd=-1;
static int pen_input_lease_test_drop_abort_ack;
static int pen_input_lease_test_worker_loses_abort_ack;
static int pen_input_lease_test_kill_guardian_before_ready;
static int pen_input_lease_test_kill_worker_after_ready_send;
static unsigned pen_input_lease_test_guardian_ready_delay_ms;
static int pen_input_lease_test_fail_guardian_fd_sweep;
static int pen_input_lease_test_enable_worker_fd_sweep;
static int pen_input_lease_test_guardian_no_child_failure;
static void (*pen_input_lease_test_after_ready_prepared)(void *);
static int pen_input_lease_test_drop_ready_ack;
static int pen_input_lease_test_kill_worker_after_guardian_end;
static int pen_input_lease_test_stop_worker_stage;
static unsigned pen_input_lease_test_delay_safe_command_ms;
static void (*pen_input_lease_test_before_final_idle)(void *);
#endif

static int guardian_ping(struct lease_context *context);
static int prove_exclusive(void *opaque,int held_fd);
static int consume_if_exact(int fd,const char *record,int *received);
static const char *end_reason(enum pen_input_lease_end_reason reason);
static int wait_guardian_exit(struct lease_context *context,uint64_t deadline,
        int *exit_code);
static int worker_close_or_reject_unrelated_fds(struct lease_context *context);
static int prepare_guardian(void *opaque,int held_fd,int standby_fd);

static int real_open_node(void *unused, const char *path, int flags) {
    (void)unused; return open(path, flags);
}
static int real_lstat_node(void *unused, const char *path, struct stat *value) {
    (void)unused; return lstat(path, value);
}
static int real_fstat_fd(void *unused, int fd, struct stat *value) {
    (void)unused; return fstat(fd, value);
}
static int real_ioctl_ptr(void *unused, int fd, unsigned long request, void *value) {
    (void)unused; return ioctl(fd, request, value);
}
static int real_ioctl_int(void *unused, int fd, unsigned long request, int value) {
    (void)unused; return ioctl(fd, request, value);
}
static int real_close_fd(void *unused, int fd) { (void)unused; return close(fd); }

static const struct pen_device_io real_device_io = {
    real_open_node, real_lstat_node, real_fstat_fd,
    real_ioctl_ptr, real_ioctl_int, real_close_fd
};

static const struct pen_device_io *device_io(const struct lease_context *context) {
    return context->device_io != NULL ? context->device_io : &real_device_io;
}

static int device_io_valid(const struct lease_context *context) {
    const struct pen_device_io *io = device_io(context);
    return io->open_node != NULL && io->lstat_node != NULL &&
        io->fstat_fd != NULL && io->ioctl_ptr != NULL &&
        io->ioctl_int != NULL && io->close_fd != NULL;
}

static int bit_set(const unsigned char *bits, unsigned code) {
    return (bits[code / 8] & (1u << (code % 8))) != 0;
}

static uint32_t rotate_right(uint32_t value, unsigned count) {
    return (value >> count) | (value << (32u - count));
}

static uint32_t load_be32(const unsigned char *bytes) {
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) |
        ((uint32_t)bytes[2] << 8) | (uint32_t)bytes[3];
}

static void store_be32(unsigned char *bytes, uint32_t value) {
    bytes[0] = (unsigned char)(value >> 24);
    bytes[1] = (unsigned char)(value >> 16);
    bytes[2] = (unsigned char)(value >> 8);
    bytes[3] = (unsigned char)value;
}

static void sha256_transform(struct sha256_state *hash,
        const unsigned char block[64]) {
    static const uint32_t constants[64] = {
        0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
        0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
        0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
        0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
        0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
        0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
        0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
        0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
    };
    uint32_t words[64];
    uint32_t a, b, c, d, e, f, g, h;
    for (unsigned index = 0; index < 16; index++) {
        words[index] = load_be32(block + index * 4u);
    }
    for (unsigned index = 16; index < 64; index++) {
        uint32_t x = words[index - 15];
        uint32_t y = words[index - 2];
        uint32_t s0 = rotate_right(x, 7) ^ rotate_right(x, 18) ^ (x >> 3);
        uint32_t s1 = rotate_right(y, 17) ^ rotate_right(y, 19) ^ (y >> 10);
        words[index] = words[index - 16] + s0 + words[index - 7] + s1;
    }
    a=hash->state[0]; b=hash->state[1]; c=hash->state[2]; d=hash->state[3];
    e=hash->state[4]; f=hash->state[5]; g=hash->state[6]; h=hash->state[7];
    for (unsigned index = 0; index < 64; index++) {
        uint32_t s1 = rotate_right(e, 6) ^ rotate_right(e, 11) ^ rotate_right(e, 25);
        uint32_t choose = (e & f) ^ ((~e) & g);
        uint32_t first = h + s1 + choose + constants[index] + words[index];
        uint32_t s0 = rotate_right(a, 2) ^ rotate_right(a, 13) ^ rotate_right(a, 22);
        uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        uint32_t second = s0 + majority;
        h=g; g=f; f=e; e=d+first; d=c; c=b; b=a; a=first+second;
    }
    hash->state[0]+=a; hash->state[1]+=b; hash->state[2]+=c; hash->state[3]+=d;
    hash->state[4]+=e; hash->state[5]+=f; hash->state[6]+=g; hash->state[7]+=h;
}

static void sha256_init(struct sha256_state *hash) {
    static const uint32_t initial[8] = {
        0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,
        0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u
    };
    memcpy(hash->state, initial, sizeof(initial));
    hash->bits = 0;
    hash->used = 0;
}

static int sha256_update(struct sha256_state *hash,
        const void *opaque, size_t length) {
    const unsigned char *bytes = opaque;
    if (length > (UINT64_MAX - hash->bits) / 8u) return -1;
    hash->bits += (uint64_t)length * 8u;
    while (length != 0) {
        size_t take = sizeof(hash->block) - hash->used;
        if (take > length) take = length;
        memcpy(hash->block + hash->used, bytes, take);
        hash->used += take;
        bytes += take;
        length -= take;
        if (hash->used == sizeof(hash->block)) {
            sha256_transform(hash, hash->block);
            hash->used = 0;
        }
    }
    return 0;
}

static void sha256_final(struct sha256_state *hash,
        unsigned char output[HASH_LENGTH]) {
    uint64_t bits = hash->bits;
    hash->block[hash->used++] = 0x80;
    if (hash->used > 56) {
        memset(hash->block + hash->used, 0, 64 - hash->used);
        sha256_transform(hash, hash->block);
        hash->used = 0;
    }
    memset(hash->block + hash->used, 0, 56 - hash->used);
    for (unsigned index = 0; index < 8; index++) {
        hash->block[63 - index] = (unsigned char)(bits >> (index * 8u));
    }
    sha256_transform(hash, hash->block);
    for (unsigned index = 0; index < 8; index++) {
        store_be32(output + index * 4u, hash->state[index]);
    }
}

static void hash_u8(struct sha256_state *hash, uint8_t value) {
    (void)sha256_update(hash, &value, 1);
}

static void hash_u16_le(struct sha256_state *hash, uint16_t value) {
    unsigned char bytes[2] = {(unsigned char)value, (unsigned char)(value >> 8)};
    (void)sha256_update(hash, bytes, sizeof(bytes));
}

static void hash_u32_le(struct sha256_state *hash, uint32_t value) {
    unsigned char bytes[4] = {(unsigned char)value, (unsigned char)(value >> 8),
        (unsigned char)(value >> 16), (unsigned char)(value >> 24)};
    (void)sha256_update(hash, bytes, sizeof(bytes));
}

static void hash_u64_le(struct sha256_state *hash, uint64_t value) {
    unsigned char bytes[8];
    for (unsigned index = 0; index < 8; index++) {
        bytes[index] = (unsigned char)(value >> (index * 8u));
    }
    (void)sha256_update(hash, bytes, sizeof(bytes));
}

static int hex_nibble(unsigned char value) {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    return -1;
}

static int parse_hash(const char *text, unsigned char output[HASH_LENGTH]) {
    if (text == NULL || strlen(text) != TOKEN_HEX_LENGTH) return -1;
    for (size_t index = 0; index < HASH_LENGTH; index++) {
        int high = hex_nibble((unsigned char)text[index * 2]);
        int low = hex_nibble((unsigned char)text[index * 2 + 1]);
        if (high < 0 || low < 0) return -1;
        output[index] = (unsigned char)((high << 4) | low);
    }
    return 0;
}

static int valid_token(const char *token) {
    if (token == NULL || strlen(token) != TOKEN_HEX_LENGTH) return 0;
    for (size_t index = 0; index < TOKEN_HEX_LENGTH; index++) {
        if (hex_nibble((unsigned char)token[index]) < 0) return 0;
    }
    return 1;
}

static int constant_equal(const unsigned char *a, const unsigned char *b,
        size_t length) {
    unsigned difference = 0;
    for (size_t index = 0; index < length; index++) difference |= a[index] ^ b[index];
    return difference == 0;
}

static int parse_fixed_hex(const char **at, const char *end, size_t digits,
        uint64_t *value) {
    uint64_t parsed = 0;
    if ((size_t)(end - *at) < digits) return -1;
    for (size_t index = 0; index < digits; index++) {
        int nibble = hex_nibble((unsigned char)(*at)[index]);
        if (nibble < 0) return -1;
        parsed = (parsed << 4) | (unsigned)nibble;
    }
    *at += digits;
    *value = parsed;
    return 0;
}

static int consume(const char **at, const char *end, const char *literal) {
    size_t length = strlen(literal);
    if ((size_t)(end - *at) < length) return -1;
    if (memcmp(*at, literal, length) != 0) return -1;
    *at += length;
    return 0;
}

static int parse_authority(struct lease_context *context,
        const char *text, size_t length) {
    const char *at = text;
    const char *end = text + length;
    uint64_t value;
    char token[TOKEN_HEX_LENGTH + 1];
    char hash_text[TOKEN_HEX_LENGTH + 1];
    if (length < 250 || length >= AUTHORITY_MAX_BYTES || text[length - 1] != '\n') return -1;
    if (consume(&at, end, "PEN_INPUT_AUTHORITY_V1 token=") != 0 ||
            (size_t)(end - at) < TOKEN_HEX_LENGTH) return -1;
    memcpy(token, at, TOKEN_HEX_LENGTH); token[TOKEN_HEX_LENGTH] = '\0'; at += TOKEN_HEX_LENGTH;
    if (!valid_token(token) || strcmp(token, context->token) != 0) return -1;
    if (consume(&at, end, " node_dev=") != 0 || parse_fixed_hex(&at, end, 16, &context->authority.node_dev) != 0 ||
            consume(&at, end, " node_ino=") != 0 || parse_fixed_hex(&at, end, 16, &context->authority.node_ino) != 0 ||
            consume(&at, end, " node_rdev=") != 0 || parse_fixed_hex(&at, end, 16, &context->authority.node_rdev) != 0 ||
            consume(&at, end, " node_mode=") != 0 || parse_fixed_hex(&at, end, 8, &value) != 0 || value > UINT32_MAX) return -1;
    context->authority.node_mode = (uint32_t)value;
    if (consume(&at, end, " identity_sha256=") != 0 ||
            (size_t)(end - at) < TOKEN_HEX_LENGTH) return -1;
    memcpy(hash_text, at, TOKEN_HEX_LENGTH); hash_text[TOKEN_HEX_LENGTH] = '\0'; at += TOKEN_HEX_LENGTH;
    if (parse_hash(hash_text, context->authority.identity_hash) != 0 ||
            consume(&at, end, " snapshot_sha256=") != 0 ||
            (size_t)(end - at) < TOKEN_HEX_LENGTH) return -1;
    memcpy(hash_text, at, TOKEN_HEX_LENGTH); hash_text[TOKEN_HEX_LENGTH] = '\0'; at += TOKEN_HEX_LENGTH;
    if (parse_hash(hash_text, context->authority.snapshot_hash) != 0 ||
            consume(&at, end, "\n") != 0 || at != end) return -1;
    return S_ISCHR((mode_t)context->authority.node_mode) ? 0 : -1;
}

static int exact_fd_number(const char *text, int *fd) {
    char *end = NULL;
    long value;
    if (text == NULL || *text == '\0') return -1;
    for (const unsigned char *at = (const unsigned char *)text; *at; at++) {
        if (*at < '0' || *at > '9') return -1;
    }
    errno = 0;
    value = strtol(text, &end, 10);
    if (errno != 0 || *end != '\0' || value < 3 || value > INT_MAX) return -1;
    *fd = (int)value;
    return 0;
}

static int exact_hold_ms(const char *text, uint64_t *value) {
    char *end = NULL;
    unsigned long long parsed;
    if (text == NULL || *text == '\0') return -1;
    for (const unsigned char *at = (const unsigned char *)text; *at; at++) {
        if (*at < '0' || *at > '9') return -1;
    }
    errno = 0;
    parsed = strtoull(text, &end, 10);
    if (errno != 0 || *end != '\0' || parsed == 0 ||
            parsed > PEN_INPUT_LEASE_MAX_HOLD_MS) return -1;
    *value = (uint64_t)parsed;
    return 0;
}

static int same_node_stat(const struct pen_authority *expected,
        const struct stat *actual) {
    return S_ISCHR(actual->st_mode) && (uint64_t)actual->st_dev == expected->node_dev &&
        (uint64_t)actual->st_ino == expected->node_ino &&
        (uint64_t)actual->st_rdev == expected->node_rdev &&
        (uint32_t)actual->st_mode == expected->node_mode;
}

static int capture_device_descriptor(struct lease_context *context, int fd,
        struct captured_device *captured) {
    const struct pen_device_io *io = device_io(context);
    void *opaque = context->device_opaque;
    int name_length, phys_length, uniq_length;
    memset(captured, 0, sizeof(*captured));
    if (io->fstat_fd(opaque, fd, &captured->node) != 0 ||
            !S_ISCHR(captured->node.st_mode) ||
            io->ioctl_ptr(opaque, fd, EVIOCGID, &captured->id) != 0) return -1;
    name_length = io->ioctl_ptr(opaque, fd,
        EVIOCGNAME(sizeof(captured->name)), captured->name);
    phys_length = io->ioctl_ptr(opaque, fd,
        EVIOCGPHYS(sizeof(captured->phys)), captured->phys);
    uniq_length = io->ioctl_ptr(opaque, fd,
        EVIOCGUNIQ(sizeof(captured->uniq)), captured->uniq);
    if (name_length <= 0 || name_length >= (int)sizeof(captured->name) ||
            phys_length < 0 || phys_length >= (int)sizeof(captured->phys) ||
            uniq_length < 0 || uniq_length >= (int)sizeof(captured->uniq) ||
            io->ioctl_ptr(opaque, fd, EVIOCGPROP(sizeof(captured->properties)),
                captured->properties) < 0 ||
            io->ioctl_ptr(opaque, fd, EVIOCGBIT(0, sizeof(captured->events)),
                captured->events) < 0 ||
            io->ioctl_ptr(opaque, fd, EVIOCGBIT(EV_KEY, sizeof(captured->keys)),
                captured->keys) < 0 ||
            io->ioctl_ptr(opaque, fd, EVIOCGBIT(EV_ABS, sizeof(captured->axes)),
                captured->axes) < 0 ||
            strcmp((const char *)captured->name, "Wacom-pen") != 0 ||
            !bit_set(captured->events, EV_SYN) ||
            !bit_set(captured->events, EV_KEY) ||
            !bit_set(captured->events, EV_ABS) ||
            !bit_set(captured->keys, BTN_TOUCH) ||
            !bit_set(captured->keys, BTN_TOOL_PEN) ||
            !bit_set(captured->keys, BTN_TOOL_RUBBER) ||
            !bit_set(captured->keys, BTN_STYLUS) ||
            !bit_set(captured->keys, BTN_STYLUS2) ||
            !bit_set(captured->axes, ABS_X) ||
            !bit_set(captured->axes, ABS_Y) ||
            !bit_set(captured->axes, ABS_PRESSURE)) return -1;
    for (unsigned code = 0; code <= ABS_MAX; code++) {
        captured->absolute[code].present =
            (uint8_t)((captured->axes[code / 8] & (1u << (code % 8))) != 0);
        if (captured->absolute[code].present &&
                io->ioctl_ptr(opaque, fd, EVIOCGABS(code),
                    &captured->absolute[code].info) != 0) return -1;
    }
    return 0;
}

static void hash_captured_descriptor(const struct captured_device *captured,
        unsigned char identity[HASH_LENGTH], unsigned char snapshot[HASH_LENGTH]) {
    struct sha256_state identity_state;
    struct sha256_state snapshot_state;
    static const char identity_domain[] = "rtl-reader-pen-device-identity-v1";
    static const char snapshot_domain[] = "rtl-reader-pen-device-snapshot-v1";
    sha256_init(&identity_state); sha256_init(&snapshot_state);
    (void)sha256_update(&identity_state, identity_domain, sizeof(identity_domain));
    (void)sha256_update(&snapshot_state, snapshot_domain, sizeof(snapshot_domain));
#define HASH_BOTH(data,length) do { \
    (void)sha256_update(&identity_state,(data),(length)); \
    (void)sha256_update(&snapshot_state,(data),(length)); \
} while (0)
    hash_u64_le(&identity_state, (uint64_t)captured->node.st_dev); hash_u64_le(&snapshot_state, (uint64_t)captured->node.st_dev);
    hash_u64_le(&identity_state, (uint64_t)captured->node.st_ino); hash_u64_le(&snapshot_state, (uint64_t)captured->node.st_ino);
    hash_u64_le(&identity_state, (uint64_t)captured->node.st_rdev); hash_u64_le(&snapshot_state, (uint64_t)captured->node.st_rdev);
    hash_u32_le(&identity_state, (uint32_t)captured->node.st_mode); hash_u32_le(&snapshot_state, (uint32_t)captured->node.st_mode);
    hash_u16_le(&identity_state,captured->id.bustype); hash_u16_le(&snapshot_state,captured->id.bustype);
    hash_u16_le(&identity_state,captured->id.vendor); hash_u16_le(&snapshot_state,captured->id.vendor);
    hash_u16_le(&identity_state,captured->id.product); hash_u16_le(&snapshot_state,captured->id.product);
    hash_u16_le(&identity_state,captured->id.version); hash_u16_le(&snapshot_state,captured->id.version);
    HASH_BOTH(captured->name,sizeof(captured->name)); HASH_BOTH(captured->phys,sizeof(captured->phys));
    HASH_BOTH(captured->uniq,sizeof(captured->uniq)); HASH_BOTH(captured->properties,sizeof(captured->properties));
    HASH_BOTH(captured->events,sizeof(captured->events)); HASH_BOTH(captured->keys,sizeof(captured->keys));
    HASH_BOTH(captured->axes,sizeof(captured->axes));
    for (unsigned code = 0; code <= ABS_MAX; code++) {
        int present = captured->absolute[code].present != 0;
        const struct input_absinfo *value = &captured->absolute[code].info;
        hash_u8(&identity_state, (uint8_t)present); hash_u8(&snapshot_state, (uint8_t)present);
        /* value is authenticated in the initial snapshot but intentionally not
         * treated as immutable identity; it is live pen state. */
        hash_u32_le(&snapshot_state, (uint32_t)value->value);
        hash_u32_le(&identity_state, (uint32_t)value->minimum); hash_u32_le(&snapshot_state, (uint32_t)value->minimum);
        hash_u32_le(&identity_state, (uint32_t)value->maximum); hash_u32_le(&snapshot_state, (uint32_t)value->maximum);
        hash_u32_le(&identity_state, (uint32_t)value->fuzz); hash_u32_le(&snapshot_state, (uint32_t)value->fuzz);
        hash_u32_le(&identity_state, (uint32_t)value->flat); hash_u32_le(&snapshot_state, (uint32_t)value->flat);
        hash_u32_le(&identity_state, (uint32_t)value->resolution); hash_u32_le(&snapshot_state, (uint32_t)value->resolution);
    }
#undef HASH_BOTH
    sha256_final(&identity_state, identity);
    sha256_final(&snapshot_state, snapshot);
}

static int descriptor_hashes(struct lease_context *context, int fd,
        unsigned char identity[HASH_LENGTH],
        unsigned char snapshot[HASH_LENGTH]) {
    struct captured_device captured;
    if (capture_device_descriptor(context, fd, &captured) != 0) return -1;
    hash_captured_descriptor(&captured, identity, snapshot);
    return 0;
}

static int path_and_fd_match(struct lease_context *context, int fd) {
    const struct pen_device_io *io = device_io(context);
    void *opaque = context->device_opaque;
    struct stat path_now, opened;
    return io->lstat_node(opaque, PEN_NODE, &path_now) == 0 &&
        io->fstat_fd(opaque, fd, &opened) == 0 &&
        same_node_stat(&context->authority, &path_now) &&
        same_node_stat(&context->authority, &opened) ? 0 : -1;
}

static int verify_device(struct lease_context *context, int fd) {
    unsigned char identity[HASH_LENGTH], snapshot[HASH_LENGTH];
    if (path_and_fd_match(context, fd) != 0 ||
            descriptor_hashes(context, fd, identity, snapshot) != 0 ||
            !constant_equal(identity, context->authority.identity_hash, HASH_LENGTH)) return -1;
    /* The externally authenticated snapshot reports live absinfo values, but
     * those values cannot be used as immutable admission identity. Current
     * pressure/tool/contact state is checked independently by pen_idle(). */
    (void)snapshot;
    return 0;
}

static int fd_flags_exact(int fd, int access) {
    int flags = fcntl(fd, F_GETFL);
    int descriptor_flags = fcntl(fd, F_GETFD);
    int allowed = O_ACCMODE | O_NONBLOCK;
#ifdef O_LARGEFILE
    allowed |= O_LARGEFILE;
#endif
    if (flags < 0 || descriptor_flags < 0 || (flags & O_ACCMODE) != access ||
            (flags & O_NONBLOCK) == 0 || (flags & ~allowed) != 0) return -1;
    if ((descriptor_flags & FD_CLOEXEC) == 0 &&
            fcntl(fd, F_SETFD, descriptor_flags | FD_CLOEXEC) != 0) return -1;
    descriptor_flags = fcntl(fd, F_GETFD);
    return descriptor_flags >= 0 && (descriptor_flags & FD_CLOEXEC) != 0 ? 0 : -1;
}

static int normalize_endpoint_status_flags(int fd, int access) {
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0 || (flags & O_ACCMODE) != access) return -1;
    /* F_SETFL changes the mutable status flags only. Supplying exactly
     * O_NONBLOCK clears inherited O_ASYNC/O_APPEND/O_DIRECT and any other
     * mutable delivery/write semantics before the endpoint is admitted. */
    if (fcntl(fd, F_SETFL, O_NONBLOCK) != 0) return -1;
#ifdef F_SETOWN
    if (fcntl(fd, F_SETOWN, 0) != 0) return -1;
    if (fcntl(fd, F_GETOWN) != 0) return -1;
#endif
#ifdef F_SETSIG
    if (fcntl(fd, F_SETSIG, 0) != 0 || fcntl(fd, F_GETSIG) != 0) return -1;
#endif
    return fd_flags_exact(fd, access);
}

static int pipe_endpoint(int fd, int access, struct stat *info) {
    struct statfs filesystem;
    /* A named FIFO can be reopened by pathname and acquire extra writers or
     * readers after admission. Only anonymous pipefs endpoints are accepted. */
    return fstat(fd, info) == 0 && S_ISFIFO(info->st_mode) &&
        fstatfs(fd,&filesystem) == 0 &&
        (unsigned long)filesystem.f_type == (unsigned long)PIPEFS_MAGIC &&
        fd_flags_exact(fd, access) == 0 ? 0 : -1;
}

static int live_pipe_endpoint(int fd, int access, short required_events,
        short forbidden_events, struct stat *info) {
    struct pollfd endpoint;
    int result;
    if (pipe_endpoint(fd, access, info) != 0) return -1;
    endpoint.fd = fd;
    endpoint.events = required_events | (access == O_RDONLY ? POLLIN : POLLOUT);
    endpoint.revents = 0;
    result = poll(&endpoint, 1, 0);
    if (result < 0 || (endpoint.revents & forbidden_events) != 0) return -1;
    return required_events == 0 ||
        (result == 1 && (endpoint.revents & required_events) == required_events) ? 0 : -1;
}

static int available_bytes(int fd, int *available) {
    return ioctl(fd, FIONREAD, available);
}

static int exact_pipe_record(int fd, const char *expected) {
    char record[GUARDIAN_RECORD_BYTES];
    size_t length = strlen(expected);
    int available = 0;
    ssize_t got;
    if (length > sizeof(record) || available_bytes(fd, &available) != 0 ||
            available != (int)length) return -1;
    got = read(fd, record, length);
    return got == (ssize_t)length && memcmp(record, expected, length) == 0 ? 0 : -1;
}

static int status_record(struct lease_context *context, const char *record) {
    struct pollfd output;
    size_t length = strlen(record);
    ssize_t written;
    if (length == 0 || context->status_pipe_buf < 1 ||
            length > (size_t)context->status_pipe_buf) return -1;
    output.fd = context->status_fd; output.events = POLLOUT; output.revents = 0;
    if (poll(&output, 1, 0) != 1 || (output.revents & POLLOUT) == 0 ||
            (output.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) return -1;
    /* O_NONBLOCK is admission-required; this single sub-PIPE_BUF write cannot
     * block and is atomic for the dedicated status pipe. */
    written = write(context->status_fd, record, length);
    return written == (ssize_t)length ? 0 : -1;
}

static int read_authority_file(struct lease_context *context) {
    struct stat before, after;
    unsigned char bytes[AUTHORITY_MAX_BYTES];
    unsigned char digest[HASH_LENGTH];
    struct sha256_state hash;
    int flags = fcntl(context->authority_fd, F_GETFL);
    int descriptor_flags = fcntl(context->authority_fd, F_GETFD);
    ssize_t got;
    if (flags < 0 || descriptor_flags < 0 || (flags & O_ACCMODE) != O_RDONLY ||
            (((descriptor_flags & FD_CLOEXEC) == 0) &&
             fcntl(context->authority_fd, F_SETFD, descriptor_flags | FD_CLOEXEC) != 0) ||
            fstat(context->authority_fd, &before) != 0 || !S_ISREG(before.st_mode) ||
            before.st_size < 1 || before.st_size >= AUTHORITY_MAX_BYTES) return -1;
    got = pread(context->authority_fd, bytes, (size_t)before.st_size, 0);
    if (got != before.st_size || fstat(context->authority_fd, &after) != 0 ||
            before.st_dev != after.st_dev || before.st_ino != after.st_ino ||
            before.st_size != after.st_size || before.st_mtime != after.st_mtime ||
            before.st_ctime != after.st_ctime) return -1;
    sha256_init(&hash); (void)sha256_update(&hash, bytes, (size_t)got); sha256_final(&hash, digest);
    if (!constant_equal(digest, context->authority_file_hash, HASH_LENGTH)) return -1;
    bytes[got] = '\0';
    if (parse_authority(context, (const char *)bytes, (size_t)got) != 0)
        return -1;
    context->authority_identity = after;
    return 0;
}

static int admit_contract(void *opaque) {
    struct lease_context *context = opaque;
    struct stat control, phase, status;
    int control_available = -1, status_available = -1;
    char initial_phase[160];
    int length;
    if (!device_io_valid(context) ||
            live_pipe_endpoint(context->control_fd, O_RDONLY, 0,
                POLLERR | POLLHUP | POLLNVAL, &control) != 0 ||
            live_pipe_endpoint(context->phase_fd, O_RDONLY, POLLIN,
                POLLERR | POLLHUP | POLLNVAL, &phase) != 0 ||
            live_pipe_endpoint(context->status_fd, O_WRONLY, POLLOUT,
                POLLERR | POLLHUP | POLLNVAL, &status) != 0 ||
            (control.st_dev == phase.st_dev && control.st_ino == phase.st_ino) ||
            (control.st_dev == status.st_dev && control.st_ino == status.st_ino) ||
            (phase.st_dev == status.st_dev && phase.st_ino == status.st_ino) ||
            available_bytes(context->control_fd, &control_available) != 0 ||
            control_available != 0 ||
            available_bytes(context->status_fd, &status_available) != 0 ||
            status_available != 0) return -1;
    context->control_identity = control;
    context->phase_identity = phase;
    context->status_identity = status;
    context->status_admitted = 1;
    context->status_pipe_buf = fpathconf(context->status_fd, _PC_PIPE_BUF);
    if (context->status_pipe_buf < 512) return -1;
    if (read_authority_file(context) != 0) return -1;
    length = snprintf(initial_phase, sizeof(initial_phase),
        "PHASE DESTROYED BEFORE %s\n", context->token);
    if (length <= 0 || (size_t)length >= sizeof(initial_phase) ||
            exact_pipe_record(context->phase_fd, initial_phase) != 0) return -1;
    context->initial_phase_proved=1;
    if (live_pipe_endpoint(context->control_fd, O_RDONLY, 0,
                POLLIN | POLLERR | POLLHUP | POLLNVAL, &control) == 0 &&
        live_pipe_endpoint(context->phase_fd, O_RDONLY, 0,
                POLLIN | POLLERR | POLLHUP | POLLNVAL, &phase) == 0 &&
        live_pipe_endpoint(context->status_fd, O_WRONLY, POLLOUT,
                POLLERR | POLLHUP | POLLNVAL, &status) == 0) {
        if (control.st_dev != context->control_identity.st_dev ||
                control.st_ino != context->control_identity.st_ino ||
                phase.st_dev != context->phase_identity.st_dev ||
                phase.st_ino != context->phase_identity.st_ino ||
                status.st_dev != context->status_identity.st_dev ||
                status.st_ino != context->status_identity.st_ino)
            return -1;
        return worker_close_or_reject_unrelated_fds(context);
    }
    return -1;
}

static int status_consumer_alive(void *opaque) {
    struct lease_context *context = opaque;
    struct stat current;
    if (context->guardian_started) return guardian_ping(context);
    if (!context->status_admitted ||
            live_pipe_endpoint(context->status_fd, O_WRONLY, POLLOUT,
                POLLERR | POLLHUP | POLLNVAL, &current) != 0) return -1;
    return current.st_dev == context->status_identity.st_dev &&
        current.st_ino == context->status_identity.st_ino &&
        current.st_rdev == context->status_identity.st_rdev &&
        current.st_mode == context->status_identity.st_mode ? 0 : -1;
}

static void request_cleanup(int signal_number) { cleanup_signal = signal_number; }

static int block_signals_before_arguments(void) {
    sigset_t all;
    return sigfillset(&all) == 0 &&
        sigprocmask(SIG_SETMASK, &all, NULL) == 0 ? 0 : -1;
}

static int drain_pending_signals(void) {
    struct timespec zero = {0, 0};
    int found = 0;
    for (;;) {
        sigset_t pending;
        int any = 0;
        if (sigpending(&pending) != 0) return -1;
        for (int signal_number = 1; signal_number < NSIG; signal_number++) {
            int member = sigismember(&pending, signal_number);
            if (member < 0) return -1;
            if (member != 0) { any = 1; break; }
        }
        if (!any) return found;
        for (;;) {
            int received = sigtimedwait(&pending, NULL, &zero);
            if (received > 0) { found = 1; break; }
            if (received < 0 && errno == EINTR) continue;
            if (received < 0 && errno == EAGAIN) break;
            return -1;
        }
    }
}

static int safe_runtime_signal_mask(sigset_t *mask) {
    /* Every asynchronous signal, including cleanup controls, stays blocked.
     * Cleanup is consumed synchronously by termination_pending(), so it cannot
     * interrupt acquisition between a safety proof and EVIOCGRAB/READY.
     * SIGPIPE/SIGIO are ignored. Synchronous hardware faults are normalized to
     * SIG_DFL and unblocked. SIGKILL/SIGSTOP cannot be caught or blocked. */
    const int unblocked[] = {
        SIGPIPE, SIGIO,
        SIGILL, SIGFPE, SIGSEGV, SIGBUS, SIGTRAP, SIGSYS
    };
    if (sigfillset(mask) != 0) return -1;
    for (size_t index = 0; index < sizeof(unblocked) / sizeof(unblocked[0]);
            index++) {
        if (sigdelset(mask, unblocked[index]) != 0) return -1;
    }
    return 0;
}

static int install_handlers(void *opaque) {
    struct lease_context *context = opaque;
    const int handled[] = {SIGHUP, SIGINT, SIGQUIT, SIGTERM};
    const int synchronous[] = {SIGILL,SIGFPE,SIGSEGV,SIGBUS,SIGTRAP,SIGSYS};
    struct sigaction action, ignored, defaults;
    sigset_t all, runtime_mask;
    int inherited_pending;
    int result = -1;
    if (sigfillset(&all) != 0 ||
            sigprocmask(SIG_SETMASK, &all, NULL) != 0) return -1;
    inherited_pending = drain_pending_signals();
    if (inherited_pending < 0) return -1;
    memset(&action,0,sizeof(action)); action.sa_handler=request_cleanup; sigemptyset(&action.sa_mask);
    memset(&ignored,0,sizeof(ignored)); ignored.sa_handler=SIG_IGN; sigemptyset(&ignored.sa_mask);
    memset(&defaults,0,sizeof(defaults)); defaults.sa_handler=SIG_DFL; sigemptyset(&defaults.sa_mask);
    if (sigaction(SIGPIPE,&ignored,NULL) != 0 ||
            sigaction(SIGIO,&ignored,NULL) != 0 ||
            sigaction(SIGCHLD,&defaults,NULL) != 0) goto done;
    for (size_t i=0;i<sizeof(handled)/sizeof(handled[0]);i++) {
        if (sigaction(handled[i],&action,NULL) != 0) goto done;
    }
    for (size_t i=0;i<sizeof(synchronous)/sizeof(synchronous[0]);i++) {
        if (sigaction(synchronous[i],&defaults,NULL) != 0) goto done;
    }
    if (normalize_endpoint_status_flags(context->control_fd, O_RDONLY) != 0 ||
            normalize_endpoint_status_flags(context->phase_fd, O_RDONLY) != 0 ||
            normalize_endpoint_status_flags(context->status_fd, O_WRONLY) != 0) goto done;
    if (safe_runtime_signal_mask(&runtime_mask) != 0) goto done;
    result = inherited_pending == 0 ? 0 : -1;
done:
    if (safe_runtime_signal_mask(&runtime_mask) != 0 ||
            sigprocmask(SIG_SETMASK, &runtime_mask, NULL) != 0 ||
            cleanup_signal != 0) result = -1;
    return result;
}

static int termination_pending(void *unused) {
    const int cleanup[] = {SIGHUP,SIGINT,SIGQUIT,SIGTERM};
    struct timespec zero={0,0};
    sigset_t pending, selected;
    int found=cleanup_signal!=0;
    (void)unused;
    if (sigpending(&pending)!=0 || sigemptyset(&selected)!=0) return -1;
    for(size_t index=0;index<sizeof(cleanup)/sizeof(cleanup[0]);index++) {
        int member=sigismember(&pending,cleanup[index]);
        if(member<0)return -1;
        if(member!=0&&sigaddset(&selected,cleanup[index])!=0)return -1;
    }
    for(;;) {
        int received=sigtimedwait(&selected,NULL,&zero);
        if(received>0){ cleanup_signal=received; found=1; continue; }
        if(received<0&&errno==EINTR)continue;
        if(received<0&&errno==EAGAIN)break;
        return -1;
    }
    return found?1:0;
}

static int64_t current_parent(void *unused) { (void)unused; return (int64_t)getppid(); }
static int arm_parent_death(void *unused) { (void)unused; return prctl(PR_SET_PDEATHSIG,SIGTERM,0,0,0); }

static int open_pen(void *opaque) {
    struct lease_context *context = opaque;
    const struct pen_device_io *io = device_io(context);
    int fd = io->open_node(context->device_opaque, PEN_NODE,
        O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_NOFOLLOW);
    if (fd < 0) return -1;
    if (path_and_fd_match(context,fd) != 0) {
        (void)io->close_fd(context->device_opaque,fd); return -1;
    }
    return fd;
}

static int verify_initial(void *opaque, int fd) { return verify_device(opaque,fd); }
static int revalidate(void *opaque, int fd) { return verify_device(opaque,fd); }

static int same_pen(void *opaque, int first, int second) {
    struct lease_context *context=opaque;
    const struct pen_device_io *io=device_io(context);
    struct stat a,b;
    if (io->fstat_fd(context->device_opaque,first,&a) != 0 ||
            io->fstat_fd(context->device_opaque,second,&b) != 0) return -1;
    return a.st_dev==b.st_dev && a.st_ino==b.st_ino && a.st_rdev==b.st_rdev ? 0 : -1;
}

static int idle_from_state(int pressure, const unsigned char keys[KEY_BYTES]) {
    const unsigned active[] = {
        BTN_TOUCH,BTN_TOOL_PEN,BTN_TOOL_RUBBER,BTN_STYLUS,BTN_STYLUS2
    };
    if (pressure != 0) return 1;
    for (size_t i=0;i<sizeof(active)/sizeof(active[0]);i++) {
        if (bit_set(keys,active[i])) return 1;
    }
    return 0;
}

static int pen_idle(void *opaque, int fd) {
    struct lease_context *context=opaque;
    const struct pen_device_io *io=device_io(context);
    struct input_absinfo pressure;
    unsigned char keys[KEY_BYTES] = {0};
    if (io->ioctl_ptr(context->device_opaque,fd,EVIOCGABS(ABS_PRESSURE),&pressure) != 0 ||
            io->ioctl_ptr(context->device_opaque,fd,EVIOCGKEY(sizeof(keys)),keys) < 0) return -1;
    return idle_from_state(pressure.value,keys);
}

static int grab_pen(void *opaque, int fd) {
    struct lease_context *context=opaque;
    if (device_io(context)->ioctl_int(context->device_opaque,fd,EVIOCGRAB,1) == 0) return 0;
    return errno==EBUSY ? 1 : -1;
}
static int kernel_release_pen(void *opaque, int fd) {
    struct lease_context *context=opaque;
    /* All authority, channel, formatting and deadline work belongs before
     * this final sample. No fallible work may intervene before EVIOCGRAB(0).
     * evdev offers no atomic idle-and-ungrab operation: safety necessarily
     * assumes no new contact between this sample and the ungrab syscall's
     * linearization point (a syscall-sized hardware/coordinator assumption). */
#ifdef PEN_INPUT_LEASE_ADAPTER_TEST
    if(pen_input_lease_test_before_final_idle!=NULL)
        pen_input_lease_test_before_final_idle(context->device_opaque);
#endif
    if(pen_idle(context,fd)!=0)return -1;
    return device_io(context)->ioctl_int(context->device_opaque,fd,EVIOCGRAB,0);
}
static int close_pen(void *opaque, int fd) {
    struct lease_context *context=opaque;
    return device_io(context)->close_fd(context->device_opaque,fd);
}

static int boottime_ms(void *unused, uint64_t *value) {
    struct timespec now; (void)unused;
    if (clock_gettime(CLOCK_BOOTTIME,&now) != 0 || now.tv_sec < 0 ||
            (uint64_t)now.tv_sec > UINT64_MAX/1000u) return -1;
    *value=(uint64_t)now.tv_sec*1000u+(uint64_t)now.tv_nsec/1000000u;
    return 0;
}

static int random_guardian_session(char output[TOKEN_HEX_LENGTH+1]) {
    static const char hex[]="0123456789abcdef";
    unsigned char random_bytes[HASH_LENGTH];
    size_t used=0;
    while(used<sizeof(random_bytes)) {
        /* Prepared before EVIOCGRAB: entropy failure cannot acquire a grab. */
        ssize_t got=getrandom(random_bytes+used,sizeof(random_bytes)-used,GRND_NONBLOCK);
        if(got<=0)return -1;
        used+=(size_t)got;
    }
    for(size_t index=0;index<sizeof(random_bytes);index++) {
        output[index*2]=hex[random_bytes[index]>>4];
        output[index*2+1]=hex[random_bytes[index]&15u];
    }
    output[TOKEN_HEX_LENGTH]='\0';
    memset(random_bytes,0,sizeof(random_bytes));
    return 0;
}

static int prepare_guardian(void *opaque,int held_fd,int standby_fd) {
    struct lease_context *context=opaque;
    if(held_fd<0||standby_fd<0||held_fd==standby_fd||
            context->guardian_session_prepared||verify_device(context,held_fd)!=0||
            verify_device(context,standby_fd)!=0||same_pen(context,held_fd,standby_fd)!=0||
            random_guardian_session(context->guardian_session)!=0)return -1;
    context->standby_fd=standby_fd;
    context->standby_acquired=0;
    context->guardian_session_prepared=1;
    return 0;
}

static int process_snapshot(pid_t pid,uint64_t *value,char *state) {
    char path[64],record[1024];
    int fd,length;
    ssize_t got;
    char *at,*end;
    if(pid<=1||value==NULL)return -1;
    length=snprintf(path,sizeof(path),"/proc/%ld/stat",(long)pid);
    if(length<=0||(size_t)length>=sizeof(path))return -1;
    fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    if(fd<0)return -1;
    got=read(fd,record,sizeof(record)-1);
    if(close(fd)!=0||got<=0||(size_t)got>=sizeof(record)-1)return -1;
    record[got]='\0';
    at=strrchr(record,')');
    if(at==NULL||at[1]!=' ')return -1;
    at+=2;
    for(int field=3;field<=22;field++) {
        while(*at==' ')at++;
        if(*at=='\0'||*at=='\n')return -1;
        end=at;
        while(*end!='\0'&&*end!=' '&&*end!='\n')end++;
        if(field==3) {
            if(end-at!=1)return -1;
            if(state!=NULL)*state=*at;
        }
        if(field==22) {
            char saved=*end;
            unsigned long long parsed;
            char *parsed_end=NULL;
            *end='\0'; errno=0; parsed=strtoull(at,&parsed_end,10); *end=saved;
            if(errno!=0||parsed==0||parsed_end==NULL||parsed_end!=end)return -1;
            *value=(uint64_t)parsed;
            return 0;
        }
        at=end;
    }
    return -1;
}

static int process_starttime(pid_t pid,uint64_t *value) {
    return process_snapshot(pid,value,NULL);
}

static int packet_send_now(int fd,const char *record) {
    struct pollfd endpoint={fd,POLLOUT,0};
    size_t length=strlen(record);
    ssize_t sent;
    if(length==0||length>=GUARDIAN_RECORD_BYTES||
            poll(&endpoint,1,0)!=1||(endpoint.revents&POLLOUT)==0||
            (endpoint.revents&(POLLERR|POLLHUP|POLLNVAL))!=0)return -1;
    sent=send(fd,record,length,MSG_DONTWAIT|MSG_NOSIGNAL);
    return sent==(ssize_t)length?0:-1;
}

/* 1 exact packet, 0 no packet, -1 malformed/error, -2 peer closed/reset. */
static int packet_receive_now(int fd,char record[GUARDIAN_RECORD_BYTES]) {
    unsigned char bytes[GUARDIAN_RECORD_BYTES];
    ssize_t got=recv(fd,bytes,sizeof(bytes)-1,MSG_DONTWAIT|MSG_TRUNC);
    if(got<0&&(errno==EAGAIN||errno==EWOULDBLOCK))return 0;
    if(got<0&&errno==EINTR)return 0;
    /* A killed peer can surface as ECONNRESET rather than a zero-length read
     * on SOCK_SEQPACKET.  Both are authenticated channel loss, not a forged
     * protocol record, and must enter the same guardian-owned orphan path. */
    if(got<0&&(errno==ECONNRESET||errno==ENOTCONN))return -2;
    if(got<0)return -1;
    if(got==0)return -2;
    if((size_t)got>=sizeof(bytes)||memchr(bytes,'\0',(size_t)got)!=NULL)return -1;
    memcpy(record,bytes,(size_t)got);record[got]='\0';
    return 1;
}

static int packet_wait_exact(int fd,const char *expected,uint64_t deadline) {
    for(;;) {
        char record[GUARDIAN_RECORD_BYTES];
        uint64_t now;
        int received=packet_receive_now(fd,record);
        if(received==1)return strcmp(record,expected)==0?0:-1;
        if(received<0)return -1;
        if(boottime_ms(NULL,&now)!=0||now>=deadline)return -1;
        {
            struct pollfd endpoint={fd,POLLIN|POLLHUP,0};
            int delay=(int)((deadline-now)>25u?25u:(deadline-now));
            int waited=poll(&endpoint,1,delay);
            if(waited<0&&errno!=EINTR)return -1;
            if(waited>0&&(endpoint.revents&(POLLERR|POLLNVAL))!=0)return -1;
        }
    }
}

static int bounded_protocol_deadline(uint64_t absolute_deadline,uint64_t *result) {
    uint64_t now,candidate;
    if(boottime_ms(NULL,&now)!=0||now>=absolute_deadline||
            UINT64_MAX-now<GUARDIAN_PROTOCOL_GRACE_MS)return -1;
    candidate=now+GUARDIAN_PROTOCOL_GRACE_MS;
    *result=candidate<absolute_deadline?candidate:absolute_deadline;
    return 0;
}

static int guardian_worker_live_at_commit(const struct lease_context *context,
        int worker_fd,pid_t worker_pid,uint64_t worker_starttime) {
    struct pollfd endpoint={worker_fd,POLLIN|POLLHUP,0};
    uint64_t current_worker=0,current_guardian=0;
    char worker_state='\0',guardian_state='\0',byte;
    ssize_t peeked;
    int polled;
    if(worker_fd<0||worker_pid<=1||getppid()!=worker_pid||
            getpid()!=context->guardian_pid||
            process_snapshot(worker_pid,&current_worker,&worker_state)!=0||
            process_snapshot(context->guardian_pid,&current_guardian,&guardian_state)!=0||
            current_worker!=worker_starttime||
            current_guardian!=context->guardian_starttime||
            worker_state=='Z'||worker_state=='X'||worker_state=='x'||
            guardian_state=='Z'||guardian_state=='X'||guardian_state=='x')return -1;
    polled=poll(&endpoint,1,0);
    if(polled<0||(endpoint.revents&(POLLIN|POLLERR|POLLHUP|POLLNVAL))!=0)return -1;
    peeked=recv(worker_fd,&byte,1,MSG_PEEK|MSG_DONTWAIT|MSG_TRUNC);
    if(peeked<0&&(errno==EAGAIN||errno==EWOULDBLOCK))return 0;
    return -1;
}

static int guardian_fd_is_kept(int fd,const int *keep,size_t keep_count) {
    for(size_t index=0;index<keep_count;index++)if(fd==keep[index])return 1;
    return 0;
}

static int exact_proc_fd_name(const char *name,int *value) {
    char *end=NULL;long parsed;
    if(name==NULL||*name=='\0')return -1;
    errno=0;parsed=strtol(name,&end,10);
    if(errno!=0||end==name||*end!='\0'||parsed<0||parsed>INT_MAX)return -1;
    *value=(int)parsed;return 0;
}

static int same_fd_identity(const struct stat *left,const struct stat *right) {
    return left->st_dev==right->st_dev && left->st_ino==right->st_ino &&
        left->st_rdev==right->st_rdev && left->st_mode==right->st_mode;
}

static int worker_close_or_reject_unrelated_fds(struct lease_context *context) {
    const int keep[4]={context->authority_fd,context->control_fd,
        context->phase_fd,context->status_fd};
    const struct stat expected[4]={context->authority_identity,
        context->control_identity,context->phase_identity,context->status_identity};
    DIR *directory;
    struct dirent *entry;
    int scan_fd=-1,result=0,alias_found=0;
#ifdef PEN_INPUT_LEASE_ADAPTER_TEST
    if(!pen_input_lease_test_enable_worker_fd_sweep)return 0;
#endif
    for(size_t index=0;index<4;index++) {
        struct stat actual;
        if(keep[index]<3||fstat(keep[index],&actual)!=0||
                !same_fd_identity(&actual,&expected[index]))return -1;
        for(size_t other=index+1;other<4;other++)if(keep[index]==keep[other])return -1;
    }
    scan_fd=open("/proc/self/fd",O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    if(scan_fd<0)return -1;
    directory=fdopendir(scan_fd);
    if(directory==NULL){(void)close(scan_fd);return -1;}
    errno=0;
    while((entry=readdir(directory))!=NULL) {
        int fd,is_kept=0;
        struct stat actual;
        if(strcmp(entry->d_name,".")==0||strcmp(entry->d_name,"..")==0)continue;
        if(exact_proc_fd_name(entry->d_name,&fd)!=0){result=-1;break;}
        if(fd==scan_fd)continue;
        for(size_t index=0;index<4;index++)if(fd==keep[index]){is_kept=1;break;}
        if(is_kept)continue;
        if(fstat(fd,&actual)!=0){result=-1;break;}
        for(size_t index=0;index<4;index++)
            if(same_fd_identity(&actual,&expected[index]))alias_found=1;
        if(close(fd)!=0&&errno!=EBADF){result=-1;break;}
        errno=0;
    }
    if(entry==NULL&&errno!=0)result=-1;
    if(closedir(directory)!=0)result=-1;
    if(result!=0)return -1;
    /* A new enumeration both proves the sweep and defeats an inherited
     * descriptor above a lowered soft RLIMIT_NOFILE. */
    scan_fd=open("/proc/self/fd",O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    if(scan_fd<0)return -1;
    directory=fdopendir(scan_fd);
    if(directory==NULL){(void)close(scan_fd);return -1;}
    errno=0;
    while((entry=readdir(directory))!=NULL) {
        int fd,is_kept=0;
        if(strcmp(entry->d_name,".")==0||strcmp(entry->d_name,"..")==0)continue;
        if(exact_proc_fd_name(entry->d_name,&fd)!=0){result=-1;break;}
        if(fd==scan_fd)continue;
        for(size_t index=0;index<4;index++)if(fd==keep[index]){is_kept=1;break;}
        if(!is_kept){result=-1;break;}
    }
    if(entry==NULL&&errno!=0)result=-1;
    if(closedir(directory)!=0)result=-1;
    for(size_t index=0;result==0&&index<4;index++) {
        struct stat actual;
        if(fstat(keep[index],&actual)!=0||!same_fd_identity(&actual,&expected[index]))result=-1;
    }
    return result==0&&!alias_found?0:-1;
}

static int guardian_sweep_or_prove_fds(const int *keep,size_t keep_count,
        int close_unknown) {
    int scan_fd=open("/proc/self/fd",O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    DIR *directory;
    struct dirent *entry;
    int result=0;
    if(scan_fd<0)return -1;
    directory=fdopendir(scan_fd);
    if(directory==NULL){close(scan_fd);return -1;}
    errno=0;
    while((entry=readdir(directory))!=NULL) {
        int fd;
        if(strcmp(entry->d_name,".")==0||strcmp(entry->d_name,"..")==0)continue;
        if(exact_proc_fd_name(entry->d_name,&fd)!=0){result=-1;break;}
        if(fd==scan_fd||guardian_fd_is_kept(fd,keep,keep_count))continue;
        if(!close_unknown){result=-1;break;}
        if(close(fd)!=0&&errno!=EBADF){result=-1;break;}
        errno=0;
    }
    if(entry==NULL&&errno!=0)result=-1;
    if(closedir(directory)!=0)result=-1;
    return result;
}

static int close_unrelated_guardian_fds(const int *keep,size_t keep_count) {
    int ordered[8];
#ifdef PEN_INPUT_LEASE_ADAPTER_TEST
    if(pen_input_lease_test_fail_guardian_fd_sweep)return -1;
#endif
    if(keep_count>sizeof(ordered)/sizeof(ordered[0]))return -1;
    for(size_t index=0;index<keep_count;index++) {
        if(keep[index]<0)return -1;
        ordered[index]=keep[index];
    }
    for(size_t left=0;left<keep_count;left++)for(size_t right=left+1;right<keep_count;right++)
        if(ordered[right]<ordered[left]){int swap=ordered[left];ordered[left]=ordered[right];ordered[right]=swap;}
    for(size_t index=0;index<keep_count;index++) {
        if(index>0&&ordered[index]==ordered[index-1])return -1;
    }
    /* /proc/self/fd enumerates the actual inherited descriptor table rather
     * than guessing an upper bound from the mutable soft RLIMIT_NOFILE. A
     * second fresh enumeration proves that only the exact allowlist remains. */
    return guardian_sweep_or_prove_fds(ordered,keep_count,1)==0&&
        guardian_sweep_or_prove_fds(ordered,keep_count,0)==0?0:-1;
}

static int guardian_bound_suffix(const struct lease_context *context,
        char *record,size_t capacity,const char *prefix) {
    int length=snprintf(record,capacity,
        "%s token=%s guardian_pid=%ld guardian_starttime=%llu guardian_session=%s\n",
        prefix,context->token,(long)context->guardian_pid,
        (unsigned long long)context->guardian_starttime,context->guardian_session);
    return length>0&&(size_t)length<capacity?0:-1;
}

static int guardian_external_records(const struct lease_context *context,
        char *release,size_t release_capacity,char *phase,size_t phase_capacity) {
    int first=snprintf(release,release_capacity,
        "RELEASE %s guardian_pid=%ld guardian_starttime=%llu guardian_session=%s\n",
        context->token,(long)context->guardian_pid,
        (unsigned long long)context->guardian_starttime,context->guardian_session);
    int second=snprintf(phase,phase_capacity,
        "PHASE DESTROYED FINAL %s guardian_pid=%ld guardian_starttime=%llu guardian_session=%s\n",
        context->token,(long)context->guardian_pid,
        (unsigned long long)context->guardian_starttime,context->guardian_session);
    return first>0&&(size_t)first<release_capacity&&second>0&&
        (size_t)second<phase_capacity?0:-1;
}

/* Progress records prove liveness, not permission to extend the original
 * contact deadline. The total legitimate idle wait can span many heartbeats. */
static int wait_final_ack(struct lease_context *context,const char *ack,
        uint64_t absolute_deadline,uint64_t *exit_deadline) {
    char progress[GUARDIAN_RECORD_BYTES],record[GUARDIAN_RECORD_BYTES];
    uint64_t now,silence,last_progress=0;
    size_t prefix_length;
    int result=-1;
    if(guardian_bound_suffix(context,progress,sizeof(progress),"GUARDIAN_PROGRESS")!=0||
            boottime_ms(NULL,&now)!=0||UINT64_MAX-now<GUARDIAN_SILENCE_MS)return -2;
    silence=now+GUARDIAN_SILENCE_MS;
    prefix_length=strlen(progress)-1;
    progress[prefix_length]='\0';
    for(;;) {
        int received=packet_receive_now(context->guardian_fd,record);
        if(received==1) {
            if(strcmp(record,ack)==0){result=0;break;}
            char *end=NULL;unsigned long long emitted;
            static const char stamp[]=" boottime_ms=";
            if(strncmp(record,progress,prefix_length)!=0||
                    strncmp(record+prefix_length,stamp,sizeof(stamp)-1)!=0)break;
            const char *digits=record+prefix_length+sizeof(stamp)-1;
            if(*digits<'0'||*digits>'9')break;
            errno=0;emitted=strtoull(digits,&end,10);
            if(errno!=0||end==NULL||strcmp(end,"\n")!=0||emitted<=last_progress)break;
            if(boottime_ms(NULL,&now)!=0||UINT64_MAX-now<GUARDIAN_SILENCE_MS)return -2;
            if(emitted>now||now-emitted>=GUARDIAN_SILENCE_MS)return -2;
            last_progress=(uint64_t)emitted;silence=last_progress+GUARDIAN_SILENCE_MS;
        } else if(received<0)break;
        if(boottime_ms(NULL,&now)!=0||now>=absolute_deadline||now>=silence)return -2;
        (void)poll(NULL,0,10);
    }
    if(boottime_ms(NULL,&now)!=0||UINT64_MAX-now<GUARDIAN_SILENCE_MS)return -2;
    *exit_deadline=now+GUARDIAN_SILENCE_MS;
    if(*exit_deadline>absolute_deadline)*exit_deadline=absolute_deadline;
    return result;
}

static void guardian_hold_forever(struct lease_context *context,int worker_fd,
        const char *stage,int notify_worker) {
    char status[GUARDIAN_RECORD_BYTES],failure[GUARDIAN_RECORD_BYTES];
    int length=snprintf(status,sizeof(status),
        "PEN_INPUT_LEASE_FAILED token=%s stage=%s held=true safe_idle_handoff=false reboot_required=true guardian_pid=%ld guardian_starttime=%llu guardian_session=%s\n",
        context->token,stage,(long)context->guardian_pid,
        (unsigned long long)context->guardian_starttime,context->guardian_session);
    if(length>0&&(size_t)length<sizeof(status)) (void)status_record(context,status);
    int failure_valid=guardian_bound_suffix(context,failure,sizeof(failure),"GUARDIAN_FAILED")==0;
    if(notify_worker&&worker_fd>=0&&failure_valid)(void)packet_send_now(worker_fd,failure);
    /* Held quarantine remains responsive. In particular, a healthy emergency
     * standby-grab holder must not be mistaken for a hung status owner. */
    for(;;) {
        char record[GUARDIAN_RECORD_BYTES],ping[GUARDIAN_RECORD_BYTES];
        if(failure_valid&&worker_fd>=0&&packet_receive_now(worker_fd,record)==1&&
                guardian_bound_suffix(context,ping,sizeof(ping),"GUARDIAN_PING")==0&&
                strcmp(record,ping)==0)
            (void)packet_send_now(worker_fd,failure);
        (void)poll(NULL,0,25);
    }
}

static int authority_equal(const struct pen_authority *left,
        const struct pen_authority *right) {
    return left->node_dev==right->node_dev&&left->node_ino==right->node_ino&&
        left->node_rdev==right->node_rdev&&left->node_mode==right->node_mode&&
        constant_equal(left->identity_hash,right->identity_hash,HASH_LENGTH)&&
        constant_equal(left->snapshot_hash,right->snapshot_hash,HASH_LENGTH);
}

static int exact_empty_endpoint(int fd,int access,const struct stat *expected,
        short required_events) {
    struct stat actual;
    int available=-1;
    return live_pipe_endpoint(fd,access,required_events,
            POLLERR|POLLHUP|POLLNVAL,&actual)==0&&
        same_fd_identity(&actual,expected)&&available_bytes(fd,&available)==0&&
        available==0?0:-1;
}

static int guardian_ready_commit_admission(struct lease_context *context,
        int worker_fd,int held_fd,pid_t worker_pid,uint64_t deadline) {
    struct pen_authority authority=context->authority;
    struct stat authority_identity=context->authority_identity;
    unsigned char authority_file_hash[HASH_LENGTH];
    int keep[7]={worker_fd,held_fd,context->authority_fd,context->control_fd,
        context->phase_fd,context->status_fd,context->standby_fd};
    uint64_t now;
    memcpy(authority_file_hash,context->authority_file_hash,HASH_LENGTH);
    if(!device_io_valid(context)||!context->initial_phase_proved||
            exact_empty_endpoint(context->control_fd,O_RDONLY,
                &context->control_identity,0)!=0||
            exact_empty_endpoint(context->phase_fd,O_RDONLY,
                &context->phase_identity,0)!=0||
            exact_empty_endpoint(context->status_fd,O_WRONLY,
                &context->status_identity,POLLOUT)!=0||
            read_authority_file(context)!=0||
            !authority_equal(&authority,&context->authority)||
            !same_fd_identity(&authority_identity,&context->authority_identity)||
            !constant_equal(authority_file_hash,context->authority_file_hash,HASH_LENGTH)||
            guardian_sweep_or_prove_fds(keep,7,0)!=0||
            revalidate(context,held_fd)!=0||prove_exclusive(context,held_fd)!=0||
            boottime_ms(NULL,&now)!=0||now>=deadline||
            guardian_worker_live_at_commit(context,worker_fd,worker_pid,
                context->worker_starttime)!=0)
        return -1;
#ifndef PEN_INPUT_LEASE_ADAPTER_TEST
    if(fcntl(held_fd,F_GETFD)<0)return -1;
#endif
    /* This is deliberately the final potentially live pen-state sample. The
     * caller performs no fallible admission work before the READY write. */
    return pen_idle(context,held_fd)==0?0:-1;
}

static int guardian_final_channels_clean(struct lease_context *context,
        int release_received,int phase_received) {
    int endpoints[2]={context->control_fd,context->phase_fd};
    const struct stat *identities[2]={&context->control_identity,&context->phase_identity};
    if(!phase_received)return -1;
    for(unsigned index=0;index<2;index++) {
        struct stat actual;
        struct pollfd endpoint={endpoints[index],POLLIN|POLLHUP,0};
        int available=-1;char trailing;
        if(pipe_endpoint(endpoints[index],O_RDONLY,&actual)!=0||
                !same_fd_identity(&actual,identities[index])||
                available_bytes(endpoints[index],&available)!=0||available!=0||
                poll(&endpoint,1,0)<0||
                (endpoint.revents&(POLLERR|POLLNVAL))!=0)return -1;
        if((endpoint.revents&POLLHUP)==0)return 1;
        if(read(endpoints[index],&trailing,1)!=0)return -1;
    }
    /* Integration requires exclusive, nonleaked anonymous-pipe peers. Each
     * final writer performs one atomic record and closes every write alias.
     * EOF/HUP plus zero trailing bytes seals the transcript against all later
     * replay. Timeout has zero control records and also closes its writer. */
    return release_received==0||release_received==1?0:-1;
}

static int guardian_wait_safe_idle(struct lease_context *context,int worker_fd,int held_fd,
        uint64_t deadline) {
    uint64_t next_progress=0;
    char progress[GUARDIAN_RECORD_BYTES],ping[GUARDIAN_RECORD_BYTES],pong[GUARDIAN_RECORD_BYTES];
    if(worker_fd>=0&&(guardian_bound_suffix(context,progress,sizeof(progress),"GUARDIAN_PROGRESS")!=0||
            guardian_bound_suffix(context,ping,sizeof(ping),"GUARDIAN_PING")!=0||
            guardian_bound_suffix(context,pong,sizeof(pong),"GUARDIAN_ALIVE")!=0))return -1;
    for(;;) {
        uint64_t now;
        int idle;
        if(boottime_ms(NULL,&now)!=0)return -1;
        if(worker_fd>=0) {
            char command[GUARDIAN_RECORD_BYTES];
            int received=packet_receive_now(worker_fd,command);
            if(received<0)return -1;
            if(received==1&&(strcmp(command,ping)!=0||packet_send_now(worker_fd,pong)!=0))return -1;
            if(now>=next_progress) {
                char stamped[GUARDIAN_RECORD_BYTES];
                int length=snprintf(stamped,sizeof(stamped),"%.*s boottime_ms=%llu\n",
                    (int)strlen(progress)-1,progress,(unsigned long long)now);
                if(length<=0||(size_t)length>=sizeof(stamped)||
                        UINT64_MAX-now<GUARDIAN_PROGRESS_MS||packet_send_now(worker_fd,stamped)!=0)return -1;
                next_progress=now+GUARDIAN_PROGRESS_MS;
            }
        }
        if(revalidate(context,held_fd)!=0||
                prove_exclusive(context,held_fd)!=0||
                status_consumer_alive(context)!=0)return -1;
        idle=pen_idle(context,held_fd);
        if(idle<0)return -1;
        if(idle==0)return 0;
        if(boottime_ms(NULL,&now)!=0||now>=deadline)return -1;
        (void)poll(NULL,0,(int)((deadline-now)>10u?10u:(deadline-now)));
    }
}

static int guardian_safe_release(struct lease_context *context,int worker_fd,
        int held_fd,enum pen_input_lease_end_reason reason,uint64_t deadline,
        int release_received,int phase_received) {
    char terminal[GUARDIAN_RECORD_BYTES],ack[GUARDIAN_RECORD_BYTES];
    int length;
    int terminal_result,ack_result=0;
    length=snprintf(terminal,sizeof(terminal),
        "PEN_INPUT_LEASE_RELEASED token=%s reason=%s held=false safe_idle_handoff=true guardian_pid=%ld guardian_starttime=%llu guardian_session=%s\n",
        context->token,end_reason(reason),(long)context->guardian_pid,
        (unsigned long long)context->guardian_starttime,context->guardian_session);
    if(length<=0||(size_t)length>=sizeof(terminal)||
            (worker_fd>=0&&guardian_bound_suffix(context,ack,sizeof(ack),
                "GUARDIAN_RELEASED")!=0))return -1;
#ifdef PEN_INPUT_LEASE_ADAPTER_TEST
    if(pen_input_lease_test_before_guardian_release!=NULL&&
            pen_input_lease_test_guardian_contact_ms>0)
        pen_input_lease_test_before_guardian_release(context->device_opaque,
            pen_input_lease_test_guardian_contact_ms);
#endif
    if(guardian_final_channels_clean(context,release_received,phase_received)!=0||
            guardian_wait_safe_idle(context,worker_fd,held_fd,deadline)!=0||
            guardian_final_channels_clean(context,release_received,phase_received)!=0)
        return -1;
    if(kernel_release_pen(context,held_fd)!=0)return -1;
    /* The exact final authority and safe-idle proof already authorized this
     * handoff.  Once ungrab succeeds it is forbidden to enter a quarantine
     * that falsely claims EVIOCGRAB is still held.  Exit status 118 tells the
     * surviving worker that release was safe but one terminal notification
     * endpoint disappeared in the post-ungrab race; the external coordinator
     * observes status HUP and must perform its documented reacquisition proof. */
    terminal_result=status_record(context,terminal);
    if(terminal_result==0&&worker_fd>=0)ack_result=packet_send_now(worker_fd,ack);
    return terminal_result==0&&ack_result==0?0:1;
}

static void guardian_child(struct lease_context context,int worker_fd,int held_fd,
        pid_t worker_pid,int64_t coordinator_parent,uint64_t deadline) {
    char hello[GUARDIAN_RECORD_BYTES],expected[GUARDIAN_RECORD_BYTES];
    char reply[GUARDIAN_RECORD_BYTES],release[GUARDIAN_RECORD_BYTES];
    char phase[GUARDIAN_RECORD_BYTES],record[GUARDIAN_RECORD_BYTES];
    int keep[7],release_received=0,phase_received=0,ready_prepared=0,ready=0,end_sent=0;
    int worker_alive=1;
    uint64_t state_deadline=context.guardian_handshake_deadline_boottime;
    uint64_t post_end_deadline=0;
    enum pen_input_lease_end_reason reason=PEN_INPUT_LEASE_END_ERROR;
    context.guardian_fd=-1;
    context.guardian_pid=getpid();
    context.guardian_ready=0;
    keep[0]=worker_fd;keep[1]=held_fd;keep[2]=context.authority_fd;
    keep[3]=context.control_fd;keep[4]=context.phase_fd;keep[5]=context.status_fd;
    keep[6]=context.standby_fd;
    /* Close every unrelated inherited descriptor before any fallible identity
     * or session setup. If the complete sweep itself cannot be proved, exit:
     * the worker retains the grabbed OFD and the guardian-owned status pipe
     * closes, providing a bounded fail-closed HUP without leaking arbitrary
     * launcher descriptors into an indefinite quarantine. */
    if(close_unrelated_guardian_fds(keep,7)!=0)_exit(119);
    if(prctl(PR_SET_PDEATHSIG,0,0,0,0)!=0||setsid()<0||
            process_starttime(context.guardian_pid,&context.guardian_starttime)!=0||
            guardian_worker_live_at_commit(&context,worker_fd,worker_pid,
                context.worker_starttime)!=0)
        guardian_hold_forever(&context,worker_fd,"guardian_identity",1);
#ifdef PEN_INPUT_LEASE_ADAPTER_TEST
    if(pen_input_lease_test_kill_worker_handshake_stage==1) {
        (void)kill(worker_pid,SIGKILL);
        guardian_hold_forever(&context,worker_fd,
            "worker_lost_handshake_stage_1",0);
    }
#endif
    if(snprintf(hello,sizeof(hello),
            "GUARDIAN_HELLO token=%s session=%s pid=%ld starttime=%llu worker_starttime=%llu\n",
            context.token,context.guardian_session,(long)context.guardian_pid,
            (unsigned long long)context.guardian_starttime,
            (unsigned long long)context.worker_starttime)<=0||
            packet_send_now(worker_fd,hello)!=0)
        guardian_hold_forever(&context,worker_fd,"guardian_hello",1);
#ifdef PEN_INPUT_LEASE_ADAPTER_TEST
    if(pen_input_lease_test_kill_worker_handshake_stage==2) {
        (void)kill(worker_pid,SIGKILL);
        guardian_hold_forever(&context,worker_fd,
            "worker_lost_handshake_stage_2",0);
    }
#endif
    if(snprintf(expected,sizeof(expected),
            "GUARDIAN_BIND token=%s session=%s worker_pid=%ld worker_starttime=%llu coordinator_parent=%lld deadline=%llu\n",
            context.token,context.guardian_session,(long)worker_pid,
            (unsigned long long)context.worker_starttime,
            (long long)coordinator_parent,(unsigned long long)deadline)<=0||
            packet_wait_exact(worker_fd,expected,state_deadline)!=0)
        guardian_hold_forever(&context,worker_fd,"guardian_bind",1);
#ifdef PEN_INPUT_LEASE_ADAPTER_TEST
    if(pen_input_lease_test_kill_worker_handshake_stage==3) {
        (void)kill(worker_pid,SIGKILL);
        guardian_hold_forever(&context,worker_fd,
            "worker_lost_handshake_stage_3",0);
    }
#endif
    if(guardian_bound_suffix(&context,reply,sizeof(reply),"GUARDIAN_BOUND")!=0||
            packet_send_now(worker_fd,reply)!=0)
        guardian_hold_forever(&context,worker_fd,"guardian_bound",1);
#ifdef PEN_INPUT_LEASE_ADAPTER_TEST
    if(pen_input_lease_test_stop_worker_stage==1)
        (void)kill(worker_pid,SIGSTOP);
    if(pen_input_lease_test_kill_worker_handshake_stage==4) {
        (void)kill(worker_pid,SIGKILL);
        guardian_hold_forever(&context,worker_fd,
            "worker_lost_handshake_stage_4",0);
    }
#endif
    if(guardian_external_records(&context,release,sizeof(release),phase,sizeof(phase))!=0)
        guardian_hold_forever(&context,worker_fd,"guardian_external_records",1);
    if(bounded_protocol_deadline(deadline,&state_deadline)!=0)
        guardian_hold_forever(&context,worker_fd,"guardian_protocol_deadline",1);

    for(;;) {
        uint64_t now;
        int packet;
        struct pollfd endpoints[4];
        if(status_consumer_alive(&context)!=0)
            guardian_hold_forever(&context,worker_fd,"status_consumer_lost",worker_alive);
        if(revalidate(&context,held_fd)!=0||prove_exclusive(&context,held_fd)!=0)
            guardian_hold_forever(&context,worker_fd,"guardian_revalidation",worker_alive);
        if(boottime_ms(NULL,&now)!=0)
            guardian_hold_forever(&context,worker_fd,"guardian_clock",worker_alive);
        if(!ready&&now>=state_deadline)
            guardian_hold_forever(&context,worker_fd,"guardian_protocol_deadline",worker_alive);
        if(ready&&end_sent&&post_end_deadline!=0&&now>=post_end_deadline) {
            int released=guardian_safe_release(&context,-1,held_fd,reason,
                deadline,release_received,phase_received);
            if(released<0)guardian_hold_forever(&context,worker_fd,
                "guardian_post_end_deadline",worker_alive);
            (void)close(held_fd);(void)close(context.control_fd);
            (void)close(context.phase_fd);(void)close(context.status_fd);
            if(worker_fd>=0)(void)close(worker_fd);
            _exit(released==0?0:118);
        }

        packet=worker_alive?packet_receive_now(worker_fd,record):0;
        if(packet==-2){
            worker_alive=0;close(worker_fd);worker_fd=-1;
            /* Before READY the coordinator has no published guardian binding
             * with which it could authorize cleanup.  Publish that binding in
             * the sole FAILED record and retain the grab until reboot. */
            if(!ready)guardian_hold_forever(&context,-1,
                "worker_lost_before_ready",0);
        }
        else if(packet<0)guardian_hold_forever(&context,worker_fd,
                "guardian_worker_protocol",worker_alive);
        else if(packet==1) {
            char ping[GUARDIAN_RECORD_BYTES],pong[GUARDIAN_RECORD_BYTES];
            char ready_prepare[GUARDIAN_RECORD_BYTES],ready_prepared_ack[GUARDIAN_RECORD_BYTES];
            char ready_commit[GUARDIAN_RECORD_BYTES],ready_ack[GUARDIAN_RECORD_BYTES];
            char abort_command[GUARDIAN_RECORD_BYTES],abort_ack[GUARDIAN_RECORD_BYTES];
            char safe_release[GUARDIAN_RECORD_BYTES],safe_timeout[GUARDIAN_RECORD_BYTES];
            char worker_failure[GUARDIAN_RECORD_BYTES];
            if(guardian_bound_suffix(&context,ping,sizeof(ping),"GUARDIAN_PING")!=0||
                    guardian_bound_suffix(&context,pong,sizeof(pong),"GUARDIAN_ALIVE")!=0||
                    guardian_bound_suffix(&context,ready_prepare,sizeof(ready_prepare),"GUARDIAN_READY_PREPARE")!=0||
                    guardian_bound_suffix(&context,ready_prepared_ack,sizeof(ready_prepared_ack),"GUARDIAN_READY_PREPARED")!=0||
                    guardian_bound_suffix(&context,ready_commit,sizeof(ready_commit),"GUARDIAN_READY_COMMIT")!=0||
                    guardian_bound_suffix(&context,ready_ack,sizeof(ready_ack),"GUARDIAN_READY_ACK")!=0||
                    guardian_bound_suffix(&context,abort_command,sizeof(abort_command),"GUARDIAN_ABORT_BEFORE_READY")!=0||
                    guardian_bound_suffix(&context,abort_ack,sizeof(abort_ack),"GUARDIAN_ABORTED")!=0||
                    guardian_bound_suffix(&context,safe_release,sizeof(safe_release),"GUARDIAN_SAFE_RELEASE")!=0||
                    guardian_bound_suffix(&context,safe_timeout,sizeof(safe_timeout),"GUARDIAN_SAFE_TIMEOUT")!=0||
                    guardian_bound_suffix(&context,worker_failure,sizeof(worker_failure),"GUARDIAN_WORKER_FAILED")!=0)
                guardian_hold_forever(&context,worker_fd,"guardian_format",worker_alive);
            if(strcmp(record,ping)==0) {
                if(packet_send_now(worker_fd,pong)!=0)
                    guardian_hold_forever(&context,worker_fd,"guardian_ping_reply",worker_alive);
                /* A live worker waiting for pen-up retains release authority.
                 * Grace expiry is a heartbeat failure, not a one-shot timer. */
                if(end_sent&&bounded_protocol_deadline(
                        deadline+GUARDIAN_PROTOCOL_GRACE_MS,&post_end_deadline)!=0)
                    guardian_hold_forever(&context,worker_fd,"guardian_heartbeat_deadline",worker_alive);
            } else if(!ready&&strcmp(record,abort_command)==0) {
                char abort_terminal[GUARDIAN_RECORD_BYTES];
                uint64_t abort_now;
                int terminal_length=snprintf(abort_terminal,sizeof(abort_terminal),
                    "PEN_INPUT_LEASE_FAILED token=%s stage=termination_before_ready held=false safe_idle_handoff=false reboot_required=false guardian_pid=%ld guardian_starttime=%llu guardian_session=%s\n",
                    context.token,(long)context.guardian_pid,
                    (unsigned long long)context.guardian_starttime,
                    context.guardian_session);
                int terminal_result,ack_result;
                if(terminal_length<=0||(size_t)terminal_length>=sizeof(abort_terminal))
                    guardian_hold_forever(&context,worker_fd,
                        "guardian_abort_format",worker_alive);
                if(boottime_ms(NULL,&abort_now)!=0||abort_now>=deadline)
                    guardian_hold_forever(&context,worker_fd,
                        "guardian_abort_deadline",worker_alive);
                if(!context.initial_phase_proved||
                        exact_empty_endpoint(context.control_fd,O_RDONLY,
                            &context.control_identity,0)!=0||
                        exact_empty_endpoint(context.phase_fd,O_RDONLY,
                            &context.phase_identity,0)!=0||
                        status_consumer_alive(&context)!=0||
                        guardian_wait_safe_idle(&context,worker_fd,held_fd,deadline)!=0||
                        exact_empty_endpoint(context.control_fd,O_RDONLY,
                            &context.control_identity,0)!=0||
                        exact_empty_endpoint(context.phase_fd,O_RDONLY,
                            &context.phase_identity,0)!=0||
                        boottime_ms(NULL,&abort_now)!=0||abort_now>=deadline)
                    guardian_hold_forever(&context,worker_fd,
                        "guardian_abort_release",worker_alive);
                if(kernel_release_pen(&context,held_fd)!=0)
                    guardian_hold_forever(&context,worker_fd,
                        "guardian_abort_ungrab",worker_alive);
                terminal_result=status_record(&context,abort_terminal);
#ifdef PEN_INPUT_LEASE_ADAPTER_TEST
                ack_result=pen_input_lease_test_drop_abort_ack?-1:
                    packet_send_now(worker_fd,abort_ack);
#else
                ack_result=packet_send_now(worker_fd,abort_ack);
#endif
                (void)close(held_fd);(void)close(context.control_fd);
                (void)close(context.phase_fd);(void)close(context.status_fd);
                (void)close(worker_fd);
                _exit(terminal_result==0&&ack_result==0?0:118);
            } else if(!ready&&!ready_prepared&&strcmp(record,ready_prepare)==0) {
                int available_control=-1,available_phase=-1;
                struct stat control_identity,phase_identity;
                if(now>=deadline)guardian_hold_forever(&context,worker_fd,
                    "guardian_ready_deadline",worker_alive);
#ifdef PEN_INPUT_LEASE_ADAPTER_TEST
                if(pen_input_lease_test_kill_worker_after_ready_send==1)
                    (void)poll(NULL,0,20);
                if(pen_input_lease_test_guardian_ready_delay_ms>0)
                    (void)poll(NULL,0,(int)pen_input_lease_test_guardian_ready_delay_ms);
#endif
                if(live_pipe_endpoint(context.control_fd,O_RDONLY,0,
                        POLLIN|POLLERR|POLLHUP|POLLNVAL,&control_identity)!=0)
                    guardian_hold_forever(&context,worker_fd,
                        "guardian_ready_control_liveness",worker_alive);
                if(available_bytes(context.control_fd,&available_control)!=0||
                        available_control!=0)guardian_hold_forever(&context,worker_fd,
                    "guardian_ready_control",worker_alive);
                if(live_pipe_endpoint(context.phase_fd,O_RDONLY,0,
                        POLLIN|POLLERR|POLLHUP|POLLNVAL,&phase_identity)!=0)
                    guardian_hold_forever(&context,worker_fd,
                        "guardian_ready_phase_liveness",worker_alive);
                if(available_bytes(context.phase_fd,&available_phase)!=0||
                        available_phase!=0)guardian_hold_forever(&context,worker_fd,
                    "guardian_ready_phase",worker_alive);
                if(pen_idle(&context,held_fd)!=0)guardian_hold_forever(&context,
                    worker_fd,"guardian_ready_active",worker_alive);
                if(revalidate(&context,held_fd)!=0)guardian_hold_forever(&context,
                    worker_fd,"guardian_ready_identity",worker_alive);
                if(prove_exclusive(&context,held_fd)!=0)guardian_hold_forever(&context,
                    worker_fd,"guardian_ready_exclusivity",worker_alive);
                /* The preceding idle, descriptor, and second-open proofs may
                 * block or be scheduler-delayed. Re-sample both process/socket
                 * authority and the original pre-grab deadline at the exact
                 * prepared-challenge boundary. The separate worker commit is
                 * validated again immediately before READY publication. */
                if(status_consumer_alive(&context)!=0)
                    guardian_hold_forever(&context,worker_fd,
                        "guardian_ready_status_liveness",worker_alive);
                if(live_pipe_endpoint(context.control_fd,O_RDONLY,0,
                        POLLIN|POLLERR|POLLHUP|POLLNVAL,&control_identity)!=0||
                        available_bytes(context.control_fd,&available_control)!=0||
                        available_control!=0)
                    guardian_hold_forever(&context,worker_fd,
                        "guardian_ready_commit_control",worker_alive);
                if(live_pipe_endpoint(context.phase_fd,O_RDONLY,0,
                        POLLIN|POLLERR|POLLHUP|POLLNVAL,&phase_identity)!=0||
                        available_bytes(context.phase_fd,&available_phase)!=0||
                        available_phase!=0)
                    guardian_hold_forever(&context,worker_fd,
                        "guardian_ready_commit_phase",worker_alive);
                if(boottime_ms(NULL,&now)!=0||now>=deadline)
                    guardian_hold_forever(&context,worker_fd,
                        "guardian_ready_commit_deadline",worker_alive);
                if(guardian_worker_live_at_commit(&context,worker_fd,worker_pid,
                        context.worker_starttime)!=0)
                    guardian_hold_forever(&context,worker_fd,
                        "guardian_ready_worker",worker_alive);
                if(packet_send_now(worker_fd,ready_prepared_ack)!=0)
                    guardian_hold_forever(&context,worker_fd,
                        "guardian_ready_prepared_ack",worker_alive);
                ready_prepared=1;
                if(bounded_protocol_deadline(deadline,&state_deadline)!=0)
                    guardian_hold_forever(&context,worker_fd,
                        "guardian_ready_commit_deadline",worker_alive);
#ifdef PEN_INPUT_LEASE_ADAPTER_TEST
                if(pen_input_lease_test_after_ready_prepared!=NULL)
                    pen_input_lease_test_after_ready_prepared(context.device_opaque);
#endif
            } else if(!ready&&ready_prepared&&strcmp(record,ready_commit)==0) {
                char ready_line[GUARDIAN_RECORD_BYTES];
                int length=snprintf(ready_line,sizeof(ready_line),
                    "PEN_INPUT_LEASE_READY token=%s device=" PEN_NODE
                    " held=true timeout_ms=%llu deviceClockDomain=android-boottime-v1 deadline_boottime_ms=%llu guardian_pid=%ld guardian_starttime=%llu guardian_session=%s\n",
                    context.token,(unsigned long long)context.hold_ms,
                    (unsigned long long)deadline,(long)context.guardian_pid,
                    (unsigned long long)context.guardian_starttime,context.guardian_session);
#ifdef PEN_INPUT_LEASE_ADAPTER_TEST
                if(pen_input_lease_test_kill_worker_after_ready_send==2)
                    (void)poll(NULL,0,20);
#endif
                if(length<=0||(size_t)length>=sizeof(ready_line))
                    guardian_hold_forever(&context,worker_fd,
                        "guardian_ready_format",worker_alive);
                if(now>=state_deadline||guardian_ready_commit_admission(&context,
                        worker_fd,held_fd,worker_pid,deadline)!=0)
                    guardian_hold_forever(&context,worker_fd,
                        "guardian_ready_commit_admission",worker_alive);
                if(status_record(&context,ready_line)!=0)
                    guardian_hold_forever(&context,worker_fd,
                        "guardian_ready_status",worker_alive);
                /* The successful external READY write is the sole linearization
                 * point. From here onward ACK/socket loss is a post-READY orphan
                 * handled by this guardian; it can never yield a contradictory
                 * pre-READY FAILED terminal. */
                ready=1;context.guardian_ready=1;
#ifdef PEN_INPUT_LEASE_ADAPTER_TEST
                if(pen_input_lease_test_drop_ready_ack) {
                    worker_alive=0;(void)close(worker_fd);worker_fd=-1;
                } else
#endif
                if(packet_send_now(worker_fd,ready_ack)!=0) {
                    worker_alive=0;(void)close(worker_fd);worker_fd=-1;
                }
            } else if(ready&&end_sent&&
                    ((reason==PEN_INPUT_LEASE_END_RELEASE&&strcmp(record,safe_release)==0)||
                     (reason==PEN_INPUT_LEASE_END_TIMEOUT&&strcmp(record,safe_timeout)==0))) {
                int released=guardian_safe_release(&context,worker_fd,held_fd,reason,
                    deadline,release_received,phase_received);
                if(released<0)
                    guardian_hold_forever(&context,worker_fd,"guardian_release",worker_alive);
                (void)close(held_fd);(void)close(context.control_fd);
                (void)close(context.phase_fd);(void)close(context.status_fd);
                (void)close(worker_fd);_exit(released==0?0:118);
            } else if(strcmp(record,worker_failure)==0) {
                guardian_hold_forever(&context,worker_fd,"worker_failure",worker_alive);
            } else {
                guardian_hold_forever(&context,worker_fd,"guardian_worker_protocol",worker_alive);
            }
        }

        if(ready) {
            if(consume_if_exact(context.control_fd,release,&release_received)!=0)
                guardian_hold_forever(&context,worker_fd,"guardian_release_protocol",worker_alive);
            if(consume_if_exact(context.phase_fd,phase,&phase_received)!=0)
                guardian_hold_forever(&context,worker_fd,"guardian_phase_protocol",worker_alive);
            if(release_received&&phase_received&&!end_sent)reason=PEN_INPUT_LEASE_END_RELEASE;
            else if(now>=deadline&&phase_received&&!end_sent)reason=PEN_INPUT_LEASE_END_TIMEOUT;
            else if(now>=deadline&&!phase_received)
                guardian_hold_forever(&context,worker_fd,"guardian_final_phase",worker_alive);
            if(reason!=PEN_INPUT_LEASE_END_ERROR) {
                int sealed=guardian_final_channels_clean(&context,release_received,phase_received);
                if(sealed<0||(sealed>0&&now>=deadline))
                    guardian_hold_forever(&context,worker_fd,"guardian_final_channels",worker_alive);
                if(sealed>0)reason=PEN_INPUT_LEASE_END_ERROR;
            }
            if(reason!=PEN_INPUT_LEASE_END_ERROR&&end_sent&&!worker_alive) {
                int released=guardian_safe_release(&context,-1,held_fd,reason,
                    deadline,release_received,phase_received);
                if(released<0)guardian_hold_forever(&context,-1,
                    "guardian_worker_lost_after_end",0);
                (void)close(held_fd);(void)close(context.control_fd);
                (void)close(context.phase_fd);(void)close(context.status_fd);
                _exit(released==0?0:118);
            }
            if(reason!=PEN_INPUT_LEASE_END_ERROR&&!end_sent) {
                if(worker_alive) {
                    int length=snprintf(reply,sizeof(reply),
                        "GUARDIAN_END token=%s guardian_pid=%ld guardian_starttime=%llu guardian_session=%s reason=%s release=%d phase=true\n",
                        context.token,(long)context.guardian_pid,
                        (unsigned long long)context.guardian_starttime,
                        context.guardian_session,end_reason(reason),release_received);
                    if(length<=0||(size_t)length>=sizeof(reply)||
                            packet_send_now(worker_fd,reply)!=0) {
                        worker_alive=0;(void)close(worker_fd);worker_fd=-1;
                    } else {
                        end_sent=1;
                        if(UINT64_MAX-deadline<GUARDIAN_PROTOCOL_GRACE_MS)
                            guardian_hold_forever(&context,worker_fd,
                                "guardian_post_end_overflow",worker_alive);
                        if(bounded_protocol_deadline(deadline+GUARDIAN_PROTOCOL_GRACE_MS,
                                &post_end_deadline)!=0)
                            guardian_hold_forever(&context,worker_fd,
                                "guardian_post_end_deadline",worker_alive);
#ifdef PEN_INPUT_LEASE_ADAPTER_TEST
                        if(pen_input_lease_test_kill_worker_after_guardian_end)
                            (void)kill(worker_pid,SIGKILL);
                        if(pen_input_lease_test_stop_worker_stage==2)
                            (void)kill(worker_pid,SIGSTOP);
#endif
                    }
                }
                if(!worker_alive) {
                    int released=guardian_safe_release(&context,-1,held_fd,reason,
                        deadline,release_received,phase_received);
                    if(released<0)
                        guardian_hold_forever(&context,-1,"guardian_orphan_release",0);
                    (void)close(held_fd);(void)close(context.control_fd);
                    (void)close(context.phase_fd);(void)close(context.status_fd);
                    _exit(released==0?0:118);
                }
            }
        }

        endpoints[0].fd=worker_alive?worker_fd:-1;endpoints[0].events=POLLIN|POLLHUP;endpoints[0].revents=0;
        endpoints[1].fd=ready&&!release_received?context.control_fd:-1;endpoints[1].events=POLLIN|POLLHUP;endpoints[1].revents=0;
        endpoints[2].fd=ready&&!phase_received?context.phase_fd:-1;endpoints[2].events=POLLIN|POLLHUP;endpoints[2].revents=0;
        endpoints[3].fd=context.status_fd;endpoints[3].events=0;endpoints[3].revents=0;
        {
            uint64_t wake_deadline=deadline;
            int delay;
            if(!ready&&state_deadline<wake_deadline)wake_deadline=state_deadline;
            if(ready&&end_sent&&post_end_deadline!=0&&post_end_deadline<wake_deadline)
                wake_deadline=post_end_deadline;
            delay=now>=wake_deadline?1:
                (int)((wake_deadline-now)>25u?25u:(wake_deadline-now));
            if(delay<1)delay=1;
            int waited=poll(endpoints,4,delay);
            if(waited<0&&errno!=EINTR)
                guardian_hold_forever(&context,worker_fd,"guardian_poll",worker_alive);
            if((endpoints[1].revents&(POLLERR|POLLNVAL))||
                    (endpoints[2].revents&(POLLERR|POLLNVAL))||
                    (endpoints[3].revents&(POLLERR|POLLHUP|POLLNVAL)))
                guardian_hold_forever(&context,worker_fd,"guardian_endpoint",worker_alive);
            /* HUP may accompany an unread atomic final record. Consume and
             * validate it at the loop head; closed empty control also permits
             * the documented timeout path. Missing final phase fails at the
             * bounded lease deadline. */
        }
    }
}

static int guardian_command(struct lease_context *context,const char *command,
        const char *ack,uint64_t deadline) {
    char request[GUARDIAN_RECORD_BYTES],expected[GUARDIAN_RECORD_BYTES];
    uint64_t state_deadline;
    if(bounded_protocol_deadline(deadline,&state_deadline)!=0)return -1;
    if(guardian_bound_suffix(context,request,sizeof(request),command)!=0||
            guardian_bound_suffix(context,expected,sizeof(expected),ack)!=0||
            packet_send_now(context->guardian_fd,request)!=0)return -1;
#ifdef PEN_INPUT_LEASE_ADAPTER_TEST
    if((pen_input_lease_test_kill_worker_after_ready_send==1&&
            strcmp(command,"GUARDIAN_READY_PREPARE")==0)||
            (pen_input_lease_test_kill_worker_after_ready_send==2&&
            strcmp(command,"GUARDIAN_READY_COMMIT")==0))
        (void)kill(getpid(),SIGKILL);
#endif
    if(packet_wait_exact(context->guardian_fd,expected,state_deadline)!=0)return -1;
    return 0;
}

static int start_guardian(void *opaque,int held_fd,uint64_t deadline,int64_t parent) {
    struct lease_context *context=opaque;
    int channel[2]={-1,-1};
    pid_t child;
    char hello[GUARDIAN_RECORD_BYTES],bind[GUARDIAN_RECORD_BYTES],bound[GUARDIAN_RECORD_BYTES];
    if(context->guardian_started||!context->guardian_session_prepared||
            context->standby_fd<0||
            process_starttime(getpid(),&context->worker_starttime)!=0||
            bounded_protocol_deadline(deadline,
                &context->guardian_handshake_deadline_boottime)!=0)
        return 1;
#ifdef PEN_INPUT_LEASE_ADAPTER_TEST
    if(pen_input_lease_test_guardian_no_child_failure==1)return 1;
#endif
    if(socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_NONBLOCK|SOCK_CLOEXEC,0,channel)!=0)
        return 1;
#ifdef PEN_INPUT_LEASE_ADAPTER_TEST
    if(pen_input_lease_test_guardian_no_child_failure==2) {
        (void)close(channel[0]);(void)close(channel[1]);return 1;
    }
#endif
    /* This process is deliberately single threaded. fork() gives the guardian
     * the same grabbed evdev open-file description, not a second independently
     * acquired handle. Either process can therefore die while the other keeps
     * EVIOCGRAB alive. The unavoidable kernel boundary is simultaneous loss
     * of both holders (SIGKILL of both, kernel crash, or power loss); the
     * external coordinator must treat status HUP without RELEASED as requiring
     * device-level recovery and an explicit reacquisition proof. */
    child=fork();
    if(child<0){close(channel[0]);close(channel[1]);return 1;}
    if(child==0) {
        close(channel[0]);
        guardian_child(*context,channel[1],held_fd,getppid(),parent,deadline);
        _exit(117);
    }
    close(channel[1]);
    context->guardian_fd=channel[0];context->guardian_pid=child;
    context->guardian_started=1;context->guardian_deadline_boottime=deadline;
    /* Transfer sole external-status ownership at fork, not at READY. The child
     * inherited the write endpoint atomically; guardian death at any handshake
     * boundary therefore becomes an immediate coordinator-visible HUP rather
     * than being masked forever by a quarantined worker copy. */
    if(context->status_fd>=0){(void)close(context->status_fd);context->status_fd=-1;}
    if(process_starttime(child,&context->guardian_starttime)!=0||
            snprintf(hello,sizeof(hello),
                "GUARDIAN_HELLO token=%s session=%s pid=%ld starttime=%llu worker_starttime=%llu\n",
                context->token,context->guardian_session,(long)child,
                (unsigned long long)context->guardian_starttime,
                (unsigned long long)context->worker_starttime)<=0||
            packet_wait_exact(context->guardian_fd,hello,
                context->guardian_handshake_deadline_boottime)!=0||
            snprintf(bind,sizeof(bind),
                "GUARDIAN_BIND token=%s session=%s worker_pid=%ld worker_starttime=%llu coordinator_parent=%lld deadline=%llu\n",
                context->token,context->guardian_session,(long)getpid(),
                (unsigned long long)context->worker_starttime,
                (long long)parent,(unsigned long long)deadline)<=0||
            packet_send_now(context->guardian_fd,bind)!=0||
            guardian_bound_suffix(context,bound,sizeof(bound),"GUARDIAN_BOUND")!=0||
            packet_wait_exact(context->guardian_fd,bound,
                context->guardian_handshake_deadline_boottime)!=0)return -1;
    if(close(context->control_fd)!=0||close(context->phase_fd)!=0)return -1;
    context->control_fd=-1;context->phase_fd=-1;
    return 0;
}

static int abort_guardian_before_ready(void *opaque,int held_fd,uint64_t deadline,
        int64_t parent) {
    struct lease_context *context=opaque;
    char request[GUARDIAN_RECORD_BYTES],ack[GUARDIAN_RECORD_BYTES];
    uint64_t grace_deadline,exit_deadline;
    int ack_result,guardian_exit=-1;
    (void)parent;(void)held_fd;
    if(!context->guardian_started||context->guardian_ready||
            UINT64_MAX-deadline<GUARDIAN_PROTOCOL_GRACE_MS)return -1;
    grace_deadline=deadline+GUARDIAN_PROTOCOL_GRACE_MS;
    if(guardian_bound_suffix(context,request,sizeof(request),
            "GUARDIAN_ABORT_BEFORE_READY")!=0||
            guardian_bound_suffix(context,ack,sizeof(ack),"GUARDIAN_ABORTED")!=0||
            packet_send_now(context->guardian_fd,request)!=0)return -1;
    ack_result=wait_final_ack(context,ack,grace_deadline,&exit_deadline);
    if(ack_result==-2)return -1;
#ifdef PEN_INPUT_LEASE_ADAPTER_TEST
    if(pen_input_lease_test_worker_loses_abort_ack&&ack_result==0)ack_result=-1;
#endif
    /* Always collect the authoritative guardian exit proof even when the ACK
     * vanished after its sole successful EVIOCGRAB(0). Exit 118 means the
     * grab was safely released but a post-release terminal/ACK endpoint was
     * lost; treating that as held would create a false quarantine. */
    if(wait_guardian_exit(context,exit_deadline,&guardian_exit)!=0||
            (guardian_exit!=0&&guardian_exit!=118))return -1;
    (void)ack_result;
    close(context->guardian_fd);context->guardian_fd=-1;
    context->guardian_started=0;context->guardian_pid=0;
    context->guardian_terminal=1;
    return 0;
}

static int guardian_ping(struct lease_context *context) {
    uint64_t now;
    if(!context->guardian_started||boottime_ms(NULL,&now)!=0||
            UINT64_MAX-now<250u)return -1;
    return guardian_command(context,"GUARDIAN_PING","GUARDIAN_ALIVE",now+250u);
}

static int emit_ready(void *opaque, uint64_t deadline) {
    struct lease_context *context=opaque;
#ifdef PEN_INPUT_LEASE_ADAPTER_TEST
    if(pen_input_lease_test_close_worker_ready_peer_fd>=0) {
        int fd=pen_input_lease_test_close_worker_ready_peer_fd;
        pen_input_lease_test_close_worker_ready_peer_fd=-1;
        if(close(fd)!=0)return -1;
    }
    if(pen_input_lease_test_kill_guardian_before_ready&&
            context->guardian_pid>1)
        (void)kill(context->guardian_pid,SIGKILL);
#endif
    if(!context->guardian_started||context->guardian_ready||
            guardian_command(context,"GUARDIAN_READY_PREPARE",
                "GUARDIAN_READY_PREPARED",deadline)!=0||
            guardian_command(context,"GUARDIAN_READY_COMMIT",
                "GUARDIAN_READY_ACK",deadline)!=0)
        return -1;
    context->guardian_ready=1;
    /* Status ownership was transferred immediately after fork. */
    if(context->status_fd>=0)return -1;
    return 0;
}

static int prove_exclusive(void *opaque, int held_fd) {
    struct lease_context *context=opaque;
    int second=context->standby_fd, acquired;
    if(context->standby_acquired||second<0||second==held_fd||
            verify_device(context,second)!=0||same_pen(context,held_fd,second)!=0)return -1;
    acquired=grab_pen(context,second);
    if(acquired==0)context->standby_acquired=1;
    /* Never close an unexpectedly acquired probe. This exact OFD was bound
     * before fork and remains open in BOTH holders, including when the worker
     * retires an unresponsive guardian. No fallback ungrab is authorized. */
    return acquired==1?0:-1;
}

static int consume_if_exact(int fd, const char *record, int *received) {
    int available=0;
    if (available_bytes(fd,&available)!=0) return -1;
    if (available==0) return 0;
    if (*received) return -1;
    if (exact_pipe_record(fd,record)!=0) return -1;
    *received=1;
    return 0;
}

static int wait_until(void *opaque, int held_fd, uint64_t deadline,
        int64_t parent, struct pen_input_lease_end *outcome) {
    struct lease_context *context=opaque;
    char release_end[GUARDIAN_RECORD_BYTES],timeout_end[GUARDIAN_RECORD_BYTES];
    char failed[GUARDIAN_RECORD_BYTES],record[GUARDIAN_RECORD_BYTES];
    char ping[GUARDIAN_RECORD_BYTES],pong[GUARDIAN_RECORD_BYTES];
    uint64_t grace_deadline=deadline;
    uint64_t ping_deadline=0,next_ping=0;
    int end_received=0,ping_pending=0;
    int first=snprintf(release_end,sizeof(release_end),
        "GUARDIAN_END token=%s guardian_pid=%ld guardian_starttime=%llu guardian_session=%s reason=control_release release=1 phase=true\n",
        context->token,(long)context->guardian_pid,
        (unsigned long long)context->guardian_starttime,context->guardian_session);
    int second=snprintf(timeout_end,sizeof(timeout_end),
        "GUARDIAN_END token=%s guardian_pid=%ld guardian_starttime=%llu guardian_session=%s reason=timeout release=0 phase=true\n",
        context->token,(long)context->guardian_pid,
        (unsigned long long)context->guardian_starttime,context->guardian_session);
    if(guardian_bound_suffix(context,failed,sizeof(failed),"GUARDIAN_FAILED")!=0||
            guardian_bound_suffix(context,ping,sizeof(ping),"GUARDIAN_PING")!=0||
            guardian_bound_suffix(context,pong,sizeof(pong),"GUARDIAN_ALIVE")!=0||
            first<=0||(size_t)first>=sizeof(release_end)||second<=0||
            (size_t)second>=sizeof(timeout_end))return -1;
    if(UINT64_MAX-grace_deadline>=250u)grace_deadline+=250u;
    (void)held_fd;
    for (;;) {
        uint64_t now;
        int packet=packet_receive_now(context->guardian_fd,record);
        if(packet==1) {
            if(ping_pending&&strcmp(record,pong)==0) {
                ping_pending=0;
                if(end_received)return 0;
            } else if(!end_received&&strcmp(record,release_end)==0) {
                outcome->reason=PEN_INPUT_LEASE_END_RELEASE;
                outcome->release_received=1;outcome->final_phase_proved=1;
                context->guardian_end_reason=outcome->reason;end_received=1;
                if(!ping_pending)return 0;
            } else if(!end_received&&strcmp(record,timeout_end)==0) {
                outcome->reason=PEN_INPUT_LEASE_END_TIMEOUT;
                outcome->release_received=0;outcome->final_phase_proved=1;
                context->guardian_end_reason=outcome->reason;end_received=1;
                if(!ping_pending)return 0;
            } else {
                outcome->reason=strcmp(record,failed)==0?
                    PEN_INPUT_LEASE_END_REVALIDATION_FAILED:PEN_INPUT_LEASE_END_ERROR;
                outcome->release_received=0;outcome->final_phase_proved=0;return 0;
            }
        }
        if(packet<0) {
            outcome->reason=PEN_INPUT_LEASE_END_CONTROL_LOST;
            outcome->release_received=0;outcome->final_phase_proved=0;return 0;
        }
        if(termination_pending(NULL)!=0) {
            outcome->reason=PEN_INPUT_LEASE_END_SIGNAL;
            outcome->release_received=0;outcome->final_phase_proved=0;return 0;
        }
        if((int64_t)getppid()!=parent) {
            outcome->reason=PEN_INPUT_LEASE_END_PARENT_LOST;
            outcome->release_received=0;outcome->final_phase_proved=0;return 0;
        }
        if(boottime_ms(NULL,&now)!=0||now>=grace_deadline) {
            outcome->reason=PEN_INPUT_LEASE_END_TIMEOUT;
            outcome->release_received=0;outcome->final_phase_proved=0;return 0;
        }
        if(ping_pending&&now>=ping_deadline)return -1;
        if(!ping_pending&&!end_received&&now>=next_ping) {
            if(UINT64_MAX-now<250u||packet_send_now(context->guardian_fd,ping)!=0)return -1;
            ping_pending=1;ping_deadline=now+250u;next_ping=ping_deadline;
        }
        {
            struct pollfd endpoint={context->guardian_fd,POLLIN|POLLHUP,0};
            int delay=(int)((grace_deadline-now)>25u?25u:(grace_deadline-now));
            int waited=poll(&endpoint,1,delay);
            if(waited<0&&errno!=EINTR)return -1;
            if(waited>0&&(endpoint.revents&(POLLERR|POLLNVAL))!=0)return -1;
        }
    }
}

static enum pen_input_lease_idle_result wait_idle_until(void *opaque, int fd,
        uint64_t deadline, int64_t parent) {
    struct lease_context *context=opaque;
    for (;;) {
        uint64_t now;
        int idle=pen_idle(context,fd);
        if (status_consumer_alive(context)!=0 || idle<0 ||
                revalidate(context,fd)!=0 || prove_exclusive(context,fd)!=0)
            return PEN_INPUT_LEASE_IDLE_ERROR;
        if (idle==0) return PEN_INPUT_LEASE_IDLE;
        /* Once cleanup began while contact was active, loss of the control
         * parent or a cleanup signal is unsafe: retain the grab in quarantine. */
        if (termination_pending(NULL)!=0 || (int64_t)getppid()!=parent)
            return PEN_INPUT_LEASE_IDLE_ERROR;
        if (boottime_ms(NULL,&now)!=0) return PEN_INPUT_LEASE_IDLE_ERROR;
        if (now>=deadline) return PEN_INPUT_LEASE_ACTIVE_AT_DEADLINE;
        (void)poll(NULL,0,(int)((deadline-now)>10u?10u:(deadline-now)));
    }
}

static const char *end_reason(enum pen_input_lease_end_reason reason) {
    switch(reason) {
        case PEN_INPUT_LEASE_END_RELEASE:return "control_release";
        case PEN_INPUT_LEASE_END_TIMEOUT:return "timeout";
        case PEN_INPUT_LEASE_END_SIGNAL:return "signal";
        case PEN_INPUT_LEASE_END_PARENT_LOST:return "parent_lost";
        case PEN_INPUT_LEASE_END_CONTROL_LOST:return "control_lost";
        case PEN_INPUT_LEASE_END_REVALIDATION_FAILED:return "revalidation_failed";
        default:return "error";
    }
}

static int wait_guardian_exit(struct lease_context *context,uint64_t deadline,
        int *exit_code) {
    for(;;) {
        int status;
        pid_t result=waitpid(context->guardian_pid,&status,WNOHANG);
        uint64_t now;
        if(result==context->guardian_pid) {
            if(!WIFEXITED(status))return -1;
            *exit_code=WEXITSTATUS(status);return 0;
        }
        if(result<0)return -1;
        if(boottime_ms(NULL,&now)!=0||now>=deadline)return -1;
        (void)poll(NULL,0,(int)((deadline-now)>10u?10u:(deadline-now)));
    }
}

static int release_pen(void *opaque,int fd) {
    struct lease_context *context=opaque;
    uint64_t now,deadline,exit_deadline;
    const char *command;char request[GUARDIAN_RECORD_BYTES],ack[GUARDIAN_RECORD_BYTES];
    int ack_result,guardian_exit=-1;
    if(!context->guardian_started)return kernel_release_pen(context,fd);
    if(!context->guardian_ready||
            (context->guardian_end_reason!=PEN_INPUT_LEASE_END_RELEASE&&
             context->guardian_end_reason!=PEN_INPUT_LEASE_END_TIMEOUT)||
            boottime_ms(NULL,&now)!=0||
            UINT64_MAX-context->guardian_deadline_boottime<GUARDIAN_PROTOCOL_GRACE_MS)return -1;
    deadline=context->guardian_deadline_boottime+GUARDIAN_PROTOCOL_GRACE_MS;
    if(now>=deadline)return -1;
    command=context->guardian_end_reason==PEN_INPUT_LEASE_END_RELEASE?
        "GUARDIAN_SAFE_RELEASE":"GUARDIAN_SAFE_TIMEOUT";
#ifdef PEN_INPUT_LEASE_ADAPTER_TEST
    if(pen_input_lease_test_delay_safe_command_ms>0)
        (void)poll(NULL,0,(int)pen_input_lease_test_delay_safe_command_ms);
#endif
    if(guardian_bound_suffix(context,request,sizeof(request),command)!=0||
            guardian_bound_suffix(context,ack,sizeof(ack),"GUARDIAN_RELEASED")!=0||
            packet_send_now(context->guardian_fd,request)!=0)return -1;
    ack_result=wait_final_ack(context,ack,deadline,&exit_deadline);
    if(ack_result==-2)return -1;
    if(wait_guardian_exit(context,exit_deadline,&guardian_exit)!=0||
            !((guardian_exit==0&&ack_result==0)||guardian_exit==118))return -1;
    if(close(context->guardian_fd)!=0)return -1;
    context->guardian_fd=-1;context->guardian_started=0;
    context->guardian_ready=0;context->guardian_terminal=1;
    context->guardian_pid=0;
    /* The guardian is the sole EVIOCGRAB(0) authority for the shared open-file
     * description. Repeating that ioctl is not idempotent on real evdev. */
    (void)fd;
    return 0;
}

static int emit_released(void *opaque, enum pen_input_lease_end_reason reason) {
    struct lease_context *context=opaque; char line[192];
    if(context->guardian_terminal)return reason==context->guardian_end_reason?0:-1;
    int length=snprintf(line,sizeof(line),
        "PEN_INPUT_LEASE_RELEASED token=%s reason=%s held=false safe_idle_handoff=true\n",
        context->token,end_reason(reason));
    return length>0 && (size_t)length<sizeof(line) ? status_record(context,line) : -1;
}

static int emit_failed(void *opaque, const char *stage, int held, int reboot) {
    struct lease_context *context=opaque; char line[256];
    if(context->guardian_terminal)return 0;
    if(context->guardian_started) {
        char request[GUARDIAN_RECORD_BYTES];
        (void)stage;(void)held;(void)reboot;
        if(guardian_bound_suffix(context,request,sizeof(request),
                "GUARDIAN_WORKER_FAILED")!=0)return -1;
        return packet_send_now(context->guardian_fd,request);
    }
    int length=snprintf(line,sizeof(line),
        "PEN_INPUT_LEASE_FAILED token=%s stage=%s held=%s safe_idle_handoff=false reboot_required=%s\n",
        context->token,stage,held?"true":"false",reboot?"true":"false");
    return length>0 && (size_t)length<sizeof(line) ? status_record(context,line) : -1;
}

static void retire_unresponsive_guardian(struct lease_context *context) {
    uint64_t now,deadline;
    char request[GUARDIAN_RECORD_BYTES],record[GUARDIAN_RECORD_BYTES];
    siginfo_t child;
    if(context==NULL||!context->guardian_started||context->guardian_pid<=1||
            context->guardian_fd<0||boottime_ms(NULL,&now)!=0||
            UINT64_MAX-now<250u)return;
    deadline=now+250u;
    if(guardian_bound_suffix(context,request,sizeof(request),"GUARDIAN_PING")==0)
        (void)packet_send_now(context->guardian_fd,request);
    for(;;) {
        int received=packet_receive_now(context->guardian_fd,record);
        /* A disconnected guardian can be an authenticated READY-ACK-loss
         * orphan and remains the release authority. A response/failure also
         * proves progress; do not kill a responsive or disconnected holder. */
        if(received==-2) {
            uint64_t actual;char state;
            /* READY-ACK-loss orphans may release independently, but a stopped
             * direct child makes no progress, and no orphan may mask status
             * beyond the original lease plus terminal protocol grace. */
            if(process_snapshot(context->guardian_pid,&actual,&state)!=0)return;
            if(state!='T'&&state!='t'&&state!='Z'&&
                    (UINT64_MAX-context->guardian_deadline_boottime<GUARDIAN_PROTOCOL_GRACE_MS||
                     now<context->guardian_deadline_boottime+GUARDIAN_PROTOCOL_GRACE_MS))return;
            break;
        }
        if(received!=0)return;
        if(boottime_ms(NULL,&now)!=0||now>=deadline)break;
        (void)poll(NULL,0,10);
    }
    /* waitid WNOWAIT proves this exact PID is still our unreaped direct child.
     * A child cannot be PID-reused until reaped by this single-threaded parent.
     * Never target a group or worker: its grabbed OFD stays open throughout. */
    memset(&child,0,sizeof(child));
    if(waitid(P_PID,(id_t)context->guardian_pid,&child,
            WEXITED|WSTOPPED|WNOHANG|WNOWAIT)!=0)return;
    if(context->guardian_starttime!=0) {
        uint64_t actual;
        if(process_starttime(context->guardian_pid,&actual)!=0||
                actual!=context->guardian_starttime)return;
    }
    if(kill(context->guardian_pid,SIGKILL)!=0&&errno!=ESRCH)return;
    if(boottime_ms(NULL,&now)!=0||UINT64_MAX-now<250u)return;
    deadline=now+250u;
    for(;;) {
        int status;
        pid_t reaped=waitpid(context->guardian_pid,&status,WNOHANG);
        if(reaped==context->guardian_pid) {
            (void)close(context->guardian_fd);context->guardian_fd=-1;
            context->guardian_started=0;context->guardian_pid=0;
            return;
        }
        if(reaped<0||boottime_ms(NULL,&now)!=0||now>=deadline)return;
        (void)poll(NULL,0,10);
    }
}

static void quarantine_forever(void *opaque, int first_fd, int second_fd) {
    /* A stopped/live-hung sole status owner otherwise masks HUP forever.
     * Retire only that unresponsive direct child while retaining our grab. */
    for (;;) {
        if(first_fd>=0||second_fd>=0)retire_unresponsive_guardian(opaque);
        (void)poll(NULL,0,250);
    }
}

static int parse_arguments(int argc, char **argv, struct lease_context *context) {
    const char *authority_hash=NULL;
    if (argc!=15) return -1;
    memset(context,0,sizeof(*context));
    context->authority_fd=context->control_fd=context->phase_fd=context->status_fd=-1;
    context->guardian_fd=-1;context->standby_fd=-1;
    for (int at=1;at<argc;at+=2) {
        if (at+1>=argc) return -1;
        if (strcmp(argv[at],"--hold-ms")==0) {
            if (exact_hold_ms(argv[at+1],&context->hold_ms)!=0) return -1;
        } else if (strcmp(argv[at],"--token")==0) {
            if (!valid_token(argv[at+1])) return -1;
            memcpy(context->token,argv[at+1],TOKEN_HEX_LENGTH+1);
        } else if (strcmp(argv[at],"--authority-fd")==0) {
            if (exact_fd_number(argv[at+1],&context->authority_fd)!=0) return -1;
        } else if (strcmp(argv[at],"--authority-sha256")==0) {
            authority_hash=argv[at+1];
        } else if (strcmp(argv[at],"--control-fd")==0) {
            if (exact_fd_number(argv[at+1],&context->control_fd)!=0) return -1;
        } else if (strcmp(argv[at],"--phase-fd")==0) {
            if (exact_fd_number(argv[at+1],&context->phase_fd)!=0) return -1;
        } else if (strcmp(argv[at],"--status-fd")==0) {
            if (exact_fd_number(argv[at+1],&context->status_fd)!=0) return -1;
        } else return -1;
    }
    if (context->hold_ms==0 || context->token[0]=='\0' || authority_hash==NULL ||
            parse_hash(authority_hash,context->authority_file_hash)!=0 ||
            context->authority_fd<3 || context->control_fd<3 || context->phase_fd<3 || context->status_fd<3 ||
            context->authority_fd==context->control_fd || context->authority_fd==context->phase_fd ||
            context->authority_fd==context->status_fd || context->control_fd==context->phase_fd ||
            context->control_fd==context->status_fd || context->phase_fd==context->status_fd) return -1;
    return 0;
}

static void configure_production_ops(struct pen_input_lease_ops *ops,
        struct lease_context *context) {
    memset(ops,0,sizeof(*ops));
    ops->context=context; ops->admit_contract=admit_contract;
    ops->parent_id=current_parent; ops->install_cleanup_handlers=install_handlers;
    ops->termination_pending=termination_pending;
    ops->arm_parent_death=arm_parent_death; ops->open_device=open_pen;
    ops->verify_initial_device=verify_initial; ops->revalidate_device=revalidate;
    ops->same_device=same_pen; ops->idle=pen_idle; ops->grab=grab_pen;
    ops->prepare_guardian=prepare_guardian;
    ops->start_guardian=start_guardian;
    ops->abort_guardian_before_ready=abort_guardian_before_ready;
    ops->release=release_pen; ops->close_device=close_pen; ops->boottime_ms=boottime_ms;
    ops->status_consumer_alive=status_consumer_alive;
    ops->emit_ready=emit_ready; ops->wait_until=wait_until;
    ops->wait_idle_until=wait_idle_until; ops->prove_still_exclusive=prove_exclusive;
    ops->emit_released=emit_released; ops->emit_failed=emit_failed;
    ops->quarantine=quarantine_forever;
}

#ifndef PEN_INPUT_LEASE_ADAPTER_TEST
int main(int argc, char **argv) {
    struct lease_context context;
    struct pen_input_lease_ops ops;
    int result;
    if (block_signals_before_arguments()!=0) return 2;
    if (parse_arguments(argc,argv,&context)!=0) return 2;
    configure_production_ops(&ops,&context);
    result=pen_input_lease_run(&ops,context.hold_ms);
    if (result==2) quarantine_forever(&context,-1,-1);
    return result;
}
#endif
