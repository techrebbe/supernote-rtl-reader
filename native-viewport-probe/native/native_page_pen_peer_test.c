#define NATIVE_PAGE_PEN_PEER_TEST 1
#include "native_page_pen_peer.c"
#include <assert.h>

struct fake {
    uint64_t now;
    int call, fail_at, closes, writes, records, closure, empty_fail, identity_fail;
    int record_fail, terminal_bad, closed_phase, closed_control;
    int publications, empty_calls, delay_empty_at;
    uint64_t delay_empty_to, delay_prepare_to;
    char ready[512], terminal[512], writes_seen[2][512];
};
static int injected(struct fake *f) {
    return ++f->call == f->fail_at;
}
static int fake_now(void *opaque, uint64_t *out) {
    struct fake *f = opaque;
    if (injected(f))
        return -1;
    *out = f->now;
    return 0;
}
static int fake_identity(void *opaque, struct process_id id, pid_t parent, int gone) {
    struct fake *f = opaque;
    (void)id;
    (void)parent;
    (void)gone;
    return injected(f) || f->identity_fail ? -1 : 0;
}
static int fake_record(void *opaque, int fd, char *line, size_t cap, uint64_t deadline) {
    struct fake *f = opaque;
    (void)fd;
    if (injected(f) || f->record_fail || f->now >= deadline)
        return -1;
    if (f->records == 1) {
        assert(f->closed_phase && f->closed_control);
        assert(f->writes == 2);
    }
    const char *text = f->records++ == 0 ? f->ready : f->terminal;
    if (strlen(text) >= cap)
        return -1;
    memcpy(line, text, strlen(text) + 1);
    if (f->terminal_bad && f->records == 2)
        line[0] = 'X';
    return 0;
}
static int fake_write(void *opaque, int fd, const char *line) {
    struct fake *f = opaque;
    (void)fd;
    if (injected(f))
        return -1;
    assert(!f->closed_phase && !f->closed_control && f->writes < 2);
    strcpy(f->writes_seen[f->writes++], line);
    return 0;
}
static int fake_close(void *opaque, int fd) {
    struct fake *f = opaque;
    f->closes++;
    assert(f->writes == 2);
    if (fd == 11)
        f->closed_phase = 1;
    else if (fd == 10)
        f->closed_control = 1;
    else
        assert(0);
    return injected(f) ? -1 : 0;
}
static int fake_empty(void *opaque, int fd, int mode) {
    struct fake *f = opaque;
    (void)fd;
    (void)mode;
    assert(!f->closed_phase && !f->closed_control);
    if (++f->empty_calls == f->delay_empty_at)
        f->now = f->delay_empty_to;
    return injected(f) || f->empty_fail ? -1 : 0;
}
static int fake_closure(void *opaque, struct peer *p, uint64_t deadline) {
    struct fake *f = opaque;
    (void)p;
    assert(f->records == 2 && f->closed_phase && f->closed_control);
    if (injected(f) || f->now >= deadline)
        return -1;
    f->closure++;
    return 0;
}
static int fake_prepare_publication(void *opaque, int fd, size_t maximum) {
    struct fake *f = opaque;
    assert(fd == STDOUT_FILENO && maximum < PEER_BYTES);
    if (f->delay_prepare_to)
        f->now = f->delay_prepare_to;
    return injected(f) ? -1 : 0;
}
static int fake_publish(void *opaque, int fd, const char *line, size_t length) {
    struct fake *f = opaque;
    assert(fd == STDOUT_FILENO && length == strlen(line));
    if (injected(f))
        return -1;
    const char *stamp = strstr(line, " device_boottime_ms=");
    char expected[64];
    (void)snprintf(expected, sizeof(expected), " device_boottime_ms=%llu ",
                   (unsigned long long)f->now);
    assert(stamp && strncmp(stamp, expected, strlen(expected)) == 0);
    f->publications++;
    return 0;
}
static const struct peer_ops fake_ops = {
    fake_now,    fake_identity, fake_record,  fake_write,
    fake_close,  fake_empty,    fake_closure, fake_prepare_publication,
    fake_publish};
static void fixture(struct peer *p, struct fake *f) {
    memset(p, 0, sizeof(*p));
    memset(f, 0, sizeof(*f));
    p->ops = &fake_ops;
    p->opaque = f;
    p->self = (struct process_id){100, 1000};
    p->owner = (struct process_id){99, 999};
    p->worker = (struct process_id){101, 1001};
    p->authority = 9;
    p->control = 10;
    p->phase = 11;
    p->status = 12;
    p->hold_ms = 10000;
    f->now = 10000;
    memset(p->token, 'b', 64);
    memset(p->stage, 'a', 64);
    char session[65];
    memset(session, 'e', 64);
    session[64] = 0;
    (void)snprintf(f->ready, sizeof(f->ready),
                   "PEN_INPUT_LEASE_READY token=%s device=/dev/input/event7 held=true "
                   "timeout_ms=10000 deviceClockDomain=" PEER_CLOCK
                   " deadline_boottime_ms=20000 guardian_pid=102 guardian_starttime=1002 "
                   "guardian_session=%s\n",
                   p->token, session);
    (void)snprintf(f->terminal, sizeof(f->terminal),
                   "PEN_INPUT_LEASE_RELEASED token=%s reason=control_release held=false "
                   "safe_idle_handoff=true "
                   "guardian_pid=102 guardian_starttime=1002 guardian_session=%s\n",
                   p->token, session);
}
static int run(struct peer *p) {
    if (peer_acquired(p) || receipt(p, "ACQUIRED", p->token))
        return -1;
    if (peer_capture(p, 2) || receipt(p, "CAPTURED", p->token))
        return -1;
    return peer_finish(p, 3) || receipt(p, "RELEASED", p->token) ? -1 : 0;
}
static void test_controller(void) {
    struct peer p;
    struct fake f;
    fixture(&p, &f);
    assert(run(&p) == 0);
    assert(p.state == PEER_RELEASED && f.closes == 2 && f.writes == 2 && f.closure == 1);
    assert(f.publications == 3);
    assert(!strncmp(f.writes_seen[0], "PHASE DESTROYED FINAL ", 22));
    assert(!strncmp(f.writes_seen[1], "RELEASE ", 8));
    int calls = f.call;
    for (int fail = 1; fail <= calls; fail++) {
        fixture(&p, &f);
        f.fail_at = fail;
        assert(run(&p) != 0);
        assert(p.state == PEER_QUARANTINED);
        assert(p.status == 12 && p.authority == 9);
        if (f.writes < 2)
            assert(f.closes == 0);
    }
    fixture(&p, &f);
    assert(peer_acquired(&p) == 0);
    f.now = 30000;
    assert(peer_capture(&p, 2) != 0 && p.state == PEER_QUARANTINED &&
           f.closes == 0); /* suspend counts */
    fixture(&p, &f);
    assert(peer_acquired(&p) == 0);
    f.now = 9999;
    assert(peer_capture(&p, 2) != 0 && f.closes == 0);
    fixture(&p, &f);
    assert(peer_acquired(&p) == 0);
    f.identity_fail = 1;
    assert(peer_capture(&p, 2) != 0 && f.closes == 0); /* orphan/identity replacement */
    fixture(&p, &f);
    assert(peer_acquired(&p) == 0);
    f.empty_fail = 1;
    assert(peer_capture(&p, 2) != 0 && f.closes == 0); /* premature peer closure */
    fixture(&p, &f);
    assert(peer_acquired(&p) == 0);
    assert(peer_capture(&p, 1) != 0 && f.closes == 0); /* replay */
    fixture(&p, &f);
    f.terminal_bad = 1;
    assert(run(&p) != 0 && f.closes == 2 && p.status == 12 && f.closure == 0);
    fixture(&p, &f);
    assert(peer_acquired(&p) == 0 && peer_capture(&p, 2) == 0);
    f.record_fail = 1;
    assert(peer_finish(&p, 3) != 0 && f.closes == 2 && p.status == 12 &&
           f.closure == 0); /* HUP without RELEASED */
    fixture(&p, &f);
    char *legacy = strstr(f.terminal, "control_release");
    assert(legacy != NULL);
    memmove(legacy, legacy + strlen("control_"), strlen(legacy + strlen("control_")) + 1);
    assert(run(&p) != 0 && p.state == PEER_QUARANTINED && f.closure == 0);
    printf("NATIVE_PAGE_PEN_PEER_CONTROLLER_PASS injected_edges=%d retained_quarantine=true "
           "seal_before_ungrab=true\n",
           calls);
}
static void test_publication_clock_freshness(void) {
    struct peer p;
    struct fake f;
    /* Suspend during the last endpoint proof, not before the initial sample. */
    for (unsigned capture = 0; capture < 2; capture++) {
        for (unsigned boundary = 0; boundary < 3; boundary++) {
            fixture(&p, &f);
            if (capture) {
                assert(peer_acquired(&p) == 0 && receipt(&p, "ACQUIRED", p.token) == 0);
                f.empty_calls = 0;
            }
            f.delay_empty_at = 3;
            f.delay_empty_to = boundary == 0 ? 20000 : boundary == 1 ? 30000 : 9999;
            assert((capture ? peer_capture(&p, 2) : peer_acquired(&p)) == 0);
            assert(receipt(&p, capture ? "CAPTURED" : "ACQUIRED", p.token) != 0);
            assert(p.state == PEER_QUARANTINED && f.publications == (int)capture && f.closes == 0);
        }
        fixture(&p, &f);
        if (capture)
            assert(peer_acquired(&p) == 0 && receipt(&p, "ACQUIRED", p.token) == 0);
        assert((capture ? peer_capture(&p, 2) : peer_acquired(&p)) == 0);
        f.delay_prepare_to = 20000; /* Output readiness itself can be delayed. */
        assert(receipt(&p, capture ? "CAPTURED" : "ACQUIRED", p.token) != 0);
        assert(f.publications == (int)capture && p.state == PEER_QUARANTINED);
    }
}
static void test_ready_parser(void) {
    struct peer p;
    struct fake f;
    char saved[512];
    fixture(&p, &f);
    strcpy(saved, f.ready);
    assert(status_ready(&p, saved) == 0);
    const char *bad[] = {"host-monotonic-v1", "android-boottime-v2"};
    for (unsigned i = 0; i < 2; i++) {
        fixture(&p, &f);
        char *at = strstr(f.ready, PEER_CLOCK);
        assert(at);
        size_t suffix = strlen(at + strlen(PEER_CLOCK));
        memmove(at + strlen(bad[i]), at + strlen(PEER_CLOCK), suffix + 1);
        memcpy(at, bad[i], strlen(bad[i]));
        assert(status_ready(&p, f.ready) != 0);
    }
    fixture(&p, &f);
    strcat(f.ready, "x");
    assert(status_ready(&p, f.ready) != 0);
    fixture(&p, &f);
    f.ready[strlen(f.ready) - 1] = 0;
    assert(status_ready(&p, f.ready) != 0);
    fixture(&p, &f);
    char *pid = strstr(f.ready, "guardian_pid=102");
    assert(pid);
    memcpy(pid + 13, "100", 3);
    assert(status_ready(&p, f.ready) != 0);
    fixture(&p, &f);
    f.now = 20000;
    assert(status_ready(&p, f.ready) != 0);
    fixture(&p, &f);
    p.hold_ms = 9999;
    assert(status_ready(&p, f.ready) != 0);
}
static int readonly_memfd(void) {
    int writable = memfd_create("peer-test", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    assert(writable >= 0);
    assert(write(writable, "abc", 3) == 3);
    char path[64];
    (void)snprintf(path, sizeof(path), "/proc/self/fd/%d", writable);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    assert(fd >= 0);
    assert(close(writable) == 0);
    return fd;
}
static void test_real_descriptors_and_records(void) {
    int a = readonly_memfd(), c[2], p[2], s[2];
    assert(pipe2(c, O_NONBLOCK | O_CLOEXEC) == 0 && pipe2(p, O_NONBLOCK | O_CLOEXEC) == 0 &&
           pipe2(s, O_NONBLOCK | O_CLOEXEC) == 0);
    assert(validate_contract(a, c[1], p[1], s[0]) == 0);
    assert(validate_contract(c[0], c[1], p[1], s[0]) != 0);
    assert(validate_contract(a, c[1], c[1], s[0]) != 0);
    int alias = dup(c[1]);
    assert(alias >= 0);
    assert(validate_contract(a, c[1], alias, s[0]) != 0);
    assert(close(alias) == 0);
    assert(validate_contract(a, c[0], p[1], s[0]) != 0);
    char record[128];
    uint64_t now;
    assert(real_now(NULL, &now) == 0);
    assert(real_write(NULL, c[1], "ONE\n") == 0);
    assert(real_record(NULL, c[0], record, sizeof(record), now + 1000) == 0 &&
           strcmp(record, "ONE\n") == 0);
    assert(real_write(NULL, c[1], "PARTIAL") == 0);
    assert(real_record(NULL, c[0], record, sizeof(record), now + 1000) != 0);
    assert(real_write(NULL, c[1], "ONE\nTWO\n") == 0);
    assert(real_record(NULL, c[0], record, sizeof(record), now + 1000) != 0);
    assert(close(c[1]) == 0);
    assert(real_empty(NULL, c[0], O_RDONLY) != 0);
    assert(real_record(NULL, c[0], record, sizeof(record), now + 1000) != 0);
    assert(close(a) == 0 && close(c[0]) == 0 && close(p[0]) == 0 && close(p[1]) == 0 &&
           close(s[0]) == 0 && close(s[1]) == 0);
}
static void test_hash_copy_and_commands(void) {
    struct hash256 h;
    char digest[65];
    hash_init(&h);
    hash_add(&h, (const unsigned char *)"abc", 3);
    hash_end(&h, digest);
    assert(!strcmp(digest, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    int source = readonly_memfd();
    char path[64];
    (void)snprintf(path, sizeof(path), "/proc/self/fd/%d", source);
    /* Source symlinks, including proc fd links, are deliberately not admitted. */
    assert(sealed_copy(path, digest, 511, 0) < 0);
    assert(close(source) == 0);
    char temporary[] = "build/native-page-pen-peer/authority-XXXXXX", absolute[PATH_MAX];
    int file = mkstemp(temporary);
    assert(file >= 0 && write(file, "abc", 3) == 3 && close(file) == 0);
    assert(realpath(temporary, absolute) != NULL);
    int sealed = sealed_copy(absolute, digest, 511, 0);
    assert(sealed >= 0);
    int seals = fcntl(sealed, F_GET_SEALS);
    assert((seals & (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL)) ==
           (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL));
    assert((fcntl(sealed, F_GETFL) & O_ACCMODE) == O_RDONLY && pwrite(sealed, "x", 1, 0) < 0);
    (void)snprintf(path, sizeof(path), "/proc/self/fd/%d", sealed);
    int writer = open(path, O_RDWR);
    if (writer >= 0) {
        assert(pwrite(writer, "x", 1, 0) < 0 && ftruncate(writer, 0) < 0);
        assert(close(writer) == 0);
    } else
        assert(errno == EACCES || errno == EPERM);
    assert(close(sealed) == 0);
    assert(sealed_copy(absolute, digest, 2, 0) < 0);
    digest[0] = '0';
    assert(sealed_copy(absolute, digest, 511, 0) < 0);
    assert(unlink(temporary) == 0);
    struct peer p;
    struct fake f;
    fixture(&p, &f);
    char command[512], proof[65];
    uint64_t seq;
    (void)snprintf(command, sizeof(command), "ACQUIRE stage_session=%s before_absence_proof=%s\n",
                   p.stage, p.token);
    assert(exact_command(&p, command, "ACQUIRE", "before_absence_proof", proof, &seq) == 0);
    strcat(command, "x");
    assert(exact_command(&p, command, "ACQUIRE", "before_absence_proof", proof, &seq) != 0);
    (void)snprintf(command, sizeof(command), "CAPTURE stage_session=%s sequence=02\n", p.stage);
    assert(exact_command(&p, command, "CAPTURE", NULL, proof, &seq) != 0);
    assert(number("18446744073709551616", &seq) != 0 && number("0", &seq) != 0 &&
           number("+1", &seq) != 0);
}
/* Fake lease ELF for an end-to-end broker launch. It never opens an evdev node,
 * grabs, or signals anything. Even if the broker fails, fake holders expire. */
static int fake_lease(int argc, char **argv) {
    const char *token = NULL;
    int control = -1, phase = -1, status = -1, authority = -1;
    uint64_t hold = 0, now;
    assert(argc == 15);
    for (int i = 1; i < argc; i += 2) {
        if (!strcmp(argv[i], "--token"))
            token = argv[i + 1];
        else if (!strcmp(argv[i], "--hold-ms"))
            assert(number(argv[i + 1], &hold) == 0);
        else if (!strcmp(argv[i], "--control-fd"))
            control = atoi(argv[i + 1]);
        else if (!strcmp(argv[i], "--phase-fd"))
            phase = atoi(argv[i + 1]);
        else if (!strcmp(argv[i], "--status-fd"))
            status = atoi(argv[i + 1]);
        else if (!strcmp(argv[i], "--authority-fd"))
            authority = atoi(argv[i + 1]);
    }
    assert(token && hex64(token) && hold && control >= 3 && phase >= 3 && status >= 3 &&
           authority >= 3);
    struct stat c, p, s, a;
    assert(pipe_identity(control, O_RDONLY, &c) == 0 && pipe_identity(phase, O_RDONLY, &p) == 0 &&
           pipe_identity(status, O_WRONLY, &s) == 0 && !same_fd(c, p) && !same_fd(c, s) &&
           !same_fd(p, s));
    assert(fstat(authority, &a) == 0 && S_ISREG(a.st_mode) &&
           (fcntl(authority, F_GETFL) & O_ACCMODE) == O_RDONLY);
    /* Python extracts this fixture from the independently hashed frozen lease's
     * end_reason constant and terminal formatter, never from this broker. */
    char wire_fixture[512];
    ssize_t fixture_length = pread(authority, wire_fixture, sizeof(wire_fixture) - 1, 0);
    assert(fixture_length > 0 && fixture_length < (ssize_t)sizeof(wire_fixture) - 1);
    wire_fixture[fixture_length] = 0;
    char *terminal_format = strchr(wire_fixture, '\n');
    assert(terminal_format != NULL);
    *terminal_format++ = 0;
    const char *release_reason = wire_fixture;
    assert(real_now(NULL, &now) == 0);
    uint64_t deadline = now + hold;
    char expected[512], actual[512];
    (void)snprintf(expected, sizeof(expected), "PHASE DESTROYED BEFORE %s\n", token);
    assert(real_record(NULL, phase, actual, sizeof(actual), deadline) == 0 &&
           !strcmp(actual, expected));
    pid_t guardian = fork();
    assert(guardian >= 0);
    if (guardian == 0) {
        uint64_t start;
        pid_t parent;
        char state, session[65];
        memset(session, 'e', 64);
        session[64] = 0;
        assert(snapshot(getpid(), &start, &parent, &state) == 0);
        (void)snprintf(expected, sizeof(expected),
                       "PEN_INPUT_LEASE_READY token=%s device=/dev/input/event7 held=true "
                       "timeout_ms=%llu deviceClockDomain=" PEER_CLOCK
                       " deadline_boottime_ms=%llu guardian_pid=%ld guardian_starttime=%llu "
                       "guardian_session=%s\n",
                       token, (unsigned long long)hold, (unsigned long long)deadline,
                       (long)getpid(), (unsigned long long)start, session);
        assert(real_write(NULL, status, expected) == 0);
        if (real_record(NULL, phase, actual, sizeof(actual), deadline))
            _exit(120);
        (void)snprintf(expected, sizeof(expected),
                       "PHASE DESTROYED FINAL %s guardian_pid=%ld guardian_starttime=%llu "
                       "guardian_session=%s\n",
                       token, (long)getpid(), (unsigned long long)start, session);
        assert(!strcmp(actual, expected));
        if (real_record(NULL, control, actual, sizeof(actual), deadline))
            _exit(120);
        (void)snprintf(expected, sizeof(expected),
                       "RELEASE %s guardian_pid=%ld guardian_starttime=%llu guardian_session=%s\n",
                       token, (long)getpid(), (unsigned long long)start, session);
        assert(!strcmp(actual, expected));
        for (unsigned i = 0; i < 2; i++) {
            int fd = i ? control : phase;
            struct pollfd endpoint = {fd, POLLHUP, 0};
            assert(poll(&endpoint, 1, 100) == 1 && (endpoint.revents & POLLHUP));
            char byte;
            assert(read(fd, &byte, 1) == 0);
        }
        (void)snprintf(expected, sizeof(expected), terminal_format, token, release_reason,
                       (long)getpid(), (unsigned long long)start, session);
        assert(real_write(NULL, status, expected) == 0);
        _exit(0);
    }
    assert(close(status) == 0 && close(control) == 0 && close(phase) == 0 && close(authority) == 0);
    int child_status;
    assert(waitpid(guardian, &child_status, 0) == guardian);
    return WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0 ? 0 : 120;
}
int main(int argc, char **argv) {
    if (argc == 15)
        return fake_lease(argc, argv);
    test_controller();
    test_publication_clock_freshness();
    test_ready_parser();
    test_real_descriptors_and_records();
    test_hash_copy_and_commands();
    puts("NATIVE_PAGE_PEN_PEER_TEST_PASS fake_only=true no_holder_signal=true exact_identity=true "
         "device_boottime_only=true");
    return 0;
}
