#include <assert.h>
#include <stdio.h>
#include "pen_grab_core.h"

struct fake {int call, fail_at, opened, closed, held, exclusivity_broken, duplicate;};
static int step(struct fake *f) {return ++f->call == f->fail_at;}
static int open_fake(void *p) {
    struct fake *f = p;
    if (step(f)) return -1;
    if (f->duplicate && f->opened) return 10;
    return 10 + f->opened++;
}
static int verify_fake(void *p, int fd) {assert(fd >= 10); return step(p) ? -1 : 0;}
static int same_fake(void *p, int a, int b) {assert(a != b); return step(p) ? -1 : 0;}
static int grab_fake(void *p, int fd) {
    struct fake *f = p;
    if (step(f)) return -1;
    if (f->held >= 0 && !f->exclusivity_broken) return 1;
    f->held = fd;
    return 0;
}
static int release_fake(void *p, int fd) {
    struct fake *f = p;
    if (step(f)) return -1;
    assert(f->held == fd);
    f->held = -1;
    return 0;
}
static int close_fake(void *p, int fd) {
    struct fake *f = p;
    if (f->held == fd) f->held = -1;
    ++f->closed;
    return step(f) ? -1 : 0;
}
static int run(struct fake *f) {
    struct pen_grab_ops ops = {f, open_fake, verify_fake, same_fake, verify_fake,
        grab_fake, release_fake, close_fake};
    int result = pen_grab_prove(&ops);
    assert(f->opened == f->closed);
    assert(f->held == -1);
    return result;
}
int main(void) {
    struct fake good = {0, 0, 0, 0, -1, 0, 0};
    assert(run(&good) == 0);
    for (int failure = 1; failure <= good.call; failure++) {
        struct fake bad = {0, failure, 0, 0, -1, 0, 0};
        assert(run(&bad) == 1);
    }
    struct fake broken = {0, 0, 0, 0, -1, 1, 0};
    assert(run(&broken) == 1);
    struct fake duplicate = {0, 0, 0, 0, -1, 0, 1};
    assert(run(&duplicate) == 1);
    printf("PASS %d native exclusivity control-flow cases; no input-device calls.\n", good.call + 3);
    return 0;
}
