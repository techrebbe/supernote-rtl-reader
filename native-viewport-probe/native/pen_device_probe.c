#include <errno.h>
#include <fcntl.h>
#include <linux/input.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>
#include "pen_grab_core.h"

#define PEN_NODE "/dev/input/event7"

static int open_pen(void *unused) {
    (void)unused;
    return open(PEN_NODE, O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
}
static int abs_axis(int fd, unsigned code, int expected_max) {
    struct input_absinfo value;
    if (ioctl(fd, EVIOCGABS(code), &value) != 0) return -1;
    return value.minimum == 0 && value.maximum == expected_max ? 0 : -1;
}
static int verify_pen(void *unused, int fd) {
    (void)unused;
    struct stat info;
    char name[80] = {0};
    unsigned char keys[(KEY_MAX + 8) / 8] = {0};
    if (fstat(fd, &info) != 0 || !S_ISCHR(info.st_mode) ||
        ioctl(fd, EVIOCGNAME(sizeof(name)), name) <= 0 ||
        memcmp(name, "Wacom-pen\0", 10) != 0 ||
        ioctl(fd, EVIOCGBIT(EV_KEY, sizeof(keys)), keys) < 0) return -1;
    const unsigned required[] = {BTN_TOUCH, BTN_TOOL_PEN, BTN_TOOL_RUBBER};
    for (unsigned index = 0; index < sizeof(required) / sizeof(required[0]); index++) {
        unsigned bit = required[index];
        if ((keys[bit / 8] & (1u << (bit % 8))) == 0) return -1;
    }
    return abs_axis(fd, ABS_X, 15819) || abs_axis(fd, ABS_Y, 11864) ||
        abs_axis(fd, ABS_PRESSURE, 4095) ? -1 : 0;
}
static int same_pen(void *unused, int first, int second) {
    (void)unused;
    struct stat a, b;
    if (fstat(first, &a) != 0 || fstat(second, &b) != 0) return -1;
    return a.st_dev == b.st_dev && a.st_ino == b.st_ino && a.st_rdev == b.st_rdev ? 0 : -1;
}
static int pen_idle(void *unused, int fd) {
    (void)unused;
    struct input_absinfo pressure;
    unsigned char keys[(KEY_MAX + 8) / 8] = {0};
    if (ioctl(fd, EVIOCGABS(ABS_PRESSURE), &pressure) != 0 || pressure.value != 0 ||
        ioctl(fd, EVIOCGKEY(sizeof(keys)), keys) < 0) return -1;
    /* Hover/tool-in-range is not an idle admission, even without pressure. */
    const unsigned active[] = {BTN_TOUCH, BTN_TOOL_PEN, BTN_TOOL_RUBBER, BTN_STYLUS, BTN_STYLUS2};
    for (unsigned index = 0; index < sizeof(active) / sizeof(active[0]); index++) {
        unsigned bit = active[index];
        if (keys[bit / 8] & (1u << (bit % 8))) return -1;
    }
    return 0;
}
static int grab_pen(void *unused, int fd) {
    (void)unused;
    if (ioctl(fd, EVIOCGRAB, 1) == 0) return 0;
    return errno == EBUSY ? 1 : -1;
}
static int release_pen(void *unused, int fd) {
    (void)unused;
    return ioctl(fd, EVIOCGRAB, 0);
}
static int close_pen(void *unused, int fd) {
    (void)unused;
    return close(fd);
}

int main(int argc, char **argv) {
    if (argc != 2 || (strcmp(argv[1], "--inspect-idle") != 0 &&
        strcmp(argv[1], "--prove-exclusive-idle") != 0)) {
        fprintf(stderr, "Use --inspect-idle or --prove-exclusive-idle. No event replay.\n");
        return 2;
    }
    if (strcmp(argv[1], "--inspect-idle") == 0) {
        int fd = open_pen(NULL);
        int result = fd < 0 ? 1 : (verify_pen(NULL, fd) != 0 || pen_idle(NULL, fd) != 0);
        if (fd >= 0 && close_pen(NULL, fd) != 0) result = 1;
        puts(result ? "PEN_INSPECT_REJECTED" : "PEN_INSPECT_IDLE exact_nomad_device=true held=false");
        return result;
    }
    struct pen_grab_ops ops = {NULL, open_pen, verify_pen, same_pen, pen_idle,
        grab_pen, release_pen, close_pen};
    int result = pen_grab_prove(&ops);
    puts(result ? "PEN_EXCLUSIVITY_REJECTED pen_ready=false" :
        "PEN_EXCLUSIVITY_PROVED held=false pen_ready=false");
    return result;
}
