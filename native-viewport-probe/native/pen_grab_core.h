#ifndef PEN_GRAB_CORE_H
#define PEN_GRAB_CORE_H

/* Exact-device, instantaneous mechanism proof. NOT a held writing interlock.
 * The caller must have closed Document, have exclusive test-device ownership,
 * and verified an idle pen. No event injection or consumption occurs here. */
struct pen_grab_ops {
    void *context;
    int (*open_device)(void *context);
    int (*verify_device)(void *context, int fd);
    int (*same_device)(void *context, int first, int second);
    int (*idle)(void *context, int fd);
    /* grab: 0 acquired, 1 busy, -1 other failure; release: 0 success. */
    int (*grab)(void *context, int fd);
    int (*release)(void *context, int fd);
    int (*close_device)(void *context, int fd);
};

static int pen_grab_prove(const struct pen_grab_ops *ops) {
    int first = -1, second = -1, okay = 0;
    void *context = ops->context;
    first = ops->open_device(context);
    if (first < 0 || ops->verify_device(context, first) != 0 ||
        ops->idle(context, first) != 0) goto finish;
    second = ops->open_device(context);
    if (second < 0 || second == first ||
        ops->verify_device(context, second) != 0 ||
        ops->same_device(context, first, second) != 0) goto finish;
    if (ops->grab(context, first) != 0 || ops->idle(context, first) != 0) goto finish;
    /* A second independently opened file description must see EBUSY. */
    if (ops->grab(context, second) != 1) goto finish;
    if (ops->release(context, first) != 0) goto finish;
    if (ops->grab(context, second) != 0 || ops->idle(context, second) != 0) goto finish;
    if (ops->release(context, second) != 0) goto finish;
    okay = 1;
finish:
    /* Closing evdev file descriptions releases any outstanding grab. This
     * also handles unexpected second acquisition and errors after acquisition.
     * Do not retry close after EINTR; the descriptor may already be closed. */
    if (second >= 0 && second != first && ops->close_device(context, second) != 0) okay = 0;
    if (first >= 0 && ops->close_device(context, first) != 0) okay = 0;
    return okay ? 0 : 1;
}
#endif
