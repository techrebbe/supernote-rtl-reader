#ifndef VIEWPORT_ISOLATION_CORE_H
#define VIEWPORT_ISOLATION_CORE_H

/* Shared ordering for a DISPOSABLE child-only isolation diagnostic. No firmware
 * loader, input replay, held pen lease, or native Document admission exists. */
enum isolation_step {
    ISO_CHILD_IDENTITY,
    ISO_PARENT_LIFELINE,
    ISO_PRIVATE_NAMESPACE,
    ISO_PRIVATE_PROPAGATION,
    ISO_PRIVATE_ROOT,
    ISO_SEED_FIXTURES,
    ISO_CLOSE_INHERITED_FDS,
    ISO_CHROOT_AND_CWD,
    ISO_DROP_PRIVILEGES,
    ISO_NO_NEW_PRIVILEGES,
    ISO_SYSCALL_FILTER,
    ISO_VERIFY_BOUNDARY,
    ISO_OWNED_IO_ONLY,
    ISO_COUNT
};

struct isolation_ops {
    void *context;
    int (*perform)(void *, enum isolation_step);
};

struct isolation_result {
    unsigned completed;
    int failed_step;
    int mechanism_pass;
    int native_start_allowed;
};

static struct isolation_result isolation_prove(const struct isolation_ops *ops) {
    struct isolation_result out = {0, -1, 0, 0};
    if (!ops || !ops->perform) {
        out.failed_step = ISO_CHILD_IDENTITY;
        return out;
    }
    for (unsigned step = 0; step < ISO_COUNT; ++step) {
        if (ops->perform(ops->context, (enum isolation_step)step) != 0) {
            out.failed_step = (int)step;
            return out;
        }
        ++out.completed;
    }
    out.mechanism_pass = 1;
    /* Even complete isolation is NOT a native-engine readiness decision. */
    return out;
}
#endif
