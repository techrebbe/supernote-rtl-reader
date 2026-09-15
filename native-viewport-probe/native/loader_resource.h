#ifndef VIEWPORT_LOADER_RESOURCE_H
#define VIEWPORT_LOADER_RESOURCE_H

#include <stdint.h>
#include <sys/resource.h>

/* Constructor diagnostics run in a disposable child, but a wall-clock alarm
 * alone cannot stop address-space or descriptor-table pressure before it fires.
 * These limits are deliberately fixed and are installed before dlopen. */
#define LOADER_AS_LIMIT_BYTES (UINT64_C(256) * 1024u * 1024u)
#define LOADER_NOFILE_LIMIT 32u

static inline int loader_resource_limits_exact(void) {
    struct rlimit address_space, descriptors;
    return getrlimit(RLIMIT_AS, &address_space) == 0 &&
        getrlimit(RLIMIT_NOFILE, &descriptors) == 0 &&
        address_space.rlim_cur == (rlim_t)LOADER_AS_LIMIT_BYTES &&
        address_space.rlim_max == (rlim_t)LOADER_AS_LIMIT_BYTES &&
        descriptors.rlim_cur == (rlim_t)LOADER_NOFILE_LIMIT &&
        descriptors.rlim_max == (rlim_t)LOADER_NOFILE_LIMIT ? 0 : -1;
}

static inline int loader_apply_resource_limits(void) {
    const struct rlimit address_space = {
        (rlim_t)LOADER_AS_LIMIT_BYTES, (rlim_t)LOADER_AS_LIMIT_BYTES};
    const struct rlimit descriptors = {
        (rlim_t)LOADER_NOFILE_LIMIT, (rlim_t)LOADER_NOFILE_LIMIT};
    if ((uint64_t)(rlim_t)LOADER_AS_LIMIT_BYTES != LOADER_AS_LIMIT_BYTES ||
        (uint64_t)(rlim_t)LOADER_NOFILE_LIMIT != LOADER_NOFILE_LIMIT ||
        setrlimit(RLIMIT_AS, &address_space) != 0 ||
        setrlimit(RLIMIT_NOFILE, &descriptors) != 0)
        return -1;
    return loader_resource_limits_exact();
}

#endif
