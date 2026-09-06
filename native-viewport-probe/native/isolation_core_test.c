#include <assert.h>
#include <stdio.h>
#include "isolation_core.h"

struct fake {
    int fail_at;
    unsigned calls;
};

static int perform(void *context, enum isolation_step step) {
    struct fake *fake = context;
    assert((unsigned)step == fake->calls); /* No skipped/reordered operations. */
    ++fake->calls;
    return (int)step == fake->fail_at ? -1 : 0;
}

int main(void) {
    unsigned cases = 0;
    for (int failure = -1; failure < ISO_COUNT; ++failure) {
        struct fake fake = {failure, 0};
        struct isolation_ops ops = {&fake, perform};
        struct isolation_result result = isolation_prove(&ops);
        assert(result.native_start_allowed == 0);
        if (failure < 0) {
            assert(fake.calls == ISO_COUNT);
            assert(result.completed == ISO_COUNT);
            assert(result.failed_step == -1 && result.mechanism_pass == 1);
        } else {
            assert(fake.calls == (unsigned)failure + 1);
            assert(result.completed == (unsigned)failure);
            assert(result.failed_step == failure && !result.mechanism_pass);
        }
        ++cases;
    }
    struct isolation_result missing = isolation_prove(NULL);
    assert(missing.completed == 0 && missing.failed_step == ISO_CHILD_IDENTITY);
    assert(!missing.mechanism_pass && !missing.native_start_allowed);
    ++cases;
    struct isolation_ops invalid = {NULL, NULL};
    missing = isolation_prove(&invalid);
    assert(missing.completed == 0 && !missing.mechanism_pass);
    assert(!missing.native_start_allowed);
    ++cases;
    printf("ISOLATION_CORE PASS cases=%u native_start_allowed=false\n", cases);
    return 0;
}
