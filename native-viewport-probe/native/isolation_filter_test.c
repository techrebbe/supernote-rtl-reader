#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "isolation_filter.h"

static uint32_t interpret(const struct isolation_instruction *code, size_t count,
        uint32_t arch, uint32_t nr, uint32_t option) {
    uint32_t accumulator = 0;
    for (size_t pc = 0, budget = 0; pc < count && budget++ <= count; ++pc) {
        const struct isolation_instruction *ins = &code[pc];
        if (ins->code == 0x20) {
            if (ins->k == 0) accumulator = nr;
            else if (ins->k == 4) accumulator = arch;
            else if (ins->k == 16) accumulator = option;
            else return ISO_KILL;
        } else if (ins->code == 0x15) {
            pc += accumulator == ins->k ? ins->jt : ins->jf;
        } else if (ins->code == 0x06) return ins->k;
        else return ISO_KILL;
    }
    return ISO_KILL;
}

/* Independent permission oracle, not a list copied from filter instructions. */
static uint32_t expected(uint32_t arch, uint32_t nr, uint32_t option) {
    if (arch != ISO_ARCH) return ISO_KILL;
    switch (nr) {
        case 56: case 57: /* openat, close */
        case 62: case 63: case 64: /* lseek, read, write */
        case 79: case 80: /* newfstatat, fstat */
        case 90: /* capget */
        case 93: case 94: case 139: /* exit, exit_group, signal return */
        case 148: case 150: case 158: /* getresuid, getresgid, getgroups */
        case 173: /* getppid */
        case 174: case 175: case 176: case 177: return ISO_ALLOW;
        case 167: return option == 2 || option == 21 || option == 39 ? ISO_ALLOW : ISO_DENY;
        default: return ISO_DENY;
    }
}

static unsigned check(const struct isolation_instruction *code, int require_all) {
    const uint32_t arches[] = {ISO_ARCH, 0x40000028, 0xc000003e, 0, 0xffffffff};
    const uint32_t options[] = {0, 1, 2, 15, 16, 21, 22, 38, 39, 40, 0xffffffff};
    unsigned checked = 0;
    for (unsigned a = 0; a < sizeof(arches) / sizeof(arches[0]); ++a)
        for (uint32_t nr = 0; nr < 1025; ++nr)
            for (unsigned o = 0; o < sizeof(options) / sizeof(options[0]); ++o) {
                int correct = interpret(code, ISOLATION_FILTER_COUNT, arches[a], nr, options[o]) ==
                    expected(arches[a], nr, options[o]);
                if (require_all) assert(correct);
                else if (!correct) return 1;
                ++checked;
            }
    return require_all ? checked : 0;
}

int main(void) {
    unsigned checked = check(isolation_filter, 1), mutations = 0;
    assert(interpret(isolation_filter, ISOLATION_FILTER_COUNT, ISO_ARCH, 0xffffffff, 0) == ISO_DENY);
    ++checked;
    /* Every decision/constant mutation must be caught by the behavioral oracle.
     * RET replacement only mutates the return constant, not ignored jump bytes. */
    for (size_t at = 0; at < ISOLATION_FILTER_COUNT; ++at) {
        struct isolation_instruction changed[ISOLATION_FILTER_COUNT];
        memcpy(changed, isolation_filter, sizeof(changed));
        if (changed[at].code == 0x06) changed[at].k =
            changed[at].k == ISO_ALLOW ? ISO_DENY : ISO_ALLOW;
        else if (changed[at].code == 0x20) changed[at].k = 1234;
        else changed[at].k ^= 0x40000000;
        assert(check(changed, 0) == 1);
        ++mutations;
    }
    printf("ISOLATION_FILTER PASS vectors=%u mutations=%u native_start_allowed=false\n", checked, mutations);
    return 0;
}
