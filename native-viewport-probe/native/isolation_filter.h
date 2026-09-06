#ifndef VIEWPORT_ISOLATION_FILTER_H
#define VIEWPORT_ISOLATION_FILTER_H
#include <stdint.h>

/* Actual AArch64 classic-BPF program, shared verbatim with the host interpreter.
 * Linux ABI constants/offsets are compile-time checked in the Android wrapper. */
struct isolation_instruction { uint16_t code; uint8_t jt, jf; uint32_t k; };
#define ISO_ALLOW 0x7fff0000u
#define ISO_DENY 0x00050001u
#define ISO_KILL 0x80000000u
#define ISO_ARCH 0xc00000b7u
#define ISO_NR(nr) {0x15, 0, 1, (nr)}, {0x06, 0, 0, ISO_ALLOW}
static const struct isolation_instruction isolation_filter[] = {
    {0x20, 0, 0, 4}, /* seccomp_data.arch */
    {0x15, 1, 0, ISO_ARCH},
    {0x06, 0, 0, ISO_KILL},
    {0x20, 0, 0, 0}, /* seccomp_data.nr */
    {0x15, 0, 6, 167}, /* prctl: only the three read-only queries below */
    {0x20, 0, 0, 16}, /* low word of first argument; prctl option is int */
    {0x15, 3, 0, 39}, /* PR_GET_NO_NEW_PRIVS */
    {0x15, 2, 0, 21}, /* PR_GET_SECCOMP */
    {0x15, 1, 0, 2}, /* PR_GET_PDEATHSIG */
    {0x06, 0, 0, ISO_DENY},
    {0x06, 0, 0, ISO_ALLOW},
    ISO_NR(63), ISO_NR(64), ISO_NR(57), /* read/write/close */
    ISO_NR(56), ISO_NR(80), ISO_NR(79), /* openat/fstat/newfstatat */
    ISO_NR(62), /* lseek */
    ISO_NR(173), /* getppid: the supervisor must still own this child */
    ISO_NR(174), ISO_NR(175), ISO_NR(176), ISO_NR(177), /* uids/gids */
    ISO_NR(148), ISO_NR(150), ISO_NR(158), ISO_NR(90), /* resids/groups/capget */
    ISO_NR(93), ISO_NR(94), ISO_NR(139), /* exit/exit_group/rt_sigreturn */
    {0x06, 0, 0, ISO_DENY}
};
#undef ISO_NR
#define ISOLATION_FILTER_COUNT (sizeof(isolation_filter) / sizeof(isolation_filter[0]))
#endif
