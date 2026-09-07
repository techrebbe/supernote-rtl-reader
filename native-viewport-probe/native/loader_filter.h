#ifndef VIEWPORT_LOADER_FILTER_H
#define VIEWPORT_LOADER_FILTER_H
#include <stdint.h>
#include <stddef.h>

/* Separate constructor-only policy candidate, NOT the tested isolation policy.
 * No Android caller installs this yet. A syscall filter is not a filesystem
 * sandbox: the future child must first have a private, read-only library root,
 * no outside descriptors, no real devices/Binder/procfs and no capabilities.
 * Unknown calls TRAP: a constructor's unsupported action is a failed probe.
 * One inherited write-only report pipe is fixed at descriptor 3. */
struct loader_instruction { uint16_t code; uint8_t jt, jf; uint32_t k; };
#define LOAD_ARCH 0xc00000b7u
#define LOAD_ALLOW 0x7fff0000u
#define LOAD_TRAP 0x00030000u
#define LOAD_KILL 0x80000000u
#define LOAD_CAPACITY 160u
struct loader_program { struct loader_instruction code[LOAD_CAPACITY]; size_t count; int error; };

static inline void load_emit(struct loader_program *p, uint16_t code, uint8_t jt, uint8_t jf, uint32_t k) {
    if (p->count >= LOAD_CAPACITY) { p->error = 1; return; }
    p->code[p->count++] = (struct loader_instruction){code,jt,jf,k};
}
static inline void load_return(struct loader_program *p, uint32_t action) { load_emit(p,0x06,0,0,action); }
static inline void load_arg(struct loader_program *p, unsigned arg, int high) {
    load_emit(p,0x20,0,0,16u + 8u*arg + (high ? 4u : 0u));
}
static inline void load_require_zero(struct loader_program *p) {
    load_emit(p,0x15,1,0,0); load_return(p,LOAD_TRAP);
}
static inline void load_arg32(struct loader_program *p, unsigned arg) {
    load_arg(p,arg,1); load_require_zero(p); load_arg(p,arg,0);
}
static inline void load_forbid_bits(struct loader_program *p, uint32_t bits) {
    load_emit(p,0x45,0,1,bits); load_return(p,LOAD_TRAP);
}
static inline void load_finish_case(struct loader_program *p, size_t at) {
    load_return(p,LOAD_ALLOW);
    if (at >= p->count || p->count-at-1 > 255) { p->error=1; return; }
    p->code[at].jf=(uint8_t)(p->count-at-1);
}
static inline size_t load_case(struct loader_program *p, uint32_t nr) {
    size_t at=p->count; load_emit(p,0x15,0,0,nr); return at;
}
static inline void load_no_wx(struct loader_program *p, unsigned arg) {
    load_arg32(p,arg);
    load_forbid_bits(p,~7u);  /* only PROT_NONE/READ/WRITE/EXEC */
    load_emit(p,0x54,0,0,6); /* PROT_WRITE | PROT_EXEC */
    load_emit(p,0x15,0,1,6); load_return(p,LOAD_TRAP);
}

static inline struct loader_program loader_filter_make(void) {
    struct loader_program p={{{0,0,0,0}},0,0};
    size_t at;
    load_emit(&p,0x20,0,0,4); load_emit(&p,0x15,1,0,LOAD_ARCH); load_return(&p,LOAD_KILL);
    load_emit(&p,0x20,0,0,0);

    at=load_case(&p,56); /* openat: read-only flags only, within an isolated root */
    load_arg32(&p,2);
    /* CLOEXEC, NONBLOCK and the architecture union of DIRECTORY/NOFOLLOW/
     * LARGEFILE. ACCESSMODE, CREATE, TRUNCATE, APPEND and TMPFILE are excluded. */
    load_forbid_bits(&p,~0x000b8800u); load_finish_case(&p,at);

    at=load_case(&p,64); /* write: exact owned report channel, no other output */
    load_arg32(&p,0); load_emit(&p,0x15,1,0,3); load_return(&p,LOAD_TRAP); load_finish_case(&p,at);

    at=load_case(&p,222); /* mmap: private only, never W+X or shared buffers */
    load_no_wx(&p,2); load_arg32(&p,3);
    load_forbid_bits(&p,~0x00104832u); /* PRIVATE, FIXED, ANON, NORESERVE, FIXED_NOREPLACE,
                                     * legacy ignored DENYWRITE used by the host loader */
    load_emit(&p,0x45,1,0,2); load_return(&p,LOAD_TRAP); load_finish_case(&p,at);

    at=load_case(&p,226); /* mprotect: private child mappings only */
    load_no_wx(&p,2); load_finish_case(&p,at);

    at=load_case(&p,98); /* futex: only private WAIT/WAKE; no PI/shared operations */
    load_arg32(&p,1); load_emit(&p,0x15,2,0,128); load_emit(&p,0x15,1,0,129);
    load_return(&p,LOAD_TRAP); load_finish_case(&p,at);

    at=load_case(&p,167); /* prctl: read-only isolation queries, never changes */
    load_arg32(&p,0); load_emit(&p,0x15,3,0,2); load_emit(&p,0x15,2,0,21);
    load_emit(&p,0x15,1,0,39); load_return(&p,LOAD_TRAP); load_finish_case(&p,at);

    /* Minimal ordinary loader/runtime operations. No ioctl, socket, Binder,
     * signal/timer reconfiguration, threads, exec, namespace/credential changes,
     * dup/FD transfer, ptrace, process_vm, shared memory or new filter calls. */
    const uint32_t ordinary[]={57,62,63,67,78,79,80,90,93,94,113,139,148,150,158,
                              169,172,173,174,175,176,177,178,214,215,233,278};
    for (size_t i=0;i<sizeof(ordinary)/sizeof(ordinary[0]);++i) {
        at=load_case(&p,ordinary[i]); load_finish_case(&p,at);
    }
    load_return(&p,LOAD_TRAP);
    return p;
}
#endif
