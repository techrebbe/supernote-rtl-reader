#ifndef VIEWPORT_LOADER_REPORT_H
#define VIEWPORT_LOADER_REPORT_H
#include <stddef.h>
#include <stdint.h>

/* Owned test protocol, not a claim that arbitrary constructors are honest.
 * Distinguish policy installed -> constructor entered -> operation returned ->
 * dlclose completed. A loader trap/stall must not pass a constructor test. */
#define LOADER_RESULT_MAGIC 0x56504c44
struct loader_result { int32_t magic,tag,nr,step; uint64_t args[6]; };
_Static_assert(sizeof(struct loader_result)==64,"bounded report ABI");
static inline int loader_marker(const struct loader_result *r,int tag,int step) {
    if(r->magic!=LOADER_RESULT_MAGIC || r->tag!=tag || r->nr!=0 || r->step!=step) return 0;
    for(unsigned i=0;i<6;++i) if(r->args[i]!=0) return 0;
    return 1;
}
static inline int loader_sequence(const struct loader_result *r,size_t bytes,
        int which,int expected_nr,int exit_code,int killed_by_parent) {
    if(!r || which<0 || which>16 || bytes%sizeof(*r) || bytes<2*sizeof(*r) ||
        !loader_marker(&r[0],10,-1) || !loader_marker(&r[1],20,which)) return 0;
    if(which==11) return bytes==2*sizeof(*r) && exit_code==-1 && killed_by_parent;
    if(killed_by_parent) return 0;
    if(which==0 || which==1 || which==12)
        return bytes==4*sizeof(*r) && exit_code==0 && loader_marker(&r[2],21,which) &&
            loader_marker(&r[3],42,-1);
    return expected_nr>=0 && bytes==3*sizeof(*r) && exit_code==77 &&
        r[2].magic==LOADER_RESULT_MAGIC && r[2].tag==77 && r[2].nr==expected_nr && r[2].step==-1;
}
#endif
