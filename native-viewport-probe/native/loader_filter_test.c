#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "loader_filter.h"

/* Interpreter of the emitted program, not the policy's generator helpers. */
static uint32_t interpret(const struct loader_program *p,uint32_t arch,uint32_t nr,const uint64_t args[6]) {
    uint32_t a=0;
    for (size_t pc=0,budget=0;pc<p->count && budget++<=p->count;++pc) {
        const struct loader_instruction *i=&p->code[pc];
        if(i->code==0x20) {
            if(i->k==0) a=nr;
            else if(i->k==4) a=arch;
            else if(i->k>=16 && i->k<64 && i->k%4==0)
                a=(uint32_t)(args[(i->k-16)/8] >> (i->k%8==4 ? 32:0));
            else return LOAD_KILL;
        } else if(i->code==0x15) pc+=a==i->k ? i->jt:i->jf;
        else if(i->code==0x45) pc+=(a&i->k)!=0 ? i->jt:i->jf;
        else if(i->code==0x54) a&=i->k;
        else if(i->code==0x06) return i->k;
        else return LOAD_KILL;
    }
    return LOAD_KILL;
}

/* Independent permission oracle. All six arguments are 64-bit, including
 * rejected high-word aliases. This is still a host policy test, not a sandbox. */
static uint32_t expected(uint32_t arch,uint32_t nr,const uint64_t a[6]) {
    if(arch!=LOAD_ARCH) return LOAD_KILL;
    switch(nr) {
        case 56: return (a[2]&~UINT64_C(0xb8800))==0 ? LOAD_ALLOW:LOAD_TRAP;
        case 64: return a[0]==3 ? LOAD_ALLOW:LOAD_TRAP;
        case 222:
            return a[2]<=7 && (a[2]&6)!=6 && (a[3]&~UINT64_C(0x104832))==0 &&
                (a[3]&2)!=0 ? LOAD_ALLOW:LOAD_TRAP;
        case 226: return a[2]<=7 && (a[2]&6)!=6 ? LOAD_ALLOW:LOAD_TRAP;
        case 98: return a[1]==128 || a[1]==129 ? LOAD_ALLOW:LOAD_TRAP;
        case 167: return a[0]==2 || a[0]==21 || a[0]==39 ? LOAD_ALLOW:LOAD_TRAP;
        case 57: case 62: case 63: case 67: /* close/seek/read/pread */
        case 78: case 79: case 80: /* readlinkat/newfstatat/fstat */
        case 90: case 148: case 150: case 158: /* credentials queries */
        case 93: case 94: case 139: /* exit and signal return */
        case 113: case 169: /* time queries */
        case 172: case 173: case 174: case 175: case 176: case 177: case 178:
        case 214: case 215: case 233: case 278: /* brk/munmap/madvise/getrandom */
            return LOAD_ALLOW;
        default: return LOAD_TRAP;
    }
}

static unsigned verify(const struct loader_program *p,int assert_all) {
    const uint64_t values[]={0,1,2,3,4,5,6,7,8,16,21,32,34,39,64,128,129,256,512,
        1024,2048,2050,16384,32768,65536,131072,524288,1048576,0xb8800,0x104832,
        UINT64_C(0x100000000),UINT64_C(0x100000003),UINT64_MAX};
    const uint32_t arches[]={LOAD_ARCH,0xc000003e,0x40000028,0,UINT32_MAX};
    unsigned checks=0;
    for(unsigned ar=0;ar<sizeof(arches)/sizeof(arches[0]);++ar)
        for(uint32_t nr=0;nr<=1024;++nr)
            for(unsigned v=0;v<sizeof(values)/sizeof(values[0]);++v) {
                uint64_t args[6]={values[v],values[v],values[v],values[v],values[v],values[v]};
                int ok=interpret(p,arches[ar],nr,args)==expected(arches[ar],nr,args);
                if(assert_all) assert(ok); else if(!ok) return 1;
                ++checks;
            }
    /* Independent mmap protection/flag products catch a valid mask with bad
     * protection (and vice versa), not just all-arguments-equal vectors. */
    for(unsigned pbits=0;pbits<16;++pbits)
        for(unsigned f=0;f<sizeof(values)/sizeof(values[0]);++f) {
            uint64_t args[6]={0,4096,pbits,values[f],UINT64_MAX,0};
            int ok=interpret(p,LOAD_ARCH,222,args)==expected(LOAD_ARCH,222,args);
            if(assert_all) assert(ok); else if(!ok) return 1;
            ++checks;
        }
    return assert_all ? checks:0;
}

int main(void) {
    struct loader_program p=loader_filter_make();
    assert(!p.error && p.count<LOAD_CAPACITY);
    unsigned checks=verify(&p,1),mutations=0;
    uint64_t args[6]={0};
    assert(interpret(&p,LOAD_ARCH,UINT32_MAX,args)==LOAD_TRAP);
    for(size_t at=0;at<p.count;++at) {
        struct loader_program changed=p;
        if(changed.code[at].code==0x06)
            changed.code[at].k=changed.code[at].k==LOAD_ALLOW ? LOAD_TRAP:LOAD_ALLOW;
        else if(changed.code[at].code==0x45 || changed.code[at].code==0x54) changed.code[at].k=0;
        else changed.code[at].k^=0x40000000;
        if(verify(&changed,0)!=1) { fprintf(stderr,"undetected mutation at %u opcode=%x\n",(unsigned)at,changed.code[at].code); return 1; }
        ++mutations;
    }
    printf("LOADER_FILTER PASS instructions=%u vectors=%u mutations=%u kernel_tested=false native_start_allowed=false\n",(unsigned)p.count,checks+1,mutations);
    return 0;
}
