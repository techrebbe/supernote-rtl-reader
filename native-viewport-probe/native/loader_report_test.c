#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "loader_report.h"

static struct loader_result marker(int tag,int step) {
    struct loader_result r={LOADER_RESULT_MAGIC,tag,0,step,{0}}; return r;
}
int main(void) {
    unsigned checks=0;
    for(int which=0;which<=16;++which) {
        int positive=which==0 || which==1 || which==12;
        size_t count=which==11 ? 2u:positive ? 4u:3u;
        int exit_code=which==11 ? -1:positive ? 0:77;
        struct loader_result r[5]={marker(10,-1),marker(20,which),marker(21,which),marker(42,-1),marker(99,-1)};
        if(!positive && which!=11) { r[2]=marker(77,-1); r[2].nr=56; }
        size_t bytes=count*sizeof(r[0]);
        assert(loader_sequence(r,bytes,which,56,exit_code,which==11)); ++checks;
        /* Every byte-count truncation and extra record must fail. */
        for(size_t n=0;n<sizeof(r);++n) if(n!=bytes) {
            assert(!loader_sequence(r,n,which,56,exit_code,which==11)); ++checks;
        }
        for(size_t i=0;i<count;++i) {
            struct loader_result bad[5];
            memcpy(bad,r,sizeof(r)); bad[i].magic^=1;
            assert(!loader_sequence(bad,bytes,which,56,exit_code,which==11)); ++checks;
            memcpy(bad,r,sizeof(r)); bad[i].tag^=128;
            assert(!loader_sequence(bad,bytes,which,56,exit_code,which==11)); ++checks;
            memcpy(bad,r,sizeof(r)); bad[i].step^=1;
            assert(!loader_sequence(bad,bytes,which,56,exit_code,which==11)); ++checks;
            memcpy(bad,r,sizeof(r)); bad[i].nr^=1;
            assert(!loader_sequence(bad,bytes,which,56,exit_code,which==11)); ++checks;
        }
        assert(!loader_sequence(r,bytes,which,56,exit_code+1,which==11)); ++checks;
        assert(!loader_sequence(r,bytes,which,56,exit_code,which!=11)); ++checks;
        /* Missing entered marker: an early loader trap or hang is NOT a pass. */
        memmove(&r[1],&r[2],3*sizeof(r[0]));
        assert(!loader_sequence(r,bytes-sizeof(r[0]),which,56,exit_code,which==11)); ++checks;
    }
    assert(!loader_sequence(NULL,0,0,0,0,0)); ++checks;
    printf("LOADER_REPORT PASS checks=%u constructor_phase_required=true\n",checks);
    return 0;
}
