/* Authored Linux/Android constructor fixture only; never Supernote firmware. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "loader_report.h"
#include "loader_resource.h"

static void marker(int tag,int which) {
    struct loader_result r={LOADER_RESULT_MAGIC,tag,0,which,{0}};
    if(syscall(__NR_write,3,&r,sizeof(r))!=(long)sizeof(r)) _exit(78);
}

int loader_fixture_value;
__attribute__((constructor)) static void fixture(void) {
    const char *mode=getenv("VIEWPORT_LOADER_FIXTURE_CASE");
    int which=mode ? atoi(mode):-1;
    marker(20,which);
    if(which==0) loader_fixture_value=42;
    else if(which==1) {
        void *p=mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
        if(p==MAP_FAILED) _exit(80);
        *(volatile char *)p=7;
        if(mprotect(p,4096,PROT_READ) || munmap(p,4096)) _exit(81);
        loader_fixture_value=42;
    } else if(which==2) (void)syscall(__NR_openat,AT_FDCWD,"./forbidden-constructor-output",O_WRONLY|O_CREAT,0600);
    else if(which==3) (void)syscall(__NR_write,4,"x",1);
    else if(which==4) (void)syscall(__NR_socket,-1,1,0);
    else if(which==5) (void)syscall(__NR_ioctl,-1,0,0);
    else if(which==6) (void)syscall(__NR_clone,CLONE_THREAD,0,0,0,0);
    else if(which==7) (void)syscall(__NR_execve,"/nonexistent-viewport-fixture",0,0);
    else if(which==8) (void)syscall(__NR_rt_sigaction,SIGALRM,0,0,8);
    else if(which==9) (void)mmap(NULL,4096,PROT_READ|PROT_WRITE|PROT_EXEC,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    else if(which==10) (void)mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);
    else if(which==11) for(;;) { /* Bounded parent timeout; never a success. */ }
    else if(which==12) {
        unsigned char bytes[32];
        if(syscall(__NR_getrandom,bytes,sizeof(bytes),0)!=(long)sizeof(bytes)) _exit(82);
        loader_fixture_value=42;
    } else if(which==13) (void)syscall(__NR_prctl,15,"reconfigure",0,0,0);
    else if(which==14) (void)syscall(__NR_mprotect,NULL,0,PROT_WRITE|PROT_EXEC);
    else if(which==15) (void)syscall(__NR_futex,NULL,0,0,0,0,0);
    else if(which==16) (void)syscall(__NR_mremap,NULL,0,0,0,0);
    else if(which==17) {
        int descriptors[LOADER_NOFILE_LIMIT + 8u];
        unsigned opened=0;
        int terminal_errno=0, invalid=0;
        for(;opened<sizeof(descriptors)/sizeof(descriptors[0]);++opened) {
            int fd=openat(AT_FDCWD,".",O_RDONLY|O_CLOEXEC|O_DIRECTORY|O_NOFOLLOW);
            if(fd<0) { terminal_errno=errno; break; }
            descriptors[opened]=fd;
        }
        if(opened==0 || opened==sizeof(descriptors)/sizeof(descriptors[0]) ||
            terminal_errno!=EMFILE) invalid=1;
        while(opened) if(close(descriptors[--opened])) invalid=1;
        if(invalid) _exit(84);
        loader_fixture_value=42;
    } else if(which==18) {
        errno=0;
        void *p=mmap(NULL,(size_t)LOADER_AS_LIMIT_BYTES,PROT_NONE,
            MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE,-1,0);
        int terminal_errno=errno;
        if(p!=MAP_FAILED) { (void)munmap(p,(size_t)LOADER_AS_LIMIT_BYTES); _exit(85); }
        if(terminal_errno!=ENOMEM) _exit(86);
        loader_fixture_value=42;
    }
    else _exit(83);
    marker(21,which);
    /* Forbidden operations returning (even errno) instead of trapping cannot
     * accidentally count as a positive fixture. */
}
