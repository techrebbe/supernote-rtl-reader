/* Unprivileged Linux x86-64 kernel/own-constructor test. NO tablet, mount,
 * chroot, firmware, real devices or annotation access. Not a sandbox proof. */
#define _GNU_SOURCE
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <ucontext.h>
#include <unistd.h>
#include "loader_filter.h"
#include "loader_report.h"
#include "isolation_supervisor.h"
#if !defined(__linux__) || !defined(__x86_64__)
#error Host test only. Do not build or run on the Nomad.
#endif

static void send_result(int tag,int nr,const unsigned long long *args) {
    struct loader_result r={LOADER_RESULT_MAGIC,tag,nr,-1,{0}};
    if(args) for(unsigned i=0;i<6;++i) r.args[i]=args[i];
    if(syscall(__NR_write,3,&r,sizeof(r))!=(long)sizeof(r)) _exit(78);
}
static void rejected(int signal,siginfo_t *info,void *opaque) {
    (void)signal;
    ucontext_t *context=opaque;
    unsigned long long args[6]={
        (unsigned long long)context->uc_mcontext.gregs[REG_RDI],
        (unsigned long long)context->uc_mcontext.gregs[REG_RSI],
        (unsigned long long)context->uc_mcontext.gregs[REG_RDX],
        (unsigned long long)context->uc_mcontext.gregs[REG_R10],
        (unsigned long long)context->uc_mcontext.gregs[REG_R8],
        (unsigned long long)context->uc_mcontext.gregs[REG_R9]};
    send_result(77,info->si_syscall,args); _exit(77);
}
static int translate(unsigned n) {
    switch(n) {
        case 56:return __NR_openat; case 57:return __NR_close; case 62:return __NR_lseek;
        case 63:return __NR_read; case 64:return __NR_write; case 67:return __NR_pread64;
        case 78:return __NR_readlinkat; case 79:return __NR_newfstatat; case 80:return __NR_fstat;
        case 90:return __NR_capget; case 93:return __NR_exit; case 94:return __NR_exit_group;
        case 98:return __NR_futex; case 113:return __NR_clock_gettime; case 139:return __NR_rt_sigreturn;
        case 148:return __NR_getresuid; case 150:return __NR_getresgid; case 158:return __NR_getgroups;
        case 167:return __NR_prctl; case 169:return __NR_gettimeofday; case 172:return __NR_getpid;
        case 173:return __NR_getppid; case 174:return __NR_getuid; case 175:return __NR_geteuid;
        case 176:return __NR_getgid; case 177:return __NR_getegid; case 178:return __NR_gettid;
        case 214:return __NR_brk; case 215:return __NR_munmap; case 222:return __NR_mmap;
        case 226:return __NR_mprotect; case 233:return __NR_madvise; case 278:return __NR_getrandom;
        default:return -1;
    }
}
static int host_program(struct loader_program *p) {
    *p=loader_filter_make();
    if(p->error || p->code[0].code!=0x20 || p->code[0].k!=4 ||
       p->code[1].k!=LOAD_ARCH || p->code[3].code!=0x20 || p->code[3].k!=0) return -1;
    p->code[1].k=AUDIT_ARCH_X86_64;
    /* Case heads contain syscall numbers. The openat flags additionally need
     * semantic translation: unlike mmap/prctl, they differ on x86-64. */
    _Static_assert((O_CLOEXEC|O_DIRECTORY|O_NOFOLLOW|O_NONBLOCK)==0xb0800,"host open flags");
    size_t at=4;
    while(at<p->count && p->code[at].code==0x15) {
        if(p->code[at].jt!=0 || !p->code[at].jf) return -1;
        if(p->code[at].k==56) {
            size_t mask=at+5;
            if(mask>=p->count || p->code[mask].code!=0x45 || p->code[mask].k!=~0xac800u) return -1;
            /* Kernel x86 O_LARGEFILE=0x8000; glibc defines its macro as zero. */
            p->code[mask].k=~0xb8800u;
        }
        int nr=translate(p->code[at].k); if(nr<0) return -1;
        p->code[at].k=(unsigned)nr; at+=1+p->code[at].jf;
    }
    return at==p->count-1 && p->code[at].code==0x06 && p->code[at].k==LOAD_TRAP ? 0:-1;
}
static int close_others(void) {
    DIR *d=opendir("/proc/self/fd"); if(!d) return -1;
    int own=dirfd(d),failed=0;
    for(;;) {
        errno=0; struct dirent *e=readdir(d);
        if(!e) { if(errno) failed=1; break; }
        if(!strcmp(e->d_name,".") || !strcmp(e->d_name,"..")) continue;
        char *end=NULL; long fd=strtol(e->d_name,&end,10);
        if(*end || fd<0 || fd>1048576) { failed=1; break; }
        if(fd!=3 && fd!=own && close((int)fd)) failed=1;
    }
    return closedir(d) || failed ? -1:0;
}
static void child_run(int pipe_fd,pid_t parent,const char *library) {
    if(pipe_fd!=3 && dup2(pipe_fd,3)!=3) _exit(70);
    if(close_others() || isolation_arm_watchdog(3) || prctl(PR_SET_PDEATHSIG,SIGKILL) ||
       getppid()!=parent) _exit(70);
    struct rlimit core={0,0}; if(setrlimit(RLIMIT_CORE,&core)) _exit(70);
    struct sigaction action; memset(&action,0,sizeof(action));
    action.sa_sigaction=rejected; action.sa_flags=SA_SIGINFO;
    if(sigemptyset(&action.sa_mask) || sigaction(SIGSYS,&action,NULL)) _exit(70);
    struct loader_program p;
    _Static_assert(sizeof(struct loader_instruction)==sizeof(struct sock_filter),"BPF layout");
    if(host_program(&p) || prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)) _exit(70);
    struct sock_fprog code={(unsigned short)p.count,(struct sock_filter *)p.code};
    if(prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&code)) _exit(70);
    send_result(10,0,NULL);
    void *loaded=dlopen(library,RTLD_NOW|RTLD_LOCAL);
    if(!loaded) { send_result(71,0,NULL); _exit(71); }
    int *value=dlsym(loaded,"loader_fixture_value");
    if(!value || *value!=42) { send_result(72,0,NULL); _exit(72); }
    if(dlclose(loaded)) _exit(73);
    send_result(42,0,NULL); _exit(0);
}
static int expected_syscall(int which) {
    switch(which) {
        case 2:return __NR_openat; case 3:return __NR_write; case 4:return __NR_socket;
        case 5:return __NR_ioctl; case 6:return __NR_clone; case 7:return __NR_execve;
        case 8:return __NR_rt_sigaction; case 9:case 10:return __NR_mmap;
        case 13:return __NR_prctl; case 14:return __NR_mprotect; case 15:return __NR_futex;
        case 16:return __NR_mremap; default:return -1;
    }
}
static int run_case(int which,const char *library) {
    char mode[16]; snprintf(mode,sizeof(mode),"%d",which);
    if(setenv("VIEWPORT_LOADER_FIXTURE_CASE",mode,1)) return -1;
    int pipe_fds[2]; if(pipe2(pipe_fds,O_CLOEXEC|O_NONBLOCK)) return -1;
    pid_t parent=getpid(),child=fork();
    if(child==0) child_run(pipe_fds[1],parent,library);
    close(pipe_fds[1]); if(child<0) { close(pipe_fds[0]); return -1; }
    int status=0,waited=isolation_wait_exit(child,&status,which==11 ? 1000:3000);
    int terminated=0;
    if(waited!=1) {
        struct isolation_reap_result stopped=isolation_stop_child(child,&status,3000,kill);
        if(stopped.reaped!=1) _exit(74);
        terminated=stopped.signal_sent;
    }
    struct loader_result messages[5]; ssize_t bytes=read(pipe_fds[0],messages,sizeof(messages));
    close(pipe_fds[0]);
    int ready=bytes>=(long)sizeof(messages[0]) && loader_marker(&messages[0],10,-1);
    int ok=bytes>=0 && loader_sequence(messages,(size_t)bytes,which,expected_syscall(which),
        WIFEXITED(status) ? WEXITSTATUS(status):-1,
        terminated && WIFSIGNALED(status) && WTERMSIG(status)==SIGKILL);
    if(!ok) {
        fprintf(stderr,"LOADER_CASE_FAIL case=%d status=%d bytes=%ld ready=%d",which,status,(long)bytes,ready);
        if(bytes>=(long)sizeof(messages[0])) {
            const struct loader_result *last=&messages[(size_t)bytes/sizeof(messages[0])-1];
            fprintf(stderr," tag=%d syscall=%d step=%d",last->tag,last->nr,last->step);
        }
        fputc('\n',stderr);
    }
    return ok ? 0:-1;
}
int main(int argc,char **argv) {
    if(argc!=2 || geteuid()==0 || isolation_prepare_parent()) return 2;
    char *library=realpath(argv[1],NULL); if(!library) return 2;
    unsigned cases=0;
    for(unsigned round=0;round<3;++round) for(int which=0;which<=16;++which) {
        if(run_case(which,library)) { free(library); return 1; }
        ++cases;
    }
    free(library);
    printf("LOADER_LINUX_TEST PASS cases=%u own_constructor_only=true filesystem_isolated=false nomad_tested=false native_start_allowed=false\n",cases);
    return 0;
}
