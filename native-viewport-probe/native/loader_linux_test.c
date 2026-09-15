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
#include <poll.h>
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
#include "loader_resource.h"
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
static int establish_child_lifeline(pid_t parent,unsigned watchdog_seconds) {
    return isolation_arm_watchdog(watchdog_seconds) ||
        prctl(PR_SET_PDEATHSIG,SIGKILL) || getppid()!=parent ? -1:0;
}
static int write_plain_exact(int fd,const void *data,size_t length) {
    const unsigned char *at=data;
    while(length) {
        ssize_t count=write(fd,at,length);
        if(count<0 && errno==EINTR) continue;
        if(count<=0) return -1;
        at+=count; length-=(size_t)count;
    }
    return 0;
}
static int read_ready_byte(int fd,unsigned timeout_ms,unsigned char *value) {
    int64_t start=isolation_clock_ms();
    if(start<0 || !value) return -1;
    for(;;) {
        int64_t now=isolation_clock_ms();
        if(now<start) return -1;
        uint64_t elapsed=(uint64_t)(now-start);
        if(elapsed>=timeout_ms) return -1;
        int remaining=(int)(timeout_ms-elapsed);
        struct pollfd ready={fd,POLLIN,0};
        int polled=poll(&ready,1,remaining);
        if(polled<0 && errno==EINTR) continue;
        if(polled<=0) return -1;
        ssize_t count=read(fd,value,1);
        if(count<0 && errno==EINTR) continue;
        return count==1 ? 0:-1;
    }
}
static int descriptor_count(void) {
    DIR *directory=opendir("/proc/self/fd");
    if(!directory) return -1;
    int count=0;
    for(;;) {
        errno=0; struct dirent *entry=readdir(directory);
        if(!entry) { if(errno) count=-1; break; }
        char *end=NULL; (void)strtol(entry->d_name,&end,10);
        if(end!=entry->d_name && *end=='\0') ++count;
    }
    return closedir(directory) || count<0 ? -1:count;
}
static int same_limit(const struct rlimit *a,const struct rlimit *b) {
    return a->rlim_cur==b->rlim_cur && a->rlim_max==b->rlim_max;
}

static int test_precleanup_stall(void) {
    int before=descriptor_count(),channel[2]={-1,-1},status=0;
    struct rlimit as_before,as_after,nofile_before,nofile_after;
    if(before<0 || getrlimit(RLIMIT_AS,&as_before) || getrlimit(RLIMIT_NOFILE,&nofile_before) ||
        pipe2(channel,O_CLOEXEC|O_NONBLOCK)) return 1;
    pid_t parent=getpid(),child=fork();
    if(child==0) {
        if(establish_child_lifeline(parent,1)) _exit(70);
        close(channel[0]);
        const unsigned char ready=0xa5;
        if(write_plain_exact(channel[1],&ready,1)) _exit(71);
        for(;;) pause(); /* Deliberate stall before inherited-FD traversal. */
    }
    close(channel[1]); channel[1]=-1;
    if(child<0) { close(channel[0]); return 1; }
    unsigned char ready=0;
    int ready_ok=read_ready_byte(channel[0],1000,&ready)==0 && ready==0xa5;
    int waited=isolation_wait_exit(child,&status,1500);
    struct isolation_reap_result stopped={ISO_WAIT_TIMELY_EXIT,0,0,0};
    if(waited!=ISO_WAIT_TIMELY_EXIT)
        stopped=isolation_stop_child(child,&status,1000,kill);
    int wire_ok=isolation_read_exact_eof(channel[0],&ready,1,ready_ok ? 1u:0u)==0;
    close(channel[0]);
    int unchanged=getrlimit(RLIMIT_AS,&as_after)==0 && getrlimit(RLIMIT_NOFILE,&nofile_after)==0 &&
        same_limit(&as_before,&as_after) && same_limit(&nofile_before,&nofile_after) &&
        descriptor_count()==before;
    return ready_ok && wire_ok && unchanged && waited==ISO_WAIT_TIMELY_EXIT &&
        !stopped.signal_sent && WIFSIGNALED(status) && WTERMSIG(status)==SIGALRM ? 0:1;
}

#define PARENT_LOSS_MAGIC 0x56504c50u
struct parent_loss_record { uint32_t magic; int32_t worker; };

static int test_parent_loss(void) {
    int old_subreaper=0,before=descriptor_count(),channel[2]={-1,-1};
    struct rlimit as_before,as_after,nofile_before,nofile_after;
    if(before<0 || getrlimit(RLIMIT_AS,&as_before) || getrlimit(RLIMIT_NOFILE,&nofile_before) ||
        prctl(PR_GET_CHILD_SUBREAPER,&old_subreaper) ||
        prctl(PR_SET_CHILD_SUBREAPER,1)) return 1;
    if(pipe2(channel,O_CLOEXEC|O_NONBLOCK)) {
        (void)prctl(PR_SET_CHILD_SUBREAPER,old_subreaper);
        return 1;
    }
    pid_t supervisor=fork();
    if(supervisor==0) {
        close(channel[0]);
        int ready_pipe[2];
        if(pipe2(ready_pipe,O_CLOEXEC)) _exit(70);
        pid_t expected_parent=getpid(),worker=fork();
        if(worker==0) {
            if(establish_child_lifeline(expected_parent,2)) _exit(71);
            close(ready_pipe[0]); close(channel[1]);
            const unsigned char ready=0x5a;
            if(write_plain_exact(ready_pipe[1],&ready,1)) _exit(72);
            close(ready_pipe[1]);
            for(;;) pause();
        }
        close(ready_pipe[1]);
        if(worker<0) _exit(73);
        unsigned char ready=0;
        if(read_ready_byte(ready_pipe[0],1000,&ready) || ready!=0x5a) {
            close(ready_pipe[0]);
            int cleanup_status=0;
            (void)isolation_stop_child(worker,&cleanup_status,1000,kill);
            _exit(74);
        }
        close(ready_pipe[0]);
        const struct parent_loss_record record={PARENT_LOSS_MAGIC,(int32_t)worker};
        if(write_plain_exact(channel[1],&record,sizeof(record))) {
            int cleanup_status=0;
            (void)isolation_stop_child(worker,&cleanup_status,1000,kill);
            _exit(75);
        }
        close(channel[1]);
        _exit(0); /* The armed worker must receive PDEATHSIG SIGKILL. */
    }
    close(channel[1]); channel[1]=-1;
    if(supervisor<0) {
        close(channel[0]); (void)prctl(PR_SET_CHILD_SUBREAPER,old_subreaper); return 1;
    }
    int supervisor_status=0;
    int supervisor_wait=isolation_wait_exit(supervisor,&supervisor_status,2000);
    if(supervisor_wait!=ISO_WAIT_TIMELY_EXIT) {
        (void)isolation_stop_child(supervisor,&supervisor_status,1000,kill);
    }
    struct parent_loss_record record={0};
    int wire_ok=supervisor_wait==ISO_WAIT_TIMELY_EXIT &&
        isolation_read_exact_eof(channel[0],&record,sizeof(record),0)==0;
    close(channel[0]);
    int worker_status=0,worker_wait=ISO_WAIT_SUPERVISOR_ERROR;
    if(wire_ok && record.magic==PARENT_LOSS_MAGIC && record.worker>0)
        worker_wait=isolation_wait_exit((pid_t)record.worker,&worker_status,2000);
    if(worker_wait!=ISO_WAIT_TIMELY_EXIT && wire_ok && record.worker>0)
        (void)isolation_stop_child((pid_t)record.worker,&worker_status,1000,kill);
    int restored=prctl(PR_SET_CHILD_SUBREAPER,old_subreaper)==0;
    int unchanged=getrlimit(RLIMIT_AS,&as_after)==0 && getrlimit(RLIMIT_NOFILE,&nofile_after)==0 &&
        same_limit(&as_before,&as_after) && same_limit(&nofile_before,&nofile_after) &&
        descriptor_count()==before;
    return wire_ok && record.magic==PARENT_LOSS_MAGIC &&
        supervisor_wait==ISO_WAIT_TIMELY_EXIT && WIFEXITED(supervisor_status) &&
        WEXITSTATUS(supervisor_status)==0 && worker_wait==ISO_WAIT_TIMELY_EXIT &&
        WIFSIGNALED(worker_status) && WTERMSIG(worker_status)==SIGKILL && restored && unchanged ? 0:1;
}
static void child_run(int pipe_fd,pid_t parent,const char *library) {
    if(pipe_fd!=3 && dup2(pipe_fd,3)!=3) _exit(70);
    /* Establish both independent lifelines before walking or closing any
     * inherited descriptor. Apply RLIMIT_NOFILE only after the traversal: a
     * dense inherited table may occupy every slot below the new ceiling. */
    if(establish_child_lifeline(parent,3) || close_others() || getppid()!=parent ||
       loader_apply_resource_limits() || loader_resource_limits_exact()) _exit(70);
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
    struct isolation_reap_result stopped={ISO_WAIT_TIMELY_EXIT,0,0,0};
    if(waited==ISO_WAIT_ELAPSED_TIMEOUT || waited==ISO_WAIT_SUPERVISOR_ERROR) {
        stopped=isolation_stop_child(child,&status,3000,kill);
        if(stopped.reaped!=ISO_WAIT_TIMELY_EXIT) _exit(74);
    }
    int forced_timeout=isolation_confirmed_forced_timeout(waited,stopped,status);
    struct loader_result messages[5];
    size_t expected_bytes=loader_expected_report_bytes(which,-1);
    int wire_ok=expected_bytes<=sizeof(messages) &&
        isolation_read_exact_eof(pipe_fds[0],messages,expected_bytes,0)==0;
    close(pipe_fds[0]);
    int ready=wire_ok && expected_bytes>=sizeof(messages[0]) && loader_marker(&messages[0],10,-1);
    int provenance_ok=which==11 ? forced_timeout : waited==ISO_WAIT_TIMELY_EXIT;
    int ok=provenance_ok && wire_ok && loader_sequence(messages,expected_bytes,which,expected_syscall(which),
        WIFEXITED(status) ? WEXITSTATUS(status):-1,
        forced_timeout);
    if(!ok) {
        fprintf(stderr,"LOADER_CASE_FAIL case=%d status=%d expected_bytes=%lu wire_ok=%d ready=%d",
            which,status,(unsigned long)expected_bytes,wire_ok,ready);
        if(wire_ok && expected_bytes>=sizeof(messages[0])) {
            const struct loader_result *last=&messages[expected_bytes/sizeof(messages[0])-1];
            fprintf(stderr," tag=%d syscall=%d step=%d",last->tag,last->nr,last->step);
        }
        fputc('\n',stderr);
    }
    return ok ? 0:-1;
}

static int test_dense_low_fds(const char *library) {
    int before=descriptor_count(),status=0;
    struct rlimit as_before,as_after,nofile_before,nofile_after;
    if(!library || before<0 || getrlimit(RLIMIT_AS,&as_before) ||
        getrlimit(RLIMIT_NOFILE,&nofile_before)) return 1;
    pid_t parent=getpid(),harness=fork();
    if(harness==0) {
        if(establish_child_lifeline(parent,8) || isolation_prepare_parent()) _exit(70);
        int seed=open("/dev/null",O_RDONLY|O_CLOEXEC);
        if(seed<0) _exit(71);
        for(int fd=3;fd<(int)LOADER_NOFILE_LIMIT;++fd) {
            if(fd!=seed && dup2(seed,fd)!=fd) _exit(72);
        }
        if(seed>=(int)LOADER_NOFILE_LIMIT && close(seed)) _exit(73);
        for(int fd=3;fd<(int)LOADER_NOFILE_LIMIT;++fd)
            if(fcntl(fd,F_GETFD)<0) _exit(74);
        _exit(run_case(0,library) ? 75:0);
    }
    if(harness<0) return 1;
    int waited=isolation_wait_exit(harness,&status,9000);
    if(waited!=ISO_WAIT_TIMELY_EXIT) {
        struct isolation_reap_result stopped=isolation_stop_child(harness,&status,1000,kill);
        if(stopped.reaped!=ISO_WAIT_TIMELY_EXIT) return 1;
    }
    int unchanged=getrlimit(RLIMIT_AS,&as_after)==0 &&
        getrlimit(RLIMIT_NOFILE,&nofile_after)==0 &&
        same_limit(&as_before,&as_after) && same_limit(&nofile_before,&nofile_after) &&
        descriptor_count()==before;
    return waited==ISO_WAIT_TIMELY_EXIT && WIFEXITED(status) &&
        WEXITSTATUS(status)==0 && unchanged ? 0:1;
}
int main(int argc,char **argv) {
    if(argc!=2 || geteuid()==0 || isolation_prepare_parent()) return 2;
    if(test_precleanup_stall() || test_parent_loss() || isolation_prepare_parent()) return 2;
    char *library=realpath(argv[1],NULL); if(!library) return 2;
    int descriptors_before=descriptor_count();
    struct rlimit as_before,as_after,nofile_before,nofile_after;
    if(descriptors_before<0 || getrlimit(RLIMIT_AS,&as_before) ||
        getrlimit(RLIMIT_NOFILE,&nofile_before)) { free(library); return 2; }
    if(test_dense_low_fds(library)) { free(library); return 1; }
    unsigned cases=0;
    for(unsigned round=0;round<3;++round) for(int which=0;which<=18;++which) {
        if(run_case(which,library)) { free(library); return 1; }
        ++cases;
    }
    free(library);
    if(getrlimit(RLIMIT_AS,&as_after) || getrlimit(RLIMIT_NOFILE,&nofile_after) ||
        !same_limit(&as_before,&as_after) || !same_limit(&nofile_before,&nofile_after) ||
        descriptor_count()!=descriptors_before) return 1;
    printf("LOADER_LINUX_TEST PASS cases=%u resource_caps=PASS dense_low_fds=PASS precleanup_stall=PASS parent_loss=PASS parent_unchanged=PASS own_constructor_only=true filesystem_isolated=false nomad_tested=false native_start_allowed=false\n",cases);
    return 0;
}
