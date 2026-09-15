/* BUILD/REVIEW ONLY until the exact-source hardware gate is approved.
 * Loads only an embedded, authored constructor fixture. No arbitrary library
 * argument, firmware, pen engine, reader, input, Binder or annotation access. */
#define _GNU_SOURCE
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/magic.h>
#include <linux/seccomp.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/personality.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/ucontext.h>
#include <sys/wait.h>
#include <unistd.h>
#include "isolation_core.h"
#include "isolation_supervisor.h"
#include "loader_filter.h"
#include "loader_report.h"
#include "loader_resource.h"
#include "loader_fixture_blob.h" /* Generated from our fixture by the build. */
#if !defined(__aarch64__)
#error Android AArch64 diagnostic only.
#endif

#define FIXTURE_UID 65534
struct context {
    pid_t parent;
    const char *root;
    struct stat namespace_before,outer_before;
    int crash_after,root_readonly,mappings_verified,resource_limits_verified;
};

static int same_node(const struct stat *a,const struct stat *b) {
    return a->st_dev==b->st_dev && a->st_ino==b->st_ino && a->st_rdev==b->st_rdev && a->st_mode==b->st_mode;
}
static int write_all(int fd,const void *data,size_t size) {
    const unsigned char *p=data;
    while(size) {
        ssize_t n=write(fd,p,size);
        if(n<0 && errno==EINTR) continue;
        if(n<=0) return -1;
        p+=n; size-=(size_t)n;
    }
    return 0;
}
static void report(int tag,int nr,int step,const uint64_t *args) {
    struct loader_result r={LOADER_RESULT_MAGIC,tag,nr,step,{0}};
    if(args) for(unsigned i=0;i<6;++i) r.args[i]=args[i];
    if(syscall(__NR_write,3,&r,sizeof(r))!=(long)sizeof(r)) _exit(78);
}
static void rejected(int signal,siginfo_t *info,void *opaque) {
    (void)signal;
    ucontext_t *u=opaque;
    uint64_t args[6];
    for(unsigned i=0;i<6;++i) args[i]=u->uc_mcontext.regs[i];
    report(77,info->si_syscall,-1,args); _exit(77);
}
static int capabilities(int require_kill) {
    struct __user_cap_header_struct h={_LINUX_CAPABILITY_VERSION_3,0};
    struct __user_cap_data_struct c[2]={{0}};
    if(syscall(__NR_capget,&h,c)) return -1;
    if(require_kill) return c[CAP_KILL/32].effective & (1u<<(CAP_KILL%32)) ? 0:-1;
    return c[0].effective || c[0].permitted || c[0].inheritable ||
        c[1].effective || c[1].permitted || c[1].inheritable ? -1:0;
}
static int close_others(void) {
    DIR *d=opendir("/proc/self/fd"); if(!d) return -1;
    int own=dirfd(d),failed=0;
    for(;;) {
        errno=0; struct dirent *e=readdir(d);
        if(!e) { if(errno) failed=1; break; }
        if(!strcmp(e->d_name,".") || !strcmp(e->d_name,"..")) continue;
        char *end=NULL; long n=strtol(e->d_name,&end,10);
        if(end==e->d_name || *end || n<0 || n>1048576) { failed=1; break; }
        if(n!=3 && n!=own && close((int)n)) failed=1;
    }
    if(closedir(d)) failed=1;
    return failed ? -1:0;
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
static int outside_absent(void) {
    const char *paths[]={"/dev","/proc","/sys","/system","/system_ext","/apex","/data","/storage"};
    for(unsigned i=0;i<sizeof(paths)/sizeof(paths[0]);++i) {
        errno=0; int fd=open(paths[i],O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
        if(fd>=0) { close(fd); return -1; }
        if(errno!=ENOENT) return -1;
    }
    return 0;
}
static int private_mappings_only(void) {
    /* mprotect could make an inherited read-only shared mapping writable, so
     * reject ALL inherited shared mappings, not just those writable now.
     * This is a fail-closed snapshot before procfs/FD authority is removed. */
    FILE *maps=fopen("/proc/self/maps","re"); if(!maps) return -1;
    char line[2048],permissions[5]; unsigned count=0;
    int valid=1;
    while(fgets(line,sizeof(line),maps)) {
        unsigned long long start,end,offset;
        if(++count>4096 || !strchr(line,'\n') ||
            sscanf(line,"%llx-%llx %4s %llx",&start,&end,permissions,&offset)!=4 || start>=end ||
            strlen(permissions)!=4 || (permissions[0]!='r' && permissions[0]!='-') ||
            (permissions[1]!='w' && permissions[1]!='-') ||
            (permissions[2]!='x' && permissions[2]!='-') || permissions[3]!='p' ||
            (permissions[1]=='w' && permissions[2]=='x')) { valid=0; break; }
    }
    if(!count || ferror(maps)) valid=0;
    if(fclose(maps)) valid=0;
    return valid ? 0:-1;
}
static int install_policy(void) {
    _Static_assert(sizeof(struct loader_instruction)==sizeof(struct sock_filter),"BPF layout");
    _Static_assert(offsetof(struct seccomp_data,arch)==4 && offsetof(struct seccomp_data,nr)==0 &&
        offsetof(struct seccomp_data,args)==16,"seccomp ABI");
    _Static_assert(AUDIT_ARCH_AARCH64==LOAD_ARCH && SECCOMP_RET_ALLOW==LOAD_ALLOW &&
        SECCOMP_RET_TRAP==LOAD_TRAP && SECCOMP_RET_KILL_PROCESS==LOAD_KILL,"filter actions");
    _Static_assert(__NR_openat==56 && __NR_write==64 && __NR_futex==98 && __NR_prctl==167 &&
        __NR_mmap==222 && __NR_mprotect==226 && __NR_read==63 && __NR_close==57 &&
        __NR_lseek==62 && __NR_pread64==67 && __NR_readlinkat==78 && __NR_newfstatat==79 &&
        __NR_fstat==80 && __NR_capget==90 && __NR_exit==93 && __NR_exit_group==94 &&
        __NR_clock_gettime==113 && __NR_rt_sigreturn==139 && __NR_getresuid==148 &&
        __NR_getresgid==150 && __NR_getgroups==158 && __NR_gettimeofday==169 && __NR_getpid==172 &&
        __NR_getppid==173 && __NR_getuid==174 && __NR_geteuid==175 && __NR_getgid==176 &&
        __NR_getegid==177 && __NR_gettid==178 && __NR_brk==214 && __NR_munmap==215 &&
        __NR_madvise==233 && __NR_getrandom==278,"pinned syscall ABI");
    _Static_assert((O_CLOEXEC|O_NOFOLLOW|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK)==0xac800 &&
        (MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS|MAP_NORESERVE|MAP_FIXED_NOREPLACE|MAP_DENYWRITE)==0x104832 &&
        (PROT_READ|PROT_WRITE|PROT_EXEC)==7,"pinned argument ABI");
    struct loader_program p=loader_filter_make();
    if(p.error) return -1;
    struct sock_filter kernel[LOAD_CAPACITY];
    memcpy(kernel,p.code,p.count*sizeof(kernel[0]));
    struct sock_fprog program={(unsigned short)p.count,kernel};
    return prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&program);
}
static int seed(struct context *ctx) {
    if(loader_fixture_blob_size==0 || loader_fixture_blob_size>131072 || chdir(ctx->root)) return -1;
    int fd=open("fixture.so",O_CREAT|O_EXCL|O_NOFOLLOW|O_WRONLY|O_CLOEXEC,0600);
    if(fd<0) return -1;
    int result=write_all(fd,loader_fixture_blob,loader_fixture_blob_size);
    if(!result && fchmod(fd,0444)) result=-1;
    if(close(fd)) result=-1;
    if(result || mount(NULL,ctx->root,NULL,MS_REMOUNT|MS_RDONLY|MS_NOSUID|MS_NODEV,NULL)) return -1;
    struct statvfs flags;
    if(statvfs(ctx->root,&flags) || !(flags.f_flag&ST_RDONLY)) return -1;
    ctx->root_readonly=1;
    return 0;
}
static int perform(void *opaque,enum isolation_step step) {
    struct context *ctx=opaque;
    struct stat info; struct statfs fs;
    int result=-1;
    switch(step) {
        case ISO_CHILD_IDENTITY:
            result=getpid()!=ctx->parent && getppid()==ctx->parent && getuid()==0 &&
                lstat(ctx->root,&info)==0 && same_node(&info,&ctx->outer_before) ? 0:-1;
            break;
        case ISO_PARENT_LIFELINE: {
            unsigned long current=(unsigned long)personality(0xffffffffUL);
            struct rlimit core={0,0};
            if(current==(unsigned long)-1 || current&READ_IMPLIES_EXEC || setrlimit(RLIMIT_CORE,&core) ||
                isolation_arm_watchdog(5) || prctl(PR_SET_PDEATHSIG,SIGKILL)) break;
            struct sigaction action; memset(&action,0,sizeof(action));
            action.sa_sigaction=rejected; action.sa_flags=SA_SIGINFO;
            if(sigemptyset(&action.sa_mask) || sigaction(SIGSYS,&action,NULL)) break;
            result=getppid()==ctx->parent ? 0:-1;
            break;
        }
        case ISO_PRIVATE_NAMESPACE:
            if(unshare(CLONE_NEWNS) || stat("/proc/self/ns/mnt",&info)) break;
            result=info.st_dev==ctx->namespace_before.st_dev && info.st_ino!=ctx->namespace_before.st_ino ? 0:-1;
            break;
        case ISO_PRIVATE_PROPAGATION: result=mount(NULL,"/",NULL,MS_REC|MS_PRIVATE,NULL); break;
        case ISO_PRIVATE_ROOT:
            /* Executable mappings are needed ONLY for the embedded fixture.
             * The root becomes read-only before dropping privileges/loading. */
            if(mount("tmpfs",ctx->root,"tmpfs",MS_NOSUID|MS_NODEV,"size=2m,mode=0755") ||
                statfs(ctx->root,&fs) || lstat(ctx->root,&info)) break;
            result=fs.f_type==TMPFS_MAGIC && S_ISDIR(info.st_mode) && info.st_dev!=ctx->outer_before.st_dev ? 0:-1;
            break;
        case ISO_SEED_FIXTURES: result=seed(ctx); break;
        case ISO_CLOSE_INHERITED_FDS:
            if(private_mappings_only()) break;
            ctx->mappings_verified=1;
            /* A dense inherited table can occupy every descriptor below the
             * cap. Walk and close it while the inherited ceiling still permits
             * opening /proc/self/fd, then install both hard caps. */
            if(close_others() || getppid()!=ctx->parent ||
                loader_apply_resource_limits() || loader_resource_limits_exact()) break;
            ctx->resource_limits_verified=1;
            result=0; break;
        case ISO_CHROOT_AND_CWD:
            if(chroot(".") || chdir("/")) break;
            result=outside_absent(); break;
        case ISO_DROP_PRIVILEGES: {
            struct __user_cap_header_struct h={_LINUX_CAPABILITY_VERSION_3,0};
            struct __user_cap_data_struct c[2]={{0}};
            if(prctl(PR_SET_KEEPCAPS,0) || setgroups(0,NULL) ||
                setresgid(FIXTURE_UID,FIXTURE_UID,FIXTURE_UID) ||
                setresuid(FIXTURE_UID,FIXTURE_UID,FIXTURE_UID) || syscall(__NR_capset,&h,c) ||
                prctl(PR_SET_PDEATHSIG,SIGKILL) || getppid()!=ctx->parent) break;
            result=capabilities(0); break;
        }
        case ISO_NO_NEW_PRIVILEGES: result=prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0); break;
        case ISO_SYSCALL_FILTER: result=install_policy(); break;
        case ISO_VERIFY_BOUNDARY: {
            uid_t r,e,s; gid_t gr,ge,gs; int death=0;
            if(getresuid(&r,&e,&s) || getresgid(&gr,&ge,&gs)) break;
            result=r==FIXTURE_UID && e==FIXTURE_UID && s==FIXTURE_UID && gr==FIXTURE_UID &&
                ge==FIXTURE_UID && gs==FIXTURE_UID && getgroups(0,NULL)==0 && capabilities(0)==0 &&
                getppid()==ctx->parent && prctl(PR_GET_PDEATHSIG,&death)==0 && death==SIGKILL &&
                prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)==1 && prctl(PR_GET_SECCOMP,0,0,0,0)==SECCOMP_MODE_FILTER &&
                ctx->root_readonly && ctx->mappings_verified && ctx->resource_limits_verified &&
                outside_absent()==0 ? 0:-1;
            break;
        }
        case ISO_OWNED_IO_ONLY: {
            /* This is the first possible fixture initializer, after isolation. */
            report(10,0,-1,NULL);
            void *library=dlopen("/fixture.so",RTLD_NOW|RTLD_LOCAL);
            if(!library) { report(71,0,-1,NULL); break; }
            int *value=dlsym(library,"loader_fixture_value");
            if(!value || *value!=42) { report(72,0,-1,NULL); break; }
            result=dlclose(library); break;
        }
        default: break;
    }
    if(!result && (int)step==ctx->crash_after) _exit(75);
    return result;
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
static int run_case(int which,int crash_after) {
    struct stat ns,ebc,pen,outer,after;
    struct rlimit parent_as_before,parent_as_after,parent_nofile_before,parent_nofile_after;
    int descriptors_before=descriptor_count();
    if(geteuid()!=0 || capabilities(1) || stat("/proc/self/ns/mnt",&ns) ||
        lstat("/dev/ebc",&ebc) || lstat("/dev/input/event7",&pen) ||
        !S_ISCHR(ebc.st_mode) || !S_ISCHR(pen.st_mode) || descriptors_before<0 ||
        getrlimit(RLIMIT_AS,&parent_as_before) || getrlimit(RLIMIT_NOFILE,&parent_nofile_before)) return -1;
    char root[]="/data/local/tmp/native-viewport-loader-XXXXXX";
    if(!mkdtemp(root)) return -1;
    int result=-1,channel[2]={-1,-1}; pid_t child=-1;
    char mode[16]; snprintf(mode,sizeof(mode),"%d",which);
    if(setenv("VIEWPORT_LOADER_FIXTURE_CASE",mode,1) || lstat(root,&outer) || outer.st_uid!=0 ||
        !S_ISDIR(outer.st_mode) || (outer.st_mode&0777)!=0700 || pipe2(channel,O_CLOEXEC|O_NONBLOCK)) goto done;
    struct context ctx={getpid(),root,ns,outer,crash_after,0,0,0};
    child=fork();
    if(child==0) {
        if(channel[1]!=3 && dup2(channel[1],3)!=3) _exit(70);
        struct isolation_ops ops={&ctx,perform};
        struct isolation_result outcome=isolation_prove(&ops);
        report(outcome.mechanism_pass ? 42:70,outcome.mechanism_pass ? 0:errno,outcome.failed_step,NULL);
        _exit(outcome.mechanism_pass ? 0:70);
    }
    if(child<0) goto done;
    close(channel[1]); channel[1]=-1;
    int status=0;
    int waited=isolation_wait_exit(child,&status,which==11 ? 2000:7000);
    struct isolation_reap_result stopped={ISO_WAIT_TIMELY_EXIT,0,0,0};
    if(waited==ISO_WAIT_ELAPSED_TIMEOUT || waited==ISO_WAIT_SUPERVISOR_ERROR) {
        stopped=isolation_stop_child(child,&status,6000,kill);
        if(stopped.reaped!=ISO_WAIT_TIMELY_EXIT) {
            fprintf(stderr,"LOADER_CLEANUP_UNCERTAIN preserve=%s signal_errno=%d wait_errno=%d\n",root,stopped.signal_error,stopped.wait_error);
            _exit(74);
        }
    }
    int forced_timeout=isolation_confirmed_forced_timeout(waited,stopped,status);
    int provenance_ok=crash_after>=0 ? waited==ISO_WAIT_TIMELY_EXIT :
        which==11 ? forced_timeout : waited==ISO_WAIT_TIMELY_EXIT;
    child=-1;
    struct loader_result messages[5];
    size_t expected_bytes=loader_expected_report_bytes(which,crash_after);
    int wire_ok=expected_bytes<=sizeof(messages) &&
        isolation_read_exact_eof(channel[0],messages,expected_bytes,0)==0;
    if(crash_after>=0) result=provenance_ok && wire_ok && WIFEXITED(status) && WEXITSTATUS(status)==75 ? 0:-1;
    else result=provenance_ok && wire_ok && loader_sequence(messages,expected_bytes,which,expected_syscall(which),
        WIFEXITED(status) ? WEXITSTATUS(status):-1,
        forced_timeout) ? 0:-1;
    if(result) {
        fprintf(stderr,"LOADER_FAIL case=%d crash=%d status=%d expected_bytes=%lu wire_ok=%d",
            which,crash_after,status,(unsigned long)expected_bytes,wire_ok);
        if(wire_ok && expected_bytes>=sizeof(messages[0])) fprintf(stderr," first_tag=%d step=%d nr=%d",messages[0].tag,messages[0].step,messages[0].nr);
        if(wire_ok && expected_bytes>=2*sizeof(messages[0])) fprintf(stderr," second_tag=%d step=%d nr=%d",messages[1].tag,messages[1].step,messages[1].nr);
        fputc('\n',stderr);
    }
    if(stat("/proc/self/ns/mnt",&after) || !same_node(&ns,&after) || lstat(root,&after) || !same_node(&outer,&after) ||
        lstat("/dev/ebc",&after) || !same_node(&ebc,&after) || lstat("/dev/input/event7",&after) || !same_node(&pen,&after) ||
        getrlimit(RLIMIT_AS,&parent_as_after) || getrlimit(RLIMIT_NOFILE,&parent_nofile_after) ||
        !same_limit(&parent_as_before,&parent_as_after) || !same_limit(&parent_nofile_before,&parent_nofile_after)) result=-1;
done:
    if(child>0) { /* No path currently reaches here with an unreaped child. */
        int status=0;
        if(isolation_stop_child(child,&status,6000,kill).reaped!=1) _exit(74);
    }
    if(channel[0]>=0) close(channel[0]);
    if(channel[1]>=0) close(channel[1]);
    if(rmdir(root)) { fprintf(stderr,"LOADER_PRESERVE %s\n",root); result=-1; }
    if(descriptor_count()!=descriptors_before) result=-1;
    printf("LOADER_CASE case=%d crash=%d result=%s embedded_fixture_only=true firmware_loaded=false\n",which,crash_after,result ? "FAIL":"PASS");
    return result;
}
int main(int argc,char **argv) {
    if(argc!=2 || strcmp(argv[1],"--prove-fixture-loader") || isolation_prepare_parent()) return 2;
    for(int which=0;which<=18;++which) if(run_case(which,-1)) return 1;
    const int crashes[]={ISO_PRIVATE_ROOT,ISO_SEED_FIXTURES,ISO_CHROOT_AND_CWD,ISO_DROP_PRIVILEGES,ISO_SYSCALL_FILTER};
    for(unsigned i=0;i<sizeof(crashes)/sizeof(crashes[0]);++i) if(run_case(0,crashes[i])) return 1;
    puts("LOADER_FIXTURE_MECHANISM PASS cases=24 resource_caps=PASS firmware_loaded=false native_start_allowed=false");
    return 0;
}
