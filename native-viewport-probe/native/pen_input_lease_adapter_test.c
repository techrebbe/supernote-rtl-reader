#define PEN_INPUT_LEASE_ADAPTER_TEST 1
#define _GNU_SOURCE 1
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
static pid_t tracked_fork(void);
static pid_t tracked_waitpid(pid_t,int *,int);
static void tracked_exit(int) __attribute__((noreturn));
#define fork tracked_fork
#define waitpid tracked_waitpid
#define _exit tracked_exit
#include "pen_input_lease.c"
#undef fork
#undef waitpid
#undef _exit

#include <assert.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <stdarg.h>
#include <stdatomic.h>

static void set_bit(unsigned char *bits, unsigned code) {
    bits[code/8] |= (unsigned char)(1u<<(code%8));
}

static void hash_bytes(const void *bytes,size_t length,unsigned char out[HASH_LENGTH]) {
    struct sha256_state hash;
    sha256_init(&hash); assert(sha256_update(&hash,bytes,length)==0); sha256_final(&hash,out);
}

static int different(const unsigned char *a,const unsigned char *b) {
    return !constant_equal(a,b,HASH_LENGTH);
}

#define FAKE_FD_FIRST 100
#define FAKE_FD_COUNT 32

struct fake_kernel_grab {
    _Atomic int grabbed_fd;
    _Atomic unsigned grab_calls;
    _Atomic unsigned ungrab_calls;
    _Atomic unsigned implicit_last_close_releases;
    _Atomic unsigned ofd_refs[FAKE_FD_COUNT];
    pid_t owners[8];
    uint32_t owner_masks[8];
    _Atomic int force_probe_loss;
    int entropy_calls,entropy_before_grab;
    int sigchld_policy_checks;
    pid_t guardian_process;
};
static struct fake_evdev *tracked_fake;

struct fake_evdev {
    struct captured_device descriptor;
    struct stat path_node;
    unsigned char current_keys[KEY_BYTES];
    int open_slots[FAKE_FD_COUNT];
    int next_slot;
    int grabbed_fd;
    struct fake_kernel_grab *kernel;
    int open_calls;
    int close_calls;
    int descriptor_captures;
    int revalidation_mutation_capture;
    int lstat_calls;
    int path_replacement_lstat;
    int idle_state_reads;
    int contact_after_idle_read;
    int contact_clear_after_idle_read;
    pid_t contact_mutation_pid;
    int termination_checks;
    int termination_on_check;
    uint64_t contact_clear_at_ms;
    unsigned contact_duration_ms;
};

static int fake_owner(struct fake_evdev *fake,pid_t process,int create) {
    for(int index=0;index<8;index++)
        if(fake->kernel->owners[index]==process)return index;
    if(create)for(int index=0;index<8;index++)if(fake->kernel->owners[index]==0) {
        fake->kernel->owners[index]=process;return index;
    }
    return -1;
}

static void fake_release_owner(struct fake_evdev *fake,pid_t process) {
    int owner=fake_owner(fake,process,0);
    if(owner<0)return;
    for(int slot=0;slot<FAKE_FD_COUNT;slot++)if(fake->kernel->owner_masks[owner]&(UINT32_C(1)<<slot)) {
        assert(fake->kernel->ofd_refs[slot]>0);
        if(--fake->kernel->ofd_refs[slot]==0&&fake->kernel->grabbed_fd==FAKE_FD_FIRST+slot) {
            fake->kernel->grabbed_fd=-1;fake->kernel->implicit_last_close_releases++;
        }
    }
    fake->kernel->owner_masks[owner]=0;fake->kernel->owners[owner]=0;
}

static int fake_grabbed_fd(const struct fake_evdev *fake) {
    return fake->kernel!=NULL?fake->kernel->grabbed_fd:fake->grabbed_fd;
}

static void fake_set_grabbed_fd(struct fake_evdev *fake,int fd) {
    if(fake->kernel!=NULL)fake->kernel->grabbed_fd=fd;
    else fake->grabbed_fd=fd;
}

static void fake_descriptor(struct fake_evdev *fake) {
    memset(fake,0,sizeof(*fake));
    fake->grabbed_fd=-1;
    fake->descriptor.node.st_mode=S_IFCHR|0600;
    fake->descriptor.node.st_dev=1;
    fake->descriptor.node.st_ino=2;
    fake->descriptor.node.st_rdev=3;
    fake->path_node=fake->descriptor.node;
    fake->descriptor.id.bustype=BUS_USB;
    fake->descriptor.id.vendor=0x056a;
    fake->descriptor.id.product=0x0001;
    fake->descriptor.id.version=1;
    memcpy(fake->descriptor.name,"Wacom-pen",10);
    memcpy(fake->descriptor.phys,"fixture-phys",13);
    memcpy(fake->descriptor.uniq,"fixture-uniq",13);
    set_bit(fake->descriptor.events,EV_SYN);
    set_bit(fake->descriptor.events,EV_KEY);
    set_bit(fake->descriptor.events,EV_ABS);
    set_bit(fake->descriptor.keys,BTN_TOUCH);
    set_bit(fake->descriptor.keys,BTN_TOOL_PEN);
    set_bit(fake->descriptor.keys,BTN_TOOL_RUBBER);
    set_bit(fake->descriptor.keys,BTN_STYLUS);
    set_bit(fake->descriptor.keys,BTN_STYLUS2);
    set_bit(fake->descriptor.axes,ABS_X);
    set_bit(fake->descriptor.axes,ABS_Y);
    set_bit(fake->descriptor.axes,ABS_PRESSURE);
    fake->descriptor.absolute[ABS_X].present=1;
    fake->descriptor.absolute[ABS_X].info.minimum=0;
    fake->descriptor.absolute[ABS_X].info.maximum=15819;
    fake->descriptor.absolute[ABS_X].info.resolution=100;
    fake->descriptor.absolute[ABS_Y].present=1;
    fake->descriptor.absolute[ABS_Y].info.minimum=0;
    fake->descriptor.absolute[ABS_Y].info.maximum=11864;
    fake->descriptor.absolute[ABS_Y].info.resolution=100;
    fake->descriptor.absolute[ABS_PRESSURE].present=1;
    fake->descriptor.absolute[ABS_PRESSURE].info.minimum=0;
    fake->descriptor.absolute[ABS_PRESSURE].info.maximum=4095;
}

static int fake_slot(struct fake_evdev *fake,int fd) {
    int slot=fd-FAKE_FD_FIRST;
    return slot>=0&&slot<FAKE_FD_COUNT&&fake->open_slots[slot] ? slot : -1;
}

static int fake_open_node(void *opaque,const char *path,int flags) {
    struct fake_evdev *fake=opaque; int slot=-1;
    assert(strcmp(path,PEN_NODE)==0);
    assert((flags&(O_ACCMODE|O_NONBLOCK|O_CLOEXEC|O_NOFOLLOW))==
        (O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_NOFOLLOW));
    /* A real descriptor number may be reused after close. Reuse a free fake
     * slot as well so long-duration continuous-revalidation tests exercise
     * the lease rather than exhausting an artificial monotonically growing
     * descriptor namespace. */
    for(int offset=0;offset<FAKE_FD_COUNT;offset++) {
        int candidate=(fake->next_slot+offset)%FAKE_FD_COUNT;
        if(!fake->open_slots[candidate]&&
                (fake->kernel==NULL||fake->kernel->ofd_refs[candidate]==0)) { slot=candidate; break; }
    }
    if(slot<0){errno=EMFILE;return -1;}
    fake->next_slot=(slot+1)%FAKE_FD_COUNT;
    fake->open_slots[slot]=1; fake->open_calls++;
    if(fake->kernel!=NULL) {
        int owner=fake_owner(fake,getpid(),1);assert(owner>=0);
        fake->kernel->ofd_refs[slot]++;
        fake->kernel->owner_masks[owner]|=UINT32_C(1)<<slot;
    }
    return FAKE_FD_FIRST+slot;
}

static int fake_lstat_node(void *opaque,const char *path,struct stat *value) {
    struct fake_evdev *fake=opaque;
    if(strcmp(path,PEN_NODE)!=0)return -1;
    fake->lstat_calls++;
    if(fake->path_replacement_lstat>0&&
            fake->lstat_calls>=fake->path_replacement_lstat) {
        fake->path_node.st_ino=fake->descriptor.node.st_ino+1;
    }
    *value=fake->path_node; return 0;
}

static int fake_fstat_fd(void *opaque,int fd,struct stat *value) {
    struct fake_evdev *fake=opaque;
    if(fake_slot(fake,fd)<0)return -1;
    *value=fake->descriptor.node; return 0;
}

static int fake_copy(void *destination,size_t destination_size,
        const void *source,size_t source_size) {
    if(destination_size<source_size)return -1;
    memcpy(destination,source,source_size); return (int)source_size;
}

static int fake_string(void *destination,size_t destination_size,
        const unsigned char *source) {
    size_t length=strnlen((const char *)source,destination_size);
    if(length>=destination_size)return -1;
    memcpy(destination,source,length+1); return (int)(length+1);
}

static int fake_ioctl_ptr(void *opaque,int fd,unsigned long request,void *value) {
    struct fake_evdev *fake=opaque;
    unsigned size=_IOC_SIZE(request);
    unsigned nr=_IOC_NR(request);
    if(fake_slot(fake,fd)<0){errno=EBADF;return -1;}
    if(request==EVIOCGID) {
        fake->descriptor_captures++;
        if(fake->revalidation_mutation_capture>0&&
                fake->descriptor_captures>=fake->revalidation_mutation_capture) {
            fake->descriptor.keys[BTN_STYLUS2/8]&=(unsigned char)~(1u<<(BTN_STYLUS2%8));
        }
        return fake_copy(value,size,&fake->descriptor.id,sizeof(fake->descriptor.id))<0?-1:0;
    }
    if(request==EVIOCGNAME(NAME_BYTES))return fake_string(value,size,fake->descriptor.name);
    if(request==EVIOCGPHYS(PHYS_BYTES))return fake_string(value,size,fake->descriptor.phys);
    if(request==EVIOCGUNIQ(UNIQ_BYTES))return fake_string(value,size,fake->descriptor.uniq);
    if(request==EVIOCGPROP(PROP_BYTES))return fake_copy(value,size,fake->descriptor.properties,sizeof(fake->descriptor.properties));
    if(request==EVIOCGBIT(0,EVENT_BYTES))return fake_copy(value,size,fake->descriptor.events,sizeof(fake->descriptor.events));
    if(request==EVIOCGBIT(EV_KEY,KEY_BYTES))return fake_copy(value,size,fake->descriptor.keys,sizeof(fake->descriptor.keys));
    if(request==EVIOCGBIT(EV_ABS,ABS_BYTES))return fake_copy(value,size,fake->descriptor.axes,sizeof(fake->descriptor.axes));
    if(request==EVIOCGKEY(KEY_BYTES)) {
        if(fake->contact_clear_at_ms>0) {
            struct timespec now;
            assert(clock_gettime(CLOCK_BOOTTIME,&now)==0);
            if((uint64_t)now.tv_sec*UINT64_C(1000)+(uint64_t)now.tv_nsec/UINT64_C(1000000)>=
                    fake->contact_clear_at_ms) {
                fake->current_keys[BTN_TOUCH/8]&=
                    (unsigned char)~(1u<<(BTN_TOUCH%8));
                fake->contact_clear_at_ms=0;
            }
        }
        fake->idle_state_reads++;
        if((fake->contact_mutation_pid==0||fake->contact_mutation_pid==getpid())&&
                fake->contact_after_idle_read>0&&
                fake->idle_state_reads>=fake->contact_after_idle_read) {
            set_bit(fake->current_keys,BTN_TOUCH);
            if(fake->contact_duration_ms>0) {
                uint64_t now;
                assert(boottime_ms(NULL,&now)==0);
                fake->contact_clear_at_ms=now+fake->contact_duration_ms;
                fake->contact_after_idle_read=0;
            }
        }
        if((fake->contact_mutation_pid==0||fake->contact_mutation_pid==getpid())&&
                fake->contact_clear_after_idle_read>0&&
                fake->idle_state_reads>=fake->contact_clear_after_idle_read) {
            fake->current_keys[BTN_TOUCH/8]&=
                (unsigned char)~(1u<<(BTN_TOUCH%8));
        }
        return fake_copy(value,size,fake->current_keys,sizeof(fake->current_keys));
    }
    if(nr>=_IOC_NR(EVIOCGABS(0))&&nr<=_IOC_NR(EVIOCGABS(ABS_MAX))) {
        unsigned code=nr-_IOC_NR(EVIOCGABS(0));
        if(!fake->descriptor.absolute[code].present)return -1;
        return fake_copy(value,size,&fake->descriptor.absolute[code].info,
            sizeof(fake->descriptor.absolute[code].info))<0?-1:0;
    }
    errno=EINVAL; return -1;
}

static int fake_ioctl_int(void *opaque,int fd,unsigned long request,int value) {
    struct fake_evdev *fake=opaque;
    if(fake_slot(fake,fd)<0||request!=EVIOCGRAB){errno=EINVAL;return -1;}
    if(value==1) {
        if(fake->kernel!=NULL&&fd!=fake_grabbed_fd(fake)&&atomic_exchange(&fake->kernel->force_probe_loss,0)) {
            fake_set_grabbed_fd(fake,-1);
        }
        if(fake->kernel!=NULL) {
            int expected=-1;
            if(!atomic_compare_exchange_strong(&fake->kernel->grabbed_fd,&expected,fd)){errno=EBUSY;return -1;}
        } else {
            if(fake_grabbed_fd(fake)>=0){errno=EBUSY;return -1;}
            fake_set_grabbed_fd(fake,fd);
        }
        if(fake->kernel!=NULL)fake->kernel->grab_calls++;
        return 0;
    }
    if(value==0&&fake_grabbed_fd(fake)==fd){
        fake_set_grabbed_fd(fake,-1);
        if(fake->kernel!=NULL)fake->kernel->ungrab_calls++;
        return 0;
    }
    errno=EINVAL; return -1;
}

static int fake_close_fd(void *opaque,int fd) {
    struct fake_evdev *fake=opaque; int slot=fake_slot(fake,fd);
    if(slot<0){errno=EBADF;return -1;}
    if(fake->kernel==NULL&&fake->grabbed_fd==fd)fake->grabbed_fd=-1;
    if(fake->kernel!=NULL) {
        int owner=fake_owner(fake,getpid(),0);assert(owner>=0);
        assert(fake->kernel->owner_masks[owner]&(UINT32_C(1)<<slot));
        fake->kernel->owner_masks[owner]&=~(UINT32_C(1)<<slot);
        assert(fake->kernel->ofd_refs[slot]>0);
        if(--fake->kernel->ofd_refs[slot]==0&&fake_grabbed_fd(fake)==fd) {
            fake_set_grabbed_fd(fake,-1);fake->kernel->implicit_last_close_releases++;
        }
    }
    fake->open_slots[slot]=0; fake->close_calls++; return 0;
}

#ifdef PEN_INPUT_LEASE_LINK_WRAPPER
extern pid_t __real_fork(void);
extern pid_t __real_waitpid(pid_t,int *,int);
extern void __real__exit(int) __attribute__((noreturn));
#endif
static pid_t tracked_fork(void) {
    struct fake_evdev *fake=tracked_fake;
    int reservation=-1;pid_t result;
    if(fake!=NULL&&fake->kernel!=NULL) {
        int owner=fake_owner(fake,getpid(),0);
        if(owner>=0&&fake->kernel->owner_masks[owner]!=0) {
            reservation=fake_owner(fake,-1,1);assert(reservation>=0);
            fake->kernel->owner_masks[reservation]=fake->kernel->owner_masks[owner];
            for(int slot=0;slot<FAKE_FD_COUNT;slot++)
                if(fake->kernel->owner_masks[reservation]&(UINT32_C(1)<<slot))fake->kernel->ofd_refs[slot]++;
        }
    }
#ifdef PEN_INPUT_LEASE_LINK_WRAPPER
    result=__real_fork();
#else
    result=fork();
#endif
    if(reservation>=0) {
        if(result<0)fake_release_owner(fake,-1);
        else fake->kernel->owners[reservation]=result==0?getpid():result;
    }
    return result;
}
static pid_t tracked_waitpid(pid_t process,int *status,int options) {
#ifdef PEN_INPUT_LEASE_LINK_WRAPPER
    pid_t result=__real_waitpid(process,status,options);
#else
    pid_t result=waitpid(process,status,options);
#endif
    if(result>0&&status!=NULL&&(WIFEXITED(*status)||WIFSIGNALED(*status))&&
            tracked_fake!=NULL&&tracked_fake->kernel!=NULL)
        fake_release_owner(tracked_fake,result);
    return result;
}
static void tracked_exit(int status) {
    if(tracked_fake!=NULL&&tracked_fake->kernel!=NULL)
        fake_release_owner(tracked_fake,getpid());
#ifdef PEN_INPUT_LEASE_LINK_WRAPPER
    __real__exit(status);
#else
    _exit(status);
#endif
}
#define fork tracked_fork
#define waitpid tracked_waitpid
#define _exit tracked_exit

static const struct pen_device_io fake_device_io={
    fake_open_node,fake_lstat_node,fake_fstat_fd,
    fake_ioctl_ptr,fake_ioctl_int,fake_close_fd
};

static void test_sha_and_descriptor(void) {
    static const unsigned char abc_expected[HASH_LENGTH]={
        0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
        0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad};
    struct captured_device base,changed;
    unsigned char identity[HASH_LENGTH],snapshot[HASH_LENGTH],other_identity[HASH_LENGTH],other_snapshot[HASH_LENGTH];
    hash_bytes("abc",3,other_identity);
    assert(constant_equal(other_identity,abc_expected,HASH_LENGTH));
    memset(&base,0,sizeof(base));
    base.node.st_mode=S_IFCHR|0600; base.node.st_dev=1; base.node.st_ino=2; base.node.st_rdev=3;
    base.id.bustype=3; base.id.vendor=0x56a; base.id.product=1; base.id.version=2;
    memcpy(base.name,"Wacom-pen",10); memcpy(base.phys,"fixture-phys",13); memcpy(base.uniq,"fixture-uniq",13);
    set_bit(base.events,EV_SYN); set_bit(base.events,EV_KEY); set_bit(base.events,EV_ABS);
    set_bit(base.keys,BTN_TOUCH); set_bit(base.keys,BTN_TOOL_PEN);
    set_bit(base.keys,BTN_TOOL_RUBBER); set_bit(base.keys,BTN_STYLUS);
    set_bit(base.keys,BTN_STYLUS2);
    set_bit(base.axes,ABS_X); set_bit(base.axes,ABS_Y); set_bit(base.axes,ABS_PRESSURE);
    base.absolute[ABS_X].present=1; base.absolute[ABS_Y].present=1;
    base.absolute[ABS_PRESSURE].present=1;
    base.absolute[ABS_X].info.value=123; base.absolute[ABS_X].info.maximum=15819;
    base.absolute[ABS_X].info.resolution=100;
    base.absolute[ABS_Y].info.value=456; base.absolute[ABS_Y].info.maximum=11864;
    base.absolute[ABS_Y].info.resolution=100;
    base.absolute[ABS_PRESSURE].info.maximum=4095;
    hash_captured_descriptor(&base,identity,snapshot);

    changed=base; changed.absolute[ABS_X].info.value=9876;
    hash_captured_descriptor(&changed,other_identity,other_snapshot);
    assert(constant_equal(identity,other_identity,HASH_LENGTH));
    assert(different(snapshot,other_snapshot));
    changed=base; changed.absolute[ABS_Y].info.value=8765;
    hash_captured_descriptor(&changed,other_identity,other_snapshot);
    assert(constant_equal(identity,other_identity,HASH_LENGTH));
    assert(different(snapshot,other_snapshot));
    changed=base; changed.absolute[ABS_PRESSURE].info.value=1;
    hash_captured_descriptor(&changed,other_identity,other_snapshot);
    assert(constant_equal(identity,other_identity,HASH_LENGTH));
    assert(different(snapshot,other_snapshot));
    changed=base; changed.absolute[ABS_X].info.maximum++;
    hash_captured_descriptor(&changed,other_identity,other_snapshot);
    assert(different(identity,other_identity)&&different(snapshot,other_snapshot));
    changed=base; changed.keys[BTN_STYLUS/8]&=(unsigned char)~(1u<<(BTN_STYLUS%8));
    hash_captured_descriptor(&changed,other_identity,other_snapshot);
    assert(different(identity,other_identity));
    changed=base; changed.id.product++;
    hash_captured_descriptor(&changed,other_identity,other_snapshot);
    assert(different(identity,other_identity));
    changed=base; changed.phys[0]^=1;
    hash_captured_descriptor(&changed,other_identity,other_snapshot);
    assert(different(identity,other_identity));
    changed=base; changed.properties[0]^=1;
    hash_captured_descriptor(&changed,other_identity,other_snapshot);
    assert(different(identity,other_identity));
    changed=base; changed.node.st_ino++;
    hash_captured_descriptor(&changed,other_identity,other_snapshot);
    assert(different(identity,other_identity));
    assert(parse_hash("short",other_identity)!=0);
}

static void test_stat_and_idle(void) {
    struct pen_authority expected;
    struct stat actual;
    unsigned char keys[KEY_BYTES]={0};
    memset(&expected,0,sizeof(expected)); memset(&actual,0,sizeof(actual));
    expected.node_dev=1; expected.node_ino=2; expected.node_rdev=3; expected.node_mode=S_IFCHR|0600;
    actual.st_dev=1; actual.st_ino=2; actual.st_rdev=3; actual.st_mode=S_IFCHR|0600;
    assert(same_node_stat(&expected,&actual));
    actual.st_ino=4; assert(!same_node_stat(&expected,&actual));
    actual.st_ino=2; actual.st_mode=S_IFLNK|0777; assert(!same_node_stat(&expected,&actual));
    assert(idle_from_state(0,keys)==0);
    assert(idle_from_state(1,keys)==1);
    set_bit(keys,BTN_TOOL_PEN); assert(idle_from_state(0,keys)==1);
    memset(keys,0,sizeof(keys)); set_bit(keys,BTN_TOUCH); assert(idle_from_state(0,keys)==1);
    memset(keys,0,sizeof(keys)); set_bit(keys,BTN_TOOL_RUBBER); assert(idle_from_state(0,keys)==1);
    memset(keys,0,sizeof(keys)); set_bit(keys,BTN_STYLUS); assert(idle_from_state(0,keys)==1);
    memset(keys,0,sizeof(keys)); set_bit(keys,BTN_STYLUS2); assert(idle_from_state(0,keys)==1);
}

static void test_fake_capture_and_required_buttons(void) {
    const unsigned required[]={BTN_TOOL_RUBBER,BTN_STYLUS,BTN_STYLUS2};
    struct fake_evdev fake; struct lease_context context;
    struct captured_device captured; int fd;
    fake_descriptor(&fake); memset(&context,0,sizeof(context));
    context.device_io=&fake_device_io; context.device_opaque=&fake;
    fd=fake_open_node(&fake,PEN_NODE,O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_NOFOLLOW);
    assert(fd>=FAKE_FD_FIRST);
    assert(capture_device_descriptor(&context,fd,&captured)==0);
    for(size_t i=0;i<sizeof(required)/sizeof(required[0]);i++) {
        unsigned code=required[i];
        fake.descriptor.keys[code/8]&=(unsigned char)~(1u<<(code%8));
        assert(capture_device_descriptor(&context,fd,&captured)!=0);
        set_bit(fake.descriptor.keys,code);
    }
    assert(fake_close_fd(&fake,fd)==0);

    /* Even if an open implementation were tricked into following the fixed
     * node path, the production post-open lstat/fstat authority check rejects
     * a symlink before descriptor admission. */
    fake_descriptor(&fake); memset(&context,0,sizeof(context));
    context.device_io=&fake_device_io; context.device_opaque=&fake;
    context.authority.node_dev=(uint64_t)fake.descriptor.node.st_dev;
    context.authority.node_ino=(uint64_t)fake.descriptor.node.st_ino;
    context.authority.node_rdev=(uint64_t)fake.descriptor.node.st_rdev;
    context.authority.node_mode=(uint32_t)fake.descriptor.node.st_mode;
    fake.path_node.st_mode=S_IFLNK|0777;
    assert(open_pen(&context)<0);
    assert(fake.open_calls==1&&fake.close_calls==1&&fake_grabbed_fd(&fake)<0);
}

static void make_pipe(int pair[2]) {
    assert(pipe2(pair,O_CLOEXEC|O_NONBLOCK)==0);
}

static int make_authority_record(struct lease_context *context,
        const struct stat *node,const unsigned char identity[HASH_LENGTH],
        const unsigned char snapshot[HASH_LENGTH]) {
    char path[]="/tmp/pen-lease-authority-XXXXXX";
    char line[AUTHORITY_MAX_BYTES];
    char identity_hex[TOKEN_HEX_LENGTH+1],snapshot_hex[TOKEN_HEX_LENGTH+1];
    unsigned char digest[HASH_LENGTH];
    int temporary=mkstemp(path),length,fd;
    struct lease_context parsed;
    assert(temporary>=0);
    for(size_t i=0;i<HASH_LENGTH;i++) {
        snprintf(identity_hex+i*2,3,"%02x",identity[i]);
        snprintf(snapshot_hex+i*2,3,"%02x",snapshot[i]);
    }
    length=snprintf(line,sizeof(line),
        "PEN_INPUT_AUTHORITY_V1 token=%s node_dev=%016llx node_ino=%016llx "
        "node_rdev=%016llx node_mode=%08x identity_sha256=%s snapshot_sha256=%s\n",
        context->token,(unsigned long long)node->st_dev,
        (unsigned long long)node->st_ino,(unsigned long long)node->st_rdev,
        (unsigned)(uint32_t)node->st_mode,identity_hex,snapshot_hex);
    assert(length>0&&(size_t)length<sizeof(line));
    memset(&parsed,0,sizeof(parsed)); memcpy(parsed.token,context->token,sizeof(parsed.token));
    assert(parse_authority(&parsed,line,(size_t)length)==0);
    for(size_t cut=0;cut<(size_t)length;cut++) {
        memset(&parsed.authority,0,sizeof(parsed.authority));
        assert(parse_authority(&parsed,line,cut)!=0);
    }
    line[length]='x'; line[length+1]='\0';
    assert(parse_authority(&parsed,line,(size_t)length+1)!=0); line[length]='\0';
    assert(write(temporary,line,(size_t)length)==length); assert(close(temporary)==0);
    fd=open(path,O_RDONLY|O_CLOEXEC); assert(fd>=0); assert(unlink(path)==0);
    hash_bytes(line,(size_t)length,digest); memcpy(context->authority_file_hash,digest,HASH_LENGTH);
    return fd;
}

static int make_authority(struct lease_context *context) {
    struct stat node; unsigned char zeros[HASH_LENGTH]={0};
    memset(&node,0,sizeof(node)); node.st_dev=1; node.st_ino=2;
    node.st_rdev=3; node.st_mode=S_IFCHR|0600;
    return make_authority_record(context,&node,zeros,zeros);
}

static int make_fake_authority(struct lease_context *context,struct fake_evdev *fake) {
    unsigned char identity[HASH_LENGTH],snapshot[HASH_LENGTH];
    hash_captured_descriptor(&fake->descriptor,identity,snapshot);
    return make_authority_record(context,&fake->descriptor.node,identity,snapshot);
}

struct endpoint_fixture {
    struct lease_context context;
    int control[2],phase[2],status[2];
    struct fake_evdev *fake;
};

static void fixture_open(struct endpoint_fixture *fixture,const char *phase_suffix) {
    char initial[192]; int length;
    memset(fixture,0,sizeof(*fixture)); memset(fixture->context.token,'a',TOKEN_HEX_LENGTH);
    fixture->context.token[TOKEN_HEX_LENGTH]='\0'; fixture->context.hold_ms=500;
    make_pipe(fixture->control); make_pipe(fixture->phase); make_pipe(fixture->status);
    fixture->context.control_fd=fixture->control[0]; fixture->context.phase_fd=fixture->phase[0];
    fixture->context.status_fd=fixture->status[1]; fixture->context.authority_fd=make_authority(&fixture->context);
    length=snprintf(initial,sizeof(initial),"PHASE DESTROYED BEFORE %s\n%s",fixture->context.token,phase_suffix);
    assert(length>0&&(size_t)length<sizeof(initial)); assert(write(fixture->phase[1],initial,(size_t)length)==length);
}

static void fixture_close(struct endpoint_fixture *fixture) {
    if(fixture->context.authority_fd>=0) close(fixture->context.authority_fd);
    if(fixture->control[0]>=0) close(fixture->control[0]);
    if(fixture->control[1]>=0) close(fixture->control[1]);
    if(fixture->phase[0]>=0) close(fixture->phase[0]);
    if(fixture->phase[1]>=0) close(fixture->phase[1]);
    if(fixture->status[0]>=0) close(fixture->status[0]);
    if(fixture->status[1]>=0) close(fixture->status[1]);
    if(fixture->fake!=NULL&&fixture->fake->kernel!=NULL) {
        assert(fixture->fake->kernel->grabbed_fd<0);
        assert(munmap(fixture->fake->kernel,sizeof(*fixture->fake->kernel))==0);
        fixture->fake->kernel=NULL;fixture->fake=NULL;
        tracked_fake=NULL;
    }
}

static void fixture_open_fake(struct endpoint_fixture *fixture,
        struct fake_evdev *fake,uint64_t hold_ms) {
    fixture_open(fixture,"");
    close(fixture->context.authority_fd);
    fixture->context.device_io=&fake_device_io;
    fixture->context.device_opaque=fake;
    fixture->context.hold_ms=hold_ms;
    fake->kernel=mmap(NULL,sizeof(*fake->kernel),PROT_READ|PROT_WRITE,
        MAP_SHARED|MAP_ANONYMOUS,-1,0);
    assert(fake->kernel!=MAP_FAILED);
    memset(fake->kernel,0,sizeof(*fake->kernel));fake->kernel->grabbed_fd=-1;
    fixture->fake=fake;
    tracked_fake=fake;
    fixture->context.authority_fd=make_fake_authority(&fixture->context,fake);
}

static void fake_cleanup(struct fake_evdev *fake) {
    int held=fake_grabbed_fd(fake);
    if(held>=0)assert(fake_ioctl_int(fake,held,EVIOCGRAB,0)==0);
    for(int slot=0;slot<FAKE_FD_COUNT;slot++) {
        if(fake->open_slots[slot])assert(fake_close_fd(fake,FAKE_FD_FIRST+slot)==0);
    }
}

static void fake_kernel_last_process_teardown(struct fake_evdev *fake) {
    assert(fake->kernel!=NULL);
    for(int owner=0;owner<8;owner++)if(fake->kernel->owners[owner]!=0)
        fake_release_owner(fake,fake->kernel->owners[owner]);
    assert(fake->kernel->grabbed_fd<0);
}

static void arm_guardian_contact(void *opaque,unsigned duration_ms) {
    struct fake_evdev *fake=opaque;
    struct timespec now;
    uint64_t current;
    assert(fake!=NULL&&duration_ms>0&&clock_gettime(CLOCK_BOOTTIME,&now)==0);
    current=(uint64_t)now.tv_sec*UINT64_C(1000)+
        (uint64_t)now.tv_nsec/UINT64_C(1000000);
    assert(UINT64_MAX-current>=duration_ms);
    set_bit(fake->current_keys,BTN_TOUCH);
    fake->contact_clear_at_ms=current+duration_ms;
}

static void arm_contact_after_prepared(void *opaque) {
    struct fake_evdev *fake=opaque;
    assert(fake!=NULL);
    set_bit(fake->current_keys,BTN_TOUCH);
}

static int test_arm_parent(void *unused) { (void)unused; return 0; }
static int injected_termination_pending(void *opaque) {
    struct lease_context *context=opaque;
    struct fake_evdev *fake=context->device_opaque;
    fake->termination_checks++;
    if(fake->termination_on_check>0&&
            fake->termination_checks==fake->termination_on_check)
        assert(raise(SIGTERM)==0);
    return termination_pending(NULL);
}
static int quarantine_calls;
static int quarantine_first;
static void returning_quarantine(void *unused,int first,int second) {
    (void)unused; (void)second; quarantine_calls++; quarantine_first=first;
}

enum coordinator_mode {
    COORDINATOR_RELEASE,
    COORDINATOR_TIMEOUT,
    COORDINATOR_LOSS,
    COORDINATOR_FAILED_ASYNC,
    COORDINATOR_FAILED_AFTER_RELEASE,
    COORDINATOR_RELEASE_AFTER_ALARM,
    COORDINATOR_SPOOFED_RELEASE,
    COORDINATOR_PARTIAL_RELEASE,
    COORDINATOR_REPLAYED_RELEASE,
    COORDINATOR_SIGNAL_AFTER_READY,
    COORDINATOR_DELAYED_REPLAY,
    COORDINATOR_LEAKED_WRITER
};

struct guardian_binding {
    pid_t pid;
    uint64_t starttime;
    char session[TOKEN_HEX_LENGTH+1];
};

static void parse_ready_binding(const char *record,struct guardian_binding *binding) {
    char *authority=strstr(record," guardian_pid=");
    unsigned long long starttime=0; long pid=0; int consumed=0;
    memset(binding,0,sizeof(*binding));
    assert(authority!=NULL&&sscanf(authority,
        " guardian_pid=%ld guardian_starttime=%llu guardian_session=%64[0-9a-f]\n%n",
        &pid,&starttime,binding->session,&consumed)==3&&
        consumed==(int)strlen(authority)&&pid>1&&starttime>0&&
        valid_token(binding->session));
    binding->pid=(pid_t)pid;binding->starttime=(uint64_t)starttime;
}

static void external_final_records(const struct endpoint_fixture *fixture,
        const struct guardian_binding *binding,char *release,size_t release_size,
        char *phase,size_t phase_size) {
    int first=snprintf(release,release_size,
        "RELEASE %s guardian_pid=%ld guardian_starttime=%llu guardian_session=%s\n",
        fixture->context.token,(long)binding->pid,
        (unsigned long long)binding->starttime,binding->session);
    int second=snprintf(phase,phase_size,
        "PHASE DESTROYED FINAL %s guardian_pid=%ld guardian_starttime=%llu guardian_session=%s\n",
        fixture->context.token,(long)binding->pid,
        (unsigned long long)binding->starttime,binding->session);
    assert(first>0&&(size_t)first<release_size&&second>0&&
        (size_t)second<phase_size);
}

static void child_read_line(int fd,const char *required_prefix,char *record,size_t capacity) {
    size_t used=0;
    while(used+1<capacity) {
        struct pollfd endpoint={fd,POLLIN,0}; ssize_t got;
        assert(poll(&endpoint,1,3000)==1&&(endpoint.revents&POLLIN)!=0);
        got=read(fd,record+used,1); assert(got==1);
        if(record[used++]=='\n')break;
    }
    assert(used>0&&used+1<=capacity&&record[used-1]=='\n');
    record[used]='\0';
    if(strncmp(record,required_prefix,strlen(required_prefix))!=0) {
        fprintf(stderr,"unexpected status record: expected_prefix=%s actual=%s",
            required_prefix,record);
        assert(0);
    }
    assert(memchr(record,'\n',used-1)==NULL);
}

static pid_t start_coordinator(struct endpoint_fixture *fixture,
        enum coordinator_mode mode) {
    pid_t child=fork(); assert(child>=0);
    if(child==0) {
        char prefix[160],release[512],phase[512],terminal[512],record[512];
        struct guardian_binding binding;
        snprintf(prefix,sizeof(prefix),"PEN_INPUT_LEASE_READY token=%s ",fixture->context.token);
        close(fixture->control[0]); close(fixture->phase[0]); close(fixture->status[1]);
        child_read_line(fixture->status[0],prefix,record,sizeof(record));
        parse_ready_binding(record,&binding);
        external_final_records(fixture,&binding,release,sizeof(release),phase,sizeof(phase));
        if(mode==COORDINATOR_LOSS) {
            close(fixture->status[0]); close(fixture->control[1]); close(fixture->phase[1]);
            _exit(0);
        }
        if(mode==COORDINATOR_SIGNAL_AFTER_READY)assert(kill(getppid(),SIGTERM)==0);
        if(mode==COORDINATOR_SPOOFED_RELEASE) {
            char spoofed[sizeof(release)];
            memcpy(spoofed,release,strlen(release)+1);
            {
                char *session=strstr(spoofed,"guardian_session=");
                assert(session!=NULL);session[strlen("guardian_session=")]^=1;
            }
            assert(write(fixture->control[1],spoofed,strlen(spoofed))==
                (ssize_t)strlen(spoofed));
        } else if(mode==COORDINATOR_PARTIAL_RELEASE) {
            assert(write(fixture->control[1],"REL",3)==3);
        } else if(mode==COORDINATOR_REPLAYED_RELEASE) {
            char replay[sizeof(release)*2];size_t length=strlen(release);
            assert(length*2<sizeof(replay));memcpy(replay,release,length);
            memcpy(replay+length,release,length);
            assert(write(fixture->control[1],replay,length*2)==(ssize_t)(length*2));
        }
        if(mode==COORDINATOR_RELEASE||mode==COORDINATOR_FAILED_AFTER_RELEASE||
                mode==COORDINATOR_RELEASE_AFTER_ALARM||
                mode==COORDINATOR_DELAYED_REPLAY||mode==COORDINATOR_LEAKED_WRITER) {
            (void)poll(NULL,0,mode==COORDINATOR_RELEASE_AFTER_ALARM?1200:80);
            assert(write(fixture->control[1],release,strlen(release))==(ssize_t)strlen(release));
        }
        if(mode!=COORDINATOR_FAILED_ASYNC&&mode!=COORDINATOR_SPOOFED_RELEASE&&
                mode!=COORDINATOR_PARTIAL_RELEASE&&
                mode!=COORDINATOR_REPLAYED_RELEASE&&
                mode!=COORDINATOR_SIGNAL_AFTER_READY) {
            assert(write(fixture->phase[1],phase,strlen(phase))==(ssize_t)strlen(phase));
        }
        if(mode==COORDINATOR_DELAYED_REPLAY) {
            (void)poll(NULL,0,100);
            assert(write(fixture->control[1],release,strlen(release))==
                (ssize_t)strlen(release));
        }
        if(mode!=COORDINATOR_LEAKED_WRITER) {
            assert(close(fixture->control[1])==0);fixture->control[1]=-1;
            assert(close(fixture->phase[1])==0);fixture->phase[1]=-1;
        }
        if(mode==COORDINATOR_FAILED_ASYNC||mode==COORDINATOR_FAILED_AFTER_RELEASE||
                mode==COORDINATOR_SPOOFED_RELEASE||
                mode==COORDINATOR_PARTIAL_RELEASE||
                mode==COORDINATOR_REPLAYED_RELEASE||mode==COORDINATOR_DELAYED_REPLAY||
                mode==COORDINATOR_LEAKED_WRITER||
                mode==COORDINATOR_SIGNAL_AFTER_READY) {
            snprintf(prefix,sizeof(prefix),"PEN_INPUT_LEASE_FAILED token=%s ",
                fixture->context.token);
            child_read_line(fixture->status[0],prefix,record,sizeof(record));
            close(fixture->status[0]); close(fixture->control[1]); close(fixture->phase[1]);
            _exit(0);
        }
        snprintf(terminal,sizeof(terminal),
            "PEN_INPUT_LEASE_RELEASED token=%s reason=%s held=false safe_idle_handoff=true guardian_pid=%ld guardian_starttime=%llu guardian_session=%s\n",
            fixture->context.token,
            (mode==COORDINATOR_RELEASE||mode==COORDINATOR_RELEASE_AFTER_ALARM)?
                "control_release":"timeout",(long)binding.pid,
                (unsigned long long)binding.starttime,binding.session);
        child_read_line(fixture->status[0],terminal,record,sizeof(record));
        assert(strcmp(record,terminal)==0);
        close(fixture->status[0]); close(fixture->control[1]); close(fixture->phase[1]);
        _exit(0);
    }
    close(fixture->control[1]); fixture->control[1]=-1;
    close(fixture->phase[1]); fixture->phase[1]=-1;
    close(fixture->status[0]); fixture->status[0]=-1;
    return child;
}

static int run_fake_production(struct endpoint_fixture *fixture,
        struct fake_evdev *fake,int quarantine_returns) {
    struct pen_input_lease_ops ops; int result;
    configure_production_ops(&ops,&fixture->context);
    ops.arm_parent_death=test_arm_parent;
    ops.termination_pending=injected_termination_pending;
    if(quarantine_returns)ops.quarantine=returning_quarantine;
    cleanup_signal=0;
    result=pen_input_lease_run(&ops,fixture->context.hold_ms);
    (void)fake;
    return result;
}

static void wait_coordinator(pid_t coordinator) {
    int status;
    assert(waitpid(coordinator,&status,0)==coordinator&&WIFEXITED(status)&&
        WEXITSTATUS(status)==0);
    /* SIGCHLD is deliberately blocked by the production policy. Reap its
     * pending notification so the next independent fixture is not correctly
     * rejected as having inherited an unaccounted signal. */
    assert(drain_pending_signals()==1);
}

static void stop_quarantined_guardian(struct lease_context *context) {
    int status;
    assert(context->guardian_started&&context->guardian_pid>1);
    assert(kill(context->guardian_pid,SIGKILL)==0);
    assert(waitpid(context->guardian_pid,&status,0)==context->guardian_pid&&
        WIFSIGNALED(status)&&WTERMSIG(status)==SIGKILL);
    if(context->guardian_fd>=0)assert(close(context->guardian_fd)==0);
    context->guardian_fd=-1;context->guardian_started=0;context->guardian_pid=0;
    assert(drain_pending_signals()==1);
}

static void reap_already_killed_guardian(struct lease_context *context) {
    int status;
    assert(context->guardian_started&&context->guardian_pid>1);
    assert(waitpid(context->guardian_pid,&status,0)==context->guardian_pid&&
        WIFSIGNALED(status)&&WTERMSIG(status)==SIGKILL);
    if(context->guardian_fd>=0)assert(close(context->guardian_fd)==0);
    context->guardian_fd=-1;context->guardian_started=0;context->guardian_pid=0;
    assert(drain_pending_signals()==1);
}

static void test_full_production_fake_evdev(void) {
    struct endpoint_fixture fixture; struct fake_evdev fake;
    pid_t coordinator;

    /* A cleanup request consumed at either pre-READY authority boundary must
     * leave through the safe non-READY path.  In particular, the second case
     * proves that an already-started guardian releases and exits rather than
     * advertising READY or entering quarantine. */
    for(int boundary=1;boundary<=2;boundary++) {
        char expected[256],record[512]; int available=0,length;
        fake_descriptor(&fake); fake.termination_on_check=boundary;
        fixture_open_fake(&fixture,&fake,3000);
        pen_input_lease_test_drop_abort_ack=boundary==2;
        quarantine_calls=0;quarantine_first=-1;
        assert(run_fake_production(&fixture,&fake,1)==1);
        assert(quarantine_calls==0&&fake_grabbed_fd(&fake)<0&&
            fake.open_calls==fake.close_calls);
        if(boundary==1)assert(fake.open_calls==2&&fake.descriptor_captures==4&&
            fake.kernel->grab_calls==0&&fake.kernel->ungrab_calls==0);
        else assert(fake.descriptor_captures>=3&&
            fixture.context.guardian_started==0&&fake.kernel->grab_calls==1&&
            fake.kernel->ungrab_calls==1);
        length=snprintf(expected,sizeof(expected),
            "PEN_INPUT_LEASE_FAILED token=%s stage=%s held=false safe_idle_handoff=false reboot_required=false",
            fixture.context.token,boundary==1?"termination_before_grab":
                "termination_before_ready");
        assert(length>0&&(size_t)length<sizeof(expected));
        child_read_line(fixture.status[0],expected,record,sizeof(record));
        if(boundary==1)assert(strcmp(record,
            "PEN_INPUT_LEASE_FAILED token=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa stage=termination_before_grab held=false safe_idle_handoff=false reboot_required=false\n")==0);
        else parse_ready_binding(record,&(struct guardian_binding){0});
        assert(available_bytes(fixture.status[0],&available)==0&&available==0);
        fixture_close(&fixture);
        pen_input_lease_test_drop_abort_ack=0;
        assert(drain_pending_signals()>=0);
    }

    /* A successfully sent guardian ACK can still be lost above the socket
     * receive boundary. Exact child exit 0 independently proves the sole
     * ungrab and must not be mislabeled as a held quarantine. */
    {
        char prefix[256],record[512];int available=0;
        fake_descriptor(&fake);fake.termination_on_check=2;
        fixture_open_fake(&fixture,&fake,3000);
        pen_input_lease_test_worker_loses_abort_ack=1;
        quarantine_calls=0;quarantine_first=-1;
        assert(run_fake_production(&fixture,&fake,1)==1);
        snprintf(prefix,sizeof(prefix),
            "PEN_INPUT_LEASE_FAILED token=%s stage=termination_before_ready held=false safe_idle_handoff=false reboot_required=false ",
            fixture.context.token);
        child_read_line(fixture.status[0],prefix,record,sizeof(record));
        parse_ready_binding(record,&(struct guardian_binding){0});
        assert(available_bytes(fixture.status[0],&available)==0&&available==0&&
            quarantine_calls==0&&fake_grabbed_fd(&fake)<0&&
            fake.kernel->grab_calls==1&&fake.kernel->ungrab_calls==1);
        fixture_close(&fixture);pen_input_lease_test_worker_loses_abort_ack=0;
        assert(drain_pending_signals()>=0);
    }

    /* Resource failures for which start_guardian proves that no child was
     * created allow exactly one sole-worker ungrab and a non-held FAILED. */
    for(int failure=1;failure<=2;failure++) {
        char prefix[256],record[512];
        fake_descriptor(&fake);fixture_open_fake(&fixture,&fake,3000);
        pen_input_lease_test_guardian_no_child_failure=failure;
        quarantine_calls=0;quarantine_first=-1;
        assert(run_fake_production(&fixture,&fake,1)==1);
        snprintf(prefix,sizeof(prefix),
            "PEN_INPUT_LEASE_FAILED token=%s stage=guardian_not_created held=false ",
            fixture.context.token);
        child_read_line(fixture.status[0],prefix,record,sizeof(record));
        assert(quarantine_calls==0&&fake_grabbed_fd(&fake)<0&&
            fake.kernel->grab_calls==1&&fake.kernel->ungrab_calls==1);
        fixture_close(&fixture);
        pen_input_lease_test_guardian_no_child_failure=0;
        assert(drain_pending_signals()>=0);
    }

    fake_descriptor(&fake); fixture_open_fake(&fixture,&fake,3000);
    coordinator=start_coordinator(&fixture,COORDINATOR_RELEASE);
    assert(run_fake_production(&fixture,&fake,1)==0);
    wait_coordinator(coordinator);
    assert(fake_grabbed_fd(&fake)<0&&fake.descriptor_captures>=3&&fake.open_calls==fake.close_calls);
    assert(fake.kernel->grab_calls==1&&fake.kernel->ungrab_calls==1);
    fixture_close(&fixture);

    /* Worker-held contact spans several heartbeat windows after END; the
     * guardian must keep answering pings and leave release to that worker. */
    fake_descriptor(&fake);fake.contact_after_idle_read=3;
    fake.contact_duration_ms=1500;fake.contact_mutation_pid=getpid();
    fixture_open_fake(&fixture,&fake,3500);
    coordinator=start_coordinator(&fixture,COORDINATOR_RELEASE);
    assert(run_fake_production(&fixture,&fake,1)==0);
    wait_coordinator(coordinator);
    assert(fake.idle_state_reads>20&&fake.kernel->ungrab_calls==1);
    fixture_close(&fixture);

    /* A guardian-only contact lasting longer than the former one-second
     * worker timeout clears before the original lease deadline. The worker
     * must wait for the one authoritative guardian ungrab and terminal. */
    fake_descriptor(&fake);fixture_open_fake(&fixture,&fake,3500);
    pen_input_lease_test_before_guardian_release=arm_guardian_contact;
    pen_input_lease_test_guardian_contact_ms=1500;
    coordinator=start_coordinator(&fixture,COORDINATOR_RELEASE);
    assert(run_fake_production(&fixture,&fake,1)==0);
    wait_coordinator(coordinator);
    assert(fake_grabbed_fd(&fake)<0&&fake.kernel->grab_calls==1&&
        fake.kernel->ungrab_calls==1);
    fixture_close(&fixture);
    pen_input_lease_test_before_guardian_release=NULL;
    pen_input_lease_test_guardian_contact_ms=0;

    /* Contact surviving the original lease deadline produces FAILED and both
     * holders remain quarantined; the worker's grace cannot race a later
     * RELEASED/ungrab from the guardian. */
    fake_descriptor(&fake);fixture_open_fake(&fixture,&fake,1000);
    pen_input_lease_test_before_guardian_release=arm_guardian_contact;
    pen_input_lease_test_guardian_contact_ms=3000;
    coordinator=start_coordinator(&fixture,COORDINATOR_FAILED_AFTER_RELEASE);
    quarantine_calls=0;quarantine_first=-1;
    assert(run_fake_production(&fixture,&fake,1)==2);
    wait_coordinator(coordinator);
    assert(quarantine_calls==1&&fake_grabbed_fd(&fake)>=0&&
        fake.kernel->ungrab_calls==0);
    stop_quarantined_guardian(&fixture.context);
    fake_cleanup(&fake);fixture_close(&fixture);
    pen_input_lease_test_before_guardian_release=NULL;
    pen_input_lease_test_guardian_contact_ms=0;

    /* FIONREAD reports zero for both a live empty pipe and EOF. Production
     * admission to READY therefore re-proves endpoint liveness first. */
    for(int endpoint=1;endpoint<=2;endpoint++) {
        char prefix[160],record[512];int available=0;
        fake_descriptor(&fake);fixture_open_fake(&fixture,&fake,3000);
        pen_input_lease_test_close_worker_ready_peer_fd=endpoint==1?
            fixture.control[1]:fixture.phase[1];
        quarantine_calls=0;quarantine_first=-1;
        assert(run_fake_production(&fixture,&fake,1)==2);
        if(endpoint==1)fixture.control[1]=-1;else fixture.phase[1]=-1;
        snprintf(prefix,sizeof(prefix),"PEN_INPUT_LEASE_FAILED token=%s stage=guardian_ready_%s_liveness ",
            fixture.context.token,endpoint==1?"control":"phase");
        child_read_line(fixture.status[0],prefix,record,sizeof(record));
        assert(available_bytes(fixture.status[0],&available)==0&&available==0);
        assert(quarantine_calls==1&&fake_grabbed_fd(&fake)>=0&&
            fake.kernel->ungrab_calls==0);
        stop_quarantined_guardian(&fixture.context);
        fake_cleanup(&fake);fixture_close(&fixture);
        pen_input_lease_test_close_worker_ready_peer_fd=-1;
    }

    /* If the guardian is SIGKILLed after its handshake but before READY, the
     * worker cannot mask failure by retaining a status writer. The coordinator
     * sees bounded HUP while the worker keeps the kernel grab quarantined. */
    {
        struct pollfd status_endpoint;
        fake_descriptor(&fake);fixture_open_fake(&fixture,&fake,1200);
        pen_input_lease_test_kill_guardian_before_ready=1;
        quarantine_calls=0;quarantine_first=-1;
        assert(run_fake_production(&fixture,&fake,1)==2);
        status_endpoint.fd=fixture.status[0];status_endpoint.events=POLLIN|POLLHUP;
        status_endpoint.revents=0;
        assert(poll(&status_endpoint,1,100)==1&&
            (status_endpoint.revents&POLLHUP)!=0&&
            (status_endpoint.revents&POLLIN)==0);
        assert(quarantine_calls==1&&fake_grabbed_fd(&fake)>=0&&
            fake.kernel->ungrab_calls==0);
        reap_already_killed_guardian(&fixture.context);
        fake_cleanup(&fake);fixture_close(&fixture);
        pen_input_lease_test_kill_guardian_before_ready=0;
    }

    /* Expiry during deliberately slow READY proofs is re-sampled at commit;
     * READY is never published from the stale pre-proof timestamp. */
    {
        char prefix[192],record[512];int available=0;
        fake_descriptor(&fake);fixture_open_fake(&fixture,&fake,300);
        pen_input_lease_test_guardian_ready_delay_ms=450;
        quarantine_calls=0;quarantine_first=-1;
        assert(run_fake_production(&fixture,&fake,1)==2);
        snprintf(prefix,sizeof(prefix),
            "PEN_INPUT_LEASE_FAILED token=%s stage=guardian_ready_commit_deadline ",
            fixture.context.token);
        child_read_line(fixture.status[0],prefix,record,sizeof(record));
        assert(strncmp(record,"PEN_INPUT_LEASE_READY",21)!=0&&
            available_bytes(fixture.status[0],&available)==0&&available==0);
        assert(quarantine_calls==1&&fake_grabbed_fd(&fake)>=0&&
            fake.kernel->ungrab_calls==0);
        stop_quarantined_guardian(&fixture.context);
        fake_cleanup(&fake);fixture_close(&fixture);
        pen_input_lease_test_guardian_ready_delay_ms=0;
    }


    /* A contact beginning after PREPARED but before READY_COMMIT is sampled by
     * the guardian's final commit admission. No READY may be published. */
    {
        char prefix[192],record[512];int available=0;
        fake_descriptor(&fake);fixture_open_fake(&fixture,&fake,3000);
        pen_input_lease_test_after_ready_prepared=arm_contact_after_prepared;
        quarantine_calls=0;quarantine_first=-1;
        assert(run_fake_production(&fixture,&fake,1)==2);
        snprintf(prefix,sizeof(prefix),
            "PEN_INPUT_LEASE_FAILED token=%s stage=guardian_ready_commit_admission ",
            fixture.context.token);
        child_read_line(fixture.status[0],prefix,record,sizeof(record));
        assert(available_bytes(fixture.status[0],&available)==0&&available==0&&
            fake.kernel->ungrab_calls==0&&fake_grabbed_fd(&fake)>=0);
        stop_quarantined_guardian(&fixture.context);
        fake_cleanup(&fake);fixture_close(&fixture);
        pen_input_lease_test_after_ready_prepared=NULL;
    }

    /* A contact which begins during final handoff is retained until it becomes
     * idle within the same absolute deadline, after which both worker and
     * guardian independently revalidate and release normally. */
    fake_descriptor(&fake);fake.contact_after_idle_read=3;
    fake.contact_clear_after_idle_read=6;fake.contact_mutation_pid=getpid();
    fixture_open_fake(&fixture,&fake,3000);
    coordinator=start_coordinator(&fixture,COORDINATOR_RELEASE);
    assert(run_fake_production(&fixture,&fake,1)==0);
    wait_coordinator(coordinator);
    assert(fake.idle_state_reads>=6&&fake_grabbed_fd(&fake)<0&&
        fake.open_calls==fake.close_calls);
    fixture_close(&fixture);

    /* An alarm armed before admission and delivered after READY remains
     * blocked while EVIOCGRAB is held; it cannot bypass controlled release. */
    fake_descriptor(&fake); fixture_open_fake(&fixture,&fake,5000);
    assert(alarm(1)==0);
    coordinator=start_coordinator(&fixture,COORDINATOR_RELEASE_AFTER_ALARM);
    assert(run_fake_production(&fixture,&fake,1)==0);
    {
        sigset_t pending;
        assert(sigpending(&pending)==0&&sigismember(&pending,SIGALRM)==1);
    }
    wait_coordinator(coordinator);
    assert(fake_grabbed_fd(&fake)<0&&fake.open_calls==fake.close_calls);
    fixture_close(&fixture);

    fake_descriptor(&fake); fixture_open_fake(&fixture,&fake,1000);
    coordinator=start_coordinator(&fixture,COORDINATOR_TIMEOUT);
    assert(run_fake_production(&fixture,&fake,1)==0);
    wait_coordinator(coordinator);
    assert(fake_grabbed_fd(&fake)<0&&fake.descriptor_captures>=3&&fake.open_calls==fake.close_calls);
    fixture_close(&fixture);

    fake_descriptor(&fake); fake.revalidation_mutation_capture=6;
    fixture_open_fake(&fixture,&fake,3000);
    quarantine_calls=0; quarantine_first=-1;
    assert(run_fake_production(&fixture,&fake,1)==2);
    assert(quarantine_calls==1&&quarantine_first==fake_grabbed_fd(&fake)&&fake_grabbed_fd(&fake)>=0);
    stop_quarantined_guardian(&fixture.context);
    fake_cleanup(&fake); fixture_close(&fixture);

    fake_descriptor(&fake); fixture_open_fake(&fixture,&fake,3000);
    coordinator=start_coordinator(&fixture,COORDINATOR_LOSS);
    quarantine_calls=0; quarantine_first=-1;
    assert(run_fake_production(&fixture,&fake,1)==2);
    wait_coordinator(coordinator);
    assert(quarantine_calls==1&&quarantine_first==fake_grabbed_fd(&fake)&&fake_grabbed_fd(&fake)>=0);
    stop_quarantined_guardian(&fixture.context);
    fake_cleanup(&fake); fixture_close(&fixture);

    /* A path swap that occurs only after READY is detected by continuous
     * production revalidation and retains the real held descriptor. */
    /* Leave a wide deterministic admission margin: the guardian may perform
     * a variable number of scheduler-driven health loops before READY.  The
     * high threshold still mutates within the 3 s held interval, but cannot
     * accidentally turn this post-READY test into an admission-race test. */
    fake_descriptor(&fake); fake.path_replacement_lstat=100;
    fixture_open_fake(&fixture,&fake,3000);
    coordinator=start_coordinator(&fixture,COORDINATOR_FAILED_ASYNC);
    quarantine_calls=0; quarantine_first=-1;
    assert(run_fake_production(&fixture,&fake,1)==2);
    wait_coordinator(coordinator);
    assert(quarantine_calls==1&&quarantine_first==fake_grabbed_fd(&fake)&&fake_grabbed_fd(&fake)>=0);
    stop_quarantined_guardian(&fixture.context);
    fake_cleanup(&fake); fixture_close(&fixture);

    /* Contact beginning at release cannot be handed back at the deadline,
     * even with the correct final coordinator phase proof. */
    fake_descriptor(&fake); fake.contact_after_idle_read=4;
    fixture_open_fake(&fixture,&fake,1000);
    coordinator=start_coordinator(&fixture,COORDINATOR_FAILED_AFTER_RELEASE);
    quarantine_calls=0; quarantine_first=-1;
    assert(run_fake_production(&fixture,&fake,1)==2);
    wait_coordinator(coordinator);
    assert(fake.idle_state_reads>=3&&quarantine_calls==1&&
        quarantine_first==fake_grabbed_fd(&fake)&&fake_grabbed_fd(&fake)>=0);
    stop_quarantined_guardian(&fixture.context);
    fake_cleanup(&fake); fixture_close(&fixture);

    /* The external final-release authority is a single exact token/session
     * record.  A spoof, truncation, replay, or post-READY cleanup signal is
     * terminally ambiguous and therefore leaves both holders quarantined. */
    {
        const enum coordinator_mode malformed[]={
            COORDINATOR_SPOOFED_RELEASE,COORDINATOR_PARTIAL_RELEASE,
            COORDINATOR_REPLAYED_RELEASE,COORDINATOR_SIGNAL_AFTER_READY,
            COORDINATOR_DELAYED_REPLAY,COORDINATOR_LEAKED_WRITER};
        for(size_t index=0;index<sizeof(malformed)/sizeof(malformed[0]);index++) {
            fake_descriptor(&fake);fixture_open_fake(&fixture,&fake,3000);
            coordinator=start_coordinator(&fixture,malformed[index]);
            quarantine_calls=0;quarantine_first=-1;
            assert(run_fake_production(&fixture,&fake,1)==2);
            wait_coordinator(coordinator);
            assert(quarantine_calls==1&&quarantine_first==fake_grabbed_fd(&fake)&&
                fake_grabbed_fd(&fake)>=0);
            stop_quarantined_guardian(&fixture.context);
            fake_cleanup(&fake);fixture_close(&fixture);
            pen_input_lease_test_delay_safe_command_ms=0;
        }
    }

    /* This hook runs after all guardian authority/channel/exclusivity work,
     * immediately before the fresh final sample. A new contact cannot ungrab. */
    fake_descriptor(&fake);fixture_open_fake(&fixture,&fake,3000);
    pen_input_lease_test_before_final_idle=arm_contact_after_prepared;
    coordinator=start_coordinator(&fixture,COORDINATOR_FAILED_AFTER_RELEASE);
    assert(run_fake_production(&fixture,&fake,1)==2);
    wait_coordinator(coordinator);
    assert(fake.kernel->ungrab_calls==0&&fake_grabbed_fd(&fake)>=0);
    stop_quarantined_guardian(&fixture.context);
    fake_cleanup(&fake);fixture_close(&fixture);
    pen_input_lease_test_before_final_idle=NULL;
}

static pid_t start_external_lease_worker(struct endpoint_fixture *fixture,
        struct fake_evdev *fake,int unrelated_read_fd) {
    pid_t worker=fork();assert(worker>=0);
    if(worker==0) {
        int result;
        close(fixture->control[1]);close(fixture->phase[1]);
        close(fixture->status[0]);
        if(unrelated_read_fd>=0)close(unrelated_read_fd);
        result=run_fake_production(fixture,fake,0);
        _exit(result);
    }
    close(fixture->context.authority_fd);fixture->context.authority_fd=-1;
    close(fixture->control[0]);fixture->control[0]=-1;
    close(fixture->phase[0]);fixture->phase[0]=-1;
    close(fixture->status[1]);fixture->status[1]=-1;
    return worker;
}

static void wait_for_hup(int fd) {
    struct pollfd endpoint={fd,POLLIN|POLLHUP,0};
    int result=poll(&endpoint,1,3000);
    assert(result==1&&(endpoint.revents&POLLHUP)!=0);
}

static void wait_until_process_gone(pid_t process) {
    for(int attempt=0;attempt<300;attempt++) {
        if(kill(process,0)!=0) { assert(errno==ESRCH); return; }
        (void)poll(NULL,0,10);
    }
    assert(!"guardian process remained observable after terminal close");
}

static void test_guardian_process_boundaries(void) {
    struct endpoint_fixture fixture;struct fake_evdev fake;
    struct guardian_binding binding;char prefix[160],record[512];
    char release[512],phase[512];int sentinel[2],high_writer=-1;pid_t worker;int status;
    struct rlimit saved_limit,lowered_limit;

    /* If the READY ACK is lost, the externally published READY is still the
     * committed state. The guardian—not the now-quarantined worker—accepts
     * final authority and emits the sole RELEASED terminal. */
    fake_descriptor(&fake);fixture_open_fake(&fixture,&fake,3000);
    pen_input_lease_test_drop_ready_ack=1;
    worker=start_external_lease_worker(&fixture,&fake,-1);
    snprintf(prefix,sizeof(prefix),"PEN_INPUT_LEASE_READY token=%s ",
        fixture.context.token);
    child_read_line(fixture.status[0],prefix,record,sizeof(record));
    assert(strstr(record," deviceClockDomain=android-boottime-v1 ")!=NULL&&
        strstr(record," deadline_boottime_ms=")!=NULL&&
        strstr(record,"monotonic") == NULL);
    parse_ready_binding(record,&binding);
    external_final_records(&fixture,&binding,release,sizeof(release),phase,sizeof(phase));
    assert(write(fixture.control[1],release,strlen(release))==(ssize_t)strlen(release));
    assert(write(fixture.phase[1],phase,strlen(phase))==(ssize_t)strlen(phase));
    assert(close(fixture.control[1])==0);fixture.control[1]=-1;
    assert(close(fixture.phase[1])==0);fixture.phase[1]=-1;
    snprintf(prefix,sizeof(prefix),"PEN_INPUT_LEASE_RELEASED token=%s ",
        fixture.context.token);
    child_read_line(fixture.status[0],prefix,record,sizeof(record));
    wait_for_hup(fixture.status[0]);
    assert(fake.kernel->grab_calls==1&&fake.kernel->ungrab_calls==1&&
        kill(worker,0)==0);
    assert(kill(worker,SIGKILL)==0&&waitpid(worker,&status,0)==worker&&
        WIFSIGNALED(status)&&WTERMSIG(status)==SIGKILL);
    wait_until_process_gone(binding.pid);
    fixture_close(&fixture);assert(drain_pending_signals()>=0);
    pen_input_lease_test_drop_ready_ack=0;

    /* A stopped worker cannot stall either side of the protocol indefinitely.
     * Before READY the guardian reports one held failure and quarantines. */
    fake_descriptor(&fake);fixture_open_fake(&fixture,&fake,1600);
    pen_input_lease_test_stop_worker_stage=1;
    worker=start_external_lease_worker(&fixture,&fake,-1);
    snprintf(prefix,sizeof(prefix),
        "PEN_INPUT_LEASE_FAILED token=%s stage=guardian_protocol_deadline ",
        fixture.context.token);
    child_read_line(fixture.status[0],prefix,record,sizeof(record));
    parse_ready_binding(record,&binding);
    assert(fake.kernel->ungrab_calls==0&&kill(worker,0)==0&&kill(binding.pid,0)==0);
    assert(kill(worker,SIGKILL)==0&&waitpid(worker,&status,0)==worker);
    assert(kill(binding.pid,SIGKILL)==0);wait_for_hup(fixture.status[0]);
    wait_until_process_gone(binding.pid);fake_kernel_last_process_teardown(&fake);
    fixture_close(&fixture);assert(drain_pending_signals()>=0);
    pen_input_lease_test_stop_worker_stage=0;

    /* After GUARDIAN_END, stopped or killed workers cannot prevent the guardian
     * from completing an already-authorized safe release. A generic provider
     * fail-stop therefore targets only the worker; it must never kill both
     * physical-grab holders. */
    for(int stopped=0;stopped<=1;stopped++) {
        fake_descriptor(&fake);fixture_open_fake(&fixture,&fake,3000);
        pen_input_lease_test_kill_worker_after_guardian_end=!stopped;
        pen_input_lease_test_stop_worker_stage=stopped?2:0;
        worker=start_external_lease_worker(&fixture,&fake,-1);
        snprintf(prefix,sizeof(prefix),"PEN_INPUT_LEASE_READY token=%s ",
            fixture.context.token);
        child_read_line(fixture.status[0],prefix,record,sizeof(record));
        parse_ready_binding(record,&binding);
        external_final_records(&fixture,&binding,release,sizeof(release),phase,sizeof(phase));
        assert(write(fixture.control[1],release,strlen(release))==(ssize_t)strlen(release));
        assert(write(fixture.phase[1],phase,strlen(phase))==(ssize_t)strlen(phase));
        assert(close(fixture.control[1])==0);fixture.control[1]=-1;
        assert(close(fixture.phase[1])==0);fixture.phase[1]=-1;
        snprintf(prefix,sizeof(prefix),"PEN_INPUT_LEASE_RELEASED token=%s ",
            fixture.context.token);
        child_read_line(fixture.status[0],prefix,record,sizeof(record));
        wait_for_hup(fixture.status[0]);
        assert(fake.kernel->grab_calls==1&&fake.kernel->ungrab_calls==1);
        if(stopped)assert(kill(worker,SIGKILL)==0);
        assert(waitpid(worker,&status,0)==worker&&WIFSIGNALED(status)&&
            WTERMSIG(status)==SIGKILL);
        wait_until_process_gone(binding.pid);
        fixture_close(&fixture);assert(drain_pending_signals()>=0);
        pen_input_lease_test_kill_worker_after_guardian_end=0;
        pen_input_lease_test_stop_worker_stage=0;
    }

    /* The guardian closes every unrelated inherited descriptor.  After the
     * worker is killed, EOF on this sentinel proves no accidental guardian
     * copy survived.  The authenticated guardian nevertheless retains its
     * dedicated status/control/phase endpoints and the grabbed evdev OFD,
     * accepts the final authority itself, reports RELEASED, then exits. */
    fake_descriptor(&fake);fixture_open_fake(&fixture,&fake,3000);
    make_pipe(sentinel);
    assert(getrlimit(RLIMIT_NOFILE,&saved_limit)==0);
    high_writer=fcntl(sentinel[1],F_DUPFD_CLOEXEC,4096);
    assert(high_writer>=4096);close(sentinel[1]);sentinel[1]=high_writer;
    lowered_limit=saved_limit;
    if(lowered_limit.rlim_cur>64)lowered_limit.rlim_cur=64;
    assert((rlim_t)high_writer>=lowered_limit.rlim_cur&&
        setrlimit(RLIMIT_NOFILE,&lowered_limit)==0);
    worker=start_external_lease_worker(&fixture,&fake,sentinel[0]);
    assert(setrlimit(RLIMIT_NOFILE,&saved_limit)==0);
    close(sentinel[1]);sentinel[1]=-1;
    snprintf(prefix,sizeof(prefix),"PEN_INPUT_LEASE_READY token=%s ",
        fixture.context.token);
    child_read_line(fixture.status[0],prefix,record,sizeof(record));
    parse_ready_binding(record,&binding);
    assert(kill(worker,SIGKILL)==0);
    assert(waitpid(worker,&status,0)==worker&&WIFSIGNALED(status)&&
        WTERMSIG(status)==SIGKILL);
    wait_for_hup(sentinel[0]);assert(read(sentinel[0],record,1)==0);
    close(sentinel[0]);sentinel[0]=-1;
    external_final_records(&fixture,&binding,release,sizeof(release),phase,sizeof(phase));
    assert(write(fixture.control[1],release,strlen(release))==(ssize_t)strlen(release));
    assert(write(fixture.phase[1],phase,strlen(phase))==(ssize_t)strlen(phase));
    assert(close(fixture.control[1])==0);fixture.control[1]=-1;
    assert(close(fixture.phase[1])==0);fixture.phase[1]=-1;
    snprintf(prefix,sizeof(prefix),"PEN_INPUT_LEASE_RELEASED token=%s ",
        fixture.context.token);
    child_read_line(fixture.status[0],prefix,record,sizeof(record));
    assert(strstr(record,"reason=control_release held=false safe_idle_handoff=true")!=NULL);
    assert(strstr(record,binding.session)!=NULL);
    wait_for_hup(fixture.status[0]);wait_until_process_gone(binding.pid);
    assert(fake.kernel->grab_calls==1&&fake.kernel->ungrab_calls==1&&
        fake.kernel->implicit_last_close_releases==0);
    fixture_close(&fixture);assert(drain_pending_signals()>=0);

    /* If the guardian dies after READY, the status owner disappears and the
     * worker's guardian channel reaches EOF.  The worker must stay alive in
     * quarantine with its duplicate of the grabbed OFD until an explicit
     * external recovery (normally device reboot). */
    fake_descriptor(&fake);fixture_open_fake(&fixture,&fake,3000);
    worker=start_external_lease_worker(&fixture,&fake,-1);
    snprintf(prefix,sizeof(prefix),"PEN_INPUT_LEASE_READY token=%s ",
        fixture.context.token);
    child_read_line(fixture.status[0],prefix,record,sizeof(record));
    parse_ready_binding(record,&binding);
    assert(kill(binding.pid,SIGKILL)==0);
    wait_for_hup(fixture.status[0]);
    (void)poll(NULL,0,150);assert(kill(worker,0)==0);
    assert(kill(worker,SIGKILL)==0);
    assert(waitpid(worker,&status,0)==worker&&WIFSIGNALED(status)&&
        WTERMSIG(status)==SIGKILL);
    wait_until_process_gone(binding.pid);
    assert(fake.kernel->grab_calls==1&&fake.kernel->ungrab_calls==0);
    fake_kernel_last_process_teardown(&fake);
    assert(fake.kernel->implicit_last_close_releases==1);
    fixture_close(&fixture);assert(drain_pending_signals()>=0);

    /* A stopped sole status writer is retired by its exact direct parent.
     * The worker stays alive with the grab, while coordinator observes HUP. */
    fake_descriptor(&fake);fixture_open_fake(&fixture,&fake,700);
    worker=start_external_lease_worker(&fixture,&fake,-1);
    snprintf(prefix,sizeof(prefix),"PEN_INPUT_LEASE_READY token=%s ",fixture.context.token);
    child_read_line(fixture.status[0],prefix,record,sizeof(record));
    parse_ready_binding(record,&binding);
    assert(kill(binding.pid,SIGSTOP)==0);
    wait_for_hup(fixture.status[0]);wait_until_process_gone(binding.pid);
    assert(kill(worker,0)==0&&fake.kernel->ungrab_calls==0&&fake_grabbed_fd(&fake)>=0);
    assert(kill(worker,SIGKILL)==0&&waitpid(worker,&status,0)==worker);
    fake_kernel_last_process_teardown(&fake);fixture_close(&fixture);
    assert(drain_pending_signals()>=0);

    /* Every worker-death boundary in HELLO/BIND/BOUND must leave the
     * independently authenticated guardian holding the shared OFD. There is
     * one FAILED record, no READY, and no kernel ungrab before last teardown. */
    for(int stage=1;stage<=4;stage++) {
        char stage_prefix[192];int available=0;
        fake_descriptor(&fake);fixture_open_fake(&fixture,&fake,3000);
        pen_input_lease_test_kill_worker_handshake_stage=stage;
        worker=start_external_lease_worker(&fixture,&fake,-1);
        snprintf(stage_prefix,sizeof(stage_prefix),
            "PEN_INPUT_LEASE_FAILED token=%s stage=worker_lost_handshake_stage_%d ",
            fixture.context.token,stage);
        child_read_line(fixture.status[0],stage_prefix,record,sizeof(record));
        parse_ready_binding(record,&binding);
        assert(waitpid(worker,&status,0)==worker&&WIFSIGNALED(status)&&
            WTERMSIG(status)==SIGKILL);
        assert(fake.kernel->grab_calls==1&&fake.kernel->ungrab_calls==0&&
            fake_grabbed_fd(&fake)>=0&&kill(binding.pid,0)==0);
        assert(available_bytes(fixture.status[0],&available)==0&&available==0);
        assert(kill(binding.pid,SIGKILL)==0);
        wait_for_hup(fixture.status[0]);wait_until_process_gone(binding.pid);
        fake_kernel_last_process_teardown(&fake);
        assert(fake.kernel->implicit_last_close_releases==1);
        fixture_close(&fixture);assert(drain_pending_signals()>=0);
        pen_input_lease_test_kill_worker_handshake_stage=0;
    }

    /* A READY datagram queued immediately before worker death carries no live
     * commit authority. The guardian observes reparenting/socket HUP, emits
     * one FAILED record, and retains the shared OFD without publishing READY. */
    for(int ready_stage=1;ready_stage<=2;ready_stage++) {
        int available=0;
        fake_descriptor(&fake);fixture_open_fake(&fixture,&fake,3000);
        pen_input_lease_test_kill_worker_after_ready_send=ready_stage;
        worker=start_external_lease_worker(&fixture,&fake,-1);
        snprintf(prefix,sizeof(prefix),
            "PEN_INPUT_LEASE_FAILED token=%s stage=%s ",
            fixture.context.token,ready_stage==1?"guardian_ready_worker":
                "guardian_ready_commit_admission");
        child_read_line(fixture.status[0],prefix,record,sizeof(record));
        parse_ready_binding(record,&binding);
        assert(waitpid(worker,&status,0)==worker&&WIFSIGNALED(status)&&
            WTERMSIG(status)==SIGKILL);
        assert(available_bytes(fixture.status[0],&available)==0&&available==0&&
            fake.kernel->grab_calls==1&&fake.kernel->ungrab_calls==0&&
            kill(binding.pid,0)==0);
        assert(kill(binding.pid,SIGKILL)==0);
        wait_for_hup(fixture.status[0]);wait_until_process_gone(binding.pid);
        fake_kernel_last_process_teardown(&fake);
        fixture_close(&fixture);assert(drain_pending_signals()>=0);
        pen_input_lease_test_kill_worker_after_ready_send=0;
    }

    /* If authoritative FD enumeration itself fails, the guardian exits rather
     * than indefinitely retaining arbitrary launcher descriptors. The worker
     * remains the fail-closed grab holder; killing it closes a deliberately
     * high inherited sentinel and the last shared OFD. */
    {
        struct pollfd status_endpoint;
        fake_descriptor(&fake);fixture_open_fake(&fixture,&fake,1200);
        make_pipe(sentinel);
        high_writer=fcntl(sentinel[1],F_DUPFD_CLOEXEC,4096);
        assert(high_writer>=4096);close(sentinel[1]);sentinel[1]=high_writer;
        pen_input_lease_test_fail_guardian_fd_sweep=1;
        worker=start_external_lease_worker(&fixture,&fake,sentinel[0]);
        close(sentinel[1]);sentinel[1]=-1;
        status_endpoint.fd=fixture.status[0];status_endpoint.events=POLLIN|POLLHUP;
        status_endpoint.revents=0;
        assert(poll(&status_endpoint,1,1200)==1&&
            (status_endpoint.revents&POLLHUP)!=0);
        assert(kill(worker,0)==0&&fake.kernel->grab_calls==1&&
            fake.kernel->ungrab_calls==0);
        assert(kill(worker,SIGKILL)==0);
        assert(waitpid(worker,&status,0)==worker&&WIFSIGNALED(status)&&
            WTERMSIG(status)==SIGKILL);
        wait_for_hup(sentinel[0]);close(sentinel[0]);sentinel[0]=-1;
        fake_kernel_last_process_teardown(&fake);
        fixture_close(&fixture);assert(drain_pending_signals()>=0);
        pen_input_lease_test_fail_guardian_fd_sweep=0;
    }
}

static void test_endpoints_and_records(void) {
    struct endpoint_fixture good,trailing,preloaded,closed_peer;
    int socket_pair[2];
    char release[128],junk[3],byte='x'; int received=0;
    fixture_open(&good,"");
    assert(admit_contract(&good.context)==0);
    assert(status_consumer_alive(&good.context)==0);
    assert(pipe_endpoint(good.context.control_fd,O_RDONLY,&(struct stat){0})==0);
    assert(socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC|SOCK_NONBLOCK,0,socket_pair)==0);
    assert(pipe_endpoint(socket_pair[0],O_RDONLY,&(struct stat){0})!=0);
    close(socket_pair[0]); close(socket_pair[1]);
    {
        char fifo_path[128];int fifo_reader=-1,fifo_writer=-1;
        snprintf(fifo_path,sizeof(fifo_path),"/tmp/pen-input-lease-fifo-%ld",
            (long)getpid());
        (void)unlink(fifo_path);assert(mkfifo(fifo_path,0600)==0);
        fifo_reader=open(fifo_path,O_RDONLY|O_NONBLOCK|O_CLOEXEC);
        assert(fifo_reader>=0);
        fifo_writer=open(fifo_path,O_WRONLY|O_NONBLOCK|O_CLOEXEC);
        assert(fifo_writer>=0&&
            pipe_endpoint(fifo_reader,O_RDONLY,&(struct stat){0})!=0&&
            pipe_endpoint(fifo_writer,O_WRONLY,&(struct stat){0})!=0);
        close(fifo_reader);close(fifo_writer);assert(unlink(fifo_path)==0);
    }
    close(good.status[0]); good.status[0]=-1;
    assert(status_consumer_alive(&good.context)!=0);
    fixture_close(&good);

    fixture_open(&trailing,"TRAILING"); assert(admit_contract(&trailing.context)!=0); fixture_close(&trailing);
    fixture_open(&preloaded,""); assert(write(preloaded.control[1],&byte,1)==1);
    assert(admit_contract(&preloaded.context)!=0); fixture_close(&preloaded);
    fixture_open(&closed_peer,""); close(closed_peer.control[1]); closed_peer.control[1]=-1;
    assert(admit_contract(&closed_peer.context)!=0); fixture_close(&closed_peer);

    make_pipe(good.control);
    memset(good.context.token,'b',TOKEN_HEX_LENGTH); good.context.token[TOKEN_HEX_LENGTH]='\0';
    snprintf(release,sizeof(release),"RELEASE %s\n",good.context.token);
    assert(write(good.control[1],release,strlen(release))==(ssize_t)strlen(release));
    assert(exact_pipe_record(good.control[0],release)==0);
    assert(write(good.control[1],"bad",3)==3); assert(exact_pipe_record(good.control[0],release)!=0);
    assert(read(good.control[0],junk,sizeof(junk))==(ssize_t)sizeof(junk));
    assert(write(good.control[1],release,strlen(release))==(ssize_t)strlen(release));
    assert(write(good.control[1],"x",1)==1); assert(exact_pipe_record(good.control[0],release)!=0);
    close(good.control[0]); close(good.control[1]);

    make_pipe(good.control); received=0;
    assert(write(good.control[1],release,strlen(release))==(ssize_t)strlen(release));
    assert(consume_if_exact(good.control[0],release,&received)==0&&received==1);
    assert(write(good.control[1],release,strlen(release))==(ssize_t)strlen(release));
    assert(consume_if_exact(good.control[0],release,&received)!=0);
    close(good.control[0]); close(good.control[1]);
}

static void test_worker_fd_allowlist(void) {
    /* Success closes an unrelated descriptor even above a lowered soft limit.
     * Exact aliases of a control endpoint—including stdio—are closed and make
     * admission fail rather than silently extending endpoint lifetime. */
    for(int mode=0;mode<3;mode++) {
        struct endpoint_fixture fixture;
        pid_t child;int status;
        fixture_open(&fixture,"");
        child=fork();assert(child>=0);
        if(child==0) {
            struct rlimit limits;
            int high=-1,result,alias_fd=-1,unrelated=-1;
            close(fixture.control[1]);close(fixture.phase[1]);close(fixture.status[0]);
            fixture.control[1]=fixture.phase[1]=fixture.status[0]=-1;
            if(mode==0) {
                unrelated=open("/dev/null",O_RDONLY|O_CLOEXEC);
                assert(unrelated>=0);
                high=fcntl(unrelated,F_DUPFD_CLOEXEC,4096);assert(high>=4096);
                close(unrelated);
            } else if(mode==1) {
                high=fcntl(fixture.context.status_fd,F_DUPFD_CLOEXEC,4096);
                assert(high>=4096);alias_fd=high;
            } else {
                assert(dup2(fixture.context.control_fd,STDIN_FILENO)==STDIN_FILENO);
                alias_fd=STDIN_FILENO;
            }
            assert(getrlimit(RLIMIT_NOFILE,&limits)==0);
            if(limits.rlim_cur>64){limits.rlim_cur=64;assert(setrlimit(RLIMIT_NOFILE,&limits)==0);}
            cleanup_signal=0;
            assert(install_handlers(&fixture.context)==0);
            pen_input_lease_test_enable_worker_fd_sweep=1;
            result=admit_contract(&fixture.context);
            if(mode==0)
                _exit(result==0&&fcntl(high,F_GETFD)<0&&errno==EBADF?0:41);
            _exit(result!=0&&fcntl(alias_fd,F_GETFD)<0&&errno==EBADF?0:42);
        }
        assert(waitpid(child,&status,0)==child&&WIFEXITED(status)&&
            WEXITSTATUS(status)==0);
        fixture_close(&fixture);assert(drain_pending_signals()>=0);
    }
    pen_input_lease_test_enable_worker_fd_sweep=0;
}

static void allow_exec_inheritance(int fd) {
    int flags=fcntl(fd,F_GETFD); assert(flags>=0);
    assert(fcntl(fd,F_SETFD,flags&~FD_CLOEXEC)==0);
}

static void test_production_binary(const char *path) {
    struct endpoint_fixture fixture;
    char hold[]="500",authority_fd[24],control_fd[24],phase_fd[24],status_fd[24],authority_hash[65];
    char expected[256],record[256];
    pid_t child; int status,length,available=0; ssize_t got;
    fixture_open(&fixture,"");
    for(size_t i=0;i<HASH_LENGTH;i++) snprintf(authority_hash+i*2,3,"%02x",fixture.context.authority_file_hash[i]);
    snprintf(authority_fd,sizeof(authority_fd),"%d",fixture.context.authority_fd);
    snprintf(control_fd,sizeof(control_fd),"%d",fixture.context.control_fd);
    snprintf(phase_fd,sizeof(phase_fd),"%d",fixture.context.phase_fd);
    snprintf(status_fd,sizeof(status_fd),"%d",fixture.context.status_fd);
    allow_exec_inheritance(fixture.context.authority_fd); allow_exec_inheritance(fixture.context.control_fd);
    allow_exec_inheritance(fixture.context.phase_fd); allow_exec_inheritance(fixture.context.status_fd);
    child=fork(); assert(child>=0);
    if(child==0) {
        char *const arguments[]={
            (char *)path,"--hold-ms",hold,"--token",fixture.context.token,
            "--authority-fd",authority_fd,"--authority-sha256",authority_hash,
            "--control-fd",control_fd,"--phase-fd",phase_fd,"--status-fd",status_fd,NULL};
        execv(path,arguments); _exit(127);
    }
    assert(waitpid(child,&status,0)==child && WIFEXITED(status) && WEXITSTATUS(status)==1);
    length=snprintf(expected,sizeof(expected),
        "PEN_INPUT_LEASE_FAILED token=%s stage=open_first held=false safe_idle_handoff=false reboot_required=false\n",
        fixture.context.token);
    assert(length>0&&(size_t)length<sizeof(expected));
    assert(available_bytes(fixture.status[0],&available)==0&&available==length);
    got=read(fixture.status[0],record,sizeof(record));
    assert(got==length&&memcmp(record,expected,(size_t)length)==0);
    fixture_close(&fixture);

    child=fork(); assert(child>=0);
    if(child==0) { char *const invalid[]={(char *)path,NULL}; execv(path,invalid); _exit(127); }
    assert(waitpid(child,&status,0)==child&&WIFEXITED(status)&&WEXITSTATUS(status)==2);
}

static volatile sig_atomic_t hostile_signal_seen;
static void hostile_signal_handler(int signal_number) {
    (void)signal_number; hostile_signal_seen++;
}

static void test_status_backpressure_and_signals(void) {
    int status[2]; char fill[4096]; struct lease_context context; int death=0;
    struct endpoint_fixture pending_fixture,fixture;
    struct sigaction disposition,hostile,ignored;
    sigset_t block,mask,pending;
    memset(fill,'z',sizeof(fill)); memset(&context,0,sizeof(context)); make_pipe(status);
    context.status_fd=status[1]; context.status_pipe_buf=fpathconf(status[1],_PC_PIPE_BUF);
    while(write(status[1],fill,sizeof(fill))>0) {}
    assert(errno==EAGAIN||errno==EWOULDBLOCK);
    assert(status_record(&context,"PEN_INPUT_LEASE_FAILED token=x\n")!=0);
    close(status[0]); close(status[1]);

    /* A signal inherited pending at admission is consumed and rejects the run
     * before EVIOCGRAB, rather than becoming a latent post-READY terminator. */
    fixture_open(&pending_fixture,"");
    sigemptyset(&block); sigaddset(&block,SIGUSR1);
    assert(sigprocmask(SIG_BLOCK,&block,NULL)==0);
    assert(raise(SIGUSR1)==0);
    assert(sigpending(&pending)==0&&sigismember(&pending,SIGUSR1)==1);
    cleanup_signal=0;
    assert(install_handlers(&pending_fixture.context)!=0);
    assert(sigpending(&pending)==0&&sigismember(&pending,SIGUSR1)==0);
    fixture_close(&pending_fixture);

    fixture_open(&fixture,"");
    memset(&hostile,0,sizeof(hostile)); hostile.sa_handler=hostile_signal_handler;
    sigemptyset(&hostile.sa_mask);
    memset(&ignored,0,sizeof(ignored)); ignored.sa_handler=SIG_IGN;
    sigemptyset(&ignored.sa_mask);
    assert(sigaction(SIGUSR1,&hostile,NULL)==0);
    assert(sigaction(SIGTERM,&ignored,NULL)==0);
    {
        const int synchronous[]={SIGILL,SIGFPE,SIGSEGV,SIGBUS,SIGTRAP,SIGSYS};
        for(size_t index=0;index<sizeof(synchronous)/sizeof(synchronous[0]);index++)
            assert(sigaction(synchronous[index],&ignored,NULL)==0);
    }
    sigemptyset(&mask);
    assert(sigprocmask(SIG_SETMASK,&mask,NULL)==0);
    sigemptyset(&block); sigaddset(&block,SIGIO);
    assert(sigprocmask(SIG_BLOCK,&block,NULL)==0);
    assert(fcntl(fixture.context.control_fd,F_SETOWN,getpid())==0);
    assert(fcntl(fixture.context.phase_fd,F_SETOWN,getpid())==0);
    assert(fcntl(fixture.context.status_fd,F_SETOWN,getpid())==0);
#ifdef F_SETSIG
    assert(fcntl(fixture.context.control_fd,F_SETSIG,SIGIO)==0);
    assert(fcntl(fixture.context.phase_fd,F_SETSIG,SIGIO)==0);
    assert(fcntl(fixture.context.status_fd,F_SETSIG,SIGIO)==0);
#endif
    {
        const int endpoints[]={fixture.context.control_fd,fixture.context.phase_fd,
            fixture.context.status_fd};
        for(size_t index=0;index<sizeof(endpoints)/sizeof(endpoints[0]);index++) {
            int flags=fcntl(endpoints[index],F_GETFL); assert(flags>=0);
            assert(fcntl(endpoints[index],F_SETFL,flags|O_ASYNC|O_APPEND)==0);
        }
    }
    cleanup_signal=0;
    assert(alarm(1)==0);
    assert(install_handlers(&fixture.context)==0);
    assert(admit_contract(&fixture.context)==0);
    {
        const int endpoints[]={fixture.context.control_fd,fixture.context.phase_fd,
            fixture.context.status_fd};
        for(size_t index=0;index<sizeof(endpoints)/sizeof(endpoints[0]);index++) {
            int flags=fcntl(endpoints[index],F_GETFL); assert(flags>=0);
            assert((flags&(O_ASYNC|O_APPEND))==0&&(flags&O_NONBLOCK)!=0);
            assert(fcntl(endpoints[index],F_GETOWN)==0);
#ifdef F_GETSIG
            assert(fcntl(endpoints[index],F_GETSIG)==0);
#endif
        }
    }
    assert(sigaction(SIGIO,NULL,&disposition)==0&&disposition.sa_handler==SIG_IGN);
    assert(sigaction(SIGPIPE,NULL,&disposition)==0&&disposition.sa_handler==SIG_IGN);
    assert(sigaction(SIGTERM,NULL,&disposition)==0&&disposition.sa_handler==request_cleanup);
    {
        const int synchronous[]={SIGILL,SIGFPE,SIGSEGV,SIGBUS,SIGTRAP,SIGSYS};
        for(size_t index=0;index<sizeof(synchronous)/sizeof(synchronous[0]);index++)
            assert(sigaction(synchronous[index],NULL,&disposition)==0&&
                disposition.sa_handler==SIG_DFL);
    }
    assert(sigprocmask(SIG_SETMASK,NULL,&mask)==0);
    assert(sigismember(&mask,SIGUSR1)==1&&sigismember(&mask,SIGALRM)==1&&
        sigismember(&mask,SIGCHLD)==1);
    assert(sigismember(&mask,SIGTERM)==1&&sigismember(&mask,SIGPIPE)==0&&
        sigismember(&mask,SIGIO)==0&&sigismember(&mask,SIGSEGV)==0);
    (void)poll(NULL,0,1100);
    assert(sigpending(&pending)==0&&sigismember(&pending,SIGALRM)==1);
    hostile_signal_seen=0; assert(raise(SIGUSR1)==0);
    assert(hostile_signal_seen==0&&sigpending(&pending)==0&&
        sigismember(&pending,SIGUSR1)==1);
    assert(drain_pending_signals()==1);
    assert(sigpending(&pending)==0&&sigismember(&pending,SIGALRM)==0&&
        sigismember(&pending,SIGUSR1)==0);
    assert(raise(SIGIO)==0);
    assert(raise(SIGTERM)==0);assert(cleanup_signal==0);
    assert(sigpending(&pending)==0&&sigismember(&pending,SIGTERM)==1);
    assert(termination_pending(NULL)==1&&cleanup_signal==SIGTERM);
    fixture_close(&fixture);
    cleanup_signal=0; assert(current_parent(NULL)>1); assert(arm_parent_death(NULL)==0);
    assert(prctl(PR_GET_PDEATHSIG,&death)==0&&death==SIGTERM); assert(prctl(PR_SET_PDEATHSIG,0)==0);
}

#ifndef PEN_INPUT_LEASE_LINK_WRAPPER
int main(int argc,char **argv) {
    assert(argc==2);
    test_sha_and_descriptor(); test_stat_and_idle();
    test_fake_capture_and_required_buttons(); test_endpoints_and_records();
    test_worker_fd_allowlist();
    test_status_backpressure_and_signals();
    test_full_production_fake_evdev();
    test_guardian_process_boundaries();
    test_production_binary(argv[1]);
    puts("PEN_INPUT_LEASE_ADAPTER_TEST_PASS descriptor=true required_buttons=true endpoints=true "
        "async_flags=true signal_policy=true status_liveness=true fake_evdev_success_timeout_revalidate_path_swap_active_release_quarantine=true "
        "single_kernel_ungrab=true guardian_handshake_death_quarantine=true guardian_high_fd_sweep=true "
        "guardian_ready_eof_rejected=true coherent_release_deadline=true "
        "abort_ack_loss_exit_proof=true pre_ready_guardian_death_hup=true "
        "ready_commit_deadline_liveness=true queued_ready_dead_worker_rejected=true "
        "worker_fd_exact_allowlist=true anonymous_pipefs_only=true "
        "early_fd_sweep_failure_closes=true guardian_worker_death_release=true "
        "guardian_death_quarantine=true production_exec=true");
    return 0;
}
#else
/* Link-time interception binds an independently compiled, unmodified production
 * translation unit to a kernel-only fake. No ops callback, test hook, admission,
 * signal policy, FD sweep or guardian path in that production object is changed. */
extern int pen_input_lease_production_main(int argc,char **argv);
extern int __real_open(const char *path,int flags,...);
extern int __real_close(int fd);
extern int __real_fstat(int fd,struct stat *value);
extern int __real_lstat(const char *path,struct stat *value);
extern int __real_ioctl(int fd,unsigned long request,...);
extern ssize_t __real_recv(int fd,void *buffer,size_t length,int flags);
extern ssize_t __real_send(int fd,const void *buffer,size_t length,int flags);
extern ssize_t __real_getrandom(void *buffer,size_t length,unsigned flags);
static struct fake_evdev *linked_fake;
static int linked_phase_fd=-1,linked_contact_case,linked_release_stage;
static int linked_scenario,linked_abort_triggered;
static pid_t linked_worker_pid;
enum {
    LINK_NORMAL,LINK_STOP_READY,LINK_FINAL_CONTACT,LINK_PROBE_LOSS,
    LINK_STOP_RELEASE,LINK_STOP_TIMEOUT,LINK_STOP_ABORT,LINK_ABORT_CONTACT,
    LINK_RELEASE_CONTACT,LINK_RELEASE_ACK_LOSS,LINK_ENTROPY_EAGAIN,LINK_ABORT_ACK_LOSS,
    LINK_SCENARIOS
};
static int linked_is_abort(void) {
    return linked_scenario==LINK_STOP_ABORT||linked_scenario==LINK_ABORT_CONTACT||
        linked_scenario==LINK_ABORT_ACK_LOSS;
}
static void linked_assert_signal_policy(void) {
    struct sigaction action;sigset_t mask;
    assert(sigaction(SIGCHLD,NULL,&action)==0&&action.sa_handler==SIG_DFL);
    assert(sigprocmask(SIG_SETMASK,NULL,&mask)==0&&sigismember(&mask,SIGCHLD)==1);
    linked_fake->kernel->sigchld_policy_checks++;
}
pid_t __wrap_fork(void) {
    pid_t result=tracked_fork();
    if(result==0&&linked_fake!=NULL&&linked_fake->open_calls>0)
        linked_fake->kernel->guardian_process=getpid();
    return result;
}
pid_t __wrap_waitpid(pid_t process,int *status,int options) { return tracked_waitpid(process,status,options); }
void __wrap__exit(int status) { tracked_exit(status); }
ssize_t __wrap_getrandom(void *buffer,size_t length,unsigned flags) {
    assert(linked_fake!=NULL&&flags==GRND_NONBLOCK&&linked_fake->kernel->grab_calls==0);
    linked_assert_signal_policy();
    linked_fake->kernel->entropy_calls++;
    linked_fake->kernel->entropy_before_grab=1;
    if(linked_scenario==LINK_ENTROPY_EAGAIN){errno=EAGAIN;return -1;}
    return __real_getrandom(buffer,length,flags);
}
ssize_t __wrap_send(int fd,const void *buffer,size_t length,int flags) {
    const char *drop=linked_scenario==LINK_RELEASE_ACK_LOSS?"GUARDIAN_RELEASED ":
        linked_scenario==LINK_ABORT_ACK_LOSS?"GUARDIAN_ABORTED ":NULL;
    if(drop!=NULL&&length>=strlen(drop)&&memcmp(buffer,drop,strlen(drop))==0) {
        errno=EPIPE;return -1;
    }
    return __real_send(fd,buffer,length,flags);
}

int __wrap_open(const char *path,int flags,...) {
    if(linked_fake!=NULL&&strcmp(path,PEN_NODE)==0) {
        int fd=fake_open_node(linked_fake,path,flags);
        int backing=__real_open("/dev/null",flags);
        assert(fd>=0&&backing>=0);
        if(backing!=fd) {
            assert(dup3(backing,fd,O_CLOEXEC)==fd);
            assert(__real_close(backing)==0);
        }
        return fd;
    }
    if((flags&O_CREAT)!=0) {
        va_list args;mode_t mode;
        va_start(args,flags);mode=(mode_t)va_arg(args,int);va_end(args);
        return __real_open(path,flags,mode);
    }
    return __real_open(path,flags);
}
int __wrap_close(int fd) {
    if(linked_fake!=NULL&&fake_slot(linked_fake,fd)>=0) {
        if(fake_close_fd(linked_fake,fd)!=0)return -1;
    }
    return __real_close(fd);
}
int __wrap_fstat(int fd,struct stat *value) {
    return linked_fake!=NULL&&fake_slot(linked_fake,fd)>=0?
        fake_fstat_fd(linked_fake,fd,value):__real_fstat(fd,value);
}
int __wrap_lstat(const char *path,struct stat *value) {
    return linked_fake!=NULL&&strcmp(path,PEN_NODE)==0?
        fake_lstat_node(linked_fake,path,value):__real_lstat(path,value);
}
ssize_t __wrap_recv(int fd,void *buffer,size_t length,int flags) {
    ssize_t result=__real_recv(fd,buffer,length,flags);
    static const char safe[]="GUARDIAN_SAFE_RELEASE ";
    if(linked_contact_case&&result>=(ssize_t)(sizeof(safe)-1)&&
            memcmp(buffer,safe,sizeof(safe)-1)==0)linked_release_stage=1;
    if(result>0) {
        const char *command=linked_is_abort()?"GUARDIAN_ABORT_BEFORE_READY ":
            linked_scenario==LINK_STOP_TIMEOUT?"GUARDIAN_SAFE_TIMEOUT ":"GUARDIAN_SAFE_RELEASE ";
        if((size_t)result>=strlen(command)&&memcmp(buffer,command,strlen(command))==0) {
            if(linked_scenario==LINK_STOP_RELEASE||linked_scenario==LINK_STOP_TIMEOUT||
                    linked_scenario==LINK_STOP_ABORT)assert(kill(getpid(),SIGSTOP)==0);
            if(linked_scenario==LINK_ABORT_CONTACT||linked_scenario==LINK_RELEASE_CONTACT)
                arm_guardian_contact(linked_fake,1500);
        }
    }
    return result;
}
int __wrap_ioctl(int fd,unsigned long request,...) {
    va_list args;int result;
    va_start(args,request);
    if(request==EVIOCGRAB) {
        int value=va_arg(args,int);
        if(linked_fake!=NULL) {
            linked_assert_signal_policy();
            assert(linked_fake->kernel->entropy_before_grab);
            if(value==1&&linked_is_abort()&&!linked_abort_triggered&&
                    getpid()==linked_worker_pid&&linked_fake->kernel->grab_calls==1&&
                    fd!=fake_grabbed_fd(linked_fake)) {
                linked_abort_triggered=1;assert(raise(SIGTERM)==0);
            }
        }
        result=linked_fake!=NULL&&fake_slot(linked_fake,fd)>=0?
            fake_ioctl_int(linked_fake,fd,request,value):__real_ioctl(fd,request,value);
    } else {
        void *value=va_arg(args,void *);
        result=linked_fake!=NULL&&fake_slot(linked_fake,fd)>=0?
            fake_ioctl_ptr(linked_fake,fd,request,value):__real_ioctl(fd,request,value);
        if(linked_contact_case&&fd==linked_phase_fd&&request==FIONREAD&&
                linked_release_stage>0&&++linked_release_stage==3)
            set_bit(linked_fake->current_keys,BTN_TOUCH);
    }
    va_end(args);return result;
}

int main(void) {
    for(int scenario=0;scenario<LINK_SCENARIOS;scenario++) {
        struct endpoint_fixture fixture;struct fake_evdev fake;
        char authority_fd[24],control_fd[24],phase_fd[24],status_fd[24],hash[65];
        char record[512],prefix[160],release[512],phase[512];
        struct guardian_binding binding;
        int status;pid_t worker;uint64_t start,finish;
        const char *hold=(scenario==LINK_STOP_RELEASE||scenario==LINK_STOP_ABORT)?"300000":
            (scenario==LINK_STOP_READY||scenario==LINK_STOP_TIMEOUT)?"700":"3000";
        fake_descriptor(&fake);fixture_open_fake(&fixture,&fake,strtoull(hold,NULL,10));
        linked_fake=&fake;linked_phase_fd=fixture.phase[0];
        linked_scenario=scenario;linked_abort_triggered=0;
        linked_contact_case=scenario==LINK_FINAL_CONTACT;linked_release_stage=0;
        snprintf(authority_fd,sizeof(authority_fd),"%d",fixture.context.authority_fd);
        snprintf(control_fd,sizeof(control_fd),"%d",fixture.control[0]);
        snprintf(phase_fd,sizeof(phase_fd),"%d",fixture.phase[0]);
        snprintf(status_fd,sizeof(status_fd),"%d",fixture.status[1]);
        for(size_t index=0;index<HASH_LENGTH;index++)
            snprintf(hash+index*2,3,"%02x",fixture.context.authority_file_hash[index]);
        worker=fork();assert(worker>=0);
        if(worker==0) {
            char *arguments[]={"linked-production","--hold-ms",(char *)hold,
                "--token",fixture.context.token,"--authority-fd",authority_fd,
                "--authority-sha256",hash,"--control-fd",control_fd,
                "--phase-fd",phase_fd,"--status-fd",status_fd,NULL};
            assert(close(fixture.control[1])==0&&close(fixture.phase[1])==0&&
                close(fixture.status[0])==0);
            linked_worker_pid=getpid();
            assert(signal(SIGCHLD,SIG_IGN)!=SIG_ERR);
            _exit(pen_input_lease_production_main(15,arguments));
        }
        close(fixture.control[0]);fixture.control[0]=-1;
        close(fixture.phase[0]);fixture.phase[0]=-1;
        close(fixture.status[1]);fixture.status[1]=-1;
        assert(boottime_ms(NULL,&start)==0);
        if(scenario==LINK_ENTROPY_EAGAIN) {
            snprintf(prefix,sizeof(prefix),"PEN_INPUT_LEASE_FAILED token=%s stage=prepare_guardian held=false ",fixture.context.token);
            child_read_line(fixture.status[0],prefix,record,sizeof(record));
            assert(waitpid(worker,&status,0)==worker&&WIFEXITED(status)&&WEXITSTATUS(status)==1);
            assert(fake.kernel->entropy_calls==1&&fake.kernel->grab_calls==0&&fake.kernel->ungrab_calls==0);
            wait_for_hup(fixture.status[0]);linked_fake=NULL;fixture_close(&fixture);continue;
        }
        if(linked_is_abort()) {
            if(scenario==LINK_STOP_ABORT) {
                wait_for_hup(fixture.status[0]);
                assert(boottime_ms(NULL,&finish)==0&&finish-start<2500);
                assert(fake.kernel->guardian_process>1);
                wait_until_process_gone(fake.kernel->guardian_process);
                assert(fake.kernel->ungrab_calls==0&&fake.kernel->implicit_last_close_releases==0&&
                    fake.kernel->ofd_refs[0]==1&&fake.kernel->ofd_refs[1]==1&&kill(worker,0)==0);
                assert(kill(worker,SIGKILL)==0&&waitpid(worker,&status,0)==worker);
                assert(fake.kernel->implicit_last_close_releases==1);
            } else {
                snprintf(prefix,sizeof(prefix),"PEN_INPUT_LEASE_FAILED token=%s stage=termination_before_ready held=false ",fixture.context.token);
                child_read_line(fixture.status[0],prefix,record,sizeof(record));
                assert(waitpid(worker,&status,0)==worker&&WIFEXITED(status)&&WEXITSTATUS(status)==1);
                assert(fake.kernel->ungrab_calls==1&&fake.kernel->implicit_last_close_releases==0);
            }
            assert(fake.kernel->sigchld_policy_checks>0);
            linked_fake=NULL;fixture_close(&fixture);continue;
        }
        snprintf(prefix,sizeof(prefix),"PEN_INPUT_LEASE_READY token=%s ",fixture.context.token);
        child_read_line(fixture.status[0],prefix,record,sizeof(record));
        parse_ready_binding(record,&binding);
        if(scenario==LINK_STOP_READY||scenario==LINK_PROBE_LOSS) {
            if(scenario==LINK_PROBE_LOSS) {
                fake.kernel->force_probe_loss=1;
                snprintf(prefix,sizeof(prefix),"PEN_INPUT_LEASE_FAILED token=%s ",fixture.context.token);
                child_read_line(fixture.status[0],prefix,record,sizeof(record));
                assert(fake.kernel->grabbed_fd==FAKE_FD_FIRST+1&&fake.kernel->grab_calls==2&&
                    fake.kernel->ofd_refs[1]==2&&fake.kernel->implicit_last_close_releases==0);
            }
            assert(kill(binding.pid,SIGSTOP)==0);
            wait_for_hup(fixture.status[0]);wait_until_process_gone(binding.pid);
            assert(kill(worker,0)==0&&fake.kernel->ungrab_calls==0&&fake_grabbed_fd(&fake)>=0);
            assert(fake.kernel->implicit_last_close_releases==0&&
                fake.kernel->ofd_refs[fake_grabbed_fd(&fake)-FAKE_FD_FIRST]==1);
            assert(kill(worker,SIGKILL)==0&&waitpid(worker,&status,0)==worker);
            fake_kernel_last_process_teardown(&fake);
        } else {
            external_final_records(&fixture,&binding,release,sizeof(release),phase,sizeof(phase));
            if(scenario!=LINK_STOP_TIMEOUT)
                assert(write(fixture.control[1],release,strlen(release))==(ssize_t)strlen(release));
            assert(write(fixture.phase[1],phase,strlen(phase))==(ssize_t)strlen(phase));
            close(fixture.control[1]);fixture.control[1]=-1;
            close(fixture.phase[1]);fixture.phase[1]=-1;
            if(scenario==LINK_STOP_RELEASE||scenario==LINK_STOP_TIMEOUT) {
                wait_for_hup(fixture.status[0]);wait_until_process_gone(binding.pid);
                assert(boottime_ms(NULL,&finish)==0&&finish-start<2500);
                assert(kill(worker,0)==0&&fake.kernel->ungrab_calls==0&&
                    fake.kernel->implicit_last_close_releases==0&&fake.kernel->ofd_refs[0]==1);
                assert(kill(worker,SIGKILL)==0&&waitpid(worker,&status,0)==worker);
                assert(fake.kernel->implicit_last_close_releases==1);
                linked_fake=NULL;fixture_close(&fixture);continue;
            }
            snprintf(prefix,sizeof(prefix),"PEN_INPUT_LEASE_%s token=%s ",
                scenario==LINK_FINAL_CONTACT?"FAILED":"RELEASED",fixture.context.token);
            child_read_line(fixture.status[0],prefix,record,sizeof(record));
            if(scenario!=LINK_FINAL_CONTACT) {
                assert(waitpid(worker,&status,0)==worker&&WIFEXITED(status)&&WEXITSTATUS(status)==0);
                assert(fake.kernel->grab_calls==1&&fake.kernel->ungrab_calls==1);
                wait_for_hup(fixture.status[0]);
            } else {
                assert(fake.kernel->ungrab_calls==0&&fake_grabbed_fd(&fake)>=0);
                assert(kill(worker,SIGKILL)==0&&waitpid(worker,&status,0)==worker);
                assert(kill(binding.pid,SIGKILL)==0);
                wait_for_hup(fixture.status[0]);wait_until_process_gone(binding.pid);
                fake_kernel_last_process_teardown(&fake);
            }
        }
        assert(fake.kernel->sigchld_policy_checks>0&&fake.kernel->entropy_before_grab);
        linked_fake=NULL;fixture_close(&fixture);
    }
    puts("PEN_INPUT_LEASE_LINK_WRAPPED_PRODUCTION_PASS unmodified_adapter=true success=true guardian_stop_hup=true final_idle_contact=true "
        "shared_standby_emergency_retained=true ofd_refcount_last_close=true final_command_silence_bounded=true "
        "abort_and_release_contact_1500ms=true ignored_sigchld_restored=true ack_loss_exit_118=true entropy_pre_grab_eagain_no_grab=true");
    return 0;
}
#endif
