#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "pen_input_lease_core.h"

struct fake {
    int call, fail_at, next_fd, open_mask, held_mask;
    int ready_lines, result_lines, quarantine_calls;
    int64_t parent;
    uint64_t now;
    int idle_result, final_idle_result;
    int idle_calls, active_on_idle_call;
    int break_exclusivity;
    int advance_after_first_grab, wait_idle_calls;
    int close_always_fails, release_always_fails, failed_emit_fails;
    int status_checks, status_fail_on_check;
    int last_idle_operation, contact_on_status_check;
    int termination_checks, termination_pending_on_check;
    int guardian_started, guardian_aborts;
    int start_guardian_result;
    int boottime_calls, suspend_on_clock_call;
    uint64_t suspend_delta, lease_deadline;
    struct pen_input_lease_end end;
    const char *failed_stage;
    int failed_held, failed_reboot;
};

static int step(struct fake *f) { return ++f->call == f->fail_at; }
static int simple(void *p) { return step(p) ? -1 : 0; }
static int64_t parent_id(void *p) { struct fake *f=p; return step(f)?-1:f->parent; }
static int termination_pending_fake(void *p) {
    struct fake *f=p;
    if(step(f))return -1;
    f->termination_checks++;
    return f->termination_checks==f->termination_pending_on_check?1:0;
}

static int open_device(void *p) {
    struct fake *f=p; int fd;
    if (step(f)) return -1;
    fd=f->next_fd++; f->open_mask|=1<<(fd-10); return fd;
}

static int fd_simple(void *p,int fd) {
    struct fake *f=p;
    assert(fd>=10 && fd<=30 && (f->open_mask&(1<<(fd-10))));
    return step(f)?-1:0;
}

static int same_device(void *p,int a,int b) {
    assert(a!=b); return step(p)?-1:0;
}

static int idle(void *p,int fd) {
    struct fake *f=p;
    assert(fd>=10 && (f->open_mask&(1<<(fd-10))));
    if (step(f)) return -1;
    f->idle_calls++;
    f->last_idle_operation=f->call;
    if (f->idle_calls==f->active_on_idle_call) return 1;
    return f->idle_result;
}

static int grab(void *p,int fd) {
    struct fake *f=p; int bit;
    if(fd<10||fd>30)return -1;
    bit=1<<(fd-10);
    if(step(f))return -1;
    if(f->held_mask&&!f->break_exclusivity)return 1;
    f->held_mask|=bit;
    if(f->advance_after_first_grab&&f->held_mask==bit)f->now+=501;
    return 0;
}

static int start_guardian_fake(void *p,int fd,uint64_t deadline,int64_t parent) {
    struct fake *f=p;
    assert(fd>=10&&deadline!=0&&parent==f->parent);
    if(step(f))return -1;
    f->lease_deadline=deadline;
    if(f->start_guardian_result!=0)return f->start_guardian_result;
    f->guardian_started=1;return 0;
}

static int abort_guardian_fake(void *p,int fd,uint64_t deadline,int64_t parent) {
    struct fake *f=p;int bit=1<<(fd-10);
    assert(f->guardian_started&&deadline==f->lease_deadline&&parent==f->parent);
    assert(f->last_idle_operation==f->call);
    if(step(f))return -1;
    f->guardian_aborts++;f->guardian_started=0;f->held_mask&=~bit;return 0;
}

static int release_device(void *p,int fd) {
    struct fake *f=p; int bit;
    if(fd<10||fd>30)return -1;
    bit=1<<(fd-10);
    assert(f->last_idle_operation==f->call);
    if(step(f)||f->release_always_fails)return -1;
    f->held_mask&=~bit;f->guardian_started=0;return 0;
}

static int close_device(void *p,int fd) {
    struct fake *f=p; int bit;
    if(fd<10||fd>30)return -1;
    bit=1<<(fd-10);
    if(step(f)||f->close_always_fails) { f->held_mask&=~bit; f->open_mask&=~bit; return -1; }
    f->held_mask&=~bit; f->open_mask&=~bit; return 0;
}

static int clock_ms(void *p,uint64_t *value) {
    struct fake *f=p;
    if(step(f))return -1;
    f->boottime_calls++;
    if(f->boottime_calls==f->suspend_on_clock_call)f->now+=f->suspend_delta;
    *value=f->now; return 0;
}

static int status_alive(void *p) {
    struct fake *f=p;
    if(step(f))return -1;
    f->status_checks++;
    if(f->status_checks==f->contact_on_status_check)f->idle_result=1;
    return f->status_checks==f->status_fail_on_check?-1:0;
}

static int emit_ready(void *p,uint64_t deadline) {
    struct fake *f=p; assert(deadline==f->lease_deadline);
    if(step(f))return -1;
    f->ready_lines++;
    return 0;
}

static int wait_until(void *p,int fd,uint64_t deadline,int64_t parent,
        struct pen_input_lease_end *outcome) {
    struct fake *f=p;
    assert(fd>=10 && deadline==f->lease_deadline && parent==f->parent);
    if(step(f))return -1;
    *outcome=f->end;
    return 0;
}

static enum pen_input_lease_idle_result wait_idle(void *p,int fd,
        uint64_t deadline,int64_t parent) {
    struct fake *f=p;
    assert(fd>=10 && deadline==f->lease_deadline && parent==f->parent);
    if(step(f))return PEN_INPUT_LEASE_IDLE_ERROR;
    f->wait_idle_calls++;
    return (enum pen_input_lease_idle_result)f->final_idle_result;
}

static int emit_released(void *p,enum pen_input_lease_end_reason reason) {
    struct fake *f=p; assert(reason==f->end.reason);
    if(step(f))return -1;
    f->result_lines++;
    return 0;
}

static int emit_failed(void *p,const char *stage,int held,int reboot) {
    struct fake *f=p;
    f->failed_stage=stage; f->failed_held=held; f->failed_reboot=reboot;
    if(step(f)||f->failed_emit_fails)return -1;
    f->result_lines++;
    return 0;
}

static void quarantine(void *p,int first,int second) {
    struct fake *f=p; f->quarantine_calls++;
    assert(first>=10 || second>=10);
}

static struct fake fresh(void) {
    struct fake f; memset(&f,0,sizeof(f));
    f.next_fd=10; f.parent=4321; f.now=100000;
    f.final_idle_result=PEN_INPUT_LEASE_IDLE;
    f.end.reason=PEN_INPUT_LEASE_END_RELEASE;
    f.end.release_received=1; f.end.final_phase_proved=1;
    return f;
}

static int run(struct fake *f,uint64_t hold) {
    struct pen_input_lease_ops ops; int result;
    memset(&ops,0,sizeof(ops));
    ops.context=f; ops.admit_contract=simple; ops.parent_id=parent_id;
    ops.install_cleanup_handlers=simple; ops.arm_parent_death=simple;
    ops.termination_pending=termination_pending_fake;
    ops.open_device=open_device; ops.verify_initial_device=fd_simple;
    ops.revalidate_device=fd_simple; ops.same_device=same_device;
    ops.idle=idle; ops.grab=grab; ops.start_guardian=start_guardian_fake;
    ops.prepare_guardian=same_device;
    ops.abort_guardian_before_ready=abort_guardian_fake;ops.release=release_device;
    ops.close_device=close_device; ops.boottime_ms=clock_ms;
    ops.status_consumer_alive=status_alive;
    ops.emit_ready=emit_ready; ops.wait_until=wait_until;
    ops.wait_idle_until=wait_idle; ops.prove_still_exclusive=fd_simple;
    ops.emit_released=emit_released; ops.emit_failed=emit_failed;
    ops.quarantine=quarantine;
    result=pen_input_lease_run(&ops,hold);
    assert(f->ready_lines<=1 && f->result_lines<=1 && f->quarantine_calls<=1);
    if(result!=2) assert(f->held_mask==0 && f->open_mask==0);
    else { assert(f->held_mask!=0 && f->open_mask!=0); f->held_mask=f->open_mask=0; }
    return result;
}

int main(void) {
    struct fake good=fresh();
    int success_calls;
    assert(run(&good,500)==0);
    assert(good.ready_lines==1 && good.result_lines==1 && good.quarantine_calls==0);
    success_calls=good.call;

    /* Every operation reached by the safe success path fails once. */
    for(int failure=1;failure<=success_calls;failure++) {
        struct fake injected=fresh(); injected.fail_at=failure;
        assert(run(&injected,500)!=0);
    }

    for(int reason=PEN_INPUT_LEASE_END_RELEASE;
            reason<=PEN_INPUT_LEASE_END_CONTROL_LOST;reason++) {
        struct fake normal=fresh(); normal.end.reason=(enum pen_input_lease_end_reason)reason;
        assert(run(&normal,500)==0);
    }

    { struct fake no_phase=fresh(); no_phase.end.final_phase_proved=0;
      assert(run(&no_phase,500)==2); assert(no_phase.failed_held==1&&no_phase.failed_reboot==1); }
    { struct fake before_grab=fresh(); before_grab.termination_pending_on_check=1;
      assert(run(&before_grab,500)==1);assert(before_grab.ready_lines==0&&
      before_grab.guardian_started==0&&before_grab.failed_held==0); }
    { struct fake before_ready=fresh(); before_ready.termination_pending_on_check=2;
      assert(run(&before_ready,500)==1);assert(before_ready.ready_lines==0&&
      before_ready.guardian_aborts==1&&before_ready.guardian_started==0&&
      before_ready.failed_held==0&&before_ready.quarantine_calls==0); }
    { struct fake active=fresh(); active.idle_result=1;
      assert(run(&active,500)==1); /* Admission rejects an initially active pen. */ }
    { struct fake active_at_end=fresh(); active_at_end.active_on_idle_call=3;
      active_at_end.final_idle_result=PEN_INPUT_LEASE_ACTIVE_AT_DEADLINE;
      assert(run(&active_at_end,500)==2);
      assert(strcmp(active_at_end.failed_stage,"final_idle")==0); }
    { struct fake settles=fresh(); settles.active_on_idle_call=3;
      settles.final_idle_result=PEN_INPUT_LEASE_IDLE;
      assert(run(&settles,500)==0); }
    { struct fake signal_active=fresh(); signal_active.end.reason=PEN_INPUT_LEASE_END_SIGNAL;
      signal_active.active_on_idle_call=3;
      assert(run(&signal_active,500)==2); assert(signal_active.wait_idle_calls==0); }
    { struct fake acquisition_overrun=fresh(); acquisition_overrun.advance_after_first_grab=1;
      assert(run(&acquisition_overrun,500)==2);
      assert(strcmp(acquisition_overrun.failed_stage,"idle_after_grab")==0); }
    { struct fake suspended=fresh(); suspended.suspend_on_clock_call=2;
      suspended.suspend_delta=501;
      assert(run(&suspended,500)==2);
      assert(strcmp(suspended.failed_stage,"idle_after_grab")==0&&
      suspended.lease_deadline==100500); }
    { struct fake resumed_before_ready=fresh();
      resumed_before_ready.suspend_on_clock_call=3;
      resumed_before_ready.suspend_delta=501;
      assert(run(&resumed_before_ready,500)==2);
      assert(strcmp(resumed_before_ready.failed_stage,"revalidate_before_ready")==0&&
      resumed_before_ready.lease_deadline==100500); }
    { struct fake no_guardian=fresh(); no_guardian.start_guardian_result=1;
      assert(run(&no_guardian,500)==1); assert(no_guardian.ready_lines==0&&
      no_guardian.quarantine_calls==0&&no_guardian.guardian_started==0&&
      strcmp(no_guardian.failed_stage,"guardian_not_created")==0); }
    { struct fake no_guardian_release_failure=fresh();
      no_guardian_release_failure.start_guardian_result=1;
      no_guardian_release_failure.release_always_fails=1;
      assert(run(&no_guardian_release_failure,500)==2);
      assert(strcmp(no_guardian_release_failure.failed_stage,"guardian_not_created")==0); }
    { struct fake broken=fresh(); broken.break_exclusivity=1;
      assert(run(&broken,500)==2); assert(broken.held_mask==0); }
    { struct fake invalid=fresh(); assert(run(&invalid,0)==1);
      assert(strcmp(invalid.failed_stage,"invalid_timeout")==0); }
    { struct fake overflow=fresh(); overflow.now=UINT64_MAX-100;
      assert(run(&overflow,500)==1); assert(strcmp(overflow.failed_stage,"clock_before_grab")==0); }
    { struct fake guardian_release_failure=fresh(); guardian_release_failure.release_always_fails=1;
      assert(run(&guardian_release_failure,500)==2);
      assert(strcmp(guardian_release_failure.failed_stage,"release")==0&&
      guardian_release_failure.failed_held==1&&guardian_release_failure.failed_reboot==1); }
    { struct fake pregrab_close=fresh(); pregrab_close.fail_at=7; pregrab_close.close_always_fails=1;
      assert(run(&pregrab_close,500)==1); assert(pregrab_close.open_mask==0&&pregrab_close.held_mask==0); }
    { struct fake status_blocked=fresh(); status_blocked.end.final_phase_proved=0;
      status_blocked.failed_emit_fails=1; assert(run(&status_blocked,500)==2);
      assert(status_blocked.result_lines==0); }
    { struct fake status_lost_after_ready=fresh(); status_lost_after_ready.status_fail_on_check=2;
      assert(run(&status_lost_after_ready,500)==2);
      assert(strcmp(status_lost_after_ready.failed_stage,"status_after_wait")==0); }
    { struct fake status_lost_before_release=fresh(); status_lost_before_release.status_fail_on_check=3;
      assert(run(&status_lost_before_release,500)==2);
      assert(strcmp(status_lost_before_release.failed_stage,"status_before_release")==0); }
    { struct fake last_moment_contact=fresh();last_moment_contact.contact_on_status_check=3;
      assert(run(&last_moment_contact,500)==2);
      assert(strcmp(last_moment_contact.failed_stage,"idle_at_release")==0&&
          last_moment_contact.failed_held==1); }
    { struct fake sole_holder_contact=fresh();sole_holder_contact.start_guardian_result=1;
      sole_holder_contact.contact_on_status_check=1;
      assert(run(&sole_holder_contact,500)==2&&sole_holder_contact.failed_held==1); }

    printf("PEN_INPUT_LEASE_CORE_TEST_PASS injected_operations=%d "
        "safe_reasons=5 quarantine=true no_device_calls=true\n",success_calls);
    return 0;
}
