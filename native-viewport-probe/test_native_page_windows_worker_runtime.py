"""Independent native shim/fault tests; no device, command backend, or network.

The fake models pipe writer ownership and a real Entry+S2 state machine. Tests
also mutate the authenticated wire independently of the implementation encoder.
Optional local native smoke exercises the OS boundary, not S6/S7 or hardware
admission. It creates a private temporary run and leaves no live process.
"""
from __future__ import annotations
from dataclasses import replace
from contextlib import contextmanager
import ctypes
import hashlib
import hmac
import json
import ntpath
import os
from pathlib import Path
import tempfile
import sys
import shutil
import threading
import time
import unittest
from unittest.mock import patch
import native_page_isolated_ipc as ipc
import native_page_windows_worker_runtime as rt
import native_page_worker_entry as entry
from native_page_cleanup_store import FileInfo, FileIdentity, AuthorityError

SESSION = "a" * 64
ROOT = r"C:\s2b-runtime"
RUN = r"C:\runs\one"

class FakeApi(rt._AcquisitionBook):
    def __init__(self):
        self._init_acquisitions()
        self.serial, self.clock = 10, 1_000_000_000
        self.handles, self.files, self.dirs = {}, {}, {}
        self.events, self.hooks = [], {}
        self._pipes, self._pipe_owner = {}, object()
        self._pipe_receipt_owner, self._closed_pipes, self._closed_pipe_values = object(), {}, {}
        self.worker = self.engine = self.entry = None
        self.identity_override = None
        self.hang = self.crash = self.join_failure = self.kill_failure = False
        self.child_handles, self.control = {}, None
        self.remote_serial = 10000
        self.parent_native = (40, 4000, r"C:\parent\python.exe")
        self.backend = entry.RoleBackend("authority_worker-v1", "b"*64, self.open_backend)
        self.add_file(ROOT+r"\python.exe", b"reviewed python")
        self.add_file(ROOT+r"\entry.py", b"reviewed entry")
        self.add_file(ROOT+r"\ipc.py", b"reviewed IPC")
    def step(self, name):
        self.events.append(name)
        if name in self.hooks: self.hooks[name](self)
    def alloc(self, kind, **values):
        self.serial += 1
        self.handles[self.serial] = dict(kind=kind, closed=False, **values)
        return self.serial
    def obj(self, handle):
        if type(handle) is rt.PipeHandle:
            rt.require(handle.owner is self._pipe_owner and self._pipes.get(handle.value) is handle,
                       "fake stale/foreign pipe generation")
            handle = handle.value
        result = self.handles[handle]
        rt.require(not result["closed"], "fake stale handle")
        return result
    def add_file(self, path, raw):
        self.files[path.casefold()] = dict(raw=raw, info=FileInfo(FileIdentity(1,len(self.files)+100),path,False,False,1))
    def open_file(self,path,**kwargs):
        self.step("open_file")
        return self.alloc("file", file=self.files[path.casefold()])
    def open_directory(self,path,**kwargs):
        self.step("open_directory")
        if path.casefold() not in self.dirs:
            self.dirs[path.casefold()] = FileInfo(FileIdentity(1,len(self.dirs)+1000),path,True,False,1)
        return self.alloc("directory", path=path.casefold())
    def info(self,handle):
        self.step("info"); obj=self.obj(handle)
        return obj["file"]["info"] if obj["kind"]=="file" else self.dirs[obj["path"]]
    def read_all(self,handle,limit):
        self.step("read_all"); raw=self.obj(handle)["file"]["raw"]
        rt.require(len(raw)<=limit,"fake file limit"); return raw
    def inventory(self,root):
        self.step("inventory"); return {p for p in self.files if p.startswith(root.casefold()+"\\")}
    def mkdir(self,path): self.step("mkdir"); rt.require(path.casefold() not in self.dirs,"CreateNew directory")
    def private_directory(self,handle): self.step("private_directory"); return not self.info(handle).reparse
    def create_sealed_file(self,path,raw):
        with self._acquiring():
            self.step("manifest_create"); rt.require(path.casefold() not in self.files,"CreateNew file")
            self.add_file(path,b""); handle=self.open_file(path); original=self._track_acquisition(handle)
            self.step("manifest_write"); self.files[path.casefold()]["raw"]=raw
            self.step("manifest_flush"); self.step("manifest_readback")
            result=self.alloc("file",file=self.obj(handle)["file"]); duplicate=self._track_acquisition(result)
            self.step("manifest_seal"); self._close_acquisition(original)
            self._publish_acquisition(duplicate); return result
    def retain_current_process(self): self.step("retain_parent"); return self.alloc("process", native=self.parent_native, alive=True)
    def inheritable_copy(self,handle):
        self.step("inherit_copy"); return self.alloc("copy", target=self.obj(handle), inheritable=True)
    def process_identity(self,handle):
        self.step("process_identity"); obj=self.obj(handle)
        return obj["native"]
    def create_job(self):
        with self._acquiring():
            self.step("create_job"); job=self.alloc("job", limits=(0x2008,1), process=None, extra=[])
            token=self._track_acquisition(job); self.step("job_policy")
            self._publish_acquisition(token); return job
    def system_root(self): return r"C:\Windows"
    def create_suspended(self,executable,argv,environment,cwd,handles):
        with self._acquiring(): return self._create_suspended(executable,argv,environment,cwd,handles)
    def _create_suspended(self,executable,argv,environment,cwd,handles):
        self.step("create_suspended")
        self.spawn_args = (executable,argv,environment,cwd,handles)
        for h in handles: rt.require(self.obj(h).get("inheritable"),"handle not marked inheritable")
        self.child_handles = {h:self.obj(h) for h in handles}
        native=self.identity_override or (90,9000,executable)
        process=self.alloc("process",native=native,alive=True,job=None)
        process_token=self._track_acquisition(process,rt._HandleKind.PROCESS,native)
        thread=self.alloc("thread",process=process,count=1)
        thread_token=self._track_acquisition(thread)
        self.worker=process
        self.descriptor=json.loads(self.files[argv[-2].casefold()]["raw"].split(b"\n--CONFIG--\n")[1])
        self.control=self.child_handles[self.descriptor["control_handle"]]["pipe"]
        self.step("created_suspended")
        self._publish_acquisition(process_token); self._publish_acquisition(thread_token)
        return process,thread
    def assign_job(self,job,process):
        self.step("assign_job"); self.obj(job)["process"]=process; self.obj(process)["job"]=job
        self.step("assigned_job")
    def in_job(self,process,job): self.step("in_job"); return self.obj(process).get("job")==job
    def job_state(self,job):
        self.step("job_state"); obj=self.obj(job); process=obj["process"]
        pids=(() if process is None or not self.obj(process)["alive"] else (self.obj(process)["native"][0],))+tuple(obj["extra"])
        return obj["limits"],pids
    def thread_suspended(self,thread): return self.obj(thread)["count"]==1
    def resume_thread(self,thread):
        self.step("resume_thread"); obj=self.obj(thread); prior=obj["count"]; obj["count"]=0
        if self.crash: self.obj(self.worker)["alive"]=False; return prior
        if not self.hang:
            self.entry=entry.Entry(self.descriptor, FakeNative(self), (self.backend,))
            self.drain()
        return prior
    def open_backend(self,descriptor,native): self.engine=Engine(self); return self.engine
    def drain(self):
        if self.entry is None or self.hang: return
        probe=ipc.FrameDecoder(); found=[]
        raw=bytes(self.control["raw"])
        for start in range(0,len(raw),ipc.MAX_CHUNK): found.extend(probe.feed(raw[start:start+ipc.MAX_CHUNK]))
        if len(found)>=(1 if self.entry.sequence==0 else 2): self.entry.serve_one()
    def alive(self,process): self.step("alive"); return self.obj(process)["alive"]
    def terminate_job(self,job):
        self.step("terminate_job")
        if self.kill_failure: raise OSError("fake job kill failure")
        process=self.obj(job)["process"]
        if process is not None: self.obj(process)["alive"]=False
        self.obj(job)["extra"]=[]
    def terminate_process(self,process):
        self.step("terminate_process")
        if self.kill_failure: raise OSError("fake process kill failure")
        self.obj(process)["alive"]=False
    def wait_process(self,process,deadline,clock):
        self.step("wait_process"); return not self.join_failure and not self.obj(process)["alive"]
    def close(self,handle):
        rt.require(type(handle) is not rt.PipeHandle and handle not in self._pipes,
                   "registered fake pipe requires typed close")
        self._acquisition_close_guard(handle)
        self.step("close"); self.obj(handle)["closed"]=True
    def _raw_close_acquisition(self,token,deadline,clock):
        self.step("close_acquired")
        if token.kind is rt._HandleKind.PROCESS:
            rt.require(clock is not None and clock()<deadline and self.obj(token.handle)["native"]==token.identity,
                       "fake unpublished process identity/deadline")
            self.terminate_process(token.handle)
            rt.require(self.wait_process(token.handle,deadline,clock),"fake unpublished join")
        self.step("close"); self.obj(token.handle)["closed"]=True
    def pipe_pair(self,*,parent_reads):
        with self._acquiring():
            self.step("reply_pipe" if parent_reads else "control_pipe")
            pipe=dict(raw=bytearray(),eof=False,reader_closed=False)
            parent=self.alloc("pipe",pipe=pipe,reads=parent_reads); p=self._track_acquisition(parent)
            self.step("pipe_parent")
            child=self.alloc("pipe",pipe=pipe,reads=not parent_reads,inheritable=True); c=self._track_acquisition(child)
            self.step("pipe_child"); self.step("pipe_connect")
            token=rt.PipeHandle(parent,self._pipe_owner); self._pipes[parent]=token
            self._publish_acquisition(p); self._publish_acquisition(c)
            return token,child
    def transfer_to_child(self,handle,process):
        self.step("transfer_writer"); self.obj(process)
        self.remote_serial+=1; self.child_handles[self.remote_serial]=self.obj(handle)
        return self.remote_serial
    def attest_pipe(self,handle):
        self.step("attest_pipe")
        rt.require(type(handle) is rt.PipeHandle and self.obj(handle)["kind"]=="pipe","wrong pipe")
    def attest_pipe_closed(self,handle,receipt):
        self.step("attest_pipe_closed")
        expected=self._closed_pipe_values.get(handle)
        rt.require(type(handle) is rt.PipeHandle and type(receipt) is rt._PipeCloseReceipt
            and receipt.endpoint is handle and receipt.native==handle.value
            and receipt.authority is self._pipe_receipt_owner
            and self._closed_pipes.get(handle) is receipt
            and expected is not None and expected[0] is receipt
            and expected[1] is handle and expected[2]==receipt.native
            and expected[3] is receipt.authority and expected[4] is receipt.generation
            and self._pipes.get(handle.value) is not handle,
            "wrong fake pipe close receipt")
    def write_pipe(self,handle,raw,deadline,clock):
        self.step("write_pipe"); pipe=self.obj(handle)["pipe"]; pipe["raw"].extend(raw); self.drain()
    def read_pipe(self,handle,limit,deadline,clock):
        self.step("read_pipe"); pipe=self.obj(handle)["pipe"]
        if pipe["raw"]:
            result=bytes(pipe["raw"][:limit]); del pipe["raw"][:limit]; return result
        return b"" if pipe["eof"] else None
    def close_pipe(self,handle):
        prior=self._closed_pipes.get(handle)
        if prior is not None:
            self.attest_pipe_closed(handle,prior); return prior
        self.step("close_pipe")
        self.attest_pipe(handle); node=self.obj(handle)
        self.step("close")
        node["pipe"]["reader_closed"]=True; node["closed"]=True
        del self._pipes[handle.value]
        generation=object()
        receipt=rt._PipeCloseReceipt(handle,handle.value,self._pipe_receipt_owner,generation)
        self._closed_pipes[handle]=receipt
        self._closed_pipe_values[handle]=(receipt,handle,handle.value,self._pipe_receipt_owner,generation)
        self.attest_pipe_closed(handle,receipt)
        return receipt
    def sleep_ns(self,ns): self.clock+=ns

class FakeNative:
    def __init__(self,api): self.api=api
    def now_ns(self): return self.api.clock
    def attest_bootstrap(self,d):
        rt.require(d["parent"]==dict(pid=self.api.parent_native[0],creation_ticks=self.api.parent_native[1],image_path=self.api.parent_native[2]),"fake parent drift")
    def self_identity(self): return self.api.obj(self.api.worker)["native"]
    def attest_writer(self,handle): rt.require(handle in self.api.child_handles,"foreign writer")
    def read_control(self,handle,limit):
        pipe=self.api.control; result=bytes(pipe["raw"][:limit]); del pipe["raw"][:limit]; return result
    def write_reply(self,handle,raw):
        self.api.step("worker_reply"); self.api.child_handles[handle]["pipe"]["raw"].extend(raw)
    def close_writer(self,handle): self.api.child_handles[handle]["pipe"]["eof"]=True

class Engine:
    def __init__(self,api): self.api=api; self.calls=[]; self.sealed=False
    def dispatch(self,operation,payload,deadline):
        self.api.step("dispatch"); self.calls.append((operation,payload,deadline)); return {"echo":payload}
    def verify_quiescent(self,operation): self.api.step("engine_quiescent")
    def seal(self): self.sealed=True

def image(api,role="authority_worker",**kwargs):
    return rt.WorkerImage(role,rt.SourcePin(ROOT+r"\python.exe",rt.sha(b"reviewed python")),
        (rt.SourcePin(ROOT+r"\entry.py",rt.sha(b"reviewed entry"),"native_page_worker_entry","source"),
         rt.SourcePin(ROOT+r"\ipc.py",rt.sha(b"reviewed IPC"),"native_page_isolated_ipc","source")),
        runtime_roots=(ROOT,),backend_sha256="b"*64,configuration={"v":1},api=api,**kwargs)

def setup(role="authority_worker"):
    api=FakeApi(); img=image(api,role)
    if role=="frida_worker": api.backend=replace(api.backend,factory_id="frida_worker-v1")
    runtime=rt.WindowsWorkerRuntime(RUN,launch_deadline_ns=api.clock+60_000_000_000,
        start_guard=lambda *args: api.step("start_guard"),api=api,clock_ns=lambda:api.clock)
    return api,img,runtime,ipc.IsolatedWorker(img,runtime,SESSION)

def packet(stream,payload=b"",terminal=False,ordinal=0,**changes):
    # Independent JSON/HMAC oracle; not rt/entry serialization helpers.
    value={"domain":rt.DOMAIN,"binding":rt.binding_wire(stream.binding),"nonce":stream.nonce,
           "ordinal":ordinal,"payload":payload.hex() if type(payload) is bytes else payload,"terminal":terminal}
    value.update(changes)
    raw=json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
    value["mac"]=hmac.new(stream.channel.key,raw,hashlib.sha256).hexdigest()
    raw=json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
    return len(raw).to_bytes(4,"big")+raw

class RuntimeTests(unittest.TestCase):
    def test_exact_two_roles_full_s2_roundtrip(self):
        for role,operation in (("authority_worker","authority_capture"),("frida_worker","frida_admission")):
            with self.subTest(role=role):
                api,img,runtime,worker=setup(role); deadline=api.clock+250_000_000
                worker.start(deadline)
                binding=runtime.binding(runtime.process)
                self.assertEqual(binding.role,role); self.assertEqual(binding.session,SESSION)
                ticket=worker.register_operation("probe",operation,{"sample":7},deadline)
                result=worker.begin_and_wait(ticket,deadline)
                self.assertEqual(result.value,{"echo":{"sample":7}})
                self.assertEqual(len(api.engine.calls),1)
                worker.fail_stop_and_quiesce(250); worker.assert_quiescent(); img.close()
    def test_closed_roles(self):
        for role in ("operation_child","pen_worker","guardian","",None,True):
            with self.subTest(role=role),self.assertRaises(ipc.IpcError): image(FakeApi(),role)
    def test_runtime_closure_must_cover_executable_directory(self):
        api=FakeApi()
        with self.assertRaisesRegex(ipc.IpcError,"executable directory"):
            rt.WorkerImage("authority_worker",rt.SourcePin(ROOT+r"\python.exe",rt.sha(b"reviewed python")),
                (rt.SourcePin(ROOT+r"\entry.py",rt.sha(b"reviewed entry"),"native_page_worker_entry","source"),
                 rt.SourcePin(ROOT+r"\ipc.py",rt.sha(b"reviewed IPC"),"native_page_isolated_ipc","source")),
                runtime_roots=(r"C:\unrelated",),backend_sha256="b"*64,configuration={},api=api)
    def test_fixed_environment_argv_inheritance_and_order(self):
        api,img,runtime,worker=setup()
        with patch.dict(os.environ,{"PATH":"evil","PYTHONPATH":"evil","PYTHONSTARTUP":"evil","COMPlus_X":"evil"}):
            worker.start(api.clock+250_000_000)
        exe,argv,env,cwd,handles=api.spawn_args
        self.assertEqual(env,{"SystemRoot":r"C:\Windows","WINDIR":r"C:\Windows"})
        self.assertEqual(argv[1:10],("-I","-S","-E","-B","-s","-P","-X","utf8","-c"))
        self.assertEqual(argv[10],rt.BOOTSTRAP); self.assertEqual(cwd,RUN); self.assertEqual(len(handles),2)
        self.assertLess(api.events.index("assign_job"),api.events.index("resume_thread"))
        self.assertLess(api.events.index("start_guard"),api.events.index("resume_thread"))
    def test_spawn_image_substitution_killed_before_resume(self):
        for path in (r"C:\evil\python.exe",r"C:\Windows\System32\conhost.exe"):
            api,img,runtime,worker=setup(); api.identity_override=(90,9000,path)
            with self.assertRaises(ipc.IpcError): runtime.launch_suspended(img,SESSION)
            self.assertNotIn("resume_thread",api.events)
            self.assertFalse(api.handles[api.worker]["alive"])
    def test_fixed_detached_flags(self):
        self.assertEqual(rt.SPAWN_FLAGS,0x8040c)
        self.assertTrue(rt.SPAWN_FLAGS & 8)
        self.assertFalse(rt.SPAWN_FLAGS & (0x10 | 0x08000000))
    def test_start_guard_consumed_once(self):
        api,img,runtime,worker=setup(); worker.start(api.clock+250_000_000)
        with self.assertRaises(ipc.IpcError): runtime.resume(runtime.process)
        self.assertEqual(api.events.count("start_guard"),1)
    def test_expiry_during_final_guard_never_resumes(self):
        api,img,runtime,worker=setup(); deadline=api.clock+25_000_000
        api.hooks["start_guard"]=lambda a:setattr(a,"clock",deadline+1)
        with self.assertRaises(ipc.IpcError): worker.start(deadline)
        self.assertNotIn("resume_thread",api.events)
    def test_final_source_change_never_resumes(self):
        api,img,runtime,worker=setup()
        api.hooks["start_guard"]=lambda a:a.files[ROOT.casefold()+r"\entry.py"].update(raw=b"evil")
        with self.assertRaises(ipc.IpcError): worker.start(api.clock+250_000_000)
        self.assertNotIn("resume_thread",api.events)
    def test_job_assignment_failure_never_resumes(self):
        api,img,runtime,worker=setup()
        api.hooks["assign_job"]=lambda a:(_ for _ in ()).throw(OSError("assignment denied"))
        with self.assertRaises(OSError): runtime.launch_suspended(img,SESSION)
        self.assertNotIn("resume_thread",api.events); self.assertFalse(api.handles[api.worker]["alive"])
    def test_assignment_race_policy_change(self):
        api,img,runtime,worker=setup()
        api.hooks["assigned_job"]=lambda a:a.obj(a.obj(a.worker)["job"]).update(limits=(0x2008,2))
        with self.assertRaises(ipc.IpcError): runtime.launch_suspended(img,SESSION)
        self.assertNotIn("resume_thread",api.events)
    def test_parent_and_child_reuse_fail_closed(self):
        for parent in (True,False):
            with self.subTest(parent=parent):
                api,img,runtime,worker=setup(); worker.start(api.clock+250_000_000)
                handle=runtime.process.parent_handle if parent else runtime.process.handle
                old=api.obj(handle)["native"]; api.obj(handle)["native"]=(old[0],old[1]+1,old[2])
                before=api.events.count("terminate_job")
                with self.assertRaises(ipc.IpcError): runtime.terminate(runtime.process,ipc.ProcessIdentity(90,9000,img.executable.sha256,img._bootstrap_sha,img.role))
                self.assertEqual(api.events.count("terminate_job"),before)
    def test_descendant_escape_and_limit_drift(self):
        for mutation in (lambda job:job.update(extra=[91]),lambda job:job.update(limits=(8,1))):
            api,img,runtime,worker=setup(); worker.start(api.clock+250_000_000)
            mutation(api.obj(runtime.process.job))
            with self.assertRaises(ipc.IpcError): runtime.attest_containment(runtime.process,())
    def test_spawn_children_always_denied(self):
        api,img,runtime,worker=setup()
        with self.assertRaises(ipc.IpcError): runtime.spawn_child_suspended(None,"op",img)
        self.assertNotIn("create_suspended",api.events)
    def test_worker_hang_and_crash(self):
        for name in ("hang","crash"):
            with self.subTest(name=name):
                api,img,runtime,worker=setup(); setattr(api,name,True)
                with self.assertRaises(ipc.IpcError): worker.start(api.clock+25_000_000)
                worker.fail_stop_and_quiesce(250); worker.assert_quiescent()
    def test_operation_hang_and_dispatch_crash(self):
        for hang in (True,False):
            api,img,runtime,worker=setup(); deadline=api.clock+25_000_000; worker.start(deadline)
            ticket=worker.register_operation("probe","authority_capture",{},deadline)
            if hang: api.hang=True
            else: api.hooks["dispatch"]=lambda a:(_ for _ in ()).throw(OSError("backend crash"))
            with self.assertRaises((OSError,ipc.IpcError)): worker.begin_and_wait(ticket,deadline)
            worker.fail_stop_and_quiesce(250); worker.assert_quiescent()
    def test_job_exit_accounting_wait_preserves_deadline(self):
        for clears in (True,False):
            api,img,runtime,worker=setup(); worker.start(api.clock+250_000_000)
            process=runtime.process; identity=runtime.identity(process)
            runtime.close_channel(runtime.channel); runtime.terminate(process,identity)
            original=api.job_state; calls=[0]
            def delayed(job):
                limits,pids=original(job); calls[0]+=1
                return limits,(() if clears and calls[0]>2 else (identity.pid,))
            api.job_state=delayed; deadline=api.clock+5_000_000
            self.assertEqual(runtime.join(process,identity,deadline),clears)
            self.assertLessEqual(api.clock,deadline)
    def test_kill_and_join_failures_remain_obligations(self):
        for name in ("kill_failure","join_failure"):
            api,img,runtime,worker=setup(); worker.start(api.clock+250_000_000); setattr(api,name,True)
            with self.assertRaises(ipc.WorkerQuiescenceError): worker.fail_stop_and_quiesce(250)
            self.assertFalse(runtime.process.closed)
            setattr(api,name,False); worker.fail_stop_and_quiesce(250); worker.assert_quiescent()
    def test_failed_launch_kill_failure_retains_retry_handles(self):
        api,img,runtime,worker=setup(); api.identity_override=(90,9000,r"C:\evil\python.exe"); api.kill_failure=True
        with self.assertRaises(ipc.WorkerQuiescenceError): runtime.launch_suspended(img,SESSION)
        self.assertFalse(api.handles[api.worker]["closed"])
        api.kill_failure=False; runtime.abort_failed_launch(runtime.launch_deadline_ns)
        self.assertTrue(api.handles[api.worker]["closed"])
        with self.assertRaises(ipc.IpcError): runtime.abort_failed_launch(runtime.launch_deadline_ns)
    def test_failed_unpublished_launch_cannot_make_s2_closed(self):
        api,img,runtime,worker=setup(); api.identity_override=(90,9000,r"C:\evil\python.exe"); api.kill_failure=True
        with self.assertRaises(ipc.WorkerQuiescenceError): worker.start(api.clock+25_000_000)
        with self.assertRaises(ipc.WorkerQuiescenceError): worker.fail_stop_and_quiesce(250)
        with self.assertRaises(ipc.IpcError): worker.assert_quiescent()
        self.assertNotEqual(worker.state,"CLOSED")
        api.kill_failure=False; runtime.abort_failed_launch(runtime.launch_deadline_ns)
        worker.fail_stop_and_quiesce(250); worker.assert_quiescent()
    def test_failed_launch_recovery_rejects_identity_and_deadline_substitution(self):
        for mutation in ("identity","deadline"):
            api,img,runtime,worker=setup(); api.identity_override=(90,9000,r"C:\evil\python.exe"); api.kill_failure=True
            with self.assertRaises(ipc.WorkerQuiescenceError): runtime.launch_suspended(img,SESSION)
            if mutation=="identity": api.obj(api.worker)["native"]=(90,9001,r"C:\evil\python.exe")
            before=api.events.count("terminate_process")
            deadline=runtime.launch_deadline_ns+1 if mutation=="deadline" else runtime.launch_deadline_ns
            with self.assertRaises(ipc.IpcError): runtime.abort_failed_launch(deadline)
            self.assertEqual(api.events.count("terminate_process"),before)
            self.assertTrue(runtime._launch_uncertain)
    def test_constructor_requires_immutable_unexpired_deadline(self):
        api=FakeApi()
        with self.assertRaises(TypeError): rt.WindowsWorkerRuntime(RUN,start_guard=lambda *args:None,api=api)
        for deadline in (None,True,api.clock,api.clock-1,api.clock+60_000_000_001):
            with self.assertRaises(ipc.IpcError):
                rt.WindowsWorkerRuntime(RUN,launch_deadline_ns=deadline,start_guard=lambda *args:None,api=api,clock_ns=lambda:api.clock)
        api,img,runtime,worker=setup()
        with self.assertRaises(AttributeError): runtime.launch_deadline_ns=runtime.launch_deadline_ns+1
        api.clock=runtime.launch_deadline_ns
        with self.assertRaises(ipc.IpcError): runtime.launch_suspended(img,SESSION)
        self.assertNotIn("mkdir",api.events)
    def test_foreign_thread_and_reentry_do_not_mutate(self):
        api,img,runtime,worker=setup(); worker.start(api.clock+250_000_000)
        errors=[]; before=len(api.events); barrier=threading.Barrier(2)
        def foreign():
            barrier.wait()
            try: runtime.open_reply_stream(runtime.channel,ipc.ReplyBinding(runtime.identity(runtime.process),SESSION,1,"x",None),api.clock+25_000_000)
            except BaseException as e: errors.append(e)
        thread=threading.Thread(target=foreign); thread.start(); barrier.wait(); thread.join()
        self.assertEqual(len(errors),1); self.assertIsInstance(errors[0],ipc.IpcError)
        with runtime._lease():
            count=len(api.events)
            with self.assertRaises(ipc.IpcError): runtime.identity(runtime.process)
            self.assertEqual(len(api.events),count)
    def test_post_terminal_use_rejected(self):
        api,img,runtime,worker=setup(); worker.start(api.clock+250_000_000); process=runtime.process
        worker.fail_stop_and_quiesce(250)
        for action in (lambda:runtime.resume(process),lambda:runtime.identity(process),lambda:runtime.launch_suspended(img,SESSION)):
            with self.assertRaises(ipc.IpcError): action()
    def test_live_source_topology_and_identity_mutations(self):
        mutations=[lambda a:a.add_file(ROOT+r"\injected.py",b"evil"),
            lambda a:a.files[(ROOT+r"\ipc.py").casefold()].update(raw=b"evil"),
            lambda a:a.files[(ROOT+r"\ipc.py").casefold()].update(info=replace(a.files[(ROOT+r"\ipc.py").casefold()]["info"],links=2)),
            lambda a:a.dirs[ROOT.casefold()] and a.dirs.update({ROOT.casefold():replace(a.dirs[ROOT.casefold()],reparse=True)}),
            lambda a:a.files[(ROOT+r"\entry.py").casefold()].update(info=replace(a.files[(ROOT+r"\entry.py").casefold()]["info"],identity=FileIdentity(1,99999)))]
        for mutation in mutations:
            api,img,runtime,worker=setup(); mutation(api)
            with self.assertRaises(ipc.IpcError): img.verify()
    def test_configuration_detachment_and_mutation(self):
        api=FakeApi(); config={"nested":[1]}
        # External data detached, later public authority edits detected.
        img=image(api); img.configuration["v"]=2
        with self.assertRaises(ipc.IpcError): img.verify()
    def test_source_locks_cannot_close_while_worker_live(self):
        api,img,runtime,worker=setup(); worker.start(api.clock+250_000_000)
        with self.assertRaises(ipc.IpcError): img.close()
        worker.fail_stop_and_quiesce(250); img.close(); self.assertTrue(img.closed)
    def test_capability_access_identity_and_inheritance(self):
        api=FakeApi(); handle=api.alloc("capability"); state=[b"id"]
        cap=rt.Capability("read-only",handle,b"id",lambda h:state[0])
        img=image(api,capabilities=(cap,)); state[0]=b"changed"
        with self.assertRaises(ipc.IpcError): img.verify()
    def test_public_binding_strict_types_and_role(self):
        api,img,runtime,worker=setup(); worker.start(api.clock+250_000_000); binding=runtime.binding(runtime.process)
        for changes in ({"pid":True},{"creation_ticks":None},{"role":"mutation_worker"},{"factory_id":"frida_worker-v1"},{"session":"x"}):
            with self.assertRaises(ipc.IpcError): replace(binding,**changes)
    def test_all_launch_boundaries_fail_closed(self):
        stages=("open_directory","mkdir","private_directory","retain_parent","inherit_copy","control_pipe",
                "manifest_create","manifest_write","manifest_flush","manifest_readback","manifest_seal",
                "create_job","create_suspended","assign_job","assigned_job")
        for name in stages:
            with self.subTest(stage=name):
                api,img,runtime,worker=setup()
                api.hooks[name]=lambda a:(_ for _ in ()).throw(OSError("fault"))
                with self.assertRaises((OSError,ipc.IpcError)): runtime.launch_suspended(img,SESSION)
                self.assertNotIn("resume_thread",api.events)
                if api.worker is not None: self.assertFalse(api.handles[api.worker]["alive"])

class ReplyTests(unittest.TestCase):
    def fixture(self):
        api,img,runtime,worker=setup(); worker.start(api.clock+250_000_000)
        binding=ipc.ReplyBinding(runtime.identity(runtime.process),SESSION,1,"probe",None)
        stream=runtime.open_reply_stream(runtime.channel,binding,api.clock+25_000_000)
        return api,img,runtime,stream
    def read(self,api,runtime,stream):
        result=[]
        for _ in range(100):
            raw=runtime.read_reply(stream,ipc.MAX_CHUNK,api.clock+25_000_000)
            if raw==b"": return b"".join(result)
            if raw: result.append(raw)
        raise AssertionError("no exact EOF")
    def test_independent_hmac_packet_oracle_exact_eof(self):
        api,img,runtime,stream=self.fixture(); pipe=api.obj(stream.handle)["pipe"]
        pipe["raw"].extend(packet(stream,b"hello")+packet(stream,terminal=True,ordinal=1)); pipe["eof"]=True
        self.assertEqual(self.read(api,runtime,stream),b"hello")
        with self.assertRaises(ipc.IpcError): runtime.read_reply(stream,1,api.clock+25_000_000)
    def test_replay_wrong_binding_nonce_domain_ordinal_type(self):
        changes=[{"nonce":"c"*64},{"domain":"wrong"},{"ordinal":True},{"terminal":1},
                 {"binding":{}},{"ordinal":7},{"payload":"GG"}]
        for mutation in changes:
            api,img,runtime,stream=self.fixture(); pipe=api.obj(stream.handle)["pipe"]
            pipe["raw"].extend(packet(stream,**mutation)); pipe["eof"]=True
            with self.assertRaises(ipc.IpcError): self.read(api,runtime,stream)
    def test_bad_mac_partial_frame_trailing_and_missing_terminal(self):
        for variant in ("mac","partial","trailing","no_terminal","duplicate"):
            api,img,runtime,stream=self.fixture(); pipe=api.obj(stream.handle)["pipe"]
            raw=packet(stream,terminal=True)
            if variant=="mac": raw=raw.replace(b'"mac":"',b'"mac":"0',1)
            if variant=="partial": raw=raw[:-1]
            if variant=="trailing": raw+=b"x"
            if variant=="no_terminal": raw=packet(stream,b"data")
            if variant=="duplicate": raw+=raw
            pipe["raw"].extend(raw); pipe["eof"]=True
            with self.assertRaises(ipc.IpcError): self.read(api,runtime,stream)
    def test_terminal_packet_without_pipe_eof_not_complete(self):
        api,img,runtime,stream=self.fixture(); api.obj(stream.handle)["pipe"]["raw"].extend(packet(stream,terminal=True))
        self.assertIsNone(runtime.read_reply(stream,4096,api.clock+25_000_000))
        self.assertIsNone(runtime.read_reply(stream,4096,api.clock+25_000_000))
        with self.assertRaises(AttributeError): getattr(stream,"eof")
    def test_late_read_output_rejected(self):
        api,img,runtime,stream=self.fixture(); deadline=api.clock+25_000_000
        api.hooks["read_pipe"]=lambda a:setattr(a,"clock",deadline+1)
        with self.assertRaises(ipc.IpcError): runtime.read_reply(stream,4096,deadline)
    def test_fresh_stream_not_reusable_and_cancel_seals(self):
        api,img,runtime,stream=self.fixture(); runtime.close_reply_stream(stream,stream.binding)
        with self.assertRaises(ipc.IpcError): runtime.open_reply_stream(runtime.channel,stream.binding,api.clock+25_000_000)
        with self.assertRaises(ipc.IpcError): runtime.attest_reply_stream(stream,stream.binding)
    def test_unpublished_reply_fault_reclaimed_by_s2_cleanup(self):
        api,img,runtime,worker=setup(); worker.start(api.clock+250_000_000)
        api.hooks["write_pipe"]=lambda a:(_ for _ in ()).throw(OSError("header publication failure"))
        with self.assertRaises(OSError): worker.register_operation("probe","authority_capture",{},api.clock+25_000_000)
        self.assertIsNone(runtime.reply); worker.assert_quiescent()

class EntryTests(unittest.TestCase):
    def descriptor(self):
        api,img,runtime,worker=setup(); runtime.launch_suspended(img,SESSION); return api,api.descriptor
    def test_no_ambient_backend(self):
        api,d=self.descriptor()
        with self.assertRaisesRegex(ipc.IpcError,"unavailable"): entry.Entry(d,FakeNative(api),())
    def test_closed_factory_registry(self):
        api,d=self.descriptor()
        for factories in ([api.backend],(replace(api.backend,factory_id="import.me"),),(api.backend,api.backend),
                          (replace(api.backend,implementation_sha256="c"*64),)):
            with self.assertRaises(ipc.IpcError): entry.Entry(d,FakeNative(api),factories)
    def test_strict_descriptor_mutations(self):
        api,d=self.descriptor()
        for name,value in (("version",True),("factory","some.module.function"),("parent_handle",True),
                           ("key",None),("capabilities",{}),("configuration",[]),("role","pen_worker")):
            changed={**d,name:value}
            with self.assertRaises(ipc.IpcError): entry.validate_descriptor(changed)
    def test_all_unregistered_commands_rejected(self):
        for operation in ("exec","eval","shell","spawn","authority_capture;anything","frida_attach"):
            api,img,runtime,worker=setup(); deadline=api.clock+250_000_000; worker.start(deadline)
            with self.assertRaises(ipc.IpcError): worker.register_operation("probe",operation,{},deadline)
            self.assertFalse(api.engine.calls)
    def test_late_backend_never_terminal_success(self):
        api,img,runtime,worker=setup(); deadline=api.clock+25_000_000; worker.start(deadline)
        ticket=worker.register_operation("probe","authority_capture",{},deadline)
        api.hooks["dispatch"]=lambda a:setattr(a,"clock",deadline+1)
        with self.assertRaises(ipc.IpcError): worker.begin_and_wait(ticket,deadline)
        self.assertTrue(api.engine.sealed)
    def test_ack_precedes_dispatch_and_quiescence_precedes_result(self):
        api,img,runtime,worker=setup(); deadline=api.clock+250_000_000; worker.start(deadline)
        ticket=worker.register_operation("probe","authority_capture",{},deadline); api.events.clear()
        worker.begin_and_wait(ticket,deadline)
        self.assertLess(api.events.index("worker_reply"),api.events.index("dispatch"))
        self.assertLess(api.events.index("dispatch"),api.events.index("engine_quiescent"))
    def test_duplicate_keys_and_noncanonical_frames(self):
        for raw in (b'{"x":1,"x":2}',b'{"x": 1}',b'{"x":1.0}',b'{"x":NaN}'):
            with self.assertRaises(ipc.IpcError): ipc.decode_json(raw)

class RetainedAuthorityRegressions(unittest.TestCase):
    """Permanent cases from the independent s2b_adversarial_probe.py review."""
    def test_constructor_authority_views_are_read_only(self):
        api,img,runtime,worker=setup()
        for target,name,value in ((runtime,"api",FakeApi()),(img,"api",FakeApi()),
                (runtime,"run_path",r"C:\runs\substituted"),(runtime,"clock",lambda:0),
                (runtime,"start_guard",lambda *args:None),(runtime,"owner",123),
                (runtime,"launch_deadline_ns",runtime.launch_deadline_ns+1),
                (runtime,"lifecycle",rt.Lifecycle.READY)):
            before=list(api.events)
            with self.subTest(name=name),self.assertRaises(AttributeError): setattr(target,name,value)
            self.assertEqual(api.events,before)
        worker.start(api.clock+250_000_000)
        self.assertEqual(api.events.count("start_guard"),1)
        self.assertEqual(api.spawn_args[3],RUN)
        worker.fail_stop_and_quiesce(250); img.close()

    def test_private_constructor_reference_substitution_is_revalidated(self):
        for field,value in (("api",FakeApi()),("run_path",r"C:\runs\substituted"),
                ("clock",lambda:0),("start_guard",lambda *args:None),("owner",123),("deadline_ns",2_000_000_000)):
            api,img,runtime,worker=setup()
            original=runtime._WindowsWorkerRuntime__authority
            runtime._WindowsWorkerRuntime__authority=replace(original,**{field:value})
            before=list(api.events)
            with self.subTest(field=field),self.assertRaises(ipc.IpcError): runtime.launch_suspended(img,SESSION)
            self.assertEqual(api.events,before)
            runtime._WindowsWorkerRuntime__authority=original
            img.close()
        api,img,runtime,worker=setup(); original=img.api
        img._WorkerImage__api=FakeApi()
        before=list(api.events)
        with self.assertRaises(ipc.IpcError): img.verify()
        self.assertEqual(api.events,before)
        img._WorkerImage__api=original; img.close()

    def test_reviewer_clock_and_lying_api_substitutions_cannot_launch(self):
        class LyingApi:
            def __init__(self,backing,path): self.backing,self.path=backing,path
            def __getattr__(self,name): return getattr(self.backing,name)
            def process_identity(self,handle):
                value=self.backing.process_identity(handle)
                return (value[0],value[1],self.path) if value[0]==90 else value
        api,img,runtime,worker=setup()
        api.clock=runtime.launch_deadline_ns+1
        with self.assertRaises(AttributeError): runtime.clock=lambda:1_000_000_000
        with self.assertRaises(ipc.IpcError): runtime.launch_suspended(img,SESSION)
        self.assertNotIn("mkdir",api.events); img.close()
        api,img,runtime,worker=setup()
        api.identity_override=(90,9000,r"C:\other\python.exe")
        replacement=LyingApi(api,img.executable.path)
        for target in (runtime,img):
            with self.assertRaises(AttributeError): target.api=replacement
        with self.assertRaises(ipc.IpcError): runtime.launch_suspended(img,SESSION)
        self.assertNotIn("resume_thread",api.events); img.close()

    def test_binding_requires_ready_publication_not_suspend_or_resume(self):
        api,img,runtime,worker=setup(); api.hang=True
        process=runtime.launch_suspended(img,SESSION).process
        self.assertEqual(runtime.lifecycle,rt.Lifecycle.SUSPENDED)
        with self.assertRaises(ipc.IpcError): runtime.binding(process)
        identity=runtime.identity(process); deadline=api.clock+250_000_000
        binding=ipc.ReplyBinding(identity,SESSION,0,None,None)
        stream=runtime.open_reply_stream(runtime.channel,binding,deadline)
        runtime.resume(process)
        self.assertEqual(runtime.lifecycle,rt.Lifecycle.RESUMED)
        with self.assertRaises(ipc.IpcError): runtime.binding(process)
        ready=ipc.encode_frame(ipc.envelope(SESSION,0,"ready",None,{"role":"authority_worker"}))
        pipe=api.obj(stream.handle)["pipe"]
        pipe["raw"].extend(packet(stream,ready)+packet(stream,terminal=True,ordinal=1))
        self.assertEqual(runtime.read_reply(stream,ipc.MAX_CHUNK,deadline),ready)
        self.assertIsNone(runtime.read_reply(stream,ipc.MAX_CHUNK,deadline))
        with self.assertRaises(ipc.IpcError): runtime.binding(process)
        pipe["eof"]=True
        self.assertEqual(runtime.read_reply(stream,ipc.MAX_CHUNK,deadline),b"")
        with self.assertRaises(ipc.IpcError): runtime.binding(process)
        runtime.close_reply_stream(stream,binding)
        self.assertEqual(runtime.lifecycle,rt.Lifecycle.READY)
        self.assertEqual(runtime.binding(process).pid,90)
        runtime.close_channel(runtime.channel); runtime.terminate(process,identity)
        self.assertTrue(runtime.join(process,identity,deadline))
        runtime.close_process(process,identity); img.close()

    def test_forged_or_wrong_ready_never_publishes_binding(self):
        for mutation in ("eof_flag","kind","role","sequence"):
            api,img,runtime,worker=setup(); api.hang=True
            process=runtime.launch_suspended(img,SESSION).process
            identity=runtime.identity(process); deadline=api.clock+250_000_000
            binding=ipc.ReplyBinding(identity,SESSION,0,None,None)
            stream=runtime.open_reply_stream(runtime.channel,binding,deadline); runtime.resume(process)
            if mutation=="eof_flag":
                with self.assertRaises((AttributeError,TypeError)): stream.eof=True
            else:
                ready=ipc.envelope(SESSION,0,"ready",None,{"role":"authority_worker"})
                if mutation=="kind": ready["kind"]="quiescent"
                elif mutation=="role": ready["body"]["role"]="frida_worker"
                else: ready["seq"]=1
                pipe=api.obj(stream.handle)["pipe"]
                pipe["raw"].extend(packet(stream,ipc.encode_frame(ready))+packet(stream,terminal=True,ordinal=1))
                pipe["eof"]=True
                runtime.read_reply(stream,ipc.MAX_CHUNK,deadline)
                with self.assertRaises(ipc.IpcError): runtime.read_reply(stream,ipc.MAX_CHUNK,deadline)
            with self.assertRaises(ipc.IpcError): runtime.binding(process)
            runtime.close_reply_stream(stream,binding); runtime.close_channel(runtime.channel)
            runtime.terminate(process,identity); self.assertTrue(runtime.join(process,identity,deadline))
            runtime.close_process(process,identity); img.close()

    def test_dead_accounted_worker_and_mid_check_exit_cannot_bind(self):
        for during in (False,True):
            api,img,runtime,worker=setup(); worker.start(api.clock+250_000_000)
            process=runtime.process; actual_job=api.job_state
            api.job_state=lambda job:((0x2008,1),(process.native[0],))
            if during:
                api.hooks["read_all"]=lambda a:a.obj(process.handle).update(alive=False)
            else: api.obj(process.handle)["alive"]=False
            with self.assertRaises(ipc.IpcError): runtime.binding(process)
            api.hooks.pop("read_all",None); api.job_state=actual_job
            worker.fail_stop_and_quiesce(250); img.close()

    def test_poisoned_launch_public_methods_cannot_consume_obligations(self):
        api,img,runtime,worker=setup(); api.kill_failure=True
        api.hooks["assigned_job"]=lambda a:(_ for _ in ()).throw(OSError("post-assignment fault"))
        with self.assertRaises(ipc.WorkerQuiescenceError): runtime.launch_suspended(img,SESSION)
        self.assertEqual(runtime.lifecycle,rt.Lifecycle.POISONED)
        process,channel=runtime.process,runtime.channel
        expected=ipc.ProcessIdentity(90,9000,img.executable.sha256,img._bootstrap_sha,img.role)
        actions=(lambda:runtime.close_channel(channel),lambda:runtime.close_process(process,expected),
            lambda:runtime.terminate(process,expected),lambda:runtime.join(process,expected,runtime.launch_deadline_ns),
            lambda:runtime.attest_containment_quiescent(process,()),lambda:runtime.binding(process),
            lambda:runtime.identity(process),lambda:runtime.resume(process),lambda:runtime.sleep_ns(1),
            lambda:runtime.read_reply(None,1,runtime.launch_deadline_ns))
        obligations=tuple(runtime._launch_obligations)
        for action in actions:
            before=list(api.events)
            with self.assertRaises(ipc.IpcError): action()
            self.assertEqual(api.events,before)
            self.assertEqual(tuple(runtime._launch_obligations),obligations)
            self.assertEqual(runtime.lifecycle,rt.Lifecycle.POISONED)
        before=list(api.events)
        self.assertEqual(runtime.diagnostic_output(process,100),b"")
        self.assertEqual(api.events,before)
        api.hooks.clear(); api.kill_failure=False
        runtime.abort_failed_launch(runtime.launch_deadline_ns)
        self.assertEqual(runtime.lifecycle,rt.Lifecycle.CLOSED)
        self.assertEqual(api._pipes,{})
        before=list(api.events)
        with self.assertRaises(ipc.IpcError): runtime.abort_failed_launch(runtime.launch_deadline_ns)
        self.assertEqual(api.events,before); img.close()

    def test_exact_abort_partial_retry_and_identity_loss_seal(self):
        api,img,runtime,worker=setup()
        api.identity_override=(90,9000,r"C:\other\python.exe")
        api.hooks["close_pipe"]=lambda a:(_ for _ in ()).throw(OSError("close boundary"))
        with self.assertRaises(ipc.WorkerQuiescenceError): runtime.launch_suspended(img,SESSION)
        self.assertEqual(api.events.count("terminate_process"),1)
        self.assertTrue(api.handles[api.worker]["closed"])
        with self.assertRaises(ipc.IpcError): img.close()
        with self.assertRaises(ipc.IpcError): runtime.abort_failed_launch(runtime.launch_deadline_ns-1)
        api.hooks.clear(); runtime.abort_failed_launch(runtime.launch_deadline_ns)
        self.assertEqual(api.events.count("terminate_process"),1); self.assertEqual(api._pipes,{})
        img.close()
        api,img,runtime,worker=setup(); api.kill_failure=True
        api.identity_override=(90,9000,r"C:\other\python.exe")
        with self.assertRaises(ipc.WorkerQuiescenceError): runtime.launch_suspended(img,SESSION)
        original=api.obj(api.worker)["native"]; api.obj(api.worker)["native"]=(90,9001,original[2])
        with self.assertRaises(ipc.IpcError): runtime.abort_failed_launch(runtime.launch_deadline_ns)
        api.obj(api.worker)["native"]=original; api.kill_failure=False
        before=list(api.events)
        with self.assertRaises(ipc.IpcError): runtime.abort_failed_launch(runtime.launch_deadline_ns)
        self.assertEqual(api.events,before)

    def test_failed_launch_retained_handle_views_cannot_be_substituted(self):
        api,img,runtime,worker=setup(); api.kill_failure=True
        api.identity_override=(90,9000,r"C:\other\python.exe")
        with self.assertRaises(ipc.WorkerQuiescenceError): runtime.launch_suspended(img,SESSION)
        for name,value in (("_failed_process",1234),("_failed_identity",(1,2,"another")),
                ("_failed_job",1235),("_launch_obligations",()),("_launch_uncertain",False)):
            before=list(api.events)
            with self.subTest(name=name),self.assertRaises(AttributeError): setattr(runtime,name,value)
            self.assertEqual(api.events,before)
        obligations=runtime._launch_obligations
        self.assertIs(type(obligations),tuple)
        with self.assertRaises(AttributeError): obligations.pop()
        api.kill_failure=False; runtime.abort_failed_launch(runtime.launch_deadline_ns)
        self.assertEqual(runtime.lifecycle,rt.Lifecycle.CLOSED); img.close()

    def test_manifest_delimiters_and_factory_mapping_are_closed(self):
        for delimiter in ("\t","\n","\r"):
            with self.assertRaises((ipc.IpcError,ValueError,AuthorityError)):
                rt.SourcePin(ROOT+"\\line"+delimiter+"name.py","a"*64,"probe","source")
        with self.assertRaises(TypeError): rt.FACTORIES["authority_worker"]="frida_worker-v1"

    def test_backend_cannot_expand_captured_operation_registry(self):
        for rebind in (False,True):
            api,img,runtime,worker=setup(); original=entry.ROLE_OPERATIONS
            def opening(descriptor,native):
                expanded={"authority_worker-v1":("authority_worker",frozenset({"authority_capture","general_operation"}))}
                if rebind: entry.ROLE_OPERATIONS=expanded
                else:
                    with self.assertRaises(TypeError): entry.ROLE_OPERATIONS["authority_worker-v1"]=expanded["authority_worker-v1"]
                return api.open_backend(descriptor,native)
            api.backend=replace(api.backend,open=opening)
            try:
                worker.start(api.clock+250_000_000)
                self.assertEqual(api.entry.allowed_operations,frozenset({"authority_admission","authority_capture"}))
                with self.assertRaises(ipc.IpcError):
                    worker.register_operation("probe","general_operation",{},api.clock+25_000_000)
                self.assertFalse(api.engine.calls)
                worker.fail_stop_and_quiesce(250); img.close()
            finally: entry.ROLE_OPERATIONS=original
        api,img,runtime,worker=setup(); worker.start(api.clock+250_000_000)
        with self.assertRaises(AttributeError): api.entry.allowed_operations=frozenset({"general_operation"})
        with self.assertRaises(AttributeError): api.entry.registry=object()
        api.entry.registry.allowed=frozenset({"general_operation"})
        with self.assertRaises(ipc.IpcError): worker.register_operation("probe","general_operation",{},api.clock+25_000_000)
        self.assertFalse(api.engine.calls); worker.fail_stop_and_quiesce(250); img.close()

class SecondBatchRegressions(unittest.TestCase):
    def suspended(self):
        api,img,runtime,worker=setup(); runtime.launch_suspended(img,SESSION)
        process=runtime.process; identity=runtime.identity(process)
        binding=ipc.ReplyBinding(identity,SESSION,0,None,None)
        stream=runtime.open_reply_stream(runtime.channel,binding,api.clock+25_000_000)
        return api,img,runtime,process,identity,stream
    def dispose(self,api,img,runtime,process,identity):
        if runtime.reply is not None: runtime.close_reply_stream(runtime.reply,runtime.reply.binding)
        runtime.close_channel(runtime.channel); runtime.terminate(process,identity)
        self.assertTrue(runtime.join(process,identity,api.clock+250_000_000))
        runtime.close_process(process,identity); img.close()
    def test_tight_deadline_cannot_be_restored_or_rebased(self):
        api,img,runtime,process,identity,stream=self.suspended()
        tight=process.deadline_ns
        with self.assertRaises(AttributeError): process.deadline_ns=runtime.launch_deadline_ns
        with self.assertRaises(ipc.IpcError): runtime._tighten_process_deadline(process,tight+1)
        api.clock=tight+1
        with self.assertRaises(ipc.IpcError): runtime.resume(process)
        self.assertNotIn("resume_thread",api.events)
        self.dispose(api,img,runtime,process,identity)
    def test_deadline_record_replacement_and_in_place_tamper_rejected(self):
        for mutation in ("replace","value"):
            with self.subTest(mutation=mutation):
                api,img,runtime,process,identity,stream=self.suspended()
                original=process._state.deadline
                if mutation=="replace": process._state.deadline=replace(original,absolute_ns=runtime.launch_deadline_ns)
                else: object.__setattr__(original,"absolute_ns",runtime.launch_deadline_ns)
                before=list(api.events)
                with self.assertRaises(ipc.IpcError): runtime.resume(process)
                self.assertEqual(api.events,before)
                if mutation=="replace": process._state.deadline=original
                else: object.__setattr__(original,"absolute_ns",api.clock+25_000_000)
                self.dispose(api,img,runtime,process,identity)
    def test_registered_endpoint_substitution_never_attests(self):
        for target in ("channel","reply"):
            with self.subTest(target=target):
                api,img,runtime,process,identity,stream=self.suspended()
                other,child=api.pipe_pair(parent_reads=True)
                victim=runtime.channel if target=="channel" else stream; original=victim.handle
                with self.assertRaises(AttributeError): victim.handle=other
                object.__setattr__(victim,"handle",other)
                before=list(api.events)
                with self.assertRaises(ipc.IpcError):
                    if target=="channel": runtime.attest_private_channel(victim,identity)
                    else: runtime.attest_reply_stream(victim,victim.binding)
                self.assertEqual(api.events,before)
                object.__setattr__(victim,"handle",original)
                api.close_pipe(other); api.close(child)
                self.dispose(api,img,runtime,process,identity)
    def test_fixed_reply_and_channel_fields_detach_and_revalidate(self):
        for name,value in (("nonce","f"*64),("remote_writer",11001),("binding_raw",b"{}"),("channel",None)):
            api,img,runtime,process,identity,stream=self.suspended(); binding=stream.binding
            with self.assertRaises(AttributeError): setattr(stream,name,value)
            old=getattr(stream,name); object.__setattr__(stream,name,value)
            with self.assertRaises(ipc.IpcError): runtime.attest_reply_stream(stream,binding)
            object.__setattr__(stream,name,old)
            self.dispose(api,img,runtime,process,identity)
        api,img,runtime,process,identity,stream=self.suspended()
        binding=stream.binding; object.__setattr__(binding.worker,"pid",1234)
        self.assertEqual(stream.binding.worker.pid,identity.pid)
        self.dispose(api,img,runtime,process,identity)
    def test_process_close_retries_every_handle_boundary_and_numeric_reuse(self):
        for name in ("thread","parent_handle","job","handle"):
            with self.subTest(name=name):
                api,img,runtime,worker=setup(); worker.start(api.clock+250_000_000)
                process=runtime.process; identity=runtime.identity(process)
                runtime.close_channel(runtime.channel); runtime.terminate(process,identity)
                self.assertTrue(runtime.join(process,identity,api.clock+250_000_000))
                original_close=api.close; target=getattr(process,name); attempts=[]
                def close(handle):
                    attempts.append(handle)
                    if handle==target: raise OSError("retained handle close failed")
                    original_close(handle)
                api.close=close
                with self.assertRaises(OSError): runtime.close_process(process,identity)
                self.assertFalse(process.closed); self.assertNotEqual(runtime.lifecycle,rt.Lifecycle.CLOSED)
                self.assertFalse(api.handles[target]["closed"])
                for prior in ("thread","parent_handle","job","handle"):
                    if prior==name: break
                    reused=getattr(process,prior)
                    api.handles[reused]=dict(kind="unrelated",closed=False)
                api.close=original_close
                runtime.close_process(process,identity)
                for prior in ("thread","parent_handle","job","handle"):
                    if prior==name: break
                    self.assertFalse(api.handles[getattr(process,prior)]["closed"])
                with self.assertRaises(ipc.IpcError): runtime.close_process(process,identity)
                img.close()
    def test_partial_process_close_receipt_blocks_reused_job_termination(self):
        api,img,runtime,worker=setup(); worker.start(api.clock+250_000_000)
        process=runtime.process; identity=runtime.identity(process)
        runtime.close_channel(runtime.channel); runtime.terminate(process,identity)
        self.assertTrue(runtime.join(process,identity,api.clock+250_000_000))
        original_close=api.close
        api.close=lambda h:(_ for _ in ()).throw(OSError("leave process handle open")) \
            if h==process.handle else original_close(h)
        with self.assertRaises(OSError): runtime.close_process(process,identity)
        self.assertEqual(set(runtime._WindowsWorkerRuntime__close_receipts),
                         {"thread","parent_handle","job"})
        unrelated=api.alloc("process",native=(777,8888,r"C:\unrelated\service.exe"),alive=True,job=None)
        api.handles[process.job]=dict(kind="job",closed=False,limits=(0x2008,1),process=unrelated,extra=[])
        api.close=original_close; before=api.events.count("terminate_job")
        runtime.terminate(process,identity)
        self.assertEqual(api.events.count("terminate_job"),before)
        self.assertTrue(api.obj(unrelated)["alive"])
        self.assertFalse(process.closed); self.assertEqual(runtime.lifecycle,rt.Lifecycle.SEALED)
        runtime.close_process(process,identity)
        api.terminate_process(unrelated); api.close(unrelated); api.close(process.job); img.close()
    def test_partial_process_close_receipt_blocks_reused_thread_query(self):
        api,img,runtime,worker=setup(); runtime.launch_suspended(img,SESSION)
        process=runtime.process; identity=runtime.identity(process)
        runtime.close_channel(runtime.channel); runtime.terminate(process,identity)
        self.assertTrue(runtime.join(process,identity,api.clock+250_000_000))
        original_close=api.close
        api.close=lambda h:(_ for _ in ()).throw(OSError("leave process handle open")) \
            if h==process.handle else original_close(h)
        with self.assertRaises(OSError): runtime.close_process(process,identity)
        self.assertIn("thread",runtime._WindowsWorkerRuntime__close_receipts)
        api.handles[process.thread]=dict(kind="thread",closed=False,count=1)
        original_query=api.thread_suspended; queries=[]
        api.thread_suspended=lambda h:(queries.append(h),original_query(h))[1]
        api.close=original_close
        self.assertFalse(runtime.is_suspended(process))
        self.assertEqual(queries,[])
        self.assertFalse(process.closed); self.assertEqual(runtime.lifecycle,rt.Lifecycle.SEALED)
        api.thread_suspended=original_query; runtime.close_process(process,identity)
        api.close(process.thread); img.close()
    def test_quiescent_attestation_rejects_foreign_process_before_liveness_query(self):
        api,img,runtime,worker=setup(); worker.start(api.clock+250_000_000)
        process=runtime.process; identity=runtime.identity(process)
        runtime.close_channel(runtime.channel); runtime.terminate(process,identity)
        self.assertTrue(runtime.join(process,identity,api.clock+250_000_000))
        original_close=api.close
        api.close=lambda h:(_ for _ in ()).throw(OSError("leave parent handle open")) \
            if h==process.parent_handle else original_close(h)
        with self.assertRaises(OSError): runtime.close_process(process,identity)
        self.assertEqual(set(runtime._WindowsWorkerRuntime__close_receipts),{"thread"})
        reused=process.thread
        api.handles[reused]=dict(kind="process",closed=False,
            native=(888,9999,r"C:\unrelated\query.exe"),alive=True,job=None)

        foreign_api,foreign_img,foreign_runtime,foreign_worker=setup()
        padding=foreign_api.alloc("padding")
        foreign_worker.start(foreign_api.clock+250_000_000)
        foreign=foreign_runtime.process
        self.assertEqual(foreign.handle,reused)
        before=list(api.events)
        with self.assertRaisesRegex(ipc.IpcError,"stale/foreign process"):
            runtime.attest_containment_quiescent(foreign,())
        self.assertEqual(api.events,before)
        self.assertTrue(api.obj(reused)["alive"])
        self.assertFalse(process.closed); self.assertEqual(runtime.lifecycle,rt.Lifecycle.SEALED)

        api.close=original_close; runtime.close_process(process,identity)
        self.assertFalse(api.handles[reused]["closed"])
        api.terminate_process(reused); api.close(reused); img.close()
        foreign_worker.fail_stop_and_quiesce(250); foreign_worker.assert_quiescent()
        foreign_img.close(); foreign_api.close(padding)
    def test_process_close_receipt_does_not_mask_other_handle_substitution(self):
        api,img,runtime,worker=setup(); worker.start(api.clock+250_000_000)
        process=runtime.process; identity=runtime.identity(process)
        runtime.close_channel(runtime.channel); runtime.terminate(process,identity)
        runtime.join(process,identity,api.clock+250_000_000)
        original_close=api.close
        api.close=lambda h:(_ for _ in ()).throw(OSError("stop")) if h==process.parent_handle else original_close(h)
        with self.assertRaises(OSError): runtime.close_process(process,identity)
        old=process.job; unrelated=api.alloc("job",limits=(0x2008,1),process=None,extra=[])
        object.__setattr__(process,"job",unrelated)
        with self.assertRaises(ipc.IpcError): runtime.close_process(process,identity)
        self.assertFalse(api.obj(unrelated)["closed"])
        object.__setattr__(process,"job",old); api.close=original_close
        runtime.close_process(process,identity); api.close(unrelated); img.close()
    def test_constructor_fault_matrix_retains_every_unclosed_generation(self):
        cases=("manifest_write","manifest_flush","manifest_readback","manifest_seal",
               "pipe_parent","pipe_child","pipe_connect","job_policy")
        for boundary in cases:
            with self.subTest(boundary=boundary):
                api=FakeApi(); api.hooks[boundary]=lambda a:(_ for _ in ()).throw(OSError("injected boundary"))
                api.hooks["close"]=lambda a:(_ for _ in ()).throw(OSError("persistent cleanup failure"))
                call=(lambda:api.create_sealed_file(r"C:\new\manifest",b"data")) if boundary.startswith("manifest") else (
                     (lambda:api.pipe_pair(parent_reads=True)) if boundary.startswith("pipe") else api.create_job)
                with self.assertRaises(ipc.WorkerQuiescenceError): call()
                live={h for h,v in api.handles.items() if not v["closed"]}
                tokens=api.acquisition_obligations
                self.assertEqual(live,{t.handle for t in tokens}); self.assertTrue(tokens)
                with self.assertRaises(ipc.IpcError): api.assert_acquisitions_clear()
                with self.assertRaises(ipc.IpcError): api.close(tokens[0].handle)
                with self.assertRaises(ipc.IpcError): api.create_job()
                with self.assertRaises(ipc.IpcError): api.recover_acquisitions(api.clock+1000,lambda:api.clock)
                self.assertEqual(tokens,api.acquisition_obligations)
                api.hooks.clear(); api.recover_acquisitions(api.clock+1000,lambda:api.clock)
                api.assert_acquisitions_clear()
                self.assertFalse(any(not v["closed"] for v in api.handles.values()))
                reused=tokens[0].handle; api.handles[reused]=dict(kind="unrelated",closed=False)
                with self.assertRaises(ipc.IpcError): api._close_acquisition(tokens[0])
                with self.assertRaises(ipc.IpcError): api.recover_acquisitions(api.clock+1000,lambda:api.clock)
                self.assertFalse(api.handles[reused]["closed"])
    def test_seal_original_close_failure_tracks_original_and_duplicate(self):
        api=FakeApi(); api.hooks["close"]=lambda a:(_ for _ in ()).throw(OSError("all closes fail"))
        with self.assertRaises(ipc.WorkerQuiescenceError): api.create_sealed_file(r"C:\new\manifest",b"data")
        self.assertEqual(len(api.acquisition_obligations),2)
        self.assertEqual({t.handle for t in api.acquisition_obligations},set(api.handles))
        api.hooks.clear(); api.recover_acquisitions(api.clock+1000,lambda:api.clock)
    def test_cleanup_attempts_sibling_after_first_close_failure(self):
        api=FakeApi(); api.hooks["pipe_connect"]=lambda a:(_ for _ in ()).throw(OSError("connect failed"))
        calls=[]
        def close(a):
            calls.append(1)
            if len(calls)==1: raise OSError("child close failed")
        api.hooks["close"]=close
        with self.assertRaises(ipc.WorkerQuiescenceError): api.pipe_pair(parent_reads=True)
        self.assertEqual(len(calls),2); self.assertEqual(len(api.acquisition_obligations),1)
        api.hooks.clear(); api.recover_acquisitions(api.clock+1000,lambda:api.clock)
    def test_reply_setup_repeated_child_close_failure_retains_all_locals(self):
        api,img,runtime,worker=setup(); runtime.launch_suspended(img,SESSION)
        process=runtime.process; identity=runtime.identity(process)
        binding=ipc.ReplyBinding(identity,SESSION,0,None,None)
        api.hooks["close"]=lambda a:(_ for _ in ()).throw(OSError("writer close failed"))
        with self.assertRaises(ipc.IpcError): runtime.open_reply_stream(runtime.channel,binding,api.clock+25_000_000)
        self.assertIsNotNone(runtime.reply)
        with self.assertRaises(AttributeError): getattr(runtime.reply,"published")
        self.assertEqual(len(runtime._WindowsWorkerRuntime__reply_setup_obligations),1)
        with self.assertRaises(ipc.IpcError): runtime.binding(process)
        with self.assertRaises(ipc.IpcError): runtime.close_channel(runtime.channel)
        api.hooks.clear(); self.dispose(api,img,runtime,process,identity)
        self.assertFalse(any(not v["closed"] for v in api.handles.values()))
    def test_failed_acquisition_launch_requires_original_deadline_and_recovery(self):
        api,img,runtime,worker=setup()
        api.hooks["job_policy"]=lambda a:(_ for _ in ()).throw(OSError("policy fail"))
        api.hooks["close"]=lambda a:(_ for _ in ()).throw(OSError("persistent close failure"))
        with self.assertRaises(ipc.WorkerQuiescenceError): runtime.launch_suspended(img,SESSION)
        self.assertEqual(runtime.lifecycle,rt.Lifecycle.POISONED)
        with self.assertRaises(ipc.IpcError): api.recover_acquisitions(runtime.launch_deadline_ns+1,lambda:api.clock,owner=runtime)
        with self.assertRaises(ipc.IpcError): api.recover_acquisitions(runtime.launch_deadline_ns,lambda:api.clock,owner=object())
        api.hooks.clear(); runtime.abort_failed_launch(runtime.launch_deadline_ns)
        api.assert_acquisitions_clear(); img.close()
        self.assertFalse(any(not v["closed"] for v in api.handles.values()))
    def test_unpublished_created_process_failure_retains_until_exact_kill_join(self):
        api,img,runtime,worker=setup(); api.kill_failure=True
        api.hooks["created_suspended"]=lambda a:(_ for _ in ()).throw(OSError("post-create publication failed"))
        with self.assertRaises(ipc.WorkerQuiescenceError): runtime.launch_suspended(img,SESSION)
        self.assertTrue(api.obj(api.worker)["alive"]); self.assertEqual(runtime.lifecycle,rt.Lifecycle.POISONED)
        self.assertTrue(any(t.kind is rt._HandleKind.PROCESS for t in api.acquisition_obligations))
        api.hooks.clear(); api.kill_failure=False; runtime.abort_failed_launch(runtime.launch_deadline_ns)
        self.assertFalse(api.handles[api.worker]["alive"]); img.close()
    def test_image_info_then_close_failure_keeps_all_acquisitions(self):
        for boundary in ("info","read_all"):
            api=FakeApi(); api.hooks[boundary]=lambda a:(_ for _ in ()).throw(OSError("image admission failure"))
            api.hooks["close"]=lambda a:(_ for _ in ()).throw(OSError("image close failure"))
            with self.assertRaises(OSError): image(api)
            self.assertEqual(set(api.handles),{t.handle for t in api.acquisition_obligations})
            api.hooks.clear(); api.recover_acquisitions(api.clock+1000,lambda:api.clock)

class ThirdBatchStateAuthorityRegressions(unittest.TestCase):
    def dispose(self,api,img,runtime,process,identity):
        if runtime.reply is not None: runtime.close_reply_stream(runtime.reply,runtime.reply.binding)
        state=runtime._WindowsWorkerRuntime__channel_state
        if state is not None and state.phase is not rt._ChannelPhase.CLOSED:
            runtime.close_channel(runtime.channel)
        if runtime.alive(process): runtime.terminate(process,identity)
        self.assertTrue(runtime.join(process,identity,api.clock+250_000_000))
        runtime.close_process(process,identity); img.close()
    def test_forged_channel_closed_state_cannot_claim_quiescence_or_hide_live_pipe(self):
        api,img,runtime,worker=setup(); worker.start(api.clock+250_000_000)
        process,channel=runtime.process,runtime.channel; identity=runtime.identity(process)
        with self.assertRaises((AttributeError,TypeError)):
            object.__setattr__(channel,"closed",True)
        runtime.terminate(process,identity)
        self.assertTrue(runtime.join(process,identity,api.clock+250_000_000))
        state=runtime._WindowsWorkerRuntime__channel_state
        object.__setattr__(state,"phase",rt._ChannelPhase.CLOSED)
        before=api.events.count("close_pipe")
        with self.assertRaises(ipc.IpcError):
            runtime.attest_containment_quiescent(process,())
        self.assertEqual(api.events.count("close_pipe"),before)
        self.assertIs(api._pipes.get(channel.handle.value),channel.handle)
        self.assertFalse(api.handles[channel.handle.value]["closed"])
        object.__setattr__(state,"phase",rt._ChannelPhase.LIVE)
        runtime.close_channel(channel)
        receipt=runtime._WindowsWorkerRuntime__channel_state.close_receipt
        generation=receipt.generation; object.__setattr__(receipt,"generation",object())
        with self.assertRaises(ipc.IpcError):
            runtime.attest_containment_quiescent(process,())
        object.__setattr__(receipt,"generation",generation)
        runtime.attest_containment_quiescent(process,())
        runtime.close_process(process,identity); img.close()
    def test_reply_has_no_injectable_raw_or_ready_buffers_and_private_mutation_seals(self):
        api,img,runtime,worker=setup(); worker.start(api.clock+250_000_000)
        process,identity=runtime.process,runtime.identity(runtime.process)
        binding=ipc.ReplyBinding(identity,SESSION,1,"probe",None)
        stream=runtime.open_reply_stream(runtime.channel,binding,api.clock+25_000_000)
        for name,value in (("raw",bytearray(b"forged")),("ready_raw",b"forged"),
                           ("terminal",True),("eof",True)):
            with self.subTest(name=name),self.assertRaises((AttributeError,TypeError)):
                object.__setattr__(stream,name,value)
        state=runtime._WindowsWorkerRuntime__reply_state
        object.__setattr__(state,"pending",b"forged")
        before=api.events.count("read_pipe")
        with self.assertRaises(ipc.IpcError):
            runtime.read_reply(stream,ipc.MAX_CHUNK,api.clock+25_000_000)
        self.assertEqual(api.events.count("read_pipe"),before)
        object.__setattr__(state,"pending",b"")
        self.assertEqual(runtime.lifecycle,rt.Lifecycle.SEALED)
        self.dispose(api,img,runtime,process,identity)
    def test_zero_packet_eof_cannot_forge_initial_ready_or_binding(self):
        api,img,runtime,worker=setup(); api.hang=True
        process=runtime.launch_suspended(img,SESSION).process
        identity=runtime.identity(process); deadline=api.clock+250_000_000
        binding=ipc.ReplyBinding(identity,SESSION,0,None,None)
        stream=runtime.open_reply_stream(runtime.channel,binding,deadline)
        runtime.resume(process)
        api.obj(stream.handle)["pipe"]["eof"]=True
        with self.assertRaisesRegex(ipc.IpcError,"authenticated terminal"):
            runtime.read_reply(stream,ipc.MAX_CHUNK,deadline)
        with self.assertRaises(ipc.IpcError): runtime.binding(process)
        self.assertIsNone(runtime._WindowsWorkerRuntime__ready_authenticated)
        self.dispose(api,img,runtime,process,identity)
    def test_legacy_image_aliases_cannot_hide_five_live_handles_or_trigger_reclose(self):
        api=FakeApi(); img=image(api)
        original=tuple(h for h,v in api.handles.items() if not v["closed"])
        self.assertEqual(len(original),5)
        img._closed=True; img._held=[]; img._directories={}
        img.close(); self.assertTrue(img.closed)
        self.assertTrue(all(api.handles[h]["closed"] for h in original))
        reused=original[-1]; api.handles[reused]=dict(kind="unrelated",closed=False)
        img.close()
        self.assertFalse(api.handles[reused]["closed"])
        api.close(reused)
    def test_image_partial_close_receipts_skip_reused_handle_on_retry(self):
        api=FakeApi(); img=image(api); calls=[]
        def fail_second(a):
            calls.append(len(calls)+1)
            if len(calls)==2: raise OSError("second image handle close failed")
        api.hooks["close"]=fail_second
        with self.assertRaises(OSError): img.close()
        closed=tuple(h for h,v in api.handles.items() if v["closed"])
        self.assertEqual(len(closed),1); self.assertFalse(img.closed)
        reused=closed[0]; api.handles[reused]=dict(kind="unrelated",closed=False)
        api.hooks.clear(); img.close(); self.assertTrue(img.closed)
        self.assertFalse(api.handles[reused]["closed"])
        api.close(reused)
    def test_image_close_reentry_cannot_double_close_or_discard_obligations(self):
        api=FakeApi(); img=image(api)
        original=tuple(h for h,v in api.handles.items() if not v["closed"])
        api.hooks["close"]=lambda a:img.close()
        with self.assertRaisesRegex(ipc.IpcError,"reentry"):
            img.close()
        self.assertTrue(all(not api.handles[h]["closed"] for h in original))
        self.assertFalse(img.closed)
        api.hooks.clear(); img.close(); self.assertTrue(img.closed)
        self.assertTrue(all(api.handles[h]["closed"] for h in original))

class NativeAcquisitionBoundaryRegressions(unittest.TestCase):
    """Invoke production constructor methods with only Win32 calls replaced."""
    def shim(self):
        api=object.__new__(rt.Win32); api._init_acquisitions()
        api._pipe_lock=threading.RLock(); api._Win32__pipe_owner=object()
        api._Win32__pipe_receipt_authority=object(); api._Win32__closed_pipes={}; api._Win32__closed_pipe_values={}
        api._pipes,api._pending,api._process_images={},{},{}
        heap,events,fail={},[],set()
        def point(name):
            events.append(name)
            if name in fail: raise OSError(name)
        def alloc(kind):
            handle=100+len(heap); heap[handle]=dict(kind=kind,closed=False); return handle
        @contextmanager
        def attributes():
            class Attr(ctypes.Structure): _fields_=[("inherit",ctypes.c_bool)]
            value=Attr(False); yield ctypes.byref(value); point("attributes_free")
        api._attributes=attributes; api._process=lambda:-1
        api._job_new=lambda *args:alloc("job")
        api._job_set=lambda *args:point("job_policy") or True
        api._pipe=lambda *args:alloc("parent")
        api._create=lambda *args:alloc("child")
        api._connect=lambda *args:point("connect") or True
        api.open_file=lambda *args,**kw:alloc("original")
        api.write=lambda handle,raw:point("write") or len(raw)
        api.flush=lambda handle:point("flush")
        api.read_all=lambda *args:point("readback") or b"data"
        def duplicate(source,handle,target,out,access,inherit,flags):
            ctypes.cast(out,ctypes.POINTER(rt.w.HANDLE))[0]=alloc("duplicate")
            return True
        api._dup=duplicate
        def close(self,handle):
            events.append("close:"+heap[handle]["kind"])
            if "close" in fail or "close:"+heap[handle]["kind"] in fail: raise OSError("close failure")
            if heap[handle]["closed"]: raise AssertionError("double close")
            heap[handle]["closed"]=True
        return api,heap,events,fail,close
    def test_production_file_job_pipe_constructor_boundary_matrix(self):
        cases=(("file","write"),("file","flush"),("file","readback"),("file","close:original"),
               ("job","job_policy"),("job","attributes_free"),("pipe","connect"),("pipe","attributes_free"))
        for kind,boundary in cases:
            with self.subTest(kind=kind,boundary=boundary):
                api,heap,events,fail,close=self.shim(); fail.update({boundary,"close"})
                with patch.object(rt.FileWin32,"close",close):
                    with self.assertRaises(ipc.WorkerQuiescenceError):
                        if kind=="file": api.create_sealed_file(r"C:\private\manifest",b"data")
                        elif kind=="job": api.create_job()
                        else: api.pipe_pair(parent_reads=True)
                    self.assertEqual({t.handle for t in api.acquisition_obligations},
                                     {h for h,row in heap.items() if not row["closed"]})
                    self.assertTrue(api.acquisition_obligations)
                    if boundary=="close:original": self.assertEqual(len(api.acquisition_obligations),2)
                    if boundary=="connect":
                        self.assertIn("close:parent",events); self.assertIn("close:child",events)
                    fail.clear(); api.recover_acquisitions(100,lambda:1)
                    self.assertTrue(all(row["closed"] for row in heap.values()))
    def test_native_file_open_attribute_cleanup_failure_keeps_handle(self):
        api,heap,events,fail,close=self.shim(); fail.update({"attributes_free","close"})
        with patch.object(rt.FileWin32,"close",close):
            with self.assertRaises(ipc.WorkerQuiescenceError): api._open(r"C:\private\file",1,1,3,0)
            self.assertEqual(len(api.acquisition_obligations),1)
            fail.clear(); api.recover_acquisitions(100,lambda:1)
    def test_native_spawn_post_create_failure_retains_creation_authority(self):
        for drift in (False,True):
            with self.subTest(drift=drift):
                api,heap,events,fail,close=self.shim(); owner=object(); kill_fails=[True]
                api.bind_acquisition_deadline(owner,100,lambda:1)
                def attr_init(attributes,count,flags,size):
                    ctypes.cast(size,ctypes.POINTER(ctypes.c_size_t))[0]=64; return attributes is not None
                api._attr_init=attr_init; api._attr_set=lambda *args:True
                api._attr_free=lambda *args:(_ for _ in ()).throw(OSError("attribute cleanup after spawn"))
                class PI(ctypes.Structure):
                    _fields_=[("process",rt.w.HANDLE),("thread",rt.w.HANDLE),("pid",rt.w.DWORD),("tid",rt.w.DWORD)]
                native=(500,6000,r"C:\exact\python.exe")
                def spawn(*args):
                    result=ctypes.cast(args[-1],ctypes.POINTER(PI)).contents
                    result.process=100; result.thread=101; result.pid=500; result.tid=501
                    heap[100]=dict(kind="process",closed=False,alive=True,native=native)
                    heap[101]=dict(kind="thread",closed=False)
                    return True
                api._spawn=spawn; api.process_identity=lambda h:heap[h]["native"]
                api.alive=lambda h:heap[h]["alive"]
                def terminate(handle):
                    if kill_fails[0]: raise OSError("retained termination unavailable")
                    heap[handle]["alive"]=False
                api.terminate_process=terminate; api.wait_process=lambda h,d,c:not heap[h]["alive"]
                with patch.object(rt.FileWin32,"close",close):
                    with self.assertRaises(ipc.WorkerQuiescenceError):
                        api.create_suspended(native[2],(native[2],"-I"),{},r"C:\private",(40,))
                    self.assertTrue(heap[100]["alive"]); self.assertTrue(heap[101]["closed"])
                    self.assertEqual(len(api.acquisition_obligations),1)
                    with self.assertRaises(ipc.IpcError): api.recover_acquisitions(101,lambda:1,owner=owner)
                    kill_fails[0]=False
                    if drift:
                        heap[100]["native"]=(500,6001,native[2])
                        with self.assertRaises(ipc.IpcError): api.recover_acquisitions(100,lambda:1,owner=owner)
                        heap[100]["native"]=native
                        with self.assertRaises(ipc.IpcError): api.recover_acquisitions(100,lambda:1,owner=owner)
                        self.assertTrue(heap[100]["alive"]); self.assertFalse(heap[100]["closed"])
                    else:
                        api.recover_acquisitions(100,lambda:1,owner=owner)
                        self.assertFalse(heap[100]["alive"]); self.assertTrue(heap[100]["closed"])
    def test_remote_duplicate_uncertainty_waits_for_exact_process_exit(self):
        api,heap,events,fail,close=self.shim(); native=(50,1234,r"C:\exact\python.exe"); alive=[True]
        api.process_identity=lambda h:native
        api.alive=lambda h:alive[0]
        def duplicate(source,handle,target,out,access,inherit,flags):
            ctypes.cast(out,ctypes.POINTER(rt.w.HANDLE))[0]=999
            return False  # Fault shim models failure after native acquisition.
        api._dup=duplicate
        with patch.object(rt.FileWin32,"close",close):
            with self.assertRaises(ipc.WorkerQuiescenceError): api.transfer_to_child(100,50)
            token=api.acquisition_obligations[0]
            self.assertEqual(token.kind,rt._HandleKind.REMOTE)
            with self.assertRaises(ipc.IpcError): api.recover_acquisitions(100,lambda:1)
            alive[0]=False; api.recover_acquisitions(100,lambda:1)
            self.assertFalse(any(e.startswith("close:") for e in events))
    def test_remote_identity_drift_cannot_be_repaired_by_restoring_values(self):
        api,heap,events,fail,close=self.shim(); native=(50,1234,r"C:\exact\python.exe")
        api.process_identity=lambda h:native; api.alive=lambda h:False
        token=api._track_acquisition(999,rt._HandleKind.REMOTE,(50,native))
        api._AcquisitionBook__acquisition_failed=True
        with patch.object(rt.FileWin32,"close",close):
            api.process_identity=lambda h:(50,1235,native[2])
            with self.assertRaises(ipc.IpcError): api.recover_acquisitions(100,lambda:1)
            api.process_identity=lambda h:native
            with self.assertRaises(ipc.IpcError): api.recover_acquisitions(100,lambda:1)
            self.assertEqual(api.acquisition_obligations,(token,))
            self.assertFalse(any(e.startswith("close:") for e in events))

class TypedPipeRegressions(unittest.TestCase):
    def shim(self):
        api=object.__new__(rt.Win32)
        api._init_acquisitions()
        api._pipe_lock=threading.RLock(); api._Win32__pipe_owner=object()
        api._Win32__pipe_receipt_authority=object(); api._Win32__closed_pipes={}; api._Win32__closed_pipe_values={}
        api._pipes,api._pending,api._process_images={},{},{}
        api._type=lambda handle:3
        endpoint=rt.PipeHandle(77,api._Win32__pipe_owner); api._pipes[77]=endpoint
        return api,endpoint
    def test_io_call_exception_retains_event_and_buffer_until_observed_cancel(self):
        api,endpoint=self.shim(); closed=[]
        api._event=lambda *args:88
        api._write=lambda *args:(_ for _ in ()).throw(OSError("after I/O issuance"))
        api._cancel=lambda *args:True; api._wait=lambda *args:258; api._overlapped=lambda *args:True
        with patch.object(rt.FileWin32,"close",lambda self,h:closed.append(h)):
            with self.assertRaises(OSError): api.write_pipe(endpoint,b"data",100,lambda:1)
            self.assertIs(api._pending[77][0],endpoint)
            self.assertEqual(api._pending[77][2].raw,b"data\0")
            with self.assertRaises(ipc.IpcError): api.close_pipe(endpoint)
            self.assertEqual(closed,[])
            api._wait=lambda *args:0; api.close_pipe(endpoint)
            self.assertEqual(closed,[88,77]); self.assertFalse(api._pending)
    def test_generic_close_and_numeric_reuse_never_attest_stale_endpoint(self):
        api,endpoint=self.shim(); closed=[]
        with patch.object(rt.FileWin32,"close",lambda self,h:closed.append(h)):
            for handle in (endpoint,endpoint.value,rt.w.HANDLE(endpoint.value)):
                with self.assertRaises(ipc.IpcError): api.close(handle)
            self.assertEqual(closed,[])
            api.close_pipe(endpoint); self.assertEqual(closed,[77]); self.assertEqual(api._pipes,{})
            with self.assertRaises(ipc.IpcError): api.attest_pipe(endpoint)
            # Deterministic numeric reuse, unlike a probabilistic OS allocation loop.
            replacement=rt.PipeHandle(77,api._Win32__pipe_owner); api._pipes[77]=replacement
            for stale in (endpoint,77,rt.PipeHandle(77,object())):
                with self.assertRaises(ipc.IpcError): api.attest_pipe(stale)
            api.attest_pipe(replacement); api.close_pipe(replacement)
            other,foreign=self.shim()
            with self.assertRaises(ipc.IpcError): api.attest_pipe(foreign)
            other.close_pipe(foreign)
    def test_pending_io_and_close_failure_retain_exact_obligation(self):
        api,endpoint=self.shim(); closed=[]
        api._pending[77]=(endpoint,rt._Overlapped(),ctypes.create_string_buffer(10),88)
        api._cancel=lambda *args:True; api._wait=lambda *args:258; api._overlapped=lambda *args:True
        with patch.object(rt.FileWin32,"close",lambda self,h:closed.append(h)):
            with self.assertRaises(ipc.IpcError): api.close(77)
            with self.assertRaises(ipc.IpcError): api.close_pipe(endpoint)
            self.assertEqual(closed,[]); self.assertIn(77,api._pending); self.assertIs(api._pipes[77],endpoint)
            api._wait=lambda *args:0
            api.close_pipe(endpoint)
            self.assertEqual(closed,[88,77]); self.assertEqual(api._pending,{}); self.assertEqual(api._pipes,{})
        api,endpoint=self.shim()
        with patch.object(rt.FileWin32,"close",side_effect=OSError("native close failure")):
            with self.assertRaises(OSError): api.close_pipe(endpoint)
        self.assertIs(api._pipes[77],endpoint)
        with patch.object(rt.FileWin32,"close",lambda *args:None): api.close_pipe(endpoint)

@unittest.skipUnless(os.name=="nt" and os.environ.get("S2B_NATIVE_SMOKE")=="1", "explicit scoped native smoke required")
class NativeSmoke(unittest.TestCase):
    def test_real_full_retained_loader_reaches_explicit_backend_blocker(self):
        api=rt.Win32(); base=Path(tempfile.mkdtemp(prefix="native-page-s2b-loader-"))
        self.assertTrue(base.resolve().is_relative_to(Path(tempfile.gettempdir()).resolve()))
        root=base/"python"; root.mkdir()
        original=Path(sys.executable).parent
        copied=[]; created_dirs=[root]; sources=[]
        excluded={"site-packages","__pycache__","test","tests","idlelib","turtledemo","ensurepip"}
        for directory in (original,original/"DLLs",original/"Lib"):
            for current,dirs,files in os.walk(directory):
                dirs[:]=[] if Path(current)==original else [n for n in dirs if n not in excluded]
                for name in files:
                    src=Path(current)/name
                    if src.suffix in (".pyc",".pyo"): continue
                    self.assertFalse(src.lstat().st_file_attributes & 0x400)
                    relative=src.relative_to(original); dst=root/relative
                    missing=[]; parent=dst.parent
                    while not parent.exists(): missing.append(parent); parent=parent.parent
                    for parent in reversed(missing): parent.mkdir(); created_dirs.append(parent)
                    shutil.copyfile(src,dst); copied.append(dst)
                    if name=="python.exe" and src.parent==original: continue
                    module,kind=None,"data"
                    if relative.parts[0]=="Lib" and src.suffix==".py":
                        parts=list(relative.with_suffix("").parts[1:]); kind="source"
                        if parts[-1]=="__init__": parts.pop(); kind="package"
                        candidate=".".join(parts)
                        if rt.MODULE.fullmatch(candidate): module=candidate
                        else: kind="data"
                    elif relative.parts[0]=="DLLs" and src.suffix==".pyd": module,kind=src.stem,"extension"
                    sources.append(rt.SourcePin(str(dst),rt.sha(dst.read_bytes()),module,kind))
        for module in ("native_page_worker_entry","native_page_isolated_ipc"):
            src=Path(__file__).with_name(module+".py"); dst=root/(module+".py")
            shutil.copyfile(src,dst); copied.append(dst)
            sources.append(rt.SourcePin(str(dst),rt.sha(dst.read_bytes()),module,"source"))
        img=runtime=None; launched=False
        try:
            img=rt.WorkerImage("authority_worker",rt.SourcePin(str(root/"python.exe"),rt.sha((root/"python.exe").read_bytes())),
                tuple(sources),runtime_roots=(str(root),),backend_sha256="b"*64,configuration={},api=api)
            runtime=rt.WindowsWorkerRuntime(str(base/"run"),launch_deadline_ns=time.monotonic_ns()+60_000_000_000,
                start_guard=lambda *args:None,api=api)
            launch=runtime.launch_suspended(img,SESSION); launched=True
            identity=runtime.identity(launch.process); deadline=time.monotonic_ns()+30_000_000_000
            self.assertEqual(api.job_state(launch.process.job),((0x2008,1),(identity.pid,)))
            binding=ipc.ReplyBinding(identity,SESSION,0,None,None)
            stream=runtime.open_reply_stream(launch.channel,binding,deadline)
            runtime.resume(launch.process)
            self.assertTrue(api.wait_process(launch.process.handle,deadline,time.monotonic_ns))
            self.assertEqual(api.exit_code(launch.process.handle),entry.EXIT_BACKEND_UNAVAILABLE)
            runtime.close_reply_stream(stream,binding); runtime.close_channel(launch.channel)
            self.assertTrue(runtime.join(launch.process,identity,time.monotonic_ns()+2_000_000_000))
            self.assertEqual(api.job_state(launch.process.job),((0x2008,1),()))
            runtime.attest_containment_quiescent(launch.process,()); runtime.close_process(launch.process,identity)
            launched=False
        finally:
            if launched and runtime.process is not None and not runtime.process.closed:
                if runtime.reply is not None: runtime.close_reply_stream(runtime.reply,runtime.reply.binding)
                if (runtime._WindowsWorkerRuntime__channel_state is not None
                        and runtime._WindowsWorkerRuntime__channel_state.phase is not rt._ChannelPhase.CLOSED):
                    runtime.close_channel(runtime.channel)
                identity=runtime.identity(runtime.process)
                if runtime.alive(runtime.process): runtime.terminate(runtime.process,identity)
                self.assertTrue(runtime.join(runtime.process,identity,time.monotonic_ns()+2_000_000_000))
                runtime.close_process(runtime.process,identity)
            if img is not None: img.close()
            # Delete only exact files created by this test after locks/child are
            # proven closed. Unknown extra entries cause rmdir to fail closed.
            manifest=base/"run"/"bootstrap.manifest"
            if manifest.exists(): manifest.unlink()
            if (base/"run").exists(): (base/"run").rmdir()
            for path in copied: path.unlink()
            for path in sorted(created_dirs,key=lambda p:len(p.parts),reverse=True): path.rmdir()
            base.rmdir()

    def test_real_private_pipe_eof_and_suspended_job_kill_join(self):
        api=rt.Win32()
        spawn=api._spawn
        def capture(*args):
            self.assertEqual(args[5],rt.SPAWN_FLAGS)
            self.assertTrue(args[5]&8); self.assertFalse(args[5]&(0x10|0x08000000))
            # Independent x64 STARTUPINFOEX wire-layout oracle: cb=112,
            # dwFlags offset60 and standard handles offsets80/88/96.
            self.assertEqual(ctypes.sizeof(ctypes.c_void_p),8)
            raw=ctypes.string_at(args[8],112)
            self.assertEqual(int.from_bytes(raw[:4],"little"),112)
            self.assertEqual(int.from_bytes(raw[60:64],"little"),0x101)
            self.assertEqual(raw[80:104],b"\0"*24)
            return spawn(*args)
        api._spawn=capture
        base=Path(tempfile.mkdtemp(prefix="native-page-s2b-smoke-"))
        self.assertTrue(base.resolve().is_relative_to(Path(tempfile.gettempdir()).resolve()))
        cwd=str(base/"private-run")
        api.mkdir(cwd)
        directory=api.open_directory(cwd)
        self.assertTrue(api.private_directory(directory))
        read=write=control=child=parent=parent_copy=job=process=thread=None
        try:
            # Exact local stream and permanent EOF are tested without a helper.
            read,write=api.pipe_pair(parent_reads=True)
            raw=b"private one-shot bytes"; buffer=ctypes.create_string_buffer(raw); count=rt.w.DWORD()
            api._check(api._write(write,buffer,len(raw),ctypes.byref(count),None))
            self.assertEqual(api.read_pipe(read,4096,time.monotonic_ns()+1_000_000_000,time.monotonic_ns),raw)
            api.close(write); write=None
            self.assertEqual(api.read_pipe(read,4096,time.monotonic_ns()+1_000_000_000,time.monotonic_ns),b"")
            api.close_pipe(read); read=None
            parent=api.retain_current_process(); parent_copy=api.inheritable_copy(parent)
            control,child=api.pipe_pair(parent_reads=False)
            job=api.create_job()
            # Fixed test program, not a production dispatch facility. It has no
            # device/filesystem command and is always killed through the job.
            program="import time; time.sleep(30)"
            argv=(sys.executable,"-I","-S","-E","-B","-c",program)
            env={"SystemRoot":api.system_root(),"WINDIR":api.system_root()}
            process,thread=api.create_suspended(sys.executable,argv,env,cwd,(parent_copy,child))
            identity=api.process_identity(process)
            self.assertEqual(identity[2].casefold(),sys.executable.casefold())
            self.assertTrue(api.thread_suspended(thread))
            api.assign_job(job,process)
            self.assertTrue(api.in_job(process,job)); self.assertEqual(api.job_state(job),((0x2008,1),(identity[0],)))
            api.close(parent_copy); parent_copy=None; api.close(child); child=None
            self.assertEqual(api.resume_thread(thread),1)
            api.terminate_job(job)
            self.assertTrue(api.wait_process(process,time.monotonic_ns()+2_000_000_000,time.monotonic_ns))
            self.assertFalse(api.alive(process)); self.assertEqual(api.process_identity(process),identity)
            end=time.monotonic_ns()+2_000_000_000
            while api.job_state(job)[1] and time.monotonic_ns()<end: time.sleep(.001)
            self.assertEqual(api.job_state(job),((0x2008,1),()))
        finally:
            if process is not None:
                if api.alive(process): api.terminate_process(process)
                self.assertTrue(api.wait_process(process,time.monotonic_ns()+2_000_000_000,time.monotonic_ns))
            for handle in (thread,process,job,parent_copy,parent,child,write):
                if handle is not None: api.close(handle)
            for handle in (control,read):
                if handle is not None: api.close_pipe(handle)
            api.close(directory)
            # Only the two known empty directories; no recursive/path-uncertain
            # cleanup and no source/runtime directory deletion.
            os.rmdir(cwd); os.rmdir(base)

if __name__=="__main__": unittest.main()
