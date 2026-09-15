"""Disposable bounded-command worker.

The caller owns this worker as its only supervised process.  On Linux the
worker starts childless, becomes a subreaper, and supervises the target and the
descendants observable inside that unprivileged worker/session boundary.  It
emits one authenticated binary result only after that observable child set has
been retired.  The caller's catastrophic-failure fallback can prove retirement
only for the worker's original process group; it does not claim authority over
a deliberately daemonized process which escaped that group before the worker
failed.  This module is never imported by the evidence parsers and never reads
project evidence.
"""
from __future__ import annotations

import ctypes
import json
import os
import signal
import struct
import subprocess
import sys
import time


MAGIC = b"BCR1"
OK, FAILED, TIMED_OUT, OVERFLOW, INTERNAL, CLEANUP_UNCERTAIN = range(6)
MAX_SPEC = 1024 * 1024
MAX_CHILDREN_TEXT = 1024 * 1024


def _emit(kind: int, output: bytes = b"") -> None:
    if kind not in (OK, FAILED, TIMED_OUT, OVERFLOW, INTERNAL, CLEANUP_UNCERTAIN):
        kind = INTERNAL
    sys.stdout.buffer.write(MAGIC + bytes((kind,)) + struct.pack("<Q", len(output)) + output)
    sys.stdout.buffer.flush()


def _specification() -> tuple[list[str], int, int]:
    raw = sys.stdin.buffer.readline(MAX_SPEC + 1)
    if (len(raw) > MAX_SPEC or not raw.endswith(b"\n") or
            sys.stdin.buffer.read(1) != b""):
        raise ValueError("invalid bounded-command specification")
    value = json.loads(raw)
    if (type(value) is not dict or set(value) != {"command", "limit", "deadlineNs"}
            or type(value["command"]) is not list or not value["command"]
            or any(type(part) is not str or "\x00" in part for part in value["command"])
            or type(value["limit"]) is not int or value["limit"] <= 0
            or type(value["deadlineNs"]) is not int or value["deadlineNs"] <= 0):
        raise ValueError("invalid bounded-command specification")
    return value["command"], value["limit"], value["deadlineNs"]


def _remaining_millis(deadline_ns: int) -> int:
    remaining_ns = max(0, deadline_ns - time.monotonic_ns())
    return min(0xFFFFFFFF, (remaining_ns + 999_999) // 1_000_000)


def _linux_children() -> set[int]:
    children: set[int] = set()
    with os.scandir("/proc/self/task") as entries:
        for entry in entries:
            try:
                with open(f"/proc/self/task/{entry.name}/children", "r", encoding="ascii") as stream:
                    raw = stream.read(MAX_CHILDREN_TEXT + 1)
                if len(raw) > MAX_CHILDREN_TEXT:
                    raise RuntimeError("bounded worker child inventory overflow")
                values = raw.split()
                if any(not value.isascii() or not value.isdecimal() for value in values):
                    raise RuntimeError("invalid bounded worker child inventory")
                children.update(int(value) for value in values)
            except FileNotFoundError:
                continue
    return children


def _linux_prepare() -> None:
    # This process is disposable, so no caller signal state is mutated.  Require
    # an initially childless worker and read back subreaper ownership.
    if _linux_children():
        raise RuntimeError("bounded worker was not childless")
    libc = ctypes.CDLL(None, use_errno=True)
    current = ctypes.c_int()
    if libc.prctl(36, 1, 0, 0, 0) != 0 or libc.prctl(37, ctypes.byref(current), 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "could not establish child-subreaper authority")
    if current.value != 1:
        raise RuntimeError("child-subreaper readback mismatch")
    signal.signal(signal.SIGCHLD, signal.SIG_DFL)


class _LinuxTarget:
    def __init__(self, pid: int, stdout_fd: int, gate_fd: int, ready_fd: int,
                 parent_only_fds: tuple[int, ...]):
        self.pid = pid
        self.stdout_fd = stdout_fd
        self.gate_fd = gate_fd
        self.ready_fd = ready_fd
        self.parent_only_fds = list(parent_only_fds)
        self.setup_failed = False


def _linux_close_fd(target: _LinuxTarget, descriptor: int) -> None:
    """Close one retained descriptor and remember any unverifiable failure."""
    try:
        os.close(descriptor)
    except OSError:
        target.setup_failed = True
        return
    if descriptor in target.parent_only_fds:
        target.parent_only_fds.remove(descriptor)


def _linux_spawn_gated(command: list[str], operation_deadline_ns: int) -> _LinuxTarget:
    """Fork a target which cannot exec until its parent releases one gate byte."""
    # Retain every endpoint immediately after allocation.  A later pipe2 or
    # nonblocking-setup failure must not leak an earlier pair in the disposable
    # worker (or in a host test which invokes this seam directly).
    # Preallocate the retirement ledger before acquiring the first resource;
    # recording a returned descriptor must itself require no list growth.
    allocated = [-1] * 6
    try:
        output_read, output_write = os.pipe2(os.O_CLOEXEC)
        allocated[0], allocated[1] = output_read, output_write
        ready_read, ready_write = os.pipe2(os.O_CLOEXEC)
        allocated[2], allocated[3] = ready_read, ready_write
        gate_read, gate_write = os.pipe2(os.O_CLOEXEC)
        allocated[4], allocated[5] = gate_read, gate_write
        os.set_blocking(output_read, False)
        os.set_blocking(ready_read, False)
        pid = os.fork()
    except BaseException:
        for descriptor in allocated:
            if descriptor < 0:
                continue
            try:
                os.close(descriptor)
            except OSError:
                # The process exits on this path, so the kernel remains the
                # final descriptor-retirement boundary if close itself faults.
                pass
        raise
    if pid == 0:
        try:
            os.close(output_read)
            os.close(ready_read)
            os.close(gate_write)
            null_read = os.open(os.devnull, os.O_RDONLY | os.O_CLOEXEC)
            null_write = os.open(os.devnull, os.O_WRONLY | os.O_CLOEXEC)
            os.dup2(null_read, 0)
            os.dup2(output_write, 1)
            os.dup2(null_write, 2)
            for descriptor in (null_read, null_write, output_write):
                if descriptor > 2:
                    os.close(descriptor)
            signal.signal(signal.SIGALRM, signal.SIG_DFL)
            signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGALRM})
            remaining_ns = operation_deadline_ns - time.monotonic_ns()
            if remaining_ns <= 0:
                os._exit(124)
            signal.setitimer(signal.ITIMER_REAL, remaining_ns / 1_000_000_000)
            os.write(ready_write, b"R")
            os.close(ready_write)
            token = os.read(gate_read, 1)
            os.close(gate_read)
            remaining_ns = operation_deadline_ns - time.monotonic_ns()
            if token != b"G" or remaining_ns <= 0:
                os._exit(124)
            signal.setitimer(signal.ITIMER_REAL, remaining_ns / 1_000_000_000)
            os.execvpe(command[0], command, os.environ)
        except BaseException:
            os._exit(127)
    # Construct the retained target authority before any post-fork operation
    # which could fail.  A close failure prevents release and is handled as an
    # internal cleanup path, so the child can never cross the gate unnoticed.
    target = _LinuxTarget(pid, output_read, gate_write, ready_read,
                          (output_write, ready_write, gate_read))
    for descriptor in tuple(target.parent_only_fds):
        _linux_close_fd(target, descriptor)
    return target


def _linux_release(target: _LinuxTarget, operation_deadline_ns: int) -> int:
    """Wait for child-side setup, then release only before the operation deadline."""
    try:
        while time.monotonic_ns() < operation_deadline_ns:
            try:
                ready = os.read(target.ready_fd, 1)
            except BlockingIOError:
                time.sleep(0.001)
                continue
            if ready == b"R":
                if time.monotonic_ns() >= operation_deadline_ns:
                    return TIMED_OUT
                os.write(target.gate_fd, b"G")
                return OK
            return INTERNAL
        return TIMED_OUT
    except OSError:
        return INTERNAL
    finally:
        for name in ("ready_fd", "gate_fd"):
            descriptor = getattr(target, name)
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
                setattr(target, name, -1)


def _linux_observe_leader(pid: int):
    flags = os.WEXITED | os.WNOHANG | os.WNOWAIT
    info = os.waitid(os.P_PID, pid, flags)
    # Linux/glibc may represent "no waitable state" either as None or as a
    # zero-filled siginfo_t.  Only an exact PID match is an exit observation.
    if info is None or info.si_pid == 0:
        return None
    if info.si_pid != pid:
        raise RuntimeError("waitid returned the wrong target")
    return info


def _linux_reap_all(operation_deadline_ns: int, hard_deadline_ns: int,
                    target: _LinuxTarget, output: bytearray,
                    limit: int, classification: int) -> tuple[int, bytes]:
    """Retire every child observable in this disposable subreaper boundary."""
    leader_info = None
    eof = False
    inventory_reliable = True
    while time.monotonic_ns() < hard_deadline_ns:
        now = time.monotonic_ns()
        if now >= operation_deadline_ns and classification == OK:
            classification = TIMED_OUT

        if not eof and len(output) <= limit:
            try:
                chunk = os.read(target.stdout_fd,
                                min(65536, limit + 1 - len(output)))
            except BlockingIOError:
                chunk = None
            except OSError:
                chunk = None
                classification = INTERNAL
            if chunk == b"":
                eof = True
            elif chunk:
                output.extend(chunk)
                if len(output) > limit and classification == OK:
                    classification = OVERFLOW

        if leader_info is None:
            try:
                leader_info = _linux_observe_leader(target.pid)
            except (ChildProcessError, OSError):
                classification = INTERNAL
                inventory_reliable = False
            if leader_info is not None and classification == OK:
                if not (leader_info.si_code == os.CLD_EXITED and
                        leader_info.si_status == 0):
                    classification = FAILED

        try:
            children = _linux_children()
            inventory_reliable = True
        except (OSError, RuntimeError, ValueError):
            children = {target.pid} if leader_info is None else set()
            inventory_reliable = False
            classification = INTERNAL

        terminating = leader_info is not None or classification != OK
        if terminating:
            for child in children:
                if child == target.pid and leader_info is not None:
                    continue
                try:
                    os.kill(child, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except OSError:
                    classification = INTERNAL
                    inventory_reliable = False
            for child in tuple(children):
                if child == target.pid:
                    continue
                try:
                    os.waitpid(child, os.WNOHANG)
                except ChildProcessError:
                    pass
                except OSError:
                    classification = INTERNAL
                    inventory_reliable = False

        others = children - {target.pid}
        if leader_info is not None and inventory_reliable and not others and (
                eof or classification != OK):
            try:
                waited, _ = os.waitpid(target.pid, os.WNOHANG)
            except (ChildProcessError, OSError):
                waited = -1
            if waited == target.pid:
                return classification, bytes(output[:limit])
            classification = INTERNAL

        time.sleep(0.001 if terminating else 0.002)

    # A valid result is never emitted as though retirement succeeded when the
    # original hard deadline ended with an owned or unverified child.
    return CLEANUP_UNCERTAIN, b""


def _linux_emergency_cleanup(hard_deadline_ns: int) -> tuple[int, bytes]:
    """Best-effort fault path which returns INTERNAL only after ECHILD proof."""
    while time.monotonic_ns() < hard_deadline_ns:
        try:
            children = _linux_children()
        except BaseException:
            children = set()
        for child in children:
            try:
                os.kill(child, signal.SIGKILL)
            except BaseException:
                pass
        try:
            while True:
                waited, _ = os.waitpid(-1, os.WNOHANG)
                if waited == 0:
                    break
        except ChildProcessError:
            # ECHILD is independent kernel proof that the disposable worker no
            # longer owns a target or any adopted descendant.
            return INTERNAL, b""
        except BaseException:
            pass
        time.sleep(0.001)
    return CLEANUP_UNCERTAIN, b""


def _run_linux(command: list[str], limit: int, operation_deadline_ns: int,
               hard_deadline_ns: int) -> tuple[int, bytes]:
    _linux_prepare()
    if time.monotonic_ns() >= operation_deadline_ns:
        return TIMED_OUT, b""
    target = None
    try:
        target = _linux_spawn_gated(command, operation_deadline_ns)
        classification = (INTERNAL if target.setup_failed else
                          _linux_release(target, operation_deadline_ns))
        # A setup failure deliberately leaves the release pipe closed in the
        # finalizer below.  The target either observes EOF or is killed here.
        if target.setup_failed:
            for name in ("ready_fd", "gate_fd"):
                descriptor = getattr(target, name)
                if descriptor >= 0:
                    _linux_close_fd(target, descriptor)
                    setattr(target, name, -1)
        try:
            return _linux_reap_all(operation_deadline_ns, hard_deadline_ns,
                                   target, bytearray(), limit, classification)
        except BaseException:
            # Retry through the same retained PID/subreaper authority.  The
            # second pass can only emit INTERNAL after verified retirement, or
            # CLEANUP_UNCERTAIN when the hard deadline makes proof impossible.
            try:
                return _linux_reap_all(operation_deadline_ns, hard_deadline_ns,
                                       target, bytearray(), limit, INTERNAL)
            except BaseException:
                return _linux_emergency_cleanup(hard_deadline_ns)
    except BaseException:
        if target is None:
            raise
        try:
            return _linux_reap_all(operation_deadline_ns, hard_deadline_ns,
                                   target, bytearray(), limit, INTERNAL)
        except BaseException:
            return _linux_emergency_cleanup(hard_deadline_ns)
    finally:
        if target is not None:
            for name in ("stdout_fd", "gate_fd", "ready_fd"):
                descriptor = getattr(target, name)
                if descriptor >= 0:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
                    setattr(target, name, -1)
            for descriptor in tuple(target.parent_only_fds):
                try:
                    os.close(descriptor)
                except OSError:
                    pass
                target.parent_only_fds.remove(descriptor)


def _windows_stop_exact(process, kernel, hard_deadline_ns: int) -> bool:
    """Terminate if needed and prove the exact target handle became signaled."""
    handle = int(process._handle)
    waited = kernel.WaitForSingleObject(handle, 0)
    if waited == 258:  # WAIT_TIMEOUT
        if not kernel.TerminateProcess(handle, 91):
            # A concurrent natural exit is acceptable only when the exact
            # retained process handle independently proves it.
            waited = kernel.WaitForSingleObject(handle, 0)
            if waited != 0:
                return False
        waited = kernel.WaitForSingleObject(
            handle, _remaining_millis(hard_deadline_ns))
    if waited != 0:
        return False
    try:
        process.wait(timeout=0)
    except (subprocess.TimeoutExpired, OSError):
        return False
    return True


def _windows_read_bounded(process, limit: int, operation_deadline_ns: int,
                          kernel, *, pipe_handle=None, read_output=None,
                          last_error=None) -> tuple[int, bytes]:
    """Incrementally read an anonymous pipe without materializing over limit+1."""
    from ctypes import wintypes
    if pipe_handle is None:
        import msvcrt
        pipe_handle = msvcrt.get_osfhandle(process.stdout.fileno())
    if read_output is None:
        read_output = os.read
    if last_error is None:
        last_error = ctypes.get_last_error
    output = bytearray()
    eof = False
    exited = False
    while time.monotonic_ns() < operation_deadline_ns:
        exit_was_already_observed = exited
        available = wintypes.DWORD()
        if not kernel.PeekNamedPipe(pipe_handle, None, 0, None,
                                    ctypes.byref(available), None):
            error = last_error()
            if error in (109, 232, 233):  # BROKEN_PIPE/NO_DATA/NOT_CONNECTED
                eof = True
            else:
                return INTERNAL, bytes(output[:limit])
        elif available.value:
            allowance = limit + 1 - len(output)
            if allowance <= 0:
                return OVERFLOW, bytes(output[:limit])
            try:
                chunk = read_output(process.stdout.fileno(),
                                    min(65536, int(available.value), allowance))
            except OSError:
                return INTERNAL, bytes(output[:limit])
            if not chunk:
                eof = True
            else:
                output.extend(chunk)
                if len(output) > limit:
                    return OVERFLOW, bytes(output[:limit])

        waited = kernel.WaitForSingleObject(int(process._handle), 0)
        if waited == 0:
            exited = True
            process.poll()
            # Preserve an observed target failure immediately. Output is not
            # authority on an unsuccessful producer, and a descendant must not
            # turn that failure into a later timeout merely by holding stdout.
            if process.returncode != 0:
                return FAILED, bytes(output)
        elif waited != 258:
            return INTERNAL, bytes(output[:limit])
        # Once success was observed in an earlier iteration, a subsequent
        # zero-byte peek proves all output written by that exact process was
        # drained. A descendant merely retaining the inherited pipe cannot
        # convert success into a timeout; the caller's Job retires it.
        if exited and (eof or (exit_was_already_observed and available.value == 0)):
            return OK, bytes(output)
        time.sleep(0.002)
    return TIMED_OUT, bytes(output[:limit])


def _windows_popen_before_deadline(command: list[str],
                                   operation_deadline_ns: int, **kwargs):
    """Create no Windows target once the original operation window expired."""
    if time.monotonic_ns() >= operation_deadline_ns:
        return None
    # Keep Popen immediately adjacent to the final pre-creation deadline gate.
    return subprocess.Popen(command, **kwargs)


def _run_windows(command: list[str], limit: int, operation_deadline_ns: int,
                 hard_deadline_ns: int, *, kernel=None, ntdll=None,
                 spawn=None, read_bounded=None) -> tuple[int, bytes]:
    # The caller starts this worker suspended and assigns it to a kill-on-close
    # Job first.  Descendants inherit that Job.  The target is also created
    # suspended and cannot execute until the deadline has been checked.
    from ctypes import wintypes
    if (kernel is None) != (ntdll is None):
        raise RuntimeError("incomplete Windows target API seam")
    if kernel is None:
        ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        ntdll.NtResumeProcess.argtypes = [wintypes.HANDLE]
        ntdll.NtResumeProcess.restype = wintypes.LONG
        kernel.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
        kernel.TerminateProcess.restype = wintypes.BOOL
        kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel.WaitForSingleObject.restype = wintypes.DWORD
        kernel.PeekNamedPipe.argtypes = [wintypes.HANDLE, ctypes.c_void_p,
            wintypes.DWORD, ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
        kernel.PeekNamedPipe.restype = wintypes.BOOL
    if spawn is None:
        spawn = _windows_popen_before_deadline
    if read_bounded is None:
        read_bounded = _windows_read_bounded
    process = spawn(
        command, operation_deadline_ns, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, close_fds=True,
        creationflags=0x00000004)  # CREATE_SUSPENDED
    if process is None:
        return TIMED_OUT, b""
    kind, output = INTERNAL, b""
    cleanup_verified = False
    try:
        if time.monotonic_ns() >= operation_deadline_ns:
            kind, output = TIMED_OUT, b""
        elif ntdll.NtResumeProcess(int(process._handle)) != 0:
            kind, output = INTERNAL, b""
        else:
            kind, output = read_bounded(
                process, limit, operation_deadline_ns, kernel)
    except BaseException:
        kind, output = INTERNAL, b""
    finally:
        try:
            cleanup_verified = _windows_stop_exact(
                process, kernel, hard_deadline_ns)
        except BaseException:
            cleanup_verified = False
        if process.stdout is not None:
            try:
                process.stdout.close()
            except OSError:
                kind = INTERNAL
    if not cleanup_verified:
        return CLEANUP_UNCERTAIN, b""
    return kind, output


def main() -> int:
    try:
        command, limit, hard_deadline_ns = _specification()
        remaining_ns = hard_deadline_ns - time.monotonic_ns()
        reserve_ns = min(500_000_000, max(50_000_000, remaining_ns // 5))
        operation_deadline_ns = hard_deadline_ns - reserve_ns
        if os.name == "posix" and sys.platform.startswith("linux"):
            kind, output = _run_linux(command, limit, operation_deadline_ns,
                                      hard_deadline_ns)
        elif os.name == "nt":
            kind, output = _run_windows(command, limit, operation_deadline_ns,
                                        hard_deadline_ns)
        else:
            kind, output = INTERNAL, b""
        _emit(kind, output)
    except BaseException:
        try:
            _emit(INTERNAL)
        except BaseException:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
