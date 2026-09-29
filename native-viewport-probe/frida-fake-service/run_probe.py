"""Bounded, local-only Frida hook lifecycle check against our own child."""

from __future__ import annotations

import hashlib
import os
import queue
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path


HERE = Path(__file__).absolute().parent
PROJECT_ROOT = HERE.parents[3]
FRIDA_PYTHON = PROJECT_ROOT / "inspection" / "native-reader" / "tools" / "python"
SOURCE = HERE / "fake_service.c"
EXE = HERE / "fake_service.exe"
HOOK = HERE / "hook.js"
LOCAL_INPUTS = (SOURCE, HOOK, EXE)
EXPECTED_SHA256 = {
    SOURCE: "85d596fa070b4c9b4631bf00ba3bca936595205338c6f6039a0bd8ff4357dc38",
    HOOK: "b2d27078e9626906abf26f684b0bf2580e10a2abb90c6c005d3564a2fe5ee87b",
    EXE: "6a7096388b3af9172751557efb7d983c1cc7ca0a77721d42606117cae49e7e1c",
}
EXPECTED_FRIDA_SHA256 = {
    "__init__.py": "018e62dbdc3fc6963145cae44f55da9b6d49695fe5416cb13621d368dbff164f",
    "core.py": "ef935a023abed0f00cd48d683ed4c349654ed042c190b0ef2c5e4244304d6451",
    "_frida.pyd": "ec9aa2a3abb841373c2637b5bf478c7cdf94892b8e8eeba73ebbf4ab3b32df6a",
    "__init__.cpython-312.pyc": "011ffa5186719244d68336c4d8da7ea7eb7491b8d014192e797c293684e34672",
    "core.cpython-312.pyc": "6b352759b44964fbb440bda31114e6d1fbef354b6d3a2ec771a3e44c15d90edd",
}
TOTAL_SECONDS = 25.0
STEP_SECONDS = 5.0


def local_sha256(path: Path) -> str:
    """Require an ordinary file inside this real directory, then hash it."""
    if HERE.resolve(strict=True) != HERE or path.parent != HERE:
        raise RuntimeError(f"probe path is not local to its real directory: {path}")
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise RuntimeError(f"pre-built local input is missing: {path}") from exc
    if (
        not stat.S_ISREG(info.st_mode)
        or path.is_symlink()
        or bool(getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT)
        or path.resolve(strict=True) != path
    ):
        raise RuntimeError(f"probe input must be a local regular non-symlink file: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run() -> None:
    # The deadline begins before preflight and Frida import; compilation is a
    # separate manual step and is never run by this host.
    deadline = time.monotonic() + TOTAL_SECONDS
    finished = threading.Event()
    proc: subprocess.Popen[str] | None = None
    session = None
    script = None
    before: dict[Path, str] = {}
    frida_before: dict[Path, str] = {}
    lines: queue.Queue[str] = queue.Queue()
    messages: queue.Queue[dict] = queue.Queue()

    def remaining() -> float:
        left = deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError("25-second probe deadline expired")
        return min(STEP_SECONDS, left)

    def collect_output(child: subprocess.Popen[str]) -> None:
        assert child.stdout is not None
        for line in child.stdout:
            lines.put(line.rstrip("\r\n"))

    def next_line(expected: str) -> str:
        line = lines.get(timeout=remaining())
        if not line.startswith(expected):
            raise RuntimeError(f"expected {expected!r}; child said {line!r}")
        return line

    def command(value: str) -> None:
        assert proc is not None and proc.stdin is not None
        if proc.poll() is not None:
            raise RuntimeError("fake child exited before command")
        proc.stdin.write(value + "\n")
        proc.stdin.flush()

    def next_message(kind: str) -> dict:
        message = messages.get(timeout=remaining())
        if message.get("type") == "error":
            raise RuntimeError(f"Frida script error: {message}")
        payload = message.get("payload")
        if not isinstance(payload, dict) or payload.get("kind") != kind:
            raise RuntimeError(f"expected Frida {kind!r}; got {message!r}")
        return payload

    def watchdog() -> None:
        # Frida attach/RPC has no Python-level deadline. On expiry, terminate
        # only our Popen child; never discover or kill processes by name.
        if finished.wait(max(0.0, deadline - time.monotonic())):
            return
        print("TIMEOUT: 25-second deadline; cleaning up exact fake child PID", flush=True)
        try:
            if proc is not None and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=2)
        finally:
            os._exit(124)

    threading.Thread(target=watchdog, daemon=True).start()
    try:
        for path in LOCAL_INPUTS:
            before[path] = local_sha256(path)
            print(f"PRE_SHA256 {path.name} {before[path]}", flush=True)
            if before[path] != EXPECTED_SHA256[path]:
                raise RuntimeError(f"probe input differs from reviewed local artifact: {path.name}")

        if not FRIDA_PYTHON.is_dir():
            raise RuntimeError(f"pinned Frida directory not found: {FRIDA_PYTHON}")
        if sys.implementation.cache_tag != "cpython-312":
            raise RuntimeError("reviewed Frida bytecode requires CPython 3.12")
        if sys.flags.optimize != 0 or sys.pycache_prefix is not None:
            raise RuntimeError("reviewed Frida bytecode requires ordinary unoptimized cache paths")
        package_dir = FRIDA_PYTHON / "frida"
        if FRIDA_PYTHON.resolve(strict=True) != FRIDA_PYTHON or package_dir.resolve(strict=True) != package_dir:
            raise RuntimeError("pinned Frida package directory must not be redirected")
        cache_dir = package_dir / "__pycache__"
        if cache_dir.resolve(strict=True) != cache_dir:
            raise RuntimeError("pinned Frida bytecode directory must not be redirected")
        pinned_origins = (
            ("Python package", package_dir / "__init__.py"),
            ("native module", package_dir / "_frida.pyd"),
        )
        pinned_inputs = (*pinned_origins,
                         ("Python core", package_dir / "core.py"),
                         ("package bytecode", cache_dir / "__init__.cpython-312.pyc"),
                         ("core bytecode", cache_dir / "core.cpython-312.pyc"))
        for name, path in pinned_inputs:
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or path.is_symlink() or bool(
                getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
            ):
                raise RuntimeError(f"pinned Frida {name} must be a regular non-symlink file")
            with path.open("rb") as stream:
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
            print(f"PRE_FRIDA_SHA256 {path.name} {digest}", flush=True)
            if digest != EXPECTED_FRIDA_SHA256[path.name]:
                raise RuntimeError(f"pinned Frida {name} differs from reviewed bytes")
            frida_before[path] = digest
        sys.path.insert(0, str(FRIDA_PYTHON))
        import frida  # type: ignore[import-not-found]
        import frida.core as frida_core  # type: ignore[import-not-found]

        for (name, expected), origin in zip(
            pinned_origins,
            (frida.__file__, frida._frida.__file__),
        ):
            if origin is None or Path(origin).resolve(strict=True) != expected:
                raise RuntimeError(f"Frida {name} did not load from pinned file")
        if Path(frida_core.__file__).resolve(strict=True) != package_dir / "core.py":
            raise RuntimeError("Frida core did not load from pinned file")
        if frida.__version__ != "17.9.11":
            raise RuntimeError(f"expected Frida 17.9.11, got {frida.__version__}")

        # Only this exact child is eligible for attachment or termination. No
        # --pid, process-name search, or attach-to-existing option exists.
        proc = subprocess.Popen(
            [str(EXE)],
            cwd=HERE,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            bufsize=1,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        threading.Thread(target=collect_output, args=(proc,), daemon=True).start()

        ready = next_line("READY ")
        reported_pid = int(ready.removeprefix("READY "))
        if reported_pid != proc.pid or proc.poll() is not None:
            raise RuntimeError(f"child identity mismatch: Popen={proc.pid}, child={reported_pid}")
        print(f"LOCAL_CHILD PID={proc.pid}", flush=True)

        # No device enumeration, app discovery, or attachment to any other PID.
        session = frida.attach(proc.pid)
        hook_bytes = HOOK.read_bytes()
        if hashlib.sha256(hook_bytes).hexdigest() != before[HOOK]:
            raise RuntimeError("hook source changed after preflight hash")
        script = session.create_script(hook_bytes.decode("utf-8"))
        script.on("message", lambda message, data: messages.put(message))
        script.load()
        next_message("armed")

        command("SET 41")
        if next_line("SCORE ") != "SCORE 41":
            raise RuntimeError("hooked setter did not preserve original behavior")
        hit = next_message("hit")
        if hit.get("value") != 41 or hit.get("ordinal") != 1:
            raise RuntimeError(f"unexpected hook callback: {hit!r}")

        observed = script.exports_sync.stop()
        if observed != 1:
            raise RuntimeError(f"listener counted {observed!r} calls, not one")
        script.unload()
        script = None
        session.detach()
        session = None

        command("SENTINEL")
        if next_line("SENTINEL_") != "SENTINEL_OK 8":
            raise RuntimeError("post-unload child sentinel failed")
        # Message delivery is asynchronous; allow a bounded quiet window.
        try:
            late = messages.get(timeout=min(0.5, remaining()))
        except queue.Empty:
            late = None
        if late is not None:
            raise RuntimeError(f"callback arrived during sentinel/quiet window: {late!r}")

        command("QUIT")
        if next_line("BYE") != "BYE":
            raise RuntimeError("fake child did not acknowledge shutdown")
        if proc.wait(timeout=remaining()) != 0:
            raise RuntimeError(f"fake child exit code was {proc.returncode}")
    finally:
        try:
            if script is not None:
                try:
                    script.unload()
                except Exception:
                    pass
            if session is not None:
                try:
                    session.detach()
                except Exception:
                    pass
            if proc is not None and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=2)
        finally:
            try:
                changed = []
                for path in before:
                    after = local_sha256(path)
                    print(f"POST_SHA256 {path.name} {after}", flush=True)
                    if after != before[path]:
                        changed.append(path.name)
                for path, digest in frida_before.items():
                    with path.open("rb") as stream:
                        after = hashlib.file_digest(stream, "sha256").hexdigest()
                    print(f"POST_FRIDA_SHA256 {path.name} {after}", flush=True)
                    if after != digest:
                        changed.append("Frida/" + path.name)
                if changed:
                    raise RuntimeError(f"local inputs changed during probe: {', '.join(changed)}")
            finally:
                finished.set()

    print(
        "PASS: one callback; listener/script/session detached; eight original "
        "sentinel calls succeeded; no callback during sentinel plus 0.5s quiet window",
        flush=True,
    )


if __name__ == "__main__":
    try:
        run()
    except Exception as exc:
        print(f"FAIL: {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
        raise SystemExit(1)
