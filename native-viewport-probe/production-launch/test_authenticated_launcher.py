"""Production-path regressions for authenticated probe Python entry points."""
from __future__ import annotations

import base64
import copy
import hashlib
import importlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest


HERE = Path(__file__).parent
ROOT = HERE.parent
INVOKER = ROOT / "invoke-authenticated-production.ps1"
LAUNCHER = HERE / "authenticated_launcher.py"
POWERSHELL = shutil.which("pwsh") or shutil.which("powershell")
SOURCE_NAMES = (
    "bounded_command_runner.py",
    "ink_oracle.py",
    "inspect_loader_bindings.py",
    "inspect_loader_dependencies.py",
    "pinned_elftools_gate.py",
    "saved_ink_reader_artifact.py",
    "test_display_host_scope.py",
    "test_saved_ink_reader_artifact.py",
)


def _canonical_source(raw):
    if b"\r" not in raw:
        return raw
    if (raw.count(b"\r") != raw.count(b"\r\n") or
            raw.count(b"\n") != raw.count(b"\r\n")):
        raise AssertionError("mixed test source newlines")
    return raw.replace(b"\r\n", b"\n")


def _invoker_contract():
    text = INVOKER.read_text(encoding="utf-8")
    bootstrap = re.search(r"\$bootstrap=@'\n(.*?)\n'@", text, re.DOTALL)
    digest = re.search(
        r"\$expectedLauncherSha256='([0-9a-f]{64})'", text)
    if bootstrap is None or digest is None:
        raise AssertionError("could not extract reviewed production bootstrap")
    return bootstrap.group(1), digest.group(1)


BOOTSTRAP, LAUNCHER_SHA256 = _invoker_contract()


def _run(mode, arguments, *, root=ROOT, launcher=LAUNCHER,
         expected=LAUNCHER_SHA256, cwd=None, env=None, timeout=45,
         input_text=None):
    return subprocess.run(
        [sys.executable, "-I", "-S", "-E", "-s", "-c", BOOTSTRAP,
         str(launcher), expected, "262144", str(root), mode, *arguments],
        cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        input=input_text, text=True, encoding="utf-8", timeout=timeout,
        close_fds=True)


def _popen(mode, arguments, *, root=ROOT, launcher=LAUNCHER,
           expected=LAUNCHER_SHA256, cwd=None, env=None):
    return subprocess.Popen(
        [sys.executable, "-I", "-S", "-E", "-s", "-c", BOOTSTRAP,
         str(launcher), expected, "262144", str(root), mode, *arguments],
        cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, encoding="utf-8", close_fds=True)


def _resolved_path(value):
    return os.path.normcase(os.path.realpath(os.path.abspath(os.fspath(value))))


def _authenticated_fixture_record(name, current_loader, authority):
    gate_module = sys.modules.get(type(current_loader).__module__)
    loader_type = getattr(gate_module, "_PinnedSourceLoader", None)
    finder_type = getattr(gate_module, "_PinnedSourceFinder", None)
    if type(current_loader) is not loader_type or finder_type is None:
        raise AssertionError("authenticated test loader identity is unavailable")
    matches = []
    for finder in tuple(sys.meta_path):
        if (type(finder) is not finder_type or
                finder.authority_sha256 != authority or
                finder.gate_authority is not current_loader.gate_authority or
                finder.gate_source is not current_loader.gate_source or
                finder.gate_method is not current_loader.gate_method):
            continue
        captured = finder.sources.get(name)
        if captured is not None:
            matches.append(captured)
    if len(matches) != 1:
        raise AssertionError("authenticated fixture source is unavailable")
    source, raw, is_package = matches[0]
    if type(raw) is not bytes or is_package is not False:
        raise AssertionError("authenticated fixture source is invalid")
    return Path(source).resolve(strict=True), raw, loader_type


def _verify_authenticated_fixture(module, name, expected_source, expected_raw,
                                  loader_type, current_loader, authority):
    spec = getattr(module, "__spec__", None)
    loader = getattr(spec, "loader", None)
    if (type(loader) is not loader_type or
            loader.authority_sha256 != authority or
            loader.gate_authority is not current_loader.gate_authority or
            loader.gate_source is not current_loader.gate_source or
            loader.gate_method is not current_loader.gate_method or
            Path(loader.source).resolve(strict=True) != expected_source or
            loader.raw is not expected_raw or loader.is_package is not False or
            getattr(spec, "name", None) != name or
            _resolved_path(getattr(spec, "origin", "")) !=
            _resolved_path(expected_source) or
            getattr(spec, "submodule_search_locations", None) is not None or
            getattr(module, "__name__", None) != name or
            getattr(module, "__package__", None) != "" or
            getattr(module, "__loader__", None) is not loader or
            _resolved_path(getattr(module, "__file__", "")) !=
            _resolved_path(expected_source) or
            getattr(module, "__cached__", None) is not None or
            sys.modules.get(name) is not module):
        raise AssertionError("fixture escaped authenticated source namespace")


def _load_test_fixtures():
    names = ("ink_oracle", "test_display_host_scope", "test_ink_oracle")
    current_loader = getattr(globals().get("__spec__"), "loader", None)
    authority = getattr(current_loader, "authority_sha256", None)
    if authority is not None:
        before = tuple(sys.path)
        if any(type(entry) is not str for entry in before):
            raise AssertionError("authenticated import path contains a non-string")
        root = _resolved_path(ROOT.resolve(strict=True))
        if root in {_resolved_path(entry or os.curdir) for entry in before}:
            raise AssertionError("probe root is ambient on authenticated import path")
        modules = []
        for name in names:
            expected_source, expected_raw, loader_type = (
                _authenticated_fixture_record(name, current_loader, authority))
            module = importlib.import_module(name)
            if tuple(sys.path) != before:
                raise AssertionError("authenticated fixture import changed sys.path")
            _verify_authenticated_fixture(
                module, name, expected_source, expected_raw, loader_type,
                current_loader, authority)
            modules.append(module)
        state = {
            "authenticated": True,
            "pathBefore": before,
            "pathAfter": tuple(sys.path),
            "root": root,
        }
        return (*modules, state)

    saved = list(sys.path)
    try:
        sys.path.insert(0, str(ROOT))
        import ink_oracle
        import test_display_host_scope
        import test_ink_oracle
        state = {"authenticated": False}
        return ink_oracle, test_display_host_scope, test_ink_oracle, state
    finally:
        sys.path[:] = saved


ORACLE, DISPLAY, INK_FIXTURES, FIXTURE_LOAD_STATE = _load_test_fixtures()


def _load_launcher_for_test(module_name):
    """Prefer the outer gate's authenticated launcher snapshot when present."""
    current_loader = getattr(globals().get("__spec__"), "loader", None)
    authority = getattr(current_loader, "authority_sha256", None)
    if authority is not None:
        module = importlib.import_module("authenticated_launcher")
        loader = getattr(getattr(module, "__spec__", None), "loader", None)
        if getattr(loader, "authority_sha256", None) != authority:
            raise AssertionError("launcher escaped authenticated test sources")
        return module
    spec = importlib.util.spec_from_file_location(module_name, LAUNCHER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _ink_arguments(parent, expectation="unchanged"):
    before = parent / "before.json"
    after = parent / "after.json"
    first = INK_FIXTURES.capture()
    second = copy.deepcopy(first)
    if expectation == "one-addition":
        second["trails"].append(INK_FIXTURES.record(2))
    before.write_text(ORACLE.canonical_json(first), encoding="utf-8")
    after.write_text(ORACLE.canonical_json(second), encoding="utf-8")
    return [str(before), str(after), "--expect", expectation,
            "--expected-source-sha256", INK_FIXTURES.EXPECTED_SOURCE]


def _framed_ink_arguments(parent, expectation="unchanged"):
    before = parent / "before.frame"
    after = parent / "after.frame"
    first = INK_FIXTURES.capture()
    second = copy.deepcopy(first)
    if expectation == "one-addition":
        second["trails"].append(INK_FIXTURES.record(2))
    prefix = ORACLE.COLLECTOR_FRAME_PREFIX
    before.write_bytes(
        prefix + ORACLE.canonical_json(first).encode("utf-8") + b"\n")
    after.write_bytes(
        prefix + ORACLE.canonical_json(second).encode("utf-8") + b"\n")
    return ["--framed-before", str(before), "--framed-after", str(after),
            "--expect", expectation, "--expected-source-sha256",
            INK_FIXTURES.EXPECTED_SOURCE]


def _invalid_frame_wires(valid_frame):
    payload = valid_frame[len(ORACLE.COLLECTOR_FRAME_PREFIX):-1]
    return {
        "wrong-prefix": b"WRONG_INK_EVIDENCE " + payload + b"\n",
        "wrong-prefix-case": (
            b"native_viewport_ink_evidence " + payload + b"\n"),
        "prefix-spacing": (
            ORACLE.COLLECTOR_FRAME_PREFIX + b" " + payload + b"\n"),
        "prefix-missing-space": (
            ORACLE.COLLECTOR_FRAME_PREFIX[:-1] + payload + b"\n"),
        "truncated": valid_frame[:-1],
        "truncated-payload": valid_frame[:-2] + b"\n",
        "concatenated": valid_frame + valid_frame,
        "trailing-chatter": valid_frame + b"trailing",
        "crlf": valid_frame[:-1] + b"\r\n",
        "bare-cr": valid_frame[:-1] + b"\r",
        "invalid-utf8": (
            ORACLE.COLLECTOR_FRAME_PREFIX + payload[:-2] + b"\xff}\n"),
        "bom-prefix": b"\xef\xbb\xbf" + valid_frame,
        "bom-payload": (
            ORACLE.COLLECTOR_FRAME_PREFIX + b"\xef\xbb\xbf" + payload + b"\n"),
        "duplicate-json": (
            ORACLE.COLLECTOR_FRAME_PREFIX + b'{"complete":true,' +
            payload[1:] + b"\n"),
        "noncanonical-json": (
            ORACLE.COLLECTOR_FRAME_PREFIX + b"{ " + payload[1:] + b"\n"),
    }


def _fake_aapt(parent, signal=None):
    script = parent / "dump"
    signal_literal = repr(str(signal)) if signal is not None else "None"
    script.write_text(
        "import base64, pathlib, sys, time\n"
        f"signal={signal_literal}\n"
        "if len(sys.argv) not in (3,4): raise SystemExit(9)\n"
        "kind=sys.argv[1]\n"
        "if signal is not None and kind == 'permissions':\n"
        " pathlib.Path(signal).write_text('ready', encoding='ascii')\n"
        " time.sleep(1.5)\n"
        f"permissions={base64.b64encode(DISPLAY.VALID_PERMISSION_BYTES)!r}\n"
        f"xmltree={base64.b64encode(DISPLAY.VALID_XMLTREE_BYTES)!r}\n"
        "sys.stdout.buffer.write(base64.b64decode(permissions if kind == "
        "'permissions' else xmltree))\n",
        encoding="utf-8")
    return script


def _display_arguments(parent, aapt):
    apk = parent / "probe.apk"
    evidence = parent / "evidence"
    evidence.mkdir()
    apk.write_bytes(b"authenticated display-only test APK")
    return apk, evidence, [
        "--aapt", str(aapt), "--apk", str(apk),
        "--permissions-out", str(evidence / "permissions.txt"),
        "--xmltree-out", str(evidence / "manifest-xmltree.txt"),
        "--authority-out", str(evidence / "packaged-scope-authority.json"),
    ]


class AuthenticatedProductionLauncherTests(unittest.TestCase):
    maxDiff = None

    def test_shell_entrypoint_and_callers_use_only_isolated_literal_bootstrap(self):
        invoker = INVOKER.read_text(encoding="utf-8")
        build = (ROOT / "build-display-host.ps1").read_text(encoding="utf-8")
        oracle = (ROOT / "run-ink-oracle.ps1").read_text(encoding="utf-8")
        artifact_builder = (ROOT / "build-saved-ink-reader.ps1").read_text(
            encoding="utf-8")
        self.assertIn("'-I', '-S', '-E', '-s', '-c', $bootstrap", invoker)
        self.assertIn("production-launch/authenticated_launcher.py", invoker)
        self.assertIn("close_ambient_descriptors()", invoker)
        self.assertIn("os.set_inheritable(descriptor, False)", invoker)
        self.assertIn("neutralize_terminal(1, \"stdout\")", invoker)
        self.assertNotIn("2>&1", invoker)
        self.assertIn("StandardOutput.BaseStream.CopyToAsync", invoker)
        self.assertIn("StandardError.BaseStream.CopyToAsync", invoker)
        self.assertIn("[Console]::OpenStandardOutput()", invoker)
        self.assertIn("[Console]::OpenStandardError()", invoker)
        self.assertNotIn("2>&1", build)
        dependency_source = (ROOT / "inspect_loader_dependencies.py").read_text(
            encoding="utf-8")
        runner_source = (ROOT / "bounded_command_runner.py").read_text(
            encoding="utf-8")
        self.assertGreaterEqual(dependency_source.count("close_fds=True"), 2)
        self.assertIn("close_fds=True", runner_source)
        self.assertNotIn("test_display_host_scope.py') --inspect", build)
        self.assertNotIn("test_display_host_scope.py') --verify", build)
        self.assertEqual(build.count("-Mode display-inspect"), 1)
        self.assertEqual(build.count("-Mode display-verify"), 1)
        self.assertIn("-Mode ink-oracle", oracle)
        self.assertNotIn("$inspectOutput", build)
        self.assertNotIn("$verifyOutput", build)
        self.assertIn("exit $inspectExit", build)
        self.assertIn("exit $verifyExit", build)
        self.assertNotIn("& $Python -I", artifact_builder)
        self.assertIn("Invoke-AuthenticatedTool -Mode 'saved-ink-artifact'",
                      artifact_builder)
        self.assertIn(
            "Invoke-AuthenticatedTool -Mode 'saved-ink-artifact-tests'",
            artifact_builder)
        self.assertIn("'-ProbeRoot', $probeRoot", artifact_builder)
        self.assertIn("'-EncodedCommandArguments', $encodedArguments",
                      artifact_builder)
        invoker_pin = re.search(
            r"\$expectedInvokerSha256 = '([0-9a-f]{64})'", artifact_builder)
        packager_pin = re.search(
            r"\$expectedPackagerSha256 = '([0-9a-f]{64})'", artifact_builder)
        tests_pin = re.search(
            r"\$expectedTestsSha256 = '([0-9a-f]{64})'", artifact_builder)
        self.assertIsNotNone(invoker_pin)
        self.assertIsNotNone(packager_pin)
        self.assertIsNotNone(tests_pin)
        self.assertEqual(
            invoker_pin.group(1),
            hashlib.sha256(_canonical_source(INVOKER.read_bytes())).hexdigest())
        self.assertEqual(
            packager_pin.group(1), hashlib.sha256(_canonical_source(
                (ROOT / "saved_ink_reader_artifact.py").read_bytes())).hexdigest())
        self.assertEqual(
            tests_pin.group(1), hashlib.sha256(_canonical_source(
                (ROOT / "test_saved_ink_reader_artifact.py").read_bytes())).hexdigest())

    def test_launcher_and_all_transitive_source_authorities_are_exact(self):
        current_loader = getattr(globals().get("__spec__"), "loader", None)
        authenticated = getattr(current_loader, "authority_sha256", None) is not None
        self.assertEqual(FIXTURE_LOAD_STATE["authenticated"], authenticated)
        if authenticated:
            self.assertEqual(FIXTURE_LOAD_STATE["pathBefore"],
                             FIXTURE_LOAD_STATE["pathAfter"])
            self.assertNotIn(
                FIXTURE_LOAD_STATE["root"],
                {_resolved_path(entry or os.curdir)
                 for entry in FIXTURE_LOAD_STATE["pathAfter"]})
        self.assertEqual(
            hashlib.sha256(_canonical_source(LAUNCHER.read_bytes())).hexdigest(),
            LAUNCHER_SHA256)
        launcher = _load_launcher_for_test("production_launcher_under_test")
        self.assertEqual(set(launcher.SOURCE_SHA256), set(SOURCE_NAMES))
        for name in SOURCE_NAMES:
            with self.subTest(name=name):
                raw = _canonical_source((ROOT / name).read_bytes())
                self.assertEqual(hashlib.sha256(raw).hexdigest(),
                                 launcher.SOURCE_SHA256[name])
        self.assertEqual(
            set(launcher.MODE_SOURCES["display-inspect"]),
            {"bounded_command_runner.py", "inspect_loader_bindings.py",
             "inspect_loader_dependencies.py", "pinned_elftools_gate.py",
             "test_display_host_scope.py"})
        self.assertEqual(launcher.MODE_SOURCES["display-inspect"],
                         launcher.MODE_SOURCES["display-verify"])
        self.assertEqual(
            set(launcher.MODE_SOURCES["ink-oracle"]),
            {"bounded_command_runner.py", "ink_oracle.py",
             "inspect_loader_dependencies.py", "pinned_elftools_gate.py"})
        self.assertEqual(
            launcher.MODE_SOURCES["saved-ink-artifact"],
            ("saved_ink_reader_artifact.py",))
        self.assertEqual(
            launcher.MODE_SOURCES["saved-ink-artifact-tests"],
            ("saved_ink_reader_artifact.py",
             "test_saved_ink_reader_artifact.py"))
        self.assertEqual(launcher.TARGET_MODULE["saved-ink-artifact"],
                         "saved_ink_reader_artifact")
        self.assertEqual(launcher.TARGET_MODULE["saved-ink-artifact-tests"],
                         "test_saved_ink_reader_artifact")
        self.assertEqual(
            launcher.MUTATING_ARTIFACT_COMMANDS,
            {"class-jar", "package", "publish-copy", "provenance"})
        invoker = INVOKER.read_text(encoding="utf-8")
        for command in launcher.MUTATING_ARTIFACT_COMMANDS:
            self.assertGreaterEqual(invoker.count('"' + command + '"'), 1)
            self.assertGreaterEqual(invoker.count("'" + command + "'"), 1)

    def test_real_ink_cli_preserves_pass_different_and_invalid_statuses(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            passed = _run("ink-oracle", _ink_arguments(parent))
            self.assertEqual((passed.returncode, passed.stderr), (0, ""))
            self.assertEqual(json.loads(passed.stdout)["status"], "PASS")

            framed_parent = parent / "framed"
            framed_parent.mkdir()
            framed_arguments = _framed_ink_arguments(framed_parent)
            framed = _run("ink-oracle", framed_arguments)
            self.assertEqual((framed.returncode, framed.stderr), (0, ""))
            self.assertEqual(json.loads(framed.stdout)["status"], "PASS")

            for frame_index in (1, 3):
                frame_path = Path(framed_arguments[frame_index])
                valid_frame = frame_path.read_bytes()
                for name, mutation in _invalid_frame_wires(valid_frame).items():
                    with self.subTest(frame=name, side=frame_index):
                        frame_path.write_bytes(mutation)
                        rejected = _run("ink-oracle", framed_arguments)
                        self.assertEqual((rejected.returncode, rejected.stderr),
                                         (2, ""))
                        self.assertEqual(json.loads(rejected.stdout)["status"],
                                         "INVALID_EVIDENCE")
                frame_path.write_bytes(valid_frame)

            common = ["--expect", "unchanged", "--expected-source-sha256",
                      INK_FIXTURES.EXPECTED_SOURCE]
            invalid_modes = (
                [],
                [str(parent / "before.json")],
                framed_arguments[:2],
                _ink_arguments(parent)[:2] + framed_arguments[:4],
                [str(parent / "before.json"),
                 "--framed-after", framed_arguments[3]],
            )
            for mode in invalid_modes:
                with self.subTest(mode=mode):
                    rejected = _run("ink-oracle", [*mode, *common])
                    self.assertEqual((rejected.returncode, rejected.stderr),
                                     (2, ""))
                    self.assertEqual(json.loads(rejected.stdout)["status"],
                                     "INVALID_EVIDENCE")

            source_mismatch = _run(
                "ink-oracle", _ink_arguments(parent)[:-1] + ["c" * 64])
            self.assertEqual((source_mismatch.returncode, source_mismatch.stderr),
                             (2, ""))
            self.assertEqual(json.loads(source_mismatch.stdout)["status"],
                             "INVALID_EVIDENCE")

            addition_parent = parent / "expected-addition"
            addition_parent.mkdir()
            addition = _run(
                "ink-oracle", _ink_arguments(addition_parent, "one-addition"))
            self.assertEqual((addition.returncode, addition.stderr), (0, ""))
            addition_payload = json.loads(addition.stdout)
            self.assertEqual(addition_payload["status"], "PASS")
            self.assertEqual(len(addition_payload["comparison"]["added"]), 1)

            different_parent = parent / "different"
            different_parent.mkdir()
            different = _run(
                "ink-oracle", _ink_arguments(different_parent, "one-addition")[:-4]
                + ["--expect", "unchanged", "--expected-source-sha256",
                   INK_FIXTURES.EXPECTED_SOURCE])
            self.assertEqual((different.returncode, different.stderr), (1, ""))
            self.assertEqual(json.loads(different.stdout)["status"], "DIFFERENT")

            invalid = _run("ink-oracle", [
                str(parent / "missing"), str(parent / "also-missing"),
                "--expect", "unchanged", "--expected-source-sha256",
                INK_FIXTURES.EXPECTED_SOURCE])
            self.assertEqual((invalid.returncode, invalid.stderr), (2, ""))
            self.assertEqual(json.loads(invalid.stdout)["status"],
                             "INVALID_EVIDENCE")

    def test_display_inspect_and_verify_both_use_authenticated_production_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            _fake_aapt(parent)
            apk, evidence, arguments = _display_arguments(parent, sys.executable)
            inspected = _run("display-inspect", arguments, cwd=parent)
            self.assertEqual(
                (inspected.returncode, inspected.stdout, inspected.stderr),
                (0, "PACKAGED_PERMISSION_SURFACES_EMPTY\n", ""))
            verified = _run("display-verify", [
                "--apk", str(apk),
                "--permissions-out", str(evidence / "permissions.txt"),
                "--xmltree-out", str(evidence / "manifest-xmltree.txt"),
                "--authority-out", str(evidence / "packaged-scope-authority.json")])
            expected = "PACKAGED_APK_AUTHORITY_VERIFIED sha256=" + hashlib.sha256(
                apk.read_bytes()).hexdigest() + "\n"
            self.assertEqual(
                (verified.returncode, verified.stdout, verified.stderr),
                (0, expected, ""))

            publish_source = parent / "source with ' quote.bin"
            publish_target = parent / "published with spaces.bin"
            publish_source.write_bytes(b"authenticated artifact bytes")
            published = _run("saved-ink-artifact", [
                "publish-copy", "--source", str(publish_source),
                "--output", str(publish_target)])
            self.assertEqual((published.returncode, published.stderr), (0, ""))
            self.assertEqual(json.loads(published.stdout), {
                "bytes": len(b"authenticated artifact bytes"),
                "sha256": hashlib.sha256(
                    b"authenticated artifact bytes").hexdigest(),
                "status": "COPY_PUBLISHED",
            })
            self.assertEqual(publish_target.read_bytes(),
                             b"authenticated artifact bytes")
            collision = _run("saved-ink-artifact", [
                "publish-copy", "--source", str(publish_source),
                "--output", str(publish_target)])
            self.assertEqual((collision.returncode, collision.stderr), (2, ""))
            self.assertEqual(json.loads(collision.stdout)["status"],
                             "INVALID_ARTIFACT")
            self.assertEqual(publish_target.read_bytes(),
                             b"authenticated artifact bytes")

    def test_isolation_ignores_startup_hooks_environment_and_cwd_shadows(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            sentinel = parent / "poison-ran"
            poison = (
                "from pathlib import Path\n"
                f"Path({str(sentinel)!r}).write_text('ran')\n")
            for name in ("sitecustomize.py", "usercustomize.py", "json.py",
                         "bounded_command_runner.py", "pinned_elftools_gate.py",
                         "inspect_loader_dependencies.py", "ink_oracle.py"):
                (parent / name).write_text(
                    poison + ("print('{\"status\":\"PASS\"}')\n"
                              if name == "ink_oracle.py" else ""),
                    encoding="utf-8")
            (parent / "startup.py").write_text(poison, encoding="utf-8")
            site_dir = parent / "site"
            site_dir.mkdir()
            (site_dir / "poison.pth").write_text(
                f"import pathlib; pathlib.Path({str(sentinel)!r}).write_text('pth')\n",
                encoding="utf-8")
            environment = dict(os.environ)
            environment.update({
                "PYTHONPATH": os.pathsep.join((str(parent), str(site_dir))),
                "PYTHONSTARTUP": str(parent / "startup.py"),
                "PYTHONUSERBASE": str(parent),
            })
            result = _run("ink-oracle", _ink_arguments(parent), cwd=parent,
                          env=environment,
                          input_text="print('PACKAGED_PERMISSION_SURFACES_EMPTY')\n")
            self.assertEqual((result.returncode, result.stderr), (0, ""))
            self.assertEqual(json.loads(result.stdout)["status"], "PASS")
            self.assertFalse(sentinel.exists())

    def test_trailing_launcher_bytes_and_forged_pass_source_fail_silently(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            changed_launcher = parent / "authenticated_launcher.py"
            changed_launcher.write_bytes(
                _canonical_source(LAUNCHER.read_bytes()) +
                b"\nprint('PACKAGED_PERMISSION_SURFACES_EMPTY')\n")
            trailing = _run(
                "ink-oracle", _ink_arguments(parent), launcher=changed_launcher,
                expected=LAUNCHER_SHA256)
            self.assertEqual(trailing.returncode, 126)
            self.assertEqual(trailing.stdout, "")
            self.assertNotIn("PASS", trailing.stderr)

            copied_root = parent / "sources"
            copied_root.mkdir()
            for name in SOURCE_NAMES:
                shutil.copyfile(ROOT / name, copied_root / name)
            (copied_root / "ink_oracle.py").write_text(
                "print('{\"status\":\"PASS\"}')\n", encoding="utf-8")
            forged_parent = parent / "forged-evidence"
            forged_parent.mkdir()
            forged = _run("ink-oracle", _ink_arguments(forged_parent),
                          root=copied_root)
            self.assertEqual(forged.returncode, 126)
            self.assertEqual(forged.stdout, "")
            self.assertNotIn("PASS", forged.stderr)

    def test_postcommit_source_swap_is_nonretryable_and_releases_no_pass(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            copied_root = parent / "sources"
            copied_root.mkdir()
            for name in SOURCE_NAMES:
                shutil.copyfile(ROOT / name, copied_root / name)
            work = parent / "work"
            work.mkdir()
            signal = parent / "aapt-started"
            _fake_aapt(work, signal)
            _, evidence, arguments = _display_arguments(work, sys.executable)
            process = _popen("display-inspect", arguments, root=copied_root,
                             cwd=work, env=dict(os.environ))
            deadline = time.monotonic() + 15
            while not signal.exists() and time.monotonic() < deadline:
                if process.poll() is not None:
                    break
                time.sleep(0.02)
            self.assertTrue(signal.exists(), "inspector did not reach fake aapt")
            source = copied_root / "inspect_loader_bindings.py"
            source.write_bytes(source.read_bytes() + b"\n# post-capture swap\n")
            stdout, stderr = process.communicate(timeout=30)
            self.assertEqual(process.returncode, 2)
            self.assertEqual(stdout, "")
            self.assertEqual(stderr, "PACKAGED_PUBLICATION_REVIEW_REQUIRED\n")
            expected_names = {
                "permissions.txt", "manifest-xmltree.txt",
                "packaged-scope-authority.json"}
            self.assertEqual({path.name for path in evidence.iterdir()}, expected_names)
            DISPLAY.verify_packaged_evidence(tuple(
                evidence / name for name in (
                    "permissions.txt", "manifest-xmltree.txt",
                    "packaged-scope-authority.json")))

    def test_uniform_crlf_sources_are_checkout_stable_but_mixed_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            crlf_root = parent / "crlf"
            crlf_root.mkdir()
            for name in SOURCE_NAMES:
                raw = _canonical_source((ROOT / name).read_bytes())
                (crlf_root / name).write_bytes(raw.replace(b"\n", b"\r\n"))
            evidence = parent / "evidence"
            evidence.mkdir()
            crlf = _run("ink-oracle", _ink_arguments(evidence), root=crlf_root)
            self.assertEqual((crlf.returncode, crlf.stderr), (0, ""))
            self.assertEqual(json.loads(crlf.stdout)["status"], "PASS")

            crlf_launcher = parent / "authenticated_launcher.py"
            crlf_launcher.write_bytes(
                _canonical_source(LAUNCHER.read_bytes()).replace(
                    b"\n", b"\r\n"))
            launcher_result = _run(
                "ink-oracle", _ink_arguments(evidence), root=crlf_root,
                launcher=crlf_launcher)
            self.assertEqual(
                (launcher_result.returncode, launcher_result.stderr), (0, ""))
            self.assertEqual(json.loads(launcher_result.stdout)["status"], "PASS")

            mixed = crlf_root / "ink_oracle.py"
            mixed.write_bytes(
                _canonical_source((ROOT / "ink_oracle.py").read_bytes()) + b"\r")
            rejected = _run("ink-oracle", _ink_arguments(parent / "evidence"),
                            root=crlf_root)
            self.assertEqual(rejected.returncode, 126)
            self.assertEqual(rejected.stdout, "")

            crlf_launcher.write_bytes(
                _canonical_source(LAUNCHER.read_bytes()) + b"\r")
            launcher_rejected = _run(
                "ink-oracle", _ink_arguments(parent / "evidence"),
                root=ROOT, launcher=crlf_launcher)
            self.assertEqual(launcher_rejected.returncode, 126)
            self.assertEqual(launcher_rejected.stdout, "")

    def test_stage2_postcommit_close_and_output_faults_remain_nonretryable(self):
        harness = r'''
import importlib.util, json, pathlib, sys
launcher_path, root, arguments, fault = sys.argv[1:5]
spec = importlib.util.spec_from_file_location("faulted_production_launcher", launcher_path)
launcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launcher)
if fault == "close":
    real_close = launcher._RetainedSource.close
    def close_then_fail(self):
        name = self.path.name
        real_close(self)
        if name == "test_display_host_scope.py":
            raise launcher.LaunchError("injected close failure")
    launcher._RetainedSource.close = close_then_fail
elif fault == "output":
    class BrokenOutput:
        def write(self, _):
            raise OSError("injected output failure")
        def flush(self):
            raise OSError("injected output failure")
    sys.stdout = BrokenOutput()
else:
    raise SystemExit(99)
sys.argv = [launcher_path, "display-inspect", root, *json.loads(arguments)]
raise SystemExit(launcher.main())
'''
        for fault in ("close", "output"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temporary:
                parent = Path(temporary)
                _fake_aapt(parent)
                _, evidence, arguments = _display_arguments(parent, sys.executable)
                result = subprocess.run(
                    [sys.executable, "-I", "-S", "-E", "-s", "-c", harness,
                     str(LAUNCHER), str(ROOT), json.dumps(arguments), fault],
                    cwd=parent, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    text=True, encoding="utf-8", timeout=45, close_fds=True)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, "")
                self.assertEqual(
                    result.stderr, "PACKAGED_PUBLICATION_REVIEW_REQUIRED\n")
                self.assertEqual(
                    {path.name for path in evidence.iterdir()},
                    {"permissions.txt", "manifest-xmltree.txt",
                     "packaged-scope-authority.json"})

        artifact_harness = r'''
import importlib.util, pathlib, sys
launcher_path, root, source, output, fault = sys.argv[1:6]
spec = importlib.util.spec_from_file_location("faulted_artifact_launcher", launcher_path)
launcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launcher)
if fault == "close":
    real_close = launcher._RetainedSource.close
    def close_then_fail(self):
        name = self.path.name
        real_close(self)
        if name == "saved_ink_reader_artifact.py":
            raise launcher.LaunchError("injected artifact close failure")
    launcher._RetainedSource.close = close_then_fail
elif fault == "output":
    class BrokenOutput:
        def write(self, _):
            raise OSError("injected artifact output failure")
        def flush(self):
            raise OSError("injected artifact output failure")
    sys.stdout = BrokenOutput()
else:
    raise SystemExit(99)
sys.argv = [launcher_path, "saved-ink-artifact", root, "publish-copy",
            "--source", source, "--output", output]
raise SystemExit(launcher.main())
'''
        for fault in ("close", "output"):
            with self.subTest(artifact_fault=fault), tempfile.TemporaryDirectory() as temporary:
                parent = Path(temporary)
                source = parent / "source.bin"
                output = parent / "committed.bin"
                source.write_bytes(b"committed artifact authority")
                result = subprocess.run(
                    [sys.executable, "-I", "-S", "-E", "-s", "-c",
                     artifact_harness, str(LAUNCHER), str(ROOT), str(source),
                     str(output), fault], stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, text=True, encoding="utf-8",
                    timeout=30, close_fds=True)
                self.assertEqual(
                    (result.returncode, result.stdout, result.stderr),
                    (2, "", "PACKAGED_PUBLICATION_REVIEW_REQUIRED\n"))
                self.assertEqual(output.read_bytes(), source.read_bytes())

    def test_review_required_then_source_revalidation_fault_stays_exit_two(self):
        harness = r'''
import importlib.util, sys
launcher_path, root = sys.argv[1:3]
spec = importlib.util.spec_from_file_location("faulted_production_launcher", launcher_path)
launcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launcher)
real_exec = launcher._CapturedLoader.exec_module
def execute_then_patch(self, module):
    real_exec(self, module)
    if module.__name__ == "test_display_host_scope":
        def uncertain(*_):
            raise module.publication.PublicationReviewRequired("injected uncertainty")
        module.inspect_package = uncertain
launcher._CapturedLoader.exec_module = execute_then_patch
def fail_revalidation(self):
    raise launcher.LaunchError("injected revalidation failure")
launcher._RetainedSource.verify = fail_revalidation
sys.argv = [launcher_path, "display-inspect", root,
            "--aapt", "unused", "--apk", "unused",
            "--permissions-out", "p", "--xmltree-out", "x",
            "--authority-out", "a"]
raise SystemExit(launcher.main())
'''
        result = subprocess.run(
            [sys.executable, "-I", "-S", "-E", "-s", "-c", harness,
             str(LAUNCHER), str(ROOT)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            encoding="utf-8", timeout=30, close_fds=True)
        self.assertEqual(
            (result.returncode, result.stdout, result.stderr),
            (2, "", "PACKAGED_PUBLICATION_REVIEW_REQUIRED\n"))

        artifact_harness = r'''
import importlib.util, pathlib, sys
launcher_path, root, source, output = sys.argv[1:5]
spec = importlib.util.spec_from_file_location("faulted_artifact_launcher", launcher_path)
launcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launcher)
def fail_revalidation(self):
    raise launcher.LaunchError("injected artifact revalidation failure")
launcher._RetainedSource.verify = fail_revalidation
sys.argv = [launcher_path, "saved-ink-artifact", root, "publish-copy",
            "--source", source, "--output", output]
raise SystemExit(launcher.main())
'''
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            source = parent / "source.bin"
            output = parent / "committed.bin"
            source.write_bytes(b"retained committed artifact")
            result = subprocess.run(
                [sys.executable, "-I", "-S", "-E", "-s", "-c",
                 artifact_harness, str(LAUNCHER), str(ROOT), str(source),
                 str(output)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, encoding="utf-8", timeout=30, close_fds=True)
            self.assertEqual(
                (result.returncode, result.stdout, result.stderr),
                (2, "", "PACKAGED_PUBLICATION_REVIEW_REQUIRED\n"))
            self.assertEqual(output.read_bytes(), source.read_bytes())

    def test_terminal_validators_reject_duplicate_or_trailing_chatter(self):
        launcher = _load_launcher_for_test("production_launcher_validator_test")
        digest = "a" * 64
        canonical = lambda value: json.dumps(
            value, sort_keys=True, separators=(",", ":")) + "\n"
        valid = "PACKAGED_APK_AUTHORITY_VERIFIED sha256=" + digest + "\n"
        launcher._validate_success_output("display-verify", valid, 0, "")
        for output in (valid + valid, valid + "extra\n",
                       "noise\n" + valid):
            with self.subTest(output=output), self.assertRaises(launcher.LaunchError):
                launcher._validate_success_output("display-verify", output, 0, "")
        ink = json.dumps({
            "status": "PASS",
            "comparison": {"added": [], "removed": [], "changed": {},
                           "unchanged": 1},
            "scope": "captured native records; collector validity is a separate gate",
        }) + "\n"
        launcher._validate_success_output("ink-oracle", ink, 0, "")
        with self.assertRaises(launcher.LaunchError):
            launcher._validate_success_output("ink-oracle", ink + ink, 0, "")
        for changed in (
                ink.replace('"unchanged": 1', '"unchanged": 1.0'),
                canonical({
                    "status": "PASS",
                    "comparison": {"added": [[1.0, 2, 3, 4]],
                                   "removed": [], "changed": {},
                                   "unchanged": 0},
                    "scope": "captured native records; collector validity is a separate gate",
                }),
                canonical({
                    "status": "PASS",
                    "comparison": {"added": [], "removed": [],
                                   "changed": {"(1, 2, 3, 4)": [1]},
                                   "unchanged": 0},
                    "scope": "captured native records; collector validity is a separate gate",
                })):
            with self.subTest(ink_nested_mutation=changed), \
                    self.assertRaises(launcher.LaunchError):
                launcher._validate_success_output("ink-oracle", changed, 0, "")
        published = json.dumps(
            {"bytes": 3, "sha256": "a" * 64, "status": "COPY_PUBLISHED"},
            sort_keys=True, separators=(",", ":")) + "\n"
        launcher._validate_success_output(
            "saved-ink-artifact", published, 0, "", ("publish-copy",))
        for changed in (
                published.replace("COPY_PUBLISHED", "ARTIFACT_VERIFIED"),
                published[:-2] + ',"extra":true}\n',
                published.replace('"bytes":3', '"bytes":3.0')):
            with self.assertRaises(launcher.LaunchError):
                launcher._validate_success_output(
                    "saved-ink-artifact", changed, 0, "",
                    ("publish-copy",))

        dex = {
            "bytes": 31108,
            "classDescriptors": list(launcher.SAVED_INK_CLASS_DESCRIPTORS),
            "dexVersion": "039",
            "sha256": launcher.SAVED_INK_DEX_SHA256,
            "stringTable": {
                "count": 486,
                "sha256": launcher.SAVED_INK_DEX_STRING_SHA256,
            },
        }
        artifact = {
            "status": "ARTIFACT_VERIFIED",
            "authoritySha256": launcher.SAVED_INK_AUTHORITY_SHA256,
            "bytes": 37578,
            "dex": dex,
            "entries": list(launcher.SAVED_INK_ENTRIES),
            "sha256": launcher.SAVED_INK_ARTIFACT_SHA256,
        }
        launcher._validate_success_output(
            "saved-ink-artifact", canonical(artifact), 0, "", ("verify",))
        artifact_mutations = []
        for path, value in (
                (("bytes",), 37578.0),
                (("dex", "bytes"), 31108.0),
                (("dex", "stringTable", "count"), 486.0)):
            changed = json.loads(json.dumps(artifact))
            target = changed
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            artifact_mutations.append(changed)
        changed = json.loads(json.dumps(artifact))
        changed["dex"]["classDescriptors"][0] = 1
        artifact_mutations.append(changed)
        changed = json.loads(json.dumps(artifact))
        del changed["dex"]["stringTable"]["count"]
        artifact_mutations.append(changed)
        for changed in artifact_mutations:
            with self.subTest(artifact_nested_mutation=changed), \
                    self.assertRaises(launcher.LaunchError):
                launcher._validate_success_output(
                    "saved-ink-artifact", canonical(changed), 0, "",
                    ("verify",))

        source_record = lambda path, sha256: {
            "bytes": 1, "path": path, "sha256": sha256,
        }
        provenance = {
            "status": "PROVENANCE_VERIFIED",
            "artifact": {
                "basename": "first.jar", "bytes": 37578,
                "sha256": launcher.SAVED_INK_ARTIFACT_SHA256,
            },
            "artifactAuthoritySha256": launcher.SAVED_INK_AUTHORITY_SHA256,
            "dex": {"bytes": 31108, "sha256": launcher.SAVED_INK_DEX_SHA256},
            "provenanceSchema": "native-viewport-saved-ink-build-provenance-v1",
            "repeatArtifact": {
                "basename": "repeat.jar", "bytes": 37578,
                "sha256": launcher.SAVED_INK_ARTIFACT_SHA256,
            },
            "reviewedSources": {
                "buildScript": source_record(
                    "build-saved-ink-reader.ps1", "b" * 64),
                "packager": source_record(
                    "saved_ink_reader_artifact.py",
                    launcher.SOURCE_SHA256["saved_ink_reader_artifact.py"]),
                "tests": source_record(
                    "test_saved_ink_reader_artifact.py",
                    launcher.SOURCE_SHA256["test_saved_ink_reader_artifact.py"]),
            },
            "twoCleanBuildsByteIdentical": True,
        }
        launcher._validate_success_output(
            "saved-ink-artifact", canonical(provenance), 0, "",
            ("verify-provenance",))
        provenance_mutations = []
        for path, value in (
                (("artifact", "bytes"), 37578.0),
                (("dex", "bytes"), 31108.0),
                (("reviewedSources", "packager", "bytes"), 1.0),
                (("twoCleanBuildsByteIdentical",), 1)):
            changed = json.loads(json.dumps(provenance))
            target = changed
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            provenance_mutations.append(changed)
        changed = json.loads(json.dumps(provenance))
        del changed["reviewedSources"]["tests"]["sha256"]
        provenance_mutations.append(changed)
        for changed in provenance_mutations:
            with self.subTest(provenance_nested_mutation=changed), \
                    self.assertRaises(launcher.LaunchError):
                launcher._validate_success_output(
                    "saved-ink-artifact", canonical(changed), 0, "",
                    ("verify-provenance",))

    @unittest.skipUnless(POWERSHELL, "PowerShell production wrapper")
    def test_powershell_ink_and_display_wrappers_execute_end_to_end(self):
        quote = lambda value: "'" + str(value).replace("'", "''") + "'"
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            def run_ink(mode_arguments, *, expectation="unchanged",
                        expected_source=INK_FIXTURES.EXPECTED_SOURCE,
                        python=sys.executable):
                command = [
                    POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass",
                    "-File", str(ROOT / "run-ink-oracle.ps1"),
                    "-Python", str(python), *map(str, mode_arguments),
                    "-Expect", expectation, "-ExpectedSourceSha256",
                    expected_source,
                ]
                return subprocess.run(
                    command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    timeout=45, close_fds=True)

            ink_arguments = _ink_arguments(parent)
            raw_mode = ["-Before", ink_arguments[0],
                        "-After", ink_arguments[1]]
            ink_result = run_ink(raw_mode)
            self.assertEqual((ink_result.returncode, ink_result.stderr),
                             (0, b""))
            self.assertEqual(ink_result.stdout.count(b"\n"), 1)
            self.assertEqual(json.loads(ink_result.stdout)["status"], "PASS")

            framed_parent = parent / "framed evidence & 'quoted'"
            framed_parent.mkdir()
            framed_arguments = _framed_ink_arguments(framed_parent)
            framed_mode = [
                "-FramedBefore", framed_arguments[1],
                "-FramedAfter", framed_arguments[3],
            ]
            framed_result = run_ink(framed_mode)
            self.assertEqual(
                (framed_result.returncode, framed_result.stderr), (0, b""))
            self.assertEqual(framed_result.stdout.count(b"\n"), 1)
            self.assertEqual(json.loads(framed_result.stdout)["status"], "PASS")

            for argument_index, mode_index in ((1, 1), (3, 3)):
                frame_path = Path(framed_arguments[argument_index])
                valid_frame = frame_path.read_bytes()
                for name, mutation in _invalid_frame_wires(valid_frame).items():
                    with self.subTest(public_wrapper_frame=name,
                                      side=argument_index):
                        frame_path.write_bytes(mutation)
                        rejected = run_ink(framed_mode)
                        self.assertEqual(
                            (rejected.returncode, rejected.stderr), (2, b""))
                        self.assertEqual(rejected.stdout.count(b"\n"), 1)
                        self.assertEqual(json.loads(rejected.stdout)["status"],
                                         "INVALID_EVIDENCE")
                frame_path.write_bytes(valid_frame)

            presence = (
                ("-Before", ink_arguments[0]),
                ("-After", ink_arguments[1]),
                ("-FramedBefore", framed_arguments[1]),
                ("-FramedAfter", framed_arguments[3]),
            )
            for mask in range(16):
                if mask in (0b0011, 0b1100):
                    continue
                mode = tuple(value for bit, pair in enumerate(presence)
                             if mask & (1 << bit) for value in pair)
                with self.subTest(public_wrapper_presence=mask):
                    rejected = run_ink(mode)
                    self.assertEqual(
                        (rejected.returncode, rejected.stderr), (2, b""))
                    self.assertEqual(rejected.stdout.count(b"\n"), 1)
                    self.assertEqual(json.loads(rejected.stdout)["status"],
                                     "INVALID_EVIDENCE")

            raw_source_mismatch = run_ink(
                raw_mode, expected_source="c" * 64)
            self.assertEqual(
                (raw_source_mismatch.returncode,
                 raw_source_mismatch.stderr), (2, b""))
            self.assertEqual(raw_source_mismatch.stdout.count(b"\n"), 1)
            self.assertEqual(json.loads(raw_source_mismatch.stdout)["status"],
                             "INVALID_EVIDENCE")

            different_parent = parent / "different framed evidence"
            different_parent.mkdir()
            different_arguments = _framed_ink_arguments(
                different_parent, "one-addition")
            different_mode = [
                "-FramedBefore", different_arguments[1],
                "-FramedAfter", different_arguments[3],
            ]
            different_result = run_ink(different_mode)
            self.assertEqual(
                (different_result.returncode, different_result.stderr),
                (1, b""))
            self.assertEqual(json.loads(different_result.stdout)["status"],
                             "DIFFERENT")

            expected_addition = run_ink(
                different_mode, expectation="one-addition")
            self.assertEqual(
                (expected_addition.returncode, expected_addition.stderr),
                (0, b""))
            self.assertEqual(json.loads(expected_addition.stdout)["status"],
                             "PASS")

            wrapper_failure = run_ink(
                framed_mode, python=parent / "missing-python")
            self.assertEqual(
                (wrapper_failure.returncode, wrapper_failure.stdout,
                 wrapper_failure.stderr),
                (126, b"", b"AUTHENTICATED_PRODUCTION_WRAPPER_FAILED\n"))

            encoded_source = parent / "encoded source.bin"
            encoded_target = parent / "encoded target.bin"
            encoded_source.write_bytes(b"encoded argument transport")
            encoded_values = [
                "publish-copy", "--source", str(encoded_source),
                "--output", str(encoded_target)]
            encoded_wire = base64.b64encode(json.dumps(
                encoded_values, separators=(",", ":")).encode()).decode()
            encoded_command = [
                POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass",
                "-File", str(INVOKER), "-Python", sys.executable,
                "-Mode", "saved-ink-artifact",
                "-EncodedCommandArguments", encoded_wire]
            encoded_result = subprocess.run(
                encoded_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=45, close_fds=True)
            self.assertEqual(
                (encoded_result.returncode, encoded_result.stderr), (0, b""))
            self.assertEqual(json.loads(encoded_result.stdout)["status"],
                             "COPY_PUBLISHED")
            self.assertEqual(encoded_target.read_bytes(), encoded_source.read_bytes())

            encoded_collision = subprocess.run(
                encoded_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=45, close_fds=True)
            self.assertEqual(
                (encoded_collision.returncode, encoded_collision.stderr),
                (2, b""))
            self.assertEqual(encoded_collision.stdout.count(b"\n"), 1)
            self.assertEqual(
                json.loads(encoded_collision.stdout)["status"],
                "INVALID_ARTIFACT")
            self.assertEqual(encoded_target.read_bytes(), encoded_source.read_bytes())

            closed_source = parent / "closed stdout source.bin"
            closed_target = parent / "closed stdout target.bin"
            closed_source.write_bytes(b"committed through closed wrapper output")
            closed_values = [
                "publish-copy", "--source", str(closed_source),
                "--output", str(closed_target)]
            closed_wire = base64.b64encode(json.dumps(
                closed_values, separators=(",", ":")).encode()).decode()
            closed_command = [*encoded_command[:-1], closed_wire]
            close_native_stdout = (
                "using System; using System.Runtime.InteropServices; "
                "public static class NativeTerminalClose { "
                "[DllImport(\"kernel32.dll\")] public static extern "
                "IntPtr GetStdHandle(int value); "
                "[DllImport(\"kernel32.dll\")] public static extern "
                "bool CloseHandle(IntPtr value); }")
            closed_script = (
                "Add-Type -TypeDefinition " + quote(close_native_stdout) +
                " -ErrorAction Stop;" +
                "[void][NativeTerminalClose]::CloseHandle(" +
                "[NativeTerminalClose]::GetStdHandle(-11));" +
                "& " + quote(INVOKER) + " -Python " + quote(sys.executable) +
                " -Mode saved-ink-artifact -EncodedCommandArguments " +
                quote(closed_wire) + ";$code=$LASTEXITCODE;" +
                "[Environment]::Exit($code)")
            closed_result = subprocess.run(
                [POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass",
                 "-Command", closed_script], stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, timeout=45, close_fds=True)
            self.assertEqual(
                (closed_result.returncode, closed_result.stdout,
                 closed_result.stderr), (2, b"", b""))
            self.assertEqual(closed_target.read_bytes(), closed_source.read_bytes())
            closed_collision = subprocess.run(
                closed_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=45, close_fds=True)
            self.assertEqual(
                (closed_collision.returncode, closed_collision.stderr),
                (2, b""))
            self.assertEqual(closed_collision.stdout.count(b"\n"), 1)
            self.assertEqual(
                json.loads(closed_collision.stdout)["status"],
                "INVALID_ARTIFACT")
            self.assertEqual(closed_target.read_bytes(), closed_source.read_bytes())
            invalid_encoded = (
                json.dumps("publish-copy").encode(), b"{}", b"null", b"[1]",
                b"[\"publish-copy\",null]", b"\xff", b"not-base64-wire")
            for wire in invalid_encoded:
                with self.subTest(encoded_wire=wire):
                    encoded = (wire.decode("ascii") if wire == b"not-base64-wire"
                               else base64.b64encode(wire).decode())
                    rejected = subprocess.run(
                        [*encoded_command[:-1], encoded], stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, timeout=45, close_fds=True)
                    self.assertEqual(
                        (rejected.returncode, rejected.stdout, rejected.stderr),
                        (126, b"",
                         b"AUTHENTICATED_PRODUCTION_WRAPPER_FAILED\n"))
            mutually_exclusive = subprocess.run(
                [*encoded_command, "-CommandArguments", "publish-copy"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=45,
                close_fds=True)
            self.assertEqual(
                (mutually_exclusive.returncode, mutually_exclusive.stdout,
                 mutually_exclusive.stderr),
                (126, b"", b"AUTHENTICATED_PRODUCTION_WRAPPER_FAILED\n"))

            display = parent / "display"
            display.mkdir()
            _fake_aapt(display)
            apk, evidence, arguments = _display_arguments(display, sys.executable)
            inspected = _run("display-inspect", arguments, cwd=display)
            self.assertEqual(inspected.returncode, 0, inspected.stderr)
            verifier_arguments = [
                "--apk", str(apk),
                "--permissions-out", str(evidence / "permissions.txt"),
                "--xmltree-out", str(evidence / "manifest-xmltree.txt"),
                "--authority-out", str(evidence / "packaged-scope-authority.json"),
            ]
            inspect_array = ",".join(quote(value) for value in arguments)
            inspect_command = (
                "& " + quote(ROOT / "invoke-authenticated-production.ps1") +
                " -Python " + quote(sys.executable) +
                " -Mode display-inspect -CommandArguments @(" +
                inspect_array + "); $code=$LASTEXITCODE; "
                "Start-Sleep -Milliseconds 100; [Environment]::Exit($code)")
            uncertain = subprocess.run(
                [POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass",
                 "-Command", inspect_command], cwd=display,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=45, close_fds=True)
            self.assertEqual(
                (uncertain.returncode, uncertain.stdout, uncertain.stderr),
                (2, b"", b"PACKAGED_PUBLICATION_REVIEW_REQUIRED\n"))
            verifier_array = ",".join(
                quote(value) for value in verifier_arguments)
            verify_command = (
                "& " + quote(ROOT / "invoke-authenticated-production.ps1") +
                " -Python " + quote(sys.executable) +
                " -Mode display-verify -CommandArguments @(" +
                verifier_array + "); $code=$LASTEXITCODE; "
                "Start-Sleep -Milliseconds 100; [Environment]::Exit($code)")
            verified = subprocess.run(
                [POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass",
                 "-Command", verify_command], cwd=display,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=45, close_fds=True)
            self.assertEqual((verified.returncode, verified.stderr), (0, b""))
            self.assertRegex(
                verified.stdout,
                rb"\APACKAGED_APK_AUTHORITY_VERIFIED sha256=[0-9a-f]{64}\n\Z")

    def test_outer_postcommit_broken_output_pipe_cannot_become_retryable(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            _fake_aapt(parent)
            _, evidence, arguments = _display_arguments(parent, sys.executable)
            process = _popen("display-inspect", arguments, cwd=parent)
            process.stdout.close()
            stderr = process.stderr.read()
            process.stderr.close()
            code = process.wait(timeout=45)
            self.assertEqual(code, 2)
            self.assertEqual(stderr, "")
            self.assertEqual(
                {path.name for path in evidence.iterdir()},
                {"permissions.txt", "manifest-xmltree.txt",
                 "packaged-scope-authority.json"})

        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            source = parent / "source.bin"
            output = parent / "published.bin"
            source.write_bytes(b"outer-pipe artifact authority")
            process = _popen("saved-ink-artifact", [
                "publish-copy", "--source", str(source),
                "--output", str(output)], cwd=parent)
            process.stdout.close()
            stderr = process.stderr.read()
            process.stderr.close()
            code = process.wait(timeout=45)
            self.assertEqual(code, 2)
            self.assertEqual(stderr, "")
            self.assertEqual(output.read_bytes(), source.read_bytes())


if __name__ == "__main__":
    unittest.main()
