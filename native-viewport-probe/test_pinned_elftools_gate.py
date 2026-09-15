"""Adversarial checks for the authenticated pyelftools source loader."""
import contextlib
import hashlib
import importlib.util
import json
import marshal
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch

import pinned_elftools_gate as gate


def write_valid_poisoned_cache(source, statement):
    cache = Path(importlib.util.cache_from_source(str(source)))
    cache.parent.mkdir()
    metadata = source.stat()
    code = compile(statement, str(source), "exec")
    cache.write_bytes(
        importlib.util.MAGIC_NUMBER + struct.pack(
            "<III", 0, int(metadata.st_mtime), metadata.st_size) +
        marshal.dumps(code))
    return cache


def pinned_python_root():
    return Path(os.environ.get(
        gate.AUTHENTICATED_ROOT_ENV,
        str(Path(__file__).resolve().parents[3] / "tools" / "python")))


def write_probe_fixture(root, relative_name, payload):
    path = root / relative_name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return path


_CAPTURED_GATE_BOOTSTRAP = r'''
import hashlib, sys, types

def read_exact(count):
    chunks = []
    while count:
        chunk = sys.stdin.buffer.read(count)
        if not chunk:
            raise SystemExit(125)
        chunks.append(chunk)
        count -= len(chunk)
    return b"".join(chunks)

header = read_exact(8)
length = int.from_bytes(header, "big")
if length <= 0 or length > 1024 * 1024:
    raise SystemExit(125)
raw = read_exact(length)
if sys.stdin.buffer.read(1) or hashlib.sha256(raw).hexdigest() != sys.argv[1]:
    raise SystemExit(126)
source_path = sys.argv[2]
sys.argv = [source_path] + sys.argv[3:]
main = types.ModuleType("__main__")
main.__file__ = source_path
main.__package__ = ""
main._rtl_reader_authenticated_gate_source = raw
sys.modules["__main__"] = main
exec(compile(raw, source_path, "exec", dont_inherit=True), main.__dict__,
     main.__dict__)
'''


def _captured_probe_source(module_name, fallback_path):
    """Use the outer authenticated gate snapshot when one is active."""
    current_loader = getattr(globals().get("__spec__"), "loader", None)
    authority = getattr(current_loader, "authority_sha256", None)
    if authority is not None:
        matches = []
        for finder in sys.meta_path:
            if getattr(finder, "authority_sha256", None) != authority:
                continue
            captured = getattr(finder, "sources", {}).get(module_name)
            if captured is not None:
                matches.append(captured)
        if len(matches) != 1:
            raise AssertionError("authenticated probe source snapshot is unavailable")
        _source, raw, is_package = matches[0]
        if type(raw) is not bytes or is_package:
            raise AssertionError("authenticated probe source snapshot is invalid")
        return raw
    raw = gate._read_regular_source(Path(fallback_path), gate.MAX_PROBE_FILE_BYTES)
    return gate._canonical_python_source(raw)


def _manifest_snapshot():
    path = Path(gate.__file__).absolute().with_name(
        "pinned_elftools_manifest.json")
    raw = gate._read_regular_source(path, gate.MAX_MANIFEST_BYTES)
    value = gate._strict_json(raw)
    canonical = json.dumps(
        value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True).encode("ascii")
    if hashlib.sha256(canonical).hexdigest() != gate.EXPECTED_MANIFEST_SHA256:
        raise AssertionError("authenticated manifest snapshot changed")
    return raw


def _run_captured_gate(runtime_root, arguments):
    """Run captured gate bytes while its display pathname is malicious."""
    source = _captured_probe_source(
        "pinned_elftools_gate", Path(gate.__file__).absolute())
    source_digest = hashlib.sha256(source).hexdigest()
    runtime_root.mkdir()
    display_path = runtime_root / "pinned_elftools_gate.py"
    sentinel = runtime_root / "mutable-gate-path-executed"
    display_path.write_text(
        "from pathlib import Path\nPath(" + repr(str(sentinel)) +
        ").write_text('executed')\n", encoding="utf-8")
    (runtime_root / "pinned_elftools_manifest.json").write_bytes(
        _manifest_snapshot())
    result = subprocess.run([
        sys.executable, "-I", "-S", "-E", "-s", "-c",
        _CAPTURED_GATE_BOOTSTRAP, source_digest, str(display_path), *arguments,
    ], input=len(source).to_bytes(8, "big") + source,
       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
       check=False)
    return result, sentinel


class PinnedElftoolsGateTests(unittest.TestCase):
    def test_host_launchers_authenticate_captured_gate_before_execution(self):
        probe_root = Path(__file__).resolve().parent
        self.assertEqual(len(gate.EXPECTED_PROBE_MODULES), 15)
        self.assertIn("saved_ink_reader_artifact.py",
                      gate.EXPECTED_PROBE_MODULES)
        self.assertIn("test_saved_ink_reader_artifact.py",
                      gate.EXPECTED_PROBE_MODULES)
        current_loader = getattr(globals().get("__spec__"), "loader", None)
        if getattr(current_loader, "authority_sha256", None) is not None:
            authenticated_gate = getattr(current_loader, "gate_authority", None)
            self.assertIsNotNone(authenticated_gate)
            probe_sources, probe_digest = authenticated_gate._probe_source_snapshot(
                probe_root)
            core_suite = authenticated_gate._authenticated_test_suite(
                probe_sources, probe_digest)
            self.assertEqual(core_suite.countTestCases(), 222)
            self.assertFalse(any(
                case.id().startswith("test_saved_ink_reader_artifact.")
                for group in core_suite for case in group))
        powershell = gate._canonical_python_source(
            (probe_root / "check.ps1").read_bytes()).decode("utf-8")
        linux = gate._canonical_python_source(
            (probe_root / "run-loader-linux-tests.sh").read_bytes()).decode("utf-8")
        powershell_match = re.search(
            r"\$gateBootstrap=@'\n(.*?)\n'@", powershell, re.DOTALL)
        linux_match = re.search(
            r"IFS= read -r -d '' gate_bootstrap <<'PY' \|\| true\n(.*?)\nPY\n",
            linux, re.DOTALL)
        self.assertIsNotNone(powershell_match)
        self.assertIsNotNone(linux_match)
        bootstrap = powershell_match.group(1)
        self.assertEqual(bootstrap, linux_match.group(1))
        self.assertIn("-c $gateTransport", powershell)
        self.assertIn("ToBase64String($gateBootstrapBytes)", powershell)
        self.assertIn('-c "$gate_bootstrap"', linux)
        self.assertIn("[IO.FileShare]::Read", powershell)
        self.assertIn("'-File',$savedInkBuilder", powershell)
        self.assertIn("RedirectStandardInput=$false", powershell)
        self.assertNotIn("[char]0xfeff", powershell)
        self.assertNotIn("[ScriptBlock]::Create", powershell)
        self.assertIn("Ran 234 tests", powershell)
        self.assertIn("PINNED_SAVED_INK_DEVICE_ARTIFACT", powershell)
        for option in (
                "--saved-ink-device-artifact",
                "--saved-ink-repeat-artifact",
                "--saved-ink-provenance",
                "--saved-ink-build-script"):
            self.assertIn(option, powershell)
            self.assertNotIn(option, linux)
        self.assertIn("Ran 222 tests", linux)
        self.assertNotIn("PINNED_SAVED_INK_DEVICE_ARTIFACT", linux)
        self.assertNotIn("test_saved_ink_reader_artifact.py", powershell)

        gate_path = probe_root / "pinned_elftools_gate.py"
        expected = hashlib.sha256(gate._canonical_python_source(
            gate_path.read_bytes())).hexdigest()
        self.assertEqual(
            expected,
            "ff7021874c16321f71b4309e131d78061d0d71c4cd6d14743574fc4eb229cd2f")
        self.assertIn(expected, powershell)
        self.assertIn(expected, linux)
        powershell_probe = re.search(
            r"\$expectedProbeSha256='([0-9a-f]{64})'", powershell)
        linux_probe = re.search(
            r'expected_probe_sha256="([0-9a-f]{64})"', linux)
        self.assertIsNotNone(powershell_probe)
        self.assertIsNotNone(linux_probe)
        expected_probe_sha256 = powershell_probe.group(1)
        self.assertEqual(expected_probe_sha256, linux_probe.group(1))

        authentic = subprocess.run([
            sys.executable, "-I", "-S", "-E", "-s", "-c", bootstrap,
            str(gate_path), expected, "65536", "--help",
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
           check=False)
        self.assertEqual(authentic.returncode, 0, authentic.stderr.decode(
            errors="replace"))
        self.assertIn(b"usage:", authentic.stdout)

        pinned_parser = (
            'PINNED_ELFTOOLS {"files":54,"sha256":'
            '"09679ad9ea7781df8fe3ef1d39b2189261f57967e06c549ce2891b977018382a",'
            '"version":"0.32"}')
        pinned_probe = (
            'PINNED_PROBE_SOURCES {"files":15,"sha256":'
            f'"{expected_probe_sha256}"}}')
        pinned_saved_ink = (
            'PINNED_SAVED_INK_GOLDEN {"frameBytes":2562,"payloadBytes":2532,'
            '"payloadSha256":'
            '"20a179534dfce744b9be97e8e40c1ab07ef19e1c1ddb618ed38f58002e648158"}')
        windows_skips = (
            "POSIX package-name replacement fault",
            "POSIX same-content name ABA fault",
            "POSIX partial-publication preservation",
            "POSIX post-link rollback race",
            "POSIX original-inode name ABA fault",
            "POSIX retained-parent swap",
            "POSIX process-group contract",
            "POSIX child-reaper contract",
            "POSIX nonblocking-pipe contract",
            "POSIX nonblocking authenticated-runner open",
            "POSIX nonblocking source-open races",
            "POSIX no-follow source-open race",
            "POSIX permits an OS-backed same-inode mutation",
            "POSIX outer-supervision contract",
            "POSIX no-follow ancestor walk",
            "Linux immutable memfd contract",
            "Linux post-fork cleanup fault",
            "Linux pre-exec deadline gate",
            "POSIX signal-fault retirement",
            "POSIX retained-directory authority",
        )
        linux_skips = (
            "Windows alternate data streams",
            "Windows output ADS rejection",
            "Windows packaged-APK ADS rejection",
            "Windows packaged-evidence crash boundaries",
            "Windows packaged-output ADS rejection",
            "Windows retained handle denies writers",
            "Windows retained-parent and rollback",
            "Windows source name/content pinning",
            "PowerShell production wrapper",
        )
        forged_wires = (
            tuple(f"forged ... skipped '{reason}'" for reason in windows_skips) + (
                "Ran 222 tests in 0.001s",
                "OK (skipped=20)",
                pinned_parser,
                pinned_probe,
                pinned_saved_ink,
            ),
            tuple(f"forged ... skipped '{reason}'" for reason in linux_skips) + (
                "Ran 222 tests in 0.001s",
                "OK (skipped=9)",
                pinned_parser,
                pinned_probe,
            ),
        )
        with tempfile.TemporaryDirectory() as temp:
            replacement = Path(temp) / "pinned_elftools_gate.py"
            for index, lines in enumerate(forged_wires):
                with self.subTest(platform=("windows", "linux")[index]):
                    wire = ("\n".join(lines) + "\n").encode("utf-8")
                    replacement.write_text(
                        "import sys\n"
                        f"sys.stdout.buffer.write({wire!r})\n",
                        encoding="utf-8")
                    direct = subprocess.run([
                        sys.executable, "-I", "-S", "-E", "-s",
                        str(replacement), "--help",
                    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
                       check=False)
                    self.assertEqual(direct.returncode, 0)
                    self.assertEqual(direct.stdout, wire)
                    forged = subprocess.run([
                        sys.executable, "-I", "-S", "-E", "-s", "-c", bootstrap,
                        str(replacement), expected, "65536", "--help",
                    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
                       check=False)
                    self.assertEqual(forged.returncode, 126)
                    self.assertEqual(forged.stdout, b"")

        # The optional artifact lane is all-or-nothing before any parser-tree
        # authentication, so no partial caller can accidentally run the core
        # suite and present that result as artifact validation.
        with patch.object(sys, "argv", [
                "pinned_elftools_gate.py", "--python-path", str(pinned_python_root()),
                "--probe-root", str(probe_root), "--expected-probe-sha256",
                "0" * 64, "--saved-ink-device-artifact", "forged.jar"]):
            with self.assertRaisesRegex(
                    RuntimeError, "all saved-ink artifact paths are required"):
                gate.main()

        # Even authenticated module identities and a forged PASS-looking file
        # cannot replace the captured reviewed-source records in provenance.
        authority = "a" * 64
        with tempfile.TemporaryDirectory() as temp:
            temp_root = Path(temp)
            packager_path = temp_root / "saved_ink_reader_artifact.py"
            tests_path = temp_root / "test_saved_ink_reader_artifact.py"
            build_path = temp_root / "build-saved-ink-reader.ps1"
            artifact_path = temp_root / "saved-ink-reader-v2.jar"
            repeat_path = temp_root / "repeat.jar"
            provenance_path = temp_root / "provenance.json"
            packager_raw = b"# captured packager\n"
            tests_raw = b"# captured tests\n"
            build_path.write_bytes(b"# captured builder\n")
            artifact_path.write_bytes(b"artifact")
            repeat_path.write_bytes(b"artifact")
            provenance_path.write_text(
                "PINNED_SAVED_INK_DEVICE_ARTIFACT forged PASS\n",
                encoding="utf-8")

            artifact_module = types.ModuleType("saved_ink_reader_artifact")
            artifact_module.__spec__ = types.SimpleNamespace(loader=
                gate._PinnedSourceLoader(
                    packager_path, packager_raw, False, authority))
            artifact_module.verify_final_artifact = lambda *_args: {
                "bytes": 8, "sha256": "0" * 64,
                "authoritySha256": "1" * 64,
                "dex": {"bytes": 1, "sha256": "2" * 64},
            }
            artifact_module.verify_provenance = lambda *_args: {
                "reviewedSources": {"forged": True},
                "twoCleanBuildsByteIdentical": True,
            }
            test_module = types.ModuleType("test_saved_ink_reader_artifact")
            test_module.__spec__ = types.SimpleNamespace(loader=
                gate._PinnedSourceLoader(
                    tests_path, tests_raw, False, authority))
            test_module.GeneratedArtifactTests = unittest.TestCase
            probe_sources = {
                "saved_ink_reader_artifact":
                    (packager_path, packager_raw, False),
                "test_saved_ink_reader_artifact":
                    (tests_path, tests_raw, False),
            }
            modules = {
                "saved_ink_reader_artifact": artifact_module,
                "test_saved_ink_reader_artifact": test_module,
            }
            with patch.object(
                    gate.importlib, "import_module",
                    side_effect=lambda name: modules[name]):
                with self.assertRaisesRegex(
                        RuntimeError,
                        "provenance differs from captured reviewed sources"):
                    gate._saved_ink_artifact_suite(
                        probe_sources, authority, artifact_path, repeat_path,
                        provenance_path, build_path)

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "mkfifo"),
                         "POSIX nonblocking source-open races")
    def test_manifest_tree_and_probe_snapshot_reject_replaced_fifo_promptly(self):
        real_read = gate._read_regular_source

        def run(surface):
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                if surface == "manifest":
                    anchor = root / "pinned_elftools_gate.py"
                    source = root / "pinned_elftools_manifest.json"
                    anchor.write_bytes(b"")
                    source.write_bytes(b"{}")
                    invoke = lambda: gate._load_expected_files()
                    contexts = (patch.object(gate, "__file__", str(anchor)),)
                elif surface == "tree":
                    package = root / "elftools"
                    package.mkdir()
                    source = package / "__init__.py"
                    source.write_bytes(b"")
                    invoke = lambda: gate._tree_snapshot(root)
                    contexts = (patch.object(gate, "_load_expected_files",
                        return_value={"__init__.py": (0, hashlib.sha256(b"").hexdigest())}),)
                else:
                    source = root / "sample_probe.py"
                    source.write_bytes(b"VALUE = 1\n")
                    invoke = lambda: gate._probe_source_snapshot(
                        root, {source.name})
                    contexts = ()
                replaced = False

                def replace_with_fifo(path, limit, expected_size=None):
                    nonlocal replaced
                    if not replaced and Path(path) == source:
                        replaced = True
                        source.unlink()
                        os.mkfifo(source)
                    return real_read(path, limit, expected_size)

                started = time.monotonic()
                with contextlib.ExitStack() as stack:
                    for context in contexts:
                        stack.enter_context(context)
                    stack.enter_context(patch.object(
                        gate, "_read_regular_source",
                        side_effect=replace_with_fifo))
                    with self.assertRaises(RuntimeError):
                        invoke()
                self.assertTrue(replaced)
                self.assertLess(time.monotonic() - started, 1)

        for surface in ("manifest", "tree", "probe"):
            with self.subTest(surface=surface):
                run(surface)

    @unittest.skipUnless(os.name == "posix",
                         "POSIX no-follow source-open race")
    def test_source_open_rejects_symlink_and_nonregular_leaf(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "target.py"
            target.write_bytes(b"VALUE = 1\n")
            link = root / "linked.py"
            link.symlink_to(target)
            directory = root / "directory.py"
            directory.mkdir()
            for path in (link, directory):
                with self.subTest(path=path.name), self.assertRaises(RuntimeError):
                    gate._read_regular_source(path, 1024)

    def test_source_snapshot_ignores_poisoned_bytecode(self):
        with tempfile.TemporaryDirectory() as temp:
            package = Path(temp) / "elftools"
            package.mkdir()
            source = package / "__init__.py"
            source.write_bytes(b"VALUE = 'authenticated-source'\n")
            cache = write_valid_poisoned_cache(
                source, "VALUE = 'unauthenticated-bytecode'\n")

            default_spec = importlib.util.spec_from_file_location(
                "default_elftools_probe", source,
                submodule_search_locations=[str(package)])
            default_module = importlib.util.module_from_spec(default_spec)
            default_spec.loader.exec_module(default_module)
            self.assertEqual(default_module.VALUE, "unauthenticated-bytecode")

            trusted = source.read_bytes()
            finder = gate._PinnedSourceFinder(
                {"elftools": (source.resolve(strict=True), trusted, True)},
                "0" * 64)
            spec = finder.find_spec("elftools")
            self.assertIsNotNone(spec)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            self.assertEqual(module.VALUE, "authenticated-source")
            self.assertIsNone(module.__cached__)
            self.assertTrue(cache.is_file())

    def test_probe_snapshot_and_authenticated_fixtures_ignore_ambient_code(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "sample_probe.py"
            source.write_bytes(b"VALUE = 'reviewed-probe-source'\n")
            cache = write_valid_poisoned_cache(
                source, "VALUE = 'unreviewed-probe-bytecode'\n")

            default_spec = importlib.util.spec_from_file_location(
                "default_sample_probe", source)
            default_module = importlib.util.module_from_spec(default_spec)
            default_spec.loader.exec_module(default_module)
            self.assertEqual(default_module.VALUE, "unreviewed-probe-bytecode")

            sources, digest = gate._probe_source_snapshot(
                root, {source.name})
            finder = gate._PinnedSourceFinder(sources, digest)
            spec = finder.find_spec("sample_probe")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            self.assertEqual(module.VALUE, "reviewed-probe-source")
            self.assertIsNone(module.__cached__)
            self.assertTrue(cache.is_file())

        test_source = _captured_probe_source(
            "test_authenticated_launcher",
            Path(__file__).resolve().parent / "production-launch" /
            "test_authenticated_launcher.py")

        def import_authenticated_test(root, poison_kind, forged_oracle=False):
            authority = "a" * 64
            gate_authority = object()
            gate_source = b"authenticated-gate"
            gate_method = object()
            invoker = root / "invoke-authenticated-production.ps1"
            invoker.write_text(
                "$expectedLauncherSha256='" + "0" * 64 + "'\n"
                "$bootstrap=@'\npass\n'@\n", encoding="utf-8")
            launcher_test = write_probe_fixture(
                root, "production-launch/test_authenticated_launcher.py",
                test_source)
            oracle_source = write_probe_fixture(
                root, "ink_oracle.py",
                b"import secrets\nSECRETS_ORIGIN = getattr(secrets, '__file__', None)\n")
            display_source = write_probe_fixture(
                root, "test_display_host_scope.py", b"")
            ink_test_source = write_probe_fixture(root, "test_ink_oracle.py", b"")
            sources = {
                "test_authenticated_launcher": (
                    launcher_test.resolve(strict=True), test_source, False),
                "ink_oracle": (
                    oracle_source.resolve(strict=True), oracle_source.read_bytes(), False),
                "test_display_host_scope": (
                    display_source.resolve(strict=True), display_source.read_bytes(), False),
                "test_ink_oracle": (
                    ink_test_source.resolve(strict=True), ink_test_source.read_bytes(), False),
            }
            finder = gate._PinnedSourceFinder(
                sources, authority, gate_authority=gate_authority,
                gate_source=gate_source, gate_method=gate_method)
            sentinel = root / "ambient-secrets-executed"
            if poison_kind == "package":
                package = root / "secrets"
                package.mkdir()
                (package / "__init__.py").write_text(
                    "from pathlib import Path\nPath(" + repr(str(sentinel)) +
                    ").write_text('executed')\n", encoding="utf-8")
            elif poison_kind == "sourceless":
                code = compile(
                    "from pathlib import Path\nPath(" + repr(str(sentinel)) +
                    ").write_text('executed')\n", str(root / "secrets.py"), "exec")
                (root / "secrets.pyc").write_bytes(
                    importlib.util.MAGIC_NUMBER + struct.pack("<III", 0, 0, 0) +
                    marshal.dumps(code))
            else:
                raise AssertionError("unknown poison kind")

            names = tuple(sources) + ("secrets",)
            saved_modules = {name: sys.modules.get(name) for name in names}
            before_path = tuple(sys.path)
            try:
                for name in names:
                    sys.modules.pop(name, None)
                if forged_oracle:
                    wrong_source = root / "forged-ink-oracle.py"
                    wrong_source.write_bytes(b"")
                    wrong_loader = gate._PinnedSourceLoader(
                        wrong_source.resolve(strict=True), b"", False, authority,
                        gate_authority, gate_source, gate_method)
                    wrong_module = types.ModuleType("ink_oracle")
                    wrong_module.__spec__ = types.SimpleNamespace(
                        loader=wrong_loader, name="ink_oracle",
                        origin=str(wrong_source),
                        submodule_search_locations=None)
                    wrong_module.__package__ = ""
                    wrong_module.__loader__ = wrong_loader
                    wrong_module.__file__ = str(wrong_source)
                    wrong_module.__cached__ = None
                    sys.modules["ink_oracle"] = wrong_module
                sys.meta_path.insert(0, finder)
                if forged_oracle:
                    with self.assertRaisesRegex(
                            AssertionError,
                            "fixture escaped authenticated source namespace"):
                        importlib.import_module("test_authenticated_launcher")
                    return None, sentinel, before_path
                loaded = importlib.import_module("test_authenticated_launcher")
                return loaded, sentinel, before_path
            finally:
                if finder in sys.meta_path:
                    sys.meta_path.remove(finder)
                for name in names:
                    sys.modules.pop(name, None)
                    if saved_modules[name] is not None:
                        sys.modules[name] = saved_modules[name]
                self.assertEqual(tuple(sys.path), before_path)

        for poison_kind in ("package", "sourceless"):
            with self.subTest(poison=poison_kind), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                loaded, sentinel, before_path = import_authenticated_test(
                    root, poison_kind)
                self.assertIsNotNone(loaded)
                self.assertTrue(loaded.FIXTURE_LOAD_STATE["authenticated"])
                self.assertEqual(loaded.FIXTURE_LOAD_STATE["pathBefore"], before_path)
                self.assertEqual(loaded.FIXTURE_LOAD_STATE["pathAfter"], before_path)
                self.assertFalse(sentinel.exists())
                self.assertNotEqual(
                    Path(loaded.ORACLE.SECRETS_ORIGIN).resolve().parent, root)

        with tempfile.TemporaryDirectory() as temp:
            loaded, sentinel, _before_path = import_authenticated_test(
                Path(temp), "package", forged_oracle=True)
            self.assertIsNone(loaded)
            self.assertFalse(sentinel.exists())

    def test_probe_authority_is_checkout_newline_stable_but_rejects_mixed(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "sample_probe.py"
            source.write_bytes(b"FIRST = 1\nSECOND = 2\n")
            lf_sources, lf_digest = gate._probe_source_snapshot(
                source.parent, {source.name})
            canonical = gate._canonical_python_source(source.read_bytes())
            source.write_bytes(canonical.replace(b"\n", b"\r\n"))
            crlf_sources, crlf_digest = gate._probe_source_snapshot(
                source.parent, {source.name})
            self.assertEqual(lf_digest, crlf_digest)
            self.assertEqual(lf_sources["sample_probe"][1],
                             crlf_sources["sample_probe"][1])
            rejected = (
                b"FIRST = 1\r\nSECOND = 2\n",
                b"FIRST = 1\rSECOND = 2\r",
                b"FIRST = 1\xc2\x85SECOND = 2\n",
                b"FIRST = 1\xe2\x80\xa8SECOND = 2\n",
                b"FIRST = 1\xe2\x80\xa9SECOND = 2\n",
            )
            for raw in rejected:
                with self.subTest(raw=raw):
                    source.write_bytes(raw)
                    with self.assertRaisesRegex(
                            RuntimeError, "newline|line separator"):
                        gate._probe_source_snapshot(source.parent, {source.name})

    def test_closed_namespace_rejects_every_unlisted_elftools_module(self):
        with tempfile.TemporaryDirectory() as temp:
            package = Path(temp) / "elftools"
            package.mkdir()
            source = package / "__init__.py"
            source.write_bytes(b"VALUE = 'authenticated-source'\n")
            finder = gate._PinnedSourceFinder(
                {"elftools": (source.resolve(strict=True), source.read_bytes(), True)},
                "0" * 64, closed_namespaces=("elftools",))

            with self.assertRaisesRegex(
                    ModuleNotFoundError, "outside the authenticated source snapshot"):
                finder.find_spec("elftools.unlisted")
            self.assertIsNone(finder.find_spec("unrelated.unlisted"))

    def test_probe_digest_mismatch_precedes_discovered_module_side_effect(self):
        parser_root = pinned_python_root().resolve(strict=True)
        self.assertTrue((parser_root / "elftools" / "__init__.py").is_file())
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            sentinel = root / "executed"
            for name in gate.EXPECTED_PROBE_MODULES:
                payload = b""
                if name == "test_ink_oracle.py":
                    payload = ("from pathlib import Path\nPath(" +
                               repr(str(sentinel)) + ").write_text('executed')\n").encode()
                write_probe_fixture(root, name, payload)
            result, mutable_gate_sentinel = _run_captured_gate(
                root / "gate-runtime", [
                "--python-path", str(parser_root), "--probe-root", str(root),
                "--expected-probe-sha256", "0" * 64,
            ])

            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b"probe source authority differs from caller trust input",
                          result.stderr)
            self.assertFalse(sentinel.exists())
            self.assertFalse(mutable_gate_sentinel.exists())

    def test_late_unlisted_test_is_not_discovered_and_postcheck_rejects_it(self):
        parser_root = pinned_python_root().resolve(strict=True)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            sentinel = root / "late-test-executed"
            late_test = root / "production-launch" / "test_late_unlisted.py"
            for name in gate.EXPECTED_PROBE_MODULES:
                payload = b""
                if name == "test_ink_oracle.py":
                    payload = (
                        "from pathlib import Path\n"
                        "Path(" + repr(str(late_test)) + ").write_text(" +
                        repr("from pathlib import Path\nPath(" +
                             repr(str(sentinel)) + ").write_text('executed')\n") +
                        ", encoding='utf-8')\n").encode("utf-8")
                write_probe_fixture(root, name, payload)
            _sources, digest = gate._probe_source_snapshot(root)
            result, mutable_gate_sentinel = _run_captured_gate(
                root / "gate-runtime", [
                "--python-path", str(parser_root), "--probe-root", str(root),
                "--expected-probe-sha256", digest,
            ])
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b"probe Python source inventory changed", result.stderr)
            self.assertTrue(late_test.is_file())
            self.assertFalse(sentinel.exists())
            self.assertFalse(mutable_gate_sentinel.exists())

    def test_listed_test_mutation_executes_snapshot_then_postcheck_rejects_it(self):
        parser_root = pinned_python_root().resolve(strict=True)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            sentinel = root / "mutated-test-executed"
            target = root / "test_loader_bindings.py"
            for name in gate.EXPECTED_PROBE_MODULES:
                payload = b""
                if name == "test_ink_oracle.py":
                    payload = (
                        "from pathlib import Path\n"
                        "Path(" + repr(str(target)) + ").write_text(" +
                        repr("from pathlib import Path\nPath(" +
                             repr(str(sentinel)) + ").write_text('executed')\n") +
                        ", encoding='utf-8')\n").encode("utf-8")
                write_probe_fixture(root, name, payload)
            _sources, digest = gate._probe_source_snapshot(root)
            result, mutable_gate_sentinel = _run_captured_gate(
                root / "gate-runtime", [
                "--python-path", str(parser_root), "--probe-root", str(root),
                "--expected-probe-sha256", digest,
            ])
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b"probe source authority changed during tests",
                          result.stderr)
            self.assertFalse(sentinel.exists())
            self.assertFalse(mutable_gate_sentinel.exists())

    def test_saved_ink_golden_requires_authenticated_oracle_and_exact_parity(self):
        authority = "1" * 64
        loader = gate._PinnedSourceLoader(Path("ink_oracle.py"), b"", False,
                                          authority)

        def fake_oracle(raw, framed, authenticated=True):
            module = types.SimpleNamespace()
            module.__spec__ = types.SimpleNamespace(
                loader=loader if authenticated else object())
            module.read = lambda *_: raw
            module.read_collector_frame = lambda *_: framed
            module.validate_java_golden = lambda _value: None
            module.canonical_json = lambda value: str(value)
            module.compare = lambda *_: {
                "added": [], "removed": [], "changed": {}, "unchanged": 1}
            module.COLLECTOR_FRAME_PREFIX = b"FRAME "
            return module

        class VirtuallyRegisteredLoader:
            authority_sha256 = authority

        gate._PinnedSourceLoader.register(VirtuallyRegisteredLoader)
        virtual_loader = VirtuallyRegisteredLoader()
        self.assertIsInstance(virtual_loader, gate._PinnedSourceLoader)
        virtual_oracle = fake_oracle({}, {})
        virtual_oracle.__spec__.loader = virtual_loader
        with patch.object(gate.importlib, "import_module",
                          return_value=virtual_oracle), \
             self.assertRaisesRegex(RuntimeError, "escaped authenticated"):
            gate._validate_saved_ink_golden(Path("raw"), Path("frame"),
                                            authority)

        with patch.object(gate.importlib, "import_module",
                          return_value=fake_oracle({}, {}, False)), \
             self.assertRaisesRegex(RuntimeError, "escaped authenticated"):
            gate._validate_saved_ink_golden(Path("raw"), Path("frame"),
                                            authority)
        with patch.object(gate.importlib, "import_module",
                          return_value=fake_oracle({"value": 1}, {"value": 2})), \
             self.assertRaisesRegex(RuntimeError, "goldens differ"):
            gate._validate_saved_ink_golden(Path("raw"), Path("frame"),
                                            authority)

    def test_real_collectors_use_source_snapshot_and_retain_closed_namespace(self):
        parser_root = pinned_python_root().resolve(strict=True)
        probe_root = Path(__file__).resolve().parent
        captured_manifest = _manifest_snapshot()
        authenticated_outer = getattr(
            getattr(globals().get("__spec__"), "loader", None),
            "authority_sha256", None) is not None
        script = (
            "import importlib,pathlib,sys\n"
            "sys.path.insert(0,sys.argv[1])\n"
            "collector=importlib.import_module(sys.argv[2])\n"
            "original=collector.authenticate_elftools\n"
            "def observed(root):\n"
            " original(root)\n"
            " import elftools\n"
            " from elftools.elf import elffile\n"
            " assert elffile.__cached__ is None\n"
            " elftools.__path__.append(sys.argv[4])\n"
            " try:\n"
            "  importlib.import_module('elftools.unlisted_production_probe')\n"
            " except ModuleNotFoundError:\n"
            "  pass\n"
            " else:\n"
            "  raise AssertionError('unlisted elftools module escaped authority')\n"
            " print('AUTHENTICATED_COLLECTOR')\n"
            " raise SystemExit(73)\n"
            "collector.authenticate_elftools=observed\n"
            "if sys.argv[2].endswith('dependencies'):\n"
            " sys.argv=['collector','--adb',sys.argv[5],'--python-path',sys.argv[3],"
            "'--output',sys.argv[6]]\n"
            "else:\n"
            " sys.argv=['collector','--adb',sys.argv[5],'--python-path',sys.argv[3],"
            "'--inventory',sys.argv[6],'--output',sys.argv[7]]\n"
            "collector.main()\n"
        )
        for module in ("inspect_loader_dependencies", "inspect_loader_bindings"):
            with self.subTest(module=module), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                collector_root = root / "collector"
                collector_root.mkdir()
                fallback_root = probe_root
                mutable_source_sentinel = root / "mutable-source-path-executed"
                if authenticated_outer:
                    fallback_root = root / "mutable-source-names"
                    fallback_root.mkdir()
                    malicious = (
                        "from pathlib import Path\nPath(" +
                        repr(str(mutable_source_sentinel)) +
                        ").write_text('executed')\n").encode("utf-8")
                    for name in ("inspect_loader_dependencies.py",
                                 "inspect_loader_bindings.py",
                                 "pinned_elftools_gate.py"):
                        (fallback_root / name).write_bytes(malicious)
                captured_sources = {
                    name: _captured_probe_source(
                        Path(name).stem, fallback_root / name)
                    for name in ("inspect_loader_dependencies.py",
                                 "inspect_loader_bindings.py",
                                 "pinned_elftools_gate.py")
                }
                for name, raw in captured_sources.items():
                    (collector_root / name).write_bytes(raw)
                (collector_root / "pinned_elftools_manifest.json").write_bytes(
                    captured_manifest)
                if module == "inspect_loader_bindings":
                    gate_copy = collector_root / "pinned_elftools_gate.py"
                    canonical = gate._canonical_python_source(gate_copy.read_bytes())
                    gate_copy.write_bytes(canonical.replace(b"\n", b"\r\n"))
                poisoned_gate = root / "poisoned-gate-bytecode-executed"
                write_valid_poisoned_cache(
                    collector_root / "pinned_elftools_gate.py",
                    "from pathlib import Path\nPath(" + repr(str(poisoned_gate)) +
                    ").write_text('executed')\n")
                copied_root = root / "python"
                shutil.copytree(parser_root / "elftools", copied_root / "elftools",
                                ignore=shutil.ignore_patterns("__pycache__"))
                poisoned = root / "poisoned-bytecode-executed"
                write_valid_poisoned_cache(
                    copied_root / "elftools" / "elf" / "elffile.py",
                    "from pathlib import Path\nPath(" + repr(str(poisoned)) +
                    ").write_text('executed')\n")
                rogue_package = root / "rogue" / "elftools"
                rogue_package.mkdir(parents=True)
                rogue = root / "unlisted-module-executed"
                (rogue_package / "unlisted_production_probe.py").write_text(
                    "from pathlib import Path\nPath(" + repr(str(rogue)) +
                    ").write_text('executed')\n", encoding="utf-8")

                result = subprocess.run([
                    sys.executable, "-I", "-S", "-c", script,
                    str(collector_root), module, str(copied_root), str(rogue_package),
                    str(root / "never-run-adb"), str(root / "input-or-output"),
                    str(root / "bindings-output"),
                ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
                   check=False)
                self.assertEqual(
                    result.returncode, 73,
                    result.stdout.decode(errors="replace") +
                    result.stderr.decode(errors="replace"))
                self.assertEqual(result.stdout.strip(), b"AUTHENTICATED_COLLECTOR")
                self.assertFalse(poisoned_gate.exists())
                self.assertFalse(poisoned.exists())
                self.assertFalse(rogue.exists())
                self.assertFalse(mutable_source_sentinel.exists())


if __name__ == "__main__":
    unittest.main()
