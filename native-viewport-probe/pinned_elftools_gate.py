"""Run evidence tests with one authenticated vendored pyelftools tree."""
from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.abc
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
import unittest


EXPECTED_VERSION = "0.32"
EXPECTED_FILES = 54
EXPECTED_TREE_SHA256 = (
    "09679ad9ea7781df8fe3ef1d39b2189261f57967e06c549ce2891b977018382a"
)
AUTHENTICATED_ROOT_ENV = "RTL_READER_AUTHENTICATED_ELFTOOLS_ROOT"
AUTHENTICATED_GATE_MODULE = "_rtl_reader_authenticated_elftools_gate"
AUTHENTICATED_GATE_SOURCE_ATTR = "_rtl_reader_authenticated_gate_source"
EXPECTED_MANIFEST_SHA256 = (
    "ee6a5b25d50d92b3e26bca9ac7c4ee9d6f23f1ffc1c5fb83d13bfbf9ed153365"
)
MAX_MANIFEST_BYTES = 32 * 1024
MAX_PROBE_FILES = 64
MAX_PROBE_FILE_BYTES = 4 * 1024 * 1024
MAX_PROBE_TOTAL_BYTES = 32 * 1024 * 1024
EXPECTED_SAVED_INK_ARTIFACT_SHA256 = (
    "fe0d42d26a8f2a21ee0a14cb88f0f57bee8cd98d5e3abfeaf8e75da4391e09b2"
)
EXPECTED_SAVED_INK_DEX_SHA256 = (
    "ede82ef546ac99cc0a4489fb1b78909ecd3f5d440ff34322cb0cf5677034c097"
)
EXPECTED_SAVED_INK_AUTHORITY_SHA256 = (
    "c6d449a492d8b4f99c79608a80be01d3de14ec6f98ad1ca39a3c0b8e9381586c"
)
EXPECTED_PROBE_MODULES = frozenset({
    "bounded_command_runner.py",
    "ink_oracle.py",
    "inspect_loader_bindings.py",
    "inspect_loader_dependencies.py",
    "pinned_elftools_gate.py",
    "production-launch/authenticated_launcher.py",
    "production-launch/test_authenticated_launcher.py",
    "saved_ink_reader_artifact.py",
    "test_display_host_scope.py",
    "test_ink_oracle.py",
    "test_loader_against_llvm.py",
    "test_loader_bindings.py",
    "test_loader_dependencies.py",
    "test_pinned_elftools_gate.py",
    "test_saved_ink_reader_artifact.py",
})


class _PinnedSourceLoader(importlib.abc.Loader):
    """Execute one already-authenticated source snapshot without bytecode I/O."""
    def __init__(self, source: Path, raw: bytes, is_package: bool,
                 authority_sha256: str, gate_authority=None,
                 gate_source=None, gate_method=None):
        self.source = source
        self.raw = raw
        self.is_package = is_package
        self.authority_sha256 = authority_sha256
        self.gate_authority = gate_authority
        self.gate_source = gate_source
        self.gate_method = gate_method

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        module.__cached__ = None
        code = compile(self.raw, str(self.source), "exec", dont_inherit=True)
        exec(code, module.__dict__)


class _PinnedSourceFinder(importlib.abc.MetaPathFinder):
    """Load only authenticated ``.py`` sources, never ambient/bytecode code."""
    def __init__(self, sources, authority_sha256: str, closed_namespaces=(),
                 gate_authority=None, gate_source=None, gate_method=None):
        self.sources = sources
        self.authority_sha256 = authority_sha256
        self.closed_namespaces = frozenset(closed_namespaces)
        self.gate_authority = gate_authority
        self.gate_source = gate_source
        self.gate_method = gate_method

    def find_spec(self, fullname, path=None, target=None):
        captured = self.sources.get(fullname)
        if captured is None:
            if any(fullname == namespace or fullname.startswith(namespace + ".")
                   for namespace in self.closed_namespaces):
                raise ModuleNotFoundError(
                    "module is outside the authenticated source snapshot: " + fullname)
            return None
        source, raw, is_package = captured
        loader = _PinnedSourceLoader(
            source, raw, is_package, self.authority_sha256,
            self.gate_authority, self.gate_source, self.gate_method)
        return importlib.util.spec_from_file_location(
            fullname, source, loader=loader,
            submodule_search_locations=[str(source.parent)] if is_package else None)


def _strict_json(raw: bytes):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise RuntimeError("duplicate pinned manifest field")
            result[key] = value
        return result
    try:
        return json.loads(raw.decode("ascii"), object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("invalid pinned manifest wire") from error


def _canonical_python_source(raw: bytes) -> bytes:
    """Accept one uniform checkout newline convention and execute exact LF."""
    if any(separator in raw for separator in (
            b"\xc2\x85", b"\xe2\x80\xa8", b"\xe2\x80\xa9")):
        raise RuntimeError("Python source has a Unicode line separator")
    if b"\r" not in raw:
        return raw
    if raw.count(b"\r") != raw.count(b"\r\n") or raw.count(b"\n") != raw.count(b"\r\n"):
        raise RuntimeError("Python source has mixed or noncanonical newlines")
    return raw.replace(b"\r\n", b"\n")


def _source_identity(value):
    # Windows can update ctime merely by opening a file through the CRT. The
    # stable file ID, type, links, size, mtime and reparse attributes retain
    # name/open authority there; POSIX ctime remains a useful mutation signal.
    fields = (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
              value.st_size, value.st_mtime_ns,
              getattr(value, "st_file_attributes", 0))
    return fields + ((value.st_ctime_ns,) if os.name == "posix" else ())


def _read_regular_source(path: Path, limit: int,
                         expected_size: int | None = None) -> bytes:
    """Read one source without following or blocking on a replaced leaf."""
    path = Path(path)
    try:
        named = path.lstat()
    except OSError as error:
        raise RuntimeError("authenticated source is unavailable") from error
    if (not stat.S_ISREG(named.st_mode) or
            getattr(named, "st_file_attributes", 0) & 0x400 or
            named.st_size < 0 or named.st_size > limit or
            (expected_size is not None and named.st_size != expected_size)):
        raise RuntimeError("authenticated source size or type changed")
    flags = (os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) |
             getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0) |
             getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0))
    descriptor = None
    try:
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if (not stat.S_ISREG(opened.st_mode) or
                getattr(opened, "st_file_attributes", 0) & 0x400 or
                _source_identity(opened) != _source_identity(named)):
            raise RuntimeError("authenticated source changed during open")
        chunks = []
        remaining = opened.st_size + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        try:
            final_named = path.lstat()
        except OSError as error:
            raise RuntimeError("authenticated source name changed") from error
        if (len(raw) != opened.st_size or
                _source_identity(after) != _source_identity(opened) or
                _source_identity(final_named) != _source_identity(opened)):
            raise RuntimeError("authenticated source changed during read")
        return raw
    except OSError as error:
        raise RuntimeError("authenticated source could not be opened") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _load_expected_files():
    path = Path(__file__).absolute().with_name(
        "pinned_elftools_manifest.json")
    raw = _read_regular_source(path, MAX_MANIFEST_BYTES)
    if not raw:
        raise RuntimeError("pinned elftools manifest size is invalid")
    value = _strict_json(raw)
    canonical = json.dumps(
        value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True).encode("ascii")
    if hashlib.sha256(canonical).hexdigest() != EXPECTED_MANIFEST_SHA256:
        raise RuntimeError("pinned elftools manifest authority changed")
    if (type(value) is not dict or set(value) != {"schema", "files"} or
            value["schema"] != "pinned-elftools-sources-v1" or
            type(value["files"]) is not dict or
            len(value["files"]) != EXPECTED_FILES):
        raise RuntimeError("invalid pinned elftools manifest")
    expected = {}
    for name, record in value["files"].items():
        posix = PurePosixPath(name)
        if (type(name) is not str or not name or posix.is_absolute() or
                ".." in posix.parts or "__pycache__" in posix.parts or
                type(record) is not dict or
                set(record) != {"bytes", "sha256"} or
                type(record["bytes"]) is not int or record["bytes"] < 0 or
                type(record["sha256"]) is not str or
                len(record["sha256"]) != 64):
            raise RuntimeError("invalid pinned elftools file authority")
        expected[name] = (record["bytes"], record["sha256"])
    return expected


def _tree_snapshot(root: Path):
    package = root / "elftools"
    try:
        package_info = package.lstat()
    except OSError as error:
        raise RuntimeError("pinned elftools package directory is unavailable") from error
    if (not stat.S_ISDIR(package_info.st_mode) or
            getattr(package_info, "st_file_attributes", 0) & 0x400):
        raise RuntimeError("pinned elftools package directory is unavailable")
    expected = _load_expected_files()
    actual_names = set()
    for path in package.rglob("*"):
        relative = path.relative_to(package)
        if "__pycache__" in relative.parts:
            continue
        try:
            entry = path.lstat()
        except OSError as error:
            raise RuntimeError("pinned elftools tree changed") from error
        if stat.S_ISDIR(entry.st_mode) and not (
                getattr(entry, "st_file_attributes", 0) & 0x400):
            continue
        if (not stat.S_ISREG(entry.st_mode) or
                getattr(entry, "st_file_attributes", 0) & 0x400):
            raise RuntimeError("pinned elftools tree contains a nonregular entry")
        actual_names.add(relative.as_posix())
    if actual_names != set(expected):
        raise RuntimeError("pinned elftools file inventory changed")
    records = []
    sources = {}
    for relative_name in sorted(expected):
        expected_size, expected_sha256 = expected[relative_name]
        path = package.joinpath(*PurePosixPath(relative_name).parts)
        raw = _read_regular_source(path, MAX_PROBE_FILE_BYTES, expected_size)
        if hashlib.sha256(raw).hexdigest() != expected_sha256:
            raise RuntimeError("pinned elftools file authority changed")
        relative = PurePosixPath(relative_name)
        name = relative_name.encode("utf-8")
        records.append(
            len(name).to_bytes(4, "big") + name +
            len(raw).to_bytes(8, "big") + hashlib.sha256(raw).digest()
        )
        if path.suffix == ".py":
            parts = list(relative.parts)
            is_package = parts[-1] == "__init__.py"
            if is_package:
                parts.pop()
            else:
                parts[-1] = Path(parts[-1]).stem
            fullname = ".".join(["elftools", *parts])
            if fullname in sources:
                raise RuntimeError("duplicate pinned elftools module")
            sources[fullname] = (path.resolve(strict=True), raw, is_package)
    digest = hashlib.sha256(b"".join(records)).hexdigest()
    return len(records), digest, sources


def _probe_source_snapshot(
        probe_root: Path, expected_names=EXPECTED_PROBE_MODULES):
    relative_names = set(expected_names)
    parsed_names = []
    for name in relative_names:
        relative = PurePosixPath(name)
        if (type(name) is not str or not name or relative.is_absolute() or
                ".." in relative.parts or relative.suffix != ".py" or
                any(not part or part == "." for part in relative.parts)):
            raise RuntimeError("invalid probe Python source inventory")
        parsed_names.append(relative)
    paths = []
    for relative_parent in sorted({item.parent for item in parsed_names},
                                  key=lambda item: item.as_posix()):
        directory = probe_root.joinpath(*(() if str(relative_parent) == "."
                                          else relative_parent.parts))
        try:
            directory_info = directory.lstat()
        except OSError as error:
            raise RuntimeError("probe Python source directory is unavailable") from error
        if (not stat.S_ISDIR(directory_info.st_mode) or
                getattr(directory_info, "st_file_attributes", 0) & 0x400):
            raise RuntimeError("probe Python source directory is unavailable")
        paths.extend(directory.glob("*.py"))
    paths.sort(key=lambda item: item.relative_to(probe_root).as_posix())
    actual_names = {
        path.relative_to(probe_root).as_posix()
        for path in paths
    }
    if actual_names != relative_names:
        raise RuntimeError("probe Python source inventory changed")
    if len(paths) > MAX_PROBE_FILES:
        raise RuntimeError("probe Python source count exceeds bound")
    sources = {}
    records = []
    total = 0
    for path in paths:
        relative_name = path.relative_to(probe_root).as_posix()
        raw = _read_regular_source(path, MAX_PROBE_FILE_BYTES)
        total += len(raw)
        if total > MAX_PROBE_TOTAL_BYTES:
            raise RuntimeError("probe Python sources exceed aggregate bound")
        raw = _canonical_python_source(raw)
        name = path.stem
        if name in sources:
            raise RuntimeError("duplicate probe Python module")
        sources[name] = (path.resolve(strict=True), raw, False)
        encoded_name = relative_name.encode("utf-8")
        records.append(len(encoded_name).to_bytes(4, "big") + encoded_name +
                       len(raw).to_bytes(8, "big") +
                       hashlib.sha256(raw).digest())
    return sources, hashlib.sha256(b"".join(records)).hexdigest()


def _authenticated_test_suite(probe_sources, authority_sha256: str):
    """Build tests only from captured allowlisted modules, never discovery."""
    suite = unittest.TestSuite()
    for filename in sorted(EXPECTED_PROBE_MODULES):
        basename = PurePosixPath(filename).name
        if (not basename.startswith("test_") or not basename.endswith(".py") or
                basename == "test_saved_ink_reader_artifact.py"):
            continue
        name = PurePosixPath(filename).stem
        module = importlib.import_module(name)
        loader = getattr(getattr(module, "__spec__", None), "loader", None)
        if (type(loader) is not _PinnedSourceLoader or
                loader.authority_sha256 != authority_sha256):
            raise RuntimeError(
                "test module escaped the authenticated source snapshot")
        suite.addTests(unittest.defaultTestLoader.loadTestsFromModule(module))
    return suite


def _saved_ink_artifact_suite(
        probe_sources, authority_sha256: str, artifact_path: Path,
        repeat_path: Path, provenance_path: Path, build_script_path: Path):
    """Verify and configure the required 12-case generated-artifact lane."""
    artifact_module = importlib.import_module("saved_ink_reader_artifact")
    test_module = importlib.import_module("test_saved_ink_reader_artifact")
    for module in (artifact_module, test_module):
        loader = getattr(getattr(module, "__spec__", None), "loader", None)
        if (type(loader) is not _PinnedSourceLoader or
                loader.authority_sha256 != authority_sha256):
            raise RuntimeError(
                "saved-ink artifact module escaped authenticated sources")
    artifact_path = artifact_path.absolute()
    repeat_path = repeat_path.absolute()
    provenance_path = provenance_path.absolute()
    build_script_path = build_script_path.absolute()
    final = artifact_module.verify_final_artifact(
        artifact_path, EXPECTED_SAVED_INK_ARTIFACT_SHA256,
        EXPECTED_SAVED_INK_DEX_SHA256,
        EXPECTED_SAVED_INK_AUTHORITY_SHA256)
    provenance = artifact_module.verify_provenance(
        artifact_path, repeat_path, provenance_path, build_script_path,
        probe_sources["test_saved_ink_reader_artifact"][0])
    build_source = _canonical_python_source(
        _read_regular_source(build_script_path, 256 * 1024))
    expected_reviewed_sources = {
        "buildScript": {
            "bytes": len(build_source),
            "path": "build-saved-ink-reader.ps1",
            "sha256": hashlib.sha256(build_source).hexdigest(),
        },
        "packager": {
            "bytes": len(probe_sources["saved_ink_reader_artifact"][1]),
            "path": "saved_ink_reader_artifact.py",
            "sha256": hashlib.sha256(
                probe_sources["saved_ink_reader_artifact"][1]).hexdigest(),
        },
        "tests": {
            "bytes": len(probe_sources["test_saved_ink_reader_artifact"][1]),
            "path": "test_saved_ink_reader_artifact.py",
            "sha256": hashlib.sha256(
                probe_sources["test_saved_ink_reader_artifact"][1]).hexdigest(),
        },
    }
    if provenance.get("reviewedSources") != expected_reviewed_sources:
        raise RuntimeError(
            "saved-ink provenance differs from captured reviewed sources")
    case = test_module.GeneratedArtifactTests
    case.artifact_path = artifact_path
    case.repeat_path = repeat_path
    case.provenance_path = provenance_path
    case.build_script_path = build_script_path
    case.tests_path = probe_sources["test_saved_ink_reader_artifact"][0]
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(case)
    if suite.countTestCases() != 12:
        raise RuntimeError("saved-ink artifact test inventory changed")
    provenance_wire = _read_regular_source(provenance_path, 128 * 1024)
    marker = {
        "artifactBytes": final["bytes"],
        "artifactSha256": final["sha256"],
        "authoritySha256": final["authoritySha256"],
        "buildScriptSha256": hashlib.sha256(build_source).hexdigest(),
        "dexBytes": final["dex"]["bytes"],
        "dexSha256": final["dex"]["sha256"],
        "provenanceSha256": hashlib.sha256(provenance_wire).hexdigest(),
        "tests": suite.countTestCases(),
        "twoCleanBuildsByteIdentical":
            provenance["twoCleanBuildsByteIdentical"],
    }
    return suite, marker


def _validate_saved_ink_golden(raw_path: Path, frame_path: Path,
                               authority_sha256: str):
    """Cross-check the real Java raw and framed wires with captured oracle code."""
    oracle = importlib.import_module("ink_oracle")
    loader = getattr(getattr(oracle, "__spec__", None), "loader", None)
    if (type(loader) is not _PinnedSourceLoader or
            loader.authority_sha256 != authority_sha256):
        raise RuntimeError("saved-ink oracle escaped authenticated source snapshot")
    expected_source = "a" * 64
    raw_capture = oracle.read(raw_path, expected_source)
    framed_capture = oracle.read_collector_frame(frame_path, expected_source)
    oracle.validate_java_golden(raw_capture)
    oracle.validate_java_golden(framed_capture)
    raw_wire = oracle.canonical_json(raw_capture).encode("utf-8")
    framed_wire = oracle.canonical_json(framed_capture).encode("utf-8")
    if raw_wire != framed_wire:
        raise RuntimeError("Java raw and framed saved-ink goldens differ")
    difference = oracle.compare(raw_capture, framed_capture, expected_source)
    if (difference["added"] or difference["removed"] or
            difference["changed"] or difference["unchanged"] != 1):
        raise RuntimeError("Java raw/framed saved-ink parity changed")
    return {
        "payloadBytes": len(raw_wire),
        "payloadSha256": hashlib.sha256(raw_wire).hexdigest(),
        "frameBytes": (len(oracle.COLLECTOR_FRAME_PREFIX) +
                       len(raw_wire) + 1),
    }


def _tree_authority(root: Path) -> tuple[int, str]:
    count, digest, _ = _tree_snapshot(root)
    return count, digest


def _verify_loaded_modules(expected_package: Path, authority_sha256: str) -> None:
    for name, module in sys.modules.items():
        if name != "elftools" and not name.startswith("elftools."):
            continue
        source = getattr(module, "__file__", None)
        spec = getattr(module, "__spec__", None)
        loader = getattr(spec, "loader", None)
        resolved = None if source is None else Path(source).resolve(strict=True)
        if (resolved is None or resolved.suffix != ".py" or
                (resolved != expected_package / "__init__.py" and
                 expected_package not in resolved.parents) or
                type(loader) is not _PinnedSourceLoader or
                loader.authority_sha256 != authority_sha256):
            raise RuntimeError(
                "pyelftools loaded code outside the authenticated source snapshot")


def _verify_and_import(root: Path) -> dict[str, object]:
    root = root.resolve(strict=True)
    count, digest, sources = _tree_snapshot(root)
    before = (count, digest)
    if before != (EXPECTED_FILES, EXPECTED_TREE_SHA256):
        raise RuntimeError("pinned elftools source-tree authority changed")
    loaded = any(name == "elftools" or name.startswith("elftools.")
                 for name in sys.modules)
    matching_finders = [finder for finder in sys.meta_path
                        if (type(finder) is _PinnedSourceFinder and
                            finder.authority_sha256 == digest and
                            finder.sources == sources and
                            "elftools" in finder.closed_namespaces)]
    if loaded:
        if len(matching_finders) != 1:
            raise RuntimeError("ambient elftools module was imported before authentication")
        _verify_loaded_modules((root / "elftools").resolve(strict=True), digest)
    else:
        if matching_finders:
            raise RuntimeError("pinned elftools finder exists without its package authority")
        finder = _PinnedSourceFinder(
            sources, digest, closed_namespaces=("elftools",))
        sys.meta_path.insert(0, finder)
        importlib.invalidate_caches()
        try:
            import elftools
            from elftools.elf import elffile
        except BaseException:
            if finder in sys.meta_path:
                sys.meta_path.remove(finder)
            for name, module in list(sys.modules.items()):
                loader = getattr(getattr(module, "__spec__", None), "loader", None)
                if type(loader) is _PinnedSourceLoader and loader.authority_sha256 == digest:
                    sys.modules.pop(name, None)
            raise

    import elftools
    from elftools.elf import elffile

    expected_package = (root / "elftools").resolve(strict=True)
    expected_module = (expected_package / "elf" / "elffile.py").resolve(strict=True)
    package_paths = [Path(item).resolve(strict=True) for item in elftools.__path__]
    if (getattr(elftools, "__version__", None) != EXPECTED_VERSION or
            Path(elftools.__file__).resolve(strict=True) !=
            (expected_package / "__init__.py").resolve(strict=True) or
            package_paths != [expected_package] or
            Path(elffile.__file__).resolve(strict=True) != expected_module):
        raise RuntimeError("pyelftools did not import from the authenticated tree")
    _verify_loaded_modules(expected_package, digest)
    after = _tree_authority(root)
    if after != before:
        raise RuntimeError("pinned elftools source tree changed during import")
    return {"version": EXPECTED_VERSION, "files": before[0], "sha256": before[1]}


def authenticate_elftools(root: Path) -> dict[str, object]:
    """Authenticate and retain the sole in-memory pyelftools source authority."""
    current = sys.modules[__name__]
    existing_gate = sys.modules.get(AUTHENTICATED_GATE_MODULE)
    if existing_gate is not None and existing_gate is not current:
        raise RuntimeError("another authenticated-gate authority already exists")
    sys.modules[AUTHENTICATED_GATE_MODULE] = current
    return _verify_and_import(root)


def _sha256_argument(value: str) -> str:
    if (len(value) != 64 or
            any(character not in "0123456789abcdef" for character in value)):
        raise argparse.ArgumentTypeError("expected a lowercase SHA-256 digest")
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--python-path", type=Path, required=True)
    parser.add_argument("--probe-root", type=Path, required=True)
    parser.add_argument("--expected-probe-sha256", type=_sha256_argument,
                        required=True)
    parser.add_argument("--saved-ink-raw-golden", type=Path)
    parser.add_argument("--saved-ink-frame-golden", type=Path)
    parser.add_argument("--saved-ink-device-artifact", type=Path)
    parser.add_argument("--saved-ink-repeat-artifact", type=Path)
    parser.add_argument("--saved-ink-provenance", type=Path)
    parser.add_argument("--saved-ink-build-script", type=Path)
    args = parser.parse_args()
    if ((args.saved_ink_raw_golden is None) !=
            (args.saved_ink_frame_golden is None)):
        raise RuntimeError("both saved-ink golden paths are required together")
    artifact_arguments = (
        args.saved_ink_device_artifact, args.saved_ink_repeat_artifact,
        args.saved_ink_provenance, args.saved_ink_build_script)
    if any(value is not None for value in artifact_arguments) and not all(
            value is not None for value in artifact_arguments):
        raise RuntimeError("all saved-ink artifact paths are required together")
    authority = authenticate_elftools(args.python_path)
    os.environ[AUTHENTICATED_ROOT_ENV] = str(args.python_path.resolve(strict=True))
    probe_root = args.probe_root.resolve(strict=True)
    if not probe_root.is_dir() or probe_root.is_symlink():
        raise RuntimeError("invalid probe test root")
    probe_sources, probe_digest = _probe_source_snapshot(probe_root)
    if probe_digest != args.expected_probe_sha256:
        raise RuntimeError("probe source authority differs from caller trust input")
    gate_authority = sys.modules.get(AUTHENTICATED_GATE_MODULE)
    gate_source = getattr(
        gate_authority, AUTHENTICATED_GATE_SOURCE_ATTR, None)
    if (gate_authority is not sys.modules.get("__main__") or
            type(gate_source) is not bytes):
        raise RuntimeError("authenticated top-level gate provenance is unavailable")
    sys.meta_path.insert(0, _PinnedSourceFinder(
        probe_sources, probe_digest, gate_authority=gate_authority,
        gate_source=gate_source,
        gate_method=gate_authority.authenticate_elftools))
    golden_authority = None
    if args.saved_ink_raw_golden is not None:
        golden_authority = _validate_saved_ink_golden(
            args.saved_ink_raw_golden, args.saved_ink_frame_golden,
            probe_digest)
    suite = _authenticated_test_suite(probe_sources, probe_digest)
    artifact_authority = None
    if all(value is not None for value in artifact_arguments):
        artifact_suite, artifact_authority = _saved_ink_artifact_suite(
            probe_sources, probe_digest, *artifact_arguments)
        suite.addTests(artifact_suite)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    after_sources, after_digest = _probe_source_snapshot(probe_root)
    if after_digest != probe_digest or any(
            after_sources[name][1:] != probe_sources[name][1:]
            for name in probe_sources):
        raise RuntimeError("probe source authority changed during tests")
    if not result.wasSuccessful():
        return 1
    if _tree_authority(args.python_path.resolve(strict=True)) != (
            EXPECTED_FILES, EXPECTED_TREE_SHA256):
        raise RuntimeError("pinned elftools source tree changed during tests")
    _verify_loaded_modules(
        (args.python_path.resolve(strict=True) / "elftools"),
        EXPECTED_TREE_SHA256)
    for name in probe_sources:
        module = sys.modules.get(name)
        if module is None:
            continue
        loader = getattr(getattr(module, "__spec__", None), "loader", None)
        if (type(loader) is not _PinnedSourceLoader or
                loader.authority_sha256 != probe_digest):
            raise RuntimeError("probe module escaped the authenticated source snapshot")
    print("PINNED_ELFTOOLS " + json.dumps(authority, sort_keys=True,
                                           separators=(",", ":")))
    print("PINNED_PROBE_SOURCES " + json.dumps(
        {"files": len(probe_sources), "sha256": probe_digest},
        sort_keys=True, separators=(",", ":")))
    if golden_authority is not None:
        print("PINNED_SAVED_INK_GOLDEN " + json.dumps(
            golden_authority, sort_keys=True, separators=(",", ":")))
    if artifact_authority is not None:
        print("PINNED_SAVED_INK_DEVICE_ARTIFACT " + json.dumps(
            artifact_authority, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
