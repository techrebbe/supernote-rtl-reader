"""Host-only tests. No ADB, firmware execution or real ELF fixture required."""
import argparse
import builtins
import contextlib
import copy
import hashlib
import importlib.machinery
import io
import json
import mmap
import os
from pathlib import Path
import signal
import struct
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch

import bounded_command_runner as runner
import inspect_loader_dependencies as inv


def loaded_production_source(module):
    """Return the outer authenticated bytes when this test is gate-loaded."""
    current_loader = getattr(globals().get("__spec__"), "loader", None)
    authority = getattr(current_loader, "authority_sha256", None)
    module_loader = getattr(getattr(module, "__spec__", None), "loader", None)
    if authority is not None:
        raw = getattr(module_loader, "raw", None)
        if (getattr(module_loader, "authority_sha256", None) != authority or
                type(raw) is not bytes):
            raise AssertionError("authenticated production source is unavailable")
        return raw
    raw = Path(module.__file__).read_bytes()
    if any(separator in raw for separator in (
            b"\xc2\x85", b"\xe2\x80\xa8", b"\xe2\x80\xa9")):
        raise AssertionError("production source has invalid line separators")
    if b"\r" in raw:
        if (raw.count(b"\r") != raw.count(b"\r\n") or
                raw.count(b"\n") != raw.count(b"\r\n")):
            raise AssertionError("production source has mixed newlines")
        raw = raw.replace(b"\r\n", b"\n")
    return raw


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--python-path", type=Path, required=True)
    args, other = parser.parse_known_args()
    import pinned_elftools_gate
    pinned_elftools_gate.authenticate_elftools(args.python_path)

try:
    import elftools.elf.elffile
    ELF_AVAILABLE = True
except ImportError:
    ELF_AVAILABLE = False


def record(path, start=0x1000, inode=123):
    return f"{start:x}-{start+4096:x} r-xp 00000000 fd:04 {inode}   {path}\n"


def fake_elf(machine=183, init_size=16, extra_tags=(), needed="libc.so"):
    strings = ("\0libexample.so\0" + needed + "\0").encode()
    tags = [(5, 0x200), (10, len(strings)), (14, 1), (1, 15), (27, init_size), *extra_tags, (0, 0)]
    data = bytearray(1024)
    ident = b"\x7fELF\x02\x01\x01" + bytes(9)
    struct.pack_into("<16sHHIQQQIHHHHHH", data, 0, ident, 3, machine, 1, 0, 64, 0, 0, 64, 56, 2, 64, 0, 0)
    struct.pack_into("<IIQQQQQQ", data, 64, 1, 5, 0, 0, 0, len(data), len(data), 4096)
    struct.pack_into("<IIQQQQQQ", data, 120, 2, 6, 0x100, 0x100, 0, len(tags)*16, len(tags)*16, 8)
    for i, tag in enumerate(tags):
        struct.pack_into("<qQ", data, 0x100 + i*16, *tag)
    data[0x200:0x200+len(strings)] = strings
    return bytes(data)


def fake_elf_with_section_name_table(names=b"\0.shstrtab\0", name_offset=1):
    data=bytearray(fake_elf())
    data.extend(bytes(1024))
    section_offset=1024
    string_offset=1152
    struct.pack_into("<Q",data,40,section_offset)
    struct.pack_into("<HHH",data,58,64,2,1)
    struct.pack_into("<IIQQQQIIQQ",data,section_offset+64,
                     name_offset,3,0,0,string_offset,len(names),0,0,1,0)
    data[string_offset:string_offset+len(names)]=names
    return bytes(data)


def meta(needed=(), digest="f"*64, size=10):
    return {"bytes": size, "sha256": digest, "needed": list(needed)}


def capture(metadata):
    size = metadata.get("bytes")
    return metadata, (b"x" * size if type(size) is int and 0 <= size <= 1024 else b"")


def inventory_v4(library_payload=None, raw_maps=None):
    raw_maps = (record(inv.ROOT_LIBRARY).encode("utf-8")
                if raw_maps is None else raw_maps)
    library_size = 1024 if library_payload is None else len(library_payload)
    library_digest = (inv.ROOT_SHA256 if library_payload is None else
                      hashlib.sha256(library_payload).hexdigest())
    maps = inv.mapped_libraries(record(inv.ROOT_LIBRARY))
    mapping = maps[inv.ROOT_LIBRARY][0]
    return {
        "schema":"native-loader-inventory-v4", "firmware":inv.FINGERPRINT,
        "serial":inv.SERIAL, "process":{"pid":1425,"startTime":2642},
        "filteredMappings":maps, "filteredMapSetSha256":inv.mapping_set_digest(maps),
        "completeRawMapsSha256":hashlib.sha256(raw_maps).hexdigest(),
        "completeRawMapsBytes":len(raw_maps),
        "nativeStartAllowed":False, "bindingAuthority":False,
        "libraries":{inv.ROOT_LIBRARY:{
            "sha256":library_digest, "bytes":library_size,
            "soname":"librecgnition.so",
            "needed":[], "initArrayEntries":0, "initFunctions":[],
            "mappings":[dict(item) for item in maps[inv.ROOT_LIBRARY]], "localFile":"0123456789abcdef.so",
            "mappedFileIdentity":{"device":mapping["device"],"inode":mapping["inode"],
                "bytes":library_size,"mtime":1,"ctime":1,
                "authority":"proc-map-files-open-descriptor-v1"}}},
        "edges":[], "notes":inv.INVENTORY_NOTES,
    }


def inventory_generation_fixture():
    raw = record(inv.ROOT_LIBRARY).encode("utf-8")
    library = b"authenticated-library-bytes"
    report = inventory_v4(library, raw)
    artifacts = [
        ("maps-before.txt", raw),
        (report["libraries"][inv.ROOT_LIBRARY]["localFile"], library),
        ("maps-after.txt", raw),
    ]
    return report, artifacts


def stage_generation(generation, artifacts):
    for name, payload in artifacts:
        generation.stage(name, payload)


def process_stat(pid=1425, start=2642):
    fields = ["S"] + ["0"] * 18 + [str(start)]
    return (f"{pid} (drawpath) " + " ".join(fields) + "\n").encode("ascii")


_INVENTORY_CRASH_BOOTSTRAP = r"""
import hashlib
import os
from pathlib import Path
import sys
import types

def exact(stream, size):
    value = bytearray()
    while len(value) < size:
        chunk = stream.read(size - len(value))
        if not chunk:
            os._exit(64)
        value.extend(chunk)
    return bytes(value)

stream = sys.stdin.buffer
size = int.from_bytes(exact(stream, 8), "big")
if size < 1 or size > 4 * 1024 * 1024:
    os._exit(64)
source = exact(stream, size)
if (stream.read(1) or
        hashlib.sha256(source).hexdigest() != sys.argv[1]):
    os._exit(64)
module = types.ModuleType("inspect_loader_dependencies")
module.__file__ = "<authenticated-inspect-loader-dependencies>"
module.__package__ = ""
sys.modules[module.__name__] = module
exec(compile(source, module.__file__, "exec", dont_inherit=True),
     module.__dict__)

parent = Path(sys.argv[2])
boundary = int(sys.argv[3])
report = module.load_strict_json(bytes.fromhex(sys.argv[4]))
artifacts = []
for value in sys.argv[5:]:
    name, encoded = value.split("=", 1)
    artifacts.append((name, bytes.fromhex(encoded)))
output = parent / "generation"
real_commit = module._commit_inventory_stage
real_activate = module._activate_inventory_generation
real_verify_terminal = module._verify_terminal_inventory_stage
real_terminal = module._publish_terminal_inventory
committed = 0

def crash_after_activation(*args):
    real_activate(*args)
    if boundary == 0:
        os._exit(80)
module._activate_inventory_generation = crash_after_activation

def crash_after_commit(staged):
    global committed
    real_commit(staged)
    committed += 1
    if committed == boundary:
        os._exit(80 + boundary)
module._commit_inventory_stage = crash_after_commit

def crash_after_terminal_verification(staged):
    real_verify_terminal(staged)
    if boundary == 4:
        os._exit(84)
module._verify_terminal_inventory_stage = crash_after_terminal_verification

def crash_after_terminal(staged):
    real_terminal(staged)
    if boundary == 5:
        os._exit(85)
module._publish_terminal_inventory = crash_after_terminal

with module.InventoryGeneration(output) as generation:
    for name, payload in artifacts:
        generation.stage(name, payload)
    generation.finalize(report)
os._exit(99)
"""


_INVENTORY_TERMINAL_STDOUT_BOOTSTRAP = r"""
import hashlib
import os
from pathlib import Path
import sys
import types

def exact(stream, size):
    value = bytearray()
    while len(value) < size:
        chunk = stream.read(size - len(value))
        if not chunk:
            os._exit(64)
        value.extend(chunk)
    return bytes(value)

stream = sys.stdin.buffer
size = int.from_bytes(exact(stream, 8), "big")
if size < 1 or size > 4 * 1024 * 1024:
    os._exit(64)
source = exact(stream, size)
if (stream.read(1) or
        hashlib.sha256(source).hexdigest() != sys.argv[1]):
    os._exit(64)
module = types.ModuleType("inspect_loader_dependencies")
module.__file__ = "<authenticated-inspect-loader-dependencies>"
module.__package__ = ""
sys.modules[module.__name__] = module
exec(compile(source, module.__file__, "exec", dont_inherit=True),
     module.__dict__)

parent = Path(sys.argv[2])
report = module.load_strict_json(bytes.fromhex(sys.argv[3]))
artifacts = []
for value in sys.argv[4:]:
    name, encoded = value.split("=", 1)
    artifacts.append((name, bytes.fromhex(encoded)))
output = parent / "generation"
with module.InventoryGeneration(output) as generation:
    for name, payload in artifacts:
        generation.stage(name, payload)
    generation.finalize(report)
module._report_terminal_success(
    "INVENTORY_COMPLETE libraries=1 edges=0 unresolved=0 "
    "native_start_allowed=false")
"""


def _run_inventory_terminal_stdout_process(root):
    """Publish once, with the child's real stdout pipe reader already closed."""
    source = loaded_production_source(inv)
    report, artifacts = inventory_generation_fixture()
    encoded_report = json.dumps(
        report, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True).encode("ascii").hex()
    encoded_artifacts = [name + "=" + payload.hex()
                         for name, payload in artifacts]
    process = subprocess.Popen([
        sys.executable, "-I", "-S", "-E", "-s", "-c",
        _INVENTORY_TERMINAL_STDOUT_BOOTSTRAP,
        hashlib.sha256(source).hexdigest(), str(root), encoded_report,
        *encoded_artifacts,
    ], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    process.stdout.close()
    try:
        process.stdin.write(len(source).to_bytes(8, "big") + source)
        process.stdin.close()
    except BrokenPipeError:
        process.stdin.close()
    try:
        code = process.wait(timeout=30)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)
        raise
    stderr = process.stderr.read(1024 * 1024 + 1)
    process.stderr.close()
    return code, stderr, report, artifacts


_STANDALONE_GATE_AUTH_BOOTSTRAP = r"""
import hashlib
from pathlib import Path
import sys
import types

def exact(size):
    value = bytearray()
    while len(value) < size:
        chunk = sys.stdin.buffer.read(size - len(value))
        if not chunk:
            raise SystemExit(64)
        value.extend(chunk)
    return bytes(value)

size = int.from_bytes(exact(8), "big")
if size < 1 or size > 4 * 1024 * 1024:
    raise SystemExit(64)
source = exact(size)
if (sys.stdin.buffer.read(1) or
        hashlib.sha256(source).hexdigest() != sys.argv[1]):
    raise SystemExit(64)
module = types.ModuleType("standalone_dependency_collector")
module.__file__ = sys.argv[2]
module.__package__ = ""
sys.modules[module.__name__] = module
exec(compile(source, module.__file__, "exec", dont_inherit=True),
     module.__dict__)
authority = module.authenticate_elftools(Path(sys.argv[3]))
if (authority.get("version") != "0.32" or authority.get("files") != 54):
    raise SystemExit(65)
mode = sys.argv[4]
if mode == "repeat":
    if module.authenticate_elftools(Path(sys.argv[3])) != authority:
        raise SystemExit(66)
elif mode == "alias-replaced":
    invoked = []
    fake = types.ModuleType(module.AUTHENTICATED_GATE_MODULE)
    def malicious(_root):
        invoked.append(True)
    fake.authenticate_elftools = malicious
    sys.modules[module.AUTHENTICATED_GATE_MODULE] = fake
    try:
        module.authenticate_elftools(Path(sys.argv[3]))
    except module.InventoryError:
        pass
    else:
        raise SystemExit(67)
    if invoked:
        raise SystemExit(68)
elif mode == "method-replaced":
    gate = sys.modules[module.AUTHENTICATED_GATE_MODULE]
    invoked = []
    def malicious(_root):
        invoked.append(True)
    gate.authenticate_elftools = malicious
    try:
        module.authenticate_elftools(Path(sys.argv[3]))
    except module.InventoryError:
        pass
    else:
        raise SystemExit(69)
    if invoked:
        raise SystemExit(70)
elif mode == "helper-replaced":
    gate = sys.modules[module.AUTHENTICATED_GATE_MODULE]
    invoked = []
    def malicious(*_args, **_kwargs):
        invoked.append(True)
        return authority
    gate._verify_and_import = malicious
    try:
        module.authenticate_elftools(Path(sys.argv[3]))
    except module.InventoryError:
        pass
    else:
        raise SystemExit(72)
    if invoked:
        raise SystemExit(73)
elif mode == "builtins-replaced":
    gate = sys.modules[module.AUTHENTICATED_GATE_MODULE]
    gate.__dict__["__builtins__"] = dict(gate.__dict__["__builtins__"])
    try:
        module.authenticate_elftools(Path(sys.argv[3]))
    except module.InventoryError:
        pass
    else:
        raise SystemExit(74)
else:
    raise SystemExit(75)
print("STANDALONE_GATE_AUTHENTICATED " + mode)
"""


_CUSTOM_GATE_SPOOF_BOOTSTRAP = r"""
import hashlib
from pathlib import Path
import sys
import types

def exact(size):
    value = bytearray()
    while len(value) < size:
        chunk = sys.stdin.buffer.read(size - len(value))
        if not chunk:
            raise SystemExit(64)
        value.extend(chunk)
    return bytes(value)

collector_size = int.from_bytes(exact(8), "big")
collector_source = exact(collector_size)
gate_size = int.from_bytes(exact(8), "big")
gate_source = exact(gate_size)
if (sys.stdin.buffer.read(1) or
        hashlib.sha256(collector_source).hexdigest() != sys.argv[1] or
        hashlib.sha256(gate_source).hexdigest() != sys.argv[2]):
    raise SystemExit(64)
collector_path = Path(sys.argv[3])
gate_path = Path(sys.argv[4])
mode = sys.argv[5]
gate = types.ModuleType("__main__" if mode == "custom" else "exact_gate_spoof")
gate.__file__ = str(gate_path)
gate.__package__ = ""
invoked = []
if mode == "custom":
 gate.gate = gate
 exec(r'''
class _PinnedSourceLoader:
    def __init__(self, source, raw, is_package, authority_sha256,
                 gate_authority=None, gate_source=None, gate_method=None):
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
        module.__file__ = str(self.source)
        module.__package__ = ""
        exec(compile(self.raw, str(self.source), "exec", dont_inherit=True),
             module.__dict__)
class _PinnedSourceFinder:
    def __init__(self, sources, authority_sha256, closed_namespaces=(),
                 gate_authority=None, gate_source=None, gate_method=None):
        self.sources = sources
        self.authority_sha256 = authority_sha256
        self.closed_namespaces = frozenset(closed_namespaces)
        self.gate_authority = gate_authority
        self.gate_source = gate_source
        self.gate_method = gate_method
    def find_spec(self, fullname, path=None, target=None):
        return None
''', gate.__dict__)
 def malicious(_root):
    invoked.append(True)
    return {"SPOOF_ACCEPTED": "unused"}
 gate.authenticate_elftools = malicious
 gate_method = malicious
elif mode in ("exact-helper", "pathlike-source", "evil-root"):
 exec(compile(gate_source, str(gate_path), "exec", dont_inherit=True),
      gate.__dict__)
 gate.__name__ = "__main__"
 gate_method = gate.authenticate_elftools
 def malicious(_root):
    invoked.append(True)
    return {"SPOOF_ACCEPTED": "unused"}
 if mode == "exact-helper":
    gate._verify_and_import = malicious
 elif mode == "pathlike-source":
    class MutatingPath:
        def __fspath__(self):
            invoked.append(True)
            gate._verify_and_import = malicious
            return str(gate_path)
    gate.__file__ = MutatingPath()
else:
 raise SystemExit(74)
gate._rtl_reader_authenticated_gate_source = gate_source
authority = "f" * 64
captured = (collector_path, collector_source, False)
finder = gate._PinnedSourceFinder(
    {"inspect_loader_dependencies": captured}, authority,
    gate_authority=gate, gate_source=gate_source, gate_method=gate_method)
loader = gate._PinnedSourceLoader(
    collector_path, collector_source, False, authority,
    gate_authority=gate, gate_source=gate_source, gate_method=gate_method)
collector = types.ModuleType("inspect_loader_dependencies")
collector.__file__ = str(collector_path)
collector.__package__ = ""
collector.__spec__ = types.SimpleNamespace(loader=loader)
sys.modules[collector.__name__] = collector
sys.modules["__main__"] = gate
sys.modules["_rtl_reader_authenticated_elftools_gate"] = gate
sys.meta_path.insert(0, finder)
loader.exec_module(collector)
root_argument = Path("unused")
if mode == "evil-root":
    class EvilRoot:
        def resolve(self, *_args, **_kwargs):
            invoked.append(True)
            gate._verify_and_import = malicious
            return Path("unused")
    root_argument = EvilRoot()
try:
    collector.authenticate_elftools(root_argument)
except collector.InventoryError:
    pass
else:
    raise SystemExit(72)
if invoked:
    raise SystemExit(73)
print("CUSTOM_GATE_SPOOF_REJECTED")
"""


class InventoryTests(unittest.TestCase):
    def test_gate_authentication_rejects_self_consistent_custom_loader_spoof(self):
        collector_source = loaded_production_source(inv)
        gate_source = getattr(sys.modules[inv.AUTHENTICATED_GATE_MODULE],
                              inv.AUTHENTICATED_GATE_SOURCE_ATTR)
        collector_digest = hashlib.sha256(collector_source).hexdigest()
        gate_digest = hashlib.sha256(gate_source).hexdigest()
        collector_path = Path(inv.__file__).absolute()
        gate_path = collector_path.with_name("pinned_elftools_gate.py")
        wire = (len(collector_source).to_bytes(8, "big") + collector_source +
                len(gate_source).to_bytes(8, "big") + gate_source)
        for mode in ("custom", "exact-helper", "pathlike-source", "evil-root"):
            with self.subTest(mode=mode):
                result = subprocess.run([
                    sys.executable, "-I", "-S", "-E", "-s", "-c",
                    _CUSTOM_GATE_SPOOF_BOOTSTRAP, collector_digest, gate_digest,
                    str(collector_path), str(gate_path), mode,
                ], input=wire, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                   timeout=30, check=False)
                self.assertEqual(
                    result.returncode, 0,
                    result.stdout.decode(errors="replace") +
                    result.stderr.decode(errors="replace"))
                self.assertEqual(
                    result.stdout.strip(), b"CUSTOM_GATE_SPOOF_REJECTED")

    def test_gate_authentication_rejects_matching_path_callable_preload(self):
        real_gate = sys.modules[inv.AUTHENTICATED_GATE_MODULE]
        fake = types.ModuleType("__main__")
        fake.__file__ = str(Path(inv.__file__).absolute().with_name(
            "pinned_elftools_gate.py"))
        fake._PinnedSourceLoader = real_gate._PinnedSourceLoader
        setattr(fake, inv.AUTHENTICATED_GATE_SOURCE_ATTR, getattr(
            real_gate, inv.AUTHENTICATED_GATE_SOURCE_ATTR))
        invoked = []

        def malicious(_root):
            invoked.append(True)
            return {"version": "forged"}

        fake.authenticate_elftools = malicious
        with patch.dict(sys.modules, {
                inv.AUTHENTICATED_GATE_MODULE: fake,
                "__main__": fake,
        }):
            with self.assertRaisesRegex(
                    inv.InventoryError,
                    "(?:gate provenance is unavailable|gate authority was replaced)"):
                inv.authenticate_elftools(Path("unused"))
        self.assertEqual(invoked, [])

    def test_gate_authentication_rejects_ordinary_loader_relabeling(self):
        real_gate = sys.modules[inv.AUTHENTICATED_GATE_MODULE]
        source_path = Path(inv.__file__).absolute()
        ordinary = importlib.machinery.SourceFileLoader(
            inv.__name__, str(source_path))
        fake = types.ModuleType("__main__")
        fake.__file__ = str(source_path.with_name("pinned_elftools_gate.py"))
        fake._PinnedSourceLoader = type(ordinary)
        fake._PinnedSourceFinder = real_gate._PinnedSourceFinder
        launch_source = getattr(
            real_gate, inv.AUTHENTICATED_GATE_SOURCE_ATTR)
        setattr(fake, inv.AUTHENTICATED_GATE_SOURCE_ATTR, launch_source)
        invoked = []

        def malicious(_root):
            invoked.append(True)
            return {"version": "forged"}

        fake.authenticate_elftools = malicious
        ordinary.gate_authority = fake
        ordinary.gate_source = launch_source
        ordinary.gate_method = malicious
        with patch.object(inv, "__spec__", types.SimpleNamespace(
                loader=ordinary)), patch.dict(sys.modules, {
                    inv.AUTHENTICATED_GATE_MODULE: fake,
                    "__main__": fake,
                }):
            with self.assertRaisesRegex(
                    inv.InventoryError,
                    "(?:gate provenance is unavailable|gate authority was replaced)"):
                inv.authenticate_elftools(Path("unused"))
        self.assertEqual(invoked, [])

    def test_gate_authentication_reuses_exact_outer_authority(self):
        real_gate = sys.modules[inv.AUTHENTICATED_GATE_MODULE]
        self.assertIs(real_gate, sys.modules["__main__"])
        root = Path(os.environ[real_gate.AUTHENTICATED_ROOT_ENV])
        expected = {
            "version": "0.32",
            "files": 54,
            "sha256": real_gate.EXPECTED_TREE_SHA256,
        }
        self.assertEqual(inv.authenticate_elftools(root), expected)
        self.assertEqual(inv.authenticate_elftools(root), expected)

        invoked = []
        def malicious(_root):
            invoked.append(True)
            return {"version": "forged"}

        fake = types.ModuleType("__main__")
        fake.authenticate_elftools = malicious
        with self.subTest(mutation="alias"), patch.dict(sys.modules, {
                inv.AUTHENTICATED_GATE_MODULE: fake,
        }):
            with self.assertRaisesRegex(
                    inv.InventoryError, "outer gate authority was replaced"):
                inv.authenticate_elftools(root)
        with self.subTest(mutation="method"), patch.object(
                real_gate, "authenticate_elftools", malicious):
            with self.assertRaisesRegex(
                    inv.InventoryError, "outer gate authority was replaced"):
                inv.authenticate_elftools(root)
        loader = inv.__spec__.loader
        with self.subTest(mutation="loader-attribute"), patch.object(
                loader, "gate_method", malicious):
            with self.assertRaisesRegex(
                    inv.InventoryError, "outer gate authority was replaced"):
                inv.authenticate_elftools(root)
        with self.subTest(mutation="transitive-helper"), patch.object(
                real_gate, "_verify_and_import", malicious):
            with self.assertRaisesRegex(
                    inv.InventoryError, "outer gate authority was replaced"):
                inv.authenticate_elftools(root)
        with self.subTest(mutation="method-dict"), patch.dict(
                real_gate.authenticate_elftools.__dict__, {"spoof": True}):
            with self.assertRaisesRegex(
                    inv.InventoryError, "outer gate authority was replaced"):
                inv.authenticate_elftools(root)
        with self.subTest(mutation="builtins"), patch.dict(
                real_gate.__dict__, {"__builtins__": dict(builtins.__dict__)}):
            with self.assertRaisesRegex(
                    inv.InventoryError, "outer gate authority was replaced"):
                inv.authenticate_elftools(root)
        hostile_invoked = []
        class HostileEquality:
            def __hash__(self):
                return 1
            def __eq__(self, _other):
                hostile_invoked.append(True)
                return True
        poisoned_modules = list(real_gate.EXPECTED_PROBE_MODULES)
        poisoned_modules[-1] = HostileEquality()
        with self.subTest(mutation="hostile-set-member"), patch.object(
                real_gate, "EXPECTED_PROBE_MODULES",
                frozenset(poisoned_modules)):
            with self.assertRaisesRegex(
                    inv.InventoryError, "outer gate authority was replaced"):
                inv.authenticate_elftools(root)
        self.assertEqual(hostile_invoked, [])
        self.assertEqual(invoked, [])
        self.assertEqual(inv.authenticate_elftools(root), expected)

    def test_gate_authentication_standalone_executes_captured_source(self):
        source = loaded_production_source(inv)
        digest = hashlib.sha256(source).hexdigest()
        real_gate = sys.modules[inv.AUTHENTICATED_GATE_MODULE]
        root = Path(os.environ[real_gate.AUTHENTICATED_ROOT_ENV])
        for mode in ("repeat", "alias-replaced", "method-replaced",
                     "helper-replaced", "builtins-replaced"):
            with self.subTest(mode=mode):
                result = subprocess.run([
                    sys.executable, "-I", "-S", "-E", "-s", "-c",
                    _STANDALONE_GATE_AUTH_BOOTSTRAP, digest,
                    str(Path(inv.__file__).absolute()), str(root), mode,
                ], input=len(source).to_bytes(8, "big") + source,
                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
                   check=False)
                self.assertEqual(
                    result.returncode, 0,
                    result.stdout.decode(errors="replace") +
                    result.stderr.decode(errors="replace"))
                self.assertEqual(result.stdout.strip(),
                    ("STANDALONE_GATE_AUTHENTICATED " + mode).encode("ascii"))

    @unittest.skipUnless(ELF_AVAILABLE,
                         "run explicitly with --python-path for inventory main")
    def _run_actual_inventory_main(self, before_raw, after_raw=None, *,
                                   before_cmdline=b"com.ratta.drawpath\0",
                                   after_cmdline=None, command_log=None):
        after_raw = before_raw if after_raw is None else after_raw
        after_cmdline = before_cmdline if after_cmdline is None else after_cmdline
        command_log = [] if command_log is None else command_log
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            adb = root / "adb"
            adb.write_bytes(b"fixture")
            output = root / "inventory"
            maps_captures = []
            cmdline_captures = []

            def command_result(command, _limit, _timeout=30):
                command_log.append(tuple(command))
                joined = " ".join(command)
                if "ro.build.fingerprint" in joined:
                    return (inv.FINGERPRINT + "\n").encode("utf-8")
                if "pidof com.ratta.drawpath" in joined:
                    return b"1425\n"
                if "/proc/1425/stat" in joined:
                    return process_stat()
                if "/proc/1425/cmdline" in joined:
                    value = (before_cmdline if not cmdline_captures else
                             after_cmdline)
                    cmdline_captures.append(value)
                    return value
                if "/proc/1425/maps" in joined:
                    value = before_raw if not maps_captures else after_raw
                    maps_captures.append(value)
                    return value
                raise AssertionError("unexpected inventory producer: " + joined)

            library_payload = b"x" * 1024
            fixture = inventory_v4(library_payload, before_raw)

            def collect_fixture(_maps, _read_library, publish_library=None):
                libraries = copy.deepcopy(fixture["libraries"])
                if publish_library is not None:
                    publish_library(inv.ROOT_LIBRARY,
                                    libraries[inv.ROOT_LIBRARY],
                                    library_payload)
                return libraries, []

            parser_root = Path(elftools.__file__).resolve().parent.parent
            old_argv, old_path = list(sys.argv), list(sys.path)
            try:
                sys.argv = ["inspect_loader_dependencies.py", "--adb", str(adb),
                            "--python-path", str(parser_root), "--output", str(output)]
                with patch.object(inv, "bounded_command", side_effect=command_result), \
                     patch.object(inv, "collect_graph", side_effect=collect_fixture), \
                     contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(inv.main(), 0)
                self.assertEqual(maps_captures, [before_raw, after_raw])
                self.assertEqual(cmdline_captures,
                                 [before_cmdline, after_cmdline])
                producer_kinds = []
                for command in command_log:
                    joined = " ".join(command)
                    if "ro.build.fingerprint" in joined:
                        producer_kinds.append("fingerprint")
                    elif "pidof com.ratta.drawpath" in joined:
                        producer_kinds.append("pid")
                    elif "/proc/1425/stat" in joined:
                        producer_kinds.append("stat")
                    elif "/proc/1425/cmdline" in joined:
                        producer_kinds.append("cmdline")
                    elif "/proc/1425/maps" in joined:
                        producer_kinds.append("maps")
                self.assertEqual(producer_kinds, [
                    "fingerprint", "pid", "stat", "cmdline", "maps", "stat",
                    "stat", "cmdline", "maps", "stat"])
                return {item.name: item.read_bytes() for item in output.iterdir()}
            finally:
                sys.argv[:] = old_argv
                sys.path[:] = old_path

    def test_inventory_json_rejects_duplicates_and_nonfinite_numbers(self):
        self.assertEqual(inv.load_strict_json(b'{"schema":"ok"}'),{"schema":"ok"})
        for raw in (b'{"schema":1,"schema":2}',b'{"value":NaN}',b'{"value":Infinity}',
                    b'{"value":1.0}',b'{"value":1e9999}'):
            with self.subTest(raw=raw),self.assertRaises(inv.InventoryError):
                inv.load_strict_json(raw)

    def test_committed_relocation_exit_class_survives_broken_stderr(self):
        error = inv.InventoryCommittedRelocatedError("committed elsewhere")
        with patch("builtins.print", side_effect=BrokenPipeError("closed")):
            self.assertEqual(inv._report_committed_relocated(error), 2)
        with patch("builtins.print", side_effect=ValueError("closed")):
            self.assertEqual(inv._report_committed_relocated(error), 2)

    def test_terminal_success_immediate_stdout_failure_is_neutralized(self):
        class FailedStdout:
            def write(self, _):
                raise BrokenPipeError("stdout reader closed")
            def flush(self):
                raise BrokenPipeError("stdout reader closed")
            def fileno(self):
                raise ValueError("stdout has no descriptor")

        failed = FailedStdout()
        with patch.object(sys, "stdout", failed):
            inv._report_terminal_success(
                "INVENTORY_COMPLETE libraries=1 edges=0 unresolved=0 "
                "native_start_allowed=false")
            self.assertIsNot(sys.stdout, failed)
            replacement = sys.stdout
        replacement.close()

    def test_stdout_neutralization_keeps_reclaimed_target_descriptor_open(self):
        class ReclaimedDescriptorStream:
            def __init__(self):
                self.flushes = 0
            def fileno(self):
                return 23
            def flush(self):
                self.flushes += 1

        stream = ReclaimedDescriptorStream()
        with patch.object(sys, "stdout", stream), \
             patch.object(inv.os, "open", return_value=23), \
             patch.object(inv.os, "dup2") as duplicate, \
             patch.object(inv.os, "close") as close_descriptor:
            inv._neutralize_failed_stdout(stream)
            self.assertIsNot(sys.stdout, stream)
            replacement = sys.stdout
        replacement.close()
        duplicate.assert_not_called()
        close_descriptor.assert_not_called()
        self.assertEqual(stream.flushes, 1)

    def test_stdout_neutralization_clears_wrapper_when_devnull_allocation_fails(self):
        class FailedStdout:
            def fileno(self):
                return 23
            def flush(self):
                raise BrokenPipeError("stdout reader closed")

        failed = FailedStdout()
        with patch.object(sys, "stdout", failed), \
             patch.object(inv.os, "open", side_effect=OSError("fd exhausted")), \
             patch("builtins.open", side_effect=OSError("fd exhausted")):
            inv._neutralize_failed_stdout(failed)
            self.assertIsNone(sys.stdout)

    def test_terminal_success_survives_closed_pipe_after_inventory_commit(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            code, stderr, report, artifacts = \
                _run_inventory_terminal_stdout_process(root)
            self.assertEqual(code, 0, stderr.decode(errors="replace"))
            generation = root / "generation"
            authority = generation / "inventory.json"
            self.assertEqual(inv.load_strict_json(authority.read_bytes()), report)
            expected_names = {"inventory.json", *(name for name, _ in artifacts)}
            self.assertEqual({path.name for path in generation.iterdir()},
                             expected_names)
            self.assertEqual(list(generation.glob("inventory.json")), [authority])
            self.assertEqual(list(root.glob(".inventory-generation-*.tmp")), [])

    def test_inventory_generation_commits_authenticated_authority_last(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "generation"
            events = []
            real_commit = inv._commit_inventory_stage
            real_terminal = inv._publish_terminal_inventory

            def record_commit(staged):
                real_commit(staged)
                events.append(("commit", staged.output.name))

            def record_terminal(staged):
                real_terminal(staged)
                events.append(("terminal", "inventory.json"))

            report, artifacts = inventory_generation_fixture()
            with patch.object(inv, "_commit_inventory_stage",
                              side_effect=record_commit), \
                 patch.object(inv, "_publish_terminal_inventory",
                              side_effect=record_terminal):
                with inv.InventoryGeneration(output) as generation:
                    self.assertTrue(output.is_dir())
                    self.assertFalse((output / "inventory.json").exists())
                    stage_generation(generation, artifacts)
                    generation.finalize(report)

            self.assertEqual([event[1] for event in events[:3]],
                             [name for name, _ in artifacts])
            self.assertEqual(events[-1], ("terminal", "inventory.json"))
            self.assertEqual(len(events), 4)
            for name, payload in artifacts:
                self.assertEqual((output / name).read_bytes(), payload)
            self.assertEqual(inv.load_strict_json(
                (output / "inventory.json").read_bytes()), report)
            self.assertEqual(sorted(item.name for item in output.iterdir()), [
                "0123456789abcdef.so", "inventory.json", "maps-after.txt",
                "maps-before.txt"])

    def test_inventory_generation_failure_before_authority_is_unambiguous(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "generation"
            real_commit = inv._commit_inventory_stage
            commits = 0

            def fail_after_first_commit(staged):
                nonlocal commits
                real_commit(staged)
                commits += 1
                if commits == 1:
                    raise OSError("injected post-data-commit failure")

            with patch.object(inv, "_commit_inventory_stage",
                              side_effect=fail_after_first_commit), \
                 self.assertRaisesRegex(OSError, "injected post-data-commit"):
                report, artifacts = inventory_generation_fixture()
                with inv.InventoryGeneration(output) as generation:
                    stage_generation(generation, artifacts)
                    generation.finalize(report)
            self.assertTrue(output.is_dir())
            self.assertTrue((output / "maps-before.txt").is_file())
            self.assertFalse((output / "inventory.json").exists())
            self.assertEqual(list(Path(temp).glob(".inventory-generation-*.tmp")), [])

    def test_inventory_crash_bootstrap_requires_exact_source_frame(self):
        source = b"raise SystemExit(99)\n"
        digest = hashlib.sha256(source).hexdigest()
        for suffix, expected in ((b"", 99), (b"trailing", 64)):
            with self.subTest(suffix=suffix):
                process = subprocess.run([
                    sys.executable, "-I", "-S", "-c",
                    _INVENTORY_CRASH_BOOTSTRAP, digest,
                ], input=len(source).to_bytes(8, "big") + source + suffix,
                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                   timeout=10, check=False)
                self.assertEqual(process.returncode, expected)

    def test_inventory_generation_hard_crash_has_no_terminal_authority(self):
        with tempfile.TemporaryDirectory() as temp:
            root_temp = Path(temp)
            source = loaded_production_source(inv)
            mutable_source_sentinel = root_temp / "mutable-source-path-executed"
            current_loader = getattr(globals().get("__spec__"), "loader", None)
            if getattr(current_loader, "authority_sha256", None) is not None:
                mutable_source = root_temp / "inspect_loader_dependencies.py"
                mutable_source.write_text(
                    "from pathlib import Path\nPath(" +
                    repr(str(mutable_source_sentinel)) +
                    ").write_text('executed')\n", encoding="utf-8")
                with patch.object(inv, "__file__", str(mutable_source)):
                    self.assertEqual(loaded_production_source(inv), source)
            source_digest = hashlib.sha256(source).hexdigest()
            report, artifacts = inventory_generation_fixture()
            encoded_report = json.dumps(
                report, sort_keys=True, separators=(",", ":"),
                ensure_ascii=True).encode("ascii").hex()
            encoded_artifacts = [name + "=" + payload.hex()
                                 for name, payload in artifacts]
            for boundary in range(6):
                root = Path(temp) / f"case-{boundary}"
                root.mkdir()
                # Execute the exact already-loaded production bytes in an
                # isolated child. Multiprocessing spawn would re-import this
                # test module through a mutable pathname on Windows.
                process = subprocess.run([
                    sys.executable, "-I", "-S", "-c",
                    _INVENTORY_CRASH_BOOTSTRAP, source_digest, str(root),
                    str(boundary), encoded_report, *encoded_artifacts,
                ], input=len(source).to_bytes(8, "big") + source,
                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                   timeout=15, check=False)
                self.assertEqual(
                    process.returncode, 80 + boundary,
                    process.stderr.decode("utf-8", errors="replace"))
                generation = root / "generation"
                self.assertTrue(generation.is_dir())
                self.assertEqual(list(root.glob(".inventory-generation-*.tmp")), [])
                if boundary < 5:
                    self.assertFalse((generation / "inventory.json").exists())
                else:
                    report, _ = inventory_generation_fixture()
                    self.assertEqual(
                        inv.load_strict_json((generation / "inventory.json").read_bytes()),
                        report)
            self.assertFalse(mutable_source_sentinel.exists())

    def test_inventory_generation_rejects_ambiguous_names_and_reuse(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "generation"
            with inv.InventoryGeneration(output) as generation:
                generation.stage("one", b"1")
                for name in ("one", "inventory.json", ".inventory-private",
                             "../escape", "a/b", ""):
                    with self.subTest(name=name), self.assertRaises(inv.InventoryError):
                        generation.stage(name, b"x")
                if os.name == "nt":
                    with self.assertRaises(inv.InventoryError):
                        generation.stage("one:alternate", b"x")
            other = Path(temp) / "complete"
            report, artifacts = inventory_generation_fixture()
            with inv.InventoryGeneration(other) as generation:
                stage_generation(generation, artifacts)
                generation.finalize(report)
            with self.assertRaises((inv.InventoryError, OSError)):
                with inv.InventoryGeneration(other):
                    pass
            self.assertEqual(list(Path(temp).glob(".inventory-generation-*.tmp")), [])

    def test_inventory_generation_staging_enforces_exact_payload_boundaries(self):
        with tempfile.TemporaryDirectory() as temp, \
             patch.object(inv, "MAX_FILE_BYTES", 4):
            output = Path(temp) / "generation"
            with inv.InventoryGeneration(output) as generation:
                generation.stage("at-cap", b"1234")
                self.assertEqual(generation.stages[-1].size, 4)
                self.assertEqual(generation.stages[-1].sha256,
                                 hashlib.sha256(b"1234").hexdigest())
                for index, payload in enumerate((b"", b"12345", bytearray(b"1"))):
                    with self.subTest(payload=payload), \
                         self.assertRaisesRegex(inv.InventoryError,
                                                "invalid staged inventory payload"):
                        generation.stage(f"rejected-{index}", payload)
            self.assertTrue(output.is_dir())
            self.assertEqual(list(output.iterdir()), [])

    def test_inventory_generation_postcommit_cleanup_cannot_report_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "generation"
            real_close = inv._InventoryStage.close

            def noisy_close(stage, publication_committed=False):
                real_close(stage, publication_committed)
                raise OSError("injected cleanup diagnostic")

            with patch.object(inv._InventoryStage, "close", noisy_close):
                report, artifacts = inventory_generation_fixture()
                with inv.InventoryGeneration(output) as generation:
                    stage_generation(generation, artifacts)
                    generation.finalize(report)
            self.assertTrue((output / "inventory.json").is_file())

    def test_inventory_generation_parent_replacement_cannot_redirect_activation(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            parent = root / "parent"
            moved = root / "moved"
            parent.mkdir()
            output = parent / "generation"
            report, artifacts = inventory_generation_fixture()
            with inv.InventoryGeneration(output) as generation:
                stage_generation(generation, artifacts)
                if os.name == "nt":
                    # The retained Windows parent denies delete sharing, so the
                    # redirection attempt itself must fail.
                    with self.assertRaises(OSError):
                        parent.rename(moved)
                    generation.finalize(report)
                    self.assertTrue((output / "inventory.json").is_file())
                else:
                    parent.rename(moved)
                    parent.mkdir()
                    with self.assertRaisesRegex(
                            inv.InventoryError, "directory name was replaced"):
                        generation.finalize(report)
                    self.assertFalse((output / "inventory.json").exists())
                    self.assertFalse((moved / "generation" / "inventory.json").exists())

    def test_inventory_generation_output_replacement_cannot_redirect_terminal(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output = root / "generation"
            moved = root / "moved-generation"
            report, artifacts = inventory_generation_fixture()
            with inv.InventoryGeneration(output) as generation:
                stage_generation(generation, artifacts)
                if os.name == "nt":
                    # Retained child authorities deny the attempted directory
                    # move on Windows; complete the original generation.
                    with self.assertRaises(OSError):
                        output.rename(moved)
                    generation.finalize(report)
                    self.assertTrue((output / "inventory.json").is_file())
                    return
                output.rename(moved)
                output.mkdir()
                with self.assertRaisesRegex(
                        inv.InventoryError, "directory name was replaced"):
                    generation.finalize(report)
            self.assertFalse((output / "inventory.json").exists())
            self.assertFalse((moved / "inventory.json").exists())

    def test_terminal_race_is_success_or_explicit_nonretryable_relocation(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output = root / "generation"
            moved = root / "moved-generation"
            report, artifacts = inventory_generation_fixture()
            real_terminal = inv._publish_terminal_inventory

            def relocate_at_terminal(stage):
                if os.name == "nt":
                    with self.assertRaises(OSError):
                        output.rename(moved)
                else:
                    output.rename(moved)
                    output.mkdir()
                real_terminal(stage)

            context = (contextlib.nullcontext() if os.name == "nt" else
                       self.assertRaisesRegex(
                           inv.InventoryCommittedRelocatedError,
                           "do not retry automatically"))
            with patch.object(inv, "_publish_terminal_inventory",
                              side_effect=relocate_at_terminal), context:
                with inv.InventoryGeneration(output) as generation:
                    stage_generation(generation, artifacts)
                    generation.finalize(report)
            if os.name == "nt":
                self.assertEqual(inv.load_strict_json(
                    (output / "inventory.json").read_bytes()), report)
            else:
                self.assertFalse((output / "inventory.json").exists())
                self.assertEqual(inv.load_strict_json(
                    (moved / "inventory.json").read_bytes()), report)

    def test_inventory_generation_existing_target_leaks_no_handle_or_private_dir(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output = root / "generation"
            output.mkdir()
            with self.assertRaises((inv.InventoryError, OSError)):
                with inv.InventoryGeneration(output):
                    pass
            self.assertEqual(list(root.glob(".inventory-generation-*.tmp")), [])
            # Windows can remove this only if every retained handle was closed.
            output.rmdir()
            self.assertFalse(output.exists())

    def test_inventory_generation_terminal_name_collision_is_no_replace(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "generation"
            report, artifacts = inventory_generation_fixture()
            with inv.InventoryGeneration(output) as generation:
                stage_generation(generation, artifacts)
                competitor = b"not authenticated inventory"
                (output / "inventory.json").write_bytes(competitor)
                with self.assertRaises((inv.InventoryError, OSError)):
                    generation.finalize(report)
            self.assertEqual((output / "inventory.json").read_bytes(), competitor)

    def test_terminal_publication_uses_retained_stage_not_private_name(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "generation"
            report, artifacts = inventory_generation_fixture()
            real_terminal = inv._publish_terminal_inventory

            def replace_private_name_then_publish(stage):
                if os.name == "posix":
                    self.assertIsNone(stage.temporary_name)
                    decoy = output / ".inventory-authority-decoy.tmp"
                    decoy.write_bytes(b"replacement")
                    decoy.unlink()
                else:
                    self.assertIsNotNone(stage.temporary_name)
                    private = output / stage.temporary_name
                    moved = output / ".moved-terminal.tmp"
                    # The retained stage denies delete/write sharing, so a
                    # competing name substitution cannot begin.
                    with self.assertRaises(OSError):
                        private.rename(moved)
                real_terminal(stage)

            with patch.object(inv, "_publish_terminal_inventory",
                              side_effect=replace_private_name_then_publish):
                with inv.InventoryGeneration(output) as generation:
                    stage_generation(generation, artifacts)
                    generation.finalize(report)
            self.assertEqual(inv.load_strict_json(
                (output / "inventory.json").read_bytes()), report)

    def test_inventory_generation_binds_exact_artifact_set_size_and_digest(self):
        report, artifacts = inventory_generation_fixture()
        cases = []
        cases.append(("missing", artifacts[:-1], report))
        cases.append(("extra", artifacts + [("extra", b"x")], report))
        wrong_raw = list(artifacts)
        wrong_raw[0] = (wrong_raw[0][0], wrong_raw[0][1] + b"x")
        cases.append(("raw-bytes", wrong_raw, report))
        wrong_sha = copy.deepcopy(report)
        wrong_sha["libraries"][inv.ROOT_LIBRARY]["sha256"] = "0" * 64
        cases.append(("library-sha", artifacts, wrong_sha))
        wrong_size = copy.deepcopy(report)
        metadata = wrong_size["libraries"][inv.ROOT_LIBRARY]
        metadata["bytes"] += 1
        metadata["mappedFileIdentity"]["bytes"] += 1
        cases.append(("library-size", artifacts, wrong_size))
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for index, (label, staged, authority) in enumerate(cases):
                output = root / f"generation-{index}"
                with self.subTest(case=label), self.assertRaisesRegex(
                        inv.InventoryError,
                        "staged artifacts differ from inventory authority"):
                    with inv.InventoryGeneration(output) as generation:
                        stage_generation(generation, staged)
                        generation.finalize(authority)
                self.assertFalse((output / "inventory.json").exists())

    def test_mapped_descriptor_identity_and_capture(self):
        maps=inv.mapped_libraries(record(inv.ROOT_LIBRARY))[inv.ROOT_LIBRARY]
        header=b"64772:123:4:81a4:1:1"
        data,identity=inv.parse_mapped_capture(header+b"\nELFx"+header+b"\n",maps)
        self.assertEqual(data,b"ELFx")
        self.assertEqual(identity["authority"],"proc-map-files-open-descriptor-v1")
        self.assertEqual(identity["device"],"fd:04")
        report=inventory_v4()
        report["libraries"][inv.ROOT_LIBRARY]["mappedFileIdentity"]=identity
        report["libraries"][inv.ROOT_LIBRARY]["bytes"]=4
        report["libraries"][inv.ROOT_LIBRARY]["sha256"]="f"*64
        self.assertIs(inv.validate_inventory_v4(report),report)
        for wrong in (b"64773:123:4:81a4:1:1",b"64772:124:4:81a4:1:1",
                      b"64772:123:4:21b6:1:1",b"64772:123:67108865:81a4:1:1"):
            with self.assertRaises(inv.InventoryError): inv.mapped_file_identity(wrong,maps)
        for body in (header+b"\nELF"+header+b"\n",header+b"\nELFx"+header[:-1]+b"2\n",
                     header+b"\nELFxx"+header+b"\n"):
            with self.assertRaises(inv.InventoryError): inv.parse_mapped_capture(body,maps)
        command=inv.mapped_capture_command(1425,maps)
        self.assertIn("/proc/1425/map_files/1000-2000",command)
        self.assertNotIn(inv.ROOT_LIBRARY,command)
        self.assertIn("count=1025",command)
        self.assertLess(command.index('[ "$size" -le 67108864 ]'),command.index("dd if="))
        with self.assertRaises(inv.InventoryError):
            inv.mapped_capture_command(1425,maps,inv.MAX_FILE_BYTES+1)

    def test_bounded_local_reads_reject_size_and_type(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/"data"
            path.write_bytes(b"abcd")
            self.assertEqual(inv.read_bounded(path,4,4),b"abcd")
            for limit,size in ((3,None),(4,3),(4,True)):
                with self.assertRaises(inv.InventoryError): inv.read_bounded(path,limit,size)
            with self.assertRaises(inv.InventoryError): inv.read_bounded(Path(temp))
            # Simulate growth after descriptor-size check: actual read remains
            # explicitly limited to old size+1 and rejects the extra byte.
            class Growing(io.BytesIO):
                def fileno(self): return 7
            old=path.stat()
            with patch.object(inv.os,"fstat",return_value=old):
                with self.assertRaises(inv.InventoryError):
                    inv._read_opened_bounded(Growing(b"abcde"),old,4)

    def test_bounded_local_read_rejects_symlink_or_fifo_without_blocking(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); target=root/"target"; target.write_bytes(b"ok")
            link=root/"link"
            try:
                link.symlink_to(target)
            except OSError:
                link=None
            if link is not None:
                with self.assertRaises(inv.InventoryError): inv.read_bounded(link,8)
            if os.name == "posix":
                fifo=root/"fifo"; os.mkfifo(fifo)
                started=time.monotonic()
                with self.assertRaises(inv.InventoryError): inv.read_bounded(fifo,8)
                self.assertLess(time.monotonic()-started,0.5)

    @unittest.skipUnless(os.name == "posix", "POSIX permits an OS-backed same-inode mutation")
    def test_bounded_read_rejects_same_inode_mmap_overwrite_after_materialization(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/"evidence"; path.write_bytes(b"original")
            with path.open("r+b") as backing:
                mapped=mmap.mmap(backing.fileno(),0,access=mmap.ACCESS_WRITE)
            original=inv._read_opened_bounded
            mutated=[]
            def mutate_after_read(*args,**kwargs):
                data=original(*args,**kwargs)
                before=path.stat()
                mapped.seek(0);mapped.write(b"mutated!");mapped.flush()
                after=path.stat()
                self.assertEqual((before.st_dev,before.st_ino),(after.st_dev,after.st_ino))
                mutated.append(True)
                return data
            try:
                with patch.object(inv,"_read_opened_bounded",side_effect=mutate_after_read):
                    with self.assertRaises(inv.InventoryError) as rejected:
                        inv.read_bounded(path,8,8)
            finally:
                mapped.close()
            self.assertEqual(mutated,[True],str(rejected.exception))

    @unittest.skipUnless(os.name == "nt", "Windows retained handle denies writers")
    def test_windows_retained_authority_prevents_same_inode_overwrite(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);path=root/"evidence";path.write_bytes(b"original")
            before=path.stat()
            with inv.EvidenceDirectory(root) as authority:
                witness={}
                with authority.open_regular("evidence",witness) as (stream,opened):
                    data=inv._read_opened_bounded(stream,opened,8,8)
                    witness["data"]=data
                    with self.assertRaises(OSError):
                        path.write_bytes(b"mutated!")
                self.assertEqual(data,b"original")
            after=path.stat()
            self.assertEqual((before.st_dev,before.st_ino),(after.st_dev,after.st_ino))
            self.assertEqual(path.read_bytes(),b"original")

    @unittest.skipUnless(os.name == "nt", "Windows alternate data streams")
    def test_windows_real_ads_is_rejected_before_evidence_open(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);base=root/"evidence";base.write_bytes(b"base")
            ads=Path(str(base)+":hidden")
            try:
                ads.write_bytes(b"alternate")
            except OSError as error:
                self.skipTest("test volume does not support alternate streams: "+str(error))
            self.assertEqual(ads.read_bytes(),b"alternate")
            with self.assertRaisesRegex(inv.InventoryError,"filename|alternate stream"):
                inv.read_bounded(ads,16)
            with self.assertRaisesRegex(inv.InventoryError,"alternate stream"):
                with inv.EvidenceDirectory(Path(str(root)+":directory-stream")):
                    pass
            with inv.EvidenceDirectory(root) as authority:
                with self.assertRaisesRegex(inv.InventoryError,"child name|filename"):
                    authority.read("evidence:hidden",16)

    @unittest.skipUnless(os.name == "posix", "POSIX retained-directory authority")
    def test_retained_directory_survives_ancestor_rename_and_rejects_child_aba(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); admitted=root/"admitted"; admitted.mkdir()
            (admitted/"evidence").write_bytes(b"original")
            with inv.EvidenceDirectory(admitted) as authority:
                moved=root/"moved"; admitted.rename(moved); admitted.mkdir()
                (admitted/"evidence").write_bytes(b"replacement")
                self.assertEqual(authority.read("evidence",16),b"original")
                with self.assertRaisesRegex(
                        inv.InventoryError,"changed during read|name replaced"):
                    with authority.open_regular("evidence") as (stream,_):
                        self.assertEqual(stream.read(),b"original")
                        (moved/"evidence").rename(moved/"old")
                        (moved/"evidence").write_bytes(b"aba")

    @unittest.skipUnless(os.name == "posix", "POSIX no-follow ancestor walk")
    def test_evidence_directory_rejects_symlinked_ancestor(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); target=root/"target"; target.mkdir()
            alias=root/"alias"; alias.symlink_to(target,target_is_directory=True)
            with self.assertRaises((inv.InventoryError,OSError)):
                with inv.EvidenceDirectory(alias):
                    pass

    def test_bounded_command_overflow_failure_and_timeout(self):
        self.assertEqual(inv.bounded_command([sys.executable,"-c","print('ok')"],10).strip(),b"ok")
        self.assertEqual(inv.bounded_command(
            [sys.executable,"-c","import time;time.sleep(.05);print('slow ok')"],16,2).strip(),
            b"slow ok")
        self.assertEqual(inv.bounded_command(
            [sys.executable,"-c","import sys;sys.stdout.buffer.write(b'x'*10)"],10),b"x"*10)
        for code,limit,timeout in (("print('x'*10000)",10,3),("raise SystemExit(3)",10,3),
                                    ("import time;time.sleep(3)",10,0.1)):
            with self.assertRaises(inv.InventoryError): inv.bounded_command([sys.executable,"-c",code],limit,timeout)
        for exit_code in range(1,5):
            with self.subTest(exit_code=exit_code), \
                 self.assertRaisesRegex(inv.InventoryError,"bounded command failed"):
                inv.bounded_command([sys.executable,"-c",f"raise SystemExit({exit_code})"],16,2)
        self.assertEqual(inv.MAX_BOUNDED_COMMAND_SPEC, runner.MAX_SPEC)
        with patch.object(inv, "MAX_BOUNDED_COMMAND_SPEC", 64), \
             patch.object(inv, "_popen_before_deadline") as posix_spawn, \
             patch.object(inv, "_windows_supervise_worker") as windows_spawn:
            for command in (["x" * 64], ["\x01" * 12], [""] * 22):
                with self.subTest(command_parts=len(command)), \
                     self.assertRaisesRegex(inv.InventoryError,
                                            "specification exceeds budget|invalid command budget"):
                    inv.bounded_command(command, 16, 2)
            posix_spawn.assert_not_called()
            windows_spawn.assert_not_called()

    def test_bounded_command_overflow_is_incremental_and_prompt(self):
        started=time.monotonic()
        with self.assertRaisesRegex(inv.InventoryError,"output budget exceeded"):
            inv.bounded_command([sys.executable,"-c",
                "import sys;sys.stdout.buffer.write(b'x'*(8*1024*1024))"],1024,5)
        self.assertLess(time.monotonic()-started,3)

    def test_bounded_runner_specification_requires_terminal_eof(self):
        specification = json.dumps({
            "command": ["program", "argument"], "limit": 32,
            "deadlineNs": 1,
        }, separators=(",", ":")).encode("ascii") + b"\n"
        fake_stdin = types.SimpleNamespace(buffer=io.BytesIO(specification))
        with patch.object(runner.sys, "stdin", fake_stdin):
            self.assertEqual(
                runner._specification(), (["program", "argument"], 32, 1))
        for trailing in (b"x", b"\n", b"{}\n"):
            with self.subTest(trailing=trailing), \
                 patch.object(runner.sys, "stdin", types.SimpleNamespace(
                     buffer=io.BytesIO(specification + trailing))), \
                 self.assertRaisesRegex(ValueError, "invalid bounded-command"):
                runner._specification()

    def test_runner_bootstrap_installs_real_main_module(self):
        source = (
            b"import sys,types\n"
            b"assert isinstance(sys.modules['__main__'], types.ModuleType)\n"
            b"assert sys.modules['__main__'].__dict__ is globals()\n"
            b"assert __file__ == '<authenticated-bounded-command-runner>'\n"
            b"assert __package__ == ''\n"
            b"sys.stdout.buffer.write(b'RUNNER_MAIN_AUTHORITY')\n"
        )
        digest = hashlib.sha256(source).hexdigest()
        process = subprocess.run([
            sys.executable, "-I", "-S", "-c", inv.RUNNER_BOOTSTRAP,
            digest, str(len(source)),
        ], input=len(source).to_bytes(8, "big") + source,
           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
           timeout=10, check=False)
        self.assertEqual(
            process.returncode, 0,
            process.stderr.decode("utf-8", errors="replace"))
        self.assertEqual(process.stdout, b"RUNNER_MAIN_AUTHORITY")

    def test_authenticated_runner_capture_is_newline_stable_and_strict(self):
        canonical = loaded_production_source(runner)
        self.assertEqual(hashlib.sha256(canonical).hexdigest(),
                         inv.PINNED_RUNNER_SHA256)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            anchor = root / "inspect_loader_dependencies.py"
            worker = root / "bounded_command_runner.py"
            anchor.write_bytes(b"")
            with patch.object(inv, "__file__", str(anchor)):
                worker.write_bytes(canonical.replace(b"\n", b"\r\n"))
                self.assertEqual(inv._authenticated_runner_source(), canonical)
                worker.write_bytes(canonical.replace(b"\n", b"\r\n", 1))
                with self.assertRaisesRegex(inv.InventoryError, "newlines changed"):
                    inv._authenticated_runner_source()
                worker.write_bytes(canonical + b"# changed\n")
                with self.assertRaisesRegex(inv.InventoryError, "runner changed"):
                    inv._authenticated_runner_source()

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "mkfifo"),
                         "POSIX nonblocking authenticated-runner open")
    def test_authenticated_runner_fifo_replacement_fails_without_blocking(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            anchor = root / "inspect_loader_dependencies.py"
            worker = root / "bounded_command_runner.py"
            anchor.write_bytes(b"")
            os.mkfifo(worker)
            started = time.monotonic()
            with patch.object(inv, "__file__", str(anchor)), \
                 self.assertRaises(inv.InventoryError):
                inv._authenticated_runner_source()
            self.assertLess(time.monotonic() - started, 1)

    def test_bounded_command_executes_captured_runner_after_name_replacement(self):
        canonical = loaded_production_source(runner)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            anchor = root / "inspect_loader_dependencies.py"
            worker = root / "bounded_command_runner.py"
            backup = root / "captured-runner.py"
            sentinel = root / "mutable-path-executed"
            anchor.write_bytes(b"")
            worker.write_bytes(canonical)
            real_spawn = inv._popen_before_deadline
            observed_commands = []

            def replace_then_spawn(command, deadline, **kwargs):
                observed_commands.append(command)
                os.replace(worker, backup)
                # First replace the authenticated name with the exact same
                # content, then mutate that new inode before child startup.
                worker.write_bytes(canonical)
                worker.write_text(
                    "from pathlib import Path\nPath(" + repr(str(sentinel)) +
                    ").write_text('executed')\n", encoding="utf-8")
                return real_spawn(command, deadline, **kwargs)

            with patch.object(inv, "__file__", str(anchor)), \
                 patch.object(inv, "_popen_before_deadline",
                              side_effect=replace_then_spawn):
                output = inv.bounded_command(
                    [sys.executable, "-c", "print('captured')"], 32, 3)
            self.assertEqual(output.strip(), b"captured")
            self.assertFalse(sentinel.exists())
            self.assertEqual(len(observed_commands), 1)
            self.assertNotIn(str(worker), observed_commands[0])

    def test_process_creation_gates_never_call_popen_after_original_deadline(self):
        with patch.object(runner.time, "monotonic_ns", return_value=100), \
             patch.object(runner.subprocess, "Popen") as spawned:
            self.assertIsNone(runner._windows_popen_before_deadline(
                ["never"], 100, stdout=subprocess.PIPE))
            spawned.assert_not_called()

        pipe_pairs = [(101, 102), (103, 104), (105, 106)]
        for failing_pipe in (1, 2, 3):
            calls = []
            closed = []
            def pipe2(_flags):
                calls.append(len(calls) + 1)
                if len(calls) == failing_pipe:
                    raise OSError("injected pipe allocation fault")
                return pipe_pairs[len(calls) - 1]
            with patch.object(runner.os, "O_CLOEXEC", 1, create=True), \
                 patch.object(runner.os, "pipe2", side_effect=pipe2,
                              create=True), \
                 patch.object(runner.os, "close", side_effect=closed.append), \
                 patch.object(runner.os, "set_blocking") as set_blocking, \
                 patch.object(runner.os, "fork", create=True) as fork, \
                 self.subTest(failing_pipe=failing_pipe), \
                 self.assertRaisesRegex(OSError, "pipe allocation fault"):
                runner._linux_spawn_gated(["unused"], time.monotonic_ns() + 1)
            expected = [descriptor for pair in pipe_pairs[:failing_pipe - 1]
                        for descriptor in pair]
            self.assertEqual(closed, expected)
            set_blocking.assert_not_called()
            fork.assert_not_called()

        for failing_nonblocking in (1, 2):
            blocking_calls = []
            closed = []
            def set_blocking(_descriptor, _enabled):
                blocking_calls.append(len(blocking_calls) + 1)
                if len(blocking_calls) == failing_nonblocking:
                    raise OSError("injected nonblocking setup fault")
            with patch.object(runner.os, "O_CLOEXEC", 1, create=True), \
                 patch.object(runner.os, "pipe2", side_effect=pipe_pairs,
                              create=True), \
                 patch.object(runner.os, "close", side_effect=closed.append), \
                 patch.object(runner.os, "set_blocking", side_effect=set_blocking), \
                 patch.object(runner.os, "fork", create=True) as fork, \
                 self.subTest(failing_nonblocking=failing_nonblocking), \
                 self.assertRaisesRegex(OSError, "nonblocking setup fault"):
                runner._linux_spawn_gated(["unused"], time.monotonic_ns() + 1)
            self.assertEqual(closed, [descriptor for pair in pipe_pairs
                                      for descriptor in pair])
            fork.assert_not_called()

        closed = []
        with patch.object(runner.os, "O_CLOEXEC", 1, create=True), \
             patch.object(runner.os, "pipe2", side_effect=pipe_pairs,
                          create=True), \
             patch.object(runner.os, "close", side_effect=closed.append), \
             patch.object(runner.os, "set_blocking"), \
             patch.object(runner.os, "fork", side_effect=OSError(
                 "injected fork fault"), create=True), \
             self.assertRaisesRegex(OSError, "fork fault"):
            runner._linux_spawn_gated(["unused"], time.monotonic_ns() + 1)
        self.assertEqual(closed, [descriptor for pair in pipe_pairs
                                  for descriptor in pair])
        with patch.object(inv.time, "monotonic", return_value=10.0), \
             patch.object(inv.subprocess, "Popen") as spawned:
            with self.assertRaisesRegex(inv.InventoryError,
                                        "before supervisor creation"):
                inv._popen_before_deadline(["never"], 10.0,
                                           stdout=subprocess.PIPE)
            spawned.assert_not_called()

    def test_bounded_command_kills_descendant_that_inherits_stdout(self):
        with tempfile.TemporaryDirectory() as temp:
            ready=Path(temp)/"ready";sentinel=Path(temp)/"survived"
            child=("import pathlib,sys,time;pathlib.Path(sys.argv[1]).write_text('ready');"
                   "time.sleep(.6);pathlib.Path(sys.argv[2]).write_text('bad')")
            parent=("import os,pathlib,subprocess,sys,time\n"
                    "subprocess.Popen([sys.executable,'-c',sys.argv[1],*sys.argv[2:]],"
                    "stdout=sys.stdout)\n"
                    "deadline=time.monotonic()+1\n"
                    "while not pathlib.Path(sys.argv[2]).exists():\n"
                    "    if time.monotonic()>=deadline: raise SystemExit(7)\n"
                    "    time.sleep(.001)\n"
                    "os.write(1,b'ok\\n')\n")
            started=inv.time.monotonic()
            self.assertEqual(inv.bounded_command([sys.executable,"-c",parent,child,
                str(ready),str(sentinel)],1024,2).strip(),b"ok")
            self.assertLess(inv.time.monotonic()-started,5)
            self.assertTrue(ready.exists())
            time.sleep(.7)
            self.assertFalse(sentinel.exists())

    @unittest.skipUnless(os.name == "posix", "POSIX process-group contract")
    def test_bounded_command_kills_quiet_same_group_descendant_after_success(self):
        with tempfile.TemporaryDirectory() as temp:
            sentinel = str(Path(temp) / "descendant-survived")
            child = ("import pathlib,time; time.sleep(0.5); "
                     f"pathlib.Path({sentinel!r}).write_text('bad')")
            parent = ("import subprocess,sys; "
                      "subprocess.Popen([sys.executable,'-c',%r],"
                      "stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); "
                      "print('ok')") % child
            self.assertEqual(inv.bounded_command([sys.executable, "-c", parent], 16, 2).strip(), b"ok")
            time.sleep(0.7)
            self.assertFalse(Path(sentinel).exists())

    @unittest.skipUnless(os.name == "posix", "POSIX outer-supervision contract")
    def test_cleanup_uncertain_wire_retires_same_group_survivor(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            ready, sentinel = root / "ready", root / "survived"
            child = (
                "import pathlib,sys,time;"
                "pathlib.Path(sys.argv[1]).write_text('ready');"
                "time.sleep(.6);pathlib.Path(sys.argv[2]).write_text('bad')")
            supervisor = (
                "import pathlib,struct,subprocess,sys,time;"
                "subprocess.Popen([sys.executable,'-c',sys.argv[1],*sys.argv[2:]],"
                "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,"
                "stderr=subprocess.DEVNULL);"
                "deadline=time.monotonic()+1;"
                "ready=pathlib.Path(sys.argv[2]);"
                "exec(\"while not ready.exists():\\n"
                " if time.monotonic()>=deadline: raise SystemExit(7)\\n"
                " time.sleep(.001)\");"
                "sys.stdout.buffer.write(b'BCR1'+bytes([5])+struct.pack('<Q',0));"
                "sys.stdout.buffer.flush()")
            real_popen = subprocess.Popen
            launched = []

            def launch_instead(_command, **kwargs):
                process = real_popen(
                    [sys.executable, "-c", supervisor, child,
                     str(ready), str(sentinel)], **kwargs)
                launched.append(process)
                return process

            with patch.object(inv.subprocess, "Popen", side_effect=launch_instead):
                with self.assertRaisesRegex(
                        inv.InventoryError,
                        "cleanup could not be authenticated"):
                    inv.bounded_command([sys.executable, "-c", "print('unused')"], 16, 2)
            self.assertTrue(ready.exists())
            self.assertEqual(len(launched), 1)
            self.assertIsNotNone(launched[0].poll())
            self.assertEqual(launched[0].wait(timeout=0), launched[0].returncode)
            time.sleep(.7)
            self.assertFalse(sentinel.exists())

    @unittest.skipUnless(os.name == "posix", "POSIX signal-fault retirement")
    def test_outer_signal_failure_still_retires_exact_same_group(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            ready, child_pid_path, sentinel = (
                root / "ready", root / "child-pid", root / "survived")
            child = (
                "import pathlib,sys,time;"
                "pathlib.Path(sys.argv[1]).write_text(str(__import__('os').getpid()));"
                "pathlib.Path(sys.argv[2]).write_text('ready');"
                "time.sleep(.7);pathlib.Path(sys.argv[3]).write_text('bad')")
            parent = (
                "import subprocess,sys,time;"
                "subprocess.Popen([sys.executable,'-c',sys.argv[1],*sys.argv[2:]],"
                "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,"
                "stderr=subprocess.DEVNULL);time.sleep(5)")
            process = subprocess.Popen(
                [sys.executable, "-c", parent, child, str(child_pid_path),
                 str(ready), str(sentinel)], stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                start_new_session=True, close_fds=True)
            deadline = time.monotonic() + 2
            while not ready.exists() and time.monotonic() < deadline:
                time.sleep(.002)
            self.assertTrue(ready.exists())
            original_killpg = inv.os.killpg
            signal_calls = []
            def fail_first_killpg(group, sig):
                signal_calls.append((group, sig))
                if len(signal_calls) == 1:
                    raise OSError("injected killpg failure")
                return original_killpg(group, sig)
            try:
                with patch.object(inv.os, "killpg", side_effect=fail_first_killpg):
                    self.assertFalse(inv._posix_retire_outer_supervision(
                        process, time.monotonic() + 2))
                self.assertGreaterEqual(len(signal_calls), 2)
                self.assertEqual(process.wait(timeout=0), process.returncode)
                group_deadline = time.monotonic() + 1
                while True:
                    try:
                        os.killpg(process.pid, 0)
                    except ProcessLookupError:
                        break
                    if time.monotonic() >= group_deadline:
                        self.fail("same-group child remained after retirement")
                    time.sleep(.01)
                time.sleep(.75)
                self.assertFalse(sentinel.exists())
            finally:
                if process.poll() is None:
                    original_killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=2)

    @unittest.skipUnless(os.name == "posix", "POSIX child-reaper contract")
    def test_bounded_command_normalizes_inherited_sigchld_without_mutating_caller(self):
        previous=signal.getsignal(signal.SIGCHLD)
        try:
            signal.signal(signal.SIGCHLD,signal.SIG_IGN)
            self.assertEqual(inv.bounded_command([sys.executable,"-c","print('ok')"],16,2).strip(),b"ok")
            self.assertEqual(signal.getsignal(signal.SIGCHLD),signal.SIG_IGN)
        finally:
            signal.signal(signal.SIGCHLD,previous)

    def test_bounded_command_does_not_reap_or_kill_preexisting_caller_child(self):
        with tempfile.TemporaryDirectory() as temp:
            sentinel=str(Path(temp)/"caller-child-completed")
            child=subprocess.Popen([sys.executable,"-c",
                "import pathlib,sys,time;time.sleep(.2);pathlib.Path(sys.argv[1]).write_text('ok')",
                sentinel])
            try:
                self.assertEqual(inv.bounded_command(
                    [sys.executable,"-c","print('bounded')"],32,10).strip(),b"bounded")
                self.assertEqual(child.wait(timeout=10),0)
                self.assertEqual(Path(sentinel).read_text(),"ok")
            finally:
                if child.poll() is None:
                    child.kill(); child.wait()

    @unittest.skipUnless(os.name == "posix" and hasattr(os,"memfd_create"),
                         "Linux immutable memfd contract")
    def test_kernel_seals_reject_write_grow_and_shrink_without_fd_leak(self):
        import fcntl
        before=len(os.listdir("/proc/self/fd"))
        descriptor=os.memfd_create("seal-test",getattr(os,"MFD_ALLOW_SEALING",2))
        try:
            os.write(descriptor,b"sealed")
            seals=fcntl.F_SEAL_SEAL|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_GROW|fcntl.F_SEAL_WRITE
            fcntl.fcntl(descriptor,fcntl.F_ADD_SEALS,seals)
            self.assertEqual(fcntl.fcntl(descriptor,fcntl.F_GET_SEALS),seals)
            for action in (lambda:os.write(descriptor,b"x"),
                           lambda:os.ftruncate(descriptor,1),
                           lambda:os.ftruncate(descriptor,100)):
                with self.assertRaises(OSError): action()
        finally:
            os.close(descriptor)
        self.assertEqual(len(os.listdir("/proc/self/fd")),before)

    @unittest.skipUnless(os.name == "posix", "POSIX nonblocking-pipe contract")
    def test_bounded_command_retires_escaped_pipe_holder_after_success(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); pid_path=root/"pid"; ready=root/"ready"; sentinel=root/"survived"
            child=("import os,pathlib,sys,time;"
                   "pathlib.Path(sys.argv[1]).write_text(str(os.getpid()));os.setsid();"
                   "pathlib.Path(sys.argv[2]).write_text('ready');time.sleep(.6);"
                   "pathlib.Path(sys.argv[3]).write_text('bad')")
            parent=("import os,subprocess,sys,time;"
                    "subprocess.Popen([sys.executable,'-c',sys.argv[1],*sys.argv[2:]],"
                    "stdout=sys.stdout);time.sleep(.2);"
                    "os.write(1,b'ok\\n');os._exit(0)")
            # A producer which deliberately daemonizes may be rejected; the
            # security contract here is that its confirmed escaped descendant
            # is nevertheless retired before bounded_command returns.
            try:
                output=inv.bounded_command([sys.executable,"-c",parent,child,
                    str(pid_path),str(ready),str(sentinel)],64,2)
                self.assertEqual(output.strip(),b"ok")
            except inv.InventoryError:
                pass
            self.assertTrue(ready.exists())
            escaped_pid=int(pid_path.read_text())
            with self.assertRaises(ProcessLookupError):
                os.kill(escaped_pid,0)
            time.sleep(.7)
            self.assertFalse(sentinel.exists())

    @unittest.skipUnless(os.name == "posix", "Linux pre-exec deadline gate")
    def test_linux_launch_gate_refuses_expired_release_without_exec(self):
        with tempfile.TemporaryDirectory() as temp:
            sentinel=Path(temp)/"executed"
            operation=time.monotonic_ns()+50_000_000
            target=runner._linux_spawn_gated(
                [sys.executable,"-c",
                 "import pathlib,sys;pathlib.Path(sys.argv[1]).write_text('bad')",
                 str(sentinel)],operation)
            try:
                time.sleep(.08)
                classification=runner._linux_release(target,operation)
                kind,_=runner._linux_reap_all(operation,time.monotonic_ns()+1_000_000_000,
                                               target,bytearray(),16,classification)
                self.assertEqual(kind,runner.TIMED_OUT)
            finally:
                if target.stdout_fd >= 0:
                    os.close(target.stdout_fd);target.stdout_fd=-1
            self.assertFalse(sentinel.exists())

    @unittest.skipUnless(os.name == "posix", "Linux post-fork cleanup fault")
    def test_linux_inventory_fault_still_retires_exact_target(self):
        operation=time.monotonic_ns()+1_000_000_000
        target=runner._linux_spawn_gated([sys.executable,"-c","import time;time.sleep(5)"],operation)
        original=runner._linux_children
        calls=0
        def fail_once():
            nonlocal calls
            calls+=1
            if calls == 1:
                raise OSError("injected inventory fault")
            return original()
        try:
            classification=runner._linux_release(target,operation)
            with patch.object(runner,"_linux_children",side_effect=fail_once):
                kind,_=runner._linux_reap_all(operation,time.monotonic_ns()+1_000_000_000,
                                               target,bytearray(),16,classification)
            self.assertEqual(kind,runner.INTERNAL)
            with self.assertRaises(ChildProcessError):
                os.waitpid(target.pid,os.WNOHANG)
        finally:
            if target.stdout_fd >= 0:
                os.close(target.stdout_fd);target.stdout_fd=-1

    def test_exact_windows_retirement_helpers_fail_closed(self):
        class Process:
            _handle=17
            def __init__(self): self.waited=0
            def wait(self,timeout): self.waited+=1;return 91
        class Kernel:
            def __init__(self,waits,terminations=()):
                self.waits=iter(waits);self.terminations=iter(terminations)
            def WaitForSingleObject(self,_handle,_timeout): return next(self.waits)
            def TerminateProcess(self,_handle,_code): return next(self.terminations,True)
        process=Process()
        self.assertTrue(runner._windows_stop_exact(
            process,Kernel([258,0],[True]),time.monotonic_ns()+1_000_000_000))
        self.assertEqual(process.waited,1)
        self.assertFalse(runner._windows_stop_exact(
            Process(),Kernel([0xffffffff]),time.monotonic_ns()+1_000_000_000))
        self.assertFalse(runner._windows_stop_exact(
            Process(),Kernel([258,258],[False]),time.monotonic_ns()+1_000_000_000))
        process=Process()
        self.assertTrue(inv._windows_retire_unassigned_process(
            process,Kernel([258,258,0,0],[False]),time.monotonic()+1))
        self.assertEqual(process.waited,1)
        self.assertFalse(inv._windows_retire_unassigned_process(
            Process(),Kernel([0xffffffff]),time.monotonic()+1))

    def test_windows_worker_production_seam_fails_closed_at_api_boundaries(self):
        state={}

        class Stream:
            def __init__(self,events):
                self.events=events
                self.closed=False
            def fileno(self): return 71
            def close(self):
                self.events.append("stream-close")
                self.closed=True

        class Process:
            _handle=17
            returncode=0
            stdin=None
            stderr=None
            def __init__(self,kernel,events):
                self.kernel=kernel
                self.events=events
                self.stdout=Stream(events)
            def poll(self): return self.returncode
            def wait(self,timeout):
                self.events.append("process-wait")
                if not self.kernel.done:
                    raise subprocess.TimeoutExpired("worker",timeout)
                return self.returncode

        class Kernel:
            def __init__(self,events,fault=None):
                self.events=events
                self.fault=fault
                self.done=False
                self.wait_calls=0
            def WaitForSingleObject(self,_handle,_timeout):
                self.events.append("wait")
                self.wait_calls+=1
                if self.fault=="wait": return 0xffffffff
                if self.fault=="terminate" and self.wait_calls>1:
                    return 0xffffffff
                return 0 if self.done else 258
            def TerminateProcess(self,_handle,_code):
                self.events.append("terminate")
                if self.fault=="terminate": return False
                self.done=True
                return True

        class NtDll:
            def __init__(self,events,fault=None):
                self.events=events
                self.fault=fault
            def NtResumeProcess(self,_handle):
                self.events.append("resume")
                if self.fault=="resume-exception":
                    raise OSError("NtResumeProcess fault")
                return 7 if self.fault=="resume" else 0

        def invoke(fault=None):
            events=[]
            kernel=Kernel(events,fault)
            process=Process(kernel,events)
            state.clear();state.update(events=events,kernel=kernel,process=process)
            def spawn(_command,_deadline,**_kwargs):
                events.append("spawn")
                if fault=="popen": raise OSError("Popen fault")
                return process
            def read(_process,_limit,_deadline,_kernel):
                events.append("read")
                if fault=="read": raise OSError("read fault")
                if fault not in ("terminate","wait"):
                    kernel.done=True
                return runner.OK,b"ok"
            operation=time.monotonic_ns()+1_000_000_000
            return runner._run_windows(
                ["producer"],16,operation,operation+1_000_000_000,
                kernel=kernel,ntdll=NtDll(events,fault),spawn=spawn,
                read_bounded=read)

        kind,output=invoke()
        self.assertEqual((kind,output),(runner.OK,b"ok"))
        events=state["events"]
        self.assertLess(events.index("spawn"),events.index("resume"))
        self.assertLess(events.index("resume"),events.index("read"))
        self.assertLess(events.index("read"),events.index("process-wait"))
        self.assertTrue(state["process"].stdout.closed)

        with self.assertRaisesRegex(OSError,"Popen fault"):
            invoke("popen")
        self.assertNotIn("resume",state["events"])
        for fault,expected in (
                ("resume",runner.INTERNAL),
                ("resume-exception",runner.INTERNAL),
                ("read",runner.INTERNAL),
                ("terminate",runner.CLEANUP_UNCERTAIN),
                ("wait",runner.CLEANUP_UNCERTAIN)):
            with self.subTest(fault=fault):
                kind,output=invoke(fault)
                self.assertEqual(kind,expected)
                if expected==runner.CLEANUP_UNCERTAIN:
                    self.assertEqual(output,b"")
                self.assertTrue(state["process"].stdout.closed)
                self.assertEqual(state["events"][-1],"stream-close")

        # Exercise actual PeekNamedPipe and os.read decision branches using
        # injected handles, without importing msvcrt or creating a process.
        class PeekKernel:
            def __init__(self,available=0,result=False):
                self.available=available;self.result=result;self.events=[]
            def PeekNamedPipe(self,_handle,_buffer,_size,_read,available,_left):
                self.events.append("peek")
                available._obj.value=self.available
                return self.result
            def WaitForSingleObject(self,_handle,_timeout):
                self.events.append("wait")
                return 258

        process=Process(PeekKernel(),[])
        operation=time.monotonic_ns()+1_000_000_000
        kind,output=runner._windows_read_bounded(
            process,16,operation,process.kernel,pipe_handle=91,
            last_error=lambda:5)
        self.assertEqual((kind,output),(runner.INTERNAL,b""))
        self.assertEqual(process.kernel.events,["peek"])
        process=Process(PeekKernel(available=1,result=True),[])
        kind,output=runner._windows_read_bounded(
            process,16,time.monotonic_ns()+1_000_000_000,process.kernel,
            pipe_handle=91,read_output=lambda *_:(_ for _ in ()).throw(
                OSError("ReadFile fault")),last_error=lambda:5)
        self.assertEqual((kind,output),(runner.INTERNAL,b""))
        self.assertEqual(process.kernel.events,["peek"])

    def test_windows_outer_production_seam_orders_assignment_and_fails_closed(self):
        state={}
        class Limits:
            def __init__(self):
                self.BasicLimitInformation=types.SimpleNamespace(LimitFlags=0)
        class Accounting:
            ActiveProcesses=0
        class Stream:
            def __init__(self,events): self.events=events;self.closed=False
            def close(self): self.events.append("stream-close");self.closed=True

        class Process:
            _handle=23
            returncode=0
            def __init__(self,kernel,events,communicate_fault=False):
                self.kernel=kernel;self.events=events
                self.communicate_fault=communicate_fault
                self.stdin=Stream(events);self.stdout=Stream(events);self.stderr=None
            def communicate(self,input,timeout):
                self.events.append("communicate")
                if self.communicate_fault: raise OSError("worker read fault")
                self.kernel.process_done=True
                return b"BCR1\0\0\0\0\0\0\0\0\0",None
            def wait(self,timeout):
                self.events.append("process-wait")
                if not self.kernel.process_done:
                    raise subprocess.TimeoutExpired("supervisor",timeout)
                return self.returncode

        class Kernel:
            def __init__(self,events,fault=None):
                self.events=events;self.fault=fault
                self.process_done=False;self.assigned=False;self.wait_calls=0
                self.job_closed=False
            def CreateJobObjectW(self,*_):
                self.events.append("create-job")
                return 0 if self.fault=="create" else 41
            def SetInformationJobObject(self,*_):
                self.events.append("set-job")
                return self.fault!="set"
            def AssignProcessToJobObject(self,*_):
                self.events.append("assign")
                if self.fault in ("assign-exception-before",
                                  "assign-exception-before-terminate-exception"):
                    raise OSError("AssignProcessToJobObject before-effect fault")
                if self.fault == "assign-baseexception":
                    raise KeyboardInterrupt("AssignProcessToJobObject BaseException")
                if self.fault in ("assign-exception-after",
                                  "assign-bool-exception"):
                    self.assigned=True
                    if self.fault == "assign-exception-after":
                        raise OSError("AssignProcessToJobObject after-effect fault")
                    class Result:
                        def __bool__(self):
                            raise OSError("AssignProcessToJobObject bool fault")
                    return Result()
                self.assigned=self.fault not in (
                    "assign","terminate-process","terminate-process-exception")
                return self.assigned
            def TerminateProcess(self,*_):
                self.events.append("terminate-process")
                if self.fault=="terminate-process": return False
                if self.fault in ("terminate-process-exception",
                                  "assign-exception-before-terminate-exception"):
                    raise OSError("TerminateProcess fault")
                self.process_done=True
                return self.fault!="terminate-process"
            def TerminateJobObject(self,*_):
                self.events.append("terminate-job")
                if self.fault!="terminate-job" and self.assigned:
                    self.process_done=True
                return self.fault!="terminate-job"
            def QueryInformationJobObject(self,_job,_kind,accounting,_size,_returned):
                self.events.append("query-job")
                if self.fault=="query": return False
                accounting.ActiveProcesses=0
                return True
            def WaitForSingleObject(self,*_):
                self.events.append("wait")
                self.wait_calls+=1
                if self.fault=="wait": return 0xffffffff
                if self.fault in ("terminate-process","terminate-process-exception",
                                  "assign-exception-before-terminate-exception"):
                    return 258 if self.wait_calls==1 else 0xffffffff
                return 0 if self.process_done else 258
            def CloseHandle(self,*_):
                self.events.append("close-job")
                if self.fault=="close": return False
                self.job_closed=True
                if self.assigned: self.process_done=True
                return True

        class NtDll:
            def __init__(self,events,fault=None): self.events=events;self.fault=fault
            def NtResumeProcess(self,_handle):
                self.events.append("resume")
                return 7 if self.fault=="resume" else 0

        def invoke(fault=None):
            events=[];kernel=Kernel(events,fault)
            state.clear();state.update(events=events,kernel=kernel,process=None)
            def spawn(_command,_deadline,**_kwargs):
                events.append("spawn")
                if fault=="popen": raise OSError("worker creation fault")
                process=Process(kernel,events,fault=="communicate")
                state["process"]=process
                return process
            def decode(payload,returncode):
                events.append("decode")
                self.assertEqual((payload,returncode),
                                 (b"BCR1\0\0\0\0\0\0\0\0\0",0))
                return b"accepted"
            # Keep this deterministic production-seam test active on POSIX as
            # well as Windows.  The platform constant is merely forwarded to
            # the injected spawn function; the real Windows value is covered
            # by the native Windows run.
            with patch.object(subprocess,"CREATE_NEW_PROCESS_GROUP",0x200,
                              create=True):
                value=inv._windows_supervise_worker(
                    ["worker"],time.monotonic()+1,b"worker-input",decode,
                    kernel=kernel,ntdll=NtDll(events,fault),limits_factory=Limits,
                    accounting_factory=Accounting,pointer=lambda value:value,
                    size_of=lambda _value:1,spawn=spawn)
            return value,events

        value,events=invoke()
        self.assertEqual(value,b"accepted")
        self.assertLess(events.index("set-job"),events.index("spawn"))
        self.assertLess(events.index("assign"),events.index("resume"))
        self.assertLess(events.index("decode"),events.index("terminate-job"))
        self.assertLess(events.index("terminate-job"),events.index("query-job"))
        self.assertLess(events.index("query-job"),events.index("close-job"))
        self.assertIn("process-wait",events)
        self.assertTrue(state["kernel"].job_closed)
        self.assertTrue(state["kernel"].process_done)
        self.assertTrue(state["process"].stdin.closed)
        self.assertTrue(state["process"].stdout.closed)

        for fault,error in (
                ("create",inv.InventoryError),("set",inv.InventoryError),
                ("popen",OSError),("assign",inv.InventoryError),
                ("resume",inv.InventoryError),("communicate",OSError),
                ("terminate-job",inv.InventoryError),("query",inv.InventoryError),
                ("wait",inv.InventoryError),("close",inv.InventoryError),
                ("terminate-process",inv.InventoryError),
                ("terminate-process-exception",inv.InventoryError),
                ("assign-exception-before",OSError),
                ("assign-exception-after",OSError),
                ("assign-bool-exception",OSError),
                ("assign-baseexception",KeyboardInterrupt),
                ("assign-exception-before-terminate-exception",
                 inv.InventoryError)):
            with self.subTest(fault=fault),self.assertRaises(error):
                invoke(fault)

        # Assignment failure may never resume an unowned process, and exact
        # handle retirement must still complete before the failure returns.
        with self.assertRaises(inv.InventoryError): invoke("assign")
        events=state["events"]
        self.assertNotIn("resume",events)
        self.assertLess(events.index("assign"),events.index("terminate-process"))
        self.assertLess(events.index("terminate-process"),
                        events.index("process-wait"))
        self.assertTrue(state["kernel"].process_done)
        self.assertTrue(state["process"].stdin.closed)
        self.assertTrue(state["process"].stdout.closed)

        # Exceptions before, after, or while converting the assignment result
        # preserve their original classification once exact suspended-worker
        # retirement has been proved.
        for fault in ("assign-exception-before", "assign-exception-after",
                      "assign-bool-exception"):
            with self.subTest(fault=fault), self.assertRaisesRegex(
                    OSError, "AssignProcessToJobObject"):
                invoke(fault)
            events=state["events"]
            self.assertNotIn("resume",events)
            self.assertLess(events.index("assign"),events.index("terminate-process"))
            self.assertLess(events.index("terminate-process"),events.index("process-wait"))
            self.assertTrue(state["kernel"].process_done)
            self.assertTrue(state["process"].stdin.closed)
            self.assertTrue(state["process"].stdout.closed)

        with self.assertRaisesRegex(
                KeyboardInterrupt, "AssignProcessToJobObject BaseException"):
            invoke("assign-baseexception")
        self.assertTrue(state["kernel"].process_done)
        self.assertNotIn("resume",state["events"])

        with self.assertRaisesRegex(
                inv.InventoryError, "cleanup uncertain") as uncertain:
            invoke("assign-exception-before-terminate-exception")
        causes=[]; cause=uncertain.exception.__context__
        while cause is not None and cause not in causes:
            causes.append(cause)
            cause=cause.__context__
        self.assertTrue(any(isinstance(item,OSError) for item in causes))
        self.assertNotIn("resume",state["events"])

        # The actual pre-Popen gate is used through the production seam.  An
        # expired operation may create/configure an empty Job, but no process.
        events=[];kernel=Kernel(events)
        with patch.object(inv.time,"monotonic",return_value=10.0), \
             patch.object(inv.subprocess,"CREATE_NEW_PROCESS_GROUP",0x200,
                          create=True), \
             patch.object(inv.subprocess,"Popen") as spawned, \
             self.assertRaisesRegex(inv.InventoryError,"before supervisor creation"):
            inv._windows_supervise_worker(
                ["worker"],10.0,b"worker-input",lambda *_:b"bad",
                kernel=kernel,ntdll=NtDll(events),limits_factory=Limits,
                accounting_factory=Accounting,pointer=lambda value:value,
                size_of=lambda _value:1)
        spawned.assert_not_called()
        self.assertNotIn("assign",events)
        self.assertNotIn("resume",events)
        self.assertLess(events.index("set-job"),events.index("terminate-job"))
        self.assertLess(events.index("query-job"),events.index("close-job"))

    def test_stat_comm_spaces_and_parentheses(self):
        tail = ["S"] + ["0"]*18 + ["2642"]
        self.assertEqual(inv.process_identity("1425 (odd (name)) " + " ".join(tail), 1425), (1425, 2642))

    def test_stat_mismatch_or_truncation(self):
        for value in ("1426 (name) S", "1425 name S", "1425 (name) S"):
            with self.assertRaises(inv.InventoryError):
                inv.process_identity(value, 1425)

    def test_maps_deduplicate_segments_not_paths(self):
        text = record(inv.ROOT_LIBRARY) + record(inv.ROOT_LIBRARY, 0x2000)
        maps = inv.mapped_libraries(text)
        self.assertEqual(len(maps), 1)
        self.assertEqual(len(maps[inv.ROOT_LIBRARY]), 2)

    def test_maps_reject_bad_records_or_identity(self):
        for text in ("bad", "2000-1000 r-xp 0000 fd:04 3 /system/lib64/a.so",
                     record(inv.ROOT_LIBRARY)+record(inv.ROOT_LIBRARY, 0x2000, 124)):
            with self.assertRaises(inv.InventoryError):
                inv.mapped_libraries(text)

    def test_complete_mapping_digest_is_deterministic_and_strict(self):
        maps=inv.mapped_libraries(record(inv.ROOT_LIBRARY))
        digest=inv.mapping_set_digest(maps)
        self.assertEqual(digest,inv.mapping_set_digest(inv.validate_mapping_set(maps)))
        changed={**maps,"/system/lib64/liblate.so": [{
            "start":0x3000,"end":0x4000,"permissions":"r-xp","offset":0,
            "device":"fd:04","inode":124}]}
        self.assertNotEqual(digest,inv.mapping_set_digest(changed))
        changed["/system/lib64/liblate.so"][0]["unexpected"]=True
        with self.assertRaises(inv.InventoryError): inv.mapping_set_digest(changed)
        raw=record(inv.ROOT_LIBRARY).encode()
        self.assertEqual(inv.complete_map_digest(raw),hashlib.sha256(raw).hexdigest())
        excluded=record("[anon:excluded]",0x3000).encode()
        unordered=record(inv.ROOT_LIBRARY,0x3000).encode()+record("[anon:excluded]",0x1000).encode()
        for invalid in (raw.rstrip(b"\n"),raw.replace(b"\n",b"\r\n"),
                        b"bad\n",raw+b"malformed\n",raw+b"\xff\n",unordered):
            with self.assertRaises(inv.InventoryError): inv.complete_map_digest(invalid)
        self.assertEqual(inv.complete_map_digest(raw+excluded),
                         hashlib.sha256(raw+excluded).hexdigest())

    @unittest.skipUnless(ELF_AVAILABLE,
                         "run explicitly with --python-path for inventory main")
    def test_actual_inventory_main_publishes_exact_complete_raw_maps(self):
        raw = (record(inv.ROOT_LIBRARY).encode() +
               record("[anon:excluded]", 0x3000).encode())
        files = self._run_actual_inventory_main(raw)
        self.assertEqual(files["maps-before.txt"], raw)
        self.assertEqual(files["maps-after.txt"], raw)
        report = inv.load_strict_json(files["inventory.json"])
        self.assertEqual(report["filteredMappings"],
                         inv.mapped_libraries(record(inv.ROOT_LIBRARY)))
        self.assertEqual(report["completeRawMapsBytes"], len(raw))
        self.assertEqual(report["completeRawMapsSha256"],
                         hashlib.sha256(raw).hexdigest())

    @unittest.skipUnless(ELF_AVAILABLE,
                         "run explicitly with --python-path for inventory main")
    def test_actual_inventory_main_rejects_crlf_and_global_excluded_order(self):
        canonical = record(inv.ROOT_LIBRARY).encode()
        invalid = (
            canonical.replace(b"\n", b"\r\n"),
            record(inv.ROOT_LIBRARY, 0x3000).encode() +
                record("[anon:excluded]", 0x1000).encode(),
            canonical + record("[anon:overlap]", 0x1800).encode(),
        )
        for raw in invalid:
            with self.subTest(raw=raw), self.assertRaises(inv.InventoryError):
                self._run_actual_inventory_main(raw)

    @unittest.skipUnless(ELF_AVAILABLE,
                         "run explicitly with --python-path for inventory main")
    def test_actual_inventory_main_rejects_nonlibrary_map_and_cmdline_mutation(self):
        root = record(inv.ROOT_LIBRARY).encode()
        before = root + record("[anon:before]", 0x3000).encode()
        after = root + record("[anon:after]", 0x3000).encode()
        self.assertEqual(inv.mapped_libraries(before.decode()),
                         inv.mapped_libraries(after.decode()))
        with self.assertRaisesRegex(inv.InventoryError,
                                    "complete raw/filtered mapping set changed"):
            self._run_actual_inventory_main(before, after)
        for before_cmdline, after_cmdline, expected_captures in (
                (b"com.ratta.drawpath", None, 1),
                (b"com.ratta.drawpath\0\0", None, 1),
                (b"com.ratta.drawpath\0", b"other.process\0", 2)):
            commands = []
            with self.subTest(before=before_cmdline, after=after_cmdline), \
                 self.assertRaisesRegex(inv.InventoryError,
                                        "process command line is not exact"):
                self._run_actual_inventory_main(
                    root, before_cmdline=before_cmdline,
                    after_cmdline=after_cmdline, command_log=commands)
            cmdline_commands = [command for command in commands
                                if "/proc/1425/cmdline" in " ".join(command)]
            self.assertEqual(len(cmdline_commands), expected_captures)

    def test_inventory_v4_uses_one_exact_mapping_authority(self):
        value=inventory_v4()
        self.assertIs(inv.validate_inventory_v4(value),value)
        for field, invalid in (
                ("completeRawMapsSha256", "0" * 63),
                ("completeRawMapsBytes", 0),
                ("completeRawMapsBytes", True)):
            changed=inventory_v4()
            changed[field]=invalid
            with self.subTest(field=field,invalid=invalid), \
                 self.assertRaises(inv.InventoryError):
                inv.validate_inventory_v4(changed)
        for mutation in ("remove", "extra", "old-schema"):
            changed=inventory_v4()
            if mutation == "remove":
                changed.pop("completeRawMapsBytes")
            elif mutation == "extra":
                changed["unexpected"] = True
            else:
                changed["schema"] = "native-loader-inventory-v3"
            with self.subTest(mutation=mutation), \
                 self.assertRaises(inv.InventoryError):
                inv.validate_inventory_v4(changed)
        changed=inventory_v4()
        changed["libraries"][inv.ROOT_LIBRARY]["mappings"][0]["start"] += 4096
        with self.assertRaises(inv.InventoryError): inv.validate_inventory_v4(changed)
        for field in ("start", "offset", "inode"):
            changed=inventory_v4()
            changed["libraries"][inv.ROOT_LIBRARY]["mappings"][0][field]=False
            with self.subTest(field=field),self.assertRaises(inv.InventoryError):
                inv.validate_inventory_v4(changed)
        changed=inventory_v4()
        changed["libraries"][inv.ROOT_LIBRARY]["mappedFileIdentity"]["bytes"]=True
        with self.assertRaises(inv.InventoryError): inv.validate_inventory_v4(changed)

    def test_inventory_v4_requires_exact_root_reachable_candidate_closure(self):
        candidate="/system/lib64/liba.so"
        value=inventory_v4()
        candidate_mapping={**value["filteredMappings"][inv.ROOT_LIBRARY][0],
                           "start":0x3000,"end":0x4000,"inode":124}
        value["filteredMappings"][candidate]=[candidate_mapping]
        value["filteredMapSetSha256"]=inv.mapping_set_digest(value["filteredMappings"])
        value["libraries"][inv.ROOT_LIBRARY]["needed"]=["liba.so"]
        value["edges"]=[{"requester":inv.ROOT_LIBRARY,"needed":"liba.so",
                         "candidates":[candidate],"resolution":"unique_mapped_candidate"}]
        with self.assertRaises(inv.InventoryError):
            inv.validate_inventory_v4(value)

        disconnected=inventory_v4()
        disconnected["filteredMappings"][candidate]=[candidate_mapping]
        disconnected["filteredMapSetSha256"]=inv.mapping_set_digest(disconnected["filteredMappings"])
        extra=copy.deepcopy(disconnected["libraries"][inv.ROOT_LIBRARY])
        extra.update(sha256="e"*64,soname="liba.so",mappings=[candidate_mapping],
                     localFile="fedcba9876543210.so",
                     mappedFileIdentity={"device":"fd:04","inode":124,"bytes":1024,
                         "mtime":1,"ctime":1,"authority":"proc-map-files-open-descriptor-v1"})
        disconnected["libraries"][candidate]=extra
        with self.assertRaises(inv.InventoryError):
            inv.validate_inventory_v4(disconnected)
        changed=inventory_v4()
        changed["libraries"][inv.ROOT_LIBRARY]["unexpected"] = True
        with self.assertRaises(inv.InventoryError): inv.validate_inventory_v4(changed)

    def test_inventory_v4_accepts_cycles_but_rejects_missing_fabricated_and_ambiguous_edges(self):
        candidate="/system/lib64/liba.so"
        base=inventory_v4()
        mapping={**base["filteredMappings"][inv.ROOT_LIBRARY][0],
                 "start":0x3000,"end":0x4000,"inode":124}
        base["filteredMappings"][candidate]=[mapping]
        base["filteredMapSetSha256"]=inv.mapping_set_digest(base["filteredMappings"])
        extra=copy.deepcopy(base["libraries"][inv.ROOT_LIBRARY])
        extra.update(sha256="e"*64,soname="liba.so",mappings=[mapping],
                     localFile="fedcba9876543210.so",needed=[],
                     mappedFileIdentity={"device":"fd:04","inode":124,"bytes":1024,
                         "mtime":1,"ctime":1,"authority":"proc-map-files-open-descriptor-v1"})
        base["libraries"][candidate]=extra
        base["libraries"][inv.ROOT_LIBRARY]["needed"]=["liba.so"]
        base["edges"]=[{"requester":inv.ROOT_LIBRARY,"needed":"liba.so",
                        "candidates":[candidate],"resolution":"unique_mapped_candidate"}]
        self.assertIs(inv.validate_inventory_v4(base),base)
        variants=[]
        missing=copy.deepcopy(base); missing["edges"]=[]; variants.append(missing)
        fabricated=copy.deepcopy(base); fabricated["edges"][0]["candidates"]=[]; variants.append(fabricated)
        cycle=copy.deepcopy(base); cycle["libraries"][candidate]["needed"]=["librecgnition.so"]
        cycle["edges"].append({"requester":candidate,"needed":"librecgnition.so",
                               "candidates":[inv.ROOT_LIBRARY],"resolution":"unique_mapped_candidate"})
        self.assertIs(inv.validate_inventory_v4(cycle),cycle)
        valid_missing=inventory_v4()
        valid_missing["libraries"][inv.ROOT_LIBRARY]["needed"]=["libmissing.so"]
        valid_missing["edges"]=[{"requester":inv.ROOT_LIBRARY,"needed":"libmissing.so",
                                  "candidates":[],"resolution":"missing"}]
        self.assertIs(inv.validate_inventory_v4(valid_missing),valid_missing)

        unresolved=copy.deepcopy(base)
        other="/apex/com.android.runtime/lib64/liba.so"
        other_mapping={**mapping,"start":0x5000,"end":0x6000,"inode":125}
        unresolved["filteredMappings"][other]=[other_mapping]
        unresolved["filteredMapSetSha256"]=inv.mapping_set_digest(unresolved["filteredMappings"])
        other_meta=copy.deepcopy(extra)
        other_meta.update(sha256="d"*64,mappings=[other_mapping],localFile="1111111111111111.so",
                          mappedFileIdentity={"device":"fd:04","inode":125,"bytes":1024,
                              "mtime":1,"ctime":1,"authority":"proc-map-files-open-descriptor-v1"})
        unresolved["libraries"][other]=other_meta
        unresolved["edges"][0]["candidates"]=sorted([candidate,other])
        unresolved["edges"][0]["resolution"]="unresolved_multiple"
        self.assertIs(inv.validate_inventory_v4(unresolved),unresolved)
        ambiguous=copy.deepcopy(unresolved)
        ambiguous["edges"][0]["resolution"]="unique_mapped_candidate"
        variants.append(ambiguous)
        for value in variants:
            with self.subTest(value=value["edges"]),self.assertRaises(inv.InventoryError):
                inv.validate_inventory_v4(value)

    def test_runtime_file_authority_models_page_replacement_and_bionic_zeroing(self):
        readable, writable = 4, 2
        # Nominal ranges are disjoint, but the later segment remaps the same
        # page.  Bytes in the earlier segment now come from the later file page.
        loads = [
            {"p_vaddr":0x100,"p_offset":0x100,"p_filesz":0x100,"p_memsz":0x100,"p_flags":readable},
            {"p_vaddr":0x300,"p_offset":0x1300,"p_filesz":1,"p_memsz":1,"p_flags":readable},
        ]
        self.assertEqual(inv.runtime_file_offset(0x180,8,loads),0x1180)
        # Read-only file tails remain file-backed even with a nominal BSS tail.
        loads[1]["p_memsz"] = 2
        self.assertEqual(inv.runtime_file_offset(0x380,8,loads),0x1380)
        # A writable one-byte BSS tail zeros through the complete mapped page.
        loads[1]["p_flags"] = readable|writable
        with self.assertRaises(inv.InventoryError): inv.runtime_file_offset(0x380,8,loads)
        # Equal file/memory sizes still trigger writable final-page zeroing.
        loads[1].update(p_filesz=1,p_memsz=1)
        with self.assertRaises(inv.InventoryError): inv.runtime_file_offset(0x380,8,loads)
        # A writable zero-size unaligned load retains the file-backed prefix
        # before p_vaddr and zeroes from p_vaddr onward, even when equal-zero.
        loads[1].update(p_filesz=0,p_memsz=0)
        self.assertEqual(inv.runtime_file_offset(0x180,8,loads),0x1180)
        with self.assertRaises(inv.InventoryError): inv.runtime_file_offset(0x380,8,loads)
        # An aligned zero-size load maps no page and therefore cannot erase
        # file authority from the same page of an earlier segment.
        aligned = [
            {"p_vaddr":0x1000,"p_offset":0x2000,"p_filesz":0x1000,
             "p_memsz":0x1000,"p_flags":readable},
            {"p_vaddr":0x1000,"p_offset":0x3000,"p_filesz":0,
             "p_memsz":0,"p_flags":readable|writable},
        ]
        self.assertEqual(inv.runtime_file_offset(0x1080,8,aligned),0x2080)
        # A later readable mapping of the exact page restores file authority
        # after an earlier writable final-page zero.
        overlap = [
            {"p_vaddr":0x300,"p_offset":0x1300,"p_filesz":1,
             "p_memsz":1,"p_flags":readable|writable},
            {"p_vaddr":0x300,"p_offset":0x2300,"p_filesz":1,
             "p_memsz":1,"p_flags":readable},
        ]
        self.assertEqual(inv.runtime_file_offset(0x380,8,overlap),0x2380)
        # Read-only zero-size unaligned loads do not fabricate a BSS overwrite.
        loads[1].update(p_vaddr=0x300,p_offset=0x1300,p_flags=readable)
        self.assertEqual(inv.runtime_file_offset(0x380,8,loads),0x1380)

    def test_non_library_private_paths_are_excluded(self):
        for path in ("/data/local/tmp/a.so", "/storage/a.so", "/system/lib64/a.so (deleted)",
                     "/system/lib64/a.so;reboot", "/system/lib64/a.so with spaces"):
            self.assertEqual(inv.mapped_libraries(record(path)), {})

    def test_noncanonical_apex_path_rejected(self):
        for part in (".", ".."):
            with self.assertRaises(inv.InventoryError):
                inv.mapped_libraries(record(f"/apex/{part}/lib64/a.so"))

    def test_dependency_name_validation(self):
        for name in ("/system/a.so", "../a.so", "a.so;id", "", "a.so\n"):
            with self.assertRaises(inv.InventoryError):
                inv.dependency_candidates(name, {})

    @unittest.skipUnless(ELF_AVAILABLE, "run explicitly with --python-path for ELF parser checks")
    def test_synthetic_elf_dynamic_without_sections(self):
        data = fake_elf()
        value = inv.elf_metadata(data)
        self.assertEqual(value["soname"], "libexample.so")
        self.assertEqual(value["needed"], ["libc.so"])
        self.assertEqual(value["initArrayEntries"], 2)
        self.assertEqual(value["bytes"], len(data))

    @unittest.skipUnless(ELF_AVAILABLE, "run explicitly with --python-path for ELF parser checks")
    def test_elf_reject_wrong_arch_and_bad_array_size(self):
        for data in (fake_elf(machine=62), fake_elf(init_size=1), fake_elf(init_size=2048),
                     fake_elf(extra_tags=((27, 16),)), fake_elf(extra_tags=((14, 1),))):
            with self.assertRaises(inv.InventoryError):
                inv.elf_metadata(data)

    @unittest.skipUnless(ELF_AVAILABLE, "run explicitly with --python-path for ELF parser checks")
    def test_section_names_fail_before_elf_parser_construction(self):
        cases = (
            fake_elf_with_section_name_table(b"\0" + b"x" * 257 + b"\0"),
            fake_elf_with_section_name_table(b"\0unterminated"),
            fake_elf_with_section_name_table(b"\0\xff\0"),
            fake_elf_with_section_name_table(b"\0ok\0", name_offset=99),
        )
        with patch("elftools.elf.elffile.ELFFile", side_effect=AssertionError(
                "parser constructed before section-name admission")) as parser:
            for data in cases:
                with self.subTest(size=len(data)), self.assertRaises(inv.InventoryError):
                    inv.elf_metadata(data)
            parser.assert_not_called()

    @unittest.skipUnless(ELF_AVAILABLE, "run explicitly with --python-path for ELF parser checks")
    def test_elf_reject_path_as_needed(self):
        with self.assertRaises(inv.InventoryError):
            inv.elf_metadata(fake_elf(needed="../libc.so"))

    @unittest.skipUnless(ELF_AVAILABLE, "run explicitly with --python-path for ELF parser checks")
    def test_elf_header_and_dynamic_budgets_precede_materialization(self):
        too_many_headers=bytearray(fake_elf())
        struct.pack_into("<H",too_many_headers,56,inv.MAX_PROGRAM_HEADERS+1)
        with self.assertRaises(inv.InventoryError): inv.elf_metadata(bytes(too_many_headers))
        too_many_dynamic=bytearray(fake_elf())
        too_many_dynamic.extend(bytes((inv.MAX_DYNAMIC_ENTRIES+1)*16))
        dynamic_size=(inv.MAX_DYNAMIC_ENTRIES+1)*16
        struct.pack_into("<QQ",too_many_dynamic,120+32,dynamic_size,dynamic_size)
        struct.pack_into("<QQ",too_many_dynamic,64+32,len(too_many_dynamic),len(too_many_dynamic))
        with self.assertRaises(inv.InventoryError): inv.elf_metadata(bytes(too_many_dynamic))
        extended_sections=bytearray(fake_elf())
        struct.pack_into("<H",extended_sections,60,0)
        struct.pack_into("<Q",extended_sections,40,0x800)
        with self.assertRaises(inv.InventoryError): inv.elf_metadata(bytes(extended_sections))

    @unittest.skipUnless(ELF_AVAILABLE, "run explicitly with --python-path for ELF parser checks")
    def test_dependency_count_budget_is_enforced_while_consuming(self):
        with patch.object(inv,"MAX_DEPENDENCIES",1),self.assertRaises(inv.InventoryError):
            inv.elf_metadata(fake_elf(extra_tags=((1,15),)))

    def test_root_digest_is_pinned(self):
        with self.assertRaises(inv.InventoryError):
            inv.collect_graph({inv.ROOT_LIBRARY: []}, lambda _path, _remaining: capture(meta()))

    def test_missing_dependency_not_silently_complete(self):
        libs, edges = inv.collect_graph(
            {inv.ROOT_LIBRARY: []},
            lambda _path, _remaining: capture(meta(["missing.so"], inv.ROOT_SHA256)))
        self.assertEqual(len(libs), 1)
        self.assertEqual(edges[0]["resolution"], "missing")

    def test_ambiguous_namespace_copies_never_select_first(self):
        a, b = "/system/lib64/libc++.so", "/apex/com.android.vndk.v30/lib64/libc++.so"
        maps = {inv.ROOT_LIBRARY: [], a: [], b: []}
        def read(path, _remaining):
            return capture(meta(["libc++.so"], inv.ROOT_SHA256) if path == inv.ROOT_LIBRARY else meta())
        libs, edges = inv.collect_graph(maps, read)
        self.assertEqual(set(libs), set(maps))
        self.assertEqual(edges[0]["resolution"], "unresolved_multiple")
        self.assertEqual(edges[0]["candidates"], sorted([a, b]))

    def test_cycle_is_bounded(self):
        a = "/system/lib64/liba.so"
        seen = []
        def read(path, _remaining):
            seen.append(path)
            return capture(meta(["liba.so"], inv.ROOT_SHA256) if path == inv.ROOT_LIBRARY else meta(["librecgnition.so"]))
        libs, _ = inv.collect_graph({inv.ROOT_LIBRARY: [], a: []}, read)
        self.assertEqual(len(seen), 2)
        self.assertEqual(len(libs), 2)

    def test_invalid_file_size_fails(self):
        for size in (0, -1, True, inv.MAX_FILE_BYTES+1):
            with self.assertRaises(inv.InventoryError):
                inv.collect_graph(
                    {inv.ROOT_LIBRARY: []},
                    lambda _path, _remaining: capture(meta(digest=inv.ROOT_SHA256, size=size)))

    def test_graph_passes_remaining_budget_and_publishes_only_after_admission(self):
        other = "/system/lib64/liba.so"
        maps = {inv.ROOT_LIBRARY: [], other: []}
        remaining = []
        published = []
        def read(path, allowance):
            remaining.append(allowance)
            value = meta(["liba.so"], inv.ROOT_SHA256, 10) if path == inv.ROOT_LIBRARY else meta(size=6)
            return capture(value)
        with patch.object(inv,"MAX_TOTAL_BYTES",15),self.assertRaises(inv.InventoryError):
            inv.collect_graph(maps,read,lambda path,_metadata,_payload: published.append(path))
        self.assertEqual(remaining,[15,5])
        self.assertEqual(published,[inv.ROOT_LIBRARY])


if __name__ == "__main__":
    if not ELF_AVAILABLE:
        raise SystemExit("Required ELF parser unavailable; explicit loader test run fails closed")
    unittest.main(argv=[sys.argv[0], *other])
