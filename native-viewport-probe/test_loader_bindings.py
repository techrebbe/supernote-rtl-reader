"""Memory read-plan and classification tests; no ADB or live memory access."""
import unittest
import hashlib
import io
import inspect
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tempfile
from unittest.mock import patch
import inspect_loader_bindings as b
import inspect_loader_dependencies as d
import test_loader_against_llvm as llvm_oracle
import test_loader_dependencies as dependency_tests

try:
    from elftools.elf.elffile import ELFFile
except ImportError:
    ELFFile=None


_PUBLICATION_PROCESS_HELPER = r"""
import hashlib
import os
from pathlib import Path
import sys
import types

def exact(stream, count):
    chunks = []
    while count:
        chunk = stream.read(count)
        if not chunk:
            raise ValueError("truncated source frame")
        chunks.append(chunk)
        count -= len(chunk)
    return b"".join(chunks)

try:
    stream = sys.stdin.buffer
    loaded = {}
    for name, expected in zip(
            ("inspect_loader_dependencies", "inspect_loader_bindings"),
            sys.argv[3:5]):
        size = int.from_bytes(exact(stream, 8), "big")
        if size <= 0 or size > 2 * 1024 * 1024:
            raise ValueError("invalid source frame size")
        source = exact(stream, size)
        if hashlib.sha256(source).hexdigest() != expected:
            raise ValueError("source digest mismatch")
        module = types.ModuleType(name)
        module.__file__ = "<authenticated-captured-" + name + ">"
        module.__package__ = ""
        sys.modules[name] = module
        exec(compile(source, module.__file__, "exec", dont_inherit=True),
             module.__dict__)
        loaded[name] = module
    if stream.read(1):
        raise ValueError("trailing source frame bytes")
except Exception:
    os._exit(64)

publication = loaded["inspect_loader_bindings"]
root = Path(sys.argv[1])
mode = sys.argv[2]
target = root / "report.json"

def staged_commit():
    staged = publication.stage_report(
        {"authority": "only"}, target, publication.WorkBudget(limit=1000))
    try:
        if mode == "postcommit":
            if os.name == "posix":
                real_fsync = publication.os.fsync
                calls = 0
                def fail_post_link(descriptor):
                    nonlocal calls
                    if descriptor == staged.authority.directory:
                        calls += 1
                        if calls == 2:
                            raise OSError("injected post-link durability fault")
                    return real_fsync(descriptor)
                publication.os.fsync = fail_post_link
            elif os.name == "nt":
                real_final = publication._windows_final_path
                def fail_post_rename(handle):
                    if staged.committed and handle == staged.windows_handle:
                        raise OSError("injected post-rename path fault")
                    return real_final(handle)
                publication._windows_final_path = fail_post_rename
        elif mode in ("crash", "outcome-unknown"):
            if os.name == "posix":
                real_commit = publication._posix_link_anonymous
                def after_link(*args):
                    real_commit(*args)
                    if mode == "crash":
                        os._exit(77)
                    raise OSError("fault immediately after successful link")
                publication._posix_link_anonymous = after_link
            elif os.name == "nt":
                real_commit = publication._windows_rename_no_replace
                def after_rename(*args):
                    real_commit(*args)
                    if mode == "crash":
                        os._exit(77)
                    raise OSError("fault immediately after successful rename")
                publication._windows_rename_no_replace = after_rename
        elif mode == "parent-after" and os.name == "posix":
            moved = root.with_name(root.name + "-moved")
            real_commit = publication._posix_link_anonymous
            def relocate_after_link(*args):
                real_commit(*args)
                root.rename(moved)
                root.mkdir()
            publication._posix_link_anonymous = relocate_after_link
        return publication.commit_report(staged)
    finally:
        staged.close()

if mode == "terminal-success":
    def operation():
        staged_commit()
        publication._report_terminal_success(
            "BINDINGS_COMPLETE native_start_allowed=false")
elif mode == "precommit":
    operation = lambda: publication.publish_after_final_window(
        {"authority": "only"}, target, publication.WorkBudget(limit=1000),
        lambda: (_ for _ in ()).throw(OSError("final window failed")))
elif mode == "parent-before" and os.name == "posix":
    def operation():
        staged = publication.stage_report(
            {"authority": "only"}, target, publication.WorkBudget(limit=1000))
        moved = root.with_name(root.name + "-moved")
        root.rename(moved)
        root.mkdir()
        try:
            publication.commit_report(staged)
        finally:
            staged.close()
else:
    operation = staged_commit
raise SystemExit(publication._run_cli(operation))
"""


def _captured_binding_source(module):
    """Capture the authenticated in-memory source used by this test process."""
    loader = getattr(getattr(module, "__spec__", None), "loader", None)
    current_loader = getattr(
        getattr(sys.modules.get(__name__), "__spec__", None), "loader", None)
    authority = getattr(current_loader, "authority_sha256", None)
    if authority is not None:
        raw = getattr(loader, "raw", None)
        if getattr(loader, "authority_sha256", None) != authority:
            raise d.InventoryError("publication test source escaped authenticated authority")
    else:
        raw = d.read_bounded(Path(module.__file__).absolute(), 2 * 1024 * 1024)
    if type(raw) is not bytes or not raw or len(raw) > 2 * 1024 * 1024:
        raise d.InventoryError("invalid captured publication-test source")
    return raw


def _run_publication_process(root, mode):
    sources = [_captured_binding_source(module) for module in (d, b)]
    wire = b"".join(len(source).to_bytes(8, "big") + source for source in sources)
    return subprocess.run(
        [sys.executable, "-I", "-S", "-E", "-s", "-c",
         _PUBLICATION_PROCESS_HELPER,
         str(root), mode, *(hashlib.sha256(source).hexdigest()
                            for source in sources)],
        input=wire, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=30, check=False)


def _run_publication_process_with_closed_stdout(root, mode):
    """Close the real pipe reader before the child emits its terminal status."""
    sources = [_captured_binding_source(module) for module in (d, b)]
    wire = b"".join(len(source).to_bytes(8, "big") + source for source in sources)
    process = subprocess.Popen(
        [sys.executable, "-I", "-S", "-E", "-s", "-c",
         _PUBLICATION_PROCESS_HELPER,
         str(root), mode, *(hashlib.sha256(source).hexdigest()
                            for source in sources)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    process.stdout.close()
    try:
        process.stdin.write(wire)
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
    return code, stderr


def region(start=4096, end=8192, permissions="r--p"):
    return {"start": start, "end": end, "permissions": permissions}


def slot(address):
    return {"address": address}


def sleb(value):
    result = bytearray()
    while True:
        byte, value = value & 127, value >> 7
        if (value == 0 and not byte & 64) or (value == -1 and byte & 64):
            return bytes(result + bytes([byte]))
        result.append(byte | 128)


def packed(*values):
    return b"APS2" + b"".join(sleb(v) for v in values)


def synthetic_import_elf(omit_packed_tags=False, wrong_section_offset=False):
    """Independent tiny binary with a renamed packed table AND ordinary PLT."""
    data=bytearray(4096)
    packed_bytes=packed(1,0x600,1,3,8,(1<<32)|1025)
    names=b"\0.dynsym\0.dynstr\0.rela.plt\0.renamed-packed-imports\0.shstrtab\0"
    tags=[(5,0x300),(10,5),(6,0x400),(11,24),(23,0x500),(2,24),(20,7),(9,24)]
    if not omit_packed_tags: tags.extend(((0x60000011,0x520),(0x60000012,len(packed_bytes))))
    tags.append((0,0))
    struct.pack_into("<16sHHIQQQIHHHHHH",data,0,b"\x7fELF\x02\x01\x01"+bytes(9),3,183,1,0,64,0x800,0,64,56,2,64,6,5)
    struct.pack_into("<IIQQQQQQ",data,64,1,6,0,0,0,4096,4096,4096)
    struct.pack_into("<IIQQQQQQ",data,120,2,6,0x100,0x100,0,len(tags)*16,len(tags)*16,8)
    for i,tag in enumerate(tags): struct.pack_into("<qQ",data,0x100+i*16,*tag)
    data[0x300:0x305]=b"\0foo\0"
    struct.pack_into("<IBBHQQ",data,0x418,1,0x12,0,0,0,0)
    struct.pack_into("<QQq",data,0x500,0x600,(1<<32)|1026,0)
    data[0x520:0x520+len(packed_bytes)]=packed_bytes
    data[0x700:0x700+len(names)]=names
    entries=[(names.index(b".dynsym"),11,2,0x400,0x400,48,2,1,8,24),
             (names.index(b".dynstr"),3,2,0x300,0x300,5,0,0,1,0),
             (names.index(b".rela.plt"),4,2,0x500,0x500,24,1,0,8,24),
             (names.index(b".renamed"),0x60000002,2,0x520,0x528 if wrong_section_offset else 0x520,len(packed_bytes),1,0,8,1),
             (names.index(b".shstrtab"),3,0,0,0x700,len(names),0,0,1,0)]
    for i,entry in enumerate(entries,1): struct.pack_into("<IIQQQQIIQQ",data,0x800+64*i,*entry)
    return bytes(data)


def page_conflict_import_elf():
    """Later nominally disjoint PT_LOAD replaces the first load's runtime page."""
    data=bytearray(synthetic_import_elf())
    data.extend(bytes(8192))
    struct.pack_into("<H",data,56,3)
    struct.pack_into("<QQ",data,64+32,0x700,0x700)
    struct.pack_into("<IIQQQQQQ",data,176,1,4,0x1702,0x702,0,3,3,0x1000)
    data[0x1700:0x1705]=b"\0bar\0"
    return bytes(data)


def mapped_record(start=0x1000, path_index=1):
    return {"start":start,"end":start+0x1000,"permissions":"r-xp","offset":0,
            "device":"fd:04","inode":path_index}


class BindingTests(unittest.TestCase):
    def test_relr_includes_bitmap_and_has_no_import_symbol_or_addend(self):
        data=struct.pack("<QQQ",0x1000,1|(1<<1)|(1<<3),0x2000)
        self.assertEqual(list(b.relr_rows(data)),[(0x1000,1027,None),(0x1008,1027,None),(0x1018,1027,None),(0x2000,1027,None)])
        for value in (b"",b"a",struct.pack("<Q",3),struct.pack("<Q",0x1002),
                      struct.pack("<QQ",0x1000,0x1000),struct.pack("<Q",0xfffffffffffffff8)):
            with self.assertRaises(d.InventoryError): list(b.relr_rows(value))

    def test_slot_file_offset_correspondence(self):
        loads=[{"p_vaddr":0x4000,"p_offset":0x1000,"p_filesz":4096,
                "p_memsz":4096,"p_flags":4}]
        maps=[{**region(0x14000,0x15000),"offset":0x1000}]
        b.slot_file_correspondence(0x4000,0x10000,loads,maps)
        maps[0]["offset"]=0x8000
        with self.assertRaises(d.InventoryError): b.slot_file_correspondence(0x4000,0x10000,loads,maps)

    def test_replaced_anchor_and_repeated_offsets_cannot_forge_load_bias(self):
        loads = [
            {"p_vaddr":0,"p_offset":0,"p_filesz":0x1000,"p_memsz":0x1000,"p_flags":4},
            {"p_vaddr":0,"p_offset":0x1000,"p_filesz":0x1000,"p_memsz":0x1000,"p_flags":4},
            {"p_vaddr":0x1000,"p_offset":0x5000,"p_filesz":0x1000,"p_memsz":0x1000,"p_flags":4},
            {"p_vaddr":0x3000,"p_offset":0x5000,"p_filesz":0x1000,"p_memsz":0x1000,"p_flags":4},
        ]
        mappings = [{**region(0x10000,0x11000),"offset":0},
                    {**region(0x11000,0x12000),"offset":0x5000},
                    {**region(0x13000,0x14000),"offset":0x5000}]
        with self.assertRaises(d.InventoryError):
            b.canonical_load_bias(loads, mappings)

        # A later same-file-page mapping can retain effective offset zero while
        # replacing the actual RVA-zero PT_LOAD owner. The raw shadowed anchor
        # must not authenticate that effective page.
        same_page = [
            {"p_vaddr":0,"p_offset":0,"p_filesz":0x1000,"p_memsz":0x1000,"p_flags":4},
            {"p_vaddr":0x800,"p_offset":0x800,"p_filesz":0x800,"p_memsz":0x800,"p_flags":4},
        ]
        with self.assertRaises(d.InventoryError):
            b.canonical_load_bias(same_page, [{**region(0x10000,0x11000),"offset":0}])

    @unittest.skipUnless(ELFFile,"required explicit ELF parser gate")
    def test_renamed_packed_import_table_is_not_omitted(self):
        slots,_=b.import_slots(synthetic_import_elf(),[{**region(0x10000,0x11000),"offset":0}])
        self.assertEqual({s["rva"] for s in slots},{0x600,0x608})
        self.assertEqual({s["symbol"] for s in slots},{"foo"})

    @unittest.skipUnless(ELFFile,"required explicit ELF parser gate")
    def test_rela_section_entry_size_cannot_silently_drop_rows(self):
        data=bytearray(synthetic_import_elf())
        # Keep sh_size and DT_RELAENT authoritative at 24 but make pyelftools'
        # section iterator believe each entry is 48 bytes. The APS2 table means
        # an implementation that silently skips this RELA row still looks nonempty.
        struct.pack_into("<Q",data,0x800+3*64+56,48)
        with self.assertRaises(d.InventoryError):
            b.import_slots(bytes(data),[{**region(0x10000,0x11000),"offset":0}])

    @unittest.skipUnless(ELFFile,"required explicit ELF parser gate")
    def test_section_names_are_bounded_before_parser_construction(self):
        data=bytearray(synthetic_import_elf())
        data[0x701:0x800]=b"x"*0xff
        struct.pack_into("<Q",data,0x800+5*64+32,0x100)
        with patch("elftools.elf.elffile.ELFFile",side_effect=AssertionError(
                "parser constructed before name admission")) as parser:
            with self.assertRaises(d.InventoryError):
                b.import_slots(bytes(data),[{**region(0x10000,0x11000),"offset":0}])
            parser.assert_not_called()

    @unittest.skipUnless(ELFFile,"required explicit ELF parser gate")
    def test_unaccounted_allocated_imports_and_wrong_storage_fail(self):
        for data in (synthetic_import_elf(omit_packed_tags=True),synthetic_import_elf(wrong_section_offset=True)):
            with self.assertRaises(d.InventoryError): b.relocation_sections(ELFFile(io.BytesIO(data)))

    @unittest.skipUnless(ELFFile,"required explicit ELF parser gate")
    def test_dynamic_symbols_and_strings_cannot_use_displaced_storage(self):
        for section in (1,2):
            data=bytearray(synthetic_import_elf())
            data[0x680:0x685]=b"\0bar\0"
            struct.pack_into("<Q",data,0x800+64*section+24,0x680)
            with self.assertRaises(d.InventoryError):
                b.import_slots(bytes(data),[{**region(0x10000,0x11000),"offset":0}])

    @unittest.skipUnless(ELFFile,"required explicit ELF parser gate")
    def test_dynamic_string_bounds_and_termination(self):
        for kind in ("address","size","name_offset","terminator"):
            data=bytearray(synthetic_import_elf())
            if kind=="address": struct.pack_into("<Q",data,0x800+128+16,0x680)
            elif kind=="size": struct.pack_into("<Q",data,0x800+128+32,10)
            elif kind=="name_offset": struct.pack_into("<I",data,0x418,5)
            else: data[0x304]=ord("x")
            with self.subTest(kind=kind),self.assertRaises(d.InventoryError):
                b.import_slots(bytes(data),[{**region(0x10000,0x11000),"offset":0}])

    @unittest.skipUnless(ELFFile,"required explicit ELF parser gate")
    def test_displaced_dynamic_segment_rejected_by_inventory_and_binding(self):
        data=bytearray(synthetic_import_elf())
        data[0xa00:0xab0]=data[0x100:0x1b0]
        struct.pack_into("<Q",data,128,0xa00)
        data[0x680:0x685]=b"\0bar\0"
        struct.pack_into("<Q",data,0x108,0x680)
        for inspect in (d.elf_metadata,lambda raw:b.import_slots(raw,[{**region(0x10000,0x11000),"offset":0}])):
            with self.assertRaises(d.InventoryError): inspect(bytes(data))

    @unittest.skipUnless(ELFFile,"required explicit ELF parser gate")
    def test_dynamic_extent_and_loader_backing_fail_closed(self):
        for kind in ("no_terminator","partial_record","truncated_segment","overlapping_load","unreadable_load","bad_load_alignment"):
            data=bytearray(synthetic_import_elf())
            if kind=="no_terminator": struct.pack_into("<qQ",data,0x1a0,1,1)
            elif kind=="partial_record": struct.pack_into("<Q",data,120+32,175)
            elif kind=="truncated_segment": struct.pack_into("<Q",data,64+32,100)
            elif kind=="overlapping_load":
                struct.pack_into("<H",data,56,3)
                data[176:232]=data[64:120]
            elif kind=="unreadable_load": struct.pack_into("<I",data,68,2)
            else: struct.pack_into("<Q",data,64+48,3)
            with self.subTest(kind=kind),self.assertRaises(d.InventoryError): d.elf_metadata(bytes(data))

    @unittest.skipUnless(ELFFile,"required explicit ELF parser gate")
    def test_allocated_compression_is_not_runtime_table_storage(self):
        for section in (1,2,3,4):
            data=bytearray(synthetic_import_elf())
            struct.pack_into("<Q",data,0x800+section*64+8,0x802)
            with self.subTest(section=section),self.assertRaises((d.InventoryError,ValueError)):
                b.import_slots(bytes(data),[{**region(0x10000,0x11000),"offset":0}])

    @unittest.skipUnless(ELFFile,"required explicit ELF parser gate")
    def test_page_rounded_later_load_cannot_replace_runtime_table_backing(self):
        data=page_conflict_import_elf()
        for inspect in (d.elf_metadata,lambda raw:b.import_slots(raw,[{**region(0x10000,0x11000),"offset":0}])):
            with self.subTest(inspect=inspect),self.assertRaises(d.InventoryError):
                inspect(data)

    def test_packed_grouped_offset_and_info(self):
        self.assertEqual(list(b.packed_rela(packed(2,4096,2,3,8,1026))),
                         [(4104,1026,0),(4112,1026,0)])

    def test_packed_individual_deltas_and_addend_reset(self):
        values = packed(3,4096,2,8,8,1025,5,-16,1026,-2,1,0,32,1026)
        self.assertEqual(list(b.packed_rela(values)),
                         [(4104,1025,5),(4088,1026,3),(4120,1026,0)])

    def test_packed_grouped_addend_changes_once_per_group(self):
        values = packed(3,4096,2,15,8,1025,9,1,15,8,1026,-3)
        self.assertEqual(list(b.packed_rela(values)),
                         [(4104,1025,9),(4112,1025,9),(4120,1026,6)])

    def test_packed_empty(self):
        self.assertEqual(list(b.packed_rela(packed(0,0))), [])

    def test_packed_malformed_rejected(self):
        cases = [b"APS1", packed(-1,0), packed(b.MAX_RELOCATIONS+1,0),
                 packed(1,-1), packed(1,0,0,0), packed(1,0,2,0),
                 packed(1,0,1,16), packed(1,0,1,4), packed(1,0,1,-1),
                 packed(1,0,1,0,-8,1025), packed(1,0,1,0,8,-1),
                 packed(1,0,1,15,8,1025,1<<63),
                 packed(0,0)+b"\0", b"APS2"+b"\x80"*11]
        for value in cases:
            with self.subTest(value=value), self.assertRaises(d.InventoryError):
                list(b.packed_rela(value))

    def test_packed_every_truncation_fails(self):
        value=packed(3,4096,2,15,8,1025,9,1,15,8,1026,-3)
        for cut in range(len(value)):
            with self.subTest(cut=cut), self.assertRaises(d.InventoryError):
                list(b.packed_rela(value[:cut]))

    def test_unsupported_relocation_format_fails(self):
        with self.assertRaises(d.InventoryError):
            b.relocation_rows({"sh_type":"SHT_REL"})

    def test_coalesces_small_gaps_only(self):
        slots = [slot(4096), slot(4112), slot(5000)]
        runs = b.checked_runs(slots, [region()])
        self.assertEqual([(r["start"], r["end"]) for r in runs], [(4096,4120), (5000,5008)])
        self.assertEqual([item["runIndex"] for item in slots], [0, 0, 1])

    def test_mapping_boundary_is_not_crossed(self):
        runs = b.checked_runs([slot(8184), slot(8192)], [region(), region(8192,12288)])
        self.assertEqual(len(runs), 2)

    def test_unreadable_unmapped_and_partial_pointer_fail(self):
        for slots, maps in (([slot(4096)],[region(permissions="--xp")]),
                            ([slot(4096)],[]), ([slot(8184)],[region(end=8188)])):
            with self.assertRaises(d.InventoryError): b.checked_runs(slots,maps)

    def test_overlapping_owner_rejected(self):
        with self.assertRaises(d.InventoryError): b.checked_runs([slot(4096)],[region(),region()])

    def test_duplicate_pointer_rejected(self):
        with self.assertRaises(d.InventoryError): b.checked_runs([slot(4096),slot(4096)],[region()])

    def test_bad_addresses_rejected(self):
        for value in (True, 1.0, 4097, -8, 0, 1<<56):
            with self.assertRaises(d.InventoryError): b.checked_runs([slot(value)],[region(0,1<<57)])

    def test_each_read_is_bounded(self):
        runs = b.checked_runs([slot(i) for i in range(4096,4096+32768,8)],[region(4096,4096+32768)])
        self.assertEqual(len(runs),2)
        self.assertTrue(all(r["end"]-r["start"] <= b.MAX_SPAN for r in runs))

    def test_total_read_budget_rejected(self):
        with self.assertRaises(d.InventoryError):
            b.checked_runs([slot(i) for i in range(4096,4096+b.MAX_MODULE_READ+8,8)],
                           [region(4096,4096+b.MAX_MODULE_READ+8)])

    @unittest.skipUnless(ELFFile,"required explicit ELF parser gate")
    def test_import_slot_budget_is_enforced_while_consuming(self):
        with patch.object(b,"MAX_IMPORT_SLOTS",1),self.assertRaises(d.InventoryError):
            b.import_slots(synthetic_import_elf(),[{**region(0x10000,0x11000),"offset":0}])

    @unittest.skipUnless(ELFFile,"required explicit ELF parser gate")
    def test_relocation_and_string_byte_budgets_precede_section_data(self):
        mappings=[{**region(0x10000,0x11000),"offset":0}]
        with patch.object(b,"MAX_RELOCATION_BYTES",1),self.assertRaises(d.InventoryError):
            b.import_slots(synthetic_import_elf(),mappings)
        with patch.object(d,"MAX_DYNAMIC_STRING_BYTES",4),self.assertRaises(d.InventoryError):
            b.import_slots(synthetic_import_elf(),mappings)

    def test_complete_mapping_authority_rejects_added_library(self):
        root=d.ROOT_LIBRARY
        extra="/system/lib64/liblate.so"
        maps={root:[mapped_record()]}
        authority={"filteredMappings":maps,"filteredMapSetSha256":d.mapping_set_digest(maps)}
        expected,digest=b.inventory_mapping_authority(authority)
        self.assertEqual(b.require_stable_mapping_set(maps,expected,digest),maps)
        changed={**maps,extra:[mapped_record(0x3000,2)]}
        with self.assertRaises(d.InventoryError):
            b.require_stable_mapping_set(changed,expected,digest)
        self.assertEqual(b.target_owner(0x3008,expected)["status"],"unresolved_target")

    def test_binding_owner_closure_is_rebuilt_from_reparsed_elf(self):
        root=d.ROOT_LIBRARY
        extra="/system/lib64/libextra.so"
        complete={root:[mapped_record()],extra:[mapped_record(0x3000,2)]}
        with tempfile.TemporaryDirectory() as temp:
            source=Path(temp)/"inventory.json"; source.write_text("{}")
            (Path(temp)/"0000000000000001.so").write_bytes(b"root")
            (Path(temp)/"0000000000000002.so").write_bytes(b"extra")
            root_meta={"sha256":d.ROOT_SHA256,"bytes":4,"soname":None,
                       "needed":["libextra.so"],"initArrayEntries":0,"initFunctions":[],
                       "localFile":"0000000000000001.so"}
            extra_meta={"sha256":"e"*64,"bytes":5,"soname":"libextra.so",
                        "needed":[],"initArrayEntries":0,"initFunctions":[],
                        "localFile":"0000000000000002.so"}
            inv={"libraries":{root:root_meta,extra:extra_meta}}
            derived=lambda meta:{key:meta[key] for key in
                ("sha256","bytes","soname","needed","initArrayEntries","initFunctions")}
            class LocalAuthority:
                def read(self,name,limit=d.MAX_FILE_BYTES,expected_size=None,budget=None):
                    data=(Path(temp)/name).read_bytes()
                    if len(data)>limit or (expected_size is not None and len(data)!=expected_size):
                        raise d.InventoryError("test authority size mismatch")
                    return data
            authority=LocalAuthority()
            with patch.object(d,"elf_metadata",side_effect=lambda data:
                    derived(root_meta if data==b"root" else extra_meta)):
                owners, data, parsed=b.authenticate_local_inventory(
                    inv,complete,source,authority=authority)
            self.assertEqual(set(owners),{root,extra})
            self.assertEqual(set(data),set(parsed))

            # A self-consistent serialized edge cannot make a disconnected ELF
            # owner-eligible when its reparsed DT_NEEDED list says otherwise.
            with patch.object(d,"elf_metadata",side_effect=lambda data:
                    ({**derived(root_meta),"needed":[]} if data==b"root" else derived(extra_meta))):
                with self.assertRaises(d.InventoryError):
                    b.authenticate_local_inventory(inv,complete,source,authority=authority)

    def test_every_owner_elf_is_recaptured_from_live_mapped_descriptor(self):
        paths = (d.ROOT_LIBRARY, "/system/lib64/libextra.so")
        owner_maps = {
            paths[0]: [mapped_record()],
            paths[1]: [mapped_record(0x3000, 2)],
        }
        identities = {
            paths[0]: {"authority": "proc-map-files-open-descriptor-v1", "bytes": 4,
                       "device": "fd:04", "inode": 1},
            paths[1]: {"authority": "proc-map-files-open-descriptor-v1", "bytes": 5,
                       "device": "fd:04", "inode": 2},
        }
        inventory = {"libraries": {
            paths[0]: {"bytes": 4, "mappedFileIdentity": identities[paths[0]]},
            paths[1]: {"bytes": 5, "mappedFileIdentity": identities[paths[1]]},
        }}
        local = {paths[0]: b"root", paths[1]: b"extra"}
        captures = []
        ordered = sorted(paths)

        def capture(command, limit):
            captures.append((command, limit))
            return b"bounded-capture"

        with patch.object(d, "mapped_capture_command", side_effect=("first-command", "second-command")), \
             patch.object(d, "parse_mapped_capture", side_effect=(
                 (local[ordered[0]], identities[ordered[0]]),
                 (local[ordered[1]], identities[ordered[1]]))):
            b.authenticate_live_inventory(capture, 123, inventory, owner_maps, local)
        self.assertEqual(captures, [("first-command", inventory["libraries"][ordered[0]]["bytes"] + 512),
                                    ("second-command", inventory["libraries"][ordered[1]]["bytes"] + 512)])

        with patch.object(d, "mapped_capture_command", return_value="changed-command"), \
             patch.object(d, "parse_mapped_capture", return_value=(b"changed", identities[paths[0]])):
            with self.assertRaises(d.InventoryError):
                b.authenticate_live_inventory(capture, 123, inventory,
                                               {paths[0]: owner_maps[paths[0]]}, local)

    def test_live_capture_reserves_bytes_before_producer_and_final_maps_are_bracketed(self):
        root=d.ROOT_LIBRARY
        maps={root:[mapped_record()]}
        inv={"libraries":{root:{"bytes":4,"mappedFileIdentity":{
            "authority":"proc-map-files-open-descriptor-v1","bytes":4,
            "device":"fd:04","inode":1}}}}
        called=[]
        with self.assertRaises(d.InventoryError):
            b.authenticate_live_inventory(lambda *_:called.append(True),123,inv,maps,
                                          {root:b"data"},b.WorkBudget(limit=1))
        self.assertEqual(called,[])
        states=iter((maps,maps))
        events=[]
        self.assertEqual(b.authenticate_final_window(lambda:next(states),lambda:events.append("auth")),maps)
        self.assertEqual(events,["auth"])
        changed={root:[{**mapped_record(),"start":0x3000,"end":0x4000}]}
        states=iter((maps,changed))
        with self.assertRaises(d.InventoryError):
            b.authenticate_final_window(lambda:next(states),lambda:None)

    @unittest.skipUnless(ELFFile,"required explicit ELF parser gate")
    def test_llvm_oracle_uses_only_authenticated_tables_and_aggregate_budget(self):
        elf=ELFFile(io.BytesIO(synthetic_import_elf()))
        observed=llvm_oracle.observed_relocations(elf)
        self.assertEqual(set(observed),{3,4})
        with patch.object(b,"MAX_RELOCATIONS",1),self.assertRaises(d.InventoryError):
            llvm_oracle.observed_relocations(ELFFile(io.BytesIO(synthetic_import_elf())))
        document=[{"Relocations":[{"SectionIndex":99,"Relocs":[]}]}]
        with self.assertRaises(d.InventoryError):
            llvm_oracle.reference_relocations(document,observed)

    def test_null_and_unknown_targets_remain_unresolved(self):
        self.assertEqual(b.target_owner(0,{})["status"], "null")
        self.assertEqual(b.target_owner(4096,{})["status"], "unresolved_target")

    def test_target_unique_or_ambiguous(self):
        maps={"a":[region()],"b":[region(8192,12288)]}
        self.assertEqual(b.target_owner(4096,maps),{"status":"unique_mapped_target","paths":["a"]})
        maps["b"]=[region()]
        with self.assertRaises(d.InventoryError): b.target_owner(4096,maps)

    def test_one_aggregate_work_budget_covers_planning_and_lookup(self):
        budget=b.WorkBudget(limit=3)
        b.checked_runs([slot(4096)], [region()], budget)
        b.target_owner(4096, b.MappingIndex({"a":[region()]}), budget)
        with self.assertRaises(d.InventoryError):
            b.target_owner(4096, b.MappingIndex({"a":[region()]}), budget)

    def test_report_and_work_limits_have_one_aggregate_ceiling(self):
        self.assertLessEqual(
            b.MAX_TOTAL_IMPORT_SLOTS*b.MAX_SERIALIZED_SLOT_BYTES+
            b.MAX_REPORT_NON_SLOT_BYTES,b.MAX_REPORT_BYTES)
        self.assertLessEqual(b.MAX_IMPORT_SLOTS,b.MAX_TOTAL_IMPORT_SLOTS)
        with self.assertRaises(d.InventoryError):
            list(b.relr_rows(struct.pack("<Q",0x1000),b.WorkBudget(limit=1)))
        payload=packed(1,4096,1,0,8,1025)
        with self.assertRaises(d.InventoryError):
            list(b.packed_rela(payload,b.WorkBudget(limit=1)))

    def test_serialized_slot_bound_is_derived_from_legal_worst_case(self):
        worst=dict(b._WORST_SERIALIZED_SLOT)
        worst["paths"]=list(worst["paths"])
        self.assertEqual(len(worst["symbol"].encode("utf-8")),d.MAX_DEPENDENCY_NAME_BYTES)
        self.assertEqual(len(worst["paths"][0].encode("ascii")),b.MAX_OWNER_PATH_BYTES)
        self.assertIsNotNone(d.PATH.fullmatch(worst["paths"][0]))
        envelope=lambda rows:{"modules":{"m":{"slots":rows}}}
        encoded=lambda rows:len(json.dumps(
            envelope(rows),indent=2,ensure_ascii=True).encode("ascii"))
        first=encoded([worst])-encoded([])
        subsequent=encoded([worst,worst])-encoded([worst])
        self.assertEqual(b.MAX_SERIALIZED_SLOT_BYTES,first)
        self.assertGreaterEqual(first,subsequent)
        self.assertEqual(b.serialized_slot_bytes(worst),b.MAX_SERIALIZED_SLOT_BYTES)
        self.assertEqual(b.MAX_SERIALIZED_SLOT_BYTES,7583)
        self.assertLessEqual(
            b.MAX_TOTAL_IMPORT_SLOTS*b.MAX_SERIALIZED_SLOT_BYTES+
            b.MAX_REPORT_NON_SLOT_BYTES,b.MAX_REPORT_BYTES)
        oversized=dict(worst); oversized["symbol"]="\x01"*(d.MAX_DEPENDENCY_NAME_BYTES+1)
        with self.assertRaises(d.InventoryError): b.serialized_slot_bytes(oversized)
        oversized=dict(worst); oversized["paths"]=[
            "/apex/"+"a"*b.MAX_OWNER_PATH_BYTES+"/lib64/bionic/z.so"]
        with self.assertRaises(d.InventoryError): b.serialized_slot_bytes(oversized)

    def test_drawpath_cmdline_is_exact_including_one_terminal_nul(self):
        exact=b"com.ratta.drawpath\0"
        self.assertIs(b.require_drawpath_cmdline(exact),exact)
        self.assertIs(d.require_drawpath_cmdline(exact),exact)
        for value in (b"com.ratta.drawpath",exact+b"\0",exact+b"ignored",
                      b"com.ratta.drawpath\0other\0",bytearray(exact),None):
            with self.subTest(value=value),self.assertRaises(d.InventoryError):
                b.require_drawpath_cmdline(value)
            with self.subTest(dependency_value=value),self.assertRaises(d.InventoryError):
                d.require_drawpath_cmdline(value)

    def test_complete_map_digest_rejects_non_lf_line_semantics(self):
        def record(start,end,path):
            return (f"{start:x}-{end:x} r--p 00000000 fd:04 1 ".encode("ascii")+
                    path)
        line=record(0x1000,0x2000,d.ROOT_LIBRARY.encode("ascii"))
        second=record(0x3000,0x4000,b"[anon:filtered-out]")
        exact=line+b"\n"+second+b"\n"
        self.assertEqual(d.complete_map_digest(exact),hashlib.sha256(exact).hexdigest())
        for raw in (line,line+b"\r\n",b"\xef\xbb\xbf"+exact,
                    line+b"\xc2\x85\n",line+b"\xe2\x80\xa8\n",
                    line+b"\xe2\x80\xa9\n",line.replace(b" r--p ",b"\tr--p ")+b"\n",
                    second+b"\n"+line+b"\n",
                    line+b"\n"+record(0x1800,0x2800,b"[filtered-overlap]")+b"\n"):
            with self.subTest(raw=raw),self.assertRaises(d.InventoryError):
                d.complete_map_digest(raw)

    def test_inventory_raw_map_artifacts_are_consumed_as_exact_authority(self):
        raw=(b"1000-2000 r-xp 00000000 fd:04 1 "+
             d.ROOT_LIBRARY.encode("ascii")+b"\n")
        maps=d.validate_mapping_set(d.mapped_libraries(raw.decode("ascii")))
        inventory={"filteredMappings":maps,
                   "filteredMapSetSha256":d.mapping_set_digest(maps),
                   "completeRawMapsSha256":hashlib.sha256(raw).hexdigest(),
                   "completeRawMapsBytes":len(raw)}
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            (root/"maps-before.txt").write_bytes(raw)
            (root/"maps-after.txt").write_bytes(raw)
            with d.EvidenceDirectory(root) as authority:
                observed,observed_maps,digest=b.authenticate_inventory_raw_maps(
                    inventory,authority,b.WorkBudget(limit=1_000_000))
            self.assertEqual(observed,raw)
            self.assertEqual(observed_maps,maps)
            self.assertEqual(digest,inventory["filteredMapSetSha256"])

        for label,mutate_inventory,after in (
                ("digest",lambda value:value.update(
                    completeRawMapsSha256="0"*64),raw),
                ("witness",lambda value:None,raw.replace(b"fd:04",b"fd:05")),
                ("filtered",lambda value:value.update(filteredMappings={}),raw)):
            with self.subTest(label=label),tempfile.TemporaryDirectory() as temp:
                changed=json.loads(json.dumps(inventory))
                mutate_inventory(changed)
                root=Path(temp)
                (root/"maps-before.txt").write_bytes(raw)
                (root/"maps-after.txt").write_bytes(after)
                with d.EvidenceDirectory(root) as authority,self.assertRaises(d.InventoryError):
                    b.authenticate_inventory_raw_maps(
                        changed,authority,b.WorkBudget(limit=1_000_000))

    def test_live_raw_map_digest_must_match_inventory_capture(self):
        digest="a"*64
        self.assertEqual(b.require_inventory_raw_map_digest(
            {"completeRawMapsSha256":digest},digest),digest)
        for value in ("b"*64,"A"*64,"a"*63,None,True):
            with self.subTest(value=value),self.assertRaises(d.InventoryError):
                b.require_inventory_raw_map_digest(
                    {"completeRawMapsSha256":digest},value)

    def test_consumer_rejects_same_inode_postpublication_raw_map_mutation(self):
        inventory,artifacts=dependency_tests.inventory_generation_fixture()
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)/"generation"
            with d.InventoryGeneration(root) as generation:
                dependency_tests.stage_generation(generation,artifacts)
                generation.finalize(inventory)
            targets=(root/"maps-before.txt",root/"maps-after.txt")
            for target in targets:
                original=os.stat(target)
                target.chmod(stat.S_IRUSR | stat.S_IWUSR)
                with target.open("r+b") as stream:
                    raw=stream.read()
                    stream.seek(raw.index(b"fd:04")+4)
                    stream.write(b"5")
                    stream.flush()
                    os.fsync(stream.fileno())
                changed=os.stat(target)
                self.assertEqual((original.st_dev,original.st_ino),
                                 (changed.st_dev,changed.st_ino))
            with d.EvidenceDirectory(root) as authority,self.assertRaises(d.InventoryError):
                b.authenticate_inventory_raw_maps(
                    inventory,authority,b.WorkBudget(limit=1_000_000))

    def test_atomic_publication_is_capped_and_never_replaces(self):
        with tempfile.TemporaryDirectory() as temp:
            target=Path(temp)/"report.json"
            b.publish_report({"ok":True},target,b.WorkBudget(limit=1000))
            self.assertEqual(target.read_text(),'{\n  "ok": true\n}\n')
            with self.assertRaises(b.PublicationReviewRequired):
                b.publish_report({"ok":False},target,b.WorkBudget(limit=1000))
            self.assertEqual(target.read_text(),'{\n  "ok": true\n}\n')
            with patch.object(b,"MAX_REPORT_BYTES",4),self.assertRaises(d.InventoryError):
                b.publish_report({"too":"large"},Path(temp)/"large.json",b.WorkBudget(limit=1000))
            self.assertFalse((Path(temp)/"large.json").exists())

    def test_report_is_fully_staged_before_no_replace_commit(self):
        with tempfile.TemporaryDirectory() as temp:
            target=Path(temp)/"report.json"
            staged=b.stage_report({"authority":"before-and-after"},target,
                                  b.WorkBudget(limit=1000))
            try:
                self.assertFalse(target.exists())
                self.assertTrue(staged.retained)
                self.assertGreater(staged.size,0)
                if os.name == "posix":
                    with self.assertRaises(OSError):
                        os.write(staged.descriptor,b"changed")
                    with self.assertRaises(OSError):
                        os.ftruncate(staged.descriptor,0)
                    with self.assertRaises(OSError):
                        os.open(f"/proc/self/fd/{staged.descriptor}",os.O_RDWR)
                    self.assertIsNone(staged.temporary_name)
                else:
                    with self.assertRaises(OSError):
                        (target.parent/staged.temporary_name).open("r+b")
                    replacement=target.parent/"replacement.tmp"
                    replacement.write_bytes(b"replacement")
                    with self.assertRaises(OSError):
                        replacement.replace(target.parent/staged.temporary_name)
                b.commit_report(staged)
            finally:
                staged.close()
            self.assertTrue(staged.committed)
            self.assertEqual(target.read_text(),'{\n  "authority": "before-and-after"\n}\n')

    def test_final_live_window_is_immediately_followed_by_terminal_commit(self):
        with tempfile.TemporaryDirectory() as temp:
            target=Path(temp)/"report.json"
            budget=b.WorkBudget(limit=1000)
            original_checkpoint=budget.checkpoint
            final_returned=False
            events=[]

            def guarded_checkpoint():
                if final_returned:
                    raise AssertionError("fallible budget check after final-live window")
                return original_checkpoint()

            def final_window():
                nonlocal final_returned
                events.append("final-window")
                final_returned=True
                return "authority"

            budget.checkpoint=guarded_checkpoint
            original_commit=b.commit_report
            def commit(staged):
                events.append("commit")
                return original_commit(staged)
            with patch.object(b,"commit_report",side_effect=commit):
                result=b.publish_after_final_window(
                    {"ok":True},target,budget,final_window)
            self.assertEqual(result,"authority")
            self.assertEqual(events,["final-window","commit"])
            self.assertTrue(target.exists())

    def test_production_main_uses_the_terminal_publication_seam(self):
        source=inspect.getsource(b.main)
        self.assertIn(
            "publish_after_final_window(report, args.output, work, final_window)",source)
        self.assertNotIn("stage_report(",source)
        self.assertNotIn("commit_report(",source)

    def test_production_main_stages_then_completes_final_window_then_commits(self):
        pinned_python = Path(os.environ.get(
            "RTL_READER_AUTHENTICATED_ELFTOOLS_ROOT",
            str(Path(__file__).resolve().parents[3] / "tools" / "python")))
        self.assertTrue((pinned_python / "elftools" / "__init__.py").is_file())
        raw_maps = b"1000-2000 r--p 00000000 00:00 0 [anon:test]\n"
        inventory = {"process": {"pid": 123, "startTime": 456}, "libraries": {},
                     "completeRawMapsSha256": hashlib.sha256(raw_maps).hexdigest()}
        maps_digest = d.mapping_set_digest({})
        events = []
        commands = []
        real_stage = b.stage_report
        real_final_window = b.authenticate_final_window
        real_commit = b.commit_report

        def bounded(command, *_):
            commands.append(tuple(command))
            rendered = " ".join(command)
            if "ro.build.fingerprint" in rendered:
                return (d.FINGERPRINT + "\n").encode("ascii")
            if f"/proc/{inventory['process']['pid']}/stat" in rendered:
                return b"authenticated-stat\n"
            if f"/proc/{inventory['process']['pid']}/cmdline" in rendered:
                return b"com.ratta.drawpath\0"
            if f"/proc/{inventory['process']['pid']}/maps" in rendered:
                return raw_maps
            raise AssertionError("unexpected external command: " + rendered)

        def staged(*args, **kwargs):
            events.append("stage")
            return real_stage(*args, **kwargs)

        def final_window(verify, authenticate):
            events.append("final-window-start")
            verifies = 0

            def observed_verify():
                nonlocal verifies
                verifies += 1
                events.append("final-verify-before" if verifies == 1 else
                              "final-verify-after")
                return verify()

            def observed_authenticate():
                events.append("final-live-authenticate")
                return authenticate()

            result = real_final_window(observed_verify, observed_authenticate)
            self.assertEqual(verifies, 2)
            events.append("final-window-complete")
            return result

        def committed(*args, **kwargs):
            events.append("commit")
            return real_commit(*args, **kwargs)

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            adb = root / "adb-test-double"
            source = root / "inventory.json"
            output = root / "bindings.json"
            adb.write_bytes(b"not executed")
            source.write_text("{}", encoding="ascii")
            original_path = list(sys.path)
            argv = ["inspect_loader_bindings.py", "--adb", str(adb),
                    "--python-path", str(pinned_python), "--inventory", str(source),
                    "--output", str(output)]
            try:
                with patch.object(b, "MODULES", ()), \
                     patch.object(d, "validate_inventory_v4", return_value=inventory), \
                     patch.object(b, "authenticate_inventory_raw_maps",
                                  return_value=(raw_maps, {}, maps_digest)), \
                     patch.object(b, "authenticate_local_inventory",
                                  return_value=({}, {}, {})), \
                     patch.object(d, "process_identity", return_value=(123, 456)), \
                     patch.object(d, "bounded_command", side_effect=bounded), \
                     patch.object(b, "stage_report", side_effect=staged), \
                     patch.object(b, "authenticate_final_window",
                                  side_effect=final_window), \
                     patch.object(b, "commit_report", side_effect=committed), \
                     patch.object(sys, "argv", argv):
                    b.main()
            finally:
                sys.path[:] = original_path

            self.assertEqual(events, [
                "stage", "final-window-start", "final-verify-before",
                "final-live-authenticate", "final-verify-after",
                "final-window-complete", "commit",
            ])
            self.assertTrue(output.is_file())
            report = json.loads(output.read_text(encoding="ascii"))
            self.assertEqual(report["schema"], "native-loader-bindings-v1")
            self.assertEqual(report["modules"], {})
            self.assertEqual(len(commands), 20)
            rendered_commands = [" ".join(command) for command in commands]
            self.assertEqual(sum("ro.build.fingerprint" in command
                                 for command in rendered_commands), 4)
            self.assertEqual(sum(f"/proc/{inventory['process']['pid']}/stat" in command
                                 for command in rendered_commands), 8)
            self.assertEqual(sum(f"/proc/{inventory['process']['pid']}/cmdline" in command
                                 for command in rendered_commands), 4)
            self.assertEqual(sum(f"/proc/{inventory['process']['pid']}/maps" in command
                                 for command in rendered_commands), 4)
            self.assertTrue(all(command[0] == str(adb.resolve()) for command in commands))

    def test_post_commit_cleanup_failure_cannot_make_publication_retryable(self):
        class BadCleanup:
            def __exit__(self,*_):
                raise OSError("cleanup diagnostic failed")
        with tempfile.TemporaryDirectory() as temp:
            target=Path(temp)/"report.json"
            staged=b.stage_report({"ok":True},target,b.WorkBudget(limit=1000))
            staged.authorities.append(BadCleanup())
            b.commit_report(staged)
            staged.close()
            self.assertTrue(staged.committed)
            self.assertEqual(target.read_text(),'{\n  "ok": true\n}\n')

        with tempfile.TemporaryDirectory() as temp:
            target=Path(temp)/"outer-seam.json"
            real_commit=b.commit_report
            real_close=b.StagedReport.close
            def committed_then_fault(staged):
                real_commit(staged)
                raise OSError("fault after commit wrapper returned")
            def cleanup_then_fault(staged):
                real_close(staged)
                raise OSError("cleanup diagnostic failed")
            diagnostics=io.StringIO()
            with patch.object(b,"commit_report",side_effect=committed_then_fault), \
                 patch.object(b.StagedReport,"close",autospec=True,
                              side_effect=cleanup_then_fault), \
                 patch.object(sys,"stderr",diagnostics):
                code=b._run_cli(lambda: b.publish_report(
                    {"ok":True},target,b.WorkBudget(limit=1000)))
            self.assertEqual(code,2)
            self.assertIn("BINDINGS_PUBLICATION_NONRETRYABLE",
                          diagnostics.getvalue())
            self.assertEqual(target.read_text(),'{\n  "ok": true\n}\n')

        with tempfile.TemporaryDirectory() as temp:
            target=Path(temp)/"cleanup-only.json"
            real_close=b.StagedReport.close
            def cleanup_only_fault(staged):
                real_close(staged)
                raise KeyboardInterrupt("cleanup-only async fault")
            with patch.object(b.StagedReport,"close",autospec=True,
                              side_effect=cleanup_only_fault):
                code=b._run_cli(lambda: b.publish_report(
                    {"ok":True},target,b.WorkBudget(limit=1000)))
            self.assertEqual(code,0)
            self.assertEqual(target.read_text(),'{\n  "ok": true\n}\n')

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
            b._report_terminal_success(
                "BINDINGS_COMPLETE native_start_allowed=false")
            self.assertIsNot(sys.stdout, failed)
            replacement = sys.stdout
        replacement.close()

    def test_terminal_success_survives_closed_pipe_after_binding_commit(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            code, stderr = _run_publication_process_with_closed_stdout(
                root, "terminal-success")
            self.assertEqual(code, 0, stderr.decode(errors="replace"))
            authority = root / "report.json"
            self.assertEqual(
                authority.read_bytes(), b'{\n  "authority": "only"\n}\n')
            self.assertEqual(list(root.iterdir()), [authority])

            # A retry still observes the single terminal name as a collision
            # and retains the established nonretryable exit classification.
            retry_code, retry_stderr = \
                _run_publication_process_with_closed_stdout(root, "collision")
            self.assertEqual(retry_code, 2,
                             retry_stderr.decode(errors="replace"))
            self.assertIn(b"BINDINGS_PUBLICATION_NONRETRYABLE", retry_stderr)
            self.assertEqual(list(root.iterdir()), [authority])

            uncertain = Path(temp) / "uncertain"
            uncertain.mkdir()
            uncertain_code, uncertain_stderr = \
                _run_publication_process_with_closed_stdout(
                    uncertain, "outcome-unknown")
            self.assertEqual(uncertain_code, 2,
                             uncertain_stderr.decode(errors="replace"))
            self.assertIn(b"BINDINGS_PUBLICATION_NONRETRYABLE",
                          uncertain_stderr)
            uncertain_authority = uncertain / "report.json"
            self.assertEqual(uncertain_authority.read_bytes(),
                             b'{\n  "authority": "only"\n}\n')
            self.assertEqual(list(uncertain.iterdir()), [uncertain_authority])
            retry_code, retry_stderr = \
                _run_publication_process_with_closed_stdout(
                    uncertain, "collision")
            self.assertEqual(retry_code, 2,
                             retry_stderr.decode(errors="replace"))
            self.assertEqual(list(uncertain.iterdir()), [uncertain_authority])

    def test_final_window_failure_leaves_no_named_report(self):
        with tempfile.TemporaryDirectory() as temp:
            target=Path(temp)/"report.json"
            with self.assertRaisesRegex(RuntimeError,"final failed"):
                b.publish_after_final_window(
                    {"ok":True},target,b.WorkBudget(limit=1000),
                    lambda: (_ for _ in ()).throw(RuntimeError("final failed")))
            self.assertFalse(target.exists())

    def test_commit_collision_preserves_existing_output_and_retires_stage(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as temp:
            target=Path(temp)/"report.json"
            staged=b.stage_report({"new":True},target,b.WorkBudget(limit=1000))
            target.write_bytes(b"existing")
            try:
                with self.assertRaises(b.PublicationReviewRequired):
                    b.commit_report(staged)
            finally:
                staged.close()
            self.assertEqual(staged.publication_state,"collision")
            self.assertEqual(target.read_bytes(),b"existing")
            if staged.temporary_name is not None:
                self.assertFalse((target.parent/staged.temporary_name).exists())

        # Exercise the exact interval after the no-replace syscall succeeds but
        # before commit_report can record a normal return from that syscall.
        # Cleanup must preserve the possible authority and the explicit state
        # must prevent an ordinary retryable classification.
        with tempfile.TemporaryDirectory() as temp:
            target=Path(temp)/"outcome-unknown.json"
            staged=b.stage_report({"only":"authority"},target,
                                  b.WorkBudget(limit=1000))
            if os.name == "posix":
                seam="_posix_link_anonymous"
            elif os.name == "nt":
                seam="_windows_rename_no_replace"
            else:
                staged.close()
                self.skipTest("publication platform")
            real_syscall=getattr(b,seam)
            def fault_after_success(*args):
                real_syscall(*args)
                raise OSError("fault after successful no-replace syscall")
            try:
                with patch.object(b,seam,side_effect=fault_after_success), \
                     self.assertRaisesRegex(
                         b.PublicationReviewRequired,"outcome is uncertain"):
                    b.commit_report(staged)
            finally:
                staged.close()
            self.assertEqual(staged.publication_state,"outcome-unknown")
            self.assertEqual(target.read_text(),
                             '{\n  "only": "authority"\n}\n')

    @unittest.skipUnless(os.name == "posix", "POSIX retained-parent swap")
    def test_parent_swap_during_commit_quarantines_retained_partial(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); parent=root/"authority"; parent.mkdir()
            moved=root/"moved"; target=parent/"report.json"
            staged=b.stage_report({"ok":True},target,b.WorkBudget(limit=1000))
            real_link=b._posix_link_anonymous
            def swap_then_link(descriptor,directory,name):
                parent.rename(moved)
                parent.mkdir()
                return real_link(descriptor,directory,name)
            try:
                with patch.object(b,"_posix_link_anonymous",side_effect=swap_then_link), \
                     self.assertRaises(b.PublicationReviewRequired):
                    b.commit_report(staged)
            finally:
                staged.close()
            self.assertTrue(staged.committed)
            self.assertFalse(target.exists())
            partial=moved/"report.json"
            self.assertEqual(partial.read_text(),'{\n  "ok": true\n}\n')
            with self.assertRaisesRegex(
                    b.PublicationReviewRequired,"output already exists"):
                b.publish_report(
                    {"retry":False},partial,b.WorkBudget(limit=1000))
            self.assertEqual(partial.read_text(),'{\n  "ok": true\n}\n')
            self.assertEqual(set(root.iterdir()),{parent,moved})

    @unittest.skipUnless(os.name == "nt", "Windows retained-parent and rollback")
    def test_windows_parent_authority_and_post_rename_failure_fail_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); target=root/"report.json"
            staged=b.stage_report({"ok":True},target,b.WorkBudget(limit=1000))
            moved=root.with_name(root.name+"-moved")
            events=[]
            real_flush=b._windows_flush
            real_rename=b._windows_rename_no_replace
            real_final=b._windows_final_path
            def observed_flush(handle):
                events.append("flush")
                return real_flush(handle)
            def observed_rename(*args):
                events.append("rename")
                return real_rename(*args)
            def fail_post_rename(handle):
                if staged.committed and handle == staged.windows_handle:
                    raise OSError("post-rename path diagnostic failed")
                return real_final(handle)
            try:
                with self.assertRaises(OSError):
                    root.rename(moved)
                with patch.object(b,"_windows_flush",side_effect=observed_flush), \
                     patch.object(b,"_windows_rename_no_replace",side_effect=observed_rename), \
                     patch.object(b,"_windows_final_path",side_effect=fail_post_rename), \
                     self.assertRaisesRegex(
                         b.PublicationReviewRequired,"authority is uncertain"):
                    b.commit_report(staged)
            finally:
                staged.close()
            self.assertEqual(events,["flush","rename"])
            self.assertTrue(staged.committed)
            self.assertEqual(target.read_text(),'{\n  "ok": true\n}\n')
            self.assertFalse(any(child.name.startswith(".bindings-")
                                 for child in root.iterdir()))

    @unittest.skipUnless(os.name == "nt", "Windows output ADS rejection")
    def test_windows_output_alternate_stream_is_rejected_before_staging(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); target=root/"report.json:alternate"
            with patch.object(b,"_windows_create_stage",
                              side_effect=AssertionError("stage must not be created")), \
                 self.assertRaises(d.InventoryError):
                b.stage_report({"ok":True},target,b.WorkBudget(limit=1000))
            self.assertEqual(list(root.iterdir()),[])

    def test_real_process_publication_boundaries_never_duplicate_authority(self):
        with tempfile.TemporaryDirectory() as temp:
            base=Path(temp)
            expected=b'{\n  "authority": "only"\n}\n'

            normal=base/"normal"; normal.mkdir()
            process=_run_publication_process(normal,"normal")
            self.assertEqual(process.returncode,0,process.stderr.decode(errors="replace"))
            self.assertEqual((normal/"report.json").read_bytes(),expected)

            precommit=base/"precommit"; precommit.mkdir()
            process=_run_publication_process(precommit,"precommit")
            self.assertEqual(process.returncode,1,process.stderr.decode(errors="replace"))
            self.assertFalse((precommit/"report.json").exists())

            collision=base/"collision"; collision.mkdir()
            (collision/"report.json").write_bytes(b"existing-authority")
            process=_run_publication_process(collision,"collision")
            self.assertEqual(process.returncode,2,process.stderr.decode(errors="replace"))
            self.assertIn(b"BINDINGS_PUBLICATION_NONRETRYABLE",process.stderr)
            self.assertEqual((collision/"report.json").read_bytes(),b"existing-authority")
            self.assertEqual(list(collision.iterdir()),[collision/"report.json"])

            postcommit=base/"postcommit"; postcommit.mkdir()
            process=_run_publication_process(postcommit,"postcommit")
            self.assertEqual(process.returncode,2,process.stderr.decode(errors="replace"))
            self.assertEqual((postcommit/"report.json").read_bytes(),expected)
            retry=_run_publication_process(postcommit,"collision")
            self.assertEqual(retry.returncode,2,retry.stderr.decode(errors="replace"))
            self.assertEqual((postcommit/"report.json").read_bytes(),expected)
            self.assertEqual(list(postcommit.iterdir()),[postcommit/"report.json"])

            crashed=base/"crashed"; crashed.mkdir()
            process=_run_publication_process(crashed,"crash")
            self.assertEqual(process.returncode,77,process.stderr.decode(errors="replace"))
            self.assertEqual((crashed/"report.json").read_bytes(),expected)
            retry=_run_publication_process(crashed,"collision")
            self.assertEqual(retry.returncode,2,retry.stderr.decode(errors="replace"))
            self.assertEqual((crashed/"report.json").read_bytes(),expected)
            self.assertEqual(list(crashed.iterdir()),[crashed/"report.json"])

            uncertain=base/"outcome-unknown"; uncertain.mkdir()
            process=_run_publication_process(uncertain,"outcome-unknown")
            self.assertEqual(process.returncode,2,process.stderr.decode(errors="replace"))
            self.assertIn(b"BINDINGS_PUBLICATION_NONRETRYABLE",process.stderr)
            self.assertEqual((uncertain/"report.json").read_bytes(),expected)
            retry=_run_publication_process(uncertain,"collision")
            self.assertEqual(retry.returncode,2,retry.stderr.decode(errors="replace"))
            self.assertEqual((uncertain/"report.json").read_bytes(),expected)
            self.assertEqual(list(uncertain.iterdir()),[uncertain/"report.json"])

            if os.name == "posix":
                before=base/"parent-before"; before.mkdir()
                process=_run_publication_process(before,"parent-before")
                self.assertEqual(process.returncode,2,process.stderr.decode(errors="replace"))
                self.assertFalse((before/"report.json").exists())
                self.assertFalse((base/"parent-before-moved"/"report.json").exists())

                after=base/"parent-after"; after.mkdir()
                process=_run_publication_process(after,"parent-after")
                self.assertEqual(process.returncode,2,process.stderr.decode(errors="replace"))
                self.assertFalse((after/"report.json").exists())
                relocated=base/"parent-after-moved"/"report.json"
                self.assertEqual(relocated.read_bytes(),expected)
                retry=_run_publication_process(
                    base/"parent-after-moved","collision")
                self.assertEqual(retry.returncode,2,
                                 retry.stderr.decode(errors="replace"))
                self.assertEqual(relocated.read_bytes(),expected)


if __name__ == "__main__": unittest.main()
