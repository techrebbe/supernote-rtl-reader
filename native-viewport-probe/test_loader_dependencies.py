"""Host-only tests. No ADB, firmware execution or real ELF fixture required."""
import argparse
import io
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

import inspect_loader_dependencies as inv

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--python-path", required=True)
    args, other = parser.parse_known_args()
    sys.path.insert(0, args.python_path)

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


def meta(needed=(), digest="f"*64, size=10):
    return {"bytes": size, "sha256": digest, "needed": list(needed)}


class InventoryTests(unittest.TestCase):
    def test_mapped_descriptor_identity_and_capture(self):
        maps=inv.mapped_libraries(record(inv.ROOT_LIBRARY))[inv.ROOT_LIBRARY]
        header=b"64772:123:4:81a4:1:1"
        data,identity=inv.parse_mapped_capture(header+b"\nELFx"+header+b"\n",maps)
        self.assertEqual(data,b"ELFx")
        self.assertEqual(identity["authority"],"proc-map-files-open-descriptor-v1")
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
            with patch.object(Path,"open",return_value=Growing(b"abcde")),patch.object(inv.os,"fstat",return_value=old):
                with self.assertRaises(inv.InventoryError): inv.read_bounded(path,4)

    def test_bounded_command_overflow_failure_and_timeout(self):
        self.assertEqual(inv.bounded_command([sys.executable,"-c","print('ok')"],10).strip(),b"ok")
        for code,limit,timeout in (("print('x'*10000)",10,3),("raise SystemExit(3)",10,3),
                                    ("import time;time.sleep(3)",10,0.1)):
            with self.assertRaises(inv.InventoryError): inv.bounded_command([sys.executable,"-c",code],limit,timeout)

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
    def test_elf_reject_path_as_needed(self):
        with self.assertRaises(inv.InventoryError):
            inv.elf_metadata(fake_elf(needed="../libc.so"))

    def test_root_digest_is_pinned(self):
        with self.assertRaises(inv.InventoryError):
            inv.collect_graph({inv.ROOT_LIBRARY: []}, lambda _: meta())

    def test_missing_dependency_not_silently_complete(self):
        libs, edges = inv.collect_graph({inv.ROOT_LIBRARY: []}, lambda _: meta(["missing.so"], inv.ROOT_SHA256))
        self.assertEqual(len(libs), 1)
        self.assertEqual(edges[0]["resolution"], "missing")

    def test_ambiguous_namespace_copies_never_select_first(self):
        a, b = "/system/lib64/libc++.so", "/apex/com.android.vndk.v30/lib64/libc++.so"
        maps = {inv.ROOT_LIBRARY: [], a: [], b: []}
        def read(path):
            return meta(["libc++.so"], inv.ROOT_SHA256) if path == inv.ROOT_LIBRARY else meta()
        libs, edges = inv.collect_graph(maps, read)
        self.assertEqual(set(libs), set(maps))
        self.assertEqual(edges[0]["resolution"], "unresolved_multiple")
        self.assertEqual(edges[0]["candidates"], sorted([a, b]))

    def test_cycle_is_bounded(self):
        a = "/system/lib64/liba.so"
        seen = []
        def read(path):
            seen.append(path)
            return meta(["liba.so"], inv.ROOT_SHA256) if path == inv.ROOT_LIBRARY else meta(["librecgnition.so"])
        libs, _ = inv.collect_graph({inv.ROOT_LIBRARY: [], a: []}, read)
        self.assertEqual(len(seen), 2)
        self.assertEqual(len(libs), 2)

    def test_invalid_file_size_fails(self):
        for size in (0, -1, True, inv.MAX_FILE_BYTES+1):
            with self.assertRaises(inv.InventoryError):
                inv.collect_graph({inv.ROOT_LIBRARY: []}, lambda _: meta(digest=inv.ROOT_SHA256, size=size))


if __name__ == "__main__":
    if not ELF_AVAILABLE:
        raise SystemExit("Required ELF parser unavailable; explicit loader test run fails closed")
    unittest.main(argv=[sys.argv[0], *other])
