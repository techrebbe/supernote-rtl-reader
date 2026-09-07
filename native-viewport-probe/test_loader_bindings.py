"""Memory read-plan and classification tests; no ADB or live memory access."""
import unittest
import io
import struct
import inspect_loader_bindings as b
import inspect_loader_dependencies as d

try:
    from elftools.elf.elffile import ELFFile
except ImportError:
    ELFFile=None


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


class BindingTests(unittest.TestCase):
    def test_relr_includes_bitmap_and_has_no_import_symbol_or_addend(self):
        data=struct.pack("<QQQ",0x1000,1|(1<<1)|(1<<3),0x2000)
        self.assertEqual(list(b.relr_rows(data)),[(0x1000,1027,None),(0x1008,1027,None),(0x1018,1027,None),(0x2000,1027,None)])
        for value in (b"",b"a",struct.pack("<Q",3),struct.pack("<Q",0x1002),
                      struct.pack("<QQ",0x1000,0x1000),struct.pack("<Q",0xfffffffffffffff8)):
            with self.assertRaises(d.InventoryError): list(b.relr_rows(value))

    def test_slot_file_offset_correspondence(self):
        loads=[{"p_vaddr":0x4000,"p_offset":0x1000,"p_filesz":4096}]
        maps=[{**region(0x14000,0x15000),"offset":0x1000}]
        b.slot_file_correspondence(0x4000,0x10000,loads,maps)
        maps[0]["offset"]=0x8000
        with self.assertRaises(d.InventoryError): b.slot_file_correspondence(0x4000,0x10000,loads,maps)

    @unittest.skipUnless(ELFFile,"required explicit ELF parser gate")
    def test_renamed_packed_import_table_is_not_omitted(self):
        slots,_=b.import_slots(synthetic_import_elf(),[{**region(0x10000,0x11000),"offset":0}])
        self.assertEqual({s["rva"] for s in slots},{0x600,0x608})
        self.assertEqual({s["symbol"] for s in slots},{"foo"})

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
        runs = b.checked_runs([slot(4096), slot(4112), slot(5000)], [region()])
        self.assertEqual([(r["start"], r["end"]) for r in runs], [(4096,4120), (5000,5008)])

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

    def test_null_and_unknown_targets_remain_unresolved(self):
        self.assertEqual(b.target_owner(0,{})["status"], "null")
        self.assertEqual(b.target_owner(4096,{})["status"], "unresolved_target")

    def test_target_unique_or_ambiguous(self):
        maps={"a":[region()],"b":[region(8192,12288)]}
        self.assertEqual(b.target_owner(4096,maps),{"status":"unique_mapped_target","paths":["a"]})
        maps["b"]=[region()]
        self.assertEqual(b.target_owner(4096,maps)["status"],"unresolved_target")


if __name__ == "__main__": unittest.main()
