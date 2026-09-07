"""Memory read-plan and classification tests; no ADB or live memory access."""
import unittest
import inspect_loader_bindings as b
import inspect_loader_dependencies as d


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


class BindingTests(unittest.TestCase):
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
