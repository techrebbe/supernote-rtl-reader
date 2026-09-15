"""Focused mutation tests for one generated SavedInkReader device artifact."""
from __future__ import annotations

import argparse
import errno
import hashlib
import importlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import struct
import sys
import tempfile
import unittest
from unittest import mock
import warnings
import zipfile
import zlib


HERE = Path(__file__).resolve().parent


def _load_artifact_module():
    """Use the enclosing authenticated capture, with a standalone fallback."""
    current_loader = getattr(globals().get("__spec__"), "loader", None)
    authority = getattr(current_loader, "authority_sha256", None)
    expected_source = (HERE / "saved_ink_reader_artifact.py").resolve(strict=True)
    if authority is None:
        spec = importlib.util.spec_from_file_location(
            "saved_ink_reader_artifact_under_test", expected_source)
        if spec is None or spec.loader is None:
            raise AssertionError("artifact test module loader is unavailable")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    matches = []
    for finder in sys.meta_path:
        if getattr(finder, "authority_sha256", None) != authority:
            continue
        captured = getattr(finder, "sources", {}).get(
            "saved_ink_reader_artifact")
        if captured is not None:
            matches.append((finder, captured))
    if len(matches) != 1:
        raise AssertionError("authenticated artifact source is unavailable")
    finder, captured = matches[0]
    if type(captured) is not tuple or len(captured) not in (2, 3):
        raise AssertionError("authenticated artifact source record is invalid")
    source, raw = captured[:2]
    is_package = captured[2] if len(captured) == 3 else False
    if (is_package or Path(source).resolve(strict=True) != expected_source or
            type(raw) is not bytes):
        raise AssertionError("authenticated artifact source is invalid")
    module = importlib.import_module("saved_ink_reader_artifact")
    loader = getattr(getattr(module, "__spec__", None), "loader", None)
    if (type(loader) is not type(current_loader) or
            getattr(loader, "authority_sha256", None) != authority or
            getattr(loader, "source", None) != source or
            getattr(loader, "raw", None) is not raw or
            Path(module.__file__).resolve(strict=True) != expected_source or
            Path(module.__spec__.origin).resolve(strict=True) != expected_source or
            sys.modules.get("saved_ink_reader_artifact") is not module or
            getattr(finder, "sources", {}).get(
                "saved_ink_reader_artifact") is not captured):
        raise AssertionError("artifact escaped authenticated source snapshot")
    return module


artifact = _load_artifact_module()

EXPECTED_ARTIFACT_SHA256 = "fe0d42d26a8f2a21ee0a14cb88f0f57bee8cd98d5e3abfeaf8e75da4391e09b2"
EXPECTED_DEX_SHA256 = "ede82ef546ac99cc0a4489fb1b78909ecd3f5d440ff34322cb0cf5677034c097"
EXPECTED_AUTHORITY_SHA256 = "c6d449a492d8b4f99c79608a80be01d3de14ec6f98ad1ca39a3c0b8e9381586c"


def repair_dex(raw: bytes) -> bytes:
    value = bytearray(raw)
    value[12:32] = hashlib.sha1(value[32:]).digest()
    struct.pack_into("<I", value, 8, zlib.adler32(value[12:]) & 0xffffffff)
    return bytes(value)


def mutate_map_type(raw: bytes, before: int, after: int) -> bytes:
    value = bytearray(raw)
    map_offset = struct.unpack_from("<I", raw, 52)[0]
    map_count = struct.unpack_from("<I", raw, map_offset)[0]
    rows = [map_offset + 4 + index * 12 for index in range(map_count)]
    types = [struct.unpack_from("<H", raw, row)[0] for row in rows]
    if types.count(before) != 1 or after in types:
        raise AssertionError("unexpected DEX map inventory for mutation")
    struct.pack_into("<H", value, rows[types.index(before)], after)
    return repair_dex(bytes(value))


def replace_once(raw: bytes, before: bytes, after: bytes) -> bytes:
    if len(before) != len(after) or raw.count(before) != 1:
        raise AssertionError("mutation needle must occur exactly once at equal length")
    return raw.replace(before, after, 1)


def mutate_main_method_name(raw: bytes, *, remove: bool) -> bytes:
    value = bytearray(raw)
    string_count, string_off = struct.unpack_from("<II", raw, 56)
    type_count, type_off = struct.unpack_from("<II", raw, 64)
    method_count, method_off = struct.unpack_from("<II", raw, 88)
    class_count, class_off = struct.unpack_from("<II", raw, 96)
    strings = []
    for index in range(string_count):
        offset = struct.unpack_from("<I", raw, string_off + index * 4)[0]
        text, _ = artifact._mutf8(raw, offset)
        strings.append(text)
    types = [strings[struct.unpack_from("<I", raw, type_off + index * 4)[0]]
             for index in range(type_count)]
    main_descriptor = "L" + artifact.MAIN_CLASS.replace(".", "/") + ";"
    main_class_index = types.index(main_descriptor)
    main_string_index = strings.index("main")
    method_rows = []
    for index in range(method_count):
        at = method_off + index * 8
        class_index, _, name_index = struct.unpack_from("<HHI", raw, at)
        method_rows.append((class_index, name_index))
    class_data_offset = None
    for index in range(class_count):
        at = class_off + index * 32
        class_index, data_offset = struct.unpack_from("<I20xI", raw, at)
        if class_index == main_class_index:
            class_data_offset = data_offset
            break
    if not class_data_offset:
        raise AssertionError("main class data missing")
    at = class_data_offset
    static_fields, at = artifact._uleb(raw, at)
    instance_fields, at = artifact._uleb(raw, at)
    direct_count, at = artifact._uleb(raw, at)
    virtual_count, at = artifact._uleb(raw, at)
    at = artifact._skip_encoded_fields(raw, at, static_fields)
    at = artifact._skip_encoded_fields(raw, at, instance_fields)
    direct, at = artifact._encoded_methods(raw, at, direct_count)
    virtual, at = artifact._encoded_methods(raw, at, virtual_count)
    definitions = [item[0] for item in direct + virtual]
    current_main = [index for index in definitions
                    if method_rows[index][1] == main_string_index]
    if len(current_main) != 1:
        raise AssertionError("expected one current main definition")
    if remove:
        target = current_main[0]
        replacement = next(index for index, text in enumerate(strings)
                           if text not in ("main", "<init>", "<clinit>"))
    else:
        target = next(index for index in definitions
                      if method_rows[index][1] != main_string_index and
                      strings[method_rows[index][1]] not in ("<init>", "<clinit>"))
        replacement = main_string_index
    struct.pack_into("<I", value, method_off + target * 8 + 4, replacement)
    return repair_dex(bytes(value))


def archive_payloads(path: Path) -> dict[str, bytes]:
    with zipfile.ZipFile(path, "r") as opened:
        return {item.filename: opened.read(item) for item in opened.infolist()}


def write_zip(path: Path, ordered, *, timestamp=artifact.CANONICAL_TIMESTAMP,
              compression=zipfile.ZIP_STORED, duplicate=None, comment=b"",
              extra=b"", external_attr=artifact.CANONICAL_EXTERNAL_ATTR) -> None:
    with zipfile.ZipFile(path, "w", compression=compression,
                         allowZip64=False) as opened:
        for name, payload in ordered:
            info = zipfile.ZipInfo(name, timestamp)
            info.compress_type = compression
            info.create_system = 0
            info.external_attr = external_attr
            info.extra = extra
            info.flag_bits = 0
            opened.writestr(info, payload)
        if duplicate is not None:
            info = zipfile.ZipInfo(duplicate[0], timestamp)
            info.compress_type = compression
            info.create_system = 0
            info.external_attr = artifact.CANONICAL_EXTERNAL_ATTR
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                opened.writestr(info, duplicate[1])
        opened.comment = comment


class GeneratedArtifactTests(unittest.TestCase):
    artifact_path: Path
    repeat_path: Path
    provenance_path: Path
    build_script_path: Path
    tests_path: Path

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="saved-ink-artifact-test-")
        self.temp = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def expect_invalid(self, action, pattern=None):
        with self.assertRaises(artifact.ArtifactError) as raised:
            action()
        if pattern is not None:
            self.assertIn(pattern, str(raised.exception))

    def test_generated_artifact_and_provenance_are_exact(self):
        first = artifact.verify_final_artifact(
            self.artifact_path, EXPECTED_ARTIFACT_SHA256,
            EXPECTED_DEX_SHA256, EXPECTED_AUTHORITY_SHA256)
        second = artifact.verify_final_artifact(
            self.repeat_path, EXPECTED_ARTIFACT_SHA256,
            EXPECTED_DEX_SHA256, EXPECTED_AUTHORITY_SHA256)
        self.assertEqual(first, second)
        self.assertEqual(self.artifact_path.read_bytes(), self.repeat_path.read_bytes())
        authority = artifact.verify_provenance(
            self.artifact_path, self.repeat_path, self.provenance_path,
            self.build_script_path, self.tests_path)
        self.assertTrue(authority["twoCleanBuildsByteIdentical"])
        self.assertEqual(first["entries"], list(artifact.EXPECTED_JAR_ENTRIES))
        self.assertEqual(len(first["dex"]["classDescriptors"]), 14)
        self.assertEqual(first["dex"]["stringTable"], {
            "count": artifact.EXPECTED_DEX_STRING_COUNT,
            "sha256": artifact.EXPECTED_DEX_STRING_SHA256,
        })
        dex = archive_payloads(self.artifact_path)["classes.dex"]
        map_offset = struct.unpack_from("<I", dex, 52)[0]
        map_count = struct.unpack_from("<I", dex, map_offset)[0]
        map_types = {
            struct.unpack_from("<H", dex, map_offset + 4 + index * 12)[0]
            for index in range(map_count)
        }
        self.assertFalse(map_types & {0x0007, 0x0008})

    def test_dex_checksum_and_signature_mutations_fail(self):
        dex = archive_payloads(self.artifact_path)["classes.dex"]
        changed = bytearray(dex)
        changed[-1] ^= 1
        self.expect_invalid(lambda: artifact.verify_dex(bytes(changed)), "signature")
        changed = bytearray(dex)
        changed[8] ^= 1
        self.expect_invalid(lambda: artifact.verify_dex(bytes(changed)), "Adler")
        for forbidden in (0x0007, 0x0008):
            with self.subTest(forbidden=hex(forbidden)):
                dynamic = mutate_map_type(dex, 0x2003, forbidden)
                self.expect_invalid(
                    lambda dynamic=dynamic: artifact.verify_dex(dynamic),
                    "dynamic invocation bootstrap")

    def test_stale_schema_main_and_class_mutations_fail_after_repair(self):
        dex = archive_payloads(self.artifact_path)["classes.dex"]
        stale = repair_dex(replace_once(
            dex, b"native-viewport-ink-evidence-v2",
            b"native-viewport-ink-evidence-v1"))
        self.expect_invalid(lambda: artifact.verify_dex(stale), "string-table")
        no_main = mutate_main_method_name(dex, remove=True)
        self.expect_invalid(lambda: artifact.verify_dex(no_main), "entrypoint inventory")
        extra_main = mutate_main_method_name(dex, remove=False)
        self.expect_invalid(lambda: artifact.verify_dex(extra_main), "entrypoint inventory")
        old = b"SavedInkReader$CanonicalArray;"
        changed = b"SavedInkReader$CanonicalArraz;"
        bad_class = repair_dex(replace_once(dex, old, changed))
        self.expect_invalid(lambda: artifact.verify_dex(bad_class), "class definitions")

    def test_archive_wire_mutations_fail(self):
        payloads = archive_payloads(self.artifact_path)
        canonical = [(name, payloads[name]) for name in artifact.EXPECTED_JAR_ENTRIES]
        mutations = []
        extra = self.temp / "extra.jar"
        write_zip(extra, canonical + [("unexpected.bin", b"x")])
        mutations.append(extra)
        duplicate = self.temp / "duplicate.jar"
        write_zip(duplicate, canonical,
                  duplicate=(artifact.EXPECTED_JAR_ENTRIES[0], artifact.MANIFEST))
        mutations.append(duplicate)
        reordered = self.temp / "reordered.jar"
        write_zip(reordered, list(reversed(canonical)))
        mutations.append(reordered)
        bad_time = self.temp / "time.jar"
        write_zip(bad_time, canonical, timestamp=(2026, 9, 10, 1, 2, 4))
        mutations.append(bad_time)
        compressed = self.temp / "compressed.jar"
        write_zip(compressed, canonical, compression=zipfile.ZIP_DEFLATED)
        mutations.append(compressed)
        trailing = self.temp / "trailing.jar"
        trailing.write_bytes(self.artifact_path.read_bytes() + b"trailing")
        mutations.append(trailing)
        comment = self.temp / "comment.jar"
        write_zip(comment, canonical, comment=b"comment")
        mutations.append(comment)
        extra_field = self.temp / "extra-field.jar"
        write_zip(extra_field, canonical, extra=b"\x01\x00\x00\x00")
        mutations.append(extra_field)
        attributes = self.temp / "attributes.jar"
        write_zip(attributes, canonical,
                  external_attr=artifact.CANONICAL_EXTERNAL_ATTR | 1)
        mutations.append(attributes)
        for path in mutations:
            with self.subTest(path=path.name):
                self.expect_invalid(lambda path=path: artifact.verify_artifact(path))

    def test_zip_reader_uses_only_retained_bytes(self):
        retained = self.artifact_path.read_bytes()
        replaced_name = self.temp / "replaced.jar"
        replaced_name.write_bytes(b"not a zip")
        with mock.patch.object(artifact, "_read_regular", return_value=retained):
            raw, payloads = artifact._read_zip(replaced_name)
        self.assertEqual(raw, retained)
        self.assertEqual(tuple(payloads), artifact.EXPECTED_JAR_ENTRIES)

    def test_atomic_publication_is_no_replace_and_evidence_preserving(self):
        normal = self.temp / "normal.zip"
        artifact._write_zip(normal, {"one": b"1"})
        self.assertTrue(normal.is_file())
        self.assertEqual(list(self.temp.glob(normal.name + ".*.tmp")), [])

        collision = self.temp / "collision.zip"
        def collide(source, destination):
            Path(destination).write_bytes(b"rival")
            raise FileExistsError(errno.EEXIST, "forced collision")
        with mock.patch.object(artifact.os, "link", side_effect=collide):
            self.expect_invalid(
                lambda: artifact._write_zip(collision, {"one": b"1"}),
                "refusing to replace")
        self.assertEqual(collision.read_bytes(), b"rival")
        self.assertEqual(list(self.temp.glob(collision.name + ".*.tmp")), [])

        uncertain = self.temp / "uncertain.zip"
        with mock.patch.object(
                artifact.os, "link", side_effect=OSError(errno.EIO, "forced")):
            self.expect_invalid(
                lambda: artifact._write_zip(uncertain, {"one": b"1"}),
                "retained staged evidence")
        self.assertFalse(uncertain.exists())
        self.assertEqual(len(list(self.temp.glob(uncertain.name + ".*.tmp"))), 1)

    def test_embedded_authority_mutations_fail(self):
        payloads = archive_payloads(self.artifact_path)
        value = json.loads(
            payloads["META-INF/native-viewport-saved-ink-reader.json"].decode("ascii"))
        cases = []
        source = json.loads(json.dumps(value))
        source["source"]["sha256"] = "0" * 64
        cases.append((source, None))
        tool = json.loads(json.dumps(value))
        tool["tools"]["d8Jar"]["bytes"] += 1
        cases.append((tool, None))
        dex = json.loads(json.dumps(value))
        dex["dex"]["sha256"] = "f" * 64
        cases.append((dex, None))
        scalar_float = json.loads(json.dumps(value))
        scalar_float["compileSdk"] = float(scalar_float["compileSdk"])
        cases.append((scalar_float, "floating-point"))
        nested_float = json.loads(json.dumps(value))
        nested_float["dex"]["bytes"] = float(nested_float["dex"]["bytes"])
        cases.append((nested_float, "floating-point"))
        unknown = json.loads(json.dumps(value))
        unknown["unknown"] = True
        cases.append((unknown, None))
        for index, (changed, pattern) in enumerate(cases):
            path = self.temp / f"authority-{index}.jar"
            modified = dict(payloads)
            modified["META-INF/native-viewport-saved-ink-reader.json"] = \
                artifact._canonical_json(changed)
            artifact._write_zip(path, modified)
            with self.subTest(index=index):
                self.expect_invalid(
                    lambda path=path: artifact.verify_artifact(path), pattern)

    def test_noncanonical_and_duplicate_authority_json_fail(self):
        payloads = archive_payloads(self.artifact_path)
        authority_name = "META-INF/native-viewport-saved-ink-reader.json"
        pretty = self.temp / "pretty.jar"
        changed = dict(payloads)
        changed[authority_name] = json.dumps(json.loads(
            payloads[authority_name]), indent=2).encode("ascii")
        artifact._write_zip(pretty, changed)
        self.expect_invalid(lambda: artifact.verify_artifact(pretty), "canonical")

        duplicate = self.temp / "duplicate-authority.jar"
        original = payloads[authority_name]
        changed = dict(payloads)
        changed[authority_name] = b'{"artifactSchema":"x",' + original[1:]
        artifact._write_zip(duplicate, changed)
        self.expect_invalid(lambda: artifact.verify_artifact(duplicate), "duplicate")

    def test_exact_string_table_and_final_hash_authority_reject_alternates(self):
        payloads = archive_payloads(self.artifact_path)
        original = payloads["classes.dex"]
        changed_dex = repair_dex(replace_once(
            original,
            b"this diagnostic is limited to the A6X2 Nomad\x00",
            b"this diagnostic is limited to the A6X2 Nomas\x00"))
        self.expect_invalid(lambda: artifact.verify_dex(changed_dex), "string-table")
        self.expect_invalid(lambda: artifact.verify_final_artifact(
            self.artifact_path, "0" * 64,
            EXPECTED_DEX_SHA256, EXPECTED_AUTHORITY_SHA256), "final authority")

    def test_provenance_mutation_and_nonidentical_repeat_fail(self):
        changed = bytearray(self.provenance_path.read_bytes())
        changed[changed.index(b"true")] = ord("f")
        bad = self.temp / "bad-provenance.json"
        bad.write_bytes(bytes(changed))
        self.expect_invalid(lambda: artifact.verify_provenance(
            self.artifact_path, self.repeat_path, bad,
            self.build_script_path, self.tests_path))

        payloads = archive_payloads(self.repeat_path)
        dex = bytearray(payloads["classes.dex"])
        dex[-1] ^= 1
        payloads["classes.dex"] = bytes(dex)
        other = self.temp / "different.jar"
        artifact._write_zip(other, payloads)
        self.expect_invalid(lambda: artifact.verify_provenance(
            self.artifact_path, other, self.provenance_path,
            self.build_script_path, self.tests_path))

        provenance = json.loads(self.provenance_path.read_text(encoding="ascii"))
        for label, keys in (
                ("artifact-bytes-float", ("artifact", "bytes")),
                ("dex-bytes-float", ("dex", "bytes"))):
            numeric = json.loads(json.dumps(provenance))
            owner, field = keys
            numeric[owner][field] = float(numeric[owner][field])
            path = self.temp / f"{label}.json"
            path.write_bytes(artifact._canonical_json(numeric) + b"\n")
            with self.subTest(label=label):
                self.expect_invalid(lambda path=path: artifact.verify_provenance(
                    self.artifact_path, self.repeat_path, path,
                    self.build_script_path, self.tests_path), "floating-point")

    def test_clean_build_outputs_must_have_distinct_file_identities(self):
        copied = self.temp / "copy.jar"
        linked = self.temp / "hardlink.jar"
        shutil.copyfile(self.artifact_path, copied)
        os.link(copied, linked)
        self.expect_invalid(lambda: artifact.write_provenance(
            copied, linked, self.temp / "same-provenance.json",
            self.build_script_path, self.tests_path), "distinct regular file identities")

    def test_provenance_binds_exact_reviewed_test_source(self):
        changed_tests = self.temp / "changed-tests.py"
        changed_tests.write_bytes(self.tests_path.read_bytes() + b"\n")
        self.expect_invalid(lambda: artifact.verify_provenance(
            self.artifact_path, self.repeat_path, self.provenance_path,
            self.build_script_path, changed_tests), "provenance")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", required=True, type=Path)
    parser.add_argument("--repeat", required=True, type=Path)
    parser.add_argument("--provenance", required=True, type=Path)
    parser.add_argument("--build-script", required=True, type=Path)
    args = parser.parse_args()
    GeneratedArtifactTests.artifact_path = args.artifact.absolute()
    GeneratedArtifactTests.repeat_path = args.repeat.absolute()
    GeneratedArtifactTests.provenance_path = args.provenance.absolute()
    GeneratedArtifactTests.build_script_path = args.build_script.absolute()
    GeneratedArtifactTests.tests_path = Path(__file__).absolute()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(GeneratedArtifactTests)
    details = io.StringIO()
    result = unittest.TextTestRunner(stream=details, verbosity=2).run(suite)
    if (not result.wasSuccessful() or result.testsRun != 12 or
            result.skipped or result.expectedFailures or
            result.unexpectedSuccesses):
        print("SAVED_INK_READER_ARTIFACT_TESTS_FAILED tests=12")
        return 1
    print("SAVED_INK_READER_ARTIFACT_TESTS_PASS tests=12")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
