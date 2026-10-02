#!/usr/bin/env python3
"""Small disposable-fixture safety gate; no native geometry/handwriting claim.

All generated PDFs and opaque source/sidecar sentinels stay in owned temporary
directories. This test never opens a device or modifies repository documents.
"""

from pathlib import Path
import errno
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

# Keep test imports from producing repository-local __pycache__ files.
sys.dont_write_bytecode = True

from pypdf import PdfReader
import build_saved_ink_geometry_fixture as builder


BUILDER = Path(__file__).with_name("build_saved_ink_geometry_fixture.py")
STATUS = "fixture-only; no native-geometry or handwriting pass"
SENTINEL = b"Owned test sentinel, not native handwriting or user material.\n"


def snapshot(path: Path) -> tuple[bytes, int, int]:
    stat = path.stat()
    return path.read_bytes(), stat.st_size, stat.st_mtime_ns


def run_cli(output: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(BUILDER), str(output)],
        capture_output=True, text=True, timeout=30,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )


class FixtureTests(unittest.TestCase):
    def test_cli_metadata_agrees_with_actual_unannotated_pdf(self):
        with tempfile.TemporaryDirectory(prefix="rtl-geometry-metadata-") as folder:
            output = Path(folder) / "new" / "fixture.pdf"
            result = run_cli(output)
            self.assertEqual(result.returncode, 0, result.stderr)
            metadata = json.loads(result.stdout)
            self.assertEqual(metadata, {
                "sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
                "pageCount": 2, "mediaBox": [0, 0, 612, 792],
                "cropBox": [0, 0, 612, 792], "rotation": 0, "userUnit": 1,
                "annotations": 0, "nativeCanvas": [1404, 1872], "status": STATUS,
            })
            reader = PdfReader(output)
            self.assertFalse(reader.is_encrypted)
            self.assertEqual(len(reader.pages), 2)
            self.assertFalse(reader.get_fields())
            for number, page in enumerate(reader.pages, 1):
                with self.subTest(page=number):
                    self.assertEqual(list(page.mediabox), metadata["mediaBox"])
                    self.assertEqual(list(page.cropbox), metadata["cropBox"])
                    self.assertEqual(page.rotation, metadata["rotation"])
                    self.assertEqual(page.get("/UserUnit", 1), metadata["userUnit"])
                    self.assertFalse(page.get("/Annots"))
                    self.assertIn(f"PAGE {number}", page.extract_text())
            self.assertNotEqual(612 * 1872, 792 * 1404,
                                "The PDF must differ from the native 3:4 canvas")
            self.assertEqual(list(output.parent.iterdir()), [output])
            self.assertFalse(Path(str(output) + ".mark").exists())

    def test_generation_is_byte_reproducible_across_new_paths(self):
        with tempfile.TemporaryDirectory(prefix="rtl-geometry-repeat-") as folder:
            root = Path(folder)
            first = root / "first" / "one.pdf"
            second = root / "different" / "two.pdf"
            first_metadata = builder.create(first)
            second_metadata = builder.create(second)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(first_metadata, second_metadata)
            self.assertEqual(first_metadata["sha256"], hashlib.sha256(first.read_bytes()).hexdigest())

    def test_existing_output_refusal_preserves_files_and_directories(self):
        with tempfile.TemporaryDirectory(prefix="rtl-geometry-existing-") as folder:
            root = Path(folder)
            output = root / "existing.pdf"
            builder.create(output)
            before = snapshot(output)
            with self.assertRaisesRegex(ValueError, "Refusing to overwrite"):
                builder.create(output)
            self.assertEqual(snapshot(output), before)
            result = run_cli(output)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Refusing to overwrite", result.stderr)
            self.assertEqual(result.stdout, "")
            self.assertEqual(snapshot(output), before)
            directory = root / "existing-directory.pdf"
            directory.mkdir()
            child = directory / "preserved.txt"
            child.write_bytes(SENTINEL)
            child_before = snapshot(child)
            with self.assertRaisesRegex(ValueError, "Refusing to overwrite"):
                builder.create(directory)
            self.assertTrue(directory.is_dir())
            self.assertEqual(snapshot(child), child_before)
            self.assertEqual(list(directory.iterdir()), [child])

    def test_destination_created_during_generation_is_never_overwritten(self):
        with tempfile.TemporaryDirectory(prefix="rtl-geometry-race-") as folder:
            output = Path(folder) / "fixture.pdf"
            original_save = builder.Canvas.save
            claimed = []

            def save_after_claim(canvas):
                with output.open("xb") as stream:
                    stream.write(SENTINEL)
                claimed.append(snapshot(output))
                return original_save(canvas)

            with patch.object(builder.Canvas, "save", save_after_claim):
                with self.assertRaises(FileExistsError):
                    builder.create(output)
            self.assertEqual(len(claimed), 1)
            self.assertEqual(snapshot(output), claimed[0])
            self.assertEqual(output.read_bytes(), SENTINEL)

    def test_source_pdf_and_sidecar_are_preserved_without_transplant(self):
        with tempfile.TemporaryDirectory(prefix="rtl-geometry-source-") as folder:
            root = Path(folder)
            source = root / "source.pdf"
            builder.create(source)
            sidecar = Path(str(source) + ".mark")
            sidecar.write_bytes(SENTINEL)  # Opaque preservation sentinel, not a native .mark.
            before = {path: snapshot(path) for path in (source, sidecar)}
            output = root / "new-fixture.pdf"
            builder.create(output)
            for path, prior in before.items():
                self.assertEqual(snapshot(path), prior)
            self.assertFalse(Path(str(output) + ".mark").exists())
            self.assertFalse(any(page.get("/Annots") for page in PdfReader(output).pages))
            self.assertEqual(set(root.iterdir()), {source, sidecar, output})

    def test_existing_or_newly_appearing_sidecar_is_preserved_and_refused(self):
        with tempfile.TemporaryDirectory(prefix="rtl-geometry-sidecar-") as folder:
            root = Path(folder)
            for concurrent in (False, True):
                with self.subTest(concurrent=concurrent):
                    output = root / ("concurrent.pdf" if concurrent else "existing.pdf")
                    sidecar = Path(str(output) + ".mark")
                    original_save = builder.Canvas.save
                    preserved = []

                    def save_after_sidecar(canvas):
                        sidecar.write_bytes(SENTINEL)
                        preserved.append(snapshot(sidecar))
                        return original_save(canvas)

                    if concurrent:
                        with patch.object(builder.Canvas, "save", save_after_sidecar):
                            with self.assertRaisesRegex(ValueError, "sidecar appeared"):
                                builder.create(output)
                    else:
                        sidecar.write_bytes(SENTINEL)
                        preserved.append(snapshot(sidecar))
                        with self.assertRaisesRegex(ValueError, "existing annotation sidecar"):
                            builder.create(output)
                    self.assertFalse(output.exists())
                    self.assertEqual(snapshot(sidecar), preserved[0])

    def test_existing_and_dangling_leaf_links_are_refused_when_supported(self):
        with tempfile.TemporaryDirectory(prefix="rtl-geometry-links-") as folder:
            root = Path(folder)
            for sidecar_link in (False, True):
                for dangling in (False, True):
                    with self.subTest(sidecar=sidecar_link, dangling=dangling):
                        label = f"link-{sidecar_link}-{dangling}"
                        output = root / f"{label}.pdf"
                        link = Path(str(output) + ".mark") if sidecar_link else output
                        target = root / f"{label}-target"
                        if not dangling:
                            target.write_bytes(SENTINEL)
                        before = snapshot(target) if target.exists() else None
                        try:
                            link.symlink_to(target)
                        except NotImplementedError:
                            self.skipTest("This platform does not support symbolic links")
                        except OSError as error:
                            if error.errno in (errno.EACCES, errno.EPERM) or getattr(error, "winerror", None) == 1314:
                                self.skipTest("Symbolic-link creation is not permitted on this host")
                            raise
                        with self.assertRaisesRegex(ValueError, "Refusing"):
                            builder.create(output)
                        result = run_cli(output)
                        self.assertNotEqual(result.returncode, 0)
                        self.assertIn("Refusing", result.stderr)
                        self.assertTrue(link.is_symlink())
                        if before is None:
                            self.assertFalse(target.exists())
                        else:
                            self.assertEqual(snapshot(target), before)
                        if sidecar_link:
                            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
