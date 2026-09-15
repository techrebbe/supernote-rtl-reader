from __future__ import annotations

import hashlib
import os
from pathlib import Path
import tempfile
import unittest

import native_page_windows_tool_authority as tool


@unittest.skipUnless(os.name == "nt", "Windows retained-handle test")
class LockedAdbBundleTests(unittest.TestCase):
    def make_bundle(self, root: Path) -> dict[str, str]:
        values = {
            "adb.exe": b"fake-adb-executable\x00authority",
            "AdbWinApi.dll": b"fake-api-dll\x00authority",
            "AdbWinUsbApi.dll": b"fake-usb-dll\x00authority",
        }
        for name, raw in values.items():
            (root / name).write_bytes(raw)
        return {name: hashlib.sha256(raw).hexdigest()
                for name, raw in values.items()}

    def test_bundle_retains_exact_bytes_and_canonical_authority(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            expected = self.make_bundle(root)
            with tool.LockedAdbBundle(root, expected) as bundle:
                values = bundle.authorities()
                self.assertEqual(set(values), set(tool.FILENAMES))
                self.assertEqual(values["adb.exe"].sha256, expected["adb.exe"])
                self.assertIn(tool.AUTHORITY.encode(), bundle.canonical_bytes())
                bundle.verify()

    def test_retained_files_and_directory_deny_mutation_and_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "bundle"
            root.mkdir()
            expected = self.make_bundle(root)
            bundle = tool.LockedAdbBundle(root, expected).open()
            try:
                with self.assertRaises(OSError):
                    with open(root / "adb.exe", "r+b") as stream:
                        stream.write(b"x")
                replacement = Path(directory) / "replacement.bin"
                replacement.write_bytes(b"replacement")
                with self.assertRaises(OSError):
                    os.replace(replacement, root / "adb.exe")
                with self.assertRaises(OSError):
                    root.rename(Path(directory) / "renamed")
                bundle.verify()
            finally:
                bundle.close()
            (root / "adb.exe").write_bytes(b"mutation-after-close")
            self.assertEqual((root / "adb.exe").read_bytes(), b"mutation-after-close")

    def test_digest_mismatch_missing_file_and_directory_member_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            expected = self.make_bundle(root)
            wrong = dict(expected)
            wrong["adb.exe"] = "0" * 64
            with self.assertRaises(tool.ToolAuthorityError):
                tool.LockedAdbBundle(root, wrong).open()
            (root / "AdbWinApi.dll").unlink()
            with self.assertRaises(tool.ToolAuthorityError):
                tool.LockedAdbBundle(root, expected).open()
            (root / "AdbWinApi.dll").mkdir()
            with self.assertRaises(tool.ToolAuthorityError):
                tool.LockedAdbBundle(root, expected).open()

    def test_invalid_digest_map_and_lifecycle_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_bundle(root)
            for invalid in ({"other": "0" * 64}, {"adb.exe": "xyz"}, {}, None,
                            [("adb.exe", "0" * 64)]):
                with self.assertRaises(tool.ToolAuthorityError):
                    tool.LockedAdbBundle(root, invalid)  # type: ignore[arg-type]
            expected = {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
                        for name in tool.FILENAMES}
            bundle = tool.LockedAdbBundle(root, expected).open()
            with self.assertRaises(tool.ToolAuthorityError):
                bundle.open()
            bundle.close()
            with self.assertRaises(tool.ToolAuthorityError):
                bundle.verify()
            with self.assertRaises(tool.ToolAuthorityError):
                bundle.open()

    def test_absolute_authority_survives_working_directory_change(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "bundle"
            root.mkdir()
            expected = self.make_bundle(root)
            bundle = tool.LockedAdbBundle(root, expected).open()
            original = Path.cwd()
            try:
                os.chdir(Path(directory))
                bundle.verify()
                self.assertEqual(Path(bundle.executable), root / "adb.exe")
            finally:
                os.chdir(original)
                bundle.close()

    def test_reparse_member_is_rejected_when_symlink_creation_is_available(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "bundle"
            root.mkdir()
            expected = self.make_bundle(root)
            target = Path(directory) / "target.bin"
            target.write_bytes(b"target")
            (root / "AdbWinApi.dll").unlink()
            try:
                (root / "AdbWinApi.dll").symlink_to(target)
            except OSError:
                self.skipTest("Windows symlink creation is not available")
            with self.assertRaises(tool.ToolAuthorityError):
                tool.LockedAdbBundle(root, expected).open()

    def test_hard_linked_member_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "bundle"
            root.mkdir()
            expected = self.make_bundle(root)
            alternate = Path(directory) / "adb-hardlink.exe"
            try:
                os.link(root / "adb.exe", alternate)
            except OSError:
                self.skipTest("Windows hard-link creation is not available")
            with self.assertRaises(tool.ToolAuthorityError):
                tool.LockedAdbBundle(root, expected).open()


if __name__ == "__main__":
    unittest.main()
