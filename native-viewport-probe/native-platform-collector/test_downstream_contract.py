"""Focused host check against two exact frozen NPPCAP01 parser sources."""
from __future__ import annotations

import hashlib
import os
import pathlib
import re
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from collections.abc import Callable
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

HEX = re.compile(r"[0-9a-f]{64}\Z")
CONTRACT_DOMAIN = b"NATIVE_PAGE_PLATFORM_COLLECTOR_DOWNSTREAM_CONTRACT_V1\n"
BACKEND_RECORD = b"native_page_private_adb_platform_backend.py="
PLATFORM_RECORD = b"native_page_visual_platform_authority.py="

CORE_TEST_EXE = ""
BACKEND_PATH = pathlib.Path()
PLATFORM_PATH = pathlib.Path()
BACKEND_SHA256 = ""
PLATFORM_SHA256 = ""
DOWNSTREAM_CONTRACT_SHA256 = ""
backend: types.ModuleType
platform: types.ModuleType


class DownstreamSourceAuthorityError(RuntimeError):
    """A frozen downstream source was not the exact admitted ordinary file."""


def _contract_digest(backend_sha256: str, platform_sha256: str) -> str:
    if HEX.fullmatch(backend_sha256) is None or HEX.fullmatch(platform_sha256) is None:
        raise DownstreamSourceAuthorityError("downstream source digest is malformed")
    canonical = (
        CONTRACT_DOMAIN
        + BACKEND_RECORD + backend_sha256.encode("ascii") + b"\n"
        + PLATFORM_RECORD + platform_sha256.encode("ascii") + b"\n"
        + b"END\n"
    )
    return hashlib.sha256(canonical).hexdigest()


def _ordinary_fingerprint(path: pathlib.Path) -> tuple[int, int, int, int, int]:
    try:
        metadata = os.lstat(path)
    except OSError as error:
        raise DownstreamSourceAuthorityError(
            "downstream source cannot be stated") from error
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        raise DownstreamSourceAuthorityError(
            "downstream source is not an ordinary non-reparse file")
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _read_authoritative_source(
    path: pathlib.Path,
    expected_sha256: str,
    after_first_read: Callable[[], None] | None = None,
) -> bytes:
    path = pathlib.Path(path)
    if not path.is_absolute() or HEX.fullmatch(expected_sha256) is None:
        raise DownstreamSourceAuthorityError(
            "downstream source authority arguments are malformed")
    before = _ordinary_fingerprint(path)
    try:
        first = path.read_bytes()
    except OSError as error:
        raise DownstreamSourceAuthorityError(
            "downstream source cannot be read") from error
    if hashlib.sha256(first).hexdigest() != expected_sha256:
        raise DownstreamSourceAuthorityError(
            "downstream source digest does not match admission")
    if after_first_read is not None:
        after_first_read()
    after = _ordinary_fingerprint(path)
    try:
        second = path.read_bytes()
    except OSError as error:
        raise DownstreamSourceAuthorityError(
            "downstream source cannot be re-read") from error
    if (before != after or second != first or
            hashlib.sha256(second).hexdigest() != expected_sha256):
        raise DownstreamSourceAuthorityError(
            "downstream source drifted during authority read")
    return first


def _load_exact_module(name: str, path: pathlib.Path, source: bytes) -> types.ModuleType:
    module = types.ModuleType(name)
    module.__file__ = str(path)
    module.__package__ = ""
    previous = sys.modules.get(name)
    sys.modules[name] = module
    try:
        code = compile(source, str(path), "exec", dont_inherit=True)
        exec(code, module.__dict__)  # noqa: S102 - exact admitted bytes are the subject.
    except BaseException:
        if previous is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = previous
        raise
    return module


class DownstreamContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.wire = subprocess.run(
            [CORE_TEST_EXE, "--emit-wire"], check=True, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).stdout

    def test_exact_frozen_parsers_accept_all_members(self) -> None:
        activity, window, process, display = backend.decode_collector_wire(
            self.wire)
        facts = backend._parse_process_facts(process)
        activity_value = platform._parse_activity_manager(activity, facts.processes)
        window_value = platform._parse_window_manager(window, facts.processes)
        display_value = platform._parse_display_inventory(display, facts.processes)
        self.assertEqual(activity_value.display_ids, (0, 5))
        self.assertEqual(len(activity_value.activities), 2)
        self.assertEqual(len(window_value.items), 2)
        self.assertEqual(len(window_value.focused), 2)
        self.assertEqual(len(display_value.displays), 2)
        self.assertEqual(facts.serial, "SN078C10015092")

    def test_each_wire_region_is_digest_bound(self) -> None:
        for index in (0, 8, 13, len(self.wire) // 2, len(self.wire) - 1):
            changed = bytearray(self.wire)
            changed[index] ^= 1
            with self.assertRaises(backend.PrivateAdbPlatformBackendError):
                backend.decode_collector_wire(bytes(changed))

    def test_contract_digest_binds_exact_ordered_module_hashes(self) -> None:
        self.assertEqual(
            _contract_digest(BACKEND_SHA256, PLATFORM_SHA256),
            DOWNSTREAM_CONTRACT_SHA256,
        )
        self.assertNotEqual(
            _contract_digest(PLATFORM_SHA256, BACKEND_SHA256),
            DOWNSTREAM_CONTRACT_SHA256,
        )

    def test_hash_mutation_is_rejected(self) -> None:
        wrong = "0" * 64 if BACKEND_SHA256 != "0" * 64 else "1" * 64
        with self.assertRaisesRegex(
                DownstreamSourceAuthorityError, "digest does not match"):
            _read_authoritative_source(BACKEND_PATH, wrong)

    def test_mid_read_content_drift_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "authority.py"
            original = b"VALUE = 1\n"
            path.write_bytes(original)
            expected = hashlib.sha256(original).hexdigest()
            with self.assertRaisesRegex(
                    DownstreamSourceAuthorityError, "drifted"):
                _read_authoritative_source(
                    path, expected, lambda: path.write_bytes(b"VALUE = 2\n"))

    def test_mid_read_path_replacement_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "authority.py"
            replacement = pathlib.Path(directory) / "replacement.py"
            original = b"VALUE = 1\n"
            path.write_bytes(original)
            replacement.write_bytes(original)
            expected = hashlib.sha256(original).hexdigest()
            with self.assertRaisesRegex(
                    DownstreamSourceAuthorityError, "drifted"):
                _read_authoritative_source(
                    path, expected, lambda: os.replace(replacement, path))

    def test_reparse_source_is_rejected(self) -> None:
        with mock.patch.object(pathlib.Path, "is_symlink", return_value=True):
            with self.assertRaisesRegex(
                    DownstreamSourceAuthorityError, "ordinary non-reparse"):
                _read_authoritative_source(BACKEND_PATH, BACKEND_SHA256)


def main(arguments: list[str]) -> None:
    if len(arguments) != 7:
        raise SystemExit(
            "usage: test_downstream_contract.py CORE_TEST_EXE BACKEND_PATH "
            "PLATFORM_PATH BACKEND_SHA256 PLATFORM_SHA256 CONTRACT_SHA256")
    global CORE_TEST_EXE, BACKEND_PATH, PLATFORM_PATH
    global BACKEND_SHA256, PLATFORM_SHA256
    global DOWNSTREAM_CONTRACT_SHA256, backend, platform
    CORE_TEST_EXE = str(pathlib.Path(arguments[1]).resolve(strict=True))
    BACKEND_PATH = pathlib.Path(arguments[2])
    PLATFORM_PATH = pathlib.Path(arguments[3])
    BACKEND_SHA256 = arguments[4]
    PLATFORM_SHA256 = arguments[5]
    DOWNSTREAM_CONTRACT_SHA256 = arguments[6]
    if (HEX.fullmatch(DOWNSTREAM_CONTRACT_SHA256) is None or
            _contract_digest(BACKEND_SHA256, PLATFORM_SHA256)
            != DOWNSTREAM_CONTRACT_SHA256):
        raise DownstreamSourceAuthorityError(
            "downstream contract digest does not match exact module identities")
    platform_source = _read_authoritative_source(
        PLATFORM_PATH, PLATFORM_SHA256)
    backend_source = _read_authoritative_source(BACKEND_PATH, BACKEND_SHA256)
    platform = _load_exact_module(
        "native_page_visual_platform_authority", PLATFORM_PATH, platform_source)
    backend = _load_exact_module(
        "native_page_private_adb_platform_backend", BACKEND_PATH, backend_source)
    unittest.main(argv=[arguments[0]])


if __name__ == "__main__":
    main(sys.argv)
