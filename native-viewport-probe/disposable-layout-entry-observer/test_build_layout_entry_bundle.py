"""Offline bundle input/pinning tests; never compiles or publishes a bundle."""
from __future__ import annotations

from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import build_layout_entry_bundle as subject


class BundleTests(unittest.TestCase):
    def test_installed_bridge_and_sources_are_exactly_pinned(self) -> None:
        subject.check_inputs()

    def test_source_change_blocks_builder(self) -> None:
        with patch.object(subject, "SOURCE_SHA256", "0" * 64):
            with self.assertRaisesRegex(subject.BundleError,
                                        "BUNDLE_SOURCE_CHANGED"):
                subject.check_inputs()

    def test_candidate_never_publishes(self) -> None:
        with patch.object(subject, "_build_bytes", return_value=b"candidate"):
            self.assertEqual(subject.candidate_digest(),
                {"sha256": subject.sha(b"candidate"), "bytes": 9,
                 "published": False})

    def test_unpinned_bundle_cannot_publish(self) -> None:
        with patch.object(subject, "BUNDLE_SHA256", None), \
             patch.object(subject, "_build_bytes", return_value=b"candidate"):
            with self.assertRaisesRegex(subject.BundleError,
                                        "BUNDLE_HASH_UNPINNED_OR_CHANGED"):
                subject.build_verified()


if __name__ == "__main__":
    unittest.main()
