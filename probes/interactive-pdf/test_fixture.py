"""Fresh-output refusal tests; no PDF generated and no original file accepted."""
import tempfile
import unittest
from unittest.mock import MagicMock, patch
from pathlib import Path
from make_fixture import fresh_outputs


class FreshOutputs(unittest.TestCase):
    def test_pdf_symlink_is_rejected_before_resolve(self):
        raw = MagicMock(suffix='.pdf')
        raw.is_symlink.return_value = True
        with patch('make_fixture.Path', return_value=raw):
            with self.assertRaises(SystemExit):
                fresh_outputs('unused.pdf')
        raw.resolve.assert_not_called()

    def test_dangling_manifest_symlink_is_rejected(self):
        raw, target, manifest = MagicMock(suffix='.pdf'), MagicMock(), MagicMock()
        raw.is_symlink.return_value = False
        raw.resolve.return_value = target
        target.exists.return_value = False
        target.with_suffix.return_value = manifest
        manifest.exists.return_value = False
        manifest.is_symlink.return_value = True
        with patch('make_fixture.Path', return_value=raw):
            with self.assertRaises(SystemExit):
                fresh_outputs('unused.pdf')

    def test_existing_pdf_is_untouched(self):
        with tempfile.TemporaryDirectory() as folder:
            pdf = Path(folder) / 'test.pdf'
            pdf.write_bytes(b'existing disposable bytes')
            with self.assertRaises(SystemExit):
                fresh_outputs(pdf)
            self.assertEqual(pdf.read_bytes(), b'existing disposable bytes')

    def test_existing_manifest_blocks_before_pdf_creation(self):
        with tempfile.TemporaryDirectory() as folder:
            pdf = Path(folder) / 'test.pdf'
            manifest = pdf.with_suffix('.json')
            manifest.write_text('existing disposable manifest', encoding='utf-8')
            with self.assertRaises(SystemExit):
                fresh_outputs(pdf)
            self.assertEqual(manifest.read_text(encoding='utf-8'), 'existing disposable manifest')
            self.assertFalse(pdf.exists())

    def test_fresh_outputs_and_exclusive_manifest_race(self):
        with tempfile.TemporaryDirectory() as folder:
            pdf, manifest = fresh_outputs(Path(folder) / 'test.pdf')
            self.assertFalse(pdf.exists())
            manifest.write_text('new concurrent disposable manifest', encoding='utf-8')
            with self.assertRaises(FileExistsError):
                with manifest.open('x', encoding='utf-8'):
                    pass
            self.assertEqual(manifest.read_text(encoding='utf-8'), 'new concurrent disposable manifest')


if __name__ == '__main__':
    unittest.main()
