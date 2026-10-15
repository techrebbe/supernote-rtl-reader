"""Link-boundary negatives plus the actual failed/corrected device-candidate ELF."""
import os
from pathlib import Path
import struct
import unittest
from pdfium_elf import JNI_EXPORTS, NEEDED, verify_wrapper


def fixture(exports=None, imports=(), needed=None, soname='librtlpdfiumreader.so'):
    exports = JNI_EXPORTS if exports is None else exports
    needed = sorted(NEEDED) if needed is None else needed
    strings = bytearray(b'\0')

    def name(value):
        offset = len(strings)
        strings.extend(value.encode('ascii') + b'\0')
        return offset

    symbols = bytearray(24)
    for value in sorted(exports):
        symbols.extend(struct.pack('<IBBHQQ', name(value), 0x12, 0, 1, 1, 1))
    for value in imports:
        symbols.extend(struct.pack('<IBBHQQ', name(value), 0x12, 0, 0, 0, 0))
    dynamic = b''.join(struct.pack('<qQ', 1, name(value)) for value in needed)
    dynamic += struct.pack('<qQ', 14, name(soname)) + bytes(16)
    strings_offset = 64 + 4 * 64
    symbols_offset = strings_offset + len(strings)
    dynamic_offset = symbols_offset + len(symbols)
    header = bytearray(64)
    header[:7] = b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HH', header, 16, 3, 183)
    struct.pack_into('<Q', header, 40, 64)
    struct.pack_into('<HHH', header, 58, 64, 4, 0)
    sections = bytes(64)
    for kind, offset, size, link, stride in (
            (3, strings_offset, len(strings), 0, 0),
            (11, symbols_offset, len(symbols), 1, 24),
            (6, dynamic_offset, len(dynamic), 1, 16)):
        sections += struct.pack('<IIQQQQIIQQ', 0, kind, 0, 0, offset, size, link, 0, 1, stride)
    return bytes(header) + sections + strings + symbols + dynamic


class Boundary(unittest.TestCase):
    def test_jni_only_with_platform_c_and_pdfium_imports(self):
        verify_wrapper(fixture(imports=('FPDF_InitLibrary', 'malloc', '__cxa_atexit', '__cxa_finalize')))

    def test_foreign_runtime_imports_rejected(self):
        for name in ('__emutls_get_address', '_Znwm', '_ZdlPv', '_Unwind_Resume',
                     '__gxx_personality_v0', '__cxa_throw', '__cxa_guard_acquire'):
            with self.subTest(symbol=name), self.assertRaisesRegex(ValueError, r'foreign C\+\+/compiler runtime'):
                verify_wrapper(fixture(imports=(name,)))

    def test_extra_export_and_missing_jni_rejected(self):
        for exports in (JNI_EXPORTS | {'__emutls_get_address'}, JNI_EXPORTS - {min(JNI_EXPORTS)}):
            with self.assertRaisesRegex(ValueError, 'nine JNI'):
                verify_wrapper(fixture(exports=exports))

    def test_shared_cxx_missing_extra_duplicate_dependencies_rejected(self):
        for needed in (sorted(NEEDED | {'libc++_shared.so'}), sorted(NEEDED - {'libpdfium.so'}),
                       sorted(NEEDED) + ['libpdfium.so']):
            with self.assertRaisesRegex(ValueError, 'shared-dependency'):
                verify_wrapper(fixture(needed=needed))

    def test_foreign_soname_rejected(self):
        with self.assertRaisesRegex(ValueError, 'SONAME'):
            verify_wrapper(fixture(soname='libother.so'))

    def test_wrong_abi_and_truncation_rejected(self):
        good = fixture()
        bad = bytearray(good)
        bad[18] = 40
        for data in (b'', good[:63], good[:-1], bytes(bad)):
            with self.assertRaises(ValueError):
                verify_wrapper(data)

    def test_invalid_section_and_string_bounds_rejected(self):
        for offset, value in ((40, 2**63), (64 + 2 * 64 + 24, 2**63)):
            bad = bytearray(fixture())
            struct.pack_into('<Q', bad, offset, value)
            with self.assertRaises(ValueError):
                verify_wrapper(bad)
        bad = bytearray(fixture())
        symbol_offset = struct.unpack_from('<Q', bad, 64 + 2 * 64 + 24)[0]
        struct.pack_into('<I', bad, symbol_offset + 24, 0xffffffff)
        with self.assertRaisesRegex(ValueError, 'string offset'):
            verify_wrapper(bad)

    def test_actual_failed_and_corrected_arm64_wrappers(self):
        failed = os.environ.get('RTL_PDFIUM_FAILED_WRAPPER')
        corrected = os.environ.get('RTL_PDFIUM_CORRECTED_WRAPPER')
        if not failed or not corrected:
            self.skipTest('Set exact retained code60 and freshly compiled corrected ARM64 ELF paths')
        with self.assertRaises(ValueError):
            verify_wrapper(Path(failed).read_bytes())
        verify_wrapper(Path(corrected).read_bytes())


if __name__ == '__main__':
    unittest.main()
