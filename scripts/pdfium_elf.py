"""Shipped ARM64 JNI link boundary; no dependence on PluginHost's C++ runtime."""
import struct

JNI_EXPORTS = {f'Java_com_supernotertlreader_PdfiumReaderCore_{name}' for name in
               ('open', 'close', 'count', 'outline', 'size', 'point', 'model', 'render', 'libraryPath', 'candidatePath', 'bindEngine')}
NEEDED = {'libdl.so', 'libm.so', 'libc.so'}


def verify_wrapper(data):
    def region(offset, length):
        if offset < 0 or length < 0 or offset > len(data) or length > len(data) - offset:
            raise ValueError('Truncated PDFium ELF')
        return data[offset:offset + length]

    def string(table, offset):
        if offset < 0 or offset >= len(table):
            raise ValueError('Invalid PDFium ELF string offset')
        end = table.find(b'\0', offset)
        if end < 0:
            raise ValueError('Unterminated PDFium ELF string')
        try:
            return table[offset:end].decode('ascii')
        except UnicodeDecodeError as error:
            raise ValueError('Invalid PDFium ELF symbol') from error

    header = region(0, 64)
    if header[:7] != b'\x7fELF\x02\x01\x01' or struct.unpack_from('<HH', header, 16) != (3, 183):
        raise ValueError('Expected ARM64 little-endian shared PDFium wrapper')
    offset = struct.unpack_from('<Q', header, 40)[0]
    stride, count = struct.unpack_from('<HH', header, 58)
    if stride != 64 or not 1 <= count <= 4096:
        raise ValueError('Invalid PDFium ELF section table')
    table = region(offset, count * stride)
    sections = [struct.unpack_from('<IIQQQQIIQQ', table, index * stride) for index in range(count)]

    def section_data(section):
        return region(section[4], section[5])

    def linked_strings(section):
        link = section[6]
        if link >= count or sections[link][1] != 3:
            raise ValueError('Invalid PDFium ELF string table')
        return section_data(sections[link])

    symbols = [section for section in sections if section[1] == 11]
    dynamics = [section for section in sections if section[1] == 6]
    if len(symbols) != 1 or len(dynamics) != 1:
        raise ValueError('Missing/duplicate PDFium ELF dynamic tables')
    symbols, dynamic = symbols[0], dynamics[0]
    if symbols[9] != 24 or symbols[5] % 24 or dynamic[9] != 16 or dynamic[5] % 16:
        raise ValueError('Invalid PDFium ELF dynamic entry size')
    names = linked_strings(symbols)
    exported, imports = set(), set()
    symbol_bytes = section_data(symbols)
    for position in range(0, symbols[5], 24):
        name, info, visibility, index, _, _ = struct.unpack_from('<IBBHQQ', symbol_bytes, position)
        if not name:
            continue
        name = string(names, name)
        if index == 0:
            imports.add(name)
        elif info >> 4 in (1, 2, 10) and visibility & 3 in (0, 3):
            exported.add(name)
    if exported != JNI_EXPORTS:
        raise ValueError('PDFium wrapper exports must be exactly the eleven JNI entry points')
    if any(name.startswith('FPDF') for name in imports):
        raise ValueError('PDFium wrapper must not import default-scope FPDF APIs')
    # --no-undefined alone accepted the failed code60 binary: libpdfium's weak
    # exports satisfied compiler/C++ symbols at link time. Keep that runtime
    # local, rather than relying on the host loader's symbol scope or ABI.
    runtime = {name for name in imports if name.startswith(('_Z', '_Unwind_', '__emutls', '__gxx')) or
               name.startswith('__cxa_') and name not in ('__cxa_atexit', '__cxa_finalize')}
    if runtime:
        raise ValueError('PDFium wrapper imports a foreign C++/compiler runtime: ' + ', '.join(sorted(runtime)))
    names = linked_strings(dynamic)
    needed, sonames = [], []
    dynamic_bytes = section_data(dynamic)
    for position in range(0, dynamic[5], 16):
        tag, value = struct.unpack_from('<qQ', dynamic_bytes, position)
        if tag == 0:
            break
        if tag == 1:
            needed.append(string(names, value))
        elif tag == 14:
            sonames.append(string(names, value))
    if set(needed) != NEEDED or len(needed) != len(NEEDED) or sonames != ['librtlpdfiumreader.so']:
        raise ValueError('PDFium wrapper shared-dependency/SONAME drift')
