"""Generate a typed private-handle API and pinned internal-relocation witness.

This does not load/modify the engine. The caller supplies its authenticated hash.
Only the shipped ARM64 ELF is admitted; an unfamiliar relocation fails closed.
"""
import hashlib
import re
import struct


def generate(core, engine, expected_sha):
    if hashlib.sha256(engine).hexdigest() != expected_sha:
        raise ValueError('Provider input is not the authenticated engine')

    def region(offset, size):
        if offset < 0 or size < 0 or offset > len(engine) or size > len(engine)-offset:
            raise ValueError('Provider ELF bounds')
        return engine[offset:offset+size]

    header = region(0, 64)
    if header[:7] != b'\x7fELF\x02\x01\x01' or struct.unpack_from('<HH', header, 16) != (3, 183):
        raise ValueError('Provider must be ARM64 shared ELF')
    shoff = struct.unpack_from('<Q', header, 40)[0]
    shsize, shcount = struct.unpack_from('<HH', header, 58)
    if shsize != 64 or not 1 <= shcount <= 4096:
        raise ValueError('Provider section table')
    sections = [struct.unpack_from('<IIQQQQIIQQ', region(shoff+i*64, 64)) for i in range(shcount)]
    dynsyms = [(i, s) for i, s in enumerate(sections) if s[1] == 11]
    if len(dynsyms) != 1:
        raise ValueError('Provider dynamic symbols')
    symindex, symbols = dynsyms[0]
    if symbols[9] != 24 or symbols[5] % 24 or symbols[6] >= shcount or sections[symbols[6]][1] != 3:
        raise ValueError('Provider symbol layout')
    strings = region(sections[symbols[6]][4], sections[symbols[6]][5])

    def name(offset):
        if offset >= len(strings) or (end := strings.find(b'\0', offset)) < 0:
            raise ValueError('Provider symbol string')
        try:
            return strings[offset:end].decode('ascii')
        except UnicodeDecodeError as error:
            raise ValueError('Provider symbol encoding') from error

    entries = []
    callable_exports = set()
    for offset in range(0, symbols[5], 24):
        item = struct.unpack('<IBBHQQ', region(symbols[4]+offset, 24))
        symbol = name(item[0])
        entries.append((symbol, item))
        if item[3] != 0 and item[1] >> 4 in (1, 2) and item[2] & 3 in (0, 3):
            if item[1] & 15 == 2:
                callable_exports.add(symbol)

    # Comments cannot manufacture a call or hide one from the inventory.
    text = re.sub(r'/\*.*?\*/|//[^\n]*', '', core, flags=re.S)
    calls = sorted(set(re.findall(r'\b(FPDF[A-Za-z0-9_]*)\s*\(', text)))
    if not calls or len(calls) > 256 or set(calls) - callable_exports:
        raise ValueError('Provider API call/export inventory')
    relocations = []
    for section in sections:
        if section[1] != 4 or section[6] != symindex:
            continue
        if section[9] != 24 or section[5] % 24 or section[5] > 24000000:
            raise ValueError('Provider relocation layout')
        for offset in range(0, section[5], 24):
            target, info, addend = struct.unpack('<QQq', region(section[4]+offset, 24))
            index, kind = info >> 32, info & 0xffffffff
            if index >= len(entries):
                raise ValueError('Provider relocation symbol index')
            symbol, item = entries[index]
            if not symbol.startswith('FPDF'):
                continue
            if not re.fullmatch(r'FPDF[A-Za-z0-9_]*',symbol):
                raise ValueError('Provider API symbol spelling')
            if item[3] == 0 or item[1] & 15 != 2 or kind not in (257, 1025, 1026) or addend != 0:
                raise ValueError('Unsupported internal PDFium API relocation')
            relocations.append((target, symbol))
    if not relocations or len(relocations) > 4096 or len({r[0] for r in relocations}) != len(relocations):
        raise ValueError('Provider internal relocation inventory')
    phoff = struct.unpack_from('<Q', header, 32)[0]
    phsize, phcount = struct.unpack_from('<HH', header, 54)
    if phsize != 56 or not 1 <= phcount <= 256:
        raise ValueError('Provider segment table')
    ranges = []
    for i in range(phcount):
        kind, flags, _, start, _, _, size, _ = struct.unpack('<IIQQQQQQ', region(phoff+i*56, 56))
        if kind == 1 and flags & 4:
            if size == 0 or start + size >= 2**63:
                raise ValueError('Provider readable segment bounds')
            ranges.append((start, start+size))
    for target, _ in relocations:
        if not any(start <= target <= end-8 for start, end in ranges):
            raise ValueError('Provider relocation outside readable image')
    lines = ['// Generated solely from authenticated engine bytes and actual core calls.',
             '#pragma once', '#include <cstddef>', '#include <cstdint>',
             '#include <fpdfview.h>', '#include <fpdf_text.h>', '#include <fpdf_doc.h>',
             'namespace rtl_provider {', 'struct Api {']
    lines += [f'    decltype(&::{symbol}) fn_{symbol}=nullptr;' for symbol in calls]
    lines += ['};', 'const Api& api();', f'constexpr size_t kEngineBytes={len(engine)};',
              f'constexpr char kEngineSha256[]="{expected_sha}";',
              'struct Range { uintptr_t start,end; };', 'constexpr Range kReadable[]={']
    lines += [f'    {{{start}ULL,{end}ULL}},' for start, end in ranges]
    lines += ['};', 'struct Relocation { uintptr_t offset; const char* symbol; };',
              'constexpr Relocation kInternalRelocations[]={']
    lines += [f'    {{{offset}ULL,"{symbol}"}},' for offset, symbol in sorted(relocations)]
    lines += ['};', '}']
    lines += ['#define RTL_PDFIUM_API_TABLE(X) ' + '\\\n'.join(
        f'X({symbol})' for symbol in calls)]
    lines += [f'#define {symbol} (rtl_provider::api().fn_{symbol})' for symbol in calls]
    return '\n'.join(lines)+'\n'
