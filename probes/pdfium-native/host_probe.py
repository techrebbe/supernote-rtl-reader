"""Actual pinned native API proof on ONE immutable disposable fixture, no writer.

This Windows characterization is not Android JNI/runtime or UI evidence.
Do not accept a personal PDF or load an unverified library through this tool.
"""
from __future__ import annotations
import argparse
import contextlib
import ctypes as c
import hashlib
import json
import math
from pathlib import Path
from PIL import Image

FIXTURE_SHA = '7cf9de8fa7ed91f7746ac44f62aa63e0641f757f330cf7d83efec7584b213905'
MAX_PIXELS, MAX_CHARS, MAX_ITEMS = 4_000_000, 20_000, 1000
P, I, U, L, F, D = c.c_void_p, c.c_int, c.c_uint, c.c_ulong, c.c_float, c.c_double


class Rect(c.Structure):
    _fields_ = [('left', F), ('top', F), ('right', F), ('bottom', F)]


def checked(value, message):
    if not value:
        raise RuntimeError(message)
    return value


def finite(values):
    checked(all(math.isfinite(x) for x in values), 'Nonfinite native geometry')
    return list(values)


class Fixture:
    def __init__(self, engine_root, fixture):
        lock = json.loads(Path(__file__).with_name('pdfium.lock.json').read_text(encoding='utf-8'))
        root = Path(engine_root).resolve(strict=True)
        for leaf in ['pdfium-win-x64.tgz', 'pdfium-attestation.json']:
            checked(hashlib.sha256((root / leaf).read_bytes()).hexdigest() == lock['assets'][leaf]['sha256'], 'Pinned archive/provenance drift')
        dll = root / 'win-x64/bin/pdfium.dll'
        checked(not dll.is_symlink() and hashlib.sha256(dll.read_bytes()).hexdigest() == lock['extractedBinaries']['win-x64/bin/pdfium.dll'], 'Pinned DLL drift')
        self.data = Path(fixture).read_bytes()
        checked(len(self.data) < 1_000_000 and hashlib.sha256(self.data).hexdigest() == FIXTURE_SHA, 'Only the exact disposable fixture is permitted')
        self.lib = c.WinDLL(str(dll))
        # Public API signatures match the pinned archive headers; no generic
        # action, form, save, annotation-edit or file-loading bridge is exposed.
        signatures = {
            'FPDF_InitLibrary': (None, []), 'FPDF_DestroyLibrary': (None, []),
            'FPDF_LoadMemDocument64': (P, [P, c.c_size_t, c.c_char_p]), 'FPDF_CloseDocument': (None, [P]),
            'FPDF_GetPageCount': (I, [P]), 'FPDF_LoadPage': (P, [P, I]), 'FPDF_ClosePage': (None, [P]),
            'FPDF_GetPageWidthF': (F, [P]), 'FPDF_GetPageHeightF': (F, [P]), 'FPDF_GetPageBoundingBox': (I, [P, c.POINTER(Rect)]),
            'FPDFText_LoadPage': (P, [P]), 'FPDFText_ClosePage': (None, [P]), 'FPDFText_CountChars': (I, [P]),
            'FPDFText_GetUnicode': (U, [P, I]), 'FPDFText_GetCharBox': (I, [P, I, *([c.POINTER(D)] * 4)]),
            'FPDFText_GetCharIndexAtPos': (I, [P, D, D, D, D]),
            'FPDFLink_Enumerate': (I, [P, c.POINTER(I), c.POINTER(P)]), 'FPDFLink_GetAnnotRect': (I, [P, c.POINTER(Rect)]),
            'FPDFLink_GetDest': (P, [P, P]), 'FPDFLink_GetAction': (P, [P]), 'FPDFAction_GetType': (L, [P]),
            'FPDFAction_GetDest': (P, [P, P]), 'FPDFAction_GetURIPath': (L, [P, P, P, L]),
            'FPDFDest_GetDestPageIndex': (I, [P, P]), 'FPDFDest_GetView': (L, [P, c.POINTER(L), c.POINTER(F)]),
            'FPDFDest_GetLocationInPage': (I, [P, *([c.POINTER(I)] * 3), *([c.POINTER(F)] * 3)]),
            'FPDF_GetNamedDestByName': (P, [P, c.c_char_p]),
            'FPDFBookmark_GetFirstChild': (P, [P, P]), 'FPDFBookmark_GetNextSibling': (P, [P, P]),
            'FPDFBookmark_GetTitle': (L, [P, P, L]), 'FPDFBookmark_GetDest': (P, [P, P]),
            'FPDF_PageToDevice': (I, [P, *([I] * 5), D, D, c.POINTER(I), c.POINTER(I)]),
            'FPDF_DeviceToPage': (I, [P, *([I] * 7), c.POINTER(D), c.POINTER(D)]),
            'FPDFBitmap_Create': (P, [I, I, I]), 'FPDFBitmap_Destroy': (None, [P]),
            'FPDFBitmap_FillRect': (I, [P, I, I, I, I, c.c_ulong]),
            'FPDFBitmap_GetBuffer': (P, [P]), 'FPDFBitmap_GetStride': (I, [P]),
            'FPDF_RenderPageBitmap': (None, [P, P, *([I] * 6)]),
        }
        for name, (restype, argtypes) in signatures.items():
            function = getattr(self.lib, name)
            function.restype, function.argtypes = restype, argtypes
        self.lib.FPDF_InitLibrary()
        self.doc = None
        self.buffer = c.create_string_buffer(self.data)
        try:
            self.doc = checked(self.lib.FPDF_LoadMemDocument64(self.buffer, len(self.data), None), 'Fixture load failed')
            self.count = self.lib.FPDF_GetPageCount(self.doc)
            checked(self.count == 4, 'Fixture original page count mismatch')
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.doc:
            self.lib.FPDF_CloseDocument(self.doc)
            self.doc = None
            self.lib.FPDF_DestroyLibrary()
        elif self.buffer is not None:
            self.lib.FPDF_DestroyLibrary()
        self.buffer = None

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        self.close()

    @contextlib.contextmanager
    def page(self, index):
        checked(self.doc and type(index) is int and 0 <= index < self.count, 'Closed or invalid original page')
        page = checked(self.lib.FPDF_LoadPage(self.doc, index), 'Page load failed')
        try:
            yield page
        finally:
            self.lib.FPDF_ClosePage(page)

    def destination(self, dest):
        if not dest:
            return {'kind': 'unsupported', 'reason': 'No destination'}
        page = self.lib.FPDFDest_GetDestPageIndex(self.doc, dest)
        checked(0 <= page < self.count, 'Invalid original target page')
        count, params = L(), (F * 4)()
        mode = self.lib.FPDFDest_GetView(dest, c.byref(count), params)
        checked(count.value <= 4, 'Native destination parameter bound')
        if mode == 2 and count.value == 0:
            return {'kind': 'internal', 'pageIndex': page, 'mode': 'Fit'}
        if mode == 1:
            has = [I() for _ in range(3)]
            xyz = [F() for _ in range(3)]
            checked(self.lib.FPDFDest_GetLocationInPage(dest, *(c.byref(x) for x in has + xyz)), 'Unsupported XYZ')
            values = [x.value if flag.value else None for flag, x in zip(has, xyz)]
            finite([x for x in values if x is not None])
            checked(values[2] is None or values[2] >= 0, 'Negative native zoom')
            return {'kind': 'internal', 'pageIndex': page, 'mode': 'XYZ', 'left': values[0], 'top': values[1], 'zoom': values[2]}
        return {'kind': 'unsupported', 'reason': f'Unsupported destination mode {mode}'}

    def outlines(self):
        seen = set()
        def children(parent, depth):
            checked(depth <= 32, 'Outline depth bound')
            items, item = [], self.lib.FPDFBookmark_GetFirstChild(self.doc, parent)
            while item:
                checked(item not in seen and len(seen) < MAX_ITEMS, 'Cyclic/large outline')
                seen.add(item)
                length = self.lib.FPDFBookmark_GetTitle(item, None, 0)
                checked(2 <= length <= 8192 and length % 2 == 0, 'Invalid outline title size')
                title = c.create_string_buffer(length)
                checked(self.lib.FPDFBookmark_GetTitle(item, title, length) == length, 'Outline title drift')
                items.append({'title': title.raw[:-2].decode('utf-16-le'), 'destination': self.destination(self.lib.FPDFBookmark_GetDest(self.doc, item)), 'children': children(item, depth + 1)})
                item = self.lib.FPDFBookmark_GetNextSibling(self.doc, item)
            return items
        return children(None, 0)

    def geometry(self, page, width, height, point):
        dx, dy, px, py = I(), I(), D(), D()
        checked(self.lib.FPDF_PageToDevice(page, 0, 0, width, height, 0, *point, c.byref(dx), c.byref(dy)), 'Page-to-view mapping failed')
        checked(self.lib.FPDF_DeviceToPage(page, 0, 0, width, height, 0, dx, dy, c.byref(px), c.byref(py)), 'View-to-page mapping failed')
        return [dx.value, dy.value], finite([px.value, py.value])

    def inspect_page(self, page):
        size = finite([self.lib.FPDF_GetPageWidthF(page), self.lib.FPDF_GetPageHeightF(page)])
        checked(all(0 < x <= 20000 for x in size), 'Page size bound')
        crop = Rect()
        checked(self.lib.FPDF_GetPageBoundingBox(page, c.byref(crop)), 'Missing page crop authority')
        text_page = checked(self.lib.FPDFText_LoadPage(page), 'Text extraction unavailable')
        try:
            count = self.lib.FPDFText_CountChars(text_page)
            checked(0 <= count <= MAX_CHARS, 'Text count bound')
            unicode = [self.lib.FPDFText_GetUnicode(text_page, i) for i in range(count)]
            checked(all(0 <= x <= 0x10ffff for x in unicode), 'Unicode bound')
            boxes = []
            for i in range(count):
                values = [D() for _ in range(4)]
                if self.lib.FPDFText_GetCharBox(text_page, i, *(c.byref(x) for x in values)):
                    box = finite([x.value for x in values])  # left/right/bottom/top
                    boxes.append({'index': i, 'rect': box})
            # Hit the center of a known ordinary glyph, not a generated newline.
            first = next(box for box in boxes if chr(unicode[box['index']]).isalpha())
            b = first['rect']
            hit = self.lib.FPDFText_GetCharIndexAtPos(text_page, (b[0]+b[1])/2, (b[2]+b[3])/2, 0, 0)
            checked(hit == first['index'], 'Actual text hit index mismatch')
        finally:
            self.lib.FPDFText_ClosePage(text_page)
        links, offset, link = [], I(), P()
        while self.lib.FPDFLink_Enumerate(page, c.byref(offset), c.byref(link)):
            checked(len(links) < MAX_ITEMS, 'Link count bound')
            rect = Rect()
            checked(self.lib.FPDFLink_GetAnnotRect(link, c.byref(rect)), 'Link rectangle unavailable')
            destination = self.lib.FPDFLink_GetDest(self.doc, link)
            if destination:
                action = self.destination(destination)
            else:
                native_action = self.lib.FPDFLink_GetAction(link)
                kind = self.lib.FPDFAction_GetType(native_action) if native_action else 0
                if kind == 1:
                    action = self.destination(self.lib.FPDFAction_GetDest(self.doc, native_action))
                elif kind == 3:
                    length = self.lib.FPDFAction_GetURIPath(self.doc, native_action, None, 0)
                    checked(1 <= length <= 4096, 'URI length bound')
                    uri = c.create_string_buffer(length)
                    checked(self.lib.FPDFAction_GetURIPath(self.doc, native_action, uri, length) == length, 'URI drift')
                    action = {'kind': 'external-confirmation-required', 'uri': uri.value.decode('utf-8')}
                else:
                    action = {'kind': 'unsupported', 'reason': f'Disabled action type {kind}'}
            links.append({'rect': finite([rect.left, rect.bottom, rect.right, rect.top]), 'action': action})
        return {'size': size, 'crop': finite([crop.left, crop.bottom, crop.right, crop.top]), 'text': ''.join(map(chr, unicode)), 'charBoxes': len(boxes), 'textHitIndex': hit, 'links': links}

    def render(self, page, width, height, output):
        checked(type(width) is int and type(height) is int and 0 < width * height <= MAX_PIXELS and width > 0 and height > 0, 'Bitmap allocation bound')
        bitmap = checked(self.lib.FPDFBitmap_Create(width, height, 0), 'Bitmap allocation failed')
        try:
            checked(self.lib.FPDFBitmap_FillRect(bitmap, 0, 0, width, height, 0xffffffff), 'Bitmap fill failed')
            self.lib.FPDF_RenderPageBitmap(bitmap, page, 0, 0, width, height, 0, 1)
            stride = self.lib.FPDFBitmap_GetStride(bitmap)
            checked(width * 4 <= stride <= width * 4 + 64, 'Unexpected bitmap stride')
            data = c.string_at(checked(self.lib.FPDFBitmap_GetBuffer(bitmap), 'Missing bitmap buffer'), stride * height)
            image = Image.frombytes('RGB', (width, height), data, 'raw', 'BGRX', stride)
            with Path(output).open('xb') as stream:
                image.save(stream, format='PNG')
        finally:
            self.lib.FPDFBitmap_Destroy(bitmap)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--engine', required=True, type=Path)
    parser.add_argument('--fixture', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    result = {'engine': '157.0.8100.0', 'fixtureSha256': FIXTURE_SHA, 'pages': [], 'androidRuntime': 'UNVERIFIED'}
    with Fixture(args.engine, args.fixture) as engine:
        result['outline'] = engine.outlines()
        result['namedDestination'] = engine.destination(engine.lib.FPDF_GetNamedDestByName(engine.doc, b'chapter-three'))
        for index in range(4):
            with engine.page(index) as page:
                model = engine.inspect_page(page)
                width = 918
                height = round(width * model['size'][1] / model['size'][0])
                model['mapping'] = engine.geometry(page, width, height, [44, 738])
                engine.render(page, width, height, args.output / f'page-{index+1}.png')
                result['pages'].append(model)
    checked(hashlib.sha256(args.fixture.read_bytes()).hexdigest() == FIXTURE_SHA, 'Fixture changed after probe')
    with (args.output / 'api-result.json').open('x', encoding='utf-8') as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2)
    # Only bounded diagnostic summary; detailed disposable text stays local.
    print(json.dumps({'pages': len(result['pages']), 'page1Links': result['pages'][0]['links'], 'namedDestination': result['namedDestination'], 'outline': result['outline'], 'page2Size': result['pages'][1]['size'], 'fixtureUnchanged': True, 'androidRuntime': 'UNVERIFIED'}, ensure_ascii=True))


if __name__ == '__main__':
    main()
