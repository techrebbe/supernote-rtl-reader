"""Create a disposable original-format PDF; never accept or edit an input PDF."""
from __future__ import annotations
import argparse
import hashlib
import io
import json
from pathlib import Path
from reportlab.pdfgen import canvas
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from pypdf import PdfReader, PdfWriter
from pypdf.generic import ArrayObject, DictionaryObject, FloatObject, NameObject, TextStringObject, RectangleObject, NullObject
from pypdf.generic import Fit


def fresh_outputs(output):
    # Check the user-spelled leaf BEFORE resolve, which follows symlinks.
    raw = Path(output)
    if raw.suffix != '.pdf' or raw.is_symlink():
        raise SystemExit('Only fresh regular disposable outputs are allowed')
    target = raw.resolve()
    manifest = target.with_suffix('.json')
    if target.exists() or manifest.exists() or manifest.is_symlink():
        raise SystemExit('Both PDF and manifest outputs must be fresh')
    return target, manifest


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--font', required=True, type=Path)
    args = parser.parse_args()
    target, manifest_path = fresh_outputs(args.output)
    target.parent.mkdir(parents=True, exist_ok=True)
    pdfmetrics.registerFont(TTFont('FixtureSans', str(args.font)))
    data = io.BytesIO()
    c = canvas.Canvas(data, pagesize=(612, 792), invariant=True)
    c.setTitle('Disposable interactive original PDF')
    for index in range(4):
        c.setFont('FixtureSans', 24)
        c.drawString(44, 738, f'SOURCE PAGE {index + 1}')
        c.setFont('FixtureSans', 14)
        c.drawString(44, 700, 'Selectable phrase: original PDF text, not a page image.')
        c.drawString(44, 670, 'Hebrew embedded text (right-to-left):')
        c.drawRightString(565, 670, 'שלום עולם', direction='RTL', shaping=True)
        c.setFont('FixtureSans', 12)
        if index == 0:
            for y, label in [(590, 'Direct link to source page 2'), (540, 'Named link to source page 3'),
                             (490, 'Same-page link to lower text'), (440, 'External link requires confirmation'),
                             (390, 'Unsupported script action must not run')]:
                c.setStrokeColorRGB(0, 0, 0)
                c.rect(42, y - 8, 450, 32)
                c.drawString(50, y, label)
        c.drawString(44, 230, f'Lower anchor on original source page {index + 1}.')
        c.drawString(44, 80, 'DISPOSABLE - no Supernote writing or annotation data.')
        c.showPage()
    c.save()
    writer = PdfWriter()
    writer.append(PdfReader(io.BytesIO(data.getvalue())))
    refs = [page.indirect_reference for page in writer.pages]
    writer.add_named_destination_array(TextStringObject('chapter-three'),
        ArrayObject([refs[2], NameObject('/XYZ'), FloatObject(44), FloatObject(738), FloatObject(1.25)]))
    links = [
        (590, {'/Dest': ArrayObject([refs[1], NameObject('/Fit')])}),
        (540, {'/Dest': TextStringObject('chapter-three')}),
        (490, {'/Dest': ArrayObject([refs[0], NameObject('/XYZ'), FloatObject(44), FloatObject(240), NullObject()])}),
        (440, {'/A': DictionaryObject({NameObject('/S'): NameObject('/URI'), NameObject('/URI'): TextStringObject('https://example.org/rtl-test')})}),
        (390, {'/A': DictionaryObject({NameObject('/S'): NameObject('/JavaScript'), NameObject('/JS'): TextStringObject('window.__pdfActionRan = true;')})}),
    ]
    for y, action in links:
        annotation = DictionaryObject({NameObject('/Type'): NameObject('/Annot'), NameObject('/Subtype'): NameObject('/Link'),
            NameObject('/Rect'): RectangleObject([42, y - 8, 492, y + 24]),
            NameObject('/Border'): ArrayObject([FloatObject(0), FloatObject(0), FloatObject(0)])})
        # Insert the new Link through the public API, then set the exact PDF
        # destination/action. add_annotation's convenience Dest dictionary is
        # not a raw PDF destination array or a named destination string.
        added = writer.add_annotation(0, annotation)
        added.update({NameObject(key): value for key, value in action.items()})
    parent = writer.add_outline_item('Part one', 0, fit=Fit.fit())
    writer.add_outline_item('Chapter three', 2, parent=parent, fit=Fit.xyz(44, 738, 1.25))
    writer.add_outline_item('ברכה', 3, parent=parent, fit=Fit.fit())
    writer.add_outline_item('Appendix', 3, fit=Fit.fit())
    writer.pages[1].cropbox = RectangleObject([20, 30, 590, 750])
    writer.pages[1].rotate(90)
    with target.open('xb') as stream:
        writer.write(stream)
    verify = PdfReader(target)
    if len(verify.pages) != 4 or len(verify.pages[0]['/Annots']) != 5 or 'chapter-three' not in verify.named_destinations:
        raise SystemExit('Fixture authority failed')
    if 'Selectable phrase' not in verify.pages[0].extract_text():
        raise SystemExit('Fixture embedded text missing')
    manifest = {'disposable': True, 'pages': 4, 'page1Links': 5, 'sha256': hashlib.sha256(target.read_bytes()).hexdigest(),
        'namedDestination': 'chapter-three', 'namedPageIndex': 2, 'page2Rotation': 90,
        'originalPdfFormat': True, 'nativeAnnotationFileCreated': False}
    # Exclusive creation is still required after the precheck: another process
    # may create a manifest meanwhile. Leave a partial disposable PDF on failure,
    # never overwrite or remove someone else's file to rescue the generator.
    with manifest_path.open('x', encoding='utf-8') as stream:
        stream.write(json.dumps(manifest, indent=2))
    print(json.dumps(manifest))


if __name__ == '__main__':
    main()
