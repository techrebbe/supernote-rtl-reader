#!/usr/bin/env python3
"""Create a NEW disposable ordinary PDF for the T008 native-canvas fit gate.

No annotation sidecar is copied or synthesized. Existing paths are rejected.
The original-size page deliberately differs from the Nomad's 3:4 ink canvas.
"""
from pathlib import Path
import argparse
import hashlib
import io
import json

from pypdf import PdfReader
from reportlab.pdfgen.canvas import Canvas


def create(output: Path) -> dict:
    if output.exists() or output.is_symlink():
        raise ValueError("Refusing to overwrite an existing fixture")
    sidecar = Path(str(output) + ".mark")
    if sidecar.exists() or sidecar.is_symlink():
        raise ValueError("Refusing a fixture path with an existing annotation sidecar")
    output.parent.mkdir(parents=True, exist_ok=True)
    width, height = 612, 792
    encoded = io.BytesIO()
    canvas = Canvas(encoded, pagesize=(width, height), invariant=1)
    canvas.setTitle("RTL saved-ink native-canvas geometry disposable fixture")
    canvas.setAuthor("RTL Reader diagnostic fixture")
    for page in range(1, 3):
        canvas.setLineWidth(1)
        canvas.rect(12, 12, width - 24, height - 24)
        canvas.setFont("Helvetica-Bold", 26)
        canvas.drawCentredString(width / 2, height - 60, f"PAGE {page}")
        canvas.setFont("Helvetica", 12)
        canvas.drawCentredString(width / 2, height - 85, "DISPOSABLE - NATIVE CANVAS ALIGNMENT")
        canvas.drawCentredString(width / 2, height - 105, "612 x 792 points; no rotation; equal page boxes")
        # Exact PDF-coordinate fiducials, independent of the implementation.
        for x, y, label in ((36, 36, "BL"), (width - 36, 36, "BR"),
                            (36, height - 140, "TL"), (width - 36, height - 140, "TR")):
            canvas.line(x - 8, y, x + 8, y)
            canvas.line(x, y - 8, x, y + 8)
            canvas.drawCentredString(x, y - 22, label)
        if page == 1:
            for x, y, label in ((84, 450, "A"), (338, 220, "B")):
                canvas.rect(x, y, 190, 110)
                canvas.setFont("Helvetica-Bold", 18)
                canvas.drawString(x + 8, y + 84, label)
            canvas.setFont("Helvetica", 12)
            canvas.drawCentredString(width / 2, 155, "When asked: use the native pen only inside the labeled boxes.")
            canvas.drawCentredString(width / 2, 135, "No generated or transplanted handwriting is present.")
        else:
            canvas.setFont("Helvetica", 16)
            canvas.drawCentredString(width / 2, height / 2, "REFERENCE PAGE - LEAVE UNMARKED")
        canvas.showPage()
    canvas.save()
    pdf_bytes = encoded.getvalue()
    reader = PdfReader(io.BytesIO(pdf_bytes))
    if len(reader.pages) != 2:
        raise ValueError("Fixture page count changed")
    for page in reader.pages:
        if list(page.mediabox) != [0, 0, width, height] or list(page.cropbox) != [0, 0, width, height]:
            raise ValueError("Fixture page boxes changed")
        if page.rotation != 0 or page.get("/UserUnit", 1) != 1 or page.get("/Annots"):
            raise ValueError("Fixture contains unsupported rotation/unit/annotations")
    # Exclusive creation is the authority, not the earlier advisory exists()
    # check: a concurrent file or dangling link must never be overwritten.
    if sidecar.exists() or sidecar.is_symlink():
        raise ValueError("Annotation sidecar appeared during fixture generation")
    with output.open("xb") as stream:
        stream.write(pdf_bytes)
    return {"sha256": hashlib.sha256(pdf_bytes).hexdigest(),
            "pageCount": 2, "mediaBox": [0, 0, width, height],
            "cropBox": [0, 0, width, height], "rotation": 0, "userUnit": 1,
            "annotations": 0, "nativeCanvas": [1404, 1872],
            "status": "fixture-only; no native-geometry or handwriting pass"}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    print(json.dumps(create(args.output.absolute()), sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
