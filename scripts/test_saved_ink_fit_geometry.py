#!/usr/bin/env python3
"""Compile the actual restricted T008 Java template and run bounded math checks.

Uses only Python's standard library and JDK 17. All rendered Java/classes stay in
an owned temporary directory; no PDF, repository candidate, or device is changed.
This is stock portrait arithmetic evidence, not native ink-registration evidence.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


HARNESS = r"""
package fitgeometrytest;

import java.util.Random;

public final class SavedInkFitGeometryTest {
    private static int checks;
    private static int groups;

    private static void check(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }

    private static void equal(int actual, int expected, String label) {
        check(actual == expected, label + ": " + actual + " != " + expected);
    }

    private static void bits(float actual, int expected, String label) {
        equal(Float.floatToIntBits(actual), expected, label);
    }

    private static SavedInkFitGeometry.Geometry fit(int width, int height) {
        return SavedInkFitGeometry.calculate(0, 0, width, height);
    }

    private static void reject(double x0, double y0, double x1, double y1,
            String label) {
        checks++;
        try {
            SavedInkFitGeometry.calculate(x0, y0, x1, y1);
        } catch (IllegalArgumentException expected) {
            return;
        }
        throw new AssertionError("Accepted unsupported bounds: " + label);
    }

    private static void vector(int width, int height, int scaledWidth,
            int scaledHeight, int bitmapWidth, int bitmapHeight,
            int offsetX, int offsetY, int fitBits, int ctmBits) {
        SavedInkFitGeometry.Geometry g = fit(width, height);
        equal(g.pageWidth, width, "page width");
        equal(g.pageHeight, height, "page height");
        equal(g.stockScaledWidth, scaledWidth, "stock RectI width");
        equal(g.stockScaledHeight, scaledHeight, "stock RectI height");
        equal(g.bitmapWidth, bitmapWidth, "bitmap width");
        equal(g.bitmapHeight, bitmapHeight, "bitmap height");
        equal(g.offsetX, offsetX, "integer offset x");
        equal(g.offsetY, offsetY, "integer offset y");
        bits(g.fitScale, fitBits, "fit binary32 bits");
        bits(g.ctmScale, ctmBits, "CTM binary32 bits");
    }

    private static void knownVectors() {
        bits(SavedInkFitGeometry.STOCK_SCALE, 0x400e38e4, "160/72f bits");
        // Independent constants from the bytecode-confirmed binary32 calculation.
        vector(612, 792, 1360, 1761, 1404, 1817, 0, 27, 0x3f842424, 0x4012d2d3);
        vector(450, 630, 1000, 1401, 1336, 1872, 34, 0, 0x3fab0839, 0x403e0923);
        // Float products round to exactly 20/40 before RectI rounding. Using
        // double products instead would incorrectly ceil the height to 41.
        vector(9, 18, 20, 40, 936, 1872, 234, 0, 0x423b3333, 0x42d00000);
        // First vector has one more bottom pixel: centering truncates, not rounds.
        SavedInkFitGeometry.Geometry g = fit(612, 792);
        equal(SavedInkFitGeometry.CANVAS_HEIGHT - g.offsetY - g.bitmapHeight,
                28, "bottom letterbox");
        // A direct continuous aspect-fit would silently change this stock CTM.
        check(Float.floatToIntBits(fit(450, 630).ctmScale)
                != Float.floatToIntBits(1872.0f / 630.0f), "not direct aspect fit");
        groups++;
    }

    private static void malformedBounds() {
        double[] invalid = {Double.NaN, Double.POSITIVE_INFINITY,
                Double.NEGATIVE_INFINITY};
        for (double value : invalid) {
            reject(value, 0, 612, 792, "nonfinite x0");
            reject(0, value, 612, 792, "nonfinite y0");
            reject(0, 0, value, 792, "nonfinite x1");
            reject(0, 0, 612, value, "nonfinite y1");
        }
        reject(0, 0, 612.5, 792, "fractional width");
        reject(0, 0, 612, 792.5, "fractional height");
        // Must not narrow doubles to floats before testing their integrality.
        reject(0, 0, Math.nextUp(612.0), 792, "width fractional below float ULP");
        reject(0, 0, 612, Math.nextDown(792.0), "height fractional below float ULP");
        reject(1, 0, 612, 792, "nonzero x origin");
        reject(0, -1, 612, 792, "nonzero y origin");
        reject(Double.MIN_VALUE, 0, 612, 792, "subnormal x origin");
        reject(0, Double.MIN_VALUE, 612, 792, "subnormal y origin");
        groups++;
    }

    private static void unsupportedBounds() {
        reject(0, 0, 792, 612, "landscape");
        reject(0, 0, 612, 612, "square");
        reject(0, 0, 0, 792, "zero width");
        reject(0, 0, 612, 0, "zero height");
        reject(0, 0, -612, 792, "negative width");
        reject(0, 0, 612, -792, "negative height");
        reject(0, 0, 1, SavedInkFitGeometry.MAX_PAGE_POINTS + 1.0, "over bound");
        reject(0, 0, 16777216, 16777217, "large float precision boundary");
        reject(0, 0, 612, Double.MAX_VALUE, "huge height");
        reject(0, 0, Double.MAX_VALUE, Double.MAX_VALUE, "huge bounds");
        // Valid input integers can still create a zero-width stock bitmap.
        reject(0, 0, 1, SavedInkFitGeometry.MAX_PAGE_POINTS, "degenerate fit");
        groups++;
    }

    private static void contained(SavedInkFitGeometry.Geometry g) {
        check(g.bitmapWidth >= 1 && g.bitmapHeight >= 1, "positive bitmap");
        check(g.offsetX >= 0 && g.offsetY >= 0, "nonnegative offsets");
        check(g.offsetX + g.bitmapWidth <= SavedInkFitGeometry.CANVAS_WIDTH,
                "horizontal containment");
        check(g.offsetY + g.bitmapHeight <= SavedInkFitGeometry.CANVAS_HEIGHT,
                "vertical containment");
        int right = SavedInkFitGeometry.CANVAS_WIDTH - g.offsetX - g.bitmapWidth;
        int bottom = SavedInkFitGeometry.CANVAS_HEIGHT - g.offsetY - g.bitmapHeight;
        check(right - g.offsetX == 0 || right - g.offsetX == 1,
                "integer horizontal centering");
        check(bottom - g.offsetY == 0 || bottom - g.offsetY == 1,
                "integer vertical centering");
        check(Float.isFinite(g.fitScale) && g.fitScale > 0, "positive finite fit");
        check(Float.isFinite(g.ctmScale) && g.ctmScale > 0, "positive finite CTM");
    }

    private static void boundedContainment() {
        int[][] boundaries = {{1, 2}, {1, 3}, {72, 144}, {225, 450},
                {612, 793}, {1000, 1001}, {1404, 1872}, {8192, 16384},
                {16383, 16384}};
        for (int[] bounds : boundaries) contained(fit(bounds[0], bounds[1]));
        Random random = new Random(0x8008L);
        for (int i = 0; i < 48; i++) {
            int width = 64 + random.nextInt(8000);
            int height = width + 1
                    + random.nextInt(SavedInkFitGeometry.MAX_PAGE_POINTS - width);
            contained(fit(width, height));
        }
        groups++;
    }

    private static void independentResults() {
        SavedInkFitGeometry.Geometry first = fit(612, 792);
        SavedInkFitGeometry.Geometry other = fit(450, 630);
        SavedInkFitGeometry.Geometry again = fit(612, 792);
        check(first != again && first != other, "no mutable/shared result");
        equal(first.bitmapHeight, 1817, "prior result remains unchanged");
        equal(again.bitmapHeight, 1817, "repeat result remains exact");
        bits(again.ctmScale, 0x4012d2d3, "repeat CTM bits");
        groups++;
    }

    public static void main(String[] args) {
        knownVectors();
        malformedBounds();
        unsupportedBounds();
        boundedContainment();
        independentResults();
        System.out.println("PASS: " + groups + " groups, " + checks
                + " checks; restricted portrait arithmetic only, no hardware/ink pass");
    }
}
"""


def java_tools(jdk_home: Path | None) -> tuple[str, str]:
    home = jdk_home or (Path(os.environ["JAVA_HOME"]) if os.environ.get("JAVA_HOME") else None)
    if home:
        suffix = ".exe" if os.name == "nt" else ""
        javac, java = (str(home / "bin" / (name + suffix)) for name in ("javac", "java"))
    else:
        javac, java = shutil.which("javac"), shutil.which("java")
    if not javac or not java:
        raise RuntimeError("JDK 17 javac/java are required (PATH, JAVA_HOME or --jdk-home)")
    for executable in (javac, java):
        result = subprocess.run([executable, "-version"], capture_output=True,
                                text=True, timeout=10, check=True)
        if not re.search(r"(?:javac\s+|version\s+\")17(?:[.\s\"]|$)",
                         result.stdout + result.stderr):
            raise RuntimeError(f"Expected JDK 17: {result.stdout}{result.stderr}")
    return javac, java


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path, nargs="?", default=Path(__file__).resolve().parents[1])
    parser.add_argument("--jdk-home", type=Path)
    args = parser.parse_args()
    template = args.root.resolve() / "native" / "SavedInkFitGeometry.java.template"
    source = template.read_text(encoding="utf-8")
    marker = "package __PACKAGE__;"
    if source.count(marker) != 1:
        raise RuntimeError("Expected exactly one Java template package marker")
    javac, java = java_tools(args.jdk_home)
    with tempfile.TemporaryDirectory(prefix="rtl-saved-ink-fit-") as folder:
        temp = Path(folder)
        helper = temp / "SavedInkFitGeometry.java"
        harness = temp / "SavedInkFitGeometryTest.java"
        classes = temp / "classes"
        helper.write_text(source.replace(marker, "package fitgeometrytest;"), encoding="utf-8")
        harness.write_text(HARNESS, encoding="utf-8")
        classes.mkdir()
        subprocess.run([javac, "--release", "8", "-encoding", "UTF-8", "-d", str(classes),
                        str(helper), str(harness)], cwd=temp, check=True, timeout=30)
        subprocess.run([java, "-ea", "-cp", str(classes),
                        "fitgeometrytest.SavedInkFitGeometryTest"],
                       cwd=temp, check=True, timeout=30)


if __name__ == "__main__":
    main()
