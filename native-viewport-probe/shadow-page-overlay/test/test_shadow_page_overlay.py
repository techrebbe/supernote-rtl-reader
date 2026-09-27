"""Host-only, fail-closed scope checks for shadow-page-overlay-v1.

These are source and pure-Java checks. They cannot certify overlay permission,
touch pass-through, stock-reader coexistence, or rendering on a Supernote.
"""

from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path


MODULE = Path(__file__).resolve().parents[1]
SOURCE = MODULE / "src/com/techrebbe/supernote/shadowpageoverlay"
SERVICE = SOURCE / "ShadowPageOverlayService.java"
GEOMETRY = SOURCE / "ShadowPageGeometry.java"
GENERATION = SOURCE / "ShadowOverlayGeneration.java"
MANIFEST = MODULE / "AndroidManifest.xml"
BUILDER = MODULE / "build.ps1"
JAVA_TEST = Path(__file__).with_name("ShadowPageGeometryTest.java")
HOST_FIXTURE = (MODULE / "../../../../output/pdf/RTL_DISPLAY0_CAPTURE_20260927.pdf").resolve()
ANDROID = "{http://schemas.android.com/apk/res/android}"
FIXTURE_NAME = "RTL_DISPLAY0_CAPTURE_20260927.pdf"
FIXTURE_SHA256 = "28b126627dd5966e8975ae1bf48385d65e1f8189e8aa32ddc0eab778904859c9"


def without_java_comments(source: str) -> str:
    """Remove comments, preserving quoted literals and line offsets."""
    result: list[str] = []
    index = 0
    while index < len(source):
        pair = source[index:index + 2]
        if pair in ("//", "/*"):
            end = (source.find("\n", index + 2) if pair == "//"
                   else source.find("*/", index + 2))
            if end < 0:
                end = len(source)
            elif pair == "/*":
                end += 2
            comment = source[index:end]
            result.extend("\n" if character == "\n" else " " for character in comment)
            index = end
            continue
        if source[index] in ('"', "'"):
            quote = source[index]
            end = index + 1
            while end < len(source):
                if source[end] == "\\":
                    end += 2
                elif source[end] == quote:
                    end += 1
                    break
                else:
                    end += 1
            result.append(source[index:end])
            index = end
            continue
        result.append(source[index])
        index += 1
    return "".join(result)


class ShadowPageOverlayOfflineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.service = without_java_comments(SERVICE.read_text(encoding="utf-8"))
        cls.geometry = without_java_comments(GEOMETRY.read_text(encoding="utf-8"))
        cls.build = BUILDER.read_text(encoding="utf-8")

    def test_comment_scrubber_does_not_let_comment_only_markers_pass(self) -> None:
        sample = '/* FLAG_NOT_TOUCHABLE */ String s = "// true"; // openPage(0)\n'
        clean = without_java_comments(sample)
        self.assertNotIn("FLAG_NOT_TOUCHABLE", clean)
        self.assertNotIn("openPage(0)", clean)
        self.assertIn('"// true"', clean)

    def test_exact_three_java_source_files_and_no_bundled_document(self) -> None:
        self.assertEqual(
            {file.resolve() for file in SOURCE.rglob("*.java")},
            {SERVICE.resolve(), GEOMETRY.resolve(), GENERATION.resolve()},
        )
        self.assertFalse(list(MODULE.rglob("*.pdf")), "fixture must never enter APK source tree")
        self.assertFalse(list(MODULE.rglob("*.mark")), "no personal annotation data")
        self.assertFalse((MODULE / "assets").exists(), "no asset-based PDF substitute")

    def test_host_disposable_fixture_bytes_match_source_pin(self) -> None:
        self.assertTrue(HOST_FIXTURE.is_file(), "reviewed disposable host fixture missing")
        self.assertEqual(HOST_FIXTURE.stat().st_size, 2419)
        with HOST_FIXTURE.open("rb") as stream:
            payload = stream.read(2420)
        self.assertEqual(len(payload), 2419)
        self.assertEqual(hashlib.sha256(payload).hexdigest(), FIXTURE_SHA256)

    def test_manifest_is_one_overlay_service_with_no_storage_permission(self) -> None:
        manifest = ET.parse(MANIFEST).getroot()
        self.assertEqual(manifest.tag, "manifest")
        self.assertEqual(
            manifest.attrib.get("package"),
            "com.techrebbe.supernote.shadowpageoverlay",
        )
        permissions = [node.attrib.get(ANDROID + "name") for node in manifest
                       if node.tag.startswith("uses-permission")]
        self.assertEqual(permissions, ["android.permission.SYSTEM_ALERT_WINDOW"])
        app = manifest.find("application")
        self.assertIsNotNone(app)
        components = [node for node in app if node.tag in {
            "activity", "activity-alias", "service", "receiver", "provider"
        }]
        self.assertEqual([node.tag for node in components], ["service"])
        self.assertEqual(components[0].attrib.get(ANDROID + "name"),
                         ".ShadowPageOverlayService")
        self.assertEqual(components[0].attrib.get(ANDROID + "exported"), "true")
        self.assertEqual(components[0].attrib.get(ANDROID + "permission"),
                         "android.permission.DUMP")
        self.assertNotIn(ANDROID + "stopWithTask", components[0].attrib)
        self.assertEqual(app.attrib.get(ANDROID + "debuggable"), "true")
        self.assertEqual(app.attrib.get(ANDROID + "allowBackup"), "false")

    def test_window_is_exactly_nonfocusable_nontouchable_visual_overlay(self) -> None:
        source = self.service
        flag_names = set(re.findall(r"\b(?:WindowManager\.LayoutParams\.)?(FLAG_[A-Z_]+)\b", source))
        self.assertEqual(flag_names, {
            "FLAG_NOT_FOCUSABLE", "FLAG_NOT_TOUCHABLE", "FLAG_LAYOUT_IN_SCREEN",
        })
        self.assertIn("TYPE_APPLICATION_OVERLAY", source)
        self.assertNotRegex(source, r"\bTYPE_(?:ACCESSIBILITY_OVERLAY|SYSTEM_ALERT|PHONE)\b")
        self.assertIn("PixelFormat.OPAQUE", source)
        self.assertIn("Gravity.TOP", source)
        self.assertRegex(source, r"\bGravity\.(?:LEFT|START)\b")
        self.assertIn("ImageView", source)
        for forbidden in (
            r"\bonTouch(?:Event)?\s*\(", r"\bsetOnTouchListener\s*\(",
            r"\bonGenericMotionEvent\s*\(", r"\brequestFocus\s*\(",
            r"\bdispatchTouchEvent\s*\(", r"\binjectInputEvent\s*\(",
        ):
            self.assertNotRegex(source, forbidden)

    def test_no_stock_reader_pen_annotation_or_second_display_api(self) -> None:
        source = self.service + "\n" + self.geometry + "\n" + without_java_comments(
            GENERATION.read_text(encoding="utf-8"))
        forbidden = (
            r"\bVirtualDisplay\b", r"\bcreateVirtualDisplay\s*\(",
            r"\bPresentation\s*\(", r"\bstartActivity\s*\(",
            r"\bMotionEvent\b", r"\bInputManager\b",
            r"\bAccessibilityService\b", r"\bInstrumentation\b",
            r"\bset(?:Current|File|Document|Reader)?Page(?:Index|Number|Num)?\s*\(",
            r"\bsaveMarkData\s*\(", r"\bgetFilePageTrails\s*\(",
            r"\bsendAddressRecognitionMode\s*\(", r"\.\s*mark\b",
            r"\bcom\.supernote\.document\b", r"\bSystem\.loadLibrary\s*\(",
            r"\bget(?:String|Int|Long|Boolean|Parcelable|Serializable)Extra\s*\(",
            r"\bgetExtras\s*\(", r"\bgetClipData\s*\(",
        )
        for pattern in forbidden:
            with self.subTest(pattern=pattern):
                self.assertNotRegex(source, pattern)

    def test_only_fixed_modes_and_pinned_read_only_fixture(self) -> None:
        source = self.service
        for action in ("SHOW_FULL", "SHOW_LEFT", "SHOW_RIGHT", "TEARDOWN", "BASELINE"):
            self.assertIn(action, source)
        self.assertEqual(set(re.findall(r"\bACTION_[A-Z_]+\b", source)), {
            "ACTION_SHOW_FULL", "ACTION_SHOW_LEFT", "ACTION_SHOW_RIGHT",
            "ACTION_TEARDOWN", "ACTION_BASELINE",
        })
        action_dispatch = source[source.index("private static String modeForAction("):
                                 source.index("private void show(")]
        self.assertIn('if (ACTION_SHOW_FULL.equals(action)) return "FULL"', action_dispatch)
        self.assertIn('if (ACTION_SHOW_LEFT.equals(action)) return "LEFT"', action_dispatch)
        self.assertIn('if (ACTION_SHOW_RIGHT.equals(action)) return "RIGHT"', action_dispatch)
        self.assertNotIn("ACTION_TEARDOWN", action_dispatch)
        self.assertNotIn("ACTION_BASELINE", action_dispatch)
        self.assertRegex(action_dispatch, r"return\s+null\s*;")
        self.assertIn(FIXTURE_NAME, source)
        self.assertRegex(source, r"\bgetFilesDir\s*\(")
        self.assertIn("new File(getFilesDir(), FIXTURE_FILENAME)", source)
        self.assertRegex(source, r"ParcelFileDescriptor\.open\s*\(\s*fixture\s*,\s*"
                                 r"ParcelFileDescriptor\.MODE_READ_ONLY\s*\)")
        self.assertNotIn("/storage/emulated/", source)
        self.assertNotIn("Environment.getExternalStorage", source)
        self.assertNotIn("MediaStore", source)
        for forbidden_write in ("FileOutputStream", "RandomAccessFile", "openFileOutput(",
                                "Os.write(", "Files.write("):
            self.assertNotIn(forbidden_write, source)
        self.assertIn(FIXTURE_SHA256, source.lower())
        self.assertIn("MODE_READ_ONLY", source)
        self.assertIn("SHA-256", source)
        self.assertIn("PdfRenderer", source)
        show = source[source.index("private void show("):
                      source.index("private static void verifyRegularFixture(")]
        self.assertIn("StructStat pinnedPath = Os.lstat(fixture.getAbsolutePath())", show)
        self.assertEqual(show.count("verifyFixtureIdentity(fixture, pinnedPath, sourceDescriptor)"), 2)
        self.assertEqual(show.count("verifyOpenedBytes(sourceDescriptor)"), 2)
        self.assertIn("ParcelFileDescriptor.dup(sourceDescriptor.getFileDescriptor())", show)
        self.assertIn("new PdfRenderer(renderDescriptor)", show)
        self.assertLess(show.index("Os.lstat(fixture.getAbsolutePath())"),
                        show.index("ParcelFileDescriptor.open("))
        self.assertLess(show.index("verifyFixtureIdentity(fixture, pinnedPath, sourceDescriptor)"),
                        show.index("verifyOpenedBytes(sourceDescriptor)"))
        self.assertLess(show.index("verifyOpenedBytes(sourceDescriptor)"),
                        show.index("ParcelFileDescriptor.dup(sourceDescriptor.getFileDescriptor())"))
        self.assertLess(show.index("new PdfRenderer(renderDescriptor)"),
                        show.rindex("verifyOpenedBytes(sourceDescriptor)"))
        self.assertLess(show.rindex("verifyFixtureIdentity(fixture, pinnedPath, sourceDescriptor)"),
                        show.index("new ImageView(this)"))
        self.assertIn("Os.fstat(descriptor.getFileDescriptor())", source)
        self.assertIn("OsConstants.S_ISREG(stat.st_mode)", source)
        self.assertIn("pathNow.st_dev != pinnedPath.st_dev", source)
        self.assertIn("pathNow.st_ino != pinnedPath.st_ino", source)
        self.assertIn("opened.st_dev != pinnedPath.st_dev", source)
        self.assertIn("opened.st_ino != pinnedPath.st_ino", source)
        self.assertIn("Os.read(descriptor.getFileDescriptor()", source)
        self.assertGreaterEqual(source.count("Os.lseek(descriptor.getFileDescriptor()"), 2)
        self.assertIn("FIXTURE_SHA256.equals(hex(digest.digest()))", source)
        self.assertIn("renderer.getPageCount() != FIXTURE_PAGE_COUNT", source)
        self.assertIn("SOURCE_PAGE_INDEX = 0", source)
        self.assertRegex(source, r"\.openPage\s*\(\s*SOURCE_PAGE_INDEX\s*\)")
        self.assertNotRegex(source, r"\.openPage\s*\(\s*[1-9][0-9]*\s*\)")
        self.assertIn("FIXTURE_BYTES = 2419L", source)
        self.assertIn("FIXTURE_PAGE_COUNT = 2", source)
        self.assertIn("SOURCE_PAGE_WIDTH = 612", source)
        self.assertIn("SOURCE_PAGE_HEIGHT = 792", source)
        self.assertIn("page.getWidth() != SOURCE_PAGE_WIDTH", source)
        self.assertIn("page.getHeight() != SOURCE_PAGE_HEIGHT", source)
        self.assertIn("CANVAS_WIDTH = 1404", self.geometry)
        self.assertIn("CANVAS_HEIGHT = 1872", self.geometry)
        self.assertIn("Color.WHITE", source)
        self.assertIn("Math.min", source)
        self.assertIn(FIXTURE_NAME, self.build)
        self.assertIn(FIXTURE_SHA256, self.build.lower())
        self.assertNotRegex(self.build, r"(?i)\b(?:Copy-Item|Move-Item)\b")

    def test_builder_is_offline_and_checks_source_inventory(self) -> None:
        build = "\n".join(line.split("#", 1)[0] for line in self.build.splitlines())
        self.assertIn("Compare-Object", build)
        self.assertIn("ShadowPageGeometry.java", build)
        self.assertIn("ShadowPageOverlayService.java", build)
        self.assertIn("ShadowOverlayGeneration.java", build)
        self.assertIn("Get-FileHash", build)
        self.assertIn("$expectedFixtureBytes=2419L", build)
        self.assertNotRegex(build, r"(?im)^\s*(?:&\s*)?\$?(?:adb|appops|apksigner|"
                                   r"install|startservice|push|Start-Process|Invoke-Expression)\b")

    def test_owned_window_and_resources_have_teardown_paths(self) -> None:
        source = self.service
        start = source[source.index("onStartCommand("):
                       source.index("private static String modeForAction(")]
        self.assertIn("removeOwnedOverlay()", start)
        self.assertLess(start.index("removeOwnedOverlay()"), start.index("if (mode == null)"))
        self.assertRegex(source, r"\bonDestroy\s*\(")
        self.assertRegex(source, r"\bremoveView(?:Immediate)?\s*\(")
        self.assertRegex(source, r"\bstopSelfResult\s*\(")
        self.assertRegex(source, r"\brecycle\s*\(")
        self.assertLess(source.index("ownedBitmap = bitmap"), source.index("new ImageView(this)"))
        self.assertLess(source.index("ownedView = view"), source.index("manager.addView(view, params)"))
        self.assertIn("ViewTreeObserver.OnGlobalLayoutListener", source)
        self.assertIn("addOnGlobalLayoutListener(frameListener)", source)
        self.assertIn("removeOnGlobalLayoutListener(frameListener)", source)
        self.assertNotRegex(source, r"\bview\.post\s*\(")
        self.assertIn("if (!generation.owns(expected, expectedGeneration)) return", source)
        self.assertIn("display.getDisplayId() != Display.DEFAULT_DISPLAY", source)
        self.assertIn("failFrame(expected, startId, expectedGeneration)", source)
        start_fail = source[source.index("} catch (IOException | ErrnoException | RuntimeException failure)"):
                            source.index("private static String modeForAction(")]
        self.assertIn("removeOwnedOverlay()", start_fail)
        self.assertIn("stopSelfResult(startId)", start_fail)
        self.assertRegex(source, r"try\s*\(\s*ParcelFileDescriptor\b")
        self.assertRegex(source, r"try\s*\(\s*PdfRenderer\b")
        self.assertRegex(source, r"try\s*\(\s*PdfRenderer\.Page\b")
        self.assertNotIn("onTaskRemoved(", source)
        for callback in ("onConfigurationChanged", "onDestroy"):
            body = source[source.index(callback + "("):]
            self.assertIn("removeOwnedOverlay()", body.split("}", 1)[0])

    def test_visible_overlay_has_bounded_generation_fenced_lifetime(self) -> None:
        source = self.service
        self.assertIn("MAX_OVERLAY_LIFETIME_MS = 30_000L", source)
        self.assertIn("new ShadowOverlayGeneration()", source)
        self.assertIn("admittedGeneration = generation.begin(view)", source)
        self.assertRegex(source, r"\bmain\.postDelayed\s*\(\s*lifetimeTimeout\s*,\s*"
                                 r"MAX_OVERLAY_LIFETIME_MS\s*\)")
        self.assertLess(source.index("manager.addView(view, params)"),
                        source.index("main.postDelayed(lifetimeTimeout, MAX_OVERLAY_LIFETIME_MS)"))
        self.assertRegex(source, r"if\s*\(\s*!main\.postDelayed\s*\(")
        self.assertIn('throw new IllegalStateException("could not arm bounded overlay lifetime")',
                      source)

        timeout = source[source.index("lifetimeTimeout = () -> {"):
                         source.index("};", source.index("lifetimeTimeout = () -> {"))]
        guard = "if (!generation.owns(view, admittedGeneration)) return"
        self.assertIn(guard, timeout)
        self.assertLess(timeout.index(guard), timeout.index("removeOwnedOverlay()"))
        self.assertLess(timeout.index("removeOwnedOverlay()"),
                        timeout.index("stopSelfResult(startId)"))

        teardown = source[source.index("private void removeOwnedOverlay()"):
                          source.index("private void clearFrameListener()")]
        self.assertLess(teardown.index("generation.clear()"),
                        teardown.index("main.removeCallbacks(lifetimeTimeout)"))
        self.assertLess(teardown.index("main.removeCallbacks(lifetimeTimeout)"),
                        teardown.index("windowManager.removeViewImmediate(view)"))
        self.assertIn("clearFrameListener()", teardown)

        listener = source[source.index("frameListener = () -> {"):
                          source.index("};", source.index("frameListener = () -> {"))]
        self.assertIn(guard, listener)
        self.assertLess(listener.index(guard), listener.index("clearFrameListener()"))
        self.assertLess(listener.index("clearFrameListener()"),
                        listener.index("verifyAttachedFrameOrTeardown"))

        # The timeout is only an emergency bound; the explicit caller command
        # remains a distinct documented action with immediate removal.
        self.assertIn("ACTION_TEARDOWN", source)
        on_start = source[source.index("onStartCommand("):
                          source.index("private static String modeForAction(")]
        self.assertLess(on_start.index("removeOwnedOverlay()"),
                        on_start.index("if (mode == null)"))

    def test_geometry_runs_on_host_without_android_or_device(self) -> None:
        javac = shutil.which("javac")
        java = shutil.which("java")
        self.assertIsNotNone(javac, "JDK required for deterministic geometry test")
        self.assertIsNotNone(java, "JDK required for deterministic geometry test")
        with tempfile.TemporaryDirectory(prefix="shadow-geometry-") as classes:
            compile_result = subprocess.run(
                [javac, "-encoding", "UTF-8", "--release", "8", "-d", classes,
                 str(GEOMETRY), str(GENERATION), str(JAVA_TEST)],
                capture_output=True, text=True, timeout=30, check=False,
            )
            self.assertEqual(compile_result.returncode, 0,
                             compile_result.stdout + compile_result.stderr)
            run_result = subprocess.run(
                [java, "-cp", classes, "ShadowPageGeometryTest"],
                capture_output=True, text=True, timeout=30, check=False,
            )
            self.assertEqual(run_result.returncode, 0,
                             run_result.stdout + run_result.stderr)
            self.assertIn("shadow geometry checks (host only)", run_result.stdout)


if __name__ == "__main__":
    unittest.main()
