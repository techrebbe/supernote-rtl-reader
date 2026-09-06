"""Regression guard for the intentionally display-only experiment boundary.

Mechanical negative checks supplement review, not an Android lifecycle test.
"""
from pathlib import Path
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).parent
ANDROID = "{http://schemas.android.com/apk/res/android}"


class DisplayScopeTest(unittest.TestCase):
    def test_manifest_has_no_permission_or_reader_hook(self):
        manifest = ET.parse(ROOT / "display-host/AndroidManifest.xml").getroot()
        self.assertEqual(manifest.attrib["package"], "com.techrebbe.supernote.viewportdisplayprobe")
        self.assertFalse(manifest.findall("uses-permission"))
        app = manifest.find("application")
        self.assertEqual(app.attrib[ANDROID + "allowBackup"], "false")
        self.assertFalse(app.findall("meta-data"))
        self.assertFalse(app.findall("service"))
        self.assertFalse(app.findall("receiver"))
        self.assertFalse(app.findall("provider"))
        activities = app.findall("activity")
        self.assertEqual(len(activities), 2)
        self.assertEqual([a.attrib[ANDROID + "name"] for a in activities if a.attrib[ANDROID + "exported"] == "true"],
                         [".DisplayProbeActivity"])

    def test_no_app_launch_and_checked_root_calibration_attachment(self):
        source = "\n".join(p.read_text(encoding="utf-8") for p in (ROOT / "display-host/src").rglob("*.java"))
        self.assertEqual(source.count("new Intent("), 0)
        self.assertNotIn("startActivity(", source)
        self.assertIn("WAIT_ROOT_CALIBRATION", source)
        for forbidden in ("Runtime.getRuntime", "ProcessBuilder", "Xposed", "System.loadLibrary",
                          "injectInputEvent", "getFilePageTrails", "saveMarkData", "setComponent(",
                          "setClassName(", "sendAddressRecognitionMode", "getContentResolver("):
            self.assertNotIn(forbidden, source)
        self.assertIn("VIRTUAL_DISPLAY_FLAG_OWN_CONTENT_ONLY", source)
        self.assertNotIn("VIRTUAL_DISPLAY_FLAG_AUTO_MIRROR", source)
        self.assertNotIn("VIRTUAL_DISPLAY_FLAG_PRESENTATION", source)
        self.assertIn("actual != expected", source)
        self.assertIn("pen-ready=false", source)
        self.assertIn("generation == captured", source)
        self.assertIn("!DisplayProbeActivity.calibrationAttached(ownerInstance, actual)", source)
        self.assertIn("if (!ownsDisplay(instance, id)) return false;", source)
        self.assertIn("!activity.lifecycle.claimCalibration()", source)
        self.assertIn("if (admitted)", source)
        self.assertIn("if (current.get() == this) current.clear();", source)
        self.assertIn("DisplayProbeActivity.calibrationEnded(ownerInstance, actualDisplay)", source)
        self.assertIn("calibration ended; close and reopen probe to restart", source)
        self.assertIn("CalibrationActivity.closeOwned(instance)", source)
        self.assertIn("surface lost; restart display-only probe explicitly", source)
        self.assertIn("new DisplayProbeLifecycle(state != null)", source)
        self.assertIn("!lifecycle.canCreate()", source)
        self.assertIn("activity.lifecycle.isActive()", source)
        self.assertIn("onSaveInstanceState(Bundle state)", source)
        self.assertIn("controls.setVisibility(View.GONE)", source)
        self.assertIn("MotionEvent.ACTION_UP", source)


if __name__ == "__main__":
    unittest.main()
