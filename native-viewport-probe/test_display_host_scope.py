"""Regression guard for the intentionally display-only experiment boundary.

Mechanical negative checks supplement review.  The pure-Java lifecycle seam is
executed on the host; Android framework callback delivery remains a hardware gate.
"""
from pathlib import Path
import argparse
import base64
import ctypes
import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

import inspect_loader_dependencies as bounded
import inspect_loader_bindings as publication

ROOT = Path(__file__).parent
ANDROID = "{http://schemas.android.com/apk/res/android}"
PACKAGE = "com.techrebbe.supernote.viewportdisplayprobe"
MAX_PERMISSION_EVIDENCE = 4 * 1024 * 1024
MAX_WINDOWS_AAPT_SNAPSHOT_PATH = 200
VALID_PERMISSION_BYTES = ("package: " + PACKAGE + "\n").encode("ascii")
VALID_XMLTREE_BYTES = b"""N: android=http://schemas.android.com/apk/res/android
  E: manifest (line=2)
    A: android:versionCode(0x0101021b)=(type 0x10)0x2
    A: android:versionName(0x0101021c)=\"0.0.2-display-only\" (Raw: \"0.0.2-display-only\")
    A: android:compileSdkVersion(0x01010572)=(type 0x10)0x23
    A: android:compileSdkVersionCodename(0x01010573)=\"15\" (Raw: \"15\")
    A: package=\"com.techrebbe.supernote.viewportdisplayprobe\" (Raw: \"com.techrebbe.supernote.viewportdisplayprobe\")
    A: platformBuildVersionCode=(type 0x10)0x23 (Raw: \"35\")
    A: platformBuildVersionName=(type 0x10)0xf (Raw: \"15\")
    E: uses-sdk (line=5)
      A: android:minSdkVersion(0x0101020c)=(type 0x10)0x1e
      A: android:targetSdkVersion(0x01010270)=(type 0x10)0x1e
    E: application (line=7)
      A: android:theme(0x01010000)=@0x01030241
      A: android:label(0x01010001)=\"Native Viewport Display Probe\" (Raw: \"Native Viewport Display Probe\")
      A: android:allowBackup(0x01010280)=(type 0x12)0x0
      A: android:supportsRtl(0x010103af)=(type 0x12)0x0
      A: android:usesCleartextTraffic(0x010104ec)=(type 0x12)0x0
      E: activity (line=10)
        A: android:name(0x01010003)=\".DisplayProbeActivity\" (Raw: \".DisplayProbeActivity\")
        A: android:exported(0x01010010)=(type 0x12)0xffffffff
        A: android:launchMode(0x0101001d)=(type 0x10)0x2
        A: android:configChanges(0x0101001f)=(type 0x11)0x1d80
        A: android:resizeableActivity(0x010104f6)=(type 0x12)0xffffffff
        E: intent-filter (line=13)
          E: action (line=14)
            A: android:name(0x01010003)=\"android.intent.action.MAIN\" (Raw: \"android.intent.action.MAIN\")
          E: category (line=15)
            A: android:name(0x01010003)=\"android.intent.category.LAUNCHER\" (Raw: \"android.intent.category.LAUNCHER\")
      E: activity (line=18)
        A: android:name(0x01010003)=\".CalibrationActivity\" (Raw: \".CalibrationActivity\")
        A: android:exported(0x01010010)=(type 0x12)0x0
        A: android:taskAffinity(0x01010012)=\"com.techrebbe.supernote.viewportdisplayprobe.calibration\" (Raw: \"com.techrebbe.supernote.viewportdisplayprobe.calibration\")
        A: android:configChanges(0x0101001f)=(type 0x11)0x1d80
        A: android:resizeableActivity(0x010104f6)=(type 0x12)0xffffffff
"""


class PackagedPermissionError(ValueError):
    pass


def _normalize_packaged_paths(paths):
    if type(paths) not in (list, tuple) or len(paths) != 3:
        raise PackagedPermissionError("packaged evidence needs exactly three outputs")
    normalized = tuple(Path(path).absolute() for path in paths)
    for path in normalized:
        name = path.name
        if (name in ("", ".", "..") or "/" in name or "\\" in name or
                "\0" in name or (os.name == "nt" and ":" in name)):
            raise PackagedPermissionError("invalid packaged evidence output name")
    if (len(set(normalized)) != 3 or
            len({path.parent for path in normalized}) != 1):
        raise PackagedPermissionError(
            "packaged evidence outputs need one parent and distinct names")
    return normalized


def _packaged_authority_bytes(apk_digest, permissions, xmltree):
    if (not isinstance(apk_digest, str) or
            re.fullmatch(r"[0-9a-f]{64}", apk_digest) is None):
        raise PackagedPermissionError("invalid packaged APK digest")
    return json.dumps({
        "schema": "native-viewport-packaged-scope-v1",
        "apkSha256": apk_digest,
        "permissionsSha256": hashlib.sha256(permissions).hexdigest(),
        "xmltreeSha256": hashlib.sha256(xmltree).hexdigest(),
        "permissionsEmpty": True,
    }, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"


def _packaged_fixture_entries(parent):
    parent = Path(parent)
    authority = _packaged_authority_bytes(
        "0" * 64, VALID_PERMISSION_BYTES, VALID_XMLTREE_BYTES)
    return (
        (parent / "permissions.txt", VALID_PERMISSION_BYTES),
        (parent / "manifest-xmltree.txt", VALID_XMLTREE_BYTES),
        (parent / "packaged-scope-authority.json", authority),
    )


def _unique_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise PackagedPermissionError("duplicate packaged authority field")
        result[key] = value
    return result


def verify_packaged_evidence(paths):
    """Accept the set only when its last-committed authority authenticates it."""
    permissions_path, xmltree_path, authority_path = _normalize_packaged_paths(paths)
    try:
        with bounded.EvidenceDirectory(authority_path.parent) as directory:
            # Authority is opened first.  A crash after either data commit is
            # therefore an unambiguously incomplete, rejected generation.
            authority_raw = directory.read(
                authority_path.name, MAX_PERMISSION_EVIDENCE)
            permissions = directory.read(
                permissions_path.name, MAX_PERMISSION_EVIDENCE)
            xmltree = directory.read(xmltree_path.name, MAX_PERMISSION_EVIDENCE)
            # Detect any change between authentication and use as well as each
            # individual retained-read identity check performed above.
            if (directory.read(authority_path.name, MAX_PERMISSION_EVIDENCE) != authority_raw or
                    directory.read(permissions_path.name, MAX_PERMISSION_EVIDENCE) != permissions or
                    directory.read(xmltree_path.name, MAX_PERMISSION_EVIDENCE) != xmltree):
                raise PackagedPermissionError("packaged evidence changed during verification")
    except (bounded.InventoryError, OSError) as error:
        raise PackagedPermissionError("incomplete packaged evidence generation") from error
    if (not authority_raw.endswith(b"\n") or authority_raw.count(b"\n") != 1 or
            b"\r" in authority_raw):
        raise PackagedPermissionError("packaged authority is not one LF-terminated record")
    try:
        authority = json.loads(authority_raw[:-1].decode("ascii"),
                               object_pairs_hook=_unique_json_object)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise PackagedPermissionError("invalid packaged authority encoding") from error
    expected_keys = {
        "schema", "apkSha256", "permissionsSha256", "xmltreeSha256",
        "permissionsEmpty",
    }
    if (type(authority) is not dict or set(authority) != expected_keys or
            authority["schema"] != "native-viewport-packaged-scope-v1" or
            authority["permissionsEmpty"] is not True or
            any(type(authority[key]) is not str or
                re.fullmatch(r"[0-9a-f]{64}", authority[key]) is None
                for key in ("apkSha256", "permissionsSha256", "xmltreeSha256")) or
            hashlib.sha256(permissions).hexdigest() != authority["permissionsSha256"] or
            hashlib.sha256(xmltree).hexdigest() != authority["xmltreeSha256"]):
        raise PackagedPermissionError("packaged authority does not authenticate evidence")
    verify_permissions(_decode_aapt_evidence(permissions, "permissions"),
                       _decode_aapt_evidence(xmltree, "xmltree"))
    return authority


def verify_packaged_bundle(apk, paths, on_verified=None):
    """Bind the retained final APK bytes to their authenticated evidence set."""
    apk = Path(apk).absolute()
    if (apk.name in ("", ".", "..") or "/" in apk.name or "\\" in apk.name or
            "\0" in apk.name or (os.name == "nt" and ":" in apk.name)):
        raise PackagedPermissionError("invalid packaged APK name")
    try:
        with _PinnedSourceApk(apk) as source:
            apk_digest = hashlib.sha256(source.payload).hexdigest()
            authority = verify_packaged_evidence(paths)
            # Evidence verification can be arbitrarily slow and reads three
            # independent names. Re-prove the retained APK/name only after it
            # completes, before accepting the digest binding.
            source.verify(apk_digest)
            if authority["apkSha256"] != apk_digest:
                raise PackagedPermissionError(
                    "packaged authority authenticates another APK")
            source_authority = source.authority_token
    except PackagedPermissionError:
        raise
    except (bounded.InventoryError, OSError) as error:
        raise PackagedPermissionError("packaged APK authority is unavailable") from error
    # Re-open the ultimately reported name only after evidence verification has
    # completed.  Bind that fresh name to both the authenticated bytes and the
    # exact filesystem object observed above, so a same-content name ABA during
    # the context-exit window cannot inherit the earlier authority.
    try:
        _rebind_packaged_apk(
            apk, apk_digest, source_authority, on_verified=on_verified)
    except PackagedPermissionError:
        raise
    except (bounded.InventoryError, OSError) as error:
        raise PackagedPermissionError(
            "packaged APK final-name authority is unavailable") from error
    return authority


def _rebind_packaged_apk(apk, expected_digest, expected_authority,
                         on_verified=None):
    if on_verified is not None and not callable(on_verified):
        raise PackagedPermissionError("invalid final APK verifier callback")
    with _PinnedSourceApk(apk) as rebound:
        if rebound.authority_token != expected_authority:
            raise PackagedPermissionError(
                "packaged APK authority changed after evidence verification")
        digest = hashlib.sha256(rebound.payload).hexdigest()
        if digest != expected_digest:
            raise PackagedPermissionError(
                "packaged APK changed after evidence verification")
        rebound.verify(expected_digest)
        # Build reporting happens while this final-name authority is retained.
        # A final recheck makes a callback-side or concurrent POSIX name change
        # a failed process even if the callback already emitted its record.
        if on_verified is not None:
            on_verified(expected_digest)
            rebound.verify(expected_digest)
    return expected_digest


_WINDOWS_CRASH_PUBLICATION_HELPER = r"""
import base64
import hashlib
import json
import os
from pathlib import Path
import sys
import types

parent = Path(sys.argv[1])
boundary = int(sys.argv[2])
wire = sys.stdin.buffer.read(4 * 1024 * 1024 + 1)
if len(wire) > 4 * 1024 * 1024:
    os._exit(64)
try:
    bundle = json.loads(wire.decode("ascii"))
    if (type(bundle) is not dict or set(bundle) != {"schema", "modules", "entries"}
            or bundle["schema"] != "native-viewport-crash-source-v1"
            or type(bundle["modules"]) is not list or len(bundle["modules"]) != 2
            or type(bundle["entries"]) is not list or len(bundle["entries"]) != 3):
        raise ValueError("invalid bundle")
    loaded = {}
    for record in bundle["modules"]:
        if (type(record) is not dict or set(record) != {"name", "sha256", "source"}
                or record["name"] not in (
                    "inspect_loader_dependencies", "inspect_loader_bindings")
                or record["name"] in loaded):
            raise ValueError("invalid module")
        source = base64.b64decode(record["source"], validate=True)
        if hashlib.sha256(source).hexdigest() != record["sha256"]:
            raise ValueError("source digest mismatch")
        module = types.ModuleType(record["name"])
        module.__file__ = "<authenticated-captured-" + record["name"] + ">"
        module.__package__ = ""
        sys.modules[record["name"]] = module
        exec(compile(source, module.__file__, "exec", dont_inherit=True),
             module.__dict__)
        loaded[record["name"]] = module
    publication = loaded["inspect_loader_bindings"]
    entries = []
    for record in bundle["entries"]:
        if (type(record) is not dict or set(record) != {"name", "payload"}
                or type(record["name"]) is not str):
            raise ValueError("invalid entry")
        entries.append((parent / record["name"],
                        base64.b64decode(record["payload"], validate=True)))
except Exception:
    os._exit(65)
if boundary not in (1, 2, 3):
    os._exit(66)

# Exercise the exact production Windows authority, private-stage, and terminal
# no-replace commit implementations from the authenticated parent snapshot.
authorities = publication._windows_authority_chain(parent)
authority = authorities[-1]
stages = [publication.stage_bytes(payload, path, None, authority)
          for path, payload in entries]
for index, staged in enumerate(stages, 1):
    publication.commit_report(staged)
    if index == boundary:
        os._exit(70 + boundary)
os._exit(99)
"""


_TERMINAL_SUCCESS_PUBLICATION_HELPER = r"""
import hashlib
import os
from pathlib import Path
import sys
import types

def exact(stream, count):
    chunks = []
    while count:
        chunk = stream.read(count)
        if not chunk:
            raise ValueError("truncated source frame")
        chunks.append(chunk)
        count -= len(chunk)
    return b"".join(chunks)

try:
    names = ("inspect_loader_dependencies", "inspect_loader_bindings",
             "test_display_host_scope")
    if len(sys.argv) != 5:
        raise ValueError("invalid source authority")
    stream = sys.stdin.buffer
    loaded = {}
    for name, expected in zip(names, sys.argv[2:]):
        size = int.from_bytes(exact(stream, 8), "big")
        if size <= 0 or size > 2 * 1024 * 1024:
            raise ValueError("invalid source frame size")
        source = exact(stream, size)
        if hashlib.sha256(source).hexdigest() != expected:
            raise ValueError("source digest mismatch")
        module = types.ModuleType(name)
        module.__file__ = "<authenticated-captured-" + name + ">"
        module.__package__ = ""
        sys.modules[name] = module
        exec(compile(source, module.__file__, "exec", dont_inherit=True),
             module.__dict__)
        loaded[name] = module
    if stream.read(1):
        raise ValueError("trailing source frame bytes")
except Exception:
    os._exit(64)

scope = loaded["test_display_host_scope"]
root = Path(sys.argv[1])
entries = scope._packaged_fixture_entries(root)
scope.publish_packaged_evidence(entries)
scope.verify_packaged_evidence(tuple(path for path, _ in entries))
scope._report_terminal_success("PACKAGED_PERMISSION_SURFACES_EMPTY")
"""


def _captured_production_source(module):
    """Return the authenticated in-memory source, with a standalone fallback."""
    loader = getattr(getattr(module, "__spec__", None), "loader", None)
    current_loader = getattr(
        getattr(sys.modules.get(__name__), "__spec__", None), "loader", None)
    authority = getattr(current_loader, "authority_sha256", None)
    if authority is not None:
        raw = getattr(loader, "raw", None)
        if getattr(loader, "authority_sha256", None) != authority:
            raise PackagedPermissionError(
                "captured production source escaped authenticated authority")
    else:
        # Direct developer runs do not use the aggregate authenticated loader.
        # Capture through the bounded descriptor reader before the subprocess;
        # the subprocess itself never resolves or imports a project pathname.
        path = Path(module.__file__).absolute()
        raw = bounded.read_bounded(path, 2 * 1024 * 1024)
    if type(raw) is not bytes or not raw or len(raw) > 2 * 1024 * 1024:
        raise PackagedPermissionError("invalid captured production source")
    return raw


def _windows_crash_publication_bundle(entries):
    modules = []
    for name, module in (("inspect_loader_dependencies", bounded),
                         ("inspect_loader_bindings", publication)):
        source = _captured_production_source(module)
        modules.append({
            "name": name,
            "sha256": hashlib.sha256(source).hexdigest(),
            "source": base64.b64encode(source).decode("ascii"),
        })
    return json.dumps({
        "schema": "native-viewport-crash-source-v1",
        "modules": modules,
        "entries": [{
            "name": path.name,
            "payload": base64.b64encode(payload).decode("ascii"),
        } for path, payload in entries],
    }, sort_keys=True, separators=(",", ":")).encode("ascii")


def verify_permissions(permission_dump: str, xmltree_dump: str) -> None:
    if type(permission_dump) is not str or type(xmltree_dump) is not str:
        raise PackagedPermissionError("permission evidence must be text")
    permission_lines = permission_dump.splitlines()
    if permission_lines != ["package: " + PACKAGE]:
        raise PackagedPermissionError("permission table root/package is missing or malformed")
    patterns = (
        r"N: android=http://schemas\.android\.com/apk/res/android",
        r"  E: manifest \(line=2\)",
        r"    A: android:versionCode\(0x0101021b\)=\(type 0x10\)0x2",
        r'    A: android:versionName\(0x0101021c\)="0\.0\.2-display-only" \(Raw: "0\.0\.2-display-only"\)',
        r"    A: android:compileSdkVersion\(0x01010572\)=\(type 0x10\)0x23",
        r'    A: android:compileSdkVersionCodename\(0x01010573\)="15" \(Raw: "15"\)',
        r'    A: package="' + re.escape(PACKAGE) + r'" \(Raw: "' + re.escape(PACKAGE) + r'"\)',
        r'    A: platformBuildVersionCode=\(type 0x10\)0x23 \(Raw: "35"\)',
        r'    A: platformBuildVersionName=\(type 0x10\)0xf \(Raw: "15"\)',
        r"    E: uses-sdk \(line=5\)",
        r"      A: android:minSdkVersion\(0x0101020c\)=\(type 0x10\)0x1e",
        r"      A: android:targetSdkVersion\(0x01010270\)=\(type 0x10\)0x1e",
        r"    E: application \(line=7\)",
        r"      A: android:theme\(0x01010000\)=@0x01030241",
        r'      A: android:label\(0x01010001\)="Native Viewport Display Probe" \(Raw: "Native Viewport Display Probe"\)',
        r"      A: android:allowBackup\(0x01010280\)=\(type 0x12\)0x0",
        r"      A: android:supportsRtl\(0x010103af\)=\(type 0x12\)0x0",
        r"      A: android:usesCleartextTraffic\(0x010104ec\)=\(type 0x12\)0x0",
        r"      E: activity \(line=10\)",
        r'        A: android:name\(0x01010003\)="\.DisplayProbeActivity" \(Raw: "\.DisplayProbeActivity"\)',
        r"        A: android:exported\(0x01010010\)=\(type 0x12\)0xffffffff",
        r"        A: android:launchMode\(0x0101001d\)=\(type 0x10\)0x2",
        r"        A: android:configChanges\(0x0101001f\)=\(type 0x11\)0x1d80",
        r"        A: android:resizeableActivity\(0x010104f6\)=\(type 0x12\)0xffffffff",
        r"        E: intent-filter \(line=13\)",
        r"          E: action \(line=14\)",
        r'            A: android:name\(0x01010003\)="android\.intent\.action\.MAIN" \(Raw: "android\.intent\.action\.MAIN"\)',
        r"          E: category \(line=15\)",
        r'            A: android:name\(0x01010003\)="android\.intent\.category\.LAUNCHER" \(Raw: "android\.intent\.category\.LAUNCHER"\)',
        r"      E: activity \(line=18\)",
        r'        A: android:name\(0x01010003\)="\.CalibrationActivity" \(Raw: "\.CalibrationActivity"\)',
        r"        A: android:exported\(0x01010010\)=\(type 0x12\)0x0",
        r'        A: android:taskAffinity\(0x01010012\)="' + re.escape(PACKAGE) + r'\.calibration" \(Raw: "' + re.escape(PACKAGE) + r'\.calibration"\)',
        r"        A: android:configChanges\(0x0101001f\)=\(type 0x11\)0x1d80",
        r"        A: android:resizeableActivity\(0x010104f6\)=\(type 0x12\)0xffffffff",
    )
    lines = xmltree_dump.splitlines()
    if len(lines) != len(patterns) or any(
            re.fullmatch(pattern, line) is None for pattern, line in zip(patterns, lines)):
        raise PackagedPermissionError("binary manifest grammar/hierarchy/attributes are not exact")


def _apk_digest(path: Path) -> str:
    return hashlib.sha256(bounded.read_bounded(path, 64 * 1024 * 1024)).hexdigest()


def _stage_evidence_bytes(path, payload, authority):
    if type(payload) is not bytes or not payload:
        raise PackagedPermissionError("empty packaged evidence output")
    path=Path(path).absolute()
    descriptor=None; handle=None; name=None
    if os.name == "posix":
        anonymous=getattr(os,"O_TMPFILE",0)
        if not anonymous:
            raise PackagedPermissionError("anonymous packaged-evidence staging unavailable")
        descriptor=os.open(".",os.O_RDWR|os.O_CLOEXEC|anonymous,0o600,
                           dir_fd=authority.directory)
        staged=publication.StagedReport(path,descriptor=descriptor,
                                        authority=authority,authorities=[])
        try:
            at=0
            while at<len(payload):
                written=os.write(descriptor,payload[at:at+65536])
                if written<=0: raise PackagedPermissionError("short evidence stage write")
                at+=written
            os.fsync(descriptor)
            os.fchmod(descriptor,stat.S_IRUSR)
            readonly=os.open(f"/proc/self/fd/{descriptor}",os.O_RDONLY|os.O_CLOEXEC)
            opened,reopened=os.fstat(descriptor),os.fstat(readonly)
            if ((opened.st_dev,opened.st_ino,opened.st_size) !=
                    (reopened.st_dev,reopened.st_ino,reopened.st_size)):
                os.close(readonly)
                raise PackagedPermissionError("evidence stage reopen mismatch")
            os.close(descriptor); descriptor=None
            staged.descriptor=readonly
        except Exception:
            staged.close(); raise
    elif os.name == "nt":
        handle,name=publication._windows_create_stage(path,[authority])
        staged=publication.StagedReport(path,authority=authority,authorities=[],
            temporary_name=name,windows_handle=handle)
        try:
            publication._windows_write(handle,payload)
            publication._windows_flush(handle)
        except Exception:
            staged.close(); raise
    else:
        raise PackagedPermissionError("unsupported packaged-evidence publication platform")
    staged.size=len(payload)
    staged.sha256=hashlib.sha256(payload).hexdigest()
    return staged


def publish_packaged_evidence(entries):
    """Logically publish outputs in order; the final entry is the authority.

    A successful no-replace rename/link is the commit boundary.  This protocol
    does not claim storage durability across sudden host power loss.
    """
    if (type(entries) not in (list,tuple) or len(entries)!=3 or
            any(type(entry) not in (list,tuple) or len(entry)!=2 for entry in entries)):
        raise PackagedPermissionError("invalid packaged evidence publication")
    paths = _normalize_packaged_paths(tuple(path for path, _ in entries))
    normalized = [(path, entries[index][1]) for index, path in enumerate(paths)]
    parent=paths[0].parent; authorities=[]; stages=[]; success=False
    active_error=None
    try:
        if os.name=="posix":
            authority=bounded.EvidenceDirectory(parent); authority.__enter__()
            authorities=[authority]
        elif os.name=="nt":
            authorities=publication._windows_authority_chain(parent)
            authority=authorities[-1]
        else:
            raise PackagedPermissionError("unsupported packaged-evidence publication platform")
        for path,payload in normalized:
            stages.append(_stage_evidence_bytes(path,payload,authority))
        for index,staged in enumerate(stages):
            try:
                if index == len(stages)-1:
                    # Bind every already-visible data name back to its retained
                    # inode/handle immediately before installing the terminal
                    # authority.  A digest in that authority must never bless
                    # bytes that lost their name between staged commits.
                    for prior in stages[:index]:
                        publication.verify_committed_stage(prior)
                publication.commit_report(staged)
                if index == len(stages)-1:
                    # Recheck the complete exact set after the unavoidable
                    # terminal syscall window.  Any uncertainty is exit 2;
                    # the no-replace authority is never rolled back or retried.
                    for published in stages:
                        publication.verify_committed_stage(published)
            except publication.PublicationReviewRequired:
                raise
            except BaseException as error:
                # The last name is the authenticated terminal authority.  Any
                # failure at that boundary requires review even when its
                # pre-rename validation can prove the private stage remained
                # private; an unattended rerun must not create a competing
                # terminal generation around already-published data files.
                if (staged.publication_state != "private" or
                        index == len(stages)-1 or
                        any(item.committed for item in stages[:index])):
                    raise publication.PublicationReviewRequired(
                        "partial or terminal packaged publication requires review") from error
                raise
        # The authenticated authority is the final entry/final logical commit.
        success=True
    except BaseException as error:
        if (not isinstance(error, publication.PublicationReviewRequired) and
                any(staged.publication_state != "private" for staged in stages)):
            active_error=publication.PublicationReviewRequired(
                "packaged publication crossed the terminal boundary; review required")
            raise active_error from error
        active_error=error
        raise
    finally:
        cleanup=[]
        for staged in reversed(stages):
            try: staged.close()
            except BaseException as error: cleanup.append(error)
        for authority in reversed(authorities):
            try: authority.__exit__(None,None,None)
            except BaseException as error: cleanup.append(error)
        # After the authority commit, cleanup diagnostics cannot make callers
        # retry a transaction that is already logically authoritative.
        if cleanup and not success and active_error is None:
            if any(staged.publication_state != "private" for staged in stages):
                raise publication.PublicationReviewRequired(
                    "packaged publication cleanup requires review") from cleanup[0]
            raise cleanup[0]


def _bounded_stream(stream, size, limit):
    if not 0 < size <= limit:
        raise PackagedPermissionError("APK size outside inspection bound")
    payload = stream.read(size + 1)
    if len(payload) != size:
        raise PackagedPermissionError("APK changed during immutable snapshot")
    return payload


def _decode_aapt_evidence(raw, label):
    """Admit one exact LF-only UTF-8 aapt surface before text decoding."""
    if type(raw) is not bytes or not raw or not raw.endswith(b"\n"):
        raise PackagedPermissionError(label + " evidence lacks one final LF")
    forbidden = (b"\r", b"\xef\xbb\xbf", b"\xc2\x85",
                 b"\xe2\x80\xa8", b"\xe2\x80\xa9",
                 b"\x0b", b"\x0c", b"\x1c", b"\x1d", b"\x1e")
    if any(token in raw for token in forbidden):
        raise PackagedPermissionError(label + " evidence is not LF-only UTF-8")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeError as error:
        raise PackagedPermissionError(label + " evidence is not strict UTF-8") from error
    if "\ufeff" in text or any(character in text for character in
                                ("\x85", "\u2028", "\u2029")):
        raise PackagedPermissionError(label + " evidence contains a Unicode separator")
    return text


def _canonicalize_aapt_output(raw, label):
    """Normalize the two admitted aapt producer wires to canonical LF bytes.

    Windows aapt emits uniform CRLF while Linux aapt emits uniform LF.  This is
    the sole producer boundary at which CRLF is admitted; retained evidence is
    always canonical LF and remains subject to ``_decode_aapt_evidence``.
    """
    if type(raw) is not bytes or not raw:
        raise PackagedPermissionError(label + " output is empty or not bytes")
    if b"\r" not in raw:
        canonical = raw
    else:
        if (not raw.endswith(b"\r\n") or
                raw.count(b"\n") != raw.count(b"\r\n") or
                b"\r" in raw.replace(b"\r\n", b"")):
            raise PackagedPermissionError(
                label + " output mixes newline encodings or contains bare CR")
        canonical = raw.replace(b"\r\n", b"\n")
    _decode_aapt_evidence(canonical, label)
    return canonical


class _ImmutableApkSnapshot:
    """One immutable byte object used by both independent aapt surfaces."""
    def __init__(self, payload, parent):
        if type(payload) is not bytes or not 0 < len(payload) <= 64 * 1024 * 1024:
            raise PackagedPermissionError("invalid APK snapshot payload")
        self.payload = payload
        self.size = len(payload)
        self.digest = hashlib.sha256(payload).hexdigest()
        self.parent = Path(parent).absolute()
        self.descriptor = None
        self.handle = None
        self.authorities = []
        self.directory = None
        self.path = None

    @property
    def command_path(self):
        if os.name == "posix":
            return f"/proc/{os.getpid()}/fd/{self.descriptor}"
        return str(self.path)

    def __enter__(self):
        if os.name == "posix":
            if not sys.platform.startswith("linux") or not hasattr(os, "memfd_create"):
                raise PackagedPermissionError("sealed APK snapshots require Linux memfd")
            import fcntl
            flags = getattr(os, "MFD_CLOEXEC", 1) | getattr(os, "MFD_ALLOW_SEALING", 2)
            descriptor = os.memfd_create("viewport-apk", flags)
            try:
                at = 0
                while at < self.size:
                    written = os.write(descriptor, self.payload[at:at + 65536])
                    if written <= 0:
                        raise PackagedPermissionError("short APK snapshot write")
                    at += written
                os.fsync(descriptor)
                seals = (fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW |
                         fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
                fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, seals)
                self.descriptor = descriptor
                self._required_seals = seals
                self.verify()
                return self
            except Exception:
                os.close(descriptor)
                self.descriptor = None
                raise
        if os.name != "nt":
            raise PackagedPermissionError("unsupported immutable APK snapshot platform")
        try:
            self._enter_windows()
            self.verify()
            return self
        except Exception:
            self.__exit__(*sys.exc_info())
            raise

    def _enter_windows(self):
        from ctypes import wintypes
        if not self.parent.is_dir():
            raise PackagedPermissionError("APK snapshot parent is not a directory")
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD,
            wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
            wintypes.HANDLE]
        kernel.CreateFileW.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.CloseHandle.restype = wintypes.BOOL
        kernel.GetCurrentProcess.argtypes = []
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        kernel.DuplicateHandle.argtypes = [wintypes.HANDLE, wintypes.HANDLE,
            wintypes.HANDLE, ctypes.POINTER(wintypes.HANDLE), wintypes.DWORD,
            wintypes.BOOL, wintypes.DWORD]
        kernel.DuplicateHandle.restype = wintypes.BOOL
        class FileTime(ctypes.Structure):
            _fields_ = [("low", wintypes.DWORD), ("high", wintypes.DWORD)]
        class HandleInfo(ctypes.Structure):
            _fields_ = [("attributes", wintypes.DWORD), ("created", FileTime),
                ("accessed", FileTime), ("written", FileTime),
                ("volume", wintypes.DWORD), ("sizeHigh", wintypes.DWORD),
                ("sizeLow", wintypes.DWORD), ("links", wintypes.DWORD),
                ("indexHigh", wintypes.DWORD), ("indexLow", wintypes.DWORD)]
        kernel.GetFileInformationByHandle.argtypes = [wintypes.HANDLE,
                                                       ctypes.c_void_p]
        kernel.GetFileInformationByHandle.restype = wintypes.BOOL
        invalid = wintypes.HANDLE(-1).value
        # aapt is a legacy Windows executable and can reject otherwise valid
        # paths inherited from this repository's unusually deep checkout.  Put
        # the private snapshot under the system temp root, cap its command-path
        # length, and retain/authenticate the newly-created leaf directory.
        directory = Path(tempfile.mkdtemp(prefix="nvp-", dir=tempfile.gettempdir())).absolute()
        self.directory = directory
        try:
            self.authorities = publication._windows_authority_chain(directory)
            directory_info = HandleInfo()
            if (not kernel.GetFileInformationByHandle(
                    self.authorities[-1].directory,
                    ctypes.byref(directory_info)) or
                    not directory_info.attributes & 0x10 or
                    directory_info.attributes & 0x400):
                raise PackagedPermissionError(
                    "unsafe Windows aapt snapshot directory authority")
            self.path = directory / ("s-" + secrets.token_hex(8) + ".apk")
            if len(str(self.path)) > MAX_WINDOWS_AAPT_SNAPSHOT_PATH:
                raise PackagedPermissionError("Windows aapt snapshot path is not short")
            # CREATE_NEW through the retained directory's stable name.  Keep
            # READ/WRITE only on this private handle while sharing READ alone;
            # aapt can consume it, but no other opener can write/delete/rename.
            handle = kernel.CreateFileW(str(self.path), 0xC0100000, 1, None, 1,
                                        0x08000100, None)
            if handle == invalid or not handle:
                raise OSError(ctypes.get_last_error(), "could not create pinned APK snapshot")
            self._kernel = kernel
            publication._windows_write(handle, self.payload)
            publication._windows_flush(handle)
            if publication._windows_final_path(handle) != self.path:
                raise PackagedPermissionError("APK snapshot resolved through another path")
            # Acquire the read-only authority before dropping our sole writable
            # descriptor.  At no instant can another opener obtain write/delete
            # access, and aapt receives only the stable name of this pinned file.
            process = kernel.GetCurrentProcess()
            pinned = wintypes.HANDLE()
            if not kernel.DuplicateHandle(process, handle, process,
                                          ctypes.byref(pinned), 0x80100000,
                                          False, 0):
                raise OSError(ctypes.get_last_error(), "could not seal APK snapshot handle")
            self.handle = pinned.value
            if not kernel.CloseHandle(handle):
                raise OSError(ctypes.get_last_error(), "could not retire writable APK snapshot handle")
            handle = None
        except Exception:
            try:
                if 'handle' in locals() and handle is not None:
                    kernel.CloseHandle(handle)
                if self.handle is not None:
                    kernel.CloseHandle(self.handle)
                    self.handle = None
                if self.path is not None and self.path.exists():
                    self.path.unlink()
                for authority in reversed(self.authorities):
                    authority.__exit__(None, None, None)
                self.authorities = []
                directory.rmdir()
            except Exception:
                pass
            raise

    def _windows_bytes(self):
        from ctypes import wintypes
        kernel = self._kernel
        kernel.SetFilePointerEx.argtypes = [wintypes.HANDLE, ctypes.c_longlong,
                                            ctypes.POINTER(ctypes.c_longlong), wintypes.DWORD]
        kernel.SetFilePointerEx.restype = wintypes.BOOL
        kernel.ReadFile.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                                    ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
        kernel.ReadFile.restype = wintypes.BOOL
        position = ctypes.c_longlong()
        if not kernel.SetFilePointerEx(self.handle, 0, ctypes.byref(position), 0):
            raise OSError(ctypes.get_last_error(), "could not rewind APK snapshot")
        chunks = []
        remaining = self.size + 1
        while remaining:
            amount = min(65536, remaining)
            buffer = ctypes.create_string_buffer(amount)
            read = wintypes.DWORD()
            if not kernel.ReadFile(self.handle, buffer, amount, ctypes.byref(read), None):
                raise OSError(ctypes.get_last_error(), "could not read pinned APK snapshot")
            if not read.value:
                break
            chunks.append(buffer.raw[:read.value])
            remaining -= read.value
        return b"".join(chunks)

    def verify(self):
        if os.name == "posix":
            import fcntl
            opened = os.fstat(self.descriptor)
            if (not stat.S_ISREG(opened.st_mode) or opened.st_size != self.size or
                    fcntl.fcntl(self.descriptor, fcntl.F_GET_SEALS) != self._required_seals):
                raise PackagedPermissionError("sealed APK snapshot authority changed")
            payload = os.pread(self.descriptor, self.size + 1, 0)
        else:
            if (publication._windows_final_path(self.handle) != self.path or
                    not self.authorities or
                    publication._windows_final_path(
                        self.authorities[-1].directory) != self.directory or
                    len(str(self.path)) > MAX_WINDOWS_AAPT_SNAPSHOT_PATH):
                raise PackagedPermissionError("private APK snapshot authority changed")
            payload = self._windows_bytes()
        if len(payload) != self.size or hashlib.sha256(payload).hexdigest() != self.digest:
            raise PackagedPermissionError("private APK snapshot changed")

    def __exit__(self, *exc):
        errors = []
        if self.descriptor is not None:
            try:
                os.close(self.descriptor)
            except OSError as error:
                errors.append(error)
            self.descriptor = None
        if self.handle is not None:
            if not self._kernel.CloseHandle(self.handle):
                errors.append(PackagedPermissionError("could not close APK snapshot handle"))
            self.handle = None
        if self.path is not None:
            try:
                self.path.unlink()
            except OSError as error:
                errors.append(error)
        for authority in reversed(self.authorities):
            try:
                authority.__exit__(None, None, None)
            except Exception as error:
                errors.append(error)
        self.authorities = []
        if self.directory is not None:
            try:
                self.directory.rmdir()
            except OSError as error:
                errors.append(error)
        if errors and exc[0] is None:
            raise errors[0]


class _PinnedSourceApk:
    """Descriptor authority for the source name while its snapshot is inspected."""
    def __init__(self, path):
        self.path = Path(path).absolute()
        self.authority = None
        self.opened_context = None
        self.stream = None
        self.handle = None
        self.directory_handle = None
        self.authority_token = None

    @staticmethod
    def _posix_authority_token(opened):
        return (
            "posix", opened.st_dev, opened.st_ino, opened.st_mode,
            opened.st_nlink, opened.st_uid, opened.st_gid,
            opened.st_rdev, opened.st_size,
            getattr(opened, "st_mtime_ns", int(opened.st_mtime * 1e9)),
            getattr(opened, "st_ctime_ns", int(opened.st_ctime * 1e9)))

    def _require_posix_authority(self, opened):
        if self._posix_authority_token(opened) != self.authority_token:
            raise PackagedPermissionError(
                "APK retained authority changed during packaged inspection")

    def __enter__(self):
        if os.name == "posix":
            self.authority = bounded.EvidenceDirectory(self.path.parent)
            self.authority.__enter__()
            try:
                self.opened_context = self.authority.open_regular(self.path.name)
                self.stream, opened = self.opened_context.__enter__()
                self.size = opened.st_size
                self.identity = (opened.st_dev,opened.st_ino)
                self.authority_token = self._posix_authority_token(opened)
                self.payload = _bounded_stream(self.stream, self.size, 64 * 1024 * 1024)
                return self
            except Exception:
                self.__exit__(*sys.exc_info())
                raise
        if os.name != "nt":
            raise PackagedPermissionError("unsupported source APK authority platform")
        try:
            self._enter_windows()
            self.payload = self._windows_bytes()
            if len(self.payload) != self.size:
                raise PackagedPermissionError("APK changed during source capture")
            return self
        except Exception:
            self.__exit__(*sys.exc_info())
            raise

    def _enter_windows(self):
        from ctypes import wintypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD,
            wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
            wintypes.HANDLE]
        kernel.CreateFileW.restype = wintypes.HANDLE
        kernel.GetFileSizeEx.argtypes = [wintypes.HANDLE,
                                         ctypes.POINTER(ctypes.c_longlong)]
        kernel.GetFileSizeEx.restype = wintypes.BOOL
        class FileTime(ctypes.Structure):
            _fields_=[("low",wintypes.DWORD),("high",wintypes.DWORD)]
        class HandleInfo(ctypes.Structure):
            _fields_=[("attributes",wintypes.DWORD),("created",FileTime),
                ("accessed",FileTime),("written",FileTime),("volume",wintypes.DWORD),
                ("sizeHigh",wintypes.DWORD),("sizeLow",wintypes.DWORD),
                ("links",wintypes.DWORD),("indexHigh",wintypes.DWORD),
                ("indexLow",wintypes.DWORD)]
        kernel.GetFileInformationByHandle.argtypes=[wintypes.HANDLE,ctypes.c_void_p]
        kernel.GetFileInformationByHandle.restype=wintypes.BOOL
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.CloseHandle.restype = wintypes.BOOL
        invalid = wintypes.HANDLE(-1).value
        directory = kernel.CreateFileW(
            str(self.path.parent), 0x00100081, 3, None, 3,
            0x02000000 | 0x00200000, None)
        if directory == invalid or not directory:
            raise OSError(ctypes.get_last_error(), "could not retain source APK directory")
        self._kernel, self.directory_handle = kernel, directory
        handle = kernel.CreateFileW(str(self.path), 0x80100000, 1, None, 3,
                                    0x00200000 | 0x08000000, None)
        if handle == invalid or not handle:
            kernel.CloseHandle(directory)
            self.directory_handle = None
            raise OSError(ctypes.get_last_error(), "could not pin source APK")
        self.handle = handle
        info=HandleInfo()
        if (not kernel.GetFileInformationByHandle(handle,ctypes.byref(info)) or
                info.attributes & (0x10 | 0x400)):
            self.__exit__(None,None,None)
            raise PackagedPermissionError("source APK is nonregular or a reparse point")
        size = ctypes.c_longlong()
        if (not kernel.GetFileSizeEx(handle, ctypes.byref(size)) or
                not 0 < size.value <= 64 * 1024 * 1024):
            self.__exit__(None,None,None)
            raise PackagedPermissionError("APK size outside inspection bound")
        self.size = size.value
        self.identity = (info.volume, info.indexHigh, info.indexLow)
        self.authority_token = (
            "windows", info.volume, info.indexHigh, info.indexLow,
            info.attributes, info.links, info.created.high, info.created.low,
            info.written.high, info.written.low, info.sizeHigh, info.sizeLow)
        if self._final_path(handle) != self.path:
            self.__exit__(None,None,None)
            raise PackagedPermissionError("source APK handle resolved to another path")

    def _final_path(self, handle):
        from ctypes import wintypes
        kernel = self._kernel
        kernel.GetFinalPathNameByHandleW.argtypes = [
            wintypes.HANDLE,wintypes.LPWSTR,wintypes.DWORD,wintypes.DWORD]
        kernel.GetFinalPathNameByHandleW.restype = wintypes.DWORD
        needed = kernel.GetFinalPathNameByHandleW(handle,None,0,0)
        if not needed:
            raise OSError(ctypes.get_last_error(),"could not resolve source APK handle")
        buffer = ctypes.create_unicode_buffer(needed+1)
        written = kernel.GetFinalPathNameByHandleW(handle,buffer,len(buffer),0)
        if not written or written >= len(buffer):
            raise OSError(ctypes.get_last_error(),"could not resolve source APK path")
        value=buffer.value
        if value.startswith("\\\\?\\UNC\\"):
            value="\\\\"+value[8:]
        elif value.startswith("\\\\?\\"):
            value=value[4:]
        return Path(value).absolute()

    def _windows_bytes(self):
        from ctypes import wintypes
        kernel=self._kernel
        kernel.SetFilePointerEx.argtypes=[wintypes.HANDLE,ctypes.c_longlong,
            ctypes.POINTER(ctypes.c_longlong),wintypes.DWORD]
        kernel.SetFilePointerEx.restype=wintypes.BOOL
        kernel.ReadFile.argtypes=[wintypes.HANDLE,ctypes.c_void_p,wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),ctypes.c_void_p]
        kernel.ReadFile.restype=wintypes.BOOL
        position=ctypes.c_longlong()
        if not kernel.SetFilePointerEx(self.handle,0,ctypes.byref(position),0):
            raise OSError(ctypes.get_last_error(),"could not rewind source APK")
        chunks=[]; remaining=self.size+1
        while remaining:
            amount=min(65536,remaining); buffer=ctypes.create_string_buffer(amount)
            read=wintypes.DWORD()
            if not kernel.ReadFile(self.handle,buffer,amount,ctypes.byref(read),None):
                raise OSError(ctypes.get_last_error(),"could not read source APK")
            if not read.value: break
            chunks.append(buffer.raw[:read.value]); remaining-=read.value
        return b"".join(chunks)

    def verify(self, digest):
        if os.name == "posix":
            self._require_posix_authority(os.fstat(self.stream.fileno()))
            self.stream.seek(0)
            self._require_posix_authority(os.fstat(self.stream.fileno()))
            current=_bounded_stream(self.stream,self.size,64*1024*1024)
            self._require_posix_authority(os.fstat(self.stream.fileno()))
            with self.authority.open_regular(self.path.name) as (named,opened):
                self._require_posix_authority(opened)
                named_bytes=_bounded_stream(named,opened.st_size,64*1024*1024)
                self._require_posix_authority(os.fstat(named.fileno()))
            self._require_posix_authority(os.fstat(self.stream.fileno()))
            if current != named_bytes:
                raise PackagedPermissionError("APK name changed during packaged inspection")
        else:
            if self._final_path(self.handle) != self.path:
                raise PackagedPermissionError("APK name changed during packaged inspection")
            current=self._windows_bytes()
        if hashlib.sha256(current).hexdigest()!=digest:
            raise PackagedPermissionError("APK changed during packaged inspection")

    def __exit__(self,*exc):
        errors=[]
        if self.opened_context is not None:
            try: self.opened_context.__exit__(*exc)
            except Exception as error: errors.append(error)
            self.opened_context=None
        if self.authority is not None:
            try: self.authority.__exit__(*exc)
            except Exception as error: errors.append(error)
            self.authority=None
        if self.handle is not None:
            if not self._kernel.CloseHandle(self.handle):
                errors.append(PackagedPermissionError("could not close source APK handle"))
            self.handle=None
        if self.directory_handle is not None:
            if not self._kernel.CloseHandle(self.directory_handle):
                errors.append(PackagedPermissionError("could not close source APK directory"))
            self.directory_handle=None
        if errors and exc[0] is None:
            raise errors[0]


def inspect_package(aapt: Path, apk: Path, permissions_out: Path,
                    xmltree_out: Path, authority_out: Path) -> None:
    apk = Path(apk).absolute()
    outputs = _normalize_packaged_paths(
        (permissions_out, xmltree_out, authority_out))
    permissions_out, xmltree_out, authority_out = outputs
    try:
        with _PinnedSourceApk(apk) as source:
            original = source.payload
            source_digest = hashlib.sha256(original).hexdigest()
            def authenticate_source_name():
                source.verify(source_digest)
            with _ImmutableApkSnapshot(original, permissions_out.parent) as snapshot:
                snapshot.verify()
                stable_path = snapshot.command_path
                permissions = bounded.bounded_command(
                    [str(aapt), "dump", "permissions", stable_path],
                    MAX_PERMISSION_EVIDENCE, 30)
                snapshot.verify()
                authenticate_source_name()
                permissions = _canonicalize_aapt_output(
                    permissions, "permissions")
                xmltree = bounded.bounded_command(
                    [str(aapt), "dump", "xmltree", stable_path,
                     "AndroidManifest.xml"], MAX_PERMISSION_EVIDENCE, 30)
                snapshot.verify()
                authenticate_source_name()
                xmltree = _canonicalize_aapt_output(xmltree, "xmltree")
        permission_text = _decode_aapt_evidence(permissions,"permissions")
        xmltree_text = _decode_aapt_evidence(xmltree,"xmltree")
    except (bounded.InventoryError, UnicodeError) as error:
        raise PackagedPermissionError(str(error)) from error
    verify_permissions(permission_text, xmltree_text)
    authority = _packaged_authority_bytes(source_digest, permissions, xmltree)
    publish_packaged_evidence((
        (permissions_out,permissions),
        (xmltree_out,xmltree),
        (authority_out,authority),
    ))


def read_bounded_text(path: Path) -> str:
    try:
        raw = bounded.read_bounded(path, MAX_PERMISSION_EVIDENCE)
    except bounded.InventoryError as error:
        raise PackagedPermissionError(str(error)) from error
    try:
        return _decode_aapt_evidence(raw,"packaged")
    except UnicodeError as error:
        raise PackagedPermissionError("permission evidence is not UTF-8") from error


def _neutralize_failed_stdout(stream):
    """Prevent interpreter shutdown from retrying a failed buffered flush."""
    replace_stdout = sys.stdout is stream
    if replace_stdout:
        # Never leave the failed wrapper installed while allocating either
        # descriptor-level or Python-level replacements.
        sys.stdout = None
    descriptor = None
    try:
        descriptor = stream.fileno()
    except (AttributeError, OSError, ValueError):
        pass
    if type(descriptor) is int and descriptor >= 0:
        devnull = None
        try:
            devnull = os.open(os.devnull, os.O_WRONLY)
            if devnull != descriptor:
                os.dup2(devnull, descriptor)
            # Empty any TextIOWrapper state now that its descriptor is safe.
            try:
                stream.flush()
            except (OSError, ValueError):
                pass
        except OSError:
            pass
        finally:
            # A closed target can be reclaimed by os.open. In that case the
            # returned descriptor is itself the replacement and must stay open
            # until interpreter shutdown.
            if devnull is not None and devnull != descriptor:
                try:
                    os.close(devnull)
                except OSError:
                    pass
    if replace_stdout:
        try:
            sys.stdout = open(os.devnull, "w", encoding="utf-8", newline="\n")
        except (OSError, ValueError):
            pass


def _report_terminal_success(message):
    """A logical evidence commit must not become a retryable CLI failure."""
    stream = sys.stdout
    try:
        print(message, file=stream)
        stream.flush()
    except (OSError, ValueError):
        _neutralize_failed_stdout(stream)


class DisplayScopeTest(unittest.TestCase):
    def test_aapt_evidence_is_strict_lf_only_utf8_before_decode(self):
        self.assertEqual(_decode_aapt_evidence(b"one\ntwo\n","surface"),"one\ntwo\n")
        invalid=(b"",b"one",b"one\r\n",b"\xef\xbb\xbf-one\n",
                 b"one\xc2\x85two\n",b"one\xe2\x80\xa8two\n",
                 b"one\xe2\x80\xa9two\n",b"one\x0btwo\n",b"\xff\n")
        for raw in invalid:
            with self.subTest(raw=raw),self.assertRaises(PackagedPermissionError):
                _decode_aapt_evidence(raw,"surface")

    def test_aapt_producer_boundary_accepts_only_uniform_lf_or_crlf(self):
        self.assertEqual(
            _canonicalize_aapt_output(b"one\ntwo\n", "surface"),
            b"one\ntwo\n")
        self.assertEqual(
            _canonicalize_aapt_output(b"one\r\ntwo\r\n", "surface"),
            b"one\ntwo\n")
        invalid = (
            b"", b"one", b"one\r\ntwo\n", b"one\ntwo\r\n",
            b"one\rtwo\r\n", b"one\r\r\n",
            b"one\r\ntwo\r", b"one\r\ntwo",
            b"one\r\n\xef\xbb\xbftwo\r\n",
            b"one\r\ntwo\xe2\x80\xa8three\r\n",
        )
        for raw in invalid:
            with self.subTest(raw=raw), self.assertRaises(PackagedPermissionError):
                _canonicalize_aapt_output(raw, "surface")

    def test_packaged_permission_dump_variants_fail_closed(self):
        valid_permissions = VALID_PERMISSION_BYTES.decode("ascii")
        valid_xml = VALID_XMLTREE_BYTES.decode("ascii")
        verify_permissions(valid_permissions, valid_xml)
        permission_variants = (
            "uses-permission: name='android.permission.INTERNET'",
            "uses-permission-sdk-23: name='android.permission.CAMERA'",
            "uses-permission-sdk-m: name='android.permission.CAMERA'",
            "uses-permission-future: name='android.permission.CAMERA'",
            "uses-permissionX: name='android.permission.CAMERA'",
            "uses-permission.foo: name='android.permission.CAMERA'",
        )
        for line in permission_variants:
            with self.subTest(line=line), self.assertRaises(PackagedPermissionError):
                verify_permissions(valid_permissions + line, valid_xml)
        for element in ("uses-permission", "uses-permission-sdk-23",
                        "uses-permission-sdk-m", "uses-permissionX", "uses-permission.foo"):
            with self.subTest(element=element), self.assertRaises(PackagedPermissionError):
                verify_permissions(valid_permissions,
                    valid_xml.replace("    E: application", "    E: " + element +
                                      " (line=6)\n    E: application"))
        for permissions, xmltree in (("", valid_xml), (valid_permissions, ""),
                                     (valid_permissions, "E: manifest\n"),
                                     ("package: wrong\n", valid_xml),
                                     (valid_permissions, valid_xml.rsplit("\n", 2)[0]),
                                     (valid_permissions, valid_xml.rstrip()[:-3]),
                                     (valid_permissions, valid_xml.replace(
                                         "    E: uses-sdk", "    A: unexpected=1\n    E: uses-sdk"))):
            with self.assertRaises(PackagedPermissionError):
                verify_permissions(permissions, xmltree)

    def test_package_inspection_bounds_producers_and_brackets_apk_identity(self):
        from unittest.mock import patch
        valid_permissions=("package: " + PACKAGE + "\n").encode()
        producer_permissions = valid_permissions.replace(b"\n", b"\r\n")
        producer_xmltree = VALID_XMLTREE_BYTES.replace(b"\n", b"\r\n")
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); apk=root/"probe.apk"; apk.write_bytes(b"immutable-apk")
            with patch.object(bounded,"bounded_command",
                              side_effect=[producer_permissions,producer_xmltree]) as run, \
                 patch(__name__ + ".verify_permissions") as verify:
                inspect_package(Path("aapt"),apk,root/"p",root/"x",root/"authority")
            self.assertEqual(run.call_args_list[0].args[1],MAX_PERMISSION_EVIDENCE)
            self.assertEqual(run.call_args_list[1].args[1],MAX_PERMISSION_EVIDENCE)
            self.assertEqual(run.call_args_list[0].args[0][-1],
                             run.call_args_list[1].args[0][-2])
            verify.assert_called_once_with(
                valid_permissions.decode(), VALID_XMLTREE_BYTES.decode())
            authority=json.loads((root/"authority").read_text())
            self.assertEqual(authority["apkSha256"],hashlib.sha256(b"immutable-apk").hexdigest())
            self.assertEqual(authority["permissionsSha256"],hashlib.sha256(valid_permissions).hexdigest())
            self.assertEqual(authority["xmltreeSha256"],
                             hashlib.sha256(VALID_XMLTREE_BYTES).hexdigest())
            self.assertEqual((root/"p").read_bytes(), valid_permissions)
            self.assertEqual((root/"x").read_bytes(), VALID_XMLTREE_BYTES)
            verify_packaged_bundle(apk, (root/"p", root/"x", root/"authority"))
            if os.name == "nt":
                # The real checkout can be much deeper than legacy aapt accepts.
                # Snapshot placement must be independent of the evidence parent.
                deep = root
                for index in range(5):
                    deep = deep / (("deep-%d-" % index) + "x" * 36)
                deep.mkdir(parents=True)
                observed = []
                def producer(command, *_):
                    stable = Path(command[-1] if command[2] == "permissions"
                                  else command[-2])
                    observed.append(stable)
                    return (valid_permissions if len(observed) == 1
                            else VALID_XMLTREE_BYTES)
                with patch.object(bounded, "bounded_command", side_effect=producer), \
                     patch(__name__ + ".publish_packaged_evidence"), \
                     patch(__name__ + ".verify_permissions"):
                    inspect_package(Path("aapt"), apk, deep/"p", deep/"x", deep/"authority")
                self.assertEqual(observed[0], observed[1])
                self.assertLessEqual(len(str(observed[0])),
                                     MAX_WINDOWS_AAPT_SNAPSHOT_PATH)
                self.assertFalse(str(observed[0]).startswith(str(deep)))
                self.assertFalse(observed[0].exists())

    def test_packaged_outputs_share_authority_and_commit_authority_last(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); entries=((root/"permissions",b"p\n"),
                                      (root/"xmltree",b"x\n"),
                                      (root/"authority",b"a\n"))
            authorities=[]; stage_owners=[]; commits=[]
            real_stage=_stage_evidence_bytes; real_commit=publication.commit_report
            def stage(path,payload,authority):
                authorities.append(authority)
                result=real_stage(path,payload,authority)
                stage_owners.append(result.authorities)
                return result
            def commit(staged):
                commits.append(staged.output.name)
                return real_commit(staged)
            with patch(__name__+"._stage_evidence_bytes",side_effect=stage), \
                 patch.object(publication,"commit_report",side_effect=commit):
                publish_packaged_evidence(entries)
            self.assertEqual(len({id(value) for value in authorities}),1)
            self.assertEqual(stage_owners,[[],[],[]])
            self.assertEqual(commits,["permissions","xmltree","authority"])
            self.assertEqual([path.read_bytes() for path,_ in entries],[b"p\n",b"x\n",b"a\n"])
        launcher=(ROOT/"build-display-host.ps1").read_text(encoding="utf-8")
        self.assertIn("$inspectExit=$LASTEXITCODE",launcher)
        self.assertIn("if ($inspectExit -eq 2)",launcher)
        self.assertIn("exit 2",launcher)

    def test_packaged_bundle_rejects_apk_replaced_after_evidence_publication(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            apk = root / "viewport-unsigned.apk"
            original = b"authenticated APK bytes"
            apk.write_bytes(original)
            entries = (
                (root / "permissions.txt", VALID_PERMISSION_BYTES),
                (root / "manifest-xmltree.txt", VALID_XMLTREE_BYTES),
                (root / "packaged-scope-authority.json", _packaged_authority_bytes(
                    hashlib.sha256(original).hexdigest(),
                    VALID_PERMISSION_BYTES, VALID_XMLTREE_BYTES)),
            )
            publish_packaged_evidence(entries)
            verify_packaged_bundle(apk, tuple(path for path, _ in entries))

            replacement = root / "replacement.apk"
            replacement.write_bytes(b"different delivered APK bytes")
            replacement.replace(apk)
            with self.assertRaisesRegex(
                    PackagedPermissionError,
                    "packaged authority authenticates another APK"):
                verify_packaged_bundle(apk, tuple(path for path, _ in entries))

    def test_packaged_bundle_rechecks_name_after_evidence_verification(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            apk = root / "viewport-unsigned.apk"
            payload = b"same authenticated APK bytes"
            apk.write_bytes(payload)
            entries = (
                (root / "permissions.txt", VALID_PERMISSION_BYTES),
                (root / "manifest-xmltree.txt", VALID_XMLTREE_BYTES),
                (root / "packaged-scope-authority.json", _packaged_authority_bytes(
                    hashlib.sha256(payload).hexdigest(),
                    VALID_PERMISSION_BYTES, VALID_XMLTREE_BYTES)),
            )
            publish_packaged_evidence(entries)
            real_verify = verify_packaged_evidence
            replacement = root / "same-content-replacement.apk"
            replacement.write_bytes(payload)
            replacement_succeeded = []

            def replace_during_verify(paths):
                try:
                    replacement.replace(apk)
                    replacement_succeeded.append(True)
                except OSError:
                    replacement_succeeded.append(False)
                return real_verify(paths)

            context = patch(__name__ + ".verify_packaged_evidence",
                            side_effect=replace_during_verify)
            if os.name == "posix":
                with context, self.assertRaisesRegex(
                        PackagedPermissionError,
                        "APK retained authority changed during packaged inspection"):
                    verify_packaged_bundle(apk, tuple(path for path, _ in entries))
                self.assertEqual(replacement_succeeded, [True])
            elif os.name == "nt":
                with context:
                    verify_packaged_bundle(apk, tuple(path for path, _ in entries))
                self.assertEqual(replacement_succeeded, [False])
            else:
                self.skipTest("packaged bundle authority platform")

            # Now mutate at the distinct boundary after the first retained APK
            # context has closed but before the final-name rebound.  Both a
            # different object and a same-content name ABA must be rejected.
            real_rebind = _rebind_packaged_apk
            for label, replacement_payload in (
                    ("replacement", b"different post-context bytes"),
                    ("same-content-aba", payload)):
                with self.subTest(boundary=label):
                    apk.write_bytes(payload)
                    replacement = root / (label + ".apk")
                    replacement.write_bytes(replacement_payload)
                    def replace_then_rebind(*arguments, **keywords):
                        replacement.replace(apk)
                        return real_rebind(*arguments, **keywords)
                    with patch(__name__ + "._rebind_packaged_apk",
                               side_effect=replace_then_rebind), \
                         self.assertRaisesRegex(
                             PackagedPermissionError,
                             "packaged APK authority changed after evidence verification"):
                        verify_packaged_bundle(
                            apk, tuple(path for path, _ in entries))
                    self.assertEqual(apk.read_bytes(), replacement_payload)

    @unittest.skipUnless(os.name == "nt", "Windows packaged-APK ADS rejection")
    def test_windows_packaged_bundle_rejects_apk_ads_before_open(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            apk_ads = Path(str(root / "viewport-unsigned.apk") + ":untrusted")
            paths = (root / "permissions.txt", root / "manifest-xmltree.txt",
                     root / "packaged-scope-authority.json")
            with patch(__name__ + "._PinnedSourceApk") as opened, \
                 self.assertRaisesRegex(PackagedPermissionError,
                                        "invalid packaged APK name"):
                verify_packaged_bundle(apk_ads, paths)
            opened.assert_not_called()

    @unittest.skipUnless(os.name == "nt", "Windows packaged-output ADS rejection")
    def test_windows_packaged_output_ads_is_rejected_before_staging(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            sentinel = root / "unrelated.keep"
            sentinel.write_bytes(b"do-not-delete")
            ordinary = [root / "permissions.txt", root / "manifest-xmltree.txt",
                        root / "packaged-scope-authority.json"]
            payloads = [VALID_PERMISSION_BYTES, VALID_XMLTREE_BYTES,
                        _packaged_authority_bytes(
                            "0" * 64, VALID_PERMISSION_BYTES, VALID_XMLTREE_BYTES)]
            for index in range(3):
                outputs = list(ordinary)
                outputs[index] = Path(str(outputs[index]) + ":untrusted")
                entries = tuple(zip(outputs, payloads))
                with self.subTest(index=index), \
                     patch(__name__ + "._stage_evidence_bytes") as stage, \
                     self.assertRaisesRegex(
                         PackagedPermissionError, "invalid packaged evidence output name"):
                    publish_packaged_evidence(entries)
                stage.assert_not_called()
                self.assertEqual(sentinel.read_bytes(), b"do-not-delete")
                self.assertEqual(set(root.iterdir()), {sentinel})

    def test_post_data_commit_fault_is_nonretryable_without_duplicate_authority(self):
        from unittest.mock import patch
        for boundary in (1, 2):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                sentinel = root / "unrelated.keep"
                sentinel.write_bytes(b"do-not-delete")
                entries = _packaged_fixture_entries(root)
                real_commit = publication.commit_report
                committed = 0

                def fail_after_commit(staged):
                    nonlocal committed
                    real_commit(staged)
                    committed += 1
                    if committed == boundary:
                        raise OSError("recoverable publication fault")

                with patch.object(publication, "commit_report",
                                  side_effect=fail_after_commit), \
                     self.assertRaisesRegex(
                         publication.PublicationReviewRequired,
                         "partial or terminal packaged publication"):
                    publish_packaged_evidence(entries)
                self.assertEqual(committed, boundary)
                self.assertEqual(
                    [path.exists() for path, _ in entries],
                    [index < boundary for index in range(3)])
                with self.assertRaisesRegex(
                        PackagedPermissionError,
                        "incomplete packaged evidence generation"):
                    verify_packaged_evidence(tuple(path for path, _ in entries))
                with self.assertRaises(publication.PublicationReviewRequired):
                    publish_packaged_evidence(entries)
                self.assertEqual(
                    [path.exists() for path, _ in entries],
                    [index < boundary for index in range(3)])
                self.assertEqual(sentinel.read_bytes(), b"do-not-delete")

        # Exercise the outer loop boundary itself: the first real commit has
        # returned, then iteration fails before the next commit call begins.
        from unittest.mock import patch
        import builtins
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); entries=_packaged_fixture_entries(root)
            real_enumerate=builtins.enumerate; calls=0
            def fail_between_commits(iterable,*args):
                nonlocal calls
                calls += 1
                actual=real_enumerate(iterable,*args)
                if calls != 2:
                    return actual
                def boundary():
                    yield next(actual)
                    raise OSError("iterator fault after first logical commit")
                return boundary()
            with patch("builtins.enumerate",side_effect=fail_between_commits), \
                 self.assertRaisesRegex(
                     publication.PublicationReviewRequired,
                     "crossed the terminal boundary"):
                publish_packaged_evidence(entries)
            self.assertEqual([path.exists() for path,_ in entries],
                             [True,False,False])
            with self.assertRaises(publication.PublicationReviewRequired):
                publish_packaged_evidence(entries)
            self.assertEqual([path.exists() for path,_ in entries],
                             [True,False,False])

        # A prior data name must still designate its retained committed inode
        # at the terminal-authority boundary.  POSIX permits the name to be
        # rebound while the old inode remains retained; Windows share mode zero
        # must deny that replacement instead.
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); entries=_packaged_fixture_entries(root)
            replacement=root/"replacement"
            replacement_payload=b"unrelated replacement bytes"
            replacement.write_bytes(replacement_payload)
            real_commit=publication.commit_report; committed=0; replaced=[]
            def replace_first_data_name(staged):
                nonlocal committed
                real_commit(staged)
                committed += 1
                if committed == 1:
                    try:
                        replacement.replace(staged.output)
                        replaced.append(True)
                    except OSError:
                        replaced.append(False)
            with patch.object(publication,"commit_report",
                              side_effect=replace_first_data_name):
                if os.name == "posix":
                    with self.assertRaisesRegex(
                            publication.PublicationReviewRequired,
                            "published output authority is uncertain"):
                        publish_packaged_evidence(entries)
                elif os.name == "nt":
                    publish_packaged_evidence(entries)
                else:
                    self.skipTest("packaged publication platform")
            if os.name == "posix":
                self.assertEqual(replaced,[True])
                self.assertEqual(entries[0][0].read_bytes(),replacement_payload)
                self.assertEqual(entries[1][0].read_bytes(),entries[1][1])
                self.assertFalse(entries[2][0].exists())
                with self.assertRaises(publication.PublicationReviewRequired):
                    publish_packaged_evidence(entries)
                self.assertEqual(entries[0][0].read_bytes(),replacement_payload)
                self.assertFalse(entries[2][0].exists())
            else:
                self.assertEqual(replaced,[False])
                verify_packaged_evidence(tuple(path for path,_ in entries))

        # A diagnostic seam after the terminal authority has committed is
        # nonretryable, retains the complete exact set, and never creates a
        # second authority on a same-destination attempt.
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); entries=_packaged_fixture_entries(root)
            real_verify=publication.verify_committed_stage; verified=0
            def fault_after_terminal_commit(staged):
                nonlocal verified
                real_verify(staged)
                verified += 1
                if verified == 3:
                    raise OSError("post-authority verification diagnostic fault")
            with patch.object(publication,"verify_committed_stage",
                              side_effect=fault_after_terminal_commit), \
                 self.assertRaisesRegex(
                     publication.PublicationReviewRequired,
                     "partial or terminal packaged publication"):
                publish_packaged_evidence(entries)
            self.assertEqual(verified,3)
            self.assertEqual([path.read_bytes() for path,_ in entries],
                             [payload for _,payload in entries])
            verify_packaged_evidence(tuple(path for path,_ in entries))
            with self.assertRaises(publication.PublicationReviewRequired):
                publish_packaged_evidence(entries)
            self.assertEqual([path.read_bytes() for path,_ in entries],
                             [payload for _,payload in entries])

    @unittest.skipUnless(os.name == "posix", "POSIX partial-publication preservation")
    def test_posix_partial_failure_never_unlinks_a_rebound_output_name(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            sentinel = root / "unrelated.keep"
            sentinel.write_bytes(b"unrelated-bytes")
            replacement = root / "same-directory-replacement"
            replacement.write_bytes(b"replacement-bytes")
            entries = _packaged_fixture_entries(root)
            real_commit = publication.commit_report

            def replace_name_after_first_commit(staged):
                real_commit(staged)
                replacement.replace(staged.output)
                raise OSError("fault after same-directory replacement")

            with patch.object(
                    publication, "commit_report",
                    side_effect=replace_name_after_first_commit), \
                 patch.object(os, "unlink",
                              side_effect=AssertionError("unsafe pathname rollback")), \
                 self.assertRaisesRegex(
                     publication.PublicationReviewRequired,
                     "partial or terminal packaged publication"):
                publish_packaged_evidence(entries)
            self.assertEqual(entries[0][0].read_bytes(), b"replacement-bytes")
            self.assertFalse(entries[1][0].exists())
            self.assertFalse(entries[2][0].exists())
            self.assertEqual(sentinel.read_bytes(), b"unrelated-bytes")

    @unittest.skipUnless(os.name == "posix", "POSIX post-link rollback race")
    def test_posix_production_commit_never_reopens_or_unlinks_after_postlink_fault(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "report.json"
            replacement = root / "same-directory-replacement"
            replacement.write_bytes(b"replacement-must-survive")
            sentinel = root / "unrelated.keep"
            sentinel.write_bytes(b"unrelated-must-survive")
            staged = publication.stage_report(
                {"ok": True}, target, publication.WorkBudget(limit=1000))
            real_stat = publication.os.stat
            real_fsync = publication.os.fsync
            named_stats = 0
            directory_fsyncs = 0

            def race_on_rollback_stat(path, *args, **kwargs):
                nonlocal named_stats
                if (path == target.name and
                        kwargs.get("dir_fd") == staged.authority.directory):
                    named_stats += 1
                    result = real_stat(path, *args, **kwargs)
                    if named_stats == 2:
                        # This is the historical stat(name)->unlink(name)
                        # window: return the old inode witness after rebinding
                        # the name to unrelated bytes.  Correct code never
                        # performs this second pathname lookup.
                        replacement.replace(target)
                    return result
                return real_stat(path, *args, **kwargs)

            def fail_directory_fsync(descriptor):
                nonlocal directory_fsyncs
                if descriptor == staged.authority.directory:
                    directory_fsyncs += 1
                    if directory_fsyncs == 2:
                        raise OSError("post-link directory durability fault")
                return real_fsync(descriptor)

            try:
                with patch.object(publication.os, "stat",
                                  side_effect=race_on_rollback_stat), \
                     patch.object(publication.os, "fsync",
                                  side_effect=fail_directory_fsync), \
                     self.assertRaisesRegex(
                         publication.PublicationReviewRequired,
                         "durability or name is uncertain"):
                    publication.commit_report(staged)
            finally:
                staged.close()
            self.assertEqual(named_stats, 1)
            self.assertEqual(directory_fsyncs, 2)
            self.assertTrue(staged.committed)
            self.assertEqual(target.read_text(encoding="ascii"),
                             '{\n  "ok": true\n}\n')
            self.assertEqual(replacement.read_bytes(),
                             b"replacement-must-survive")
            self.assertEqual(sentinel.read_bytes(), b"unrelated-must-survive")

    @unittest.skipUnless(os.name == "nt", "Windows packaged-evidence crash boundaries")
    def test_windows_process_crash_boundaries_fail_closed_and_versioned_retry(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            sentinel = root / "unrelated.keep"
            sentinel.write_bytes(b"do-not-delete")
            for boundary in (1, 2, 3):
                attempt = root / ("generation-%04d" % boundary)
                attempt.mkdir()
                entries = _packaged_fixture_entries(attempt)
                # Use an explicitly captured, isolated helper rather than a
                # multiprocessing spawn target.  Windows spawn would re-import
                # this test module by mutable pathname, correctly violating the
                # authenticated source-loader gate used by the aggregate suite.
                bundle = _windows_crash_publication_bundle(entries)
                process = subprocess.run(
                    [sys.executable, "-I", "-S", "-c",
                     _WINDOWS_CRASH_PUBLICATION_HELPER,
                     str(attempt), str(boundary)],
                    input=bundle, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, timeout=30, check=False)
                self.assertEqual(
                    process.returncode, 70 + boundary,
                    process.stderr.decode("utf-8", errors="replace"))
                committed = [path.name for path, _ in entries if path.exists()]
                self.assertEqual(committed,
                                 [path.name for path, _ in entries[:boundary]])
                private_stages = [
                    child for child in attempt.iterdir()
                    if child.name.startswith(".bindings-") and
                    child.name.endswith(".tmp")]
                self.assertEqual(len(private_stages), 3 - boundary)
                self.assertEqual(
                    sorted(hashlib.sha256(child.read_bytes()).hexdigest()
                           for child in private_stages),
                    sorted(hashlib.sha256(payload).hexdigest()
                           for _, payload in entries[boundary:]))
                self.assertEqual(len(list(attempt.iterdir())), 3)
                if boundary < 3:
                    with self.assertRaisesRegex(
                            PackagedPermissionError,
                            "incomplete packaged evidence generation"):
                        verify_packaged_evidence(
                            tuple(path for path, _ in entries))
                else:
                    verify_packaged_evidence(tuple(path for path, _ in entries))

                # A hard-crashed generation is quarantined, not guessed-at or
                # deleted.  Restart publishes to a fresh deterministic version
                # directory; the abandoned tree and unrelated sibling remain.
                before = {
                    child.name: ("directory" if child.is_dir() else
                                 hashlib.sha256(child.read_bytes()).hexdigest())
                    for child in attempt.iterdir()
                }
                retry = root / ("generation-%04d-retry-0002" % boundary)
                retry.mkdir()
                retry_entries = _packaged_fixture_entries(retry)
                publish_packaged_evidence(retry_entries)
                verify_packaged_evidence(
                    tuple(path for path, _ in retry_entries))
                after = {
                    child.name: ("directory" if child.is_dir() else
                                 hashlib.sha256(child.read_bytes()).hexdigest())
                    for child in attempt.iterdir()
                }
                self.assertEqual(after, before)
                self.assertEqual(sentinel.read_bytes(), b"do-not-delete")

    def test_packaged_authority_commit_failure_is_platform_specific(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); entries=((root/"permissions",b"p\n"),
                                      (root/"xmltree",b"x\n"),
                                      (root/"authority",b"a\n"))
            real_commit=publication.commit_report; calls=[]
            def fail_authority(staged):
                calls.append(staged.output.name)
                if staged.output.name=="authority":
                    raise OSError("authority commit fault")
                return real_commit(staged)
            with patch.object(publication,"commit_report",side_effect=fail_authority), \
                 self.assertRaisesRegex(
                     publication.PublicationReviewRequired,
                     "partial or terminal packaged publication"):
                publish_packaged_evidence(entries)
            self.assertEqual(calls,["permissions","xmltree","authority"])
            self.assertEqual(
                [path.exists() for path, _ in entries], [True, True, False])

    def test_post_authority_cleanup_fault_is_not_retryable_failure(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); entries=((root/"permissions",b"p\n"),
                                      (root/"xmltree",b"x\n"),
                                      (root/"authority",b"a\n"))
            real_close=publication.StagedReport.close
            def noisy_close(staged):
                real_close(staged)
                raise KeyboardInterrupt("postcommit cleanup fault")
            with patch.object(publication.StagedReport,"close",noisy_close):
                publish_packaged_evidence(entries)
            self.assertEqual([path.read_bytes() for path,_ in entries],[b"p\n",b"x\n",b"a\n"])

    def test_post_authority_stdout_fault_is_not_retryable_failure(self):
        from unittest.mock import patch
        class FailedStdout:
            def write(self, _):
                raise OSError("stdout closed")
            def flush(self):
                raise OSError("stdout closed")
            def fileno(self):
                raise ValueError("stdout has no descriptor")
        failed = FailedStdout()
        with patch.object(sys, "stdout", failed):
            _report_terminal_success("PACKAGED_PERMISSION_SURFACES_EMPTY")
            self.assertIsNot(sys.stdout, failed)
            replacement = sys.stdout
        replacement.close()

        class ReclaimedStdout(FailedStdout):
            def fileno(self):
                return 17

        reclaimed = ReclaimedStdout()
        with patch.object(sys, "stdout", reclaimed), \
             patch.object(os, "open", return_value=17), \
             patch.object(os, "dup2") as duplicate, \
             patch.object(os, "close") as close_descriptor, \
             patch("builtins.open", side_effect=OSError("descriptor exhaustion")):
            _neutralize_failed_stdout(reclaimed)
            self.assertIsNone(sys.stdout)
        duplicate.assert_not_called()
        close_descriptor.assert_not_called()

    def test_terminal_success_survives_closed_os_pipe_after_real_publication(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            modules = (
                ("inspect_loader_dependencies", bounded),
                ("inspect_loader_bindings", publication),
                ("test_display_host_scope", sys.modules[__name__]),
            )
            mutable_root = root / "mutable-source-names"
            mutable_source_sentinel = root / "mutable-source-path-executed"
            mutable_root.mkdir()
            mutable_paths = []
            for name, module in modules:
                mutable_path = mutable_root / (name + ".py")
                mutable_path.write_bytes(_captured_production_source(module))
                mutable_paths.append(mutable_path)
            with patch.object(modules[0][1], "__file__", str(mutable_paths[0])), \
                 patch.object(modules[1][1], "__file__", str(mutable_paths[1])), \
                 patch.object(modules[2][1], "__file__", str(mutable_paths[2])):
                # Capture a reviewed source snapshot, then replace every source
                # pathname before the child starts.  The child must execute the
                # framed bytes, never any of these now-hostile names.
                sources = [_captured_production_source(module)
                           for _, module in modules]
                hostile = (
                    "from pathlib import Path\nPath(" +
                    repr(str(mutable_source_sentinel)) +
                    ").write_text('executed')\n")
                for mutable_path in mutable_paths:
                    mutable_path.write_text(hostile, encoding="utf-8")
                source_frames = b"".join(
                    len(source).to_bytes(8, "big") + source
                    for source in sources)
                source_digests = [
                    hashlib.sha256(source).hexdigest() for source in sources]
                process = subprocess.Popen(
                    [sys.executable, "-I", "-S", "-c",
                     _TERMINAL_SUCCESS_PUBLICATION_HELPER, str(root),
                     *source_digests],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE)
                process.stdout.close()
                try:
                    process.stdin.write(source_frames)
                    process.stdin.close()
                except BrokenPipeError:
                    process.stdin.close()
                try:
                    code = process.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)
                    self.fail(
                        "closed-reader publication child did not terminate")
                stderr = process.stderr.read(MAX_PERMISSION_EVIDENCE + 1)
                process.stderr.close()
                self.assertEqual(
                    code, 0, stderr.decode("utf-8", errors="replace"))
                verify_packaged_evidence(tuple(
                    path for path, _ in _packaged_fixture_entries(root)))
                self.assertFalse(mutable_source_sentinel.exists())

    def test_packaged_outputs_in_different_parents_fail_before_staging(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); other=root/"other"; other.mkdir()
            with self.assertRaises(PackagedPermissionError):
                publish_packaged_evidence(((root/"p",b"p\n"),(other/"x",b"x\n"),
                                            (root/"a",b"a\n")))
            self.assertFalse((root/"p").exists())

    def test_both_aapt_surfaces_receive_one_mutation_resistant_snapshot(self):
        from unittest.mock import patch
        valid_permissions=("package: " + PACKAGE + "\n").encode()
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); apk=root/"probe.apk"; apk.write_bytes(b"immutable-apk")
            paths=[]; blocked=[]
            def producer(command,*_):
                stable=Path(command[-1] if command[2]=="permissions" else command[-2])
                paths.append(str(stable))
                try:
                    with stable.open("r+b") as stream:
                        stream.seek(0); stream.write(b"X"); stream.flush()
                    blocked.append(False)
                except OSError:
                    blocked.append(True)
                if os.name == "nt":
                    moved=stable.parent.with_name(stable.parent.name+"-moved")
                    try:
                        stable.parent.rename(moved)
                        blocked.append(False)
                    except OSError:
                        blocked.append(True)
                return valid_permissions if len(paths)==1 else b"xml\n"
            with patch.object(bounded,"bounded_command",side_effect=producer), \
                 patch(__name__+".verify_permissions"):
                inspect_package(Path("aapt"),apk,root/"p",root/"x",root/"authority")
            self.assertEqual(len(set(paths)),1)
            self.assertTrue(all(blocked))
            self.assertEqual(apk.read_bytes(),b"immutable-apk")

    @unittest.skipUnless(os.name == "nt", "Windows source name/content pinning")
    def test_windows_source_apk_in_place_and_aba_attempts_are_blocked(self):
        from unittest.mock import patch
        valid_permissions=("package: " + PACKAGE + "\n").encode()
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); apk=root/"probe.apk"; apk.write_bytes(b"original")
            replacement=root/"replacement.apk"; replacement.write_bytes(b"replacement")
            attempts=[]
            def producer(*_):
                for mutate in (lambda: apk.write_bytes(b"changed"),
                               lambda: replacement.replace(apk)):
                    try:
                        mutate(); attempts.append(False)
                    except OSError:
                        attempts.append(True)
                return valid_permissions if len(attempts)==2 else b"xml\n"
            with patch.object(bounded,"bounded_command",side_effect=producer), \
                 patch(__name__+".verify_permissions"):
                inspect_package(Path("aapt"),apk,root/"p",root/"x",root/"authority")
            self.assertEqual(attempts,[True,True,True,True])
            self.assertEqual(apk.read_bytes(),b"original")

    @unittest.skipUnless(os.name == "posix", "POSIX package-name replacement fault")
    def test_package_name_replacement_between_producers_fails_closed(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); apk=root/"probe.apk"; apk.write_bytes(b"first")
            calls=[]
            def producer(*_):
                calls.append(True)
                replacement=root/"replacement.apk"; replacement.write_bytes(b"second")
                replacement.replace(apk)
                return ("package: " + PACKAGE + "\n").encode()
            with patch.object(bounded,"bounded_command",side_effect=producer), \
                 self.assertRaises(PackagedPermissionError):
                inspect_package(Path("aapt"),apk,root/"p",root/"x",root/"authority")
            self.assertEqual(len(calls),1)
            self.assertFalse((root/"authority").exists())

    @unittest.skipUnless(os.name == "posix", "POSIX same-content name ABA fault")
    def test_package_same_content_replacement_between_producers_fails_closed(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); apk=root/"probe.apk"; apk.write_bytes(b"same")
            calls=[]
            def producer(*_):
                calls.append(True)
                replacement=root/"replacement.apk"; replacement.write_bytes(b"same")
                replacement.replace(apk)
                return ("package: " + PACKAGE + "\n").encode()
            with patch.object(bounded,"bounded_command",side_effect=producer), \
                 self.assertRaises(PackagedPermissionError):
                inspect_package(Path("aapt"),apk,root/"p",root/"x",root/"authority")
            self.assertEqual(len(calls),1)
            self.assertFalse((root/"authority").exists())

    @unittest.skipUnless(os.name == "posix", "POSIX original-inode name ABA fault")
    def test_source_apk_rename_away_and_restore_original_is_rejected(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            apk = root / "probe.apk"
            moved = root / "probe-away.apk"
            apk.write_bytes(b"same retained bytes")
            # The enclosing retained-read context independently notices the
            # ctime-changing ABA at teardown too.  The inner assertion proves
            # _PinnedSourceApk.verify rejects it at its first post-read boundary
            # rather than relying on that later defense.
            with self.assertRaisesRegex(
                    bounded.InventoryError, "retained evidence changed during read"):
                with _PinnedSourceApk(apk) as source:
                    digest = hashlib.sha256(source.payload).hexdigest()
                    original_authority = source.authority_token
                    real_read = _bounded_stream
                    calls = 0

                    def read_then_name_aba(stream, size, limit):
                        nonlocal calls
                        result = real_read(stream, size, limit)
                        calls += 1
                        if calls == 1:
                            apk.rename(moved)
                            moved.rename(apk)
                        return result

                    with patch(__name__ + "._bounded_stream",
                               side_effect=read_then_name_aba), \
                         self.assertRaisesRegex(
                             PackagedPermissionError,
                             "retained authority changed during packaged inspection"):
                        source.verify(digest)
                    self.assertNotEqual(
                        source._posix_authority_token(os.stat(apk)),
                        original_authority)
                    self.assertEqual(apk.read_bytes(), b"same retained bytes")

    def test_permission_evidence_read_is_bounded(self):
        from unittest.mock import patch
        with patch.object(bounded, "read_bounded",
                          side_effect=bounded.InventoryError("evidence size budget/mismatch")) as opened:
            with self.assertRaises(PackagedPermissionError):
                read_bounded_text(Path("evidence"))
            opened.assert_called_once_with(Path("evidence"), MAX_PERMISSION_EVIDENCE)

    def test_manifest_has_no_permission_or_reader_hook(self):
        manifest = ET.parse(ROOT / "display-host/AndroidManifest.xml").getroot()
        self.assertEqual(manifest.attrib["package"], PACKAGE)
        permission_tags = [node.tag for node in manifest
                           if node.tag == "uses-permission" or node.tag.startswith("uses-permission-")]
        self.assertEqual(permission_tags, [])
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
        self.assertIn("!activity.lifecycle.onCalibrationAttached()", source)
        self.assertIn("if (admitted)", source)
        self.assertIn("if (current.get() == this) current.clear();", source)
        self.assertIn("DisplayProbeActivity.calibrationEnded(ownerInstance, actualDisplay)", source)
        self.assertIn("calibration ended; close and reopen probe to restart", source)
        self.assertIn("CalibrationActivity.closeOwned(instance)", source)
        self.assertIn("surface lost; restart display-only probe explicitly", source)
        self.assertIn("new DisplayProbeLifecycle(state != null)", source)
        self.assertIn("!lifecycle.onSurfaceReady()", source)
        self.assertIn("lifecycle.onDisplayCreated()", source)
        self.assertIn("lifecycle.onDisplayCreateFailed()", source)
        self.assertIn("lifecycle.onConfigurationChanged()", source)
        self.assertIn("lifecycle.onSurfaceDestroyed()", source)
        self.assertIn("lifecycle.onDisplayReleased()", source)
        self.assertIn("lifecycle.onCalibrationEnded()", source)
        self.assertIn("lifecycle.onFailure()", source)
        self.assertIn("lifecycle.onActivityDestroyed()", source)
        self.assertIn("lifecycle.onStateSaved()", source)
        self.assertIn("activity.lifecycle.isActive()", source)
        self.assertIn("onSaveInstanceState(Bundle state)", source)
        self.assertIn("controls.setVisibility(View.GONE)", source)
        self.assertIn("MotionEvent.ACTION_UP", source)


def _run_requested_mode():
    parser = argparse.ArgumentParser()
    parser.add_argument("--inspect-package", action="store_true")
    parser.add_argument("--verify-package", action="store_true")
    parser.add_argument("--aapt", type=Path)
    parser.add_argument("--apk", type=Path)
    parser.add_argument("--permissions-out", type=Path)
    parser.add_argument("--xmltree-out", type=Path)
    parser.add_argument("--authority-out", type=Path)
    parser.add_argument("--permissions", type=Path)
    parser.add_argument("--xmltree", type=Path)
    args, remaining = parser.parse_known_args()
    if args.inspect_package:
        if (args.verify_package or remaining or None in (args.aapt, args.apk, args.permissions_out,
                                  args.xmltree_out, args.authority_out)
                or args.permissions is not None or args.xmltree is not None):
            parser.error("complete --inspect-package arguments are required")
        inspect_package(args.aapt, args.apk, args.permissions_out, args.xmltree_out,
                        args.authority_out)
        _report_terminal_success("PACKAGED_PERMISSION_SURFACES_EMPTY")
    elif args.verify_package:
        if (remaining or args.aapt is not None or
                None in (args.apk, args.permissions_out, args.xmltree_out,
                         args.authority_out) or
                args.permissions is not None or args.xmltree is not None):
            parser.error("complete --verify-package arguments are required")
        verify_packaged_bundle(args.apk, (
            args.permissions_out, args.xmltree_out, args.authority_out),
            on_verified=lambda digest: _report_terminal_success(
                "PACKAGED_APK_AUTHORITY_VERIFIED sha256=" + digest))
    elif args.permissions is not None or args.xmltree is not None:
        if args.permissions is None or args.xmltree is None or remaining:
            parser.error("--permissions and --xmltree must be supplied together")
        verify_permissions(read_bounded_text(args.permissions), read_bounded_text(args.xmltree))
        _report_terminal_success("PACKAGED_PERMISSION_SURFACES_EMPTY")
    else:
        unittest.main(argv=[__file__, *remaining])


if __name__ == "__main__":
    try:
        _run_requested_mode()
    except publication.PublicationReviewRequired as error:
        try:
            print("PACKAGED_PUBLICATION_REVIEW_REQUIRED", str(error),
                  file=sys.stderr)
        except (OSError, ValueError):
            pass
        raise SystemExit(2)
