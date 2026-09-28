"""Explicit one-variant executable for the disposable synthetic API-30 app.

Never installs an APK, discovers a device, retries a mutating provider call, or
targets a stock app. Importing this module is inert. See README before use.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import sys

from emulator_trial import EmulatorApp, WorkerTransport
from emulator_wire import (ExactAdb, OwnedFridaServer, file_sha,
                           verify_installed_apk, verify_signed_apk)
from host_protocol import Pins, TrialError, VARIANTS, need, run_mockable


# Reviewed synthetic artifacts only. CLI digests are assertions, not authority.
REVIEWED_APK_SHA256 = "d4c38a2c2b914819ec41c13e7e4b08fa78eba1767f40335b135dac99092bad0c"
REVIEWED_SIGNER_SHA256 = "4d4f0f18e10114c7a801bcdb87dd4fd2d75ebc24ca0ad5bcb6967009e62ead6a"
REVIEWED_SERVER_SHA256 = "9dcb1c12fa528070f2f6590b245e2c66cb1f931e0975bc911d9ff476394879d7"
REVIEWED_SERVER_BYTES = 110_837_320
REVIEWED_BUNDLE_SHA256 = "241fd6a94067b26a737df8ddf6c192b82895006472c434cae4cbd06dc29a2d66"
REVIEWED_BUNDLE_BYTES = 476_101


class RunnerFailure(TrialError):
    """Dominant fixed code plus earlier fixed codes needed to audit cleanup."""

    def __init__(self, code: str, *, primary_code: str | None = None,
                 cleanup_codes: tuple[str, ...] = (),
                 refresh_evidence: dict | None = None) -> None:
        super().__init__(code)
        self.primary_code = primary_code
        self.cleanup_codes = cleanup_codes
        self.refresh_evidence = refresh_evidence


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--execute-synthetic-api30-only", action="store_true",
                   help="required explicit opt-in; never use with the Nomad")
    p.add_argument("--variant", required=True, choices=sorted(VARIANTS))
    for name in ("adb", "apksigner", "apk", "server", "python",
                 "frida-site", "bundle"):
        p.add_argument("--" + name, required=True, type=Path)
    for name in ("apk-sha256", "signer-sha256", "server-sha256",
                 "bundle-sha256"):
        p.add_argument("--" + name, required=True)
    return p


def _lock() -> tuple[int, Path]:
    path = Path(__file__).resolve().with_name(".synthetic-emulator.lock")
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    if os.name == "nt":
        # Windows cannot reliably unlink a CRT-open file. This flag ties
        # deletion to our exact handle at close, never to a later path lookup.
        temporary = getattr(os, "O_TEMPORARY", 0)
        need(temporary != 0, "TRIAL_LOCK_UNSUPPORTED")
        flags |= temporary
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as error:
        raise TrialError("TRIAL_LOCK_PRESENT") from error
    return fd, path


def _unlock(fd: int, path: Path) -> None:
    try:
        owner = os.fstat(fd)
        current = path.lstat()
        need(stat.S_ISREG(owner.st_mode) and stat.S_ISREG(current.st_mode) and
             owner.st_ino != 0 and current.st_ino != 0 and
             owner.st_ino == current.st_ino and owner.st_dev == current.st_dev,
             "LOCK_CLEANUP_UNCERTAIN")
        if os.name != "nt":
            path.unlink()
    except OSError as error:
        raise TrialError("LOCK_CLEANUP_UNCERTAIN") from error
    finally:
        try:
            os.close(fd)
        except OSError as error:
            raise TrialError("LOCK_CLEANUP_UNCERTAIN") from error
    # On Windows O_TEMPORARY removes only our handle's file. A replacement
    # remains untouched and is an uncertain cleanup, never a clean verdict.
    try:
        path.lstat()
    except FileNotFoundError:
        return
    except OSError as error:
        raise TrialError("LOCK_CLEANUP_UNCERTAIN") from error
    raise TrialError("LOCK_CLEANUP_UNCERTAIN")


def _exact_size(path: Path, size: int) -> None:
    try:
        need(path.is_file() and not path.is_symlink() and
             path.stat().st_size == size, "REVIEWED_SIZE_MISMATCH")
    except OSError as error:
        raise TrialError("REVIEWED_SIZE_MISMATCH") from error


def run(args: argparse.Namespace) -> dict:
    if not args.execute_synthetic_api30_only:
        raise TrialError("SYNTHETIC_OPT_IN_REQUIRED")
    need(args.apk_sha256 == REVIEWED_APK_SHA256 and
         args.signer_sha256 == REVIEWED_SIGNER_SHA256 and
         args.server_sha256 == REVIEWED_SERVER_SHA256 and
         args.bundle_sha256 == REVIEWED_BUNDLE_SHA256,
         "REVIEWED_PIN_MISMATCH")
    pins = Pins(args.apk_sha256, args.signer_sha256)
    # Check every local input before contacting ADB. Exact hashes are supplied
    # by the separately reviewed disposable build, not inferred from ambient
    # tools or a device-selected APK.
    verify_signed_apk(args.apksigner, args.apk,
                      args.apk_sha256, args.signer_sha256)
    _exact_size(args.server, REVIEWED_SERVER_BYTES)
    file_sha(args.server, args.server_sha256, maximum=120_000_000)
    _exact_size(args.bundle, REVIEWED_BUNDLE_BYTES)
    file_sha(args.bundle, args.bundle_sha256, maximum=2_097_152)
    if not (args.python.is_absolute() and args.python.is_file() and
            args.frida_site.is_absolute() and args.frida_site.is_dir()):
        raise TrialError("WORKER_PATH_INVALID")
    fd, lock_path = _lock()
    server: OwnedFridaServer | None = None
    app: EmulatorApp | None = None
    verdict: dict | None = None
    failure: TrialError | None = None
    primary_failure: TrialError | None = None
    cleanup_codes: list[str] = []
    refresh_evidence: dict | None = None
    try:
        adb = ExactAdb(args.adb)
        adb.check_emulator()
        verify_installed_apk(adb, REVIEWED_APK_SHA256)
        server = OwnedFridaServer(adb, args.server, args.server_sha256)
        server.prepare()
        app = EmulatorApp(adb, pins)
        transport = WorkerTransport(app, args.python, args.frida_site,
                                    args.bundle, args.bundle_sha256)
        verdict = run_mockable(app, transport, pins, args.variant)
    except BaseException as error:
        primary_failure = (error if isinstance(error, TrialError)
                           else TrialError("TRIAL_UNCERTAIN"))
        failure = primary_failure
        evidence_reader = getattr(app, "refresh_failure_evidence", None)
        if callable(evidence_reader):
            try:
                refresh_evidence = evidence_reader()
            except BaseException:
                pass  # Diagnostic must never mask the original failure.
        if (app is not None and app.launch_attempted and
                app.prearm_host_start is None):
            try:
                app.cleanup_unarmed_launch()
                failure = TrialError("PREFLIGHT_UNKNOWN_CLEANED")
            except BaseException:
                failure = TrialError("PREARM_CLEANUP_UNCERTAIN")
                cleanup_codes.append(str(failure))
    finally:
        if server is not None:
            try:
                server.cleanup()
            except BaseException:
                failure = TrialError("SERVER_CLEANUP_UNCERTAIN")
                cleanup_codes.append(str(failure))
        try:
            _unlock(fd, lock_path)
        except BaseException:
            failure = TrialError("LOCK_CLEANUP_UNCERTAIN")
            cleanup_codes.append(str(failure))
    if cleanup_codes:
        raise RunnerFailure(cleanup_codes[-1],
                            primary_code=(str(primary_failure)
                                          if primary_failure is not None else None),
                            cleanup_codes=tuple(cleanup_codes),
                            refresh_evidence=refresh_evidence)
    if failure is not None:
        if refresh_evidence is not None or (primary_failure is not None and
                                            failure is not primary_failure):
            raise RunnerFailure(str(failure),
                primary_code=(str(primary_failure)
                              if primary_failure is not None and
                                 failure is not primary_failure else None),
                refresh_evidence=refresh_evidence)
        raise failure
    if verdict is None:
        raise TrialError("TRIAL_UNCERTAIN")
    return verdict


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        result = run(args)
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except TrialError as error:
        output = {"verdict": "UNKNOWN", "code": str(error),
                  "observationOnly": True,
                  "compositingAdmitted": False,
                  "completeMutationCoverage": False,
                  "portRevision": -1}
        if isinstance(error, RunnerFailure):
            if error.primary_code is not None:
                output["primaryCode"] = error.primary_code
            if error.cleanup_codes:
                output["cleanupCodes"] = list(error.cleanup_codes)
            if error.refresh_evidence is not None:
                output["refreshEvidence"] = error.refresh_evidence
        print(json.dumps(output,
                         sort_keys=True, separators=(",", ":")))
        return 2


if __name__ == "__main__":
    sys.exit(main())
