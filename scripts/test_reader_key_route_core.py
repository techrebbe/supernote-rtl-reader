#!/usr/bin/env python3
"""Compile real isolated T014 Core; optionally compile Host against actual Android/RN jars.

No ADB, emulator, package/installer mutation or device action. Source templates
are mechanically materialized inside a fresh tempfile, never the repository.
Android compilation establishes API compatibility, not native focus/HID delivery.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument("--android-classpath")
    parser.add_argument("--mutations", action="store_true")
    args = parser.parse_args()
    root = Path(args.root).resolve()
    java_bin = Path(os.environ.get("JAVA_HOME", "")) / "bin"
    javac = shutil.which("javac", path=str(java_bin)) or shutil.which("javac")
    java = shutil.which("java", path=str(java_bin)) or shutil.which("java")
    if not javac or not java:
        raise SystemExit("test_reader_key_route_core: JDK unavailable")
    with tempfile.TemporaryDirectory(prefix="rtl-t014-core-") as temporary:
        build = Path(temporary).resolve()
        core = build / "ReaderKeyRouteCore.java"
        core.write_text((root / "native/ReaderKeyRouteCore.java.template").read_text(encoding="utf-8").replace("__PACKAGE__", "t014"), encoding="utf-8")
        tests = root / "scripts/ReaderKeyRouteCoreTests.java"
        subprocess.run([javac, "-encoding", "UTF-8", "-d", str(build), str(core), str(tests)], check=True, timeout=60)
        subprocess.run([java, "-cp", str(build), "t014.ReaderKeyRouteCoreTests"], check=True, timeout=60)
        host = build / "ReaderKeyHost.java"
        host.write_text((root / "native/ReaderKeyHost.java.template").read_text(encoding="utf-8").replace("__PACKAGE__", "t014"), encoding="utf-8")
        bridge = []
        for name in ("ReaderKeyConfiguration", "ReaderKeyEvent", "ReaderKeyHostManager"):
            destination = build / f"{name}.java"
            destination.write_text((root / f"native/{name}.java.template").read_text(encoding="utf-8").replace("__PACKAGE__", "t014"), encoding="utf-8")
            bridge.append(str(destination))
        model = build / "model"
        model.mkdir()
        stubs = sorted((root / "scripts/reader_key_host_test_stubs").rglob("*.java"))
        if len(stubs) != 19:
            raise SystemExit("test_reader_key_route_core: unexpected callback model inventory")
        subprocess.run([javac, "-encoding", "UTF-8", "-d", str(model), str(core), str(host), *bridge, str(root / "scripts/ReaderKeyHostTests.java"), str(root / "scripts/ReaderKeyBridgeTests.java"), *(str(item) for item in stubs)], check=True, timeout=60)
        subprocess.run([java, "-cp", str(model), "t014.ReaderKeyHostTests"], check=True, timeout=60)
        subprocess.run([java, "-cp", str(model), "t014.ReaderKeyBridgeTests"], check=True, timeout=60)
        if args.mutations:
            core_text = core.read_text(encoding="utf-8")
            host_text = host.read_text(encoding="utf-8")
            configuration = build / "ReaderKeyConfiguration.java"
            configuration_text = configuration.read_text(encoding="utf-8")
            mutations = [
                ("state-sink-escapes", "host", "try { recipient.state(state); } catch (RuntimeException failure) { drop(); }", "recipient.state(state);", "t014.ReaderKeyHostTests"),
                ("detach-attachment-aba", "host", "lifecycleAttached = false;", "lifecycleAttached = true;", "t014.ReaderKeyHostTests"),
                ("long-hold-falls-through", "core", 'repeatCount < 0) return new Decision(false, "invalid", null);', 'repeatCount < 0 || repeatCount > 255) return new Decision(false, "invalid", null);', "t014.ReaderKeyRouteCoreTests"),
                ("terminal-sink-escapes", "host", """try { old.state(terminal); } catch (RuntimeException ignored) {
                // Revocation and Sink release already completed. A terminal
                // notification failure cannot rearm or escape key dispatch.
            }""", "old.state(terminal);", "t014.ReaderKeyHostTests"),
                ("vertical-core-missing", "core", "key == 19 || key == 20 || ", "", "t014.ReaderKeyRouteCoreTests"),
                ("vertical-config-missing", "configuration", "key == 19 || key == 20 || ", "", "t014.ReaderKeyBridgeTests"),
                ("vertical-diagnostic-missing", "host", "key == 19 || key == 20 || ", "", "t014.ReaderKeyHostTests"),
            ]
            for name, target, old, new, suite in mutations:
                originals = {"core": core_text, "host": host_text, "configuration": configuration_text}
                if originals[target].count(old) != 1:
                    raise SystemExit(f"test_reader_key_route_core: ambiguous mutation {name}")
                mutant = build / name
                mutant.mkdir()
                mutated_core = mutant / "ReaderKeyRouteCore.java"
                mutated_host = mutant / "ReaderKeyHost.java"
                mutated_configuration = mutant / "ReaderKeyConfiguration.java"
                mutated_core.write_text(core_text.replace(old, new) if target == "core" else core_text, encoding="utf-8")
                mutated_host.write_text(host_text.replace(old, new) if target == "host" else host_text, encoding="utf-8")
                mutated_configuration.write_text(configuration_text.replace(old, new) if target == "configuration" else configuration_text, encoding="utf-8")
                mutant_bridge = [str(mutated_configuration) if item == str(configuration) else item for item in bridge]
                subprocess.run([javac, "-encoding", "UTF-8", "-d", str(mutant), str(mutated_core), str(mutated_host), *mutant_bridge, str(tests), str(root / "scripts/ReaderKeyHostTests.java"), str(root / "scripts/ReaderKeyBridgeTests.java"), *(str(item) for item in stubs)], check=True, timeout=60)
                result = subprocess.run([java, "-cp", str(mutant), suite], capture_output=True, text=True, timeout=60)
                missing_vertical_key = name == "vertical-core-missing" and "Unsupported/duplicate key" in result.stderr
                if result.returncode == 0 or not missing_vertical_key and "AssertionError" not in result.stderr and "state failure" not in result.stderr:
                    raise SystemExit(f"test_reader_key_route_core: mutation not rejected by expected regression {name}: {result.stderr}")
                print(f"Reader key accepted-defect mutation: REJECTED {name}")
        if args.android_classpath:
            paths = [Path(item).resolve() for item in args.android_classpath.split(os.pathsep)]
            if not paths or any(not item.is_file() or item.suffix != ".jar" for item in paths):
                raise SystemExit("test_reader_key_route_core: explicit Android classpath must contain existing jars only")
            module = build / "ReaderKeyModule.java"
            module.write_text((root / "native/ReaderKeyModule.java.template").read_text(encoding="utf-8").replace("__PACKAGE__", "t014"), encoding="utf-8")
            subprocess.run([javac, "-encoding", "UTF-8", "-cp", os.pathsep.join(str(item) for item in paths), "-d", str(build), str(core), str(host), *bridge, str(module)], check=True, timeout=60)
            print("Reader key Host/atomic RN bridge: actual Android/RN API compile PASS; device delivery NOT TESTED")


if __name__ == "__main__":
    main()
