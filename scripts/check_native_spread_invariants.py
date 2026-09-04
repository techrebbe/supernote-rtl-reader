#!/usr/bin/env python3
"""Verify fail-closed Native Spread handshake and lifecycle invariants."""

from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path

import yaml


def fail(message: str) -> None:
    raise SystemExit(f"check_native_spread_invariants.py: {message}")


def normalized_text_sha256(path: Path) -> str:
    """Hash canonical LF text so frozen review gates are checkout-independent."""

    text = path.read_text(encoding="utf-8")
    canonical = text.replace("\r\n", "\n").replace("\r", "\n")
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def tokenize_powershell(text: str) -> list[tuple[str, str, int, int]]:
    """Tokenize enough PowerShell to make review gates comment-aware.

    Comments, whitespace, and explicit line continuations are discarded. Quoted
    strings remain single tokens, so text inside a comment or string cannot act
    as an executable-code decoy.
    """

    tokens: list[tuple[str, str, int, int]] = []
    index = 0
    while index < len(text):
        char = text[index]
        if char.isspace():
            index += 1
            continue
        if char == "`" and index + 1 < len(text):
            continuation = index + 1
            if text[continuation] == "\r":
                index = continuation + 1
                if index < len(text) and text[index] == "\n":
                    index += 1
                continue
            if text[continuation] == "\n":
                index = continuation + 1
                continue
        if char == "#":
            cr = text.find("\r", index + 1)
            lf = text.find("\n", index + 1)
            line_ends = [position for position in (cr, lf) if position >= 0]
            index = len(text) if not line_ends else min(line_ends) + 1
            continue
        if text.startswith("<#", index):
            comment_end = text.find("#>", index + 2)
            if comment_end < 0:
                fail("native build contains an unterminated PowerShell block comment")
            index = comment_end + 2
            continue
        if (
            char == "@"
            and index + 2 < len(text)
            and text[index + 1] in ("'", '"')
            and text[index + 2] in ("\r", "\n")
        ):
            quote = text[index + 1]
            start = index
            line_start = index + 2
            if text[line_start] == "\r":
                line_start += 1
                if line_start < len(text) and text[line_start] == "\n":
                    line_start += 1
            else:
                line_start += 1
            index = line_start
            while index <= len(text):
                cr = text.find("\r", index)
                lf = text.find("\n", index)
                line_ends = [position for position in (cr, lf) if position >= 0]
                line_end = len(text) if not line_ends else min(line_ends)
                if text[index:line_end] == quote + "@":
                    index = line_end
                    break
                if not line_ends:
                    fail("native build contains an unterminated PowerShell here-string")
                index = line_end + 1
                if (
                    text[line_end] == "\r"
                    and index < len(text)
                    and text[index] == "\n"
                ):
                    index += 1
            tokens.append(("string", text[start:index], start, index))
            continue
        if char in ("'", '"'):
            quote = char
            start = index
            index += 1
            while index < len(text):
                if quote == "'" and text.startswith("''", index):
                    index += 2
                    continue
                if quote == '"' and text[index] == "`":
                    index += min(2, len(text) - index)
                    continue
                if text[index] == quote:
                    index += 1
                    break
                index += 1
            else:
                fail("native build contains an unterminated PowerShell string")
            tokens.append(("string", text[start:index], start, index))
            continue
        if char == "$":
            start = index
            index += 1
            if index < len(text) and text[index] == "{":
                variable_end = text.find("}", index + 1)
                if variable_end < 0:
                    fail("native build contains an unterminated PowerShell variable")
                index = variable_end + 1
            else:
                while index < len(text) and (
                    text[index].isalnum() or text[index] in "_:?"
                ):
                    index += 1
            tokens.append(("variable", text[start:index].casefold(), start, index))
            continue
        if char.isalpha() or char == "_" or (
            char == "-"
            and index + 1 < len(text)
            and (text[index + 1].isalpha() or text[index + 1] == "_")
        ):
            start = index
            index += 1
            while index < len(text) and (
                text[index].isalnum() or text[index] in "_-?"
            ):
                index += 1
            tokens.append(("word", text[start:index].casefold(), start, index))
            continue
        if char.isdigit():
            start = index
            index += 1
            while index < len(text) and text[index].isalnum():
                index += 1
            tokens.append(("number", text[start:index].casefold(), start, index))
            continue
        start = index
        if text.startswith("::", index):
            index += 2
        else:
            index += 1
        tokens.append(("symbol", text[start:index], start, index))
    return tokens


def powershell_token_keys(
    tokens: list[tuple[str, str, int, int]],
) -> list[tuple[str, str]]:
    return [(kind, value) for kind, value, _start, _end in tokens]


def powershell_sequence_positions(
    tokens: list[tuple[str, str, int, int]],
    snippet: str,
) -> list[int]:
    expected = powershell_token_keys(tokenize_powershell(snippet))
    actual = powershell_token_keys(tokens)
    if not expected:
        fail("internal error: empty PowerShell invariant snippet")
    return [
        index
        for index in range(len(actual) - len(expected) + 1)
        if actual[index : index + len(expected)] == expected
    ]


def require_unique_powershell_sequence(
    tokens: list[tuple[str, str, int, int]],
    snippet: str,
    label: str,
) -> int:
    positions = powershell_sequence_positions(tokens, snippet)
    if len(positions) != 1:
        fail(f"expected exactly one executable {label}, found {len(positions)}")
    return positions[0]


def powershell_brace_depths(
    tokens: list[tuple[str, str, int, int]],
) -> list[int]:
    depths: list[int] = []
    depth = 0
    for kind, value, _start, _end in tokens:
        depths.append(depth)
        if kind == "symbol" and value == "{":
            depth += 1
        elif kind == "symbol" and value == "}":
            depth -= 1
            if depth < 0:
                fail("native build contains an unmatched PowerShell closing brace")
    if depth != 0:
        fail("native build contains an unmatched PowerShell opening brace")
    return depths


def matching_powershell_brace_token(
    tokens: list[tuple[str, str, int, int]],
    opening: int,
    label: str,
) -> int:
    if opening >= len(tokens) or tokens[opening][:2] != ("symbol", "{"):
        fail(f"could not locate {label} opening brace")
    depth = 0
    for index in range(opening, len(tokens)):
        kind, value, _start, _end = tokens[index]
        if kind == "symbol" and value == "{":
            depth += 1
        elif kind == "symbol" and value == "}":
            depth -= 1
            if depth == 0:
                return index
    fail(f"could not locate {label} closing brace")
    raise AssertionError("unreachable")


def extract_powershell_function_tokens(
    tokens: list[tuple[str, str, int, int]],
    name: str,
) -> list[tuple[str, str, int, int]]:
    keys = powershell_token_keys(tokens)
    signature = [("word", "function"), ("word", name.casefold())]
    starts = [
        index
        for index in range(len(keys) - 1)
        if keys[index : index + 2] == signature
    ]
    if len(starts) != 1:
        fail(f"expected exactly one executable PowerShell function {name}")
    start = starts[0]
    if start + 2 >= len(tokens) or tokens[start + 2][:2] != ("symbol", "{"):
        fail(f"PowerShell function {name} has no structural body")
    depth = 0
    for index in range(start + 2, len(tokens)):
        kind, value, _token_start, _token_end = tokens[index]
        if kind == "symbol" and value == "{":
            depth += 1
        elif kind == "symbol" and value == "}":
            depth -= 1
            if depth == 0:
                return tokens[start : index + 1]
    fail(f"PowerShell function {name} has an unterminated body")
    raise AssertionError("unreachable")


def require_markers(text: str, markers: tuple[str, ...], label: str) -> None:
    missing = [marker for marker in markers if marker not in text]
    if missing:
        fail(f"{label} is missing required markers: {missing}")


def mask_cpp_comments_and_literals(text: str) -> str:
    """Mask C++ comments and literals while preserving source offsets."""

    pattern = re.compile(
        r"//[^\r\n]*|/\*.*?\*/|\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'",
        re.DOTALL,
    )

    def mask(match: re.Match[str]) -> str:
        return "".join("\n" if char == "\n" else " " for char in match.group(0))

    return pattern.sub(mask, text)


def mask_comments_preserve_literals(text: str) -> str:
    """Mask comments while keeping quoted source literals and offsets."""

    pattern = re.compile(
        r"//[^\r\n]*|/\*.*?\*/|\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'",
        re.DOTALL,
    )

    def mask(match: re.Match[str]) -> str:
        value = match.group(0)
        if not value.startswith("/"):
            return value
        return "".join("\n" if char == "\n" else " " for char in value)

    return pattern.sub(mask, text)


def compact_code(text: str) -> str:
    """Remove C-style comments and insignificant whitespace for exact checks."""

    return re.sub(r"\s+", "", mask_comments_preserve_literals(text))


def mask_yaml_comments(text: str) -> str:
    """Mask workflow line comments while preserving offsets and newlines."""

    return re.sub(
        r"(?m)#.*$",
        lambda match: " " * len(match.group(0)),
        text,
    )


def mask_shell_comments(text: str) -> str:
    """Mask executable shell comments without treating ${#array[@]} as one."""

    chars = list(text)
    index = 0
    quote: str | None = None
    while index < len(chars):
        char = chars[index]
        if quote is not None:
            if quote == '"' and char == "\\":
                index += 2
                continue
            if char == quote:
                quote = None
            index += 1
            continue
        if char in ("'", '"'):
            quote = char
            index += 1
            continue
        comment_boundary = (
            index == 0
            or chars[index - 1].isspace()
            or chars[index - 1] in ";|&()"
        )
        if char == "#" and comment_boundary:
            while index < len(chars) and chars[index] not in "\r\n":
                chars[index] = " "
                index += 1
            continue
        index += 1
    return "".join(chars)


def extract_cpp_function(text: str, signature: str, label: str) -> tuple[str, str]:
    """Return the unique C++ definition and a comment/literal-masked copy."""

    masked = mask_cpp_comments_and_literals(text)
    candidates: list[tuple[int, int]] = []
    search_from = 0
    while True:
        start = masked.find(signature, search_from)
        if start < 0:
            break
        parameter_start = start + len(signature) - 1
        parameter_depth = 0
        parameter_end = -1
        for index in range(parameter_start, len(masked)):
            char = masked[index]
            if char == "(":
                parameter_depth += 1
            elif char == ")":
                parameter_depth -= 1
                if parameter_depth == 0:
                    parameter_end = index
                    break
        if parameter_end >= 0:
            body_start = parameter_end + 1
            while body_start < len(masked) and masked[body_start].isspace():
                body_start += 1
            if body_start < len(masked) and masked[body_start] == "{":
                body_end = matching_brace(masked, body_start, label) + 1
                candidates.append((start, body_end))
        search_from = start + len(signature)
    if len(candidates) != 1:
        fail(
            f"expected exactly one {label} definition, found "
            f"{len(candidates)}"
        )
    start, end = candidates[0]
    return text[start:end], masked[start:end]


def extract_java_method(text: str, signature: str, label: str) -> str:
    """Return one comment-masked Java method definition by signature prefix."""

    masked = mask_comments_preserve_literals(text)
    starts = [
        match.start()
        for match in re.finditer(re.escape(signature), masked)
    ]
    if len(starts) != 1:
        fail(f"expected exactly one {label}, found {len(starts)}")
    start = starts[0]
    body_start = masked.find("{", start + len(signature))
    if body_start < 0:
        fail(f"could not locate {label} body")
    body_end = matching_brace(masked, body_start, label) + 1
    return masked[start:body_end]


def matching_brace(text: str, opening: int, label: str) -> int:
    if opening < 0 or opening >= len(text) or text[opening] != "{":
        fail(f"could not locate {label} opening brace")
    depth = 0
    for index in range(opening, len(text)):
        char = text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
    fail(f"could not locate {label} closing brace")


def matching_parenthesis(text: str, opening: int, label: str) -> int:
    if opening < 0 or opening >= len(text) or text[opening] != "(":
        fail(f"could not locate {label} opening parenthesis")
    depth = 0
    for index in range(opening, len(text)):
        char = text[index]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index
    fail(f"could not locate {label} closing parenthesis")


def brace_depth_at(text: str, position: int) -> int:
    """Return lexical brace depth immediately before *position*."""

    depth = 0
    for char in text[:position]:
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
    return depth


def identifier_mutations(text: str, name: str) -> list[re.Match[str]]:
    """Find assignments, compound assignments, and increments for a name."""

    escaped = re.escape(name)
    return list(
        re.finditer(
            rf"(?:\+\+|--)\s*\b{escaped}\b|"
            rf"\b{escaped}\b\s*(?:\+\+|--|(?:>>>|>>|<<|[+\-*/%&|^])?=(?!=))",
            text,
        )
    )


def require_cpp_pattern(text: str, pattern: str, label: str) -> int:
    match = re.search(pattern, text, re.DOTALL)
    if match is None:
        fail(f"{label} does not match the required native control flow")
    return match.start()


def require_only_cpp_calls(
    masked_function: str,
    allowed_calls: set[str],
    label: str,
) -> None:
    calls = set(
        re.findall(
            r"([A-Za-z_][A-Za-z0-9_:]*)\s*\(", masked_function
        )
    )
    calls.update(
        re.findall(
            r"\(\s*\*?\s*([A-Za-z_][A-Za-z0-9_:]*)\s*\)\s*\(",
            masked_function,
        )
    )
    calls.update(
        re.findall(
            r"([A-Za-z_][A-Za-z0-9_:]*)\s*<[^;{}()]*>\s*\(",
            masked_function,
        )
    )
    unexpected = sorted(calls - allowed_calls)
    if unexpected:
        fail(f"{label} invokes unexpected synchronous calls: {unexpected}")
    if re.search(
        r"(?i)(?:__android_log|android_log|logcat|printf|fprintf|vprintf|"
        r"vfprintf|puts|fputs|syslog|std::(?:cerr|clog|cout))",
        masked_function,
    ):
        fail(f"{label} performs synchronous native logging or output")


def check(repo_root: Path) -> None:
    plugin_path = repo_root / "native" / "ReaderPreferencesModule.kt.template"
    module_path = (
        repo_root
        / "native-spread-module"
        / "src"
        / "com"
        / "techrebbe"
        / "supernote"
        / "spreadprobe"
        / "SpreadProbe.java"
    )
    v2_hooks_path = (
        repo_root
        / "native-spread-module"
        / "src"
        / "com"
        / "techrebbe"
        / "supernote"
        / "spreadprobe"
        / "v2android"
        / "NativeReaderV2Hooks.java"
    )
    v2_marker_claim_path = (
        repo_root
        / "native-spread-module"
        / "src"
        / "com"
        / "techrebbe"
        / "supernote"
        / "spreadprobe"
        / "v2"
        / "NativeReaderV2MarkerClaim.java"
    )
    manifest_path = repo_root / "native-spread-module" / "AndroidManifest.xml"
    native_build_path = repo_root / "native-spread-module" / "build.ps1"
    native_cpp_path = (
        repo_root / "native-spread-module" / "native" / "spread_probe_native.cpp"
    )
    trace_script_path = repo_root / "native-spread-module" / "trace.ps1"
    trace_helper_test_path = (
        repo_root / "scripts" / "test_trace_helper_fail_closed.ps1"
    )
    app_path = repo_root / "overlay" / "App.js"
    workflow_path = repo_root / ".github" / "workflows" / "build.yml"
    plugin_build_path = repo_root / "build.sh"
    packager_patch_path = repo_root / "scripts" / "patch_plugin_packager.py"
    package_verifier_path = repo_root / "scripts" / "verify_plugin_package.py"
    package_test_path = (
        repo_root / "scripts" / "test_plugin_packaging_fail_closed.py"
    )
    pdf_view_path = repo_root / "native" / "PdfPageView.kt.template"
    pdf_view_manager_path = repo_root / "native" / "PdfPageViewManager.kt.template"
    direct_patch_path = repo_root / "scripts" / "patch_direct_view.py"
    workflow_path = repo_root / ".github" / "workflows" / "build.yml"

    plugin = plugin_path.read_text(encoding="utf-8")
    module = module_path.read_text(encoding="utf-8")
    v2_hooks = v2_hooks_path.read_text(encoding="utf-8")
    v2_marker_claim = v2_marker_claim_path.read_text(encoding="utf-8")
    manifest = manifest_path.read_text(encoding="utf-8")
    native_build = native_build_path.read_text(encoding="utf-8")
    native_cpp = native_cpp_path.read_text(encoding="utf-8")
    trace_script = trace_script_path.read_text(encoding="utf-8")
    trace_helper_test = trace_helper_test_path.read_text(encoding="utf-8")
    app = app_path.read_text(encoding="utf-8")
    workflow = workflow_path.read_text(encoding="utf-8")
    plugin_build_script = plugin_build_path.read_text(encoding="utf-8")
    packager_patch = packager_patch_path.read_text(encoding="utf-8")
    package_verifier = package_verifier_path.read_text(encoding="utf-8")
    package_test = package_test_path.read_text(encoding="utf-8")
    pdf_view = pdf_view_path.read_text(encoding="utf-8")
    pdf_view_manager = pdf_view_manager_path.read_text(encoding="utf-8")
    direct_patch = direct_patch_path.read_text(encoding="utf-8")
    workflow = workflow_path.read_text(encoding="utf-8")

    parsed_workflow = yaml.safe_load(workflow)
    if not isinstance(parsed_workflow, dict):
        fail("workflow YAML must decode to an object")
    if parsed_workflow.get("permissions") != {"contents": "read"}:
        fail("workflow token permissions must be explicitly read-only")
    jobs = parsed_workflow.get("jobs")
    if not isinstance(jobs, dict):
        fail("workflow jobs must decode to an object")
    native_assembly_job = jobs.get("native-spread-build")
    native_release_job = jobs.get("native-spread-upgrade-artifact")
    plugin_job_definition = jobs.get("build")
    test_job = jobs.get("virtual-spread-tests")
    assembly_job = jobs.get("virtual-spread-release-assembly")
    release_job = jobs.get("virtual-spread-release-apk")
    if any(
        not isinstance(job, dict)
        for job in (
            native_assembly_job,
            native_release_job,
            plugin_job_definition,
            test_job,
            assembly_job,
            release_job,
        )
    ):
        fail(
            "workflow must contain Native Reader, plugin, Virtual Spread test, "
            "clean assembly, and protected release jobs"
        )
    assert isinstance(native_assembly_job, dict)
    assert isinstance(native_release_job, dict)
    assert isinstance(plugin_job_definition, dict)
    assert isinstance(assembly_job, dict)
    if release_job.get("if") != (
        "github.event_name == 'push' && github.ref == 'refs/heads/main'"
    ):
        fail("protected release job must run only for trusted main pushes")
    if assembly_job.get("if") != (
        "github.event_name == 'push' && github.ref == 'refs/heads/main'"
    ) or assembly_job.get("needs") != "virtual-spread-tests":
        fail("clean assembly must follow tests on trusted main only")
    if release_job.get("needs") != "virtual-spread-release-assembly":
        fail("protected release job must depend on clean assembly")
    if release_job.get("environment") != "virtual-spread-release":
        fail("protected release job must use the signing environment")
    test_steps = test_job.get("steps")
    assembly_steps = assembly_job.get("steps")
    release_steps = release_job.get("steps")
    if any(
        not isinstance(steps, list)
        for steps in (test_steps, assembly_steps, release_steps)
    ):
        fail("workflow job steps must be lists")
    assert isinstance(assembly_steps, list)

    all_steps: list[dict[str, object]] = []
    for job_name, job in jobs.items():
        if not isinstance(job, dict) or not isinstance(job.get("steps"), list):
            fail(f"workflow job has invalid steps: {job_name}")
        for step in job["steps"]:
            if not isinstance(step, dict):
                fail(f"workflow job has a non-object step: {job_name}")
            all_steps.append(step)
            uses = step.get("uses")
            if uses is not None and (
                not isinstance(uses, str)
                or re.fullmatch(r"[^/@]+/[^@]+@[0-9a-f]{40}", uses) is None
            ):
                fail(f"workflow action is not commit-pinned: {uses}")
            if isinstance(uses, str) and uses.startswith("actions/checkout@"):
                settings = step.get("with")
                if not isinstance(settings, dict) or settings.get(
                    "persist-credentials"
                ) is not False:
                    fail("workflow checkout must not persist credentials")

    def named_step(steps: list[object], name: str) -> dict[str, object]:
        matches = [
            step
            for step in steps
            if isinstance(step, dict) and step.get("name") == name
        ]
        if len(matches) != 1:
            fail(f"workflow must contain exactly one step named {name!r}")
        return matches[0]

    native_condition = " ".join(str(native_release_job.get("if", "")).split())
    expected_native_condition = (
        "(github.event_name == 'push' && github.ref == 'refs/heads/main') || "
        "(github.event_name == 'workflow_dispatch' && "
        "github.ref == 'refs/heads/main' && "
        "github.actor == github.repository_owner)"
    )
    if native_condition != expected_native_condition:
        fail(
            "Native Reader stable-signer job must be restricted to trusted "
            "main pushes or owner-triggered main dispatches"
        )
    if native_assembly_job.get("needs") != [
        "invariant-suites",
        "trace-helper-tests",
    ]:
        fail("Native Reader unsigned assembly must follow both safety jobs")
    if native_release_job.get("needs") != ["native-spread-build", "build"]:
        fail(
            "Native Reader protected signing must follow unsigned assembly "
            "and the finished plugin build"
        )
    if native_release_job.get("environment") != "virtual-spread-release":
        fail("Native Reader protected signing must use the release environment")
    if plugin_job_definition.get("needs") != [
        "native-spread-build",
        "virtual-spread-tests",
    ]:
        fail("plugin publication must follow Native Reader and Virtual Spread gates")

    native_assembly_steps = native_assembly_job.get("steps")
    native_release_steps = native_release_job.get("steps")
    plugin_steps = plugin_job_definition.get("steps")
    if any(
        not isinstance(steps, list)
        for steps in (native_assembly_steps, native_release_steps, plugin_steps)
    ):
        fail("Native Reader and plugin workflow steps must be lists")
    assert isinstance(native_assembly_steps, list)
    assert isinstance(native_release_steps, list)
    assert isinstance(plugin_steps, list)

    native_compile = named_step(
        native_assembly_steps,
        "Compile deterministic aligned Native Reader v2 package",
    )
    native_prepare = named_step(
        native_assembly_steps,
        "Prepare aligned APK and machine-readable provenance",
    )
    native_upload_input = named_step(
        native_assembly_steps,
        "Upload aligned APK for protected signing",
    )
    native_compile_run = str(native_compile.get("run", ""))
    native_prepare_run = str(native_prepare.get("run", ""))
    if (
        "-File .\\native-spread-module\\build.ps1 `" not in native_compile_run
        or "-AlignedOnly" not in native_compile_run
        or "if ($LASTEXITCODE -ne 0)" not in native_compile_run
        or "SupernoteNativeReaderV2-v0.0.140-aligned.apk"
        not in native_prepare_run
        or "sourceCommit = '${{ github.sha }}'" not in native_prepare_run
        or "artifactSha256 = $artifactSha256" not in native_prepare_run
        or "versionCode = 140" not in native_prepare_run
        or "versionName = '0.0.140'" not in native_prepare_run
        or native_upload_input.get("uses")
        != "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"
        or "native-reader-v2-release-input-${{ github.sha }}"
        not in str(native_upload_input.get("with", {}))
    ):
        fail(
            "Native Reader unsigned assembly must publish exact aligned APK "
            "and commit-bound provenance"
        )
    native_assembly_text = str(native_assembly_job)
    if "secrets." in native_assembly_text or "environment" in native_assembly_job:
        fail("Native Reader unsigned assembly must not access signing credentials")

    native_download = named_step(
        native_release_steps, "Download tested aligned APK"
    )
    native_verify = named_step(
        native_release_steps,
        "Verify aligned APK provenance without signing credentials",
    )
    native_signer = named_step(
        native_release_steps,
        "Sign, verify, and remove protected Native Reader signing key",
    )
    native_upload = named_step(
        native_release_steps, "Upload upgrade-compatible Native Reader APK"
    )
    native_verify_run = str(native_verify.get("run", ""))
    native_signer_run = str(native_signer.get("run", ""))
    native_signer_env = native_signer.get("env")
    native_secret = "secrets.NATIVE_SPREAD_KEYSTORE_B64"
    if (
        native_download.get("uses")
        != "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093"
        or "native-reader-v2-release-input-${{ github.sha }}"
        not in str(native_download.get("with", {}))
        or "sourceCommit" not in native_verify_run
        or "artifactSha256" not in native_verify_run
        or "Release input contains unexpected files." not in native_verify_run
        or "versionCode='140' versionName='0\\.0\\.140'" not in native_verify_run
        or "unexpectedly already signed" not in native_verify_run
        or not isinstance(native_signer_env, dict)
        or native_secret
        not in str(native_signer_env.get("NATIVE_SPREAD_KEYSTORE_B64", ""))
        or "$expectedSignedLength = 274971L" not in native_signer_run
        or "dd40b89f4bbc6d161b90ea631efccac8c185e3ae8b2cc0cb13d5791f35464c48"
        not in native_signer_run
        or "[Array]::Clear($keyBytes, 0, $keyBytes.Length)"
        not in native_signer_run
        or "Remove-Item -LiteralPath $keystore -Force" not in native_signer_run
        or native_upload.get("uses")
        != "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"
        or "SupernoteNativeSpreadProbe-v0.0.140.apk"
        not in str(native_upload.get("with", {}))
    ):
        fail(
            "Native Reader protected signer must verify exact provenance, "
            "signer identity, final bytes, cleanup, and publication"
        )
    native_release_text = str(native_release_job)
    if "actions/checkout@" in native_release_text or "build.ps1" in native_release_text:
        fail("Native Reader protected signer must not checkout or build project code")
    native_secret_steps = [
        step for step in all_steps if native_secret in str(step)
    ]
    if native_secret_steps != [native_signer]:
        fail("Native Reader stable signer must appear only in its protected step")

    plugin_verify = named_step(plugin_steps, "Verify package")
    plugin_upload = named_step(plugin_steps, "Upload plugin package")
    plugin_verify_run = str(plugin_verify.get("run", ""))
    if (
        "scripts/verify_plugin_package.py" not in plugin_verify_run
        or "out/build-provenance/SupernoteRtlReader.bundle"
        not in plugin_verify_run
        or "out/build-provenance/app.npk" not in plugin_verify_run
        or plugin_upload.get("uses")
        != "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"
        or "path': 'out/*.snplg'" not in str(plugin_upload.get("with", {}))
    ):
        fail("plugin publication must verify exact bundle/APK provenance first")

    ephemeral = named_step(
        test_steps, "Prepare ephemeral companion signing key"
    )
    ephemeral_run = str(ephemeral.get("run", ""))
    if (
        ephemeral.get("id") != "companion-signing"
        or "-validity 2" not in ephemeral_run
        or 'echo "sha256=$fingerprint" >> "$GITHUB_OUTPUT"' not in ephemeral_run
    ):
        fail("pull-request CI must identify its two-day ephemeral signer")
    test_build = named_step(
        test_steps, "Build and verify virtual-spread companion APK"
    )
    test_build_run = str(test_build.get("run", ""))
    test_build_env = test_build.get("env")
    if (
        "-ExpectedSignerSha256 $env:EXPECTED_SIGNER_SHA256"
        not in test_build_run
        or not isinstance(test_build_env, dict)
        or "steps.companion-signing.outputs.sha256"
        not in str(test_build_env.get("EXPECTED_SIGNER_SHA256", ""))
    ):
        fail("pull-request CI must verify its selected APK certificate")
    mismatch = named_step(
        test_steps, "Reject mismatched virtual-spread companion signer"
    )
    if (
        "-ExpectedSignerSha256 ('0' * 64)" not in str(mismatch.get("run", ""))
        or "certificate does not match the expected release signer"
        not in str(mismatch.get("run", ""))
    ):
        fail("pull-request CI must reject a mismatched APK certificate")
    prepare_input = named_step(
        assembly_steps, "Prepare clean aligned APK evidence"
    )
    upload_input = named_step(
        assembly_steps, "Upload clean aligned APK for protected signing"
    )
    assembly_build = named_step(
        assembly_steps,
        "Assemble aligned APK without Python or signing credentials",
    )
    if (
        "-SkipTests -AlignedOnly" not in str(assembly_build.get("run", ""))
        or "virtual-spread-aligned.apk.sha256"
        not in str(prepare_input.get("run", ""))
        or upload_input.get("uses")
        != "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"
        or "virtual-spread-release-input-${{ github.sha }}"
        not in str(upload_input.get("with", {}))
    ):
        fail("clean no-Python assembly must publish the release input")
    assembly_text = str(assembly_job)
    if any(
        forbidden in assembly_text
        for forbidden in (
            "actions/setup-python@",
            "pip install",
            "VIRTUAL_SPREAD_APK_KEYSTORE_BASE64",
        )
    ):
        fail("clean assembly must not load Python packages or signing secrets")
    release_text = str(release_job)
    if any(
        forbidden in release_text
        for forbidden in (
            "actions/checkout@",
            "actions/setup-python@",
            "pip install",
            "build.ps1",
        )
    ):
        fail("protected signer job must not checkout or execute project code")
    download_input = named_step(release_steps, "Download tested aligned APK")
    verify_input = named_step(
        release_steps, "Verify tested aligned APK digest"
    )
    if (
        download_input.get("uses")
        != "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093"
        or "virtual-spread-release-input-${{ github.sha }}"
        not in str(download_input.get("with", {}))
        or "sha256sum --check --strict"
        not in str(verify_input.get("run", ""))
    ):
        fail("protected signer must verify the tested aligned APK artifact")
    secret_reference = "secrets.VIRTUAL_SPREAD_APK_KEYSTORE_BASE64"
    if secret_reference in str(test_job):
        fail("pull-request-controlled CI can access the stable APK signer")
    signer_step = named_step(
        release_steps, "Sign, verify, and remove protected signing key"
    )
    signer_env = signer_step.get("env")
    signer_run = signer_step.get("run")
    if not isinstance(signer_env, dict) or secret_reference not in str(
        signer_env.get("KEYSTORE_BASE64", "")
    ):
        fail("protected signing secret must be scoped to the signing step")
    if not isinstance(signer_run, str) or any(
        marker not in signer_run
        for marker in (
            "try {",
            "finally {",
            "$env:KEYSTORE_BASE64 = $null",
            "[Array]::Clear($bytes, 0, $bytes.Length)",
            "[Guid]::NewGuid().ToString('N')",
            "Remove-Item -LiteralPath $stablePath -Force",
            "& $apksigner sign",
            "virtual-spread-aligned.apk",
            "Expected exactly one APK signer certificate",
            "APK signer certificate does not match the expected release signer",
        )
    ):
        fail("protected signer must be verified and deleted in one step")
    if not (
        signer_run.find("$env:KEYSTORE_BASE64 = $null")
        < signer_run.find("& $apksigner sign")
    ):
        fail("stable credential must leave the environment before signing")
    secret_steps = [
        step for step in all_steps if secret_reference in str(step)
    ]
    if secret_steps != [signer_step]:
        fail("stable signer must appear only in the protected signing step")
    upload_step = named_step(
        release_steps, "Upload upgrade-compatible companion APK"
    )
    if upload_step.get("uses") != (
        "actions/upload-artifact@"
        "ea165f8d65b6e75b540449e92b4886f43607fa02"
    ):
        fail("protected APK upload action must remain commit-pinned")

    native_gate_declaration = (
        "private static native void "
        "nativeSetCalibrationEnabled(boolean enabled);"
    )
    if mask_cpp_comments_and_literals(module).count(native_gate_declaration) != 1:
        fail(
            "the Java native eraser gate declaration is missing, duplicated, "
            "or replaced by a Java no-op"
        )

    frozen_source_digests = (
        (
            plugin_path,
            "485bf036775d1c553f366a1c8c00e144be335e03a423463e302d4cc373f86c86",
            "ReaderPreferencesModule.kt.template",
        ),
        (
            module_path,
            "7883f6bc72e9dced6066ff8873a993faa0b65ed970bd9911523819952d55f77f",
            "SpreadProbe.java",
        ),
        (
            native_build_path,
            "c69aed736866691f77d2c92655c8ec22ed13407b3049d2d40b15992fb14bccd1",
            "native build script",
        ),
        (
            trace_script_path,
            "adead52df5ace68ee59949501ae764aefe338dc6feac1aacd0259f05da8c9e06",
            "Native Spread trace helper",
        ),
        (
            trace_helper_test_path,
            "a6c3c249d3239ee4fec9dd465b01182e6a493965fc82f0230b78963d8611ca3d",
            "Native Spread trace-helper test",
        ),
        (
            app_path,
            "6606708256234c109530d03b8de7888179bb3886bc2def6bbde3b6f549dd6123",
            "Native Spread UI authority source",
        ),
        (
            workflow_path,
            "275fd959afc4db9754c5bb1418125b1473d7840f8eddc1dc492e0235b727a08f",
            "Native Spread companion-build workflow",
        ),
        (
            plugin_build_path,
            "cab3726f8249eee4c7cc31dc14934b8d7b164e86d7a152cd6807b4863ebbe5e9",
            "native plugin build entrypoint",
        ),
        (
            packager_patch_path,
            "6bf380d6ca8bde781523a6e3e49c70c7612cb4fe74a51d43afa61974301698fb",
            "generated plugin-packager hardening",
        ),
        (
            package_verifier_path,
            "b7cf13aaea2df510772e7e25ad8ff2dd51c49e3a29bbe35ab52f591c76728e52",
            "finished native plugin package verifier",
        ),
        (
            package_test_path,
            "d01d274cb40907a834e446476a33c19cb2cbb42a4978d1f4d88ddd1dadb48598",
            "native plugin packaging failure-injection tests",
        ),
    )
    for frozen_path, expected_digest, label in frozen_source_digests:
        actual_digest = normalized_text_sha256(frozen_path)
        if actual_digest != expected_digest:
            fail(
                f"{label} changed without an explicit frozen-source digest "
                f"review: expected {expected_digest}, got {actual_digest}"
            )

    shadow_method = extract_java_method(
        module,
        "private static void publishV2Shadow(",
        "Native Reader v2 shadow publication",
    )
    require_markers(
        shadow_method,
        (
            "SpreadPairing.forPage(",
            "new SpreadSnapshot(",
            "state.session.publish(snapshot)",
            "verifyV2ShadowAgreement(snapshot, readySnapshot)",
            'log("v2_shadow_rejected reason=authority_mismatch "',
        ),
        "Native Reader v2 shadow publication",
    )
    for forbidden in (
        "XposedHelpers",
        "param.setResult",
        "setImageBitmap",
        "saveTrails",
        "loadPage",
        "sendWriteInfo",
        "nativeSetCalibrationEnabled",
        "showOverlay",
        "showStatusOverlay",
    ):
        if forbidden in shadow_method:
            fail(
                "Native Reader v2 shadow publication changes native behavior: "
                + forbidden
            )
    if module.count("publishV2Shadow(") != 2:
        fail("Native Reader v2 shadow must have one definition and one call")
    if "V2ShadowState v2State = V2_SHADOW_STATES.remove(activity);" not in module:
        fail("Native Reader v2 shadow state is not retired with its Activity")

    invariant_commands = str(jobs["invariant-suites"])
    for command in (
        "python3 scripts/test_native_reader_v2_core.py .",
        "python3 scripts/test_native_reader_v2_mutations.py .",
        "python3 scripts/check_native_reader_v2_invariants.py .",
        "python3 scripts/check_native_invariants.py .",
        "python3 scripts/check_native_spread_invariants.py .",
        "python3 scripts/test_build_provenance.py .",
        "python3 scripts/test_plugin_packaging_fail_closed.py",
    ):
        if invariant_commands.count(command) != 1:
            fail(f"workflow invariant gate must execute exactly once: {command}")
    for guarded_job_name in (
        "trace-helper-tests",
        "invariant-suites",
        "native-spread-build",
        "build",
    ):
        guarded_job = jobs[guarded_job_name]
        if (
            "continue-on-error" in guarded_job
            or guarded_job.get("if") is not None
        ):
            fail(f"required workflow job can be bypassed: {guarded_job_name}")

    plugin_build_code = mask_shell_comments(plugin_build_script)
    require_markers(
        plugin_build_code,
        (
            '"${PYTHON_CMD[@]}" "$ROOT/scripts/check_native_spread_invariants.py" "$ROOT"',
            '"${PYTHON_CMD[@]}" "$ROOT/scripts/patch_plugin_packager.py" "$PROJECT/buildPlugin.sh"',
            'export MSYS2_ARG_CONV_EXCL=',
            './buildPlugin.sh',
            'mapfile -t PACKAGES < <(find "$PROJECT/build/outputs"',
            'if [[ "${#PACKAGES[@]}" -ne 1 ]]',
            '"${PYTHON_CMD[@]}" "$ROOT/scripts/verify_plugin_package.py"',
            '"$EXPECTED_BUNDLE" "$EXPECTED_NATIVE_APK"',
            'cp "${PACKAGES[0]}" "$ROOT/out/"',
        ),
        "fail-closed native plugin build",
    )
    patch_position = plugin_build_code.find("patch_plugin_packager.py")
    build_position = plugin_build_code.find("./buildPlugin.sh", patch_position)
    verify_position = plugin_build_code.find("verify_plugin_package.py", build_position)
    copy_position = plugin_build_code.find('cp "${PACKAGES[0]}"', verify_position)
    if not 0 <= patch_position < build_position < verify_position < copy_position:
        fail(
            "plugin packager hardening, native build, finished-package "
            "verification, and publication are not strictly ordered"
        )
    for marker, label in (
        ("patch_plugin_packager.py", "packager hardening"),
        ("./buildPlugin.sh", "generated plugin build"),
        ("verify_plugin_package.py", "finished-package verification"),
        ('cp "${PACKAGES[0]}"', "verified-package publication"),
    ):
        if plugin_build_code.count(marker) != 1:
            fail(f"plugin build must execute {label} exactly once")

    require_markers(
        packager_patch,
        (
            'EXPECTED_PACKAGE = "com.supernotertlreader.PdfRendererPackage"',
            'local project_react_pkgs="$expected_react_package"',
            'if [[ "$all_pkgs" != "$expected_react_package" ]]',
            'if ! build_android_apk "$project_root" "$gen_cfg"',
            'if ! copy_apk_and_update_config "$project_root" "$gen_dir" "$gen_cfg"',
            'write_color_output "Required RTL Reader native build was not selected" "Red"',
            'signed_apk="$(sign_compacted_apk "$project_root" "$apk_path")"',
            '"$apksigner" verify --verbose --print-certs "$signed"',
            'Final compacted APK signer is not the reviewed identity',
            'for required_scheme in 2 3; do',
            "return 1",
        ),
        "generated native packager fail-closed patch",
    )
    require_markers(
        package_verifier,
        (
            'EXPECTED_REACT_PACKAGES = ["com.supernotertlreader.PdfRendererPackage"]',
            '"nativeCodePackage"] = "/app.npk"',
            'expected_config["iconPath"] = "/icon.png"',
            'native_apk = require_single_entry(package, "app.npk")',
            'native_apk_validator(native_apk)',
            '"lib/arm64-v8a/libnative-lib.so"',
            'EXPECTED_NATIVE_CLASS_DESCRIPTORS',
            'verify_apk_tools(Path(temporary_name))',
            'EXPECTED_NATIVE_APK_SIGNER_SHA256',
            'embedded app.npk must have verified v2 and v3 APK signatures',
            'JavaScript bundle does not match the independently named build output',
            'embedded app.npk does not match the independently named build output',
            'expected_runtime_marker(repo_root)',
        ),
        "finished native plugin package verification",
    )
    require_markers(
        package_test,
        (
            "UPSTREAM_SOFT_NATIVE_BUILD",
            "STRICT_NATIVE_BUILD",
            "patch_text(upstream)",
            "patch_text(upstream.replace(UPSTREAM_PACKAGE_SCAN",
            "missing app.npk",
            "converted nativeCodePackage path",
            "unexpected archive payload",
            "wrong runtime marker",
            "missing reviewed native classes",
            "invalid embedded APK",
            "duplicate PluginConfig.json",
            "bundle provenance mismatch",
            "native APK provenance mismatch",
            "missing signer digest",
            "multiple signer digests",
            "unexpected signer identity",
            "missing v2 signature scheme",
            "missing v3 signature scheme",
            "application-class decoy in nested activity",
            "plugin verifier selected unpinned Android build-tools",
            "Native plugin packaging fail-closed tests: PASS",
        ),
        "native plugin packaging failure-injection coverage",
    )

    expected_native_cpp_sha256 = (
        "9584855fdefac7e7795d8ad34dde6b0d17ecfd8c93518d309f170af2bb882221"
    )
    actual_native_cpp_sha256 = normalized_text_sha256(native_cpp_path)
    if actual_native_cpp_sha256 != expected_native_cpp_sha256:
        fail(
            "native eraser source changed without an explicit frozen-source "
            "digest review: expected "
            f"{expected_native_cpp_sha256}, got {actual_native_cpp_sha256}"
        )

    native_trail_hot_path, native_trail_masked = extract_cpp_function(
        native_cpp,
        "int32_t& trail_int(",
        "native trail field accessor",
    )
    native_erase_hot_path, native_erase_masked = extract_cpp_function(
        native_cpp,
        "void replacement_grid_line_erase(",
        "native eraser replacement",
    )
    native_regular_erase_hot_path, native_regular_erase_masked = (
        extract_cpp_function(
            native_cpp,
            "int replacement_regular_erase(",
            "native regular eraser replacement",
        )
    )
    native_hook_install_hot_path, native_hook_install_masked = (
        extract_cpp_function(
            native_cpp,
            "void on_library_loaded(",
            "native eraser hook installer",
        )
    )
    native_gate_hot_path, native_gate_masked = extract_cpp_function(
        native_cpp,
        "SpreadProbe_nativeSetCalibrationEnabled(",
        "native eraser gate setter",
    )
    if re.search(
        r"(?m)^\s*#\s*define\s+(?:trail_int|original_grid_line_erase|"
        r"original_regular_erase|replacement_grid_line_erase|"
        r"replacement_regular_erase|calibration_enabled)\b",
        mask_cpp_comments_and_literals(native_cpp),
    ):
        fail("native eraser critical symbols may not be macro-redefined")
    if len(
        re.findall(
            r"\bstd::atomic\s*<\s*bool\s*>\s+calibration_enabled\s*"
            r"\{\s*false\s*\}\s*;",
            mask_cpp_comments_and_literals(native_cpp),
        )
    ) != 1:
        fail("native eraser calibration gate must be one atomic bool")
    native_cpp_masked = mask_cpp_comments_and_literals(native_cpp)
    for pointer_type, pointer_name in (
        ("GridLineErase", "original_grid_line_erase"),
        ("RegularErase", "original_regular_erase"),
    ):
        if len(
            re.findall(
                rf"\bstd::atomic\s*<\s*{pointer_type}\s*>\s+"
                rf"{pointer_name}\s*\{{\s*nullptr\s*\}}\s*;",
                native_cpp_masked,
            )
        ) != 1:
            fail(f"{pointer_name} must be one atomic function pointer")
    for state_name in (
        "grid_hook_attempted",
        "regular_hook_attempted",
        "grid_hook_installed",
        "regular_hook_installed",
    ):
        if len(
            re.findall(
                rf"\bstd::atomic\s*<\s*bool\s*>\s+{state_name}\s*"
                rf"\{{\s*false\s*\}}\s*;",
                native_cpp_masked,
            )
        ) != 1:
            fail(f"native hook state {state_name} must be one atomic bool")
    trail_body_start = native_trail_masked.find("{")
    trail_body_end = native_trail_masked.rfind("}")
    normalized_trail_body = re.sub(
        r"\s+", "", native_trail_masked[trail_body_start + 1:trail_body_end]
    )
    if normalized_trail_body != (
        "return*reinterpret_cast<int32_t*>("
        "reinterpret_cast<std::uint8_t*>(trail)+offset);"
    ):
        fail(
            "native trail field accessor must remain a side-effect-free "
            "offset reference"
        )
    original_load = require_cpp_pattern(
        native_erase_masked,
        r"GridLineErase\s+original\s*=\s*original_grid_line_erase\s*\.\s*"
        r"load\s*\(\s*std::memory_order_acquire\s*\)\s*;",
        "native eraser atomic original load",
    )
    null_original_guard = require_cpp_pattern(
        native_erase_masked,
        r"if\s*\(\s*original\s*==\s*nullptr\s*\)\s*\{\s*return\s*;\s*\}",
        "native eraser null-original fail-closed guard",
    )
    gate_condition = require_cpp_pattern(
        native_erase_masked,
        r"if\s*\(\s*calibration_enabled\s*\.\s*load\s*\(\s*"
        r"std::memory_order_acquire\s*\)\s*&&\s*operation_trail\s*!=\s*"
        r"nullptr\s*\)",
        "native eraser acquire gate and non-null guard",
    )
    exact_signature = require_cpp_pattern(
        native_erase_masked,
        r"if\s*\(\s*pen_type\s*==\s*3\s*&&\s*original_width\s*==\s*"
        r"932\s*&&\s*original_height\s*==\s*1243\s*\)",
        "native eraser exact disposable-spread signature",
    )
    patch_width = require_cpp_pattern(
        native_erase_masked,
        r"trail_int\s*\(\s*operation_trail\s*,\s*kTrailRedrawWidth\s*\)"
        r"\s*=\s*1872\s*;",
        "native eraser width patch",
    )
    patch_height = require_cpp_pattern(
        native_erase_masked,
        r"trail_int\s*\(\s*operation_trail\s*,\s*kTrailRedrawHeight\s*\)"
        r"\s*=\s*2496\s*;",
        "native eraser height patch",
    )
    patched_true = require_cpp_pattern(
        native_erase_masked,
        r"patched\s*=\s*true\s*;",
        "native eraser patched-state publication",
    )
    original_call = require_cpp_pattern(
        native_erase_masked,
        r"\boriginal\s*\(\s*current_page_trails\s*,\s*"
        r"operation_trail\s*,\s*erased_trail_numbers\s*,\s*scale\s*,\s*"
        r"first_flag\s*,\s*mode\s*,\s*second_flag\s*,\s*third_flag\s*\)"
        r"\s*;",
        "native eraser original invocation",
    )
    restore_block = require_cpp_pattern(
        native_erase_masked,
        r"if\s*\(\s*patched\s*\)\s*\{\s*"
        r"trail_int\s*\(\s*operation_trail\s*,\s*kTrailRedrawWidth\s*\)"
        r"\s*=\s*original_width\s*;\s*"
        r"trail_int\s*\(\s*operation_trail\s*,\s*kTrailRedrawHeight\s*\)"
        r"\s*=\s*original_height\s*;\s*\}",
        "native eraser post-call restoration",
    )
    gate_open = native_erase_masked.find("{", gate_condition)
    gate_close = matching_brace(
        native_erase_masked, gate_open, "native eraser acquire gate"
    )
    signature_open = native_erase_masked.find("{", exact_signature)
    signature_close = matching_brace(
        native_erase_masked,
        signature_open,
        "native eraser exact-signature branch",
    )
    if not (
        original_load < null_original_guard < gate_condition
        < exact_signature < patch_width < patch_height
        < patched_true < signature_close <= gate_close < original_call
        < restore_block
    ):
        fail(
            "native eraser patch, original call, and restoration are not "
            "strictly ordered"
        )
    if native_erase_masked[gate_close + 1:original_call].strip():
        fail("native eraser original invocation is not unconditional")
    original_call_match = re.search(
        r"\boriginal\s*\(\s*current_page_trails\s*,\s*"
        r"operation_trail\s*,\s*erased_trail_numbers\s*,\s*scale\s*,\s*"
        r"first_flag\s*,\s*mode\s*,\s*second_flag\s*,\s*third_flag\s*\)"
        r"\s*;",
        native_erase_masked,
        re.DOTALL,
    )
    restore_match = re.search(
        r"if\s*\(\s*patched\s*\)\s*\{\s*"
        r"trail_int\s*\(\s*operation_trail\s*,\s*kTrailRedrawWidth\s*\)"
        r"\s*=\s*original_width\s*;\s*"
        r"trail_int\s*\(\s*operation_trail\s*,\s*kTrailRedrawHeight\s*\)"
        r"\s*=\s*original_height\s*;\s*\}",
        native_erase_masked,
        re.DOTALL,
    )
    if original_call_match is None or restore_match is None:
        fail("could not isolate native eraser delegation and restoration")
    if native_erase_masked[original_call_match.end():restore_match.start()].strip():
        fail("native eraser restoration is not immediately post-delegation")
    function_body_end = native_erase_masked.rfind("}")
    if native_erase_masked[restore_match.end():function_body_end].strip():
        fail("native eraser performs work after restoring trail dimensions")
    if len(
        re.findall(
            r"\boriginal\s*\(", native_erase_masked
        )
    ) != 1:
        fail("native eraser must invoke the original function exactly once")
    if len(re.findall(r"\bif\s*\(", native_erase_masked)) != 4:
        fail(
            "native eraser may only use the null-original, acquire, signature, "
            "and restore guards"
        )
    if len(re.findall(r"\bpatched\s*=\s*false\s*;", native_erase_masked)) != 1:
        fail("native eraser patched state must initialize false exactly once")
    if len(re.findall(r"\bpatched\s*=\s*true\s*;", native_erase_masked)) != 1:
        fail("native eraser patched state must publish true exactly once")
    if re.search(
        r"\b(?:for|while|switch|goto|throw|try|catch)\b|\?",
        native_erase_masked,
    ):
        fail("native eraser contains unexpected conditional control flow")
    if len(re.findall(r"\breturn\s*;", native_erase_masked)) != 1:
        fail("native eraser must fail closed exactly once for a missing original")
    if len(re.findall(r"\btrail_int\s*\(", native_erase_masked)) != 7:
        fail("native eraser must perform exactly three reads and four writes")
    if len(re.findall(r"kTrailRedrawWidth\s*\)\s*=", native_erase_masked)) != 2:
        fail("native eraser width may only be patched and restored once")
    if len(re.findall(r"kTrailRedrawHeight\s*\)\s*=", native_erase_masked)) != 2:
        fail("native eraser height may only be patched and restored once")
    require_only_cpp_calls(
        native_erase_masked,
        {
            "replacement_grid_line_erase",
            "if",
            "load",
            "trail_int",
            "original",
        },
        "native eraser replacement",
    )

    regular_original_load = require_cpp_pattern(
        native_regular_erase_masked,
        r"RegularErase\s+original\s*=\s*original_regular_erase\s*\.\s*"
        r"load\s*\(\s*std::memory_order_acquire\s*\)\s*;",
        "native regular eraser atomic original load",
    )
    regular_null_original_guard = require_cpp_pattern(
        native_regular_erase_masked,
        r"if\s*\(\s*original\s*==\s*nullptr\s*\)\s*\{\s*"
        r"return\s+0\s*;\s*\}",
        "native regular eraser null-original fail-closed guard",
    )
    regular_gate = require_cpp_pattern(
        native_regular_erase_masked,
        r"if\s*\(\s*calibration_enabled\s*\.\s*load\s*\(\s*"
        r"std::memory_order_acquire\s*\)\s*&&\s*operation_trail\s*!=\s*"
        r"nullptr\s*\)",
        "native regular eraser acquire gate and non-null guard",
    )
    regular_signature = require_cpp_pattern(
        native_regular_erase_masked,
        r"if\s*\(\s*pen_type\s*==\s*16\s*&&\s*pen_color\s*==\s*255\s*"
        r"&&\s*original_width\s*==\s*932\s*&&\s*original_height\s*==\s*"
        r"1243\s*\)",
        "native regular eraser exact disposable-spread signature",
    )
    regular_patch_width = require_cpp_pattern(
        native_regular_erase_masked,
        r"trail_int\s*\(\s*operation_trail\s*,\s*kTrailRedrawWidth\s*\)"
        r"\s*=\s*1872\s*;",
        "native regular eraser width patch",
    )
    regular_patch_height = require_cpp_pattern(
        native_regular_erase_masked,
        r"trail_int\s*\(\s*operation_trail\s*,\s*kTrailRedrawHeight\s*\)"
        r"\s*=\s*2496\s*;",
        "native regular eraser height patch",
    )
    regular_patched_true = require_cpp_pattern(
        native_regular_erase_masked,
        r"patched\s*=\s*true\s*;",
        "native regular eraser patched-state publication",
    )
    regular_original_call = require_cpp_pattern(
        native_regular_erase_masked,
        r"const\s+int\s+result\s*=\s*original\s*\(\s*"
        r"operation_trail\s*,\s*current_page_trails\s*,\s*"
        r"erased_trail_numbers\s*,\s*affected_trail_numbers\s*,\s*mode\s*"
        r"\)\s*;",
        "native regular eraser original invocation",
    )
    regular_restore = require_cpp_pattern(
        native_regular_erase_masked,
        r"if\s*\(\s*patched\s*\)\s*\{\s*"
        r"trail_int\s*\(\s*operation_trail\s*,\s*kTrailRedrawWidth\s*\)"
        r"\s*=\s*original_width\s*;\s*"
        r"trail_int\s*\(\s*operation_trail\s*,\s*kTrailRedrawHeight\s*\)"
        r"\s*=\s*original_height\s*;\s*\}",
        "native regular eraser post-call restoration",
    )
    regular_return = require_cpp_pattern(
        native_regular_erase_masked,
        r"return\s+result\s*;",
        "native regular eraser return preservation",
    )
    regular_gate_open = native_regular_erase_masked.find("{", regular_gate)
    regular_gate_close = matching_brace(
        native_regular_erase_masked,
        regular_gate_open,
        "native regular eraser acquire gate",
    )
    regular_signature_open = native_regular_erase_masked.find(
        "{", regular_signature
    )
    regular_signature_close = matching_brace(
        native_regular_erase_masked,
        regular_signature_open,
        "native regular eraser exact-signature branch",
    )
    if not (
        regular_original_load < regular_null_original_guard < regular_gate
        < regular_signature < regular_patch_width
        < regular_patch_height < regular_patched_true
        < regular_signature_close <= regular_gate_close
        < regular_original_call < regular_restore < regular_return
    ):
        fail(
            "native regular eraser patch, delegation, restoration, and "
            "return are not strictly ordered"
        )
    if native_regular_erase_masked[
        regular_gate_close + 1:regular_original_call
    ].strip():
        fail("native regular eraser original invocation is not unconditional")
    if len(re.findall(r"\bif\s*\(", native_regular_erase_masked)) != 4:
        fail(
            "native regular eraser may only use the null-original, acquire, "
            "signature, and restore guards"
        )
    if len(re.findall(r"\btrail_int\s*\(", native_regular_erase_masked)) != 8:
        fail("native regular eraser must perform four reads and four writes")
    if len(
        re.findall(
            r"kTrailRedrawWidth\s*\)\s*=", native_regular_erase_masked
        )
    ) != 2:
        fail("native regular eraser width may only be patched and restored once")
    if len(
        re.findall(
            r"kTrailRedrawHeight\s*\)\s*=", native_regular_erase_masked
        )
    ) != 2:
        fail("native regular eraser height may only be patched and restored once")
    if len(
        re.findall(r"\boriginal\s*\(", native_regular_erase_masked)
    ) != 1:
        fail("native regular eraser must invoke the original exactly once")
    if re.search(
        r"\b(?:for|while|switch|goto|throw|try|catch)\b|\?",
        native_regular_erase_masked,
    ):
        fail("native regular eraser contains unexpected conditional control flow")
    if len(re.findall(r"\breturn\s+0\s*;", native_regular_erase_masked)) != 1:
        fail(
            "native regular eraser must fail closed exactly once for a missing "
            "original"
        )
    require_only_cpp_calls(
        native_regular_erase_masked,
        {
            "replacement_regular_erase",
            "if",
            "load",
            "trail_int",
            "original",
        },
        "native regular eraser replacement",
    )

    if (
        native_cpp.count(
            '"_Z10eraseTrailR14TrailContainerRNSt6__ndk16vectorIS_NS1_"'
        ) != 1
        or native_cpp.count(
            '"9allocatorIS_EEEERNS2_IiNS3_IiEEEES6_i"'
        ) != 1
    ):
        fail("native regular eraser must target exactly the reviewed vector symbol")
    if len(re.findall(r"\bdlsym\s*\(", native_hook_install_masked)) != 2:
        fail("native eraser installer must resolve exactly two reviewed symbols")
    if len(re.findall(r"\bhook_function\s*\(", native_hook_install_masked)) != 2:
        fail("native eraser installer must install exactly two reviewed hooks")
    require_cpp_pattern(
        native_hook_install_masked,
        r"dlsym\s*\(\s*handle\s*,\s*kGridLineTargetSymbol\s*\)",
        "native grid eraser symbol resolution",
    )
    require_cpp_pattern(
        native_hook_install_masked,
        r"dlsym\s*\(\s*handle\s*,\s*kRegularTargetSymbol\s*\)",
        "native regular eraser symbol resolution",
    )
    for hook_prefix in ("grid", "regular"):
        require_cpp_pattern(
            native_hook_install_masked,
            rf"!{hook_prefix}_hook_installed\s*\.\s*load\s*\(\s*"
            rf"std::memory_order_acquire\s*\)\s*&&\s*"
            rf"!{hook_prefix}_hook_attempted\s*\.\s*exchange\s*\(\s*"
            rf"true\s*,\s*std::memory_order_acq_rel\s*\)",
            f"native {hook_prefix} hook single-installer guard",
        )
        if len(
            re.findall(
                rf"{hook_prefix}_hook_installed\s*\.\s*store\s*\(\s*"
                rf"installed\s*,\s*std::memory_order_release\s*\)",
                native_hook_install_masked,
            )
        ) != 1:
            fail(
                f"native {hook_prefix} hook result must publish installed state "
                "exactly once"
            )
        if len(
            re.findall(
                rf"{hook_prefix}_hook_attempted\s*\.\s*store\s*\(\s*"
                rf"false\s*,\s*std::memory_order_release\s*\)",
                native_hook_install_masked,
            )
        ) != 2:
            fail(
                f"native {hook_prefix} hook must have exactly the symbol and "
                "unambiguous installer retry publications"
            )
        require_cpp_pattern(
            native_hook_install_masked,
            r"if\s*\(\s*!\s*installed\s*&&\s*result\s*!=\s*0\s*&&\s*"
            r"backup\s*==\s*nullptr\s*\)\s*\{\s*"
            rf"{hook_prefix}_hook_attempted\s*\.\s*store\s*\(\s*false\s*,\s*"
            r"std::memory_order_release\s*\)\s*;\s*\}",
            f"native {hook_prefix} hook unambiguous-failure retry guard",
        )
    if len(
        re.findall(
            r"void\s*\*\s*backup\s*=\s*nullptr\s*;",
            native_hook_install_masked,
        )
    ) != 2:
        fail("native eraser hooks must use two local null backup pointers")
    if len(
        re.findall(
            r"hook_function\s*\([^;]*?&\s*backup\s*\)",
            native_hook_install_masked,
            re.DOTALL,
        )
    ) != 2:
        fail("native eraser hook backups must be written only to local pointers")
    if len(
        re.findall(
            r"const\s+bool\s+installed\s*=\s*result\s*==\s*0\s*&&\s*"
            r"original\s*!=\s*nullptr\s*;",
            native_hook_install_masked,
        )
    ) != 2:
        fail("native eraser hook success must require result zero and a backup")
    for pointer_name in (
        "original_grid_line_erase",
        "original_regular_erase",
    ):
        if len(
            re.findall(
                rf"if\s*\(\s*installed\s*\)\s*\{{\s*{pointer_name}\s*\.\s*"
                rf"store\s*\(\s*original\s*,\s*std::memory_order_release\s*\)"
                rf"\s*;\s*\}}",
                native_hook_install_masked,
                re.DOTALL,
            )
        ) != 1:
            fail(
                f"{pointer_name} must publish only inside the proven installer "
                "success branch"
            )
    readiness_guard = require_cpp_pattern(
        native_hook_install_masked,
        r"if\s*\(\s*grid_hook_installed\s*\.\s*load\s*\(\s*"
        r"std::memory_order_acquire\s*\)\s*&&\s*"
        r"regular_hook_installed\s*\.\s*load\s*\(\s*"
        r"std::memory_order_acquire\s*\)\s*\)\s*\{\s*"
        r"hook_state\s*\.\s*store\s*\(\s*2\s*,\s*"
        r"std::memory_order_release\s*\)\s*;\s*\}",
        "native two-hook readiness publication",
    )
    readiness_store = native_hook_install_masked.find(
        "hook_state.store(2", readiness_guard
    )
    if readiness_store < 0:
        fail("could not isolate native eraser readiness publication")
    readiness_prefix = native_hook_install_masked[
        readiness_guard:readiness_store
    ]
    if "original_grid_line_erase" in readiness_prefix or (
        "original_regular_erase" in readiness_prefix
    ):
        fail("native hook readiness may not be inferred from backup pointers")
    if len(
        re.findall(
            r"hook_state\s*\.\s*store\s*\(\s*2\s*,",
            native_hook_install_masked,
        )
    ) != 1:
        fail("native hook readiness may be published exactly once")

    gate_body_start = native_gate_masked.find("{")
    gate_body_end = native_gate_masked.rfind("}")
    normalized_gate_body = re.sub(
        r"\s+", "", native_gate_masked[gate_body_start + 1:gate_body_end]
    )
    if normalized_gate_body != (
        "calibration_enabled.store(enabled==JNI_TRUE,"
        "std::memory_order_release);"
    ):
        fail(
            "native eraser gate setter must only publish the requested "
            "boolean with release ordering"
        )
    require_only_cpp_calls(
        native_gate_masked,
        {
            "SpreadProbe_nativeSetCalibrationEnabled",
            "store",
        },
        "native eraser gate setter",
    )

    require_markers(
        plugin,
        (
            "NATIVE_READER_V2_MIN_VERSION_CODE = 140L",
            "private const val NATIVE_SPREAD_HANDSHAKE_PROTOCOL = 4",
            "private const val NATIVE_SPREAD_EDITABLE_MARKER_PROTOCOL = 3",
            '"protected-editable-transactional-v2"',
            'private const val NATIVE_SPREAD_ACTIVATION_PENDING = "pending"',
            'private const val NATIVE_SPREAD_ACTIVATION_COMMITTED = "committed"',
            'setProperty("documentSha256", backup.documentSha256)',
            'backup.documentSha256 == sha256(pdfFile)',
            "NATIVE_SPREAD_HANDSHAKE_REQUEST",
            "NATIVE_SPREAD_HANDSHAKE_RESPONSE",
            "requestNativeSpreadHandshake(",
            "if (!handshake.active)",
            "writeNativeSpreadReadOnlyMarker(",
            "check(handshake.active)",
            "reportedPath == expectedPath",
            "documentApkLength == SUPPORTED_DOCUMENT_APK_LENGTH",
            "RTL_READER_NATIVE_SPREAD_HANDSHAKE_REQUEST",
            'putBoolean("configured", configured)',
            'putBoolean("configuredEditable", configuredEditable)',
            'configuredEditable && runtimeCompatible',
            "fun configureNativeSpreadEditable(",
            "ensureNativeAnnotationBackup(pdfFile)",
            'startNativeBackupWorker("RTLReaderNativeBackupCreate")',
            'startNativeBackupWorker("RTLReaderNativeBackupRetire")',
            "retireNativeAnnotationBackup(",
            "val previousMarkerBytes = readPersistedBytesIfFile(marker)",
            "publishNativeSpreadOffMarkerLocked(",
            "NativeReaderV2AuthorityJournal.publish(",
            "RTL_READER_NATIVE_SPREAD_TRANSITION_PENDING",
            "RTL_READER_NATIVE_EDITABLE_ACTIVATION_ROLLED_BACK",
            "sameNativeAnnotationBackup(backup, revalidatedBackup)",
            "A verified annotation backup belongs to an inactive protected session",
            "writeNativeSpreadPendingMarker(",
            "commitNativeSpreadEditableMarker(",
            "fun restoreNativeAnnotationBackup(",
            "scheduleAnnotationRestore(",
            "nativeMarkRecoveryJournalMatchesBackup(recoveryJournal, backup)",
            "private fun documentPids(activityManager: ActivityManager): List<Int>?",
            "activityManager.runningAppProcesses ?: return null",
            "documentPids(activityManager) ?: run {",
            "DOCUMENT_PROCESS_QUIET_WINDOW_MS",
            "RTL_READER_NATIVE_BACKUP_RESTORE_STABLE_PROCESS_ABSENCE",
            "RTL_READER_NATIVE_BACKUP_RESTORE_RACE_KILL_SENT",
            '"before-mark-publish"',
            '"after-mark-publish"',
            '"before-backup-retirement"',
            'promise.resolve(nativeAnnotationBackupMap(backup, "restored"))',
            "Toast.makeText(",
            "RTL_READER_NATIVE_BACKUP_RETIREMENT_ROLLED_BACK",
            "RTL_READER_NATIVE_BACKUP_CREATION_ROLLED_BACK",
            "nativeAnnotationRetiringSnapshot(pdfFile)",
            "removeNativeAnnotationBackupFiles(pdfFile, backup)",
            "NATIVE_SPREAD_LEGACY_EDITABLE_MODE",
            "legacyConfiguredEditable",
            '"RTLReaderNativeEditableMigrate",',
            "migrateLegacyProtectedEditableSession(",
            "protectedEditableSessionMarkerValid(",
            "RTL_READER_NATIVE_LEGACY_SESSION_MIGRATED",
            'putBoolean("backupAvailable", backupResult.backup != null)',
            'setProperty("showDivider", showDivider.toString())',
            'setProperty("showHeader", showHeader.toString())',
            '"spreadSizing"',
            'putBoolean("showDivider", showDivider)',
            'putBoolean("showHeader", showHeader)',
            'putString("spreadSizing", spreadSizing)',
        ),
        "plugin handshake",
    )
    if plugin.count('"protected-editable-pilot"') != 1:
        fail(
            "legacy editable mode must appear only as the one-time migration "
            "constant, never as a newly published marker"
        )

    editable_marker_writer_start = plugin.find(
        "private fun nativeSpreadEditableMarkerProperties("
    )
    editable_marker_writer_end = plugin.find(
        "private fun resolveNativeSpreadMode(", editable_marker_writer_start
    )
    editable_marker_validator_start = plugin.find(
        "private fun transactionalEditableMarkerMatchesBackup("
    )
    editable_marker_validator_end = plugin.find(
        "private fun protectedEditableMarkerValid(",
        editable_marker_validator_start,
    )
    if min(
        editable_marker_writer_start,
        editable_marker_writer_end,
        editable_marker_validator_start,
        editable_marker_validator_end,
    ) < 0:
        fail("could not isolate versioned protected-editable marker handling")
    editable_marker_writer = plugin[
        editable_marker_writer_start:editable_marker_writer_end
    ]
    editable_marker_validator = plugin[
        editable_marker_validator_start:editable_marker_validator_end
    ]
    require_markers(
        editable_marker_writer,
        (
            'setProperty("mode", NATIVE_SPREAD_EDITABLE_MODE)',
            '"transactionProtocol"',
            "NATIVE_SPREAD_EDITABLE_MARKER_PROTOCOL.toString()",
            '"minimumModuleVersionCode"',
            "NATIVE_READER_V2_MIN_VERSION_CODE.toString()",
            'setProperty("activationToken", activationToken)',
            'setProperty("activationState", activationState)',
            "NATIVE_SPREAD_ACTIVATION_PENDING",
            "NATIVE_SPREAD_ACTIVATION_COMMITTED",
            'setProperty("pendingIntent", checkNotNull(pendingIntent))',
            'setProperty("previousMarkerSha256",',
            'setProperty("previousMarkerBase64",',
            "private fun writeNativeSpreadPendingMarker(",
            "readPendingEditableActivation(",
            "private fun commitNativeSpreadEditableMarker(",
            "protectedEditableMarkerValid(pdfFile, committedProperties, backup)",
            '"Supernote RTL protected editable committed activation"',
            "onCommitted",
        ),
        "protocol-3 pending/committed protected-editable publication",
    )
    if "NATIVE_SPREAD_LEGACY_EDITABLE_MODE" in editable_marker_writer:
        fail("protected editable marker writer can republish the legacy mode")
    committed_writer_start = editable_marker_writer.find(
        "private fun commitNativeSpreadEditableMarker("
    )
    committed_writer_end = len(editable_marker_writer)
    if committed_writer_start < 0:
        fail("could not isolate committed editable authorization point")
    committed_writer = editable_marker_writer[
        committed_writer_start:committed_writer_end
    ]
    committed_writer_masked = mask_cpp_comments_and_literals(committed_writer)
    committed_publish = committed_writer_masked.find("writePropertiesAtomicallyCas(")
    committed_publish_open = committed_writer_masked.find("(", committed_publish)
    committed_publish_close = matching_parenthesis(
        committed_writer_masked,
        committed_publish_open,
        "committed editable atomic publication",
    )
    committed_postcondition = committed_writer_masked.find(
        "val committedMarkerAuthority =", committed_publish_close
    )
    committed_ack = committed_writer_masked.find(
        "requireDocumentAuthorityAck(", committed_postcondition
    )
    committed_return = committed_writer_masked.find(
        "committedBackup", committed_ack
    )
    if not (
        0 <= committed_publish < committed_publish_close
        < committed_postcondition < committed_ack < committed_return
    ):
        fail(
            "committed editable publication must be followed by durable "
            "journal revalidation and exact Document acknowledgement"
        )
    committed_call = committed_writer[
        committed_publish:committed_publish_close + 1
    ]
    committed_call_masked = committed_writer_masked[
        committed_publish:committed_publish_close + 1
    ]
    before_publish_label = committed_call_masked.find("beforePublish =")
    before_publish_open = committed_call_masked.find("{", before_publish_label)
    before_publish_close = matching_brace(
        committed_call_masked,
        before_publish_open,
        "committed editable live-baseline guard",
    )
    before_publish_body = committed_call_masked[
        before_publish_open + 1:before_publish_close
    ]
    require_markers(
        committed_call,
        (
            "expected = pendingMarkerAuthority",
            "onPublished = onCommitted",
            "beforePublish = {",
            "requireNativeSpreadConfigurationGeneration(",
            "samePersistedAuthority(",
            "sameNativeAnnotationBackup(backup, immediateBackup)",
            "nativeAnnotationBackupSourceFilesMatch(immediateBackup)",
            "if (requireLiveBaselineMatch &&",
            "!liveNativeAnnotationMatchesBackup(backup)",
            "Supernote annotations changed immediately before protected editing authorization",
        ),
        "committed editable live-baseline revalidation",
    )
    if committed_writer.count("requireLiveBaselineMatch") != 2:
        fail(
            "committed editable live-baseline authority must appear only in "
            "the helper parameter and its before-publish guard"
        )
    unsafe_committed_tail = tuple(
        marker for marker in (
            "rollbackNativeSpreadEditableActivation(",
            "writeBytesAtomically(",
            "Os.rename(",
            "marker.delete(",
        )
        if marker in committed_writer[committed_publish_close + 1:committed_return]
    )
    if unsafe_committed_tail:
        fail(
            "committed authority can be rolled back or replaced after its "
            f"journal publication: {unsafe_committed_tail}"
        )

    properties_writer_start = plugin.find(
        "private fun writePropertiesAtomically("
    )
    bytes_writer_start = plugin.find(
        "private fun writeBytesAtomically(", properties_writer_start
    )
    copy_writer_start = plugin.find(
        "private fun copyFileAtomically(", bytes_writer_start
    )
    if min(properties_writer_start, bytes_writer_start, copy_writer_start) < 0:
        fail("could not isolate atomic marker publication helpers")
    properties_writer = plugin[properties_writer_start:bytes_writer_start]
    bytes_writer = plugin[bytes_writer_start:copy_writer_start]
    require_markers(
        properties_writer,
        (
            "beforePublish: () -> Unit = {}",
            "if (file.name.endsWith(NATIVE_SPREAD_MARKER_SUFFIX))",
            "NativeReaderV2AuthorityJournal.initialize(file)",
            "NativeReaderV2AuthorityJournal.publish(",
            "current?.journalGeneration",
            "current?.journalAuthoritySha256",
            "onPublished()",
            "writeBytesAtomically(",
            "onPublished = onPublished",
            "beforePublish = beforePublish",
        ),
        "atomic properties publication callback forwarding",
    )
    require_markers(
        bytes_writer,
        (
            "beforePublish: () -> Unit = {}",
            "writeBytesSynced(temporary, bytes)",
            "beforePublish()",
            "Os.rename(temporary.absolutePath, file.absolutePath)",
            "onPublished()",
        ),
        "atomic byte publication boundary",
    )
    bytes_writer_masked = mask_cpp_comments_and_literals(bytes_writer)
    if bytes_writer_masked.count("beforePublish()") != 1:
        fail("atomic byte publication must invoke beforePublish exactly once")
    if re.search(
        r"writeBytesSynced\s*\(\s*temporary\s*,\s*bytes\s*\)\s*"
        r"beforePublish\s*\(\s*\)\s*"
        r"Os\.rename\s*\(\s*temporary\.absolutePath\s*,\s*"
        r"file\.absolutePath\s*\)",
        bytes_writer_masked,
    ) is None:
        fail(
            "live-baseline revalidation must run after temporary marker sync "
            "and immediately before the atomic authorization rename"
        )
    require_markers(
        editable_marker_validator,
        (
            'properties.getProperty("mode", "") == NATIVE_SPREAD_EDITABLE_MODE',
            'properties.getProperty("transactionProtocol", "") ==',
            "NATIVE_SPREAD_EDITABLE_MARKER_PROTOCOL.toString()",
            'properties.getProperty("minimumModuleVersionCode", "") ==',
            "NATIVE_READER_V2_MIN_VERSION_CODE.toString()",
            'val activationToken = properties.getProperty("activationToken", "")',
            "UUID.fromString(activationToken).toString() == activationToken",
            'properties.getProperty("activationState", "") == activationState',
            "activationState != NATIVE_SPREAD_ACTIVATION_COMMITTED ||",
            "pendingOnlyKeys.none { key -> properties.containsKey(key) }",
            "nativeAnnotationBackupSourceFilesMatch(backup)",
            "private fun readPendingEditableActivation(",
            "NATIVE_SPREAD_ACTIVATION_PENDING",
            "pendingActivationMatchesEvidence(",
        ),
        "strict protocol-3 marker-state and backup validation",
    )
    load_mode_start = plugin.find("fun loadNativeSpreadMode(")
    configure_read_only_start = plugin.find(
        "fun configureNativeSpreadReadOnly(", load_mode_start
    )
    if load_mode_start < 0 or configure_read_only_start < 0:
        fail("could not isolate Native Spread load-time legacy migration")
    load_mode = plugin[load_mode_start:configure_read_only_start]
    legacy_detect = load_mode.find("val settings = nativeSpreadMarkerSettings(")
    handshake_start = load_mode.find(
        "requestNativeSpreadHandshake(", legacy_detect
    )
    migration_guard = load_mode.find(
        "if (handshake.active && settings.legacyConfiguredEditable)", handshake_start
    )
    migration_worker = load_mode.find(
        '"RTLReaderNativeEditableMigrate",',
        migration_guard,
    )
    migration_call = load_mode.find(
        "migrateLegacyProtectedEditableSession(", migration_worker
    )
    migrated_resolve = load_mode.find(
        '"verified:migrated-legacy-session"', migration_call
    )
    migration_failure = load_mode.find(
        "RTL_READER_NATIVE_LEGACY_MIGRATION_FAILED", migrated_resolve
    )
    if not (
        0 <= legacy_detect < handshake_start < migration_guard
        < migration_worker < migration_call < migrated_resolve
        < migration_failure
    ):
        fail(
            "verified legacy protected sessions are not migrated under the "
            "live handshake before load resolves"
        )

    migration_start = plugin.find(
        "private fun migrateLegacyProtectedEditableSession("
    )
    retire_start = plugin.find(
        "private fun retireNativeAnnotationBackup(", migration_start
    )
    if migration_start < 0 or retire_start < 0:
        fail("could not isolate legacy protected-session migration")
    migration = plugin[migration_start:retire_start]
    legacy_validate = migration.find(
        "legacyProtectedEditableMarkerValid("
    )
    migration_activate = migration.find(
        "activateNativeSpreadEditableWithStableBackup(", legacy_validate
    )
    migrated_log = migration.find(
        "runCatching {", migration_activate
    )
    migrated_log_message = migration.find(
        "RTL_READER_NATIVE_LEGACY_SESSION_MIGRATED", migrated_log
    )
    migrated_return = migration.find(
        "return migrated", migrated_log_message
    )
    if not (
        0 <= legacy_validate < migration_activate < migrated_log
        < migrated_log_message < migrated_return
    ):
        fail(
            "legacy protected-session migration does not reuse the verified "
            "backup and return directly from the committed transactional rename"
        )
    fallible_migration_tail = tuple(
        marker for marker in (
            "readNativeAnnotationBackup(",
            "readPropertiesIfFile(",
            "protectedEditableMarkerValid(",
            "throw IllegalStateException(",
        )
        if marker in migration[migration_activate:migrated_return]
    )
    if fallible_migration_tail:
        fail(
            "legacy migration makes a fallible state decision after committed "
            f"authorization: {fallible_migration_tail}"
        )

    legacy_validator_start = plugin.find(
        "private fun legacyProtectedEditableMarkerValid("
    )
    write_properties_start = plugin.find(
        "private fun writePropertiesAtomically(", legacy_validator_start
    )
    if legacy_validator_start < 0 or write_properties_start < 0:
        fail("could not isolate legacy protected-session validator")
    legacy_validator = plugin[
        legacy_validator_start:write_properties_start
    ]
    require_markers(
        legacy_validator,
        (
            'properties.getProperty("mode", "") !=',
            "NATIVE_SPREAD_LEGACY_EDITABLE_MODE",
            'properties.getProperty("managedBy", "") != "supernote-rtl-reader"',
            'properties.getProperty("backupVerified", "false")',
            'properties.getProperty("documentPath", "")',
            'properties.getProperty("backupManifestPath", "")',
            'properties.getProperty("backupManifestSha256", "")',
            "sha256(backup.manifest)",
        ),
        "strict legacy protected-session migration authorization",
    )

    recovery_reconcile_start = plugin.find(
        "fun reconcileNativeSpreadRecovery(filePath: String, promise: Promise)"
    )
    configure_readonly_start = plugin.find(
        "fun configureNativeSpreadReadOnly(", recovery_reconcile_start
    )
    if recovery_reconcile_start < 0 or configure_readonly_start < 0:
        fail("could not isolate explicit Native Spread recovery reconciliation")
    recovery_reconcile = mask_comments_preserve_literals(
        plugin[recovery_reconcile_start:configure_readonly_start]
    )
    recovery_worker = recovery_reconcile.find(
        'startNativeBackupWorker("RTLReaderNativeRecoveryReconcile")'
    )
    recovery_before = recovery_reconcile.find(
        "val before = assessNativeSpreadAuthority(", recovery_worker
    )
    recovery_guard = recovery_reconcile.find(
        "if (before.recoveryNeeded)", recovery_before
    )
    recovery_delegate = recovery_reconcile.find(
        "reconcileFailedActivationBackupForExplicitActivation(", recovery_guard
    )
    recovery_after = recovery_reconcile.find(
        "val after = assessNativeSpreadAuthority(", recovery_delegate
    )
    recovery_ready_guard = recovery_reconcile.find(
        'if (after.status != "ready" || after.recoveryNeeded)', recovery_after
    )
    recovery_resolve = recovery_reconcile.find(
        "promise.resolve(true)", recovery_ready_guard
    )
    if not (
        0 <= recovery_worker < recovery_before < recovery_guard
        < recovery_delegate < recovery_after < recovery_ready_guard
        < recovery_resolve
    ):
        fail(
            "explicit recovery does not delegate through exact reconciliation "
            "and re-assess ready authority before resolving"
        )
    recovery_calls_masked = mask_cpp_comments_and_literals(recovery_reconcile)
    recovery_calls = re.findall(
        r"([A-Za-z_][A-Za-z0-9_.]*)\s*\(", recovery_calls_masked
    )
    allowed_recovery_calls = {
        "IllegalStateException",
        "Log.e",
        "Log.i",
        "UUID.randomUUID",
        "annotationRecoveryPending.get",
        "assessNativeSpreadAuthority",
        "beginNativeSpreadRecovery",
        "catch",
        "completeNativeSpreadRecovery",
        "finalProperties.getProperty",
        "if",
        "journalExpectation",
        "nativeSpreadMarker",
        "publishNativeSpreadOffMarkerLocked",
        "promise.reject",
        "promise.resolve",
        "readPersistedAuthorityIfFile",
        "readNativeAnnotationBackup",
        "reconcileFailedActivationBackupForExplicitActivation",
        "reconcileNativeSpreadRecovery",
        "requireDocumentAuthorityAck",
        "requireNativeSpreadConfigurationGeneration",
        "requirePdf",
        "startNativeBackupWorker",
        "strictNativeSpreadMarkerProperties",
        "toString",
        "withNativeSpreadConfigurationAuthority",
        "withNativeSpreadPublicationLock",
    }
    unexpected_recovery_calls = sorted(
        set(recovery_calls) - allowed_recovery_calls
    )
    if unexpected_recovery_calls:
        fail(
            "explicit recovery invokes unreviewed operations: "
            f"{unexpected_recovery_calls}"
        )
    if (
        recovery_calls.count("assessNativeSpreadAuthority") != 2
        or recovery_calls.count("readNativeAnnotationBackup") != 2
        or recovery_calls.count(
            "reconcileFailedActivationBackupForExplicitActivation"
        ) != 1
    ):
        fail("explicit recovery does not use the exact assess/delegate/assess flow")

    plugin_code = mask_comments_preserve_literals(plugin)
    if plugin_code.count(
        "private val annotationRecoveryPending = AtomicBoolean(false)"
    ) != 1 or plugin_code.count(
        "private val annotationRecoveryHandoffPending = AtomicBoolean(false)"
    ) != 1:
        fail("annotation recovery worker ownership and handoff skip must be separate")
    restore_start = plugin_code.find(
        "fun restoreNativeAnnotationBackup(filePath: String, promise: Promise)"
    )
    restore_end = plugin_code.find(
        "private fun writeNativeSpreadReadOnlyMarker(", restore_start
    )
    if restore_start < 0 or restore_end < 0:
        fail("could not isolate annotation recovery worker ownership")
    restore_backup = plugin_code[restore_start:restore_end]
    recovery_claim = restore_backup.find(
        "beginNativeSpreadRecovery()"
    )
    stale_handoff_clear = restore_backup.find(
        "annotationRecoveryHandoffPending.set(false)", recovery_claim
    )
    restore_schedule = restore_backup.find(
        "scheduleAnnotationRestore(", stale_handoff_clear
    )
    handoff_publish = restore_backup.find(
        "annotationRecoveryHandoffPending.set(true)", restore_schedule
    )
    worker_release = restore_backup.find(
        "completeNativeSpreadRecovery(configurationGeneration)", handoff_publish
    )
    recovery_resolve = restore_backup.find(
        'promise.resolve(nativeAnnotationBackupMap(backup, "restored"))',
        worker_release,
    )
    stale_handoff_expiry = restore_backup.find(
        "annotationRecoveryHandoffPending.compareAndSet(", recovery_resolve
    )
    if not (
        0 <= recovery_claim < stale_handoff_clear < restore_schedule
        < handoff_publish < worker_release < recovery_resolve
        < stale_handoff_expiry
    ):
        fail(
            "annotation recovery must retain worker ownership until completion, "
            "publish a separate one-shot handoff skip before releasing that "
            "ownership, and only then resolve"
        )
    if restore_backup.count("completeNativeSpreadRecovery(") != 2:
        fail(
            "annotation recovery ownership must be released exactly by the "
            "completion callback or the pre-worker-failure path"
        )
    handoff_start = plugin_code.find("fun handoffLastSavedPage(promise: Promise)")
    handoff_end = plugin_code.find(
        "private fun findMatchingConfig(", handoff_start
    )
    if handoff_start < 0 or handoff_end < 0:
        fail("could not isolate native-reader handoff recovery guard")
    handoff = re.sub(r"\s+", "", plugin_code[handoff_start:handoff_end])
    if (
        "if(nativeMarkRecoveryRequiredPending()||durableRecovery||"
        "annotationRecoveryPending.get()||"
        "annotationRecoveryHandoffPending.compareAndSet(true,false))"
        not in handoff
        or "annotationRecoveryPending.compareAndSet(true,false)" in handoff
    ):
        fail(
            "native handoff can consume in-progress annotation recovery ownership"
        )

    authority_assessment_model_start = plugin.find(
        "private data class NativeSpreadAuthorityAssessment("
    )
    authority_assessment_start = plugin.find(
        "private fun assessNativeSpreadAuthority(",
        authority_assessment_model_start,
    )
    package_version_start = plugin.find(
        "private fun packageVersionCode(", authority_assessment_start
    )
    if min(
        authority_assessment_model_start,
        authority_assessment_start,
        package_version_start,
    ) < 0:
        fail("could not isolate persisted Native Spread authority assessment")
    authority_assessment = mask_comments_preserve_literals(
        plugin[authority_assessment_model_start:package_version_start]
    )
    require_markers(
        authority_assessment,
        (
            "private data class NativeSpreadAuthorityAssessment(",
            "val reconciliationAvailable: Boolean",
            '"marker_unreadable:${error.message}"',
            "NATIVE_SPREAD_ACTIVATION_PENDING",
            "protectedEditableSessionMarkerValid(",
            "nativeAnnotationRetiringSnapshot(pdfFile).exists()",
            ".getOrDefault(true)",
            'backupResult.status.startsWith("invalid:")',
            "managedEditableMarker && !activationPending && !protectedMarkerValid",
            "backupResult.backup != null && !activationPending && !protectedMarkerValid",
            "canonicalEvidencePresent && backupResult.backup == null",
            'activationPending -> "pending_protected_transition"',
            'unresolvedManagedMarker -> "managed_editable_authority_invalid"',
            'backupInvalid -> "canonical_backup_invalid"',
            'orphanedVerifiedBackup -> "orphaned_verified_backup"',
            'incompleteCanonicalEvidence -> "orphaned_recovery_files"',
            'if (activationPending) "pending" else "recovery"',
        ),
        "fail-closed persisted Native Spread authority assessment",
    )

    resolve_mode_start = plugin.find("private fun resolveNativeSpreadMode(")
    capability_class_start = plugin.find(
        "private data class NativeSpreadCapability(", resolve_mode_start
    )
    if resolve_mode_start < 0 or capability_class_start < 0:
        fail("could not isolate Native Spread authority result publication")
    authority_result = plugin[resolve_mode_start:capability_class_start]
    require_markers(
        authority_result,
        (
            "authority: NativeSpreadAuthorityAssessment",
            'putBoolean("activationPending", authority.activationPending)',
            'putBoolean("recoveryNeeded", authority.recoveryNeeded)',
            'putBoolean("reconciliationAvailable", authority.reconciliationAvailable)',
            'putString("authorityStatus", authority.status)',
            'putString("authorityReason", authority.reason)',
        ),
        "persisted Native Spread authority result publication",
    )

    app_code = mask_comments_preserve_literals(app)
    app_compact = compact_code(app)
    require_markers(
        app_code,
        (
            "const [nativeSpreadConfigured, setNativeSpreadConfigured]",
            "function classifyNativeSpreadAuthority(value)",
            "'activationPending'",
            "'recoveryNeeded'",
            "'reconciliationAvailable'",
            "value.authorityStatus",
            "value.authorityReason",
            "metadataTrusted: false",
            "metadataTrusted: true",
            "useState('unknown')",
            "nativeSpreadAuthorityState === NATIVE_SPREAD_AUTHORITY_READY",
            "loadedNativeSpreadAuthority = classifyNativeSpreadAuthority(",
            "const trustedNativeSpread =",
            "loadedNativeSpreadAuthority.metadataTrusted === true",
            "trustedNativeSpread?.configured === true",
            "trustedNativeSpread?.configuredEditable === true",
            "next === 'ltr' &&",
            "nativeSpreadConfigured &&",
            "!nativeSpreadConfiguredEditable",
            "setNativeSpreadConfigured(enabled);",
            "nativeSpreadAuthorityResolved && !nativeSpreadConfigured",
            "RTL editable remains configured, but its verified hooks are inactive.",
            "RTL editable",
            "Back up & enable",
            "restoreNativeAnnotationBackup",
            "reconcileNativeSpreadRecovery",
            "const nativeSpreadBusyRef = useRef(false);",
            "nativeSpreadBusyRef.current = true;",
            "if (nativeSpreadBusyRef.current) return;",
            "BackHandler.addEventListener(",
            "if (!nativeSpreadBusyRef.current) return false;",
            "Wait for the native reader change to finish before closing.",
            "const [showSpreadDivider, setShowSpreadDivider]",
            "const [showNativeSpreadHeader, setShowNativeSpreadHeader]",
            "const [spreadSizing, setSpreadSizing]",
            "setNativeSpreadAppearanceValue",
            "trustedNativeSpread.showHeader !== false",
            "Active-page header",
            """const restoredCoverSeparate = nativeSpreadHasPersistedAppearance
          ? trustedNativeSpread.coverSeparate === true
          : restored.coverSeparate;""",
            """const restoredSizing = nativeSpreadHasPersistedAppearance
          ? trustedNativeSpread.spreadSizing === 'native_fill'
            ? 'native_fill'
            : 'fit'
          : restored.spreadSizing;""",
        ),
        "configured/runtime Native Spread state separation",
    )
    authority_classifier_start = app_code.find(
        "function classifyNativeSpreadAuthority(value)"
    )
    authority_component_start = app_code.find(
        "export default function App()", authority_classifier_start
    )
    authority_classifier_open = app_code.find("{", authority_classifier_start)
    if min(
        authority_classifier_start,
        authority_classifier_open,
        authority_component_start,
    ) < 0:
        fail("could not isolate Native Spread UI authority classifier")
    authority_classifier_end = matching_brace(
        app_code,
        authority_classifier_open,
        "Native Spread UI authority classifier",
    ) + 1
    if authority_classifier_end >= authority_component_start:
        fail("Native Spread UI authority classifier is not a closed function")
    authority_classifier = app_code[
        authority_classifier_start:authority_classifier_end
    ]
    authority_classifier_compact = compact_code(authority_classifier)
    require_markers(
        authority_classifier_compact,
        (
            "if(!value||typeofvalue!=='object'){return{state:'error',"
            "metadataTrusted:false,detail:'Nativereaderstatecouldnotbeverified."
            "Native-readerchangesarelocked.',};}",
            "constrequiredBooleanFields=['configured','configuredEditable',"
            "'activationPending','recoveryNeeded','enabled','editable',"
            "'coverSeparate','showDivider','showHeader','compatible',"
            "'backupAvailable','backupOriginalMarkPresent',"
            "'reconciliationAvailable',];",
            "constinvalidBooleanField=requiredBooleanFields.find("
            "field=>typeofvalue[field]!=='boolean',);",
            "if(invalidBooleanField||!['fit','native_fill'].includes("
            "value.spreadSizing)||typeofvalue.backupStatus!=='string'||"
            "!['ready','pending','recovery','error'].includes("
            "value.authorityStatus)||typeofvalue.authorityReason!=='string')"
            "{return{state:'error',metadataTrusted:false,detail:"
            "'Nativereaderreturnedincompletestate.Native-readerchangesare"
            "locked.',};}",
            "if(value.authorityStatus==='error'){return{state:'error',"
            "metadataTrusted:true,detail:`Nativereaderauthoritycouldnotbe"
            "verified(${value.authorityReason}).Onlyvalidatedrecoveryis"
            "available.`,};}",
            "if(value.authorityStatus==='pending'){if(!value.activationPending"
            "||!value.recoveryNeeded){return{state:'error',metadataTrusted:"
            "false,detail:'Nativereaderreturnedinconsistentpendingauthority."
            "Onlyvalidatedrecoveryisavailable.',};}return{state:'pending',"
            "metadataTrusted:true,detail:`AprotectedNativeSpreadtransitiondid"
            "notfinish(${value.authorityReason}).Changesarelockeduntilitis"
            "safelyreconciledortheverifiedsnapshotisrestored.`,};}",
            "if(value.authorityStatus==='recovery'){if(!value.recoveryNeeded||"
            "value.activationPending){return{state:'error',metadataTrusted:"
            "false,detail:'Nativereaderreturnedinconsistentrecoveryauthority."
            "Onlyvalidatedrecoveryisavailable.',};}return{state:'recovery',"
            "metadataTrusted:true,detail:`Nativeannotationauthorityisunresolved"
            "(${value.authorityReason}).Changesarelockeduntilitissafely"
            "reconciledortheverifiedsnapshotisrestored.`,};}",
            "if(value.activationPending||value.recoveryNeeded){return{state:"
            "'error',metadataTrusted:false,detail:'Nativereaderreturned"
            "inconsistentreadyauthority.Onlyvalidatedrecoveryisavailable.',};}",
            "return{state:NATIVE_SPREAD_AUTHORITY_READY,metadataTrusted:true,"
            "detail:null,};",
        ),
        "exact fail-closed Native Spread UI authority classifier",
    )
    error_authority = authority_classifier_compact.find(
        "if(value.authorityStatus==='error')"
    )
    pending_authority = authority_classifier_compact.find(
        "if(value.authorityStatus==='pending')"
    )
    recovery_authority = authority_classifier_compact.find(
        "if(value.authorityStatus==='recovery')"
    )
    inconsistent_ready_authority = authority_classifier_compact.find(
        "if(value.activationPending||value.recoveryNeeded)"
    )
    ready_authority = authority_classifier_compact.find(
        "return{state:NATIVE_SPREAD_AUTHORITY_READY,metadataTrusted:true,"
        "detail:null,};"
    )
    if not (
        0 <= error_authority < pending_authority < recovery_authority
        < inconsistent_ready_authority < ready_authority
    ):
        fail("Native Spread UI does not preserve exact authority-state priority")

    require_markers(
        app_compact,
        (
            "const[nativeSpreadAuthorityState,setNativeSpreadAuthorityState]="
            "useState('unknown');",
            "constnativeSpreadAuthorityResolved=nativeSpreadAuthorityState==="
            "NATIVE_SPREAD_AUTHORITY_READY;",
            "constnativeSpreadRecoveryAllowed=(nativeSpreadAuthorityState==="
            "'pending'||nativeSpreadAuthorityState==='recovery'||"
            "nativeSpreadAuthorityState==='error')&&"
            "nativeBackupAvailable;",
        ),
        "exact Native Spread UI authority derivation",
    )

    initialize_start = app_code.find("async function initialize()")
    initialization_effect_end = app_code.find("  }, []);", initialize_start)
    if initialize_start < 0 or initialization_effect_end < 0:
        fail("could not isolate Native Spread UI authority loading")
    authority_load = app_code[initialize_start:initialization_effect_end]
    require_markers(
        authority_load,
        (
            "Native reader state loader is unavailable.",
            "RTL_READER_NATIVE_SPREAD_LOAD_FAILED",
            "Native reader state could not be loaded.",
            "loadedNativeSpreadAuthority.metadataTrusted === true ? nativeSpread : null",
            "setNativeSpreadAuthorityState(loadedNativeSpreadAuthority.state)",
            "setNativeSpreadAuthorityDetail(loadedNativeSpreadAuthority.detail)",
            "setNativeSpreadReconciliationAvailable(",
        ),
        "fail-closed Native Spread UI authority loading",
    )
    authority_load_compact = compact_code(authority_load)
    require_markers(
        authority_load_compact,
        (
            "letloadedNativeSpreadAuthority={state:'error',detail:"
            "'Nativereaderstateloaderisunavailable.Native-readerchangesare"
            "locked.',};",
            "loadedNativeSpreadAuthority=classifyNativeSpreadAuthority("
            "nativeSpread,);",
            "consttrustedNativeSpread=loadedNativeSpreadAuthority."
            "metadataTrusted===true?nativeSpread:null;",
            "setPreferencesReady(true);setNativeSpreadAuthorityState("
            "loadedNativeSpreadAuthority.state);setNativeSpreadAuthorityDetail("
            "loadedNativeSpreadAuthority.detail);setNativeSpreadConfigured("
            "trustedNativeSpread?.configured===true);",
            "setNativeSpreadReconciliationAvailable(trustedNativeSpread?."
            "reconciliationAvailable===true,);",
        ),
        "exact fail-closed Native Spread UI authority loading flow",
    )

    direction_transition_start = app_code.find("const setDirectionValue = async")
    view_transition_start = app_code.find(
        "const setViewModeValue =", direction_transition_start
    )
    cover_transition_start = app_code.find(
        "const setCoverSeparateValue = async", view_transition_start
    )
    appearance_transition_start = app_code.find(
        "const setNativeSpreadAppearanceValue = async", cover_transition_start
    )
    readonly_transition_start = app_code.find(
        "const setNativeSpreadReadOnly = async", appearance_transition_start
    )
    editable_transition_start = app_code.find(
        "const setNativeSpreadEditableMode = async", readonly_transition_start
    )
    reconcile_transition_start = app_code.find(
        "const reconcileNativeSpreadRecovery = async", editable_transition_start
    )
    restore_transition_start = app_code.find(
        "const restoreNativeBackup = async", reconcile_transition_start
    )
    open_jump_start = app_code.find("const openJump =", restore_transition_start)
    authority_transition_sections = (
        (
            "direction",
            app_code[direction_transition_start:view_transition_start],
            "if((next!=='rtl'&&next!=='ltr')||nativeSpreadBusyRef.current)"
            "{return;}if(!nativeSpreadAuthorityResolved){"
            "reportNativeSpreadAuthorityLocked();return;}",
        ),
        (
            "cover",
            app_code[cover_transition_start:appearance_transition_start],
            "if(nativeSpreadBusyRef.current)return;if("
            "!nativeSpreadAuthorityResolved){reportNativeSpreadAuthorityLocked();"
            "return;}",
        ),
        (
            "appearance",
            app_code[appearance_transition_start:readonly_transition_start],
            "if(nativeSpreadBusyRef.current)return;if("
            "!nativeSpreadAuthorityResolved){reportNativeSpreadAuthorityLocked();"
            "return;}",
        ),
        (
            "read-only",
            app_code[readonly_transition_start:editable_transition_start],
            "if(!filePath||nativeSpreadBusyRef.current||"
            "!nativeSpreadAuthorityResolved||!ReaderPreferencesModule?."
            "configureNativeSpreadReadOnly){returnfalse;}",
        ),
        (
            "editable",
            app_code[editable_transition_start:reconcile_transition_start],
            "if(!filePath||nativeSpreadBusyRef.current||"
            "!nativeSpreadAuthorityResolved||directionRef.current!=='rtl'||"
            "!nativeSpreadCompatible||!ReaderPreferencesModule?."
            "configureNativeSpreadEditable){return;}",
        ),
    )
    if min(
        direction_transition_start,
        view_transition_start,
        cover_transition_start,
        appearance_transition_start,
        readonly_transition_start,
        editable_transition_start,
        reconcile_transition_start,
        restore_transition_start,
        open_jump_start,
    ) < 0:
        fail("could not isolate Native Spread UI state transitions")
    for label, transition, exact_guard in authority_transition_sections:
        if exact_guard not in compact_code(transition):
            fail(f"{label} transition is not exactly locked by native authority")
    reconcile_transition = app_code[
        reconcile_transition_start:restore_transition_start
    ]
    reconcile_transition_compact = compact_code(reconcile_transition)
    require_markers(
        reconcile_transition_compact,
        (
            "if(!filePath||nativeSpreadBusyRef.current||"
            "!nativeSpreadReconciliationAvailable||!ReaderPreferencesModule?."
            "reconcileNativeSpreadRecovery||!ReaderPreferencesModule?."
            "loadNativeSpreadMode){return;}",
            "awaitReaderPreferencesModule.reconcileNativeSpreadRecovery("
            "filePath);constrefreshed=awaitReaderPreferencesModule."
            "loadNativeSpreadMode(filePath);constauthority="
            "classifyNativeSpreadAuthority(refreshed);if(authority.state!=="
            "NATIVE_SPREAD_AUTHORITY_READY){thrownewError(",
            "setNativeSpreadReconciliationAvailable(false);"
            "setNativeSpreadAuthorityState(NATIVE_SPREAD_AUTHORITY_READY);"
            "setNativeSpreadAuthorityDetail(null);",
            "markNativeSpreadAuthorityError(",
        ),
        "exact Native Spread UI reconciliation flow",
    )
    restore_transition = app_code[restore_transition_start:open_jump_start]
    require_markers(
        restore_transition,
        (
            "(!nativeSpreadAuthorityResolved && !nativeSpreadRecoveryAllowed)",
            "setNativeSpreadAuthorityState(NATIVE_SPREAD_AUTHORITY_READY)",
            "Annotation recovery did not complete.",
        ),
        "explicit Native Spread UI recovery transition",
    )
    require_markers(
        compact_code(restore_transition),
        (
            "if(!filePath||nativeSpreadBusyRef.current||"
            "(!nativeSpreadAuthorityResolved&&!nativeSpreadRecoveryAllowed)||"
            "!nativeBackupAvailable||!ReaderPreferencesModule?."
            "restoreNativeAnnotationBackup){return;}",
        ),
        "exact Native Spread UI recovery authority gate",
    )

    settings_start = app_code.find(
        "<Text style={styles.settingLabel}>Reading direction"
    )
    settings_end = app_code.find("{jumpOpen && (", settings_start)
    if settings_start < 0 or settings_end < 0:
        fail("could not isolate Native Spread authority settings UI")
    authority_settings = app_code[settings_start:settings_end]
    if authority_settings.count(
        "nativeSpreadBusy || !nativeSpreadAuthorityResolved"
    ) != 3:
        fail("direction/native Off controls are not locked by native authority")
    if authority_settings.count("!nativeSpreadAuthorityResolved ||") != 9:
        fail("state-dependent local/native controls are not authority-locked")
    require_markers(
        app_code,
        (
            "!fatalError && !nativeSpreadAuthorityResolved",
            "styles.nativeAuthorityBanner",
            "{nativeSpreadAuthorityDetail}",
        ),
        "visible unresolved Native Spread authority state",
    )
    require_markers(
        compact_code(authority_settings),
        (
            "{nativeSpreadAuthorityResolved&&nativeEditableConfirmOpen&&("
            "<Viewstyle={styles.nativeWarningPanel}>",
            "{nativeSpreadReconciliationAvailable&&(<Viewstyle={"
            "styles.nativeRecoveryRow}>",
            "disabled={nativeSpreadBusy}onPress={reconcileNativeSpreadRecovery}",
            "disabled={nativeSpreadBusy||(!nativeSpreadAuthorityResolved&&"
            "!nativeSpreadRecoveryAllowed)}onPress={restoreNativeBackup}",
        ),
        "exact Native Spread authority settings controls",
    )
    history_hook_start = module.find(
        'for (String methodName : new String[] {"undo", "redo"})'
    )
    history_hook_end = module.find(
        '"loadHandWrite",\n            int.class,', history_hook_start
    )
    if history_hook_start < 0 or history_hook_end < 0:
        fail("could not isolate native Undo/Redo transaction guards")
    history_hook = module[history_hook_start:history_hook_end]
    history_reset = history_hook.find(
        "PAGE_ACTIVATION_HISTORY_BLOCKED.remove();"
    )
    history_capture = history_hook.find(
        "capturePresenterCallbackScope(param.thisObject)", history_reset
    )
    history_scope = history_hook.find(
        "new HistoryMutationScope(presenterScope)", history_capture
    )
    history_push = history_hook.find(
        "pushHistoryMutationScope(scope);", history_scope
    )
    history_owner_guard = history_hook.find(
        "if (!presenterScope.activeOwner)", history_push
    )
    history_transaction = history_hook.find(
        "PAGE_ACTIVATION_TRANSACTIONS.get(activity)", history_owner_guard
    )
    history_recovery = history_hook.find(
        "PAGE_ACTIVATION_ROLLBACK_RECOVERIES.get(activity)",
        history_transaction,
    )
    history_uncertain_guard = history_hook.find(
        "if (transaction != null || rollbackRecovery != null)",
        history_recovery,
    )
    history_mark_blocked = history_hook.find(
        "scope.blocked = true;",
        history_uncertain_guard,
    )
    history_thread_blocked = history_hook.find(
        "PAGE_ACTIVATION_HISTORY_BLOCKED.set(Boolean.TRUE)",
        history_mark_blocked,
    )
    history_suppress = history_hook.find(
        "param.setResult(null);", history_thread_blocked
    )
    history_writer_guard = history_hook.find(
        "if (!documentMutationAuthorityCurrent(", history_suppress
    )
    history_writer_rejection = history_hook.find(
        "reason=writer_authority_unavailable", history_writer_guard
    )
    history_native_path = history_hook.find(
        "scope.forceCanonical = true;", history_writer_rejection
    )
    history_force_canonical = history_hook.find(
        "FORCE_CANONICAL_ACTIVE_INK.set(Boolean.TRUE);", history_native_path
    )
    history_after = history_hook.find(
        "protected void afterHookedMethod", history_force_canonical
    )
    history_pop = history_hook.find(
        "popHistoryMutationScope();", history_after
    )
    history_after_clear = history_hook.find(
        "PAGE_ACTIVATION_HISTORY_BLOCKED.remove();", history_pop
    )
    history_after_guard = history_hook.find(
        "if (scope == null || scope.blocked", history_after_clear
    )
    history_after_owner = history_hook.find(
        "presenterCallbackScopeStillActive(", history_after_guard
    )
    history_after_return = history_hook.find("return;", history_after_owner)
    history_after_native = history_hook.find(
        "Activity activity = scope.presenterScope.activity;",
        history_after_return,
    )
    history_restore = history_hook.find(
        "restoreHistoryCanonicalScopeState();", history_after_native
    )
    if not (
        0 <= history_reset < history_capture < history_scope < history_push
        < history_owner_guard < history_transaction < history_recovery
        < history_uncertain_guard < history_mark_blocked
        < history_thread_blocked < history_suppress < history_writer_guard
        < history_writer_rejection < history_native_path
        < history_force_canonical < history_after < history_pop
        < history_after_clear < history_after_guard < history_after_owner
        < history_after_return < history_after_native < history_restore
    ):
        fail(
            "native Undo/Redo can mutate or reload presenter state during an "
            "ownership transfer or rollback recovery"
        )
    require_markers(
        history_hook,
        (
            'reason=rollback_recovery path=',
            "rollbackRecovery.documentPath",
        ),
        "rollback-recovery Undo/Redo rejection",
    )

    require_markers(
        module,
        (
            "final boolean showDivider;",
            "final boolean showHeader;",
            "final boolean nativeFill;",
            'properties.getProperty("showDivider", "true")',
            'properties.getProperty("showHeader", "true")',
            'properties.getProperty("spreadSizing", "fit")',
            "LEFT_VISIBLE_BOUNDS",
            "RIGHT_VISIBLE_BOUNDS",
            "SpreadPageLayout",
            "drawPageBitmap(canvas, leftBitmap, leftLayout, bitmapPaint)",
            "canvas.clipRect(layout.visibleBounds)",
            "showStatusOverlay(",
            "!config.showHeader",
            "removeOverlay(activity);",
            "visibleBoundsOrDestination(activity, activeDestination)",
            "Math.max(",
        ),
        "native spread appearance geometry",
    )
    captured_ink_start = module.find(
        "private static Bitmap renderCapturedFullInk("
    )
    combined_ink_start = module.find(
        "private static Bitmap renderCombinedCommittedInk(",
        captured_ink_start,
    )
    if captured_ink_start < 0 or combined_ink_start < 0:
        fail("could not isolate active settled-ink compositor")
    require_markers(
        module[captured_ink_start:combined_ink_start],
        (
            "RectF activeVisibleBounds = activePageVisibleBounds(activity)",
            "activeVisibleBounds = new RectF(activeDestination)",
            "canvas.clipRect(activeVisibleBounds)",
            "canvas.drawBitmap(",
            "canvas.restoreToCount(saveCount)",
        ),
        "Native Fill active settled-ink clipping",
    )
    require_markers(
        pdf_view + pdf_view_manager + direct_patch,
        (
            'var pendingContentMode: String = "fit"',
            'if (pendingContentMode == "native_fill")',
            "max(widthScale, heightScale)",
            '@ReactProp(name = "contentMode")',
            "contentMode={spreadSizing}",
            'contentMode="fit"',
            "{showSpreadDivider && <View style={styles.spreadDivider} />}",
        ),
        "full-screen custom reader spread sizing",
    )
    configure_start = plugin.find("fun configureNativeSpreadReadOnly(")
    marker_writer_start = plugin.find(
        "private fun writeNativeSpreadReadOnlyMarker(",
        configure_start,
    )
    if configure_start < 0 or marker_writer_start < 0:
        fail("could not isolate Native Spread configuration method")
    configure = plugin[configure_start:marker_writer_start]
    rejection = configure.find("if (!handshake.active)")
    marker_write = configure.find("writeNativeSpreadReadOnlyMarker(")
    handshake_apply = configure.find(
        "applyReadOnlyConfiguration(handshake)",
        rejection,
    )
    if (
        rejection < 0
        or marker_write < 0
        or "checkNotNull(handshake)" not in configure
        or handshake_apply < rejection
    ):
        fail("marker creation is not gated by a successful live handshake")

    editable_start = plugin.find("fun configureNativeSpreadEditable(")
    restore_start = plugin.find("fun restoreNativeAnnotationBackup(", editable_start)
    if editable_start < 0 or restore_start < 0:
        fail("could not isolate protected editable configuration method")
    editable_configure = plugin[editable_start:restore_start]
    editable_handshake = editable_configure.find("if (!handshake.active)")
    editable_worker = editable_configure.find(
        'startNativeBackupWorker("RTLReaderNativeBackupCreate")'
    )
    editable_activation = editable_configure.find(
        "activateNativeSpreadEditableWithStableBackup("
    )
    if not (
        0 <= editable_handshake < editable_worker < editable_activation
    ):
        fail(
            "editable marker is not gated by handshake then background verified backup"
        )

    stable_backup_start = plugin.find(
        "private fun ensureStableNativeAnnotationBackupForActivation("
    )
    activation_helper_start = plugin.find(
        "private fun activateNativeSpreadEditableWithStableBackup(",
        stable_backup_start,
    )
    rollback_helper_start = plugin.find(
        "private fun rollbackNativeSpreadEditableActivation(",
        activation_helper_start,
    )
    live_match_start = plugin.find(
        "private fun liveNativeAnnotationMatchesBackup(",
        rollback_helper_start,
    )
    read_backup_start = plugin.find(
        "private fun readNativeAnnotationBackup(",
        live_match_start,
    )
    if min(
        stable_backup_start,
        activation_helper_start,
        rollback_helper_start,
        live_match_start,
        read_backup_start,
    ) < 0:
        fail("could not isolate live annotation backup stabilization")
    stable_backup = plugin[stable_backup_start:activation_helper_start]
    require_markers(
        plugin[stable_backup_start:read_backup_start],
        (
            "repeat(maximumAttempts)",
            "val backup = ensureNativeAnnotationBackup(pdfFile)",
            "liveNativeAnnotationMatchesBackup(backup)",
            "removeNativeAnnotationBackupFiles(pdfFile, backup)",
            "mark.length() == backup.markLength",
            "sha256(mark) == backup.markSha256",
            "!mark.exists()",
            "RTL_READER_NATIVE_BACKUP_LIVE_MARK_CHANGED",
        ),
        "live annotation backup stabilization",
    )
    snapshot_attempt = stable_backup.find(
        "val backup = ensureNativeAnnotationBackup(pdfFile)"
    )
    live_check = stable_backup.find(
        "liveNativeAnnotationMatchesBackup(backup)",
        snapshot_attempt,
    )
    retry_cleanup = stable_backup.find(
        "removeNativeAnnotationBackupFiles(pdfFile, backup)",
        live_check,
    )
    if not 0 <= snapshot_attempt < live_check < retry_cleanup:
        fail("editable activation does not retry a snapshot after live .mark drift")

    activation_helper = plugin[activation_helper_start:rollback_helper_start]
    marker_snapshot = activation_helper.find(
        "val previousMarkerBytes = readPersistedBytesIfFile(marker)"
    )
    backup_existed = activation_helper.find(
        "val backupManifestExisted = nativeAnnotationBackupManifest(pdfFile).isFile"
    )
    backup_create = activation_helper.find(
        "ensureStableNativeAnnotationBackupForActivation("
    )
    activation_token = activation_helper.find(
        "val activationToken = UUID.randomUUID().toString()"
    )
    pending_write = activation_helper.find(
        "writeNativeSpreadPendingMarker(", backup_create
    )
    pending_published = activation_helper.find(
        "markerPublishedByActivation = true", pending_write
    )
    post_publication_live_check = activation_helper.find(
        "liveNativeAnnotationMatchesBackup(activationBackup)", pending_published
    )
    committed_write = activation_helper.find(
        "commitNativeSpreadEditableMarker(", post_publication_live_check
    )
    final_revalidation_required = activation_helper.find(
        "requireLiveBaselineMatch =", committed_write
    )
    committed_published = activation_helper.find(
        "committedMarkerPublishedByActivation = true", final_revalidation_required
    )
    rollback = activation_helper.find(
        "rollbackNativeSpreadEditableActivation(", committed_published
    )
    fail_closed_throw = activation_helper.find("throw changed", rollback)
    committed_catch_guard = activation_helper.find(
        "if (committedMarkerPublishedByActivation)",
        fail_closed_throw,
    )
    committed_catch_return = activation_helper.find(
        "throw activationError", committed_catch_guard
    )
    if not (
        0 <= marker_snapshot < backup_existed < activation_token
        < backup_create < pending_write < pending_published
        < post_publication_live_check < committed_write
        < final_revalidation_required
        < committed_published < rollback < fail_closed_throw
        < committed_catch_guard < committed_catch_return
    ):
        fail(
            "editable activation is not linearized as pending publication, "
            "final live-mark check, committed authorization, and fail-closed rollback"
        )
    if compact_code(activation_helper).count(
        "requireLiveBaselineMatch=!backupManifestExisted&&legacyMigration==null"
    ) != 1:
        fail(
            "editable activation must require final live-baseline matching "
            "exactly for first-time backup creation outside legacy migration"
        )
    if "Thread.sleep(100L)" in activation_helper or "retrying activation" in activation_helper:
        fail("post-publication .mark divergence is retried from changed bytes")
    rollback_helper = plugin[rollback_helper_start:live_match_start]
    require_markers(
        rollback_helper,
        (
            "): Boolean",
            "markerPublishedByActivation: Boolean",
            "val ownsPublishedMarker = currentMarkerProperties.getProperty(",
            '"activationToken",',
            "== activationToken",
            "val markerOwnershipLost = !ownsPublishedMarker && !markerAlreadyPrevious",
            "val archiveNewBackup = !backupManifestExisted &&",
            "markerPublishedByActivation || ownsPublishedMarker",
            "if (markerOwnershipLost && !archiveNewBackup)",
            "RTL_READER_NATIVE_EDITABLE_ACTIVATION_ROLLBACK_SKIPPED reason=marker_ownership_lost",
            "fun restorePublishedMarkerIfOwned()",
            "publishNativeSpreadOffMarkerLocked(",
            "writeBytesAtomicallyCas(",
            "currentMarkerAuthority",
            "requireDocumentAuthorityAck(",
            "failedActivationArchive = archiveFailedActivationBackup(",
            "restorePublishedMarkerIfOwned()",
            "removeNativeAnnotationBackupFiles(pdfFile, backup)",
            "val preserved = readNativeAnnotationBackup(pdfFile).backup",
            "sameNativeAnnotationBackup(backup, preserved)",
            "failedActivationBackupArchived(pdfFile, archive)",
            "failedActivationEvidenceMatchesBackup(evidence, backup)",
            "readPersistedBytesIfFile(marker)",
            "?.contentEquals(previousMarkerBytes) == true",
            "!nativeAnnotationBackupManifest(pdfFile).exists()",
            "!nativeAnnotationBackupSnapshot(pdfFile).exists()",
            "!nativeAnnotationRetiringSnapshot(pdfFile).exists()",
            '"Protected editable activation rollback could not be verified"',
            "RTL_READER_NATIVE_EDITABLE_ACTIVATION_ROLLED_BACK",
        ),
        "verified post-publication editable activation rollback",
    )
    archive_decision = rollback_helper.find(
        "val archiveNewBackup = !backupManifestExisted &&"
    )
    archive_call = rollback_helper.find(
        "failedActivationArchive = archiveFailedActivationBackup(",
        archive_decision,
    )
    marker_restore = rollback_helper.find(
        "restorePublishedMarkerIfOwned()", archive_call
    )
    archived_verify = rollback_helper.find(
        "failedActivationBackupArchived(pdfFile, archive)", marker_restore
    )
    if not (
        0 <= archive_decision < archive_call < marker_restore < archived_verify
    ):
        fail(
            "activation rollback restores/removes its pending marker before "
            "the sole pre-activation recovery snapshot is durably archived"
        )
    if "liveNativeAnnotationMatchesBackup(backup)" in rollback_helper:
        fail(
            "rollback conditionally deletes recovery evidence based on a "
            "racy live .mark comparison"
        )
    require_markers(
        plugin,
        (
            "private val nativeSpreadConfigurationLock = Any()",
            "synchronized(nativeSpreadConfigurationLock) { action() }",
            "activationToken: String",
            'setProperty("activationToken", activationToken)',
            'setProperty("activationState", activationState)',
            'properties.getProperty("activationState", "") == activationState',
        ),
        "serialized ownership-tagged native spread configuration",
    )

    configure_worker = configure.find(
        'startNativeBackupWorker("RTLReaderNativeBackupRetire")'
    )
    retirement_reconcile = configure.find(
        "reconcileFailedActivationBackupForExplicitActivation(",
        configure_worker,
    )
    marker_snapshot = configure.find(
        "val previousMarkerBytes =", retirement_reconcile
    )
    retirement_pending = configure.find(
        "writeNativeSpreadPendingMarker(", marker_snapshot
    )
    retirement = configure.find(
        "retireNativeAnnotationBackup(", retirement_pending
    )
    retirement_verified = configure.find(
        "Protected-session recovery retirement was not verified",
        retirement,
    )
    pending_revalidated = configure.find(
        "readPendingEditableActivation(", retirement_verified
    )
    final_disable = configure.find("if (!enabled)", pending_revalidated)
    final_read_only = configure.find(
        "writeNativeSpreadReadOnlyMarker(", final_disable
    )
    if not (
        0 <= configure_worker < retirement_reconcile < marker_snapshot
        < retirement_pending < retirement < retirement_verified
        < pending_revalidated < final_disable < final_read_only
    ):
        fail(
            "read-only/off transition is not durably journaled before backup "
            "retirement and revalidated before final marker publication"
        )

    require_markers(
        module,
        (
            "final long documentModified;",
            "final long documentLength;",
            "final long documentDevice;",
            "final long documentInode;",
            "final long documentChangeSeconds;",
            "final long documentChangeNanos;",
            "&& cached.documentModified == documentModified",
            "&& cached.documentLength == documentLength",
            "&& cached.documentDevice == documentDevice",
            "&& cached.documentInode == documentInode",
            "&& cached.documentChangeSeconds == documentChangeSeconds",
            "&& cached.documentChangeNanos == documentChangeNanos",
            "&& documentModified == nextDocumentModified",
            "&& documentLength == nextDocumentLength",
            "&& documentDevice == nextDocumentDevice",
            "&& documentInode == nextDocumentInode",
            "&& documentChangeSeconds == nextDocumentChangeSeconds",
            "&& documentChangeNanos == nextDocumentChangeNanos",
            "FileIdentity documentIdentity = FileIdentity.capture(document);",
            "if (!documentIdentity.isRegular())",
            "long documentModified = documentIdentity.modified;",
            "long documentLength = documentIdentity.length;",
            "long documentDevice = documentIdentity.device;",
            "long documentInode = documentIdentity.inode;",
            "long documentChangeSeconds = documentIdentity.changeSeconds;",
            "long documentChangeNanos = documentIdentity.changeNanos;",
            "final FileIdentity markerIdentity;",
            "final FileIdentity backupIdentity;",
            "final FileIdentity snapshotIdentity;",
            "FileIdentity markerIdentity = FileIdentity.capture(marker);",
            "FileIdentity backupIdentity = FileIdentity.capture(backupManifest);",
            "FileIdentity snapshotIdentity = FileIdentity.capture(backupSnapshot);",
            "&& cached.markerIdentity.sameAs(markerIdentity)",
            "&& cached.backupIdentity.sameAs(backupIdentity)",
            "&& cached.snapshotIdentity.sameAs(snapshotIdentity)",
            "&& markerIdentity.sameAs(nextMarkerIdentity)",
            "&& backupIdentity.sameAs(nextBackupIdentity)",
            "&& snapshotIdentity.sameAs(nextSnapshotIdentity)",
            "startProtectedEditableVerification(",
        ),
        "protected PDF replacement invalidation",
    )

    ensure_start = plugin.find("private fun ensureNativeAnnotationBackup(")
    read_backup_start = plugin.find("private fun readNativeAnnotationBackup(", ensure_start)
    if ensure_start < 0 or read_backup_start < 0:
        fail("could not isolate annotation backup creation/reuse method")
    ensure_backup = plugin[ensure_start:read_backup_start]
    inactive_guard = ensure_backup.find(
        "protectedEditableSessionMarkerValid("
    )
    reuse_log = ensure_backup.find("RTL_READER_NATIVE_BACKUP_REUSED")
    if inactive_guard < 0 or reuse_log < 0 or inactive_guard > reuse_log:
        fail("a verified backup can be reused without an active protected session")
    retire_start = plugin.find("private fun retireNativeAnnotationBackup(")
    cleanup_start = plugin.find(
        "private fun removeNativeAnnotationBackupFiles(", retire_start
    )
    if retire_start < 0 or cleanup_start < 0:
        fail("could not isolate protected backup retirement authorization")
    retire_backup = plugin[retire_start:cleanup_start]
    retire_authorization = retire_backup.find(
        "protectedEditableSessionMarkerValid("
    )
    retire_remove = retire_backup.find(
        "removeNativeAnnotationBackupFiles(pdfFile, backup)",
        retire_authorization,
    )
    if not 0 <= retire_authorization < retire_remove:
        fail(
            "legacy/current protected backup cannot be safely retired after "
            "the marker is disabled or downgraded"
        )
    snapshot_copy = ensure_backup.find("copyFileAtomically(mark, snapshot)")
    final_verification = ensure_backup.find(
        "val verified = readNativeAnnotationBackup(pdfFile)",
        snapshot_copy,
    )
    creation_catch = ensure_backup.find("catch (error: Throwable)", snapshot_copy)
    rollback_log = ensure_backup.find(
        "RTL_READER_NATIVE_BACKUP_CREATION_ROLLED_BACK",
        creation_catch,
    )
    if not (
        0 <= snapshot_copy < final_verification < creation_catch < rollback_log
    ):
        fail("annotation backup final verification is outside rollback scope")

    close_start = app.find("const close = async () =>")
    go_by_start = app.find("const goBy = delta =>", close_start)
    if close_start < 0 or go_by_start < 0:
        fail("could not isolate plugin Close handler")
    close_handler = app[close_start:go_by_start]
    busy_guard = close_handler.find("if (nativeSpreadBusyRef.current)")
    close_plugin = close_handler.find("PluginManager.closePluginView()")
    if not (0 <= busy_guard < close_plugin):
        fail("Close can hand off while a native-mode transition is pending")
    close_settings_start = close_handler.find("const closeSettings = () =>")
    close_settings_guard = close_handler.find(
        "if (nativeSpreadBusyRef.current)",
        close_settings_start,
    )
    close_settings_commit = close_handler.find(
        "setSettingsOpen(false);",
        close_settings_start,
    )
    if not (
        0 <= close_settings_start < close_settings_guard < close_settings_commit
    ):
        fail("Settings can close before the busy ref clears")

    settings_start = app.find("{settingsOpen && !fatalError && (")
    cover_controls_start = app.find(
        "<Text style={styles.settingLabel}>Treat Cover Page Separately</Text>",
        settings_start,
    )
    settings_header = app[settings_start:cover_controls_start]
    if (
        "disabled={nativeSpreadBusy}" not in settings_header
        or "onPress={closeSettings}" not in settings_header
        or "nativeSpreadBusy ? 'Applying...' : 'Done'" not in settings_header
    ):
        fail("Settings Done remains available during a native-mode transition")

    settings_panel_start = app.find("<View style={styles.settingsPanel}>")
    settings_scroll_start = app.find(
        "<ScrollView", settings_panel_start
    )
    warning_panel_start = app.find(
        "{nativeSpreadAuthorityResolved && nativeEditableConfirmOpen && (",
        settings_scroll_start,
    )
    recovery_row_start = app.find(
        "{nativeBackupAvailable && (", warning_panel_start
    )
    settings_scroll_end = app.find("</ScrollView>", recovery_row_start)
    if not (
        0 <= settings_panel_start < settings_scroll_start
        < warning_panel_start < recovery_row_start < settings_scroll_end
    ):
        fail("expanded native settings controls are not inside the settings scroll view")
    if (
        "style={styles.settingsScroll}" not in app[
            settings_scroll_start:warning_panel_start
        ]
        or "maxHeight: '90%'" not in app
        or "settingsScroll: {" not in app
        or "flexShrink: 1" not in app
    ):
        fail("settings panel is not bounded to a scrollable viewport")

    restore_worker_start = plugin.find("private fun scheduleAnnotationRestore(")
    restore_worker_end = plugin.find("\n    }\n}", restore_worker_start)
    if restore_worker_start < 0 or restore_worker_end < 0:
        fail("could not isolate annotation restore worker")
    restore_worker = plugin[restore_worker_start:restore_worker_end]
    nullable_sample = plugin.find(
        "private fun documentPids(activityManager: ActivityManager): List<Int>?"
    )
    nullable_fail_closed = plugin.find(
        "activityManager.runningAppProcesses ?: return null",
        nullable_sample,
    )
    nullable_throw = plugin.find(
        "documentPids(activityManager) ?: run {",
        nullable_fail_closed,
    )
    if not 0 <= nullable_sample < nullable_fail_closed < nullable_throw:
        fail("unavailable document-process samples do not fail closed")
    stable_absence = restore_worker.find(
        "RTL_READER_NATIVE_BACKUP_RESTORE_STABLE_PROCESS_ABSENCE"
    )
    replacement_generation = restore_worker.find(
        "pid !in initialPids ||"
    )
    repeated_pid_generation = restore_worker.find(
        "pid in signaledPids && pid !in previousRunning",
        replacement_generation,
    )
    document_revalidation = restore_worker.find(
        "val revalidatedBackup = readNativeAnnotationBackup(pdfFile).backup"
    )
    backup_identity_check = restore_worker.find(
        "sameNativeAnnotationBackup(backup, revalidatedBackup)"
    )
    recovery_fence = restore_worker.find(
        "publishNativeMarkRecoveryJournal(", backup_identity_check
    )
    mark_write = restore_worker.find(
        "publishNativeAnnotationRestore(", recovery_fence
    )
    before_publish_callback = restore_worker.find(
        "beforePublish = {", mark_write
    )
    before_publish_guard = restore_worker.find(
        '"before-mark-publish"', before_publish_callback
    )
    after_publish_callback = restore_worker.find(
        "afterPublish = {", before_publish_guard
    )
    after_publish_guard = restore_worker.find(
        '"after-mark-publish"', after_publish_callback
    )
    mark_verification = restore_worker.find(
        "Restored annotation file verification failed", after_publish_guard
    )
    if not (
        0 <= replacement_generation < repeated_pid_generation < stable_absence
        < document_revalidation < backup_identity_check < recovery_fence
        < mark_write
        < before_publish_callback < before_publish_guard
        < after_publish_callback < after_publish_guard < mark_verification
    ):
        fail(
            "annotation restore can publish .mark without stable process "
            "absence, replacement-PID handling, or adjacent publication guards"
        )
    race_kill = plugin.find(
        "RTL_READER_NATIVE_BACKUP_RESTORE_RACE_KILL_SENT"
    )
    if race_kill < 0:
        fail("annotation restore does not terminate a publication-race process")
    copy_helper_start = plugin.find("private fun copyFileAtomically(")
    copy_helper_end = plugin.find("private fun sha256(file: File)", copy_helper_start)
    if copy_helper_start < 0 or copy_helper_end < 0:
        fail("could not isolate atomic annotation restore copy helper")
    copy_helper = plugin[copy_helper_start:copy_helper_end]
    helper_before = copy_helper.find("beforePublish()")
    helper_rename = copy_helper.find(
        "Os.rename(temporary.absolutePath, destination.absolutePath)",
        helper_before,
    )
    helper_after = copy_helper.find("onPublished()", helper_rename)
    if not 0 <= helper_before < helper_rename < helper_after:
        fail("atomic annotation copy does not guard both sides of publication")
    retirement_guard = restore_worker.find(
        '"before-backup-retirement"',
        mark_verification,
    )
    journal_retirement = restore_worker.find(
        "retireNativeMarkRecoveryJournal(", retirement_guard
    )
    recovery_commit = restore_worker.find(
        "recoveryCommitProven = true", journal_retirement
    )
    transactional_cleanup = restore_worker.find(
        "removeNativeAnnotationBackupFiles(",
        recovery_commit,
    )
    restore_success = restore_worker.find(
        "completion(persistenceError)", transactional_cleanup
    )
    if not (
        0 <= mark_verification < retirement_guard < journal_retirement
        < recovery_commit < transactional_cleanup < restore_success
    ):
        fail(
            "annotation restore does not commit the exact RECOVERY journal to "
            "acknowledged OFF authority before retiring backup evidence"
        )

    restore_api_start = plugin.find("fun restoreNativeAnnotationBackup(")
    marker_writer_start = plugin.find(
        "private fun writeNativeSpreadReadOnlyMarker(", restore_api_start
    )
    if restore_api_start < 0 or marker_writer_start < 0:
        fail("could not isolate annotation restore API")
    restore_api = plugin[restore_api_start:marker_writer_start]
    scheduled = restore_api.find("scheduleAnnotationRestore(")
    completed = restore_api.find(
        'promise.resolve(nativeAnnotationBackupMap(backup, "restored"))'
    )
    failure_toast = restore_api.find("Toast.makeText(")
    if not (0 <= scheduled < completed and 0 <= scheduled < failure_toast):
        fail("annotation restore promise does not report the worker's final outcome")
    if "restore_scheduled" in restore_api:
        fail("annotation restore still reports scheduling as successful recovery")

    restore_handler_start = app.find("const restoreNativeBackup = async () =>")
    open_jump_start = app.find("const openJump = () =>", restore_handler_start)
    if restore_handler_start < 0 or open_jump_start < 0:
        fail("could not isolate Restore snapshot UI handler")
    restore_handler = app[restore_handler_start:open_jump_start]
    restore_completed = restore_handler.find(
        "await ReaderPreferencesModule.restoreNativeAnnotationBackup(filePath)"
    )
    clear_restore_busy_ref = restore_handler.find(
        "nativeSpreadBusyRef.current = false;",
        restore_completed,
    )
    clear_restore_busy_state = restore_handler.find(
        "setNativeSpreadBusy(false);",
        clear_restore_busy_ref,
    )
    restore_close = restore_handler.find("await close();", restore_completed)
    if not (
        0 <= restore_completed < clear_restore_busy_ref
        < clear_restore_busy_state < restore_close
    ):
        fail("successful Restore remains blocked by the native transition busy guard")

    cleanup_start = plugin.find("private fun removeNativeAnnotationBackupFiles(")
    ensure_start = plugin.find("private fun ensureNativeAnnotationBackup(", cleanup_start)
    if cleanup_start < 0 or ensure_start < 0:
        fail("could not isolate transactional annotation backup cleanup")
    cleanup = plugin[cleanup_start:ensure_start]
    stage_snapshot = cleanup.find(
        "renameFileDurably(backup.snapshot, retiring)"
    )
    delete_manifest = cleanup.find("deleteFileDurably(backup.manifest)")
    rollback_snapshot = cleanup.find(
        "renameFileDurably(retiring, backup.snapshot)"
    )
    if not (0 <= stage_snapshot < delete_manifest < rollback_snapshot):
        fail("annotation backup retirement can lose its manifest before safe staging")

    require_markers(
        module,
        (
            "HANDSHAKE_REQUEST_ACTION",
            "HANDSHAKE_RESPONSE_ACTION",
            "private static final int HANDSHAKE_PROTOCOL = 2;",
            "private static final long MODULE_VERSION_CODE = 135L;",
            "private static final long TRANSACTIONAL_MIN_MODULE_VERSION_CODE = 118L;",
            "private static final int EDITABLE_MARKER_PROTOCOL = 2;",
            '"protected-editable-transactional-v1"',
            "private static volatile boolean hooksReady;",
            "registerHandshakeReceiver(createdActivity);",
            "hooksReady = true;",
            "response.setPackage(PLUGIN_HOST_PACKAGE);",
            "response.putExtra(HANDSHAKE_EXTRA_HOOKS_READY, true);",
            "HANDSHAKE_EXTRA_DOCUMENT_APK_LENGTH",
            "HANDSHAKE_EXTRA_PROCESS_ID",
            "sameCanonicalPath(",
            "releaseActivityResources(activity);",
            "activeActivity = null;",
            "recycleRemovedBitmap(COMPOSITES, activity)",
            "COMMITTED_INK_COMPOSITES",
            "FULL_INK_BITMAPS",
            "DIGEST_COMPOSITES",
            "LEFT_DESTINATIONS.remove(activity);",
            "RIGHT_DESTINATIONS.remove(activity);",
            "SPREAD_CONFIGS.remove(activity);",
            "PROTECTED_VERIFICATIONS.remove(activity);",
            "activity_resources_released",
            "protectedEditableBackupValid(",
            "startProtectedEditableVerification(",
            'new Thread(() -> {',
            '"SNSpreadBackupVerify"',
            "verification.complete",
            "verification.valid",
            '"protected_backup_verified"',
            "protected_editable_backup_refresh_scheduled",
            '"transactionProtocol"',
            '"minimumModuleVersionCode"',
            "validActivationToken(",
            "expectedManifestHash.equals(sha256(expectedManifest))",
            'backup.getProperty("documentSha256", "")',
            "backupDocumentHash.equals(markerDocumentHash)",
            "backupDocumentHash.equals(currentDocumentHash)",
            "protected_editable_document_mtime_changed",
            "protected_editable_backup_verified",
            "cached.backupIdentity.sameAs(backupIdentity)",
            "cached.snapshotIdentity.sameAs(snapshotIdentity)",
            "spreadLassoCanonicalSelection",
            "pureCanonicalMove",
            '" preserve_size=" + preserveCanonicalSize',
            '" content_padding=" + contentPaddingX',
        ),
        "companion handshake/lifecycle",
    )
    if '"protected-editable-pilot"' in module:
        fail("companion module still accepts the legacy editable pilot marker")

    # LSPosed loads this class into the document process, so installation by
    # itself must not change an ordinary document.  Only a successfully
    # published, enabled sidecar may arm behavior-changing hooks.  Keep these
    # structural checks in addition to the frozen digest so an intentional
    # source review cannot accidentally bless a fail-open containment change.
    module_compact = compact_code(module)
    if module_compact.count(
        "privatestaticfinalMap<Activity,String>"
        "NATIVE_SPREAD_CONTROL_CLAIMS=newConcurrentHashMap<>();"
    ) != 1:
        fail("Native Spread must have one explicit per-activity control claim")
    claim_method = compact_code(
        extract_java_method(
            module,
            "private static boolean nativeSpreadControlClaimed(",
            "Native Spread control-claim predicate",
        )
    )
    if (
        "returnactivity!=null&&NATIVE_SPREAD_CONTROL_CLAIMS.get(activity)"
        "!=null;"
    ) not in claim_method:
        fail("Native Spread control claims are not exact per-activity claims")
    any_claim_method = compact_code(
        extract_java_method(
            module,
            "private static boolean hasAnyNativeSpreadControlClaim(",
            "current-owner Native Spread claim predicate",
        )
    )
    if (
        "Activitycurrent=activeActivity;Activitypending=pendingActivity;"
        "returnnativeSpreadControlClaimed(current)||"
        "nativeSpreadControlClaimed(pending);"
    ) not in any_claim_method:
        fail("unbound-hook blocking is not limited to the current/pending claim")
    unbound_method = compact_code(
        extract_java_method(
            module,
            "private static boolean mustBlockUnboundModuleComponent(",
            "unbound component containment predicate",
        )
    )
    if "&&hasAnyNativeSpreadControlClaim();" not in unbound_method:
        fail("unbound ordinary-reader components can be blocked without a claim")
    if "activeActivity!=null||pendingActivity!=null" in unbound_method:
        fail("mere activity existence still arms behavior-changing hooks")

    claimed_component_method = compact_code(
        extract_java_method(
            module,
            "private static Activity claimedActivityForComponent(",
            "claimed component identity resolver",
        )
    )
    require_markers(
        claimed_component_method,
        (
            "for(Map.Entry<Activity,Object>entry:bindings.entrySet())",
            "entry.getValue()==component",
            "nativeSpreadControlClaimed(owner)",
        ),
        "claimed component identity resolver",
    )
    for signature, owner_name, label in (
        (
            "private static Activity activityForNativeEventCallback(",
            "activity",
            "native pen callback resolver",
        ),
        (
            "private static Activity activeActivityForDocumentViewModel(",
            "candidate",
            "document view-model resolver",
        ),
        (
            "private static Activity activityForHandWriteClient(",
            "candidate",
            "handwriting client resolver",
        ),
        (
            "private static Activity activeActivityForHandWriteView(",
            "candidate",
            "handwriting view resolver",
        ),
        (
            "private static Activity activityForHandWritePresenter(",
            "candidate",
            "handwriting presenter resolver",
        ),
        (
            "private static Activity activityForSuperNoteNote(",
            "candidate",
            "native note resolver",
        ),
    ):
        resolver = compact_code(extract_java_method(module, signature, label))
        if (
            f"!nativeSpreadControlClaimed({owner_name})" not in resolver
            or resolver.find(f"!nativeSpreadControlClaimed({owner_name})")
            > resolver.find("synchronized(PAGE_ACTIVATION_OWNERSHIP_LOCK)")
        ):
            fail(f"{label} can bind an ordinary-reader component")

    for signature, binding, label in (
        (
            "private static boolean knownNativeEventCallback(",
            "NATIVE_EVENT_CALLBACKS",
            "known native callback",
        ),
        (
            "private static boolean knownDocumentViewModel(",
            "DOCUMENT_VIEW_MODELS",
            "known document view model",
        ),
        (
            "private static boolean knownHandWriteClient(",
            "HANDWRITE_CLIENTS",
            "known handwriting client",
        ),
        (
            "private static boolean knownHandWriteView(",
            "HANDWRITE_VIEWS",
            "known handwriting view",
        ),
        (
            "private static boolean knownSuperNoteNote(",
            "SUPER_NOTE_NOTES",
            "known native note",
        ),
    ):
        known_method = compact_code(
            extract_java_method(module, signature, label)
        )
        if f"claimedActivityForComponent({binding}," not in known_method:
            fail(f"{label} is not constrained by an enabled-document claim")

    owner_barrier = compact_code(
        extract_java_method(
            module,
            "private static void installOwnerLifetimeBarriers(",
            "owner-lifetime barrier installer",
        )
    )
    inert_barrier = owner_barrier.find(
        "if(!hasAnyNativeSpreadControlClaim()){"
    )
    first_lock = owner_barrier.find("booleanownerAcquired=false;")
    if not 0 <= inert_barrier < first_lock:
        fail("ordinary-reader callbacks enter Native Spread lifetime locks")
    inert_return = owner_barrier.find("return;", inert_barrier, first_lock)
    if inert_return < 0 or "param.setResult" in owner_barrier[
        inert_barrier:inert_return
    ]:
        fail("ordinary-reader lifetime-barrier bypass can suppress firmware")

    ordinary_activity_guards = (
        (
            '"onConfigurationChanged",Configuration.class,',
            "if(!nativeSpreadControlClaimed(activity)){return;}",
        ),
        (
            '"dispatchTouchEvent",MotionEvent.class,',
            "if(!nativeSpreadControlClaimed(activity)){return;}",
        ),
        (
            '"changeSelectTextModel",int.class,',
            "if(!nativeSpreadControlClaimed(activity)){return;}",
        ),
        (
            '"handWriteSelectText",int.class,List.class,',
            "if(!nativeSpreadControlClaimed(activity)){return;}",
        ),
        (
            '"showSelectTextPopView",newXC_MethodHook()',
            "if(!nativeSpreadControlClaimed(activity)){return;}",
        ),
        (
            '"setDigestImage",Bitmap.class,',
            "if(!nativeSpreadControlClaimed(activity)){return;}",
        ),
    )
    for hook_signature, guard in ordinary_activity_guards:
        hook_start = module_compact.find(hook_signature)
        guard_start = module_compact.find(guard, hook_start)
        next_hook = module_compact.find(
            "XposedHelpers.findAndHookMethod(", hook_start + 1
        )
        if not (
            hook_start >= 0
            and guard_start > hook_start
            and (next_hook < 0 or guard_start < next_hook)
        ):
            fail(
                "ordinary-reader direct hook lacks an inert control-claim "
                f"guard: {hook_signature}"
            )

    set_image_guard = (
        "pushSetImageScope(scope);if(!activeOwner){"
        "if(nativeSpreadControlClaimed(activity)){param.setResult(null);}"
        "return;}if(!nativeSpreadControlClaimed(activity)){return;}"
    )
    if set_image_guard not in module_compact:
        fail("ordinary setImage can withdraw or suppress native presentation")

    activity_create_hook = compact_code(
        module[
            module.find(
                'XposedHelpers.findAndHookMethod(\n            TARGET_ACTIVITY,\n'
                '            loadPackageParam.classLoader,\n            "onCreate"'
            ) : module.find(
                'XposedHelpers.findAndHookMethod(\n            TARGET_ACTIVITY,\n'
                '            loadPackageParam.classLoader,\n'
                '            "onConfigurationChanged"'
            )
        ]
    )
    create_claim = activity_create_hook.find(
        "booleanpreviousControlClaimed="
        "nativeSpreadControlClaimed(previous);"
    )
    create_lock_guard = activity_create_hook.find(
        "if(previousControlClaimed){"
        "OWNER_LIFETIME_LOCK.writeLock().lock();"
        "ACTIVITY_CREATE_WRITE_HELD.set(Boolean.TRUE);"
        "}else{ACTIVITY_CREATE_WRITE_HELD.remove();}"
    )
    create_native_withdraw = activity_create_hook.find(
        "if(previousControlClaimed){"
        'disableNativeGateForOwnershipHandoffLocked("activity_create_pending");'
        "}"
    )
    create_config = activity_create_hook.find(
        "SpreadConfigcreatedConfig=spreadConfig(createdActivity);"
    )
    create_new_claim_guard = activity_create_hook.find(
        "if(createdConfig!=null&&"
        "nativeSpreadControlClaimed(createdActivity)){"
        'updateNativeEraserGate(createdActivity,"activity_created");'
        "}"
    )
    if not (
        0 <= create_claim < create_lock_guard < create_native_withdraw
        < create_config < create_new_claim_guard
    ):
        fail("ordinary DocumentActivity startup can enter Native Spread hardware state")

    on_destroy_start = module_compact.find(
        '"onDestroy",newXC_MethodHook()'
    )
    on_destroy_end = module_compact.find(
        "XposedHelpers.findAndHookMethod(", on_destroy_start + 1
    )
    on_destroy_hook = module_compact[on_destroy_start:on_destroy_end]
    if (
        "booleandestroyControlClaimed="
        "nativeSpreadControlClaimed(activity);"
        "if(destroyControlClaimed){"
        "OWNER_LIFETIME_LOCK.writeLock().lock();"
        "ACTIVITY_DESTROY_WRITE_HELD.set(Boolean.TRUE);"
        "}else{ACTIVITY_DESTROY_WRITE_HELD.remove();}"
    ) not in on_destroy_hook or (
        "if(destroyControlClaimed){"
        'updateNativeEraserGate(activity,"activity_destroyed",false);'
        "}"
    ) not in on_destroy_hook:
        fail("ordinary DocumentActivity teardown can enter Native Spread locks or JNI")

    for signature, required, label in (
        (
            "private static boolean isCalibrationLandscape(",
            "returnnativeSpreadControlClaimed(activity)&&",
            "spread-landscape predicate",
        ),
        (
            "private static boolean isReadOnlyNativeMode(",
            "returnnativeSpreadControlClaimed(activity)&&",
            "read-only predicate",
        ),
        (
            "private static boolean isCachedSpreadLandscape(",
            "&&nativeSpreadControlClaimed(activity)&&",
            "cached spread predicate",
        ),
        (
            "private static boolean isCalibrationFile(",
            "returnnativeSpreadControlClaimed(activity)&&",
            "enabled-document predicate",
        ),
    ):
        predicate = compact_code(extract_java_method(module, signature, label))
        if required not in predicate:
            fail(f"{label} can arm without an exact Native Spread claim")

    gate_update = compact_code(
        extract_java_method(
            module,
            "private static void updateNativeEraserGate(\n"
            "        Activity activity,\n        String reason\n    )",
            "native eraser discovery gate",
        )
    )
    gate_config = gate_update.find("SpreadConfigconfig=spreadConfig(activity);")
    gate_claim = gate_update.find(
        "if(!nativeSpreadControlClaimed(activity)){return;}", gate_config
    )
    gate_orientation = gate_update.find(
        "intorientation=activity.getResources()", gate_claim
    )
    if not 0 <= gate_config < gate_claim < gate_orientation:
        fail("ordinary config discovery can mutate the JNI/writer gate")

    cache_config = compact_code(
        extract_java_method(
            module,
            "private static SpreadConfig cacheSpreadConfig(",
            "spread config publication",
        )
    )
    claim_publish = cache_config.find(
        "if(config.enabled){acquiredControlClaim="
        "NATIVE_SPREAD_CONTROL_CLAIMS.put(activity,config.documentPath)==null;"
    )
    claim_release = cache_config.find(
        "elseif(PAGE_ACTIVATION_TRANSACTIONS.get(activity)==null&&"
        "PAGE_ACTIVATION_ROLLBACK_RECOVERIES.get(activity)==null&&"
        "DEFERRED_SPREAD_TURNS.get(activity)==null){"
    )
    claim_remove = cache_config.find(
        "NATIVE_SPREAD_CONTROL_CLAIMS.remove(activity)", claim_release
    )
    hardware_restore = cache_config.find(
        "scheduleOrdinaryReaderHardwareRestore(activity,"
        '"verified_native_spread_off")',
        claim_remove,
    )
    if not 0 <= claim_publish < claim_release < claim_remove < hardware_restore:
        fail("Native Spread claim publication/release is not transactional")
    if cache_config.count("NATIVE_SPREAD_CONTROL_CLAIMS.put(") != 1:
        fail("Native Spread control may be claimed outside enabled publication")

    hardware_restore_method = compact_code(
        extract_java_method(
            module,
            "private static void scheduleOrdinaryReaderHardwareRestore(",
            "ordinary reader hardware restore",
        )
    )
    restore_claim_guard = hardware_restore_method.find(
        "nativeSpreadControlClaimed(activity)"
    )
    native_gate_off = hardware_restore_method.find(
        'updateNativeEraserGate(activity,"ordinary_reader_restore_"+reason,false)'
    )
    firmware_restore = hardware_restore_method.find(
        'XposedHelpers.callMethod(activity,"sendDisableWriteArea")'
    )
    if not 0 <= restore_claim_guard < native_gate_off < firmware_restore:
        fail("ordinary-reader hardware state is not restored after claim release")
    release_resources = compact_code(
        extract_java_method(
            module,
            "private static void releaseActivityResources(",
            "activity resource release",
        )
    )
    if "NATIVE_SPREAD_CONTROL_CLAIMS.remove(activity);" not in release_resources:
        fail("destroyed activities can retain a Native Spread control claim")

    protected_backup_start = module.find(
        "private static boolean protectedEditableBackupValid("
    )
    protected_backup_end = module.find(
        "private static ProtectedVerification startProtectedEditableVerification(",
        protected_backup_start,
    )
    activation_token_start = module.find(
        "private static boolean validActivationToken("
    )
    activation_token_end = module.find(
        "/** Input-path check:", activation_token_start
    )
    if min(
        protected_backup_start,
        protected_backup_end,
        activation_token_start,
        activation_token_end,
    ) < 0:
        fail("could not isolate companion editable marker attestation")
    require_markers(
        module[protected_backup_start:protected_backup_end],
        (
            "EDITABLE_MARKER_MODE.equals(",
            'markerProperties.getProperty("mode", "")',
            'markerProperties.getProperty(\n                    "transactionProtocol",',
            "!= EDITABLE_MARKER_PROTOCOL",
            'markerProperties.getProperty(\n                    "minimumModuleVersionCode",',
            "minimumModuleVersionCode\n                    < TRANSACTIONAL_MIN_MODULE_VERSION_CODE",
            "minimumModuleVersionCode > MODULE_VERSION_CODE",
            "!validActivationToken(",
        ),
        "companion versioned editable marker attestation",
    )
    committed_candidate_start = module.find(
        "private static boolean committedTransactionalMarkerCandidate("
    )
    committed_candidate_end = module.find(
        "private static boolean transactionalMarkerAuthorityPresent(",
        committed_candidate_start,
    )
    if committed_candidate_start < 0 or committed_candidate_end < 0:
        fail("could not isolate committed transactional marker classification")
    committed_candidate = mask_comments_preserve_literals(
        module[committed_candidate_start:committed_candidate_end]
    )
    require_markers(
        committed_candidate,
        (
            "Long.parseLong(",
            'properties.getProperty("minimumModuleVersionCode", "-1")',
            ">= TRANSACTIONAL_MIN_MODULE_VERSION_CODE",
            "<= MODULE_VERSION_CODE",
        ),
        "companion committed-marker version range",
    )
    if "Long.toString(TRANSACTIONAL_MIN_MODULE_VERSION_CODE).equals(" in (
        committed_candidate
    ):
        fail(
            "committed marker classification requires one historical minimum "
            "exactly instead of accepting the supported version range"
        )

    spread_config_start = module.find(
        "private static SpreadConfig spreadConfig(Activity activity)"
    )
    spread_config_end = module.find(
        "private static void publishSpreadConfigLoadFailure(",
        spread_config_start,
    )
    if spread_config_start < 0 or spread_config_end < 0:
        fail("could not isolate spread config loading")
    spread_config_loader = mask_comments_preserve_literals(
        module[spread_config_start:spread_config_end]
    )
    require_markers(
        spread_config_loader,
        (
            "boolean authorityArtifactsAbsent = markerIdentity.isMissing()",
            "if (TARGET_FILE.equals(path) && authorityArtifactsAbsent)",
            "Properties properties = new Properties();",
        ),
        "calibration/protected-authority routing",
    )
    if re.search(
        r"if\s*\(\s*TARGET_FILE\.equals\(path\)\s*\)",
        spread_config_loader,
    ):
        fail(
            "the reserved calibration path unconditionally bypasses protected "
            "transactional marker validation"
        )
    calibration_absent = spread_config_loader.find(
        "boolean authorityArtifactsAbsent = markerIdentity.isMissing()"
    )
    calibration_branch = spread_config_loader.find(
        "if (TARGET_FILE.equals(path) && authorityArtifactsAbsent)"
    )
    protected_properties = spread_config_loader.find(
        "Properties properties = new Properties();"
    )
    if not 0 <= calibration_absent < calibration_branch < protected_properties:
        fail(
            "calibration authority routing does not fall through to protected "
            "marker validation when authority artifacts exist"
        )
    protected_backup = module[protected_backup_start:protected_backup_end]
    if '.trim()' in protected_backup:
        fail(
            "companion editable authorization normalizes marker fields "
            "instead of requiring the exact protocol-2 representation"
        )
    if "!= MODULE_VERSION_CODE" in protected_backup:
        fail("companion treats a marker version floor as an exact module version")
    require_markers(
        module[activation_token_start:activation_token_end],
        (
            "UUID.fromString(value).toString()",
            "return false;",
        ),
        "canonical editable activation-token validation",
    )

    spread_config_start = module.find("private static SpreadConfig spreadConfig(")
    spread_pair_start = module.find(
        "private static SpreadPair spreadPair(",
        spread_config_start,
    )
    if spread_config_start < 0 or spread_pair_start < 0:
        fail("could not isolate spreadConfig")
    spread_config = module[spread_config_start:spread_pair_start]
    if "protectedEditableBackupValid(document, properties)" in spread_config:
        fail("protected backup verification still hashes the PDF on the activity thread")
    if not all(
        marker in spread_config
        for marker in (
            "startProtectedEditableVerification(",
            "verification.complete",
            "verification.valid",
        )
    ):
        fail("spreadConfig does not fail closed while asynchronous verification is pending")

    verification_start = module.find(
        "private static ProtectedVerification startProtectedEditableVerification("
    )
    sha_start = module.find("private static String sha256(", verification_start)
    if verification_start < 0 or sha_start < 0:
        fail("could not isolate asynchronous protected-backup verification")
    verification = module[verification_start:sha_start]
    verification_valid = verification.find("if (valid &&")
    refresh_spread = verification.find(
        "scheduleConfigurationRefresh(",
        verification_valid,
    )
    if not (0 <= verification_valid < refresh_spread):
        fail("successful protected verification does not refresh handwriting geometry")

    cover_start = app.find("const setCoverSeparateValue = async next =>")
    readonly_start = app.find("const setNativeSpreadReadOnly = async", cover_start)
    if cover_start < 0 or readonly_start < 0:
        fail("could not isolate Cover synchronization")
    cover_sync = app[cover_start:readonly_start]
    cover_guard = cover_sync.find("if (nativeSpreadBusyRef.current) return;")
    configured_unavailable = cover_sync.find(
        "nativeSpreadConfigured && !nativeSpreadCompatible"
    )
    unconfigured_local = cover_sync.find("if (!nativeSpreadConfigured)")
    cover_busy = cover_sync.find("nativeSpreadBusyRef.current = true;")
    cover_configure = cover_sync.find("configureNativeSpreadEditable(")
    cover_release = cover_sync.find(
        "nativeSpreadBusyRef.current = false;",
        cover_configure,
    )
    if not (
        0 <= cover_guard < configured_unavailable < unconfigured_local
        < cover_busy < cover_configure < cover_release
    ):
        fail("Cover synchronization is not blocked during native mode transitions")
    if "nativeSpreadConfiguredEditable" not in cover_sync:
        fail("Cover synchronization does not follow the configured marker mode")
    cover_controls_start = app.find(
        "<Text style={styles.settingLabel}>Treat Cover Page Separately</Text>"
    )
    appearance_controls_start = app.find(
        "<Text style={styles.settingLabel}>Spread page sizing</Text>",
        cover_controls_start,
    )
    cover_controls = app[cover_controls_start:appearance_controls_start]
    cover_controls_compact = compact_code(cover_controls)
    unavailable_guard = (
        "nativeSpreadConfigured&&"
        "(!nativeSpreadCompatible||!nativeSpreadConfiguredEditable)"
    )
    if cover_controls.count("nativeSpreadBusy ||") != 2:
        fail("both Cover controls must be disabled during native mode transitions")
    if cover_controls_compact.count(unavailable_guard) != 2:
        fail(
            "Cover controls remain enabled for unavailable or legacy "
            "configured authority"
        )

    native_controls_start = app.find(
        "<Text style={styles.settingLabel}>Supernote native reader</Text>",
        appearance_controls_start,
    )
    appearance_controls = app[appearance_controls_start:native_controls_start]
    appearance_controls_compact = compact_code(appearance_controls)
    if appearance_controls.count("nativeSpreadBusy ||") != 6:
        fail("all native spread appearance controls must be transition-safe")
    if appearance_controls_compact.count(unavailable_guard) != 6:
        fail(
            "native spread appearance controls ignore unavailable hooks or "
            "legacy read-only authority"
        )
    for required in (
        "showSpreadDivider",
        "showNativeSpreadHeader",
        "spreadSizing",
        "setNativeSpreadAppearanceValue",
        "native_fill",
    ):
        if required not in appearance_controls:
            fail(f"native spread appearance controls missing {required}")

    readonly_transition_start = app.find("const setNativeSpreadReadOnly = async")
    editable_transition_start = app.find(
        "const setNativeSpreadEditableMode = async",
        readonly_transition_start,
    )
    readonly_transition = app[readonly_transition_start:editable_transition_start]
    readonly_success = readonly_transition.find(
        "await ReaderPreferencesModule.configureNativeSpreadReadOnly("
    )
    clear_backup = readonly_transition.find(
        "setNativeBackupAvailable(false);",
        readonly_success,
    )
    clear_original = readonly_transition.find(
        "setNativeBackupOriginalMarkPresent(false);",
        readonly_success,
    )
    clear_status = readonly_transition.find(
        "setNativeBackupStatus('missing');",
        readonly_success,
    )
    if not (
        0 <= readonly_success < clear_backup
        and 0 <= readonly_success < clear_original
        and 0 <= readonly_success < clear_status
    ):
        fail("leaving editable mode can leave retired backup state in the UI")

    direction_start = app.find("const setDirectionValue = async next =>")
    view_mode_start = app.find("const setViewModeValue = next =>", direction_start)
    if direction_start < 0 or view_mode_start < 0:
        fail("could not isolate asynchronous reading-direction transition")
    direction_transition = app[direction_start:view_mode_start]
    await_shutdown = direction_transition.find(
        "const disabled = await setNativeSpreadReadOnly(false);"
    )
    shutdown_guard = direction_transition.find("if (!disabled)", await_shutdown)
    commit_ref = direction_transition.find("directionRef.current = next;")
    commit_state = direction_transition.find("setDirection(next);", commit_ref)
    if not (
        0 <= await_shutdown < shutdown_guard < commit_ref < commit_state
    ):
        fail("LTR can commit before protected native mode shuts down successfully")
    if "return true;" not in readonly_transition or "return false;" not in readonly_transition:
        fail("native read-only transition does not report success to direction changes")

    handle_start = module.find("public void handleLoadPackage(")
    first_helper = module.find(
        "private static synchronized void registerHandshakeReceiver(",
        handle_start,
    )
    if handle_start < 0 or first_helper < 0:
        fail("could not isolate handleLoadPackage")
    handle = module[handle_start:first_helper]
    hooks_ready = handle.rfind("hooksReady = true;")
    last_hook = handle.rfind("XposedHelpers.findAndHookMethod(")
    if hooks_ready < 0 or last_hook < 0 or hooks_ready < last_hook:
        fail("hooksReady must be set only after all hook registrations succeed")

    destroy_match = re.search(
        r'"onDestroy".*?new XC_MethodHook\(\) \{(.*?)\n\s*\}\n\s*\);',
        module,
        flags=re.DOTALL,
    )
    if not destroy_match:
        fail("could not isolate DocumentActivity onDestroy hook")
    destroy = destroy_match.group(1)
    if "protected void afterHookedMethod" not in destroy:
        fail("destroyed activity resources must be released after onDestroy")
    if "releaseActivityResources(activity);" not in destroy:
        fail("onDestroy does not release all per-activity resources")

    require_markers(
        module,
        (
            '"com.supernote.document.document.DocumentActivity$6"',
            '"onDigitalPosition"',
            "handlePenPageActivation(",
            "interceptPenPageActivation(",
            "private static final class PageActivationTransaction",
            "private static final class PenContactIdentityCapture",
            "private static final class PenContactOwnership",
            "private static final class ReceiveTrialsScope",
            "PAGE_ACTIVATION_TRANSACTIONS",
            "PAGE_ACTIVATION_SOURCE_SAVE_SCOPES",
            "PEN_CONTACT_OWNERSHIPS",
            "DOCUMENT_RECEIVE_TOMBSTONES",
            "publishPenContactOwnershipLocked(",
            "receiveTrialsOwnershipFailure(",
            'return "document_context_receive_quarantine";',
            "beginPageActivationTransaction(",
            "finishPageActivationTransaction(",
            "abortPageActivationTransaction(",
            '"page_activation_source_save_allowed"',
            '"source_save_not_completed"',
        ),
        "transactional inactive-page activation and receive quarantine",
    )
    require_markers(
        module,
        (
            "DOCUMENT_CONTEXTS_PRESENTED",
            "final boolean receiveQuarantineRequired;",
            "fence.receiveQuarantineRequired",
            "DOCUMENT_CONTEXTS_PRESENTED.put(activity, Boolean.TRUE)",
            "DOCUMENT_CONTEXTS_PRESENTED.remove(activity)",
        ),
        "fresh-process versus sequential-document receive quarantine",
    )
    weak_map_declarations = tuple(
        re.finditer(r"new\s+WeakHashMap\s*<\s*>\s*\(\s*\)", module)
    )
    if len(weak_map_declarations) != 25:
        fail(
            "per-activity weak-map inventory changed without an explicit "
            f"concurrency review: found {len(weak_map_declarations)}"
        )
    for declaration in weak_map_declarations:
        prefix = module[max(0, declaration.start() - 60):declaration.start()]
        if not re.search(r"Collections\s*\.\s*synchronizedMap\s*\(\s*$", prefix):
            fail("a shared per-activity WeakHashMap is not synchronized")

    invalidate_identity_start = module.find(
        "private static DocumentIdentityAdmission invalidateDocumentIdentityAdmission("
    )
    finish_identity_start = module.find(
        "private static void finishDocumentIdentityAdmission(",
        invalidate_identity_start,
    )
    note_identity_start = module.find(
        "private static boolean noteDocumentIdentityPresentation(",
        finish_identity_start,
    )
    prove_identity_start = module.find(
        "private static boolean proveDocumentIdentityPresentation(",
        note_identity_start,
    )
    receive_identity_start = module.find(
        "private static void publishDocumentReceiveIdentity(",
        prove_identity_start,
    )
    if min(
        invalidate_identity_start,
        finish_identity_start,
        note_identity_start,
        prove_identity_start,
        receive_identity_start,
    ) < 0:
        fail("could not isolate document receive-quarantine lifecycle")
    invalidate_identity = compact_code(
        module[invalidate_identity_start:finish_identity_start]
    )
    note_identity = compact_code(
        module[note_identity_start:prove_identity_start]
    )
    prove_identity = compact_code(
        module[prove_identity_start:receive_identity_start]
    )
    prior_context = invalidate_identity.find(
        "booleanpriorDocumentContext=Boolean.TRUE.equals("
        "DOCUMENT_CONTEXTS_PRESENTED.get(activity));"
    )
    fence_publish = invalidate_identity.find(
        "newDocumentIdentityFence(activity,documentContextGeneration,"
        "priorDocumentContext)",
        prior_context,
    )
    quarantine_guard = invalidate_identity.find(
        "if(fence.receiveQuarantineRequired)", fence_publish
    )
    quarantine_publish = invalidate_identity.find(
        "DOCUMENT_RECEIVE_TOMBSTONES.put(", quarantine_guard
    )
    fresh_branch = invalidate_identity.find("else{", quarantine_publish)
    fresh_remove = invalidate_identity.find(
        "DOCUMENT_RECEIVE_TOMBSTONES.remove(activity);", fresh_branch
    )
    if not (
        0 <= prior_context < fence_publish < quarantine_guard
        < quarantine_publish < fresh_branch < fresh_remove
    ):
        fail(
            "document receive quarantine is not conditional on an exactly "
            "proved prior document context"
        )
    if "DOCUMENT_CONTEXT_GENERATIONS.get(activity)" in invalidate_identity[
        max(0, prior_context - 100):fence_publish
    ]:
        fail("mere startup generation state can falsely enable receive quarantine")
    fence_absent = note_identity.find("if(fence==null)")
    fence_absent_return = note_identity.find("returntrue;", fence_absent)
    if not 0 <= fence_absent < fence_absent_return:
        fail("could not isolate provisional no-fence presentation")
    if "DOCUMENT_CONTEXTS_PRESENTED.put" in note_identity[
        fence_absent:fence_absent_return
    ]:
        fail("provisional startup presentation can be mistaken for a prior document")
    exact_fence_remove = prove_identity.find(
        "if(!DOCUMENT_IDENTITY_ADMISSIONS.remove(activity,fence))"
    )
    exact_presentation_publish = prove_identity.find(
        "DOCUMENT_CONTEXTS_PRESENTED.put(activity,Boolean.TRUE);",
        exact_fence_remove,
    )
    editable_guard = prove_identity.find(
        "PEN_INPUT_EDITABLE_GUARDS.put(activity,Boolean.TRUE);",
        exact_presentation_publish,
    )
    if not 0 <= exact_fence_remove < exact_presentation_publish < editable_guard:
        fail(
            "prior-document state is not published only after exact reset-fence "
            "identity proof"
        )
    forbidden_legacy_activation_markers = (
        "PEN_ACTIVATION_TARGETS",
        "PEN_ACTIVATION_MARK_PRIMING",
        "capturePendingPenActivationTrails(",
        "normalizePendingPenTrail(",
        "persistPendingPenActivationTrails(",
        "PEN_ACTIVATION_STALE_SAVE_PENDING",
        "PEN_ACTIVATION_STALE_SAVE_SCOPE",
        "PENDING_PAGE_EDIT_HISTORY",
        "PAGE_EDIT_HISTORY_ACTIONS",
        "PEN_ACTIVATION_ERASERS",
        "eraserIntersectsTrail(",
        "normalizedTrailMatchPoints(",
        "matchingTrailInkAttributes(",
        "matchingTrailValue(",
        "hasPendingPenActivationEdits(",
        "activateDocumentPageFromPen(",
        "completePendingPenPageActivation(",
        "cancelPendingPenPageActivation(",
        "matchingTrailPoints(",
        "private static final class PageEditHistory",
        "registerPendingPageEditHistory(",
        "applyPageEditHistory(",
        "pen_activation_native_save_bypassed",
    )
    leaked_legacy_activation_markers = [
        marker
        for marker in forbidden_legacy_activation_markers
        if marker in module
    ]
    if leaked_legacy_activation_markers:
        fail(
            "removed inactive-page capture/merge/history architecture is still "
            f"reachable: {leaked_legacy_activation_markers}"
        )

    activity_create_start = module.find(
        'XposedHelpers.findAndHookMethod(\n            TARGET_ACTIVITY,\n'
        '            loadPackageParam.classLoader,\n            "onCreate"'
    )
    activity_create_end = module.find(
        'XposedHelpers.findAndHookMethod(\n            TARGET_ACTIVITY,\n'
        '            loadPackageParam.classLoader,\n            "onConfigurationChanged"',
        activity_create_start,
    )
    if activity_create_start < 0 or activity_create_end < 0:
        fail("could not isolate DocumentActivity startup hook")
    activity_create = module[activity_create_start:activity_create_end]
    startup_guard = activity_create.find(
        "PEN_INPUT_EDITABLE_GUARDS.put("
    )
    startup_publish = activity_create.find(
        "activeActivity = createdActivity;", startup_guard
    )
    startup_config = activity_create.find(
        "SpreadConfig createdConfig = spreadConfig(", startup_publish
    )
    startup_claim = activity_create.find(
        "nativeSpreadControlClaimed(createdActivity)", startup_config
    )
    startup_gate = activity_create.find(
        'updateNativeEraserGate(\n'
        '                                createdActivity,\n'
        '                                "activity_created"',
        startup_claim,
    )
    if not (
        0 <= startup_guard < startup_publish < startup_config
        < startup_claim < startup_gate
    ):
        fail(
            "DocumentActivity startup exposes pen callbacks before publishing "
            "a fail-closed editable guard or arms hardware without a claim"
        )
    if "PEN_INPUT_EDITABLE_GUARDS.remove(createdActivity)" in activity_create:
        fail("DocumentActivity startup clears its pen guard before config authority")

    transaction_markers = (
        "private static final class PageActivationTransaction",
        "PAGE_ACTIVATION_TRANSACTIONS",
        "PAGE_ACTIVATION_BLOCKED_TOUCHES",
        "PAGE_ACTIVATION_HISTORY_BLOCKED",
        "PEN_CONTACT_START_PAGES",
        "PEN_ACTIVE_STROKE_SOURCE_PAGES",
        "PEN_CONTACT_GENERATIONS",
        "PEN_CONTACT_RECEIVE_FALLBACK_GENERATIONS",
        "PEN_RECEIVE_EXPIRED_GENERATIONS",
        "PAGE_ACTIVATION_OWNERSHIP_LOCK",
        "PAGE_ACTIVATION_SOURCE_SAVE_SCOPES",
        "private static final class PageActivationSourceSaveToken",
        "pushPageActivationSourceSaveToken(",
        "popPageActivationSourceSaveToken(",
        "PAGE_SAVE_IN_FLIGHT_COUNTS",
        "PAGE_SAVE_ADMISSIONS",
        "new ConcurrentHashMap<>()",
        "volatile boolean triggerContactObserved",
        "volatile boolean triggerPenLifted",
        "volatile long triggerContactGeneration",
        "volatile long pendingPenLiftGeneration",
        "volatile boolean geometryCommitted",
        "volatile boolean rollbackPending",
        "PAGE_ACTIVATION_COUNTER.incrementAndGet()",
        "interceptPenPageActivation(",
        "beginPageActivationTransaction(",
        "requestPageActivationLoad(",
        "schedulePageActivationTimeout(",
        "commitPageActivationGeometry(",
        "markPageActivationPenLifted(",
        "notePageActivationTriggerContactLocked(",
        "capturePageActivationPenLiftGeneration(",
        "restoreTransactionalActivePageGeometry(",
        "finishPageActivationTransaction(",
        "finishPageActivationRollback(",
        "finishPageActivationRollbackIfConverged(",
        "abortPageActivationTransaction(",
        "failClosedPageActivation(",
        '"page_activation_transaction_started"',
        '"page_activation_transaction_committed"',
        '"page_activation_transaction_aborted"',
        '"trigger_gesture_discarded".equals(reason)',
        '"page_activation_status_refresh_failed id="',
        '"SN_SPREAD_PROBE discard activation gesture"',
        "LOW_LATENCY_LOG_EXECUTOR",
        "PEN_INPUT_BLOCK_LOG_STATES",
        "PAGE_ACTIVATION_UI_BLOCK_LOG_STATES",
        "queueLowLatencyLog(",
        "notePenInputBlock(",
        "finishPenInputBlock(",
        '"activation_trigger"',
        '"transaction"',
        '"nonwritable_contact"',
        '"active_stroke_cross_page"',
        '"native_chrome_contact_classified generation="',
        '"page_activation_active_stroke_terminal_preserved"',
        '"page_activation_ignored_cross_page_stroke current="',
        '"page_activation_rejected reason=pen_contact_active"',
        '"page_activation_source_save_allowed"',
        '"page_activation_ui_input_blocked phase=start state="',
        '"page_activation_history_blocked id="',
        "admitPageSave(",
        "finishPageSaveAdmission()",
        '"RTL SPREAD: page switch failed - writing disabled"',
    )
    require_markers(
        module,
        transaction_markers,
        "transactional single-active-page ownership",
    )
    require_markers(
        module,
        (
            "PAGE_LOAD_GENERATION_COUNTER",
            "PAGE_LOAD_GENERATIONS",
            "PAGE_ACTIVATION_LOAD_SCOPE",
            "final SpreadConfig documentConfig;",
            "volatile long loadGeneration = -1L;",
            "isCachedSpreadConfigCurrent(",
            "isPageActivationLoadIdentityCurrent(",
        ),
        "exact document/load-generation activation identity",
    )

    load_hook_start = module.find(
        '"com.supernote.document.document.DocumentViewModel",\n'
        '            loadPackageParam.classLoader,\n'
        '            "loadPage",'
    )
    turn_hook_start = module.find(
        '"com.supernote.document.document.DocumentViewModel",\n'
        '            loadPackageParam.classLoader,\n'
        '            "turnPage",',
        load_hook_start,
    )
    if load_hook_start < 0 or turn_hook_start < 0:
        fail("could not isolate document load-generation hook")
    load_hook = module[load_hook_start:turn_hook_start]
    load_owner_resolution = load_hook.find(
        "activeActivityForDocumentViewModel("
    )
    load_owner_reject = load_hook.find(
        "if (activity == null)", load_owner_resolution
    )
    scoped_load_lock = load_hook.find(
        "synchronized (PAGE_ACTIVATION_OWNERSHIP_LOCK)", load_owner_reject
    )
    scoped_load_identity = load_hook.find(
        "if (PAGE_ACTIVATION_TRANSACTIONS.get(activity)", scoped_load_lock
    )
    scoped_load_reject = load_hook.find(
        "param.setResult(null);", scoped_load_identity
    )
    load_generation_increment = load_hook.find(
        "PAGE_LOAD_GENERATION_COUNTER.incrementAndGet()",
        scoped_load_reject,
    )
    load_generation_publish = load_hook.find(
        "PAGE_LOAD_GENERATIONS.put(activity, loadGeneration)",
        load_generation_increment,
    )
    scoped_load_capture = load_hook.find(
        "scoped.loadGeneration = loadGeneration", load_generation_publish
    )
    snapshot_invalidate = load_hook.find(
        "PEN_INPUT_SNAPSHOTS.remove(activity);", scoped_load_capture
    )
    editable_guard = load_hook.find(
        "PEN_INPUT_EDITABLE_GUARDS.put(", snapshot_invalidate
    )
    native_gate_close = load_hook.find(
        "disableNativeGateForOwnershipHandoffLocked(", editable_guard
    )
    if not (
        0 <= load_owner_resolution < load_owner_reject < scoped_load_lock
        < scoped_load_identity < scoped_load_reject < load_generation_increment
        < load_generation_publish
        < scoped_load_capture < snapshot_invalidate < editable_guard
        < native_gate_close
    ):
        fail(
            "loadPage is not bound to the exact active DocumentViewModel or "
            "does not reject a stale scoped load before publishing its exact "
            "generation and atomically withdrawing prior writer authority"
        )

    check_link_hook_start = module.find('"checkLink",', turn_hook_start)
    if check_link_hook_start < 0:
        fail("could not isolate fail-closed page-turn hook")
    turn_hook = module[turn_hook_start:check_link_hook_start]
    turn_owner_resolution = turn_hook.find(
        "activeActivityForDocumentViewModel("
    )
    turn_owner_reject = turn_hook.find(
        "if (activity == null)", turn_owner_resolution
    )
    turn_navigation_guard = turn_hook.find(
        "shouldSuppressFailClosedNavigation(activity)", turn_owner_reject
    )
    if not (
        0 <= turn_owner_resolution < turn_owner_reject
        < turn_navigation_guard
    ):
        fail(
            "turnPage can route a stale DocumentViewModel through the active "
            "activity's navigation state"
        )
    require_markers(
        turn_hook,
        (
            "shouldSuppressFailClosedNavigation(activity)",
            'rtl_turn_suppressed reason=config_unavailable',
            "param.setResult(null)",
            "SpreadConfig navigationConfig = spreadConfig(activity)",
            "navigationConfig == null",
            'rtl_turn_suppressed reason=config_failed_during_turn',
            "isCachedSpreadConfigCurrent(",
            'rtl_turn_suppressed reason=config_not_current',
            "handleRtlSpreadTurn(",
            "navigationConfig",
        ),
        "watcher-failure fail-closed navigation suppression",
    )
    first_navigation_guard = turn_hook.find(
        "if (shouldSuppressFailClosedNavigation(activity))"
    )
    first_turn_suppression = turn_hook.find(
        "param.setResult(null);", first_navigation_guard
    )
    config_lookup = turn_hook.find(
        "SpreadConfig navigationConfig = spreadConfig(activity)",
        first_turn_suppression,
    )
    second_navigation_guard = turn_hook.find(
        "if (shouldSuppressFailClosedNavigation(activity))", config_lookup
    )
    second_turn_suppression = turn_hook.find(
        "param.setResult(null);", second_navigation_guard
    )
    current_config_check = turn_hook.find(
        "if (!isCachedSpreadConfigCurrent(", second_turn_suppression
    )
    stale_config_suppression = turn_hook.find(
        "param.setResult(null);", current_config_check
    )
    handler_call = turn_hook.find(
        "handleRtlSpreadTurn(", stale_config_suppression
    )
    if not (
        0 <= first_navigation_guard < first_turn_suppression < config_lookup
        < second_navigation_guard < second_turn_suppression
        < current_config_check < stale_config_suppression < handler_call
    ):
        fail(
            "turnPage can leak native LTR navigation before or during a "
            "failed persisted-config lookup"
        )
    rtl_turn_handler_start = module.find(
        "private static boolean handleRtlSpreadTurn("
    )
    rtl_turn_handler_end = module.find(
        "private static void activateDocumentPage(", rtl_turn_handler_start
    )
    if rtl_turn_handler_start < 0 or rtl_turn_handler_end < 0:
        fail("could not isolate fail-closed RTL spread-turn handler")
    rtl_turn_handler = module[rtl_turn_handler_start:rtl_turn_handler_end]
    require_markers(
        rtl_turn_handler,
        (
            "SpreadConfig config",
            "shouldSuppressFailClosedNavigation(activity)",
            "!isCachedSpreadConfigCurrent(activity, config)",
            'rtl_spread_turn_rejected reason=config_unavailable',
            'rtl_spread_turn_rejected reason=invalid_pair',
            'rtl_spread_turn_failed offset=',
        ),
        "single-snapshot fail-closed RTL spread turn",
    )
    if "spreadConfig(activity)" in rtl_turn_handler:
        fail("RTL turn handler reparses config after navigation admission")
    failed_turn = rtl_turn_handler.find('log("rtl_spread_turn_failed offset="')
    failed_turn_consume = rtl_turn_handler.find("return true;", failed_turn)
    if not 0 <= failed_turn < failed_turn_consume:
        fail("managed RTL turn failure falls through to native LTR navigation")

    digital_position_start = module.find(
        '"com.supernote.document.document.DocumentActivity$6"'
    )
    dispatch_touch_start = module.find('"dispatchTouchEvent",')
    if dispatch_touch_start < 0 or digital_position_start < 0:
        fail("could not isolate transactional UI-input guard")
    dispatch_touch_hook = module[dispatch_touch_start:digital_position_start]
    dispatch_finger_stream = dispatch_touch_hook.find(
        "trackFingerTouchStream(activity, event);"
    )
    dispatch_trace = dispatch_touch_hook.find(
        "traceTouchEvent(activity, event);", dispatch_finger_stream
    )
    dispatch_config = dispatch_touch_hook.find(
        "SpreadConfig config = SPREAD_CONFIGS.get(activity);", dispatch_trace
    )
    dispatch_editable_spread = dispatch_touch_hook.find(
        "isCachedEditableSpreadLandscape(activity, config)", dispatch_config
    )
    dispatch_contact_latch = dispatch_touch_hook.find(
        "latchPenContactFromActivityTouch(", dispatch_editable_spread
    )
    dispatch_block = dispatch_touch_hook.find(
        "blockPageActivationUiInput(activity, event)", dispatch_contact_latch
    )
    dispatch_consume = dispatch_touch_hook.find(
        "param.setResult(true);", dispatch_block
    )
    dispatch_return = dispatch_touch_hook.find("return;", dispatch_consume)
    dispatch_after = dispatch_touch_hook.find(
        "protected void afterHookedMethod", dispatch_return
    )
    dispatch_finger_finish = dispatch_touch_hook.find(
        "finishFingerTouchStream(", dispatch_after
    )
    dispatch_contact_terminal = dispatch_touch_hook.find(
        "schedulePenContactFallbackFromActivityTouch(",
        dispatch_finger_finish,
    )
    if not (
        0 <= dispatch_finger_stream < dispatch_trace < dispatch_config
        < dispatch_editable_spread < dispatch_contact_latch
        < dispatch_block < dispatch_consume < dispatch_return < dispatch_after
        < dispatch_finger_finish < dispatch_contact_terminal
    ):
        fail(
            "touch input is not consumed before native chrome and page "
            "controls can run during an ownership transfer"
        )
    require_markers(
        dispatch_touch_hook,
        (
            "isCachedSpreadLandscape(activity, config)",
            "cachedSpreadLandscape",
            "trackFingerTouchStream(activity, event)",
            "latchPenContactFromActivityTouch(",
            "finishFingerTouchStream(",
            "schedulePenContactFallbackFromActivityTouch(",
            "trackFingerTapNavigation(",
            "handlePageActivationTouch(",
        ),
        "memory-only touch dispatch routing",
    )
    dispatch_blocking_hits = [
        marker
        for marker in (
            "spreadConfig(",
            "FileIdentity.capture(",
            "new File(",
            "Os.stat(",
            "FileInputStream",
            "Properties",
        )
        if marker in dispatch_touch_hook
    ]
    if dispatch_blocking_hits:
        fail(
            "touch dispatch performs filesystem/config refresh work: "
            f"{dispatch_blocking_hits}"
        )
    digital_state_start = module.find(
        '"onDigital",', digital_position_start
    )
    if digital_position_start < 0 or digital_state_start < 0:
        fail("could not isolate native pen-position interception hook")
    digital_position_hook = module[digital_position_start:digital_state_start]
    before_native_callback = digital_position_hook.find(
        "protected void beforeHookedMethod"
    )
    callback_owner_resolution = digital_position_hook.find(
        "activityForNativeEventCallback(", before_native_callback
    )
    callback_owner_reject = digital_position_hook.find(
        "if (activity == null)", callback_owner_resolution
    )
    pressure_capture = digital_position_hook.find(
        'XposedHelpers.getIntField(', callback_owner_reject
    )
    native_chrome_route = digital_position_hook.find(
        "routeNativeChromeNativePen(", pressure_capture
    )
    native_chrome_pass = digital_position_hook.find(
        "nativeChromeRoute == NATIVE_CHROME_ROUTE_PASS", native_chrome_route
    )
    native_chrome_pass_return = digital_position_hook.find(
        "return;", native_chrome_pass
    )
    native_chrome_block = digital_position_hook.find(
        "nativeChromeRoute == NATIVE_CHROME_ROUTE_BLOCK",
        native_chrome_pass_return,
    )
    native_chrome_block_result = digital_position_hook.find(
        "param.setResult(null);", native_chrome_block
    )
    native_chrome_block_return = digital_position_hook.find(
        "return;", native_chrome_block_result
    )
    text_selection_route = digital_position_hook.find(
        "routeTextSelectionNativePen(", native_chrome_block_return
    )
    text_selection_pass = digital_position_hook.find(
        "textSelectionRoute == NATIVE_CHROME_ROUTE_PASS",
        text_selection_route,
    )
    text_selection_pass_return = digital_position_hook.find(
        "return;", text_selection_pass
    )
    text_selection_block = digital_position_hook.find(
        "textSelectionRoute == NATIVE_CHROME_ROUTE_BLOCK",
        text_selection_pass_return,
    )
    text_selection_block_result = digital_position_hook.find(
        "param.setResult(null);", text_selection_block
    )
    text_selection_block_return = digital_position_hook.find(
        "return;", text_selection_block_result
    )
    pen_snapshot_lookup = digital_position_hook.find(
        "PenInputSnapshot inputSnapshot =", text_selection_block_return
    )
    pen_snapshot_read = digital_position_hook.find(
        "penInputSnapshot(activity)",
        pen_snapshot_lookup,
    )
    contact_identity_capture = digital_position_hook.find(
        "PenContactIdentityCapture contactIdentity =", pen_snapshot_read
    )
    positive_contact_branch = digital_position_hook.find(
        "if (pressure > 0) {", contact_identity_capture
    )
    contact_ownership_lock = digital_position_hook.find(
        "synchronized (PAGE_ACTIVATION_OWNERSHIP_LOCK)",
        positive_contact_branch,
    )
    prior_contact_phase_guard = digital_position_hook.find(
        "existingOwnership.phase", contact_ownership_lock
    )
    contact_snapshot_identity = digital_position_hook.find(
        "PEN_INPUT_SNAPSHOTS.get(activity)", prior_contact_phase_guard
    )
    contact_config_identity = digital_position_hook.find(
        "SPREAD_CONFIGS.get(activity)", contact_snapshot_identity
    )
    editable_guard_reject = digital_position_hook.find(
        "PEN_INPUT_EDITABLE_GUARDS.get(activity)", contact_config_identity
    )
    contact_transaction_lookup = digital_position_hook.find(
        "PageActivationTransaction ownershipTransaction =",
        editable_guard_reject,
    )
    atomic_contact_generation = digital_position_hook.find(
        "notePageActivationTriggerContactLocked(",
        contact_transaction_lookup,
    )
    contact_geometry_ready = digital_position_hook.find(
        "inputSnapshot.geometryReady", atomic_contact_generation
    )
    contact_page_mapping = digital_position_hook.find(
        "int mappedContactPage = pageAt(", contact_geometry_ready
    )
    contact_page_valid = digital_position_hook.find(
        "if (mappedContactPage >= 0)", contact_page_mapping
    )
    unmapped_contact_reason = digital_position_hook.find(
        'guardReason = "blocked_unmapped"', contact_page_valid
    )
    contact_ownership_publish = digital_position_hook.find(
        "publishPenContactOwnershipLocked(", unmapped_contact_reason
    )
    quarantine_retire = digital_position_hook.find(
        "retireDocumentReceiveQuarantineAfterFreshContactLocked(",
        contact_ownership_publish,
    )
    pending_snapshot_guard = digital_position_hook.find(
        "publishedEditablePenInput(", quarantine_retire
    )
    pending_contact_publish = digital_position_hook.find(
        "publishPenContactOwnershipLocked(",
        pending_snapshot_guard,
    )
    if not (
        0 <= before_native_callback < callback_owner_resolution
        < callback_owner_reject < pressure_capture < native_chrome_route
        < native_chrome_pass < native_chrome_pass_return
        < native_chrome_block < native_chrome_block_result
        < native_chrome_block_return < text_selection_route
        < text_selection_pass < text_selection_pass_return
        < text_selection_block < text_selection_block_result
        < text_selection_block_return < pen_snapshot_lookup
        < pen_snapshot_read < contact_identity_capture
        < positive_contact_branch < contact_ownership_lock
        < prior_contact_phase_guard
        < contact_snapshot_identity < contact_config_identity
        < editable_guard_reject < contact_transaction_lookup
        < atomic_contact_generation
        < contact_geometry_ready
        < contact_page_mapping < contact_page_valid
        < unmapped_contact_reason < contact_ownership_publish
        < quarantine_retire
        < pending_snapshot_guard
        < pending_contact_publish
    ):
        fail(
            "contact start is not atomically latched against transaction "
            "commit, exact writer identity, native-chrome/text-selection "
            "pass-through, "
            "quarantine, or an "
            "unmapped held gesture before page ownership"
        )
    if (
        "isNativeChromeTouch(" in digital_position_hook
        or "blocked_native_chrome" in digital_position_hook
    ):
        fail(
            "native chrome is still converted into handwriting ownership "
            "inside the low-latency contact publisher"
        )
    if "Integer.valueOf(pageAt(" in digital_position_hook:
        fail("the pen-contact guard can still permanently latch page -1")
    contact_publish_start = module.find(
        "private static boolean publishPenContactOwnershipLocked("
    )
    contact_publish_end = module.find(
        "private static void retireDocumentReceiveQuarantineAfterFreshContactLocked(",
        contact_publish_start,
    )
    if contact_publish_start < 0 or contact_publish_end < 0:
        fail("could not isolate immutable contact-ownership publication")
    require_markers(
        module[contact_publish_start:contact_publish_end],
        (
            "PEN_ACTIVE_STROKE_SOURCE_PAGES.put(",
            "identity.readerPage != sourcePage",
            "identity.presenterMarkPage != sourcePage + 1",
            "PEN_ACTIVE_STROKE_SOURCE_PAGES.remove(",
            "PEN_CONTACT_OWNERSHIPS.put(activity, candidate)",
        ),
        "independent admitted-stroke source identity",
    )
    if (
        "Map<Activity, Integer> PEN_ACTIVE_STROKE_SOURCE_PAGES =\n"
        "        new ConcurrentHashMap<>()"
    ) not in module:
        fail("admitted active-stroke identity is not thread-safe")
    active_stroke_terminal = digital_position_hook.find(
        "boolean completingActivePageStroke =",
        before_native_callback,
    )
    active_stroke_terminal_helper = digital_position_hook.find(
        "isCompletingActivePageStroke(",
        active_stroke_terminal,
    )
    intercept_input = digital_position_hook.find(
        "interceptPenPageActivation(", active_stroke_terminal_helper
    )
    discard_input = digital_position_hook.find(
        "param.setResult(null);", intercept_input
    )
    preserve_terminal = digital_position_hook.find(
        "if (completingActivePageStroke)", discard_input
    )
    schedule_activation = digital_position_hook.find(
        "handlePenPageActivation(", preserve_terminal
    )
    if not (
        0 <= before_native_callback < active_stroke_terminal
        < active_stroke_terminal_helper < intercept_input
        < discard_input < preserve_terminal
        < schedule_activation
    ):
        fail(
            "inactive-page pen input must be discarded before Supernote's "
            "native callback runs, then schedule the ownership transaction"
        )
    blocking_markers = (
        "spreadConfig(",
        "FileIdentity",
        "FileInputStream",
        "Os.stat",
        "new File(",
        "Properties",
        "getWindow()",
        "getDecorView()",
        "isNativeChromeTouch(activity",
    )
    blocking_hits = [
        marker for marker in blocking_markers
        if marker in digital_position_hook
    ]
    if blocking_hits:
        fail(
            "native pen-position callback performs blocking config/filesystem "
            f"work instead of using its immutable snapshot: {blocking_hits}"
        )
    synchronous_diagnostic_hits = [
        marker for marker in (
            "log(",
            "traceEvent(",
            "JSONObject",
            "XposedBridge.log(",
            "Log.i(",
        )
        if marker in digital_position_hook
    ]
    if synchronous_diagnostic_hits:
        fail(
            "native pen-position callback performs synchronous logging/JSON "
            f"work: {synchronous_diagnostic_hits}"
        )
    require_markers(
        digital_position_hook,
        (
            "queueLowLatencyLog(",
            "tracePenPosition(",
        ),
        "queued native pen-position diagnostics",
    )
    trace_pen_start = module.find("private static void tracePenPosition(")
    trace_pen_end = module.find(
        "private static void tracePenLeftScreen(", trace_pen_start
    )
    if trace_pen_start < 0 or trace_pen_end < 0:
        fail("could not isolate native pen trace enqueueing")
    trace_pen = module[trace_pen_start:trace_pen_end]
    require_markers(
        trace_pen,
        (
            "synchronized (PAGE_ACTIVATION_OWNERSHIP_LOCK)",
            "expected.penInputAdmissionClosed",
            "expected.penInputMutationGeneration.incrementAndGet()",
            "traceEvent(",
            "expected,",
            "capturedResolvedPage",
            "capturedTransactionId",
        ),
        "immutable native pen trace capture",
    )
    forbidden_pen_trace_work = tuple(
        marker for marker in (
            "JSONObject",
            "entry.toString()",
            "synchronized (TRACE_LOCK)",
            "appendTraceRecord(",
        )
        if marker in trace_pen
    )
    if forbidden_pen_trace_work:
        fail(
            "native pen trace performs serialization or I/O before the event "
            f"worker enqueue: {forbidden_pen_trace_work}"
        )
    if "TraceEventContext.capture(" in trace_pen:
        fail("native pen trace captures UI context on the low-latency callback")
    trace_pen_left_start = trace_pen_end
    trace_pen_left_end = module.find(
        "private static void finishTraceSuppressedPenContact(",
        trace_pen_left_start,
    )
    if trace_pen_left_end < 0:
        fail("could not isolate pen-left-screen trace admission")
    require_markers(
        module[trace_pen_left_start:trace_pen_left_end],
        (
            "synchronized (PAGE_ACTIVATION_OWNERSHIP_LOCK)",
            "expected.penInputAdmissionClosed",
            "expected.penInputMutationGeneration.incrementAndGet()",
        ),
        "atomic trace pen-left-screen admission",
    )
    suppressed_terminal_guard = digital_position_hook.find(
        "if (pressure == 0 && suppressedPenCallback)", schedule_activation
    )
    suppressed_trace_finish = digital_position_hook.find(
        "finishTraceSuppressedPenContact(activity)", suppressed_terminal_guard
    )
    if not (
        0 <= schedule_activation < suppressed_terminal_guard
        < suppressed_trace_finish
    ):
        fail(
            "a pressure-zero suppressed contact does not finish trace state "
            "after activation handling"
        )
    if "clearPenContactStartPage(" in digital_position_hook:
        fail(
            "the pen-position callback clears source/contact ownership before "
            "receiveTrials can validate and persist the native trail"
        )
    trace_suppressed_start = module.find(
        "private static void finishTraceSuppressedPenContact("
    )
    trace_suppressed_end = module.find(
        "private static void traceAnnotationBoundary(", trace_suppressed_start
    )
    if trace_suppressed_start < 0 or trace_suppressed_end < 0:
        fail("could not isolate suppressed-contact trace cleanup")
    require_markers(
        module[trace_suppressed_start:trace_suppressed_end],
        (
            "TRACE_TRANSACTION_IDS.remove(activity)",
            '"suppressed_pen_contact_finished"',
            '"transactionId"',
            "transactionId",
        ),
        "fully suppressed pen-contact trace completion",
    )
    if "protected void afterHookedMethod" in digital_position_hook:
        fail(
            "the pen-position hook has a terminal after-hook that can release "
            "source ownership before receiveTrials"
        )

    digital_state_end = module.find(
        '"com.supernote.document.handwrite.HandWriteClient",\n'
        '            loadPackageParam.classLoader,\n'
        '            "sendDisableAreaInfo"',
        digital_state_start,
    )
    if digital_state_end < 0:
        fail("could not isolate native pen-left-screen fallback hook")
    digital_state_hook = module[digital_state_start:digital_state_end]
    require_markers(
        digital_state_hook,
        (
            "activityForNativeEventCallback(",
            "tracePenLeftScreen(activity, state)",
            "schedulePenContactReceiveFallback(",
        ),
        "owner-bound pen-left-screen receive fallback",
    )
    if "clearPenContactStartPage(" in digital_state_hook:
        fail(
            "pen-left-screen immediately releases ownership instead of "
            "allowing a late receiveTrials callback"
        )
    receive_fallback_start = module.find(
        "private static void schedulePenContactReceiveFallback("
    )
    receive_fallback_end = module.find(
        "private static void notePageActivationTriggerContactLocked(",
        receive_fallback_start,
    )
    if receive_fallback_start < 0 or receive_fallback_end < 0:
        fail("could not isolate generation-scoped receive fallback")
    require_markers(
        module[receive_fallback_start:receive_fallback_end],
        (
            "PEN_CONTACT_GENERATIONS.get(activity)",
            "PEN_CONTACT_RECEIVE_FALLBACK_GENERATIONS.put(",
            "mainHandler.postDelayed(",
            "PEN_RECEIVE_EXPIRED_GENERATIONS.put(",
            '"pen_contact_receive_expired generation="',
            "PEN_CONTACT_RECEIVE_FALLBACK_MS",
        ),
        "generation-scoped delayed receive fallback tombstone",
    )

    pen_activation_start = module.find(
        "private static void handlePenPageActivation("
    )
    pending_target_start = module.find(
        "private static Integer pendingPageActivationTarget(",
        pen_activation_start,
    )
    if pen_activation_start < 0 or pending_target_start < 0:
        fail("could not isolate live pen page-activation routing")
    live_pen_activation = module[pen_activation_start:pending_target_start]
    if "beginPageActivationTransaction(" not in live_pen_activation:
        fail("live inactive-page pen input does not start an ownership transaction")
    forbidden_live_merge_markers = (
        "activateDocumentPageFromPen(",
        "PEN_ACTIVATION_TARGETS.put(",
        "capturePendingPenActivationTrails(",
        "persistPendingPenActivationTrails(",
    )
    leaked_live_markers = [
        marker
        for marker in forbidden_live_merge_markers
        if marker in live_pen_activation
    ]
    if leaked_live_markers:
        fail(
            "live pen activation still reaches the experimental inactive-page "
            f"merge path: {leaked_live_markers}"
        )
    target_mapping = live_pen_activation.find(
        "final int requestedTarget = pageAt(inputSnapshot, x, y);"
    )
    lift_generation_capture = live_pen_activation.find(
        "capturePageActivationPenLiftGeneration(activity)",
        target_mapping,
    )
    pre_dispatch_transaction = live_pen_activation.find(
        "PageActivationTransaction observedTransaction =",
        lift_generation_capture,
    )
    pre_dispatch_contact_latch = live_pen_activation.find(
        "notePageActivationTriggerContactLocked(",
        pre_dispatch_transaction,
    )
    pre_dispatch_boundary_guard = live_pen_activation.find(
        "!observedTransaction.triggerContactObserved",
        pre_dispatch_contact_latch,
    )
    pre_dispatch_snapshot_guard = live_pen_activation.find(
        "if (inputSnapshot == null || !inputSnapshot.editable",
        pre_dispatch_boundary_guard,
    )
    pre_dispatch_active_page_filter = live_pen_activation.find(
        "requestedTarget == current",
        pre_dispatch_snapshot_guard,
    )
    ui_dispatch = live_pen_activation.find(
        "new Handler(activity.getMainLooper()).post(new Runnable()",
        pre_dispatch_active_page_filter,
    )
    transaction_lookup_for_lift = live_pen_activation.find(
        "PAGE_ACTIVATION_TRANSACTIONS.get(activity)", ui_dispatch
    )
    transaction_lift = live_pen_activation.find(
        "markPageActivationPenLifted(", transaction_lookup_for_lift
    )
    transaction_return = live_pen_activation.find(
        "return;", transaction_lift
    )
    snapshot_validation = live_pen_activation.find(
        "currentSnapshot != inputSnapshot", transaction_return
    )
    current_mapping = live_pen_activation.find(
        "int current = inputSnapshot.currentPage;", snapshot_validation
    )
    blocked_contact_guard = live_pen_activation.find(
        "== PEN_CONTACT_BLOCKED_PAGE", current_mapping
    )
    blocked_contact_return = live_pen_activation.find(
        "return;", blocked_contact_guard
    )
    if not (
        0 <= target_mapping < lift_generation_capture
        < pre_dispatch_transaction
        < pre_dispatch_contact_latch < pre_dispatch_boundary_guard
        < pre_dispatch_snapshot_guard < pre_dispatch_active_page_filter
        < ui_dispatch < transaction_lookup_for_lift
        < transaction_lift < transaction_return < snapshot_validation
        < current_mapping < blocked_contact_guard < blocked_contact_return
    ):
        fail(
            "active-page pen samples are not filtered from the UI queue while "
            "transactional contact/pen-up boundaries remain preserved"
        )

    intercept_method_start = module.find(
        "private static boolean interceptPenPageActivation("
    )
    pending_target_after_intercept = module.find(
        "private static Integer pendingPageActivationTarget(",
        intercept_method_start,
    )
    if intercept_method_start < 0 or pending_target_after_intercept < 0:
        fail("could not isolate synchronous pen interception")
    intercept_method = mask_comments_preserve_literals(
        module[intercept_method_start:pending_target_after_intercept]
    )
    contact_start_lookup = intercept_method.find(
        "Integer contactStartPage = PEN_CONTACT_START_PAGES.get(activity);"
    )
    intercept_terminal_identity = intercept_method.find(
        "isCompletingActivePageStroke(", contact_start_lookup
    )
    null_snapshot_guard = intercept_method.find(
        "if (inputSnapshot == null)", intercept_terminal_identity
    )
    null_snapshot_terminal = intercept_method.find(
        "if (completingActivePageStroke)", null_snapshot_guard
    )
    null_snapshot_preserve = intercept_method.find(
        "return false;", null_snapshot_terminal
    )
    pending_geometry_guard = intercept_method.find(
        "if (!inputSnapshot.geometryReady)",
        null_snapshot_preserve,
    )
    pending_geometry_terminal = intercept_method.find(
        "if (completingActivePageStroke)",
        pending_geometry_guard,
    )
    pending_geometry_preserve = intercept_method.find(
        "return false;",
        pending_geometry_terminal,
    )
    pending_geometry_block = intercept_method.find(
        '"geometry_pending"',
        pending_geometry_preserve,
    )
    intercept_page_mapping = intercept_method.find(
        "int target = pageAt(inputSnapshot, x, y);", pending_geometry_block
    )
    nonwritable_start_guard = intercept_method.find(
        "contactStartPage.intValue() != current",
        intercept_page_mapping,
    )
    nonwritable_start_discard = intercept_method.find(
        "return true;", nonwritable_start_guard
    )
    current_page_passthrough = intercept_method.find(
        "if (target == current)",
        nonwritable_start_discard,
    )
    if not (
        0 <= contact_start_lookup < intercept_terminal_identity
        < null_snapshot_guard < null_snapshot_terminal
        < null_snapshot_preserve < pending_geometry_guard
        < pending_geometry_terminal
        < pending_geometry_preserve < pending_geometry_block
        < intercept_page_mapping
        < nonwritable_start_guard
        < nonwritable_start_discard < current_page_passthrough
    ):
        fail(
            "pen interception does not preserve source terminal callbacks and "
            "discard a non-writable-start gesture before current-page input"
        )
    if (
        "isNativeChromeTouch(" in live_pen_activation
        or "isNativeChromeTouch(" in intercept_method
        or '"native_chrome"' in intercept_method
    ):
        fail(
            "document-origin pen contacts can still be reclassified as "
            "native chrome after ACTION_DOWN"
        )
    nonwritable_guard_prefix = intercept_method[
        intercept_page_mapping:nonwritable_start_guard
    ]
    if "pressure > 0" in nonwritable_guard_prefix:
        fail(
            "queued inactive-page activation still lets the contact's "
            "terminal pen-up reach the native writer"
        )
    masked_intercept = mask_cpp_comments_and_literals(intercept_method)
    if identifier_mutations(masked_intercept, "pressure"):
        fail("pen interception rewrites pressure before fail-closed routing")
    target_writes = identifier_mutations(masked_intercept, "target")
    if (
        len(target_writes) != 1
        or "int target = pageAt(inputSnapshot, x, y);" not in masked_intercept
    ):
        fail("pen interception rewrites its mapped target before routing")
    crossing_guard = masked_intercept.find(
        "contactStartPage.intValue() == current"
    )
    crossing_pressure_guard = masked_intercept.find(
        "if (pressure > 0)", crossing_guard
    )
    crossing_discard = masked_intercept.find("return true;", crossing_guard)
    terminal_pressure_guard = masked_intercept.find(
        "if (completingActivePageStroke)", crossing_discard
    )
    terminal_preserved = masked_intercept.find(
        "return false;", terminal_pressure_guard
    )
    unmapped_guard = masked_intercept.find(
        "if (target < 0)", terminal_preserved
    )
    unmapped_pressure_guard = masked_intercept.find(
        "if (pressure > 0)", unmapped_guard
    )
    unmapped_ownership_latch = masked_intercept.find(
        "publishAmbiguousPenContactLocked(activity)",
        unmapped_pressure_guard,
    )
    unmapped_note = masked_intercept.find(
        "notePenInputBlock(", unmapped_ownership_latch
    )
    unmapped_reason_match = re.match(
        r"\s*activity\s*,\s*\"unmapped_positive_pressure\"\s*,\s*"
        r"x\s*,\s*y\s*,\s*pressure\s*,\s*-1L\s*,\s*current\s*,\s*"
        r"target\s*,\s*capturedContactStart\s*\)\s*;",
        intercept_method[unmapped_note + len("notePenInputBlock("):],
        re.DOTALL,
    )
    unmapped_reason_end = (
        unmapped_note + len("notePenInputBlock(") + unmapped_reason_match.end()
        if unmapped_reason_match is not None
        else -1
    )
    unmapped_block = masked_intercept.find(
        "return true;", unmapped_reason_end
    )
    unmapped_hover_passthrough = masked_intercept.find(
        "return false;", unmapped_block
    )
    unmapped_open = masked_intercept.find("{", unmapped_guard)
    unmapped_close = matching_brace(
        masked_intercept, unmapped_open, "unmapped pen-page guard"
    )
    unmapped_pressure_open = masked_intercept.find(
        "{", unmapped_pressure_guard
    )
    unmapped_pressure_close = matching_brace(
        masked_intercept,
        unmapped_pressure_open,
        "unmapped positive-pressure guard",
    )
    if re.search(
        r"\btarget\s*<\s*0\b",
        masked_intercept[
            terminal_preserved + len("return false;"):unmapped_guard
        ],
    ):
        fail("an earlier unmapped-page guard can preempt fail-closed routing")
    if not (
        brace_depth_at(masked_intercept, unmapped_guard) == 1
        and brace_depth_at(masked_intercept, unmapped_pressure_guard) == 2
        and brace_depth_at(masked_intercept, unmapped_ownership_latch) == 5
        and brace_depth_at(masked_intercept, unmapped_block) == 3
        and brace_depth_at(masked_intercept, unmapped_hover_passthrough) == 2
    ):
        fail(
            "unmapped positive-pressure blocking is disabled or nested under "
            "an additional condition"
        )
    if not (
        0 <= current_page_passthrough < crossing_guard
        < crossing_pressure_guard < crossing_discard
        < terminal_pressure_guard < terminal_preserved
        < unmapped_guard < unmapped_pressure_guard
        < unmapped_ownership_latch < unmapped_note < unmapped_reason_end
        < unmapped_block
        < unmapped_pressure_close < unmapped_hover_passthrough
        < unmapped_close
    ):
        fail(
            "a stroke begun on the active page is not kept on that page "
            "through divider/margin points and its terminal frame, or an "
            "unowned ink-bearing point can reach the native writer"
        )

    ambiguous_latch_start = module.find(
        "private static void publishAmbiguousPenContactLocked(Activity activity)"
    )
    ambiguous_latch_end = module.find(
        "private static void clearPenContactStartPage(", ambiguous_latch_start
    )
    if ambiguous_latch_start < 0 or ambiguous_latch_end < 0:
        fail("could not isolate ambiguous-contact latch helper")
    ambiguous_latch = mask_cpp_comments_and_literals(
        module[ambiguous_latch_start:ambiguous_latch_end]
    )
    latch_owner = ambiguous_latch.find(
        "PEN_CONTACT_OWNERSHIPS.put(activity, blocked);"
    )
    latch_generation = ambiguous_latch.find(
        "PEN_CONTACT_GENERATIONS.put(", latch_owner
    )
    latch_blocked_page = ambiguous_latch.find(
        "PEN_CONTACT_START_PAGES.put(", latch_generation
    )
    blocked_value = ambiguous_latch.find(
        "Integer.valueOf(PEN_CONTACT_BLOCKED_PAGE)", latch_blocked_page
    )
    if not (
        0 <= latch_owner < latch_generation < latch_blocked_page < blocked_value
        and brace_depth_at(ambiguous_latch, latch_owner) == 1
        and brace_depth_at(ambiguous_latch, latch_generation) == 1
        and brace_depth_at(ambiguous_latch, latch_blocked_page) == 1
    ):
        fail(
            "ambiguous-contact latch does not directly publish blocked "
            "ownership, generation, and start-page authority"
        )

    snapshot_class_start = module.find(
        "private static final class PenInputSnapshot"
    )
    snapshot_class_end = module.find(
        "private static final class SpreadPageLayout",
        snapshot_class_start,
    )
    pending_snapshot_start = module.find(
        "private static void publishPendingPenInputSnapshot("
    )
    geometry_snapshot_start = module.find(
        "private static void publishPenInputGeometrySnapshot(",
        pending_snapshot_start,
    )
    activation_ready_snapshot_start = module.find(
        "private static boolean publishReadyPenInputGeometryAfterActivation(",
        geometry_snapshot_start,
    )
    snapshot_read_start = module.find(
        "private static PenInputSnapshot penInputSnapshot(",
        activation_ready_snapshot_start,
    )
    snapshot_read_end = module.find(
        "private static void publishPenInputSnapshot(", snapshot_read_start
    )
    published_snapshot_start = module.find(
        "private static boolean publishedEditablePenInput(",
        snapshot_read_end,
    )
    editable_ready_start = module.find(
        "private static boolean editablePenInputReady(",
        published_snapshot_start,
    )
    spread_pair_start = module.find(
        "private static SpreadPair spreadPair(",
        editable_ready_start,
    )
    if min(
        snapshot_class_start,
        snapshot_class_end,
        pending_snapshot_start,
        geometry_snapshot_start,
        activation_ready_snapshot_start,
        snapshot_read_start,
        snapshot_read_end,
        published_snapshot_start,
        editable_ready_start,
        spread_pair_start,
    ) < 0:
        fail("could not isolate immutable pen-input snapshot publication")
    snapshot_class = module[snapshot_class_start:snapshot_class_end]
    require_markers(
        snapshot_class,
        (
            "final SpreadConfig config;",
            "final String documentPath;",
            "final int currentPage;",
            "final int pageCount;",
            "final int rightPage;",
            "final int leftPage;",
            "final RectF rightVisibleBounds;",
            "final RectF leftVisibleBounds;",
            "final int chromeOutputHeight;",
            "final boolean editable;",
            "final boolean geometryReady;",
            "new RectF(rightVisibleBounds)",
            "new RectF(leftVisibleBounds)",
            "this.documentPath = config.documentPath;",
            "this.chromeOutputHeight = chromeOutputHeight;",
            "this.editable = config.enabled && config.editable",
            "&& nativeBridgeLoaded && nativeHookReady;",
            "this.writerAuthority = writerAuthority;",
            "chromeOutputHeight",
        ),
        "immutable pen-input config/page-geometry snapshot",
    )
    if "Map<Activity, PenInputSnapshot> PEN_INPUT_SNAPSHOTS" not in module \
            or "new ConcurrentHashMap<>()" not in module[
                module.find("PEN_INPUT_SNAPSHOTS"):
                module.find("SPREAD_CONFIGS", module.find("PEN_INPUT_SNAPSHOTS"))
            ]:
        fail("pen-input snapshot is not atomically published across threads")
    editable_guard_start = module.find(
        "Map<Activity, Boolean> PEN_INPUT_EDITABLE_GUARDS"
    )
    if editable_guard_start < 0 or "new ConcurrentHashMap<>()" not in module[
        editable_guard_start:module.find(
            "PEN_INPUT_BLOCK_LOG_STATES", editable_guard_start
        )
    ]:
        fail("editable transition sentinel is not atomically published")
    snapshot_publish = module[pending_snapshot_start:snapshot_read_start]
    require_markers(
        snapshot_publish,
        (
            "publishPenInputEditableGuard(activity, config)",
            "captureNativeChromeOutputHeight(activity)",
            "chromeOutputHeight > 0",
            "Looper.myLooper() != activity.getMainLooper()",
            "PEN_INPUT_SNAPSHOTS.put(",
            "int currentPage = XposedHelpers.getIntField(",
            '"currentPage"',
            'XposedHelpers.getIntField(viewModel, "pageCount")',
        ),
        "UI-published pen-input state snapshot",
    )
    snapshot_read = module[snapshot_read_start:snapshot_read_end]
    require_markers(
        snapshot_read,
        (
            "activity != activeActivity",
            "PEN_INPUT_SNAPSHOTS.get(activity)",
        ),
        "memory-only native pen-input snapshot lookup",
    )
    forbidden_snapshot_lookup_markers = (
        "getResources(",
        "currentDocumentPath(",
        "XposedHelpers.",
        "isFinishing(",
        "isDestroyed(",
    )
    leaked_snapshot_lookups = [
        marker for marker in forbidden_snapshot_lookup_markers
        if marker in snapshot_read
    ]
    if leaked_snapshot_lookups:
        fail(
            "native pen-input snapshot lookup still reads live Activity, "
            f"document, or view-model state: {leaked_snapshot_lookups}"
        )
    editable_guard_publish_start = module.find(
        "private static void publishPenInputEditableGuard(",
        published_snapshot_start,
    )
    if editable_guard_publish_start < 0:
        fail("could not isolate editable transition-guard publication")
    published_snapshot = module[
        published_snapshot_start:editable_guard_publish_start
    ]
    require_markers(
        published_snapshot,
        (
            "PenInputSnapshot published = penInputSnapshot(activity);",
            "published != null && published.editable",
            "PEN_INPUT_EDITABLE_GUARDS.get(activity)",
        ),
        "memory-only published editable-state lookup",
    )
    if any(
        marker in published_snapshot
        for marker in forbidden_snapshot_lookup_markers
    ):
        fail("published editable-state lookup reads live Activity state")
    editable_guard_publish = module[
        editable_guard_publish_start:editable_ready_start
    ]
    require_markers(
        editable_guard_publish,
        (
            "activity != activeActivity",
            "DOCUMENT_IDENTITY_ADMISSIONS.get(activity) != null",
            "SPREAD_CONFIGS.get(activity) != config",
            "currentDocumentPath(activity)",
            "config.enabled && config.editable",
            "PEN_INPUT_EDITABLE_GUARDS.put(activity, Boolean.TRUE)",
        ),
        "UI-side exact editable transition-guard publication",
    )

    configuration_hook_start = module.find('"onConfigurationChanged",')
    configuration_hook_end = module.find(
        '"dispatchTouchEvent",', configuration_hook_start
    )
    if configuration_hook_start < 0 or configuration_hook_end < 0:
        fail("could not isolate orientation snapshot invalidation")
    configuration_hook = module[
        configuration_hook_start:configuration_hook_end
    ]
    configuration_before = configuration_hook.find(
        "protected void beforeHookedMethod"
    )
    configuration_owner_guard = configuration_hook.find(
        "isCurrentOrPendingActivityOwner(activity)", configuration_before
    )
    configuration_lock = configuration_hook.find(
        "synchronized (PAGE_ACTIVATION_OWNERSHIP_LOCK)",
        configuration_owner_guard,
    )
    configuration_invalidate = configuration_hook.find(
        "PEN_INPUT_SNAPSHOTS.remove(activity);",
        configuration_lock,
    )
    configuration_guard = configuration_hook.find(
        "PEN_INPUT_EDITABLE_GUARDS.put(", configuration_invalidate
    )
    configuration_gate = configuration_hook.find(
        "disableNativeGateForOwnershipHandoffLocked(", configuration_guard
    )
    configuration_after = configuration_hook.find(
        "protected void afterHookedMethod", configuration_gate
    )
    if not (
        0 <= configuration_before < configuration_owner_guard
        < configuration_lock < configuration_invalidate
        < configuration_guard < configuration_gate < configuration_after
    ):
        fail(
            "orientation change does not atomically withdraw stale pen geometry "
            "and native writer authority before the original callback"
        )

    load_page_hook_start = module.find(
        '"loadPage",', module.find(
            '"com.supernote.document.document.DocumentViewModel"'
        )
    )
    turn_page_hook_start = module.find('"turnPage",', load_page_hook_start)
    if load_page_hook_start < 0 or turn_page_hook_start < 0:
        fail("could not isolate page-load snapshot invalidation")
    load_page_hook = module[load_page_hook_start:turn_page_hook_start]
    if "PEN_INPUT_SNAPSHOTS.remove(activity);" not in load_page_hook:
        fail("page load does not withdraw stale pen geometry before mutation")
    if "PEN_INPUT_EDITABLE_GUARDS.remove(activity);" in load_page_hook:
        fail("page load drops editable fail-closed authority with stale geometry")

    set_image_hook_start = module.find('"setImage",')
    set_image_hook_end = module.find('"onDestroy",', set_image_hook_start)
    if set_image_hook_start < 0 or set_image_hook_end < 0:
        fail("could not isolate image-boundary snapshot invalidation")
    set_image_hook = module[set_image_hook_start:set_image_hook_end]
    set_image_owner = set_image_hook.find(
        "boolean activeOwner = isActiveActivityOwner(activity)"
    )
    set_image_owner_reject = set_image_hook.find(
        "if (!activeOwner)", set_image_owner
    )
    set_image_lock = set_image_hook.find(
        "synchronized (PAGE_ACTIVATION_OWNERSHIP_LOCK)",
        set_image_owner_reject,
    )
    set_image_invalidate = set_image_hook.find(
        "PEN_INPUT_SNAPSHOTS.remove(activity);", set_image_lock
    )
    set_image_guard = set_image_hook.find(
        "PEN_INPUT_EDITABLE_GUARDS.put(", set_image_invalidate
    )
    set_image_gate = set_image_hook.find(
        "disableNativeGateForOwnershipHandoffLocked(", set_image_guard
    )
    set_image_landscape = set_image_hook.find(
        "if (!isCalibrationLandscape(activity))", set_image_gate
    )
    if not (
        0 <= set_image_owner < set_image_owner_reject < set_image_lock
        < set_image_invalidate < set_image_guard < set_image_gate
        < set_image_landscape
    ):
        fail(
            "setImage does not reject stale owners and atomically withdraw "
            "stale pen geometry/native authority before branching"
        )
    if "PEN_INPUT_EDITABLE_GUARDS.remove(activity);" in set_image_hook:
        fail("setImage drops editable fail-closed authority before replacement geometry")

    update_gate_start = module.find(
        "private static void updateNativeEraserGate(\n"
        "        Activity activity,\n"
        "        String reason\n"
        "    )"
    )
    update_gate_end = module.find(
        "private static void updateNativeEraserGate(", update_gate_start + 1
    )
    if update_gate_start < 0 or update_gate_end < 0:
        fail("could not isolate orientation-aware snapshot publication")
    update_gate = module[update_gate_start:update_gate_end]
    require_markers(
        update_gate,
        (
            "boolean landscape =",
            "if (landscape)",
            "publishDocumentReceiveIdentity(activity, config);",
            "publishPendingPenInputSnapshot(activity, config, reason);",
            "clearPenInputSnapshot(activity);",
            "config != null",
            "nativeSafePresentationAuthorityCurrentLocked(",
            "PEN_INPUT_EDITABLE_GUARDS.remove(activity)",
            "PEN_INPUT_EDITABLE_GUARDS.put(activity, Boolean.TRUE)",
        ),
        "orientation-aware pen snapshot publication",
    )
    update_gate_apply_start = update_gate_end
    update_gate_apply_end = module.find(
        "private static boolean nativeGateAuthorityCurrentLocked(",
        update_gate_apply_start,
    )
    if update_gate_apply_end < 0:
        fail("could not isolate native eraser gate application")
    update_gate_apply = module[
        update_gate_apply_start:update_gate_apply_end
    ]
    update_gate_apply_masked = mask_cpp_comments_and_literals(update_gate_apply)
    effective_init = update_gate_apply_masked.find(
        "boolean effectiveEnabled = false;"
    )
    effective_assignment = update_gate_apply_masked.find(
        "effectiveEnabled = apply && enabled", effective_init
    )
    authority_check = update_gate_apply_masked.find(
        "&& nativeGateAuthorityCurrentLocked(activity, true);",
        effective_assignment,
    )
    jni_gate_marker = "nativeSetCalibrationEnabled(effectiveEnabled);"
    jni_gate_write = update_gate_apply_masked.find(
        jni_gate_marker, authority_check
    )
    guard_remove = update_gate_apply_masked.find(
        "if (effectiveEnabled)", jni_gate_write
    )
    fail_closed_guard = update_gate_apply_masked.find(
        "else if (enabled)", guard_remove
    )
    if not (
        0 <= effective_init < effective_assignment < authority_check
        < jni_gate_write < guard_remove < fail_closed_guard
    ):
        fail(
            "native eraser gate does not propagate false and authority-checked "
            "true values directly to JNI before publishing editable authority"
        )
    if update_gate_apply_masked.count(jni_gate_marker) != 1:
        fail("native eraser gate must write its effective boolean to JNI once")
    effective_writes = identifier_mutations(
        update_gate_apply_masked, "effectiveEnabled"
    )
    if len(effective_writes) != 2:
        fail(
            "native eraser gate effective authority is reassigned outside its "
            "single fail-closed initialization and authority expression"
        )
    if identifier_mutations(update_gate_apply_masked, "enabled"):
        fail("native eraser gate mutates its requested enabled state")
    authority_end = authority_check + len(
        "&& nativeGateAuthorityCurrentLocked(activity, true);"
    )
    if re.match(
        r"\s*if\s*\(\s*!\s*apply\s*\)",
        update_gate_apply_masked[authority_end:],
    ) is None:
        fail(
            "native eraser gate can mutate authority between its checked "
            "expression and owner decision"
        )
    inner_try = update_gate_apply_masked.rfind(
        "try {", authority_check, jni_gate_write
    )
    owner_else = update_gate_apply_masked.rfind(
        "} else {", authority_check, inner_try
    )
    if (
        inner_try < 0
        or owner_else < 0
        or update_gate_apply_masked[owner_else + len("} else {"):inner_try].strip()
        or update_gate_apply_masked[inner_try + len("try {"):jni_gate_write].strip()
        or brace_depth_at(update_gate_apply_masked, jni_gate_write) != 5
    ):
        fail(
            "native eraser JNI publication is nested under an extra condition "
            "instead of executing directly inside the authority-checked owner path"
        )
    if update_gate_apply_masked[
        jni_gate_write + len(jni_gate_marker):guard_remove
    ].strip():
        fail(
            "native eraser JNI write is conditionally wrapped instead of "
            "publishing both false and authority-checked true values"
        )
    native_gate_authority_start = module.find(
        "private static boolean nativeGateAuthorityCurrentLocked("
    )
    native_gate_authority_end = module.find(
        "private static boolean nativeGateAuthorityCurrentForTransactionLocked(",
        native_gate_authority_start,
    )
    if native_gate_authority_start < 0 or native_gate_authority_end < 0:
        fail("could not isolate exact native-writer gate authority")
    require_markers(
        module[native_gate_authority_start:native_gate_authority_end],
        (
            "activity == activeActivity",
            "DOCUMENT_IDENTITY_ADMISSIONS.get(activity) == null",
            "NAVIGATION_FAIL_CLOSED_DOCUMENTS.get(activity) == null",
            "PAGE_ACTIVATION_TRANSACTIONS.get(activity) == null",
            "PAGE_ACTIVATION_ROLLBACK_RECOVERIES.get(activity) == null",
            "PEN_CONTACT_OWNERSHIPS.get(activity) == null",
            "PEN_CONTACT_START_PAGES.get(activity) == null",
            "snapshot != null && snapshot.config == config",
            "snapshot.editable && snapshot.geometryReady",
            "isSpreadConfigPublicationCurrentLocked(",
        ),
        "exact native-writer gate authority",
    )
    editable_guard_start = module.find(
        "private static void publishPenInputEditableGuard("
    )
    editable_guard_end = module.find(
        "private static boolean editablePenInputReady(", editable_guard_start
    )
    portrait_restore_start = module.find(
        "private static void restorePortraitPresentation("
    )
    portrait_restore_end = module.find(
        "private static void scheduleCompose(", portrait_restore_start
    )
    if min(
        editable_guard_start,
        editable_guard_end,
        portrait_restore_start,
        portrait_restore_end,
    ) < 0:
        fail("could not isolate rollback-aware editable guard lifecycle")
    editable_guard = module[editable_guard_start:editable_guard_end]
    require_markers(
        editable_guard,
        (
            "config.enabled && config.editable",
            "PAGE_ACTIVATION_ROLLBACK_RECOVERIES.get(activity) != null",
            "PEN_INPUT_EDITABLE_GUARDS.put(activity, Boolean.TRUE)",
            "PEN_INPUT_EDITABLE_GUARDS.remove(activity)",
        ),
        "rollback-aware editable guard publication",
    )
    portrait_restore = module[portrait_restore_start:portrait_restore_end]
    portrait_snapshot_clear = portrait_restore.find(
        "clearPenInputSnapshot(activity)"
    )
    portrait_receive_identity = portrait_restore.find(
        "publishDocumentReceiveIdentity(activity, config)",
        portrait_snapshot_clear,
    )
    portrait_lock = portrait_restore.find(
        "synchronized (PAGE_ACTIVATION_OWNERSHIP_LOCK)",
        portrait_receive_identity,
    )
    portrait_recovery_check = portrait_restore.find(
        "nativeSafePresentationAuthorityCurrentLocked(", portrait_lock
    )
    portrait_guard_remove = portrait_restore.find(
        "PEN_INPUT_EDITABLE_GUARDS.remove(activity)", portrait_recovery_check
    )
    portrait_guard_retain = portrait_restore.find(
        "PEN_INPUT_EDITABLE_GUARDS.put(activity, Boolean.TRUE)",
        portrait_guard_remove,
    )
    if not (
        0 <= portrait_snapshot_clear < portrait_receive_identity
        < portrait_lock < portrait_recovery_check
        < portrait_guard_remove < portrait_guard_retain
    ):
        fail("portrait restoration can reopen pen input during rollback recovery")
    publish_snapshot_start = module.find(
        "private static void publishPenInputSnapshot("
    )
    clear_snapshot_start = module.find(
        "private static void clearPenInputSnapshot(", publish_snapshot_start
    )
    editable_lookup_start = module.find(
        "private static boolean publishedEditablePenInput(",
        clear_snapshot_start,
    )
    if min(
        publish_snapshot_start,
        clear_snapshot_start,
        editable_lookup_start,
    ) < 0:
        fail("could not isolate ownership-fenced pen snapshot helpers")
    snapshot_helpers = module[publish_snapshot_start:editable_lookup_start]
    require_markers(
        snapshot_helpers,
        (
            "synchronized (PAGE_ACTIVATION_OWNERSHIP_LOCK)",
            "SPREAD_CONFIGS.get(activity) != snapshot.config",
            "PEN_INPUT_EDITABLE_GUARDS.put(activity, Boolean.TRUE)",
            "PEN_INPUT_SNAPSHOTS.put(activity, snapshot)",
            "PEN_INPUT_SNAPSHOTS.remove(activity)",
        ),
        "ownership-fenced pen snapshot publication",
    )
    rollback_convergence_start = module.find(
        "private static boolean clearRollbackRecoveryIfConvergedLocked(",
        publish_snapshot_start,
    )
    if rollback_convergence_start < 0 or rollback_convergence_start >= clear_snapshot_start:
        fail("could not isolate rollback-recovery snapshot fence")
    snapshot_publisher = module[
        publish_snapshot_start:rollback_convergence_start
    ]
    if "PAGE_ACTIVATION_ROLLBACK_RECOVERIES.remove(" in snapshot_publisher:
        fail("generic ready snapshot publication clears uncertain rollback ownership")
    require_markers(
        snapshot_publisher,
        (
            "snapshot.editable && snapshot.geometryReady",
            "PAGE_ACTIVATION_ROLLBACK_RECOVERIES.get(activity) != null",
            "PEN_INPUT_SNAPSHOTS.remove(activity, snapshot)",
            "PEN_INPUT_EDITABLE_GUARDS.put(activity, Boolean.TRUE)",
        ),
        "fail-closed rollback-recovery snapshot publication",
    )
    require_markers(
        module[rollback_convergence_start:clear_snapshot_start],
        (
            "SPREAD_CONFIGS.get(activity) != config",
            "recovery.sameDocumentIdentity(config)",
            "rebindRollbackRecoveryToValidatedConfigLocked(",
            "recovery = PAGE_ACTIVATION_ROLLBACK_RECOVERIES.get(activity)",
            "recovery != config",
            "recovery.samePersistedState(config)",
            '"page_activation_rollback_recovery_adopted_config"',
            "presenterMarkPage != readerPage + 1",
            "PAGE_ACTIVATION_ROLLBACK_RECOVERIES.remove(",
            '"page_activation_rollback_recovery_converged"',
        ),
        "explicit reader/presenter rollback convergence",
    )
    activation_ready_snapshot = module[
        activation_ready_snapshot_start:snapshot_read_start
    ]
    require_markers(
        activation_ready_snapshot,
        (
            "PenInputSnapshot pending = penInputSnapshot(activity)",
            "pending.currentPage != transaction.targetPage",
            "PenInputSnapshot readySnapshot = new PenInputSnapshot(",
            "synchronized (PAGE_ACTIVATION_OWNERSHIP_LOCK)",
            "PAGE_ACTIVATION_TRANSACTIONS.get(activity) == transaction",
            "!transaction.rollbackPending",
            "PEN_INPUT_SNAPSHOTS.get(activity) == pending",
            "SPREAD_CONFIGS.get(activity) == pending.config",
            "pending.writerAuthority",
            "publishPenInputSnapshot(activity, readySnapshot)",
        ),
        "post-activation ready pen-geometry publication",
    )
    snapshot_blocking_hits = [
        marker for marker in blocking_markers
        if marker in module[snapshot_read_start:editable_ready_start]
    ]
    if snapshot_blocking_hits:
        fail(
            "pen-input snapshot reads perform blocking config/filesystem work: "
            f"{snapshot_blocking_hits}"
        )
    compose_start = module.find("private static boolean compose(")
    reapply_start = module.find(
        "private static void reapplyCanonicalCommittedInk(",
        compose_start,
    )
    compose_method = module[compose_start:reapply_start]
    compose_config = compose_method.find(
        "SpreadConfig config = spreadConfig(activity);"
    )
    compose_config_stop = compose_method.find(
        "config == null || !config.enabled", compose_config
    )
    compose_pair = compose_method.find(
        "SpreadPair pair = spreadPair(config", compose_config_stop
    )
    if not 0 <= compose_config < compose_config_stop < compose_pair:
        fail(
            "spread composition consumes fallback/default parity after config "
            "publication fails"
        )
    compose_watch_capture = compose_method.find(
        "PersistedConfigWatch composeConfigWatch", compose_config_stop
    )
    compose_generation_capture = compose_method.find(
        "composeConfigWatch.generation.get()", compose_watch_capture
    )
    compose_presenter_page = compose_method.find(
        "int composePresenterMarkPage =", compose_generation_capture
    )
    compose_initial_ownership_fence = compose_method.find(
        "synchronized (PAGE_ACTIVATION_OWNERSHIP_LOCK)",
        compose_presenter_page,
    )
    compose_initial_config_check = compose_method.find(
        "isSpreadConfigPublicationCurrentLocked(",
        compose_initial_ownership_fence,
    )
    compose_initial_recovery_convergence = compose_method.find(
        "clearRollbackRecoveryIfConvergedLocked(",
        compose_initial_config_check,
    )
    compose_image_publish = compose_method.find(
        "imageView.setImageBitmap(composite)", compose_initial_recovery_convergence
    )
    compose_fail_closed_gate = compose_method.find(
        '"compose_geometry_pending",', compose_image_publish
    )
    compose_writer_info = compose_method.find(
        'XposedHelpers.callMethod(presenter, "sendWriteInfo")',
        compose_fail_closed_gate,
    )
    compose_geometry_send = compose_method.find(
        "sendCalibrationGeometry(", compose_writer_info
    )
    compose_geometry_commit = compose_method.find(
        "commitPageActivationGeometry(", compose_geometry_send
    )
    compose_final_ownership_fence = compose_method.find(
        "synchronized (PAGE_ACTIVATION_OWNERSHIP_LOCK)",
        compose_geometry_commit,
    )
    compose_final_config_check = compose_method.find(
        "isSpreadConfigPublicationCurrentLocked(",
        compose_final_ownership_fence,
    )
    compose_snapshot_publish = compose_method.find(
        "publishPenInputSnapshot(activity, readySnapshot)",
        compose_final_config_check,
    )
    compose_recovery_convergence = compose_method.find(
        "clearRollbackRecoveryIfConvergedLocked(",
        compose_final_config_check,
    )
    compose_ready_snapshot = compose_method.find(
        '"compose_geometry_committed"', compose_snapshot_publish
    )
    if not (
        0 <= compose_watch_capture < compose_generation_capture
        < compose_presenter_page < compose_initial_ownership_fence
        < compose_initial_config_check < compose_initial_recovery_convergence
        < compose_image_publish < compose_fail_closed_gate
        < compose_writer_info < compose_geometry_send
        < compose_geometry_commit < compose_final_ownership_fence
        < compose_final_config_check < compose_recovery_convergence
        < compose_snapshot_publish
        < compose_ready_snapshot
    ):
        fail(
            "compose does not keep slow presenter work outside two exact, "
            "atomic config/watch publication fences"
        )
    initial_lock_body = compose_method[
        compose_initial_ownership_fence:compose_image_publish
    ]
    final_lock_end = compose_method.find(
        "if (readyPublished)", compose_final_ownership_fence
    )
    final_lock_body = compose_method[
        compose_final_ownership_fence:final_lock_end
    ]
    forbidden_locked_compose_work = (
        "setImageBitmap",
        "setDisableAreaList",
        "sendWriteInfo",
        "sendCalibrationGeometry",
        "commitPageActivationGeometry",
        "showStatusOverlay",
        "showOverlay",
    )
    locked_hits = [
        marker for marker in forbidden_locked_compose_work
        if marker in initial_lock_body or marker in final_lock_body
    ]
    if final_lock_end < 0 or locked_hits:
        fail(
            "compose holds the low-latency pen ownership lock across slow "
            f"bitmap/presenter/UI work: {locked_hits}"
        )
    geometry_pending = compose_method.find(
        '"compose_geometry_pending"'
    )
    geometry_commit = compose_method.find(
        "commitPageActivationGeometry(", geometry_pending
    )
    geometry_ready = compose_method.find(
        '"compose_geometry_committed"', geometry_commit
    )
    if not 0 <= geometry_pending < geometry_commit < geometry_ready:
        fail(
            "pen input is not kept pending until page geometry ownership "
            "commits"
        )
    page_at_start = module.find(
        "private static int pageAt(Activity activity, float x, float y)"
    )
    current_page_start = module.find(
        "private static int currentDocumentPage(", page_at_start
    )
    if page_at_start < 0 or current_page_start < 0:
        fail("could not isolate memory-only pageAt routing")
    page_at_method = module[page_at_start:current_page_start]
    if "return pageAt(penInputSnapshot(activity), x, y);" not in page_at_method:
        fail("pageAt does not use the immutable geometry snapshot")
    page_at_blocking_hits = [
        marker for marker in blocking_markers
        if marker in page_at_method
    ]
    if page_at_blocking_hits:
        fail(
            "pageAt performs blocking config/filesystem work: "
            f"{page_at_blocking_hits}"
        )

    ui_block_start = module.find(
        "private static boolean blockPageActivationUiInput("
    )
    activity_contact_latch_start = module.find(
        "private static void latchPenContactFromActivityTouch(", ui_block_start
    )
    activity_contact_terminal_start = module.find(
        "private static void schedulePenContactFallbackFromActivityTouch(",
        activity_contact_latch_start,
    )
    activation_touch_start = module.find(
        "private static boolean handlePageActivationTouch(",
        activity_contact_terminal_start,
    )
    native_chrome_start = module.find(
        "private static void queueLowLatencyLog(", activation_touch_start
    )
    if (ui_block_start < 0 or activity_contact_latch_start < 0
            or activity_contact_terminal_start < 0
            or activation_touch_start < 0 or native_chrome_start < 0):
        fail("could not isolate page-activation UI-input blocking")
    ui_block_method = module[ui_block_start:activity_contact_latch_start]
    require_markers(
        ui_block_method,
        (
            "PAGE_ACTIVATION_BLOCKED_TOUCHES.get(activity)",
            "PAGE_ACTIVATION_TRANSACTIONS.get(activity)",
            "action == MotionEvent.ACTION_HOVER_EXIT",
            "action == MotionEvent.ACTION_DOWN",
            "action == MotionEvent.ACTION_MOVE",
            "PAGE_ACTIVATION_BLOCKED_TOUCHES.put(activity, Boolean.TRUE)",
            "PAGE_ACTIVATION_BLOCKED_TOUCHES.remove(activity)",
            "notePageActivationUiBlock(activity, transaction, event, action)",
            "PAGE_ACTIVATION_UI_BLOCK_LOG_STATES.put(",
            "PAGE_ACTIVATION_UI_BLOCK_LOG_STATES.get(activity)",
            "PAGE_ACTIVATION_UI_BLOCK_LOG_STATES.remove(",
            "previous.matches(transactionId, targetPage, tool)",
            '"page_activation_ui_input_blocked phase=start state="',
            '"page_activation_ui_input_blocked phase=end state="',
            "queueLowLatencyLog(",
            "return true;",
        ),
        "transactional UI-input blocking",
    )
    if "log(" in ui_block_method:
        fail("blocked UI-input hook performs synchronous per-motion logging")
    activity_contact_latch = module[
        activity_contact_latch_start:activity_contact_terminal_start
    ]
    require_markers(
        activity_contact_latch,
        (
            "event.getActionMasked() != MotionEvent.ACTION_DOWN",
            "MotionEvent.TOOL_TYPE_STYLUS",
            "MotionEvent.TOOL_TYPE_ERASER",
            "PenInputSnapshot snapshot = penInputSnapshot(activity)",
            "PenContactIdentityCapture identity = snapshot == null",
            "synchronized (PAGE_ACTIVATION_OWNERSHIP_LOCK)",
            "PEN_CONTACT_OWNERSHIPS.get(activity)",
            "PEN_INPUT_EDITABLE_GUARDS.get(activity)",
            "PAGE_ACTIVATION_TRANSACTIONS.get(activity)",
            "PEN_INPUT_SNAPSHOTS.get(activity) != snapshot",
            "SPREAD_CONFIGS.get(activity) != snapshot.config",
            "publishAmbiguousPenContactLocked(activity)",
            "int mappedPage = pageAt(",
            "mappedPage == snapshot.currentPage",
            "publishPenContactOwnershipLocked(",
            "PEN_PHYSICAL_CONTACT_DOWNS.put(",
            "retireDocumentReceiveQuarantineAfterFreshContactLocked(",
            '"pen_contact_activity_touch_latched"',
        ),
        "identity-validated Android stylus contact fallback",
    )
    fallback_lock = activity_contact_latch.find(
        "synchronized (PAGE_ACTIVATION_OWNERSHIP_LOCK)"
    )
    fallback_existing = activity_contact_latch.find(
        "PEN_CONTACT_OWNERSHIPS.get(activity)", fallback_lock
    )
    fallback_authority = activity_contact_latch.find(
        "PEN_INPUT_EDITABLE_GUARDS.get(activity)", fallback_existing
    )
    fallback_snapshot = activity_contact_latch.find(
        "PEN_INPUT_SNAPSHOTS.get(activity) != snapshot", fallback_authority
    )
    fallback_mapping = activity_contact_latch.find(
        "int mappedPage = pageAt(", fallback_snapshot
    )
    fallback_publish = activity_contact_latch.find(
        "published = publishPenContactOwnershipLocked(", fallback_mapping
    )
    fallback_physical = activity_contact_latch.find(
        "PEN_PHYSICAL_CONTACT_DOWNS.put(", fallback_publish
    )
    fallback_quarantine = activity_contact_latch.find(
        "retireDocumentReceiveQuarantineAfterFreshContactLocked(",
        fallback_physical,
    )
    if not (
        0 <= fallback_lock < fallback_existing < fallback_authority
        < fallback_snapshot < fallback_mapping < fallback_publish
        < fallback_physical < fallback_quarantine
    ):
        fail(
            "Android stylus fallback does not validate and publish one exact "
            "contact owner before retiring receive quarantine"
        )
    fallback_blocking_hits = [
        marker for marker in blocking_markers
        if marker in activity_contact_latch
    ]
    if fallback_blocking_hits or "log(" in activity_contact_latch:
        fail(
            "Android stylus fallback performs blocking or synchronous work: "
            f"{fallback_blocking_hits}"
        )
    if "blocked_native_chrome" in activity_contact_latch:
        fail(
            "Android stylus fallback still converts a native-control contact "
            "into blocked handwriting ownership"
        )
    activity_contact_terminal = module[
        activity_contact_terminal_start:activation_touch_start
    ]
    require_markers(
        activity_contact_terminal,
        (
            "action != MotionEvent.ACTION_UP",
            "&& action != MotionEvent.ACTION_CANCEL",
            "MotionEvent.TOOL_TYPE_STYLUS",
            "MotionEvent.TOOL_TYPE_ERASER",
            "synchronized (PAGE_ACTIVATION_OWNERSHIP_LOCK)",
            "PEN_CONTACT_OWNERSHIPS.get(activity)",
            "owner.phase != PEN_CONTACT_PHASE_ACTIVE",
            "capturePageActivationPenLiftGeneration(activity)",
            "schedulePenContactReceiveFallback(",
            '"pen_contact_activity_touch_terminal_fallback"',
        ),
        "Android stylus terminal fallback",
    )
    terminal_lock = activity_contact_terminal.find(
        "synchronized (PAGE_ACTIVATION_OWNERSHIP_LOCK)"
    )
    terminal_owner = activity_contact_terminal.find(
        "PEN_CONTACT_OWNERSHIPS.get(activity)", terminal_lock
    )
    terminal_phase = activity_contact_terminal.find(
        "owner.phase != PEN_CONTACT_PHASE_ACTIVE", terminal_owner
    )
    terminal_lift = activity_contact_terminal.find(
        "capturePageActivationPenLiftGeneration(activity)", terminal_phase
    )
    terminal_schedule = activity_contact_terminal.find(
        "schedulePenContactReceiveFallback(", terminal_lift
    )
    if not (
        0 <= terminal_lock < terminal_owner < terminal_phase
        < terminal_lift < terminal_schedule
    ):
        fail(
            "Android stylus terminal fallback does not validate the active "
            "owner before scheduling the receive fallback"
        )
    terminal_blocking_hits = [
        marker for marker in blocking_markers
        if marker in activity_contact_terminal
    ]
    if terminal_blocking_hits or "log(" in activity_contact_terminal:
        fail(
            "Android stylus terminal fallback performs blocking or "
            f"synchronous work: {terminal_blocking_hits}"
        )
    activation_touch_method = module[
        activation_touch_start:native_chrome_start
    ]
    require_markers(
        activation_touch_method,
        (
            "boolean finger = toolType == MotionEvent.TOOL_TYPE_FINGER",
            "boolean stylus = toolType == MotionEvent.TOOL_TYPE_STYLUS",
            "|| toolType == MotionEvent.TOOL_TYPE_ERASER",
            "if (!finger && !stylus)",
            "if (stylus)",
            "action != MotionEvent.ACTION_DOWN",
            "PenInputSnapshot stylusSnapshot = penInputSnapshot(activity)",
            "int target = pageAt(",
            "target >= 0 && target != current",
            "stylusSnapshot.geometryReady",
            "stylusSnapshot.config.samePersistedState(cachedConfig)",
            "isCachedSpreadConfigCurrent(",
            "PAGE_ACTIVATION_BLOCKED_TOUCHES.put(",
            "notePageActivationUiBlock(",
            '"page_activation_stylus_stream_latched current="',
            '"stylus_touch_contact"',
            "beginPageActivationTransaction(",
            '"page_activation_stylus_touch_result current="',
            "return true;",
        ),
        "inactive-page stylus-stream admission latch",
    )
    stylus_branch = activation_touch_method.find("if (stylus)")
    stylus_down_only = activation_touch_method.find(
        "action != MotionEvent.ACTION_DOWN", stylus_branch
    )
    stylus_snapshot = activation_touch_method.find(
        "PenInputSnapshot stylusSnapshot = penInputSnapshot(activity)",
        stylus_down_only,
    )
    stylus_persisted_guard = activation_touch_method.find(
        "stylusSnapshot.config.samePersistedState(cachedConfig)",
        stylus_snapshot,
    )
    stylus_current_guard = activation_touch_method.find(
        "isCachedSpreadConfigCurrent(", stylus_persisted_guard
    )
    stylus_latch = activation_touch_method.find(
        "PAGE_ACTIVATION_BLOCKED_TOUCHES.put(", stylus_current_guard
    )
    stylus_note = activation_touch_method.find(
        "notePageActivationUiBlock(", stylus_latch
    )
    stylus_activation = activation_touch_method.find(
        "beginPageActivationTransaction(", stylus_note
    )
    stylus_result = activation_touch_method.find(
        '"page_activation_stylus_touch_result current="', stylus_activation
    )
    finger_activation = activation_touch_method.find(
        "Integer trackedTarget = ACTIVATION_TOUCH_TARGETS.get(activity)",
        stylus_result,
    )
    if not (
        0 <= stylus_branch < stylus_down_only < stylus_snapshot
        < stylus_persisted_guard < stylus_current_guard < stylus_latch
        < stylus_note < stylus_activation < stylus_result < finger_activation
    ):
        fail(
            "inactive-page stylus DOWN is not validated and latched before "
            "finger activation routing can expose the stream to the old page"
        )
    finger_stream_start = module.find(
        "private static void trackFingerTouchStream(", ui_block_start
    )
    finger_stream_end = module.find(
        "private static void notePageActivationUiBlock(",
        finger_stream_start,
    )
    if finger_stream_start < 0 or finger_stream_end < 0:
        fail("could not isolate pre-activation finger-stream guard")
    finger_finish_start = module.find(
        "private static void finishFingerTouchStream(",
        finger_stream_start,
    )
    if finger_finish_start < 0 or finger_finish_start >= finger_stream_end:
        fail("could not isolate post-dispatch finger-stream release")
    finger_stream = module[finger_stream_start:finger_finish_start]
    finger_finish = module[finger_finish_start:finger_stream_end]
    require_markers(
        finger_stream,
        (
            "MotionEvent.ACTION_DOWN",
            "synchronized (PAGE_ACTIVATION_OWNERSHIP_LOCK)",
            "ACTIVE_FINGER_TOUCH_STREAMS.put(activity, Boolean.TRUE)",
        ),
        "ownership-serialized finger-stream admission",
    )
    require_markers(
        finger_finish,
        (
            "MotionEvent.ACTION_UP",
            "MotionEvent.ACTION_CANCEL",
            "synchronized (PAGE_ACTIVATION_OWNERSHIP_LOCK)",
            "ACTIVE_FINGER_TOUCH_STREAMS.remove(activity)",
        ),
        "post-dispatch finger-stream release",
    )
    if "ACTIVE_FINGER_TOUCH_STREAMS.remove(activity)" in finger_stream:
        fail("finger stream is released before native dispatch completes")
    if (
        "Map<Activity, Boolean> ACTIVE_FINGER_TOUCH_STREAMS =\n"
        "        new ConcurrentHashMap<>()"
    ) not in module:
        fail("finger-stream activation guard is not thread-safe")
    validated_activation_start = module.find(
        "private static boolean beginPageActivationTransaction(\n"
        "        Activity activity,\n"
        "        int targetPage,\n"
        "        String trigger,\n"
        "        boolean triggerContactObserved,\n"
        "        DeferredSpreadTurn persistedConfigGuard"
    )
    request_load_start = module.find(
        "private static void requestPageActivationLoad(",
        validated_activation_start,
    )
    if validated_activation_start < 0 or request_load_start < 0:
        fail("could not isolate validated page-activation admission")
    validated_activation = module[
        validated_activation_start:request_load_start
    ]
    ownership_lock = validated_activation.find(
        "synchronized (PAGE_ACTIVATION_OWNERSHIP_LOCK)"
    )
    active_finger_guard = validated_activation.find(
        "ACTIVE_FINGER_TOUCH_STREAMS.get(activity)", ownership_lock
    )
    active_finger_reject = validated_activation.find(
        'page_activation_rejected reason=finger_touch_active',
        active_finger_guard,
    )
    transaction_publish = validated_activation.find(
        "PAGE_ACTIVATION_TRANSACTIONS.put(activity, transaction)",
        active_finger_reject,
    )
    if not (
        0 <= ownership_lock < active_finger_guard
        < active_finger_reject < transaction_publish
    ):
        fail(
            "page activation can begin after a native finger ACTION_DOWN "
            "without closing or rejecting that gesture"
        )
    activation_touch_method = module[activation_touch_start:native_chrome_start]
    touch_transaction = activation_touch_method.find(
        "PageActivationTransaction transaction ="
    )
    touch_pending_guard = activation_touch_method.find(
        "if (transaction != null)", touch_transaction
    )
    touch_pending_discard = activation_touch_method.find(
        "return true;", touch_pending_guard
    )
    if not 0 <= touch_transaction < touch_pending_guard < touch_pending_discard:
        fail("finger input can reach native controls during an ownership transfer")
    if "transaction != null && !isNativeChromeTouch" in activation_touch_method:
        fail("native chrome remains exempt from ownership-transfer input blocking")
    require_markers(
        activation_touch_method,
        (
            "boolean spreadLandscape",
            "SpreadConfig cachedConfig",
            "!spreadLandscape",
            "ActivationTouchIdentity identity",
            "ACTIVATION_TOUCH_IDENTITIES.put(",
            "PenInputSnapshot releaseSnapshot = penInputSnapshot(activity)",
            "boolean geometryRefreshGap = releasedTarget < 0",
            "boolean identityCurrent = identity != null",
            "boolean targetStillVisible = identity != null",
            "isCachedSpreadConfigCurrent(activity, identity.config)",
            "cancelNativeFingerTouchStream(activity, event)",
            "MotionEvent.obtain(terminalEvent)",
            "cancelEvent.setAction(MotionEvent.ACTION_CANCEL)",
            "superDispatchTouchEvent(",
            "activity.onTouchEvent(cancelEvent)",
            "cancelEvent.recycle()",
            "deferRtlPageActivation(",
            '"finger_tap"',
        ),
        "geometry-refresh-safe cached page-activation touch routing",
    )
    touch_up = activation_touch_method.find(
        "if (action == MotionEvent.ACTION_UP)"
    )
    touch_cancel = activation_touch_method.find(
        "cancelNativeFingerTouchStream(activity, event)", touch_up
    )
    touch_activate = activation_touch_method.find(
        "deferRtlPageActivation(", touch_cancel
    )
    touch_swallow = activation_touch_method.find(
        "return true;", touch_activate
    )
    if not 0 <= touch_up < touch_cancel < touch_activate < touch_swallow:
        fail(
            "inactive-page finger activation swallows ACTION_UP without "
            "first cancelling the native child touch stream"
        )
    cancel_helper_start = module.find(
        "private static boolean cancelNativeFingerTouchStream("
    )
    native_chrome_helper_start = module.find(
        "private static void queueLowLatencyLog(", cancel_helper_start
    )
    if cancel_helper_start < 0 or native_chrome_helper_start < 0:
        fail("could not isolate native finger-stream cancellation")
    cancel_helper = module[cancel_helper_start:native_chrome_helper_start]
    child_cancel = cancel_helper.find("superDispatchTouchEvent(")
    child_result = cancel_helper.rfind(
        "boolean childHandled =", 0, child_cancel
    )
    activity_fallback = cancel_helper.find(
        "activity.onTouchEvent(cancelEvent)", child_cancel
    )
    activity_result = cancel_helper.rfind(
        "activityHandled =", child_cancel, activity_fallback
    )
    unhandled_diagnostic = cancel_helper.find(
        '"activation_touch_cancel_delivered_unhandled"', activity_fallback
    )
    return_delivered = cancel_helper.find("return true;", unhandled_diagnostic)
    if not (
        0 <= child_result < child_cancel < activity_result
        < activity_fallback < unhandled_diagnostic < return_delivered
    ):
        fail(
            "synthetic finger CANCEL does not traverse both possible owners "
            "or confuses Android's consumption result with delivery"
        )
    if "return handled;" in cancel_helper:
        fail(
            "synthetic finger CANCEL still mistakes an unconsumed terminal "
            "event for a delivery failure"
        )
    if "activateDocumentPage(" in activation_touch_method:
        fail("inactive-page finger taps can bypass persisted config validation")
    finger_tracking_start = module.find(
        "private static void trackFingerTapNavigation("
    )
    finger_tracking_end = module.find(
        "private static boolean shouldSuppressNonEdgeTapTurn(",
        finger_tracking_start,
    )
    cached_activate_start = module.find(
        "private static void activateDocumentPage(\n"
        "        Activity activity,\n"
        "        int targetPage,\n"
        "        SpreadConfig cachedConfig"
    )
    cached_activate_end = module.find(
        "private static void setReplaceActiveInkMode(", cached_activate_start
    )
    if min(
        finger_tracking_start,
        finger_tracking_end,
        cached_activate_start,
        cached_activate_end,
    ) < 0:
        fail("could not isolate memory-only touch helper chain")
    input_path_helpers = (
        activation_touch_method
        + module[finger_tracking_start:finger_tracking_end]
        + module[cached_activate_start:cached_activate_end]
    )
    helper_blocking_hits = [
        marker
        for marker in (
            "spreadConfig(",
            "FileIdentity.capture(",
            "new File(",
            "Os.stat(",
            "FileInputStream",
            "Properties",
        )
        if marker in input_path_helpers
    ]
    if helper_blocking_hits:
        fail(
            "touch helper chain performs filesystem/config refresh work: "
            f"{helper_blocking_hits}"
        )

    terminal_helper_start = module.find(
        "private static boolean isCompletingActivePageStroke("
    )
    pending_target_start_for_terminal = module.find(
        "private static Integer pendingPageActivationTarget(",
        terminal_helper_start,
    )
    if terminal_helper_start < 0 or pending_target_start_for_terminal < 0:
        fail("could not isolate active-stroke terminal identity helper")
    terminal_helper = module[
        terminal_helper_start:pending_target_start_for_terminal
    ]
    require_markers(
        terminal_helper,
        (
            "pressure != 0",
            "PAGE_ACTIVATION_TRANSACTIONS.get(activity) != null",
            "PEN_CONTACT_START_PAGES.get(activity)",
            "PEN_ACTIVE_STROKE_SOURCE_PAGES.get(activity)",
            "contactStartPage.intValue() == admittedSourcePage.intValue()",
        ),
        "snapshot-independent active-stroke terminal identity",
    )
    if "inputSnapshot" in terminal_helper:
        fail(
            "active-stroke terminal callback still depends on a transient "
            "geometry snapshot"
        )
    clear_contact_start = module.find(
        "private static void clearPenContactStartPage("
    )
    contact_generation_start_for_clear = module.find(
        "private static void notePageActivationTriggerContactLocked(",
        clear_contact_start,
    )
    if clear_contact_start < 0 or contact_generation_start_for_clear < 0:
        fail("could not isolate admitted-stroke identity cleanup")
    if "PEN_ACTIVE_STROKE_SOURCE_PAGES.remove(activity)" not in module[
        clear_contact_start:contact_generation_start_for_clear
    ]:
        fail("pen-up does not clear admitted active-stroke identity")

    digital_lift_start = module.find('"onDigital",', digital_position_start)
    digital_lift_end = module.find(
        "/*", digital_lift_start + len('"onDigital",')
    )
    if digital_lift_start < 0 or digital_lift_end < 0:
        fail("could not isolate pen-lift ownership cleanup")
    digital_lift_hook = module[digital_lift_start:digital_lift_end]
    lift_owner = digital_lift_hook.find(
        "activityForNativeEventCallback("
    )
    lift_generation = digital_lift_hook.find(
        "capturePageActivationPenLiftGeneration(activity)", lift_owner
    )
    lift_fallback = digital_lift_hook.find(
        "schedulePenContactReceiveFallback(", lift_generation
    )
    if not 0 <= lift_owner < lift_generation < lift_fallback:
        fail(
            "pen-up does not preserve the admitted source latch through a "
            "generation-scoped receive fallback"
        )
    if "clearPenContactStartPage(" in digital_lift_hook:
        fail(
            "pen-up clears the admitted source latch before receiveTrials "
            "can validate and persist the completed stroke"
        )

    transaction_start = module.find(
        "private static boolean beginPageActivationTransaction("
    )
    request_load_start = module.find(
        "private static void requestPageActivationLoad(", transaction_start
    )
    if transaction_start < 0 or request_load_start < 0:
        fail("could not isolate page-activation transaction start")
    transaction_start_method = module[transaction_start:request_load_start]
    validated_transaction_start = module.find(
        "private static boolean beginPageActivationTransaction(",
        transaction_start + 1,
    )
    if not transaction_start < validated_transaction_start < request_load_start:
        fail("could not isolate validated page-activation transaction entry")
    activation_request = module[
        transaction_start:validated_transaction_start
    ]
    validated_activation_start = module[
        validated_transaction_start:request_load_start
    ]
    require_markers(
        activation_request,
        (
            "PenInputSnapshot activationSnapshot = penInputSnapshot(activity)",
            "DeferredSpreadTurn pending = DEFERRED_SPREAD_TURNS.get(activity)",
            "pending.config.samePersistedState(",
            "return deferRtlPageActivation(",
        ),
        "persisted-validation activation admission",
    )
    if "null,\n            null" in activation_request:
        fail("an activation request can still bypass persisted config validation")
    require_markers(
        validated_activation_start,
        (
            "persistedConfigGuard == null",
            "persistedValidation == null",
            "!persistedValidation.isCurrent(persistedConfigGuard)",
            "reason=persisted_config_not_validated",
            "persistedValidation.generation",
        ),
        "strict persisted-config transaction authority",
    )
    if "this.persistedConfigValidated = false;" not in module:
        fail("a new activation transaction can begin as config-validated")
    ownership_lock = transaction_start_method.find(
        "synchronized (PAGE_ACTIVATION_OWNERSHIP_LOCK)"
    )
    source_presenter_read = transaction_start_method.find(
        "int sourcePresenterMarkPage = XposedHelpers.getIntField("
    )
    source_presenter_guard = transaction_start_method.find(
        "sourcePresenterMarkPage != sourcePage + 1",
        source_presenter_read,
    )
    active_pen_guard = transaction_start_method.find(
        "!triggerContactObserved", ownership_lock
    )
    active_pen_identity = transaction_start_method.find(
        "PEN_CONTACT_START_PAGES.get(activity) != null",
        active_pen_guard,
    )
    save_in_flight_read = transaction_start_method.find(
        "pageSaveInFlightCountLocked(activity)", active_pen_identity
    )
    save_in_flight_reject = transaction_start_method.find(
        '"page_activation_rejected reason=save_in_flight"',
        save_in_flight_read,
    )
    transaction_lookup = transaction_start_method.find(
        "PageActivationTransaction currentTransaction =", save_in_flight_reject
    )
    if not (
        0 <= source_presenter_read < source_presenter_guard < ownership_lock
        < active_pen_guard
        < active_pen_identity < save_in_flight_read
        < save_in_flight_reject < transaction_lookup
    ):
        fail(
            "activation does not verify source presenter ownership and "
            "atomically reject active pen contact/in-flight native saves "
            "before publishing ownership"
        )
    publish_transaction = transaction_start_method.find(
        "PAGE_ACTIVATION_TRANSACTIONS.put(activity, transaction);",
        transaction_lookup,
    )
    snapshot_withdraw = transaction_start_method.find(
        "PEN_INPUT_SNAPSHOTS.remove(activity, activationSnapshot);",
        publish_transaction,
    )
    editable_guard_publish = transaction_start_method.find(
        "PEN_INPUT_EDITABLE_GUARDS.put(activity, Boolean.TRUE);",
        snapshot_withdraw,
    )
    native_gate_close = transaction_start_method.find(
        "disableNativeGateForOwnershipHandoffLocked(",
        editable_guard_publish,
    )
    source_save_scope = transaction_start_method.find(
        "PageActivationSourceSaveToken sourceSave =",
        native_gate_close,
    )
    source_save_scope_push = transaction_start_method.find(
        "pushPageActivationSourceSaveToken(sourceSave);",
        source_save_scope,
    )
    source_save = transaction_start_method.find(
        '"saveTrails",', source_save_scope_push
    )
    source_save_scope_clear = transaction_start_method.find(
        "popPageActivationSourceSaveToken();", source_save
    )
    source_save_verified = transaction_start_method.find(
        "if (!sourceSave.claimed || !sourceSave.completed",
        source_save_scope_clear,
    )
    writer_disable = transaction_start_method.find(
        '"SN_SPREAD_PROBE transactional page activation"',
        source_save_verified,
    )
    request_target_load = transaction_start_method.find(
        "requestPageActivationLoad(activity, transaction, viewModel);",
        publish_transaction,
    )
    if not (
        0 <= source_presenter_guard < publish_transaction
        < snapshot_withdraw < editable_guard_publish < native_gate_close
        < source_save_scope < source_save_scope_push < source_save
        < source_save_scope_clear < source_save_verified
        < writer_disable < request_target_load
    ):
        fail(
            "ownership transfer must publish the exact input/save guard before "
            "its scoped source flush, disable writing, and load the target"
        )
    activation_snapshot = transaction_start_method.find(
        "PenInputSnapshot activationSnapshot = penInputSnapshot(activity)"
    )
    activation_config = transaction_start_method.find(
        "final SpreadConfig activationConfig = activationSnapshot.config",
        activation_snapshot,
    )
    activation_document_guard = transaction_start_method.find(
        "isCachedSpreadConfigCurrent(", activation_config
    )
    transaction_config_capture = transaction_start_method.find(
        "activationConfig,", activation_document_guard
    )
    if not (
        0 <= activation_snapshot < activation_config
        < activation_document_guard < transaction_config_capture
    ):
        fail(
            "page activation does not capture and validate the exact immutable "
            "document configuration before publishing ownership"
        )

    request_load_end = module.find(
        "private static void schedulePageActivationTimeout(", request_load_start
    )
    if request_load_end < 0:
        fail("could not isolate scoped transactional load request")
    request_load = module[request_load_start:request_load_end]
    require_markers(
        request_load,
        (
            "PAGE_ACTIVATION_LOAD_SCOPE.set(transaction)",
            '"loadPage"',
            "PAGE_ACTIVATION_LOAD_SCOPE.remove()",
        ),
        "transaction-scoped target load generation capture",
    )
    load_identity_start = module.find(
        "private static boolean isPageActivationLoadIdentityCurrent("
    )
    load_identity_end = module.find(
        "private static void releaseActivityResources(", load_identity_start
    )
    if load_identity_start < 0 or load_identity_end < 0:
        fail("could not isolate exact page-activation load identity fence")
    require_markers(
        module[load_identity_start:load_identity_end],
        (
            "transaction.rollbackPending",
            "transaction.sourcePage : transaction.targetPage",
            "PenContactIdentityCapture authority = transaction.writerAuthority",
            "authority.viewModel",
            '"currentPage"',
            "== expectedPage",
            "authority.presenter",
            "== expectedPage + 1",
        ),
        "exact reader/presenter activation and rollback identity fence",
    )
    timeout_end = module.find(
        "private static boolean commitPageActivationGeometry(",
        request_load_end,
    )
    if timeout_end < 0:
        fail("could not isolate transactional activation timeout")
    activation_timeout = module[request_load_end:timeout_end]
    require_markers(
        activation_timeout,
        (
            "transaction.geometryCommitted",
            "!transaction.persistedConfigValidated",
            "transaction.persistedConfigGuard != null",
            "transaction.persistedConfigValidationPending",
            "transaction.triggerContactObserved",
            "!transaction.triggerPenLifted",
            "SystemClock.uptimeMillis()",
            "- transaction.startedAt",
            "PAGE_ACTIVATION_COMPLETION_DEADLINE_MS",
            '"post_commit_guard_timeout"',
            "abortPageActivationTransaction(",
            "schedulePageActivationTimeout(activity, transactionId)",
        ),
        "bounded committed-activation completion timeout",
    )
    completion_deadline = activation_timeout.find(
        "PAGE_ACTIVATION_COMPLETION_DEADLINE_MS"
    )
    completion_reschedule = activation_timeout.find(
        "schedulePageActivationTimeout(activity, transactionId)",
        completion_deadline,
    )
    completion_abort = activation_timeout.find(
        '"post_commit_guard_timeout"', completion_reschedule
    )
    if not 0 <= completion_deadline < completion_reschedule < completion_abort:
        fail(
            "committed activation can reschedule without a finite overall "
            "completion deadline"
        )

    save_hook_start = module.find(
        '"saveTrails",\n            boolean.class,\n            boolean.class,'
    )
    receive_hook_start = module.find(
        '"receiveTrials",', save_hook_start
    )
    if save_hook_start < 0 or receive_hook_start < 0:
        fail("could not isolate saveTrails ownership guard")
    save_hook = module[save_hook_start:receive_hook_start]
    save_owner_resolution = save_hook.find(
        "capturePresenterCallbackScope(param.thisObject)"
    )
    save_owner_activity = save_hook.find(
        "Activity activity = ownerScope.activity;", save_owner_resolution
    )
    save_hook_begin = save_hook.find(
        "beginPageSaveHook(activity);", save_owner_activity
    )
    save_owner_guard = save_hook.find(
        "if (!ownerScope.activeOwner)", save_hook_begin
    )
    save_stale_owner_suppress = save_hook.find(
        "param.setResult(null);", save_owner_guard
    )
    source_save_token = save_hook.find(
        "PageActivationSourceSaveToken sourceToken =",
        save_stale_owner_suppress,
    )
    source_save_exact_owner = save_hook.find(
        "sourceToken.presenter == param.thisObject", source_save_token
    )
    source_save_exact_transaction = save_hook.find(
        "PAGE_ACTIVATION_TRANSACTIONS.get(activity)",
        source_save_exact_owner,
    )
    source_save_unclaimed = save_hook.find(
        "!sourceToken.claimed", source_save_exact_transaction
    )
    source_save_allowed = save_hook.find(
        '"page_activation_source_save_allowed"', source_save_unclaimed
    )
    save_admission = save_hook.find(
        "admitPageSave(", source_save_allowed
    )
    blocked_result = save_hook.find("param.setResult(null);", save_admission)
    save_after = save_hook.find(
        "protected void afterHookedMethod", blocked_result
    )
    save_admission_finish = save_hook.find(
        "finishPageSaveAdmission();", save_after
    )
    if not (
        0 <= save_owner_resolution < save_owner_activity < save_hook_begin
        < save_owner_guard < save_stale_owner_suppress
        < source_save_token < source_save_exact_owner
        < source_save_exact_transaction < source_save_unclaimed
        < source_save_allowed
        < save_admission < blocked_result < save_after
        < save_admission_finish
    ):
        fail(
            "native save admission is not bound to the calling presenter and "
            "paired around every hook call after synthetic bypasses"
        )

    commit_start = module.find(
        "private static boolean commitPageActivationGeometry("
    )
    pen_lift_start = module.find(
        "private static void markPageActivationPenLifted(", commit_start
    )
    if commit_start < 0 or pen_lift_start < 0:
        fail("could not isolate transactional geometry commit")
    commit_method = module[commit_start:pen_lift_start]
    commit_document_identity = commit_method.find(
        "isCachedSpreadConfigCurrent("
    )
    commit_load_identity = commit_method.find(
        "isPageActivationLoadIdentityCurrent(", commit_document_identity
    )
    reader_identity = commit_method.find(
        "currentPage != transaction.targetPage", commit_load_identity
    )
    presenter_identity = commit_method.find(
        "presenterMarkPage != transaction.targetPage + 1",
        reader_identity,
    )
    commit_state = commit_method.find(
        "transaction.geometryCommitted = true;", presenter_identity
    )
    discard_contact = commit_method.find(
        "transaction.triggerContactObserved", commit_state
    )
    retained_writer_disable = commit_method.find(
        '"SN_SPREAD_PROBE discard activation gesture"', discard_contact
    )
    retained_return = commit_method.find(
        "return true;", retained_writer_disable
    )
    persisted_validation_guard = commit_method.find(
        "transaction.persistedConfigGuard != null", retained_return
    )
    persisted_validation_schedule = commit_method.find(
        "schedulePageActivationPersistedConfigValidation(",
        persisted_validation_guard,
    )
    persisted_validation_return = commit_method.find(
        "return scheduled;", persisted_validation_schedule
    )
    if not (
        0 <= commit_document_identity < commit_load_identity < reader_identity
        < presenter_identity < commit_state
        < discard_contact < retained_writer_disable < retained_return
        < persisted_validation_guard < persisted_validation_schedule
        < persisted_validation_return
    ):
        fail(
            "ownership must commit only after reader and presenter identities "
            "match the target, while a concurrently latched contact and final "
            "persisted-config validation remain fail-closed"
        )
    finish_identity_start = module.find(
        "private static boolean finishPageActivationTransaction("
    )
    finish_identity_end = module.find(
        "private static boolean shouldBlockPageActivationGesture(",
        finish_identity_start,
    )
    if finish_identity_start < 0 or finish_identity_end < 0:
        fail("could not isolate final activation identity release")
    require_markers(
        module[finish_identity_start:finish_identity_end],
        (
            "isPageActivationLoadIdentityCurrent(activity, current)",
            "isPageActivationPersistedConfigCurrent(current)",
            "nativeGateAuthorityCurrentForTransactionLocked(",
            "PAGE_ACTIVATION_TRANSACTIONS.remove(",
            "nativeSetCalibrationEnabled(true)",
            "PEN_INPUT_EDITABLE_GUARDS.remove(activity)",
            "spreadPair(",
            "transaction.documentConfig",
        ),
        "final activation identity release",
    )
    if "spreadConfig(" in module[finish_identity_start:finish_identity_end]:
        fail(
            "successful activation commit rereads persisted config on the "
            "main thread instead of reusing its validated transaction config"
        )
    rollback_request_start = module.find(
        "private static void requestPageActivationRollback("
    )
    rollback_retry_start = module.find(
        "private static void schedulePageActivationRollbackRetry(",
        rollback_request_start,
    )
    rollback_finish_start = module.find(
        "private static boolean finishPageActivationRollback(",
        rollback_retry_start,
    )
    rollback_release_start = module.find(
        "private static void releasePageActivationConfigGuard(",
        rollback_finish_start,
    )
    if min(
        rollback_request_start,
        rollback_retry_start,
        rollback_finish_start,
        rollback_release_start,
    ) < 0:
        fail("could not isolate exact-generation rollback fencing")
    require_markers(
        module[rollback_request_start:rollback_retry_start],
        (
            "PAGE_ACTIVATION_LOAD_SCOPE.set(transaction)",
            '"loadPage"',
            "PAGE_ACTIVATION_LOAD_SCOPE.remove()",
        ),
        "transaction-scoped rollback load generation capture",
    )
    require_markers(
        module[rollback_finish_start:rollback_release_start],
        ("isPageActivationLoadIdentityCurrent(activity, current)",),
        "rollback completion load identity",
    )

    restore_geometry_start = module.find(
        "private static boolean restoreTransactionalActivePageGeometry(",
        pen_lift_start,
    )
    if restore_geometry_start < 0:
        fail("could not isolate pen-lift geometry restoration")
    pen_lift_method = module[pen_lift_start:restore_geometry_start]
    lift_ownership_lock = pen_lift_method.find(
        "synchronized (PAGE_ACTIVATION_OWNERSHIP_LOCK)"
    )
    lift_generation_guard = pen_lift_method.find(
        "transaction.triggerContactGeneration",
        lift_ownership_lock,
    )
    lift_expected_generation = pen_lift_method.find(
        "!= expectedContactGeneration", lift_generation_guard
    )
    lift_state_publish = pen_lift_method.find(
        "transaction.triggerPenLifted = true;",
        lift_expected_generation,
    )
    delayed_generation_guard = pen_lift_method.find(
        "current.triggerContactGeneration",
        lift_state_publish,
    )
    if not (
        0 <= lift_ownership_lock < lift_generation_guard
        < lift_expected_generation < lift_state_publish
        < delayed_generation_guard
    ):
        fail(
            "pen-lift publication and settle completion are not bound to "
            "the originating contact generation under the ownership lock"
        )
    lift_restore = pen_lift_method.find(
        "restoreTransactionalActivePageGeometry("
    )
    lift_ready_snapshot = pen_lift_method.find(
        "publishReadyPenInputGeometryAfterActivation(",
        lift_restore,
    )
    lift_config_guard = pen_lift_method.find(
        "current.persistedConfigGuard != null",
        lift_ready_snapshot,
    )
    lift_config_unvalidated = pen_lift_method.find(
        "!current.persistedConfigValidated",
        lift_config_guard,
    )
    lift_config_schedule = pen_lift_method.find(
        "schedulePageActivationPersistedConfigValidation(",
        lift_config_unvalidated,
    )
    lift_config_return = pen_lift_method.find(
        "return;",
        lift_config_schedule,
    )
    lift_guard_release = pen_lift_method.find(
        "finishPageActivationTransaction(",
        lift_config_return,
    )
    if not (
        0 <= lift_restore < lift_ready_snapshot < lift_config_guard
        < lift_config_unvalidated < lift_config_schedule < lift_config_return
        < lift_guard_release
    ):
        fail(
            "trigger-gesture pen lift does not publish ready geometry and "
            "complete deferred persisted-config validation before releasing "
            "ownership"
        )
    for failure_reason in (
        "pen_lift_geometry_failed",
        "pen_lift_snapshot_publish_failed",
        "pen_lift_config_validation_schedule_failed",
        "pen_lift_failed",
    ):
        reason_position = pen_lift_method.find(f'"{failure_reason}"')
        abort_position = pen_lift_method.rfind(
            "abortPageActivationTransaction(",
            0,
            reason_position,
        )
        fail_closed_position = pen_lift_method.rfind(
            "failClosedPageActivation(",
            0,
            reason_position,
        )
        if (
            reason_position < 0
            or abort_position < 0
            or abort_position <= fail_closed_position
            or reason_position - abort_position > 240
            or "true" not in pen_lift_method[
                reason_position:reason_position + 100
            ]
        ):
            fail(
                "pen-lift recovery failure does not abort and roll back its "
                f"retained transaction: {failure_reason}"
            )

    validation_complete_start = module.find(
        "private static void completePageActivationPersistedConfigValidation("
    )
    validation_complete_end = module.find(
        "private static boolean isPageActivationPersistedConfigCurrent(",
        validation_complete_start,
    )
    if validation_complete_start < 0 or validation_complete_end < 0:
        fail("could not isolate persisted-config validation completion")
    validation_complete = module[
        validation_complete_start:validation_complete_end
    ]
    validation_restore = validation_complete.find(
        "restoreTransactionalActivePageGeometry("
    )
    validation_final_identity = validation_complete.find(
        "isPageActivationPersistedConfigAuthorityCurrent(",
        validation_restore,
    )
    validation_ready_publish = validation_complete.find(
        "publishReadyPenInputGeometryAfterActivation(",
        validation_final_identity,
    )
    if not (
        0 <= validation_restore < validation_final_identity
        < validation_ready_publish
    ):
        fail(
            "activation publishes writable geometry without a final persisted "
            "identity validation after native geometry restoration"
        )
    authority_start = module.find(
        "private static boolean isPageActivationPersistedConfigAuthorityCurrent("
    )
    authority_end = module.find(
        "private static void markPageActivationPenLifted(", authority_start
    )
    if authority_start < 0 or authority_end < 0:
        fail("could not isolate final activation config-authority check")
    require_markers(
        module[authority_start:authority_end],
        (
            "persistedSpreadConfigIdentityCurrent(",
            "isPageActivationPersistedConfigCurrent(transaction)",
            "isCachedSpreadConfigCurrent(",
            "PAGE_ACTIVATION_TRANSACTIONS.get(activity) == transaction",
            "!transaction.rollbackPending",
        ),
        "post-geometry persisted config authority revalidation",
    )
    validation_finish = validation_complete.find(
        "if (!finishPageActivationTransaction("
    )
    validation_retain = validation_complete.find(
        "retainPageActivationForHeldContact(",
        validation_finish,
    )
    validation_retained_return = validation_complete.find(
        "return;",
        validation_retain,
    )
    validation_abort = validation_complete.find(
        "abortPageActivationTransaction(",
        validation_retained_return,
    )
    if not (
        0 <= validation_finish < validation_retain
        < validation_retained_return < validation_abort
    ):
        fail(
            "a validated activation raced by held pen contact is rolled back "
            "instead of retaining its transaction through pen lift"
        )

    pen_lift_final_identity = pen_lift_method.find(
        "isPageActivationPersistedConfigAuthorityCurrent(", lift_restore
    )
    if not 0 <= lift_restore < pen_lift_final_identity < lift_ready_snapshot:
        fail(
            "held-contact pen lift can publish writable geometry without "
            "post-restore persisted config revalidation"
        )

    retained_contact_start = module.find(
        "private static boolean retainPageActivationForHeldContact("
    )
    retained_contact_end = module.find(
        "private static boolean restoreTransactionalActivePageGeometry(",
        retained_contact_start,
    )
    if retained_contact_start < 0 or retained_contact_end < 0:
        fail("could not isolate held-contact activation retention")
    require_markers(
        module[retained_contact_start:retained_contact_end],
        (
            "synchronized (PAGE_ACTIVATION_OWNERSHIP_LOCK)",
            "current != transaction",
            "current.rollbackPending",
            "!current.triggerContactObserved",
            "current.triggerPenLifted",
            '"SN_SPREAD_PROBE retained activation contact"',
            '"page_activation_commit_retained_for_contact id="',
        ),
        "held-contact activation retention",
    )

    finish_transaction_start = module.find(
        "private static boolean finishPageActivationTransaction("
    )
    gesture_blocker_start = module.find(
        "private static boolean shouldBlockPageActivationGesture(",
        finish_transaction_start,
    )
    if finish_transaction_start < 0 or gesture_blocker_start < 0:
        fail("could not isolate atomic transaction completion")
    finish_transaction = module[
        finish_transaction_start:gesture_blocker_start
    ]
    finish_lock = finish_transaction.find(
        "synchronized (PAGE_ACTIVATION_OWNERSHIP_LOCK)"
    )
    finish_current = finish_transaction.find(
        "PAGE_ACTIVATION_TRANSACTIONS.get(activity)", finish_lock
    )
    finish_contact = finish_transaction.find(
        "current.triggerContactObserved", finish_current
    )
    finish_lift = finish_transaction.find(
        "!current.triggerPenLifted", finish_contact
    )
    finish_retained = finish_transaction.find(
        "return false;", finish_lift
    )
    finish_remove = finish_transaction.find(
        "PAGE_ACTIVATION_TRANSACTIONS.remove(",
        finish_retained,
    )
    if not (
        0 <= finish_lock < finish_current < finish_contact < finish_lift
        < finish_retained < finish_remove
    ):
        fail(
            "transaction removal is not serialized with contact latching and "
            "revalidated through pen lift"
        )

    save_hook_start_transactional = module.find('"saveTrails",')
    receive_hook_start_transactional = module.find(
        '"receiveTrials",', save_hook_start_transactional
    )
    receive_hook_end_transactional = module.find(
        '"areaSelectionTransition",', receive_hook_start_transactional
    )
    save_hook_end_transactional = receive_hook_start_transactional
    if (
        receive_hook_start_transactional < 0
        or receive_hook_end_transactional < 0
        or save_hook_start_transactional < 0
        or save_hook_end_transactional < 0
    ):
        fail("could not isolate transactional writer guards")
    transaction_receive_hook = module[
        receive_hook_start_transactional:receive_hook_end_transactional
    ]
    transaction_save_hook = module[
        save_hook_start_transactional:save_hook_end_transactional
    ]
    require_markers(
        transaction_receive_hook,
        (
            "ReceiveTrialsScope receiveScope =",
            "pushReceiveTrialsScope(receiveScope)",
            "capturePresenterCallbackScope(param.thisObject)",
            "if (!ownerScope.activeOwner)",
            "shouldBlockPageActivationGesture(activity)",
            "claimBlockedPageActivationContact(",
            "param.setResult(null);",
            "receiveTrialsOwnershipFailure(",
            "receiveScope.ownershipFailure = ownershipFailure",
            "popPresenterCallbackScope(",
            "currentReceiveTrialsScope()",
            "popReceiveTrialsScope()",
            "presenterCallbackScopeStillActive(",
            "PenContactOwnership contactOwnership =",
            "markPageActivationPenLifted(",
            '"page_activation_trigger_gesture_discarded"',
            "clearExactPenContactOwnership(",
            "contactOwnership.phase =",
            "PEN_CONTACT_PHASE_EXPIRED;",
            "PEN_RECEIVE_EXPIRED_GENERATIONS.put(",
            "receive_trials_scope_pop_mismatch",
            "finishTraceMutationAdmission(",
        ),
        "transactional receiveTrials guard",
    )
    receive_scope_lookup = transaction_receive_hook.find(
        "ReceiveTrialsScope receiveScope =\n"
        "                        currentReceiveTrialsScope();"
    )
    receive_active_refresh = transaction_receive_hook.find(
        "persistActiveMutationBeforeCanonicalRefresh(",
        receive_scope_lookup,
    )
    receive_terminal_scope_pop = transaction_receive_hook.find(
        "ReceiveTrialsScope poppedReceiveScope =",
        receive_active_refresh,
    )
    receive_scope_mismatch = transaction_receive_hook.find(
        'log("receive_trials_scope_pop_mismatch")',
        receive_terminal_scope_pop,
    )
    receive_trace_finish = transaction_receive_hook.find(
        "finishTraceMutationAdmission(",
        receive_scope_mismatch,
    )
    if not (
        0 <= receive_scope_lookup < receive_active_refresh
        < receive_terminal_scope_pop < receive_scope_mismatch
        < receive_trace_finish
    ):
        fail(
            "terminal receive ownership is not retained through the exact "
            "active-page canonical save and retired before trace admission"
        )
    receive_scope_helper_start = module.find(
        "private static ReceiveTrialsScope currentReceiveTrialsScope()"
    )
    receive_scope_pop_helper_start = module.find(
        "private static ReceiveTrialsScope popReceiveTrialsScope()",
        receive_scope_helper_start,
    )
    if receive_scope_helper_start < 0 or receive_scope_pop_helper_start < 0:
        fail("could not isolate terminal receive-scope lookup")
    receive_scope_helper = module[
        receive_scope_helper_start:receive_scope_pop_helper_start
    ]
    if (
        "RECEIVE_TRIALS_OWNERSHIP_SCOPES.get()" not in receive_scope_helper
        or "scopes.peek()" not in receive_scope_helper
        or "scopes.pop()" in receive_scope_helper
    ):
        fail("terminal receive-scope lookup can consume or lose ownership")

    # A recognized straight line is a two-stage native edit. Supernote emits
    # receiveTrials() while the pen is still held, then commits the adjusted
    # endpoints through onEditLineTransition(). The spread module must retain
    # exact writer/page/layout authority across that interval, keep the live
    # editor in physical spread coordinates, and publish the canonical reload
    # only after the native commit succeeds.
    trail_hook_start = module.find('"getTrailContainer",')
    trail_hook_end = module.find(
        '"modifyPageTrailsFromFile",', trail_hook_start
    )
    if trail_hook_start < 0 or trail_hook_end < 0:
        fail("could not isolate recognized-line trail classification")
    trail_hook = mask_comments_preserve_literals(
        module[trail_hook_start:trail_hook_end]
    )
    trail_receive_scope = trail_hook.find(
        "ReceiveTrialsScope receiveScope ="
    )
    trail_owner = trail_hook.find("scope.activeOwner", trail_receive_scope)
    trail_current = trail_hook.find(
        "nativeNoteScopeStillActive(", trail_owner
    )
    trail_editable = trail_hook.find(
        "isEditableSpreadLandscape(activity)", trail_current
    )
    trail_classifier = trail_hook.find(
        "containsRecognizedStraightLine(", trail_editable
    )
    trail_classified = trail_hook.find(
        "receiveScope.recognizedStraightLine = true", trail_classifier
    )
    trail_transaction_flag = trail_hook.find(
        "receiveScope.recognizedLineTransactionStarted =",
        trail_classified,
    )
    trail_transaction_begin = trail_hook.find(
        "beginRecognizedLineTransaction(", trail_transaction_flag
    )
    if not (
        0 <= trail_receive_scope < trail_owner < trail_current < trail_editable
        < trail_classifier < trail_classified < trail_transaction_flag
        < trail_transaction_begin
    ):
        fail(
            "recognized-line classification can escape the exact active "
            "receive/note/editable authority or fail to start its transaction"
        )

    receive_masked = mask_comments_preserve_literals(transaction_receive_hook)
    recognized_condition = receive_masked.find(
        "receiveScope.recognizedStraightLine"
    )
    recognized_open = receive_masked.find("{", recognized_condition)
    if recognized_condition < 0 or recognized_open < 0:
        fail("receiveTrials lacks an exact recognized-line deferred branch")
    recognized_close = matching_brace(
        receive_masked,
        recognized_open,
        "recognized-line receive branch",
    )
    recognized_branch = receive_masked[recognized_open:recognized_close + 1]
    recognized_deferred = recognized_branch.find(
        '"recognized_line_canonical_reload_deferred"'
    )
    if recognized_deferred < 0:
        fail("recognized-line receive branch does not record its deferred reload")
    if (
        "persistActiveMutationBeforeCanonicalRefresh(" in recognized_branch
        or "beginRecognizedLineTransaction(" in recognized_branch
    ):
        fail(
            "recognized-line receive branch can save/reload or begin authority "
            "after Supernote has already entered its live editor"
        )
    recognized_else = receive_masked.find("else", recognized_close)
    ordinary_retire = receive_masked.find(
        "retireAbandonedRecognizedLineTransaction(", recognized_else
    )
    ordinary_persist = receive_masked.find(
        "persistActiveMutationBeforeCanonicalRefresh(", ordinary_retire
    )
    if not (
        recognized_close < recognized_else < ordinary_retire < ordinary_persist
    ):
        fail(
            "ordinary receiveTrials mutations no longer retire stale line "
            "authority before their canonical save/reload"
        )

    editor_hook_start = module.find('"onEditLineMode",', receive_hook_start_transactional)
    line_commit_hook_start = module.find(
        '"onEditLineTransition",', editor_hook_start
    )
    line_commit_hook_end = module.find(
        '"areaSelectionTransition",', line_commit_hook_start
    )
    if (
        editor_hook_start < 0
        or line_commit_hook_start < 0
        or line_commit_hook_end < 0
    ):
        fail("could not isolate recognized-line editor/commit hooks")
    editor_hook = mask_comments_preserve_literals(
        module[editor_hook_start:line_commit_hook_start]
    )
    editor_landscape_gate = editor_hook.find(
        "!isEditableSpreadLandscape(activity)"
    )
    editor_receive_scope = editor_hook.find(
        "ReceiveTrialsScope receiveScope =", editor_landscape_gate
    )
    editor_recognized = editor_hook.find(
        "receiveScope.recognizedStraightLine", editor_receive_scope
    )
    editor_started = editor_hook.find(
        "receiveScope.recognizedLineTransactionStarted", editor_recognized
    )
    editor_transaction_present = editor_hook.find(
        "transaction != null", editor_started
    )
    editor_authority = editor_hook.find(
        "recognizedLineTransactionCurrent(", editor_transaction_present
    )
    editor_admission_block = editor_hook.find(
        "if (!admitted)", editor_authority
    )
    editor_admission_retire = editor_hook.find(
        "RECOGNIZED_LINE_TRANSACTIONS.remove(", editor_admission_block
    )
    editor_admission_result = editor_hook.find(
        "param.setResult(null);", editor_admission_retire
    )
    editor_points = editor_hook.find(
        "mapRecognizedLinePointsToSpread(", editor_admission_result
    )
    editor_layers = editor_hook.find(
        "mapRecognizedLineLayerPointsToSpread(", editor_points
    )
    editor_invalid = editor_hook.find(
        "if (displayPoints == null || displayPoints.size() != 2",
        editor_layers,
    )
    editor_retire = editor_hook.find(
        "RECOGNIZED_LINE_TRANSACTIONS.remove(", editor_invalid
    )
    editor_block = editor_hook.find("param.setResult(null);", editor_retire)
    editor_points_publish = editor_hook.find(
        "param.args[0] = displayPoints", editor_block
    )
    editor_layers_publish = editor_hook.find(
        "param.args[1] = displayLayerPoints", editor_points_publish
    )
    editor_width = editor_hook.find(
        "param.args[4] = Math.max(1, handWriteView.getWidth())",
        editor_layers_publish,
    )
    editor_height = editor_hook.find(
        "param.args[5] = Math.max(1, handWriteView.getHeight())",
        editor_width,
    )
    if not (
        0 <= editor_landscape_gate < editor_receive_scope < editor_recognized
        < editor_started < editor_transaction_present < editor_authority
        < editor_admission_block < editor_admission_retire
        < editor_admission_result < editor_points < editor_layers < editor_invalid
        < editor_retire < editor_block < editor_points_publish
        < editor_layers_publish < editor_width < editor_height
    ):
        fail(
            "recognized-line editor can run without exact receive/transaction "
            "authority or is not mapped into the active spread destination "
            "before Supernote displays it"
        )
    if "if (!recognizedLineTransactionCurrent(" in editor_hook:
        fail(
            "recognized-line editor still returns to the unsafe native editor "
            "when its transaction authority is stale"
        )
    if '"setEditLineViewOnTouchEvent"' in module:
        fail(
            "recognized-line support still rewrites raw stylus events instead "
            "of mapping the bounded native editor transaction"
        )

    line_commit_hook = mask_comments_preserve_literals(
        module[line_commit_hook_start:line_commit_hook_end]
    )
    commit_missing_transaction = line_commit_hook.find(
        "boolean editableSpreadWithoutTransaction ="
    )
    commit_missing_landscape = line_commit_hook.find(
        "isEditableSpreadLandscape(activity)", commit_missing_transaction
    )
    commit_missing_null = line_commit_hook.find(
        "transaction == null", commit_missing_landscape
    )
    commit_authority = line_commit_hook.find(
        "recognizedLineTransactionCurrent(", commit_missing_null
    )
    commit_presenter = line_commit_hook.find(
        "transaction.presenter == param.thisObject", commit_authority
    )
    commit_geometry = line_commit_hook.find(
        "mapRecognizedLinePointsToNative(", commit_presenter
    )
    commit_geometry_guard = line_commit_hook.find(
        "if (nativePoints == null", commit_geometry
    )
    commit_geometry_publish = line_commit_hook.find(
        "param.args[3] = nativePoints", commit_geometry_guard
    )
    commit_scope = line_commit_hook.find(
        "pushRecognizedLineCommitScope(", commit_geometry_publish
    )
    commit_missing_block = line_commit_hook.find(
        "if (editableSpreadWithoutTransaction", commit_scope
    )
    commit_block = line_commit_hook.find(
        "param.setResult(null);", commit_missing_block
    )
    commit_throwable = line_commit_hook.find(
        "if (param.getThrowable() != null)", commit_block
    )
    commit_revalidate = line_commit_hook.find(
        "if (!recognizedLineTransactionCurrent(", commit_throwable
    )
    commit_persist = line_commit_hook.find(
        "persistActiveMutationBeforeCanonicalRefresh(", commit_revalidate
    )
    commit_finally = line_commit_hook.find("finally", commit_persist)
    commit_retire = line_commit_hook.find(
        "RECOGNIZED_LINE_TRANSACTIONS.remove(", commit_finally
    )
    if not (
        0 <= commit_missing_transaction < commit_missing_landscape
        < commit_missing_null < commit_authority < commit_presenter < commit_geometry
        < commit_geometry_guard < commit_geometry_publish < commit_scope
        < commit_missing_block < commit_block < commit_throwable
        < commit_revalidate < commit_persist
        < commit_finally < commit_retire
    ):
        fail(
            "recognized-line commit can run without a transaction, publish "
            "invalid geometry, skip its post-commit authority check, save "
            "early, or leak authority"
        )

    point_to_spread, point_to_spread_masked = extract_cpp_function(
        module,
        "private static Point mapRecognizedLinePointToSpread(",
        "recognized-line display point mapper",
    )
    points_to_native, points_to_native_masked = extract_cpp_function(
        module,
        "private static List<Point> mapRecognizedLinePointsToNative(",
        "recognized-line native point mapper",
    )
    require_markers(
        point_to_spread_masked,
        (
            "nativePoint.x + transaction.nativeSplitOffsetX",
            "nativePoint.y + transaction.nativeSplitOffsetY",
            "destination.left",
            "destination.top",
            "CANONICAL_PAGE_WIDTH",
            "CANONICAL_PAGE_HEIGHT",
        ),
        "recognized-line display point mapper",
    )
    require_markers(
        points_to_native_masked,
        (
            "source.size() != 2",
            "displayPoint.x - destination.left",
            "displayPoint.y - destination.top",
            "canonicalX - transaction.nativeSplitOffsetX",
            "canonicalY - transaction.nativeSplitOffsetY",
        ),
        "recognized-line native point mapper",
    )
    line_begin, _ = extract_cpp_function(
        module,
        "private static boolean beginRecognizedLineTransaction(",
        "recognized-line authority publisher",
    )
    line_current, _ = extract_cpp_function(
        module,
        "private static boolean recognizedLineTransactionCurrent(",
        "recognized-line authority validator",
    )
    line_begin_masked = mask_comments_preserve_literals(line_begin)
    line_current_masked = mask_comments_preserve_literals(line_current)
    require_markers(
        line_begin_masked,
        (
            'getDeclaredField("isSplit")',
            '"getShowRectOffset"',
            "contact.phase != PEN_CONTACT_PHASE_RECEIVING",
            "PEN_CONTACT_OWNERSHIPS.get(activity) != contact",
            "DOCUMENT_CONTEXT_GENERATIONS.get(activity)",
            "CONFIG_AUTHORITY_GENERATIONS.get(activity)",
            "RECOGNIZED_LINE_TRANSACTIONS.put(activity, transaction)",
        ),
        "recognized-line authority publisher",
    )
    require_markers(
        line_current_masked,
        (
            "RECOGNIZED_LINE_TRANSACTIONS.get(activity) != transaction",
            "documentMutationAuthorityCurrent(",
            'getDeclaredField("isSplit")',
            '"getShowRectOffset"',
            "activePageDestination(activity)",
            "transaction.documentContextGeneration",
            "transaction.configAuthorityGeneration",
            "transaction.markPath",
            "transaction.documentPage",
            "transaction.markPage",
        ),
        "recognized-line authority validator",
    )
    require_markers(
        module,
        (
            'retireAbandonedRecognizedLineTransaction(\n'
            '            activity,\n'
            '            "activity_release"',
            '"editing_reset_" + reason',
            '"onEditLineTransition", "areaSelectionTransition"',
            '"setBitmap", "showAreaSelection",\n'
            '                "onEditLineMode"',
        ),
        "recognized-line lifecycle cleanup/barriers",
    )

    require_markers(
        transaction_save_hook,
        (
            "capturePresenterCallbackScope(param.thisObject)",
            "if (!ownerScope.activeOwner)",
            "beginPageSaveHook(activity)",
            "admitPageSave(",
            "param.setResult(null);",
            '"page_activation_save_blocked id="',
            "finishPageSaveAdmission()",
        ),
        "transactional saveTrails guard",
    )
    save_blocker_start = module.find(
        "private static void beginPageSaveHook("
    )
    abort_transaction_start = module.find(
        "private static void abortPageActivationTransaction(",
        save_blocker_start,
    )
    if save_blocker_start < 0 or abort_transaction_start < 0:
        fail("could not isolate atomic native-save admission")
    save_blocker = module[save_blocker_start:abort_transaction_start]
    require_markers(
        save_blocker,
        (
            "ArrayDeque<PageSaveAdmission>",
            "synchronized (PAGE_ACTIVATION_OWNERSHIP_LOCK)",
            "PageActivationTransaction transaction =",
            "!activationSourceSave",
            "PAGE_ACTIVATION_ROLLBACK_RECOVERIES.get(activity) != null",
            "|| rollbackOwnershipUncertain",
            "PAGE_SAVE_IN_FLIGHT_COUNTS.get(activity)",
            "inFlight.incrementAndGet()",
            "admission.counted = true",
            "admissions.pop()",
            "inFlight.decrementAndGet()",
        ),
        "atomic native-save admission and release",
    )
    rollback_save_guard = save_blocker.find(
        "PAGE_ACTIVATION_ROLLBACK_RECOVERIES.get(activity) != null"
    )
    save_count_increment = save_blocker.find(
        "inFlight.incrementAndGet()", rollback_save_guard
    )
    if not 0 <= rollback_save_guard < save_count_increment:
        fail(
            "rollback-recovery ownership does not fence lifecycle saves before "
            "their admission"
        )
    presenter_owner_start = module.find(
        "private static Activity activityForHandWritePresenter("
    )
    release_resources_start = module.find(
        "private static void releaseActivityResources(",
        presenter_owner_start,
    )
    if presenter_owner_start < 0 or release_resources_start < 0:
        fail("could not isolate exact presenter/activity save ownership")
    require_markers(
        module[presenter_owner_start:release_resources_start],
        (
            "Activity candidate = activeActivity;",
            "refreshActivityComponentBindings(candidate);",
            "synchronized (PAGE_ACTIVATION_OWNERSHIP_LOCK)",
            "candidate == activeActivity",
            "HANDWRITE_PRESENTERS.get(candidate) == presenter",
            "!RETIRED_HANDWRITE_PRESENTERS.containsKey(presenter)",
            '"handWritePresenter"',
            ") == presenter",
        ),
        "identity-verified presenter/activity save ownership",
    )
    require_markers(
        module,
        (
            "bindingsReady = refreshActivityComponentBindings(",
            "bindComponentIdentity(",
            "HANDWRITE_PRESENTERS,",
            "RETIRED_HANDWRITE_PRESENTERS,",
            "retireActivityComponentIdentity(",
        ),
        "presenter/activity ownership lifecycle",
    )
    forbidden_save_waits = (
        "Thread.sleep(",
        ".wait(",
        "SystemClock.sleep(",
    )
    if any(marker in save_blocker for marker in forbidden_save_waits):
        fail("save/activation ownership fencing blocks while waiting for a save")

    rollback_request_start = module.find(
        "private static void requestPageActivationRollback(",
        abort_transaction_start,
    )
    rollback_retry_start = module.find(
        "private static void schedulePageActivationRollbackRetry(",
        rollback_request_start,
    )
    rollback_timeout_start = module.find(
        "private static void schedulePageActivationRollbackTimeout(",
        rollback_retry_start,
    )
    rollback_terminal_start = module.find(
        "private static void releaseFailedPageActivationRollback(",
        rollback_timeout_start,
    )
    rollback_finish_start = module.find(
        "private static boolean finishPageActivationRollback(",
        rollback_terminal_start,
    )
    rollback_guard_release_start = module.find(
        "private static void releasePageActivationConfigGuard(",
        rollback_finish_start,
    )
    fail_closed_start = module.find(
        "private static boolean failClosedPageActivation(",
        rollback_finish_start,
    )
    if any(
        position < 0
        for position in (
            rollback_request_start,
            rollback_retry_start,
            rollback_timeout_start,
            rollback_terminal_start,
            rollback_finish_start,
            rollback_guard_release_start,
            fail_closed_start,
        )
    ):
        fail("could not isolate page-activation rollback")
    abort_transaction = module[abort_transaction_start:rollback_request_start]
    request_rollback = module[rollback_request_start:rollback_retry_start]
    retry_rollback = module[rollback_retry_start:rollback_timeout_start]
    timeout_rollback = module[rollback_timeout_start:rollback_terminal_start]
    terminal_rollback = module[rollback_terminal_start:rollback_finish_start]
    finish_rollback = module[
        rollback_finish_start:rollback_guard_release_start
    ]
    retained_transaction = abort_transaction.find(
        "PAGE_ACTIVATION_TRANSACTIONS.get(activity)"
    )
    rollback_published = abort_transaction.find(
        "transaction.rollbackPending = true;",
        retained_transaction,
    )
    rollback_request = abort_transaction.find("requestPageActivationRollback(")
    if not (
        0 <= retained_transaction < rollback_published < rollback_request
    ):
        fail(
            "page-activation rollback is not published before source recovery"
        )
    require_markers(
        request_rollback,
        (
            "current != transaction",
            "PAGE_ACTIVATION_ROLLBACK_MAX_ATTEMPTS",
            "++transaction.rollbackAttempts",
            '"loadPage"',
            "schedulePageActivationRollbackTimeout(",
            "schedulePageActivationRollbackRetry(",
        ),
        "bounded exact-transaction page-activation rollback request",
    )
    if "PAGE_ACTIVATION_TRANSACTIONS.remove(" in request_rollback:
        fail("rollback load request releases its save guard before convergence")
    require_markers(
        retry_rollback,
        (
            "current != transaction",
            "PAGE_ACTIVATION_ROLLBACK_MAX_ATTEMPTS",
            "releaseFailedPageActivationRollback(",
            "requestPageActivationRollback(",
            "PAGE_ACTIVATION_ROLLBACK_RETRY_MS",
        ),
        "bounded page-activation rollback retry",
    )
    require_markers(
        timeout_rollback,
        (
            "current != transaction",
            "finishPageActivationRollbackIfConverged(",
            "PAGE_ACTIVATION_ROLLBACK_MAX_ATTEMPTS",
            "requestPageActivationRollback(",
            "releaseFailedPageActivationRollback(",
            "PAGE_ACTIVATION_TIMEOUT_MS",
        ),
        "rollback convergence timeout",
    )
    terminal_fail_closed = terminal_rollback.find(
        "failClosedPageActivation(activity, reason)"
    )
    terminal_snapshot_invalidation = terminal_rollback.find(
        "invalidatePenInputGeometrySnapshot(",
        terminal_fail_closed,
    )
    terminal_recovery_publish = terminal_rollback.find(
        "PAGE_ACTIVATION_ROLLBACK_RECOVERIES.put(",
        terminal_snapshot_invalidation,
    )
    terminal_pen_guard = terminal_rollback.find(
        "PEN_INPUT_EDITABLE_GUARDS.put(activity, Boolean.TRUE)",
        terminal_recovery_publish,
    )
    terminal_recovery_verify = terminal_rollback.find(
        "PAGE_ACTIVATION_ROLLBACK_RECOVERIES.get(activity)",
        terminal_pen_guard,
    )
    terminal_remove = terminal_rollback.find(
        "PAGE_ACTIVATION_TRANSACTIONS.remove(",
        terminal_recovery_verify,
    )
    if not (
        0 <= terminal_fail_closed
        < terminal_snapshot_invalidation
        < terminal_recovery_publish < terminal_pen_guard
        < terminal_recovery_verify < terminal_remove
    ):
        fail(
            "exhausted rollback does not atomically publish and verify its "
            "navigation-recovery authority before withdrawing the transaction"
        )
    require_markers(
        terminal_rollback,
        (
            "current != transaction",
            "PAGE_ACTIVATION_OWNERSHIP_LOCK",
            "transaction.documentConfig.sameDocumentIdentity(",
            "recoveryConfig",
            "NAVIGATION_FAIL_CLOSED_DOCUMENTS.put(",
            '"page_activation_rollback_released_fail_closed id="',
        ),
        "terminal fail-closed rollback release",
    )
    require_markers(
        finish_rollback,
        (
            "current.rollbackPending",
            "PAGE_ACTIVATION_TRANSACTIONS.remove(activity, current)",
            '"page_activation_rollback_completed id="',
            "return true;",
        ),
        "identity-verified, geometry-rearming rollback completion",
    )
    if '"disableHandWrite"' in finish_rollback:
        fail(
            "verified source rollback disables the writer after compose has "
            "already re-armed its geometry"
        )

    portrait_set_image = module.find(
        "if (!isCalibrationLandscape(activity)) {",
        module.find('"setImage",'),
    )
    portrait_rollback_completion = module.find(
        "finishPageActivationRollbackIfConverged(",
        portrait_set_image,
    )
    portrait_return = module.find("return;", portrait_rollback_completion)
    if not (
        0 <= portrait_set_image < portrait_rollback_completion < portrait_return
    ):
        fail(
            "portrait setImage does not complete an identity-converged rollback"
        )

    converged_start = module.find(
        "private static boolean finishPageActivationRollbackIfConverged("
    )
    fail_closed_start = module.find(
        "private static boolean failClosedPageActivation(",
        converged_start,
    )
    if converged_start < 0 or fail_closed_start < 0:
        fail("could not isolate orientation-independent rollback completion")
    converged_rollback = module[converged_start:fail_closed_start]
    require_markers(
        converged_rollback,
        (
            "readerPage != transaction.sourcePage",
            "presenterMarkPage != transaction.sourcePage + 1",
            "Configuration.ORIENTATION_LANDSCAPE",
            "PAGE_ACTIVATION_TRANSACTIONS.remove(",
            "releasePageActivationConfigGuard(transaction)",
            '"page_activation_rollback_completed_native_layout id="',
            '"page_activation_rollback_waiting_for_geometry id="',
        ),
        "orientation-independent rollback identity convergence",
    )
    native_layout_release = converged_rollback.find(
        "PAGE_ACTIVATION_TRANSACTIONS.remove("
    )
    landscape_wait = converged_rollback.find(
        '"page_activation_rollback_waiting_for_geometry id="',
        native_layout_release,
    )
    if not 0 <= native_layout_release < landscape_wait:
        fail(
            "landscape rollback can release before verified compose geometry, "
            "or native-layout rollback cannot recover"
        )

    configuration_hook_start = module.find('"onConfigurationChanged",')
    set_image_hook_start = module.find('"setImage",', configuration_hook_start)
    if configuration_hook_start < 0 or set_image_hook_start < 0:
        fail("could not isolate orientation-change rollback handling")
    configuration_hook = module[
        configuration_hook_start:set_image_hook_start
    ]
    require_markers(
        configuration_hook,
        (
            "configuration.orientation",
            "Configuration.ORIENTATION_LANDSCAPE",
            "PAGE_ACTIVATION_TRANSACTIONS.get(activity) != null",
            "abortPageActivationTransaction(",
            '"orientation_changed"',
            "true",
        ),
        "orientation-change source rollback",
    )

    pen_activation_start = module.find(
        "private static void handlePenPageActivation("
    )
    intercept_activation_start = module.find(
        "private static boolean interceptPenPageActivation(",
        pen_activation_start,
    )
    if pen_activation_start < 0 or intercept_activation_start < 0:
        fail("could not isolate spread-inactive pen rollback")
    pen_activation = module[pen_activation_start:intercept_activation_start]
    spread_inactive = pen_activation.find('"pen_snapshot_stale"')
    restore_source = pen_activation.find("true", spread_inactive)
    if not 0 <= spread_inactive < restore_source:
        fail("stale-snapshot pen handling does not restore the source page")

    begin_transaction_start = module.find(
        "private static boolean beginPageActivationTransaction("
    )
    request_load_start = module.find(
        "private static void requestPageActivationLoad(",
        begin_transaction_start,
    )
    if begin_transaction_start < 0 or request_load_start < 0:
        fail("could not isolate page-activation start failure handling")
    begin_transaction = module[begin_transaction_start:request_load_start]
    start_failure = begin_transaction.find(
        '"page_activation_start_failed target="'
    )
    guarded_start_failure = begin_transaction.find(
        "PAGE_ACTIVATION_TRANSACTIONS.get(activity) == transaction",
        start_failure,
    )
    start_failure_abort = begin_transaction.find(
        "abortPageActivationTransaction(",
        guarded_start_failure,
    )
    start_failure_restore = begin_transaction.find(
        "true",
        start_failure_abort,
    )
    start_failure_handled = begin_transaction.find(
        "return ownershipAcquired;",
        start_failure_restore,
    )
    if not (
        0 <= start_failure < guarded_start_failure
        < start_failure_abort < start_failure_restore
        < start_failure_handled
    ):
        fail(
            "partial activation-start failure does not roll back to source "
            "and suppress the legacy target-page fallback"
        )
    if "boolean ownershipAcquired = transaction != null;" not in begin_transaction:
        fail("activation-start failure does not remember acquired ownership")
    if begin_transaction.find(
        "PAGE_ACTIVATION_TRANSACTIONS.remove(activity)",
        start_failure,
    ) >= 0:
        fail("activation-start failure drops its guard before rollback")

    deferred_turn_start = module.find(
        "private static boolean deferRtlSpreadTurn("
    )
    deferred_turn_schedule_start = module.find(
        "private static void scheduleDeferredRtlSpreadTurn(",
        deferred_turn_start,
    )
    rtl_turn_start = module.find(
        "private static boolean handleRtlSpreadTurn(",
        deferred_turn_schedule_start,
    )
    activate_page_start = module.find(
        "private static void activateDocumentPage(",
        rtl_turn_start,
    )
    if any(
        position < 0
        for position in (
            deferred_turn_start,
            deferred_turn_schedule_start,
            rtl_turn_start,
            activate_page_start,
        )
    ):
        fail("could not isolate rejected RTL spread-turn preservation")
    deferred_turn = module[
        deferred_turn_start:deferred_turn_schedule_start
    ]
    deferred_turn_schedule = module[
        deferred_turn_schedule_start:rtl_turn_start
    ]
    rtl_turn = module[rtl_turn_start:activate_page_start]
    rtl_turn_config = rtl_turn.find(
        "SpreadConfig config\n    )"
    )
    rtl_turn_config_stop = rtl_turn.find(
        "config == null || !config.enabled", rtl_turn_config
    )
    rtl_turn_pair = rtl_turn.find(
        "SpreadPair pair = spreadPair(config", rtl_turn_config_stop
    )
    if not 0 <= rtl_turn_config < rtl_turn_config_stop < rtl_turn_pair:
        fail(
            "RTL turn routing consumes fallback/default cover parity after "
            "config publication fails"
        )
    if "spreadConfig(activity)" in rtl_turn:
        fail("RTL turn routing reparses persisted config after admission")
    require_markers(
        deferred_turn,
        (
            "deferRtlPageActivation(",
            "DEFERRED_SPREAD_TURN_COUNTER.incrementAndGet()",
            "new DeferredSpreadTurn(",
            "config,",
            "trigger",
            '"deferred_spread_turn".equals(trigger)',
            "Boolean.valueOf(config.coverSeparate)",
            "DEFERRED_SPREAD_TURNS.put(",
            "scheduleDeferredRtlSpreadTurn(activity, deferred)",
        ),
        "rejected RTL spread-turn publication",
    )
    require_markers(
        deferred_turn_schedule,
        (
            "current != deferred",
            "deferred.documentPath.equals(",
            "currentDocumentPath(activity)",
            "DEFERRED_CONFIG_EXECUTOR.schedule(",
            "validateDeferredConfig(deferred)",
            "runDeferredRtlSpreadTurnRetry(",
            "!persistedValidation.isCurrent(deferred)",
            'reason=persisted_config_generation_changed',
            'reason=persisted_config_generation_raced',
            'persisted_config_changed_during_start',
            "!deferred.config.samePersistedState(",
            'reason=runtime_config_changed',
            "!publishedConfig.enabled || !publishedConfig.editable",
            'reason=editing_disabled',
            "deferred.coverSeparate != null",
            "publishedConfig.coverSeparate",
            'reason=cover_parity_changed',
            "currentPage == deferred.targetPage",
            "currentPage != deferred.sourcePage",
            "editablePenInputReady(activity)",
            "beginPageActivationTransaction(",
            "persistedValidation",
            "transferDeferredSpreadTurnToActivation(",
            "deferred.trigger",
            "scheduleDeferredRtlSpreadTurn(activity, deferred)",
        ),
        "exact-context deferred RTL spread-turn replay",
    )
    parity_guard = deferred_turn_schedule.find(
        "if (deferred.coverSeparate != null"
    )
    persisted_guard = deferred_turn_schedule.find(
        "!persistedValidation.isCurrent(deferred)"
    )
    persisted_cancel = deferred_turn_schedule.find(
        'reason=persisted_config_generation_changed', persisted_guard
    )
    runtime_config_guard = deferred_turn_schedule.find(
        "!deferred.config.samePersistedState(", persisted_cancel
    )
    runtime_config_cancel = deferred_turn_schedule.find(
        'reason=runtime_config_changed', runtime_config_guard
    )
    editable_guard = deferred_turn_schedule.find(
        "!publishedConfig.enabled || !publishedConfig.editable",
        runtime_config_cancel,
    )
    editable_cancel = deferred_turn_schedule.find(
        'reason=editing_disabled',
        editable_guard,
    )
    parity_compare = deferred_turn_schedule.find(
        "publishedConfig.coverSeparate",
        parity_guard,
    )
    parity_cancel = deferred_turn_schedule.find(
        'reason=cover_parity_changed',
        parity_compare,
    )
    target_satisfied = deferred_turn_schedule.find(
        "currentPage == deferred.targetPage",
        parity_cancel,
    )
    final_generation_guard = deferred_turn_schedule.find(
        "!persistedValidation.isCurrent(deferred)",
        target_satisfied,
    )
    final_generation_cancel = deferred_turn_schedule.find(
        'reason=persisted_config_generation_raced',
        final_generation_guard,
    )
    activation_start = deferred_turn_schedule.find(
        "beginPageActivationTransaction(",
        final_generation_cancel,
    )
    post_start_generation_guard = deferred_turn_schedule.find(
        "!persistedValidation.isCurrent(deferred)",
        activation_start,
    )
    changed_start_abort = deferred_turn_schedule.find(
        '"persisted_config_changed_during_start"',
        post_start_generation_guard,
    )
    if not (
        0 <= persisted_guard < persisted_cancel < runtime_config_guard
        < runtime_config_cancel < editable_guard < editable_cancel < parity_guard
        < parity_compare < parity_cancel < target_satisfied
        < final_generation_guard < final_generation_cancel < activation_start
        < post_start_generation_guard < changed_start_abort
    ):
        fail(
            "deferred activation can replay before persisted identity, runtime "
            "editable, or cover-parity revalidation"
        )

    persisted_config_start = deferred_turn_schedule.find(
        "private static boolean persistedDeferredConfigUnchanged("
    )
    deferred_retry_start = deferred_turn_schedule.find(
        "private static void runDeferredRtlSpreadTurnRetry("
    )
    if persisted_config_start < 0 or deferred_retry_start < 0:
        fail("could not isolate asynchronous deferred-config validation")
    deferred_schedule_method = deferred_turn_schedule[
        :persisted_config_start
    ]
    persisted_config_method = deferred_turn_schedule[
        persisted_config_start:deferred_retry_start
    ]
    deferred_retry_method = deferred_turn_schedule[deferred_retry_start:]
    require_markers(
        deferred_schedule_method,
        (
            "DEFERRED_CONFIG_EXECUTOR.schedule(",
            "validateDeferredConfig(deferred)",
            "new Handler(activity.getMainLooper()).post(",
            "runDeferredRtlSpreadTurnRetry(",
        ),
        "off-UI deferred-config validation",
    )
    observer_start = module.find(
        "private static boolean ensureDeferredConfigWatch(",
        deferred_turn_start,
    )
    if observer_start < 0 or observer_start >= deferred_turn_schedule_start:
        fail("could not isolate deferred-config change-generation fence")
    deferred_config_fence = module[
        observer_start:deferred_turn_schedule_start
    ]
    require_markers(
        deferred_config_fence,
        (
            "if (deferred.canceled)",
            "ensurePersistedConfigWatch(activity, deferred.config)",
            "PERSISTED_CONFIG_WATCHES.get(activity)",
            "deferred.persistedConfigWatch = watch",
            "deferred.persistedConfigWatchReady = true",
            "isDeferredConfigWatchCurrent(",
            "watch.generation.get()",
            "handleDeferredConfigWatchEvent(",
            "deferred.canceled = true;",
            "if (deferred == null || deferred.canceled",
            "long before = watch == null ? 0L : watch.generation.get()",
            "persistedDeferredConfigUnchanged(deferred)",
            "unchanged && before == after",
        ),
        "shared persisted-config change-generation fence",
    )
    if "volatile boolean canceled;" not in module:
        fail("deferred activation has no terminal canceled state")
    ensure_observer = deferred_config_fence.find(
        "private static boolean ensureDeferredConfigWatch("
    )
    canceled_admission = deferred_config_fence.find(
        "if (deferred.canceled)", ensure_observer
    )
    persisted_watch_ensure = deferred_config_fence.find(
        "ensurePersistedConfigWatch(activity, deferred.config)",
        canceled_admission,
    )
    observer_stop = deferred_config_fence.find(
        "private static void releaseDeferredConfigWatch(",
        persisted_watch_ensure,
    )
    canceled_publish = deferred_config_fence.find(
        "deferred.canceled = true;", observer_stop
    )
    validation_start = deferred_config_fence.find(
        "private static DeferredConfigValidation validateDeferredConfig(",
        canceled_publish,
    )
    canceled_validation = deferred_config_fence.find(
        "deferred == null || deferred.canceled", validation_start
    )
    validation_observer_ensure = deferred_config_fence.find(
        "ensureDeferredConfigWatch(deferred)", canceled_validation
    )
    if not (
        0 <= ensure_observer < canceled_admission < persisted_watch_ensure
        < observer_stop < canceled_publish < validation_start
        < canceled_validation < validation_observer_ensure
    ):
        fail(
            "canceled deferred activation can rebind its persisted config watch"
        )
    deferred_watch_method_end = deferred_config_fence.find(
        "private static boolean isDeferredConfigWatchCurrent(",
        ensure_observer,
    )
    if deferred_watch_method_end < 0:
        fail("could not isolate shared deferred-config watch binding")
    deferred_watch_method = deferred_config_fence[
        ensure_observer:deferred_watch_method_end
    ]
    for forbidden in (
        "new FileObserver(",
        ".startWatching()",
        ".stopWatching()",
    ):
        if forbidden in deferred_watch_method:
            fail(
                "deferred activation creates or owns a duplicate persisted-config "
                f"observer: {forbidden}"
            )
    require_markers(
        module,
        (
            "final DeferredSpreadTurn persistedConfigGuard;",
            "final long persistedConfigGeneration;",
            "volatile PersistedConfigWatch persistedConfigWatch;",
            "volatile boolean persistedConfigWatchReady;",
            "volatile boolean persistedConfigValidationPending;",
            "volatile boolean persistedConfigValidated;",
            "schedulePageActivationPersistedConfigValidation(",
            "completePageActivationPersistedConfigValidation(",
            "PAGE_ACTIVATION_CONFIG_SETTLE_MS",
            "validation.generation != transaction.persistedConfigGeneration",
            "isPageActivationPersistedConfigCurrent(transaction)",
            "releasePageActivationConfigGuard(transaction)",
        ),
        "activation-lifetime deferred-config guard",
    )
    activation_config_validation_start = module.find(
        "private static boolean schedulePageActivationPersistedConfigValidation("
    )
    activation_config_completion_start = module.find(
        "private static void completePageActivationPersistedConfigValidation(",
        activation_config_validation_start,
    )
    if (
        activation_config_validation_start < 0
        or activation_config_completion_start < 0
    ):
        fail("could not isolate post-settle persisted-config validation")
    activation_config_schedule = module[
        activation_config_validation_start:activation_config_completion_start
    ]
    settle_delay = activation_config_schedule.find("postDelayed(")
    background_submit = activation_config_schedule.find(
        "DEFERRED_CONFIG_EXECUTOR.execute(", settle_delay
    )
    fresh_validation = activation_config_schedule.find(
        "validateDeferredConfig(deferred)", background_submit
    )
    completion_post = activation_config_schedule.find(
        "new Handler(activity.getMainLooper()).post(", fresh_validation
    )
    if not (
        0 <= settle_delay < background_submit < fresh_validation
        < completion_post
    ):
        fail(
            "persisted config is not freshly reread off-thread after the full "
            "activation settle window"
        )
    transfer_guard_start = module.find(
        "private static boolean transferDeferredSpreadTurnToActivation("
    )
    validate_guard_start = module.find(
        "private static DeferredConfigValidation validateDeferredConfig(",
        transfer_guard_start,
    )
    if transfer_guard_start < 0 or validate_guard_start < 0:
        fail("could not isolate deferred observer ownership transfer")
    transfer_guard = module[transfer_guard_start:validate_guard_start]
    if "releaseDeferredConfigWatch(" in transfer_guard:
        fail("shared config-watch guard is released during activation transfer")
    observer_event_start = module.find(
        "private static void handleDeferredConfigWatchEvent("
    )
    observer_event_end = module.find(
        "private static void releaseDeferredConfigWatch(", observer_event_start
    )
    if observer_event_start < 0 or observer_event_end < 0:
        fail("could not isolate activation-lifetime config observer callback")
    require_markers(
        module[observer_event_start:observer_event_end],
        (
            "deferred.persistedConfigWatch != watch",
            "transaction.persistedConfigGeneration == generation",
            '"persisted_config_changed_during_activation"',
            "abortPageActivationTransaction(",
        ),
        "multiplexed late persisted-config change abort",
    )
    persisted_watch_start = module.find(
        "private static boolean ensurePersistedConfigWatch("
    )
    persisted_watch_end = module.find(
        "private static void applyPersistedConfigWatchChange(",
        persisted_watch_start,
    )
    if persisted_watch_start < 0 or persisted_watch_end < 0:
        fail("could not isolate authoritative persisted-config observer")
    persisted_watch_method = module[persisted_watch_start:persisted_watch_end]
    watch_generation = persisted_watch_method.find(
        "generation = watch.generation.incrementAndGet()"
    )
    activation_multiplex = persisted_watch_method.find(
        "handleDeferredConfigWatchEvent(", watch_generation
    )
    if not (0 <= watch_generation < activation_multiplex):
        fail(
            "authoritative persisted-config observer does not multiplex its "
            "generation into activation validation"
        )
    require_markers(
        persisted_config_method,
        (
            "config != null && config.enabled && config.editable",
            "nativeBridgeLoaded && nativeHookReady",
            "persistedSpreadConfigIdentityCurrent(config)",
        ),
        "persisted deferred-config identity validation",
    )
    recovery_call = deferred_retry_method.find(
        "runFailedRollbackNavigationRecovery("
    )
    snapshot_gate = deferred_retry_method.find(
        "PenInputSnapshot deferredSnapshot =", recovery_call
    )
    if not 0 <= recovery_call < snapshot_gate:
        fail(
            "rollback-exhaustion navigation still waits on missing pen geometry "
            "instead of using its fail-closed recovery path"
        )
    recovery_start = module.find(
        "private static boolean runFailedRollbackNavigationRecovery("
    )
    recovery_end = module.find(
        "private static boolean handleRtlSpreadTurn(", recovery_start
    )
    if recovery_start < 0:
        fail("could not isolate exhausted-rollback navigation recovery")
    if recovery_end < 0:
        recovery_end = len(module)
    recovery_method = module[recovery_start:recovery_end]
    require_markers(
        recovery_method,
        (
            "persistedValidation.isCurrent(deferred)",
            "PAGE_ACTIVATION_OWNERSHIP_LOCK",
            "PAGE_ACTIVATION_ROLLBACK_RECOVERIES.get(activity)",
            "PEN_CONTACT_START_PAGES.get(activity)",
            "ACTIVE_FINGER_TOUCH_STREAMS.get(activity)",
            "pageSaveInFlightCountLocked(activity)",
            '"disableHandWrite"',
            "invalidatePenInputGeometrySnapshot(",
            "transferDeferredSpreadTurnToActivation(",
            '"loadPage"',
            "releaseDeferredConfigWatch(deferred)",
            '"page_activation_rollback_navigation_load_requested id="',
        ),
        "persistently validated fail-closed rollback navigation recovery",
    )
    if "PAGE_ACTIVATION_ROLLBACK_RECOVERIES.remove(" in recovery_method:
        fail(
            "failed-rollback navigation releases ownership when loadPage returns "
            "instead of waiting for reader/presenter convergence"
        )
    spread_config_class_start = module.find(
        "private static final class SpreadConfig"
    )
    protected_verification_start = module.find(
        "private static final class ProtectedVerification",
        spread_config_class_start,
    )
    if spread_config_class_start < 0 or protected_verification_start < 0:
        fail("could not isolate persisted SpreadConfig equality")
    spread_config_class = module[
        spread_config_class_start:protected_verification_start
    ]
    require_markers(
        spread_config_class,
        (
            "boolean samePersistedState(SpreadConfig other)",
            "markerIdentity.sameAs(other.markerIdentity)",
            "backupIdentity.sameAs(other.backupIdentity)",
            "snapshotIdentity.sameAs(other.snapshotIdentity)",
            "enabled == other.enabled",
            "coverSeparate == other.coverSeparate",
            "showDivider == other.showDivider",
            "showHeader == other.showHeader",
            "nativeFill == other.nativeFill",
            "editable == other.editable",
        ),
        "complete persisted negative-state equality",
    )
    config_cache_start = module.find(
        "private static SpreadConfig cacheSpreadConfig("
    )
    pen_snapshot_start = module.find(
        "private static void publishPendingPenInputSnapshot(",
        config_cache_start,
    )
    if config_cache_start < 0 or pen_snapshot_start < 0:
        fail("could not isolate always-on persisted-config watcher")
    config_watch_source = module[config_cache_start:pen_snapshot_start]
    config_watch = mask_comments_preserve_literals(config_watch_source)
    require_markers(
        config_watch,
        (
            "ensurePersistedConfigWatch(activity, config)",
            "spread_config_fail_closed reason=watch_unavailable_or_stale",
            "spread_config_fail_closed reason=watch_changed_during_publish",
            "NAVIGATION_FAIL_CLOSED_DOCUMENTS",
            "private static boolean ensurePersistedConfigWatch(",
            "PERSISTED_CONFIG_WATCHES.get(activity)",
            "new FileObserver(watch.directoryPath, mask)",
            "watch.generation.incrementAndGet()",
            "observer.startWatching()",
            "persistedSpreadConfigIdentityCurrent(config)",
            "generationBefore != watch.generation.get()",
            "persisted_config_watch_stale_at_start",
            "rebindRollbackRecoveryToValidatedConfigLocked(",
            "private static boolean rebindRollbackRecoveryToValidatedConfigLocked(",
            "PAGE_ACTIVATION_ROLLBACK_RECOVERIES.put(activity, config)",
            "PEN_INPUT_SNAPSHOTS.remove(activity)",
            "updateNativeEraserGate(",
            "applyPersistedConfigWatchChange(",
            "PenContactOwnership contact =",
            "contact.phase = PEN_CONTACT_PHASE_EXPIRED;",
            "PEN_RECEIVE_EXPIRED_GENERATIONS.put(",
            "contactActive = false;",
            "PAGE_ACTIVATION_TRANSACTIONS.get(activity) != null",
            "SPREAD_CONFIGS.remove(activity)",
            "PROTECTED_VERIFICATIONS.remove(activity)",
            '"SN_SPREAD_PROBE " + reason',
            'XposedHelpers.callMethod(viewModel, "reloadPage")',
            "private static void stopPersistedConfigWatch(",
        ),
        "always-on fail-closed persisted-config invalidation",
    )
    cache_publish_end = config_watch.find(
        "private static boolean rebindRollbackRecoveryToValidatedConfigLocked("
    )
    ensure_watch_start = config_watch.find(
        "private static boolean ensurePersistedConfigWatch("
    )
    if cache_publish_end < 0 or ensure_watch_start < 0:
        fail("could not isolate calibration watcher cleanup")
    cache_method = config_watch[:cache_publish_end]
    ensure_watch_method = config_watch[ensure_watch_start:]
    cache_non_null = cache_method.find("if (config != null) {")
    cache_ensure = cache_method.find(
        "ensurePersistedConfigWatch(activity, config)", cache_non_null
    )
    if not 0 <= cache_non_null < cache_ensure:
        fail("spread config can publish without establishing its watcher")
    if "if (config != null && !config.calibration)" in cache_method:
        fail("calibration config bypasses persisted watcher cleanup")
    if "if (config.calibration)" in cache_method + ensure_watch_method:
        fail("calibration config bypasses the authoritative persisted watcher")
    require_markers(
        module,
        (
            "private static boolean shouldSuppressFailClosedNavigation(",
            "private static void clearFailClosedNavigation(",
        ),
        "watcher-failure navigation guard lifecycle",
    )
    if "Map<Activity, SpreadConfig> SPREAD_CONFIGS =\n        new ConcurrentHashMap<>()" not in module:
        fail("observer-visible spread config publication is not thread-safe")
    if (
        "Map<Activity, String>\n        NAVIGATION_FAIL_CLOSED_DOCUMENTS = "
        "new ConcurrentHashMap<>()"
    ) not in module:
        fail("watcher-failure navigation guard is not thread-safe")
    if "SPREAD_CONFIGS.put(activity," in (
        module[:config_cache_start] + module[pen_snapshot_start:]
    ):
        fail("spread configs can bypass watcher-backed cache publication")
    unavailable_navigation_guard = config_watch.find(
        "NAVIGATION_FAIL_CLOSED_DOCUMENTS.put("
    )
    unavailable_fail_closed = config_watch.find(
        "SPREAD_CONFIGS.remove(activity);"
    )
    unavailable_withdraw = config_watch.find(
        "withdrawFailClosedPenInputAuthorityLocked(",
        unavailable_fail_closed,
    )
    unavailable_return = config_watch.find(
        "return null;",
        unavailable_withdraw,
    )
    cache_publish = config_watch.find(
        "SPREAD_CONFIGS.put(activity, config);",
        unavailable_return,
    )
    cache_generation_recheck = config_watch.find(
        "watch.generation.get() != watchGeneration", cache_publish
    )
    changed_navigation_guard = config_watch.find(
        "NAVIGATION_FAIL_CLOSED_DOCUMENTS.put(", cache_generation_recheck
    )
    changed_remove = config_watch.find(
        "SPREAD_CONFIGS.remove(activity, config);",
        changed_navigation_guard,
    )
    changed_withdraw = config_watch.find(
        "withdrawFailClosedPenInputAuthorityLocked(",
        changed_remove,
    )
    recovery_rebind = config_watch.find(
        "rebindRollbackRecoveryToValidatedConfigLocked(", changed_withdraw
    )
    successful_navigation_release = config_watch.find(
        "clearFailClosedNavigation(", recovery_rebind
    )
    changed_return = config_watch.find(
        "return null;", successful_navigation_release
    )
    if not (
        0 <= unavailable_navigation_guard < unavailable_fail_closed
        < unavailable_withdraw
        < unavailable_return < cache_publish < cache_generation_recheck
        < changed_navigation_guard < changed_remove
        < changed_withdraw < recovery_rebind < successful_navigation_release
        < changed_return
    ):
        fail(
            "spread config publication is not fenced by watcher generation "
            "without caching temporary fail-closed state"
        )
    if "SPREAD_CONFIGS.put(activity, published)" in config_watch:
        fail("temporary fail-closed spread config can become a sticky cache entry")
    rebind_helper_start = config_watch.find(
        "private static boolean rebindRollbackRecoveryToValidatedConfigLocked("
    )
    rebind_helper_end = config_watch.find(
        "private static void withdrawFailClosedPenInputAuthority(",
        rebind_helper_start,
    )
    if rebind_helper_start < 0 or rebind_helper_end < 0:
        fail("could not isolate validated rollback-recovery config rebinding")
    require_markers(
        config_watch[rebind_helper_start:rebind_helper_end],
        (
            "SPREAD_CONFIGS.get(activity) != config",
            "PAGE_ACTIVATION_ROLLBACK_RECOVERIES.get(activity)",
            "recovery == null || recovery == config",
            "recovery.sameDocumentIdentity(config)",
            '"page_activation_rollback_recovery_rebind_rejected"',
            "PAGE_ACTIVATION_ROLLBACK_RECOVERIES.put(activity, config)",
            "PAGE_ACTIVATION_ROLLBACK_RECOVERIES.get(activity) != config",
            "PEN_INPUT_EDITABLE_GUARDS.put(activity, Boolean.TRUE)",
            '"page_activation_rollback_recovery_rebound path="',
        ),
        "validated rollback-recovery config rebinding",
    )
    if "failClosedSpreadConfig(" in module:
        fail("watcher failure still publishes a consumable default config")
    require_markers(
        config_watch,
        (
            "private static void withdrawFailClosedPenInputAuthority(",
            "withdrawFailClosedPenInputAuthorityLocked(activity, reason)",
            "private static void withdrawFailClosedPenInputAuthorityLocked(",
            "PEN_INPUT_SNAPSHOTS.remove(activity)",
            "DOCUMENT_RECEIVE_IDENTITIES.remove(activity)",
            "PEN_INPUT_EDITABLE_GUARDS.put(activity, Boolean.TRUE)",
            "disableNativeGateForOwnershipHandoffLocked(reason)",
        ),
        "watcher-failure fail-closed pen-authority retention",
    )
    withdraw_start = config_watch.find(
        "private static void withdrawFailClosedPenInputAuthority("
    )
    ensure_watch_start = config_watch.find(
        "private static boolean ensurePersistedConfigWatch(", withdraw_start
    )
    if withdraw_start < 0 or ensure_watch_start < 0:
        fail("could not isolate watcher-failure pen guard")
    if "PEN_INPUT_EDITABLE_GUARDS.remove(activity)" in config_watch[
        withdraw_start:ensure_watch_start
    ]:
        fail("watcher failure opens a null-snapshot pen-admission gap")
    watch_event_start = config_watch.find(
        "public void onEvent(int event, String path)"
    )
    watch_event_end = config_watch.find(
        "watch.observer = observer;", watch_event_start
    )
    if watch_event_start < 0 or watch_event_end < 0:
        fail("could not isolate persisted-config observer callback")
    watch_event_source = config_watch_source[watch_event_start:watch_event_end]
    watch_event = mask_cpp_comments_and_literals(watch_event_source)
    if watch_event.count("final boolean contactActive;") != 1:
        fail("persisted-config watcher contact authority is not final")
    contact_active_writes = identifier_mutations(watch_event, "contactActive")
    if (
        len(contact_active_writes) != 2
        or watch_event.count("contactActive = false;") != 2
        or "contactActive = true" in watch_event
    ):
        fail("persisted-config watcher can republish active contact authority")
    watch_ownership_fence = watch_event.find(
        "synchronized (PAGE_ACTIVATION_OWNERSHIP_LOCK)"
    )
    navigation_guard = watch_event.find(
        "NAVIGATION_FAIL_CLOSED_DOCUMENTS.put(", watch_ownership_fence
    )
    config_remove = watch_event.find(
        "SPREAD_CONFIGS.remove(activity)", navigation_guard
    )
    fail_closed_guard = watch_event.find(
        "PEN_INPUT_EDITABLE_GUARDS.put(activity, Boolean.TRUE)",
        config_remove,
    )
    contact_ownership = watch_event.find(
        "PenContactOwnership contact =",
        fail_closed_guard,
    )
    expire_contact = watch_event.find(
        "contact.phase = PEN_CONTACT_PHASE_EXPIRED;", contact_ownership
    )
    publish_receive_tombstone = watch_event.find(
        "PEN_RECEIVE_EXPIRED_GENERATIONS.put(", expire_contact
    )
    contact_inactive = watch_event.find(
        "contactActive = false;", publish_receive_tombstone
    )
    snapshot_withdraw = watch_event.find(
        "PEN_INPUT_SNAPSHOTS.remove(activity);", contact_inactive
    )
    retired_owner_match = re.search(
        r"if\s*\(\s*retiredOwner\s*\)\s*\{\s*"
        r"retirePersistedConfigWatch\s*\(\s*activity\s*,\s*watch\s*\)"
        r"\s*;\s*return\s*;\s*\}",
        watch_event[snapshot_withdraw:],
        re.DOTALL,
    )
    retired_owner_guard = (
        snapshot_withdraw + retired_owner_match.start()
        if retired_owner_match is not None
        else -1
    )
    retired_owner_return = (
        snapshot_withdraw + retired_owner_match.end()
        if retired_owner_match is not None
        else -1
    )
    gate_guard_match = re.match(
        r"\s*if\s*\(\s*!\s*contactActive\s*\)\s*\{\s*"
        r"updateNativeEraserGate\s*\(\s*activity\s*,\s*"
        r'"persisted_config_watch_event"\s*,\s*false\s*\)\s*;\s*\}',
        mask_comments_preserve_literals(
            watch_event_source[retired_owner_return:]
        ),
        re.DOTALL,
    ) if retired_owner_return >= 0 else None
    gate_before_post = retired_owner_return if gate_guard_match is not None else -1
    gate_end = (
        retired_owner_return + gate_guard_match.end()
        if gate_guard_match is not None
        else -1
    )
    callback_post = watch_event.find(
        "new Handler(activity.getMainLooper()).post(", gate_end
    )
    pending_writer_disable = mask_comments_preserve_literals(
        watch_event_source
    ).find(
        '"config reload pending"', callback_post
    )
    delayed_reload = watch_event.find(
        "new Handler(activity.getMainLooper()).postDelayed(",
        pending_writer_disable,
    )
    if not (
        0 <= watch_ownership_fence < navigation_guard < config_remove
        < fail_closed_guard
        < contact_ownership < expire_contact < publish_receive_tombstone
        < contact_inactive < snapshot_withdraw < retired_owner_guard
        < retired_owner_return <= gate_before_post
        < gate_end < callback_post < pending_writer_disable < delayed_reload
    ):
        fail(
            "persisted config changes do not expire the contact, publish its "
            "receive tombstone, withdraw the snapshot, reject a retired "
            "owner, and disable native writer input before delayed validation"
        )
    if brace_depth_at(watch_event, contact_inactive) != 4:
        fail(
            "persisted-config watcher contact withdrawal is disabled or "
            "nested under an additional condition"
        )
    if "PEN_INPUT_EDITABLE_GUARDS.remove(activity)" in watch_event:
        fail("persisted config observer opens a stale-editable admission gap")
    forbidden_watch_callback_work = [
        marker
        for marker in (
            "Os.stat(",
            "FileIdentity.capture(",
            "FileInputStream",
            "Properties",
            "sha256(",
            "spreadConfig(",
            "getFilePageTrails",
            "getCurPageTrails",
        )
        if marker in watch_event
    ]
    if forbidden_watch_callback_work:
        fail(
            "persisted-config FileObserver performs blocking validation work: "
            f"{forbidden_watch_callback_work}"
        )
    if "stopPersistedConfigWatch(activity);" not in module[
        module.find("private static void releaseActivityResources("):
        module.find("private static int recycleRemovedBitmap(")
    ]:
        fail("activity teardown leaks its persisted-config observer")
    ui_blocking_config_hits = [
        marker for marker in (
            "Os.stat(",
            "FileIdentity.capture(",
            "new File(",
            "FileInputStream",
            "Properties",
            "spreadConfig(",
        )
        if marker in deferred_retry_method
    ]
    if ui_blocking_config_hits:
        fail(
            "deferred UI retry performs persisted-config I/O instead of using "
            f"the worker result: {ui_blocking_config_hits}"
        )
    editable_turn = rtl_turn.find(
        "if (isCachedEditableSpreadLandscape(activity, config))"
    )
    turn_started = rtl_turn.find(
        "boolean started = beginPageActivationTransaction(",
        editable_turn,
    )
    turn_deferred = rtl_turn.find(
        "boolean deferred = !started && deferRtlSpreadTurn(",
        turn_started,
    )
    turn_result = rtl_turn.find(
        "return started || deferred;",
        turn_deferred,
    )
    if not 0 <= editable_turn < turn_started < turn_deferred < turn_result:
        fail("rejected editable RTL spread turn can still be silently consumed")

    activate_page_end = module.find(
        "private static void setReplaceActiveInkMode(",
        activate_page_start,
    )
    if activate_page_end < 0:
        fail("could not isolate explicit page activation")
    activate_page = module[activate_page_start:activate_page_end]
    explicit_started = activate_page.find(
        "boolean started = beginPageActivationTransaction("
    )
    explicit_deferred = activate_page.find(
        "if (!started)",
        explicit_started,
    )
    explicit_queue = activate_page.find(
        "deferRtlPageActivation(",
        explicit_deferred,
    )
    explicit_trigger = activate_page.find(
        '"deferred_explicit_activation"',
        explicit_queue,
    )
    if not (
        0 <= explicit_started < explicit_deferred
        < explicit_queue < explicit_trigger
    ):
        fail("transiently rejected explicit page activation can be lost")

    contact_generation_start = module.find(
        "private static void notePageActivationTriggerContactLocked("
    )
    lift_capture_start = module.find(
        "private static long capturePageActivationPenLiftGeneration(",
        contact_generation_start,
    )
    handle_pen_start = module.find(
        "private static void handlePenPageActivation("
    )
    intercept_pen_start = module.find(
        "private static boolean interceptPenPageActivation(",
        handle_pen_start,
    )
    complete_stroke_start = module.find(
        "private static boolean isCompletingActivePageStroke(",
        intercept_pen_start,
    )
    if min(
        contact_generation_start,
        lift_capture_start,
        handle_pen_start,
        intercept_pen_start,
        complete_stroke_start,
    ) < 0:
        fail("could not isolate transfer-overlap contact latching")
    contact_generation_helper = module[
        contact_generation_start:lift_capture_start
    ]
    lift_capture_helper = module[lift_capture_start:handle_pen_start]
    require_markers(
        contact_generation_helper,
        (
            "transaction.triggerPenLifted",
            "transaction.pendingPenLiftGeneration",
            "== transaction.triggerContactGeneration",
            "transaction.triggerContactGeneration++",
            "transaction.pendingPenLiftGeneration = -1L",
            "transaction.triggerPenLifted = false",
        ),
        "new-contact generation advancement",
    )
    require_markers(
        lift_capture_helper,
        (
            "synchronized (PAGE_ACTIVATION_OWNERSHIP_LOCK)",
            "PAGE_ACTIVATION_TRANSACTIONS.get(activity)",
            "transaction.pendingPenLiftGeneration =",
            "transaction.triggerContactGeneration",
        ),
        "originating-contact pen-lift capture",
    )
    handle_pen = module[handle_pen_start:intercept_pen_start]
    intercept_pen = module[intercept_pen_start:complete_stroke_start]
    for label, method, pressure_marker in (
        ("queued", handle_pen, "if (requestedPressure > 0)"),
        ("synchronous", intercept_pen, "if (pressure > 0)"),
    ):
        transaction_branch = method.find(
            "if (transaction != null)"
        )
        contact_latch = method.find(pressure_marker, transaction_branch)
        ownership_lock = method.find(
            "synchronized (PAGE_ACTIVATION_OWNERSHIP_LOCK)",
            contact_latch,
        )
        generation_latch = method.find(
            "notePageActivationTriggerContactLocked(",
            ownership_lock,
        )
        if not (
            0 <= transaction_branch < contact_latch < ownership_lock
            < generation_latch
        ):
            fail(
                f"{label} transfer path does not latch every overlapping contact"
            )
    if "target == transaction.targetPage && pressure > 0" in intercept_pen:
        fail("gutter/wrong-half transfer contact remains unlatchable")
    if (
        "requestedTarget == transaction.targetPage" in handle_pen[
            handle_pen.find("if (transaction != null)"):
        ]
    ):
        fail("queued gutter/wrong-half transfer contact remains unlatchable")
    queued_transaction = handle_pen.find("if (transaction != null)")
    queued_snapshot_validation = handle_pen.find(
        "currentSnapshot != inputSnapshot",
        queued_transaction,
    )
    queued_current = handle_pen.find(
        "int current = inputSnapshot.currentPage;",
        queued_snapshot_validation,
    )
    if not (
        0 <= queued_transaction < queued_snapshot_validation < queued_current
    ):
        fail(
            "queued transaction input is not guarded by the immutable "
            "document/geometry snapshot after orientation or page changes"
        )
    synchronous_transaction = intercept_pen.find("if (transaction != null)")
    synchronous_missing_snapshot = intercept_pen.find(
        "if (inputSnapshot == null)",
        synchronous_transaction,
    )
    synchronous_pending_geometry = intercept_pen.find(
        "if (!inputSnapshot.geometryReady)",
        synchronous_missing_snapshot,
    )
    synchronous_mapping = intercept_pen.find(
        "int target = pageAt(inputSnapshot, x, y);",
        synchronous_pending_geometry,
    )
    if not (
        0 <= synchronous_transaction < synchronous_missing_snapshot
        < synchronous_pending_geometry < synchronous_mapping
    ):
        fail(
            "synchronous transaction input is not guarded by the immutable "
            "snapshot before document-page routing"
        )
    if "isNativeChromeTouch(" in handle_pen or "isNativeChromeTouch(" in intercept_pen:
        fail("pen routing still reclassifies a contact after its DOWN boundary")
    for label, method in (
        ("queued", handle_pen),
        ("synchronous", intercept_pen),
    ):
        blocking_hits = [
            marker for marker in blocking_markers
            if marker in method
        ]
        if blocking_hits:
            fail(
                f"{label} pen activation performs blocking config/filesystem "
                f"work: {blocking_hits}"
            )
    synchronous_pen_diagnostic_hits = [
        marker for marker in (
            "log(",
            "traceEvent(",
            "JSONObject",
            "XposedBridge.log(",
            "Log.i(",
        )
        if marker in intercept_pen
    ]
    if synchronous_pen_diagnostic_hits:
        fail(
            "synchronous pen interceptor performs logging/JSON work: "
            f"{synchronous_pen_diagnostic_hits}"
        )
    require_markers(
        intercept_pen,
        (
            "finishPenInputBlock(activity, x, y, pressure)",
            "notePenInputBlock(",
        ),
        "coalesced asynchronous pen-interceptor diagnostics",
    )

    low_latency_log_start = module.find(
        "private static void queueLowLatencyLog("
    )
    clear_contact_start = module.find(
        "private static void clearPenContactStartPage(",
        low_latency_log_start,
    )
    if low_latency_log_start < 0 or clear_contact_start < 0:
        fail("could not isolate low-latency diagnostic queue")
    low_latency_log = module[low_latency_log_start:clear_contact_start]
    require_markers(
        low_latency_log,
        (
            "LOW_LATENCY_LOG_EXECUTOR.execute(",
            "PEN_INPUT_BLOCK_LOG_STATES.put(activity, state)",
            "if (state.equals(previous))",
            "PEN_INPUT_BLOCK_LOG_STATES.remove(activity)",
            "queueLowLatencyLog(captured)",
        ),
        "serialized coalesced low-latency diagnostics",
    )

    commit_start = module.find(
        "private static boolean commitPageActivationGeometry("
    )
    mark_lift_start = module.find(
        "private static void markPageActivationPenLifted(",
        commit_start,
    )
    if commit_start < 0 or mark_lift_start < 0:
        fail("could not isolate transactional ownership commit")
    commit_transaction = module[commit_start:mark_lift_start]
    rollback_branch = commit_transaction.find(
        "if (transaction.rollbackPending)"
    )
    source_reader_check = commit_transaction.find(
        "currentPage != transaction.sourcePage",
        rollback_branch,
    )
    source_presenter_check = commit_transaction.find(
        "presenterMarkPage != transaction.sourcePage + 1",
        source_reader_check,
    )
    finish_verified_rollback = commit_transaction.find(
        "return finishPageActivationRollback(",
        source_presenter_check,
    )
    target_identity_check = commit_transaction.find(
        "currentPage != transaction.targetPage",
        finish_verified_rollback,
    )
    if not (
        0 <= rollback_branch < source_reader_check < source_presenter_check
        < finish_verified_rollback < target_identity_check
    ):
        fail(
            "rollback guard is not released only after reader and presenter "
            "reconverge on the source page"
        )
    compose_start = module.find("private static boolean compose(")
    compose_end = module.find(
        "private static void reapplyCanonicalCommittedInk(", compose_start
    )
    if compose_start < 0 or compose_end < 0:
        fail("could not isolate rollback geometry re-publication")
    compose_method = module[compose_start:compose_end]
    rollback_commit = compose_method.find("commitPageActivationGeometry(")
    ready_snapshot = compose_method.find(
        "PenInputSnapshot readySnapshot =", rollback_commit
    )
    ready_publish = compose_method.find(
        "publishPenInputSnapshot(activity, readySnapshot)", ready_snapshot
    )
    if not 0 <= rollback_commit < ready_snapshot < ready_publish:
        fail(
            "verified source rollback cannot flow through the same compose pass "
            "to a ready pen-input snapshot"
        )

    require_markers(
        module,
        (
            "REPLACE_ACTIVE_INK_MODES",
            "CANONICAL_ONLY_INK_MODES",
            "FORCE_CANONICAL_ACTIVE_INK",
            "EXPLICIT_CANONICAL_TRAIL_SAVE",
            'setReplaceActiveInkMode(',
            '"area_selection"',
            '"eraser:" + eraserType',
            '"pen"',
            'new String[] {"undo", "redo"}',
            'ink_composition_force_canonical reason=',
            'undo_redo_saved_before_canonical_reload',
            "boolean replaceActiveSlot",
            "boolean canonicalOnly",
            "readOnly || canonicalOnly",
            'committed_ink_canonical_only reason=eraser',
            "persistActiveMutationBeforeCanonicalRefresh(",
            'active_mutation_saved_before_canonical_refresh',
            'active_mutation_canonical_reloaded',
            'active_mutation_canonical_reload_skipped',
            '"active_mutation_canonical_reload"',
            "saveTrailsForCanonicalReload(",
            "ExplicitCanonicalSaveScope",
            "EXPLICIT_CANONICAL_SAVE_SCOPES",
            'reason=save_not_committed',
            'reason=authority_changed_after_save',
            '"undo_redo:" + mutationName',
            '"active_eraser"',
            '"active_pen"',
            'explicit_canonical_trail_save reason=',
            "if (replaceActiveSlot && activeDestination != null)",
            '" mode=" + (replaceActiveSlot ? "replace" : "add")',
        ),
        "settled ink composition",
    )

    active_mutation_start = module.find(
        "private static void persistActiveMutationBeforeCanonicalRefresh("
    )
    canonical_save_start = module.find(
        "private static boolean saveTrailsForCanonicalReload(",
        active_mutation_start,
    )
    if active_mutation_start < 0 or canonical_save_start < 0:
        fail("could not isolate active-page canonical mutation refresh")
    active_mutation_refresh = module[
        active_mutation_start:canonical_save_start
    ]
    active_mutation_masked = mask_comments_preserve_literals(
        active_mutation_refresh
    )
    if active_mutation_masked.count(
        'if ("lasso".equals(TRACE_TOOLS.get(activity)))'
    ) != 1:
        fail("active mutation refresh must have one exact lasso-command guard")
    lasso_refresh_guard = active_mutation_masked.find(
        'if ("lasso".equals(TRACE_TOOLS.get(activity)))'
    )
    lasso_refresh_open = active_mutation_masked.find(
        "{", lasso_refresh_guard
    )
    lasso_refresh_close = matching_brace(
        active_mutation_masked,
        lasso_refresh_open,
        "lasso native-buffer refresh guard",
    )
    lasso_refresh_reason = active_mutation_masked.find(
        'reason=native_selection_buffer_owns_refresh', lasso_refresh_guard
    )
    lasso_refresh_return = active_mutation_masked.find(
        "return;", lasso_refresh_reason
    )
    mutation_kind = active_mutation_refresh.find(
        'String mutationKind = eraserMutation', lasso_refresh_return
    )
    mutation_save = active_mutation_refresh.find(
        "saveTrailsForCanonicalReload(", mutation_kind
    )
    mutation_save_guard = active_mutation_refresh.find(
        "if (!saved)", mutation_save
    )
    mutation_save_return = active_mutation_refresh.find(
        "return;", mutation_save_guard
    )
    mutation_force = active_mutation_refresh.find(
        "FORCE_CANONICAL_ACTIVE_INK.set(Boolean.TRUE)", mutation_save_return
    )
    mutation_reload_guard = active_mutation_refresh.find(
        "if (!loadCanonicalHandwritingIfAuthorityCurrent(", mutation_force
    )
    mutation_authority_reason = active_mutation_refresh.find(
        'reason=authority_changed_after_save', mutation_reload_guard
    )
    mutation_restore = active_mutation_refresh.find(
        "if (previousForceCanonical == null)", mutation_authority_reason
    )
    mutation_trace = active_mutation_refresh.find(
        '"active_mutation_canonical_reload"', mutation_restore
    )
    if not (
        0 <= lasso_refresh_guard < lasso_refresh_open < lasso_refresh_reason
        < lasso_refresh_return < lasso_refresh_close < mutation_kind
        < mutation_save
        < mutation_save_guard
        < mutation_save_return < mutation_force < mutation_reload_guard
        < mutation_authority_reason < mutation_restore < mutation_trace
    ):
        fail(
            "lasso selection must retain its native live buffer, while a real "
            "active-page mutation must prove its exact save and current writer "
            "authority before forcing a canonical-only reload"
        )
    if (
        brace_depth_at(active_mutation_masked, lasso_refresh_reason) != 2
        or brace_depth_at(active_mutation_masked, lasso_refresh_return) != 2
    ):
        fail(
            "lasso native-buffer guard can bypass its diagnostic or immediate "
            "return"
        )

    lasso_publish, lasso_publish_masked = extract_cpp_function(
        module,
        "private static boolean publishCanonicalLassoMutationAuthority(",
        "canonical lasso mutation-authority publisher",
    )
    lasso_authority_current, lasso_authority_current_masked = extract_cpp_function(
        module,
        "private static boolean canonicalLassoMutationAuthorityCurrentLocked(",
        "canonical lasso mutation-authority validator",
    )
    lasso_completion, lasso_completion_masked = extract_cpp_function(
        module,
        "private static void scheduleCanonicalLassoCompletion(",
        "canonical lasso completion",
    )
    lasso_locked_retirement, _lasso_locked_retirement_masked = (
        extract_cpp_function(
            module,
            "retireCanonicalLassoMutationAuthorityLocked(",
            "locked canonical lasso retirement",
        )
    )
    require_markers(
        lasso_publish,
        (
            "LASSO_TRANSACTION_COUNTER.incrementAndGet()",
            "penWriterAuthorityCurrentLocked(activity, authority)",
            "LASSO_MUTATION_AUTHORITIES.put(activity, published)",
            "lasso_mutation_authority_published",
        ),
        "canonical lasso transaction publication",
    )
    require_markers(
        lasso_authority_current,
        (
            "LASSO_MUTATION_AUTHORITIES.get(activity) != authority",
            "DOCUMENT_IDENTITY_ADMISSIONS.get(activity) != null",
            "NAVIGATION_FAIL_CLOSED_DOCUMENTS.get(activity) != null",
            "PAGE_ACTIVATION_TRANSACTIONS.get(activity) != null",
            "PAGE_ACTIVATION_ROLLBACK_RECOVERIES.get(activity) != null",
            "PEN_CONTACT_OWNERSHIPS.get(activity) != null",
            "PEN_CONTACT_START_PAGES.get(activity) != null",
            "samePenWriterDocumentAuthority(",
            "penWriterAuthorityCurrentLocked(activity, current)",
        ),
        "canonical lasso transaction revalidation",
    )
    require_markers(
        lasso_completion,
        (
            "LASSO_MUTATION_AUTHORITIES.remove(",
            "LASSO_UI_CONTACT_DOWNS.remove(authority.activity)",
            "spreadLassoCanonicalSelection = false",
            "spreadLassoToolArmed = true",
            "lasso_mutation_authority_completed",
        ),
        "canonical lasso completion retirement",
    )
    lasso_transition_repair, lasso_transition_repair_masked = extract_cpp_function(
        module,
        "private static void repairSpreadLassoTransition(",
        "spread lasso transition repair",
    )
    require_markers(
        lasso_transition_repair_masked,
        (
            "Rect canonicalSelection = spreadLassoCanonicalSelectionRect;",
            "Rect displaySelection = spreadLassoDisplaySelectionRect;",
            "Math.max(\n                    LASSO_MIN_UI_FRAME_SIZE,",
            "boolean pureCanonicalMove = spreadLassoCanonicalSelection",
            "&& mode == 1 && rotation == 0",
            "int contentPaddingX = pureCanonicalMove",
            "int contentPaddingY = pureCanonicalMove",
            "x + contentPaddingX - writable.left",
            "y + contentPaddingY - writable.top",
            "boolean preserveCanonicalSize = pureCanonicalMove;",
            "? canonicalSelection.width()",
            "? canonicalSelection.height()",
        ),
        "padded lasso-content transition mapping",
    )
    if (
        "? width\n                : Math.max(1, Math.round(width / scaleX))"
        in lasso_transition_repair_masked
        or "? height\n                : Math.max(1, Math.round(height / scaleY))"
        in lasso_transition_repair_masked
    ):
        fail("pure lasso moves still commit the padded UI frame dimensions")

    area_selection_hook_start = module.find(
        '"com.supernote.document.areaselection.AreaSelectionView"'
    )
    area_selection_hook_end = module.find(
        '"com.example.libsupernote.SuperNoteNote"',
        area_selection_hook_start,
    )
    if min(area_selection_hook_start, area_selection_hook_end) < 0:
        fail("could not isolate the native lasso move-preview hook")
    area_selection_hook = module[
        area_selection_hook_start:area_selection_hook_end
    ]
    area_selection_hook_masked = mask_cpp_comments_and_literals(
        area_selection_hook
    )
    require_markers(
        area_selection_hook_masked,
        (
            "protected void afterHookedMethod(MethodHookParam param)",
            "spreadLassoStateOwner != activity",
            "!spreadLassoCanonicalSelection",
            'XposedHelpers.getObjectField(\n                            param.thisObject,\n                            ',
            "Bitmap preservedMove = stationary.copy(",
            "Bitmap.Config.ARGB_8888",
            "XposedHelpers.setObjectField(",
            "previousMove.recycle();",
        ),
        "lossless native lasso move preview",
    )
    if "removeAntiAliasingFillPoints" in area_selection_hook:
        fail("lasso move preview still applies the destructive native thinning pass")
    require_markers(
        lasso_locked_retirement,
        (
            "LASSO_MUTATION_AUTHORITIES.remove(activity)",
            "LASSO_UI_CONTACT_DOWNS.remove(activity)",
            "spreadLassoActive = false",
            "spreadLassoCanonicalSelection = false",
        ),
        "locked canonical lasso retirement",
    )
    document_admission, _document_admission_masked = extract_cpp_function(
        module,
        "private static DocumentIdentityAdmission "
        "invalidateDocumentIdentityAdmission(",
        "document-identity admission invalidation",
    )
    persisted_watch_disable, _persisted_watch_disable_masked = (
        extract_cpp_function(
            module,
            "private static boolean disableWriterForPersistedConfigWatch(",
            "persisted-config writer disable",
        )
    )
    require_markers(
        document_admission,
        (
            "retireCanonicalLassoMutationAuthorityLocked(activity)",
            "reason=document_identity_admission:",
        ),
        "document reset lasso retirement",
    )
    require_markers(
        persisted_watch_disable,
        (
            "retireCanonicalLassoMutationAuthorityLocked(activity)",
            "reason=persisted_config_watch:",
        ),
        "persisted-config reload lasso retirement",
    )
    lasso_publish_compact = compact_code(lasso_publish)
    publish_store = lasso_publish_compact.find(
        "LASSO_MUTATION_AUTHORITIES.put(activity,published);"
    )
    publish_success = lasso_publish_compact.find("returntrue;", publish_store)
    if not 0 <= publish_store < publish_success:
        fail("canonical lasso authority may succeed before publication")
    if "LASSO_MUTATION_AUTHORITIES.clear()" not in module:
        fail("lasso transaction authority is not retired on lifecycle reset")

    digital_position_start = module.find('"onDigitalPosition",')
    digital_position_end = module.find('"onDigital",', digital_position_start)
    if digital_position_start < 0 or digital_position_end < 0:
        fail("could not isolate native digital-position hook")
    digital_position_hook = mask_comments_preserve_literals(
        module[digital_position_start:digital_position_end]
    )
    lasso_native_bypass = digital_position_hook.find(
        "if (canonicalLassoUiOwnsPenContact(activity))"
    )
    lasso_native_result = digital_position_hook.find(
        "param.setResult(null);", lasso_native_bypass
    )
    ordinary_pressure_path = digital_position_hook.find(
        "if (pressure <= 0)", lasso_native_result
    )
    if not (
        0 <= lasso_native_bypass < lasso_native_result < ordinary_pressure_path
    ):
        fail(
            "canonical lasso UI contacts must be removed before the native "
            "handwriting contact path"
        )

    activity_latch, _activity_latch_masked = extract_cpp_function(
        module,
        "private static void latchPenContactFromActivityTouch(",
        "activity stylus contact latch",
    )
    activity_latch_code = mask_comments_preserve_literals(activity_latch)
    activity_lasso_bypass = activity_latch_code.find(
        "if (canonicalLassoUiOwnsPenContact(activity))"
    )
    activity_snapshot = activity_latch_code.find(
        "PenInputSnapshot snapshot", activity_lasso_bypass
    )
    if not 0 <= activity_lasso_bypass < activity_snapshot:
        fail(
            "canonical lasso UI contacts must bypass the Android handwriting "
            "contact latch"
        )

    activity_fallback, _activity_fallback_masked = extract_cpp_function(
        module,
        "private static void schedulePenContactFallbackFromActivityTouch(",
        "activity stylus terminal fallback",
    )
    fallback_code = mask_comments_preserve_literals(activity_fallback)
    fallback_lasso_bypass = fallback_code.find(
        "if (canonicalLassoUiOwnsPenContact(activity))"
    )
    fallback_owner = fallback_code.find(
        "PEN_CONTACT_OWNERSHIPS.get(activity)", fallback_lasso_bypass
    )
    if not 0 <= fallback_lasso_bypass < fallback_owner:
        fail(
            "canonical lasso UI terminal events must not schedule a handwriting "
            "receive fallback"
        )

    canonical_reload_start = module.find(
        "private static boolean loadCanonicalHandwritingIfAuthorityCurrent(",
        canonical_save_start,
    )
    if canonical_reload_start < 0:
        fail("could not isolate explicit canonical save acknowledgement")
    canonical_save = mask_comments_preserve_literals(
        module[canonical_save_start:canonical_reload_start]
    )
    canonical_save_compact = re.sub(r"\s+", "", canonical_save)
    for marker in (
        "ExplicitCanonicalSaveScopescope=newExplicitCanonicalSaveScope(presenter);",
        "EXPLICIT_CANONICAL_SAVE_SCOPES.set(scope);",
        'XposedHelpers.callMethod(presenter,"saveTrails",false,false);',
        "returnscope.completed;",
        "EXPLICIT_CANONICAL_SAVE_SCOPES.remove();",
        "EXPLICIT_CANONICAL_SAVE_SCOPES.set(previousScope);",
    ):
        if marker not in canonical_save_compact:
            fail(
                "explicit canonical save does not preserve and return its exact "
                f"hook acknowledgement: missing {marker}"
            )

    canonical_reload_end = module.find(
        "private static void trackFingerTapNavigation(", canonical_reload_start
    )
    if canonical_reload_end < 0:
        fail("could not isolate ownership-linearized canonical reload")
    canonical_reload = compact_code(
        module[canonical_reload_start:canonical_reload_end]
    )
    lifecycle_lock = canonical_reload.find(
        "OWNER_LIFETIME_LOCK.readLock().lock();"
    )
    reload_lock = canonical_reload.find(
        "synchronized(PAGE_ACTIVATION_OWNERSHIP_LOCK)", lifecycle_lock
    )
    reload_authority = canonical_reload.find(
        "if(!documentMutationAuthorityCurrent(activity,presenter))",
        reload_lock,
    )
    reload_reject = canonical_reload.find("returnfalse;", reload_authority)
    reload_call = canonical_reload.find(
        'XposedHelpers.callMethod(presenter,"loadHandWrite",markPage);',
        reload_reject,
    )
    reload_success = canonical_reload.find("returntrue;", reload_call)
    lifecycle_finally = canonical_reload.find("}finally{", reload_success)
    lifecycle_unlock = canonical_reload.find(
        "OWNER_LIFETIME_LOCK.readLock().unlock();", lifecycle_finally
    )
    if not (
        0 <= lifecycle_lock < reload_lock < reload_authority < reload_reject
        < reload_call < reload_success < lifecycle_finally < lifecycle_unlock
    ):
        fail(
            "canonical handwriting reload is not lifecycle-safe and linearized "
            "with its final writer-authority proof in OWNER-then-PAGE lock order"
        )

    save_hook_start = module.find(
        '"saveTrails",\n            boolean.class', 0, active_mutation_start
    )
    receive_hook_start = module.find(
        '"receiveTrials",', save_hook_start, active_mutation_start
    )
    if save_hook_start < 0 or receive_hook_start < 0:
        fail("could not isolate saveTrails acknowledgement hook")
    save_hook = re.sub(
        r"\s+",
        "",
        mask_comments_preserve_literals(module[save_hook_start:receive_hook_start]),
    )
    save_admission = save_hook.find("booleansaveAdmitted=admitPageSave(")
    root_admission = save_hook.find(
        "explicitScope.rootAdmitted=saveAdmitted;", save_admission
    )
    finish_admission = save_hook.find("finishPageSaveAdmission();", root_admission)
    completion = save_hook.find(
        "explicitScope.completed=explicitScope.rootAdmitted&&admission!=null&&"
        "admission.counted&&param.getThrowable()==null;",
        finish_admission,
    )
    if not 0 <= save_admission < root_admission < finish_admission < completion:
        fail(
            "explicit canonical save completion is not derived from the exact "
            "admitted root save and its throwable-free after-hook"
        )

    history_hook_start = module.find(
        'for (String methodName : new String[] {"undo", "redo"})'
    )
    load_handwrite_hook_start = module.find(
        '"loadHandWrite",', history_hook_start
    )
    if history_hook_start < 0 or load_handwrite_hook_start < 0:
        fail("could not isolate undo/redo acknowledged canonical reload")
    history_hook = re.sub(
        r"\s+",
        "",
        mask_comments_preserve_literals(
            module[history_hook_start:load_handwrite_hook_start]
        ),
    )
    history_save = history_hook.find(
        "booleansaved=saveTrailsForCanonicalReload("
    )
    history_save_guard = history_hook.find(
        "if(!saved)", history_save
    )
    history_reload = history_hook.find(
        "if(!loadCanonicalHandwritingIfAuthorityCurrent(",
        history_save_guard,
    )
    if not 0 <= history_save < history_save_guard < history_reload:
        fail("undo/redo can reload canonical ink without a committed current save")

    combined_start = module.find(
        "private static Bitmap renderCombinedCommittedInk("
    )
    destination_start = module.find(
        "private static RectF activePageDestination(", combined_start
    )
    if combined_start < 0 or destination_start < 0:
        fail("could not isolate settled ink composition")
    combined = module[combined_start:destination_start]
    clear_slot = combined.find("PorterDuff.Mode.CLEAR")
    replacement_guard = combined.find(
        "if (replaceActiveSlot && activeDestination != null)"
    )
    draw_active = combined.find("canvas.drawBitmap(active, 0.0f, 0.0f, paint)")
    if not 0 <= replacement_guard < clear_slot < draw_active:
        fail("normal pen commits can still clear previously settled active-page ink")

    require_markers(
        module,
        (
            "configuration_refresh_waiting_for_layout",
            "configuration_refresh_native_reload",
            "configuration_refresh_not_scheduled reason=identity_unavailable",
            "configuration_refresh_stale orientation=",
            "configuration_refresh_stale reason=field_identity",
            'XposedHelpers.callMethod(viewModel, "reloadPage")',
        ),
        "portrait rotation refresh",
    )
    refresh_start = module.find(
        "private static void scheduleConfigurationRefresh("
    )
    portrait_restore_start = module.find(
        "private static void restorePortraitPresentation(", refresh_start
    )
    if refresh_start < 0 or portrait_restore_start < 0:
        fail("could not isolate delayed configuration refresh identity")
    refresh = compact_code(module[refresh_start:portrait_restore_start])
    capture_generation = refresh.find(
        "LongdocumentContextGeneration=activity==null?null:"
        "DOCUMENT_CONTEXT_GENERATIONS.get(activity);"
    )
    capture_path = refresh.find(
        "StringdocumentPath=activity==null?null:currentDocumentPath(activity);",
        capture_generation,
    )
    capture_view_model = refresh.find(
        "ObjectviewModel=activity==null?null:DOCUMENT_VIEW_MODELS.get(activity);",
        capture_path,
    )
    capture_presenter = refresh.find(
        "Objectpresenter=activity==null?null:HANDWRITE_PRESENTERS.get(activity);",
        capture_view_model,
    )
    overload = refresh.find(
        "finallongexpectedDocumentContextGeneration,"
        "finalStringexpectedDocumentPath,finalObjectexpectedViewModel,"
        "finalObjectexpectedPresenter",
        capture_presenter,
    )
    generation_guard = refresh.find(
        "Long.valueOf(expectedDocumentContextGeneration),"
        "DOCUMENT_CONTEXT_GENERATIONS.get(activity)",
        overload,
    )
    path_guard = refresh.find(
        "expectedDocumentPath,currentDocumentPath(activity)", generation_guard
    )
    view_model_guard = refresh.find(
        "DOCUMENT_VIEW_MODELS.get(activity)!=expectedViewModel", path_guard
    )
    presenter_guard = refresh.find(
        "HANDWRITE_PRESENTERS.get(activity)!=expectedPresenter", view_model_guard
    )
    reflected_view_model = refresh.find(
        'XposedHelpers.getObjectField(activity,"documentViewModel")',
        presenter_guard,
    )
    reflected_presenter = refresh.find(
        'XposedHelpers.getObjectField(activity,"handWritePresenter")',
        reflected_view_model,
    )
    reflected_guard = refresh.find(
        "if(viewModel!=expectedViewModel||presenter!=expectedPresenter)",
        reflected_presenter,
    )
    if not (
        0 <= capture_generation < capture_path < capture_view_model
        < capture_presenter < overload < generation_guard < path_guard
        < view_model_guard < presenter_guard < reflected_view_model
        < reflected_presenter < reflected_guard
    ):
        fail(
            "delayed configuration refresh does not carry and revalidate the "
            "exact document generation, path, view model, and presenter"
        )
    retry_calls = tuple(
        re.finditer(
            r"scheduleConfigurationRefresh\(activity,orientation,attempt\+1,"
            r"expectedDocumentContextGeneration,expectedDocumentPath,"
            r"expectedViewModel,expectedPresenter\)",
            refresh,
        )
    )
    if len(retry_calls) != 2:
        fail("configuration refresh retries can shed their document identity")

    require_markers(
        module,
        (
            "nativeTrimmingRect(",
            '"com.supernote.document.utils.TrimmingUtil"',
            '"getTrimmingRect"',
            "trimmingRect.left / horizontalMargin",
            "trimmingRect.top / verticalMargin",
            "left + sourceWidth * scale",
            "top + sourceHeight * scale",
            '"native_fill_trim_detected page="',
        ),
        "native-reader-equivalent spread trimming",
    )

    native_chrome_code = mask_comments_preserve_literals(module)
    require_markers(
        native_chrome_code,
        (
            "private static final class NativeChromeRect",
            "private static final class NativeChromeSnapshot",
            "private static final class NativeChromeTracker",
            "private static final class NativeChromePassThrough",
            "NATIVE_CHROME_TRACKERS",
            "NATIVE_CHROME_SNAPSHOTS",
            "NATIVE_CHROME_PEN_PASSTHROUGHS",
            "private static final class TextSelectionPenContact",
            "TEXT_SELECTION_PEN_CONTACTS",
            "TEXT_SELECTION_MODES",
            "ViewTreeObserver.OnGlobalLayoutListener",
            "installNativeChromeTracker(createdActivity);",
            "removeNativeChromeTracker(activity);",
            "view.getGlobalVisibleRect(visible)",
            "collectAdditionalWindowChromeRects(",
            '"android.view.WindowManagerGlobal"',
            '"getWindowViews"',
            'getDeclaredField("mViews")',
            'native_chrome_window_discovery_ready source=',
            "view.isShown()",
            "view.getAlpha() <= 0.0f",
            "OVERLAY_TAG.equals(view.getTag())",
            'refreshNativeChromeSnapshot(activity, "contact_down")',
            "routeNativeChromeActivityStylus(activity, event)",
            "routeNativeChromeNativePen(",
            "adoptNativeChromeActivityDown(",
            "nativeChromeSetterPassThroughCurrent(",
            "finishNativeChromeActivityContact(",
            "routeTextSelectionActivityStylus(activity, event)",
            "routeTextSelectionNativePen(",
            "finishTextSelectionActivityContact(",
            '"native_chrome_contact_classified generation="',
            '"native_chrome_contact_finished generation="',
            "activation_touch_ignored_native_chrome",
            "activation_touch_cancelled_native_chrome",
        ),
        "dynamic native-chrome contact routing",
    )
    if (
        "NATIVE_TOP_CHROME_TOUCH_EXCLUSION_PX" in native_chrome_code
        or "NATIVE_BOTTOM_CHROME_TOUCH_EXCLUSION_PX" in native_chrome_code
        or "isNativeChromeTouch(" in native_chrome_code
    ):
        fail("native chrome still relies on a fixed top/bottom exclusion band")

    chrome_native_first_guard_start = native_chrome_code.find(
        "private static boolean nativeChromeNativeFirstMayClassifyLocked("
    )
    chrome_activity_route_start = native_chrome_code.find(
        "private static int routeNativeChromeActivityStylus(",
        chrome_native_first_guard_start,
    )
    chrome_native_route_start = native_chrome_code.find(
        "private static int routeNativeChromeNativePen(",
        chrome_activity_route_start,
    )
    chrome_current_start = native_chrome_code.find(
        "private static boolean nativeChromeActivityContactCurrent(",
        chrome_native_route_start,
    )
    chrome_finish_start = native_chrome_code.find(
        "private static void finishNativeChromeActivityContact(",
        chrome_current_start,
    )
    chrome_latch_start = native_chrome_code.find(
        "private static void latchPenContactFromActivityTouch(",
        chrome_finish_start,
    )
    if min(
        chrome_native_first_guard_start,
        chrome_activity_route_start,
        chrome_native_route_start,
        chrome_current_start,
        chrome_finish_start,
        chrome_latch_start,
    ) < 0:
        fail("could not isolate gesture-scoped native-chrome routing")
    chrome_native_first_guard = native_chrome_code[
        chrome_native_first_guard_start:chrome_activity_route_start
    ]
    require_markers(
        chrome_native_first_guard,
        (
            "PEN_CONTACT_OWNERSHIPS.get(activity) == null",
            "PEN_CONTACT_START_PAGES.get(activity) == null",
            "!Boolean.TRUE.equals(PEN_PHYSICAL_CONTACT_DOWNS.get(activity))",
            "TEXT_SELECTION_PEN_CONTACTS.get(activity) == null",
        ),
        "document-origin contact exclusion from native-first chrome routing",
    )
    for forbidden in (
        "SPREAD_CONFIGS",
        "PERSISTED_CONFIG_WATCHES",
        "PEN_INPUT_EDITABLE_GUARDS",
        "PAGE_ACTIVATION_TRANSACTIONS",
        "PAGE_SAVE_IN_FLIGHT_COUNTS",
    ):
        if forbidden in chrome_native_first_guard:
            fail(
                "native-first chrome classification is incorrectly vetoed "
                f"by {forbidden} instead of only preserving an existing "
                "document-origin contact"
            )
    if (
        "allowNative" in native_chrome_code
        or "nativeChromePassThroughSafeLocked" in native_chrome_code
    ):
        fail(
            "a visible native-chrome DOWN can still be downgraded to a "
            "blocked route by module authority state"
        )
    chrome_activity_route = native_chrome_code[
        chrome_activity_route_start:chrome_native_route_start
    ]
    activity_existing_branch = chrome_activity_route.find(
        "if (action != MotionEvent.ACTION_DOWN)"
    )
    activity_down_refresh = chrome_activity_route.find(
        "NativeChromeRect refreshedHit = nativeChromeHit(",
        activity_existing_branch,
    )
    activity_down_refresh_flag = chrome_activity_route.find(
        "true", activity_down_refresh
    )
    activity_hit_guard = chrome_activity_route.find(
        "if (hit == null)",
        activity_down_refresh_flag,
    )
    activity_token_construct = chrome_activity_route.find(
        "NativeChromePassThrough token = new NativeChromePassThrough(",
        activity_hit_guard,
    )
    activity_token_publish = chrome_activity_route.find(
        "NATIVE_CHROME_PEN_PASSTHROUGHS.putIfAbsent(",
        activity_token_construct,
    )
    activity_pass_log = chrome_activity_route.find(
        '"native_chrome_contact_classified generation="',
        activity_token_publish,
    )
    activity_pass_literal = chrome_activity_route.find(
        '" route=pass"', activity_pass_log
    )
    activity_pass_return = chrome_activity_route.find(
        "return NATIVE_CHROME_ROUTE_PASS;", activity_pass_literal
    )
    if not (
        0 <= activity_existing_branch < activity_down_refresh
        < activity_down_refresh_flag < activity_hit_guard
        < activity_token_construct < activity_token_publish
        < activity_pass_log < activity_pass_literal < activity_pass_return
    ):
        fail(
            "stylus chrome routing is not classified once from refreshed "
            "visible geometry at ACTION_DOWN and passed to firmware"
        )
    if "PAGE_ACTIVATION_OWNERSHIP_LOCK" in chrome_activity_route:
        fail(
            "Activity-confirmed native chrome is still conditioned on module "
            "page/writer authority"
        )
    if "PEN_CONTACT_OWNERSHIPS.put" in chrome_activity_route:
        fail("native-chrome pass-through publishes handwriting ownership")
    require_markers(
        chrome_activity_route,
        (
            'native_chrome_contact_reclassified_document',
            "adoptNativeChromeActivityDown(",
            'reason=publication_race',
            "return NATIVE_CHROME_ROUTE_BLOCK;",
        ),
        "race-safe Activity native-chrome publication",
    )

    chrome_native_route = native_chrome_code[
        chrome_native_route_start:chrome_current_start
    ]
    native_existing = chrome_native_route.find(
        "NATIVE_CHROME_PEN_PASSTHROUGHS.get(activity)"
    )
    native_existing_pass = chrome_native_route.find(
        "return NATIVE_CHROME_ROUTE_PASS;", native_existing
    )
    native_positive = chrome_native_route.find(
        "if (pressure <= 0)", native_existing_pass
    )
    native_document_guard_lock = chrome_native_route.find(
        "synchronized (PAGE_ACTIVATION_OWNERSHIP_LOCK)", native_positive
    )
    native_document_guard = chrome_native_route.find(
        "!nativeChromeNativeFirstMayClassifyLocked(activity)",
        native_document_guard_lock,
    )
    native_document_return = chrome_native_route.find(
        "return NATIVE_CHROME_ROUTE_DOCUMENT;", native_document_guard
    )
    native_cached_hit = chrome_native_route.find(
        "nativeChromeHit(activity, x, y, true)", native_document_return
    )
    native_token_publish = chrome_native_route.find(
        "NATIVE_CHROME_PEN_PASSTHROUGHS.putIfAbsent(", native_cached_hit
    )
    if not (
        0 <= native_existing < native_existing_pass < native_positive
        < native_document_guard_lock < native_document_guard
        < native_document_return < native_cached_hit < native_token_publish
    ):
        fail(
            "native-first chrome DOWN does not preserve document-origin "
            "classification before adopting cached UI geometry"
        )
    native_pass_log = chrome_native_route.find(
        '"native_chrome_contact_native_first generation="',
        native_token_publish,
    )
    native_pass_literal = chrome_native_route.find(
        '" route=pass"', native_pass_log
    )
    native_pass_return = chrome_native_route.find(
        "return NATIVE_CHROME_ROUTE_PASS;", native_pass_literal
    )
    if not (
        0 <= native_token_publish < native_pass_log
        < native_pass_literal < native_pass_return
    ):
        fail("native-first visible chrome is not unconditionally passed")
    require_markers(
        chrome_native_route,
        (
            "raced.downBounds.contains(x, y)",
            'reason=native_publication_race',
            "return NATIVE_CHROME_ROUTE_BLOCK;",
        ),
        "race-safe native-first chrome publication",
    )

    handwrite_area_selection_start = native_chrome_code.find(
        '"setAreaSelection"'
    )
    handwrite_set_pen_start = native_chrome_code.find(
        '"setPen"', handwrite_area_selection_start
    )
    if min(handwrite_area_selection_start, handwrite_set_pen_start) < 0:
        fail("could not isolate the handwriting lasso setter hook")
    handwrite_area_selection = native_chrome_code[
        handwrite_area_selection_start:handwrite_set_pen_start
    ]
    setter_pass = handwrite_area_selection.find(
        "nativeChromeSetterPassThroughCurrent(activity)"
    )
    writer_check = handwrite_area_selection.find(
        "documentMutationAuthorityCurrent(", setter_pass
    )
    setter_admitted = handwrite_area_selection.find(
        "scope.mutationAdmitted = true;", writer_check
    )
    setter_log = handwrite_area_selection.find(
        'native_chrome_setter_passthrough', setter_admitted
    )
    if not 0 <= setter_pass < writer_check < setter_admitted < setter_log:
        fail(
            "native-chrome lasso setter is not admitted by its exact-contact "
            "token before writer-authority rejection"
        )

    chrome_finish = native_chrome_code[chrome_finish_start:chrome_latch_start]
    finish_up = chrome_finish.find("action != MotionEvent.ACTION_UP")
    finish_cancel = chrome_finish.find("action != MotionEvent.ACTION_CANCEL")
    finish_exact = chrome_finish.find("token.matches(event)", finish_cancel)
    finish_remove = chrome_finish.find(
        "NATIVE_CHROME_PEN_PASSTHROUGHS.remove(activity, token)", finish_exact
    )
    if not 0 <= finish_up < finish_cancel < finish_exact < finish_remove:
        fail("native-chrome token is not cleared only by its exact UP/CANCEL")

    dispatch_chrome_route = dispatch_touch_hook.find(
        "routeNativeChromeActivityStylus(activity, event)"
    )
    dispatch_chrome_pass = dispatch_touch_hook.find(
        "nativeChromeRoute == NATIVE_CHROME_ROUTE_PASS", dispatch_chrome_route
    )
    dispatch_chrome_pass_return = dispatch_touch_hook.find(
        "return;", dispatch_chrome_pass
    )
    dispatch_chrome_block = dispatch_touch_hook.find(
        "nativeChromeRoute == NATIVE_CHROME_ROUTE_BLOCK",
        dispatch_chrome_pass_return,
    )
    dispatch_chrome_block_result = dispatch_touch_hook.find(
        "param.setResult(true);", dispatch_chrome_block
    )
    dispatch_tracking = dispatch_touch_hook.find(
        "trackFingerTouchStream(activity, event)", dispatch_chrome_block_result
    )
    dispatch_contact_latch = dispatch_touch_hook.find(
        "latchPenContactFromActivityTouch(", dispatch_tracking
    )
    if not (
        0 <= dispatch_chrome_route < dispatch_chrome_pass
        < dispatch_chrome_pass_return < dispatch_chrome_block
        < dispatch_chrome_block_result
        < dispatch_contact_latch
    ):
        fail(
            "Activity stylus chrome pass-through does not precede every "
            "trace/ownership/activation path"
        )

    text_mode_start = native_chrome_code.find(
        "private static boolean textSelectionModeActive("
    )
    text_guard_start = native_chrome_code.find(
        "private static String textSelectionClassificationBlockReasonLocked(",
        text_mode_start,
    )
    text_preclassified_adopt_start = native_chrome_code.find(
        "private static void adoptTextSelectionPreclassifiedDigitalDownLocked(",
        text_guard_start,
    )
    text_activity_route_start = native_chrome_code.find(
        "private static int routeTextSelectionActivityStylus(",
        text_preclassified_adopt_start,
    )
    text_native_route_start = native_chrome_code.find(
        "private static int routeTextSelectionNativePen(",
        text_activity_route_start,
    )
    text_adopt_start = native_chrome_code.find(
        "private static boolean adoptTextSelectionActivityDown(",
        text_native_route_start,
    )
    text_apply_gate_start = native_chrome_code.find(
        "private static boolean applyTextSelectionActivityGate(",
        text_adopt_start,
    )
    text_restore_gate_start = native_chrome_code.find(
        "private static boolean restoreTextSelectionActivityGate(",
        text_apply_gate_start,
    )
    text_retire_start = native_chrome_code.find(
        "private static boolean retireTextSelectionContact(",
        text_restore_gate_start,
    )
    text_clear_start = native_chrome_code.find(
        "private static void clearTextSelectionContact(",
        text_retire_start,
    )
    text_fallback_start = native_chrome_code.find(
        "private static void scheduleTextSelectionTerminalFallback(",
        text_clear_start,
    )
    text_current_start = native_chrome_code.find(
        "private static boolean textSelectionActivityContactCurrent(",
        text_fallback_start,
    )
    text_finish_start = native_chrome_code.find(
        "private static void finishTextSelectionActivityContact(",
        text_current_start,
    )
    if not (
        0 <= text_mode_start < text_guard_start
        < text_preclassified_adopt_start < text_activity_route_start
        < text_native_route_start < text_adopt_start < text_apply_gate_start
        < text_restore_gate_start < text_retire_start < text_clear_start
        < text_fallback_start < text_current_start < text_finish_start
        < chrome_latch_start
    ):
        fail("could not isolate gesture-scoped text-selection routing")

    text_guard = native_chrome_code[
        text_guard_start:text_preclassified_adopt_start
    ]
    require_markers(
        text_guard,
        (
            "NATIVE_CHROME_PEN_PASSTHROUGHS.get(activity) != null",
            "PEN_CONTACT_OWNERSHIPS.get(activity) != null",
            "PEN_CONTACT_START_PAGES.get(activity) != null",
            "Boolean.TRUE.equals(PEN_PHYSICAL_CONTACT_DOWNS.get(activity))",
            "&& !authoritativeActivityDown",
            'return "physical_contact_down";',
            "PAGE_ACTIVATION_TRANSACTIONS.get(activity) != null",
            "canonicalLassoUiOwnsPenContact(activity)",
        ),
        "text-selection classification of every competing contact owner",
    )
    if "TEXT_SELECTION_PEN_CONTACTS.get(activity)" in text_guard:
        fail(
            "the shared text-selection guard rejects a same-subsystem "
            "publication race before putIfAbsent can adopt it"
        )
    physical_gate = text_guard.find(
        "Boolean.TRUE.equals(PEN_PHYSICAL_CONTACT_DOWNS.get(activity))"
    )
    authoritative_exception = text_guard.find(
        "&& !authoritativeActivityDown", physical_gate
    )
    physical_reason = text_guard.find(
        'return "physical_contact_down";', authoritative_exception
    )
    if not (0 <= physical_gate < authoritative_exception < physical_reason):
        fail(
            "native-first text selection no longer rejects an already-down "
            "physical contact while authoritative Activity DOWN may adopt it"
        )

    text_preclassified_adopt = native_chrome_code[
        text_preclassified_adopt_start:text_activity_route_start
    ]
    require_markers(
        text_preclassified_adopt,
        (
            "TEXT_SELECTION_PEN_CONTACTS.get(activity) != token",
            "PEN_CONTACT_OWNERSHIPS.get(activity) != null",
            "PEN_CONTACT_START_PAGES.get(activity) != null",
            "!PEN_PHYSICAL_CONTACT_DOWNS.remove(activity, Boolean.TRUE)",
            '"text_selection_preclassified_digital_down_adopted generation="',
        ),
        "atomic adoption of the preclassified digital-down signal",
    )
    if "PEN_PHYSICAL_CONTACT_DOWNS.put" in text_preclassified_adopt:
        fail("text-selection digital-down adoption can publish writer state")

    text_activity_route = native_chrome_code[
        text_activity_route_start:text_native_route_start
    ]
    require_markers(
        text_activity_route,
        (
            "event.getActionMasked()",
            "textSelectionModeActive(activity)",
            "snapshot.editable",
            "snapshot.geometryReady",
            "mappedPage != snapshot.currentPage",
            "PEN_INPUT_SNAPSHOTS.get(activity) != snapshot",
            "SPREAD_CONFIGS.get(activity) != snapshot.config",
            "synchronized (PAGE_ACTIVATION_OWNERSHIP_LOCK)",
            "textSelectionClassificationBlockReasonLocked(",
            "TEXT_SELECTION_PEN_CONTACTS.putIfAbsent(activity, token)",
            "adoptTextSelectionPreclassifiedDigitalDownLocked(",
            '"text_selection_contact_rejected source=activity reason="',
            "return NATIVE_CHROME_ROUTE_BLOCK;",
            "applyTextSelectionActivityGate(activity, existing)",
            "applyTextSelectionActivityGate(activity, raced)",
            "applyTextSelectionActivityGate(activity, token)",
            '"text_selection_contact_classified generation="',
            '" source=activity page="',
            "return NATIVE_CHROME_ROUTE_PASS;",
        ),
        "Activity text-selection exact-contact publication",
    )
    if re.search(
        r"textSelectionClassificationBlockReasonLocked\s*\(\s*"
        r"activity\s*,\s*true\s*\)",
        text_activity_route,
    ) is None:
        fail("Activity text selection is not the authoritative DOWN classifier")
    if text_activity_route.count(
        "adoptTextSelectionPreclassifiedDigitalDownLocked("
    ) != 3:
        fail(
            "Activity text selection does not adopt the early digital-down "
            "signal on existing, raced, and newly published token paths"
        )
    activity_reject = text_activity_route.find(
        '"text_selection_contact_rejected source=activity reason="'
    )
    activity_block = text_activity_route.find(
        "return NATIVE_CHROME_ROUTE_BLOCK;", activity_reject
    )
    activity_publish = text_activity_route.find(
        "TEXT_SELECTION_PEN_CONTACTS.putIfAbsent(activity, token)"
    )
    if not (0 <= activity_reject < activity_block < activity_publish):
        fail("rejected Activity text selection can fall through as handwriting")
    if (
        "PEN_CONTACT_OWNERSHIPS.put" in text_activity_route
        or "PEN_PHYSICAL_CONTACT_DOWNS.put" in text_activity_route
        or "beginPageActivationTransaction(" in text_activity_route
    ):
        fail("Activity text selection still publishes handwriting/activation")
    text_non_down_gate = text_activity_route.find(
        "existing.matches(event) && existing.activityGateApplied"
    )
    text_new_gate = text_activity_route.find(
        "if (!applyTextSelectionActivityGate(activity, token))"
    )
    text_new_classified = text_activity_route.find(
        '"text_selection_contact_classified generation="', text_new_gate
    )
    if not (0 <= text_non_down_gate < text_new_gate < text_new_classified):
        fail(
            "Activity text selection can pass without the exact native "
            "page-turn gate"
        )

    text_native_route = native_chrome_code[
        text_native_route_start:text_adopt_start
    ]
    require_markers(
        text_native_route,
        (
            "TEXT_SELECTION_PEN_CONTACTS.get(activity)",
            "pressure <= 0",
            "textSelectionModeActive(activity)",
            "mappedPage != snapshot.currentPage",
            "PEN_INPUT_SNAPSHOTS.get(activity) != snapshot",
            "SPREAD_CONFIGS.get(activity) != snapshot.config",
            "synchronized (PAGE_ACTIVATION_OWNERSHIP_LOCK)",
            "textSelectionClassificationBlockReasonLocked(",
            "TEXT_SELECTION_PEN_CONTACTS.putIfAbsent(activity, token)",
            '"text_selection_contact_rejected source=native reason="',
            "return NATIVE_CHROME_ROUTE_DOCUMENT;",
            '" source=native page="',
            "return NATIVE_CHROME_ROUTE_PASS;",
        ),
        "native-first text-selection exact-contact publication",
    )
    if re.search(
        r"textSelectionClassificationBlockReasonLocked\s*\(\s*"
        r"activity\s*,\s*false\s*\)",
        text_native_route,
    ) is None:
        fail(
            "native-first text selection can adopt an already-down physical "
            "contact"
        )
    if (
        "PEN_CONTACT_OWNERSHIPS.put" in text_native_route
        or "PEN_PHYSICAL_CONTACT_DOWNS.put" in text_native_route
        or "beginPageActivationTransaction(" in text_native_route
    ):
        fail("native text selection still publishes handwriting/activation")

    text_apply_gate = native_chrome_code[
        text_apply_gate_start:text_restore_gate_start
    ]
    require_markers(
        text_apply_gate,
        (
            "synchronized (token)",
            "TEXT_SELECTION_PEN_CONTACTS.get(activity) != token",
            "token.activityDownTime < 0L",
            "token.activityGateApplied",
            "XposedHelpers.getBooleanField(",
            '"isAllowTurnPage"',
            "XposedHelpers.setBooleanField(",
            "false",
            "token.previousAllowTurnPage = previous",
            "token.activityGateApplied = true",
            '"text_selection_activity_gate_applied generation="',
        ),
        "text-selection native page-turn gate application",
    )

    text_restore_gate = native_chrome_code[
        text_restore_gate_start:text_retire_start
    ]
    require_markers(
        text_restore_gate,
        (
            "synchronized (token)",
            "!token.activityGateApplied",
            "previous = token.previousAllowTurnPage",
            "XposedHelpers.setBooleanField(",
            '"isAllowTurnPage"',
            "previous",
            "token.activityGateApplied = false",
            '"text_selection_activity_gate_restored generation="',
        ),
        "text-selection native page-turn gate restoration",
    )

    text_retire = native_chrome_code[text_retire_start:text_clear_start]
    retire_restore = text_retire.find(
        "restoreTextSelectionActivityGate(activity, token, reason)"
    )
    retire_remove = text_retire.find(
        "TEXT_SELECTION_PEN_CONTACTS.remove(activity, token)",
        retire_restore,
    )
    if not (0 <= retire_restore < retire_remove):
        fail("text-selection contact can retire before restoring page turns")

    text_fallback = native_chrome_code[
        text_fallback_start:text_current_start
    ]
    require_markers(
        text_fallback,
        (
            "token.terminalFallbackScheduled",
            "new Handler(activity.getMainLooper()).postDelayed",
            "TEXT_SELECTION_PEN_CONTACTS.get(activity) != token",
            "retireTextSelectionContact(",
            '"native_terminal_fallback_state_" + state',
        ),
        "bounded text-selection missing-Activity-terminal recovery",
    )

    text_finish = native_chrome_code[text_finish_start:chrome_latch_start]
    text_finish_up = text_finish.find("action != MotionEvent.ACTION_UP")
    text_finish_cancel = text_finish.find("action != MotionEvent.ACTION_CANCEL")
    text_finish_exact = text_finish.find("token.matches(event)", text_finish_cancel)
    text_finish_retire = text_finish.find(
        "retireTextSelectionContact(",
        text_finish_exact,
    )
    if not (
        0 <= text_finish_up < text_finish_cancel < text_finish_exact
        < text_finish_retire
    ):
        fail(
            "text-selection token/gate is not retired by its exact "
            "post-dispatch UP/CANCEL"
        )

    dispatch_text_route = dispatch_touch_hook.find(
        "routeTextSelectionActivityStylus(activity, event)",
        dispatch_chrome_block_result,
    )
    dispatch_text_pass = dispatch_touch_hook.find(
        "textSelectionRoute == NATIVE_CHROME_ROUTE_PASS",
        dispatch_text_route,
    )
    dispatch_text_pass_return = dispatch_touch_hook.find(
        "return;", dispatch_text_pass
    )
    dispatch_text_block = dispatch_touch_hook.find(
        "textSelectionRoute == NATIVE_CHROME_ROUTE_BLOCK",
        dispatch_text_pass_return,
    )
    dispatch_text_block_result = dispatch_touch_hook.find(
        "param.setResult(true);", dispatch_text_block
    )
    dispatch_tracking = dispatch_touch_hook.find(
        "trackFingerTouchStream(activity, event)", dispatch_text_block_result
    )
    dispatch_text_finish = dispatch_touch_hook.find(
        "finishTextSelectionActivityContact(", dispatch_after
    )
    if not (
        0 <= dispatch_chrome_block_result < dispatch_text_route
        < dispatch_text_pass < dispatch_text_pass_return
        < dispatch_text_block < dispatch_text_block_result < dispatch_tracking
        < dispatch_contact_latch < dispatch_after < dispatch_text_finish
        < dispatch_finger_finish
    ):
        fail(
            "Activity text selection does not bypass every ordinary touch, "
            "handwriting, activation, and terminal-fallback path"
        )

    digital_state_end = module.find(
        "XposedHelpers.findAndHookMethod(", digital_state_start + 1
    )
    if digital_state_end < 0:
        fail("could not isolate native digital-state contact bookkeeping")
    digital_state_hook = mask_comments_preserve_literals(
        module[digital_state_start:digital_state_end]
    )
    state_text_lookup = digital_state_hook.find(
        "TEXT_SELECTION_PEN_CONTACTS.get(activity)"
    )
    state_text_terminal = digital_state_hook.find(
        "if (state != 1", state_text_lookup
    )
    state_text_activity_owned = digital_state_hook.find(
        "textSelectionContact.activityDownTime >= 0L",
        state_text_terminal,
    )
    state_text_fallback = digital_state_hook.find(
        "scheduleTextSelectionTerminalFallback(",
        state_text_activity_owned,
    )
    state_text_remove = digital_state_hook.find(
        "TEXT_SELECTION_PEN_CONTACTS.remove(", state_text_fallback
    )
    state_text_return = digital_state_hook.find("return;", state_text_remove)
    state_writer_state_one = digital_state_hook.find(
        "if (state == 1)", state_text_return
    )
    state_writer_text_recheck = digital_state_hook.find(
        "if (TEXT_SELECTION_PEN_CONTACTS.get(activity)",
        state_writer_state_one,
    )
    state_writer_down = digital_state_hook.find(
        "PEN_PHYSICAL_CONTACT_DOWNS.put(", state_writer_text_recheck
    )
    state_writer_lift = digital_state_hook.find(
        "PEN_PHYSICAL_CONTACT_DOWNS.remove(", state_writer_down
    )
    if not (
        0 <= state_text_lookup < state_text_terminal
        < state_text_activity_owned < state_text_fallback < state_text_remove
        < state_text_return < state_writer_state_one
        < state_writer_text_recheck < state_writer_down < state_writer_lift
    ):
        fail(
            "native text-selection terminal handling can enter ordinary "
            "physical-contact bookkeeping"
        )

    change_select_start = native_chrome_code.find('"changeSelectTextModel"')
    change_select_end = native_chrome_code.find(
        "XposedHelpers.findAndHookMethod(", change_select_start + 1
    )
    handwrite_select_start = native_chrome_code.find('"handWriteSelectText"')
    handwrite_select_end = native_chrome_code.find(
        "XposedHelpers.findAndHookMethod(", handwrite_select_start + 1
    )
    configure_select_start = native_chrome_code.find(
        "private static void configureTextSelectionHardware("
    )
    configure_select_end = native_chrome_code.find(
        "private static boolean applySpreadMarkGeometry(",
        configure_select_start,
    )
    if min(
        change_select_start,
        change_select_end,
        handwrite_select_start,
        handwrite_select_end,
        configure_select_start,
        configure_select_end,
    ) < 0:
        fail("could not isolate native text-selection hardware configuration")
    change_select = native_chrome_code[change_select_start:change_select_end]
    configure_select = native_chrome_code[
        configure_select_start:configure_select_end
    ]
    require_markers(
        change_select,
        (
            "TEXT_SELECTION_MODES.put(activity, model)",
            "TEXT_SELECTION_MODES.remove(activity)",
            "configureTextSelectionHardware(",
            '"model_changed:" + model',
        ),
        "text-selection mode publication and native hardware configuration",
    )
    require_markers(
        configure_select,
        (
            "resolveActivePageDestination(activity, presenter)",
            "activePageDisabledAreas(",
            '"setDisableAreaList"',
            '"sendWriteInfo"',
            "applySpreadMarkGeometry(",
            '"text_selection_hardware_configured reason="',
        ),
        "active-page native text-selection hardware configuration",
    )
    forbidden_text_selection_disable = (
        "setTextSelectionHardwareGate(",
        '"SN_SPREAD_PROBE text-selection hardware trail"',
        '"text_selection_hardware_disabled reason="',
    )
    for forbidden in forbidden_text_selection_disable:
        if forbidden in native_chrome_code:
            fail(
                "native text-selection hardware is still disabled by "
                + forbidden
            )
    handwrite_select = native_chrome_code[
        handwrite_select_start:handwrite_select_end
    ]
    if (
        "configureTextSelectionHardware(" in handwrite_select
        or "disableHandWrite" in handwrite_select
    ):
        fail("handWriteSelectText can still disable/reconfigure hardware mid-gesture")

    release_start = native_chrome_code.find(
        "private static void releaseActivityResources("
    )
    retire_identity_start = native_chrome_code.find(
        "private static void retireActivityComponentIdentity(", release_start
    )
    reset_editing_start = native_chrome_code.find(
        "private static void resetSpreadEditingState(", retire_identity_start
    )
    reset_editing_end = native_chrome_code.find(
        "private static boolean isCalibrationFile(", reset_editing_start
    )
    if min(
        release_start,
        retire_identity_start,
        reset_editing_start,
        reset_editing_end,
    ) < 0:
        fail("could not isolate text-selection lifecycle cleanup")
    require_markers(
        native_chrome_code[release_start:retire_identity_start],
        (
            'clearTextSelectionContact(activity, "activity_release")',
            "TEXT_SELECTION_MODES.remove(activity)",
        ),
        "per-activity text-selection cleanup",
    )
    require_markers(
        native_chrome_code[reset_editing_start:reset_editing_end],
        (
            "TEXT_SELECTION_PEN_CONTACTS.keySet()",
            "clearTextSelectionContact(",
            '"editing_reset_" + reason',
            "TEXT_SELECTION_MODES.clear()",
        ),
        "global text-selection cleanup",
    )
    if "TEXT_SELECTION_PEN_CONTACTS.clear()" in native_chrome_code:
        fail("global text-selection cleanup can discard an applied gate")

    require_markers(
        module,
        (
            "TRACE_CONTROL_ACTION",
            "TRACE_CONTROL_PERMISSION",
            '"android.permission.DUMP"',
            "registerTraceControlReceiver(createdActivity)",
            '"trace_session_started"',
            '"pen_contact_started"',
            '"annotation_boundary"',
            '"save_trails_before"',
            '"save_trails_after"',
            '"receive_trials_before"',
            '"receive_trials_after"',
            '"modify_page_trails"',
            "beginTraceMutationAdmission(",
            '"modify_page_trails_finished"',
            '"mark_snapshot"',
            '"orderedFingerprint"',
            "FileObserver.CLOSE_WRITE",
            "TRACE_MAX_SNAPSHOT_BYTES",
            "TRACE_SNAPSHOT_DEBOUNCE_MS",
            "ScheduledExecutorService",
            "snapshotExecutor.schedule(",
            "pendingSnapshot.cancel(false)",
            "scheduleTraceWorkerTask(",
            "scheduleTraceMarkSnapshot(",
            "lastSnapshotIdentity",
            "traceLogMessage(message)",
        ),
        "opt-in annotation transaction tracing",
    )

    observer_start = module.find(
        "private static void startTraceMarkObserver("
    )
    touch_trace_start = module.find(
        "private static void traceTouchEvent(", observer_start
    )
    if observer_start < 0 or touch_trace_start < 0:
        fail("could not isolate mark observer trace scheduling")
    mark_observer = module[observer_start:touch_trace_start]
    if "scheduleTraceMarkSnapshot(" not in mark_observer:
        fail("mark observer does not use the serialized snapshot worker")
    if "session.markGeneration.incrementAndGet()" not in mark_observer:
        fail("mark observer does not fence final trace source generations")
    if "Looper.getMainLooper()" in mark_observer:
        fail("mark observer still posts snapshot hashing onto the UI thread")

    trace_start = module.find("private static void startAnnotationTrace(")
    checkpoint_start = module.find(
        "private static void checkpointAnnotationTrace(", trace_start
    )
    if trace_start < 0 or checkpoint_start < 0:
        fail("could not isolate trace startup failure cleanup")
    require_markers(
        module[trace_start:checkpoint_start],
        (
            "boolean activePointerAttempted = false;",
            "writeNewTracePointer(existingActive, sessionId)",
            "FileIdentity activePointerIdentity =",
            "tracePointerMatchesSession(",
            "existingActive,",
            "activePointerIdentity",
            "failedObserver.stopWatching()",
            "started.mutationAdmissionClosed = true",
            "started.pendingSnapshot.cancel(false)",
            "started.snapshotExecutor.shutdownNow()",
            "started.eventExecutor.shutdownNow()",
            "if (activePointerAttempted)",
            "preserveTraceStartupFailure(started, throwable)",
            "ensureExactTracePointer(",
            'new File(root, "incomplete.txt")',
            'new File(root, "publication-failed.txt")',
        ),
        "failed trace startup cleanup",
    )
    trace_startup = module[trace_start:checkpoint_start]
    if '"last.txt"' in trace_startup:
        fail("trace startup publishes last.txt before finalization")

    finish_start = module.find("private static void finishTraceSession(")
    observer_start = module.find(
        "private static void startTraceMarkObserver(", finish_start
    )
    if finish_start < 0 or observer_start < 0:
        fail("could not isolate completed trace pointer publication")
    finish_trace = module[finish_start:observer_start]
    if module.count('"last.txt"') != 1:
        fail("last.txt must be published only by completed trace finalization")
    require_markers(
        finish_trace,
        (
            "boolean requestedCompleted",
            "boolean mutationAdmissionsDrained =",
            "awaitTraceMutationAdmissions(session)",
            "boolean eventAdmissionsDrained = awaitTraceEventAdmissions(session)",
            "boolean eventWriterDrained = drainTraceEventWriter(session)",
            "boolean eventLogComplete = eventAdmissionsDrained",
            "session.finalPenInputMutationGeneration",
            "session.penInputMutationGeneration.get()",
            "boolean completed = requestedCompleted",
            "File active = new File(",
            "File incomplete = new File(",
            'new File(session.rootDirectory, "last.txt")',
            "if (!completed)",
            "ensureExactTracePointer(incomplete, session.id)",
            '"publication-failed.txt"',
            "preserveTracePublicationFailure(",
            "session.mutationAdmissionSealed = true",
            "validateCompletedTracePointerForCommit(",
            "Os.rename(activePath, lastPath)",
            "if (publicationFailure == null && !completed",
            "tracePointerMatchesSession(",
            "session.activePointerIdentity",
        ),
        "completed-versus-incomplete trace pointer publication",
    )
    writer_drain = finish_trace.find("drainTraceEventWriter(session)")
    prepublication_source_check = finish_trace.find(
        "isTraceFinalSourceCurrent(session)", writer_drain
    )
    initial_incomplete = finish_trace.find(
        "ensureExactTracePointer(incomplete, session.id)",
        prepublication_source_check,
    )
    stop_observer = finish_trace.find(
        "stopTraceMarkObserver(session)", initial_incomplete
    )
    post_cleanup_source_check = finish_trace.find(
        "isTraceFinalSourceCurrent(session)", stop_observer
    )
    completed_pointer_guard = finish_trace.find(
        "if (publicationFailure == null && completed)",
        post_cleanup_source_check,
    )
    incomplete_absence_guard = finish_trace.find(
        "traceGuardNodeExists(incomplete)",
        completed_pointer_guard,
    )
    final_input_lock = finish_trace.find(
        "synchronized (PAGE_ACTIVATION_OWNERSHIP_LOCK)",
        incomplete_absence_guard,
    )
    final_admission_close = finish_trace.find(
        "session.penInputAdmissionClosed = true", final_input_lock
    )
    final_input_check = finish_trace.find(
        "isTraceInputQuiescent(activity)", final_admission_close
    )
    final_generation_check = finish_trace.find(
        "session.penInputMutationGeneration.get()", final_input_check
    )
    final_reject_incomplete = finish_trace.find(
        "ensureExactTracePointer(incomplete, session.id)",
        final_generation_check,
    )
    mutation_lock = finish_trace.find(
        "synchronized (TRACE_LOCK)", final_reject_incomplete
    )
    mutation_zero = finish_trace.find(
        "session.mutationAdmissions.get() == 0", mutation_lock
    )
    mutation_not_late = finish_trace.find(
        "!session.lateMutationObserved", mutation_zero
    )
    mutation_seal = finish_trace.find(
        "session.mutationAdmissionSealed = true", mutation_not_late
    )
    final_snapshot_check = finish_trace.find(
        "isTraceFinalSnapshotArtifactCurrent(session)", mutation_seal
    )
    pointer_validation = finish_trace.find(
        "validateCompletedTracePointerForCommit(", final_snapshot_check
    )
    active_path = finish_trace.find(
        "String activePath = active.getAbsolutePath()", pointer_validation
    )
    final_source_check = finish_trace.find(
        "isTraceFinalSourceCurrent(session)", active_path
    )
    atomic_rename = finish_trace.find(
        "Os.rename(activePath, lastPath)", final_source_check
    )
    retain_active_guard = finish_trace.find(
        "if (publicationFailure == null && !completed", atomic_rename
    )
    exact_active_guard = finish_trace.find(
        "tracePointerMatchesSession(", retain_active_guard
    )
    if not (
        0 <= writer_drain < prepublication_source_check
        < initial_incomplete < stop_observer < post_cleanup_source_check
        < completed_pointer_guard < incomplete_absence_guard < final_input_lock
        < final_admission_close < final_input_check < final_generation_check
        < final_reject_incomplete < mutation_lock < mutation_zero
        < mutation_not_late < mutation_seal < final_snapshot_check
        < pointer_validation
        < active_path < final_source_check < atomic_rename
        < retain_active_guard < exact_active_guard
    ):
        fail(
            "trace completion publishes last.txt before its observer boundary, "
            "incomplete cleanup, adjacent live-input/source revalidation, and "
            "atomic terminal pointer commit are complete"
        )
    final_publication_fence = finish_trace[
        final_input_lock:atomic_rename
    ]
    require_markers(
        final_publication_fence,
        (
            "isTraceInputQuiescent(activity)",
            "session.penInputAdmissionClosed = true",
            "session.penInputMutationGeneration.get()",
            "!= expectedPenInputGeneration",
            "completed = false;",
            "ensureExactTracePointer(incomplete, session.id)",
            "session.mutationAdmissions.get() == 0",
            "!session.lateMutationObserved",
            "session.mutationAdmissionSealed = true",
            "isTraceFinalSnapshotArtifactCurrent(session)",
            "validateCompletedTracePointerForCommit(",
            "isTraceFinalSourceCurrent(session)",
            "} else {",
        ),
        "post-cleanup trace source/input publication fence",
    )
    if (
        "writeTraceText(last, session.id" in finish_trace
        or "writeTraceText(incomplete" in finish_trace
        or "incomplete.delete()" in finish_trace
        or "active.delete()" in finish_trace
        or "publishCompletedTracePointerAtomically(" in finish_trace
        or "last.delete()" in finish_trace
        or "appendAcceptedTraceTerminalEvent(" in finish_trace
        or '"trace_session_stopped"' in finish_trace
    ):
        fail("trace completion exposes or retracts an unaccepted last.txt")
    require_markers(
        finish_trace,
        (
            "validateCompletedTracePointerForCommit(",
            "String activePath = active.getAbsolutePath()",
            "String lastPath = last.getAbsolutePath()",
            "Os.rename(activePath, lastPath)",
        ),
        "single-operation completed-trace terminal pointer commit",
    )
    trace_overlay_refresh_start = module.find(
        "private static void refreshStatusOverlayAfterTraceStop(", finish_start
    )
    trace_overlay_refresh_end = module.find(
        "private static boolean isTraceInputQuiescent(",
        trace_overlay_refresh_start,
    )
    if trace_overlay_refresh_start < 0 or trace_overlay_refresh_end < 0:
        fail("could not isolate post-trace status-overlay restoration")
    finish_method = mask_comments_preserve_literals(
        module[finish_start:trace_overlay_refresh_start]
    )
    overlay_restore_call = finish_method.find(
        "refreshStatusOverlayAfterTraceStop("
    )
    overlay_complete_argument = finish_method.find(
        "completed && publicationFailure == null", overlay_restore_call
    )
    if not (0 <= overlay_restore_call < overlay_complete_argument):
        fail(
            "trace finalization does not restore status from the accepted "
            "durable completion result"
        )
    trace_overlay_refresh = mask_comments_preserve_literals(
        module[trace_overlay_refresh_start:trace_overlay_refresh_end]
    )
    require_markers(
        trace_overlay_refresh,
        (
            "new Handler(activity.getMainLooper()).post(",
            "synchronized (TRACE_LOCK)",
            "traceSession != null || traceStartPending",
            "!isActiveActivityOwner(activity)",
            "config == null || !config.enabled || !config.showHeader",
            "if (!completed)",
            '"SPREAD TRACE: stopped incompletely - recovery required"',
            "snapshot == null || !snapshot.editable",
            "|| !snapshot.geometryReady",
            'activeSide = "LEFT"',
            'activeSide = "RIGHT"',
            '"RTL SPREAD: ACTIVE " + activeSide',
            '"trace_status_overlay_restored state=active"',
        ),
        "post-trace truthful status-overlay restoration",
    )
    trace_overlay_lock = trace_overlay_refresh.find("synchronized (TRACE_LOCK)")
    trace_overlay_session_guard = trace_overlay_refresh.find(
        "traceSession != null || traceStartPending", trace_overlay_lock
    )
    trace_overlay_owner = trace_overlay_refresh.find(
        "!isActiveActivityOwner(activity)", trace_overlay_session_guard
    )
    trace_overlay_incomplete = trace_overlay_refresh.find(
        "if (!completed)", trace_overlay_owner
    )
    trace_overlay_normal = trace_overlay_refresh.find(
        '"RTL SPREAD: ACTIVE " + activeSide', trace_overlay_incomplete
    )
    if not (
        0 <= trace_overlay_lock < trace_overlay_session_guard
        < trace_overlay_owner < trace_overlay_incomplete < trace_overlay_normal
    ):
        fail(
            "post-trace overlay can overwrite a newer trace or report ordinary "
            "status after an incomplete stop"
        )
    pointer_commit_validator_start = module.find(
        "private static void validateCompletedTracePointerForCommit("
    )
    pointer_commit_validator_end = module.find(
        "private static void copyTraceFile(", pointer_commit_validator_start
    )
    if pointer_commit_validator_start < 0 or pointer_commit_validator_end < 0:
        fail("could not isolate completed-trace pointer validator")
    require_markers(
        module[pointer_commit_validator_start:pointer_commit_validator_end],
        (
            "tracePointerMatchesSession(",
            "active,",
            "sessionId,",
            "expectedActiveIdentity",
            "active.getParentFile().equals(last.getParentFile())",
            "FileIdentity immediatelyBeforeRename = FileIdentity.capture(active)",
            "expectedActiveIdentity.sameAs(immediatelyBeforeRename)",
        ),
        "exact completed-trace pointer validation",
    )
    require_markers(
        finish_trace,
        (
            "isTraceInputQuiescent(activity)",
            "private static boolean isTraceLiveSourceCurrent(",
            "private static boolean isTraceFinalSourceCurrent(",
            "session.activity.get()",
            "activeActivity != activity",
            "session.documentPath",
            "currentDocumentPath(activity)",
            '"handWritePresenter"',
            "session.markPath",
            "liveMarkPath",
            "session.finalSnapshotMarkGeneration",
            "session.lastSnapshotIdentity.sameAs(current)",
            "generationBefore == generationAfter",
        ),
        "final trace source/contact publication fence",
    )
    final_source_method_start = finish_trace.find(
        "private static boolean isTraceFinalSourceCurrent("
    )
    final_source_method_end = finish_trace.find(
        "private static HandshakeContext captureHandshakeContext(",
        final_source_method_start,
    )
    if final_source_method_start < 0 or final_source_method_end < 0:
        fail("could not isolate final trace live-source validation")
    final_source_method = finish_trace[
        final_source_method_start:final_source_method_end
    ]
    if final_source_method.count("isTraceLiveSourceCurrent(session)") < 2:
        fail(
            "trace completion does not revalidate the live activity, document, "
            "and presenter mark source after copying its final source identity"
        )
    final_live_before = final_source_method.find(
        "boolean liveSourceCurrentBefore ="
    )
    final_identity_capture = final_source_method.find(
        "FileIdentity current = FileIdentity.capture(", final_live_before
    )
    final_live_after = final_source_method.find(
        "boolean liveSourceCurrentAfter =", final_identity_capture
    )
    final_source_lock = final_source_method.find(
        "synchronized (TRACE_LOCK)", final_live_after
    )
    if not (
        0 <= final_live_before < final_identity_capture < final_live_after
        < final_source_lock
    ):
        fail("final trace source identity is not captured outside TRACE_LOCK")
    final_source_locked_body = final_source_method[final_source_lock:]
    final_source_blocking_hits = [
        marker for marker in (
            "isTraceLiveSourceCurrent(",
            "FileIdentity.capture(",
            "currentDocumentPath(",
            "XposedHelpers.",
        )
        if marker in final_source_locked_body
    ]
    if final_source_blocking_hits:
        fail(
            "final trace validation performs blocking source/filesystem work "
            f"while holding TRACE_LOCK: {final_source_blocking_hits}"
        )
    require_markers(
        finish_trace,
        (
            "private static boolean drainTraceEventWriter(",
            "session.eventExecutor.shutdown()",
            "session.eventExecutor.awaitTermination(",
            "session.eventWriteFailure",
            "private static void preserveTracePublicationFailure(",
            "ensureExactTracePointer(failed, session.id)",
            "tracePointerMatchesSession(failed, session.id)",
            '"publication-failure.txt"',
        ),
        "event-writer drain and explicit publication-failure state",
    )
    if ("active.renameTo(failed)" in finish_trace
        or "active.delete()" in finish_trace):
        fail("trace publication failure can remove the active durable guard")

    stable_final_start = module.find(
        "private static boolean captureStableFinalTraceMarkSnapshot("
    )
    snapshot_start = module.find(
        "private static boolean captureTraceMarkSnapshot(", stable_final_start
    )
    if stable_final_start < 0 or snapshot_start < 0:
        fail("could not isolate stable final trace snapshot retry")
    stable_final = module[stable_final_start:snapshot_start]
    require_markers(
        stable_final,
        (
            "TRACE_FINAL_SNAPSHOT_ATTEMPTS",
            "captureTraceMarkSnapshot(",
            "return true",
            "SystemClock.sleep(TRACE_FINAL_SNAPSHOT_RETRY_MS)",
            "return false",
        ),
        "stable final trace snapshot retry",
    )
    snapshot_capture_end = module.find(
        "private static void traceEvent(", snapshot_start
    )
    if snapshot_capture_end < 0:
        fail("could not isolate final snapshot source verification")
    snapshot_capture = module[snapshot_start:snapshot_capture_end]
    published_source = snapshot_capture.find(
        "FileIdentity publishedSource = FileIdentity.capture(mark);"
    )
    snapshot_before = snapshot_capture.find(
        "FileIdentity snapshotBefore = FileIdentity.capture(snapshot);",
        published_source,
    )
    verify_snapshot = snapshot_capture.find(
        "String publishedHash = sha256(snapshot);", snapshot_before
    )
    snapshot_after = snapshot_capture.find(
        "FileIdentity snapshotAfter = FileIdentity.capture(snapshot);",
        verify_snapshot,
    )
    verified_source = snapshot_capture.find(
        "FileIdentity verifiedSource = FileIdentity.capture(mark);",
        snapshot_after,
    )
    compare_verified = snapshot_capture.find(
        "!publishedSource.sameAs(verifiedSource)", verified_source
    )
    accepted_source = snapshot_capture.find(
        "FileIdentity acceptedSource = FileIdentity.capture(mark);",
        compare_verified,
    )
    compare_accepted = snapshot_capture.find(
        "!verifiedSource.sameAs(acceptedSource)", accepted_source
    )
    accepted_state = snapshot_capture.find(
        "expected.lastSnapshotIdentity = acceptedSource;",
        compare_accepted,
    )
    accepted_artifact = snapshot_capture.find(
        "expected.lastSnapshotArtifactIdentity = snapshotAfter;",
        accepted_state,
    )
    snapshot_event = snapshot_capture.find(
        '"mark_snapshot",', accepted_artifact
    )
    if not (
        0 <= published_source < snapshot_before < verify_snapshot
        < snapshot_after < verified_source
        < compare_verified < accepted_source < compare_accepted
        < accepted_state < accepted_artifact < snapshot_event
    ):
        fail(
            "snapshot publication does not recheck the source after "
            "verifying the copied snapshot"
        )
    initial_identity = snapshot_capture.find(
        "FileIdentity initialIdentity = FileIdentity.capture(mark);"
    )
    missing_branch = snapshot_capture.find(
        "if (initialIdentity.isMissing())", initial_identity
    )
    missing_before = snapshot_capture.find(
        "FileIdentity missingBefore = initialIdentity;", missing_branch
    )
    missing_after = snapshot_capture.find(
        "FileIdentity missingAfter = FileIdentity.capture(mark);",
        missing_before,
    )
    missing_compare = snapshot_capture.find(
        "!missingBefore.sameAs(missingAfter)", missing_after
    )
    missing_accept = snapshot_capture.find(
        'expected.lastSnapshotHash = "missing";', missing_compare
    )
    missing_source_identity = snapshot_capture.find(
        "expected.lastSnapshotIdentity = missingAfter;", missing_accept
    )
    missing_artifact_identity = snapshot_capture.find(
        "FileIdentity.missing();", missing_source_identity
    )
    missing_event = snapshot_capture.find(
        '"mark_snapshot",', missing_artifact_identity
    )
    unchanged_branch = snapshot_capture.find("if (unchanged)")
    unchanged_verified = snapshot_capture.find(
        "FileIdentity unchangedVerified = FileIdentity.capture(mark);",
        unchanged_branch,
    )
    unchanged_compare = snapshot_capture.find(
        "!after.sameAs(unchangedVerified)", unchanged_verified
    )
    unchanged_accept = snapshot_capture.find(
        "expected.lastSnapshotIdentity = unchangedVerified;",
        unchanged_compare,
    )
    unchanged_event = snapshot_capture.find(
        '"mark_snapshot_unchanged"', unchanged_accept
    )
    if not (
        0 <= initial_identity < missing_branch < missing_before
        < missing_after < missing_compare < missing_accept
        < missing_source_identity < missing_artifact_identity < missing_event
        and 0 <= unchanged_branch < unchanged_verified
        < unchanged_compare < unchanged_accept < unchanged_event
    ):
        fail(
            "missing or unchanged final snapshots bypass their final "
            "source-identity recheck"
        )
    stop_session_start = module.find(
        "private static void stopAnnotationTrace("
    )
    if stop_session_start < 0 or stable_final_start < stop_session_start:
        fail("could not isolate final snapshot completion gating")
    stop_session = module[stop_session_start:stable_final_start]
    require_markers(
        stop_session,
        (
            "awaitTraceMutationAdmissions(session)",
            "finishTraceSession(session, activity, reason, false)",
            "captureStableFinalTraceMarkSnapshot(session)",
            "session.eventAdmissionClosed = true",
            "awaitTraceEventAdmissions(session)",
            "finishTraceSession(",
            "stableFinalSnapshot",
        ),
        "stable snapshot requirement before completed trace publication",
    )
    if (
        "traceFinalEvent(" in stop_session
        or '"trace_session_stopped"' in stop_session
        or '"trace_session_incomplete"' in stop_session
    ):
        fail("trace stop emits a terminal result before final acceptance")
    final_pen_generation_before = stop_session.find(
        "session.penInputMutationGeneration.get()"
    )
    final_generation_before = stop_session.find(
        "session.markGeneration.get()"
    )
    final_snapshot = stop_session.find(
        "captureStableFinalTraceMarkSnapshot(session)", final_generation_before
    )
    final_generation_after = stop_session.find(
        "session.markGeneration.get()", final_snapshot
    )
    final_generation_publish = stop_session.find(
        "session.finalSnapshotMarkGeneration = generationAfter",
        final_generation_after,
    )
    final_pen_generation_after = stop_session.find(
        "session.penInputMutationGeneration.get()", final_generation_publish
    )
    final_pen_generation_publish = stop_session.find(
        "session.finalPenInputMutationGeneration =",
        final_pen_generation_after,
    )
    admission_close = stop_session.find(
        "session.eventAdmissionClosed = true", final_pen_generation_publish
    )
    admission_drain = stop_session.find(
        "awaitTraceEventAdmissions(session)", admission_close
    )
    finalization = stop_session.find("finishTraceSession(", admission_drain)
    if not (
        0 <= final_pen_generation_before < final_generation_before
        < final_snapshot
        < final_generation_after < final_generation_publish
        < final_pen_generation_after < final_pen_generation_publish
        < admission_close < admission_drain < finalization
    ):
        fail(
            "trace stop does not admit and generation-fence its final snapshot "
            "before closing ordinary admissions and finalizing the session"
        )

    if "appendAcceptedTraceTerminalEvent(" in module:
        fail(
            "trace event log still publishes a terminal outcome separately "
            "from the atomic completion pointer"
        )
    if "traceFinalEvent(" in module:
        fail("closed-admission terminal-event bypass still exists")
    require_markers(
        stop_session,
        (
            "String inputStateReason =",
            "traceInputStateReason(activity)",
            "inputStateReason == null",
        ),
        "explicit trace-stop input-state gate",
    )
    input_state_start = module.find(
        "private static String tracePenContactStateReason("
    )
    final_source_start = module.find(
        "private static boolean isTraceFinalSourceCurrent(", input_state_start
    )
    if input_state_start < 0 or final_source_start < 0:
        fail("could not isolate trace input-state quiescence fence")
    require_markers(
        module[input_state_start:final_source_start],
        (
            "TRACE_LAST_PRESSURES.get(activity)",
            "PEN_CONTACT_START_PAGES.get(activity)",
            "String penContactState = tracePenContactStateReason(activity)",
            "TRACE_TRANSACTION_IDS.get(activity)",
            'return "native_trail_completion_pending"',
            "PAGE_ACTIVATION_TRANSACTIONS.get(activity)",
            "DEFERRED_SPREAD_TURNS.get(activity)",
            "ACTIVATION_TOUCH_TARGETS.get(activity)",
            "ACTIVE_FINGER_TOUCH_STREAMS.get(activity)",
            'return "finger_touch_active"',
        ),
        "trace input and ownership quiescence fence",
    )
    if (
        "Map<Activity, Integer> ACTIVATION_TOUCH_TARGETS =\n"
        "        new ConcurrentHashMap<>()"
    ) not in module:
        fail(
            "trace finalization reads activation-touch ownership from a "
            "non-concurrent map"
        )

    boundary_start = module.find(
        "private static void traceAnnotationBoundary("
    )
    capture_trails_start = module.find(
        "private static TraceTrailListCapture captureTraceTrailList(",
        boundary_start,
    )
    if boundary_start < 0 or capture_trails_start < 0:
        fail("could not isolate annotation-boundary trace collection")
    boundary = module[boundary_start:capture_trails_start]
    if "sha256(mark)" in boundary:
        fail("annotation boundaries still hash the .mark file on the UI thread")
    if "scheduleTraceMarkSnapshot(" not in boundary:
        fail("annotation boundary snapshots do not use the background worker")
    boundary_generation_capture = boundary.find(
        "session.annotationBoundaryGeneration.incrementAndGet()"
    )
    pre_boundary = boundary.find('boundary.endsWith("_before")')
    pre_deferred = boundary.find(
        '"annotation_boundary_deferred"', pre_boundary
    )
    pre_unavailable = boundary.find(
        '"pre_operation_state_not_captured"', pre_deferred
    )
    captured_note = boundary.find(
        "final Object capturedSuperNoteNote", pre_unavailable
    )
    captured_path = boundary.find(
        "final String capturedMarkPath", captured_note
    )
    captured_page = boundary.find(
        "final int capturedMarkPage", captured_path
    )
    worker_submit = boundary.find("scheduleTraceWorkerTask(")
    worker_run = boundary.find("public void run()", worker_submit)
    generation_before = boundary.find(
        "session.annotationBoundaryGeneration.get()",
        worker_run,
    )
    pen_generation_before = boundary.find(
        "long penInputGenerationBefore =", generation_before
    )
    pen_state_before = boundary.find(
        "tracePenContactStateReason(activity)", pen_generation_before
    )
    source_before = boundary.find(
        "traceAnnotationBoundaryPresenterCurrent(", pen_state_before
    )
    native_file_trails = boundary.find('"getFilePageTrails"', worker_run)
    native_current_trails = boundary.find('"getCurPageTrails"', worker_run)
    trail_capture = boundary.find("captureTraceTrailList(", native_current_trails)
    pen_generation_after = boundary.find(
        "long penInputGenerationAfter =", trail_capture
    )
    pen_state_after = boundary.find(
        "tracePenContactStateReason(activity)", pen_generation_after
    )
    generation_after = boundary.find(
        "session.annotationBoundaryGeneration.get()",
        pen_state_after,
    )
    source_revalidation = boundary.find(
        "traceAnnotationBoundaryPresenterCurrent(", trail_capture
    )
    boundary_hash = boundary.find(
        "traceLastSnapshotHash(", source_revalidation
    )
    trail_serialize = boundary.find(
        "traceTrailList(fileTrails)", boundary_hash
    )
    current_trail_serialize = boundary.find(
        "traceTrailList(currentTrails)", trail_serialize
    )
    publication_identity = boundary.find(
        "FileIdentity.capture(mark)", current_trail_serialize
    )
    publication_pen_generation = boundary.find(
        "long publicationPenInputGeneration =", publication_identity
    )
    publication_pen_state = boundary.find(
        "tracePenContactStateReason(activity)", publication_pen_generation
    )
    final_session_identity = boundary.find(
        "traceSession != session", publication_pen_state
    )
    final_activity_identity = boundary.find(
        "session.activity.get() != activity", final_session_identity
    )
    final_generation = boundary.find(
        "session.annotationBoundaryGeneration.get()",
        final_activity_identity,
    )
    final_file_identity = boundary.find(
        "!markAfter.sameAs(publicationIdentity)", final_generation
    )
    final_presenter_identity = boundary.find(
        "traceAnnotationBoundaryPresenterCurrent(", final_file_identity
    )
    final_publication = boundary.find(
        '"annotation_boundary",', final_presenter_identity
    )
    if not (
        0 <= boundary_generation_capture < pre_boundary < pre_deferred
        < pre_unavailable < captured_note < captured_path < captured_page
        < worker_submit < worker_run < generation_before
        < pen_generation_before < pen_state_before < source_before
        < native_file_trails < native_current_trails < trail_capture
        < pen_generation_after < pen_state_after < generation_after
        < source_revalidation < boundary_hash
        < trail_serialize < current_trail_serialize < publication_identity
        < publication_pen_generation < publication_pen_state
        < final_session_identity < final_activity_identity < final_generation
        < final_file_identity < final_presenter_identity < final_publication
    ):
        fail(
            "annotation boundaries are not callback-versioned before worker "
            "trail traversal, revalidation, and serialization"
        )
    boundary_caller = boundary[:worker_submit]
    caller_boundary_blocking_hits = [
        marker
        for marker in (
            '"getFilePageTrails"',
            '"getCurPageTrails"',
            "captureTraceTrailList(",
            "new File(",
            "FileIdentity.capture(",
            "traceLastSnapshotHash(",
        )
        if marker in boundary_caller
    ]
    if caller_boundary_blocking_hits:
        fail(
            "annotation boundary performs native traversal or filesystem work "
            "before worker admission: "
            f"{caller_boundary_blocking_hits}"
        )
    require_markers(
        boundary,
        (
            "traceLastSnapshotHash(",
            '"trace_stop".equals(boundary)',
            "capturedSuperNoteNote",
            "capturedMarkPath",
            "capturedMarkPage",
            '"annotation_boundary_stale"',
            '"source_identity_before"',
            '"boundary_generation_before"',
            '"boundary_generation_after"',
            '"pen_contact_before"',
            '"pen_input_generation_after"',
            '"pen_contact_after"',
            '"publication_revalidation"',
            "markBefore.sameAs(markAfter)",
            "markAfter.sameAs(publicationIdentity)",
            "traceSession != session",
            "session.activity.get() != activity",
            "traceAnnotationBoundaryPresenterCurrent(",
            '"markSha256"',
            "markHash",
        ),
        "identity-aware annotation boundary hash and final boundary queueing",
    )
    for comparison in (
        r"penInputGenerationBefore\s*!=\s*penInputGenerationAfter",
        r"publicationPenInputGeneration\s*!=\s*penInputGenerationAfter",
    ):
        if re.search(comparison, boundary) is None:
            fail("annotation boundary does not reject pen-generation drift")
    delayed_source_reads = boundary[worker_run:native_file_trails]
    for marker in (
        'getObjectField(\n                                presenter,\n                                "markPath"',
        'getIntField(\n                                presenter,\n                                "currentPage"',
    ):
        if marker in delayed_source_reads:
            fail("annotation worker captures source identity after deferral")
    if "final AtomicLong annotationBoundaryGeneration = new AtomicLong();" not in module:
        fail("trace sessions do not version annotation callback boundaries")
    if "final AtomicLong penInputMutationGeneration = new AtomicLong();" not in module:
        fail("trace sessions do not version pen-input mutations")

    pen_trace_start = module.find("private static void tracePenPosition(")
    pen_left_start = module.find(
        "private static void tracePenLeftScreen(", pen_trace_start
    )
    suppressed_contact_start = module.find(
        "private static void finishTraceSuppressedPenContact(", pen_left_start
    )
    if min(pen_trace_start, pen_left_start, suppressed_contact_start) < 0:
        fail("could not isolate trace pen-input generation updates")
    pen_trace = module[pen_trace_start:pen_left_start]
    pen_left_trace = module[pen_left_start:suppressed_contact_start]
    require_markers(
        pen_trace,
        (
            "synchronized (PAGE_ACTIVATION_OWNERSHIP_LOCK)",
            "expected.penInputAdmissionClosed",
            "TRACE_LAST_PRESSURES.put(activity, pressure)",
            "contactStarted = pressure > 0",
            "contactEnded = pressure <= 0",
            "expected.penInputMutationGeneration.incrementAndGet()",
        ),
        "nonblocking pen-input mutation generation",
    )
    require_markers(
        pen_left_trace,
        (
            "final Integer previous;",
            "synchronized (PAGE_ACTIVATION_OWNERSHIP_LOCK)",
            "expected.penInputAdmissionClosed",
            "previous = TRACE_LAST_PRESSURES.remove(activity)",
            "previous.intValue() > 0",
            "expected.penInputMutationGeneration.incrementAndGet()",
        ),
        "pen-left-screen mutation generation",
    )

    trace_list_start = module.find(
        "private static JSONObject traceTrailList(", capture_trails_start
    )
    if trace_list_start < 0:
        fail("could not isolate immutable trace trail capture")
    trail_capture_code = module[capture_trails_start:trace_list_start]
    if "traceTrailFingerprint(" in trail_capture_code or "sha256Text(" in trail_capture_code:
        fail("trail fingerprinting still runs while capturing hook-thread input")
    if "traceValueDescription(" in trail_capture_code:
        fail("trail auxiliary values are still serialized on the hook thread")
    require_markers(
        trail_capture_code,
        (
            'captureTraceValue(traceCall(trail, "get_pressures"))',
            'captureTraceValue(traceCall(trail, "get_angles"))',
            'captureTraceValue(traceCall(trail, "get_timestamp"))',
            'captureTraceValue(traceCall(trail, "get_write_app_name"))',
            'captureTraceRect(rrd == null ? null : traceCall(rrd, "getRect"))',
            'captureTraceRect(traceCall(trail, "get_refresh_rect"))',
            'captureTraceRect(traceCall(trail, "get_m_before_shift_rect"))',
            'captureTraceRect(traceCall(trail, "get_m_after_shift_rect"))',
            'captureTraceContours(traceCall(trail, "get_m_contours_src"))',
        ),
        "immutable auxiliary trail-value capture",
    )

    trace_trail_start = module.find(
        "private static JSONObject traceTrail(", trace_list_start
    )
    if trace_trail_start < 0:
        fail("could not isolate trace trail-list fingerprinting")
    trace_list = module[trace_list_start:trace_trail_start]
    require_markers(
        trace_list,
        (
            "for (int index = 0; index < captured.trails.length; index++)",
            "String fingerprint = traceTrailFingerprint(trail)",
            "if (index < limit)",
            "items.put(traceTrail(trail, index, fingerprint))",
            "ordered.append(fingerprint).append(';')",
            "Math.max(0, captured.trails.length - limit)",
        ),
        "complete trail fingerprint with capped details",
    )

    fingerprint_start = module.find(
        "private static String traceTrailFingerprint(", trace_trail_start
    )
    point_description_start = module.find(
        "private static String capturedPointDescription(", fingerprint_start
    )
    if fingerprint_start < 0 or point_description_start < 0:
        fail("could not isolate complete trail fingerprint")
    require_markers(
        module[fingerprint_start:point_description_start],
        (
            ".append(trail.flagPenup).append('|')",
            ".append(trail.flagSpecial).append('|')",
            ".append(trail.layer).append('|')",
            ".append(trail.recMod).append('|')",
            ".append(trail.emrPointAxis).append('|')",
            ".append(trail.trailType).append('|')",
            ".append(trail.drawVersion).append('|')",
            ".append(trail.recognTrailType).append('|')",
            ".append(trail.rotation).append('|')",
            ".append(trail.redrawWidth).append('|')",
            ".append(trail.redrawHeight).append('|')",
            ".append(trail.maxX).append('|')",
            ".append(trail.maxY).append('|')",
            ".append(traceValueDescription(trail.rrdRect)).append('|')",
            ".append(traceValueDescription(trail.refreshRect)).append('|')",
            ".append(traceValueDescription(trail.beforeShiftRect)).append('|')",
            ".append(traceValueDescription(trail.afterShiftRect)).append('|')",
            ".append(traceValueDescription(trail.contours)).append('|')",
            ".append(traceValueDescription(trail.writeAppName)).append('|')",
        ),
        "complete production trail-identity fingerprint coverage",
    )

    hash_state_start = module.find(
        "private static String traceLastSnapshotHash("
    )
    snapshot_schedule_start = module.find(
        "private static void scheduleTraceWorkerTask(", hash_state_start
    )
    if hash_state_start < 0 or snapshot_schedule_start < 0:
        fail("could not isolate identity-aware boundary hash state")
    hash_state = module[hash_state_start:snapshot_schedule_start]
    require_markers(
        hash_state,
        (
            "FileIdentity.capture(mark)",
            "expected.lastSnapshotIdentity.sameAs(currentIdentity)",
            'return "pending"',
        ),
        "non-stale annotation boundary hash",
    )

    worker_start = module.find(
        "private static void scheduleTraceWorkerTask(",
        snapshot_schedule_start,
    )
    worker_end = module.find(
        "private static void scheduleTraceMarkSnapshot(", worker_start
    )
    if worker_start < 0 or worker_end < 0:
        fail("could not isolate trace worker admission logic")
    require_markers(
        module[worker_start:worker_end],
        (
            "final boolean allowWhenStopping",
            "expected.stopping && !allowWhenStopping",
        ),
        "trace-stop boundary worker admission",
    )

    mutation_admission_start = module.find(
        "private static TraceMutationAdmission beginTraceMutationAdmission("
    )
    mutation_admission_end = module.find(
        "private static void preserveTraceStartupFailure(",
        mutation_admission_start,
    )
    if mutation_admission_start < 0 or mutation_admission_end < 0:
        fail("could not isolate trace mutation admission lifecycle")
    mutation_admission = module[
        mutation_admission_start:mutation_admission_end
    ]
    require_markers(
        module,
        (
            "ThreadLocal<ArrayDeque<TraceMutationAdmission>>",
            "TRACE_MUTATION_ADMISSION_SCOPES",
            "private static final class TraceMutationAdmission",
            "final AtomicInteger mutationAdmissions = new AtomicInteger()",
            "volatile boolean mutationAdmissionClosed",
            "volatile boolean mutationAdmissionSealed",
            "volatile boolean lateMutationObserved",
        ),
        "trace mutation admission state",
    )
    require_markers(
        mutation_admission,
        (
            "synchronized (TRACE_LOCK)",
            "TRACE_MUTATION_ADMISSION_SCOPES.get()",
            "if (scope.admitted && scope.session == expected)",
            "if (expected.mutationAdmissionSealed)",
            "if (expected.mutationAdmissionClosed && !inherited)",
            "expected.lateMutationObserved = true",
            "expected.mutationAdmissions.incrementAndGet()",
            "private static void pushTraceMutationAdmission(",
            "private static TraceMutationAdmission popTraceMutationAdmission()",
            "private static void finishTraceMutationAdmission(",
            ".decrementAndGet()",
            "private static boolean awaitTraceMutationAdmissions(",
            "session.mutationAdmissions.get() > 0",
            "session.mutationAdmissions.get() == 0",
        ),
        "race-free nested trace mutation admission",
    )
    modify_hook_start = module.find('"modifyPageTrailsFromFile",')
    modify_hook_end = module.find('"getRegionTrailRect",', modify_hook_start)
    lasso_transition_start = module.find(
        '"areaSelectionTransition",', receive_hook_end_transactional
    )
    lasso_rewrite_start = module.find(
        '"reWriteTrails",', lasso_transition_start
    )
    lasso_rewrite_end = module.find("hooksReady = true;", lasso_rewrite_start)
    document_reset_hook_start = module.find(
        "private static void installDocumentIdentityAdmissionHook("
    )
    document_reset_hook_end = module.find(
        "private static DocumentIdentityAdmission "
        "invalidateDocumentIdentityAdmission(",
        document_reset_hook_start,
    )
    if min(
        modify_hook_start,
        modify_hook_end,
        lasso_transition_start,
        lasso_rewrite_start,
        lasso_rewrite_end,
        document_reset_hook_start,
        document_reset_hook_end,
    ) < 0:
        fail("could not isolate trace mutation hook coverage")
    mutation_hook_slices = (
        ("history", history_hook),
        ("modify", module[modify_hook_start:modify_hook_end]),
        ("save", transaction_save_hook),
        ("receive", transaction_receive_hook),
        (
            "lasso transition",
            module[lasso_transition_start:lasso_rewrite_start],
        ),
        ("lasso rewrite", module[lasso_rewrite_start:lasso_rewrite_end]),
        (
            "document identity reset",
            module[document_reset_hook_start:document_reset_hook_end],
        ),
    )
    for label, hook_slice in mutation_hook_slices:
        begin = hook_slice.find("beginTraceMutationAdmission(")
        push = hook_slice.find("pushTraceMutationAdmission(")
        finish = hook_slice.find("finishTraceMutationAdmission(", push)
        pop = hook_slice.find("popTraceMutationAdmission()", finish)
        nested_admission = re.search(
            r"pushTraceMutationAdmission\(\s*beginTraceMutationAdmission\(",
            hook_slice,
        )
        explicit_admission = 0 <= begin < push
        nested_admission_order = (
            nested_admission is not None
            and nested_admission.start() == push
            and nested_admission.start() <= begin < nested_admission.end()
        )
        if not (
            (explicit_admission or nested_admission_order)
            and 0 <= begin < finish < pop
            and 0 <= push < finish
        ):
            fail(f"{label} hook is not enclosed by trace mutation admission")
    for label, hook_slice in (
        ("modify", module[modify_hook_start:modify_hook_end]),
        (
            "lasso transition",
            module[lasso_transition_start:lasso_rewrite_start],
        ),
        ("lasso rewrite", module[lasso_rewrite_start:lasso_rewrite_end]),
    ):
        markers = (
            "documentMutationAuthorityCurrent(",
            "reason=writer_authority_unavailable",
        )
        if label.startswith("lasso"):
            markers = (
                "canonicalLassoMutationAuthority(",
                "beginCanonicalLassoOperation(",
                "reason=selection_authority_unavailable",
            )
            if label in ("lasso transition", "lasso rewrite"):
                markers += ("scheduleCanonicalLassoCompletion(",)
        require_markers(
            hook_slice,
            markers,
            f"{label} writer-authority rejection",
        )

    lasso_transition = mask_comments_preserve_literals(
        module[lasso_transition_start:lasso_rewrite_start]
    )
    move_mode_guard = lasso_transition.find(
        "((Integer) param.args[5]) == 1"
    )
    move_commit_call = lasso_transition.find(
        "commitCanonicalLassoMove(operation)", move_mode_guard
    )
    move_origin_restore = lasso_transition.find(
        "endCanonicalLassoOperation(", move_commit_call
    )
    move_completion = lasso_transition.find(
        "scheduleCanonicalLassoCompletion(", move_origin_restore
    )
    move_failed_retirement = lasso_transition.find(
        '"transition_move_commit_failed"', move_completion
    )
    if not (
        0 <= move_mode_guard < move_commit_call < move_origin_restore
        < move_completion < move_failed_retirement
    ):
        fail(
            "lasso move is not canonically committed before origin restore "
            "and authority completion"
        )
    lasso_commit_start = module.find(
        "private static boolean commitCanonicalLassoMove("
    )
    lasso_commit_end = module.find(
        "private static void endCanonicalLassoOperation(", lasso_commit_start
    )
    if lasso_commit_start < 0 or lasso_commit_end < 0:
        fail("could not isolate canonical lasso move commit")
    lasso_commit = mask_comments_preserve_literals(
        module[lasso_commit_start:lasso_commit_end]
    )
    lasso_commit_authority = lasso_commit.find(
        "canonicalLassoMutationAuthority("
    )
    lasso_commit_rewrite = lasso_commit.find(
        '"reWriteTrails"', lasso_commit_authority
    )
    lasso_commit_layout = lasso_commit.find(
        '"setOnGlobalLayout"', lasso_commit_rewrite
    )
    lasso_commit_refresh = lasso_commit.find(
        '"refreshBitmap"', lasso_commit_layout
    )
    lasso_commit_clear = lasso_commit.find(
        '"sendClearAll"', lasso_commit_refresh
    )
    lasso_commit_success = lasso_commit.find(
        '"lasso_transition_canonical_commit generation="', lasso_commit_clear
    )
    if not (
        0 <= lasso_commit_authority < lasso_commit_rewrite
        < lasso_commit_layout < lasso_commit_refresh < lasso_commit_clear
        < lasso_commit_success
    ):
        fail(
            "canonical lasso move does not serialize selection data and "
            "refresh the layer bitmap under the same origin authority"
        )
    if "endCanonicalLassoOperation(" in lasso_commit:
        fail("canonical lasso move restores its origin before finalization")

    lasso_preview_start = module.find(
        "private static void prepareSelectedTrailPreview("
    )
    lasso_preview_end = module.find(
        "private static String jniRectDescription(", lasso_preview_start
    )
    if lasso_preview_start < 0 or lasso_preview_end < 0:
        fail("could not isolate canonical lasso preview reconstruction")
    lasso_preview = mask_comments_preserve_literals(
        module[lasso_preview_start:lasso_preview_end]
    )
    preview_selected_count = lasso_preview.find(
        'int selectedTrailCount = callInt(lassoInfo, "getTrailnum")'
    )
    preview_trails_only = lasso_preview.find(
        "boolean trailsOnly = selectedTrailCount > 0",
        preview_selected_count,
    )
    preview_drawn_count = lasso_preview.find(
        "int drawnTrails = 0", preview_trails_only
    )
    preview_incomplete_guard = lasso_preview.find(
        "if (trailsOnly && drawnTrails != selectedTrailCount)",
        preview_drawn_count,
    )
    preview_discard = lasso_preview.find(
        "corrected.recycle()", preview_incomplete_guard
    )
    preview_native_fallback = lasso_preview.find(
        "spreadLassoCorrectedPreview = Bitmap.createBitmap(\n"
        "                    nativePreview\n"
        "                )",
        preview_discard,
    )
    preview_fallback_log = lasso_preview.find(
        '"lasso_preview_rebuild_incomplete_fallback controls="',
        preview_native_fallback,
    )
    preview_complete_branch = lasso_preview.find(
        "else if (drawnTrails > 0 || !trailsOnly)",
        preview_fallback_log,
    )
    if not (
        0 <= preview_selected_count < preview_trails_only
        < preview_drawn_count < preview_incomplete_guard < preview_discard
        < preview_native_fallback < preview_fallback_log
        < preview_complete_branch
    ):
        fail(
            "an incomplete canonical lasso reconstruction can replace the "
            "firmware's native multi-trail preview"
        )

    event_activity_start = module.find(
        "private static void traceEvent(\n        Activity activity"
    )
    event_start = module.find(
        "private static void traceEvent(\n        TraceSession expected",
        event_activity_start,
    )
    event_admission_start = module.find(
        "private static boolean acquireTraceEventAdmission(",
        event_start,
    )
    event_queue_start = module.find(
        "private static void queueAdmittedTraceEventCapture(",
        event_admission_start,
    )
    event_writer_start = module.find(
        "private static void writeTraceEventCapture(", event_queue_start
    )
    trace_log_start = module.find(
        "private static void traceLogMessage(", event_writer_start
    )
    trace_log_end = module.find(
        "private static int traceCurrentDocumentPage(", trace_log_start
    )
    if min(
        event_activity_start,
        event_start,
        event_admission_start,
        event_queue_start,
        event_writer_start,
        trace_log_start,
        trace_log_end,
    ) < 0:
        fail("could not isolate serialized trace-event writer")
    activity_event_capture = module[event_activity_start:event_start]
    session_event_capture = module[event_start:event_admission_start]
    for label, event_capture, admission_marker in (
        ("activity", activity_event_capture,
         "acquireTraceEventAdmission(expected)"),
        ("session", session_event_capture,
         "acquireTraceEventAdmission(expected)"),
    ):
        admission = event_capture.find(admission_marker)
        immutable_capture = event_capture.find("new TraceEventCapture(")
        order_token = event_capture.find(
            "expected.eventOrder.incrementAndGet()", immutable_capture
        )
        release = event_capture.find(
            "expected.eventAdmissions.decrementAndGet()",
            order_token,
        )
        if not 0 <= admission < immutable_capture < order_token < release:
            fail(
                f"{label} trace event does not acquire admission before "
                "immutable caller-side capture, reserve hook order, and "
                "release it afterward"
            )
    event_admission = module[event_admission_start:event_queue_start]
    require_markers(
        event_admission,
        (
            "synchronized (TRACE_LOCK)",
            "traceSession != expected",
            "expected.eventAdmissionClosed",
            "expected.eventAdmissions.incrementAndGet()",
        ),
        "atomic pre-capture trace-event admission",
    )
    caller_thread_trace_work = tuple(
        marker for marker in (
            "new JSONObject()",
            "entry.toString()",
            "appendTraceRecord(",
            "FileOutputStream",
        )
        if marker in module[event_activity_start:event_queue_start]
    )
    if caller_thread_trace_work:
        fail(
            "traceEvent still performs JSON serialization or file "
            f"I/O on its caller thread: {caller_thread_trace_work}"
        )
    require_markers(
        module[event_queue_start:trace_log_start],
        (
            "expected.eventExecutor.execute(",
            "acceptOrderedTraceEventCapture(expected, capture)",
            "private static void acceptOrderedTraceEventCapture(",
            "expected.pendingTraceEvents.put(capture.order, capture)",
            "expected.nextTraceEventOrder",
            "writeTraceEventCapture(expected, next)",
            "private static void writeTraceEventCapture(",
            "JSONObject entry = new JSONObject()",
            'entry.put("seq", capture.order)',
            "entry.toString()",
            "appendTraceRecord(",
            "expected.eventWriteFailure",
        ),
        "admission-fenced serialized background trace-event writer",
    )
    if "eventAdmissions.incrementAndGet()" in module[
        event_queue_start:trace_log_start
    ]:
        fail("trace admission is acquired after immutable event capture")
    require_markers(
        module[trace_log_start:trace_log_end],
        ("traceEvent(expected, null, \"module_log\"",),
        "module-log event delegation",
    )
    require_markers(
        module,
        (
            "final ScheduledExecutorService eventExecutor;",
            "final AtomicInteger eventAdmissions = new AtomicInteger();",
            "final AtomicLong eventOrder = new AtomicLong();",
            "final TreeMap<Long, TraceEventCapture> pendingTraceEvents",
            "long nextTraceEventOrder = 1L;",
            "final long order;",
            "expected.eventOrder.incrementAndGet()",
            "volatile boolean eventAdmissionClosed;",
            "volatile boolean penInputAdmissionClosed;",
            "final AtomicLong penInputMutationGeneration = new AtomicLong();",
            "volatile long finalPenInputMutationGeneration = -1L;",
            '"SNSpreadTraceEvent-" + id',
        ),
        "hook-ordered per-session trace-event executor",
    )

    finish_trace_start = module.find("private static void finishTraceSession(")
    drain_trace_start = module.find(
        "private static boolean drainTraceEventWriter(", finish_trace_start
    )
    admission_drain_end = module.find(
        "private static void preserveTracePublicationFailure(", drain_trace_start
    )
    if min(finish_trace_start, drain_trace_start, admission_drain_end) < 0:
        fail("could not isolate trace-event admission shutdown")
    require_markers(
        module[finish_trace_start:admission_drain_end],
        (
            "session.eventAdmissionClosed = true",
            "awaitTraceEventAdmissions(session)",
            "session.eventAdmissions.get() > 0",
            "drainTraceEventWriter(session)",
        ),
        "race-free trace-event admission shutdown",
    )

    require_markers(
        trace_script,
        (
            "[ValidateSet('Start', 'Checkpoint', 'Stop', 'Status')]",
            "com.techrebbe.supernote.spreadprobe.TRACE_CONTROL",
            "SupernoteNativeSpreadTrace",
            "screencap -p",
            "Invoke-Adb pull",
            "Compress-Archive",
            "module-logcat.txt",
            "summary.md",
            "Write-TraceSummary",
            "function Wait-TraceFinalization",
            "function Reconcile-AbandonedTracePointer",
            "function Read-AbandonedRecoveryState",
            "function Read-RemotePointer",
            "function Assert-NoUnresolvedTraceFailure",
            "function Assert-ValidTraceSession",
            "function Read-LocalExpectedTraceSession",
            "function Read-ExpectedTraceSession",
            "function Publish-ExpectedTraceSession",
            "function Clear-ExpectedTraceSession",
            "function Clear-MatchingLocalExpectedTraceSession",
            ".native-spread-expected-session.txt",
            "[string]$CurrentAction",
            "[switch]$NoPing",
            "pidof '$documentPackage'",
            '"$remoteRoot/.active-recovery"',
            "__SNTRACE_RECOVERY_PRESENT__",
            "__TRACE_POINTER_REPLACEMENT_RETAINED__",
            "__TRACE_ABANDONED_ARCHIVED__",
            "candidate_identity=`$(stat -c '%d:%i:%s:%Y'",
            "claimed_identity=`$(stat -c '%d:%i:%s:%Y'",
            "archived_identity=`$(stat -c '%d:%i:%s:%Y'",
            "$script:recoveredAbandonedTraceSession = $session",
            "active.txt was retained",
            "Reconcile-AbandonedTracePointer -CurrentAction $Action",
            "Stop did not pull the preceding completed session.",
            "Read-IncompleteTraceState",
            "Read-RemotePointer -Name incomplete",
            "could not obtain a stable final ",
            "annotation snapshot; incomplete guard",
            "Read-PublicationFailedTraceState",
            "Read-RemotePointer -Name publication-failed",
            "Assert-NoUnresolvedTraceFailure -CurrentAction $Action",
            "__SNTRACE_ABSENT__",
            "__SNTRACE_PRESENT__",
            "__SNTRACE_NOT_REGULAR__",
            "__SNTRACE_MALFORMED__",
            "[ ! -e '$pointer' ]",
            "[ ! -f '$pointer' ]",
            "Explicit operator recovery is required",
            "function Read-TraceOwnerProcessId",
            "function Read-DocumentProcessIds",
            "function Read-GuardedActiveTraceSession",
            "function Assert-CompletedTraceStillPullable",
            '"$remoteRoot/.screenshots/$Session"',
            "function Pull-StagedScreenshots",
            '"$remoteFile.partial"',
            "Trace bundle contains $parseErrors malformed JSON event",
            "Trace bundle contains no JSON events",
            "'.partial-' + [Guid]::NewGuid().ToString('N')",
            "Timed out waiting for trace",
        ),
        "Native Spread trace collection script",
    )
    require_markers(
        trace_helper_test,
        (
            "malformed-active-$action",
            "malformed-incomplete-$action",
            "malformed-publication-$action",
            "space-padded-active-$action",
            "multiline-last-$action",
            "valid-incomplete-start",
            "unreadable-publication-start",
            "nonregular-active-status",
            "unreadable-session-metadata-stop",
            "malformed-session-metadata-stop",
            "pidof-failure-stop",
            "transport-failure-start",
            "start-success-control",
            "active-pointer-changed-checkpoint",
            "unstable-active-pointer-status",
            "stale-last-stop",
            "abandoned-pointer-recovery-failure-stop",
            "abandoned-pointer-replaced-during-claim-stop",
            "abandoned-pointer-recovery-clears-matching-expected-stop",
            "abandoned-pointer-android-rename-ctime-change-stop",
            "rename-changing ctime",
            "-NoPing",
            "abandoned-pointer-recovery-retains-mismatched-expected-stop",
            "retained-recovery-guard-$action",
            "retained-recovery-guard-Status",
            "replacement was retained inside the recovery guard",
            "malformed JSON summary unexpectedly succeeded",
            "valid JSON summary control did not publish its summary",
            "'/last.txt'",
            "'rm -f'",
            "('pull' + $separator)",
            "Native Spread trace helper fail-closed tests: PASS",
        ),
        "trace-helper failure-injection regression tests",
    )
    require_markers(
        native_build,
        (
            "scripts\\test_trace_helper_fail_closed.ps1",
            "Trace-helper tests failed with exit code",
            "function Get-NormalizedTextSha256",
            '$normalized = $text.Replace("`r`n", "`n").Replace("`r", "`n")',
            "$actualTraceSourceSha256 = Get-NormalizedTextSha256 `",
        ),
        "checkout-independent Native Spread build trace-helper regression gate",
    )
    require_markers(
        native_build,
        (
            "$verifiedTraceSources = @(",
            "Trace safety source digest mismatch for",
            "$legacySource = [System.IO.Path]::GetFullPath((Join-Path",
            "$javaSources = @(",
            "-not [System.IO.Path]::GetFullPath($_).Equals(",
            "$legacySource,",
            "$javaSources",
            "Legacy SpreadProbe executable classes entered the v2 build.",
            "jar class packaging failed with exit code",
            "jar dex/metadata update failed with exit code",
            "APK normalization failed with exit code",
            "zipalign failed with exit code",
            "APK contains duplicate entry",
            "APK required entry is empty",
            "APK entry timestamp is not canonical",
            "APK entry order is not canonical.",
            "APK payload entry appears after signature metadata.",
            "'assets/native_init'",
            "'lib/arm64-v8a/libspreadprobe.so'",
            "v2 APK contains forbidden legacy payload",
            "Two clean Native Reader builds were not byte-for-byte reproducible",
        ),
        "Native Reader v2 exclusive Java source and canonical APK build gate",
    )
    native_build_tokens = tokenize_powershell(native_build)
    native_build_depths = powershell_brace_depths(native_build_tokens)

    normalized_digest_function = r'''
function Get-NormalizedTextSha256 {
    param(
        [Parameter(Mandatory = $true)][string]$LiteralPath
    )
    $text = [System.IO.File]::ReadAllText(
        $LiteralPath,
        [System.Text.Encoding]::UTF8
    )
    $normalized = $text.Replace("`r`n", "`n").Replace("`r", "`n")
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($normalized)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        return [System.BitConverter]::ToString(
            $sha256.ComputeHash($bytes)
        ).Replace('-', '')
    } finally {
        $sha256.Dispose()
    }
}
'''
    actual_digest_function = extract_powershell_function_tokens(
        native_build_tokens,
        "Get-NormalizedTextSha256",
    )
    if powershell_token_keys(actual_digest_function) != powershell_token_keys(
        tokenize_powershell(normalized_digest_function)
    ):
        fail(
            "normalized text digest helper does not have the exact canonical "
            "LF and SHA-256 control flow"
        )
    digest_function = require_unique_powershell_sequence(
        native_build_tokens,
        normalized_digest_function,
        "normalized text digest helper",
    )

    trace_review_gate = r'''
foreach ($verifiedTraceSource in $verifiedTraceSources) {
    $actualTraceSourceSha256 = Get-NormalizedTextSha256 `
        -LiteralPath $verifiedTraceSource[0]
    if ($actualTraceSourceSha256 -ne $verifiedTraceSource[1]) {
        throw (
            "Trace safety source digest mismatch for $($verifiedTraceSource[0]): " +
            "expected $($verifiedTraceSource[1]), got $actualTraceSourceSha256"
        )
    }
}
'''
    trace_review = require_unique_powershell_sequence(
        native_build_tokens,
        trace_review_gate,
        "trace-source digest review loop",
    )

    trace_test_gate = r'''
& $windowsPowerShell `
    -NoProfile `
    -ExecutionPolicy Bypass `
    -File $traceHelperTest `
    -RepositoryRoot $repositoryRoot
if ($LASTEXITCODE -ne 0) {
    throw "Trace-helper tests failed with exit code $LASTEXITCODE"
}
'''
    trace_test = require_unique_powershell_sequence(
        native_build_tokens,
        trace_test_gate,
        "trace-helper regression-test gate",
    )

    legacy_source_exclusion_gate = r'''
$legacySource = [System.IO.Path]::GetFullPath((Join-Path `
    $projectRoot `
    'src\com\techrebbe\supernote\spreadprobe\SpreadProbe.java'
))
$javaSources = @(
    Get-ChildItem -LiteralPath (Join-Path $projectRoot 'src') -Recurse -Filter '*.java' -File
    Get-ChildItem -LiteralPath (Join-Path $projectRoot 'stubs') -Recurse -Filter '*.java' -File
) | ForEach-Object FullName | Where-Object {
    -not [System.IO.Path]::GetFullPath($_).Equals(
        $legacySource,
        [System.StringComparison]::OrdinalIgnoreCase
    )
}
'''
    legacy_source_exclusion = require_unique_powershell_sequence(
        native_build_tokens,
        legacy_source_exclusion_gate,
        "legacy engine source-exclusion gate",
    )

    java_compile_gate = r'''
& javac `
    -source 8 `
    -target 8 `
    -encoding UTF-8 `
    -cp $androidJar `
    -d $classesDir `
    $javaSources
if ($LASTEXITCODE -ne 0) {
    throw "javac failed with exit code $LASTEXITCODE"
}
'''
    java_compile = require_unique_powershell_sequence(
        native_build_tokens,
        java_compile_gate,
        "exclusive v2 Java compiler-input gate",
    )

    legacy_class_rejection_gate = r'''
if (Get-ChildItem -LiteralPath $legacyClassRoot -Filter 'SpreadProbe*.class' -File) {
    throw 'Legacy SpreadProbe executable classes entered the v2 build.'
}
'''
    legacy_class_rejection = require_unique_powershell_sequence(
        native_build_tokens,
        legacy_class_rejection_gate,
        "post-compile legacy class rejection gate",
    )

    forbidden_payload_gate = r'''
foreach ($forbiddenEntry in @(
    'assets/native_init',
    'lib/arm64-v8a/libspreadprobe.so'
)) {
    if ($entriesByName.ContainsKey($forbiddenEntry)) {
        throw "v2 APK contains forbidden legacy payload: $forbiddenEntry"
    }
}
'''
    forbidden_payload_review = require_unique_powershell_sequence(
        native_build_tokens,
        forbidden_payload_gate,
        "forbidden legacy APK payload gate",
    )

    apk_archive_header = r'''
$apkArchive = [IO.Compression.ZipFile]::OpenRead($outputApk)
try {
'''
    apk_archive = require_unique_powershell_sequence(
        native_build_tokens,
        apk_archive_header,
        "APK archive review block",
    )
    apk_archive_opening = apk_archive + len(
        tokenize_powershell(apk_archive_header)
    ) - 1
    apk_archive_closing = matching_powershell_brace_token(
        native_build_tokens,
        apk_archive_opening,
        "APK archive review block",
    )
    apk_archive_finally = require_unique_powershell_sequence(
        native_build_tokens,
        r'''
} finally {
    $apkArchive.Dispose()
}
''',
        "APK archive disposal guard",
    )

    final_apk_hash = require_unique_powershell_sequence(
        native_build_tokens,
        r'''
$firstBuildHash = (Get-FileHash `
    -Algorithm SHA256 `
    -LiteralPath $outputApk
).Hash
''',
        "first raw final-APK digest command",
    )
    reproducibility_guard = require_unique_powershell_sequence(
        native_build_tokens,
        r'''
if ($secondBuildHash -cne $firstBuildHash) {
    throw (
        'Two clean Native Reader builds were not byte-for-byte reproducible: ' +
        "$firstBuildHash != $secondBuildHash"
    )
}
''',
        "two-clean-build reproducibility guard",
    )

    top_level_gates = (
        digest_function,
        trace_review,
        trace_test,
        legacy_source_exclusion,
        java_compile,
        legacy_class_rejection,
        apk_archive,
        final_apk_hash,
    )
    if any(native_build_depths[position] != 0 for position in top_level_gates):
        fail("native build review gates must execute at top level")
    if (
        native_build_depths[forbidden_payload_review] != 1
        or not apk_archive_opening < forbidden_payload_review < apk_archive_closing
        or apk_archive_closing != apk_archive_finally
    ):
        fail("forbidden legacy payload gate must execute directly in APK review")
    if not (
        digest_function < trace_review < trace_test < legacy_source_exclusion
        < java_compile < legacy_class_rejection < apk_archive
        < forbidden_payload_review < apk_archive_closing < final_apk_hash
        < reproducibility_guard
    ):
        fail("exclusive v2 sources are not bound through canonical APK packaging")

    executable_words = [
        value
        for kind, value, _start, _end in native_build_tokens
        if kind == "word"
    ]
    if executable_words.count("get-normalizedtextsha256") != 2:
        fail("normalized text hashing must be limited to reviewed trace sources")
    if executable_words.count("get-filehash") != 2:
        fail("Native Reader reproducibility must compare exactly two APK hashes")
    if executable_words.count("computehash") != 1:
        fail("raw SHA-256 must hash only the normalized helper bytes")
    if len(powershell_sequence_positions(native_build_tokens, "$legacySource =")) != 1:
        fail("native build must identify the excluded legacy source exactly once")

    pointer_reader_start = trace_script.find("function Read-RemotePointer")
    publication_reader_start = trace_script.find(
        "function Read-PublicationFailedTraceState", pointer_reader_start
    )
    incomplete_reader_start = trace_script.find(
        "function Read-IncompleteTraceState", publication_reader_start
    )
    abandoned_reader_start = trace_script.find(
        "function Read-AbandonedRecoveryState", incomplete_reader_start
    )
    unresolved_guard_start = trace_script.find(
        "function Assert-NoUnresolvedTraceFailure", abandoned_reader_start
    )
    session_validator_start = trace_script.find(
        "function Assert-ValidTraceSession", unresolved_guard_start
    )
    helper_reconcile = trace_script.find(
        "function Reconcile-AbandonedTracePointer", session_validator_start
    )
    helper_wait = trace_script.find(
        "function Wait-TraceFinalization", helper_reconcile
    )
    action_switch = trace_script.find("switch ($Action)")
    if not (
        0 <= pointer_reader_start < publication_reader_start
        < incomplete_reader_start < abandoned_reader_start
        < unresolved_guard_start
        < session_validator_start < helper_reconcile < helper_wait
        < action_switch
    ):
        fail("could not isolate fail-closed trace helper functions")

    pointer_reader_code = trace_script[
        pointer_reader_start:publication_reader_start
    ]
    require_markers(
        pointer_reader_code,
        (
            "if [ ! -e '$pointer' ]",
            "elif [ -L '$pointer' ] || [ ! -f '$pointer' ]",
            "__SNTRACE_ABSENT__",
            "__SNTRACE_NOT_REGULAR__",
            "__SNTRACE_CHANGED__",
            "__SNTRACE_PRESENT__",
            "cat '$pointer'",
            "pointer_snapshot_before=`$(stat -c '%i:%s:%Y' '$pointer')",
            "pointer_snapshot_after=`$(stat -c '%i:%s:%Y' '$pointer')",
            "if [ `\"`$pointer_snapshot_before`\" != ",
            "No status was returned while reading trace pointer",
            "Ambiguous absent trace pointer response",
            "Invalid status while reading trace pointer",
            "pointer_size=`$(printf '%s\\n' `\"`$pointer_snapshot_after`\" |",
            "expected_size=`$((`${#pointer_value} + 1))",
            "Malformed trace pointer response",
            "Malformed trace pointer content was retained",
        ),
        "transport-distinguishing trace pointer reader",
    )
    publication_reader_code = trace_script[
        publication_reader_start:incomplete_reader_start
    ]
    incomplete_reader_code = trace_script[
        incomplete_reader_start:abandoned_reader_start
    ]
    abandoned_reader_code = trace_script[
        abandoned_reader_start:unresolved_guard_start
    ]
    if "catch" in publication_reader_code or "catch" in incomplete_reader_code:
        fail("trace failure-pointer reads can disguise transport errors as absence")
    if "rm -f" in publication_reader_code or "rm -f" in incomplete_reader_code:
        fail("trace helper can delete malformed failure guards")
    require_markers(
        publication_reader_code,
        (
            "[invalid publication-failed pointer]",
            "Retained an invalid trace publication-failure pointer",
        ),
        "malformed publication-failure guard retention",
    )
    require_markers(
        incomplete_reader_code,
        (
            "[invalid incomplete pointer]",
            "Retained an invalid Native Spread incomplete pointer",
        ),
        "malformed incomplete guard retention",
    )
    if "catch" in abandoned_reader_code or "rm -f" in abandoned_reader_code:
        fail("abandoned recovery-guard reads can hide or delete unresolved state")
    require_markers(
        abandoned_reader_code,
        (
            '$recoveryLock = "$remoteRoot/.active-recovery"',
            "if [ ! -e '$recoveryLock' ]",
            "[ -L '$recoveryLock' ]",
            "[ ! -d '$recoveryLock' ]",
            "__SNTRACE_RECOVERY_ABSENT__",
            "__SNTRACE_RECOVERY_PRESENT__",
            "$script:abandonedRecoveryPending = $true",
        ),
        "fail-closed abandoned recovery-guard reader",
    )

    pre_action_code = trace_script[helper_wait:action_switch]
    abandoned_call = pre_action_code.rfind("Read-AbandonedRecoveryState")
    publication_call = pre_action_code.rfind(
        "Read-PublicationFailedTraceState"
    )
    incomplete_call = pre_action_code.rfind("Read-IncompleteTraceState")
    unresolved_call = pre_action_code.rfind(
        "Assert-NoUnresolvedTraceFailure -CurrentAction $Action"
    )
    reconcile_call = pre_action_code.rfind(
        "Reconcile-AbandonedTracePointer -CurrentAction $Action"
    )
    if not (
        0 <= abandoned_call < publication_call < incomplete_call < unresolved_call
        < reconcile_call
    ):
        fail(
            "trace actions can mutate recovery state before unreadable or "
            "unresolved failure guards are checked"
        )

    if "pidof '$documentPackage' 2>/dev/null || true" in trace_script:
        fail("trace helper can treat an unknown pidof failure as no process")
    require_markers(
        trace_script,
        (
            "grep -c '^processId='",
            "__SNTRACE_METADATA_ABSENT__",
            "__SNTRACE_METADATA_NOT_REGULAR__",
            "__SNTRACE_PID_LIST__",
            "__SNTRACE_NO_PROCESS__",
            "Assert-TraceFailureGuardsClear -CurrentAction $CurrentAction",
            "Assert-CompletedTraceStillPullable -Session $session",
        ),
        "exact trace-owner and fallback revalidation",
    )

    matching_clear_start = trace_script.find(
        "function Clear-MatchingLocalExpectedTraceSession"
    )
    matching_clear_end = trace_script.find(
        "function Read-TraceOwnerProcessId", matching_clear_start
    )
    if matching_clear_start < 0 or matching_clear_end < 0:
        fail("could not isolate exact abandoned-session local cleanup")
    matching_clear = trace_script[matching_clear_start:matching_clear_end]
    matching_read = matching_clear.find(
        "$published = Read-LocalExpectedTraceSession"
    )
    matching_absent = matching_clear.find(
        "if ($null -eq $published)", matching_read
    )
    matching_mismatch = matching_clear.find(
        "if ($published -ne $Session)", matching_absent
    )
    matching_delete = matching_clear.find(
        "Clear-ExpectedTraceSession -Session $Session", matching_mismatch
    )
    if not (
        0 <= matching_read < matching_absent < matching_mismatch
        < matching_delete
    ):
        fail(
            "abandoned-session recovery can clear absent or mismatched local "
            "expected-session state"
        )

    helper_reconcile_code = trace_script[helper_reconcile:helper_wait]
    stable_identity_stat = "stat -c '%d:%i:%s:%Y'"
    if helper_reconcile_code.count(stable_identity_stat) != 5:
        fail(
            "abandoned-pointer recovery must validate the same stable "
            "device/inode/size/mtime identity at all five claim stages"
        )
    if "stat -c '%d:%i:%s:%Y:%Z'" in helper_reconcile_code:
        fail(
            "abandoned-pointer recovery includes ctime even though Android "
            "changes it during the helper's own atomic rename"
        )
    active_pointer_path = helper_reconcile_code.find(
        '$activePointer = "$remoteRoot/active.txt"'
    )
    recovery_lock_path = helper_reconcile_code.find(
        '$recoveryLock = "$remoteRoot/.active-recovery"', active_pointer_path
    )
    claimed_pointer_path = helper_reconcile_code.find(
        '$claimedPointer = "$recoveryLock/active.txt"', recovery_lock_path
    )
    archived_recovery_path = helper_reconcile_code.find(
        '$archivedRecovery = "$remoteRoot/.abandoned-$session"',
        claimed_pointer_path,
    )
    recovery_invoke = helper_reconcile_code.find(
        "$result = @(", archived_recovery_path
    )
    recovery_lock_create = helper_reconcile_code.find(
        "if ! mkdir '$recoveryLock'; then", recovery_invoke
    )
    candidate_identity = helper_reconcile_code.find(
        "candidate_identity=`$(stat -c '%d:%i:%s:%Y'", recovery_lock_create
    )
    candidate_value = helper_reconcile_code.find(
        "candidate_value=`$(cat '$activePointer')", candidate_identity
    )
    candidate_confirmed = helper_reconcile_code.find(
        "candidate_confirmed=`$(stat -c '%d:%i:%s:%Y'", candidate_value
    )
    claim_move = helper_reconcile_code.find(
        "if ! mv '$activePointer' '$claimedPointer'; then", candidate_confirmed
    )
    claimed_identity = helper_reconcile_code.find(
        "claimed_identity=`$(stat -c '%d:%i:%s:%Y'", claim_move
    )
    claimed_confirmed = helper_reconcile_code.find(
        "claimed_confirmed=`$(stat -c '%d:%i:%s:%Y'", claimed_identity
    )
    archive_create = helper_reconcile_code.find(
        "if ! mkdir '$archivedRecovery'; then", claimed_confirmed
    )
    archive_move = helper_reconcile_code.find(
        "if ! mv '$claimedPointer' '$archivedPointer'; then", archive_create
    )
    archived_identity = helper_reconcile_code.find(
        "archived_identity=`$(stat -c '%d:%i:%s:%Y'", archive_move
    )
    archived_status = helper_reconcile_code.find(
        "if ! rmdir '$recoveryLock'; then", archived_identity
    )
    archived_complete = helper_reconcile_code.find(
        "echo __TRACE_ABANDONED_ARCHIVED__", archived_status
    )
    recovery_result_count = helper_reconcile_code.find(
        "if ($result.Count -ne 1)", archived_complete
    )
    replacement_retained = helper_reconcile_code.find(
        "if ($recoveryStatus -eq '__TRACE_POINTER_REPLACEMENT_RETAINED__')",
        recovery_result_count,
    )
    pointer_changed = helper_reconcile_code.find(
        "if ($recoveryStatus -eq '__TRACE_POINTER_CHANGED__')",
        replacement_retained,
    )
    unexpected_recovery = helper_reconcile_code.find(
        "if ($recoveryStatus -ne '__TRACE_ABANDONED_ARCHIVED__')",
        pointer_changed,
    )
    recovered_check = helper_reconcile_code.find(
        "if ($recoveryStatus -eq '__TRACE_ABANDONED_ARCHIVED__')",
        unexpected_recovery,
    )
    recovered_identity = helper_reconcile_code.find(
        "$script:recoveredAbandonedTraceSession = $session",
        recovered_check,
    )
    recovered_local_clear = helper_reconcile_code.find(
        "Clear-MatchingLocalExpectedTraceSession -Session $session",
        recovered_identity,
    )
    if not (
        0 <= active_pointer_path < recovery_lock_path < claimed_pointer_path
        < archived_recovery_path < recovery_invoke < recovery_lock_create
        < candidate_identity < candidate_value < candidate_confirmed
        < claim_move < claimed_identity < claimed_confirmed < archive_create
        < archive_move < archived_identity < archived_status
        < archived_complete < recovery_result_count
        < replacement_retained < pointer_changed < unexpected_recovery
        < recovered_check < recovered_identity < recovered_local_clear
    ):
        fail(
            "trace helper does not atomically claim, revalidate, archive, and "
            "clear only the matching abandoned-session state"
        )
    if "mv '$recoveryLock' '$archivedRecovery'" in helper_reconcile_code:
        fail(
            "trace helper still relies on an unsupported Android "
            "shared-storage directory rename"
        )

    invalid_status_retention = helper_reconcile_code.find(
        "if ($CurrentAction -eq 'Status')"
    )
    stop_only_recovery = helper_reconcile_code.find(
        "if ($CurrentAction -ne 'Stop')"
    )
    pointer_removal = helper_reconcile_code.find(
        "$result = @(", stop_only_recovery
    )
    if not (
        0 <= invalid_status_retention < stop_only_recovery < pointer_removal
    ):
        fail("a non-Stop trace action can consume an abandoned active pointer")
    invalid_pointer_branch = helper_reconcile_code[
        helper_reconcile_code.find("if ($session -notmatch"):
        helper_reconcile_code.find(
            "$processId = Read-TraceOwnerProcessId",
            invalid_status_retention,
        )
    ]
    if "rm -f" in invalid_pointer_branch:
        fail("trace helper can delete a malformed active pointer")

    stop_trace = trace_script.find("'Stop' {")
    status_trace = trace_script.find("'Status' {", stop_trace)
    if stop_trace < 0 or status_trace < 0:
        fail("could not isolate Native Spread trace Stop action")
    stop_action = trace_script[stop_trace:status_trace]
    status_action = trace_script[status_trace:]
    abandoned_guard = stop_action.find(
        "if ($recoveredAbandonedTraceSession)"
    )
    active_read = stop_action.find("Read-RemotePointer -Name active")
    completed_fallback = stop_action.find("Read-RemotePointer -Name last")
    completed_validation = stop_action.find(
        "Assert-ValidTraceSession -Session $session -PointerName last"
    )
    wait_for_finalization = stop_action.find(
        "Wait-TraceFinalization -Session $session"
    )
    pull_bundle = stop_action.find('Invoke-Adb pull "$remoteRoot/$session"')
    if not (
        0 <= abandoned_guard < active_read < completed_fallback
        < completed_validation < pull_bundle
    ):
        fail("trace Stop can substitute a prior session after crash recovery")
    if not 0 <= wait_for_finalization < pull_bundle:
        fail("trace bundle can be pulled before asynchronous finalization")
    if stop_action.count("Assert-CompletedTraceStillPullable -Session $session") < 3:
        fail(
            "trace Stop does not revalidate guards/completion before and "
            "after its remote pulls"
        )
    if "Read-GuardedActiveTraceSession" not in stop_action:
        fail("trace Stop performs side effects without exact active-session guards")
    if "Pull-StagedScreenshots" not in stop_action:
        fail("trace Stop does not merge separately staged screenshots locally")
    if "Start-Sleep -Milliseconds 500" in stop_action:
        fail("trace Stop still relies on a fixed finalization delay")
    status_abandoned_guard = status_action.find(
        "if ($recoveredAbandonedTraceSession)"
    )
    status_publication_guard = status_action.find(
        "if ($publicationFailedTraceSession)"
    )
    status_incomplete_guard = status_action.find(
        "if ($incompleteTraceSession)"
    )
    status_reads_active = status_action.find(
        "Read-RemotePointer -Name active"
    )
    status_reads_last = status_action.find("Read-RemotePointer -Name last")
    if not (
        0 <= status_publication_guard < status_incomplete_guard
        < status_abandoned_guard < status_reads_active < status_reads_last
    ):
        fail("trace Status can fall back past a retained failure guard")

    wait_start = trace_script.find("function Wait-TraceFinalization")
    safe_label_start = trace_script.find("function Get-SafeLabel", wait_start)
    if wait_start < 0 or safe_label_start < 0:
        fail("could not isolate trace finalization polling")
    wait_action = trace_script[wait_start:safe_label_start]
    publication_failed_result = wait_action.find(
        "Read-RemotePointer -Name publication-failed"
    )
    incomplete_result = wait_action.find(
        "Read-RemotePointer -Name incomplete"
    )
    active_result = wait_action.find("Read-RemotePointer -Name active")
    completed_result = wait_action.find("Read-RemotePointer -Name last")
    if not (
        0 <= publication_failed_result < incomplete_result < active_result
        < completed_result
    ):
        fail(
            "trace finalization can wait on active.txt or publish completion "
            "before checking failure guards"
        )
    if "catch" in wait_action:
        fail("trace finalization can disguise pointer-read failures as absence")

    start_trace = trace_script.find("'Start' {")
    checkpoint_trace = trace_script.find("'Checkpoint' {", start_trace)
    start_action = trace_script[start_trace:checkpoint_trace]
    checkpoint_action = trace_script[checkpoint_trace:stop_trace]
    if "Read-GuardedActiveTraceSession -CurrentAction Start" not in start_action:
        fail(
            "trace Start can report success without rechecking failure "
            "guards and the exact active pointer"
        )
    if checkpoint_action.count("Read-GuardedActiveTraceSession") < 3:
        fail(
            "trace Checkpoint does not revalidate guards/identity before "
            "its control request and on both sides of its staged screenshot"
        )
    if '"$remoteRoot/$Session/screenshots"' in trace_script:
        fail("desktop screenshots can mutate an already-published trace bundle")

    if 'android:versionCode="140"' not in manifest:
        fail("companion manifest must use versionCode 140")
    if 'android:versionName="0.0.140"' not in manifest:
        fail("companion manifest must use versionName 0.0.140")

    manifest_version = re.search(
        r'android:versionCode="(\d+)"', manifest
    )
    plugin_minimum = re.search(
        r'NATIVE_READER_V2_MIN_VERSION_CODE = (\d+)L', plugin
    )
    companion_minimum = re.search(
        r'MINIMUM_COMPANION_MODULE_VERSION = (\d+)L;', v2_marker_claim
    )
    plugin_handshake = re.search(
        r'NATIVE_SPREAD_HANDSHAKE_PROTOCOL = (\d+)', plugin
    )
    companion_handshake = re.search(
        r'private static final int HANDSHAKE_PROTOCOL = (\d+);', v2_hooks
    )
    plugin_transaction = re.search(
        r'NATIVE_SPREAD_EDITABLE_MARKER_PROTOCOL = (\d+)', plugin
    )
    companion_transaction = re.search(
        r'public static final int TRANSACTION_PROTOCOL = (\d+);',
        v2_marker_claim,
    )
    if (
        not manifest_version
        or not plugin_minimum
        or not companion_minimum
        or not plugin_handshake
        or not companion_handshake
        or not plugin_transaction
        or not companion_transaction
    ):
        fail("could not read packaged, handshake, and authority protocol versions")
    packaged_version = int(manifest_version.group(1))
    required_version = int(plugin_minimum.group(1))
    companion_version = int(companion_minimum.group(1))
    if not packaged_version == required_version == companion_version:
        fail(
            "packaged, plugin-required, and companion-reported versions "
            "must match exactly: "
            f"manifest={manifest_version.group(1)} "
            f"plugin={plugin_minimum.group(1)} "
            f"companion={companion_minimum.group(1)}"
        )
    if plugin_handshake.group(1) != companion_handshake.group(1):
        fail(
            "plugin and companion handshake protocols must match exactly: "
            f"plugin={plugin_handshake.group(1)} "
            f"companion={companion_handshake.group(1)}"
        )
    if plugin_transaction.group(1) != companion_transaction.group(1):
        fail(
            "plugin and companion journal payload protocols must match "
            "exactly: "
            f"plugin={plugin_transaction.group(1)} "
            f"companion={companion_transaction.group(1)}"
        )

    print("Native Spread safety invariants: PASS")


def main() -> None:
    if len(sys.argv) != 2:
        fail("usage: check_native_spread_invariants.py <repo-root>")
    check(Path(sys.argv[1]).resolve())


if __name__ == "__main__":
    main()
