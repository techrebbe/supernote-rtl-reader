#!/usr/bin/env bash
# Unprivileged host-only tests; no tablet or firmware access.
set -euo pipefail
probe_root="$(dirname "$(readlink -f "$0")")"
mkdir -p "$probe_root/build"
loader_build="$(mktemp -d "$probe_root/build/loader-linux-XXXXXX")"
gcc -std=c11 -O2 -Wall -Wextra -Werror -fPIC -shared \
    "$probe_root/native/loader_fixture.c" -o "$loader_build/loader-fixture.so"
gcc -std=c11 -O2 -Wall -Wextra -Werror \
    "$probe_root/native/loader_linux_test.c" -ldl -o "$loader_build/loader-linux-test"
gcc -std=c11 -O2 -Wall -Wextra -Werror \
    "$probe_root/native/loader_report_test.c" -o "$loader_build/loader-report-test"
gcc -std=c11 -O2 -Wall -Wextra -Werror \
    "$probe_root/native/isolation_filter_linux_test.c" -o "$loader_build/isolation-filter-linux-test"
# If the policy regresses, any attempted relative fixture file creation remains
# in this disposable build directory, never a caller's working directory.
cd "$loader_build"
./loader-report-test
./loader-linux-test ./loader-fixture.so
./isolation-filter-linux-test
elftools_root="$(readlink -f "${RTL_READER_AUTHENTICATED_ELFTOOLS_ROOT:-$probe_root/../../../tools/python}")"
gate_path="$probe_root/pinned_elftools_gate.py"
expected_gate_sha256="ff7021874c16321f71b4309e131d78061d0d71c4cd6d14743574fc4eb229cd2f"
IFS= read -r -d '' gate_bootstrap <<'PY' || true
import hashlib, os, stat, sys, types

def fail():
    raise SystemExit(126)

def identity(value):
    fields = (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
              value.st_size, value.st_mtime_ns,
              getattr(value, "st_file_attributes", 0))
    return fields + ((value.st_ctime_ns,) if os.name == "posix" else ())

def capture(path, expected, limit):
    descriptor = None
    try:
        named = os.lstat(path)
        if (not stat.S_ISREG(named.st_mode) or
                getattr(named, "st_file_attributes", 0) & 0x400 or
                named.st_size < 1 or named.st_size > limit):
            fail()
        flags = (os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) |
                 getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0) |
                 getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0))
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if (not stat.S_ISREG(opened.st_mode) or
                getattr(opened, "st_file_attributes", 0) & 0x400 or
                identity(opened) != identity(named)):
            fail()
        chunks = []
        remaining = opened.st_size + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        final_named = os.lstat(path)
        if (len(raw) != opened.st_size or identity(after) != identity(opened) or
                identity(final_named) != identity(opened)):
            fail()
    except (OSError, OverflowError, TypeError, ValueError):
        fail()
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                fail()
    if any(separator in raw for separator in (
            b"\xc2\x85", b"\xe2\x80\xa8", b"\xe2\x80\xa9")):
        fail()
    if b"\r" in raw:
        if raw.count(b"\r") != raw.count(b"\r\n") or raw.count(b"\n") != raw.count(b"\r\n"):
            fail()
        raw = raw.replace(b"\r\n", b"\n")
    if hashlib.sha256(raw).hexdigest() != expected:
        fail()
    return raw

gate_path, expected_digest, limit_text = sys.argv[1:4]
try:
    gate_limit = int(limit_text)
except ValueError:
    fail()
if gate_limit != 65536:
    fail()
gate_source = capture(gate_path, expected_digest, gate_limit)
sys.argv = [gate_path] + sys.argv[4:]
main = types.ModuleType("__main__")
main.__file__ = gate_path
main.__package__ = ""
main._rtl_reader_authenticated_gate_source = gate_source
sys.modules["__main__"] = main
exec(compile(gate_source, gate_path, "exec", dont_inherit=True),
     main.__dict__, main.__dict__)
PY
expected_probe_sha256="07e205bc314fc1cdbbc23fa58391b2f5450cdda791d83c08e32651a74f8e300b"
test_log="$loader_build/python-tests.log"
if ! python3 -I -S -E -s -c "$gate_bootstrap" \
        "$gate_path" "$expected_gate_sha256" 65536 \
        --python-path "$elftools_root" --probe-root "$probe_root" \
        --expected-probe-sha256 "$expected_probe_sha256" 2>&1 | tee "$test_log"; then
    printf '%s\n' 'Full authenticated Linux evidence suite failed' >&2
    exit 1
fi

ran_count="$(awk '$0 ~ /^Ran 222 tests in [0-9]+([.][0-9]+)?s$/ { count++ }
    END { print count + 0 }' "$test_log")"
if [[ "$ran_count" != 1 ]]; then
    printf '%s\n' 'Authenticated Linux test count changed from required 222' >&2
    exit 1
fi
terminal_count="$(awk '$0 == "OK (skipped=9)" { count++ }
    END { print count + 0 }' "$test_log")"
if [[ "$terminal_count" != 1 ]]; then
    printf '%s\n' 'Authenticated Linux terminal result is not exact' >&2
    exit 1
fi

mapfile -t actual_skip_reasons < <(
    sed -n "s/.* skipped '\([^']*\)'$/\1/p" "$test_log" | LC_ALL=C sort
)
expected_skip_reasons=(
    'PowerShell production wrapper'
    'Windows alternate data streams'
    'Windows output ADS rejection'
    'Windows packaged-APK ADS rejection'
    'Windows packaged-evidence crash boundaries'
    'Windows packaged-output ADS rejection'
    'Windows retained handle denies writers'
    'Windows retained-parent and rollback'
    'Windows source name/content pinning'
)
if [[ "${#actual_skip_reasons[@]}" -ne "${#expected_skip_reasons[@]}" ]]; then
    printf '%s\n' 'Authenticated Linux skip count differs from the required platform gates' >&2
    exit 1
fi
for index in "${!expected_skip_reasons[@]}"; do
    if [[ "${actual_skip_reasons[$index]}" != "${expected_skip_reasons[$index]}" ]]; then
        printf '%s\n' 'Authenticated Linux skip multiset differs from the required platform gates' >&2
        exit 1
    fi
done

pinned_parser='PINNED_ELFTOOLS {"files":54,"sha256":"09679ad9ea7781df8fe3ef1d39b2189261f57967e06c549ce2891b977018382a","version":"0.32"}'
pinned_probe="PINNED_PROBE_SOURCES {\"files\":15,\"sha256\":\"$expected_probe_sha256\"}"
for expected_line in "$pinned_parser" "$pinned_probe"; do
    line_count="$(awk -v expected="$expected_line" '$0 == expected { count++ }
        END { print count + 0 }' "$test_log")"
    if [[ "$line_count" != 1 ]]; then
        printf '%s\n' 'Linux suite did not execute the exact authenticated source snapshots' >&2
        exit 1
    fi
done
printf '%s\n' "$loader_build"
