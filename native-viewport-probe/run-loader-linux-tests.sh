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
# If the policy regresses, any attempted relative fixture file creation remains
# in this disposable build directory, never a caller's working directory.
cd "$loader_build"
./loader-report-test
./loader-linux-test ./loader-fixture.so
printf '%s\n' "$loader_build"
