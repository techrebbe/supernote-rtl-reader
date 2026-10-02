# T011 Windows packager follow-up

Narrow independent review CLEAN. The pinned template's native Windows jq
converted logical archive paths into host paths; native Python CRLF output also
made the existing exact ReactPackage exclusions fail during build replay.

The patch now excludes only the two JSON path arguments from MSYS conversion,
preserving caller exclusions and limiting each change to its jq invocation.
The scanner removes one terminal CR; embedded/doubled CR emits an invalid
sentinel, which the unchanged exact package-set guard rejects. Unknown packages,
template drift and duplicate markers still fail closed. No signer, verifier,
payload, expected-package, native writer, source geometry or annotation changes.

Actual pinned-template/native jq/Python regressions 8/8 PASS; diagnostic build
boundary 11/11 PASS; existing packaging failure-injection PASS. Independent
review reran the tests. Only packager and its existing failure-test digests are
repinned to the reviewed text. Frozen legacy sources and verifier pins unchanged.
Full production build/replay remains the next candidate's gate, not a result
retroactively attributed to the manually repackaged T011 diagnostic.

No device access, external source upload or merge in this follow-up.
