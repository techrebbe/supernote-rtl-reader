# T017 — unrooted3.30.45 compatibility, bounded outcome

## Authoritative hardware observations

User authorizes checks without restoring root. Exact NomadSN078C10015092, firmware
Chauvet.E103.2610091001.2545_release/Android11/API30. PluginHost1002610090 and
Document102511 still share system UID1000; shell is2000/SELinux shell. No su,
adb root, run-as, relabel, module/firmware change or installation attempted.
Source T008 SHA256bd0fd00b4879cedb1b768a19deb2901a6d50dc7373decc8ef60e445613d83e64;
mark13309bytes SHA256cf4446631eca6644d42c305af46729374369a341f3a1c00892586b266f9e5724.
Both unchanged from retained previous-firmware evidence and at final postflight.

Exact readable public APKs:

- PluginHost:37530743bytes, SHA256
  f60ce4830c09c5d1ff2453e02b74fa0f7d1d098484b04380fc4517f0007d2aad.
- SupernoteDocument:SHA256
  dd77ff2ce412983c62c2c13f2212b2e79ed3a772d12001de22a6afa40076f986.

Own private plug-in files/preferences unavailable to shell, recorded without
bypass. Native UI confirms RTL Reader enabled0.4.24-keys-exp3; installed private
payload checksum/current exact executable head UNVERIFIED. Code55/bb9dbf6 is
retained known source/artifact identity, not a new installed-byte assertion.
New actual plug-in list15 entries/10 enabled; not compared to old inventory4.

## Bounded sequence and stop

Initial read-only phase6142673172 released6142717023 on other-app ownership.
User confirms free, reserve6142772888. Concurrent other-chat launch caught by
owner guard before tap; explicitly authorized coordination obtained actual
release/no active test before resuming. No other-app data/controls operated;
normal HOME and exported stock Settings/library routes only.

Exact normal T008 selection opened nativePAGE1. New footer initially hidden;
two XML-only reads stopped before screenshot/input. User exposed footer, then
exact title/PAGE1 witnessed and saved BoxA line/blank BoxB confirmed. Normal
native More/Plugins/RTL Reader produced host incompatibility dialog. Record
launch FAIL; reading/native render/SDK ink/Edit/Return/Bluetooth NOTPERFORMED.
Dismiss OK normally; no reader-side handoff/restart or SDK generation began.

Final nativePAGE1 screenshot matches baseline exactly. PDF/mark/both public APKs
exact;34 explicit regular/nonsymlink/hash-backed remote XML/PNG copies removed
once, absence verified. Local evidence retained only, no vendor/raw/PDF/mark/
credential upload. Private preference/cache postflight not verifiable through
shell, not a full private-state cleanup claim. RELEASED6143161919. Separate chat
notified; no active device process. Timer PAUSED, no merge/finalization.

## Concrete source finding: version-report handshake, not missing root

Filtered hardware log: PluginApp.isPluginAvailableVersion libVersion0.1.60.
Exact new public APK bytecode shows constructor initializes that field to0.1.60
and isAvailableVersion=false. Therefore that log is NOT proof that the installed
dependency is0.1.60. isPluginAvailableVersion gates on the availability boolean;
reportSdkVersion sets it true only when reported version is>=0.1.62 and<=0.3.1.
Retained source dependency lock0.1.43 and exact code55 bundle lack the report call.

Published sn-plugin-lib0.1.65 metadata/archive inspected without installing or
executing it. SHA512 integrity from official npm metadata verified:
sha512-jMQhpOHyzi3AxyxO7kc4OwXYQKgQ7tQXSFYH1l5W4po4w2GXEBfg2mrD8x0otv2jbwjYwvUZ+VZLe0RJZCQWyA==.
Its PluginManager.init calls onMounted then reportSdkVersion(pkg.version).
This is a concrete supported SDK candidate within Supernote's announced<=0.1.65
legacy-coordinate band. It is not a new-firmware hardware compatibility PASS.

References:

- [Official developer compatibility/coordinate announcement](https://www.reddit.com/r/Supernote_dev/comments/1x3qtce/plugin_release_manta_nomad_chauvet_33045_and_a5x/).
- [Published SDK0.1.65 metadata](https://registry.npmjs.org/sn-plugin-lib/0.1.65).
- Local evidence tmp/t017b-unrooted-20261013:baseline/postflight JSON, filtered log,
  APK, narrow dexdump extracts and SDK tarball. Vendor bytecode remains local.
- Retained reviewed package tmp/t016g-bb9dbf6-build1/out; sourcebb9dbf6.

## Focused host validation and minimum next stage

Native/Edit/v2 invariants,6 saved-ink wiring,2 actual key assembly,42 Edit/Return,
62 actual lifecycle callback tests PASS. First host-temp PermissionError resolved
using a workspace-local temp root; no source or test edits. Tests characterize
existing software, not new firmware/API/geometry compatibility.

Prepare a proper dependency/version-report update, keeping current architecture,
root-free handoff, legacy coordinate contracts, native/JS key guards, saved-ink
fences and source provenance intact. Do not spoof SDK metadata, weaken firmware
pins or change the frozen Virtual Spread contract. Old rooted module remains
incompatible with the new fingerprint/Document102511; do not revive it.

Review the actual supported-SDK API delta, pin/authenticate all changed dependency
inputs, test actual initialization reporting/package assembly and relevant
existing gates, independently review, then exact clean signed build. Only after
explicit normal-upgrade scope/fresh exclusive reservation, run the smallest
T008 launch/settled saved-ink reading gate, one logical page turn, exact-page
Edit/Return without fresh pen, then normal Close/integrity/owned cleanup. Stop
first identity/ink/access/lifecycle/cleanup mismatch; no rescue or speculative
extra keys. Physical writing and Bluetooth remain later separate gates.

No production code, lock, protected source digest or package changed by T017.
