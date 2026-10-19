# T020 independent source review — 2026-10-19

## Hardware gate status (not an additional review)

Current setup gate R3/release6271422662: display/input orientation disagreement
after a misplaced Settings-row tap, before stage/install or settings changes.
Product72/openFile/show remain untested. Local driver now rejects mismatched
frames (13 offline cases PASS), no production correction/rebuild inferred.
R1/R2 return-to-library was caused by the host's normal Back closing Settings,
not an independently established spontaneous change. Prior no-input wording
is corrected by actual host/event evidence; do not treat it as a reader defect.

H1R1 reservation6270552551 also stopped before package selection/installation
after an uncommanded foreground change; RELEASE6270642388, integrity/owned scratch
cleanup PASS. Installed71 verified ON; exact72 still uninstalled. This is not a
reader software failure or a visible-favourite acceptance. Cause remains UNKNOWN;
do not attribute it to openFile/showPluginView, which were never invoked.

Reviewed exact72 published through fc64026 with explicit user approval. First
approved reservation6269131197 stopped at unexpected foreground owner before
capture/input/install; RELEASE6269173663. No device behavior was tested and no
source correction/new review is warranted by this stopped setup. The original
required exact-book visible-open gate below remains pending on the SAME signed
candidate; no hardware acceptance is inferred from publication or SDK return.

User explicitly approved a separate source-only independent review. Reviewer
`t020_independent_review` inspected the frozen18-file working diff, including all
new source/tests, on base2d815e7e7a2531b427e702c5d3056730260fa6c7. The reviewer
did not edit the repository, build/install, access hardware, publish, use the
network or delegate further. Source-first; no broad historical architecture audit.

## Completed report

No confirmed actionable source defect or critical/high blocker found. Ready for
next-build preparation, NOT hardware/release acceptance.

Independently rerun: new library/UI and existing PDF interaction/lifecycle/
bookmark tests58/58; permission/SDK handoff/Bluetooth transport/session74/74;
generated integration9/9 including actual generated Close/activation guards;
native library109 controlled-peer assertions; bounded source-session/hash73
controlled-peer assertions; pinned SDK0.1.65 JS forwarding/validation including
openFile(path,-1)/showPluginView. All PASS.

Real Android compilation and temporary JNI loading were independently unverified
because of sandbox restrictions; the reviewer did not route around those limits.
Main had previously passed focused real Android35/RN0.79.2 compilation and streamed
Session/JNI gates on this same frozen source. These are host evidence, not device
permissions, visible presentation or writer-safety witnesses.

Conclusions: separate metadata does not modify saved-page/Edit authority;
missing/malformed/replaced/mismatched favourites fail closed; staged-owner
admission is retained; one exclusive SDK open/no mutation retry; chooser Close
skips stale handoff; copies/native registration/source receipts/classes include
new components; existing portrait/spread/key/Edit/Close reuse retained. No new
PDF, annotation, private-config or native-restart write path identified.

## Required first device observation

SDK0.1.65 PluginModule.java141–152 resolves showPluginView after POSTING its UI
operation. That acknowledgement does not prove actual visibility. A later approved,
fresh-reservation disposable test must prove openFile preserves the launch context
and the exact selected book visibly opens in RTL Reader. Stop on context retirement,
hidden/missing reader or mismatch; do not add retries/fallback mutations.

## Frozen source identity

Raw SHA256 values independently confirmed unchanged throughout initial review:

- overlay/ReaderLaunch.js:6080083d6aafe992cd34bde7535f79998b0fb408a9d92678148a86eda247cafa
- overlay/readerLibrary.js:70de0a64dddf40005365df703eb271eb3c7ed94e2f2548a6377dfa6a35615d89
- native/ReaderLibraryModule.java.template:eb3674f4c4ec2e3bd9577effbf07361d5996f5b6d5c4c2cc39e5c3f488cdfd32

Old71 candidate identity and unchanged workflow/build frozen pins were known
pre-build gates, not ignored failures. A follow-up must verify the new72 identity,
exact scoped workflow/build/marker digest expectations and source aggregate before
normal exact-source build. No publication, installation or merge authority follows
from this review. Retain71 and70 packages, evidence and unrelated work.

## Identity/pin follow-up — CLEAN

The same independent reviewer confirmed0.4.25-library-exp1/code72, matching
runtime/artifact labels, and READ-only/plugin-ID stability. Reversing only the
intended edits exactly restored the base LF hashes:

- index57307660...6e7e19 ->0d0a9290...e6b9a (runtime marker only).
- workflow02d59e20...5398c1 ->ccaf9cd8...174727 (one native test and artifact label).
- build a65b62b0...323ae ->e2744c4e...a210e3 (two JS copies/two JS tests).

Token-level comparison confirmed the identity-check scripts changed only matching
expectations/comments; the cross-layer gate changed only the three corresponding
hashes/comments. No signing/SDK/dependency/permission/native-writer pin weakened.
All three main source hashes remained unchanged. Independently recomputed27-input
LF-text source map aggregate (SHA256 of sorted compact JSON):
9840778312d78d31bcf212fde9f33804cc00561b7a7de0b807b5abd8841e63e9.

No finding blocks local build preparation. Built-package signer, actual visible
reopen and hardware behavior still need their own evidence. No reviewer mutation,
build, device access or publication occurred.

## Main build evidence after review

Exact source106ec80e566adce8555ab69fd94e6745c7708116 normal clean-source build
attempt2 exited0/75tasks; SDK+JS58, complete package/source/DEX/ELF/engine/notices/
bundle gate and actual-APK provider11 PASS. Main separately verified27 source
inputs/aggregate, library class/private-store/UI presence and exact marker. v2/v3
signer fac61745dc0903786fb9ede62a962b399f7348f0bb6f899b8332667591033b9c
matches retained71. SNPLG3327f873c7436a7e183a9648395fa4352aebcae236b2cf6115b07498e119d29d.

Attempt1 stock-SDK CMake/Ninja path failure was retained; same source succeeded
with a shorter temporary root, no production change or gate bypass. This evidence
is main verification after source review, not a separate reviewer claim of building
or testing the Nomad. No hardware, installation or publication has occurred.
