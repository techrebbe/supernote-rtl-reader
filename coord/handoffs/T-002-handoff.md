# T-002 handoff — corrected candidate to hardware gate

Claude head `904ee54a8b26d05dd6faa2eb37ffd1a909e35d90` was reviewed read-only.
Corrections are on Codex's separate branch `agent/edit-return-correction`:
exact software commit `66ac1d56546db1102d3a50ae0c021d57653d6c35`.
Claude's branch remains unchanged. All findings 1–6 are CLOSED in the corrected
candidate, with independent exact-head review finding no remaining scoped
critical/high blocker. No Nomad access, installation, push or merge was performed.

## Candidate and retained local artifacts

`0.4.24-edit-exp2`, code 44; marker
`RTL_READER_OPEN v0.4.24-edit-exp2-native-reader-v2`.
Retained build root (relative to the local Supernote project mirror):
`tmp/edit-exp2-66ac1d5-build1/`.
Installable file: `out/SupernoteRtlReader.snplg`, 7,363,845 bytes.
SHA-256: `c5954a12429a89ba502310f9cac79f270da83eb1ec0e3ac36d4989173d0fbf0a`.
Embedded APK (inspection only):
`out/SupernoteRtlReader-0.4.24-edit-exp2-66ac1d5-embedded.apk`, 7,256,039 bytes.
SHA-256: `b8e9943fb8249805023757a1ff7ed6add59d555686d336db95687b48f18a56cf`.
APK package `com.supernotertlreader`, template version 1.0/code 1.
APK v2/v3 signatures verified, one signer, certificate SHA-256:
`fac61745dc0903786fb9ede62a962b399f7348f0bb6f899b8332667591033b9c`.
Matches the retained v0.4.23 installed-package evidence; no fresh device query.
Full local evidence: `candidate-verification.json` and both clean build logs.

Known-good v0.4.23/code 42 package (relative to local project mirror):
`inspection/native-reader/prototype/supernote-rtl-reader-pr22-upload/out/SupernoteRtlReader.snplg`.
SHA-256: `ee2f0623c878ea830a6d7b8c693efd7d4144194779c41f01808bd468cfc5cc96`.
Retaining the file does not itself prove a supported downgrade/install route.

## Passed offline gates

38 Edit/Return and 37 actual-App lifecycle tests; 85,407 Java assertions;
271 mutations and ten interleaving groups; renderer/v2/Edit/cross-layer pins;
packaging, provenance and fake-ADB trace-helper gates; independent exact-head
review. Two clean detached builds passed; JS, DEX, executable native sections,
manifest and resources match. Raw package bytes differ in debug/symbol/build-id,
signing and archive metadata: do not claim byte-for-byte reproducibility.

## Next and unresolved

Current bounded plan: `../tasks/T-002.md`; earliest hardware gate reached.
Need explicit session/install approval and issue #23 reservation, not another
offline cycle. Immediate handoff acknowledges config/restart scheduling only;
actual target loading and saved ink retention need hardware evidence. Unsaved
stock ink across SIGKILL (T-001 E3) and absent `.mark` display in RTL remain
separate follow-ups; a saved-stroke smoke pass is not release approval.
