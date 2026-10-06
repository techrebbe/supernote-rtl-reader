# T014 native key-host slice — offline, separate from installed code51

Owned branch agent/page-turner-bridge, based on4c3465a. Installed code51 and
completed T013C evidence are unchanged. No device access or package registration.
Status: isolated native slice and focused corrections independently confirmed
CLEAN; ready for bounded RN transport integration, NOT a hardware candidate.

Implement one ReaderKeyHost ReactViewGroup around the future reader page area,
not competing page-surface listeners, PluginHost Activity overrides or native
reader hooks. Native Core stamps immutable document/activation/generation at
dispatch on the UI thread. Every routing configuration/focus/visibility/attachment
change fences the old activation; native uptime cutover rejects earlier contacts.
Attachment is explicitly false during detach, even while framework live state
still reports attached. Direct host focus is required; no automatic focus request
or descendant-focus blocking. Explicit focus request cannot steal another view.

Keys are opt-in allowlisted; defaults/mapping remain the separate existing JS
controller. Volume/media/system behavior outside the focused reader is retained.
One exact device/key/downTime DOWN produces one packet, repeated DOWN is consumed
without another turn, exact UP releases, focus loss cancels. Android nonnegative
int32 repeatCount is respected rather than inventing a255-repeat device limit.
Contacts bounded32 with retired-time replay fence and missing-UP recovery only
through a genuinely newer press, not timers or queued turns.

Sink failure terminally revokes, releases references and consumes a possibly
partly delivered accepted key without retry/fall-through. A failed terminal
notification cannot escape cleanup. No source/page/annotation IO or save/restart
route exists in these classes. Caller state validation remains owner-thread only.

## Focused checks

Actual Core Java suite, actual Host source under narrowly defined callback-order
doubles, real Android35/ReactNative0.79.2 API compilation, existing21 JS controller
and actual App navigation-route tests. Doubles intentionally model attachment
remaining true inside detach, and state/key/terminal Sink exceptions. Accepted
defect mutations must each be rejected. No Android/HID runtime pass claimed.
Actual API compile may warn about absent dependency Nullsafe.Mode annotation;
that warning is not suppressed or treated as device evidence.

Independent review found state/terminal callback failure, detach attachment ABA,
and >255 held-repeat fall-through. Corrections passed2134 Core assertions,
25 actual-Host/callback-model assertions, four accepted-defect mutation rejections,
real Android35/RN0.79.2 API compile,21 JS/controller/current-App route tests and
unchanged native/Edit/v2 source invariants. Independent correction confirmation
is CLEAN for the isolated source slice. Reviews retained locally at
tmp/t014-key-host-review1.md and review2.md; reviewers inspected source only,
not independently executed tests. Reentrant Sink/long-held opt-in paths were
inspected, not directly runtime-tested; no issue found. Native device/RN/HID
delivery remains unverified. No installer/manager/App/frozen source digest changed.

## Next concrete step / earliest safe hardware gate

Add exactly one React Native manager and one ordered, non-coalescing native key/
state event route; atomically commit complete routing configuration after props.
The JS consumer must retain exact bridge-stamped identity, reject stale packets,
and use existing current-modal/Edit/Close/render guards and logical page handlers.
Never restamp queued packets with newer JS IDs. Define the config-request identity
and state/key delivery ordering before wiring; current classes alone do not prove
cross-runtime queue revocation. Persist opt-in per-document configuration using
existing preference machinery, preserving explicit disabled settings.

Update2026-10-06: that isolated transport step is now implemented/tested and
independently confirmed CLEAN; see T-014-key-transport.md for its exact contract
and evidence. It is still NOT registered/copied/imported/shipped. Next is the
bounded App/preferences/focus integration, followed by the full integrated gate.

After focused integrated tests, one independent exact-head review, package build/
signer and fresh reservation, first bounded injected-key disposable test establishes
real focus/delivery. Then human paired-turner button/hold evidence identifies its
actual HID keys. Neither a JVM double nor injected key freezes a remote mapping.
Fail/unknown stops, no global-hook rescue. No stock reader/original/BOOX changes,
new installation under old reservation, broad rewrite, PR finalization or merge.
