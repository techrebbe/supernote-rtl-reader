# Isolated Android visual-lease Port (offline only)

These sources are intentionally outside the disposable host's normal `src/`
tree. Its existing APK does not include them, and no Activity instantiates the
Port or visual child. `test-lease-port.ps1` compiles them separately against
Android API 30 and runs pure-Java paint/mutation-fence tests. This is not a
Nomad or production-reader adapter.

The controlled root records a monotonically increasing revision when an actual
`dispatchDraw` pass begins. Its effective order comes from actual `drawChild`
calls, with each child's identity, index, and evidence captured at that call.
It publishes a completed frame only if the root/scene/hierarchy evidence is
unchanged after the pass. The visual child gates its entire `draw(Canvas)`
before admission, not just its `onDraw` body. The Port removes only the exact
owned child from the exact original root.

The separate mutation revision must advance **before** every scene, hierarchy,
geometry, child-metadata, and draw-policy mutation. The Port currently reports
invalid mutation authority and refuses root admission unless a future Activity
owner explicitly certifies complete synchronous coverage. Known Port-owned
add/remove and root layout paths bump the ledger, but this does not cover
arbitrary external setters. No existing Activity supplies that certification;
do not wire one in merely to make a test pass. The final revision getter is a
non-reentrant local read; stale completed frames are rejected after a bump.

The current generic `addView` path is intentionally not an admission-ready
path: Android may schedule a later `onLayout`, and that callback bumps the
mutation revision before it changes child geometry. The core requires exactly
one revision for the owned add and an unchanged revision through its first
completed admission frame, so such a later layout must fail closed. A future
disposable-only candidate would need to pre-measure/place the owned child
inside one bounded root-owned add transaction while proving that no original
or root geometry changes, and suppress any *extra* layout only when it can
prove that no evidence mutates. Genuine scene, root, or original changes must
still bump before mutation and reject the lease. Do not simply suppress
`onLayout` bumps or relabel them as the add.

The disposable host paints nine **visible** synthetic children. The offline
Core now represents nine exact structural originals separately from their
actual `drawChild` order: a Snapshot may independently mark one original as
not expected to paint, and an eight-identity completed order must contain
every expected visible original exactly once. Admission, owned-child rank,
draw gating, and live rollback compare that same expectation. The legacy
Snapshot constructor still means all nine are expected to paint. Host tests
cover the pinned XML shape with child 7 `GONE`, missing visible children,
visibility transitions, and an owned child at a distinct structural/paint
slot. This is an offline representation result, not stock runtime evidence.

The offline Android paint root now derives expected participants from each
child's visibility and rejects missing, extra, or duplicate actual
`drawChild` calls. After a mutation, `currentSnapshot()` can report the
current structure with an empty paint order; it does not borrow an old frame.
The Core uses that cut only for the immediate post-removal structural check
and still requires a later completed paint frame to report restoration.
These source and host checks do not wire an Activity or exercise a real
Android child insertion. The Nomad hierarchy capture matched the pinned
nine-child shape, but neither the XML nor that capture proves stock paint
order or final e-ink composition.

Remaining gates: independently review these sources; wire an Activity-owned
scene/lifecycle/mutation authority only in a separate reviewed change; prove
pixel silence and actual draw order on the disposable emulator; then determine
whether the stock structural and paint assumptions are valid. No insertion on
the Nomad is authorized by this scaffold.
