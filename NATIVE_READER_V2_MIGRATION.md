# Native Reader v2 cutover

## Executable boundary

Native Reader v2 is now an exclusive implementation, not a shadow of the
experimental Native Spread engine:

- `assets/xposed_init` names only `NativeReaderV2EntryPoint`;
- the v0.0.135 `SpreadProbe.java` and native interception source are retained
  only as hash-pinned forensic evidence;
- neither the legacy Java entry point nor `libspreadprobe.so` is compiled or
  packaged; and
- the build rejects either legacy payload if it re-enters the APK.

The exact v0.0.135 sources remain available for comparison, but no production
callback, bitmap, gesture, annotation, or writer state is shared with v2.

## Admission and cutover rule

Behavioral cutover is all-or-nothing for one exact PDF and
`DocumentActivity` generation. The plugin must first publish a committed
record in the fixed-inode `.snspread-v3` authority journal and a verified
recovery snapshot. The injected companion then verifies:

- the exact supported firmware fingerprint and system Document APK bytes;
- the exact companion package version and signer;
- the original PDF inode/version, SHA-256, and canonical path;
- an exact committed journal record and immutable recovery evidence;
- the live PDF and `.mark` paths;
- the current reader, presenter, note, DrawPath, bitmap-view, page, and layout
  identities; and
- one authoritative source-to-screen affine for each visible page.

Only after those checks pass may v2 publish a `SpreadSession`. A document
without that exact authority remains completely stock.

## Failure and lifecycle rule

Writer transfer failures roll back to the witnessed source page. If rollback,
component identity, native chrome discovery, save acknowledgement, or partial
presentation publication cannot be proved, v2 disables itself and keeps native
writing blocked until the stock reader is recreated. It never falls through to
the legacy engine.

If rotation or pause begins during an already-live native contact, v2 does not
save, remap, or disable that contact mid-gesture. It preserves its exact native
restoration leases while Supernote's lifecycle cancels or settles the contact.
After both the stock callback and the physical terminal sample complete, v2
saves through the witnessed native path, disables the writer, restores the
original page/presentation geometry, and then either rebuilds the rotated
spread or waits for resume. Missing authority fails closed instead of
abandoning modified geometry in the stock reader.

Containment follows the same physical-contact fence across both Supernote's
digital-position callback and Android stylus dispatch. A failure discovered
during a native pass-through contact freezes new v2 work immediately but
defers writer disable until the exact UP/CANCEL boundary, so fail-closed
handling cannot truncate a stroke that Supernote already owns. A contained
runtime cannot schedule or publish another writer/session generation.

Safe runtime detachment is likewise acknowledged, not assumed. v2 restores
its geometry leases and asks Supernote to reload the stock page, then remains
installed and input-frozen until fresh stock background, handwriting, and
digest layers have all been presented. Only after those three independent
signals and a final live-component check may hook ownership be removed.

Activity destruction is a distinct boundary. Supernote's pinned `onDestroy`
is allowed to perform its final native save, writer disable, and surface clear
while the v2 transform is still authoritative. Only its after-hook retires the
runtime and discards the now-dead component leases; v2 never restores stock
geometry before that final save.

Projection shutdown first rejects new work and cancels queued work. Any
already-running native projection is drained on a dedicated daemon cleanup
thread; component identities are released only after that drain. Lifecycle UI
callbacks never wait on the projection lock, and late or stale results recycle
their bitmaps instead of publishing them.

Native saves do not rewrite the immutable recovery snapshot. Each witnessed
dirty save publishes a separate exact-schema live-mark checkpoint while the
exclusive writer lease remains current. The checkpoint binds the original PDF,
the precise recovery manifest/snapshot evidence, and the resulting live `.mark`
hash. On a cold process restart, a live mark newer than the rollback baseline
is admitted only through that exact persisted witness; missing, stale, torn, or
unwitnessed state remains fenced. Directory publication uses a no-follow,
descriptor-pinned FUSE fallback. A durable pending-publication fence is created
before the checkpoint pathname changes and is retired only after complete
post-rename verification, so an interrupted or ambiguously verified checkpoint
cannot become cold-start authority. A zero-byte regular `.mark` is treated as
valid content rather than absence.

Authority acknowledgements are similarly restart-safe: each request uses a
replaceable worker, keeps the live PDF descriptor pinned across hashing and the
exact journal reread, and performs a final PDF path/version check before
replying. An acknowledged recovery-to-OFF transition immediately retries the
still-open activity's ordinary admission.

## Hardware gate

v0.0.140 is a pre-hardware candidate. It must not replace the stable baseline
until the exact-head automated review is clean and the full matrix in
`NATIVE_READER_V2_REVIEW_GATES.md` passes on the Nomad.

The paired v0.4.22 plugin never renames, deletes, truncates, resizes, or
recreates an initialized authority journal. It publishes PENDING, COMMITTED,
RECOVERY, and OFF records into alternating fixed slots and requires an exact
Document-process acknowledgement of the current record before completing a
state transition. Legacy `.snspread` files are preserved as migration evidence;
a valid v3 record is the only authority that supersedes them.

Normal admission rejects the complete journal if either nonzero slot is torn or
malformed. Explicit annotation restore has one narrower recovery operation: once
DocumentActivity is proven stopped and the recovery snapshot is revalidated, it
may repair exactly one valid-slot/one-malformed-slot journal by overwriting only
the malformed slot with a higher-generation RECOVERY record on the same inode.
The valid older slot supplies only monotonic generation evidence and is never
used to authorize reader behavior. Every other malformed shape remains
non-repairable and preserves the fail-closed fence.
