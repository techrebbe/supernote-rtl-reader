# Native-page visual artifact authority: production review record

Status: the immutable large-artifact authority exists as an isolated production
component. It is not wired into a hardware command or used to clear the visual
session harness admission blocker. That integration still requires a separate
review of the exact store locations and target filesystem.

## Reviewed harness contract

`WindowsVisualArtifactAuthority` directly implements the existing retained
`ArtifactAuthority` shape:

```text
verify() -> None
canonical_bytes() -> bytes
retain(logical_name, raw, media_type, producer_authority_sha256, captured_ns)
    -> native_page_visual_session_harness.ArtifactRef
verify_ref(reference) -> None
assert_quiescent() -> None
```

No harness validator, protocol, artifact bound, or `ArtifactRef` definition was
changed. The adapter returns the exact harness dataclass. Its 64 MiB limit is
checked against the harness constant at construction, so the implementation
fails closed if the two contracts diverge.

## Authority and identity model

One adapter instance owns exactly one dedicated private Windows directory. The
caller retains an immutable `ArtifactStoreAuthority` containing:

- the canonical short local DOS path;
- the directory's native volume/file identity;
- a fresh 128-bit store nonce;
- the SHA-256 of the exact retained adapter source bytes.

The canonical SHA-256 of that record is the sole
`storeIdentitySha256` placed in every returned reference and every stored object.
Reopen requires the external record, the same directory identity, an exact
private DACL, and matching `authority.json`. Two directories cannot be presented
as one store, and a reference from a second store is rejected before readback.

The adapter source is opened without write or delete sharing and retained for the
life of the adapter. `verify()` and `canonical_bytes()` re-read that handle and
compare both its exact bytes and digest. The canonical adapter pin is independent
of a particular evidence directory but binds the full source image and the exact
capability/bounds record.

For the reviewed source image in this change:

```text
source SHA-256: f3c2d51880ddc24ff1f058180088e3182683504b8ee69bd8926440096336f5d4
canonical pin SHA-256: 2129b49ca6e4c13141600b63d58e1d67378c0954e2fb9a77d647b34b5d82cc91
```

The exact canonical pin bytes, including the terminating LF, are:

```json
{"artifactRefAuthority":"rtl-reader-native-page-visual-artifact-ref-v1","authority":"rtl-reader-native-page-visual-artifact-authority-v1","capabilities":["private-single-store-identity","retained-source-and-object-handles","create-new-and-native-no-replace","file-readback-and-directory-flush","fail-closed-additive-recovery","two-pass-quiescence"],"maxArtifactBytes":67108864,"maxArtifacts":1024,"schemaVersion":1,"sourceSha256":"f3c2d51880ddc24ff1f058180088e3182683504b8ee69bd8926440096336f5d4","supportedMediaTypes":["application/json","application/octet-stream","image/png","text/plain"],"windowsNativeOnly":true}
```

## Stored-object binding

Physical object names are a contiguous sequence
`00000000000000000000.artifact`, not user-controlled paths. Each object is an
exact binary envelope consisting of a versioned magic value, a bounded canonical
JSON header length, the canonical header, and the raw bytes. The header binds:

- physical sequence and store identity;
- exact case-sensitive logical name;
- exact admitted media type;
- byte count and raw SHA-256;
- producer authority SHA-256;
- trusted capture timestamp supplied by the harness.

Logical names are bounded ASCII path-like labels only. Empty components,
backslashes, traversal components, alternate streams, DOS device names, trailing
dots/spaces, and components over 96 characters are rejected. A case-folded name
may occur only once for the life of a store, so exact replay and Windows case
ambiguity are both denied.

The admitted media types are exactly `application/json`,
`application/octet-stream`, `image/png`, and `text/plain`, matching current
harness calls. Raw objects must contain 1 through 67,108,864 bytes; the store is
bounded to 1,024 objects. This admits raw AM/WM/provider wires and worst-case
1404x1872 four-channel screenshot payloads with substantial framing headroom.
PNG structure and decoded geometry remain the harness's responsibility before
retention.

## Publication linearization

The only successful `retain` path is:

1. Revalidate every retained directory/source/control handle, private DACL,
   authority record, writer lock, and exact namespace.
2. Reject logical-name reuse and validate all caller bindings before mutation.
3. Create a random pending path with native `CREATE_NEW` and exclusive sharing.
4. Write the complete envelope with checked forward progress.
5. Flush the file and re-read the complete envelope through the same retained
   handle; validate canonical metadata, length, and SHA-256.
6. Rename relative to the retained directory handle with the native no-replace
   information class.
7. Revalidate native identity, single-link/non-reparse state, final path, and the
   complete envelope through the still-retained handle.
8. Flush the retained writable directory handle.
9. Re-read and re-hash the complete final object, re-compare every caller
   binding (including capture time), and re-enumerate the exact namespace.
10. Add the reference to the in-memory index and return it.

The native file handle is deliberately not closed at a logical publication
boundary. It stays open without delete sharing until authority disposal, denying
path swap, link, overwrite, rename, and deletion through ordinary Windows sharing
semantics. Any exception after mutation poisons the instance; only close and a
fresh externally authorized reopen remain possible.

Store creation uses the same file-flush, retained-handle readback, no-replace
rename, and directory-flush sequence for `authority.json`, then flushes the
parent directory before returning the new store authority. If Windows or the
target filesystem refuses directory `FlushFileBuffers`, there is no fallback and
no successful return.

## Crash and partial-publication recovery

Recovery first opens the exclusive writer and retains every admitted entry. It
rejects an unknown name, case-ambiguous inventory, missing control object,
noncontiguous published sequence, bad private DACL, reparse point, hardlink,
identity/path drift, malformed envelope, reused logical name, or multiple pending
objects.

There is only one recovery mutation: a single complete canonical pending object
whose sequence is exactly next and whose logical name is new may be renamed to
its exact unoccupied sequence destination using the native no-replace operation.
Recovery first freezes the pending object's complete reference and capture-time
binding, then re-flushes and re-reads the complete pending file; it does not
infer that surviving bytes prove the pre-crash file flush completed. That exact
frozen binding is checked again after the file flush, after the no-replace
rename, and after the directory flush. Every recovered object is then read and
hashed again before the adapter is exposed. A crash after the original rename
is handled by validating the surviving published object and flushing its
namespace before exposure.

Torn, conflicting, duplicate, foreign, or otherwise uncertain paths are left in
place. The production boundary has no delete operation. It never overwrites,
replaces, truncates, quarantines, or guesses ownership of such a path.

## Quiescence proof

`assert_quiescent()` performs two full retained-handle verification passes around
a successful directory flush. Each pass validates the source and canonical pin,
directory/control identities, exact inventory, every immutable object envelope,
all content lengths/digests, and the sequence/reference index. The pre/post
inventories and reference tuples must be identical. Any mutation at or after the
flush is therefore detected and poisons the live authority.

## Windows boundary and threat scope

The production API binds `CreateFileW`, `ReadFile`, `WriteFile`,
`FlushFileBuffers`, `GetFileInformationByHandle`,
`GetFinalPathNameByHandleW`, security descriptor APIs, and the native
handle-relative no-replace rename information class. It accepts fixed local
drives only and rejects reparses on every retained traversal component. There is
no POSIX implementation, `os.replace` fallback, device access, network access,
subprocess, shell, Git, or ambient path lookup.

The optional API/source seam exists for deterministic FakeWin32 review only.
When the native boundary is selected, the authority refuses any source path
other than this module's own resolved image.

The guarantees are fail-closed application/OS/filesystem acknowledgements. They
do not claim resistance to a privileged kernel, compromised storage firmware,
lying hardware, direct mutation of Python object internals, or power loss beyond
the filesystem's acknowledged contract.

## Deterministic review evidence

`test_native_page_visual_artifact_authority.py` uses a stateful FakeWin32 that
separates visible bytes, file-flushed bytes, durable directory namespaces,
sharing, retained handles, and native identities. The review suite currently has
29 tests and includes:

- a golden harness-compatible retain, verify, quiescence, close, and reopen;
- exact canonical source/pin-byte comparison;
- a 1404x1872 four-channel-sized object plus raw manager wires;
- strict path, logical-name, media, producer, time, size, and replay rejection;
- before/after faults at all 36 store-initialization edges;
- control-object mutation after all 11 writer/authority publication edges;
- before/after faults at all 26 immutable-object publication edges;
- content mutation after all 11 immutable-object publication edges;
- additive recovery of one verified pending object;
- before/after faults and post-operation mutation at every additive recovery
  file-flush, no-replace rename, and directory-flush boundary;
- well-formed caller-binding substitution after the final publication flush and
  after every recovery durability/namespace boundary, all rejected before
  exposure;
- unchanged torn, duplicate, conflicting, case-ambiguous, and foreign paths;
- store/source/directory/file replacement, ACL, reparse, hardlink, and identity
  drift;
- split-store and cross-store reference rejection;
- media, producer, size, digest, store, and timestamp envelope mutation;
- two-pass quiescence mutation, writer exclusion, reentrancy, concurrency,
  invalid write progress, unsupported directory flush, native symbol binding,
  explicit non-Windows failure, and rejection of a non-module source path on the
  non-injected production boundary.

Self-review found one important exposure edge: an initial recovery draft parsed
objects before its recovery directory flush but did not re-read every object
after that flush. The production path now performs that second retained-handle
read/hash before `open_existing` returns, and `retained_refs()` also verifies all
object bytes before exposing the recovered index.

No hardware CLI or session-harness construction path was changed by this work.
