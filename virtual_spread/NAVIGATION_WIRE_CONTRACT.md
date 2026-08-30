# Virtual Spread navigation authority v1

Status: proposed schema-v4 extension; schema v3 remains frozen and unchanged.

The generator uses manifest schema
`techrebbe.supernote.virtual-spread/v4` and generator format
`techrebbe.supernote.virtual-spread-generator/v2` when it preserves a document
outline or when the adjacent-page link policy is explicitly supplied as either
enabled or disabled. Documents with no outline and an omitted policy retain the
byte-compatible schema-v3/generator-v1 identity. Thus an explicit
`--no-remove-adjacent-page-links` is authenticated and distinguishable from a
legacy invocation that predates the policy.

## Canonical authority

The PDF tail and sidecar carry the same lowercase SHA-256 over ASCII records:

```text
techrebbe.supernote.virtual-spread-navigation/v1
config|<filter:0|1>|<removed-count>|<retained-count>
outline|<index>|<parent-or->|<open>|<bold>|<italic>|<r-bits>|<g-bits>|<b-bits>|<title-utf8-sha256>|<destination-or->
```

Indices and counts are zero-based/nonnegative decimal integers within Java
`int`. Floating values are finite IEEE-754 binary64 encoded as exactly 16
lowercase hexadecimal digits; signed zero is retained. Colors contain exactly
three values in `[0,1]`. Titles are strict well-formed UTF-8 and are represented
by their SHA-256. Records are pre-order, and a parent must precede its child.

An actionable destination appends:

```text
sourcePageIndex|virtualPageIndex|side|targetView|mode|operandCount|operands...
```

`side` is `left` or `right`. `targetView` is `fit-source-page`. The stored
transformed mode is `/FitR` with four finite operands. No inverse transform is
serialized.

The navigation digest, mapping digest, filter setting, schema, and generator
version feed the version-2 canonical view identity. Consequently bookmark or
filter changes create a different deterministic cache basename.

Schema-v4 native-viewport delivery is also representation-versioned. The
companion publishes and serves it only through provider protocol v2, which
binds manifest schema, generator version, and this navigation digest in
addition to every frozen v1 request field. Provider v1 remains schema-v3-only;
older InkBridge consumers therefore fail closed rather than exporting schema-v4
ink under schema-v3 assumptions. See
`../virtual-spread-module/NATIVE_VIEWPORT_V2.md`.

PDF tail order is source, layout, links, mapping, view, navigation, then
`startxref`. The runtime rejects a displaced, uppercase, missing, duplicated,
or inconsistent navigation marker and strictly re-canonicalizes the sidecar.

## Outline preservation

The generator preserves outline title, hierarchy, order, open/closed state,
bold, italic, color, and supported internal destination semantics. Structural
items without destinations remain structural. Direct and named destinations
use the same strict resolver as link annotations.

Source `/Fit` becomes an authenticated `/FitR` landing rectangle plus
`targetView=fit-source-page`; the companion restores native Fit-page behavior
and the intended left/right half. Supernote's outline UI exposes only page-level
loading, so source `/XYZ`, explicit `/FitR`, and other viewport-bearing outline
destinations fail explicitly rather than being degraded. Unsupported actions,
destination modes, coordinates, hierarchy links, or ambiguous companion
matches fail closed before publication rather than silently losing or degrading
a bookmark. In particular, duplicate outline entries with the same title and
virtual page but different target halves are rejected because Supernote's
outline callback does not expose a stable identity that distinguishes them.

Named destinations referenced by a preserved outline or link are resolved
strictly before composition and the resulting navigation remains functional.
Standalone named destinations are not yet representable in the authenticated
navigation contract and therefore fail explicitly before publication rather
than silently disappearing from the derived PDF.
Documents containing both a legacy catalog `/Dests` dictionary and a
`/Names/Dests` name tree also fail closed: their independent namespaces must
not be partially enumerated or silently merged.

## Optional adjacent-page link removal

`--remove-adjacent-page-links` is opt-in. The generator resolves and validates
link semantics against original zero-based source pages before composition and
removes only:

- direct or named internal destinations whose target differs by exactly `-1`
  or `+1`; and
- exact `/Named /PrevPage` or `/Named /NextPage` actions when that neighboring
  source page exists.

Same-page links, links two or more pages away, absolute URI links, and every
outline entry remain. Unresolved boundary actions and unsupported action types
still fail closed. This option also removes a genuine adjacent-page reference,
not just navigation buttons, and it does not remove arrows or buttons drawn in
the underlying page content. Removed links are absent from the derived PDF,
manifest link list, and link authority. Removed/retained counts and the filter
state are authenticated by the navigation digest.

Forced replacement requires the policy to be restated explicitly as either
`--remove-adjacent-page-links` or `--no-remove-adjacent-page-links`; omission
cannot silently change a previously published representation.
