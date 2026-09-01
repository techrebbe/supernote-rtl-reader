# Native Reader v2 migration

## Shadow phase

The first adapter phase is deliberately non-authoritative. After the existing
probe has completed a landscape composition, it publishes the same native
document, component, page-pair, and geometry evidence into a v2
`SpreadSession`. The v2 model then validates:

- zero-based RTL/cover pairing;
- exact document and activity generations;
- full-page source-to-screen affines for both physical slots;
- exact native writer component identity and page agreement; and
- physical page-hit agreement with the established reader.

Any disagreement retires the shadow session and emits
`v2_shadow_rejected`. It does not change a bitmap, route input, call a native
setter, save a page, or enable the writer.

This temporary phase is permitted to observe the legacy implementation because
it has no behavioral authority. It must be deleted when the v2 adapter begins
controlling a document; production may never run both authorities.

## Cutover rule

Behavioral cutover is all-or-nothing for one exact document/activity
generation. The v2 adapter may claim control only after shadow evidence has
passed for portrait, both landscape rotations, both active sides, cover parity,
odd final pages, mixed page sizes, and every writer component identity.

Once claimed, all legacy composition, page activation, gesture routing,
annotation overlay, and mutation-admission paths are bypassed for that
generation. If v2 loses authority it disables its complete feature and returns
to an ordinary native-reader recreation; it may not fall through into a
partially active legacy spread.
