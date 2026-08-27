# Page-143 Virtual Spread fixture v1

This directory is the normative byte-level handoff from RTL Reader v0.0.25 to InkBridge. `page-143-source-v1.pdf` contains three physical pages; zero-based source page index 2 is the synthetic page-143 stand-in.

The generated PDF and schema-v3 sidecar are tracked under short artifact names so a default Windows Git checkout remains portable. Their bytes are unchanged from the production pair; the descriptor and sidecar retain the exact authenticated cache basename that must be materialized for cache activation. `page-143-artifacts-v1.json` records stable hashes, mapping/view identities, the page-143 forward mapping, derived inverse round trips, verifier rules, and the hardware-proven cache assumptions. `page-143-pdf-tail-authorities-v1.txt` is the exact generated PDF tail beginning with the five authenticated authority markers immediately before `startxref`.

Contract and synthetic-golden text hashes use UTF-8 bytes with CRLF and CR normalized to LF and no other normalization. Only the forward source-to-spread transform is authoritative. InkBridge must derive and validate the inverse. The sidecar's diagnostic `path` fields are normalized to filenames so the fixture carries no host path; they are not mapping, view, cache, or activation authority.
