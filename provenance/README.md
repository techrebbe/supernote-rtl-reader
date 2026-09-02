# Build provenance

The plugin bootstrap is intentionally fail-closed.

- `@supernote-plugin/sn-plugin-template` is fixed at version `1.0.12` and its
  downloaded tarball must match both the committed SHA-256 and npm SHA-512 SRI
  in `scripts/materialize_plugin_template.py` before any archive member is
  extracted.
- `plugin-template-package-lock.json.gz.b64` is the gzip/base64 form of the
  reviewed npm lockfile. Its decompressed SHA-256 is
  `33ea436d56b68d332949db0689f4b0c2bfd6f227e78e904b7706360ebc161022`.
  The materializer validates the digest and every registry record before
  `npm ci --ignore-scripts` consumes it.
- The encoded lock is committed instead of regenerated during CI. Updating the
  template or any dependency requires an explicit provenance update and review.

No signing key or signing-key encoding belongs in this directory. Stable APK
signing material is supplied only through the encrypted GitHub Actions secret.
