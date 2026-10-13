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

The materializer now derives one explicit override from that authenticated base:
`sn-plugin-lib` is pinned exactly to `0.1.65` with its published SHA-512 SRI
`sha512-jMQhpOHyzi3AxyxO7kc4OwXYQKgQ7tQXSFYH1l5W4po4w2GXEBfg2mrD8x0otv2jbwjYwvUZ+VZLe0RJZCQWyA==`.
Only the package/root dependency requirement and SDK version/resolved/integrity
record change; all other records, React19 and RN0.79.2 are unchanged. The base
lock/hash remains historical authority, not the installed SDK version. No npm
resolution or mutable range is used. `npm ci` checks tarball integrity; the normal
build executes the actual SDK init/reader/thumbnail validators with mocked native
endpoints and retains the effective package/lock/SDK metadata with its artifacts.
This SDK implements the real version report and remains in the vendor's legacy
EMR-coordinate band. No metadata spoof or frozen coordinate-contract migration.

No signing key or signing-key encoding belongs in this directory. Stable APK
signing material is supplied only as an environment-scoped GitHub Actions
secret. The protected release job has no repository checkout or repository
script execution, and a repository-wide copy of the secret is forbidden.
