# Native viewport provider v2

Provider v2 extends the frozen native viewport v1 handshake for authenticated
schema-v4 Virtual Spread representations. The descriptor itself remains
`rtl-reader-native-viewport-v1`: its seven fields, affine convention, numeric
rules, process-lifetime ownership, package/signer checks, and page-load
generation fence are unchanged. Only the representation evidence exchanged
with the provider is versioned.

Schema-v3/generator-v1 documents continue to use `get_v1`. A v1 read can never
return a v2 record, and a v2 read can never return a v1 record.

## Provider API

Provider URI:

```text
content://com.techrebbe.supernote.virtualspread.viewport/v2/current
```

Read method:

```text
get_v2
```

The caller restrictions and release-signer requirement are identical to v1.
The request contains every v1 field plus these exact schema-v4 fields:

```text
manifestSchema            String = techrebbe.supernote.virtual-spread/v4
generatorVersion          String = techrebbe.supernote.virtual-spread-generator/v2
navigationAuthoritySha256 String (64 lowercase hex)
```

The provider record was published from the same already-verified manifest. It
requires exact equality for all v1 and v2 evidence, including navigation
authority, or returns:

```text
protocolVersion = 2
status = unavailable
```

An accepted response has `protocolVersion = 2`, `status = ok`, all v1 response
fields, and the same three representation fields. Consumers must independently
verify the schema-v4 sidecar, PDF-tail navigation marker, mapping authority,
view identity, file hashes, and current native canvas before making the call.
Unknown/missing fields and any schema/generator/authority disagreement fail
closed. Provider v2 does not serialize an inverse transform.

InkBridge releases that only understand schema v3 must continue to reject
schema-v4 documents. They must not fall back to `get_v1`; schema-v4 export/apply
becomes available only after InkBridge implements this exact v2 handshake.
