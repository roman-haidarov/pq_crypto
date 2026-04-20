# Security notes

## Scope of the public API

`pq_crypto` 0.1.0 exposes a primitive-first public surface:

- `PQCrypto::KEM` (`ML-KEM-768`)
- `PQCrypto::Signature` (`ML-DSA-65`)
- `PQCrypto::HybridKEM` (custom `ML-KEM-768 + X25519 + HKDF-SHA256` combiner)
- `PQCrypto.secure_wipe`

The gem does **not** publish protocol/session helpers as part of the supported public API in this release.

## Audit status

This project has not been audited. Treat it as experimental software.

## Algorithm notes

### ML-KEM-768 / ML-DSA-65

The core post-quantum primitives are backed by vendored `PQClean` sources.

### HybridKEM

`PQCrypto::HybridKEM` is a pq_crypto-specific hybrid combiner. It is **not** claimed to be HPKE-, TLS-, or X-Wing-compatible.

Use it only if you explicitly want this project-local construction.

## Serialization

`pqc_container_*` DER/PEM wrappers are pq_crypto-specific containers.

They are:
- not real SPKI
- not real PKCS#8
- not advertised as interoperable with OpenSSL, Go, Java, or PKI tooling

The OIDs embedded in these containers are project-local UUID-derived OIDs under `2.25.*`. They are not registrations for interoperable standard key formats. Within the `pqc_container_*` format they are treated as part of pq_crypto's own serialized container schema, not as external interoperability identifiers.

Future releases may replace these project-local identifiers if pq_crypto adopts standardized external container formats. Persisted `pqc_container_*` blobs should therefore be treated as pq_crypto-local artifacts, not as a long-term interoperability format.

## Memory wiping

`PQCrypto.secure_wipe` clears mutable Ruby strings in place. Ruby copies, GC behavior, and prior derived copies may still leave sensitive material elsewhere in process memory.

## OpenSSL baseline

`pq_crypto` requires OpenSSL **3.0 or later**.

OpenSSL is used for conventional primitives and plumbing such as:
- `X25519`
- `HKDF-SHA256`

## Threading

Concurrent read-only operations on primitive key objects are supported. Native calls copy Ruby string inputs before releasing the GVL, so normal concurrent use does not rely on Ruby string storage remaining pinned in place. Deterministic testing helpers remain test-only utilities and should not be treated as a general multi-threading contract.
