# Security notes

## Scope of the public API

`pq_crypto` exposes a primitive-first public surface:

- `PQCrypto::KEM` — ML-KEM-512, ML-KEM-768, ML-KEM-1024
- `PQCrypto::Signature` — ML-DSA-44, ML-DSA-65, ML-DSA-87
- `PQCrypto::HybridKEM` — ML-KEM-768 + X25519 via the X-Wing combiner
- `PQCrypto.secure_wipe`
- `PQCrypto.ct_equals`

The gem does not publish protocol/session helpers as part of the supported
public API.

## Audit status

This project has not been audited. Treat it as experimental software.

The test surface includes deterministic regression tests, NIST ACVP KAT test
infrastructure, and OpenSSL 3.5+ interoperability tests for standard SPKI /
PKCS#8 encodings where the linked OpenSSL exposes the corresponding ML-KEM /
ML-DSA EVP support. These tests improve compatibility coverage but are not a
substitute for a security audit.

## Algorithm notes

### ML-KEM / ML-DSA

As of `0.5.0`, the post-quantum primitives are backed by vendored PQ Code
Package `mlkem-native` and `mldsa-native` sources. PQClean is not built and
there is intentionally no PQClean fallback.

The gem calls the native package entrypoints for ML-KEM key generation,
encapsulation, decapsulation, ML-DSA key generation, signing, verification, and
test-only deterministic hooks. It does not reimplement ML-KEM, ML-DSA, SHAKE,
or Keccak.

### HybridKEM

`PQCrypto::HybridKEM` implements the X-Wing construction from
`draft-connolly-cfrg-xwing-kem-10`.

The X-Wing secret decapsulation key is a 32-byte seed. It is expanded with
SHAKE256 into the ML-KEM-768 and X25519 private material used internally for
decapsulation. The public key and ciphertext are the fixed-length
concatenations specified by the draft.

```text
ss = SHA3-256( ss_M || ss_X || ct_X || pk_X || XWingLabel )
```

where `XWingLabel = "\.//^\"`.

External interoperability should be verified against the reference
implementation before relying on it.

## Serialization formats

### pq_crypto-local `pqc_container_*`

`pqc_container_*` DER/PEM wrappers are pq_crypto-specific containers. They are:

- not ASN.1
- not SPKI
- not PKCS#8
- not advertised as interoperable with OpenSSL, Go, Java, or PKI tooling

This format is frozen for backward compatibility and remains limited to the
original three algorithms:

- `:ml_kem_768`
- `:ml_dsa_65`
- `:ml_kem_768_x25519_xwing`

### Standard SPKI / PKCS#8

ML-KEM and ML-DSA use standard SPKI public-key and PKCS#8 private-key encodings
for the NIST parameter sets. AlgorithmIdentifier parameters are absent, not
encoded as `NULL`.

| Algorithm | Standard OID | Reference |
| --- | --- | --- |
| ML-KEM-512 | `2.16.840.1.101.3.4.4.1` | RFC 9935 |
| ML-KEM-768 | `2.16.840.1.101.3.4.4.2` | RFC 9935 |
| ML-KEM-1024 | `2.16.840.1.101.3.4.4.3` | RFC 9935 |
| ML-DSA-44 | `2.16.840.1.101.3.4.3.17` | RFC 9881 |
| ML-DSA-65 | `2.16.840.1.101.3.4.3.18` | RFC 9881 |
| ML-DSA-87 | `2.16.840.1.101.3.4.3.19` | RFC 9881 |

`PQCrypto::KEM.details` / `PQCrypto::Signature.details` keep `:oid` as the
legacy `pqc_container_*` OID for backward compatibility. Use
`PQCrypto::AlgorithmRegistry.standard_oid` for the standard OID.

## ML-DSA seed-format imports

ML-DSA seed and both-form PKCS#8 imports are disabled by default. To import
these encodings, callers must explicitly set:

```ruby
PQCrypto::PKCS8.allow_ml_dsa_seed_format = true
```

This opt-in remains explicit because seed and both-form imports are more
sensitive than expanded-key imports: the decoder expands the seed into an
expanded private key and, for `both` encodings, rejects the key if the
expandedKey half does not match the seed-derived key.

The expansion path uses the vendored `mldsa-native` deterministic keypair
entrypoints rather than a `randombytes()` seed-replay fallback.

## Deterministic test hooks

`PQCrypto::Testing` deterministic helpers drive the vendored PQ Code Package
native deterministic entrypoints against caller-supplied seeds. ML-DSA
deterministic signing passes the FIPS 204 pure-mode domain-separation prefix
into `mldsa-native` `signature_internal`; for an empty context this prefix is
`00 00`.

Outside of test-only deterministic calls, production randomness delegates
directly to OpenSSL `RAND_bytes`.

## Memory wiping

`PQCrypto.secure_wipe` clears mutable Ruby strings in place. Ruby key objects
take a copy of the bytes passed into their constructor and expose `#wipe!` to
zero only that internal copy. Ruby garbage collection and prior derived copies
may still leave sensitive material elsewhere in process memory.

Secret key objects redact `inspect` output and intentionally do not expose a
public `fingerprint` method. This avoids accidental logging of raw secret bytes
or stable secret-derived identifiers.

## OpenSSL baseline

`pq_crypto` requires OpenSSL 3.0 or later.

OpenSSL is used for:

- X25519 key generation and key agreement
- SHA3-256 for the X-Wing combiner
- RAND_bytes as the production entropy source for `randombytes()`
- CRYPTO_memcmp for constant-time comparison
- Base64 encode/decode for PEM

OpenSSL 3.5+ is additionally used in interop tests when ML-KEM / ML-DSA EVP
support is available.

## Threading

Concurrent read-only operations on primitive key objects are supported.
Mutating operations such as `wipe!` must not race with other uses of the same
object.
