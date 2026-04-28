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

The post-quantum primitives are backed by vendored `PQClean` sources and called
through PQClean's public `crypto_kem_*` and `crypto_sign_*` entrypoints. The gem
does not reimplement ML-KEM, ML-DSA, SHAKE, or Keccak.

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

This opt-in exists because PQClean exposes no public ML-DSA
`crypto_sign_keypair_derand` entrypoint. The implementation therefore reuses the
same thread-local seed-replay `randombytes()` path introduced for KAT tests to
expand the RFC 9881 seed into an expanded private key. The replay buffer is
thread-local, cleared immediately after expansion, and remains inactive for all
normal production randomness paths.

For `both` encodings, the decoder expands the seed and rejects the key if the
expandedKey half does not match the seed-derived key.

## Deterministic test hooks

`PQCrypto::Testing` deterministic helpers drive the stock PQClean entrypoints
against caller-supplied seeds. For ML-DSA, which has no derand API upstream, the
gem installs a thread-local seed-replay buffer inside its `randombytes()`
implementation; outside of a test call the same `randombytes()` entry delegates
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
- Base64 encode/decode for PEM via OpenSSL BIOs

OpenSSL 3.5+ is additionally used in interop tests when ML-KEM / ML-DSA EVP
support is available.

## Threading

Concurrent read-only operations on primitive key objects are supported.
Mutating operations such as `wipe!` must not race with other uses of the same
object.
