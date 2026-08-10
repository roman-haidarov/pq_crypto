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

The test surface also includes libFuzzer targets for PKCS#8 DER/PEM decoding
and pq_crypto-local container decoding, built with AddressSanitizer and
UndefinedBehaviorSanitizer. A representative clang-17 run executed
approximately 253 million inputs across these targets and produced no crash
artifacts. This improves malformed-input parser coverage but is not a proof of
memory safety and is not a substitute for a security audit.

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

## Key import validation (0.6.7+)

ML-KEM public/secret keys and ML-DSA secret keys are structure-checked when
the corresponding Ruby key objects are constructed:

| Object | Check | Source |
| --- | --- | --- |
| `KEM::PublicKey` | FIPS 203 §7.2 modulus check | `check_pk` |
| `KEM::SecretKey` | FIPS 203 §7.3 `H(pk)` check | `check_sk` |
| `Signature::SecretKey` | norms / `t0` / `tr` consistency | `pk_from_sk` |
| `Signature::PublicKey` | length only | — |
| X-Wing public key | ML-KEM-768 half only | `check_pk` |
| X-Wing secret key | none (32-byte seed) | — |

These are **import diagnostics**. Encapsulation, decapsulation, signing, and
verification still apply their own backend checks. A true `#valid?` result
does not prove full cryptographic integrity of every field (for example an
ML-KEM secret key with a corrupted IND-CPA `dk` but intact `H(pk)` still
passes §7.3).

The checks run on import. Keys produced by this process's own key generation
are valid by construction and are not re-checked, because the ML-DSA check
re-derives the public key and would roughly double the cost of every keypair.

The ML-DSA check (`pk_from_sk`) is documented upstream as leaking whether the
secret key is valid, through both its return value and its timing.

`require_encrypted:` applies only to the PKCS#8 branch. `PQCrypto::Key.from_der`
and `.from_pem` also accept SPKI public keys, and for those inputs the flag has
no effect and is silently ignored.

Public-key internal buffers are frozen after construction. Secret-key buffers
remain mutable so `#wipe!` can zero them.

### `require_encrypted:`

`require_encrypted: true` on PKCS#8 loaders rejects plaintext PrivateKeyInfo
and requires EncryptedPrivateKeyInfo (classified from DER, not PEM labels).
It does **not**:

- apply to `from_bytes` / `pqc_container_*` loaders
- enforce passphrase quality or PBKDF iteration count
- default on (default remains `false`)

The flag must be a boolean; non-boolean values raise `ArgumentError`.

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
