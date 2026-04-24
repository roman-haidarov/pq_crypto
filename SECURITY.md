# Security notes

## Scope of the public API

`pq_crypto` 0.3.0 exposes a primitive-first public surface:

- `PQCrypto::KEM` (`ML-KEM-768`)
- `PQCrypto::Signature` (`ML-DSA-65`)
- `PQCrypto::HybridKEM` (`ML-KEM-768 + X25519` via the X-Wing combiner)
- `PQCrypto.secure_wipe`
- `PQCrypto.ct_equals` (constant-time byte-string comparison)

The gem does **not** publish protocol/session helpers as part of the
supported public API.

## Audit status

This project has not been audited. Treat it as experimental software.

## Algorithm notes

### ML-KEM-768 / ML-DSA-65

The post-quantum primitives are backed by vendored `PQClean` sources
and called through PQClean's public `crypto_kem_*` and `crypto_sign_*`
entrypoints only. Internal PQClean symbols are not called from this
gem.

### HybridKEM

`PQCrypto::HybridKEM` implements the **X-Wing** construction from
[`draft-connolly-cfrg-xwing-kem`](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/):

    ss = SHA3-256( XWingLabel || ss_M || ss_X || ct_X || pk_X )

where `XWingLabel = "\.//^\"` (6 ASCII bytes). The hybrid public key,
secret key, and ciphertext are the byte concatenations of the ML-KEM
and X25519 halves exactly as specified by X-Wing.

X-Wing as specified has a proof of classical IND-CCA security under
the strong Diffie-Hellman assumption for X25519 (in the ROM), and
post-quantum IND-CCA security in the standard model assuming ML-KEM-768
is IND-CCA secure and SHA3-256 behaves as a PRF.

This gem is **not** yet part of a cross-language X-Wing interop test
suite; wire-format claims for this release are limited to "follows the
X-Wing draft as of version 10." External interoperability should be
verified against the reference implementation before relying on it.

### Deterministic test hooks

`PQCrypto::Testing` deterministic helpers drive the stock PQClean
`crypto_sign_keypair` / `crypto_sign_signature` (for ML-DSA) and
`crypto_kem_keypair_derand` / `crypto_kem_enc_derand` (for ML-KEM)
against a caller-supplied seed. For ML-DSA, which has no derand API
upstream, the gem installs a thread-local seed-replay buffer inside
its `randombytes()` implementation; outside of a test call the same
`randombytes()` entry delegates directly to OpenSSL `RAND_bytes`. No
internal PQClean algorithm logic is reimplemented in this gem.

## Serialization

`pqc_container_*` DER/PEM wrappers are pq_crypto-specific containers.

They are:

- not real SPKI
- not real PKCS#8
- not advertised as interoperable with OpenSSL, Go, Java, or PKI tooling

The OIDs embedded in these containers are project-local UUID-derived
OIDs under `2.25.*`. They are part of pq_crypto's own serialized
container schema, not external interoperability identifiers.

The hybrid OID used by 0.2.0
(`2.25.260242945110721168101139140490528778800`) is retired in 0.3.0
because the combiner semantics changed (0.2.0 used an ad-hoc
HKDF-SHA256 combiner; 0.3.0 uses X-Wing / SHA3-256). The new hybrid
OID is `2.25.318532651283923671095712569430174917109`. A 0.2.0 hybrid
container is rejected at decode time in 0.3.0.

## Memory wiping

`PQCrypto.secure_wipe` clears mutable Ruby strings in place. Ruby key
objects (`PublicKey`, `SecretKey`) take a copy of the bytes passed into
their constructor and expose `#wipe!` to zero only that internal copy
— any prior Ruby string the caller still holds is untouched. Ruby
garbage collection and prior derived copies may still leave sensitive
material elsewhere in process memory.

## OpenSSL baseline

`pq_crypto` requires OpenSSL **3.0 or later**.

OpenSSL is used for:

- `X25519` key generation and key agreement (`EVP_PKEY_*`)
- `SHA3-256` (X-Wing combiner, via `EVP_sha3_256`)
- `RAND_bytes` (production entropy source for `randombytes()`)
- `CRYPTO_memcmp` (constant-time comparison used by `PQCrypto.ct_equals`)
- Base64 encode/decode for PEM via the streaming `EVP_Encode*` /
  `EVP_Decode*` API, which rejects invalid base64 rather than treating
  it as zeros.

## Threading

Concurrent read-only operations on primitive key objects are supported.
Native calls copy Ruby string inputs before releasing the GVL, so
normal concurrent use does not rely on Ruby string storage remaining
pinned in place.

The deterministic test hooks use a thread-local seed-replay mode
around `randombytes()`, so a test running on one thread does not
affect production callers on other threads. The deterministic helpers
remain test-only utilities and should not be relied on as a general
multi-threading contract.
