# pq_crypto

`pq_crypto` is a primitive-first Ruby gem for post-quantum cryptography.
It wraps vendored `PQClean` implementations and OpenSSL-backed conventional
primitives behind small Ruby APIs.

## Status

- primitive-first API only; no protocol/session helpers
- supports ML-KEM, ML-DSA, and one hybrid X-Wing KEM
- supports pq_crypto-local containers plus standard SPKI / PKCS#8 for the
  NIST parameter sets
- not audited
- experimental; not yet positioned as production-ready

## Supported parameter sets

| Family | Parameter sets | Serialization support |
| --- | --- | --- |
| KEM | ML-KEM-512, ML-KEM-768, ML-KEM-1024 | SPKI public keys and PKCS#8 private keys for all three; `pqc_container_*` only for the original ML-KEM-768 algorithm. |
| Signature | ML-DSA-44, ML-DSA-65, ML-DSA-87 | SPKI public keys and PKCS#8 private keys for all three; ML-DSA seed/both PKCS#8 import is opt-in; `pqc_container_*` only for the original ML-DSA-65 algorithm. |
| Hybrid | ML-KEM-768 + X25519 (X-Wing) | pq_crypto-local `pqc_container_*` only. |

Standard SPKI / PKCS#8 encodings use the RFC 9935 OIDs for ML-KEM and the
RFC 9881 OIDs for ML-DSA. `AlgorithmIdentifier.parameters` are omitted, not
encoded as `NULL`.

The older `pqc_container_*` format is project-local and frozen for backward
compatibility. It is not ASN.1, SPKI, or PKCS#8.

## Installation

Add the gem to your project and compile the extension:

```ruby
gem "pq_crypto"
```

```bash
bundle install
bundle exec rake compile
```

### Native dependencies

- Ruby 3.4 or later
- a C toolchain with C11 support
- OpenSSL 3.0 or later with SHA3-256 and SHAKE256 available

### Build-time Keccak backend

The default build uses PQClean's scalar `common/fips202.c` backend:

```bash
PQCRYPTO_KECCAK_BACKEND=clean bundle exec rake compile
```

`PQCRYPTO_KECCAK_BACKEND=xkcp` is reserved for a separately vendored,
reviewed, `fips202.h`-compatible XKCP adapter. If requested without that
adapter, the build aborts instead of silently falling back to `clean`.

## Primitive API

### ML-KEM

```ruby
keypair = PQCrypto::KEM.generate(:ml_kem_768)
result = keypair.public_key.encapsulate
shared_secret = keypair.secret_key.decapsulate(result.ciphertext)
```

Supported algorithms:

```ruby
PQCrypto.supported_kems
# => [:ml_kem_512, :ml_kem_768, :ml_kem_1024]
```

### ML-DSA

```ruby
keypair = PQCrypto::Signature.generate(:ml_dsa_65)
signature = keypair.secret_key.sign("hello")

keypair.public_key.verify("hello", signature)    # => true / false
keypair.public_key.verify!("hello", signature)   # raises on mismatch
```

Supported algorithms:

```ruby
PQCrypto.supported_signatures
# => [:ml_dsa_44, :ml_dsa_65, :ml_dsa_87]
```

For large inputs, use streaming IO so the message does not need to be
materialized as one Ruby string:

```ruby
signature = File.open("document.bin", "rb") do |io|
  keypair.secret_key.sign_io(io, chunk_size: 1 << 20)
end

ok = File.open("document.bin", "rb") do |io|
  keypair.public_key.verify_io(io, signature, chunk_size: 1 << 20)
end
```

`sign_io` / `verify_io` use pure ML-DSA with an internal FIPS 204 ExternalMu
flow. They are not HashML-DSA/prehash shortcuts and do not expose public
`sign_mu` / `verify_mu` APIs. Optional context is supported and must match on
verify:

```ruby
ctx = "invoice-v1".b
signature = File.open("document.bin", "rb") { |io| keypair.secret_key.sign_io(io, context: ctx) }
ok = File.open("document.bin", "rb") { |io| keypair.public_key.verify_io(io, signature, context: ctx) }
```

`chunk_size` must be positive. `context` is limited to 255 bytes by FIPS 204.

### Hybrid ML-KEM-768 + X25519 (X-Wing)

```ruby
keypair = PQCrypto::HybridKEM.generate(:ml_kem_768_x25519_xwing)
result = keypair.public_key.encapsulate
shared_secret = keypair.secret_key.decapsulate(result.ciphertext)
```

The implementation follows draft-10 key expansion: the X-Wing secret
decapsulation key is a 32-byte seed expanded with SHAKE256 into ML-KEM and
X25519 private material. The combiner is exactly:

```text
ss = SHA3-256( ss_M || ss_X || ct_X || pk_X || "\.//^\" )
```

as specified by `draft-connolly-cfrg-xwing-kem-10`. See `SECURITY.md` for
audit status and interoperability caveats.

## Serialization

### pq_crypto-local containers

The project-local container APIs are retained for backward compatibility:

- `to_pqc_container_der`
- `to_pqc_container_pem`
- `*_from_pqc_container_der`
- `*_from_pqc_container_pem`

Example:

```ruby
keypair = PQCrypto::KEM.generate(:ml_kem_768)
der = keypair.public_key.to_pqc_container_der
imported = PQCrypto::KEM.public_key_from_pqc_container_der(der)
```

`pqc_container_*` is supported only for the original three algorithms:

- `:ml_kem_768`
- `:ml_dsa_65`
- `:ml_kem_768_x25519_xwing`

These containers are not real ASN.1 SPKI or PKCS#8 and are not advertised as
interoperable with external PKI tooling.

### SPKI public keys

ML-KEM and ML-DSA public keys can be encoded as standard SubjectPublicKeyInfo:

```ruby
keypair = PQCrypto::KEM.generate(:ml_kem_512)
pem = keypair.public_key.to_spki_pem
imported = PQCrypto::KEM.public_key_from_spki_pem(pem)
```

For signatures:

```ruby
keypair = PQCrypto::Signature.generate(:ml_dsa_87)
der = keypair.public_key.to_spki_der
imported = PQCrypto::Signature.public_key_from_spki_der(der)
```

### PKCS#8 private keys

ML-KEM private keys support `:seed`, `:expanded`, and `:both` PKCS#8 formats.
`SecretKey#to_pkcs8_der` / `#to_pkcs8_pem` export the expanded key by default.

```ruby
keypair = PQCrypto::KEM.generate(:ml_kem_768)
pem = keypair.secret_key.to_pkcs8_pem
imported = PQCrypto::KEM.secret_key_from_pkcs8_pem(pem)
```

ML-DSA private keys support expanded-key PKCS#8 by default. Seed and both-form
ML-DSA PKCS#8 imports are opt-in:

```ruby
PQCrypto::PKCS8.allow_ml_dsa_seed_format = true
imported = PQCrypto::Signature.secret_key_from_pkcs8_pem(pem)
```

ML-DSA seed/both export from an existing `SecretKey` is intentionally not
available because the key object does not retain the original seed material.
Call `PQCrypto::PKCS8.encode_der` / `encode_pem` directly when you explicitly
have the seed.

## Secure wiping

`PQCrypto.secure_wipe(str)` zeros the bytes of a mutable Ruby string in place.
Key objects hold a private copy of their bytes, so `wipe!` on a `SecretKey`
zeroes only that internal copy; any prior Ruby string the caller holds is
untouched.

```ruby
raw = File.binread(path)
key = PQCrypto::KEM.secret_key_from_bytes(:ml_kem_768, raw)
PQCrypto.secure_wipe(raw)
key.wipe!
```

`wipe!` remains best-effort only: it clears the current Ruby string buffer
owned by the key object, not every possible copy made by Ruby, OpenSSL,
serialization, logging, or the garbage collector.

## Constant-time comparison

`==` on `PublicKey` / `SecretKey` instances uses OpenSSL `CRYPTO_memcmp`
through `PQCrypto.ct_equals` so comparisons do not leak prefix-match timing.
Secret key `inspect` output is intentionally redacted and secret key objects do
not expose a public `fingerprint` method.

## Introspection

```ruby
PQCrypto.version
PQCrypto.backend
PQCrypto.supported_kems
PQCrypto.supported_hybrid_kems
PQCrypto.supported_signatures
PQCrypto::KEM.details(:ml_kem_768)
PQCrypto::HybridKEM.details(:ml_kem_768_x25519_xwing)
PQCrypto::Signature.details(:ml_dsa_65)
PQCrypto::AlgorithmRegistry.standard_oid(:ml_kem_768)
```

`DETAILS[:oid]` remains the legacy `pqc_container_*` OID for backward
compatibility. Use `AlgorithmRegistry.standard_oid` for the RFC 9935 / RFC 9881
OID.

## Async / Fiber scheduler support

On Ruby 3.4, `sign` and `verify` use Ruby's scheduler-aware
`rb_nogvl(..., RB_NOGVL_OFFLOAD_SAFE)` path automatically. With a scheduler
that implements `blocking_operation_wait`, the blocking native work can be
moved off the event loop.

## Testing helpers

Deterministic test hooks are exposed under `PQCrypto::Testing` for regression
coverage:

- `ml_kem_keypair_from_seed` — requires a 64-byte `d||z` seed
- `ml_kem_encapsulate_from_seed` — requires a 32-byte seed
- `ml_dsa_keypair_from_seed` — requires a 32-byte seed
- `ml_dsa_sign_from_seed` — requires a 32-byte seed

These helpers are intended for tests only. They drive the stock PQClean
entrypoints and, for ML-DSA, use a thread-local seed-replay mode inside the
gem's `randombytes()` override for the duration of the call.

## Development

Run the test suite with:

```bash
bundle exec rake test
```

Refresh vendored PQClean sources manually only when you intentionally update
the vendor snapshot. The refresh script has a safe pinned default and records
the exact vendored snapshot in `ext/pqcrypto/vendor/.vendored`:

```bash
bundle exec ruby script/vendor_libs.rb
```

To intentionally change the upstream snapshot, override all four pinning inputs
together:

```bash
PQCLEAN_VERSION=<full-git-commit> \
PQCLEAN_URL=https://github.com/PQClean/PQClean/archive/<full-git-commit>.tar.gz \
PQCLEAN_SHA256=<archive-sha256> \
PQCLEAN_STRIP=PQClean-<full-git-commit> \
  bundle exec ruby script/vendor_libs.rb
```
