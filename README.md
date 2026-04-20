# pq_crypto

`pq_crypto` is a primitive-first Ruby gem for post-quantum cryptography.

It currently exposes three public building blocks:

- `PQCrypto::KEM` — pure `ML-KEM-768`
- `PQCrypto::Signature` — `ML-DSA-65`
- `PQCrypto::HybridKEM` — an optional custom hybrid KEM that combines `ML-KEM-768` and `X25519` with transcript-bound `HKDF-SHA256`

The gem is backed by vendored `PQClean` sources for `ML-KEM-768` / `ML-DSA-65` and OpenSSL for conventional primitives such as `X25519` and `HKDF-SHA256`.

## Status

- first public release
- primitive-first API only
- no protocol/session helpers in the public surface
- serialization uses pq_crypto-specific `pqc_container_*` wrappers
- not audited
- not yet positioned as production-ready

## Installation

Add the gem to your project and compile the extension:

```ruby
# Gemfile
gem "pq_crypto"
```

```bash
bundle install
bundle exec rake compile
```

### Native dependencies

- Ruby 3.1+
- a C toolchain
- OpenSSL **3.0 or later**

## Primitive API

### ML-KEM-768

```ruby
keypair = PQCrypto::KEM.generate(:ml_kem_768)
result = keypair.public_key.encapsulate
shared_secret = keypair.secret_key.decapsulate(result.ciphertext)
```

### ML-DSA-65

```ruby
keypair = PQCrypto::Signature.generate(:ml_dsa_65)
signature = keypair.secret_key.sign("hello")
keypair.public_key.verify!("hello", signature)
```

### Hybrid ML-KEM-768 + X25519

```ruby
keypair = PQCrypto::HybridKEM.generate(:ml_kem_768_x25519_hkdf_sha256)
result = keypair.public_key.encapsulate
shared_secret = keypair.secret_key.decapsulate(result.ciphertext)
```

`PQCrypto::HybridKEM` is a **custom pq_crypto construction**. It is not advertised as compatible with HPKE, TLS hybrid drafts, X-Wing, OpenSSL native PQ APIs, or any other external wire format.

## Serialization

Key import/export is available through pq_crypto-specific containers:

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

These containers are **not real ASN.1 SPKI or PKCS#8**. They are intended for stable import/export inside `pq_crypto` itself and are not advertised as interoperable with external PKI tooling.

## Introspection

```ruby
PQCrypto.version
PQCrypto.backend
PQCrypto.supported_kems
PQCrypto.supported_hybrid_kems
PQCrypto.supported_signatures
PQCrypto::KEM.details(:ml_kem_768)
PQCrypto::HybridKEM.details(:ml_kem_768_x25519_hkdf_sha256)
PQCrypto::Signature.details(:ml_dsa_65)
```

## Testing helpers

Deterministic test hooks are exposed under `PQCrypto::Testing` for regression coverage:

- `ml_kem_keypair_from_seed`
- `ml_kem_encapsulate_from_seed`
- `ml_dsa_keypair_from_seed`
- `ml_dsa_sign_from_seed`

These helpers are intended for tests only.

## Development

Run the test suite with:

```bash
bundle exec rake test
```

Refresh vendored PQClean sources manually only when you intentionally update the vendor snapshot. The refresh script now has a safe pinned default and records the exact vendored snapshot in `ext/pqcrypto/vendor/.vendored`:

```bash
bundle exec ruby script/vendor_libs.rb
```

To intentionally change the upstream snapshot, override all four pinning inputs together:

```bash
PQCLEAN_VERSION=<full-git-commit> \
PQCLEAN_URL=https://github.com/PQClean/PQClean/archive/<full-git-commit>.tar.gz \
PQCLEAN_SHA256=<archive-sha256> \
PQCLEAN_STRIP=PQClean-<full-git-commit> \
  bundle exec ruby script/vendor_libs.rb
```
