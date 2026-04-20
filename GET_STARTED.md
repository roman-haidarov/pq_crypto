# Get Started with PQCrypto

## 1. Current direction

`PQCrypto` should be approached as a **primitive-first Ruby PQ library**.

The core surface is:
- `PQCrypto::KEM`
- `PQCrypto::Signature`
- typed key objects
- raw-byte import/export
- capability introspection

High-level protocol-style helpers still exist for compatibility, but they are experimental and are no longer the recommended entrypoint.

## 2. Install

```bash
bundle install
bundle exec rake vendor
bundle exec rake compile
bundle exec rake test
```

## 3. Load the gem

```ruby
require "pq_crypto"
```

## 4. Check capabilities

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

## 5. Use KEM primitives

```ruby
keypair = PQCrypto::KEM.generate(:ml_kem_768)
result = keypair.public_key.encapsulate
shared_secret = keypair.secret_key.decapsulate(result.ciphertext)

raise "mismatch" unless shared_secret == result.shared_secret
```

## 6. Use signature primitives

```ruby
signer = PQCrypto::Signature.generate(:ml_dsa_65)
signature = signer.secret_key.sign("hello")

puts signer.public_key.verify("hello", signature)
signer.public_key.verify!("hello", signature)
```

## 7. Import/export raw key bytes

```ruby
kem = PQCrypto::KEM.generate(:ml_kem_768)
pub = PQCrypto::KEM.public_key_from_bytes(:ml_kem_768, kem.public_key.to_bytes)
sec = PQCrypto::KEM.secret_key_from_bytes(:ml_kem_768, kem.secret_key.to_bytes)
```

```ruby
sig = PQCrypto::Signature.generate(:ml_dsa_65)
pub = PQCrypto::Signature.public_key_from_bytes(:ml_dsa_65, sig.public_key.to_bytes)
sec = PQCrypto::Signature.secret_key_from_bytes(:ml_dsa_65, sig.secret_key.to_bytes)
```

## 8. Hybrid KEM and legacy helpers

`PQCrypto::KEM` is now the pure ML-KEM primitive.
The older top-level `PQCrypto.kem_*` methods remain as compatibility helpers backed by the gem's hybrid ML-KEM-768 + X25519 construction.

If you need the hybrid primitive explicitly, use:

```ruby
keypair = PQCrypto::HybridKEM.generate(:ml_kem_768_x25519_hkdf_sha256)
```

These legacy/compatibility APIs still exist, but are no longer the recommended center of the gem:
- `PQCrypto.kem_keypair`
- `PQCrypto.sign_keypair`
- `PQCrypto::KEMKeypair`
- `PQCrypto::SignKeypair`
- `PQCrypto::Session`
- `PQCrypto::Identity`
- `PQCrypto::Experimental.*`

## 9. Experimental status

The gem remains experimental. The next major area of work is:
- interop and serialization;
- KAT/conformance coverage;
- continued protocol hardening;
- cleaner separation between primitives and optional high-level helpers.
