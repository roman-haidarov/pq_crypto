# PQCrypto

> **Status:** experimental native Ruby gem for post-quantum cryptographic primitives.
>
> `pq_crypto` is now positioned as a **primitive-first** library: key generation, encapsulation/decapsulation, signatures, raw key bytes, and capability introspection. Higher-level protocol helpers still exist for compatibility, but they are **experimental** and are no longer the core story of the gem.

`pq_crypto` currently wraps a fixed native suite:
- **ML-KEM-768** for key encapsulation;
- **ML-DSA-65** for signatures;
- **PQClean** as the post-quantum implementation source;
- **X25519 + AES-256-GCM** only inside the gem's experimental protocol helpers.

## Install

```bash
bundle install
bundle exec rake vendor
bundle exec rake compile
bundle exec rake test
```

The supported build path is native-only. If vendored PQClean sources are missing, the build fails explicitly.

## Primitive-first quick start

```ruby
require "pq_crypto"

kem = PQCrypto::KEM.generate(:ml_kem_768)
encapsulation = kem.public_key.encapsulate
shared_secret = kem.secret_key.decapsulate(encapsulation.ciphertext)

raise "mismatch" unless shared_secret == encapsulation.shared_secret

signer = PQCrypto::Signature.generate(:ml_dsa_65)
signature = signer.secret_key.sign("hello")
verified = signer.public_key.verify("hello", signature)

puts verified
puts PQCrypto.supported_kems.inspect
puts PQCrypto.supported_signatures.inspect
puts PQCrypto.backend
```

## Public API direction

The intended core API is:
- `PQCrypto::KEM`
- `PQCrypto::Signature`
- typed public/secret key objects
- raw-byte import/export
- capability introspection

Compatibility helpers such as `PQCrypto.kem_keypair`, `PQCrypto.sign_keypair`, and legacy wrapper classes are still available, but they are not the long-term primary surface.

## Supported primitive APIs

### KEM

```ruby
keypair = PQCrypto::KEM.generate(:ml_kem_768)
pub = keypair.public_key
sec = keypair.secret_key

ciphertext, shared_secret_a = pub.encapsulate_to_bytes
shared_secret_b = sec.decapsulate(ciphertext)
```

```ruby
pub2 = PQCrypto::KEM.public_key_from_bytes(:ml_kem_768, pub.to_bytes)
sec2 = PQCrypto::KEM.secret_key_from_bytes(:ml_kem_768, sec.to_bytes)
```

### Signatures

```ruby
keypair = PQCrypto::Signature.generate(:ml_dsa_65)
pub = keypair.public_key
sec = keypair.secret_key

signature = sec.sign("message")
puts pub.verify("message", signature)
pub.verify!("message", signature)
```

```ruby
pub2 = PQCrypto::Signature.public_key_from_bytes(:ml_dsa_65, pub.to_bytes)
sec2 = PQCrypto::Signature.secret_key_from_bytes(:ml_dsa_65, sec.to_bytes)
```

### Introspection

```ruby
PQCrypto.version
PQCrypto.backend
PQCrypto.supported_kems
PQCrypto.supported_signatures
PQCrypto::KEM.details(:ml_kem_768)
PQCrypto::Signature.details(:ml_dsa_65)
```

## Experimental helpers

The following remain available for compatibility, but should be treated as **experimental protocol helpers**, not as the core primitive interface:
- `PQCrypto::Session`
- `PQCrypto::Identity`
- `PQCrypto::Experimental.establish_session`
- `PQCrypto::Experimental.accept_session`
- `PQCrypto::Experimental.seal`
- `PQCrypto::Experimental.unseal`
- `PQCrypto::Experimental.sign_and_seal`
- `PQCrypto::Experimental.unseal_and_verify`

These helpers are custom to this gem and are not advertised as interoperable with HPKE, X-Wing, OpenSSL, Go, or other PQ ecosystems.

## Secret wiping

`secure_wipe` intentionally requires a mutable `String`.

```ruby
secret = String.new("sensitive bytes")
PQCrypto.secure_wipe(secret)
```

## What this gem is not yet

This gem is still experimental. It is **not** yet:
- externally audited;
- backed by full NIST KAT coverage;
- positioned as a production-ready secure-channel protocol;
- an interoperability layer for HPKE/X-Wing/SPKI/PKCS#8 yet.

## License

MIT. See [LICENSE.txt](LICENSE.txt).


## Serialization

Primitive key objects support raw byte export/import and project-scoped ASN.1 DER/PEM containers:

```ruby
kem = PQCrypto::KEM.generate(:ml_kem_768)
pub_der = kem.public_key.to_spki_der
sec_pem = kem.secret_key.to_pkcs8_pem

imported_pub = PQCrypto::KEM.public_key_from_spki_der(pub_der)
imported_sec = PQCrypto::KEM.secret_key_from_pkcs8_pem(sec_pem)
```

These DER/PEM wrappers are currently project-local serialization containers intended for stable export/import inside pq_crypto. They are not yet advertised as interoperable with OpenSSL, Go, or other ecosystems.
