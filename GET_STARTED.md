# Getting started with pq_crypto

This guide shows the common `pq_crypto` workflows. The README is intentionally
short; examples and practical details live here.

## 1. Install

Add the gem to your application:

```ruby
# Gemfile
gem "pq_crypto"
```

Install it:

```bash
bundle install
```

If you are working from a repository checkout, compile the native extension:

```bash
bundle exec rake compile
```

Use the gem from Ruby:

```ruby
require "pq_crypto"
```

## 2. Check the available algorithms

```ruby
PQCrypto.supported_kems
# => [:ml_kem_512, :ml_kem_768, :ml_kem_1024]

PQCrypto.supported_signatures
# => [:ml_dsa_44, :ml_dsa_65, :ml_dsa_87]

PQCrypto.supported_hybrid_kems
# => [:ml_kem_768_x25519_xwing]
```

Useful metadata:

```ruby
PQCrypto.version
PQCrypto.backend

PQCrypto::KEM.details(:ml_kem_768)
PQCrypto::Signature.details(:ml_dsa_65)
PQCrypto::AlgorithmRegistry.standard_oid(:ml_kem_768)
```

`DETAILS[:oid]` remains the legacy `pqc_container_*` OID for backward
compatibility. Use `AlgorithmRegistry.standard_oid` when you need the standard
RFC OID.

## 3. ML-KEM: generate, encapsulate, decapsulate

Generate a keypair:

```ruby
keypair = PQCrypto::KEM.generate(:ml_kem_768)
public_key = keypair.public_key
secret_key = keypair.secret_key
```

Encapsulate with the public key:

```ruby
result = public_key.encapsulate
ciphertext = result.ciphertext
sender_shared_secret = result.shared_secret
```

Decapsulate with the secret key:

```ruby
receiver_shared_secret = secret_key.decapsulate(ciphertext)

sender_shared_secret == receiver_shared_secret
# => true
```

The same API shape applies to other supported ML-KEM parameter sets:

```ruby
PQCrypto::KEM.generate(:ml_kem_512)
PQCrypto::KEM.generate(:ml_kem_1024)
```

## 4. ML-DSA: sign and verify

Generate a signature keypair:

```ruby
keypair = PQCrypto::Signature.generate(:ml_dsa_65)
public_key = keypair.public_key
secret_key = keypair.secret_key
```

Sign and verify a message:

```ruby
message = "hello".b
signature = secret_key.sign(message)

public_key.verify(message, signature)
# => true

public_key.verify!(message, signature)
# returns true, or raises on mismatch
```

The same API shape applies to other supported ML-DSA parameter sets:

```ruby
PQCrypto::Signature.generate(:ml_dsa_44)
PQCrypto::Signature.generate(:ml_dsa_87)
```

## 5. ML-DSA for large files

For large inputs, use the streaming helpers so the whole message does not need
to be materialized as one Ruby string.

```ruby
keypair = PQCrypto::Signature.generate(:ml_dsa_65)

signature = File.open("document.bin", "rb") do |io|
  keypair.secret_key.sign_io(io, chunk_size: 1 << 20)
end

ok = File.open("document.bin", "rb") do |io|
  keypair.public_key.verify_io(io, signature, chunk_size: 1 << 20)
end
```

With an optional FIPS 204 context:

```ruby
context = "invoice-v1".b

signature = File.open("document.bin", "rb") do |io|
  keypair.secret_key.sign_io(io, context: context)
end

ok = File.open("document.bin", "rb") do |io|
  keypair.public_key.verify_io(io, signature, context: context)
end
```

Notes:

- `context` must match during verification.
- `context` is limited to 255 bytes by FIPS 204.
- `chunk_size` must be positive.
- `sign_io` / `verify_io` are pure ML-DSA streaming helpers. They are not
  HashML-DSA/prehash shortcuts and do not expose public `sign_mu` /
  `verify_mu` APIs.

## 6. Hybrid KEM: ML-KEM-768 + X25519 X-Wing

```ruby
keypair = PQCrypto::HybridKEM.generate(:ml_kem_768_x25519_xwing)

result = keypair.public_key.encapsulate
ciphertext = result.ciphertext
sender_shared_secret = result.shared_secret

receiver_shared_secret = keypair.secret_key.decapsulate(ciphertext)

sender_shared_secret == receiver_shared_secret
# => true
```

The raw X-Wing secret key exported by this API is the draft-style 32-byte
secret seed, not the expanded ML-KEM/X25519 private material.

See `SECURITY.md` for audit status and hybrid interoperability caveats.

## 7. SPKI public-key serialization

Use SPKI when you need standard public-key serialization for ML-KEM or ML-DSA.

ML-KEM example:

```ruby
keypair = PQCrypto::KEM.generate(:ml_kem_768)

pem = keypair.public_key.to_spki_pem
imported = PQCrypto::KEM.public_key_from_spki_pem(pem)

imported == keypair.public_key
# => true
```

DER form:

```ruby
der = keypair.public_key.to_spki_der
imported = PQCrypto::KEM.public_key_from_spki_der(der)
```

ML-DSA example:

```ruby
keypair = PQCrypto::Signature.generate(:ml_dsa_65)

pem = keypair.public_key.to_spki_pem
imported = PQCrypto::Signature.public_key_from_spki_pem(pem)
```

You can require an expected algorithm during import:

```ruby
PQCrypto::KEM.public_key_from_spki_pem(pem, algorithm: :ml_kem_768)
```

## 8. PKCS#8 private-key serialization

Use PKCS#8 when you need standard private-key serialization for ML-KEM or
ML-DSA.

### ML-KEM PKCS#8

`SecretKey#to_pkcs8_pem` exports the expanded private key by default:

```ruby
keypair = PQCrypto::KEM.generate(:ml_kem_768)

pem = keypair.secret_key.to_pkcs8_pem
imported = PQCrypto::KEM.secret_key_from_pkcs8_pem(pem)

imported == keypair.secret_key
# => true
```

DER form:

```ruby
der = keypair.secret_key.to_pkcs8_der
imported = PQCrypto::KEM.secret_key_from_pkcs8_der(der)
```

ML-KEM PKCS#8 supports `:seed`, `:expanded`, and `:both` formats. A generated
`SecretKey` does not retain the original seed, so exporting `:seed` or `:both`
from `SecretKey#to_pkcs8_*` is intentionally unavailable. If you explicitly
have the seed material, use the low-level PKCS#8 encoder.

### ML-DSA PKCS#8

ML-DSA private keys support expanded-key PKCS#8 by default:

```ruby
keypair = PQCrypto::Signature.generate(:ml_dsa_65)

pem = keypair.secret_key.to_pkcs8_pem
imported = PQCrypto::Signature.secret_key_from_pkcs8_pem(pem)
```

ML-DSA seed/both import is intentionally opt-in:

```ruby
PQCrypto::PKCS8.allow_ml_dsa_seed_format = true
imported = PQCrypto::Signature.secret_key_from_pkcs8_pem(pem)
```

Seed/both export from an existing ML-DSA `SecretKey` is intentionally not
available because the object does not retain the original seed material. When
you explicitly have seed material, call `PQCrypto::PKCS8.encode_der` /
`encode_pem` directly.

## 9. pq_crypto-local container serialization

The `pqc_container_*` APIs are retained for backward compatibility with older
`pq_crypto` releases.

```ruby
keypair = PQCrypto::KEM.generate(:ml_kem_768)

der = keypair.public_key.to_pqc_container_der
imported = PQCrypto::KEM.public_key_from_pqc_container_der(der)
```

PEM form:

```ruby
pem = keypair.secret_key.to_pqc_container_pem
imported = PQCrypto::KEM.secret_key_from_pqc_container_pem(pem)
```

Important caveats:

- `pqc_container_*` is project-local.
- It is not ASN.1 SPKI or PKCS#8.
- It is not advertised as interoperable with external PKI tooling.
- It remains limited to the original algorithms:
  - `:ml_kem_768`
  - `:ml_dsa_65`
  - `:ml_kem_768_x25519_xwing`

For external interoperability, prefer SPKI for public keys and PKCS#8 for
private keys.

## 10. Raw key import/export

Raw bytes can be useful when integrating with storage or protocols that already
handle framing.

```ruby
keypair = PQCrypto::KEM.generate(:ml_kem_768)

public_bytes = keypair.public_key.to_bytes
secret_bytes = keypair.secret_key.to_bytes

public_key = PQCrypto::KEM.public_key_from_bytes(:ml_kem_768, public_bytes)
secret_key = PQCrypto::KEM.secret_key_from_bytes(:ml_kem_768, secret_bytes)
```

Signature keys have the same shape:

```ruby
keypair = PQCrypto::Signature.generate(:ml_dsa_65)

public_key = PQCrypto::Signature.public_key_from_bytes(:ml_dsa_65, keypair.public_key.to_bytes)
secret_key = PQCrypto::Signature.secret_key_from_bytes(:ml_dsa_65, keypair.secret_key.to_bytes)
```

## 11. Secure wiping

`PQCrypto.secure_wipe(str)` zeroes a mutable Ruby string in place.

```ruby
raw = File.binread("secret-key.bin")
key = PQCrypto::KEM.secret_key_from_bytes(:ml_kem_768, raw)

PQCrypto.secure_wipe(raw)
key.wipe!
```

`wipe!` is best-effort only. It clears the current Ruby string buffer owned by
the key object. It cannot erase every copy that may have been created by Ruby,
OpenSSL, serialization, logging, or the garbage collector.

## 12. Equality and inspection

Key equality uses constant-time comparison through OpenSSL `CRYPTO_memcmp` via
`PQCrypto.ct_equals`.

```ruby
keypair.public_key == imported_public_key
keypair.secret_key == imported_secret_key
```

Secret key `inspect` output is intentionally redacted, and secret key objects
do not expose a public fingerprint method.

## 13. Native backend

Since `0.5.0`, the build uses PQ Code Package `mlkem-native` / `mldsa-native`
sources only. There is no PQClean fallback and no separate
`PQCRYPTO_KECCAK_BACKEND` switch: Keccak/SHAKE comes from the selected PQ Code
Package native source tree.

For release gems, the vendor snapshot should already be packaged. For source or
Git installs, `extconf.rb` auto-vendors the snapshot during native extension
build if `ext/pqcrypto/vendor/.vendored` is missing. Auto-vendoring requires
`git` and network access; disable it with `PQCRYPTO_AUTO_VENDOR=0` when you want
the build to fail instead of downloading sources.

For local development, explicit vendoring is still recommended:

```bash
bundle exec rake vendor
bundle exec rake compile
```

To try the upstream native assembly backend, opt in explicitly:

```bash
PQCRYPTO_NATIVE_ASM=1 bundle exec rake compile
```

## 14. Async / Fiber scheduler behavior

On Ruby 3.4, signing and verification use Ruby's scheduler-aware
`rb_nogvl(..., RB_NOGVL_OFFLOAD_SAFE)` path automatically. With a scheduler
that implements `blocking_operation_wait`, blocking native work can be moved
off the event loop.

## 15. Test-only deterministic helpers

`PQCrypto::Testing` exposes deterministic helpers for regression tests:

```ruby
PQCrypto::Testing.ml_kem_keypair_from_seed(seed)       # 64-byte d||z seed
PQCrypto::Testing.ml_kem_encapsulate_from_seed(pk, seed) # 32-byte seed
PQCrypto::Testing.ml_dsa_keypair_from_seed(seed)       # 32-byte seed
PQCrypto::Testing.ml_dsa_sign_from_seed(message, sk, seed)
```

These helpers are intended for tests only. They drive deterministic PQ Code
Package native entrypoints and are not part of the normal application API.

## 16. Development commands

Run the test suite:

```bash
bundle exec rake test
```

Refresh the pinned PQ Code Package native vendor snapshot only when intentionally
updating vendored sources:

```bash
bundle exec ruby script/vendor_libs.rb
```

Native extension installation from a Git dependency also runs this script
automatically when the vendor snapshot is absent. For offline/reproducible
installs, commit the vendored snapshot or build/install from a packaged gem that
contains `ext/pqcrypto/vendor`.

To intentionally change the upstream snapshot, override the native package refs:

```bash
MLKEM_NATIVE_REF=<tag-or-commit> \
MLDSA_NATIVE_REF=<tag-or-commit> \
  bundle exec ruby script/vendor_libs.rb
```
