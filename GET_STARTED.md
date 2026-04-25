# Getting started with pq_crypto

## 1. Build the extension

```bash
bundle install
bundle exec rake compile
```

## 2. Generate an ML-KEM-768 keypair

```ruby
keypair = PQCrypto::KEM.generate(:ml_kem_768)
```

## 3. Encapsulate and decapsulate

```ruby
result = keypair.public_key.encapsulate
shared_secret = keypair.secret_key.decapsulate(result.ciphertext)
```

## 4. Generate an ML-DSA-65 keypair

```ruby
sig = PQCrypto::Signature.generate(:ml_dsa_65)
```

## 5. Sign and verify

```ruby
signature = sig.secret_key.sign("message")

sig.public_key.verify("message", signature)
sig.public_key.verify!("message", signature)
```

For large files, use streaming ML-DSA:

```ruby
signature = File.open("document.bin", "rb") do |io|
  sig.secret_key.sign_io(io, chunk_size: 1 << 20)
end

ok = File.open("document.bin", "rb") do |io|
  sig.public_key.verify_io(io, signature, chunk_size: 1 << 20)
end
```

With an optional context:

```ruby
ctx = "document-v1".b
signature = File.open("document.bin", "rb") { |io| sig.secret_key.sign_io(io, context: ctx) }
ok = File.open("document.bin", "rb") { |io| sig.public_key.verify_io(io, signature, context: ctx) }
```

`sign_io` / `verify_io` are pure ML-DSA streaming helpers, not prehash
shortcuts. `verify_io!` raises on mismatch.

## 6. Hybrid KEM (X-Wing)

```ruby
hybrid = PQCrypto::HybridKEM.generate(:ml_kem_768_x25519_xwing)
result = hybrid.public_key.encapsulate
shared_secret = hybrid.secret_key.decapsulate(result.ciphertext)
```

The raw X-Wing secret key exported by this API is the draft-10 32-byte
decapsulation seed, not the expanded ML-KEM/X25519 private material.

The hybrid mode follows `draft-connolly-cfrg-xwing-kem`. See
`SECURITY.md` for audit status.

## 7. Serialize a key

```ruby
der = keypair.public_key.to_pqc_container_der
imported = PQCrypto::KEM.public_key_from_pqc_container_der(der)
```

`pqc_container_*` formats are pq_crypto-specific.

## 8. Inspect supported algorithms

```ruby
PQCrypto.supported_kems           # => [:ml_kem_768]
PQCrypto.supported_hybrid_kems    # => [:ml_kem_768_x25519_xwing]
PQCrypto.supported_signatures     # => [:ml_dsa_65]
```

## 9. Practical notes

- OpenSSL 3.0+ with SHA3-256 is required.
- `PQCrypto::Testing` exposes deterministic helpers only for
  regression tests.
- Key equality uses constant-time comparison. `#hash` returns a
  hash derived from a SHA-256 fingerprint, not the raw bytes.
