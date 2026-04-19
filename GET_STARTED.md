# Get Started with PQCrypto

## 1. What this gem is today

`PQCrypto` is a native Ruby wrapper around a fixed cryptographic suite:
- hybrid KEM: ML-KEM-768 + X25519;
- signatures: ML-DSA-65;
- transport/session AEAD: AES-256-GCM.

It is intentionally **native-only** in the supported path. There is no supported Ruby fallback anymore.

## 2. Install correctly

```bash
bundle install
bundle exec rake vendor
bundle exec rake compile
bundle exec rake test
```

If PQClean sources are missing, the extension build fails on purpose.

## 3. Check runtime mode

```ruby
require "pq_crypto"

PQCrypto.backend        # => :native_pqclean
PQCrypto.experimental?  # => true
PQCrypto.version
```

`production_ready?` currently returns `false` deliberately: the gem still needs stronger protocol hardening, KAT coverage, interop tests, CI, and external review.

## 4. Key establishment

```ruby
public_key, secret_key = PQCrypto.kem_keypair
ciphertext, shared_secret_a = PQCrypto.kem_encapsulate(public_key)
shared_secret_b = PQCrypto.kem_decapsulate(ciphertext, secret_key)

raise "mismatch" unless shared_secret_a == shared_secret_b
```

## 5. Signatures

```ruby
public_key, secret_key = PQCrypto.sign_keypair
signature = PQCrypto.sign("hello", secret_key)
PQCrypto.verify("hello", signature, public_key)
```

Verification failure raises `PQCrypto::VerificationError`.

## 6. Sessions

```ruby
shared_secret = "A" * PQCrypto::KEM_SHARED_SECRET_BYTES
alice = PQCrypto::Session.new(shared_secret, true)
bob = PQCrypto::Session.new(shared_secret, false)

ciphertext = alice.encrypt("hello", aad: "meta")
plaintext = bob.decrypt(ciphertext, aad: "meta")
```

Sessions now derive separate send/receive keys and enforce a monotonic receive nonce.

## 7. One-shot sealing

```ruby
public_key, secret_key = PQCrypto.kem_keypair
sealed = PQCrypto.seal("payload", public_key)
plain = PQCrypto.unseal(sealed, secret_key)
```

## 8. Authenticated one-shot payloads

```ruby
sign_public_key, sign_secret_key = PQCrypto.sign_keypair
kem_public_key, kem_secret_key = PQCrypto.kem_keypair

payload = PQCrypto.sign_and_seal("payload", kem_public_key, sign_secret_key)
plain = PQCrypto.unseal_and_verify(payload, kem_secret_key, sign_public_key)
```

## 9. Main caveats

This gem is still experimental. The most important remaining work is:
- stronger protocol hardening and wire-format versioning;
- KAT and interop tests;
- CI;
- external security review.
