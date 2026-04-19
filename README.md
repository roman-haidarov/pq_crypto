# PQCrypto

> **Status:** experimental native Ruby gem for post-quantum cryptography. The gem now requires a compiled native extension with vendored PQClean sources. It is usable for development and research, but it has **not** passed an external security audit and should not be marketed as production-ready yet.

`pq_crypto` gives Ruby a native wrapper around:
- ML-KEM-768 for key establishment;
- ML-DSA-65 for digital signatures;
- X25519 as the classical hybrid component;
- AES-256-GCM for session and payload encryption.

## What changed in this iteration

This version takes larger corrective steps:
- insecure runtime fallbacks were removed from the supported build path;
- `require "pq_crypto"` now works as documented;
- hybrid key derivation is transcript-bound instead of a bare secret concatenation;
- sessions now use separate send/receive keys with monotonic nonces;
- replay/out-of-order ciphertexts are rejected inside a session.

## Install

```bash
bundle install
bundle exec rake vendor
bundle exec rake compile
bundle exec rake test
```

`bundle exec rake vendor` is required. If PQClean sources are missing, the extension build now fails explicitly instead of silently switching to a fake crypto backend.

## Quick start

```ruby
require "pq_crypto"

kem_public_key, kem_secret_key = PQCrypto.kem_keypair
sign_public_key, sign_secret_key = PQCrypto.sign_keypair

payload = PQCrypto.sign_and_seal("hello", kem_public_key, sign_secret_key)
message = PQCrypto.unseal_and_verify(payload, kem_secret_key, sign_public_key)

puts message
puts PQCrypto.backend        # => :native_pqclean
puts PQCrypto.experimental?  # => true
```

## Session example

```ruby
public_key, secret_key = PQCrypto.kem_keypair
alice_session, ciphertext = PQCrypto.establish_session(public_key)
bob_session = PQCrypto.accept_session(ciphertext, secret_key)

encrypted = alice_session.encrypt("secret", aad: "metadata")
plain = bob_session.decrypt(encrypted, aad: "metadata")
```

Each session derives separate send/receive keys from the shared secret and uses a monotonic nonce sequence.

## Secret wiping

`secure_wipe` intentionally requires a mutable `String`.

```ruby
secret = String.new("sensitive bytes")
PQCrypto.secure_wipe(secret)
```

## Development

```bash
bundle exec rake vendor
bundle exec rake compile
bundle exec rake test
```

`bundle exec rake spec` is kept as a compatibility alias for the old task name.

## License

MIT. See [LICENSE.txt](LICENSE.txt).
