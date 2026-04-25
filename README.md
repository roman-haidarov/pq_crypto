# pq_crypto

`pq_crypto` is a primitive-first Ruby gem for post-quantum cryptography.

It exposes three public building blocks:

- `PQCrypto::KEM` — pure `ML-KEM-768` (FIPS 203)
- `PQCrypto::Signature` — `ML-DSA-65` (FIPS 204)
- `PQCrypto::HybridKEM` — `ML-KEM-768 + X25519` combined via the
  [X-Wing](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/)
  SHA3-256 combiner

The gem is backed by vendored `PQClean` sources for `ML-KEM-768` /
`ML-DSA-65` and by OpenSSL for `X25519` and `SHA3-256`. Every piece of
conventional-crypto functionality goes through standard library calls
(`EVP_*`, `RAND_bytes`, `CRYPTO_memcmp`, `BIO_f_base64`) — nothing
roll-your-own where a library primitive exists.

## Status

- primitive-first API only
- no protocol/session helpers in the public surface
- streaming ML-DSA signing/verification is available for large IO inputs
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

- Ruby 3.4.x
- a C toolchain with C11 support (for `_Static_assert` / `_Thread_local`)
- OpenSSL **3.0 or later** with SHA3-256 and SHAKE256 available (default provider)

### Build-time Keccak backend

The default build uses PQClean's scalar `common/fips202.c` backend:

```bash
PQCRYPTO_KECCAK_BACKEND=clean bundle exec rake compile
```

`PQCRYPTO_KECCAK_BACKEND=xkcp` is reserved for a separately vendored,
reviewed, `fips202.h`-compatible XKCP adapter. If requested without that
adapter, the build aborts instead of silently falling back to `clean`.
This avoids mixing OpenSSL EVP SHAKE state with PQClean SHAKE state and
keeps output-byte compatibility explicit.

## Async / Fiber scheduler support

`pq_crypto` does not require any gem-specific Async configuration. On
Ruby 3.4, `sign` and `verify` use Ruby's scheduler-aware
`rb_nogvl(..., RB_NOGVL_OFFLOAD_SAFE)` path automatically.

That means:

- without a Fiber scheduler, these methods fall back to the ordinary
  no-GVL behavior;
- with a scheduler that implements `blocking_operation_wait` (for
  example `Async` with a worker pool), the blocking native work can
  be moved off the event loop.

This integration is intentionally limited to `sign` and `verify`; the
faster primitive operations keep the lower-overhead path.

Example with `Async`:

```ruby
require "async"
require "pq_crypto"

keypair = PQCrypto::Signature.generate(:ml_dsa_65)
message = "hello" * 100_000

reactor = Async::Reactor.new(worker_pool: true)
root = reactor.async do |task|
  task.async do
    signature = keypair.secret_key.sign(message)
    keypair.public_key.verify(message, signature)
  end

  task.async do
    sleep 0.01
    puts "event loop stayed responsive"
  end
end

reactor.run
root.wait
reactor.close
```

## Primitive API

### ML-KEM-768

```ruby
keypair = PQCrypto::KEM.generate(:ml_kem_768)
result = keypair.public_key.encapsulate
shared_secret = keypair.secret_key.decapsulate(result.ciphertext)
```

### ML-DSA-65

One-shot signing keeps the existing API:

```ruby
keypair = PQCrypto::Signature.generate(:ml_dsa_65)
signature = keypair.secret_key.sign("hello")

keypair.public_key.verify("hello", signature)    # => true / false
keypair.public_key.verify!("hello", signature)   # raises on mismatch
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

`sign_io` / `verify_io` use pure ML-DSA with an internal FIPS 204
ExternalMu flow. They are not HashML-DSA/prehash shortcuts and do not
expose public `sign_mu` / `verify_mu` APIs. With the default empty
context, streaming signatures verify with `verify(message, signature)`
and one-shot signatures verify with `verify_io(io, signature)`.

Optional context is supported and must match on verify:

```ruby
ctx = "invoice-v1".b
signature = File.open("document.bin", "rb") { |io| keypair.secret_key.sign_io(io, context: ctx) }
ok = File.open("document.bin", "rb") { |io| keypair.public_key.verify_io(io, signature, context: ctx) }
```

`chunk_size` must be positive. `context` is limited to 255 bytes by
FIPS 204. `verify_io!` raises `PQCrypto::VerificationError` on mismatch.

Note: `verify` returns a plain boolean for normal outcomes. `verify!`
raises `PQCrypto::VerificationError` when the signature does not
match.

### Hybrid ML-KEM-768 + X25519 (X-Wing)

```ruby
keypair = PQCrypto::HybridKEM.generate(:ml_kem_768_x25519_xwing)
result = keypair.public_key.encapsulate
shared_secret = keypair.secret_key.decapsulate(result.ciphertext)
```

The implementation follows draft-10 key expansion: the X-Wing secret
decapsulation key is a 32-byte seed expanded with SHAKE256 into ML-KEM
and X25519 private material. The combiner is exactly:

```
ss = SHA3-256( ss_M || ss_X || ct_X || pk_X || "\.//^\" )
```

as specified by `draft-connolly-cfrg-xwing-kem-10`. See `SECURITY.md`
for audit status and interoperability caveats.

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

These containers are **not real ASN.1 SPKI or PKCS#8**. They are
intended for stable import/export inside `pq_crypto` itself and are
not advertised as interoperable with external PKI tooling.

## Secure wiping

`PQCrypto.secure_wipe(str)` zeros the bytes of a mutable Ruby string
in place. Key objects hold a private copy of their bytes, so `wipe!`
on a `SecretKey` zeroes **only** that internal copy — any prior Ruby
string the caller holds is untouched. If you need to wipe the
caller-side buffer, do so explicitly:

```ruby
raw = File.binread(path)
key = PQCrypto::KEM.secret_key_from_bytes(:ml_kem_768, raw)
PQCrypto.secure_wipe(raw)  # scrub the original input
# ... use key ...
key.wipe!                  # scrub the key's internal copy
```

## Constant-time comparison

`==` on `PublicKey` / `SecretKey` instances uses OpenSSL
`CRYPTO_memcmp` through a `PQCrypto.ct_equals` helper so comparisons
do not leak timing information about a prefix match.

Secret key `inspect` output is intentionally redacted and secret key
objects do not expose a public `fingerprint` method. `wipe!` remains
best-effort only: it clears the current Ruby string buffer owned by the
key object, not every possible copy made by Ruby, OpenSSL, serialization,
logging, or the garbage collector.

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
```

## Testing helpers

Deterministic test hooks are exposed under `PQCrypto::Testing` for
regression coverage:

- `ml_kem_keypair_from_seed` — requires a 64-byte `d||z` seed (FIPS 203)
- `ml_kem_encapsulate_from_seed` — requires a 32-byte seed
- `ml_dsa_keypair_from_seed` — requires a 32-byte seed
- `ml_dsa_sign_from_seed` — requires a 32-byte seed

These helpers are intended for tests only. They work by installing a
thread-local seed-replay mode inside the gem's `randombytes()` for
the duration of the call, then call the stock PQClean entrypoints.
No internal PQClean algorithm logic is reimplemented in this gem.

## Development

Run the test suite with:

```bash
bundle exec rake test
```

Refresh vendored PQClean sources manually only when you intentionally
update the vendor snapshot. The refresh script has a safe pinned
default and records the exact vendored snapshot in
`ext/pqcrypto/vendor/.vendored`:

```bash
bundle exec ruby script/vendor_libs.rb
```

To intentionally change the upstream snapshot, override all four
pinning inputs together:

```bash
PQCLEAN_VERSION=<full-git-commit> \
PQCLEAN_URL=https://github.com/PQClean/PQClean/archive/<full-git-commit>.tar.gz \
PQCLEAN_SHA256=<archive-sha256> \
PQCLEAN_STRIP=PQClean-<full-git-commit> \
  bundle exec ruby script/vendor_libs.rb
```
