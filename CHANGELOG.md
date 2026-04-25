# Changelog

## [0.3.2] — 2026-04-25

### Added — streaming ML-DSA for large inputs

- Added `PQCrypto::Signature::SecretKey#sign_io(io, chunk_size: 1 << 20, context: "".b)`.
- Added `PQCrypto::Signature::PublicKey#verify_io(io, signature, chunk_size: 1 << 20, context: "".b)` and `verify_io!`.
- Implemented streaming pure ML-DSA through an internal FIPS 204 ExternalMu path. Existing one-shot `sign` / `verify` semantics are unchanged; no public `sign_mu` / `verify_mu` API is exposed.

### Notes

- Streaming is primarily for large IO inputs and lower peak memory pressure. It is not a HashML-DSA/prehash speed mode; CPU cost is still dominated by SHAKE/Keccak.
- Default empty-context streaming signatures interoperate with the existing one-shot `verify(message, signature)` API. Non-empty `context:` must be supplied again during `verify_io`.

## [0.3.1] — 2026-04-24

### Fixed — X-Wing draft-10 compatibility

- Changed `:ml_kem_768_x25519_xwing` secret keys to the draft-10 32-byte
  X-Wing decapsulation seed and derive ML-KEM/X25519 private material with
  SHAKE256 during key generation and decapsulation.
- Corrected the X-Wing combiner transcript to
  `ss = SHA3-256( ss_M || ss_X || ct_X || pk_X || XWingLabel )`.
- Updated the hybrid serialization OID to the X-Wing draft OID
  `1.3.6.1.4.1.62253.25722`.
- Redacted key `inspect` output, removed public secret-key fingerprints,
  improved native extension load diagnostics, switched the extension build
  flag to C11, and aligned docs with the implementation.

## [0.3.0] — 2026-04-24

**Breaking release.** Hybrid KEM keys, ciphertexts, and `pqc_container_*`
blobs produced by 0.2.0 are not compatible with 0.3.0. Pure ML-KEM-768
and ML-DSA-65 material is unaffected.

### Changed — hybrid KEM (breaking)

- Replaced the 0.2.0 ad-hoc `HKDF-SHA256`-with-double-transcript combiner
  with a SHA3-256 X-Wing-inspired combiner. This was later corrected in
  `0.3.1` to match draft-10 transcript order and 32-byte secret keys.
- Renamed the hybrid algorithm symbol
  `:ml_kem_768_x25519_hkdf_sha256` → `:ml_kem_768_x25519_xwing`.
- Retired the 0.2.0 project-local hybrid OID
  (`2.25.260242945110721168101139140490528778800`). 0.3.0 used
  `2.25.318532651283923671095712569430174917109`; this was later replaced
  in `0.3.1` by the X-Wing draft OID.

### Changed — native code hygiene

- Removed the copy of PQClean internal ML-DSA keypair and signature logic
  that 0.2.0 used to implement deterministic test hooks. Tests now drive
  the stock PQClean `crypto_sign_keypair` / `crypto_sign_signature`
  through a new `randombytes()` override
  (`ext/pqcrypto/pq_randombytes.c`) that swaps in a thread-local
  seed-replay mode for the duration of a deterministic call and delegates
  to `OpenSSL RAND_bytes` otherwise.
- Deleted the non-FIPS 32-byte ML-KEM seed with HKDF expansion; the
  deterministic ML-KEM keypair hook now accepts only the
  FIPS 203 64-byte `d||z` seed.
- Replaced `uint8_t*` → `hybrid_*_t*` strict-aliasing casts with
  explicit `memcpy` into typed stack locals throughout the hybrid path.
- Added `_Static_assert` guards on the byte-packed layout of
  `hybrid_public_key_t`, `hybrid_secret_key_t`, and
  `hybrid_ciphertext_t` so any future change that introduces padding
  fails at compile time rather than silently shifting byte offsets.
- Migrated PEM codec to OpenSSL `BIO_f_base64` with stricter PEM
  header/footer framing and trailing-garbage checks.
- Deleted the entire internal HKDF and SHA-256 helper paths that 0.2.0
  used for its combiner; the X-Wing combiner is a single SHA3-256
  invocation through `EVP_DigestUpdate`.
- Tightened `extconf.rb`: the broad `-Wno-unused-parameter`
  `-Wno-unused-function` `-Wno-strict-prototypes` `-Wno-pedantic`
  `-Wno-c23-extensions` `-Wno-undef` suppressions now apply **only** to
  vendored PQClean translation units; our own code compiles with the
  strict warning set. Added a compile probe for `EVP_sha3_256`.

### Changed — Ruby API

- `Signature::PublicKey#verify` now returns `true` / `false` for normal
  cryptographic outcomes. Previously an invalid signature surfaced
  through a caught `VerificationError`; the native entrypoint no longer
  raises for this case. `verify!` still raises on mismatch.
- `PublicKey#==` / `SecretKey#==` on all key types now use OpenSSL
  `CRYPTO_memcmp` through a new `PQCrypto.ct_equals` native helper, so
  key equality checks no longer leak timing information about a
  prefix-match.
- `PublicKey#hash` and `SecretKey#hash` now hash a SHA-256 fingerprint
  of the bytes instead of the raw bytes. The public secret-key fingerprint
  method is removed in `0.3.1` to reduce accidental logging risk.
- Native entrypoints and their `native_*` aliases are installed once via
  the new `PQCrypto::NativeBindings` module instead of the ad-hoc
  `unless method_defined?` guards on the singleton.
- Renamed `Signature.validate_algorithm!` → `resolve_algorithm!` to
  match `KEM` / `HybridKEM`.

### Changed — packaging

- Intended to change `required_ruby_version` from `">= 3.4.0.a"` to
  `">= 3.4"`; the gemspec is aligned in `0.3.1`.
- Version bumped to `0.3.0`.
- `VerificationError` class is still defined (and still raised by
  `verify!`) for backward compatibility, but the native `verify`
  entrypoint no longer raises it.

### Migration notes

- Hybrid keys and ciphertexts must be regenerated with 0.3.0; old blobs
  are rejected by the new container decoder.
- Code referencing the old hybrid symbol must update to
  `:ml_kem_768_x25519_xwing`. Pure ML-KEM and ML-DSA symbols are
  unchanged.
- Code relying on `verify` raising `VerificationError` should switch
  to `verify!` or a `verify` + explicit `false` check.

## [0.2.0]

### Changed

- Raised the minimum supported Ruby to the 3.4 series.
- Switched `PQCrypto::Signature::SecretKey#sign` and `PQCrypto::Signature::PublicKey#verify` to Ruby 3.4's scheduler-aware `rb_nogvl(..., RB_NOGVL_OFFLOAD_SAFE)` path.
- Left the faster KEM and key-generation operations on the existing lower-overhead no-GVL path.
- Removed gem-specific scheduler configuration; runtime behavior now follows the active Ruby Fiber scheduler automatically.

### Testing

- Added Async integration tests that verify sibling `task.async` work keeps making progress while `sign` and `verify` run under an Async worker-pool-enabled reactor.
- Updated CI to target the supported Ruby 3.4 series.

## [0.1.0]

Initial public release.

### Public API

- Added primitive-first `PQCrypto::KEM` for pure `ML-KEM-768`.
- Added primitive-first `PQCrypto::Signature` for `ML-DSA-65`.
- Added `PQCrypto::HybridKEM` for the pq_crypto-specific `ML-KEM-768 + X25519 + HKDF-SHA256` hybrid combiner.
- Added typed key objects with raw-byte import/export and `details`/supported-algorithm introspection.
- Added `pqc_container_*` DER/PEM import/export for pq_crypto-specific key containers.
- Documented that `pqc_container_*` containers use pq_crypto-local OIDs and are not a long-term external interoperability guarantee.
- Added `PQCrypto::Testing` deterministic hooks for regression coverage.

### Native / build

- Vendored `PQClean` sources for `ML-KEM-768` and `ML-DSA-65`.
- Integrated OpenSSL-backed conventional primitives for hybrid mode and utility operations.
- Require OpenSSL 3.0 or later.

### Testing

- Added deterministic regression coverage for `ML-KEM-768` and `ML-DSA-65`.
- Hardened native bindings by copying Ruby string inputs before running no-GVL native operations.
- Tightened manual vendoring workflow to require an explicit pinned upstream URL, version label, strip prefix, and SHA-256.
- Added primitive interop tests for OpenSSL and Go where toolchain support is available.
- Added serialization hardening tests.
