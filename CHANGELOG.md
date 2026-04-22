# Changelog

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
