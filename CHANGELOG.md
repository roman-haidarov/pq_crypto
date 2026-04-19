## [0.5.0] - 2026-04-19

### Added
- Added project-scoped SPKI/PKCS#8 DER and PEM serialization helpers for primitive key objects.
- Added import helpers for KEM and signature keys from DER and PEM containers.
- Exposed `family` and `oid` metadata through KEM and Signature details APIs.

### Changed
- Promoted raw-bytes-plus-serialization as the primary key import/export story for the primitive-first API.
- Clarified that high-level protocol helpers remain experimental and that DER/PEM serialization is not yet advertised as ecosystem-wide interop.

### Tests
- Added serialization round-trip coverage for KEM and signature keys.
- Added serialization mismatch and metadata coverage.

# Changelog

## [0.4.0]

### Changed
- Repositioned the gem around a **primitive-first** public API.
- Added `PQCrypto::KEM` and `PQCrypto::Signature` as the intended core namespaces.
- Added typed primitive objects:
  - `PQCrypto::KEM::Keypair`
  - `PQCrypto::KEM::PublicKey`
  - `PQCrypto::KEM::SecretKey`
  - `PQCrypto::KEM::EncapsulationResult`
  - `PQCrypto::Signature::Keypair`
  - `PQCrypto::Signature::PublicKey`
  - `PQCrypto::Signature::SecretKey`
- Added capability/introspection APIs:
  - `PQCrypto.supported_kems`
  - `PQCrypto.supported_signatures`
  - `PQCrypto::KEM.details(...)`
  - `PQCrypto::Signature.details(...)`
- Reframed `Session`, `Identity`, and sealing/session helpers as compatibility / experimental helpers rather than the center of the gem.
- Updated `README` and `GET_STARTED` to reflect the primitive-first model.

### Compatibility
- Kept the legacy top-level byte-oriented methods (`kem_keypair`, `kem_encapsulate`, `kem_decapsulate`, `sign_keypair`, `sign`, `verify`) as compatibility wrappers.
- Kept `PQCrypto::KEMKeypair`, `PQCrypto::SignKeypair`, and `PQCrypto::Identity` for compatibility while rebasing them on the new primitive objects.
- Added `PQCrypto::Experimental` as an explicit home for protocol-style helpers.

### Notes
- The gem remains experimental.
- Protocol helpers are custom to this gem and are not advertised as interoperable with HPKE, X-Wing, Go, or OpenSSL.
- Full serialization/interoperability work is planned for the next major step.

## [0.3.1]

### Breaking
- `sign_and_seal` / `unseal_and_verify` payloads now carry a 6-byte version header `"PQ10" || version(1) || suite_id(1)` before the existing signature-length prefix. Payloads produced by 0.3.0 and earlier cannot be verified by 0.3.1 and vice-versa. This enables future algorithm suites to be added without another breaking change.

### Removed
- Physically removed ~290 lines of dead fallback code from `ext/pqcrypto/pqcrypto_secure.c` (fake X25519, fake AES-GCM, fake ML-KEM, fake ML-DSA). Previously these were gated by `#error` at compile time but still present in the source tree. They are now gone.
- Removed `SECURITY_AUDIT.md` reference from the gemspec file manifest (the file was already deleted upstream but the manifest still referenced it).
- Removed stale `.rspec_status` artifact from the repository.

### Added
- New `SECURITY.md` with threat model, algorithm list, combiner description, wire format documentation, and vulnerability disclosure policy. This is NOT an audit report — the gem has not been audited.
- New test suite `test/test_fips_constants.rb` with lightweight sanity checks that verify FIPS 203 (ML-KEM-768) and FIPS 204 (ML-DSA-65) constants are wired up correctly. These are not full NIST KAT vectors.
- New tests covering rejection of tampered wire-format headers: bad magic, bad version, bad suite_id.

### Notes
- The hybrid KEM combiner is transcript-bound but is **not** X-Wing or HPKE. Payloads from this gem are not expected to interoperate with other PQ libraries. See SECURITY.md for details.
- KAT-based validation against NIST test vectors is not yet implemented and remains a known gap.
- Added a minimal GitHub Actions CI workflow for vendoring, compiling, and testing on Ubuntu and macOS across supported Ruby versions.

## [0.3.0]

### Changed
- Reworked the native/runtime boundary so Ruby acts as a thin API layer and delegates cryptographic operations to the native extension.
- Added a proper `require "pq_crypto"` entrypoint while keeping `require "pqcrypto"` as a compatibility shim.
- Aligned project metadata, Rake tasks, and documentation with the actual supported runtime/build model.
- Marked the gem as experimental rather than production-ready.

### Security
- Removed the insecure fallback runtime path from the supported build flow.
- Changed the build behavior to require vendored PQClean for post-quantum functionality instead of silently degrading to unsafe substitutes.
- Strengthened the hybrid key schedule by binding more context into shared secret derivation.
- Reworked session key derivation to use separate directional keys instead of a single shared transport key.
- Replaced the previous nonce strategy with a monotonic per-direction nonce/counter policy.
- Added stricter runtime validation around session state and invalid decrypt flows.

### Fixed
- Fixed the main public load path so `require "pq_crypto"` works as documented.
- Fixed inconsistencies between README / GET_STARTED / gemspec / Rakefile and the current project layout.
- Fixed vendored PQClean integration so PQClean sources are actually compiled and linked into the native extension.
- Fixed the vendored build warning handling without patching vendored upstream sources directly.
- Fixed native build/runtime issues that previously caused crashes in the vendored PQClean path.
- Fixed signed/sealed payload handling and related boundary validation behavior.

### Tests
- Updated the test suite for the new native-first behavior and stricter session semantics.
- Expanded coverage for current supported flows and regressions fixed in this release.

## 0.2.0

- refactored the gem layout to match the structure used in `multi_compress`;
- moved versioning into `lib/pq_crypto/version.rb`;
- introduced a clean `lib/pq_crypto.rb` entrypoint with compatibility fallback loading;
- added `pq_crypto` / `pqcrypto` require-path compatibility;
- switched the test suite to `minitest` and added a `rake spec` compatibility alias;
- corrected the signed payload format to use a 4-byte signature length prefix;
- clarified the difference between `:native_pqclean`, `:native_fallback`, and `:ruby_fallback`;
- fixed `secure_wipe` semantics for frozen strings;
- cleaned the build configuration and documentation.

## 0.1.0

- initial project version.
