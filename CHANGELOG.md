# Changelog

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
