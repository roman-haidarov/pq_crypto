# Changelog

## [0.6.1] - 2026-05-14

### Security

- Moved PKCS#8 PEM handling, PrivateKeyInfo wrapping/unwrapping, and encrypted PKCS#8 encryption/decryption to native C/OpenSSL helpers.
- Removed Ruby `OpenSSL::ASN1` parsing/building from the PKCS#8 path while preserving the existing Ruby API.

## [0.6.0] - 2026-05-14

### Added

- Added seed-aware `SecretKey.from_seed` helpers for ML-KEM and ML-DSA, with PKCS#8 `:seed` / `:both` re-export when seed material is retained.
- Added one-shot ML-DSA `context:` support, ML-DSA-44/65/87 streaming coverage, encrypted PKCS#8, and `PQCrypto::Key.from_pem/from_der` auto-dispatch.

### Security

- Tightened secret-key lifetime handling for PKCS#8 temporary buffers, key equality, and HybridKEM expanded-key wiping.

## [0.5.3] - 2026-05-08

### Compatibility

- Lowered the minimum supported Ruby version from `>= 3.4.0` to `>= 3.1`.
- Kept the Ruby 3.4+ optimized `rb_nogvl(..., RB_NOGVL_OFFLOAD_SAFE)` path intact.
- Added explicit native build probes for `ruby/thread.h`, `rb_thread_call_without_gvl`, and `rb_nogvl`.
- Ruby 3.1-3.3 now build the same selected `rb_nogvl` calls with a local `PQ_RB_NOGVL_OFFLOAD_SAFE` fallback of `0`, preserving ordinary no-GVL behavior without claiming scheduler offload guarantees.

### CI

- Added Ruby 3.1-3.3 compatibility coverage as compile + smoke checks while keeping full test coverage on Ruby 3.4 and 4.0.
- Scoped the strict Async/Fiber Scheduler integration assertion to Ruby 3.4+ so compatibility runtimes do not claim `RB_NOGVL_OFFLOAD_SAFE` behavior.
- Pinned the test-only `async` dependency to the Ruby 3.1-compatible `2.21.x` line, which still contains the worker-pool support needed for the Ruby 3.4+ offload test.

### Documentation

- Documented the Ruby 3.1+ support policy and the difference between compatibility no-GVL behavior and Ruby 3.4+ scheduler-aware offload.

## [0.5.2] - 2026-05-06

### Build

- Added Linux/OpenSSL discovery via `OPENSSL_ROOT_DIR`, `OPENSSL_DIR`, and `pkg-config`.
- Preserved `$(CFLAGS)`/`$(CCDLFLAGS)` for vendored native objects so Linux shared-object builds keep `-fPIC`.
- Added opt-in Linux x86_64 native-backend support through `PQCRYPTO_NATIVE_ASM=1`.
- Added x86_64 AVX2 vendor flags for mlkem-native/mldsa-native when native backends are explicitly enabled.
- Added separate `PQCRYPTO_NATIVE_ARITH` and `PQCRYPTO_NATIVE_FIPS202` switches for native arithmetic and Keccak/FIPS202 backends.
- Kept AArch64 native asm enabled by default; verified macOS arm64 still builds ML-KEM/ML-DSA native asm paths.

### CI

- Added a Linux native-backend job that compiles with `PQCRYPTO_NATIVE_ASM=1`, runs ML-KEM/ML-DSA smoke checks, and verifies AVX2 symbols in the extension.

## [0.5.1] - 2026-05-04

### Performance

- Enabled native asm/SIMD paths for ML-DSA/ML-KEM where available.
- Reduced Hybrid KEM X25519 overhead by reusing expanded/native key state and avoiding repeated private/public key reconstruction.
- Moved hot crypto calls under `rb_nogvl` where applicable.
- Optimized PEM export path by replacing BIO/streaming base64 with direct encode.
- Reduced small-buffer streaming overhead by avoiding unnecessary `malloc`/`nogvl` work for tiny chunks.

### Vendoring

- Committed `mlkem-native` and `mldsa-native` sources to the repository. Builds no longer require git or network.
- Pinned upstream by `commit` + `tree_sha256` in `script/vendor_libs.rb`; manifest signed with `manifest_sha256`.
- Deterministic vendor tree (no symlinks, dotfiles, normalized mtime/permissions).
- `script/vendor_libs.rb` now supports `--verify`, `--sync`, `--bump`.

### Build

- `extconf.rb` no longer auto-fetches upstream. Missing vendor aborts the build; opt in with `PQCRYPTO_AUTO_VENDOR=1`.

### Rakefile

- Added `vendor:verify`, `vendor:sync`, `vendor:bump`. Default task runs `vendor:verify` before `compile` and `test`.

### CI

- Added `vendor-verify` gating job; `vendor:verify` also runs in each test job before compile.

### Repository

- `.gitattributes` enforces `eol=lf` and marks vendor as binary (CRLF protection).
- `.gitignore` no longer hides `sempls/`.

## [0.5.0] - 2026-05-04

### Changed — native backend migration

- Replaced the PQClean runtime/build path with PQ Code Package `mlkem-native` and `mldsa-native` as the only ML-KEM / ML-DSA backend.
- Removed the PQClean fallback entirely so backend failures are attributable to the new native path instead of mixed old/new implementations.
- Updated the native extension build to require `ext/pqcrypto/vendor/mlkem-native/mlkem/mlkem_native.c` and `ext/pqcrypto/vendor/mldsa-native/mldsa/mldsa_native.c`.
- Changed vendoring and gem packaging to keep only a minimal PQ Code Package source snapshot, avoiding upstream examples and symlink-heavy trees in packaged gems.
- Switched native compilation to `-O3`; optional upstream native assembly remains opt-in through `PQCRYPTO_NATIVE_ASM=1`.
- `PQCrypto.backend` now reports `:native_pq_code_package`.

### Fixed

- Corrected deterministic ML-DSA test signing on `mldsa-native` by passing the FIPS 204 pure-mode domain-separation prefix (`00 00` for an empty context) into `signature_internal`. This restores deterministic round-trip verification and ML-DSA siggen KAT compatibility.

### Documentation

- Updated README, GET_STARTED, SECURITY, and migration notes for the native-only backend and the no-PQClean policy.
- Documented that `pqc_container_*` remains a compatibility serialization format while the cryptographic backend has moved to PQ Code Package native sources.

### Migration notes

- Source checkouts must refresh vendor sources with `bundle exec rake vendor` before compiling if `ext/pqcrypto/vendor/.vendored` is missing or stale.
- This release intentionally does not support falling back to PQClean. If native sources are absent or incompatible, the extension build fails early.

## [0.4.2] - 2026-04-29

### Fixed
- Fixed native extension build from packaged gem by keeping generated
  `pqcrypto_version.h` available after `make clean`.

## [0.4.1] — 2026-04-29

### Fixed

- Hardened native ML-DSA signing error handling by checking RNG failures.
- Improved streaming ML-DSA validation and context handling without regressing throughput.

## [0.4.0] — 2026-04-28

### Added — standard serialization and expanded parameter sets

- Added a central algorithm registry with legacy `pqc_container_*` OIDs kept separate from RFC 9935 / RFC 9881 standard OIDs.
- Added RFC 9935 SPKI public-key and PKCS#8 private-key support for ML-KEM.
- Added RFC 9881 SPKI public-key and expanded-key PKCS#8 support for ML-DSA.
- Added public API support for ML-KEM-512, ML-KEM-1024, ML-DSA-44, and ML-DSA-87 alongside the existing ML-KEM-768 and ML-DSA-65 support.
- Added OpenSSL 3.5+ interoperability tests for standard SPKI / PKCS#8 encodings where supported by the linked OpenSSL.
- Added NIST ACVP KAT test infrastructure for ML-KEM and ML-DSA parameter sets.
- Added opt-in ML-DSA seed/both PKCS#8 import support. The default remains off; callers must set `PQCrypto::PKCS8.allow_ml_dsa_seed_format = true`.

### Changed

- Bumped the gem version to `0.4.0`.
- `pqc_container_*` remains frozen and project-local. It is still limited to the original three algorithms: `:ml_kem_768`, `:ml_dsa_65`, and `:ml_kem_768_x25519_xwing`.
- `DETAILS[:oid]` continues to expose the legacy `pqc_container_*` OID for backward compatibility. Standard OIDs are available via `PQCrypto::AlgorithmRegistry.standard_oid`.
- The native `PQCrypto.version` path now derives from `lib/pq_crypto/version.rb` through a generated C header, avoiding a second manually maintained version string.

### Security notes

- ML-DSA seed-format imports are opt-in because PQClean does not expose a public ML-DSA derandomized keypair entrypoint. The implementation reuses the thread-local seed-replay path documented in `SECURITY.md`.
- The project remains unaudited and experimental.

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
