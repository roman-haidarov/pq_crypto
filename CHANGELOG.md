# Changelog

## [0.6.7] - 2026-08-10

### Fixed

- **DER parsers could raise exceptions outside the `PQCrypto::Error` hierarchy.**
  `OpenSSL::ASN1.decode` raises more than `OpenSSL::ASN1::ASN1Error`, and
  re-encoding a successfully decoded object can fail as well. Three shapes
  escaped the previous handling in `PQCrypto::SPKI`:

  - `"\x0A\x01\xFF"` (ENUMERATED) raised `OpenSSL::OpenSSLError`
  - `"\x17\x00"` / `"\x18\x00"` (empty UTCTIME / GENERALIZEDTIME) raised `TypeError`
  - `"\x10\x00"` (universal SEQUENCE tag without the constructed bit) decoded
    cleanly but raised `TypeError` from the `to_der` round trip used for the
    trailing-data check

  `TypeError` does not descend from `OpenSSL::OpenSSLError`, so widening the
  rescue to the OpenSSL base class alone was not sufficient. Both rescue sites
  now catch `OpenSSL::OpenSSLError, TypeError`, and `SPKI.decode_der` is guarded
  end to end rather than only around the decode call.

  Impact: code written as `rescue PQCrypto::Error` around key loading could be
  bypassed by malformed input. No memory-safety consequence. Covered by a
  systematic tag sweep over 1,280 DER shapes × three entry points
  (`Key.from_der`, `SPKI.decode_der`, `PKCS8.decode_der`).

### Added

- **FIPS 203 key validation for ML-KEM (boundary diagnostics).** mlkem-native
  v2 exposes `check_pk` and `check_sk`, which this gem did not use. Both are
  now wired in and run when a `PQCrypto::KEM::PublicKey` or `SecretKey` is
  constructed:

  - public keys get the Section 7.2 modulus check (coefficients in `[0,q-1]`)
  - secret keys get the Section 7.3 hash check (`H(pk)` embedded in the sk)

  Scope limits (intentional, matching FIPS 203):

  - these checks are **diagnostics at import**, not a substitute for the
    checks already performed inside encapsulation / decapsulation
  - Section 7.3 does **not** detect a corrupted IND-CPA secret (`dk`) when
    the embedded `H(pk)` is still intact — `#valid?` can still be true
  - X-Wing public keys validate only the ML-KEM-768 half; the X25519 half is
    unrestricted. X-Wing secret keys are 32-byte seeds and are not structure-
    checked

  `#valid?` is exposed on both key classes. Failures raise
  `PQCrypto::InvalidKeyError`. Public-key internal buffers are frozen after
  construction to block post-validation mutation; secret-key buffers stay
  mutable so `#wipe!` can still zero them in place.

  New C API: `pq_mlkem{,512,1024}_check_public_key` / `_check_secret_key`,
  plus `PQ_ERROR_INVALID_PUBLIC_KEY` (-11) and `PQ_ERROR_INVALID_SECRET_KEY`
  (-12). Upstream OOM (`-2`) is mapped to `PQ_ERROR_NOMEM` rather than
  “invalid key”.

- **ML-DSA secret-key structure check on import.** Expanded ML-DSA secret
  keys are validated via upstream `pk_from_sk` (coefficient norms, recomputed
  `t0`, and `tr = H(pk)`). This matches the check mldsa-native documents for
  importers and is enforced on `Signature::SecretKey` construction with
  `#valid?` exposed. Public keys remain length-checked only (FIPS 204 has no
  ML-KEM-style modulus check for the public key).

  The check runs on import only. Keys produced by this process's own key
  generation are valid by construction, and `pk_from_sk` re-derives the public
  key, so validating them would roughly double the cost of every ML-DSA
  keypair. Upstream also documents `pk_from_sk` as leaking secret-key validity
  through its return value and timing.

  New C API: `pq_mldsa{,44,87}_check_secret_key`.

- **`PQCRYPTO_KEYGEN_PCT=1` build option.** Enables the FIPS 140-3 pairwise
  consistency test in both backends (`MLK_CONFIG_KEYGEN_PCT` /
  `MLD_CONFIG_KEYGEN_PCT`): after generating a keypair it is exercised to catch
  a faulty RNG or memory corruption at generation time. Upstream ships this
  opt-in because it makes key generation noticeably more expensive, and it stays
  opt-in here for the same reason. The selected setting is reported in the
  build configuration banner.

- **`require_encrypted:` for PKCS#8 loading.** Supplying a passphrase states an
  expectation that the key at rest is encrypted, but an unencrypted
  PrivateKeyInfo was previously accepted and the passphrase left unused. An
  encrypted key file replaced with a plaintext one therefore loaded without
  complaint.

  `require_encrypted: true` enforces that the input is an
  EncryptedPrivateKeyInfo (DER content, not PEM label — relabeling a plaintext
  key as `ENCRYPTED PRIVATE KEY` does not satisfy the policy). Available on
  `PKCS8.decode_der` / `decode_pem`, `Key.from_der` / `from_pem`, and
  `secret_key_from_pkcs8_der` / `_pem` on both `KEM` and `Signature`.

  Limits (documented so the flag is not over-read):

  - default is `false`; other loaders (`from_bytes`, `pqc_container_*`) are
    unchanged
  - the flag checks **format**, not passphrase strength (empty passphrase and
    low PBKDF iterations still count as encrypted)
  - the value must be a real boolean (`true`/`false`); strings like `"false"`
    raise `ArgumentError` instead of being treated as truthy

## [0.6.6] - 2026-08-10

### Changed

- update native mlkem `v1.3.0` -> `v2.0.0` and mldsa `v1.0.0-beta2` -> `v2.0.0`

  `mldsa-native` v2.0.0 is that project's first stable release; it is numbered
  `2` only to align its API and configuration with `mlkem-native` v2. Upstream
  now guarantees that non-experimental APIs and configuration options stay
  stable until a `v3`.

  No cryptographic output changed. All six `kat-sha256` values in the upstream
  `META.yml` files are identical to the previously vendored versions, and the
  vendored ML-KEM-768 keygen, ML-DSA-65 keygen and ML-DSA-65 siggen KAT vectors
  reproduce byte-for-byte. This release is purely an API migration.

### Breaking upstream changes handled

- **`siglen` removed from the ML-DSA signing and verification APIs.** Upstream
  signatures are always exactly `MLDSA_BYTES(level)`, so `signature`,
  `signature_internal`, `verify`, `signature_extmu` and `verify_extmu` no longer
  carry a length parameter. Fifteen declarations in
  `ext/pqcrypto/pqcrypto_native_api.h` were updated accordingly.

  The `pq_crypto` C API is deliberately *not* changed to match: `pq_sign`,
  `pq_verify`, `pq_sign_mu` and `pq_verify_mu` keep their length parameters.
  The adaptation happens at the vendor boundary instead.

- **`pq_crypto` now owns the signing output length.** Because the backend no
  longer reports it, every signing wrapper sets `*signature_len` itself from a
  compile-time constant and clears it to `0` when the signing operation fails,
  reproducing the pre-v2 behaviour. This affects `pq_sign`, `pq_mldsa44_sign`,
  `pq_mldsa87_sign`, the level-agnostic deterministic helper
  `pq_testing_mldsa_sign_from_seed_with`, and `pq_sign_mu`.

  Argument-validation failures (`PQ_ERROR_BUFFER`) still leave `*signature_len`
  untouched, exactly as before, since the pointer itself may be the invalid one.

- **`pq_crypto` now validates signature length before verifying (security
  relevant).** Prior to v2, `mldsa-native` rejected a wrongly sized signature
  itself via `if (siglen != MLDSA_BYTES) return -1;`, and `pq_crypto` relied on
  that. In v2 the verification entry points take a fixed-size array and read
  `MLDSA_BYTES(level)` bytes unconditionally, so a short caller-supplied buffer
  would be an out-of-bounds read. `pq_verify`, `pq_mldsa44_verify` and
  `pq_mldsa87_verify` now enforce the exact length and return `PQ_ERROR_VERIFY`
  otherwise; the Ruby bindings additionally reject the wrong length before
  copying the buffer.

  This was not exploitable in 0.6.5 or earlier: the previously vendored
  `mldsa-native` performed the check. It is a latent contract dependency that a
  naive port to v2 would have turned into a real memory-safety bug. Verified
  with AddressSanitizer: removing this check alone reproduces a
  `heap-buffer-overflow` read inside `pqcr_mldsa65_verify_internal`.

  Observable Ruby behaviour is unchanged: a wrongly sized signature is a failed
  verification (`false`), never an `ArgumentError`.

- **ExternalMu callbacks adapted rather than re-typed.** Six new adapters,
  `pq_mldsa{44,65,87}_{signature,verify}_extmu_compat`, sit between the
  pre-v2 callback contract and the fixed-size v2 API. `pq_sign_mu` and
  `pq_verify_mu` therefore keep their existing signatures and no consumer of the
  C interface has to change.

- **`MLK_CONFIG_NO_SUPERCOP` / `MLD_CONFIG_NO_SUPERCOP` removed upstream**
  along with the SUPERCOP `crypto_*` aliases themselves. The define is no longer
  passed by `extconf.rb`. Upstream has no guard against the stale macro, so it
  would have been a silently dead `-D` rather than a build failure.

- **Legacy `MLK_CONFIG_API_*` / `MLD_CONFIG_API_*` configuration removed
  upstream.** The extension build already used the modern `*_CONFIG_*` macros;
  only `test/native_api_conformance` still used the legacy path and has been
  converted.

Upstream breaking changes that do not affect this gem, checked explicitly: the
SUPERCOP `crypto_*` and signed-message APIs (never used), the split of
`*_ERR_FAIL` into specific error codes (all call sites compare against `0`), the
`*_SYS_CAP_*` and `*_USE_NATIVE_FIPS202_*` renames (only relevant to custom
backends), and the raised `MLD_CONFIG_MAX_SIGNING_ATTEMPTS` floor of 821, which
this build does not set. `MLD_CONFIG_KEYGEN_PCT` / `MLK_CONFIG_KEYGEN_PCT`
remain opt-in upstream and are not enabled here, so key generation gains no new
failure mode or cost.

### Testing

- `test/native_api_conformance` reworked. It previously proved size agreement
  via `_Static_assert` and, through the double declaration of upstream and
  gem headers, prototype agreement. It could not detect a symbol that upstream
  removed entirely, because it only ever compiled to an object file and both a
  plain compile and a relocatable link tolerate unresolved symbols. The harness
  now also builds the vendored objects with the same flags `extconf.rb` uses
  (including which level owns the shared code) and diffs `nm -u` on the probe
  object against the symbols the vendored build actually defines.

- Conformance now covers `pqcr_mlkem_shake256` and `pqcr_mlkem_sha3_256`, the
  extension's only dependency on a non-public part of `mlkem-native` (they back
  the X-Wing key expansion and combiner). They were absent from `probes[]`
  entirely, and because they are not declared in `mlkem_native.h` the
  double-declaration check could not reach them either. The shared-level
  conformance unit now includes the internal `src/fips202/fips202.h` so that
  prototype drift in these two is caught as well.

- Added `test/c_api`, direct tests for the `pq_crypto` C API, runnable under
  AddressSanitizer via `PQCRYPTO_SANITIZE=address test/c_api/run.sh`. The Ruby
  bindings pre-set `call.signature_len` before invoking the signing entry points
  and read the same field back afterwards, so a wrapper that stopped writing
  `*signature_len` would leave the entire Ruby suite green. That contract, and
  the new signature-length validation, now have coverage that does not go
  through Ruby.

- `rake test` now runs the native API conformance and C API checks alongside the
  Ruby suite.

- The C API tests were themselves audited by mutation testing: each contract
  this release changes was deliberately broken in turn and the suite had to
  fail. That found three checks which passed against broken code and have been
  rewritten:

  - The ML-DSA-44 output-length check was phrased as "signing failed OR the
    length is right" and reused the ML-DSA-65 secret key, so a
    `pq_mldsa44_sign` that always returned an error satisfied it. ML-DSA-44 and
    -87 now have their own key material and unconditional assertions.
  - The ExternalMu failure check used a stub callback that cleared `*siglen`
    itself, so it passed even when the real adapter had stopped doing so. It now
    drives the genuine backend error path by exhausting the thread-local test
    seed in `pq_randombytes.c`, which makes `randombytes()` fail. The same
    technique gives `pq_sign` real coverage of its own error path.
  - The verify adapters' length guards were unreachable through `pq_verify_mu`,
    which validates the length first, so they were never exercised. They are now
    called directly.

  Two further gaps were closed: `pq_sign`'s recovery after a transient RNG
  failure is now asserted, and a poisoned `*signature_len` that was set but
  never checked is now checked.

## [0.6.5] - 2026-08-04

### Changed

- update native mlkem `v1.2.0` -> `v1.3.0`

  Upstream is a feature/integration release with no security fixes and no
  changes to the ML-KEM algorithm implementation. Everything relevant to this
  gem is unchanged: the exported symbol set, all key/ciphertext/shared-secret
  sizes, and the derived key material for ML-KEM-512/768/1024 (verified
  byte-for-byte against `v1.2.0` for both the portable and the AVX2 build,
  including the implicit-rejection path and the SHAKE256/SHA3-256 helpers used
  by the X-Wing combiner).

  What upstream changed that is visible in the vendored tree:
  - new opt-in `MLK_CONFIG_NO_{KEYPAIR,ENCAPS,DECAPS}_API` build options; the
    gem needs all three operations and does not set them
  - the AArch64 arithmetic and FIPS-202 backends are now gated on compile-time
    NEON availability (`MLK_SYS_AARCH64_NEON`) and on the new `MLK_SYS_CAP_NEON`
    runtime capability, which defaults to "available"
  - new opt-in `MLK_SYS_AARCH64_FAST_SHA3` for CPUs with high SHA3 throughput
  - backend assembly files renamed with an `mlkem_` prefix and assembly-local
    labels namespaced with `mlk_`; both are internal to the vendored aggregator
    `mlkem_native_asm.S` and transparent to this build
  - context-parameter machinery moved into the new `mlkem/src/context.h`

  Note that `mlkem-native` v1.3.0 is the last release before a breaking v2;
  `release/v1.3` is the upstream support branch.

- `mldsa-native` remains pinned at `v1.0.0-beta2`, which is still the latest
  upstream tag.

### Testing

- Added `test/native_api_conformance`, a compile-only check that validates the
  hand-written declarations in `ext/pqcrypto/pqcrypto_native_api.h` against the
  vendored upstream headers. The extension deliberately never includes
  `mlkem_native.h` / `mldsa_native.h`, so nothing else in the build could catch
  size or prototype drift after a vendor bump.

### CI

- Run the native API conformance check right after `vendor:verify`.
- Verify that the AArch64 assembly backends are actually compiled in on
  macOS ARM runners, and smoke-test ML-KEM and ML-DSA against that build.

## [0.6.4] - 2026-07-18

### Compatibility

- Lowered the minimum supported Ruby version from `>= 3.1` to `>= 2.7.1`.
- Kept the Ruby 3.4+ scheduler-aware `RB_NOGVL_OFFLOAD_SAFE` path unchanged.
- Ruby 2.7.1-3.3 use the existing no-GVL compatibility path without claiming Fiber Scheduler offload guarantees.
- Made the test-only `async` dependency conditional so development dependencies resolve on Ruby 2.7.1.

### CI

- Added an Ubuntu Ruby 2.7 compatibility job on Ruby 2.7.2, including the full test suite and a built-gem install smoke test. Ruby 2.7.1 remains the declared floor; the hosted Linux job uses 2.7.2 because exact 2.7.1 is not available through the runner toolchain.

### Build

- Fixed OpenSSL 3 discovery on Intel and Apple Silicon macOS by resolving the Homebrew `openssl@3` prefix dynamically.
- Ignore stale OpenSSL 1.1 `pkg-config` metadata instead of injecting incompatible headers into native builds.
- Validate the selected OpenSSL prefix and link against the OpenSSL 3 API during configuration, preventing mixed headers/library builds.
- Link the validated OpenSSL libraries by absolute path, preventing Ruby 2.7 Linux toolchains from selecting their bundled OpenSSL 1.1 while preserving mkmf's libruby-safe default path precedence.
- Prefer Linux multiarch OpenSSL library directories over generic `lib` directories when resolving an explicit installation prefix.
- Avoid Clang macro-expansion warnings on Ruby 2.7 by using the function-form `rb_intern2` API without changing symbol semantics.
- Remove only Ruby 2.7's obsolete macOS `-multiply_defined,suppress` linker option, preserving all other inherited linker flags including `-undefined,dynamic_lookup`.

### Documentation

- Documented the Ruby 2.7.1+ support policy and the concurrency guarantees for compatibility runtimes.

## [0.6.3] - 2026-06-24

### Changed
- update native mlkem `v1.1.0` → `v1.2.0` (new PowerPC backend, Windows/RISC-V portability, 16-bit `int` UB fix; public API unchanged)

## [0.6.2] - 2026-05-24

### Changed
- update native mldsa `v1.0.0-beta` → `v1.0.0-beta2`

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
