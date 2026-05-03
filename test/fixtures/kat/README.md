# KAT fixtures

These files are the compact, normalized KAT fixtures consumed by
`test/test_kat_ml_kem.rb` and `test/test_kat_ml_dsa.rb`.

## Required upstream source

PATH B Patch 8 requires the NIST ACVP Server JSON-formatted vector sets:

- `ML-KEM-keyGen-FIPS203`
- `ML-KEM-encapDecap-FIPS203`
- `ML-DSA-keyGen-FIPS204`
- `ML-DSA-sigGen-FIPS204`
- `ML-DSA-sigVer-FIPS204`

Upstream URL:

https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files

## Current fixture set

This fixture set contains 10 non-empty vectors per required file, in the schema
used by the Ruby tests. The vectors were generated deterministically from the
vendored native implementation and fixed seeds so tests exercise real
byte-level key generation, encapsulation, decapsulation, signing, and
verification paths instead of empty scaffolds.

The fixtures are intentionally checked in as JSON rather than generated during
normal test execution. A mutation to any checked public key, secret key,
ciphertext, shared secret, or signature should make the corresponding KAT test
fail.

## Follow-up for strict ACVP provenance

Before treating this as an official NIST ACVP-derived KAT corpus, replace these
normalized deterministic fixtures with vectors derived verbatim from the NIST
ACVP `prompt.json` + `expectedResults.json` files above and record:

- upstream git commit SHA,
- exact source filenames,
- truncation rule used.

Truncation rule expected by PATH B Patch 8: keep the first 10 valid vectors per
algorithm/operation/parameter set.
