# NIST ACVP KAT fixtures

Source required by PATH B Patch 8: NIST ACVP Server JSON files:
https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files

Required upstream directories:

- `ML-KEM-keyGen-FIPS203`
- `ML-KEM-encapDecap-FIPS203`
- `ML-DSA-keyGen-FIPS204`
- `ML-DSA-sigGen-FIPS204`
- `ML-DSA-sigVer-FIPS204`

Upstream git commit SHA at fixture fetch time: `TODO-FETCH-FROM-NIST-ACVP-SERVER`.

Truncation rule: keep the first 10 valid vectors per parameter set and preserve all
hex values verbatim. The checked-in JSON files intentionally use a small normalized
schema consumed by `test/test_kat_ml_kem.rb` and `test/test_kat_ml_dsa.rb`.

NOTE: In this workspace the upstream ACVP JSON could not be downloaded, so the JSON
files are seed-only scaffolds. Replace them with verbatim-derived ACVP vectors before
merging Patch 8.
