# Fuzz notes

Do not commit generated fuzz outputs.

Ignored local paths:

- `fuzz/build/`
- `fuzz/corpus/`
- `fuzz/findings/`
- `fuzz/runs/`

Recommended local run:

```sh
./fuzz/run_all.sh
```

Useful knobs:

```sh
PQCRYPTO_FUZZ_MAX_TOTAL_TIME=300
PQCRYPTO_FUZZ_MAX_LEN=16384
PQCRYPTO_FUZZ_OUT=/tmp/pq_crypto_fuzz_findings
PQCRYPTO_FUZZ_RUNS=/tmp/pq_crypto_fuzz_runs
```

One target:

```sh
./fuzz/run_one.sh pkcs8_pem_to_der
```

The libFuzzer build must instrument the extension objects with
`fuzzer-no-link,address,undefined`; otherwise coverage may only include the tiny
harness and not the parser code.


Noise controls:

```sh
# compact libFuzzer output, default
PQCRYPTO_FUZZ_VERBOSITY=0 ./fuzz/run_all.sh

# full libFuzzer progress and build logs
PQCRYPTO_FUZZ_VERBOSITY=1 PQCRYPTO_FUZZ_VERBOSE=1 ./fuzz/run_all.sh
```
