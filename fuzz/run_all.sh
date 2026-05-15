#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
IMAGE="${PQCRYPTO_FUZZ_IMAGE:-pq_crypto-libfuzzer}"
OUT="${PQCRYPTO_FUZZ_OUT:-${TMPDIR:-/tmp}/pq_crypto_fuzz_findings}"
RUNS="${PQCRYPTO_FUZZ_RUNS:-${TMPDIR:-/tmp}/pq_crypto_fuzz_runs}"
MAX_TOTAL_TIME="${PQCRYPTO_FUZZ_MAX_TOTAL_TIME:-300}"
MAX_LEN="${PQCRYPTO_FUZZ_MAX_LEN:-16384}"
VERBOSITY="${PQCRYPTO_FUZZ_VERBOSITY:-0}"

mkdir -p "$OUT" "$RUNS"

echo "[fuzz] repo:     $ROOT"
echo "[fuzz] image:    $IMAGE"
echo "[fuzz] findings: $OUT"
echo "[fuzz] logs:     $RUNS"

docker build -f "$ROOT/fuzz/Dockerfile" -t "$IMAGE" "$ROOT"

docker run --rm \
  -e PQCRYPTO_FUZZ_MAX_TOTAL_TIME="$MAX_TOTAL_TIME" \
  -e PQCRYPTO_FUZZ_MAX_LEN="$MAX_LEN" \
  -e PQCRYPTO_FUZZ_JOBS="${PQCRYPTO_FUZZ_JOBS:-2}" \
  -e PQCRYPTO_FUZZ_VERBOSE="${PQCRYPTO_FUZZ_VERBOSE:-0}" \
  -e PQCRYPTO_FUZZ_VERBOSITY="$VERBOSITY" \
  -v "$ROOT:/src_ro:ro" \
  -v "$OUT:/out" \
  -v "$RUNS:/runs" \
  "$IMAGE" bash -lc '
set -euo pipefail

rm -rf /work
cp -a /src_ro /work
cd /work

./fuzz/generate_corpus.sh
PQCRYPTO_FUZZ_EXT_SANITIZE="fuzzer-no-link,address,undefined" ./fuzz/build.sh

BUILD_DIR="${PQCRYPTO_FUZZ_WORKDIR:-${TMPDIR:-/tmp}/pq_crypto_fuzz}/build"
status=0

for target in pkcs8_private_key_info_from_der pkcs8_pem_to_der pkcs8_decrypt_private_key_info_der pqc_container_from_der; do
  echo
  echo "============================================================"
  echo "=== fuzzing ${target} ==="
  echo "============================================================"

  log="/runs/${target}.log"
  set +e
  "${BUILD_DIR}/fuzz_${target}" "fuzz/corpus/${target}" \
    -max_total_time="${PQCRYPTO_FUZZ_MAX_TOTAL_TIME}" \
    -max_len="${PQCRYPTO_FUZZ_MAX_LEN}" \
    -verbosity="${PQCRYPTO_FUZZ_VERBOSITY}" \
    -artifact_prefix="/out/${target}-" \
    -print_final_stats=1 2>&1 | tee "$log"
  rc=${PIPESTATUS[0]}
  set -e

  if [[ $rc -ne 0 ]]; then
    echo "[fuzz] ${target} exited with status ${rc}" | tee -a "$log"
    status=1
  fi

done

echo
echo "=== crash artifacts / findings ==="
ls -la /out || true
exit "$status"
'

echo "[fuzz] done"
echo "[fuzz] findings: $OUT"
echo "[fuzz] logs: $RUNS"
