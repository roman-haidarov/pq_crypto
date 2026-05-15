#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <target>" >&2
  echo "targets: pkcs8_private_key_info_from_der pkcs8_pem_to_der pkcs8_decrypt_private_key_info_der pqc_container_from_der" >&2
  exit 64
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
TARGET="$1"
IMAGE="${PQCRYPTO_FUZZ_IMAGE:-pq_crypto-libfuzzer}"
OUT="${PQCRYPTO_FUZZ_OUT:-${TMPDIR:-/tmp}/pq_crypto_fuzz_findings}"
RUNS="${PQCRYPTO_FUZZ_RUNS:-${TMPDIR:-/tmp}/pq_crypto_fuzz_runs}"
MAX_TOTAL_TIME="${PQCRYPTO_FUZZ_MAX_TOTAL_TIME:-300}"
MAX_LEN="${PQCRYPTO_FUZZ_MAX_LEN:-16384}"
VERBOSITY="${PQCRYPTO_FUZZ_VERBOSITY:-0}"

mkdir -p "$OUT" "$RUNS"
docker build -f "$ROOT/fuzz/Dockerfile" -t "$IMAGE" "$ROOT"

docker run --rm \
  -e TARGET="$TARGET" \
  -e PQCRYPTO_FUZZ_MAX_TOTAL_TIME="$MAX_TOTAL_TIME" \
  -e PQCRYPTO_FUZZ_MAX_LEN="$MAX_LEN" \
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
"${BUILD_DIR}/fuzz_${TARGET}" "fuzz/corpus/${TARGET}" \
  -max_total_time="${PQCRYPTO_FUZZ_MAX_TOTAL_TIME}" \
  -max_len="${PQCRYPTO_FUZZ_MAX_LEN}" \
  -verbosity="${PQCRYPTO_FUZZ_VERBOSITY}" \
  -artifact_prefix="/out/${TARGET}-" \
  -print_final_stats=1 2>&1 | tee "/runs/${TARGET}.log"
ls -la /out || true
'
