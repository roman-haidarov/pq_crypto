# Usage, from the repository root:
#   test/native_api_conformance/run.sh
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${HERE}/../.." && pwd)"
EXT="${ROOT}/ext/pqcrypto"
MLKEM="${EXT}/vendor/mlkem-native/mlkem"
MLDSA="${EXT}/vendor/mldsa-native/mldsa"
CC="${CC:-cc}"

for dir in "${MLKEM}" "${MLDSA}"; do
  if [ ! -d "${dir}" ]; then
    echo "missing vendored sources: ${dir}" >&2
    echo "run: bundle exec rake vendor:sync" >&2
    exit 1
  fi
done

WARN=(-std=c11 -Wall -Wextra -Werror -Wno-array-parameter)

workdir="$(mktemp -d)"
trap 'rm -rf "${workdir}"' EXIT

for level in 512 768 1024; do
  "${CC}" "${WARN[@]}" -c "${HERE}/conf_mlkem.c" \
    -DLEVEL="${level}" \
    -DMLK_CONFIG_API_NAMESPACE_PREFIX="pqcr_mlkem${level}" \
    -I"${MLKEM}" -I"${EXT}" \
    -o "${workdir}/conf_mlkem_${level}.o"
  echo "ml-kem-${level}: pqcrypto_native_api.h matches upstream"
done

for level in 44 65 87; do
  "${CC}" "${WARN[@]}" -c "${HERE}/conf_mldsa.c" \
    -DMLD_CONFIG_API_PARAMETER_SET="${level}" \
    -DMLD_CONFIG_API_NAMESPACE_PREFIX="pqcr_mldsa${level}" \
    -I"${MLDSA}" -I"${EXT}" \
    -o "${workdir}/conf_mldsa_${level}.o"
  echo "ml-dsa-${level}: pqcrypto_native_api.h matches upstream"
done

echo "native API conformance: ok"
