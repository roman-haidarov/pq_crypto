# Usage, from the repository root:
#   test/c_api/run.sh
#   PQCRYPTO_SANITIZE=address test/c_api/run.sh

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

SAN=()
if [ -n "${PQCRYPTO_SANITIZE:-}" ]; then
  SAN=(-fsanitize="${PQCRYPTO_SANITIZE}" -g -O1 -fno-omit-frame-pointer)
else
  SAN=(-O2)
fi

SSL_INC=()
SSL_LIB=()
if [ -n "${OPENSSL_ROOT_DIR:-}" ]; then
  SSL_INC=(-I"${OPENSSL_ROOT_DIR}/include")

  for d in "${OPENSSL_ROOT_DIR}"/lib "${OPENSSL_ROOT_DIR}"/lib64 \
           "${OPENSSL_ROOT_DIR}"/lib/*-linux-gnu; do
    [ -d "${d}" ] && SSL_LIB+=(-L"${d}")
  done
elif command -v pkg-config >/dev/null 2>&1 && pkg-config --exists openssl; then
  read -r -a SSL_INC <<< "$(pkg-config --cflags openssl)"
  read -r -a SSL_LIB <<< "$(pkg-config --libs-only-L openssl)"
fi

workdir="$(mktemp -d)"
trap 'rm -rf "${workdir}"' EXIT

for level in 512 768 1024; do
  if [ "${level}" = "512" ]; then shared=WITH; else shared=NO; fi
  "${CC}" -std=c11 -w "${SAN[@]}" \
    -DMLK_CONFIG_MULTILEVEL_BUILD -DMLK_CONFIG_PARAMETER_SET="${level}" \
    -DMLK_CONFIG_NAMESPACE_PREFIX=pqcr_mlkem -DMLK_CONFIG_MULTILEVEL_${shared}_SHARED \
    -I"${MLKEM}" -c "${MLKEM}/mlkem_native.c" -o "${workdir}/mlkem_${level}.o"
done

for level in 44 65 87; do
  if [ "${level}" = "44" ]; then shared=WITH; else shared=NO; fi
  "${CC}" -std=c11 -w "${SAN[@]}" \
    -DMLD_CONFIG_MULTILEVEL_BUILD -DMLD_CONFIG_PARAMETER_SET="${level}" \
    -DMLD_CONFIG_NAMESPACE_PREFIX=pqcr_mldsa -DMLD_CONFIG_MULTILEVEL_${shared}_SHARED \
    -I"${MLDSA}" -c "${MLDSA}/mldsa_native.c" -o "${workdir}/mldsa_${level}.o"
done

"${CC}" -std=c11 -Wall -Wextra "${SAN[@]}" \
  -DHAVE_OPENSSL_EVP_H -DHAVE_OPENSSL_RAND_H \
  "${SSL_INC[@]}" -I"${EXT}" -I"${MLKEM}" -I"${MLDSA}" \
  "${HERE}/test_c_api.c" \
  "${EXT}/pqcrypto_secure.c" "${EXT}/pq_externalmu.c" "${EXT}/pq_randombytes.c" \
  "${workdir}"/mlkem_*.o "${workdir}"/mldsa_*.o \
  "${SSL_LIB[@]}" -lcrypto \
  -o "${workdir}/test_c_api"

"${workdir}/test_c_api"
echo "c api tests: ok"
