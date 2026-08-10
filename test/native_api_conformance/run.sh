# Usage, from the repository root:
#   test/native_api_conformance/run.sh
#
# Checks that ext/pqcrypto/pqcrypto_native_api.h still agrees with the vendored
# PQ Code Package sources, on three axes:
#
#   sizes      -- _Static_assert in the conformance units
#   prototypes -- upstream header and ours both declare the same symbols, so a
#                 signature change is a compile error
#   existence  -- probes[] leaves an undefined reference per depended-on symbol;
#                 we diff those against what the vendored build actually
#                 defines, which catches a symbol removed upstream. A plain
#                 compile cannot catch that, and a relocatable link would not
#                 either, since both tolerate unresolved symbols.
#
# The vendor objects are built with exactly the flags extconf.rb uses, including
# which level owns the shared code, so the symbol sets line up.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${HERE}/../.." && pwd)"
EXT="${ROOT}/ext/pqcrypto"
MLKEM="${EXT}/vendor/mlkem-native/mlkem"
MLDSA="${EXT}/vendor/mldsa-native/mldsa"
CC="${CC:-cc}"
NM="${NM:-nm}"

for dir in "${MLKEM}" "${MLDSA}"; do
  if [ ! -d "${dir}" ]; then
    echo "missing vendored sources: ${dir}" >&2
    echo "run: bundle exec rake vendor:sync" >&2
    exit 1
  fi
done

WARN=(-std=c11 -Wall -Wextra -Werror -Wno-array-parameter)
# The vendored sources are third-party; build them with the same warning
# suppressions extconf.rb applies rather than -Werror.
VENDOR_QUIET=(-std=c11 -w)

workdir="$(mktemp -d)"
trap 'rm -rf "${workdir}"' EXIT

# Mirrors the shared/no-shared split in extconf.rb: exactly one level per
# library owns the shared code.
shared_flag() {
  case "$1" in
    512|44) echo "-D$2_CONFIG_MULTILEVEL_WITH_SHARED" ;;
    *)      echo "-D$2_CONFIG_MULTILEVEL_NO_SHARED" ;;
  esac
}

check_symbols() {
  local label="$1" probe_obj="$2" vendor_obj="$3"
  "${NM}" -u "${probe_obj}" | awk '{print $NF}' | sort -u > "${workdir}/need"
  "${NM}" --defined-only "${vendor_obj}" | awk '{print $NF}' | sort -u > "${workdir}/have"
  local missing
  missing="$(comm -23 "${workdir}/need" "${workdir}/have" || true)"
  if [ -n "${missing}" ]; then
    echo "${label}: symbols required by pqcrypto_native_api.h are not defined by the vendored build:" >&2
    echo "${missing}" | sed 's/^/  /' >&2
    exit 1
  fi
}

for level in 512 768 1024; do
  common=(
    -DMLK_CONFIG_MULTILEVEL_BUILD
    -DMLK_CONFIG_PARAMETER_SET="${level}"
    -DMLK_CONFIG_NAMESPACE_PREFIX=pqcr_mlkem
    "$(shared_flag "${level}" MLK)"
  )

  "${CC}" "${WARN[@]}" "${common[@]}" \
    -c "${HERE}/conf_mlkem.c" \
    -I"${MLKEM}" -I"${EXT}" \
    -o "${workdir}/conf_mlkem_${level}.o"

  "${CC}" "${VENDOR_QUIET[@]}" "${common[@]}" \
    -c "${MLKEM}/mlkem_native.c" \
    -I"${MLKEM}" \
    -o "${workdir}/vendor_mlkem_${level}.o"

  check_symbols "ml-kem-${level}" \
    "${workdir}/conf_mlkem_${level}.o" "${workdir}/vendor_mlkem_${level}.o"

  echo "ml-kem-${level}: pqcrypto_native_api.h matches upstream"
done

for level in 44 65 87; do
  common=(
    -DMLD_CONFIG_MULTILEVEL_BUILD
    -DMLD_CONFIG_PARAMETER_SET="${level}"
    -DMLD_CONFIG_NAMESPACE_PREFIX=pqcr_mldsa
    "$(shared_flag "${level}" MLD)"
  )

  "${CC}" "${WARN[@]}" "${common[@]}" \
    -c "${HERE}/conf_mldsa.c" \
    -I"${MLDSA}" -I"${EXT}" \
    -o "${workdir}/conf_mldsa_${level}.o"

  "${CC}" "${VENDOR_QUIET[@]}" "${common[@]}" \
    -c "${MLDSA}/mldsa_native.c" \
    -I"${MLDSA}" \
    -o "${workdir}/vendor_mldsa_${level}.o"

  check_symbols "ml-dsa-${level}" \
    "${workdir}/conf_mldsa_${level}.o" "${workdir}/vendor_mldsa_${level}.o"

  echo "ml-dsa-${level}: pqcrypto_native_api.h matches upstream"
done

echo "native API conformance: ok"
