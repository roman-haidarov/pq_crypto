#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
EXT_SRC_DIR="$ROOT/ext/pqcrypto"
LIB_SRC_DIR="$ROOT/lib"

raw_workdir="${PQCRYPTO_FUZZ_WORKDIR:-${TMPDIR:-/tmp}/pq_crypto_fuzz}"
mkdir -p "$(dirname "$raw_workdir")"
WORKDIR="$(cd "$(dirname "$raw_workdir")" && pwd -P)/$(basename "$raw_workdir")"
EXT_BUILD_DIR="$WORKDIR/ext/pqcrypto"
BUILD_DIR="$WORKDIR/build"

if [[ "$WORKDIR" == "$ROOT" || "$WORKDIR" == "$ROOT/"* ]]; then
  echo "[fuzz] refusing to use a workdir inside the repository: $WORKDIR" >&2
  echo "[fuzz] set PQCRYPTO_FUZZ_WORKDIR to a path under /tmp or \$TMPDIR" >&2
  exit 1
fi

if [[ ! -d "$EXT_SRC_DIR" || ! -d "$LIB_SRC_DIR" ]]; then
  echo "[fuzz] missing project directories; run from a full pq_crypto checkout" >&2
  exit 1
fi

has_darwin_libfuzzer_runtime() {
  local cc_bin="$1"
  local resource_dir
  resource_dir="$($cc_bin --print-resource-dir 2>/dev/null || true)"
  [[ -n "$resource_dir" && -f "$resource_dir/lib/darwin/libclang_rt.fuzzer_osx.a" ]]
}

select_cc() {
  local requested="${CC:-}"
  local candidates=()
  local brew_llvm=""

  if [[ -n "$requested" ]]; then
    candidates+=("$requested")
  else
    candidates+=("clang")
    if command -v brew >/dev/null 2>&1; then
      brew_llvm="$(brew --prefix llvm 2>/dev/null || true)"
      [[ -n "$brew_llvm" ]] && candidates+=("$brew_llvm/bin/clang")
    fi
    candidates+=("/opt/homebrew/opt/llvm/bin/clang" "/usr/local/opt/llvm/bin/clang")
  fi

  local candidate
  local seen=""
  for candidate in "${candidates[@]}"; do
    [[ -n "$candidate" ]] || continue
    [[ "$seen" == *"|$candidate|"* ]] && continue
    seen="$seen|$candidate|"

    command -v "$candidate" >/dev/null 2>&1 || continue

    if [[ "$(uname -s)" == "Darwin" ]]; then
      if has_darwin_libfuzzer_runtime "$candidate"; then
        command -v "$candidate"
        return 0
      fi
    else
      command -v "$candidate"
      return 0
    fi
  done

  if [[ "$(uname -s)" == "Darwin" ]]; then
    local hint_cmd
    if [[ "$(basename "$PWD")" == "fuzz" ]]; then
      hint_cmd='CC="$(brew --prefix llvm)/bin/clang" ./build.sh'
    else
      hint_cmd='CC="$(brew --prefix llvm)/bin/clang" ./fuzz/build.sh'
    fi

    cat >&2 <<MSG
[fuzz] no clang with libFuzzer runtime was found.
[fuzz] Apple Command Line Tools clang usually misses libclang_rt.fuzzer_osx.a.
[fuzz]
[fuzz] Fix on macOS:
[fuzz]
[fuzz]   brew install llvm openssl@3 pkg-config
[fuzz]   $hint_cmd
[fuzz]
MSG
  else
    echo "[fuzz] no usable clang compiler was found" >&2
  fi
  exit 1
}

CC_BIN="$(select_cc)"
EXT_SANITIZE="${PQCRYPTO_FUZZ_EXT_SANITIZE:-fuzzer-no-link,address,undefined}"
FUZZ_SANITIZE="${PQCRYPTO_FUZZ_SANITIZE:--fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer -O1 -g}"
VERBOSE="${PQCRYPTO_FUZZ_VERBOSE:-0}"

check_fuzzer_link() {
  local check_src="$WORKDIR/fuzzer_link_check.c"
  local check_bin="$WORKDIR/fuzzer_link_check"
  cat > "$check_src" <<'C'
#include <stddef.h>
#include <stdint.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  (void)data;
  (void)size;
  return 0;
}
C

  if ! "$CC_BIN" $FUZZ_SANITIZE "$check_src" -o "$check_bin" >/tmp/pq_crypto_fuzzer_link_check.log 2>&1; then
    echo "[fuzz] compiler cannot link a libFuzzer binary with the requested sanitizer flags" >&2
    echo "[fuzz] compiler: $CC_BIN" >&2
    echo "[fuzz] clang resource dir: $("$CC_BIN" --print-resource-dir 2>/dev/null || true)" >&2
    echo "[fuzz] sanitizer flags: $FUZZ_SANITIZE" >&2
    echo "[fuzz] linker check log:" >&2
    cat /tmp/pq_crypto_fuzzer_link_check.log >&2 || true
    exit 1
  fi
}

if [[ -z "${OPENSSL_ROOT_DIR:-}" && "$(uname -s)" == "Darwin" ]] && command -v brew >/dev/null 2>&1; then
  brew_openssl="$(brew --prefix openssl@3 2>/dev/null || true)"
  [[ -n "$brew_openssl" && -d "$brew_openssl" ]] && OPENSSL_ROOT_DIR="$brew_openssl"
fi

if [[ -n "${OPENSSL_ROOT_DIR:-}" ]]; then
  export PKG_CONFIG_PATH="${OPENSSL_ROOT_DIR}/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
fi

rm -rf "$WORKDIR"
mkdir -p "$WORKDIR/ext" "$WORKDIR/lib" "$BUILD_DIR" "$WORKDIR/logs"
LOG_DIR="$WORKDIR/logs"

if command -v rsync >/dev/null 2>&1; then
  rsync -a --delete \
    --exclude='.git' \
    --exclude='*.o' \
    --exclude='*.bundle' \
    --exclude='*.so' \
    --exclude='*.dSYM' \
    --exclude='Makefile' \
    --exclude='mkmf.log' \
    "$EXT_SRC_DIR/" "$EXT_BUILD_DIR/"
  rsync -a --delete "$LIB_SRC_DIR/" "$WORKDIR/lib/"
else
  cp -R "$EXT_SRC_DIR" "$EXT_BUILD_DIR"
  cp -R "$LIB_SRC_DIR"/* "$WORKDIR/lib/"
  find "$EXT_BUILD_DIR" \( -name '*.o' -o -name '*.bundle' -o -name '*.so' -o -name '*.dSYM' -o -name 'Makefile' -o -name 'mkmf.log' \) -prune -exec rm -rf {} +
fi

echo "[fuzz] compiler: $CC_BIN"
echo "[fuzz] clang resource dir: $("$CC_BIN" --print-resource-dir 2>/dev/null || true)"
echo "[fuzz] extension sanitizer: $EXT_SANITIZE"
echo "[fuzz] fuzz sanitizer flags: $FUZZ_SANITIZE"
echo "[fuzz] temp workdir: $WORKDIR"
echo "[fuzz] build output: $BUILD_DIR"

check_fuzzer_link

cd "$EXT_BUILD_DIR"
extconf_args=()
if [[ -n "${OPENSSL_ROOT_DIR:-}" ]]; then
  extconf_args+=("--with-openssl-dir=$OPENSSL_ROOT_DIR")
fi

export PATH="/usr/local/bin:${PATH}"

EXTCONF_LOG="$LOG_DIR/extconf.log"

if [[ "$VERBOSE" == "1" ]]; then
  CC="$CC_BIN" \
    PQCRYPTO_NATIVE_ASM="${PQCRYPTO_NATIVE_ASM:-0}" \
    PQCRYPTO_NATIVE_ARITH="${PQCRYPTO_NATIVE_ARITH:-0}" \
    PQCRYPTO_NATIVE_FIPS202="${PQCRYPTO_NATIVE_FIPS202:-0}" \
    PQCRYPTO_SANITIZE="" \
    ruby extconf.rb "${extconf_args[@]}"
else
  if ! CC="$CC_BIN" \
    PQCRYPTO_NATIVE_ASM="${PQCRYPTO_NATIVE_ASM:-0}" \
    PQCRYPTO_NATIVE_ARITH="${PQCRYPTO_NATIVE_ARITH:-0}" \
    PQCRYPTO_NATIVE_FIPS202="${PQCRYPTO_NATIVE_FIPS202:-0}" \
    PQCRYPTO_SANITIZE="" \
    ruby extconf.rb "${extconf_args[@]}" >"$EXTCONF_LOG" 2>&1; then
    echo "[fuzz] extconf.rb failed; dumping $EXTCONF_LOG" >&2
    cat "$EXTCONF_LOG" >&2 || true
    find "$EXT_BUILD_DIR" -maxdepth 2 -name mkmf.log -print -exec cat {} \; >&2 || true
    exit 1
  fi
fi

EXT_CFLAGS="-fsanitize=${EXT_SANITIZE} -fno-omit-frame-pointer -O1 -g"

# Only patch CFLAGS.
ruby - "$EXT_CFLAGS" <<'RUBY'
makefile = "Makefile"
cflags = ARGV.fetch(0)
text = File.read(makefile)
text.gsub!(/-D_FORTIFY_SOURCE=\d+/, "")
text.gsub!(/-fstack-clash-protection/, "")
text.gsub!(/-Wno-c23-extensions/, "-Wno-c2x-extensions")

patched_cflags = false
text = text.gsub(/^CFLAGS\s*=.*$/) do |line|
  patched_cflags = true
  "#{line} #{cflags}"
end

unless patched_cflags
  raise "could not patch CFLAGS in #{makefile}"
end

File.write(makefile, text)
RUBY

MAKE_LOG="$LOG_DIR/make.log"
make clean CC="$CC_BIN" >"$LOG_DIR/make.clean.log" 2>&1 || true
if [[ "$VERBOSE" == "1" ]]; then
  make CC="$CC_BIN" -j"${PQCRYPTO_FUZZ_JOBS:-2}"
else
  if ! make CC="$CC_BIN" -j"${PQCRYPTO_FUZZ_JOBS:-2}" >"$MAKE_LOG" 2>&1; then
    echo "[fuzz] make failed; dumping $MAKE_LOG" >&2
    cat "$MAKE_LOG" >&2 || true
    exit 1
  fi
fi

OPENSSL_LIBS="${OPENSSL_LIBS:-}"
OPENSSL_CFLAGS="${OPENSSL_CFLAGS:-}"
if [[ -z "$OPENSSL_LIBS" ]] && command -v pkg-config >/dev/null 2>&1; then
  OPENSSL_LIBS="$(pkg-config --libs openssl 2>/dev/null || true)"
  OPENSSL_CFLAGS="$(pkg-config --cflags openssl 2>/dev/null || true)"
fi
[[ -z "$OPENSSL_LIBS" ]] && OPENSSL_LIBS="-lssl -lcrypto"
if [[ -n "${OPENSSL_ROOT_DIR:-}" ]]; then
  OPENSSL_CFLAGS="-I${OPENSSL_ROOT_DIR}/include ${OPENSSL_CFLAGS}"
  OPENSSL_LIBS="-L${OPENSSL_ROOT_DIR}/lib ${OPENSSL_LIBS}"
fi

OBJECTS=(
  "$EXT_BUILD_DIR/pqcrypto_secure.o"
  "$EXT_BUILD_DIR/pq_externalmu.o"
  "$EXT_BUILD_DIR/pq_randombytes.o"
)
while IFS= read -r -d '' obj; do
  OBJECTS+=("$obj")
done < <(find "$EXT_BUILD_DIR" -maxdepth 1 -name 'pqnative_*.o' -print0)

INCLUDES=(
  -I"$EXT_BUILD_DIR"
  -I"$EXT_BUILD_DIR/vendor/mlkem-native/mlkem"
  -I"$EXT_BUILD_DIR/vendor/mldsa-native/mldsa"
)

for src in "$ROOT"/fuzz/fuzz_*.c; do
  name="$(basename "$src" .c)"
  echo "[fuzz] building $name"
  "$CC_BIN" $FUZZ_SANITIZE -std=c11 -Wall -Wextra \
    "${INCLUDES[@]}" $OPENSSL_CFLAGS \
    "$src" "${OBJECTS[@]}" $OPENSSL_LIBS \
    -o "$BUILD_DIR/$name"
done

cat <<MSG

[fuzz] done
[fuzz] targets written to: $BUILD_DIR

Example:
  "$BUILD_DIR/fuzz_pkcs8_private_key_info_from_der" \
    "$ROOT/fuzz/corpus/pkcs8_private_key_info_from_der" \
    -max_total_time=60 -max_len=16384

MSG
