#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CORPUS_ROOT="${PQCRYPTO_FUZZ_CORPUS_DIR:-$ROOT/fuzz/corpus}"
PASS="${PQCRYPTO_FUZZ_PASSPHRASE:-pq_crypto fuzz passphrase}"
ITERATIONS="${PQCRYPTO_FUZZ_FAST_ITERATIONS:-1,10,100,1000}"

build_extension_if_needed() {
  local dlex_t
  dlex_t="$(ruby -rrbconfig -e 'print RbConfig::CONFIG.fetch("DLEXT")')"
  if [[ -f "$ROOT/lib/pqcrypto/pqcrypto_secure.$dlex_t" ]]; then
    return 0
  fi

  echo "[fuzz-corpus] native extension not found under lib/pqcrypto; building in this checkout copy"
  (cd "$ROOT/ext/pqcrypto" && \
    CC="${CC:-clang}" \
    PQCRYPTO_NATIVE_ASM="${PQCRYPTO_NATIVE_ASM:-0}" \
    PQCRYPTO_NATIVE_ARITH="${PQCRYPTO_NATIVE_ARITH:-0}" \
    PQCRYPTO_NATIVE_FIPS202="${PQCRYPTO_NATIVE_FIPS202:-0}" \
    ruby extconf.rb >/dev/null && \
    make CC="${CC:-clang}" -j"${PQCRYPTO_FUZZ_JOBS:-2}" >/dev/null)
  mkdir -p "$ROOT/lib/pqcrypto"
  cp "$ROOT/ext/pqcrypto/pqcrypto_secure.$dlex_t" "$ROOT/lib/pqcrypto/"
}

build_extension_if_needed
mkdir -p "$CORPUS_ROOT"

PASS="$PASS" ITERATIONS="$ITERATIONS" CORPUS_ROOT="$CORPUS_ROOT" ruby -I"$ROOT/lib" <<'RUBY'
# frozen_string_literal: true

require "fileutils"
require "pq_crypto"

PASS = ENV.fetch("PASS")
ITERATIONS = ENV.fetch("ITERATIONS").split(",").map { |s| Integer(s.strip) }
ROOT = ENV.fetch("CORPUS_ROOT")

KEM_ALGS = %i[ml_kem_512 ml_kem_768 ml_kem_1024].freeze
DSA_ALGS = %i[ml_dsa_44 ml_dsa_65 ml_dsa_87].freeze
ALL_ALGS = (KEM_ALGS + DSA_ALGS).freeze
PQC_LEGACY = %i[ml_kem_768 ml_dsa_65 ml_kem_768_x25519_xwing].freeze

DIR_DER = File.join(ROOT, "pkcs8_private_key_info_from_der")
DIR_PEM = File.join(ROOT, "pkcs8_pem_to_der")
DIR_DEC = File.join(ROOT, "pkcs8_decrypt_private_key_info_der")
DIR_PQC = File.join(ROOT, "pqc_container_from_der")
[DIR_DER, DIR_PEM, DIR_DEC, DIR_PQC].each { |dir| FileUtils.mkdir_p(dir) }

# Keep corpus generation deterministic enough to be reproducible across local runs.
def bytes(seed, len)
  rng = Random.new(seed)
  Array.new(len) { rng.rand(256) }.pack("C*")
end

def factory(alg)
  case alg
  when :ml_kem_768_x25519_xwing
    PQCrypto::HybridKEM
  else
    alg.to_s.start_with?("ml_kem") ? PQCrypto::KEM : PQCrypto::Signature
  end
end

def seeded_secret(alg, index)
  if alg.to_s.start_with?("ml_kem")
    PQCrypto::KEM::SecretKey.from_seed(alg, bytes(10_000 + index, PQCrypto::PKCS8::ML_KEM_SEED_BYTES))
  else
    PQCrypto::Signature::SecretKey.from_seed(alg, bytes(20_000 + index, PQCrypto::PKCS8::ML_DSA_SEED_BYTES))
  end
end

def write(path, data)
  File.binwrite(path, data.b)
end

previous_ml_dsa_seed_flag = PQCrypto::PKCS8.allow_ml_dsa_seed_format
PQCrypto::PKCS8.allow_ml_dsa_seed_format = true

begin

puts "[fuzz-corpus] writing corpus to #{ROOT}"

# === 1) Plain PKCS#8 DER ===
write(File.join(DIR_DER, "empty.der"), "")
write(File.join(DIR_DER, "empty_sequence.der"), [0x30, 0x00].pack("C*"))
write(File.join(DIR_DER, "truncated_len.der"), [0x30, 0x82, 0x01].pack("C*"))
write(File.join(DIR_DER, "noncanonical_len.der"), [0x30, 0x81, 0x00].pack("C*"))
write(File.join(DIR_DER, "minimal_v1_unknown_oid.der"),
      [0x30, 0x0d, 0x02, 0x01, 0x00, 0x30, 0x06, 0x06, 0x04, 0x2a, 0x03, 0x04, 0x05, 0x04, 0x00].pack("C*"))

ALL_ALGS.each_with_index do |alg, i|
  sk = seeded_secret(alg, i)
  %i[expanded seed both].each do |fmt|
    begin
      write(File.join(DIR_DER, "#{alg}_#{fmt}.der"), sk.to_pkcs8_der(format: fmt))
    rescue => e
      warn "[fuzz-corpus] plain #{alg}/#{fmt}: #{e.class}: #{e.message}"
    end
  end
end

if File.exist?(File.join(DIR_DER, "ml_kem_768_expanded.der"))
  v = File.binread(File.join(DIR_DER, "ml_kem_768_expanded.der"))
  [1, 2, 4, 8, 16, 32, 64, 128, v.bytesize - 1].uniq.each do |k|
    next if k >= v.bytesize
    write(File.join(DIR_DER, "ml_kem_768_truncated_#{k}.der"), v.byteslice(0, k))
  end
  d = v.dup
  d.setbyte([v.bytesize - 16, 0].max, d.getbyte([v.bytesize - 16, 0].max) ^ 0x55)
  write(File.join(DIR_DER, "ml_kem_768_damaged_tail.der"), d)
end

# === 2) PKCS#8 PEM ===
write(File.join(DIR_PEM, "bad_base64.pem"), "-----BEGIN PRIVATE KEY-----\n!!!!\n-----END PRIVATE KEY-----\n")
write(File.join(DIR_PEM, "empty_private_key.pem"), "-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----\n")
write(File.join(DIR_PEM, "encrypted_label_empty.pem"), "-----BEGIN ENCRYPTED PRIVATE KEY-----\n-----END ENCRYPTED PRIVATE KEY-----\n")
write(File.join(DIR_PEM, "mismatched_footer.pem"), "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n")

ALL_ALGS.each_with_index do |alg, i|
  sk = seeded_secret(alg, 100 + i)
  begin
    write(File.join(DIR_PEM, "#{alg}_expanded.pem"), sk.to_pkcs8_pem(format: :expanded))
    write(File.join(DIR_PEM, "#{alg}_encrypted.pem"), sk.to_pkcs8_pem(format: :expanded, passphrase: PASS, iterations: 100))
  rescue => e
    warn "[fuzz-corpus] pem #{alg}: #{e.class}: #{e.message}"
  end
end

# === 3) Encrypted PKCS#8 DER ===
write(File.join(DIR_DEC, "empty.der"), "")
write(File.join(DIR_DEC, "empty_sequence.der"), [0x30, 0x00].pack("C*"))
write(File.join(DIR_DEC, "pbes2_shape_short.der"), [0x30, 0x0a, 0x30, 0x08, 0x06, 0x06, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d].pack("C*"))

ALL_ALGS.each_with_index do |alg, i|
  sk = seeded_secret(alg, 200 + i)
  begin
    write(File.join(DIR_DEC, "#{alg}_encrypted_iter100.der"),
          sk.to_pkcs8_der(format: :expanded, passphrase: PASS, iterations: 100))
  rescue => e
    warn "[fuzz-corpus] enc #{alg}: #{e.class}: #{e.message}"
  end
end

ITERATIONS.each do |iters|
  sk = seeded_secret(:ml_kem_768, 300 + iters)
  begin
    write(File.join(DIR_DEC, "ml_kem_768_iter#{iters}.der"),
          sk.to_pkcs8_der(format: :expanded, passphrase: PASS, iterations: iters))
  rescue => e
    warn "[fuzz-corpus] enc iter=#{iters}: #{e.class}: #{e.message}"
  end
end

sample_enc = File.join(DIR_DEC, "ml_kem_768_iter100.der")
if File.exist?(sample_enc)
  v = File.binread(sample_enc)
  [1, 4, 8, 16, 32, 64, 128, v.bytesize - 1].uniq.each do |k|
    next if k >= v.bytesize
    write(File.join(DIR_DEC, "encrypted_truncated_#{k}.der"), v.byteslice(0, k))
  end
  d = v.dup
  d.setbyte([v.bytesize - 32, 0].max, d.getbyte([v.bytesize - 32, 0].max) ^ 0x55)
  write(File.join(DIR_DEC, "encrypted_damaged_ciphertext.der"), d)
end

# === 4) legacy pqc_container DER ===
write(File.join(DIR_PQC, "empty.der"), "")
write(File.join(DIR_PQC, "empty_sequence.der"), [0x30, 0x00].pack("C*"))
write(File.join(DIR_PQC, "garbage_short.der"), [0x30, 0x05, 0x06, 0x03, 0x55, 0x04, 0x03].pack("C*"))

PQC_LEGACY.each do |alg|
  begin
    kp = factory(alg).generate(alg)
    write(File.join(DIR_PQC, "#{alg}_public.der"), kp.public_key.to_pqc_container_der)
    write(File.join(DIR_PQC, "#{alg}_secret.der"), kp.secret_key.to_pqc_container_der)
  rescue => e
    warn "[fuzz-corpus] pqc #{alg}: #{e.class}: #{e.message}"
  end
end

sample_pqc = File.join(DIR_PQC, "ml_kem_768_public.der")
if File.exist?(sample_pqc)
  v = File.binread(sample_pqc)
  [1, 4, 8, 16, 32, v.bytesize - 1].uniq.each do |k|
    next if k >= v.bytesize
    write(File.join(DIR_PQC, "ml_kem_768_public_truncated_#{k}.der"), v.byteslice(0, k))
  end
  write(File.join(DIR_PQC, "ml_kem_768_public_with_trailer.der"), v + "\x00\x00\x00\x00".b)
end

puts "[fuzz-corpus] summary"
[DIR_DER, DIR_PEM, DIR_DEC, DIR_PQC].each do |dir|
  files = Dir.glob(File.join(dir, "*"))
  bytes = files.sum { |f| File.size(f) }
  puts "  #{dir}: #{files.size} files, #{bytes} bytes"
end
ensure
  PQCrypto::PKCS8.allow_ml_dsa_seed_format = previous_ml_dsa_seed_flag if defined?(previous_ml_dsa_seed_flag)
end
RUBY
