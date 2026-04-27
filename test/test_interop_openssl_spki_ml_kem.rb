# frozen_string_literal: true

require_relative "test_helper"
require_relative "support/interop_helper"

class TestInteropOpenSSLSPKIMLKEM768 < Minitest::Test
  SEED = (0...64).to_a.pack("C*").b

  def setup
    skip InteropHelper.openssl_mlkem_spki_skip_reason unless InteropHelper.openssl_mlkem_spki_supported?
  end

  def test_ruby_spki_decoded_by_openssl
    keypair = PQCrypto::KEM.generate(:ml_kem_768)
    spki_der = keypair.public_key.to_spki_der

    openssl_raw_hex = InteropHelper.run_openssl_helper(
      "mlkem-spki-decode-to-raw",
      InteropHelper.hex(spki_der)
    ).first

    assert_equal keypair.public_key.to_bytes, InteropHelper.bin(openssl_raw_hex)
  end

  def test_openssl_spki_decoded_by_ruby
    keypair = PQCrypto::KEM.generate(:ml_kem_768)
    raw_public_key = keypair.public_key.to_bytes

    openssl_spki_hex = InteropHelper.run_openssl_helper(
      "mlkem-spki-encode-from-raw",
      InteropHelper.hex(raw_public_key)
    ).first
    algorithm, decoded_public_key = PQCrypto::SPKI.decode_der(InteropHelper.bin(openssl_spki_hex))

    assert_equal :ml_kem_768, algorithm
    assert_equal raw_public_key, decoded_public_key
  end

  def test_ruby_pkcs8_seed_decoded_by_openssl
    pkcs8_der = PQCrypto::PKCS8.encode_der(:ml_kem_768, SEED, format: :seed)

    openssl_seed_hex = InteropHelper.run_openssl_helper(
      "mlkem-pkcs8-decode-to-raw",
      InteropHelper.hex(pkcs8_der)
    ).first

    assert_equal SEED, InteropHelper.bin(openssl_seed_hex)
  end

  def test_openssl_pkcs8_seed_decoded_by_ruby
    openssl_pkcs8_hex = InteropHelper.run_openssl_helper(
      "mlkem-pkcs8-encode-from-seed",
      InteropHelper.hex(SEED)
    ).first
    algorithm, format, material = PQCrypto::PKCS8.decode_der(InteropHelper.bin(openssl_pkcs8_hex))

    assert_equal :ml_kem_768, algorithm
    assert_equal :seed, format
    assert_equal SEED, material
  end
end
