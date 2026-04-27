# frozen_string_literal: true

require_relative "test_helper"
require_relative "support/interop_helper"

class TestInteropOpenSSLSPKIMLDSA65 < Minitest::Test
  def setup
    skip InteropHelper.openssl_mldsa_spki_skip_reason unless InteropHelper.openssl_mldsa_spki_supported?
  end

  def test_ruby_spki_decoded_by_openssl
    keypair = PQCrypto::Signature.generate(:ml_dsa_65)
    spki_der = keypair.public_key.to_spki_der

    openssl_raw_hex = InteropHelper.run_openssl_helper(
      "mldsa-spki-decode-to-raw",
      InteropHelper.hex(spki_der)
    ).first

    assert_equal keypair.public_key.to_bytes, InteropHelper.bin(openssl_raw_hex)
  end

  def test_openssl_spki_decoded_by_ruby
    keypair = PQCrypto::Signature.generate(:ml_dsa_65)
    raw_public_key = keypair.public_key.to_bytes

    openssl_spki_hex = InteropHelper.run_openssl_helper(
      "mldsa-spki-encode-from-raw",
      InteropHelper.hex(raw_public_key)
    ).first
    algorithm, decoded_public_key = PQCrypto::SPKI.decode_der(InteropHelper.bin(openssl_spki_hex))

    assert_equal :ml_dsa_65, algorithm
    assert_equal raw_public_key, decoded_public_key
  end

  def test_ruby_pkcs8_expanded_decoded_by_openssl
    keypair = PQCrypto::Signature.generate(:ml_dsa_65)
    pkcs8_der = keypair.secret_key.to_pkcs8_der

    openssl_secret_hex = InteropHelper.run_openssl_helper(
      "mldsa-pkcs8-decode-to-raw",
      InteropHelper.hex(pkcs8_der)
    ).first

    assert_equal keypair.secret_key.to_bytes, InteropHelper.bin(openssl_secret_hex)
  end

  def test_openssl_pkcs8_expanded_decoded_by_ruby
    keypair = PQCrypto::Signature.generate(:ml_dsa_65)
    raw_secret_key = keypair.secret_key.to_bytes

    openssl_pkcs8_hex = InteropHelper.run_openssl_helper(
      "mldsa-pkcs8-encode-from-expanded",
      InteropHelper.hex(raw_secret_key)
    ).first
    algorithm, format, material = PQCrypto::PKCS8.decode_der(InteropHelper.bin(openssl_pkcs8_hex))

    assert_equal :ml_dsa_65, algorithm
    assert_equal :expanded, format
    assert_equal raw_secret_key, material
  end
end
