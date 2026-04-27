# frozen_string_literal: true

require_relative "test_helper"

class TestPQCryptoMLDSA44 < Minitest::Test
  def test_generate_sign_verify
    keypair = PQCrypto::Signature.generate(:ml_dsa_44)
    signature = keypair.secret_key.sign("message")

    assert_equal :ml_dsa_44, keypair.algorithm
    assert_equal PQCrypto::SIGN_44_PUBLIC_KEY_BYTES, keypair.public_key.to_bytes.bytesize
    assert_equal PQCrypto::SIGN_44_SECRET_KEY_BYTES, keypair.secret_key.to_bytes.bytesize
    assert_equal PQCrypto::SIGN_44_BYTES, signature.bytesize
    assert keypair.public_key.verify("message", signature)
    refute keypair.public_key.verify("tampered", signature)
  end

  def test_pkcs8_and_spki_round_trip
    keypair = PQCrypto::Signature.generate(:ml_dsa_44)

    assert_equal keypair.public_key.to_bytes,
                 PQCrypto::Signature.public_key_from_spki_der(keypair.public_key.to_spki_der).to_bytes
    assert_equal keypair.secret_key.to_bytes,
                 PQCrypto::Signature.secret_key_from_pkcs8_der(keypair.secret_key.to_pkcs8_der).to_bytes
  end
end
