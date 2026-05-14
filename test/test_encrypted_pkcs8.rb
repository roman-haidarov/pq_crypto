# frozen_string_literal: true

require_relative "test_helper"

class TestEncryptedPKCS8 < Minitest::Test
  def test_kem_encrypted_pkcs8_pem_roundtrip
    keypair = PQCrypto::KEM.generate(:ml_kem_768)
    pem = keypair.secret_key.to_pkcs8_pem(passphrase: "correct horse", iterations: 1_000)

    imported = PQCrypto::KEM.secret_key_from_pkcs8_pem(pem, passphrase: "correct horse")

    assert_match(/BEGIN ENCRYPTED PRIVATE KEY/, pem)
    assert_equal keypair.secret_key.to_bytes, imported.to_bytes
  end

  def test_signature_encrypted_pkcs8_der_roundtrip
    keypair = PQCrypto::Signature.generate(:ml_dsa_65)
    der = keypair.secret_key.to_pkcs8_der(passphrase: "correct horse", iterations: 1_000)

    imported = PQCrypto::Signature.secret_key_from_pkcs8_der(der, passphrase: "correct horse")
    signature = imported.sign("encrypted pkcs8".b)

    assert_equal keypair.secret_key.to_bytes, imported.to_bytes
    assert keypair.public_key.verify("encrypted pkcs8".b, signature)
  end

  def test_wrong_passphrase_fails
    pem = PQCrypto::KEM.generate(:ml_kem_768).secret_key.to_pkcs8_pem(passphrase: "right", iterations: 1_000)

    assert_raises(PQCrypto::SerializationError) do
      PQCrypto::KEM.secret_key_from_pkcs8_pem(pem, passphrase: "wrong")
    end
  end
end
