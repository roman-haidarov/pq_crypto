# frozen_string_literal: true

require_relative "test_helper"

class TestPKCS8RequireEncrypted < Minitest::Test
  PASSPHRASE = "correct horse battery staple"

  def kem_secret_key
    PQCrypto::KEM.generate(:ml_kem_768).secret_key
  end

  def signature_secret_key
    PQCrypto::Signature.generate(:ml_dsa_65).secret_key
  end

  def test_unencrypted_der_is_rejected_when_encryption_is_required
    der = kem_secret_key.to_pkcs8_der

    error = assert_raises(PQCrypto::SerializationError) do
      PQCrypto::PKCS8.decode_der(der, passphrase: PASSPHRASE, require_encrypted: true)
    end
    assert_match(/not encrypted/, error.message)
  end

  def test_unencrypted_der_is_still_accepted_by_default
    secret_key = kem_secret_key
    der = secret_key.to_pkcs8_der

    assert PQCrypto::PKCS8.decode_der(der, passphrase: PASSPHRASE)
    assert PQCrypto::PKCS8.decode_der(der)
  end

  def test_encrypted_der_round_trips_under_strict_mode
    secret_key = kem_secret_key
    der = secret_key.to_pkcs8_der(passphrase: PASSPHRASE)

    loaded = PQCrypto::KEM.secret_key_from_pkcs8_der(
      der, passphrase: PASSPHRASE, require_encrypted: true
    )
    assert_equal secret_key.to_bytes, loaded.to_bytes
  end

  def test_wrong_passphrase_still_fails_under_strict_mode
    der = kem_secret_key.to_pkcs8_der(passphrase: PASSPHRASE)

    assert_raises(PQCrypto::SerializationError) do
      PQCrypto::PKCS8.decode_der(der, passphrase: "wrong", require_encrypted: true)
    end
  end

  def test_strict_mode_reaches_every_public_entry_point
    secret_key = kem_secret_key
    plain_der = secret_key.to_pkcs8_der
    plain_pem = secret_key.to_pkcs8_pem
    encrypted_der = secret_key.to_pkcs8_der(passphrase: PASSPHRASE)
    encrypted_pem = secret_key.to_pkcs8_pem(passphrase: PASSPHRASE)

    assert_raises(PQCrypto::SerializationError, "KEM der") do
      PQCrypto::KEM.secret_key_from_pkcs8_der(plain_der, require_encrypted: true)
    end
    assert_raises(PQCrypto::SerializationError, "KEM pem") do
      PQCrypto::KEM.secret_key_from_pkcs8_pem(plain_pem, require_encrypted: true)
    end
    assert_raises(PQCrypto::SerializationError, "Key.from_der") do
      PQCrypto::Key.from_der(plain_der, passphrase: PASSPHRASE, require_encrypted: true)
    end
    assert_raises(PQCrypto::SerializationError, "Key.from_pem") do
      PQCrypto::Key.from_pem(plain_pem, passphrase: PASSPHRASE, require_encrypted: true)
    end

    assert PQCrypto::KEM.secret_key_from_pkcs8_der(
      encrypted_der, passphrase: PASSPHRASE, require_encrypted: true
    )
    assert PQCrypto::Key.from_pem(
      encrypted_pem, passphrase: PASSPHRASE, require_encrypted: true
    )
  end

  def test_strict_mode_applies_to_ml_dsa_keys
    secret_key = signature_secret_key
    plain_der = secret_key.to_pkcs8_der
    encrypted_der = secret_key.to_pkcs8_der(passphrase: PASSPHRASE)

    assert_raises(PQCrypto::SerializationError) do
      PQCrypto::Signature.secret_key_from_pkcs8_der(
        plain_der, passphrase: PASSPHRASE, require_encrypted: true
      )
    end

    loaded = PQCrypto::Signature.secret_key_from_pkcs8_der(
      encrypted_der, passphrase: PASSPHRASE, require_encrypted: true
    )
    assert_equal secret_key.to_bytes, loaded.to_bytes
  end

  def test_seed_format_is_preserved_under_strict_mode
    seed = "\x11".b * 64
    secret_key = PQCrypto::KEM.secret_key_from_seed(:ml_kem_768, seed)
    der = secret_key.to_pkcs8_der(format: :seed, passphrase: PASSPHRASE)

    loaded = PQCrypto::KEM.secret_key_from_pkcs8_der(
      der, passphrase: PASSPHRASE, require_encrypted: true
    )
    assert_equal secret_key.to_bytes, loaded.to_bytes

    assert_raises(PQCrypto::SerializationError) do
      PQCrypto::KEM.secret_key_from_pkcs8_der(
        secret_key.to_pkcs8_der(format: :seed), require_encrypted: true
      )
    end
  end

  def test_require_encrypted_rejects_non_boolean_values
    der = kem_secret_key.to_pkcs8_der

    ["false", 0, 1, "", nil].each do |value|
      error = assert_raises(ArgumentError, value.inspect) do
        PQCrypto::PKCS8.decode_der(der, require_encrypted: value)
      end
      assert_match(/require_encrypted must be true or false/, error.message)
    end
  end

  def test_pem_label_spoof_does_not_satisfy_encryption_policy
    plain = kem_secret_key.to_pkcs8_der
    body = [plain].pack("m0").scan(/.{1,64}/).join("\n")
    fake = "-----BEGIN ENCRYPTED PRIVATE KEY-----\n#{body}\n-----END ENCRYPTED PRIVATE KEY-----\n"

    error = assert_raises(PQCrypto::SerializationError) do
      PQCrypto::PKCS8.decode_pem(fake, passphrase: PASSPHRASE, require_encrypted: true)
    end
    assert_match(/not encrypted/, error.message)
  end
end
