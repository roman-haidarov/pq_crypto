# frozen_string_literal: true

require_relative "test_helper"

class TestPQCryptoPKCS8MLDSA65Seed < Minitest::Test
  SEED = (0...32).map(&:chr).join.b

  def setup
    @previous = PQCrypto::PKCS8.allow_ml_dsa_seed_format
    PQCrypto::PKCS8.allow_ml_dsa_seed_format = false
  end

  def teardown
    PQCrypto::PKCS8.allow_ml_dsa_seed_format = @previous
  end

  def test_default_off_importing_seed_pkcs8_raises
    PQCrypto::PKCS8.allow_ml_dsa_seed_format = true
    der = PQCrypto::PKCS8.encode_der(:ml_dsa_65, SEED, format: :seed)
    PQCrypto::PKCS8.allow_ml_dsa_seed_format = false

    error = assert_raises(PQCrypto::SerializationError) do
      PQCrypto::Signature.secret_key_from_pkcs8_der(der)
    end
    assert_match(/ML-DSA seed-format PKCS#8 is opt-in/, error.message)
  end

  def test_opt_in_seed_import_expands_to_usable_secret_key
    expected_public_key, expected_secret_key = PQCrypto::Testing.ml_dsa_keypair_from_seed(SEED, algorithm: :ml_dsa_65)

    PQCrypto::PKCS8.allow_ml_dsa_seed_format = true
    der = PQCrypto::PKCS8.encode_der(:ml_dsa_65, SEED, format: :seed)
    imported = PQCrypto::Signature.secret_key_from_pkcs8_der(der)

    assert_equal :ml_dsa_65, imported.algorithm
    assert_equal expected_secret_key, imported.to_bytes

    signature = imported.sign("ml-dsa-seed-pkcs8")
    public_key = PQCrypto::Signature.public_key_from_bytes(:ml_dsa_65, expected_public_key)
    assert public_key.verify("ml-dsa-seed-pkcs8", signature)
  end

  def test_opt_in_both_import_uses_expanded_half_after_consistency_check
    _public_key, expected_secret_key = PQCrypto::Testing.ml_dsa_keypair_from_seed(SEED, algorithm: :ml_dsa_65)

    PQCrypto::PKCS8.allow_ml_dsa_seed_format = true
    der = PQCrypto::PKCS8.encode_der(:ml_dsa_65, [SEED, expected_secret_key], format: :both)
    algorithm, format, material = PQCrypto::PKCS8.decode_der(der)
    imported = PQCrypto::Signature.secret_key_from_pkcs8_der(der)

    assert_equal :ml_dsa_65, algorithm
    assert_equal :both, format
    assert_equal SEED, material.first
    assert_equal expected_secret_key, material.last
    assert_equal expected_secret_key, imported.to_bytes
  end

  def test_opt_in_both_import_rejects_seed_expanded_mismatch
    _public_key, expected_secret_key = PQCrypto::Testing.ml_dsa_keypair_from_seed(SEED, algorithm: :ml_dsa_65)
    wrong_secret_key = expected_secret_key.dup
    wrong_secret_key.setbyte(0, wrong_secret_key.getbyte(0) ^ 0x01)

    PQCrypto::PKCS8.allow_ml_dsa_seed_format = true
    der = PQCrypto::PKCS8.encode_der(:ml_dsa_65, [SEED, wrong_secret_key], format: :both)

    error = assert_raises(PQCrypto::SerializationError) do
      PQCrypto::PKCS8.decode_der(der)
    end
    assert_match(/seed\/expandedKey inconsistency in ML-DSA PKCS#8 'both' encoding/, error.message)
  end

  def test_opt_in_supports_all_ml_dsa_parameter_sets
    PQCrypto::PKCS8.allow_ml_dsa_seed_format = true

    {
      ml_dsa_44: PQCrypto::SIGN_44_SECRET_KEY_BYTES,
      ml_dsa_65: PQCrypto::SIGN_SECRET_KEY_BYTES,
      ml_dsa_87: PQCrypto::SIGN_87_SECRET_KEY_BYTES,
    }.each_key do |algorithm|
      _public_key, expected_secret_key = PQCrypto::Testing.ml_dsa_keypair_from_seed(SEED, algorithm: algorithm)
      der = PQCrypto::PKCS8.encode_der(algorithm, SEED, format: :seed)
      imported = PQCrypto::Signature.secret_key_from_pkcs8_der(der)

      assert_equal algorithm, imported.algorithm
      assert_equal expected_secret_key, imported.to_bytes
    end
  end
end
