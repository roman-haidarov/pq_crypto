# frozen_string_literal: true

require "openssl"
require_relative "test_helper"

class TestPQCryptoPKCS8MLDSA65Expanded < Minitest::Test
  ML_DSA_SEED_BYTES = 32

  def test_der_round_trip
    keypair = PQCrypto::Signature.generate(:ml_dsa_65)
    der = keypair.secret_key.to_pkcs8_der

    imported = PQCrypto::Signature.secret_key_from_pkcs8_der(der)
    algorithm, format, material = PQCrypto::PKCS8.decode_der(der)

    assert_equal :ml_dsa_65, imported.algorithm
    assert_equal keypair.secret_key.to_bytes, imported.to_bytes
    assert_equal :ml_dsa_65, algorithm
    assert_equal :expanded, format
    assert_equal keypair.secret_key.to_bytes, material
    assert_equal der, imported.to_pkcs8_der
  end

  def test_pem_round_trip
    keypair = PQCrypto::Signature.generate(:ml_dsa_65)
    pem = keypair.secret_key.to_pkcs8_pem

    imported = PQCrypto::Signature.secret_key_from_pkcs8_pem(pem)

    assert_equal :ml_dsa_65, imported.algorithm
    assert_equal keypair.secret_key.to_bytes, imported.to_bytes
    assert_equal pem, imported.to_pkcs8_pem
  end

  def test_imported_secret_key_signs
    keypair = PQCrypto::Signature.generate(:ml_dsa_65)
    imported = PQCrypto::Signature.secret_key_from_pkcs8_der(keypair.secret_key.to_pkcs8_der)
    signature = imported.sign("pkcs8-ml-dsa")

    assert keypair.public_key.verify("pkcs8-ml-dsa", signature)
  end

  def test_secret_key_export_rejects_seed_and_both
    secret_key = PQCrypto::Signature.generate(:ml_dsa_65).secret_key

    [:seed, :both].each do |format|
      error = assert_raises(PQCrypto::SerializationError) do
        secret_key.to_pkcs8_der(format: format)
      end
      assert_match(/ML-DSA seed\/both PKCS#8 export requires original seed material/, error.message)
    end
  end

  def test_pkcs8_encoder_rejects_seed_and_both_for_ml_dsa_by_default
    [:seed, :both].each do |format|
      material = format == :both ? ["\0" * ML_DSA_SEED_BYTES, "\0" * PQCrypto::SIGN_SECRET_KEY_BYTES] : "\0" * ML_DSA_SEED_BYTES

      error = assert_raises(PQCrypto::SerializationError) do
        PQCrypto::PKCS8.encode_der(:ml_dsa_65, material, format: format)
      end
      assert_match(/ML-DSA seed-format PKCS#8 is opt-in/, error.message)
    end
  end

  def test_decode_der_rejects_seed_choice_for_ml_dsa_by_default
    der = pkcs8_der(seed_choice_der("\0" * ML_DSA_SEED_BYTES))

    error = assert_raises(PQCrypto::SerializationError) do
      PQCrypto::PKCS8.decode_der(der)
    end
    assert_match(/ML-DSA seed-format PKCS#8 is opt-in/, error.message)
  end

  def test_decode_der_rejects_both_choice_for_ml_dsa_by_default
    der = pkcs8_der(OpenSSL::ASN1::Sequence.new([
      OpenSSL::ASN1::OctetString.new("\0" * ML_DSA_SEED_BYTES),
      OpenSSL::ASN1::OctetString.new("\0" * PQCrypto::SIGN_SECRET_KEY_BYTES),
    ]).to_der)

    error = assert_raises(PQCrypto::SerializationError) do
      PQCrypto::PKCS8.decode_der(der)
    end
    assert_match(/ML-DSA seed-format PKCS#8 is opt-in/, error.message)
  end

  def test_decode_der_rejects_wrong_expanded_key_size
    der = pkcs8_der(OpenSSL::ASN1::OctetString.new("\0" * (PQCrypto::SIGN_SECRET_KEY_BYTES - 1)).to_der)

    assert_raises(PQCrypto::SerializationError) do
      PQCrypto::PKCS8.decode_der(der)
    end
  end

  def test_decode_der_rejects_algorithm_identifier_null_parameters
    der = pkcs8_der(
      OpenSSL::ASN1::OctetString.new("\0" * PQCrypto::SIGN_SECRET_KEY_BYTES).to_der,
      algorithm_identifier: OpenSSL::ASN1::Sequence.new([
        OpenSSL::ASN1::ObjectId.new("2.16.840.1.101.3.4.3.18"),
        OpenSSL::ASN1::Null.new(nil),
      ])
    )

    assert_raises(PQCrypto::SerializationError) do
      PQCrypto::PKCS8.decode_der(der)
    end
  end

  private

  def pkcs8_der(choice_der, algorithm_identifier: nil)
    algorithm_identifier ||= OpenSSL::ASN1::Sequence.new([
      OpenSSL::ASN1::ObjectId.new("2.16.840.1.101.3.4.3.18"),
    ])

    OpenSSL::ASN1::Sequence.new([
      OpenSSL::ASN1::Integer.new(0),
      algorithm_identifier,
      OpenSSL::ASN1::OctetString.new(choice_der),
    ]).to_der
  end

  def seed_choice_der(seed)
    0x80.chr.b + seed.bytesize.chr.b + seed
  end
end
