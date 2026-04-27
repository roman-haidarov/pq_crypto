# frozen_string_literal: true

require "openssl"
require_relative "test_helper"

class TestPQCryptoPKCS8MLKEM768Expanded < Minitest::Test
  def test_der_round_trip
    keypair = PQCrypto::KEM.generate(:ml_kem_768)
    der = keypair.secret_key.to_pkcs8_der

    imported = PQCrypto::KEM.secret_key_from_pkcs8_der(der)
    algorithm, format, material = PQCrypto::PKCS8.decode_der(der)

    assert_equal :ml_kem_768, imported.algorithm
    assert_equal keypair.secret_key.to_bytes, imported.to_bytes
    assert_equal :ml_kem_768, algorithm
    assert_equal :expanded, format
    assert_equal keypair.secret_key.to_bytes, material
    assert_equal der, imported.to_pkcs8_der
  end

  def test_pem_round_trip
    keypair = PQCrypto::KEM.generate(:ml_kem_768)
    pem = keypair.secret_key.to_pkcs8_pem

    imported = PQCrypto::KEM.secret_key_from_pkcs8_pem(pem)

    assert_equal :ml_kem_768, imported.algorithm
    assert_equal keypair.secret_key.to_bytes, imported.to_bytes
    assert_equal pem, imported.to_pkcs8_pem
  end

  def test_to_pkcs8_rejects_non_expanded_formats_until_patch_2c
    secret_key = PQCrypto::KEM.generate(:ml_kem_768).secret_key

    [:seed, :both].each do |format|
      error = assert_raises(PQCrypto::SerializationError) do
        secret_key.to_pkcs8_der(format: format)
      end
      assert_match(/Patch 2c/, error.message)
    end
  end

  def test_decode_der_of_seed_format_mentions_patch_2c
    der = pkcs8_der(seed_choice_der("\0" * 64))

    error = assert_raises(PQCrypto::SerializationError) do
      PQCrypto::PKCS8.decode_der(der)
    end

    assert_match(/Patch 2c/, error.message)
  end

  def test_decode_der_of_both_format_mentions_patch_2c
    der = pkcs8_der(OpenSSL::ASN1::Sequence.new([
      OpenSSL::ASN1::OctetString.new("\0" * 64),
      OpenSSL::ASN1::OctetString.new("\0" * PQCrypto::ML_KEM_SECRET_KEY_BYTES),
    ]).to_der)

    error = assert_raises(PQCrypto::SerializationError) do
      PQCrypto::PKCS8.decode_der(der)
    end

    assert_match(/Patch 2c/, error.message)
  end

  def test_decode_der_rejects_garbage
    assert_raises(PQCrypto::SerializationError) do
      PQCrypto::PKCS8.decode_der("not-a-valid-pkcs8")
    end
  end

  def test_decode_der_rejects_unknown_oid
    der = pkcs8_der(
      OpenSSL::ASN1::OctetString.new("\0" * PQCrypto::ML_KEM_SECRET_KEY_BYTES).to_der,
      oid: "1.2.3.4"
    )

    assert_raises(PQCrypto::SerializationError) do
      PQCrypto::PKCS8.decode_der(der)
    end
  end

  def test_decode_der_rejects_wrong_expanded_key_size
    der = pkcs8_der(OpenSSL::ASN1::OctetString.new("\0" * (PQCrypto::ML_KEM_SECRET_KEY_BYTES - 1)).to_der)

    assert_raises(PQCrypto::SerializationError) do
      PQCrypto::PKCS8.decode_der(der)
    end
  end

  def test_decode_der_rejects_algorithm_identifier_null_parameters
    der = pkcs8_der(
      OpenSSL::ASN1::OctetString.new("\0" * PQCrypto::ML_KEM_SECRET_KEY_BYTES).to_der,
      algorithm_identifier: OpenSSL::ASN1::Sequence.new([
        OpenSSL::ASN1::ObjectId.new("2.16.840.1.101.3.4.4.2"),
        OpenSSL::ASN1::Null.new(nil),
      ])
    )

    assert_raises(PQCrypto::SerializationError) do
      PQCrypto::PKCS8.decode_der(der)
    end
  end

  def test_decode_der_rejects_trailing_garbage
    keypair = PQCrypto::KEM.generate(:ml_kem_768)

    assert_raises(PQCrypto::SerializationError) do
      PQCrypto::PKCS8.decode_der(keypair.secret_key.to_pkcs8_der + "TRAILING-GARBAGE")
    end
  end

  def test_decode_der_rejects_trailing_garbage_inside_private_key_choice
    inner = OpenSSL::ASN1::OctetString.new("\0" * PQCrypto::ML_KEM_SECRET_KEY_BYTES).to_der + "TRAILING"
    der = pkcs8_der(inner)

    assert_raises(PQCrypto::SerializationError) do
      PQCrypto::PKCS8.decode_der(der)
    end
  end

  def test_decode_pem_rejects_wrong_label
    keypair = PQCrypto::KEM.generate(:ml_kem_768)
    pem = keypair.secret_key.to_pkcs8_pem.sub("PRIVATE KEY", "PQC PRIVATE KEY CONTAINER")

    assert_raises(PQCrypto::SerializationError) do
      PQCrypto::PKCS8.decode_pem(pem)
    end
  end

  private

  def pkcs8_der(choice_der, oid: "2.16.840.1.101.3.4.4.2", algorithm_identifier: nil)
    algorithm_identifier ||= OpenSSL::ASN1::Sequence.new([
      OpenSSL::ASN1::ObjectId.new(oid),
    ])

    OpenSSL::ASN1::Sequence.new([
      OpenSSL::ASN1::Integer.new(0),
      algorithm_identifier,
      OpenSSL::ASN1::OctetString.new(choice_der),
    ]).to_der
  end

  def seed_choice_der(seed)
    OpenSSL::ASN1::ASN1Data.new(seed, 0, :CONTEXT_SPECIFIC).to_der
  end
end
