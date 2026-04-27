# frozen_string_literal: true

require "openssl"
require_relative "test_helper"

class TestPQCryptoSPKIMLKEM768 < Minitest::Test
  def test_der_round_trip
    keypair = PQCrypto::KEM.generate(:ml_kem_768)
    der = keypair.public_key.to_spki_der

    imported = PQCrypto::KEM.public_key_from_spki_der(der)

    assert_equal :ml_kem_768, imported.algorithm
    assert_equal keypair.public_key.to_bytes, imported.to_bytes
    assert_equal der, imported.to_spki_der
  end

  def test_pem_round_trip
    keypair = PQCrypto::KEM.generate(:ml_kem_768)
    pem = keypair.public_key.to_spki_pem

    imported = PQCrypto::KEM.public_key_from_spki_pem(pem)

    assert_equal :ml_kem_768, imported.algorithm
    assert_equal keypair.public_key.to_bytes, imported.to_bytes
    assert_equal pem, imported.to_spki_pem
  end

  def test_public_key_from_spki_der_rejects_algorithm_mismatch
    keypair = PQCrypto::KEM.generate(:ml_kem_768)

    assert_raises(PQCrypto::SerializationError) do
      PQCrypto::KEM.public_key_from_spki_der(keypair.public_key.to_spki_der, algorithm: :not_real)
    end
  end

  def test_decode_der_rejects_garbage
    assert_raises(PQCrypto::SerializationError) do
      PQCrypto::SPKI.decode_der("not-a-valid-spki")
    end
  end

  def test_decode_der_rejects_algorithm_identifier_null_parameters
    der = spki_der(
      OpenSSL::ASN1::Sequence.new([
        OpenSSL::ASN1::ObjectId.new("2.16.840.1.101.3.4.4.2"),
        OpenSSL::ASN1::Null.new(nil),
      ]),
      "\0" * PQCrypto::ML_KEM_PUBLIC_KEY_BYTES
    )

    assert_raises(PQCrypto::SerializationError) do
      PQCrypto::SPKI.decode_der(der)
    end
  end

  def test_decode_der_rejects_unknown_oid
    der = spki_der(
      OpenSSL::ASN1::Sequence.new([
        OpenSSL::ASN1::ObjectId.new("1.2.3.4"),
      ]),
      "\0" * PQCrypto::ML_KEM_PUBLIC_KEY_BYTES
    )

    assert_raises(PQCrypto::SerializationError) do
      PQCrypto::SPKI.decode_der(der)
    end
  end

  def test_decode_der_rejects_wrong_size_bit_string
    der = spki_der(
      OpenSSL::ASN1::Sequence.new([
        OpenSSL::ASN1::ObjectId.new("2.16.840.1.101.3.4.4.2"),
      ]),
      "\0" * (PQCrypto::ML_KEM_PUBLIC_KEY_BYTES - 1)
    )

    assert_raises(PQCrypto::SerializationError) do
      PQCrypto::SPKI.decode_der(der)
    end
  end

  def test_decode_der_rejects_non_zero_unused_bits
    bit_string = OpenSSL::ASN1::BitString.new("\0" * PQCrypto::ML_KEM_PUBLIC_KEY_BYTES)
    bit_string.unused_bits = 1
    der = OpenSSL::ASN1::Sequence.new([
      OpenSSL::ASN1::Sequence.new([
        OpenSSL::ASN1::ObjectId.new("2.16.840.1.101.3.4.4.2"),
      ]),
      bit_string,
    ]).to_der

    assert_raises(PQCrypto::SerializationError) do
      PQCrypto::SPKI.decode_der(der)
    end
  end

  def test_decode_der_rejects_trailing_garbage
    keypair = PQCrypto::KEM.generate(:ml_kem_768)

    assert_raises(PQCrypto::SerializationError) do
      PQCrypto::SPKI.decode_der(keypair.public_key.to_spki_der + "TRAILING-GARBAGE")
    end
  end

  def test_decode_pem_rejects_embedded_nul
    keypair = PQCrypto::KEM.generate(:ml_kem_768)
    pem = keypair.public_key.to_spki_pem.sub("\n-----END", "\0\n-----END")

    assert_raises(PQCrypto::SerializationError) do
      PQCrypto::SPKI.decode_pem(pem)
    end
  end

  def test_decode_pem_rejects_trailing_garbage_after_end_line
    keypair = PQCrypto::KEM.generate(:ml_kem_768)

    assert_raises(PQCrypto::SerializationError) do
      PQCrypto::SPKI.decode_pem(keypair.public_key.to_spki_pem + "TRAILING-GARBAGE")
    end
  end

  def test_decode_pem_rejects_wrong_label
    keypair = PQCrypto::KEM.generate(:ml_kem_768)
    pem = keypair.public_key.to_spki_pem.sub("PUBLIC KEY", "PQC PUBLIC KEY CONTAINER")

    assert_raises(PQCrypto::SerializationError) do
      PQCrypto::SPKI.decode_pem(pem)
    end
  end

  def test_details_oid_still_uses_legacy_oid
    assert_equal "2.25.186599352125448088867056807454444238446",
                 PQCrypto::KEM.details(:ml_kem_768).fetch(:oid)
  end

  private

  def spki_der(algorithm_identifier, public_key_bytes)
    OpenSSL::ASN1::Sequence.new([
      algorithm_identifier,
      OpenSSL::ASN1::BitString.new(public_key_bytes),
    ]).to_der
  end
end
