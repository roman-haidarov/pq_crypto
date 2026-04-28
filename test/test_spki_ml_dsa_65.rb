# frozen_string_literal: true

require "openssl"
require_relative "test_helper"

class TestPQCryptoSPKIMLDSA65 < Minitest::Test
  def test_der_round_trip
    keypair = PQCrypto::Signature.generate(:ml_dsa_65)
    der = keypair.public_key.to_spki_der

    imported = PQCrypto::Signature.public_key_from_spki_der(der)

    assert_equal :ml_dsa_65, imported.algorithm
    assert_equal keypair.public_key.to_bytes, imported.to_bytes
    assert_equal der, imported.to_spki_der
  end

  def test_pem_round_trip
    keypair = PQCrypto::Signature.generate(:ml_dsa_65)
    pem = keypair.public_key.to_spki_pem

    imported = PQCrypto::Signature.public_key_from_spki_pem(pem)

    assert_equal :ml_dsa_65, imported.algorithm
    assert_equal keypair.public_key.to_bytes, imported.to_bytes
    assert_equal pem, imported.to_spki_pem
  end

  def test_public_key_from_spki_der_rejects_algorithm_mismatch
    keypair = PQCrypto::Signature.generate(:ml_dsa_65)

    assert_raises(PQCrypto::SerializationError) do
      PQCrypto::Signature.public_key_from_spki_der(keypair.public_key.to_spki_der, algorithm: :not_real)
    end
  end

  def test_imported_public_key_verifies_signature
    keypair = PQCrypto::Signature.generate(:ml_dsa_65)
    imported = PQCrypto::Signature.public_key_from_spki_der(keypair.public_key.to_spki_der)
    signature = keypair.secret_key.sign("spki-ml-dsa")

    assert imported.verify("spki-ml-dsa", signature)
  end

  def test_decode_der_rejects_algorithm_identifier_null_parameters
    der = spki_der(
      OpenSSL::ASN1::Sequence.new([
        OpenSSL::ASN1::ObjectId.new("2.16.840.1.101.3.4.3.18"),
        OpenSSL::ASN1::Null.new(nil),
      ]),
      "\0" * PQCrypto::SIGN_PUBLIC_KEY_BYTES
    )

    assert_raises(PQCrypto::SerializationError) do
      PQCrypto::SPKI.decode_der(der)
    end
  end

  def test_decode_der_rejects_wrong_size_bit_string
    der = spki_der(
      OpenSSL::ASN1::Sequence.new([
        OpenSSL::ASN1::ObjectId.new("2.16.840.1.101.3.4.3.18"),
      ]),
      "\0" * (PQCrypto::SIGN_PUBLIC_KEY_BYTES - 1)
    )

    assert_raises(PQCrypto::SerializationError) do
      PQCrypto::SPKI.decode_der(der)
    end
  end

  def test_details_oid_still_uses_legacy_oid
    assert_equal "2.25.305232938483772195555080795650659207792",
                 PQCrypto::Signature.details(:ml_dsa_65).fetch(:oid)
  end

  private

  def spki_der(algorithm_identifier, public_key_bytes)
    OpenSSL::ASN1::Sequence.new([
      algorithm_identifier,
      OpenSSL::ASN1::BitString.new(public_key_bytes),
    ]).to_der
  end
end
