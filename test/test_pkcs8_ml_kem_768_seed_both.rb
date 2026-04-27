# frozen_string_literal: true

require "openssl"
require_relative "test_helper"

class TestPQCryptoPKCS8MLKEM768SeedBoth < Minitest::Test
  FIXTURE_DIR = File.expand_path("fixtures/rfc9935", __dir__)
  SEED = (0...64).to_a.pack("C*").b

  def test_decode_rfc9935_seed_fixture
    algorithm, format, material = PQCrypto::PKCS8.decode_pem(read_fixture("ml_kem_768_seed.pem"))

    assert_equal :ml_kem_768, algorithm
    assert_equal :seed, format
    assert_equal SEED, material
  end

  def test_decode_rfc9935_expanded_fixture
    algorithm, format, material = PQCrypto::PKCS8.decode_pem(read_fixture("ml_kem_768_expanded.pem"))

    assert_equal :ml_kem_768, algorithm
    assert_equal :expanded, format
    assert_equal PQCrypto::ML_KEM_SECRET_KEY_BYTES, material.bytesize
  end

  def test_decode_rfc9935_both_fixture
    algorithm, format, material = PQCrypto::PKCS8.decode_pem(read_fixture("ml_kem_768_both.pem"))

    assert_equal :ml_kem_768, algorithm
    assert_equal :both, format
    assert_equal SEED, material.fetch(0)
    assert_equal PQCrypto::ML_KEM_SECRET_KEY_BYTES, material.fetch(1).bytesize
  end

  def test_rfc9935_fixtures_round_trip_byte_for_byte
    {
      "ml_kem_768_seed.pem" => :seed,
      "ml_kem_768_expanded.pem" => :expanded,
      "ml_kem_768_both.pem" => :both,
    }.each do |filename, expected_format|
      pem = read_fixture(filename)
      original_der = der_from_pem(pem)
      algorithm, format, material = PQCrypto::PKCS8.decode_pem(pem)
      reencoded_der = PQCrypto::PKCS8.encode_der(algorithm, material, format: format)
      reencoded_pem_der = der_from_pem(PQCrypto::PKCS8.encode_pem(algorithm, material, format: format))

      assert_equal :ml_kem_768, algorithm
      assert_equal expected_format, format
      assert_equal original_der, reencoded_der, "#{filename} DER did not round-trip"
      assert_equal original_der, reencoded_pem_der, "#{filename} PEM did not round-trip"
    end
  end

  def test_decode_seed_import_to_secret_key_mentions_patch_4
    error = assert_raises(PQCrypto::SerializationError) do
      PQCrypto::KEM.secret_key_from_pkcs8_pem(read_fixture("ml_kem_768_seed.pem"))
    end

    assert_match(/Patch 4 seed expansion/, error.message)
  end

  def test_decode_both_imports_secret_key_from_expanded_half
    _algorithm, _format, (_seed, expanded) = PQCrypto::PKCS8.decode_pem(read_fixture("ml_kem_768_both.pem"))

    secret_key = PQCrypto::KEM.secret_key_from_pkcs8_pem(read_fixture("ml_kem_768_both.pem"))

    assert_equal :ml_kem_768, secret_key.algorithm
    assert_equal expanded, secret_key.to_bytes
  end

  def test_encode_der_rejects_32_byte_seed
    error = assert_raises(PQCrypto::SerializationError) do
      PQCrypto::PKCS8.encode_der(:ml_kem_768, "\0" * 32, format: :seed)
    end

    assert_match(/seed private key length/, error.message)
  end

  def test_decode_der_rejects_both_sequence_with_extra_element
    der = pkcs8_der(OpenSSL::ASN1::Sequence.new([
      OpenSSL::ASN1::OctetString.new(SEED),
      OpenSSL::ASN1::OctetString.new("\0" * PQCrypto::ML_KEM_SECRET_KEY_BYTES),
      OpenSSL::ASN1::OctetString.new("extra"),
    ]).to_der)

    assert_raises(PQCrypto::SerializationError) do
      PQCrypto::PKCS8.decode_der(der)
    end
  end

  private

  def read_fixture(filename)
    File.read(File.join(FIXTURE_DIR, filename))
  end

  def der_from_pem(pem)
    body = pem.lines.reject { |line| line.start_with?("-----") }.join
    body.gsub(/[\r\n]/, "").unpack1("m0").b
  end

  def pkcs8_der(choice_der)
    OpenSSL::ASN1::Sequence.new([
      OpenSSL::ASN1::Integer.new(0),
      OpenSSL::ASN1::Sequence.new([
        OpenSSL::ASN1::ObjectId.new("2.16.840.1.101.3.4.4.2"),
      ]),
      OpenSSL::ASN1::OctetString.new(choice_der),
    ]).to_der
  end
end
