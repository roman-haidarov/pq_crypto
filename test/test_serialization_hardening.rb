# frozen_string_literal: true

require_relative "test_helper"

class TestPQCryptoSerializationHardening < Minitest::Test
  def test_rejects_random_der_garbage
    assert_raises(PQCrypto::SerializationError) do
      PQCrypto::KEM.public_key_from_pqc_container_der("not-a-valid-container")
    end
  end

  def test_rejects_truncated_public_container_prefixes
    keypair = PQCrypto::KEM.generate(:ml_kem_768)
    der = keypair.public_key.to_pqc_container_der

    [0, 1, 4, 8, 12, der.bytesize - 1].uniq.each do |prefix_len|
      next if prefix_len >= der.bytesize

      assert_raises(PQCrypto::SerializationError, "prefix_len=#{prefix_len}") do
        PQCrypto::KEM.public_key_from_pqc_container_der(der.byteslice(0, prefix_len))
      end
    end
  end

  def test_rejects_public_container_when_secret_expected
    keypair = PQCrypto::KEM.generate(:ml_kem_768)
    der = keypair.public_key.to_pqc_container_der

    assert_raises(PQCrypto::SerializationError) do
      PQCrypto::KEM.secret_key_from_pqc_container_der(der)
    end
  end

  def test_rejects_secret_container_when_public_expected
    keypair = PQCrypto::Signature.generate(:ml_dsa_65)
    pem = keypair.secret_key.to_pqc_container_pem

    assert_raises(PQCrypto::SerializationError) do
      PQCrypto::Signature.public_key_from_pqc_container_pem(pem)
    end
  end

  def test_rejects_bad_base64_pem_body
    bad_pem = <<~PEM
      -----BEGIN PQC PUBLIC KEY CONTAINER-----
      !!!!
      -----END PQC PUBLIC KEY CONTAINER-----
    PEM

    assert_raises(PQCrypto::SerializationError) do
      PQCrypto::KEM.public_key_from_pqc_container_pem(bad_pem)
    end
  end

  def test_rejects_trailing_non_whitespace_after_footer
    keypair = PQCrypto::Signature.generate(:ml_dsa_65)
    pem = keypair.public_key.to_pqc_container_pem + "TRAILING-GARBAGE"

    assert_raises(PQCrypto::SerializationError) do
      PQCrypto::Signature.public_key_from_pqc_container_pem(pem)
    end
  end

  def test_rejects_container_with_bogus_key_length_field
    keypair = PQCrypto::KEM.generate(:ml_kem_768)
    der = keypair.public_key.to_pqc_container_der.dup

    oid_len = ((der.getbyte(6) << 8) | der.getbyte(7))
    key_len_offset = 8 + oid_len
    der.setbyte(key_len_offset + 0, 0x00)
    der.setbyte(key_len_offset + 1, 0x00)
    der.setbyte(key_len_offset + 2, 0xFF)
    der.setbyte(key_len_offset + 3, 0xFF)

    assert_raises(PQCrypto::SerializationError) do
      PQCrypto::KEM.public_key_from_pqc_container_der(der)
    end
  end

  def test_rejects_pem_with_embedded_nul_in_body
    keypair = PQCrypto::HybridKEM.generate(:ml_kem_768_x25519_xwing)
    pem = keypair.public_key.to_pqc_container_pem.sub("\n-----END", "\0\n-----END")

    assert_raises(PQCrypto::SerializationError) do
      PQCrypto::HybridKEM.public_key_from_pqc_container_pem(pem)
    end
  end
end
