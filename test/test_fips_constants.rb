# frozen_string_literal: true

require_relative "test_helper"

class TestFIPSConstants < Minitest::Test
  def test_ml_kem_768_sizes
    assert_equal 1184, PQCrypto::ML_KEM_PUBLIC_KEY_BYTES
    assert_equal 2400, PQCrypto::ML_KEM_SECRET_KEY_BYTES
    assert_equal 1088, PQCrypto::ML_KEM_CIPHERTEXT_BYTES
    assert_equal 32, PQCrypto::ML_KEM_SHARED_SECRET_BYTES
  end

  def test_hybrid_kem_sizes
    assert_equal 1216, PQCrypto::HYBRID_KEM_PUBLIC_KEY_BYTES
    assert_equal 2432, PQCrypto::HYBRID_KEM_SECRET_KEY_BYTES
    assert_equal 1120, PQCrypto::HYBRID_KEM_CIPHERTEXT_BYTES
    assert_equal 32, PQCrypto::HYBRID_KEM_SHARED_SECRET_BYTES
  end

  def test_ml_dsa_65_sizes
    assert_equal 1952, PQCrypto::SIGN_PUBLIC_KEY_BYTES
    assert_equal 4032, PQCrypto::SIGN_SECRET_KEY_BYTES
    assert_equal 3309, PQCrypto::SIGN_BYTES
  end

  def test_pure_ml_kem_roundtrip_stability
    10.times do
      keypair = PQCrypto::KEM.generate(:ml_kem_768)
      result = keypair.public_key.encapsulate
      shared_secret = keypair.secret_key.decapsulate(result.ciphertext)
      assert_equal result.shared_secret, shared_secret
      assert_equal 32, shared_secret.bytesize
    end
  end

  def test_hybrid_kem_roundtrip_stability
    10.times do
      keypair = PQCrypto::HybridKEM.generate(:ml_kem_768_x25519_hkdf_sha256)
      result = keypair.public_key.encapsulate
      shared_secret = keypair.secret_key.decapsulate(result.ciphertext)
      assert_equal result.shared_secret, shared_secret
      assert_equal 32, shared_secret.bytesize
    end
  end

  def test_sign_verify_stability
    keypair = PQCrypto::Signature.generate(:ml_dsa_65)
    10.times do |i|
      msg = "message #{i}"
      sig = keypair.secret_key.sign(msg)
      assert keypair.public_key.verify(msg, sig)
      assert_operator sig.bytesize, :<=, PQCrypto::SIGN_BYTES
    end
  end
end
