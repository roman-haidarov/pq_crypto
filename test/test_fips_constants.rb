# frozen_string_literal: true

require_relative "test_helper"

# Lightweight sanity checks that the gem was built against the right PQClean
# algorithms. These are NOT full NIST KAT vectors (which would require
# intercepting the RNG). They are a first line of defense against a build that
# accidentally links against a different algorithm variant.
class TestFIPSConstants < Minitest::Test
  # FIPS 203 - ML-KEM-768 (pure primitive)
  def test_ml_kem_768_sizes
    assert_equal 1184, PQCrypto::ML_KEM_PUBLIC_KEY_BYTES, "ML-KEM-768 pubkey is 1184"
    assert_equal 2400, PQCrypto::ML_KEM_SECRET_KEY_BYTES, "ML-KEM-768 seckey is 2400"
    assert_equal 1088, PQCrypto::ML_KEM_CIPHERTEXT_BYTES, "ML-KEM-768 ciphertext is 1088"
    assert_equal 32, PQCrypto::ML_KEM_SHARED_SECRET_BYTES, "ML-KEM-768 shared secret is 32"
  end

  # Legacy compatibility KEM surface remains hybrid until the old protocol API is removed.
  def test_hybrid_kem_sizes
    assert_equal 1184, PQCrypto::KEM_PUBLIC_KEY_BYTES - 32, "legacy KEM pubkey keeps ML-KEM-768 + 32 X25519"
    assert_equal 2400, PQCrypto::KEM_SECRET_KEY_BYTES - 32, "legacy KEM seckey keeps ML-KEM-768 + 32 X25519"
    assert_equal 1088, PQCrypto::KEM_CIPHERTEXT_BYTES - 32, "legacy KEM ciphertext keeps ML-KEM-768 + 32 X25519"
    assert_equal 32, PQCrypto::KEM_SHARED_SECRET_BYTES, "legacy hybrid shared secret is 32"
  end

  # FIPS 204 - ML-DSA-65
  def test_ml_dsa_65_sizes
    assert_equal 1952, PQCrypto::SIGN_PUBLIC_KEY_BYTES, "ML-DSA-65 pubkey is 1952"
    assert_equal 4032, PQCrypto::SIGN_SECRET_KEY_BYTES, "ML-DSA-65 seckey is 4032"
    assert_equal 3309, PQCrypto::SIGN_BYTES, "ML-DSA-65 max signature is 3309"
  end

  def test_aes_gcm_session_overhead
    assert_equal 28, PQCrypto::SESSION_OVERHEAD
  end

  def test_legacy_hybrid_roundtrip_stability
    10.times do
      pk, sk = PQCrypto.kem_keypair
      ct, ss1 = PQCrypto.kem_encapsulate(pk)
      ss2 = PQCrypto.kem_decapsulate(ct, sk)
      assert_equal ss1, ss2
      assert_equal 32, ss1.bytesize
    end
  end

  def test_pure_ml_kem_roundtrip_stability
    10.times do
      keypair = PQCrypto::KEM.generate(:ml_kem_768)
      result = keypair.public_key.encapsulate
      ss2 = keypair.secret_key.decapsulate(result.ciphertext)
      assert_equal result.shared_secret, ss2
      assert_equal 32, ss2.bytesize
    end
  end

  def test_sign_verify_stability
    pk, sk = PQCrypto.sign_keypair
    10.times do |i|
      msg = "message #{i}"
      sig = PQCrypto.sign(msg, sk)
      assert PQCrypto.verify(msg, sig, pk)
      assert_operator sig.bytesize, :<=, PQCrypto::SIGN_BYTES
    end
  end
end
