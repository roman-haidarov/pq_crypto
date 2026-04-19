# frozen_string_literal: true

require_relative "test_helper"

# Lightweight sanity checks that the gem was built against the right PQClean
# algorithms. These are NOT full NIST KAT vectors (which would require
# intercepting the RNG). They are a first line of defense against a build that
# accidentally links against a different algorithm variant.
#
# For full KAT validation, a future version should:
#   - link against PQClean's test harness with a deterministic DRBG,
#   - load official FIPS 203 / 204 intermediate values,
#   - compare byte-for-byte.
class TestFIPSConstants < Minitest::Test
  # FIPS 203 - ML-KEM-768
  def test_ml_kem_768_sizes
    assert_equal 1184, PQCrypto::KEM_PUBLIC_KEY_BYTES - 32, "ML-KEM-768 pubkey should be 1184 (+32 X25519)"
    assert_equal 2400, PQCrypto::KEM_SECRET_KEY_BYTES - 32, "ML-KEM-768 seckey should be 2400 (+32 X25519)"
    assert_equal 1088, PQCrypto::KEM_CIPHERTEXT_BYTES - 32, "ML-KEM-768 ciphertext should be 1088 (+32 X25519 ephemeral)"
    assert_equal 32, PQCrypto::KEM_SHARED_SECRET_BYTES, "hybrid shared secret is 32"
  end

  # FIPS 204 - ML-DSA-65
  def test_ml_dsa_65_sizes
    assert_equal 1952, PQCrypto::SIGN_PUBLIC_KEY_BYTES, "ML-DSA-65 pubkey is 1952"
    assert_equal 4032, PQCrypto::SIGN_SECRET_KEY_BYTES, "ML-DSA-65 seckey is 4032"
    assert_equal 3309, PQCrypto::SIGN_BYTES, "ML-DSA-65 max signature is 3309"
  end

  def test_aes_gcm_session_overhead
    # nonce(12) + tag(16) = 28 bytes
    assert_equal 28, PQCrypto::SESSION_OVERHEAD
  end

  def test_deterministic_roundtrip_stability
    # Not a KAT, but a regression test: encapsulate+decapsulate must agree
    # over many iterations. Catches RNG or buffer-size regressions.
    10.times do
      pk, sk = PQCrypto.kem_keypair
      ct, ss1 = PQCrypto.kem_encapsulate(pk)
      ss2 = PQCrypto.kem_decapsulate(ct, sk)
      assert_equal ss1, ss2
      assert_equal 32, ss1.bytesize
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
