# frozen_string_literal: true

require "digest"
require_relative "test_helper"

class TestRegressionMLDSA < Minitest::Test
  KEYPAIR_SEED = ["22" * 32].pack("H*")
  SIGNING_SEED = ["33" * 32].pack("H*")
  MESSAGE = "pq_crypto deterministic regression"

  def test_deterministic_keypair_and_signature_round_trip
    public_key, secret_key = PQCrypto::Testing.ml_dsa_keypair_from_seed(KEYPAIR_SEED)
    signature = PQCrypto::Testing.ml_dsa_sign_from_seed(MESSAGE, secret_key, SIGNING_SEED)

    verifier = PQCrypto::Signature.public_key_from_bytes(:ml_dsa_65, public_key)
    assert verifier.verify(MESSAGE, signature)
    refute verifier.verify("wrong message", signature)
  end

  def test_same_seed_is_reproducible
    pk1, sk1 = PQCrypto::Testing.ml_dsa_keypair_from_seed(KEYPAIR_SEED)
    pk2, sk2 = PQCrypto::Testing.ml_dsa_keypair_from_seed(KEYPAIR_SEED)
    sig1 = PQCrypto::Testing.ml_dsa_sign_from_seed(MESSAGE, sk1, SIGNING_SEED)
    sig2 = PQCrypto::Testing.ml_dsa_sign_from_seed(MESSAGE, sk1, SIGNING_SEED)

    assert_equal pk1, pk2
    assert_equal sk1, sk2
    assert_equal sig1, sig2
  end

  def test_different_seeds_diverge
    pk1, _sk1 = PQCrypto::Testing.ml_dsa_keypair_from_seed(KEYPAIR_SEED)
    other = ["44" * 32].pack("H*")
    pk2, _sk2 = PQCrypto::Testing.ml_dsa_keypair_from_seed(other)
    refute_equal pk1, pk2
  end

  def test_deterministic_signing_hook_requires_32_byte_seed
    _, secret_key = PQCrypto::Testing.ml_dsa_keypair_from_seed(KEYPAIR_SEED)

    error = assert_raises(PQCrypto::InvalidKeyError) do
      PQCrypto::Testing.ml_dsa_sign_from_seed(MESSAGE, secret_key, "short")
    end
    assert_match(/32 bytes/, error.message)
  end
end
