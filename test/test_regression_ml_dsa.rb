# frozen_string_literal: true

require "digest"
require_relative "test_helper"

class TestRegressionMLDSA < Minitest::Test
  KEYPAIR_SEED = ["22" * 32].pack("H*")
  SIGNING_SEED = ["33" * 32].pack("H*")
  MESSAGE = "pq_crypto deterministic regression"

  EXPECTED = {
    public_key_sha256: "c1f4a9647ca87f13ac5d2fb8cfaa4d3c40f89793171e13cd2130c1c44efbc19f",
    secret_key_sha256: "e72fda582e734d36fd3a05623822d32c600ec7fd6b95da418cfcecc4a4dcaae5",
    signature_sha256: "622adc2bf5a505e96687e285185342b7c1c5117b54d9e7d83889bccb54214235",
  }.freeze

  def test_deterministic_keypair_and_signature_match_regression_vectors
    public_key, secret_key = PQCrypto::Testing.ml_dsa_keypair_from_seed(KEYPAIR_SEED)
    signature = PQCrypto::Testing.ml_dsa_sign_from_seed(MESSAGE, secret_key, SIGNING_SEED)

    assert_equal EXPECTED[:public_key_sha256], Digest::SHA256.hexdigest(public_key)
    assert_equal EXPECTED[:secret_key_sha256], Digest::SHA256.hexdigest(secret_key)
    assert_equal EXPECTED[:signature_sha256], Digest::SHA256.hexdigest(signature)

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

  def test_deterministic_signing_hook_requires_32_byte_seed
    _, secret_key = PQCrypto::Testing.ml_dsa_keypair_from_seed(KEYPAIR_SEED)

    error = assert_raises(PQCrypto::InvalidKeyError) do
      PQCrypto::Testing.ml_dsa_sign_from_seed(MESSAGE, secret_key, "short")
    end
    assert_match(/32 bytes/, error.message)
  end
end
