# frozen_string_literal: true

require "digest"
require_relative "test_helper"

class TestKATMLKEM < Minitest::Test
  KEYPAIR_SEED = ["00" * 32].pack("H*")
  ENCAPSULATION_SEED = ["11" * 32].pack("H*")

  EXPECTED = {
    public_key_sha256: "1e0b70e4b55e3b3e5f76abba6b4b5f036938b9dacb5d0f4eb6af38bb40fe9746",
    secret_key_sha256: "cd35e40d18c50771731a4c8e9905f11764c5cf59b303f5ee069763b04eda764d",
    ciphertext_sha256: "04012ad88c19da7a519a19639699e77c1290c4c4bc56a47e28da427a88245870",
    shared_secret_sha256: "4496bc4351a4eef33c2a72d76876280da2a4c155538d6fadf2b065a1fb1997e3",
  }.freeze

  def test_deterministic_keypair_and_encapsulation_match_regression_vectors
    public_key, secret_key = PQCrypto::Testing.ml_kem_keypair_from_seed(KEYPAIR_SEED)
    ciphertext, shared_secret = PQCrypto::Testing.ml_kem_encapsulate_from_seed(public_key, ENCAPSULATION_SEED)

    assert_equal EXPECTED[:public_key_sha256], Digest::SHA256.hexdigest(public_key)
    assert_equal EXPECTED[:secret_key_sha256], Digest::SHA256.hexdigest(secret_key)
    assert_equal EXPECTED[:ciphertext_sha256], Digest::SHA256.hexdigest(ciphertext)
    assert_equal EXPECTED[:shared_secret_sha256], Digest::SHA256.hexdigest(shared_secret)

    recovered = PQCrypto::KEM.secret_key_from_bytes(:ml_kem_768, secret_key).decapsulate(ciphertext)
    assert_equal shared_secret, recovered
  end

  def test_same_seed_is_reproducible
    pk1, sk1 = PQCrypto::Testing.ml_kem_keypair_from_seed(KEYPAIR_SEED)
    pk2, sk2 = PQCrypto::Testing.ml_kem_keypair_from_seed(KEYPAIR_SEED)

    assert_equal pk1, pk2
    assert_equal sk1, sk2

    ct1, ss1 = PQCrypto::Testing.ml_kem_encapsulate_from_seed(pk1, ENCAPSULATION_SEED)
    ct2, ss2 = PQCrypto::Testing.ml_kem_encapsulate_from_seed(pk1, ENCAPSULATION_SEED)

    assert_equal ct1, ct2
    assert_equal ss1, ss2
  end

  def test_deterministic_hooks_require_32_byte_seed
    error = assert_raises(PQCrypto::InvalidKeyError) do
      PQCrypto::Testing.ml_kem_keypair_from_seed("short")
    end
    assert_match(/32 or 64 bytes/, error.message)
  end
end
