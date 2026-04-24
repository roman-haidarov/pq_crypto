# frozen_string_literal: true

require "digest"
require_relative "test_helper"

class TestRegressionMLKEM < Minitest::Test
  KEYPAIR_SEED = (["00" * 32].pack("H*") + ["11" * 32].pack("H*"))
  ENCAPSULATION_SEED = ["22" * 32].pack("H*")

  def test_deterministic_keypair_and_encapsulation_are_reproducible
    pk1, sk1 = PQCrypto::Testing.ml_kem_keypair_from_seed(KEYPAIR_SEED)
    pk2, sk2 = PQCrypto::Testing.ml_kem_keypair_from_seed(KEYPAIR_SEED)
    assert_equal pk1, pk2
    assert_equal sk1, sk2

    ct1, ss1 = PQCrypto::Testing.ml_kem_encapsulate_from_seed(pk1, ENCAPSULATION_SEED)
    ct2, ss2 = PQCrypto::Testing.ml_kem_encapsulate_from_seed(pk1, ENCAPSULATION_SEED)
    assert_equal ct1, ct2
    assert_equal ss1, ss2

    recovered = PQCrypto::KEM.secret_key_from_bytes(:ml_kem_768, sk1).decapsulate(ct1)
    assert_equal ss1, recovered
  end

  def test_deterministic_keypair_hook_requires_64_byte_seed
    error = assert_raises(PQCrypto::InvalidKeyError) do
      PQCrypto::Testing.ml_kem_keypair_from_seed("short")
    end
    assert_match(/64 bytes/, error.message)
  end

  def test_deterministic_keypair_hook_rejects_32_byte_seed
    error = assert_raises(PQCrypto::InvalidKeyError) do
      PQCrypto::Testing.ml_kem_keypair_from_seed(["00" * 32].pack("H*"))
    end
    assert_match(/64 bytes/, error.message)
  end

  def test_deterministic_encapsulation_hook_requires_32_byte_seed
    pk, _sk = PQCrypto::Testing.ml_kem_keypair_from_seed(KEYPAIR_SEED)
    error = assert_raises(PQCrypto::InvalidKeyError) do
      PQCrypto::Testing.ml_kem_encapsulate_from_seed(pk, "short")
    end
    assert_match(/32/, error.message)
  end
end
