# frozen_string_literal: true

require_relative "test_helper"

class TestMLDSAContext < Minitest::Test
  def test_one_shot_sign_verify_context_for_all_mldsa_variants
    PQCrypto::Signature.supported.each do |algorithm|
      keypair = PQCrypto::Signature.generate(algorithm)
      message = "ctx-bound message".b
      signature = keypair.secret_key.sign(message, context: "ctx-a")

      assert keypair.public_key.verify(message, signature, context: "ctx-a")
      refute keypair.public_key.verify(message, signature, context: "ctx-b")
      refute keypair.public_key.verify(message, signature)
    end
  end

  def test_one_shot_sign_rejects_oversized_context
    keypair = PQCrypto::Signature.generate(:ml_dsa_65)
    assert_raises(ArgumentError) do
      keypair.secret_key.sign("message".b, context: "C" * 256)
    end
  end

  def test_one_shot_verify_rejects_oversized_context
    keypair = PQCrypto::Signature.generate(:ml_dsa_65)
    signature = keypair.secret_key.sign("message".b)
    assert_raises(ArgumentError) do
      keypair.public_key.verify("message".b, signature, context: "C" * 256)
    end
  end
end
