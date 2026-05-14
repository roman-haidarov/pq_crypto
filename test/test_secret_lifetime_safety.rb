# frozen_string_literal: true

require_relative "test_helper"

class TestSecretLifetimeSafety < Minitest::Test
  def test_hybrid_kem_wipe_releases_expanded_secret_key_immediately
    keypair = PQCrypto::HybridKEM.generate
    encapsulation = keypair.public_key.encapsulate

    assert_equal encapsulation.shared_secret, keypair.secret_key.decapsulate(encapsulation.ciphertext)
    expanded_key = keypair.secret_key.instance_variable_get(:@expanded_key)
    refute_nil expanded_key

    keypair.secret_key.wipe!
    assert_nil keypair.secret_key.instance_variable_get(:@expanded_key)

    assert_raises(PQCrypto::Error) do
      PQCrypto.__send__(:native_hybrid_kem_decapsulate_expanded_object, encapsulation.ciphertext, expanded_key)
    end
  end

  def test_kem_secret_key_equality_does_not_call_public_to_bytes_copy
    secret_key = PQCrypto::KEM.generate(:ml_kem_768).secret_key
    secret_key.define_singleton_method(:to_bytes) { raise "to_bytes should not be used for equality" }

    assert_equal secret_key, secret_key
  end

  def test_signature_secret_key_equality_does_not_call_public_to_bytes_copy
    secret_key = PQCrypto::Signature.generate(:ml_dsa_65).secret_key
    secret_key.define_singleton_method(:to_bytes) { raise "to_bytes should not be used for equality" }

    assert_equal secret_key, secret_key
  end
end
