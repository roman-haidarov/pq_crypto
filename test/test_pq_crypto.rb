# frozen_string_literal: true

require_relative "test_helper"

class TestPQCrypto < Minitest::Test
  def test_version_constant
    assert_equal "0.3.2", PQCrypto::VERSION
    assert_equal "0.3.2", PQCrypto.version
  end

  def test_backend_is_native_pqclean
    assert_equal :native_pqclean, PQCrypto.backend
    assert PQCrypto.native_extension_loaded?
  end

  def test_supported_algorithm_lists
    assert_equal [:ml_kem_768], PQCrypto.supported_kems
    assert_equal [:ml_kem_768_x25519_xwing], PQCrypto.supported_hybrid_kems
    assert_equal [:ml_dsa_65], PQCrypto.supported_signatures
  end

  def test_secure_wipe_requires_mutable_string
    error = assert_raises(ArgumentError) do
      PQCrypto.secure_wipe("secret".freeze)
    end

    assert_match(/mutable String/, error.message)
  end

  def test_secure_wipe_zeroes_bytes
    secret = String.new("sensitive-data")
    PQCrypto.secure_wipe(secret)

    assert_equal("\x00" * 14, secret)
  end

  def test_legacy_top_level_api_is_not_public
    refute_respond_to PQCrypto, :kem_keypair
    refute_respond_to PQCrypto, :kem_encapsulate
    refute_respond_to PQCrypto, :kem_decapsulate
    refute_respond_to PQCrypto, :sign_keypair
    refute_respond_to PQCrypto, :sign
    refute_respond_to PQCrypto, :verify
    refute_respond_to PQCrypto, :seal
    refute_respond_to PQCrypto, :unseal
    refute_respond_to PQCrypto, :sign_and_seal
    refute_respond_to PQCrypto, :unseal_and_verify
  end

  def test_protocol_helpers_are_not_public
    refute defined?(PQCrypto::Experimental)
    refute defined?(PQCrypto::Session)
    refute defined?(PQCrypto::Identity)
    refute defined?(PQCrypto::KEMKeypair)
    refute defined?(PQCrypto::SignKeypair)
  end

  def test_removed_legacy_native_entrypoints_are_absent_even_privately
    hidden = PQCrypto.singleton_class.private_instance_methods(false)

    refute_includes hidden, :kem_keypair
    refute_includes hidden, :kem_encapsulate
    refute_includes hidden, :kem_decapsulate
    refute_includes hidden, :seal
    refute_includes hidden, :unseal
    refute_includes hidden, :sign_and_seal
    refute_includes hidden, :unseal_and_verify
    refute_includes hidden, :establish_session
    refute_includes hidden, :accept_session
    refute_includes hidden, :public_key_pem
    refute_includes hidden, :public_key_to_spki_der
    refute_includes hidden, :secret_key_from_pkcs8_pem
  end
end
