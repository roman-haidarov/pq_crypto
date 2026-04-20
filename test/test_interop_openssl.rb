# frozen_string_literal: true

require_relative "test_helper"
require_relative "support/interop_helper"

class TestInteropOpenSSL < Minitest::Test
  KEM_SEED = (0...64).to_a.pack("C*")
  SIG_SEED = (0...32).map { |i| (255 - i) & 0xff }.pack("C*")
  MESSAGE = "interop message for openssl"

  def setup
    skip InteropHelper.openssl_skip_reason unless InteropHelper.openssl_supported?
  end

  def test_ml_kem_keygen_from_seed_matches_openssl_raw_bytes
    ruby_pub, ruby_priv = PQCrypto::Testing.ml_kem_keypair_from_seed(KEM_SEED)
    openssl_pub_hex, openssl_priv_hex = InteropHelper.run_openssl_helper(
      "mlkem-keygen-from-seed", InteropHelper.hex(KEM_SEED)
    )

    assert_equal ruby_pub, InteropHelper.bin(openssl_pub_hex)
    assert_equal ruby_priv, InteropHelper.bin(openssl_priv_hex)
  end

  def test_ml_kem_encapsulation_interoperates_with_openssl
    ruby_pub, ruby_priv = PQCrypto::Testing.ml_kem_keypair_from_seed(KEM_SEED)
    ruby_secret_key = PQCrypto::KEM.secret_key_from_bytes(:ml_kem_768, ruby_priv)
    ruby_public_key = PQCrypto::KEM.public_key_from_bytes(:ml_kem_768, ruby_pub)

    openssl_ct_hex, openssl_ss_hex = InteropHelper.run_openssl_helper("mlkem-encap", InteropHelper.hex(ruby_pub))
    assert_equal InteropHelper.bin(openssl_ss_hex), ruby_secret_key.decapsulate(InteropHelper.bin(openssl_ct_hex))

    ruby_ciphertext, ruby_shared_secret = ruby_public_key.encapsulate_to_bytes
    openssl_shared_secret_hex = InteropHelper.run_openssl_helper(
      "mlkem-decap",
      InteropHelper.hex(ruby_priv),
      InteropHelper.hex(ruby_ciphertext)
    ).first
    assert_equal ruby_shared_secret, InteropHelper.bin(openssl_shared_secret_hex)
  end

  def test_ml_dsa_keygen_from_seed_matches_openssl_raw_bytes
    ruby_pub, ruby_priv = PQCrypto::Testing.ml_dsa_keypair_from_seed(SIG_SEED)
    openssl_pub_hex, openssl_priv_hex = InteropHelper.run_openssl_helper(
      "mldsa-keygen-from-seed",
      InteropHelper.hex(SIG_SEED)
    )

    assert_equal ruby_pub, InteropHelper.bin(openssl_pub_hex)
    assert_equal ruby_priv, InteropHelper.bin(openssl_priv_hex)
  end

  def test_ml_dsa_sign_and_verify_interoperate_with_openssl
    ruby_pub, ruby_priv = PQCrypto::Testing.ml_dsa_keypair_from_seed(SIG_SEED)
    ruby_public_key = PQCrypto::Signature.public_key_from_bytes(:ml_dsa_65, ruby_pub)
    ruby_secret_key = PQCrypto::Signature.secret_key_from_bytes(:ml_dsa_65, ruby_priv)

    openssl_signature_hex = InteropHelper.run_openssl_helper(
      "mldsa-sign",
      InteropHelper.hex(ruby_priv),
      InteropHelper.hex(MESSAGE)
    ).first
    assert ruby_public_key.verify(MESSAGE, InteropHelper.bin(openssl_signature_hex))

    ruby_signature = ruby_secret_key.sign(MESSAGE)
    assert_equal ["OK"], InteropHelper.run_openssl_helper(
      "mldsa-verify",
      InteropHelper.hex(ruby_pub),
      InteropHelper.hex(MESSAGE),
      InteropHelper.hex(ruby_signature)
    )
  end
end
