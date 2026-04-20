# frozen_string_literal: true

require_relative "test_helper"
require_relative "support/interop_helper"

class TestInteropGoMLKEM < Minitest::Test
  KEM_SEED = (0...64).map { |i| (i * 3) & 0xff }.pack("C*")

  def setup
    skip InteropHelper.go_skip_reason unless InteropHelper.go_supported?
  end

  def test_go_keygen_from_seed_matches_ruby_public_key_bytes
    ruby_pub, = PQCrypto::Testing.ml_kem_keypair_from_seed(KEM_SEED)
    go_pub_hex = InteropHelper.run_go_helper("keygen-from-seed", InteropHelper.hex(KEM_SEED)).first

    assert_equal ruby_pub, InteropHelper.bin(go_pub_hex)
  end

  def test_go_public_key_roundtrip_matches_raw_encoding
    ruby_pub, = PQCrypto::Testing.ml_kem_keypair_from_seed(KEM_SEED)
    roundtrip_hex = InteropHelper.run_go_helper("pub-roundtrip", InteropHelper.hex(ruby_pub)).first

    assert_equal ruby_pub, InteropHelper.bin(roundtrip_hex)
  end

  def test_go_and_ruby_ml_kem_encapsulation_interoperate
    ruby_pub, ruby_priv = PQCrypto::Testing.ml_kem_keypair_from_seed(KEM_SEED)
    ruby_secret_key = PQCrypto::KEM.secret_key_from_bytes(:ml_kem_768, ruby_priv)
    ruby_public_key = PQCrypto::KEM.public_key_from_bytes(:ml_kem_768, ruby_pub)

    go_ciphertext_hex, go_shared_secret_hex = InteropHelper.run_go_helper("encap", InteropHelper.hex(ruby_pub))
    assert_equal InteropHelper.bin(go_shared_secret_hex), ruby_secret_key.decapsulate(InteropHelper.bin(go_ciphertext_hex))

    ruby_ciphertext, ruby_shared_secret = ruby_public_key.encapsulate_to_bytes
    go_shared_secret_from_ruby_hex = InteropHelper.run_go_helper(
      "decap",
      InteropHelper.hex(KEM_SEED),
      InteropHelper.hex(ruby_ciphertext)
    ).first
    assert_equal ruby_shared_secret, InteropHelper.bin(go_shared_secret_from_ruby_hex)
  end
end
