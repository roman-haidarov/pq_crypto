# frozen_string_literal: true

require_relative "test_helper"

class TestKeyLoader < Minitest::Test
  def test_generate_dispatches_by_algorithm_family
    assert_instance_of PQCrypto::KEM::Keypair, PQCrypto::Key.generate(:ml_kem_768)
    assert_instance_of PQCrypto::Signature::Keypair, PQCrypto::Key.generate(:ml_dsa_65)
    assert_instance_of PQCrypto::HybridKEM::Keypair, PQCrypto::Key.generate(:ml_kem_768_x25519_xwing)
  end

  def test_from_pem_loads_spki_public_keys
    keypair = PQCrypto::Signature.generate(:ml_dsa_65)
    loaded = PQCrypto::Key.from_pem(keypair.public_key.to_spki_pem)

    assert_instance_of PQCrypto::Signature::PublicKey, loaded
    assert_equal keypair.public_key, loaded
  end

  def test_from_pem_loads_plain_pkcs8_secret_keys
    keypair = PQCrypto::KEM.generate(:ml_kem_768)
    loaded = PQCrypto::Key.from_pem(keypair.secret_key.to_pkcs8_pem)

    assert_instance_of PQCrypto::KEM::SecretKey, loaded
    assert_equal keypair.secret_key, loaded
  end

  def test_from_pem_loads_encrypted_pkcs8_secret_keys
    keypair = PQCrypto::Signature.generate(:ml_dsa_65)
    loaded = PQCrypto::Key.from_pem(keypair.secret_key.to_pkcs8_pem(passphrase: "pw", iterations: 1_000), passphrase: "pw")

    assert_instance_of PQCrypto::Signature::SecretKey, loaded
    assert_equal keypair.secret_key, loaded
  end
end
