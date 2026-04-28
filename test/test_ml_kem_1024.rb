# frozen_string_literal: true

require_relative "test_helper"

class TestPQCryptoMLKEM1024 < Minitest::Test
  def test_generate_encapsulate_decapsulate
    keypair = PQCrypto::KEM.generate(:ml_kem_1024)

    assert_equal :ml_kem_1024, keypair.algorithm
    assert_equal PQCrypto::ML_KEM_1024_PUBLIC_KEY_BYTES, keypair.public_key.to_bytes.bytesize
    assert_equal PQCrypto::ML_KEM_1024_SECRET_KEY_BYTES, keypair.secret_key.to_bytes.bytesize

    result = keypair.public_key.encapsulate
    assert_equal PQCrypto::ML_KEM_1024_CIPHERTEXT_BYTES, result.ciphertext.bytesize
    assert_equal PQCrypto::ML_KEM_1024_SHARED_SECRET_BYTES, result.shared_secret.bytesize
    assert_equal result.shared_secret, keypair.secret_key.decapsulate(result.ciphertext)
  end

  def test_keypair_from_seed_pkcs8_and_spki_round_trip
    seed = (0...64).map { |i| i.chr }.join.b
    public_key, secret_key = PQCrypto.__send__(:native_ml_kem_1024_keypair_from_seed, seed)
    key = PQCrypto::KEM.secret_key_from_bytes(:ml_kem_1024, secret_key)
    public = PQCrypto::KEM.public_key_from_bytes(:ml_kem_1024, public_key)

    assert_equal secret_key, PQCrypto::KEM.secret_key_from_pkcs8_der(key.to_pkcs8_der).to_bytes
    assert_equal public_key, PQCrypto::KEM.public_key_from_spki_der(public.to_spki_der).to_bytes
  end
end
