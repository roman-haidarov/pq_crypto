# frozen_string_literal: true

require_relative "test_helper"
require "digest"

class TestSeedAwareSecretKeys < Minitest::Test
  def test_kem_secret_key_from_seed_can_reexport_seed_and_both_pkcs8
    PQCrypto::KEM.supported.each do |algorithm|
      seed = deterministic_bytes(PQCrypto::PKCS8::ML_KEM_SEED_BYTES, algorithm.to_s)
      secret_key = PQCrypto::KEM.secret_key_from_seed(algorithm, seed)

      seed_imported = PQCrypto::KEM.secret_key_from_pkcs8_der(secret_key.to_pkcs8_der(format: :seed))
      both_imported = PQCrypto::KEM.secret_key_from_pkcs8_der(secret_key.to_pkcs8_der(format: :both))

      assert_equal secret_key.to_bytes, seed_imported.to_bytes
      assert_equal secret_key.to_bytes, both_imported.to_bytes
      assert_equal secret_key.to_pkcs8_der(format: :seed), seed_imported.to_pkcs8_der(format: :seed)
      assert_equal secret_key.to_pkcs8_der(format: :both), both_imported.to_pkcs8_der(format: :both)
    end
  end

  def test_mldsa_secret_key_from_seed_can_reexport_seed_and_both_pkcs8_when_opted_in
    with_mldsa_seed_pkcs8_enabled do
      PQCrypto::Signature.supported.each do |algorithm|
        seed = deterministic_bytes(PQCrypto::PKCS8::ML_DSA_SEED_BYTES, algorithm.to_s)
        secret_key = PQCrypto::Signature.secret_key_from_seed(algorithm, seed)

        seed_imported = PQCrypto::Signature.secret_key_from_pkcs8_der(secret_key.to_pkcs8_der(format: :seed))
        both_imported = PQCrypto::Signature.secret_key_from_pkcs8_der(secret_key.to_pkcs8_der(format: :both))
        public_key_bytes, = PQCrypto::Testing.ml_dsa_keypair_from_seed(seed, algorithm: algorithm)
        public_key = PQCrypto::Signature.public_key_from_bytes(algorithm, public_key_bytes)
        signature = seed_imported.sign("seed-aware".b)

        assert_equal secret_key.to_bytes, seed_imported.to_bytes
        assert_equal secret_key.to_bytes, both_imported.to_bytes
        assert public_key.verify("seed-aware".b, signature)
        assert_equal secret_key.to_pkcs8_der(format: :seed), seed_imported.to_pkcs8_der(format: :seed)
        assert_equal secret_key.to_pkcs8_der(format: :both), both_imported.to_pkcs8_der(format: :both)
      end
    end
  end

  def test_expanded_only_keys_still_cannot_export_seed_formats
    kem_key = PQCrypto::KEM.secret_key_from_bytes(:ml_kem_768, PQCrypto::KEM.generate.secret_key.to_bytes)
    sig_key = PQCrypto::Signature.secret_key_from_bytes(:ml_dsa_65, PQCrypto::Signature.generate.secret_key.to_bytes)

    [:seed, :both].each do |format|
      assert_raises(PQCrypto::SerializationError) { kem_key.to_pkcs8_der(format: format) }
      assert_raises(PQCrypto::SerializationError) { sig_key.to_pkcs8_der(format: format) }
    end
  end

  private

  def with_mldsa_seed_pkcs8_enabled
    previous = PQCrypto::PKCS8.allow_ml_dsa_seed_format
    PQCrypto::PKCS8.allow_ml_dsa_seed_format = true
    yield
  ensure
    PQCrypto::PKCS8.allow_ml_dsa_seed_format = previous
  end

  def deterministic_bytes(length, label)
    out = String.new.b
    counter = 0
    while out.bytesize < length
      out << Digest::SHA256.digest("#{label}:#{counter}")
      counter += 1
    end
    out.byteslice(0, length).b
  end
end
