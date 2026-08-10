# frozen_string_literal: true

require_relative "test_helper"

# ML-DSA secret-key structure check via mldsa-native pk_from_sk (norms, t0, tr).
class TestMLDSAKeyValidation < Minitest::Test
  ALGORITHMS = %i[ml_dsa_44 ml_dsa_65 ml_dsa_87].freeze

  def test_generated_secret_keys_are_valid
    ALGORITHMS.each do |algorithm|
      keypair = PQCrypto::Signature.generate(algorithm)
      assert keypair.secret_key.valid?, "#{algorithm} secret key should validate"
    end
  end

  def test_corrupted_secret_key_is_rejected
    ALGORITHMS.each do |algorithm|
      bytes = PQCrypto::Signature.generate(algorithm).secret_key.to_bytes
      bytes.setbyte(0, bytes.getbyte(0) ^ 0xff)

      error = assert_raises(PQCrypto::InvalidKeyError, algorithm.to_s) do
        PQCrypto::Signature.secret_key_from_bytes(algorithm, bytes)
      end
      assert_match(/structure check/, error.message)
    end
  end

  def test_round_trips_still_work_for_valid_keys
    ALGORITHMS.each do |algorithm|
      keypair = PQCrypto::Signature.generate(algorithm)
      reimported = PQCrypto::Signature.secret_key_from_bytes(algorithm, keypair.secret_key.to_bytes)
      message = "ml-dsa validation #{algorithm}"
      signature = reimported.sign(message)
      assert keypair.public_key.verify(message, signature)
    end
  end

  def test_public_key_bytes_are_frozen_after_construction
    public_key = PQCrypto::Signature.generate(:ml_dsa_65).public_key
    bytes = public_key.instance_variable_get(:@bytes)
    assert bytes.frozen?
    assert_raises(FrozenError) { bytes.setbyte(0, 0xff) }
  end
  # Generated keys are valid by construction, so the check is skipped on that
  # path: pk_from_sk re-derives the public key and would roughly double the cost
  # of every keypair. Import paths must still validate.
  def test_generation_paths_skip_validation_but_import_paths_do_not
    ALGORITHMS.each do |algorithm|
      keypair = PQCrypto::Signature.generate(algorithm)
      assert keypair.secret_key.valid?, "#{algorithm} generated key must still be valid"

      corrupted = keypair.secret_key.to_bytes
      corrupted.setbyte(200, corrupted.getbyte(200) ^ 0xff)

      assert_raises(PQCrypto::InvalidKeyError, "#{algorithm} from_bytes") do
        PQCrypto::Signature.secret_key_from_bytes(algorithm, corrupted)
      end

      der = keypair.secret_key.to_pkcs8_der
      offset = der.index(keypair.secret_key.to_bytes)
      refute_nil offset, "expected the expanded key inside the PKCS#8 DER"
      bad_der = der.dup
      bad_der.setbyte(offset + 200, bad_der.getbyte(offset + 200) ^ 0xff)

      assert_raises(PQCrypto::InvalidKeyError, "#{algorithm} pkcs8") do
        PQCrypto::Signature.secret_key_from_pkcs8_der(bad_der)
      end
    end
  end

  # Seed-derived keys are expanded by the backend in this process, so they are
  # also valid by construction and must keep working.
  def test_seed_derived_keys_round_trip
    ALGORITHMS.each do |algorithm|
      seed = "\x2b".b * 32
      secret_key = PQCrypto::Signature.secret_key_from_seed(algorithm, seed)
      assert secret_key.valid?

      # ML-DSA seed-format PKCS#8 is opt-in, so round-trip through the
      # expanded encoding, which is the default.
      reloaded = PQCrypto::Signature.secret_key_from_pkcs8_der(secret_key.to_pkcs8_der)
      assert_equal secret_key.to_bytes, reloaded.to_bytes
    end
  end
end
