# frozen_string_literal: true

require_relative "test_helper"

# FIPS 203 key validation, exposed from mlkem-native v2 as check_pk / check_sk.
#
# Encapsulation and decapsulation already run these checks internally, so this
# adds no security to those operations. What it adds is the failure being
# reported where the key enters the process rather than at first use.
class TestMLKEMKeyValidation < Minitest::Test
  ALGORITHMS = %i[ml_kem_512 ml_kem_768 ml_kem_1024].freeze

  def test_generated_keys_are_valid
    ALGORITHMS.each do |algorithm|
      keypair = PQCrypto::KEM.generate(algorithm)
      assert keypair.public_key.valid?, "#{algorithm} public key should validate"
      assert keypair.secret_key.valid?, "#{algorithm} secret key should validate"
    end
  end

  # Section 7.2: coefficients must lie in [0,q-1]. The first two bytes carry the
  # first packed coefficients, so forcing them to 0xFF pushes one out of range.
  def test_public_key_failing_the_modulus_check_is_rejected
    ALGORITHMS.each do |algorithm|
      bytes = PQCrypto::KEM.generate(algorithm).public_key.to_bytes
      bytes.setbyte(0, 0xff)
      bytes.setbyte(1, 0xff)

      error = assert_raises(PQCrypto::InvalidKeyError, algorithm.to_s) do
        PQCrypto::KEM.public_key_from_bytes(algorithm, bytes)
      end
      assert_match(/modulus check/, error.message)
    end
  end

  # Section 7.3: the secret key carries a hash of its own public key. Corrupting
  # it simulates a secret key assembled from mismatched halves.
  def test_secret_key_failing_the_hash_check_is_rejected
    ALGORITHMS.each do |algorithm|
      bytes = PQCrypto::KEM.generate(algorithm).secret_key.to_bytes
      offset = bytes.bytesize - 33
      bytes.setbyte(offset, bytes.getbyte(offset) ^ 0xff)

      error = assert_raises(PQCrypto::InvalidKeyError, algorithm.to_s) do
        PQCrypto::KEM.secret_key_from_bytes(algorithm, bytes)
      end
      assert_match(/hash check/, error.message)
    end
  end

  def test_validation_applies_to_every_import_path
    keypair = PQCrypto::KEM.generate(:ml_kem_768)
    bad_public = keypair.public_key.to_bytes
    bad_public.setbyte(0, 0xff)
    bad_public.setbyte(1, 0xff)

    assert_raises(PQCrypto::InvalidKeyError, "from_bytes") do
      PQCrypto::KEM.public_key_from_bytes(:ml_kem_768, bad_public)
    end

    # A container carrying the same corrupted key must be refused as well: the
    # container format only checks lengths, so validation has to happen when the
    # key object is constructed.
    good_der = keypair.public_key.to_pqc_container_der
    bad_der = good_der.dup
    index = bad_der.index(keypair.public_key.to_bytes)
    refute_nil index, "expected the raw public key inside the container"
    bad_der[index, bad_public.bytesize] = bad_public

    assert_raises(PQCrypto::InvalidKeyError, "pqc container") do
      PQCrypto::KEM.public_key_from_pqc_container_der(bad_der)
    end
  end

  def test_round_trips_still_work_for_valid_keys
    ALGORITHMS.each do |algorithm|
      keypair = PQCrypto::KEM.generate(algorithm)

      reimported = PQCrypto::KEM.public_key_from_bytes(algorithm, keypair.public_key.to_bytes)
      assert_equal keypair.public_key.to_bytes, reimported.to_bytes

      reimported_secret = PQCrypto::KEM.secret_key_from_bytes(algorithm, keypair.secret_key.to_bytes)
      assert_equal keypair.secret_key.to_bytes, reimported_secret.to_bytes

      encapsulation = reimported.encapsulate
      assert_equal encapsulation.shared_secret,
                   reimported_secret.decapsulate(encapsulation.ciphertext)
    end
  end

  # X-Wing public keys are ML-KEM-768 ‖ X25519. The ML-KEM half is validated;
  # the X25519 half is not, since every 32-byte string is a valid X25519 key.
  def test_hybrid_public_key_validates_its_ml_kem_half
    keypair = PQCrypto::HybridKEM.generate
    assert keypair.public_key.valid?

    bytes = keypair.public_key.to_bytes
    bytes.setbyte(0, 0xff)
    bytes.setbyte(1, 0xff)

    assert_raises(PQCrypto::InvalidKeyError) do
      PQCrypto::HybridKEM.public_key_from_bytes(:ml_kem_768_x25519_xwing, bytes)
    end
  end

  def test_hybrid_secret_key_is_not_subject_to_the_hash_check
    # The X-Wing secret key is a 32-byte seed with no internal structure, so
    # validation is a no-op rather than a false rejection.
    keypair = PQCrypto::HybridKEM.generate
    assert keypair.secret_key.valid?
  end

  def test_public_key_bytes_are_frozen_after_construction
    public_key = PQCrypto::KEM.generate(:ml_kem_768).public_key
    bytes = public_key.instance_variable_get(:@bytes)
    assert bytes.frozen?
    assert_raises(FrozenError) { bytes.setbyte(0, 0xff) }
  end

  def test_secret_key_bytes_remain_mutable_for_wipe
    secret_key = PQCrypto::KEM.generate(:ml_kem_768).secret_key
    refute secret_key.instance_variable_get(:@bytes).frozen?
    secret_key.wipe!
  end

  def test_hash_check_is_not_a_full_integrity_proof
    # Section 7.3 only checks H(pk). Corrupting the IND-CPA secret (dk) leaves
    # the hash intact, so import still succeeds — documented limit, not a regression.
    bytes = PQCrypto::KEM.generate(:ml_kem_768).secret_key.to_bytes
    bytes.setbyte(0, bytes.getbyte(0) ^ 0xff)
    key = PQCrypto::KEM.secret_key_from_bytes(:ml_kem_768, bytes)
    assert key.valid?
  end
end

