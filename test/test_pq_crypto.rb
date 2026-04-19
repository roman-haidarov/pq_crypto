# frozen_string_literal: true

require_relative "test_helper"

class TestPQCrypto < Minitest::Test
  def setup
    @message = "Hello, quantum world!"
    @shared_secret = "A" * PQCrypto::KEM_SHARED_SECRET_BYTES
  end

  def test_version_constant
    assert_equal "0.5.0", PQCrypto::VERSION
  end

  def test_backend_is_native_pqclean
    assert_equal :native_pqclean, PQCrypto.backend
    assert PQCrypto.experimental?
    refute PQCrypto.production_ready?
  end

  def test_kem_keypair_lengths
    public_key, secret_key = PQCrypto.kem_keypair

    assert_equal PQCrypto::KEM_PUBLIC_KEY_BYTES, public_key.bytesize
    assert_equal PQCrypto::KEM_SECRET_KEY_BYTES, secret_key.bytesize
  end

  def test_kem_keypair_is_not_reused
    first_public_key, = PQCrypto.kem_keypair
    second_public_key, = PQCrypto.kem_keypair

    refute_equal first_public_key, second_public_key
  end

  def test_kem_roundtrip
    public_key, secret_key = PQCrypto.kem_keypair
    ciphertext, encapsulated_secret = PQCrypto.kem_encapsulate(public_key)
    decapsulated_secret = PQCrypto.kem_decapsulate(ciphertext, secret_key)

    assert_equal PQCrypto::KEM_CIPHERTEXT_BYTES, ciphertext.bytesize
    assert_equal PQCrypto::KEM_SHARED_SECRET_BYTES, encapsulated_secret.bytesize
    assert_equal encapsulated_secret, decapsulated_secret
  end

  def test_kem_validates_input_lengths
    _, secret_key = PQCrypto.kem_keypair

    assert_raises(PQCrypto::InvalidKeyError) { PQCrypto.kem_encapsulate("short") }
    assert_raises(PQCrypto::InvalidCiphertextError) { PQCrypto.kem_decapsulate("short", secret_key) }
  end

  def test_sign_keypair_lengths
    public_key, secret_key = PQCrypto.sign_keypair

    assert_equal PQCrypto::SIGN_PUBLIC_KEY_BYTES, public_key.bytesize
    assert_equal PQCrypto::SIGN_SECRET_KEY_BYTES, secret_key.bytesize
  end

  def test_sign_and_verify
    public_key, secret_key = PQCrypto.sign_keypair
    signature = PQCrypto.sign(@message, secret_key)

    assert_operator signature.bytesize, :>, 0
    assert_operator signature.bytesize, :<=, PQCrypto::SIGN_BYTES
    assert PQCrypto.verify(@message, signature, public_key)
  end

  def test_verify_rejects_invalid_signature
    public_key, secret_key = PQCrypto.sign_keypair
    signature = PQCrypto.sign(@message, secret_key).dup
    signature.setbyte(0, (signature.getbyte(0) + 1) % 256)

    assert_raises(PQCrypto::VerificationError) do
      PQCrypto.verify(@message, signature, public_key)
    end
  end

  def test_verify_rejects_wrong_message
    public_key, secret_key = PQCrypto.sign_keypair
    signature = PQCrypto.sign(@message, secret_key)

    assert_raises(PQCrypto::VerificationError) do
      PQCrypto.verify("wrong message", signature, public_key)
    end
  end

  def test_session_encrypts_and_decrypts
    alice = PQCrypto::Session.new(@shared_secret, true)
    bob = PQCrypto::Session.new(@shared_secret, false)

    ciphertext = alice.encrypt("Secret message")

    assert_equal "Secret message", bob.decrypt(ciphertext)
  end

  def test_session_includes_expected_overhead
    session = PQCrypto::Session.new(@shared_secret, true)
    plaintext = "Hello"
    ciphertext = session.encrypt(plaintext)

    assert_equal plaintext.bytesize + PQCrypto::SESSION_OVERHEAD, ciphertext.bytesize
  end

  def test_session_supports_aad
    alice = PQCrypto::Session.new(@shared_secret, true)
    bob = PQCrypto::Session.new(@shared_secret, false)
    ciphertext = alice.encrypt("Secret", aad: "metadata")

    assert_equal "Secret", bob.decrypt(ciphertext, aad: "metadata")
  end

  def test_session_rejects_wrong_aad
    alice = PQCrypto::Session.new(@shared_secret, true)
    bob = PQCrypto::Session.new(@shared_secret, false)
    ciphertext = alice.encrypt("Secret", aad: "correct")

    assert_raises(PQCrypto::DecryptionError) do
      bob.decrypt(ciphertext, aad: "wrong")
    end
  end

  def test_session_rejects_replay
    alice = PQCrypto::Session.new(@shared_secret, true)
    bob = PQCrypto::Session.new(@shared_secret, false)
    ciphertext = alice.encrypt("Secret")

    assert_equal "Secret", bob.decrypt(ciphertext)
    assert_raises(PQCrypto::DecryptionError) { bob.decrypt(ciphertext) }
  end

  def test_establish_and_accept_session_are_compatible
    public_key, secret_key = PQCrypto.kem_keypair
    alice_session, ciphertext = PQCrypto.establish_session(public_key)
    bob_session = PQCrypto.accept_session(ciphertext, secret_key)

    encrypted = alice_session.encrypt("Hello Bob!")

    assert_equal "Hello Bob!", bob_session.decrypt(encrypted)
  end

  def test_seal_and_unseal
    public_key, secret_key = PQCrypto.kem_keypair
    sealed = PQCrypto.seal("Sealed message", public_key)

    assert_equal "Sealed message", PQCrypto.unseal(sealed, secret_key)
  end

  def test_sign_and_seal_has_versioned_wire_format
    alice_sign_public, alice_sign_secret = PQCrypto.sign_keypair
    bob_kem_public, = PQCrypto.kem_keypair

    payload = PQCrypto.sign_and_seal("Authenticated and encrypted", bob_kem_public, alice_sign_secret)

    # Header: magic(4) "PQ10" + version(1) 0x01 + suite_id(1) 0x01
    assert_equal "PQ10", payload.byteslice(0, 4)
    assert_equal 0x01, payload.getbyte(4)
    assert_equal 0x01, payload.getbyte(5)

    signature_length = payload.byteslice(6, 4).unpack1("N")
    signature = payload.byteslice(10, signature_length)
    sealed = payload.byteslice(10 + signature_length..)

    assert_equal signature_length, signature.bytesize
    assert PQCrypto.verify(sealed, signature, alice_sign_public)
  end

  def test_unseal_and_verify_rejects_bad_magic
    alice_sign_public, alice_sign_secret = PQCrypto.sign_keypair
    bob_kem_public, bob_kem_secret = PQCrypto.kem_keypair

    payload = PQCrypto.sign_and_seal("hello", bob_kem_public, alice_sign_secret)
    tampered = payload.dup
    tampered.setbyte(0, 0xFF)

    assert_raises(PQCrypto::VerificationError) do
      PQCrypto.unseal_and_verify(tampered, bob_kem_secret, alice_sign_public)
    end
  end

  def test_unseal_and_verify_rejects_bad_version
    alice_sign_public, alice_sign_secret = PQCrypto.sign_keypair
    bob_kem_public, bob_kem_secret = PQCrypto.kem_keypair

    payload = PQCrypto.sign_and_seal("hello", bob_kem_public, alice_sign_secret)
    tampered = payload.dup
    tampered.setbyte(4, 0xFF)

    assert_raises(PQCrypto::VerificationError) do
      PQCrypto.unseal_and_verify(tampered, bob_kem_secret, alice_sign_public)
    end
  end

  def test_unseal_and_verify_rejects_bad_suite_id
    alice_sign_public, alice_sign_secret = PQCrypto.sign_keypair
    bob_kem_public, bob_kem_secret = PQCrypto.kem_keypair

    payload = PQCrypto.sign_and_seal("hello", bob_kem_public, alice_sign_secret)
    tampered = payload.dup
    tampered.setbyte(5, 0xFF)

    assert_raises(PQCrypto::VerificationError) do
      PQCrypto.unseal_and_verify(tampered, bob_kem_secret, alice_sign_public)
    end
  end

  def test_unseal_and_verify
    alice_sign_public, alice_sign_secret = PQCrypto.sign_keypair
    bob_kem_public, bob_kem_secret = PQCrypto.kem_keypair

    payload = PQCrypto.sign_and_seal("Authenticated and encrypted", bob_kem_public, alice_sign_secret)

    assert_equal "Authenticated and encrypted", PQCrypto.unseal_and_verify(payload, bob_kem_secret, alice_sign_public)
  end

  def test_kem_keypair_object
    keypair = PQCrypto::KEMKeypair.generate

    assert_equal PQCrypto::KEM_PUBLIC_KEY_BYTES, keypair.public_key.bytesize
    assert_equal PQCrypto::KEM_SECRET_KEY_BYTES, keypair.secret_key.bytesize
  end

  def test_kem_keypair_pem_export
    pem = PQCrypto::KEMKeypair.generate.public_key_pem

    assert_match(/\A-----BEGIN HYBRID PUBLIC KEY-----/, pem)
    assert_match(/-----END HYBRID PUBLIC KEY-----\n\z/, pem)
  end

  def test_kem_keypair_from_existing_keys
    public_key, secret_key = PQCrypto.kem_keypair
    keypair = PQCrypto::KEMKeypair.from_keys(public_key, secret_key)

    assert_equal public_key, keypair.public_key
    assert_equal secret_key, keypair.secret_key
  end

  def test_sign_keypair_object
    keypair = PQCrypto::SignKeypair.generate
    signature = keypair.sign("message")

    assert_operator signature.bytesize, :>, 0
    assert PQCrypto.verify("message", signature, keypair.public_key)
  end

  def test_identity_generate_and_public_keys
    identity = PQCrypto::Identity.generate
    public_keys = identity.public_keys

    assert_instance_of PQCrypto::KEMKeypair, identity.kem_keypair
    assert_instance_of PQCrypto::SignKeypair, identity.sign_keypair
    assert_equal PQCrypto::KEM_PUBLIC_KEY_BYTES, public_keys[:kem].bytesize
    assert_equal PQCrypto::SIGN_PUBLIC_KEY_BYTES, public_keys[:sign].bytesize
  end

  def test_identity_authenticated_session
    alice = PQCrypto::Identity.generate
    bob = PQCrypto::Identity.generate

    alice_session, ciphertext, signature = alice.initiate_authenticated_session(bob.public_keys[:kem])
    bob_session = bob.accept_authenticated_session(ciphertext, signature, alice.public_keys[:sign])

    encrypted = alice_session.encrypt("Authenticated and secure!")

    assert_equal "Authenticated and secure!", bob_session.decrypt(encrypted)
  end

  def test_secure_wipe_zeroes_mutable_string
    sensitive = String.new("sensitive data here")
    PQCrypto.secure_wipe(sensitive)

    assert sensitive.bytes.all?(&:zero?)
  end

  def test_secure_wipe_rejects_frozen_string
    sensitive = "sensitive data here".freeze

    error = assert_raises(ArgumentError) do
      PQCrypto.secure_wipe(sensitive)
    end

    assert_match(/mutable String/, error.message)
  end

  def test_main_require_path
    require "pq_crypto"
    assert_equal PQCrypto::VERSION, ::PQCrypto::VERSION
  end

  def test_compatibility_require_path
    require "pqcrypto"
    assert_equal PQCrypto::VERSION, ::PQCrypto::VERSION
  end
end
