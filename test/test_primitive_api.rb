# frozen_string_literal: true

require_relative "test_helper"

class TestPQCryptoPrimitiveAPI < Minitest::Test
  def test_supported_algorithms
    assert_equal [:ml_kem_768], PQCrypto.supported_kems
    assert_equal [:ml_dsa_65], PQCrypto.supported_signatures
  end

  def test_kem_details
    details = PQCrypto::KEM.details(:ml_kem_768_x25519)

    assert_equal :ml_kem_768_x25519, details[:name]
    assert_equal PQCrypto::KEM_PUBLIC_KEY_BYTES, details[:public_key_bytes]
    assert_equal PQCrypto::KEM_SECRET_KEY_BYTES, details[:secret_key_bytes]
    assert_equal PQCrypto::KEM_CIPHERTEXT_BYTES, details[:ciphertext_bytes]
    assert_equal PQCrypto::KEM_SHARED_SECRET_BYTES, details[:shared_secret_bytes]
  end

  def test_signature_details
    details = PQCrypto::Signature.details(:ml_dsa_65)

    assert_equal :ml_dsa_65, details[:name]
    assert_equal PQCrypto::SIGN_PUBLIC_KEY_BYTES, details[:public_key_bytes]
    assert_equal PQCrypto::SIGN_SECRET_KEY_BYTES, details[:secret_key_bytes]
    assert_equal PQCrypto::SIGN_BYTES, details[:signature_bytes]
  end

  def test_kem_generate_returns_typed_keypair
    keypair = PQCrypto::KEM.generate(:ml_kem_768_x25519)

    assert_instance_of PQCrypto::KEM::Keypair, keypair
    assert_instance_of PQCrypto::KEM::PublicKey, keypair.public_key
    assert_instance_of PQCrypto::KEM::SecretKey, keypair.secret_key
    assert_equal :ml_kem_768_x25519, keypair.algorithm
  end

  def test_kem_roundtrip_with_typed_api
    keypair = PQCrypto::KEM.generate(:ml_kem_768_x25519)
    result = keypair.public_key.encapsulate
    shared_secret = keypair.secret_key.decapsulate(result.ciphertext)

    assert_instance_of PQCrypto::KEM::EncapsulationResult, result
    assert_equal result.shared_secret, shared_secret
  end

  def test_kem_import_export_raw_bytes
    keypair = PQCrypto::KEM.generate(:ml_kem_768_x25519)

    imported_pub = PQCrypto::KEM.public_key_from_bytes(:ml_kem_768_x25519, keypair.public_key.to_bytes)
    imported_sec = PQCrypto::KEM.secret_key_from_bytes(:ml_kem_768_x25519, keypair.secret_key.to_bytes)
    result = imported_pub.encapsulate

    assert_equal result.shared_secret, imported_sec.decapsulate(result.ciphertext)
  end

  def test_signature_generate_returns_typed_keypair
    keypair = PQCrypto::Signature.generate(:ml_dsa_65)

    assert_instance_of PQCrypto::Signature::Keypair, keypair
    assert_instance_of PQCrypto::Signature::PublicKey, keypair.public_key
    assert_instance_of PQCrypto::Signature::SecretKey, keypair.secret_key
    assert_equal :ml_dsa_65, keypair.algorithm
  end

  def test_signature_sign_verify_with_typed_api
    keypair = PQCrypto::Signature.generate(:ml_dsa_65)
    signature = keypair.secret_key.sign("hello")

    assert keypair.public_key.verify("hello", signature)
    assert keypair.public_key.verify!("hello", signature)
    refute keypair.public_key.verify("wrong", signature)
  end

  def test_signature_import_export_raw_bytes
    keypair = PQCrypto::Signature.generate(:ml_dsa_65)
    imported_pub = PQCrypto::Signature.public_key_from_bytes(:ml_dsa_65, keypair.public_key.to_bytes)
    imported_sec = PQCrypto::Signature.secret_key_from_bytes(:ml_dsa_65, keypair.secret_key.to_bytes)
    signature = imported_sec.sign("interop-ish")

    assert imported_pub.verify("interop-ish", signature)
  end


  def test_kem_spki_and_pkcs8_roundtrip
    keypair = PQCrypto::KEM.generate(:ml_kem_768_x25519)

    pub_der = keypair.public_key.to_spki_der
    sec_der = keypair.secret_key.to_pkcs8_der

    imported_pub = PQCrypto::KEM.public_key_from_spki_der(pub_der)
    imported_sec = PQCrypto::KEM.secret_key_from_pkcs8_der(sec_der)
    result = imported_pub.encapsulate

    assert_equal result.shared_secret, imported_sec.decapsulate(result.ciphertext)
  end

  def test_signature_spki_and_pkcs8_roundtrip
    keypair = PQCrypto::Signature.generate(:ml_dsa_65)

    pub_pem = keypair.public_key.to_spki_pem
    sec_pem = keypair.secret_key.to_pkcs8_pem

    imported_pub = PQCrypto::Signature.public_key_from_spki_pem(pub_pem)
    imported_sec = PQCrypto::Signature.secret_key_from_pkcs8_pem(sec_pem)
    signature = imported_sec.sign("serialized")

    assert imported_pub.verify("serialized", signature)
  end

  def test_serialization_rejects_wrong_algorithm_expectation
    keypair = PQCrypto::KEM.generate(:ml_kem_768_x25519)

    error = assert_raises(PQCrypto::SerializationError) do
      PQCrypto::Signature.public_key_from_spki_der(keypair.public_key.to_spki_der, :ml_dsa_65)
    end

    assert_match(/Expected/, error.message)
  end

  def test_details_expose_family_and_oid
    kem = PQCrypto::KEM.details(:ml_kem_768_x25519)
    sig = PQCrypto::Signature.details(:ml_dsa_65)

    assert_equal :ml_kem_hybrid, kem[:family]
    assert_match(/\A1\.3\.6\.1\.4\.1\./, kem[:oid])
    assert_equal :ml_dsa, sig[:family]
    assert_match(/\A1\.3\.6\.1\.4\.1\./, sig[:oid])
  end

  def test_unsupported_algorithm_errors
    assert_raises(PQCrypto::UnsupportedAlgorithmError) do
      PQCrypto::KEM.generate(:ml_kem_1024)
    end

    assert_raises(PQCrypto::UnsupportedAlgorithmError) do
      PQCrypto::Signature.generate(:ml_dsa_87)
    end
  end

  def test_experimental_namespace_still_exists
    assert_respond_to PQCrypto::Experimental, :seal
    assert_respond_to PQCrypto::Experimental, :unseal
    assert_respond_to PQCrypto::Experimental, :sign_and_seal
    assert_respond_to PQCrypto::Experimental, :unseal_and_verify
  end
end
