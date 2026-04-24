# frozen_string_literal: true

require_relative "test_helper"

class TestPQCryptoPrimitiveAPI < Minitest::Test
  def test_kem_details
    details = PQCrypto::KEM.details(:ml_kem_768)

    assert_equal :ml_kem_768, details[:name]
    assert_equal :ml_kem, details[:family]
    assert_equal PQCrypto::ML_KEM_PUBLIC_KEY_BYTES, details[:public_key_bytes]
    assert_equal PQCrypto::ML_KEM_SECRET_KEY_BYTES, details[:secret_key_bytes]
    assert_equal PQCrypto::ML_KEM_CIPHERTEXT_BYTES, details[:ciphertext_bytes]
    assert_equal PQCrypto::ML_KEM_SHARED_SECRET_BYTES, details[:shared_secret_bytes]
  end

  def test_hybrid_kem_details
    details = PQCrypto::HybridKEM.details(:ml_kem_768_x25519_xwing)

    assert_equal :ml_kem_768_x25519_xwing, details[:name]
    assert_equal :ml_kem_hybrid, details[:family]
    assert_equal PQCrypto::HYBRID_KEM_PUBLIC_KEY_BYTES, details[:public_key_bytes]
    assert_equal PQCrypto::HYBRID_KEM_SECRET_KEY_BYTES, details[:secret_key_bytes]
    assert_equal PQCrypto::HYBRID_KEM_CIPHERTEXT_BYTES, details[:ciphertext_bytes]
    assert_equal PQCrypto::HYBRID_KEM_SHARED_SECRET_BYTES, details[:shared_secret_bytes]
  end

  def test_signature_details
    details = PQCrypto::Signature.details(:ml_dsa_65)

    assert_equal :ml_dsa_65, details[:name]
    assert_equal :ml_dsa, details[:family]
    assert_equal PQCrypto::SIGN_PUBLIC_KEY_BYTES, details[:public_key_bytes]
    assert_equal PQCrypto::SIGN_SECRET_KEY_BYTES, details[:secret_key_bytes]
    assert_equal PQCrypto::SIGN_BYTES, details[:signature_bytes]
  end

  def test_kem_roundtrip_with_typed_api
    keypair = PQCrypto::KEM.generate(:ml_kem_768)
    result = keypair.public_key.encapsulate
    shared_secret = keypair.secret_key.decapsulate(result.ciphertext)

    assert_instance_of PQCrypto::KEM::EncapsulationResult, result
    assert_equal result.shared_secret, shared_secret
  end

  def test_hybrid_kem_roundtrip_with_typed_api
    keypair = PQCrypto::HybridKEM.generate(:ml_kem_768_x25519_xwing)
    result = keypair.public_key.encapsulate
    shared_secret = keypair.secret_key.decapsulate(result.ciphertext)

    assert_instance_of PQCrypto::HybridKEM::EncapsulationResult, result
    assert_equal result.shared_secret, shared_secret
  end

  def test_signature_sign_verify_with_typed_api
    keypair = PQCrypto::Signature.generate(:ml_dsa_65)
    signature = keypair.secret_key.sign("hello")

    assert keypair.public_key.verify("hello", signature)
    assert keypair.public_key.verify!("hello", signature)
    refute keypair.public_key.verify("wrong", signature)
  end

  def test_kem_import_export_raw_bytes
    keypair = PQCrypto::KEM.generate(:ml_kem_768)
    imported_pub = PQCrypto::KEM.public_key_from_bytes(:ml_kem_768, keypair.public_key.to_bytes)
    imported_sec = PQCrypto::KEM.secret_key_from_bytes(:ml_kem_768, keypair.secret_key.to_bytes)
    result = imported_pub.encapsulate

    assert_equal result.shared_secret, imported_sec.decapsulate(result.ciphertext)
  end

  def test_hybrid_kem_import_export_raw_bytes
    keypair = PQCrypto::HybridKEM.generate(:ml_kem_768_x25519_xwing)
    imported_pub = PQCrypto::HybridKEM.public_key_from_bytes(:ml_kem_768_x25519_xwing, keypair.public_key.to_bytes)
    imported_sec = PQCrypto::HybridKEM.secret_key_from_bytes(:ml_kem_768_x25519_xwing, keypair.secret_key.to_bytes)
    result = imported_pub.encapsulate

    assert_equal result.shared_secret, imported_sec.decapsulate(result.ciphertext)
  end

  def test_signature_import_export_raw_bytes
    keypair = PQCrypto::Signature.generate(:ml_dsa_65)
    imported_pub = PQCrypto::Signature.public_key_from_bytes(:ml_dsa_65, keypair.public_key.to_bytes)
    imported_sec = PQCrypto::Signature.secret_key_from_bytes(:ml_dsa_65, keypair.secret_key.to_bytes)
    signature = imported_sec.sign("interop-ish")

    assert imported_pub.verify("interop-ish", signature)
  end

  def test_kem_pqc_container_roundtrip
    keypair = PQCrypto::KEM.generate(:ml_kem_768)
    pub_der = keypair.public_key.to_pqc_container_der
    sec_der = keypair.secret_key.to_pqc_container_der
    imported_pub = PQCrypto::KEM.public_key_from_pqc_container_der(pub_der)
    imported_sec = PQCrypto::KEM.secret_key_from_pqc_container_der(sec_der)
    result = imported_pub.encapsulate

    assert_equal result.shared_secret, imported_sec.decapsulate(result.ciphertext)
  end

  def test_hybrid_kem_pqc_container_roundtrip
    keypair = PQCrypto::HybridKEM.generate(:ml_kem_768_x25519_xwing)
    pub_der = keypair.public_key.to_pqc_container_der
    sec_der = keypair.secret_key.to_pqc_container_der
    imported_pub = PQCrypto::HybridKEM.public_key_from_pqc_container_der(pub_der)
    imported_sec = PQCrypto::HybridKEM.secret_key_from_pqc_container_der(sec_der)
    result = imported_pub.encapsulate

    assert_equal result.shared_secret, imported_sec.decapsulate(result.ciphertext)
  end

  def test_signature_pqc_container_roundtrip
    keypair = PQCrypto::Signature.generate(:ml_dsa_65)
    pub_pem = keypair.public_key.to_pqc_container_pem
    sec_pem = keypair.secret_key.to_pqc_container_pem
    imported_pub = PQCrypto::Signature.public_key_from_pqc_container_pem(pub_pem)
    imported_sec = PQCrypto::Signature.secret_key_from_pqc_container_pem(sec_pem)
    signature = imported_sec.sign("serialized")

    assert imported_pub.verify("serialized", signature)
  end

  def test_serialization_rejects_wrong_algorithm_expectation
    keypair = PQCrypto::KEM.generate(:ml_kem_768)

    error = assert_raises(PQCrypto::SerializationError) do
      PQCrypto::Signature.public_key_from_pqc_container_der(keypair.public_key.to_pqc_container_der, :ml_dsa_65)
    end

    assert_match(/Expected/, error.message)
  end

  def test_details_expose_family_and_oid
    kem = PQCrypto::KEM.details(:ml_kem_768)
    hybrid = PQCrypto::HybridKEM.details(:ml_kem_768_x25519_xwing)
    sig = PQCrypto::Signature.details(:ml_dsa_65)

    assert_equal :ml_kem, kem[:family]
    assert_match(/\A2\.25\./, kem[:oid])
    assert_equal :ml_kem_hybrid, hybrid[:family]
    assert_equal "1.3.6.1.4.1.62253.25722", hybrid[:oid]
    assert_equal :ml_dsa, sig[:family]
    assert_match(/\A2\.25\./, sig[:oid])
  end



  def test_secret_key_inspect_does_not_leak_key_material
    kem = PQCrypto::KEM.generate(:ml_kem_768).secret_key
    hybrid = PQCrypto::HybridKEM.generate(:ml_kem_768_x25519_xwing).secret_key
    sig = PQCrypto::Signature.generate(:ml_dsa_65).secret_key

    [kem, hybrid, sig].each do |secret_key|
      raw_hex = secret_key.to_bytes.unpack1("H*")
      inspected = secret_key.inspect

      refute_includes inspected, "@bytes"
      refute_includes inspected, raw_hex
      refute_respond_to secret_key, :fingerprint
    end
  end

  def test_encapsulation_result_inspect_does_not_leak_shared_secret
    result = PQCrypto::KEM.generate(:ml_kem_768).public_key.encapsulate
    inspected = result.inspect

    refute_includes inspected, result.shared_secret.unpack1("H*")
    refute_includes inspected, "@shared_secret"
  end

  def test_unsupported_algorithm_errors
    assert_raises(PQCrypto::UnsupportedAlgorithmError) { PQCrypto::KEM.generate(:ml_kem_1024) }
    assert_raises(PQCrypto::UnsupportedAlgorithmError) { PQCrypto::HybridKEM.generate(:ml_kem_1024_x25519) }
    assert_raises(PQCrypto::UnsupportedAlgorithmError) { PQCrypto::Signature.generate(:ml_dsa_87) }
  end

  def test_legacy_aliases_are_absent
    keypair = PQCrypto::KEM.generate(:ml_kem_768)
    refute_respond_to keypair.public_key, :to_spki_der
    refute_respond_to keypair.public_key, :to_spki_pem
    refute_respond_to keypair.secret_key, :to_pkcs8_der
    refute_respond_to keypair.secret_key, :to_pkcs8_pem

    refute_respond_to PQCrypto::KEM, :public_key_from_spki_der
    refute_respond_to PQCrypto::KEM, :public_key_from_spki_pem
    refute_respond_to PQCrypto::KEM, :secret_key_from_pkcs8_der
    refute_respond_to PQCrypto::KEM, :secret_key_from_pkcs8_pem
    refute_respond_to PQCrypto::HybridKEM, :public_key_from_spki_der
    refute_respond_to PQCrypto::Signature, :public_key_from_spki_der
  end
end
