# frozen_string_literal: true

begin
  require "pqcrypto/pqcrypto_secure" # native extension first
rescue LoadError => original_error
  require "rbconfig"

  ext_dir = File.expand_path("pqcrypto", __dir__)
  extensions = [".#{RbConfig::CONFIG.fetch('DLEXT')}", ".bundle", ".so"].uniq
  search_dirs = [ext_dir, File.join(ext_dir, "pqcrypto")].uniq
  candidates = search_dirs.flat_map do |dir|
    extensions.map { |ext| File.join(dir, "pqcrypto_secure#{ext}") }
  end
  existing = candidates.select { |path| File.exist?(path) }

  raise LoadError,
        "Could not find compiled PQCrypto extension. Run: bundle exec rake compile" if existing.empty?

  loaded = existing.any? do |path|
    begin
      require path
      true
    rescue LoadError
      false
    end
  end

  raise original_error unless loaded
end

require_relative "pq_crypto/errors"
require_relative "pq_crypto/version"
require_relative "pq_crypto/internal"
require_relative "pq_crypto/algorithm_registry"
require_relative "pq_crypto/serialization"
require_relative "pq_crypto/spki"
require_relative "pq_crypto/pkcs8/der"
require_relative "pq_crypto/pkcs8/private_key_choice"
require_relative "pq_crypto/pkcs8"
require_relative "pq_crypto/kem"
require_relative "pq_crypto/signature"
require_relative "pq_crypto/hybrid_kem"
require_relative "pq_crypto/key"

module PQCrypto
  SUITES = {
    kem: AlgorithmRegistry.supported_kems,
    hybrid_kem: AlgorithmRegistry.supported_hybrid_kems,
    signature: AlgorithmRegistry.supported_signatures,
  }.freeze

  NATIVE_EXTENSION_LOADED = true

  module NativeBindings
    NATIVE_METHODS = %i[
      ml_kem_keypair
      ml_kem_keypair_from_seed
      ml_kem_encapsulate
      ml_kem_decapsulate
      ml_kem_512_keypair
      ml_kem_512_keypair_from_seed
      ml_kem_512_encapsulate
      ml_kem_512_decapsulate
      ml_kem_1024_keypair
      ml_kem_1024_keypair_from_seed
      ml_kem_1024_encapsulate
      ml_kem_1024_decapsulate
      hybrid_kem_keypair
      hybrid_kem_encapsulate
      hybrid_kem_expand_secret_key
      hybrid_kem_expand_secret_key_object
      hybrid_kem_expanded_secret_key_wipe
      hybrid_kem_decapsulate
      hybrid_kem_decapsulate_expanded
      hybrid_kem_decapsulate_expanded_object
      sign_keypair
      sign
      verify
      ml_dsa_44_keypair
      ml_dsa_44_keypair_from_seed
      ml_dsa_keypair_from_seed
      ml_dsa_44_sign
      ml_dsa_44_verify
      ml_dsa_87_keypair
      ml_dsa_87_keypair_from_seed
      ml_dsa_87_sign
      ml_dsa_87_verify
      ct_equals
      secure_wipe
      version
      public_key_to_pqc_container_der
      public_key_to_pqc_container_pem
      secret_key_to_pqc_container_der
      secret_key_to_pqc_container_pem
      public_key_from_pqc_container_der
      public_key_from_pqc_container_pem
      secret_key_from_pqc_container_der
      secret_key_from_pqc_container_pem
      pkcs8_private_key_info_to_der
      pkcs8_private_key_info_from_der
      pkcs8_encrypt_der
      pkcs8_decrypt_der
      pkcs8_encrypted_der?
      pkcs8_der_to_pem
      pkcs8_pem_to_der
      __test_ml_kem_keypair_from_seed
      __test_ml_kem_encapsulate_from_seed
      __test_ml_kem_512_encapsulate_from_seed
      __test_ml_kem_1024_encapsulate_from_seed
      __test_sign_keypair_from_seed
      __test_ml_dsa_44_keypair_from_seed
      __test_ml_dsa_87_keypair_from_seed
      __test_sign_from_seed
      __test_ml_dsa_44_sign_from_seed
      __test_ml_dsa_87_sign_from_seed
    ].freeze

    EXTERNAL_MU_METHODS = %i[
      _native_mldsa_extract_tr
      _native_mldsa_compute_tr
      _native_mldsa_mu_builder_new
      _native_mldsa_mu_builder_update
      _native_mldsa_mu_builder_finalize
      _native_mldsa_mu_builder_release
      _native_mldsa_sign_mu
      _native_mldsa_verify_mu
    ].freeze

    class << PQCrypto
      NativeBindings::NATIVE_METHODS.each do |name|
        alias_name = :"native_#{name.to_s.sub(/\A__/, '')}"
        next if private_method_defined?(alias_name)
        alias_method alias_name, name
      end

      private(*NativeBindings::NATIVE_METHODS)
      private(*NativeBindings::NATIVE_METHODS.map { |n| :"native_#{n.to_s.sub(/\A__/, '')}" })
      private(*NativeBindings::EXTERNAL_MU_METHODS)
    end
  end

  class << self
    def version
      native_version
    end

    def backend
      :native_pq_code_package
    end

    def native_extension_loaded?
      true
    end

    def supported_kems
      SUITES.fetch(:kem).dup
    end

    def supported_hybrid_kems
      SUITES.fetch(:hybrid_kem).dup
    end

    def supported_signatures
      SUITES.fetch(:signature).dup
    end

    def secure_wipe(string)
      string = String(string)
      raise ArgumentError, "secure_wipe requires a mutable String" if string.frozen?

      native_secure_wipe(string)
    end
  end

  module Testing
    KEM_KEYPAIR_METHODS = {
      ml_kem_512: :native_ml_kem_512_keypair_from_seed,
      ml_kem_768: :native_ml_kem_keypair_from_seed,
      ml_kem_1024: :native_ml_kem_1024_keypair_from_seed
    }.freeze

    KEM_ENCAPSULATE_METHODS = {
      ml_kem_512: :native_test_ml_kem_512_encapsulate_from_seed,
      ml_kem_768: :native_test_ml_kem_encapsulate_from_seed,
      ml_kem_1024: :native_test_ml_kem_1024_encapsulate_from_seed
    }.freeze

    MLDSA_KEYPAIR_METHODS = {
      ml_dsa_44: :native_test_ml_dsa_44_keypair_from_seed,
      ml_dsa_65: :native_test_sign_keypair_from_seed,
      ml_dsa_87: :native_test_ml_dsa_87_keypair_from_seed
    }.freeze

    MLDSA_SIGN_METHODS = {
      ml_dsa_44: :native_test_ml_dsa_44_sign_from_seed,
      ml_dsa_65: :native_test_sign_from_seed,
      ml_dsa_87: :native_test_ml_dsa_87_sign_from_seed
    }.freeze

    def self.ml_kem_keypair_from_seed(seed, algorithm: :ml_kem_768)
      PQCrypto.__send__(KEM_KEYPAIR_METHODS.fetch(algorithm), String(seed).b)
    rescue KeyError
      raise UnsupportedAlgorithmError, "Unsupported ML-KEM KAT algorithm: #{algorithm.inspect}"
    rescue ArgumentError => e
      raise InvalidKeyError, e.message
    end

    def self.ml_kem_encapsulate_from_seed(public_key, seed, algorithm: :ml_kem_768)
      PQCrypto.__send__(KEM_ENCAPSULATE_METHODS.fetch(algorithm), String(public_key).b, String(seed).b)
    rescue KeyError
      raise UnsupportedAlgorithmError, "Unsupported ML-KEM KAT algorithm: #{algorithm.inspect}"
    rescue ArgumentError => e
      raise InvalidKeyError, e.message
    end

    def self.ml_dsa_keypair_from_seed(seed, algorithm: :ml_dsa_65)
      PQCrypto.__send__(MLDSA_KEYPAIR_METHODS.fetch(algorithm), String(seed).b)
    rescue KeyError
      raise UnsupportedAlgorithmError, "Unsupported ML-DSA KAT algorithm: #{algorithm.inspect}"
    rescue ArgumentError => e
      raise InvalidKeyError, e.message
    end

    def self.ml_dsa_sign_from_seed(message, secret_key, seed, algorithm: :ml_dsa_65)
      PQCrypto.__send__(MLDSA_SIGN_METHODS.fetch(algorithm), String(message).b, String(secret_key).b, String(seed).b)
    rescue KeyError
      raise UnsupportedAlgorithmError, "Unsupported ML-DSA KAT algorithm: #{algorithm.inspect}"
    rescue ArgumentError => e
      raise InvalidKeyError, e.message
    end
  end
end

