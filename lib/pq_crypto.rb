# frozen_string_literal: true

require "rbconfig"
require_relative "pq_crypto/version"
require_relative "pq_crypto/errors"

begin
  require "pqcrypto/pqcrypto_secure"
rescue LoadError => original_error
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

require_relative "pq_crypto/serialization"

module PQCrypto
  SUITES = {
    kem: [:ml_kem_768].freeze,
    hybrid_kem: [:ml_kem_768_x25519_xwing].freeze,
    signature: [:ml_dsa_65].freeze,
  }.freeze

  NATIVE_EXTENSION_LOADED = true

  module NativeBindings
    NATIVE_METHODS = %i[
      ml_kem_keypair
      ml_kem_encapsulate
      ml_kem_decapsulate
      hybrid_kem_keypair
      hybrid_kem_encapsulate
      hybrid_kem_decapsulate
      sign_keypair
      sign
      verify
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
      __test_ml_kem_keypair_from_seed
      __test_ml_kem_encapsulate_from_seed
      __test_sign_keypair_from_seed
      __test_sign_from_seed
    ].freeze

    class << PQCrypto
      NativeBindings::NATIVE_METHODS.each do |name|
        alias_name = :"native_#{name.to_s.sub(/\A__/, '')}"
        next if private_method_defined?(alias_name)
        alias_method alias_name, name
      end

      private(*NativeBindings::NATIVE_METHODS)
      private(*NativeBindings::NATIVE_METHODS.map { |n| :"native_#{n.to_s.sub(/\A__/, '')}" })
    end
  end

  class << self
    def version
      native_version
    end

    def backend
      :native_pqclean
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
    def self.ml_kem_keypair_from_seed(seed)
      PQCrypto.__send__(:native_test_ml_kem_keypair_from_seed, String(seed).b)
    rescue ArgumentError => e
      raise InvalidKeyError, e.message
    end

    def self.ml_kem_encapsulate_from_seed(public_key, seed)
      PQCrypto.__send__(:native_test_ml_kem_encapsulate_from_seed, String(public_key).b, String(seed).b)
    rescue ArgumentError => e
      raise InvalidKeyError, e.message
    end

    def self.ml_dsa_keypair_from_seed(seed)
      PQCrypto.__send__(:native_test_sign_keypair_from_seed, String(seed).b)
    rescue ArgumentError => e
      raise InvalidKeyError, e.message
    end

    def self.ml_dsa_sign_from_seed(message, secret_key, seed)
      PQCrypto.__send__(:native_test_sign_from_seed, String(message).b, String(secret_key).b, String(seed).b)
    rescue ArgumentError => e
      raise InvalidKeyError, e.message
    end
  end
end

require_relative "pq_crypto/kem"
require_relative "pq_crypto/hybrid_kem"
require_relative "pq_crypto/signature"
