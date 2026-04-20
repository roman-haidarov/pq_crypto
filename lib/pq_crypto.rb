# frozen_string_literal: true

require "rbconfig"
require_relative "pq_crypto/version"
require_relative "pq_crypto/errors"
require_relative "pq_crypto/serialization"

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
        "Could not find compiled PQCrypto extension. Run: bundle exec rake vendor && bundle exec rake compile" if existing.empty?

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

module PQCrypto
  SUITES = {
    kem: [:ml_kem_768].freeze,
    hybrid_kem: [:ml_kem_768_x25519_hkdf_sha256].freeze,
    signature: [:ml_dsa_65].freeze,
  }.freeze

  NATIVE_EXTENSION_LOADED = true unless const_defined?(:NATIVE_EXTENSION_LOADED)

  class << self
    unless private_method_defined?(:native_ml_kem_keypair)
      alias_method :native_ml_kem_keypair, :ml_kem_keypair
      alias_method :native_ml_kem_encapsulate, :ml_kem_encapsulate
      alias_method :native_ml_kem_decapsulate, :ml_kem_decapsulate
      alias_method :native_hybrid_kem_keypair, :hybrid_kem_keypair
      alias_method :native_hybrid_kem_encapsulate, :hybrid_kem_encapsulate
      alias_method :native_hybrid_kem_decapsulate, :hybrid_kem_decapsulate
      alias_method :native_kem_keypair, :kem_keypair
      alias_method :native_kem_encapsulate, :kem_encapsulate
      alias_method :native_kem_decapsulate, :kem_decapsulate
      alias_method :native_sign_keypair, :sign_keypair
      alias_method :native_sign, :sign
      alias_method :native_verify, :verify
      alias_method :native_secure_wipe, :secure_wipe
      alias_method :native_version, :version
      alias_method :native_establish_session, :establish_session
      alias_method :native_accept_session, :accept_session
      alias_method :native_seal, :seal
      alias_method :native_unseal, :unseal
      alias_method :native_sign_and_seal, :sign_and_seal
      alias_method :native_unseal_and_verify, :unseal_and_verify
      alias_method :native_public_key_pem, :public_key_pem
      alias_method :native_test_ml_kem_keypair_from_seed, :__test_ml_kem_keypair_from_seed
      alias_method :native_test_ml_kem_encapsulate_from_seed, :__test_ml_kem_encapsulate_from_seed
      alias_method :native_test_sign_keypair_from_seed, :__test_sign_keypair_from_seed
      alias_method :native_test_sign_from_seed, :__test_sign_from_seed

      private :native_ml_kem_keypair,
              :native_ml_kem_encapsulate,
              :native_ml_kem_decapsulate,
              :native_hybrid_kem_keypair,
              :native_hybrid_kem_encapsulate,
              :native_hybrid_kem_decapsulate,
              :native_kem_keypair,
              :native_kem_encapsulate,
              :native_kem_decapsulate,
              :native_sign_keypair,
              :native_sign,
              :native_verify,
              :native_secure_wipe,
              :native_version,
              :native_establish_session,
              :native_accept_session,
              :native_seal,
              :native_unseal,
              :native_sign_and_seal,
              :native_unseal_and_verify,
              :native_public_key_pem,
              :native_test_ml_kem_keypair_from_seed,
              :native_test_ml_kem_encapsulate_from_seed,
              :native_test_sign_keypair_from_seed,
              :native_test_sign_from_seed,
              :ml_kem_keypair,
              :ml_kem_encapsulate,
              :ml_kem_decapsulate,
              :hybrid_kem_keypair,
              :hybrid_kem_encapsulate,
              :hybrid_kem_decapsulate
    end

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

    def experimental?
      true
    end

    def production_ready?
      false
    end

    # Legacy compatibility surface backed by hybrid KEM.
    def kem_keypair
      native_kem_keypair
    end

    def kem_encapsulate(public_key)
      native_kem_encapsulate(String(public_key))
    rescue ArgumentError => e
      raise InvalidKeyError, e.message
    end

    def kem_decapsulate(ciphertext, secret_key)
      native_kem_decapsulate(String(ciphertext), String(secret_key))
    rescue ArgumentError => e
      raise InvalidCiphertextError, e.message
    end

    def sign_keypair
      native_sign_keypair
    end

    def sign(message, secret_key)
      native_sign(String(message), String(secret_key))
    rescue ArgumentError => e
      raise InvalidKeyError, e.message
    end

    def verify(message, signature, public_key)
      native_verify(String(message), String(signature), String(public_key))
    rescue ArgumentError => e
      raise InvalidKeyError, e.message
    end

    def secure_wipe(string)
      string = String(string)
      raise ArgumentError, "secure_wipe requires a mutable String" if string.frozen?

      native_secure_wipe(string)
    end

    # Legacy experimental protocol helpers based on the hybrid KEM compatibility layer.
    def establish_session(public_key)
      native_establish_session(String(public_key))
    rescue ArgumentError => e
      raise InvalidKeyError, e.message
    end

    def accept_session(ciphertext, secret_key)
      native_accept_session(String(ciphertext), String(secret_key))
    rescue ArgumentError => e
      raise InvalidCiphertextError, e.message
    end

    def seal(message, public_key)
      native_seal(String(message), String(public_key))
    rescue ArgumentError => e
      raise InvalidKeyError, e.message
    end

    def unseal(sealed_data, secret_key)
      native_unseal(String(sealed_data), String(secret_key))
    rescue ArgumentError => e
      raise InvalidCiphertextError, e.message
    end

    def sign_and_seal(message, kem_public_key, sign_secret_key)
      native_sign_and_seal(String(message), String(kem_public_key), String(sign_secret_key))
    rescue ArgumentError => e
      raise InvalidKeyError, e.message
    end

    def unseal_and_verify(data, kem_secret_key, sign_public_key)
      native_unseal_and_verify(String(data), String(kem_secret_key), String(sign_public_key))
    rescue ArgumentError => e
      raise InvalidCiphertextError, e.message
    end

    def public_key_pem(public_key)
      native_public_key_pem(String(public_key))
    rescue ArgumentError => e
      raise SerializationError, e.message
    end

    alias_method :keypair, :kem_keypair
    alias_method :encapsulate, :kem_encapsulate
    alias_method :decapsulate, :kem_decapsulate
  end

  module Testing
    def self.ml_kem_keypair_from_seed(seed)
      PQCrypto.send(:native_test_ml_kem_keypair_from_seed, String(seed).b)
    rescue ArgumentError => e
      raise InvalidKeyError, e.message
    end

    def self.ml_kem_encapsulate_from_seed(public_key, seed)
      PQCrypto.send(:native_test_ml_kem_encapsulate_from_seed, String(public_key).b, String(seed).b)
    rescue ArgumentError => e
      raise InvalidKeyError, e.message
    end

    def self.ml_dsa_keypair_from_seed(seed)
      PQCrypto.send(:native_test_sign_keypair_from_seed, String(seed).b)
    rescue ArgumentError => e
      raise InvalidKeyError, e.message
    end

    def self.ml_dsa_sign_from_seed(message, secret_key, seed)
      PQCrypto.send(:native_test_sign_from_seed, String(message).b, String(secret_key).b, String(seed).b)
    rescue ArgumentError => e
      raise InvalidKeyError, e.message
    end
  end

  module Experimental
    def self.establish_session(public_key)
      PQCrypto.establish_session(public_key)
    end

    def self.accept_session(ciphertext, secret_key)
      PQCrypto.accept_session(ciphertext, secret_key)
    end

    def self.seal(message, public_key)
      PQCrypto.seal(message, public_key)
    end

    def self.unseal(sealed_data, secret_key)
      PQCrypto.unseal(sealed_data, secret_key)
    end

    def self.sign_and_seal(message, kem_public_key, sign_secret_key)
      PQCrypto.sign_and_seal(message, kem_public_key, sign_secret_key)
    end

    def self.unseal_and_verify(data, kem_secret_key, sign_public_key)
      PQCrypto.unseal_and_verify(data, kem_secret_key, sign_public_key)
    end
  end
end

require_relative "pq_crypto/kem"
require_relative "pq_crypto/hybrid_kem"
require_relative "pq_crypto/signature"
require_relative "pq_crypto/session"
require_relative "pq_crypto/kem_keypair"
require_relative "pq_crypto/sign_keypair"
require_relative "pq_crypto/identity"
