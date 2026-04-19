# frozen_string_literal: true

require "rbconfig"
require_relative "pq_crypto/version"

begin
  require "pqcrypto/pqcrypto_secure"
rescue LoadError => original_error
  ext_dir = File.expand_path("pqcrypto", __dir__)
  extensions = [".#{RbConfig::CONFIG.fetch("DLEXT")}", ".bundle", ".so"].uniq
  search_dirs = [ext_dir, File.join(ext_dir, "pqcrypto")].uniq
  candidates = search_dirs.flat_map do |dir|
    extensions.map { |ext| File.join(dir, "pqcrypto_secure#{ext}") }
  end
  existing = candidates.select { |path| File.exist?(path) }

  raise LoadError, "Could not find compiled PQCrypto extension. Run: bundle exec rake vendor && bundle exec rake compile" if existing.empty?

  loaded = false
  existing.each do |path|
    begin
      require path
      loaded = true
      break
    rescue LoadError
      next
    end
  end

  raise original_error unless loaded
end

module PQCrypto
  NATIVE_EXTENSION_LOADED = true unless const_defined?(:NATIVE_EXTENSION_LOADED)

  class << self
    unless private_method_defined?(:native_kem_keypair)
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

      private :native_kem_keypair,
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
              :native_public_key_pem
    end

    def kem_keypair
      native_kem_keypair
    end

    def kem_encapsulate(public_key)
      native_kem_encapsulate(String(public_key))
    end

    def kem_decapsulate(ciphertext, secret_key)
      native_kem_decapsulate(String(ciphertext), String(secret_key))
    end

    def sign_keypair
      native_sign_keypair
    end

    def sign(message, secret_key)
      native_sign(String(message), String(secret_key))
    end

    def verify(message, signature, public_key)
      native_verify(String(message), String(signature), String(public_key))
    end

    def secure_wipe(string)
      string = String(string)
      raise ArgumentError, "secure_wipe requires a mutable String" if string.frozen?

      native_secure_wipe(string)
    end

    def version
      native_version
    end

    def establish_session(public_key)
      native_establish_session(String(public_key))
    end

    def accept_session(ciphertext, secret_key)
      native_accept_session(String(ciphertext), String(secret_key))
    end

    def seal(message, public_key)
      native_seal(String(message), String(public_key))
    end

    def unseal(sealed_data, secret_key)
      native_unseal(String(sealed_data), String(secret_key))
    end

    def sign_and_seal(message, kem_public_key, sign_secret_key)
      native_sign_and_seal(String(message), String(kem_public_key), String(sign_secret_key))
    end

    def unseal_and_verify(data, kem_secret_key, sign_public_key)
      native_unseal_and_verify(String(data), String(kem_secret_key), String(sign_public_key))
    end

    def public_key_pem(public_key)
      native_public_key_pem(String(public_key))
    end

    alias_method :keypair, :kem_keypair
    alias_method :encapsulate, :kem_encapsulate
    alias_method :decapsulate, :kem_decapsulate

    def native_extension_loaded?
      true
    end

    def backend
      :native_pqclean
    end

    def production_ready?
      false
    end

    def experimental?
      true
    end
  end
end

require_relative "pq_crypto/kem_keypair"
require_relative "pq_crypto/sign_keypair"
require_relative "pq_crypto/identity"
