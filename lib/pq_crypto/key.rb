# frozen_string_literal: true

module PQCrypto
  module Key
    class << self
      def generate(algorithm)
        algorithm = resolve_algorithm!(algorithm)
        case AlgorithmRegistry.fetch(algorithm).fetch(:family)
        when :ml_kem
          KEM.generate(algorithm)
        when :ml_dsa
          Signature.generate(algorithm)
        when :ml_kem_hybrid
          HybridKEM.generate(algorithm)
        else
          raise UnsupportedAlgorithmError, "Unsupported key generation algorithm: #{algorithm.inspect}"
        end
      end

      def from_pem(pem, passphrase: nil, require_encrypted: false)
        require_encrypted = Internal.strict_boolean!(require_encrypted, name: "require_encrypted")
        text = String(pem)
        if text.include?(SPKI::PEM_BEGIN)
          public_key_from_spki_pem(text)
        elsif text.include?(PKCS8::PEM_BEGIN) || text.include?(PKCS8::ENCRYPTED_PEM_BEGIN)
          secret_key_from_pkcs8_pem(text, passphrase: passphrase, require_encrypted: require_encrypted)
        else
          raise SerializationError, "Unsupported PEM label for PQCrypto::Key.from_pem"
        end
      end

      def from_der(der, passphrase: nil, require_encrypted: false)
        require_encrypted = Internal.strict_boolean!(require_encrypted, name: "require_encrypted")
        public_key_from_spki_der(der)
      rescue SerializationError => spki_error
        begin
          secret_key_from_pkcs8_der(der, passphrase: passphrase, require_encrypted: require_encrypted)
        rescue SerializationError => pkcs8_error
          raise SerializationError,
                "Unable to decode DER as SPKI or PKCS#8 (SPKI: #{spki_error.message}; PKCS#8: #{pkcs8_error.message})"
        end
      end

      private

      def resolve_algorithm!(algorithm)
        AlgorithmRegistry.fetch(algorithm)
        algorithm
      end

      def public_key_from_spki_pem(pem)
        algorithm, bytes = SPKI.decode_pem(pem)
        public_key_from_algorithm_and_bytes(algorithm, bytes)
      end

      def public_key_from_spki_der(der)
        algorithm, bytes = SPKI.decode_der(der)
        public_key_from_algorithm_and_bytes(algorithm, bytes)
      end

      def secret_key_from_pkcs8_pem(pem, passphrase: nil, require_encrypted: false)
        secret_key_from_decoded_pkcs8(
          *PKCS8.decode_pem(pem, passphrase: passphrase, require_encrypted: require_encrypted)
        )
      end

      def secret_key_from_pkcs8_der(der, passphrase: nil, require_encrypted: false)
        secret_key_from_decoded_pkcs8(
          *PKCS8.decode_der(der, passphrase: passphrase, require_encrypted: require_encrypted)
        )
      end

      def secret_key_from_decoded_pkcs8(algorithm, format, material)
        case AlgorithmRegistry.fetch(algorithm).fetch(:family)
        when :ml_kem
          KEM.send(:secret_key_from_decoded_pkcs8, algorithm, format, material)
        when :ml_dsa
          Signature.send(:secret_key_from_decoded_pkcs8, algorithm, format, material)
        else
          raise SerializationError, "PKCS#8 private key codec is not supported for #{algorithm.inspect}"
        end
      end

      def public_key_from_algorithm_and_bytes(algorithm, bytes)
        case AlgorithmRegistry.fetch(algorithm).fetch(:family)
        when :ml_kem
          KEM::PublicKey.new(algorithm, bytes)
        when :ml_dsa
          Signature::PublicKey.new(algorithm, bytes)
        else
          raise SerializationError, "SPKI public key codec is not supported for #{algorithm.inspect}"
        end
      end
    end
  end
end
