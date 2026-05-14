# frozen_string_literal: true

module PQCrypto
  module HybridKEM
    CANONICAL_ALGORITHM = :ml_kem_768_x25519_xwing

    DETAILS = AlgorithmRegistry.details_for_family(:ml_kem_hybrid).freeze

    class << self
      def generate(algorithm = CANONICAL_ALGORITHM)
        algorithm = resolve_algorithm!(algorithm)
        public_key, secret_key = PQCrypto.__send__(:native_hybrid_kem_keypair)
        Keypair.new(PublicKey.new(algorithm, public_key), SecretKey.new(algorithm, secret_key))
      end

      def public_key_from_bytes(algorithm, bytes)
        PublicKey.new(resolve_algorithm!(algorithm), bytes)
      end

      def secret_key_from_bytes(algorithm, bytes)
        SecretKey.new(resolve_algorithm!(algorithm), bytes)
      end

      def public_key_from_pqc_container_der(der, algorithm = nil)
        resolved_algorithm, bytes = Serialization.public_key_from_pqc_container_der(algorithm, der)
        PublicKey.new(resolve_algorithm!(resolved_algorithm), bytes)
      end

      def public_key_from_pqc_container_pem(pem, algorithm = nil)
        resolved_algorithm, bytes = Serialization.public_key_from_pqc_container_pem(algorithm, pem)
        PublicKey.new(resolve_algorithm!(resolved_algorithm), bytes)
      end

      def secret_key_from_pqc_container_der(der, algorithm = nil)
        resolved_algorithm, bytes = Serialization.secret_key_from_pqc_container_der(algorithm, der)
        SecretKey.new(resolve_algorithm!(resolved_algorithm), bytes)
      end

      def secret_key_from_pqc_container_pem(pem, algorithm = nil)
        resolved_algorithm, bytes = Serialization.secret_key_from_pqc_container_pem(algorithm, pem)
        SecretKey.new(resolve_algorithm!(resolved_algorithm), bytes)
      end

      def details(algorithm)
        DETAILS.fetch(resolve_algorithm!(algorithm)).dup
      end

      def supported
        DETAILS.keys.dup
      end

      private

      def resolve_algorithm!(algorithm)
        return algorithm if DETAILS.key?(algorithm)

        raise UnsupportedAlgorithmError, "Unsupported hybrid KEM algorithm: #{algorithm.inspect}"
      end
    end

    class Keypair < KEM::Keypair; end
    class EncapsulationResult < KEM::EncapsulationResult; end

    class PublicKey < KEM::PublicKey
      def encapsulate
        ciphertext, shared_secret = PQCrypto.__send__(:native_hybrid_kem_encapsulate, @bytes)
        EncapsulationResult.new(ciphertext, shared_secret)
      rescue ArgumentError => e
        raise InvalidKeyError, e.message
      end

      private

      def validate_length!
        expected = HybridKEM.details(@algorithm).fetch(:public_key_bytes)
        raise InvalidKeyError, "Invalid hybrid KEM public key length" unless @bytes.bytesize == expected
      end
    end

    class SecretKey < KEM::SecretKey
      def decapsulate(ciphertext)
        PQCrypto.__send__(:native_hybrid_kem_decapsulate_expanded_object, String(ciphertext).b, expanded_key_for_native)
      rescue ArgumentError => e
        raise InvalidCiphertextError, e.message
      end

      def wipe!
        PQCrypto.__send__(:native_hybrid_kem_expanded_secret_key_wipe, @expanded_key) if @expanded_key
        @expanded_key = nil
        super
      end

      private

      def expanded_key_for_native
        @expanded_key ||= PQCrypto.__send__(:native_hybrid_kem_expand_secret_key_object, @bytes)
      end

      def validate_length!
        expected = HybridKEM.details(@algorithm).fetch(:secret_key_bytes)
        raise InvalidKeyError, "Invalid hybrid KEM secret key length" unless @bytes.bytesize == expected
      end
    end
  end
end
