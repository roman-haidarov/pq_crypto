# frozen_string_literal: true

module PQCrypto
  module HybridKEM
    CANONICAL_ALGORITHM = :ml_kem_768_x25519_hkdf_sha256

    DETAILS = {
      CANONICAL_ALGORITHM => {
        name: CANONICAL_ALGORITHM,
        family: Serialization.algorithm_to_family(CANONICAL_ALGORITHM),
        oid: Serialization.algorithm_to_oid(CANONICAL_ALGORITHM),
        public_key_bytes: HYBRID_KEM_PUBLIC_KEY_BYTES,
        secret_key_bytes: HYBRID_KEM_SECRET_KEY_BYTES,
        ciphertext_bytes: HYBRID_KEM_CIPHERTEXT_BYTES,
        shared_secret_bytes: HYBRID_KEM_SHARED_SECRET_BYTES,
        description: "Hybrid KEM: ML-KEM-768 + X25519 combined via transcript-bound HKDF-SHA256.",
      }.freeze,
    }.freeze

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
        PQCrypto.__send__(:native_hybrid_kem_decapsulate, String(ciphertext).b, @bytes)
      rescue ArgumentError => e
        raise InvalidCiphertextError, e.message
      end

      private

      def validate_length!
        expected = HybridKEM.details(@algorithm).fetch(:secret_key_bytes)
        raise InvalidKeyError, "Invalid hybrid KEM secret key length" unless @bytes.bytesize == expected
      end
    end
  end
end
