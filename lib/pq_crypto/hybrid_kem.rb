# frozen_string_literal: true

module PQCrypto
  module HybridKEM
    CANONICAL_ALGORITHM = :ml_kem_768_x25519_hkdf_sha256
    DEPRECATED_ALIASES = { ml_kem_768_x25519: CANONICAL_ALGORITHM }.freeze

    DETAILS = {
      CANONICAL_ALGORITHM => {
        name: CANONICAL_ALGORITHM,
        family: Serialization.algorithm_to_family(CANONICAL_ALGORITHM),
        oid: Serialization.algorithm_to_oid(CANONICAL_ALGORITHM),
        public_key_bytes: HYBRID_KEM_PUBLIC_KEY_BYTES,
        secret_key_bytes: HYBRID_KEM_SECRET_KEY_BYTES,
        ciphertext_bytes: HYBRID_KEM_CIPHERTEXT_BYTES,
        shared_secret_bytes: HYBRID_KEM_SHARED_SECRET_BYTES,
        description:
          "Hybrid KEM: ML-KEM-768 + X25519 combined via transcript-bound HKDF-SHA256.",
      }.freeze,
    }.freeze

    class << self
      def generate(algorithm = CANONICAL_ALGORITHM)
        algorithm = resolve_algorithm!(algorithm)
        public_key, secret_key = PQCrypto.send(:native_hybrid_kem_keypair)
        Keypair.new(PublicKey.new(algorithm, public_key), SecretKey.new(algorithm, secret_key))
      end

      def public_key_from_bytes(algorithm, bytes)
        algorithm = resolve_algorithm!(algorithm)
        PublicKey.new(algorithm, bytes)
      end

      def secret_key_from_bytes(algorithm, bytes)
        algorithm = resolve_algorithm!(algorithm)
        SecretKey.new(algorithm, bytes)
      end

      def public_key_from_pqc_container_der(der, algorithm = nil)
        resolved_algorithm, bytes = Serialization.public_key_from_spki_der(algorithm, der)
        PublicKey.new(resolve_algorithm!(resolved_algorithm), bytes)
      end

      def public_key_from_pqc_container_pem(pem, algorithm = nil)
        resolved_algorithm, bytes = Serialization.public_key_from_spki_pem(algorithm, pem)
        PublicKey.new(resolve_algorithm!(resolved_algorithm), bytes)
      end

      def secret_key_from_pqc_container_der(der, algorithm = nil)
        resolved_algorithm, bytes = Serialization.secret_key_from_pkcs8_der(algorithm, der)
        SecretKey.new(resolve_algorithm!(resolved_algorithm), bytes)
      end

      def secret_key_from_pqc_container_pem(pem, algorithm = nil)
        resolved_algorithm, bytes = Serialization.secret_key_from_pkcs8_pem(algorithm, pem)
        SecretKey.new(resolve_algorithm!(resolved_algorithm), bytes)
      end

      def public_key_from_spki_der(der, algorithm = nil)
        warn_once_about_deprecated_serializer(:public_key_from_spki_der, :public_key_from_pqc_container_der)
        public_key_from_pqc_container_der(der, algorithm)
      end

      def public_key_from_spki_pem(pem, algorithm = nil)
        warn_once_about_deprecated_serializer(:public_key_from_spki_pem, :public_key_from_pqc_container_pem)
        public_key_from_pqc_container_pem(pem, algorithm)
      end

      def secret_key_from_pkcs8_der(der, algorithm = nil)
        warn_once_about_deprecated_serializer(:secret_key_from_pkcs8_der, :secret_key_from_pqc_container_der)
        secret_key_from_pqc_container_der(der, algorithm)
      end

      def secret_key_from_pkcs8_pem(pem, algorithm = nil)
        warn_once_about_deprecated_serializer(:secret_key_from_pkcs8_pem, :secret_key_from_pqc_container_pem)
        secret_key_from_pqc_container_pem(pem, algorithm)
      end

      def details(algorithm)
        algorithm = resolve_algorithm!(algorithm)
        DETAILS.fetch(algorithm).dup
      end

      def supported
        DETAILS.keys
      end

      private

      def resolve_algorithm!(algorithm)
        return algorithm if DETAILS.key?(algorithm)

        canonical = DEPRECATED_ALIASES[algorithm]
        if canonical
          warn_once_about_alias(algorithm, canonical)
          return canonical
        end

        raise UnsupportedAlgorithmError, "Unsupported hybrid KEM algorithm: #{algorithm.inspect}"
      end

      def warn_once_about_alias(alias_name, canonical_name)
        @warned_aliases ||= {}
        return if @warned_aliases[alias_name]

        @warned_aliases[alias_name] = true
        Warning.warn(
          "[pq_crypto] HybridKEM algorithm #{alias_name.inspect} is a deprecated alias for " \
          "#{canonical_name.inspect}. Please update your code.\n",
        )
      end

      def warn_once_about_deprecated_serializer(old_name, new_name)
        @warned_serializers ||= {}
        return if @warned_serializers[old_name]

        @warned_serializers[old_name] = true
        Warning.warn(
          "[pq_crypto] #{old_name} is deprecated because the output was never real " \
          "SPKI/PKCS#8 ASN.1 DER — it is a pq_crypto-specific container. Use " \
          "#{new_name} to make this explicit. #{old_name} will be removed in a future release.\n",
        )
      end
    end

    class Keypair < KEM::Keypair; end
    class EncapsulationResult < KEM::EncapsulationResult; end

    class PublicKey < KEM::PublicKey
      def to_spki_der
        HybridKEM.send(:warn_once_about_deprecated_serializer, :to_spki_der, :to_pqc_container_der)
        to_pqc_container_der
      end

      def to_spki_pem
        HybridKEM.send(:warn_once_about_deprecated_serializer, :to_spki_pem, :to_pqc_container_pem)
        to_pqc_container_pem
      end

      def encapsulate
        ciphertext, shared_secret = PQCrypto.send(:native_hybrid_kem_encapsulate, @bytes)
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
      def to_pkcs8_der
        HybridKEM.send(:warn_once_about_deprecated_serializer, :to_pkcs8_der, :to_pqc_container_der)
        to_pqc_container_der
      end

      def to_pkcs8_pem
        HybridKEM.send(:warn_once_about_deprecated_serializer, :to_pkcs8_pem, :to_pqc_container_pem)
        to_pqc_container_pem
      end

      def decapsulate(ciphertext)
        PQCrypto.send(:native_hybrid_kem_decapsulate, String(ciphertext), @bytes)
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
