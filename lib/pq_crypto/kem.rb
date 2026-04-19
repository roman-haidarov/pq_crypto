# frozen_string_literal: true

module PQCrypto
  module KEM
    CANONICAL_ALGORITHM = :ml_kem_768_x25519
    DEPRECATED_ALIASES = { ml_kem_768: CANONICAL_ALGORITHM }.freeze

    DETAILS = {
      CANONICAL_ALGORITHM => {
        name: CANONICAL_ALGORITHM,
        family: Serialization.algorithm_to_family(CANONICAL_ALGORITHM),
        oid: Serialization.algorithm_to_oid(CANONICAL_ALGORITHM),
        public_key_bytes: KEM_PUBLIC_KEY_BYTES,
        secret_key_bytes: KEM_SECRET_KEY_BYTES,
        ciphertext_bytes: KEM_CIPHERTEXT_BYTES,
        shared_secret_bytes: KEM_SHARED_SECRET_BYTES,
        description:
          "Hybrid KEM: ML-KEM-768 (FIPS 203) + X25519 combined via transcript-bound HKDF-SHA256. " \
          "Not interoperable with pure ML-KEM-768.",
      }.freeze,
    }.freeze

    class << self
      def generate(algorithm = CANONICAL_ALGORITHM)
        algorithm = resolve_algorithm!(algorithm)
        public_key, secret_key = PQCrypto.kem_keypair
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

      def public_key_from_spki_der(der, algorithm = nil)
        resolved_algorithm, bytes = Serialization.public_key_from_spki_der(algorithm, der)
        PublicKey.new(resolved_algorithm, bytes)
      end

      def public_key_from_spki_pem(pem, algorithm = nil)
        resolved_algorithm, bytes = Serialization.public_key_from_spki_pem(algorithm, pem)
        PublicKey.new(resolved_algorithm, bytes)
      end

      def secret_key_from_pkcs8_der(der, algorithm = nil)
        resolved_algorithm, bytes = Serialization.secret_key_from_pkcs8_der(algorithm, der)
        SecretKey.new(resolved_algorithm, bytes)
      end

      def secret_key_from_pkcs8_pem(pem, algorithm = nil)
        resolved_algorithm, bytes = Serialization.secret_key_from_pkcs8_pem(algorithm, pem)
        SecretKey.new(resolved_algorithm, bytes)
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

        raise UnsupportedAlgorithmError, "Unsupported KEM algorithm: #{algorithm.inspect}"
      end

      def warn_once_about_alias(alias_name, canonical_name)
        @warned_aliases ||= {}
        return if @warned_aliases[alias_name]

        @warned_aliases[alias_name] = true
        Warning.warn(
          "[pq_crypto] KEM algorithm #{alias_name.inspect} is a deprecated alias for " \
          "#{canonical_name.inspect} (hybrid ML-KEM-768 + X25519). The :ml_kem_768 name " \
          "was misleading because the wire shape is not pure ML-KEM-768. " \
          "Please update your code to use #{canonical_name.inspect}.\n",
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

    class Keypair
      attr_reader :public_key, :secret_key

      def initialize(public_key, secret_key)
        @public_key = public_key
        @secret_key = secret_key

        unless @public_key.algorithm == @secret_key.algorithm
          raise InvalidKeyError, "KEM keypair algorithms do not match"
        end
      end

      def algorithm
        @public_key.algorithm
      end
    end

    class PublicKey
      attr_reader :algorithm

      def initialize(algorithm, bytes)
        @algorithm = algorithm
        @bytes = String(bytes).b
        validate_length!
      end

      def to_bytes
        @bytes.dup
      end

      def to_pqc_container_der
        Serialization.public_key_to_spki_der(@algorithm, @bytes)
      end

      def to_pqc_container_pem
        Serialization.public_key_to_spki_pem(@algorithm, @bytes)
      end

      def to_spki_der
        KEM.send(:warn_once_about_deprecated_serializer, :to_spki_der, :to_pqc_container_der)
        to_pqc_container_der
      end

      def to_spki_pem
        KEM.send(:warn_once_about_deprecated_serializer, :to_spki_pem, :to_pqc_container_pem)
        to_pqc_container_pem
      end

      def encapsulate
        ciphertext, shared_secret = PQCrypto.kem_encapsulate(@bytes)
        EncapsulationResult.new(ciphertext, shared_secret)
      rescue ArgumentError => e
        raise InvalidKeyError, e.message
      end

      def encapsulate_to_bytes
        result = encapsulate
        [result.ciphertext, result.shared_secret]
      end

      def ==(other)
        other.is_a?(PublicKey) && other.algorithm == algorithm && other.to_bytes == @bytes
      end

      alias eql? ==

      def hash
        [self.class, algorithm, @bytes].hash
      end

      private

      def validate_length!
        expected = KEM.details(@algorithm).fetch(:public_key_bytes)
        raise InvalidKeyError, "Invalid KEM public key length" unless @bytes.bytesize == expected
      end
    end

    class SecretKey
      attr_reader :algorithm

      def initialize(algorithm, bytes)
        @algorithm = algorithm
        @bytes = String(bytes).b
        validate_length!
      end

      def to_bytes
        @bytes.dup
      end

      def to_pqc_container_der
        Serialization.secret_key_to_pkcs8_der(@algorithm, @bytes)
      end

      def to_pqc_container_pem
        Serialization.secret_key_to_pkcs8_pem(@algorithm, @bytes)
      end

      def to_pkcs8_der
        KEM.send(:warn_once_about_deprecated_serializer, :to_pkcs8_der, :to_pqc_container_der)
        to_pqc_container_der
      end

      def to_pkcs8_pem
        KEM.send(:warn_once_about_deprecated_serializer, :to_pkcs8_pem, :to_pqc_container_pem)
        to_pqc_container_pem
      end

      def decapsulate(ciphertext)
        PQCrypto.kem_decapsulate(String(ciphertext), @bytes)
      rescue ArgumentError => e
        raise InvalidCiphertextError, e.message
      end

      def wipe!
        PQCrypto.secure_wipe(@bytes)
        self
      end

      def ==(other)
        other.is_a?(SecretKey) && other.algorithm == algorithm && other.to_bytes == @bytes
      end

      alias eql? ==

      def hash
        [self.class, algorithm, @bytes].hash
      end

      private

      def validate_length!
        expected = KEM.details(@algorithm).fetch(:secret_key_bytes)
        raise InvalidKeyError, "Invalid KEM secret key length" unless @bytes.bytesize == expected
      end
    end

    class EncapsulationResult
      attr_reader :ciphertext, :shared_secret

      def initialize(ciphertext, shared_secret)
        @ciphertext = String(ciphertext).b
        @shared_secret = String(shared_secret).b
      end
    end
  end
end
