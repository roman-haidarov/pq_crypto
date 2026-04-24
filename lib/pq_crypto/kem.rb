# frozen_string_literal: true

require "digest"

module PQCrypto
  module KEM
    CANONICAL_ALGORITHM = :ml_kem_768

    DETAILS = {
      CANONICAL_ALGORITHM => {
        name: CANONICAL_ALGORITHM,
        family: Serialization.algorithm_to_family(CANONICAL_ALGORITHM),
        oid: Serialization.algorithm_to_oid(CANONICAL_ALGORITHM),
        public_key_bytes: ML_KEM_PUBLIC_KEY_BYTES,
        secret_key_bytes: ML_KEM_SECRET_KEY_BYTES,
        ciphertext_bytes: ML_KEM_CIPHERTEXT_BYTES,
        shared_secret_bytes: ML_KEM_SHARED_SECRET_BYTES,
        description: "Pure ML-KEM-768 primitive (FIPS 203).",
      }.freeze,
    }.freeze

    class << self
      def generate(algorithm = CANONICAL_ALGORITHM)
        algorithm = resolve_algorithm!(algorithm)
        public_key, secret_key = PQCrypto.__send__(:native_ml_kem_keypair)
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

        raise UnsupportedAlgorithmError, "Unsupported KEM algorithm: #{algorithm.inspect}"
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
        Serialization.public_key_to_pqc_container_der(@algorithm, @bytes)
      end

      def to_pqc_container_pem
        Serialization.public_key_to_pqc_container_pem(@algorithm, @bytes)
      end

      def encapsulate
        ciphertext, shared_secret = PQCrypto.__send__(:native_ml_kem_encapsulate, @bytes)
        EncapsulationResult.new(ciphertext, shared_secret)
      rescue ArgumentError => e
        raise InvalidKeyError, e.message
      end

      def encapsulate_to_bytes
        result = encapsulate
        [result.ciphertext, result.shared_secret]
      end

      def ==(other)
        return false unless other.is_a?(PublicKey) && other.algorithm == algorithm
        PQCrypto.__send__(:native_ct_equals, other.to_bytes, @bytes)
      end

      alias eql? ==

      def hash
        fingerprint.hash
      end

      def fingerprint
        Digest::SHA256.digest(@bytes)
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
        Serialization.secret_key_to_pqc_container_der(@algorithm, @bytes)
      end

      def to_pqc_container_pem
        Serialization.secret_key_to_pqc_container_pem(@algorithm, @bytes)
      end

      def decapsulate(ciphertext)
        PQCrypto.__send__(:native_ml_kem_decapsulate, String(ciphertext).b, @bytes)
      rescue ArgumentError => e
        raise InvalidCiphertextError, e.message
      end

      def wipe!
        PQCrypto.secure_wipe(@bytes)
        self
      end

      def ==(other)
        return false unless other.is_a?(SecretKey) && other.algorithm == algorithm
        PQCrypto.__send__(:native_ct_equals, other.to_bytes, @bytes)
      end

      alias eql? ==

      def hash
        object_id.hash
      end

      def inspect
        "#<#{self.class}:0x#{object_id.to_s(16)} algorithm=#{algorithm.inspect}>"
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

      def inspect
        "#<#{self.class}:0x#{object_id.to_s(16)} ciphertext_bytes=#{@ciphertext.bytesize} shared_secret_bytes=#{@shared_secret.bytesize}>"
      end
    end
  end
end
