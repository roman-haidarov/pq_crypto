# frozen_string_literal: true

module PQCrypto
  module Signature
    CANONICAL_ALGORITHM = :ml_dsa_65

    DETAILS = {
      CANONICAL_ALGORITHM => {
        name: CANONICAL_ALGORITHM,
        family: Serialization.algorithm_to_family(CANONICAL_ALGORITHM),
        oid: Serialization.algorithm_to_oid(CANONICAL_ALGORITHM),
        public_key_bytes: SIGN_PUBLIC_KEY_BYTES,
        secret_key_bytes: SIGN_SECRET_KEY_BYTES,
        signature_bytes: SIGN_BYTES,
        description: "ML-DSA-65 signature primitive (FIPS 204).",
      }.freeze,
    }.freeze

    class << self
      def generate(algorithm = CANONICAL_ALGORITHM)
        validate_algorithm!(algorithm)
        public_key, secret_key = PQCrypto.__send__(:native_sign_keypair)
        Keypair.new(PublicKey.new(algorithm, public_key), SecretKey.new(algorithm, secret_key))
      end

      def public_key_from_bytes(algorithm, bytes)
        validate_algorithm!(algorithm)
        PublicKey.new(algorithm, bytes)
      end

      def secret_key_from_bytes(algorithm, bytes)
        validate_algorithm!(algorithm)
        SecretKey.new(algorithm, bytes)
      end

      def public_key_from_pqc_container_der(der, algorithm = nil)
        resolved_algorithm, bytes = Serialization.public_key_from_pqc_container_der(algorithm, der)
        validate_algorithm!(resolved_algorithm)
        PublicKey.new(resolved_algorithm, bytes)
      end

      def public_key_from_pqc_container_pem(pem, algorithm = nil)
        resolved_algorithm, bytes = Serialization.public_key_from_pqc_container_pem(algorithm, pem)
        validate_algorithm!(resolved_algorithm)
        PublicKey.new(resolved_algorithm, bytes)
      end

      def secret_key_from_pqc_container_der(der, algorithm = nil)
        resolved_algorithm, bytes = Serialization.secret_key_from_pqc_container_der(algorithm, der)
        validate_algorithm!(resolved_algorithm)
        SecretKey.new(resolved_algorithm, bytes)
      end

      def secret_key_from_pqc_container_pem(pem, algorithm = nil)
        resolved_algorithm, bytes = Serialization.secret_key_from_pqc_container_pem(algorithm, pem)
        validate_algorithm!(resolved_algorithm)
        SecretKey.new(resolved_algorithm, bytes)
      end

      def details(algorithm)
        DETAILS.fetch(validate_algorithm!(algorithm)).dup
      end

      def supported
        DETAILS.keys.dup
      end

      private

      def validate_algorithm!(algorithm)
        return algorithm if DETAILS.key?(algorithm)

        raise UnsupportedAlgorithmError, "Unsupported signature algorithm: #{algorithm.inspect}"
      end
    end

    class Keypair
      attr_reader :public_key, :secret_key

      def initialize(public_key, secret_key)
        @public_key = public_key
        @secret_key = secret_key

        unless @public_key.algorithm == @secret_key.algorithm
          raise InvalidKeyError, "Signature keypair algorithms do not match"
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

      def verify(message, signature)
        PQCrypto.__send__(:native_verify, String(message).b, String(signature).b, @bytes)
      rescue PQCrypto::VerificationError
        false
      rescue ArgumentError => e
        raise InvalidKeyError, e.message
      end

      def verify!(message, signature)
        ok = verify(message, signature)
        raise PQCrypto::VerificationError, "Verification failed" unless ok

        true
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
        expected = Signature.details(@algorithm).fetch(:public_key_bytes)
        raise InvalidKeyError, "Invalid signature public key length" unless @bytes.bytesize == expected
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

      def sign(message)
        PQCrypto.__send__(:native_sign, String(message).b, @bytes)
      rescue ArgumentError => e
        raise InvalidKeyError, e.message
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
        expected = Signature.details(@algorithm).fetch(:secret_key_bytes)
        raise InvalidKeyError, "Invalid signature secret key length" unless @bytes.bytesize == expected
      end
    end
  end
end
