# frozen_string_literal: true

module PQCrypto
  module Signature
    DETAILS = {
      ml_dsa_65: {
        name: :ml_dsa_65,
        family: Serialization.algorithm_to_family(:ml_dsa_65),
        oid: Serialization.algorithm_to_oid(:ml_dsa_65),
        public_key_bytes: SIGN_PUBLIC_KEY_BYTES,
        secret_key_bytes: SIGN_SECRET_KEY_BYTES,
        signature_bytes: SIGN_BYTES,
      }.freeze,
    }.freeze

    class << self
      def generate(algorithm = :ml_dsa_65)
        validate_algorithm!(algorithm)
        public_key, secret_key = PQCrypto.sign_keypair
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
        validate_algorithm!(algorithm)
        DETAILS.fetch(algorithm).dup
      end

      def supported
        DETAILS.keys
      end

      private

      def validate_algorithm!(algorithm)
        return if DETAILS.key?(algorithm)

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

      def to_spki_der
        Serialization.public_key_to_spki_der(@algorithm, @bytes)
      end

      def to_spki_pem
        Serialization.public_key_to_spki_pem(@algorithm, @bytes)
      end

      def verify(message, signature)
        PQCrypto.verify(String(message), String(signature), @bytes)
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

      def to_pkcs8_der
        Serialization.secret_key_to_pkcs8_der(@algorithm, @bytes)
      end

      def to_pkcs8_pem
        Serialization.secret_key_to_pkcs8_pem(@algorithm, @bytes)
      end

      def sign(message)
        PQCrypto.sign(String(message), @bytes)
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
