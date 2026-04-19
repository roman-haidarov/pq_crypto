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

      # Project-local serialization container. NOT interoperable with
      # OpenSSL/Go/etc. (not real ASN.1 SPKI).
      def to_pqc_container_der
        Serialization.public_key_to_spki_der(@algorithm, @bytes)
      end

      def to_pqc_container_pem
        Serialization.public_key_to_spki_pem(@algorithm, @bytes)
      end

      # Deprecated names. The output was never real SPKI; it's a pq_crypto
      # project container. Will be removed in a future release.
      def to_spki_der
        Signature.send(:warn_once_about_deprecated_serializer, :to_spki_der, :to_pqc_container_der)
        to_pqc_container_der
      end

      def to_spki_pem
        Signature.send(:warn_once_about_deprecated_serializer, :to_spki_pem, :to_pqc_container_pem)
        to_pqc_container_pem
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

      def to_pqc_container_der
        Serialization.secret_key_to_pkcs8_der(@algorithm, @bytes)
      end

      def to_pqc_container_pem
        Serialization.secret_key_to_pkcs8_pem(@algorithm, @bytes)
      end

      def to_pkcs8_der
        Signature.send(:warn_once_about_deprecated_serializer, :to_pkcs8_der, :to_pqc_container_der)
        to_pqc_container_der
      end

      def to_pkcs8_pem
        Signature.send(:warn_once_about_deprecated_serializer, :to_pkcs8_pem, :to_pqc_container_pem)
        to_pqc_container_pem
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
