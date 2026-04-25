# frozen_string_literal: true

require "digest"

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
        resolve_algorithm!(algorithm)
        public_key, secret_key = PQCrypto.__send__(:native_sign_keypair)
        Keypair.new(PublicKey.new(algorithm, public_key), SecretKey.new(algorithm, secret_key))
      end

      def public_key_from_bytes(algorithm, bytes)
        resolve_algorithm!(algorithm)
        PublicKey.new(algorithm, bytes)
      end

      def secret_key_from_bytes(algorithm, bytes)
        resolve_algorithm!(algorithm)
        SecretKey.new(algorithm, bytes)
      end

      def public_key_from_pqc_container_der(der, algorithm = nil)
        resolved_algorithm, bytes = Serialization.public_key_from_pqc_container_der(algorithm, der)
        resolve_algorithm!(resolved_algorithm)
        PublicKey.new(resolved_algorithm, bytes)
      end

      def public_key_from_pqc_container_pem(pem, algorithm = nil)
        resolved_algorithm, bytes = Serialization.public_key_from_pqc_container_pem(algorithm, pem)
        resolve_algorithm!(resolved_algorithm)
        PublicKey.new(resolved_algorithm, bytes)
      end

      def secret_key_from_pqc_container_der(der, algorithm = nil)
        resolved_algorithm, bytes = Serialization.secret_key_from_pqc_container_der(algorithm, der)
        resolve_algorithm!(resolved_algorithm)
        SecretKey.new(resolved_algorithm, bytes)
      end

      def secret_key_from_pqc_container_pem(pem, algorithm = nil)
        resolved_algorithm, bytes = Serialization.secret_key_from_pqc_container_pem(algorithm, pem)
        resolve_algorithm!(resolved_algorithm)
        SecretKey.new(resolved_algorithm, bytes)
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

        raise UnsupportedAlgorithmError, "Unsupported signature algorithm: #{algorithm.inspect}"
      end

      def _streaming_sign(secret_key, io, chunk_size, context)
        validate_chunk_size!(chunk_size)
        validate_context!(context)
        validate_io!(io)

        sk_bytes = secret_key.__send__(:bytes_for_native)
        begin
          tr = PQCrypto.__send__(:_native_mldsa_extract_tr, sk_bytes)
        rescue ArgumentError => e
          raise InvalidKeyError, e.message
        end

        builder = PQCrypto.__send__(:_native_mldsa_mu_builder_new, tr, context.b)
        builder_consumed = false
        mu = nil
        begin
          _drain_io_into_builder(io, builder, chunk_size)
          mu = PQCrypto.__send__(:_native_mldsa_mu_builder_finalize, builder)
          builder_consumed = true
          PQCrypto.__send__(:_native_mldsa_sign_mu, mu, sk_bytes)
        ensure
          PQCrypto.__send__(:_native_mldsa_mu_builder_release, builder) unless builder_consumed
          PQCrypto.secure_wipe(tr) if tr && !tr.frozen?
          PQCrypto.secure_wipe(mu) if mu && !mu.frozen?
        end
      end

      def _streaming_verify(public_key, io, signature, chunk_size, context)
        validate_chunk_size!(chunk_size)
        validate_context!(context)
        validate_io!(io)

        pk_bytes = public_key.__send__(:bytes_for_native)
        begin
          tr = PQCrypto.__send__(:_native_mldsa_compute_tr, pk_bytes)
        rescue ArgumentError => e
          raise InvalidKeyError, e.message
        end

        builder = PQCrypto.__send__(:_native_mldsa_mu_builder_new, tr, context.b)
        builder_consumed = false
        mu = nil
        sig_bytes = String(signature).b
        begin
          _drain_io_into_builder(io, builder, chunk_size)
          mu = PQCrypto.__send__(:_native_mldsa_mu_builder_finalize, builder)
          builder_consumed = true
          PQCrypto.__send__(:_native_mldsa_verify_mu, mu, sig_bytes, pk_bytes)
        ensure
          PQCrypto.__send__(:_native_mldsa_mu_builder_release, builder) unless builder_consumed

          PQCrypto.secure_wipe(tr) if tr && !tr.frozen?
          PQCrypto.secure_wipe(mu) if mu && !mu.frozen?
        end
      end

      def _drain_io_into_builder(io, builder, chunk_size)
        buffer = String.new(capacity: chunk_size).b
        loop do
          result = io.read(chunk_size, buffer)
          break if result.nil?

          chunk = result.equal?(buffer) ? buffer : result
          chunk_bytes = chunk.encoding == Encoding::BINARY ? chunk : chunk.b
          break if chunk_bytes.bytesize.zero?

          PQCrypto.__send__(:_native_mldsa_mu_builder_update, builder, chunk_bytes)
        end
      end

      def validate_io!(io)
        unless io.respond_to?(:read)
          raise ArgumentError, "io must respond to #read"
        end
      end

      def validate_chunk_size!(chunk_size)
        unless chunk_size.is_a?(Integer) && chunk_size > 0
          raise ArgumentError, "chunk_size must be a positive Integer"
        end
      end

      def validate_context!(context)
        ctx = String(context).b
        if ctx.bytesize > 255
          raise ArgumentError, "context must be at most 255 bytes (FIPS 204)"
        end
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
      rescue ArgumentError => e
        raise InvalidKeyError, e.message
      end

      def verify!(message, signature)
        raise PQCrypto::VerificationError, "Verification failed" unless verify(message, signature)
        true
      end

      def verify_io(io, signature, chunk_size: 1 << 20, context: "".b)
        Signature.send(:_streaming_verify, self, io, signature, chunk_size, context)
      end

      def verify_io!(io, signature, chunk_size: 1 << 20, context: "".b)
        unless verify_io(io, signature, chunk_size: chunk_size, context: context)
          raise PQCrypto::VerificationError, "Verification failed"
        end
        true
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

      def bytes_for_native
        @bytes
      end

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

      def sign_io(io, chunk_size: 1 << 20, context: "".b)
        Signature.send(:_streaming_sign, self, io, chunk_size, context)
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

      def bytes_for_native
        @bytes
      end

      def validate_length!
        expected = Signature.details(@algorithm).fetch(:secret_key_bytes)
        raise InvalidKeyError, "Invalid signature secret key length" unless @bytes.bytesize == expected
      end
    end
  end
end
