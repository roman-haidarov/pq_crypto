# frozen_string_literal: true

require "digest"

module PQCrypto
  module Signature
    CANONICAL_ALGORITHM = :ml_dsa_65

    DETAILS = AlgorithmRegistry.details_for_family(:ml_dsa).freeze

    NATIVE_DISPATCH = {
      ml_dsa_44: {
        keypair: :native_ml_dsa_44_keypair,
        sign: :native_ml_dsa_44_sign,
        verify: :native_ml_dsa_44_verify,
        keypair_from_seed: :native_ml_dsa_44_keypair_from_seed,
        check_secret_key: :native_ml_dsa_44_check_secret_key,
      }.freeze,
      ml_dsa_65: {
        keypair: :native_sign_keypair,
        sign: :native_sign,
        verify: :native_verify,
        keypair_from_seed: :native_ml_dsa_keypair_from_seed,
        check_secret_key: :native_ml_dsa_check_secret_key,
      }.freeze,
      ml_dsa_87: {
        keypair: :native_ml_dsa_87_keypair,
        sign: :native_ml_dsa_87_sign,
        verify: :native_ml_dsa_87_verify,
        keypair_from_seed: :native_ml_dsa_87_keypair_from_seed,
        check_secret_key: :native_ml_dsa_87_check_secret_key,
      }.freeze,
    }.freeze

    class << self
      def generate(algorithm = CANONICAL_ALGORITHM)
        algorithm = resolve_algorithm!(algorithm)
        public_key, secret_key = PQCrypto.__send__(native_method_for(algorithm, :keypair))
        Keypair.new(PublicKey.new(algorithm, public_key),
                    SecretKey.new(algorithm, secret_key, freshly_generated: true))
      end

      def public_key_from_bytes(algorithm, bytes)
        resolve_algorithm!(algorithm)
        PublicKey.new(algorithm, bytes)
      end

      def secret_key_from_bytes(algorithm, bytes)
        resolve_algorithm!(algorithm)
        SecretKey.new(algorithm, bytes)
      end

      def secret_key_from_seed(algorithm, seed)
        SecretKey.from_seed(resolve_algorithm!(algorithm), seed)
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

      def public_key_from_spki_der(der, algorithm: nil)
        resolved_algorithm, bytes = SPKI.decode_der(der)
        validate_algorithm_match!(algorithm, resolved_algorithm) if algorithm
        PublicKey.new(resolve_algorithm!(resolved_algorithm), bytes)
      end

      def public_key_from_spki_pem(pem, algorithm: nil)
        resolved_algorithm, bytes = SPKI.decode_pem(pem)
        validate_algorithm_match!(algorithm, resolved_algorithm) if algorithm
        PublicKey.new(resolve_algorithm!(resolved_algorithm), bytes)
      end

      def secret_key_from_pkcs8_der(der, passphrase: nil, require_encrypted: false)
        require_encrypted = Internal.strict_boolean!(require_encrypted, name: "require_encrypted")
        secret_key_from_decoded_pkcs8(
          *PKCS8.decode_der(der, passphrase: passphrase, require_encrypted: require_encrypted)
        )
      end

      def secret_key_from_pkcs8_pem(pem, passphrase: nil, require_encrypted: false)
        require_encrypted = Internal.strict_boolean!(require_encrypted, name: "require_encrypted")
        secret_key_from_decoded_pkcs8(
          *PKCS8.decode_pem(pem, passphrase: passphrase, require_encrypted: require_encrypted)
        )
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

      def secret_key_from_decoded_pkcs8(algorithm, format, material)
        algorithm = resolve_algorithm!(algorithm)

        case format
        when :expanded
          SecretKey.new(algorithm, material)
        when :seed
          _public_key, expanded = PQCrypto.__send__(native_method_for(algorithm, :keypair_from_seed), material)
          SecretKey.new(algorithm, expanded, seed: material, freshly_generated: true)
        when :both
          _seed, expanded = material
          SecretKey.new(algorithm, expanded, seed: _seed)
        else
          raise SerializationError, "Unsupported ML-DSA PKCS#8 private key format: #{format.inspect}"
        end
      rescue ArgumentError => e
        raise InvalidKeyError, e.message
      end

      def native_method_for(algorithm, operation)
        NATIVE_DISPATCH.fetch(resolve_algorithm!(algorithm)).fetch(operation)
      end

      def secret_key_checkable?(algorithm)
        NATIVE_DISPATCH.key?(algorithm) && NATIVE_DISPATCH.fetch(algorithm).key?(:check_secret_key)
      end

      def validate_algorithm_match!(expected_algorithm, actual_algorithm)
        expected = resolve_algorithm!(expected_algorithm)
        return if expected == actual_algorithm

        raise SerializationError,
              "Expected #{expected.inspect}, got #{actual_algorithm.inspect} (SPKI key algorithm mismatch)"
      rescue UnsupportedAlgorithmError => e
        raise SerializationError, e.message
      end

      def _streaming_sign(secret_key, io, chunk_size, context)
        validate_streaming_algorithm!(secret_key.algorithm)
        validate_chunk_size!(chunk_size)
        context = validate_context!(context)
        validate_io!(io)

        algorithm = secret_key.algorithm
        sk_bytes = secret_key.__send__(:bytes_for_native)
        begin
          tr = PQCrypto.__send__(:_native_mldsa_extract_tr, algorithm, sk_bytes)
        rescue ArgumentError => e
          raise InvalidKeyError, e.message
        end

        builder = PQCrypto.__send__(:_native_mldsa_mu_builder_new, tr, context)
        builder_consumed = false
        mu = nil
        begin
          _drain_io_into_builder(io, builder, chunk_size)
          mu = PQCrypto.__send__(:_native_mldsa_mu_builder_finalize, builder)
          builder_consumed = true
          PQCrypto.__send__(:_native_mldsa_sign_mu, algorithm, mu, sk_bytes)
        ensure
          PQCrypto.__send__(:_native_mldsa_mu_builder_release, builder) unless builder_consumed
          PQCrypto.secure_wipe(tr) if tr && !tr.frozen?
          PQCrypto.secure_wipe(mu) if mu && !mu.frozen?
        end
      end

      def _streaming_verify(public_key, io, signature, chunk_size, context)
        validate_streaming_algorithm!(public_key.algorithm)
        validate_chunk_size!(chunk_size)
        context = validate_context!(context)
        validate_io!(io)

        algorithm = public_key.algorithm
        pk_bytes = public_key.__send__(:bytes_for_native)
        begin
          tr = PQCrypto.__send__(:_native_mldsa_compute_tr, algorithm, pk_bytes)
        rescue ArgumentError => e
          raise InvalidKeyError, e.message
        end

        builder = PQCrypto.__send__(:_native_mldsa_mu_builder_new, tr, context)
        builder_consumed = false
        mu = nil
        sig_bytes = Internal.binary_string(signature)
        begin
          _drain_io_into_builder(io, builder, chunk_size)
          mu = PQCrypto.__send__(:_native_mldsa_mu_builder_finalize, builder)
          builder_consumed = true
          PQCrypto.__send__(:_native_mldsa_verify_mu, algorithm, mu, sig_bytes, pk_bytes)
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
        ctx = Internal.binary_string(context)
        if ctx.bytesize > 255
          raise ArgumentError, "context must be at most 255 bytes (FIPS 204)"
        end
        ctx
      end

      def validate_streaming_algorithm!(algorithm)
        resolve_algorithm!(algorithm)
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
        @bytes = Internal.frozen_binary_string(bytes)
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

      def to_spki_der
        SPKI.encode_der(@algorithm, @bytes)
      end

      def to_spki_pem
        SPKI.encode_pem(@algorithm, @bytes)
      end

      def verify(message, signature, context: "".b)
        context = Signature.send(:validate_context!, context)
        begin
          PQCrypto.__send__(Signature.send(:native_method_for, @algorithm, :verify), Internal.binary_string(message), Internal.binary_string(signature), @bytes, context)
        rescue ArgumentError => e
          raise InvalidKeyError, e.message
        end
      end

      def verify!(message, signature, context: "".b)
        raise PQCrypto::VerificationError, "Verification failed" unless verify(message, signature, context: context)
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
        Internal.constant_time_equal?(other.send(:bytes_for_native), @bytes)
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

      def initialize(algorithm, bytes, seed: nil, freshly_generated: false)
        @algorithm = algorithm
        @bytes = Internal.binary_string(bytes)
        @seed = seed.nil? ? nil : Internal.binary_string(seed)
        validate_length!
        validate_seed_length! if @seed
        validate_structure! unless freshly_generated
      end

      def valid?
        return true unless Signature.send(:secret_key_checkable?, @algorithm)

        PQCrypto.__send__(Signature.send(:native_method_for, @algorithm, :check_secret_key), @bytes)
      end

      def self.from_seed(algorithm, seed)
        seed_bytes = Internal.binary_string(seed)
        _public_key, expanded = PQCrypto.__send__(Signature.send(:native_method_for, algorithm, :keypair_from_seed), seed_bytes)
        new(algorithm, expanded, seed: seed_bytes, freshly_generated: true)
      rescue ArgumentError => e
        raise InvalidKeyError, e.message
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

      def to_pkcs8_der(format: :expanded, passphrase: nil, iterations: PKCS8::ENCRYPTED_PKCS8_DEFAULT_ITERATIONS)
        PKCS8.encode_der(@algorithm, pkcs8_material(format), format: format, passphrase: passphrase, iterations: iterations)
      end

      def to_pkcs8_pem(format: :expanded, passphrase: nil, iterations: PKCS8::ENCRYPTED_PKCS8_DEFAULT_ITERATIONS)
        PKCS8.encode_pem(@algorithm, pkcs8_material(format), format: format, passphrase: passphrase, iterations: iterations)
      end

      def sign(message, context: "".b)
        context = Signature.send(:validate_context!, context)
        begin
          PQCrypto.__send__(Signature.send(:native_method_for, @algorithm, :sign), Internal.binary_string(message), @bytes, context)
        rescue ArgumentError => e
          raise InvalidKeyError, e.message
        end
      end

      def sign_io(io, chunk_size: 1 << 20, context: "".b)
        Signature.send(:_streaming_sign, self, io, chunk_size, context)
      end

      def wipe!
        PQCrypto.secure_wipe(@bytes)
        PQCrypto.secure_wipe(@seed) if @seed
        self
      end

      def ==(other)
        return false unless other.is_a?(SecretKey) && other.algorithm == algorithm
        Internal.constant_time_equal?(other.send(:bytes_for_native), @bytes)
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

      def validate_structure!
        raise InvalidKeyError, "Invalid #{@algorithm} secret key: ML-DSA structure check failed" unless valid?
      end

      def pkcs8_material(format)
        case format
        when :expanded
          @bytes
        when :seed
          ensure_seed_available!(format)
          @seed
        when :both
          ensure_seed_available!(format)
          [@seed, @bytes]
        else
          raise SerializationError, "Unsupported PKCS#8 private key format: #{format.inspect}"
        end
      end

      def validate_seed_length!
        expected = PKCS8::PrivateKeyChoice.seed_bytes(@algorithm)
        raise InvalidKeyError, "Invalid signature seed length" unless @seed.bytesize == expected
      end

      def ensure_seed_available!(format)
        return if @seed

        raise SerializationError, "ML-DSA #{format.inspect} PKCS#8 export requires original seed material"
      end
    end
  end
end
