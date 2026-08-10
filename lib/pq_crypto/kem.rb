# frozen_string_literal: true

require "digest"

module PQCrypto
  module KEM
    CANONICAL_ALGORITHM = :ml_kem_768

    DETAILS = AlgorithmRegistry.details_for_family(:ml_kem).freeze

    NATIVE_DISPATCH = {
      ml_kem_512: {
        keypair: :native_ml_kem_512_keypair,
        keypair_from_seed: :native_ml_kem_512_keypair_from_seed,
        encapsulate: :native_ml_kem_512_encapsulate,
        decapsulate: :native_ml_kem_512_decapsulate,
        check_public_key: :native_ml_kem_512_check_public_key,
        check_secret_key: :native_ml_kem_512_check_secret_key,
      }.freeze,
      ml_kem_768: {
        keypair: :native_ml_kem_keypair,
        keypair_from_seed: :native_ml_kem_keypair_from_seed,
        encapsulate: :native_ml_kem_encapsulate,
        decapsulate: :native_ml_kem_decapsulate,
        check_public_key: :native_ml_kem_check_public_key,
        check_secret_key: :native_ml_kem_check_secret_key,
      }.freeze,
      ml_kem_1024: {
        keypair: :native_ml_kem_1024_keypair,
        keypair_from_seed: :native_ml_kem_1024_keypair_from_seed,
        encapsulate: :native_ml_kem_1024_encapsulate,
        decapsulate: :native_ml_kem_1024_decapsulate,
        check_public_key: :native_ml_kem_1024_check_public_key,
        check_secret_key: :native_ml_kem_1024_check_secret_key,
      }.freeze,
    }.freeze

    class << self
      def generate(algorithm = CANONICAL_ALGORITHM)
        algorithm = resolve_algorithm!(algorithm)
        public_key, secret_key = PQCrypto.__send__(native_method_for(algorithm, :keypair))
        Keypair.new(PublicKey.new(algorithm, public_key), SecretKey.new(algorithm, secret_key))
      end

      def public_key_from_bytes(algorithm, bytes)
        PublicKey.new(resolve_algorithm!(algorithm), bytes)
      end

      def secret_key_from_bytes(algorithm, bytes)
        SecretKey.new(resolve_algorithm!(algorithm), bytes)
      end

      def secret_key_from_seed(algorithm, seed)
        SecretKey.from_seed(resolve_algorithm!(algorithm), seed)
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

      def secret_key_from_decoded_pkcs8(algorithm, format, material)
        algorithm = resolve_algorithm!(algorithm)

        case format
        when :seed
          _public_key, expanded = PQCrypto.__send__(native_method_for(algorithm, :keypair_from_seed), material)
          SecretKey.new(algorithm, expanded, seed: material)
        when :both
          seed, expanded = material
          SecretKey.new(algorithm, expanded, seed: seed)
        when :expanded
          SecretKey.new(algorithm, material)
        else
          raise SerializationError, "Unsupported PKCS#8 private key format: #{format.inspect}"
        end
      end

      def checkable?(algorithm)
        NATIVE_DISPATCH.key?(algorithm) && NATIVE_DISPATCH.fetch(algorithm).key?(:check_public_key)
      end

      def native_method_for(algorithm, operation)
        NATIVE_DISPATCH.fetch(resolve_algorithm!(algorithm)).fetch(operation)
      end

      def validate_algorithm_match!(expected_algorithm, actual_algorithm)
        expected = resolve_algorithm!(expected_algorithm)
        return if expected == actual_algorithm

        raise SerializationError,
              "Expected #{expected.inspect}, got #{actual_algorithm.inspect} (SPKI key algorithm mismatch)"
      rescue UnsupportedAlgorithmError => e
        raise SerializationError, e.message
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
        @bytes = Internal.frozen_binary_string(bytes)
        validate_length!
        validate_structure!
      end

      def valid?
        if @algorithm == :ml_kem_768_x25519_xwing
          mlkem_half = @bytes.byteslice(0, KEM.details(:ml_kem_768).fetch(:public_key_bytes))
          return PQCrypto.__send__(:native_ml_kem_check_public_key, mlkem_half)
        end
        return true unless KEM.send(:checkable?, @algorithm)

        PQCrypto.__send__(KEM.send(:native_method_for, @algorithm, :check_public_key), @bytes)
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

      def encapsulate
        ciphertext, shared_secret = PQCrypto.__send__(KEM.send(:native_method_for, @algorithm, :encapsulate), @bytes)
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
        expected = KEM.details(@algorithm).fetch(:public_key_bytes)
        raise InvalidKeyError, "Invalid KEM public key length" unless @bytes.bytesize == expected
      end

      def validate_structure!
        raise InvalidKeyError, "Invalid #{@algorithm} public key: FIPS 203 modulus check failed" unless valid?
      end
    end

    class SecretKey
      attr_reader :algorithm

      def initialize(algorithm, bytes, seed: nil)
        @algorithm = algorithm
        @bytes = Internal.binary_string(bytes)
        @seed = seed.nil? ? nil : Internal.binary_string(seed)
        validate_length!
        validate_seed_length! if @seed
        validate_structure!
      end

      def valid?
        return true unless KEM.send(:checkable?, @algorithm)

        PQCrypto.__send__(KEM.send(:native_method_for, @algorithm, :check_secret_key), @bytes)
      end

      def self.from_seed(algorithm, seed)
        seed_bytes = Internal.binary_string(seed)
        _public_key, expanded = PQCrypto.__send__(KEM.send(:native_method_for, algorithm, :keypair_from_seed), seed_bytes)
        new(algorithm, expanded, seed: seed_bytes)
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

      def decapsulate(ciphertext)
        PQCrypto.__send__(KEM.send(:native_method_for, @algorithm, :decapsulate), Internal.binary_string(ciphertext), @bytes)
      rescue ArgumentError => e
        raise InvalidCiphertextError, e.message
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
        expected = KEM.details(@algorithm).fetch(:secret_key_bytes)
        raise InvalidKeyError, "Invalid KEM secret key length" unless @bytes.bytesize == expected
      end

      def validate_structure!
        raise InvalidKeyError, "Invalid #{@algorithm} secret key: FIPS 203 hash check failed" unless valid?
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
        raise InvalidKeyError, "Invalid KEM seed length" unless @seed.bytesize == expected
      end

      def ensure_seed_available!(format)
        return if @seed

        raise SerializationError, "PKCS#8 #{format.inspect} export from KEM::SecretKey requires original seed material"
      end
    end

    class EncapsulationResult
      attr_reader :ciphertext, :shared_secret

      def initialize(ciphertext, shared_secret)
        @ciphertext = Internal.binary_string(ciphertext)
        @shared_secret = Internal.binary_string(shared_secret)
      end

      def inspect
        "#<#{self.class}:0x#{object_id.to_s(16)} ciphertext_bytes=#{@ciphertext.bytesize} shared_secret_bytes=#{@shared_secret.bytesize}>"
      end
    end
  end
end
