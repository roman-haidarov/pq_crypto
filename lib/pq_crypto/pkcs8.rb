# frozen_string_literal: true

module PQCrypto
  module PKCS8
    PEM_LABEL = "PRIVATE KEY"
    PEM_BEGIN = "-----BEGIN #{PEM_LABEL}-----"
    PEM_END = "-----END #{PEM_LABEL}-----"
    ENCRYPTED_PEM_LABEL = "ENCRYPTED PRIVATE KEY"
    ENCRYPTED_PEM_BEGIN = "-----BEGIN #{ENCRYPTED_PEM_LABEL}-----"
    ENCRYPTED_PEM_END = "-----END #{ENCRYPTED_PEM_LABEL}-----"
    ML_KEM_SEED_BYTES = 64
    ML_DSA_SEED_BYTES = 32
    ENCRYPTED_PKCS8_DEFAULT_ITERATIONS = 200_000

    @allow_ml_dsa_seed_format = false

    PRIVATE_KEY_CHOICES = {
      ml_kem_512: {
        seed_bytes: ML_KEM_SEED_BYTES,
        expanded_bytes: PQCrypto::ML_KEM_512_SECRET_KEY_BYTES,
        supported_formats: %i[seed expanded both],
      }.freeze,
      ml_kem_768: {
        seed_bytes: ML_KEM_SEED_BYTES,
        expanded_bytes: PQCrypto::ML_KEM_SECRET_KEY_BYTES,
        supported_formats: %i[seed expanded both],
      }.freeze,
      ml_kem_1024: {
        seed_bytes: ML_KEM_SEED_BYTES,
        expanded_bytes: PQCrypto::ML_KEM_1024_SECRET_KEY_BYTES,
        supported_formats: %i[seed expanded both],
      }.freeze,
      ml_dsa_44: {
        seed_bytes: ML_DSA_SEED_BYTES,
        expanded_bytes: PQCrypto::SIGN_44_SECRET_KEY_BYTES,
        supported_formats: %i[seed expanded both],
      }.freeze,
      ml_dsa_65: {
        seed_bytes: ML_DSA_SEED_BYTES,
        expanded_bytes: PQCrypto::SIGN_SECRET_KEY_BYTES,
        supported_formats: %i[seed expanded both],
      }.freeze,
      ml_dsa_87: {
        seed_bytes: ML_DSA_SEED_BYTES,
        expanded_bytes: PQCrypto::SIGN_87_SECRET_KEY_BYTES,
        supported_formats: %i[seed expanded both],
      }.freeze,
    }.freeze

    class << self
      attr_accessor :allow_ml_dsa_seed_format

      def encode_der(algorithm, secret_material, format:, passphrase: nil, iterations: ENCRYPTED_PKCS8_DEFAULT_ITERATIONS)
        entry = AlgorithmRegistry.fetch(algorithm)
        PrivateKeyChoice.validate_secret_key_algorithm!(algorithm, entry)

        choice_der = PrivateKeyChoice.encode(algorithm, secret_material, format)
        der = private_key_info_to_der(algorithm, choice_der)
        return der if passphrase.nil?

        encrypt_der(der, passphrase: passphrase, iterations: iterations)
      rescue ArgumentError => e
        raise SerializationError, e.message
      ensure
        Internal.safe_wipe(choice_der) if defined?(choice_der)
        Internal.safe_wipe(der) if passphrase && defined?(der)
      end

      def encode_pem(algorithm, secret_material, format:, passphrase: nil, iterations: ENCRYPTED_PKCS8_DEFAULT_ITERATIONS)
        der = encode_der(algorithm, secret_material, format: format, passphrase: passphrase, iterations: iterations)
        pkcs8_native { PQCrypto.__send__(:native_pkcs8_der_to_pem, der, !passphrase.nil?) }
      end

      def decode_der(der, passphrase: nil)
        input = Internal.binary_string(der)
        return decode_encrypted_der(input, passphrase: passphrase) if encrypted_der?(input)

        oid, choice_der = private_key_info_from_der(input)
        algorithm = AlgorithmRegistry.by_standard_oid(oid)
        raise SerializationError, "Unsupported PKCS#8 algorithm OID: #{oid}" if algorithm.nil?

        entry = AlgorithmRegistry.fetch(algorithm)
        PrivateKeyChoice.validate_secret_key_algorithm!(algorithm, entry)
        PrivateKeyChoice.decode(algorithm, Internal.binary_string(choice_der))
      rescue ArgumentError => e
        raise SerializationError, e.message
      ensure
        Internal.safe_wipe(choice_der) if defined?(choice_der)
      end

      def decode_pem(pem, passphrase: nil)
        _encrypted, der = pkcs8_native { PQCrypto.__send__(:native_pkcs8_pem_to_der, String(pem)) }
        begin
          decode_der(der, passphrase: passphrase)
        ensure
          Internal.safe_wipe(der)
        end
      end

      private

      def private_key_info_to_der(algorithm, choice_der)
        pkcs8_native do
          PQCrypto.__send__(:native_pkcs8_private_key_info_to_der,
                            AlgorithmRegistry.standard_oid(algorithm), choice_der)
        end
      end

      def private_key_info_from_der(der)
        pkcs8_native { PQCrypto.__send__(:native_pkcs8_private_key_info_from_der, der) }
      end

      def encrypted_der?(der)
        pkcs8_native { PQCrypto.__send__(:native_pkcs8_encrypted_der?, der) }
      end

      def encrypt_der(der, passphrase:, iterations:)
        iterations = Integer(iterations)
        raise SerializationError, "Encrypted PKCS#8 iterations must be positive" unless iterations.positive?

        pkcs8_native { PQCrypto.__send__(:native_pkcs8_encrypt_der, der, String(passphrase), iterations) }
      end

      def decode_encrypted_der(der, passphrase:)
        raise SerializationError, "Encrypted PKCS#8 requires passphrase" if passphrase.nil?

        plain_der = pkcs8_native { PQCrypto.__send__(:native_pkcs8_decrypt_der, der, String(passphrase)) }
        begin
          decode_der(plain_der)
        ensure
          Internal.safe_wipe(plain_der)
        end
      end

      def pkcs8_native
        yield
      rescue SerializationError
        raise
      rescue PQCrypto::Error => e
        raise SerializationError, e.message
      end
    end
  end
end
