# frozen_string_literal: true

module PQCrypto
  module Serialization
    ALGORITHM_METADATA = {
      ml_kem_768_x25519: {
        family: :ml_kem_hybrid,
        # UUID c3c8f7d4-1e6a-4b5f-9a2e-8f1d7c4b6a30
        oid: "1.3.6.1.4.1.55555.1",
      }.freeze,
      ml_dsa_65: {
        family: :ml_dsa,
        # UUID e5a1b9c2-7d3f-4c8e-a6b1-2f5d8e9c4a70
        oid: "1.3.6.1.4.1.55555.2",
      }.freeze,
    }.freeze

    class << self
      def algorithm_metadata(algorithm)
        metadata = ALGORITHM_METADATA[algorithm]
        raise SerializationError, "unsupported serialization algorithm: #{algorithm.inspect}" unless metadata

        metadata
      end

      def algorithm_to_oid(algorithm)
        algorithm_metadata(algorithm).fetch(:oid)
      end

      def algorithm_to_family(algorithm)
        algorithm_metadata(algorithm).fetch(:family)
      end

      def public_key_to_spki_der(algorithm, bytes)
        PQCrypto.public_key_to_spki_der(algorithm, String(bytes))
      rescue PQCrypto::Error => e
        raise SerializationError, e.message
      end

      def public_key_to_spki_pem(algorithm, bytes)
        PQCrypto.public_key_to_spki_pem(algorithm, String(bytes))
      rescue PQCrypto::Error => e
        raise SerializationError, e.message
      end

      def secret_key_to_pkcs8_der(algorithm, bytes)
        PQCrypto.secret_key_to_pkcs8_der(algorithm, String(bytes))
      rescue PQCrypto::Error => e
        raise SerializationError, e.message
      end

      def secret_key_to_pkcs8_pem(algorithm, bytes)
        PQCrypto.secret_key_to_pkcs8_pem(algorithm, String(bytes))
      rescue PQCrypto::Error => e
        raise SerializationError, e.message
      end

      def public_key_from_spki_der(exp_algorithm, der)
        algorithm, bytes = PQCrypto.public_key_from_spki_der(String(der))
        validate_algorithm_expectation!(exp_algorithm, algorithm)
        [algorithm, bytes]
      rescue PQCrypto::Error => e
        raise SerializationError, e.message
      end

      def public_key_from_spki_pem(exp_algorithm, pem)
        algorithm, bytes = PQCrypto.public_key_from_spki_pem(String(pem))
        validate_algorithm_expectation!(exp_algorithm, algorithm)
        [algorithm, bytes]
      rescue PQCrypto::Error => e
        raise SerializationError, e.message
      end

      def secret_key_from_pkcs8_der(exp_algorithm, der)
        algorithm, bytes = PQCrypto.secret_key_from_pkcs8_der(String(der))
        validate_algorithm_expectation!(exp_algorithm, algorithm)
        [algorithm, bytes]
      rescue PQCrypto::Error => e
        raise SerializationError, e.message
      end

      def secret_key_from_pkcs8_pem(exp_algorithm, pem)
        algorithm, bytes = PQCrypto.secret_key_from_pkcs8_pem(String(pem))
        validate_algorithm_expectation!(exp_algorithm, algorithm)
        [algorithm, bytes]
      rescue PQCrypto::Error => e
        raise SerializationError, e.message
      end

      private

      def validate_algorithm_expectation!(exp_algorithm, actual_algorithm)
        return if exp_algorithm.nil? || exp_algorithm == actual_algorithm

        raise SerializationError,
              "Expected #{exp_algorithm.inspect}, got #{actual_algorithm.inspect} (serialized key algorithm mismatch)"
      end
    end
  end
end
