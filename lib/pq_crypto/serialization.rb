# frozen_string_literal: true

module PQCrypto
  module Serialization
    ALGORITHM_METADATA = AlgorithmRegistry.legacy_metadata_view.freeze

    class << self
      def algorithm_metadata(algorithm)
        metadata = ALGORITHM_METADATA[algorithm]
        raise SerializationError, "Unsupported serialization algorithm: #{algorithm.inspect}" unless metadata

        metadata
      end

      def algorithm_to_oid(algorithm)
        algorithm_metadata(algorithm).fetch(:oid)
      end

      def algorithm_to_family(algorithm)
        algorithm_metadata(algorithm).fetch(:family)
      end

      def public_key_to_pqc_container_der(algorithm, bytes)
        PQCrypto.__send__(:native_public_key_to_pqc_container_der, String(algorithm), String(bytes).b)
      rescue ArgumentError, PQCrypto::Error => e
        raise SerializationError, e.message
      end

      def public_key_to_pqc_container_pem(algorithm, bytes)
        PQCrypto.__send__(:native_public_key_to_pqc_container_pem, String(algorithm), String(bytes).b)
      rescue ArgumentError, PQCrypto::Error => e
        raise SerializationError, e.message
      end

      def secret_key_to_pqc_container_der(algorithm, bytes)
        PQCrypto.__send__(:native_secret_key_to_pqc_container_der, String(algorithm), String(bytes).b)
      rescue ArgumentError, PQCrypto::Error => e
        raise SerializationError, e.message
      end

      def secret_key_to_pqc_container_pem(algorithm, bytes)
        PQCrypto.__send__(:native_secret_key_to_pqc_container_pem, String(algorithm), String(bytes).b)
      rescue ArgumentError, PQCrypto::Error => e
        raise SerializationError, e.message
      end

      def public_key_from_pqc_container_der(expected_algorithm, der)
        algorithm, bytes = PQCrypto.__send__(:native_public_key_from_pqc_container_der, String(der).b)
        validate_algorithm_expectation!(expected_algorithm, algorithm)
        [algorithm, bytes]
      rescue ArgumentError, PQCrypto::Error => e
        raise SerializationError, e.message
      end

      def public_key_from_pqc_container_pem(expected_algorithm, pem)
        algorithm, bytes = PQCrypto.__send__(:native_public_key_from_pqc_container_pem, String(pem).b)
        validate_algorithm_expectation!(expected_algorithm, algorithm)
        [algorithm, bytes]
      rescue ArgumentError, PQCrypto::Error => e
        raise SerializationError, e.message
      end

      def secret_key_from_pqc_container_der(expected_algorithm, der)
        algorithm, bytes = PQCrypto.__send__(:native_secret_key_from_pqc_container_der, String(der).b)
        validate_algorithm_expectation!(expected_algorithm, algorithm)
        [algorithm, bytes]
      rescue ArgumentError, PQCrypto::Error => e
        raise SerializationError, e.message
      end

      def secret_key_from_pqc_container_pem(expected_algorithm, pem)
        algorithm, bytes = PQCrypto.__send__(:native_secret_key_from_pqc_container_pem, String(pem).b)
        validate_algorithm_expectation!(expected_algorithm, algorithm)
        [algorithm, bytes]
      rescue ArgumentError, PQCrypto::Error => e
        raise SerializationError, e.message
      end

      private

      def validate_algorithm_expectation!(expected_algorithm, actual_algorithm)
        return if expected_algorithm.nil? || expected_algorithm == actual_algorithm

        raise SerializationError,
              "Expected #{expected_algorithm.inspect}, got #{actual_algorithm.inspect} (serialized key algorithm mismatch)"
      end
    end
  end
end
