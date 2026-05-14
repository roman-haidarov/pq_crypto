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
        dump(:native_public_key_to_pqc_container_der, algorithm, bytes)
      end

      def public_key_to_pqc_container_pem(algorithm, bytes)
        dump(:native_public_key_to_pqc_container_pem, algorithm, bytes)
      end

      def secret_key_to_pqc_container_der(algorithm, bytes)
        dump(:native_secret_key_to_pqc_container_der, algorithm, bytes)
      end

      def secret_key_to_pqc_container_pem(algorithm, bytes)
        dump(:native_secret_key_to_pqc_container_pem, algorithm, bytes)
      end

      def public_key_from_pqc_container_der(expected_algorithm, der)
        load(:native_public_key_from_pqc_container_der, expected_algorithm, der)
      end

      def public_key_from_pqc_container_pem(expected_algorithm, pem)
        load(:native_public_key_from_pqc_container_pem, expected_algorithm, pem)
      end

      def secret_key_from_pqc_container_der(expected_algorithm, der)
        load(:native_secret_key_from_pqc_container_der, expected_algorithm, der)
      end

      def secret_key_from_pqc_container_pem(expected_algorithm, pem)
        load(:native_secret_key_from_pqc_container_pem, expected_algorithm, pem)
      end

      private

      def dump(native_method, algorithm, bytes)
        PQCrypto.__send__(native_method, String(algorithm), Internal.binary_string(bytes))
      rescue ArgumentError, PQCrypto::Error => e
        raise SerializationError, e.message
      end

      def load(native_method, expected_algorithm, source)
        algorithm, bytes = PQCrypto.__send__(native_method, Internal.binary_string(source))
        validate_algorithm_expectation!(expected_algorithm, algorithm)
        [algorithm, bytes]
      rescue ArgumentError, PQCrypto::Error => e
        raise SerializationError, e.message
      end

      def validate_algorithm_expectation!(expected_algorithm, actual_algorithm)
        return if expected_algorithm.nil? || expected_algorithm == actual_algorithm

        raise SerializationError,
              "Expected #{expected_algorithm.inspect}, got #{actual_algorithm.inspect} (serialized key algorithm mismatch)"
      end
    end
  end
end
