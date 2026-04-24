# frozen_string_literal: true

module PQCrypto
  module Serialization
    ALGORITHM_METADATA = {
      ml_kem_768: {
        family: :ml_kem,
        oid: "2.25.186599352125448088867056807454444238446",
      }.freeze,
      ml_kem_768_x25519_xwing: {
        family: :ml_kem_hybrid,
        oid: "1.3.6.1.4.1.62253.25722",
      }.freeze,
      ml_dsa_65: {
        family: :ml_dsa,
        oid: "2.25.305232938483772195555080795650659207792",
      }.freeze,
    }.freeze

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
