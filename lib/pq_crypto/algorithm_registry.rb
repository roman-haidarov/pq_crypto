# frozen_string_literal: true

module PQCrypto
  module AlgorithmRegistry
    class << self
      def entries
        @entries ||= begin
          {
            ml_kem_512: {
              family: :ml_kem,
              legacy_oid: nil,
              standard_oid: "2.16.840.1.101.3.4.4.1",
              public_key_bytes: PQCrypto::ML_KEM_512_PUBLIC_KEY_BYTES,
              secret_key_bytes: PQCrypto::ML_KEM_512_SECRET_KEY_BYTES,
              ciphertext_bytes: PQCrypto::ML_KEM_512_CIPHERTEXT_BYTES,
              shared_secret_bytes: PQCrypto::ML_KEM_512_SHARED_SECRET_BYTES,
              signature_bytes: nil,
              description: "Pure ML-KEM-512 primitive (FIPS 203).",
            }.freeze,
            ml_kem_768: {
              family: :ml_kem,
              legacy_oid: "2.25.186599352125448088867056807454444238446",
              standard_oid: "2.16.840.1.101.3.4.4.2",
              public_key_bytes: PQCrypto::ML_KEM_PUBLIC_KEY_BYTES,
              secret_key_bytes: PQCrypto::ML_KEM_SECRET_KEY_BYTES,
              ciphertext_bytes: PQCrypto::ML_KEM_CIPHERTEXT_BYTES,
              shared_secret_bytes: PQCrypto::ML_KEM_SHARED_SECRET_BYTES,
              signature_bytes: nil,
              description: "Pure ML-KEM-768 primitive (FIPS 203).",
            }.freeze,
            ml_kem_1024: {
              family: :ml_kem,
              legacy_oid: nil,
              standard_oid: "2.16.840.1.101.3.4.4.3",
              public_key_bytes: PQCrypto::ML_KEM_1024_PUBLIC_KEY_BYTES,
              secret_key_bytes: PQCrypto::ML_KEM_1024_SECRET_KEY_BYTES,
              ciphertext_bytes: PQCrypto::ML_KEM_1024_CIPHERTEXT_BYTES,
              shared_secret_bytes: PQCrypto::ML_KEM_1024_SHARED_SECRET_BYTES,
              signature_bytes: nil,
              description: "Pure ML-KEM-1024 primitive (FIPS 203).",
            }.freeze,
            ml_kem_768_x25519_xwing: {
              family: :ml_kem_hybrid,
              legacy_oid: "1.3.6.1.4.1.62253.25722",
              standard_oid: nil,
              public_key_bytes: PQCrypto::HYBRID_KEM_PUBLIC_KEY_BYTES,
              secret_key_bytes: PQCrypto::HYBRID_KEM_SECRET_KEY_BYTES,
              ciphertext_bytes: PQCrypto::HYBRID_KEM_CIPHERTEXT_BYTES,
              shared_secret_bytes: PQCrypto::HYBRID_KEM_SHARED_SECRET_BYTES,
              signature_bytes: nil,
              description: "Hybrid KEM: ML-KEM-768 + X25519 combined via X-Wing SHA3-256 combiner (draft-connolly-cfrg-xwing-kem).",
            }.freeze,
            ml_dsa_44: {
              family: :ml_dsa,
              legacy_oid: nil,
              standard_oid: "2.16.840.1.101.3.4.3.17",
              public_key_bytes: PQCrypto::SIGN_44_PUBLIC_KEY_BYTES,
              secret_key_bytes: PQCrypto::SIGN_44_SECRET_KEY_BYTES,
              ciphertext_bytes: nil,
              shared_secret_bytes: nil,
              signature_bytes: PQCrypto::SIGN_44_BYTES,
              description: "ML-DSA-44 signature primitive (FIPS 204).",
            }.freeze,
            ml_dsa_65: {
              family: :ml_dsa,
              legacy_oid: "2.25.305232938483772195555080795650659207792",
              standard_oid: "2.16.840.1.101.3.4.3.18",
              public_key_bytes: PQCrypto::SIGN_PUBLIC_KEY_BYTES,
              secret_key_bytes: PQCrypto::SIGN_SECRET_KEY_BYTES,
              ciphertext_bytes: nil,
              shared_secret_bytes: nil,
              signature_bytes: PQCrypto::SIGN_BYTES,
              description: "ML-DSA-65 signature primitive (FIPS 204).",
            }.freeze,
            ml_dsa_87: {
              family: :ml_dsa,
              legacy_oid: nil,
              standard_oid: "2.16.840.1.101.3.4.3.19",
              public_key_bytes: PQCrypto::SIGN_87_PUBLIC_KEY_BYTES,
              secret_key_bytes: PQCrypto::SIGN_87_SECRET_KEY_BYTES,
              ciphertext_bytes: nil,
              shared_secret_bytes: nil,
              signature_bytes: PQCrypto::SIGN_87_BYTES,
              description: "ML-DSA-87 signature primitive (FIPS 204).",
            }.freeze,
          }.freeze
        end
      end

      def fetch(symbol)
        entries.fetch(symbol) do
          raise UnsupportedAlgorithmError, "Unsupported algorithm: #{symbol.inspect}"
        end
      end

      def legacy_oid(symbol)
        fetch(symbol).fetch(:legacy_oid)
      end

      def standard_oid(symbol)
        oid = fetch(symbol).fetch(:standard_oid)
        raise SerializationError, "No standard OID registered for #{symbol.inspect}" if oid.nil?

        oid
      end

      def by_legacy_oid(oid)
        legacy_oid_index.fetch(oid, nil)
      end

      def by_standard_oid(oid)
        standard_oid_index.fetch(oid, nil)
      end

      def supported_kems
        supported_by_family(:ml_kem)
      end

      def supported_hybrid_kems
        supported_by_family(:ml_kem_hybrid)
      end

      def supported_signatures
        supported_by_family(:ml_dsa)
      end

      def legacy_metadata_view
        @legacy_metadata_view ||= entries.each_with_object({}) do |(algorithm, entry), view|
          oid = entry.fetch(:legacy_oid)
          next if oid.nil?

          view[algorithm] = {
            family: entry.fetch(:family),
            oid: oid,
          }.freeze
        end.freeze
      end

      def details_for_family(family)
        @details_for_family ||= {}
        @details_for_family[family] ||= begin
          entries.each_with_object({}) do |(algorithm, entry), details|
            next unless entry.fetch(:family) == family

            details[algorithm] = details_entry(algorithm, entry)
          end.freeze
        end
      end

      private

      def supported_by_family(family)
        supported_by_family_cache[family] ||= entries.each_with_object([]) do |(algorithm, entry), supported|
          supported << algorithm if entry.fetch(:family) == family
        end.freeze
      end

      def supported_by_family_cache
        @supported_by_family_cache ||= {}
      end

      def legacy_oid_index
        @legacy_oid_index ||= entries.each_with_object({}) do |(algorithm, entry), index|
          oid = entry.fetch(:legacy_oid)
          index[oid] = algorithm unless oid.nil?
        end.freeze
      end

      def standard_oid_index
        @standard_oid_index ||= entries.each_with_object({}) do |(algorithm, entry), index|
          oid = entry.fetch(:standard_oid)
          index[oid] = algorithm unless oid.nil?
        end.freeze
      end

      def details_entry(algorithm, entry)
        # :oid intentionally remains an alias for the legacy pqc_container_* OID.
        # Use .standard_oid when an RFC 9935/9881 OID is required.
        detail = {
          name: algorithm,
          family: entry.fetch(:family),
          oid: entry.fetch(:legacy_oid),
          public_key_bytes: entry.fetch(:public_key_bytes),
          secret_key_bytes: entry.fetch(:secret_key_bytes),
        }

        if entry.fetch(:ciphertext_bytes)
          detail[:ciphertext_bytes] = entry.fetch(:ciphertext_bytes)
          detail[:shared_secret_bytes] = entry.fetch(:shared_secret_bytes)
        end

        detail[:signature_bytes] = entry.fetch(:signature_bytes) if entry.fetch(:signature_bytes)
        detail[:description] = entry.fetch(:description)

        detail.freeze
      end

    end
  end
end
