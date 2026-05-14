# frozen_string_literal: true

module PQCrypto
  module PKCS8
    module PrivateKeyChoice
      SEED_TAG = 0x80
      EXPANDED_TAG = 0x04
      BOTH_TAG = 0x30

      KEYPAIR_FROM_SEED_METHODS = {
        ml_kem_512: :native_ml_kem_512_keypair_from_seed,
        ml_kem_768: :native_ml_kem_keypair_from_seed,
        ml_kem_1024: :native_ml_kem_1024_keypair_from_seed,
        ml_dsa_44: :native_ml_dsa_44_keypair_from_seed,
        ml_dsa_65: :native_ml_dsa_keypair_from_seed,
        ml_dsa_87: :native_ml_dsa_87_keypair_from_seed,
      }.freeze

      module_function

      def encode(algorithm, secret_material, format)
        ensure_format_supported!(algorithm, format)

        case format
        when :seed
          encode_seed(algorithm, secret_material)
        when :expanded
          encode_expanded(algorithm, secret_material)
        when :both
          encode_both(algorithm, secret_material)
        else
          raise SerializationError, "Unsupported PKCS#8 private key format: #{format.inspect}"
        end
      end

      def decode(algorithm, choice_der)
        tag = choice_der.getbyte(0)
        raise SerializationError, "PKCS#8 privateKey CHOICE is empty" if tag.nil?

        case tag
        when SEED_TAG
          ensure_format_supported!(algorithm, :seed)
          decode_seed(algorithm, choice_der)
        when EXPANDED_TAG
          ensure_format_supported!(algorithm, :expanded)
          decode_expanded(algorithm, choice_der)
        when BOTH_TAG
          ensure_format_supported!(algorithm, :both)
          decode_both(algorithm, choice_der)
        else
          raise SerializationError,
                "Unsupported PKCS#8 #{algorithm.inspect} private key CHOICE tag: 0x#{tag.to_s(16).rjust(2, '0')}"
        end
      end

      def validate_secret_key_algorithm!(algorithm, entry)
        return if PKCS8::PRIVATE_KEY_CHOICES.key?(algorithm) && %i[ml_kem ml_dsa].include?(entry.fetch(:family))

        raise SerializationError, "PKCS#8 private key codec is not supported for #{algorithm.inspect}"
      end

      def ensure_format_supported!(algorithm, format)
        if ml_dsa_algorithm?(algorithm) && %i[seed both].include?(format) && !PKCS8.allow_ml_dsa_seed_format
          raise SerializationError,
                "ML-DSA seed-format PKCS#8 is opt-in; set PQCrypto::PKCS8.allow_ml_dsa_seed_format = true to enable (see SECURITY.md for caveats)"
        end

        return if profile(algorithm).fetch(:supported_formats).include?(format)

        raise SerializationError, "Unsupported PKCS#8 private key format for #{algorithm.inspect}: #{format.inspect}"
      end

      def seed_bytes(algorithm)
        profile(algorithm).fetch(:seed_bytes)
      end

      def expanded_bytes(algorithm)
        profile(algorithm).fetch(:expanded_bytes)
      end

      def ml_dsa_algorithm?(algorithm)
        %i[ml_dsa_44 ml_dsa_65 ml_dsa_87].include?(algorithm)
      end

      def profile(algorithm)
        PKCS8::PRIVATE_KEY_CHOICES.fetch(algorithm) do
          raise SerializationError, "PKCS#8 private key codec is not supported for #{algorithm.inspect}"
        end
      end

      def validate_seed_length!(algorithm, seed)
        expected = seed_bytes(algorithm)
        return if seed.bytesize == expected

        raise SerializationError,
              "Invalid #{algorithm.inspect} seed private key length: expected #{expected}, got #{seed.bytesize}"
      end

      def validate_expanded_length!(algorithm, expanded)
        expected = expanded_bytes(algorithm)
        return if expanded.bytesize == expected

        raise SerializationError,
              "Invalid #{algorithm.inspect} expanded private key length: expected #{expected}, got #{expanded.bytesize}"
      end

      def decode_seed(algorithm, choice_der)
        _tag, seed, next_offset = DER.decode_tlv(choice_der, 0, expected_tag: SEED_TAG, label: "seed")
        raise SerializationError, "PKCS#8 seed contains trailing data" unless next_offset == choice_der.bytesize

        validate_seed_length!(algorithm, seed)
        [algorithm, :seed, seed]
      end

      def decode_expanded(algorithm, choice_der)
        _tag, bytes, next_offset = DER.decode_tlv(choice_der, 0, expected_tag: EXPANDED_TAG, label: "expandedKey")
        raise SerializationError, "PKCS#8 expandedKey contains trailing data" unless next_offset == choice_der.bytesize

        validate_expanded_length!(algorithm, bytes)
        [algorithm, :expanded, bytes]
      end

      def decode_both(algorithm, choice_der)
        _tag, body, next_offset = DER.decode_tlv(choice_der, 0, expected_tag: BOTH_TAG, label: "both")
        raise SerializationError, "PKCS#8 both contains trailing data" unless next_offset == choice_der.bytesize

        _seed_tag, seed_bytes, offset = DER.decode_tlv(body, 0, expected_tag: EXPANDED_TAG, label: "both seed")
        _expanded_tag, expanded_bytes, offset = DER.decode_tlv(body, offset, expected_tag: EXPANDED_TAG, label: "both expandedKey")
        raise SerializationError, "PKCS#8 both must contain exactly 2 elements" unless offset == body.bytesize

        validate_seed_length!(algorithm, seed_bytes)
        validate_expanded_length!(algorithm, expanded_bytes)
        verify_both_consistency!(algorithm, seed_bytes, expanded_bytes)

        [algorithm, :both, [seed_bytes, expanded_bytes]]
      end

      def encode_seed(algorithm, secret_material)
        seed = Internal.binary_string(secret_material)
        validate_seed_length!(algorithm, seed)

        DER.encode_tlv(SEED_TAG, seed)
      end

      def encode_expanded(algorithm, secret_material)
        bytes = Internal.binary_string(secret_material)
        validate_expanded_length!(algorithm, bytes)

        DER.encode_tlv(EXPANDED_TAG, bytes)
      end

      def encode_both(algorithm, secret_material)
        unless secret_material.is_a?(Array) && secret_material.size == 2
          raise SerializationError, "PKCS#8 both format requires [seed, expandedKey]"
        end

        seed, expanded = secret_material
        seed_bytes = Internal.binary_string(seed)
        expanded_bytes = Internal.binary_string(expanded)
        validate_seed_length!(algorithm, seed_bytes)
        validate_expanded_length!(algorithm, expanded_bytes)

        body = DER.encode_tlv(EXPANDED_TAG, seed_bytes) + DER.encode_tlv(EXPANDED_TAG, expanded_bytes)
        DER.encode_tlv(BOTH_TAG, body)
      end

      def verify_both_consistency!(algorithm, seed, expanded)
        native_method = KEYPAIR_FROM_SEED_METHODS.fetch(algorithm, nil)
        return if native_method.nil?

        _public_key, expected_expanded = PQCrypto.__send__(native_method, seed)
        return if Internal.constant_time_equal?(expected_expanded, expanded)

        raise SerializationError, consistency_error_message(algorithm)
      ensure
        Internal.safe_wipe(expected_expanded) if defined?(expected_expanded)
      end

      def consistency_error_message(algorithm)
        return "seed/expandedKey inconsistency in ML-DSA PKCS#8 'both' encoding (RFC 9881 §6)" if ml_dsa_algorithm?(algorithm)

        "seed/expandedKey inconsistency in PKCS#8 'both' encoding (RFC 9935 §8)"
      end
    end
  end
end
