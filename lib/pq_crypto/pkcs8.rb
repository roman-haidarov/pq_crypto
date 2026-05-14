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

      def encode_der(algorithm_symbol, secret_material, format:, passphrase: nil, iterations: ENCRYPTED_PKCS8_DEFAULT_ITERATIONS)
        entry = AlgorithmRegistry.fetch(algorithm_symbol)
        validate_secret_key_algorithm!(algorithm_symbol, entry)
        ensure_format_supported!(algorithm_symbol, format)

        choice_der = case format
                     when :seed
                       encode_seed_choice(secret_material, algorithm_symbol)
                     when :expanded
                       encode_expanded_key_choice(secret_material, algorithm_symbol)
                     when :both
                       encode_both_choice(secret_material, algorithm_symbol)
                     else
                       raise SerializationError, "Unsupported PKCS#8 private key format: #{format.inspect}"
                     end

        der = native_call do
          PQCrypto.__send__(:native_pkcs8_private_key_info_to_der,
                            AlgorithmRegistry.standard_oid(algorithm_symbol), choice_der)
        end

        return der if passphrase.nil?

        iterations = Integer(iterations)
        raise SerializationError, "Encrypted PKCS#8 iterations must be positive" unless iterations.positive?

        native_call { PQCrypto.__send__(:native_pkcs8_encrypt_der, der, String(passphrase), iterations) }
      rescue ArgumentError => e
        raise SerializationError, e.message
      ensure
        safe_wipe(choice_der) if defined?(choice_der)
        safe_wipe(der) if passphrase && defined?(der)
      end

      def encode_pem(algorithm_symbol, secret_material, format:, passphrase: nil, iterations: ENCRYPTED_PKCS8_DEFAULT_ITERATIONS)
        der = encode_der(algorithm_symbol, secret_material, format: format, passphrase: passphrase, iterations: iterations)
        native_call { PQCrypto.__send__(:native_pkcs8_der_to_pem, der, !passphrase.nil?) }
      end

      def decode_der(der, passphrase: nil)
        input = String(der).b
        if native_call { PQCrypto.__send__(:native_pkcs8_encrypted_der?, input) }
          raise SerializationError, "Encrypted PKCS#8 requires passphrase" if passphrase.nil?

          plain_der = native_call { PQCrypto.__send__(:native_pkcs8_decrypt_der, input, String(passphrase)) }
          begin
            return decode_der(plain_der)
          ensure
            safe_wipe(plain_der)
          end
        end

        oid, choice_der = native_call { PQCrypto.__send__(:native_pkcs8_private_key_info_from_der, input) }
        algorithm = AlgorithmRegistry.by_standard_oid(oid)
        raise SerializationError, "Unsupported PKCS#8 algorithm OID: #{oid}" if algorithm.nil?

        entry = AlgorithmRegistry.fetch(algorithm)
        validate_secret_key_algorithm!(algorithm, entry)
        decode_private_key_choice(algorithm, String(choice_der).b)
      rescue ArgumentError => e
        raise SerializationError, e.message
      ensure
        safe_wipe(choice_der) if defined?(choice_der)
      end

      def decode_pem(pem, passphrase: nil)
        _encrypted, der = native_call { PQCrypto.__send__(:native_pkcs8_pem_to_der, String(pem)) }
        begin
          decode_der(der, passphrase: passphrase)
        ensure
          safe_wipe(der)
        end
      end

      private

      def native_call
        yield
      rescue SerializationError
        raise
      rescue PQCrypto::Error => e
        raise SerializationError, e.message
      end

      def safe_wipe(value)
        return unless value.is_a?(String) && !value.frozen?

        PQCrypto.secure_wipe(value)
      rescue ArgumentError
        nil
      end

      def decode_private_key_choice(algorithm, choice_der)
        tag = choice_der.getbyte(0)
        raise SerializationError, "PKCS#8 privateKey CHOICE is empty" if tag.nil?

        case tag
        when 0x80
          ensure_format_supported!(algorithm, :seed)
          decode_seed_choice(algorithm, choice_der)
        when 0x04
          ensure_format_supported!(algorithm, :expanded)
          decode_expanded_key(algorithm, choice_der)
        when 0x30
          ensure_format_supported!(algorithm, :both)
          decode_both_choice(algorithm, choice_der)
        else
          raise SerializationError,
                "Unsupported PKCS#8 #{algorithm.inspect} private key CHOICE tag: 0x#{tag.to_s(16).rjust(2, '0')}"
        end
      end

      def decode_seed_choice(algorithm, choice_der)
        _tag, seed, next_offset = decode_tlv(choice_der, 0, expected_tag: 0x80, label: "seed")
        raise SerializationError, "PKCS#8 seed contains trailing data" unless next_offset == choice_der.bytesize

        validate_seed_length!(algorithm, seed)
        [algorithm, :seed, seed]
      end

      def decode_expanded_key(algorithm, choice_der)
        _tag, bytes, next_offset = decode_tlv(choice_der, 0, expected_tag: 0x04, label: "expandedKey")
        raise SerializationError, "PKCS#8 expandedKey contains trailing data" unless next_offset == choice_der.bytesize

        validate_expanded_key_length!(algorithm, bytes)
        [algorithm, :expanded, bytes]
      end

      def decode_both_choice(algorithm, choice_der)
        _tag, body, next_offset = decode_tlv(choice_der, 0, expected_tag: 0x30, label: "both")
        raise SerializationError, "PKCS#8 both contains trailing data" unless next_offset == choice_der.bytesize

        _seed_tag, seed_bytes, offset = decode_tlv(body, 0, expected_tag: 0x04, label: "both seed")
        _expanded_tag, expanded_bytes, offset = decode_tlv(body, offset, expected_tag: 0x04, label: "both expandedKey")
        raise SerializationError, "PKCS#8 both must contain exactly 2 elements" unless offset == body.bytesize

        validate_seed_length!(algorithm, seed_bytes)
        validate_expanded_key_length!(algorithm, expanded_bytes)
        verify_both_consistency!(algorithm, seed_bytes, expanded_bytes)

        [algorithm, :both, [seed_bytes, expanded_bytes]]
      end

      def encode_seed_choice(secret_material, algorithm)
        seed = String(secret_material).b
        validate_seed_length!(algorithm, seed)

        encode_tlv(0x80, seed)
      end

      def encode_expanded_key_choice(secret_material, algorithm)
        bytes = String(secret_material).b
        validate_expanded_key_length!(algorithm, bytes)

        encode_tlv(0x04, bytes)
      end

      def encode_both_choice(secret_material, algorithm)
        unless secret_material.is_a?(Array) && secret_material.size == 2
          raise SerializationError, "PKCS#8 both format requires [seed, expandedKey]"
        end

        seed, expanded = secret_material
        seed_bytes = String(seed).b
        expanded_bytes = String(expanded).b
        validate_seed_length!(algorithm, seed_bytes)
        validate_expanded_key_length!(algorithm, expanded_bytes)

        body = encode_tlv(0x04, seed_bytes) + encode_tlv(0x04, expanded_bytes)
        encode_tlv(0x30, body)
      end

      def verify_both_consistency!(algorithm, seed, expanded)
        native_method = {
          ml_kem_512: :native_ml_kem_512_keypair_from_seed,
          ml_kem_768: :native_ml_kem_keypair_from_seed,
          ml_kem_1024: :native_ml_kem_1024_keypair_from_seed,
          ml_dsa_44: :native_ml_dsa_44_keypair_from_seed,
          ml_dsa_65: :native_ml_dsa_keypair_from_seed,
          ml_dsa_87: :native_ml_dsa_87_keypair_from_seed,
        }[algorithm]
        return if native_method.nil?

        _public_key, expected_expanded = PQCrypto.__send__(native_method, seed)
        return if PQCrypto.__send__(:native_ct_equals, expected_expanded, expanded)

        message = if ml_dsa_algorithm?(algorithm)
                    "seed/expandedKey inconsistency in ML-DSA PKCS#8 'both' encoding (RFC 9881 §6)"
                  else
                    "seed/expandedKey inconsistency in PKCS#8 'both' encoding (RFC 9935 §8)"
                  end
        raise SerializationError, message
      ensure
        safe_wipe(expected_expanded) if defined?(expected_expanded)
      end

      def validate_seed_length!(algorithm, seed)
        expected = choice_profile(algorithm).fetch(:seed_bytes)
        return if seed.bytesize == expected

        raise SerializationError,
              "Invalid #{algorithm.inspect} seed private key length: expected #{expected}, got #{seed.bytesize}"
      end

      def validate_expanded_key_length!(algorithm, expanded)
        expected = choice_profile(algorithm).fetch(:expanded_bytes)
        return if expanded.bytesize == expected

        raise SerializationError,
              "Invalid #{algorithm.inspect} expanded private key length: expected #{expected}, got #{expanded.bytesize}"
      end

      def validate_secret_key_algorithm!(algorithm_symbol, entry)
        return if PRIVATE_KEY_CHOICES.key?(algorithm_symbol) && %i[ml_kem ml_dsa].include?(entry.fetch(:family))

        raise SerializationError, "PKCS#8 private key codec is not supported for #{algorithm_symbol.inspect}"
      end

      def choice_profile(algorithm)
        PRIVATE_KEY_CHOICES.fetch(algorithm) do
          raise SerializationError, "PKCS#8 private key codec is not supported for #{algorithm.inspect}"
        end
      end

      def ensure_format_supported!(algorithm, format)
        if ml_dsa_algorithm?(algorithm) && %i[seed both].include?(format) && !allow_ml_dsa_seed_format
          raise SerializationError,
                "ML-DSA seed-format PKCS#8 is opt-in; set PQCrypto::PKCS8.allow_ml_dsa_seed_format = true to enable (see SECURITY.md for caveats)"
        end

        profile = choice_profile(algorithm)
        return if profile.fetch(:supported_formats).include?(format)

        raise SerializationError, "Unsupported PKCS#8 private key format for #{algorithm.inspect}: #{format.inspect}"
      end

      def ml_dsa_algorithm?(algorithm)
        %i[ml_dsa_44 ml_dsa_65 ml_dsa_87].include?(algorithm)
      end

      def encode_tlv(tag, value)
        tag.chr.b + encode_der_length(value.bytesize) + value
      end

      def decode_tlv(der, offset, expected_tag:, label:)
        tag = der.getbyte(offset)
        raise SerializationError, "PKCS#8 #{label} is missing" if tag.nil?
        unless tag == expected_tag
          raise SerializationError, "PKCS#8 #{label} has unexpected tag: 0x#{tag.to_s(16).rjust(2, '0')}"
        end

        length, length_bytes = decode_der_length(der, offset + 1)
        value_offset = offset + 1 + length_bytes
        value_end = value_offset + length
        raise SerializationError, "PKCS#8 #{label} length exceeds available data" if value_end > der.bytesize

        [tag, der.byteslice(value_offset, length).b, value_end]
      end

      def encode_der_length(length)
        raise SerializationError, "Invalid DER length" if length.negative?
        return length.chr.b if length < 0x80

        encoded = []
        remaining = length
        until remaining.zero?
          encoded.unshift(remaining & 0xff)
          remaining >>= 8
        end

        (0x80 | encoded.length).chr.b + encoded.pack("C*").b
      end

      def decode_der_length(der, offset)
        first = der.getbyte(offset)
        raise SerializationError, "PKCS#8 DER length is missing" if first.nil?

        return [first, 1] if first < 0x80

        length_octets = first & 0x7f
        raise SerializationError, "PKCS#8 DER indefinite length is not allowed" if length_octets.zero?
        raise SerializationError, "PKCS#8 DER length is too large" if length_octets > 4
        if offset + 1 + length_octets > der.bytesize
          raise SerializationError, "PKCS#8 DER length exceeds available data"
        end

        length = 0
        length_octets.times do |i|
          byte = der.getbyte(offset + 1 + i)
          length = (length << 8) | byte
        end

        if length < 0x80 || (length_octets > 1 && der.getbyte(offset + 1).zero?)
          raise SerializationError, "PKCS#8 DER length is not minimally encoded"
        end

        [length, 1 + length_octets]
      end
    end
  end
end
