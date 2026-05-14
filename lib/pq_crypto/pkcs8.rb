# frozen_string_literal: true

require "openssl"

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
    PBES2_OID = "1.2.840.113549.1.5.13"
    PBKDF2_OID = "1.2.840.113549.1.5.12"
    HMAC_SHA256_OID = "1.2.840.113549.2.9"
    AES_256_CBC_OID = "2.16.840.1.101.3.4.1.42"
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

        der = OpenSSL::ASN1::Sequence.new([
          OpenSSL::ASN1::Integer.new(0),
          OpenSSL::ASN1::Sequence.new([
            OpenSSL::ASN1::ObjectId.new(AlgorithmRegistry.standard_oid(algorithm_symbol)),
          ]),
          OpenSSL::ASN1::OctetString.new(choice_der),
        ]).to_der.b

        return der if passphrase.nil?

        encrypt_der(der, passphrase: passphrase, iterations: iterations)
      rescue OpenSSL::ASN1::ASN1Error => e
        raise SerializationError, e.message
      ensure
        safe_wipe(choice_der) if defined?(choice_der)
        safe_wipe(der) if passphrase && defined?(der)
      end

      def encode_pem(algorithm_symbol, secret_material, format:, passphrase: nil, iterations: ENCRYPTED_PKCS8_DEFAULT_ITERATIONS)
        der = encode_der(algorithm_symbol, secret_material, format: format, passphrase: passphrase, iterations: iterations)
        body = encode_base64(der).scan(/.{1,64}/).join("\n")
        if passphrase.nil?
          "#{PEM_BEGIN}\n#{body}\n#{PEM_END}\n"
        else
          "#{ENCRYPTED_PEM_BEGIN}\n#{body}\n#{ENCRYPTED_PEM_END}\n"
        end
      end

      def decode_der(der, passphrase: nil)
        input = String(der).b
        outer = decode_asn1(input)
        raise SerializationError, "PKCS#8 DER contains trailing data" unless outer.to_der.b == input
        raise SerializationError, "PKCS#8 must be an ASN.1 SEQUENCE" unless outer.is_a?(OpenSSL::ASN1::Sequence)

        if encrypted_private_key_info?(outer)
          raise SerializationError, "Encrypted PKCS#8 requires passphrase" if passphrase.nil?

          plain_der = decrypt_der(outer, passphrase: passphrase)
          begin
            return decode_der(plain_der)
          ensure
            safe_wipe(plain_der)
          end
        end

        raise SerializationError, "PKCS#8 OneAsymmetricKey must contain exactly 3 elements" unless outer.value.size == 3

        version, algorithm_identifier, private_key = outer.value
        decode_version(version)
        algorithm = decode_algorithm_identifier(algorithm_identifier)
        entry = AlgorithmRegistry.fetch(algorithm)
        validate_secret_key_algorithm!(algorithm, entry)

        unless private_key.is_a?(OpenSSL::ASN1::OctetString)
          raise SerializationError, "PKCS#8 privateKey must be an OCTET STRING"
        end

        decode_private_key_choice(algorithm, String(private_key.value).b)
      end

      def decode_pem(pem, passphrase: nil)
        der = der_from_pem(pem)
        decode_der(der, passphrase: passphrase)
      end

      private

      def decode_asn1(der)
        OpenSSL::ASN1.decode(der)
      rescue OpenSSL::ASN1::ASN1Error => e
        raise SerializationError, e.message
      end

      def safe_wipe(value)
        return unless value.is_a?(String) && !value.frozen?

        PQCrypto.secure_wipe(value)
      rescue ArgumentError
        nil
      end

      def encrypt_der(der, passphrase:, iterations:)
        passphrase = String(passphrase)
        iterations = Integer(iterations)
        raise SerializationError, "Encrypted PKCS#8 iterations must be positive" unless iterations.positive?

        salt = OpenSSL::Random.random_bytes(16)
        cipher = OpenSSL::Cipher.new("AES-256-CBC")
        cipher.encrypt
        iv = cipher.random_iv
        key = OpenSSL::PKCS5.pbkdf2_hmac(passphrase, salt, iterations, 32, OpenSSL::Digest::SHA256.new)
        cipher.key = key
        encrypted = cipher.update(String(der).b) + cipher.final
        PQCrypto.secure_wipe(key) if key && !key.frozen?

        encrypted_private_key_info_der(salt, iterations, iv, encrypted)
      rescue ArgumentError, OpenSSL::Cipher::CipherError => e
        raise SerializationError, e.message
      end

      def decrypt_der(outer, passphrase:)
        salt, iterations, iv, encrypted = decode_encrypted_private_key_info(outer)
        key = OpenSSL::PKCS5.pbkdf2_hmac(String(passphrase), salt, iterations, 32, OpenSSL::Digest::SHA256.new)
        cipher = OpenSSL::Cipher.new("AES-256-CBC")
        cipher.decrypt
        cipher.key = key
        cipher.iv = iv
        (cipher.update(encrypted) + cipher.final).b
      rescue ArgumentError, OpenSSL::Cipher::CipherError => e
        raise SerializationError, "Failed to decrypt PKCS#8 private key: #{e.message}"
      ensure
        PQCrypto.secure_wipe(key) if defined?(key) && key && !key.frozen?
      end

      def encrypted_private_key_info_der(salt, iterations, iv, encrypted)
        OpenSSL::ASN1::Sequence.new([
          OpenSSL::ASN1::Sequence.new([
            OpenSSL::ASN1::ObjectId.new(PBES2_OID),
            OpenSSL::ASN1::Sequence.new([
              OpenSSL::ASN1::Sequence.new([
                OpenSSL::ASN1::ObjectId.new(PBKDF2_OID),
                OpenSSL::ASN1::Sequence.new([
                  OpenSSL::ASN1::OctetString.new(salt),
                  OpenSSL::ASN1::Integer.new(iterations),
                  OpenSSL::ASN1::Integer.new(32),
                  OpenSSL::ASN1::Sequence.new([
                    OpenSSL::ASN1::ObjectId.new(HMAC_SHA256_OID),
                    OpenSSL::ASN1::Null.new(nil),
                  ]),
                ]),
              ]),
              OpenSSL::ASN1::Sequence.new([
                OpenSSL::ASN1::ObjectId.new(AES_256_CBC_OID),
                OpenSSL::ASN1::OctetString.new(iv),
              ]),
            ]),
          ]),
          OpenSSL::ASN1::OctetString.new(encrypted),
        ]).to_der.b
      rescue OpenSSL::ASN1::ASN1Error => e
        raise SerializationError, e.message
      end

      def encrypted_private_key_info?(outer)
        outer.value.size == 2 &&
          outer.value.first.is_a?(OpenSSL::ASN1::Sequence) &&
          outer.value.first.value.first.is_a?(OpenSSL::ASN1::ObjectId) &&
          outer.value.first.value.first.oid == PBES2_OID
      end

      def decode_encrypted_private_key_info(outer)
        raise SerializationError, "Encrypted PKCS#8 must contain exactly 2 elements" unless outer.value.size == 2

        algorithm_identifier, encrypted_data = outer.value
        raise SerializationError, "Encrypted PKCS#8 encryptedData must be an OCTET STRING" unless encrypted_data.is_a?(OpenSSL::ASN1::OctetString)
        raise SerializationError, "Encrypted PKCS#8 algorithm must be an AlgorithmIdentifier SEQUENCE" unless algorithm_identifier.is_a?(OpenSSL::ASN1::Sequence)
        raise SerializationError, "Encrypted PKCS#8 AlgorithmIdentifier must contain PBES2 parameters" unless algorithm_identifier.value.size == 2

        pbes2_oid, pbes2_params = algorithm_identifier.value
        raise SerializationError, "Encrypted PKCS#8 algorithm must be PBES2" unless pbes2_oid.is_a?(OpenSSL::ASN1::ObjectId) && pbes2_oid.oid == PBES2_OID
        raise SerializationError, "PBES2 parameters must be a SEQUENCE" unless pbes2_params.is_a?(OpenSSL::ASN1::Sequence)
        raise SerializationError, "PBES2 parameters must contain KDF and encryption scheme" unless pbes2_params.value.size == 2

        salt, iterations = decode_pbkdf2_params(pbes2_params.value[0])
        iv = decode_aes256_cbc_params(pbes2_params.value[1])
        [salt, iterations, iv, String(encrypted_data.value).b]
      end

      def decode_pbkdf2_params(kdf_alg)
        raise SerializationError, "PBES2 KDF must be an AlgorithmIdentifier SEQUENCE" unless kdf_alg.is_a?(OpenSSL::ASN1::Sequence)
        raise SerializationError, "PBES2 KDF AlgorithmIdentifier must contain parameters" unless kdf_alg.value.size == 2

        oid, params = kdf_alg.value
        raise SerializationError, "PBES2 KDF must be PBKDF2" unless oid.is_a?(OpenSSL::ASN1::ObjectId) && oid.oid == PBKDF2_OID
        raise SerializationError, "PBKDF2 params must be a SEQUENCE" unless params.is_a?(OpenSSL::ASN1::Sequence)
        raise SerializationError, "PBKDF2 params must contain salt, iteration count, key length, and PRF" unless params.value.size == 4

        salt_asn1, iterations_asn1, key_length_asn1, prf_alg = params.value
        raise SerializationError, "PBKDF2 salt must be an OCTET STRING" unless salt_asn1.is_a?(OpenSSL::ASN1::OctetString)
        raise SerializationError, "PBKDF2 iterations must be an INTEGER" unless iterations_asn1.is_a?(OpenSSL::ASN1::Integer)
        raise SerializationError, "PBKDF2 key length must be an INTEGER" unless key_length_asn1.is_a?(OpenSSL::ASN1::Integer)

        iterations = iterations_asn1.value.to_i
        key_length = key_length_asn1.value.to_i
        raise SerializationError, "PBKDF2 iterations must be positive" unless iterations.positive?
        raise SerializationError, "PBKDF2 key length must be 32 bytes" unless key_length == 32
        validate_hmac_sha256_prf!(prf_alg)

        [String(salt_asn1.value).b, iterations]
      end

      def validate_hmac_sha256_prf!(prf_alg)
        raise SerializationError, "PBKDF2 PRF must be an AlgorithmIdentifier SEQUENCE" unless prf_alg.is_a?(OpenSSL::ASN1::Sequence)
        raise SerializationError, "PBKDF2 PRF AlgorithmIdentifier must contain OID and NULL" unless prf_alg.value.size == 2

        oid, null = prf_alg.value
        raise SerializationError, "PBKDF2 PRF must be HMAC-SHA256" unless oid.is_a?(OpenSSL::ASN1::ObjectId) && oid.oid == HMAC_SHA256_OID
        raise SerializationError, "PBKDF2 PRF parameters must be NULL" unless null.is_a?(OpenSSL::ASN1::Null)
      end

      def decode_aes256_cbc_params(encryption_scheme)
        raise SerializationError, "PBES2 encryption scheme must be an AlgorithmIdentifier SEQUENCE" unless encryption_scheme.is_a?(OpenSSL::ASN1::Sequence)
        raise SerializationError, "PBES2 encryption scheme must contain OID and IV" unless encryption_scheme.value.size == 2

        oid, iv = encryption_scheme.value
        raise SerializationError, "PBES2 encryption scheme must be AES-256-CBC" unless oid.is_a?(OpenSSL::ASN1::ObjectId) && oid.oid == AES_256_CBC_OID
        raise SerializationError, "AES-256-CBC IV must be an OCTET STRING" unless iv.is_a?(OpenSSL::ASN1::OctetString)

        iv_bytes = String(iv.value).b
        raise SerializationError, "AES-256-CBC IV must be 16 bytes" unless iv_bytes.bytesize == 16
        iv_bytes
      end

      def decode_version(value)
        raise SerializationError, "PKCS#8 version must be an INTEGER" unless value.is_a?(OpenSSL::ASN1::Integer)

        version = value.value.respond_to?(:to_i) ? value.value.to_i : value.value
        raise SerializationError, "PKCS#8 version must be 0" unless version == 0
      end

      def decode_algorithm_identifier(value)
        unless value.is_a?(OpenSSL::ASN1::Sequence)
          raise SerializationError, "PKCS#8 algorithm must be an AlgorithmIdentifier SEQUENCE"
        end
        unless value.value.size == 1
          raise SerializationError, "PKCS#8 AlgorithmIdentifier parameters must be absent"
        end

        oid = value.value.first
        raise SerializationError, "PKCS#8 AlgorithmIdentifier must contain an OBJECT IDENTIFIER" unless oid.is_a?(OpenSSL::ASN1::ObjectId)

        algorithm = AlgorithmRegistry.by_standard_oid(oid.oid)
        raise SerializationError, "Unsupported PKCS#8 algorithm OID: #{oid.oid}" if algorithm.nil?

        algorithm
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
        seed = decode_tlv_value(choice_der, expected_tag: 0x80, label: "seed")
        validate_seed_length!(algorithm, seed)

        [algorithm, :seed, seed]
      end

      def decode_expanded_key(algorithm, choice_der)
        expanded = decode_asn1(choice_der)
        unless expanded.to_der.b == choice_der
          raise SerializationError, "PKCS#8 expandedKey contains trailing data"
        end
        unless expanded.is_a?(OpenSSL::ASN1::OctetString)
          raise SerializationError, "PKCS#8 expandedKey must be an OCTET STRING"
        end

        bytes = String(expanded.value).b
        validate_expanded_key_length!(algorithm, bytes)

        [algorithm, :expanded, bytes]
      end

      def decode_both_choice(algorithm, choice_der)
        both = decode_asn1(choice_der)
        raise SerializationError, "PKCS#8 both contains trailing data" unless both.to_der.b == choice_der
        raise SerializationError, "PKCS#8 both must be a SEQUENCE" unless both.is_a?(OpenSSL::ASN1::Sequence)
        raise SerializationError, "PKCS#8 both must contain exactly 2 elements" unless both.value.size == 2

        seed, expanded = both.value
        raise SerializationError, "PKCS#8 both seed must be an OCTET STRING" unless seed.is_a?(OpenSSL::ASN1::OctetString)
        unless expanded.is_a?(OpenSSL::ASN1::OctetString)
          raise SerializationError, "PKCS#8 both expandedKey must be an OCTET STRING"
        end

        seed_bytes = String(seed.value).b
        expanded_bytes = String(expanded.value).b
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

        OpenSSL::ASN1::OctetString.new(bytes).to_der.b
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

        OpenSSL::ASN1::Sequence.new([
          OpenSSL::ASN1::OctetString.new(seed_bytes),
          OpenSSL::ASN1::OctetString.new(expanded_bytes),
        ]).to_der.b
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

      def decode_tlv_value(der, expected_tag:, label:)
        tag = der.getbyte(0)
        unless tag == expected_tag
          raise SerializationError, "PKCS#8 #{label} has unexpected tag: 0x#{tag.to_s(16).rjust(2, '0')}"
        end

        length, length_bytes = decode_der_length(der, 1)
        value_offset = 1 + length_bytes
        value_end = value_offset + length
        raise SerializationError, "PKCS#8 #{label} length exceeds available data" if value_end > der.bytesize
        raise SerializationError, "PKCS#8 #{label} contains trailing data" unless value_end == der.bytesize

        der.byteslice(value_offset, length).b
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

      def encode_base64(bytes)
        [String(bytes).b].pack("m0")
      end

      def decode_base64(body)
        compact = body.gsub(/[\r\n]/, "")
        unless compact.match?(/\A(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?\z/)
          raise SerializationError, "Invalid PKCS#8 PEM: invalid base64"
        end

        compact.unpack1("m0").b
      rescue ArgumentError => e
        raise SerializationError, e.message
      end

      def der_from_pem(pem)
        text = String(pem)
        match = text.match(/\A#{Regexp.escape(PEM_BEGIN)}\r?\n(?<body>[A-Za-z0-9+\/=\r\n]+)\r?\n#{Regexp.escape(PEM_END)}[ \t\r\n]*\z/) ||
                text.match(/\A#{Regexp.escape(ENCRYPTED_PEM_BEGIN)}\r?\n(?<body>[A-Za-z0-9+\/=\r\n]+)\r?\n#{Regexp.escape(ENCRYPTED_PEM_END)}[ \t\r\n]*\z/)
        raise SerializationError, "Invalid PKCS#8 PEM: expected #{PEM_LABEL.inspect} or #{ENCRYPTED_PEM_LABEL.inspect} label" unless match

        body = match[:body]
        raise SerializationError, "Invalid PKCS#8 PEM: embedded NUL in body" if body.include?("\0")

        decode_base64(body)
      end
    end
  end
end
