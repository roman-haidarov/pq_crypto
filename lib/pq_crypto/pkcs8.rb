# frozen_string_literal: true

require "openssl"

module PQCrypto
  module PKCS8
    PEM_LABEL = "PRIVATE KEY"
    PEM_BEGIN = "-----BEGIN #{PEM_LABEL}-----"
    PEM_END = "-----END #{PEM_LABEL}-----"
    ML_KEM_SEED_BYTES = 64

    class << self
      def encode_der(algorithm_symbol, secret_material, format:)
        entry = AlgorithmRegistry.fetch(algorithm_symbol)
        validate_secret_key_algorithm!(algorithm_symbol, entry)

        choice_der = case format
                     when :seed
                       encode_seed_choice(secret_material, algorithm_symbol)
                     when :expanded
                       encode_expanded_key_choice(secret_material, algorithm_symbol, entry)
                     when :both
                       encode_both_choice(secret_material, algorithm_symbol, entry)
                     else
                       raise SerializationError, "Unsupported PKCS#8 private key format: #{format.inspect}"
                     end

        OpenSSL::ASN1::Sequence.new([
          OpenSSL::ASN1::Integer.new(0),
          OpenSSL::ASN1::Sequence.new([
            OpenSSL::ASN1::ObjectId.new(AlgorithmRegistry.standard_oid(algorithm_symbol)),
          ]),
          OpenSSL::ASN1::OctetString.new(choice_der),
        ]).to_der.b
      rescue OpenSSL::ASN1::ASN1Error => e
        raise SerializationError, e.message
      end

      def encode_pem(algorithm_symbol, secret_material, format:)
        der = encode_der(algorithm_symbol, secret_material, format: format)
        body = encode_base64(der).scan(/.{1,64}/).join("\n")
        "#{PEM_BEGIN}\n#{body}\n#{PEM_END}\n"
      end

      def decode_der(der)
        input = String(der).b
        outer = decode_asn1(input)
        raise SerializationError, "PKCS#8 DER contains trailing data" unless outer.to_der.b == input
        raise SerializationError, "PKCS#8 must be an ASN.1 SEQUENCE" unless outer.is_a?(OpenSSL::ASN1::Sequence)
        raise SerializationError, "PKCS#8 OneAsymmetricKey must contain exactly 3 elements" unless outer.value.size == 3

        version, algorithm_identifier, private_key = outer.value
        decode_version(version)
        algorithm = decode_algorithm_identifier(algorithm_identifier)
        entry = AlgorithmRegistry.fetch(algorithm)
        validate_secret_key_algorithm!(algorithm, entry)

        unless private_key.is_a?(OpenSSL::ASN1::OctetString)
          raise SerializationError, "PKCS#8 privateKey must be an OCTET STRING"
        end

        decode_private_key_choice(algorithm, entry, String(private_key.value).b)
      end

      def decode_pem(pem)
        der = der_from_pem(pem)
        decode_der(der)
      end

      private

      def decode_asn1(der)
        OpenSSL::ASN1.decode(der)
      rescue OpenSSL::ASN1::ASN1Error => e
        raise SerializationError, e.message
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

      def decode_private_key_choice(algorithm, entry, choice_der)
        tag = choice_der.getbyte(0)
        raise SerializationError, "PKCS#8 privateKey CHOICE is empty" if tag.nil?

        case tag
        when 0x80
          decode_seed_choice(algorithm, choice_der)
        when 0x04
          decode_expanded_key(algorithm, entry, choice_der)
        when 0x30
          decode_both_choice(algorithm, entry, choice_der)
        else
          raise SerializationError, "Unsupported PKCS#8 ML-KEM private key CHOICE tag: 0x#{tag.to_s(16).rjust(2, '0')}"
        end
      end

      def decode_seed_choice(algorithm, choice_der)
        seed = decode_tlv_value(choice_der, expected_tag: 0x80, label: "seed")
        validate_seed_length!(algorithm, seed)

        [algorithm, :seed, seed]
      end

      def decode_expanded_key(algorithm, entry, choice_der)
        expanded = decode_asn1(choice_der)
        unless expanded.to_der.b == choice_der
          raise SerializationError, "PKCS#8 expandedKey contains trailing data"
        end
        unless expanded.is_a?(OpenSSL::ASN1::OctetString)
          raise SerializationError, "PKCS#8 expandedKey must be an OCTET STRING"
        end

        bytes = String(expanded.value).b
        validate_expanded_key_length!(algorithm, entry, bytes)

        [algorithm, :expanded, bytes]
      end

      def decode_both_choice(algorithm, entry, choice_der)
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
        validate_expanded_key_length!(algorithm, entry, expanded_bytes)
        verify_both_consistency!(seed_bytes, expanded_bytes)

        [algorithm, :both, [seed_bytes, expanded_bytes]]
      end

      def encode_seed_choice(secret_material, algorithm)
        seed = String(secret_material).b
        validate_seed_length!(algorithm, seed)

        encode_tlv(0x80, seed)
      end

      def encode_expanded_key_choice(secret_material, algorithm, entry)
        bytes = String(secret_material).b
        validate_expanded_key_length!(algorithm, entry, bytes)

        OpenSSL::ASN1::OctetString.new(bytes).to_der.b
      end

      def encode_both_choice(secret_material, algorithm, entry)
        unless secret_material.is_a?(Array) && secret_material.size == 2
          raise SerializationError, "PKCS#8 both format requires [seed, expandedKey]"
        end

        seed, expanded = secret_material
        seed_bytes = String(seed).b
        expanded_bytes = String(expanded).b
        validate_seed_length!(algorithm, seed_bytes)
        validate_expanded_key_length!(algorithm, entry, expanded_bytes)

        OpenSSL::ASN1::Sequence.new([
          OpenSSL::ASN1::OctetString.new(seed_bytes),
          OpenSSL::ASN1::OctetString.new(expanded_bytes),
        ]).to_der.b
      end

      def verify_both_consistency!(seed, expanded)
        _public_key, expected_expanded = PQCrypto.__send__(:native_ml_kem_keypair_from_seed, seed)
        return if PQCrypto.__send__(:native_ct_equals, expected_expanded, expanded)

        raise SerializationError,
              "seed/expandedKey inconsistency in PKCS#8 'both' encoding (RFC 9935 §8)"
      end

      def validate_seed_length!(algorithm, seed)
        return if seed.bytesize == ML_KEM_SEED_BYTES

        raise SerializationError,
              "Invalid #{algorithm.inspect} seed private key length: expected #{ML_KEM_SEED_BYTES}, got #{seed.bytesize}"
      end

      def validate_expanded_key_length!(algorithm, entry, expanded)
        expected = entry.fetch(:secret_key_bytes)
        return if expanded.bytesize == expected

        raise SerializationError,
              "Invalid #{algorithm.inspect} expanded private key length: expected #{expected}, got #{expanded.bytesize}"
      end

      def validate_secret_key_algorithm!(algorithm_symbol, entry)
        return if entry.fetch(:family) == :ml_kem

        raise SerializationError, "PKCS#8 private key codec is not supported for #{algorithm_symbol.inspect}"
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
        match = text.match(/\A#{Regexp.escape(PEM_BEGIN)}\r?\n(?<body>[A-Za-z0-9+\/=\r\n]+)\r?\n#{Regexp.escape(PEM_END)}[ \t\r\n]*\z/)
        raise SerializationError, "Invalid PKCS#8 PEM: expected #{PEM_LABEL.inspect} label" unless match

        body = match[:body]
        raise SerializationError, "Invalid PKCS#8 PEM: embedded NUL in body" if body.include?("\0")

        decode_base64(body)
      end
    end
  end
end
