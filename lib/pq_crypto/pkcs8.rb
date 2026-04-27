# frozen_string_literal: true

require "openssl"

module PQCrypto
  module PKCS8
    PEM_LABEL = "PRIVATE KEY"
    PEM_BEGIN = "-----BEGIN #{PEM_LABEL}-----"
    PEM_END = "-----END #{PEM_LABEL}-----"
    PATCH_2C_MESSAGE = "PKCS#8 seed/both formats land in Patch 2c"

    class << self
      def encode_der(algorithm_symbol, secret_material, format:)
        unless format == :expanded
          raise SerializationError, "PKCS#8 #{format.inspect} format requires Patch 2c"
        end

        entry = AlgorithmRegistry.fetch(algorithm_symbol)
        validate_secret_key_algorithm!(algorithm_symbol, entry)

        bytes = String(secret_material).b
        expected = entry.fetch(:secret_key_bytes)
        unless bytes.bytesize == expected
          raise SerializationError,
                "Invalid #{algorithm_symbol.inspect} expanded private key length: expected #{expected}, got #{bytes.bytesize}"
        end

        expanded_choice = OpenSSL::ASN1::OctetString.new(bytes).to_der.b

        OpenSSL::ASN1::Sequence.new([
          OpenSSL::ASN1::Integer.new(0),
          OpenSSL::ASN1::Sequence.new([
            OpenSSL::ASN1::ObjectId.new(AlgorithmRegistry.standard_oid(algorithm_symbol)),
          ]),
          OpenSSL::ASN1::OctetString.new(expanded_choice),
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
          raise SerializationError, PATCH_2C_MESSAGE
        when 0x04
          decode_expanded_key(algorithm, entry, choice_der)
        when 0x30
          raise SerializationError, PATCH_2C_MESSAGE
        else
          raise SerializationError, "Unsupported PKCS#8 ML-KEM private key CHOICE tag: 0x#{tag.to_s(16).rjust(2, '0')}"
        end
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
        expected = entry.fetch(:secret_key_bytes)
        unless bytes.bytesize == expected
          raise SerializationError,
                "Invalid #{algorithm.inspect} expanded private key length: expected #{expected}, got #{bytes.bytesize}"
        end

        [algorithm, :expanded, bytes]
      end

      def validate_secret_key_algorithm!(algorithm_symbol, entry)
        return if entry.fetch(:family) == :ml_kem

        raise SerializationError, "PKCS#8 private key codec is not supported for #{algorithm_symbol.inspect}"
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
