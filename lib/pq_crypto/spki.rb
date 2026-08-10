# frozen_string_literal: true

require "openssl"

module PQCrypto
  module SPKI
    PEM_LABEL = "PUBLIC KEY"
    PEM_BEGIN = "-----BEGIN #{PEM_LABEL}-----"
    PEM_END = "-----END #{PEM_LABEL}-----"

    class << self
      def encode_der(algorithm_symbol, public_key_bytes)
        entry = AlgorithmRegistry.fetch(algorithm_symbol)
        validate_public_key_algorithm!(algorithm_symbol, entry)

        bytes = String(public_key_bytes).b
        expected = entry.fetch(:public_key_bytes)
        unless bytes.bytesize == expected
          raise SerializationError,
                "Invalid #{algorithm_symbol.inspect} public key length: expected #{expected}, got #{bytes.bytesize}"
        end

        OpenSSL::ASN1::Sequence.new([
          OpenSSL::ASN1::Sequence.new([
            OpenSSL::ASN1::ObjectId.new(AlgorithmRegistry.standard_oid(algorithm_symbol)),
          ]),
          OpenSSL::ASN1::BitString.new(bytes),
        ]).to_der.b
      rescue OpenSSL::OpenSSLError, TypeError => e
        raise SerializationError, e.message
      end

      def encode_pem(algorithm_symbol, public_key_bytes)
        der = encode_der(algorithm_symbol, public_key_bytes)
        body = encode_base64(der).scan(/.{1,64}/).join("\n")
        "#{PEM_BEGIN}\n#{body}\n#{PEM_END}\n"
      end

      def decode_der(der)
        input = String(der).b
        outer = decode_asn1(input)
        raise SerializationError, "SPKI DER contains trailing data" unless outer.to_der.b == input
        raise SerializationError, "SPKI must be an ASN.1 SEQUENCE" unless outer.is_a?(OpenSSL::ASN1::Sequence)
        raise SerializationError, "SPKI SEQUENCE must contain exactly 2 elements" unless outer.value.size == 2

        algorithm_identifier, subject_public_key = outer.value
        algorithm = decode_algorithm_identifier(algorithm_identifier)
        entry = AlgorithmRegistry.fetch(algorithm)
        validate_public_key_algorithm!(algorithm, entry)

        unless subject_public_key.is_a?(OpenSSL::ASN1::BitString)
          raise SerializationError, "SPKI subjectPublicKey must be a BIT STRING"
        end
        unless subject_public_key.unused_bits.zero?
          raise SerializationError, "SPKI subjectPublicKey must have zero unused bits"
        end

        bytes = String(subject_public_key.value).b
        expected = entry.fetch(:public_key_bytes)
        unless bytes.bytesize == expected
          raise SerializationError,
                "Invalid #{algorithm.inspect} SPKI public key length: expected #{expected}, got #{bytes.bytesize}"
        end

        [algorithm, bytes]
      rescue OpenSSL::OpenSSLError, TypeError => e
        raise SerializationError, e.message
      end

      def decode_pem(pem)
        der = der_from_pem(pem)
        decode_der(der)
      end

      private

      def decode_asn1(der)
        OpenSSL::ASN1.decode(der)
      rescue OpenSSL::OpenSSLError, TypeError => e
        raise SerializationError, e.message
      end

      def decode_algorithm_identifier(value)
        unless value.is_a?(OpenSSL::ASN1::Sequence)
          raise SerializationError, "SPKI algorithm must be an AlgorithmIdentifier SEQUENCE"
        end
        unless value.value.size == 1
          raise SerializationError, "SPKI AlgorithmIdentifier parameters must be absent"
        end

        oid = value.value.first
        raise SerializationError, "SPKI AlgorithmIdentifier must contain an OBJECT IDENTIFIER" unless oid.is_a?(OpenSSL::ASN1::ObjectId)

        algorithm = AlgorithmRegistry.by_standard_oid(oid.oid)
        raise SerializationError, "Unsupported SPKI algorithm OID: #{oid.oid}" if algorithm.nil?

        algorithm
      end

      def validate_public_key_algorithm!(algorithm_symbol, entry)
        return if %i[ml_kem ml_dsa].include?(entry.fetch(:family))

        raise SerializationError, "SPKI public key codec is not supported for #{algorithm_symbol.inspect}"
      end

      def encode_base64(bytes)
        [String(bytes).b].pack("m0")
      end

      def decode_base64(body)
        compact = body.gsub(/[\r\n]/, "")
        unless compact.match?(/\A(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?\z/)
          raise SerializationError, "Invalid SPKI PEM: invalid base64"
        end

        compact.unpack1("m0").b
      rescue ArgumentError => e
        raise SerializationError, e.message
      end

      def der_from_pem(pem)
        text = String(pem)
        match = text.match(/\A#{Regexp.escape(PEM_BEGIN)}\r?\n(?<body>[A-Za-z0-9+\/=\r\n]+)\r?\n#{Regexp.escape(PEM_END)}[ \t\r\n]*\z/)
        raise SerializationError, "Invalid SPKI PEM: expected #{PEM_LABEL.inspect} label" unless match

        body = match[:body]
        raise SerializationError, "Invalid SPKI PEM: embedded NUL in body" if body.include?("\0")

        decode_base64(body)
      end
    end
  end
end
