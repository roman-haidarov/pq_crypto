# frozen_string_literal: true

module PQCrypto
  module PKCS8
    module DER
      module_function

      def encode_tlv(tag, value)
        tag.chr.b + encode_length(value.bytesize) + value
      end

      def decode_tlv(der, offset, expected_tag:, label:)
        tag = der.getbyte(offset)
        raise SerializationError, "PKCS#8 #{label} is missing" if tag.nil?
        unless tag == expected_tag
          raise SerializationError, "PKCS#8 #{label} has unexpected tag: 0x#{tag.to_s(16).rjust(2, '0')}"
        end

        length, length_bytes = decode_length(der, offset + 1)
        value_offset = offset + 1 + length_bytes
        value_end = value_offset + length
        raise SerializationError, "PKCS#8 #{label} length exceeds available data" if value_end > der.bytesize

        [tag, der.byteslice(value_offset, length).b, value_end]
      end

      def encode_length(length)
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

      def decode_length(der, offset)
        first = der.getbyte(offset)
        raise SerializationError, "PKCS#8 DER length is missing" if first.nil?

        return [first, 1] if first < 0x80

        length_octets = long_length_octet_count(first)
        length = decode_long_length(der, offset, length_octets)

        [length, 1 + length_octets]
      end

      def long_length_octet_count(first)
        length_octets = first & 0x7f
        raise SerializationError, "PKCS#8 DER indefinite length is not allowed" if length_octets.zero?
        raise SerializationError, "PKCS#8 DER length is too large" if length_octets > 4

        length_octets
      end

      def decode_long_length(der, offset, length_octets)
        ensure_long_length_available!(der, offset, length_octets)
        length = length_octets.times.reduce(0) do |total, index|
          (total << 8) | der.getbyte(offset + 1 + index)
        end
        ensure_minimal_long_length!(der, offset, length, length_octets)
        length
      end

      def ensure_long_length_available!(der, offset, length_octets)
        return if offset + 1 + length_octets <= der.bytesize

        raise SerializationError, "PKCS#8 DER length exceeds available data"
      end

      def ensure_minimal_long_length!(der, offset, length, length_octets)
        return unless length < 0x80 || (length_octets > 1 && der.getbyte(offset + 1).zero?)

        raise SerializationError, "PKCS#8 DER length is not minimally encoded"
      end
    end
  end
end
