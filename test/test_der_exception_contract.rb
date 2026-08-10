# frozen_string_literal: true

require_relative "test_helper"

class TestDERExceptionContract < Minitest::Test
  LEAK_SAMPLES = {
    "0a01ff" => "ENUMERATED: OpenSSL::OpenSSLError (wrong integer type)",
    "1700" => "UTCTIME with empty value: TypeError",
    "1800" => "GENERALIZEDTIME with empty value: TypeError",
    "1000" => "universal SEQUENCE tag without constructed bit: TypeError on the to_der round trip"
  }.freeze

  def each_entry_point
    yield("PQCrypto::Key.from_der", ->(der) { PQCrypto::Key.from_der(der) })
    yield("PQCrypto::SPKI.decode_der", ->(der) { PQCrypto::SPKI.decode_der(der) })
    yield("PQCrypto::PKCS8.decode_der", ->(der) { PQCrypto::PKCS8.decode_der(der) })
  end

  def test_known_leak_samples_raise_pq_crypto_error
    LEAK_SAMPLES.each do |hex, description|
      der = [hex].pack("H*")

      each_entry_point do |name, call|
        error = nil
        begin
          call.call(der)
        rescue StandardError => e
          error = e
        end

        refute_nil error, "#{name} accepted #{hex} (#{description})"
        assert_kind_of PQCrypto::Error, error,
                       "#{name} leaked #{error.class} for #{hex} (#{description}): #{error.message}"
      end
    end
  end

  def test_systematic_tag_sweep_raises_only_pq_crypto_error
    inputs = []
    (0..255).each do |tag|
      inputs << [tag, 0]
      inputs << [tag, 1, 0x00]
      inputs << [tag, 1, 0xff]
      inputs << [tag, 2, 0x00, 0x00]
      inputs << [tag, 0x81, 1, 0x41]
    end

    leaked = []
    inputs.each do |bytes|
      der = bytes.pack("C*")

      each_entry_point do |name, call|
        call.call(der)
      rescue PQCrypto::Error
        next
      rescue StandardError => e
        leaked << "#{name}: der=#{der.unpack1('H*')} -> #{e.class}: #{e.message}"
      end
    end

    assert_empty leaked, "parsers leaked non-PQCrypto exceptions:\n#{leaked.first(10).join("\n")}"
  end

  def test_valid_der_still_decodes
    keypair = PQCrypto::KEM.generate(:ml_kem_768)

    algorithm, bytes = PQCrypto::SPKI.decode_der(keypair.public_key.to_spki_der)
    assert_equal :ml_kem_768, algorithm
    assert_equal keypair.public_key.to_bytes, bytes

    assert_kind_of PQCrypto::KEM::PublicKey,
                   PQCrypto::Key.from_der(keypair.public_key.to_spki_der)
  end
end
