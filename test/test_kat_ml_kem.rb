# frozen_string_literal: true

require "json"
require_relative "test_helper"

class TestKATMLKEM < Minitest::Test
  FIXTURE_DIR = File.expand_path("fixtures/kat", __dir__)

  KEYGEN_FIXTURES = {
    ml_kem_512: "ml_kem_512_keygen.json",
    ml_kem_768: "ml_kem_768_keygen.json",
    ml_kem_1024: "ml_kem_1024_keygen.json",
  }.freeze

  ENCAPDECAP_FIXTURES = {
    ml_kem_512: "ml_kem_512_encapdecap.json",
    ml_kem_768: "ml_kem_768_encapdecap.json",
    ml_kem_1024: "ml_kem_1024_encapdecap.json",
  }.freeze

  def test_keygen_kats
    KEYGEN_FIXTURES.each do |algorithm, filename|
      each_vector(filename) do |vector|
        seed = hex(vector.fetch("seed"))
        public_key, secret_key = PQCrypto::Testing.ml_kem_keypair_from_seed(seed, algorithm: algorithm)

        assert_equal hex(vector.fetch("publicKey")), public_key, "#{filename} tcId=#{vector['tcId']} public key"
        assert_equal hex(vector.fetch("secretKey")), secret_key, "#{filename} tcId=#{vector['tcId']} secret key"
      end
    end
  end

  def test_encapdecap_kats
    ENCAPDECAP_FIXTURES.each do |algorithm, filename|
      each_vector(filename) do |vector|
        public_key = hex(vector.fetch("publicKey"))
        secret_key = hex(vector.fetch("secretKey"))
        seed = hex(vector.fetch("encapSeed"))

        ciphertext, shared_secret = PQCrypto::Testing.ml_kem_encapsulate_from_seed(public_key, seed, algorithm: algorithm)
        assert_equal hex(vector.fetch("ciphertext")), ciphertext, "#{filename} tcId=#{vector['tcId']} ciphertext"
        assert_equal hex(vector.fetch("sharedSecret")), shared_secret, "#{filename} tcId=#{vector['tcId']} shared secret"

        decapsulated = PQCrypto::KEM.secret_key_from_bytes(algorithm, secret_key).decapsulate(ciphertext)
        assert_equal shared_secret, decapsulated, "#{filename} tcId=#{vector['tcId']} decapsulation"
      end
    end
  end

  private

  def each_vector(filename)
    path = File.join(FIXTURE_DIR, filename)
    data = JSON.parse(File.read(path))
    vectors = data.fetch("vectors")
    refute_empty vectors, "#{filename} must contain trimmed NIST ACVP vectors"
    vectors.each { |vector| yield vector }
  end

  def hex(value)
    [value].pack("H*").b
  end
end
