# frozen_string_literal: true

require "json"
require_relative "test_helper"

class TestKATMLDSA < Minitest::Test
  FIXTURE_DIR = File.expand_path("fixtures/kat", __dir__)

  KEYGEN_FIXTURES = {
    ml_dsa_44: "ml_dsa_44_keygen.json",
    ml_dsa_65: "ml_dsa_65_keygen.json",
    ml_dsa_87: "ml_dsa_87_keygen.json",
  }.freeze

  SIGGEN_FIXTURES = {
    ml_dsa_44: "ml_dsa_44_siggen.json",
    ml_dsa_65: "ml_dsa_65_siggen.json",
    ml_dsa_87: "ml_dsa_87_siggen.json",
  }.freeze

  SIGVER_FIXTURES = {
    ml_dsa_44: "ml_dsa_44_sigver.json",
    ml_dsa_65: "ml_dsa_65_sigver.json",
    ml_dsa_87: "ml_dsa_87_sigver.json",
  }.freeze

  def test_keygen_kats
    KEYGEN_FIXTURES.each do |algorithm, filename|
      each_vector(filename) do |vector|
        public_key, secret_key = PQCrypto::Testing.ml_dsa_keypair_from_seed(hex(vector.fetch("seed")), algorithm: algorithm)
        assert_equal hex(vector.fetch("publicKey")), public_key, "#{filename} tcId=#{vector['tcId']} public key"
        assert_equal hex(vector.fetch("secretKey")), secret_key, "#{filename} tcId=#{vector['tcId']} secret key"
      end
    end
  end

  def test_siggen_kats
    SIGGEN_FIXTURES.each do |algorithm, filename|
      each_vector(filename) do |vector|
        message = hex(vector.fetch("message"))
        secret_key = hex(vector.fetch("secretKey"))
        sign_seed = hex(vector.fetch("signSeed"))
        signature = PQCrypto::Testing.ml_dsa_sign_from_seed(message, secret_key, sign_seed, algorithm: algorithm)
        assert_equal hex(vector.fetch("signature")), signature, "#{filename} tcId=#{vector['tcId']} signature"
      end
    end
  end

  def test_sigver_kats
    SIGVER_FIXTURES.each do |algorithm, filename|
      each_vector(filename) do |vector|
        public_key = PQCrypto::Signature.public_key_from_bytes(algorithm, hex(vector.fetch("publicKey")))
        verified = public_key.verify(hex(vector.fetch("message")), hex(vector.fetch("signature")))
        assert_equal vector.fetch("testPassed"), verified, "#{filename} tcId=#{vector['tcId']} verification"
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
