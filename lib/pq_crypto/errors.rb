# frozen_string_literal: true

module PQCrypto
  class Error < StandardError; end unless const_defined?(:Error)
  class UnsupportedAlgorithmError < Error; end unless const_defined?(:UnsupportedAlgorithmError)
  class InvalidKeyError < Error; end unless const_defined?(:InvalidKeyError)
  class InvalidCiphertextError < Error; end unless const_defined?(:InvalidCiphertextError)
  class SerializationError < Error; end unless const_defined?(:SerializationError)
  class VerificationError < Error; end unless const_defined?(:VerificationError)
  class DecryptionError < Error; end unless const_defined?(:DecryptionError)
end
