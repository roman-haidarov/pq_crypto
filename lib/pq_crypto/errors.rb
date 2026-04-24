# frozen_string_literal: true

module PQCrypto
  unless const_defined?(:Error)
    class Error < StandardError; end
  end

  class UnsupportedAlgorithmError < Error; end
  class InvalidKeyError < Error; end
  class InvalidCiphertextError < Error; end
  class SerializationError < Error; end

  unless const_defined?(:VerificationError)
    class VerificationError < Error; end
  end
end
