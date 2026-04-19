# frozen_string_literal: true

module PQCrypto
  class SignKeypair
    attr_reader :public_key, :secret_key

    def self.generate
      new(*PQCrypto.sign_keypair)
    end

    def initialize(public_key, secret_key)
      @public_key = String(public_key).b
      @secret_key = String(secret_key).b

      validate_lengths!
    end

    def sign(message)
      PQCrypto.sign(message, @secret_key)
    end

    def wipe!
      PQCrypto.secure_wipe(@secret_key)
      self
    end

    private

    def validate_lengths!
      raise ArgumentError, "Invalid public key length" unless @public_key.bytesize == SIGN_PUBLIC_KEY_BYTES
      raise ArgumentError, "Invalid secret key length" unless @secret_key.bytesize == SIGN_SECRET_KEY_BYTES
    end
  end
end
