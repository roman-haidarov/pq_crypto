# frozen_string_literal: true

module PQCrypto
  class SignKeypair
    attr_reader :public_key, :secret_key

    def self.generate
      new(*PQCrypto.sign_keypair)
    end

    def initialize(public_key, secret_key)
      @typed = Signature::Keypair.new(
        Signature.public_key_from_bytes(:ml_dsa_65, public_key),
        Signature.secret_key_from_bytes(:ml_dsa_65, secret_key)
      )
      @public_key = @typed.public_key.to_bytes
      @secret_key = @typed.secret_key.to_bytes
    end

    def algorithm
      @typed.algorithm
    end

    def public_key_object
      @typed.public_key
    end

    def secret_key_object
      @typed.secret_key
    end

    def sign(message)
      @typed.secret_key.sign(message)
    end

    def verify(message, signature)
      @typed.public_key.verify(message, signature)
    end

    def wipe!
      @typed.secret_key.wipe!
      @secret_key = @typed.secret_key.to_bytes
      self
    end
  end
end
