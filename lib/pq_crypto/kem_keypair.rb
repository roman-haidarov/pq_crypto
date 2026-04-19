# frozen_string_literal: true

module PQCrypto
  class KEMKeypair
    attr_reader :public_key, :secret_key

    def self.generate
      new(*PQCrypto.kem_keypair)
    end

    def self.from_keys(public_key, secret_key)
      new(public_key, secret_key)
    end

    def initialize(public_key, secret_key)
      @typed = KEM::Keypair.new(
        KEM.public_key_from_bytes(:ml_kem_768, public_key),
        KEM.secret_key_from_bytes(:ml_kem_768, secret_key)
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

    def public_key_pem
      PQCrypto.public_key_pem(@public_key)
    end

    def wipe!
      @typed.secret_key.wipe!
      @secret_key = @typed.secret_key.to_bytes
      self
    end
  end
end
