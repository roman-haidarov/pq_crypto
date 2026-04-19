# frozen_string_literal: true

module PQCrypto
  class Identity
    attr_reader :kem_keypair, :sign_keypair

    def self.generate
      new(KEMKeypair.generate, SignKeypair.generate)
    end

    def initialize(kem_keypair, sign_keypair)
      @kem_keypair = kem_keypair
      @sign_keypair = sign_keypair
    end

    def public_keys
      {
        kem: @kem_keypair.public_key,
        sign: @sign_keypair.public_key,
      }
    end

    def initiate_authenticated_session(remote_kem_public_key)
      session, ciphertext = PQCrypto::Experimental.establish_session(remote_kem_public_key)
      signature = @sign_keypair.sign(ciphertext)
      [session, ciphertext, signature]
    end

    def accept_authenticated_session(ciphertext, signature, remote_sign_public_key)
      verifier = Signature.public_key_from_bytes(:ml_dsa_65, remote_sign_public_key)
      verifier.verify!(ciphertext, signature)
      PQCrypto::Experimental.accept_session(ciphertext, @kem_keypair.secret_key)
    end

    def wipe!
      @kem_keypair.wipe!
      @sign_keypair.wipe!
      self
    end
  end
end
