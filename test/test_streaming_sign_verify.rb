# frozen_string_literal: true

require_relative "test_helper"
require "stringio"

class TestStreamingSignVerify < Minitest::Test
  CHUNK_SIZES = [1, 7, 136, 1024, 1 << 20].freeze
  MESSAGE_SIZES = [0, 1, 135, 136, 137, 1024, 1 << 20].freeze

  def setup
    @keypair = PQCrypto::Signature.generate
    @sk = @keypair.secret_key
    @pk = @keypair.public_key
  end

  def test_sign_io_then_one_shot_verify
    MESSAGE_SIZES.each do |msize|
      message = build_message(msize)
      CHUNK_SIZES.each do |csize|
        io = StringIO.new(message)
        sig = @sk.sign_io(io, chunk_size: csize)
        assert_equal PQCrypto::SIGN_BYTES, sig.bytesize,
                     "wrong sig length for msize=#{msize} csize=#{csize}"
        assert @pk.verify(message, sig),
               "stream-sign + one-shot-verify failed for msize=#{msize} csize=#{csize}"
      end
    end
  end

  def test_one_shot_sign_then_verify_io
    MESSAGE_SIZES.each do |msize|
      message = build_message(msize)
      sig = @sk.sign(message)
      CHUNK_SIZES.each do |csize|
        io = StringIO.new(message)
        assert @pk.verify_io(io, sig, chunk_size: csize),
               "one-shot-sign + stream-verify failed for msize=#{msize} csize=#{csize}"
      end
    end
  end

  def test_sign_io_then_verify_io
    MESSAGE_SIZES.each do |msize|
      message = build_message(msize)
      CHUNK_SIZES.each do |sign_csize|
        sig = @sk.sign_io(StringIO.new(message), chunk_size: sign_csize)
        CHUNK_SIZES.each do |verify_csize|
          ok = @pk.verify_io(StringIO.new(message), sig, chunk_size: verify_csize)
          assert ok, "stream-stream failed msize=#{msize} sign_csize=#{sign_csize} verify_csize=#{verify_csize}"
        end
      end
    end
  end

  def test_chunk_boundary_independence
    message = build_message(2_000)
    CHUNK_SIZES.each do |csize|
      sig = @sk.sign_io(StringIO.new(message), chunk_size: csize)
      assert @pk.verify(message, sig), "sig from csize=#{csize} did not verify"
      assert @pk.verify_io(StringIO.new(message), sig, chunk_size: 7),
             "sig from csize=#{csize} did not stream-verify"
    end
  end

  def test_binary_message_with_nuls
    message = (0..255).map(&:chr).join.b * 4
    sig = @sk.sign_io(StringIO.new(message))
    assert @pk.verify(message, sig)
    assert @pk.verify_io(StringIO.new(message), sig)
  end

  def test_message_starting_with_nuls
    message = ("\x00".b * 200) + "tail".b
    sig = @sk.sign_io(StringIO.new(message))
    assert @pk.verify_io(StringIO.new(message), sig)
  end

  def test_verify_io_rejects_modified_message
    message = build_message(500)
    sig = @sk.sign(message)
    tampered = message.dup
    tampered.setbyte(0, tampered.getbyte(0) ^ 0x01)
    refute @pk.verify_io(StringIO.new(tampered), sig)
  end

  def test_verify_io_rejects_modified_signature
    message = build_message(500)
    sig = @sk.sign(message).dup
    sig.setbyte(0, sig.getbyte(0) ^ 0x01)
    refute @pk.verify_io(StringIO.new(message), sig)
  end

  def test_verify_io_rejects_truncated_signature
    message = build_message(500)
    sig = @sk.sign(message)
    truncated = sig[0...-1]
    refute @pk.verify_io(StringIO.new(message), truncated)
  end

  def test_verify_io_rejects_signature_from_different_message
    sig = @sk.sign("original message".b)
    refute @pk.verify_io(StringIO.new("different message".b), sig)
  end

  def test_empty_message_round_trip
    sig_oneshot = @sk.sign("".b)
    sig_stream = @sk.sign_io(StringIO.new("".b))

    assert @pk.verify("".b, sig_oneshot)
    assert @pk.verify("".b, sig_stream)
    assert @pk.verify_io(StringIO.new("".b), sig_oneshot)
    assert @pk.verify_io(StringIO.new("".b), sig_stream)
  end

  def test_sign_io_propagates_io_errors_without_leaking
    raising_io = Object.new
    def raising_io.read(_n, _buf = nil)
      raise IOError, "simulated read failure"
    end

    assert_raises(IOError) do
      @sk.sign_io(raising_io)
    end

    msg = "post-error message".b
    sig = @sk.sign_io(StringIO.new(msg))
    assert @pk.verify(msg, sig)
  end

  def test_verify_io_propagates_io_errors
    raising_io = Object.new
    def raising_io.read(_n, _buf = nil)
      raise IOError, "simulated read failure"
    end

    assert_raises(IOError) do
      @pk.verify_io(raising_io, "x" * PQCrypto::SIGN_BYTES)
    end
  end

  def test_sign_io_rejects_non_io
    assert_raises(ArgumentError) do
      @sk.sign_io("not an io")
    end
  end

  def test_sign_io_rejects_invalid_chunk_size
    [0, -1, "1024", nil, 1.5].each do |bad|
      assert_raises(ArgumentError) { @sk.sign_io(StringIO.new("x"), chunk_size: bad) }
    end
  end

  def test_sign_io_rejects_oversized_context
    assert_raises(ArgumentError) do
      @sk.sign_io(StringIO.new("x"), context: "C" * 256)
    end
  end

  def test_verify_io_rejects_oversized_context
    sig = @sk.sign("hello".b)
    assert_raises(ArgumentError) do
      @pk.verify_io(StringIO.new("hello".b), sig, context: "C" * 256)
    end
  end

  def test_verify_io_bang_succeeds_for_valid_signature
    message = build_message(100)
    sig = @sk.sign(message)
    assert_equal true, @pk.verify_io!(StringIO.new(message), sig)
  end

  def test_verify_io_bang_raises_for_invalid_signature
    message = build_message(100)
    sig = @sk.sign(message).dup
    sig.setbyte(0, sig.getbyte(0) ^ 0xff)
    assert_raises(PQCrypto::VerificationError) do
      @pk.verify_io!(StringIO.new(message), sig)
    end
  end

  def test_context_tied_to_signature
    message = "ctx-bound message".b
    ctx_a = "context-A".b
    ctx_b = "context-B".b

    sig = @sk.sign_io(StringIO.new(message), context: ctx_a)
    assert @pk.verify_io(StringIO.new(message), sig, context: ctx_a)
    refute @pk.verify_io(StringIO.new(message), sig, context: ctx_b)
    refute @pk.verify_io(StringIO.new(message), sig)
    refute @pk.verify(message, sig)
  end

  private

  def build_message(size)
    return "".b if size.zero?
    bytes = String.new(capacity: size).b
    size.times { |i| bytes << ((i * 31 + 7) & 0xff).chr }
    bytes
  end
end
