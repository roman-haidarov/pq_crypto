# frozen_string_literal: true

require "async"
require_relative "test_helper"

class TestPQCryptoAsyncSignVerify < Minitest::Test
  MESSAGE = ("fiber-scheduler-signature\n" * 16_384).b.freeze
  ITERATIONS = 24
  SLEEP_SECONDS = 0.02

  def test_sign_does_not_block_sibling_async_task
    keypair = PQCrypto::Signature.generate(:ml_dsa_65)

    tick_at = nil
    sign_done_at = nil

    run_with_async_worker_pool do |task|
      ticker = task.async do
        sleep(SLEEP_SECONDS)
        tick_at = monotonic_time
      end

      signer = task.async do
        ITERATIONS.times { keypair.secret_key.sign(MESSAGE) }
        sign_done_at = monotonic_time
      end

      signer.wait

      assert tick_at, "expected sibling Async task to make progress before sign finished"
      assert_operator tick_at, :<, sign_done_at

      ticker.wait
    end
  end

  def test_verify_does_not_block_sibling_async_task
    keypair = PQCrypto::Signature.generate(:ml_dsa_65)
    signature = keypair.secret_key.sign(MESSAGE)

    tick_at = nil
    verify_done_at = nil

    run_with_async_worker_pool do |task|
      ticker = task.async do
        sleep(SLEEP_SECONDS)
        tick_at = monotonic_time
      end

      verifier = task.async do
        ITERATIONS.times do
          assert keypair.public_key.verify(MESSAGE, signature)
        end
        verify_done_at = monotonic_time
      end

      verifier.wait

      assert tick_at, "expected sibling Async task to make progress before verify finished"
      assert_operator tick_at, :<, verify_done_at

      ticker.wait
    end
  end

  private

  def monotonic_time
    Process.clock_gettime(Process::CLOCK_MONOTONIC)
  end

  def run_with_async_worker_pool
    reactor = Async::Reactor.new(worker_pool: true)
    skip "Async worker pool is not available on this platform" unless reactor.respond_to?(:blocking_operation_wait)

    root_task = reactor.async do |task|
      yield task
    end

    reactor.run
    root_task.wait
  ensure
    reactor&.close unless reactor.nil? || reactor.closed?
  end
end
