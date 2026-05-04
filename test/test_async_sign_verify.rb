# frozen_string_literal: true

require "async"
require_relative "test_helper"

class TestPQCryptoAsyncSignVerify < Minitest::Test
  MESSAGE = ("fiber-scheduler-signature\n" * 16_384).b.freeze

  TICK_SLEEP_SECONDS = 0.001
  MIN_WORK_SECONDS = 0.05

  def test_sign_does_not_block_sibling_async_task
    keypair = PQCrypto::Signature.generate(:ml_dsa_65)

    assert_async_progress_during_native_work("sign") do
      keypair.secret_key.sign(MESSAGE)
    end
  end

  def test_verify_does_not_block_sibling_async_task
    keypair = PQCrypto::Signature.generate(:ml_dsa_65)
    signature = keypair.secret_key.sign(MESSAGE)

    assert_async_progress_during_native_work("verify") do
      assert keypair.public_key.verify(MESSAGE, signature)
    end
  end

  private

  def assert_async_progress_during_native_work(label)
    tick_at = nil
    work_started_at = nil
    work_done_at = nil
    iterations = 0

    run_with_async_worker_pool do |task|
      ticker = task.async do
        sleep(TICK_SLEEP_SECONDS)
        tick_at = monotonic_time
      end

      sleep(0)

      worker = task.async do
        work_started_at = monotonic_time
        deadline = work_started_at + MIN_WORK_SECONDS

        begin
          yield
          iterations += 1
        end while monotonic_time < deadline

        work_done_at = monotonic_time
      end

      worker.wait
      ticker.wait

      assert_operator iterations, :>, 0
      assert_operator work_done_at - work_started_at, :>=, MIN_WORK_SECONDS

      assert tick_at, "expected sibling Async task to make progress during #{label}"
      assert_operator tick_at, :<, work_done_at,
        "expected sibling Async task to progress before #{label} finished"
    end
  end

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
