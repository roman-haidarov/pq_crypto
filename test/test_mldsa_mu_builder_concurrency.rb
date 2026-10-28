# frozen_string_literal: true

require_relative "test_helper"

class TestMLDSAMuBuilderConcurrency < Minitest::Test
  def test_release_fails_fast_while_update_is_running_without_gvl
    builder = PQCrypto.__send__(:_native_mldsa_mu_builder_new, "\0" * 64, "")
    chunk = "x" * (16 * 1024 * 1024)
    update = Thread.new do
      PQCrypto.__send__(:_native_mldsa_mu_builder_update, builder, chunk)
    end

    wait_for_native_update(update)
    error = assert_raises(PQCrypto::Error) do
      PQCrypto.__send__(:_native_mldsa_mu_builder_release, builder)
    end
    assert_equal "mu builder is busy", error.message
  ensure
    update&.join
    if builder
      PQCrypto.__send__(:_native_mldsa_mu_builder_release, builder)
      PQCrypto.__send__(:_native_mldsa_mu_builder_release, builder)
    end
  end

  private

  def wait_for_native_update(thread)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 5
    Thread.pass while thread.status != "sleep" && thread.alive? &&
                      Process.clock_gettime(Process::CLOCK_MONOTONIC) < deadline
    assert_equal "sleep", thread.status, "native update did not yield without the GVL"
  end
end
