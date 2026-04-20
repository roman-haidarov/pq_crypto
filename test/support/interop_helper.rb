# frozen_string_literal: true

require "json"
require "open3"
require "fileutils"
require "tmpdir"

module InteropHelper
  module_function

  def project_root
    @project_root ||= File.expand_path("../..", __dir__)
  end

  def tmp_dir
    @tmp_dir ||= File.join(project_root, "tmp", "interop")
  end

  def ensure_tmp_dir!
    FileUtils.mkdir_p(tmp_dir)
  end

  def openssl_helper_source
    File.join(project_root, "test", "interop", "openssl_pq_interop.c")
  end

  def go_helper_source
    File.join(project_root, "test", "interop", "go_mlkem_interop.go")
  end

  def pkg_config_flags
    candidates = [
      %w[openssl],
      %w[libssl libcrypto],
      ["openssl@3"],
      ["openssl3"],
    ]

    candidates.each do |packages|
      stdout, status = Open3.capture2("pkg-config", "--cflags", "--libs", *packages)
      return stdout.split if status.success?
    end

    nil
  end

  def openssl_helper
    return @openssl_helper if defined?(@openssl_helper)

    flags = pkg_config_flags
    unless flags
      @openssl_helper = { supported: false, reason: "pkg-config could not locate OpenSSL development flags" }
      return @openssl_helper
    end

    ensure_tmp_dir!
    binary = File.join(tmp_dir, "openssl_pq_interop")
    source = openssl_helper_source
    cmd = ["cc", "-std=c11", "-O2", "-Wall", "-Wextra", source, "-o", binary, *flags]
    stdout, status = Open3.capture2e(*cmd)
    unless status.success?
      @openssl_helper = { supported: false, reason: "failed to compile OpenSSL interop helper: #{stdout.strip}" }
      return @openssl_helper
    end

    probe_out, probe_status = Open3.capture2e(binary, "probe")
    unless probe_status.success?
      @openssl_helper = { supported: false, reason: "failed to probe OpenSSL helper: #{probe_out.strip}" }
      return @openssl_helper
    end

    probe = JSON.parse(probe_out)
    unless probe.fetch("mlkem") && probe.fetch("mldsa")
      @openssl_helper = {
        supported: false,
        reason: "OpenSSL does not expose ML-KEM-768 and ML-DSA-65 in this environment (#{probe.fetch('openssl_version')})",
      }
      return @openssl_helper
    end

    @openssl_helper = { supported: true, path: binary, probe: probe }
  end

  def openssl_supported?
    openssl_helper.fetch(:supported)
  end

  def openssl_skip_reason
    openssl_helper.fetch(:reason)
  end

  def run_openssl_helper(*args)
    helper = openssl_helper
    raise helper.fetch(:reason) unless helper.fetch(:supported)

    stdout, status = Open3.capture2e(helper.fetch(:path), *args)
    raise stdout.strip unless status.success?

    stdout.lines.map(&:strip).reject(&:empty?)
  end

  def go_available?
    return @go_available if defined?(@go_available)

    stdout, status = Open3.capture2e("go", "list", "crypto/mlkem")
    if status.success?
      @go_available = { supported: true }
    else
      @go_available = {
        supported: false,
        reason: "Go toolchain with crypto/mlkem is unavailable: #{stdout.strip}",
      }
    end
  end

  def go_supported?
    go_available?.fetch(:supported)
  end

  def go_skip_reason
    go_available?.fetch(:reason)
  end

  def run_go_helper(*args)
    availability = go_available?
    raise availability.fetch(:reason) unless availability.fetch(:supported)

    stdout, status = Open3.capture2e({ "GO111MODULE" => "off" }, "go", "run", go_helper_source, *args, chdir: project_root)
    raise stdout.strip unless status.success?

    stdout.lines.map(&:strip).reject(&:empty?)
  end

  def hex(bytes)
    String(bytes).unpack1("H*")
  end

  def bin(hex_string)
    [hex_string].pack("H*")
  end
end
