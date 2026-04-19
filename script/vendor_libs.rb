#!/usr/bin/env ruby
# frozen_string_literal: true

require "digest"
require "fileutils"
require "open-uri"
require "rubygems/package"
require "tmpdir"
require "zlib"

VENDOR_DIR = File.expand_path("../ext/pqcrypto/vendor", __dir__)

PQCLEAN = {
  version: ENV.fetch("PQCLEAN_VERSION", "master"),
  url: ENV.fetch("PQCLEAN_URL", "https://github.com/PQClean/PQClean/archive/refs/heads/master.tar.gz"),
  sha256: ENV["PQCLEAN_SHA256"],
  strip: ENV.fetch("PQCLEAN_STRIP", "PQClean-master"),
  keep: %w[
    crypto_kem/ml-kem-768/clean
    crypto_sign/ml-dsa-65/clean
    common
  ]
}.freeze

def download(url, destination)
  puts "Downloading #{url}"
  URI.open(url) { |remote| File.binwrite(destination, remote.read) }
end


def verify_checksum!(archive, expected_sha256)
  actual = Digest::SHA256.file(archive).hexdigest

  return puts("SHA256: #{actual} (set PQCLEAN_SHA256 to pin it)") unless expected_sha256

  abort "SHA256 mismatch: expected #{expected_sha256}, got #{actual}" unless actual == expected_sha256
end


def extract_subset(archive, destination, strip_prefix:, keep_dirs:)
  prefix_re = /\A#{Regexp.escape(strip_prefix)}\//

  Gem::Package::TarReader.new(Zlib::GzipReader.open(archive)) do |tar|
    tar.each do |entry|
      relative_path = entry.full_name.sub(prefix_re, "")
      next if relative_path.empty? || relative_path == entry.full_name
      next unless keep_dirs.any? { |dir| relative_path.start_with?(dir) }

      target = File.join(destination, relative_path)

      if entry.directory?
        FileUtils.mkdir_p(target)
      elsif entry.file?
        FileUtils.mkdir_p(File.dirname(target))
        File.binwrite(target, entry.read)
      end
    end
  end
end


def write_manifest!
  File.write(File.join(VENDOR_DIR, ".vendored"), "pqclean=#{PQCLEAN[:version]}\n")
end

puts "Vendoring PQClean into #{VENDOR_DIR}"
FileUtils.rm_rf(VENDOR_DIR)
FileUtils.mkdir_p(VENDOR_DIR)

Dir.mktmpdir("pq_crypto-vendor") do |tmpdir|
  archive = File.join(tmpdir, "pqclean.tar.gz")
  destination = File.join(VENDOR_DIR, "pqclean")

  download(PQCLEAN[:url], archive)
  verify_checksum!(archive, PQCLEAN[:sha256])
  extract_subset(archive, destination, strip_prefix: PQCLEAN[:strip], keep_dirs: PQCLEAN[:keep])
  write_manifest!
end

puts "Done. PQClean sources are now available in ext/pqcrypto/vendor/."
puts "Next step: bundle exec rake compile"
