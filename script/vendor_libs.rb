#!/usr/bin/env ruby
# frozen_string_literal: true

require "digest"
require "fileutils"
require "open-uri"
require "rubygems/package"
require "tmpdir"
require "zlib"

VENDOR_DIR = File.expand_path("../ext/pqcrypto/vendor", __dir__)
MANIFEST_PATH = File.join(VENDOR_DIR, ".vendored")

DEFAULT_PQCLEAN = {
  version: "2cc64716044832eea747234ddbffc06746ab815d",
  url: "https://github.com/PQClean/PQClean/archive/2cc64716044832eea747234ddbffc06746ab815d.tar.gz",
  strip: "PQClean-2cc64716044832eea747234ddbffc06746ab815d",
  sha256: "0e92076a79082a8d220e27227f37b280fb2ce050af412babd2bc755ab37b871a"
}.freeze

KEEP_DIRS = %w[
  crypto_kem/ml-kem-768/clean
  crypto_sign/ml-dsa-65/clean
  common
].freeze

WARNING = <<~TEXT.freeze
  WARNING: this script is a manual vendor refresh tool.

  pq_crypto relies on the vendored PQClean snapshot committed to the repository.
  Running this script will replace ext/pqcrypto/vendor with a fresh upstream copy.
  Use the pinned defaults unless you are intentionally updating the upstream snapshot.
TEXT

def load_manifest(path)
  return {} unless File.exist?(path)

  File.readlines(path, chomp: true).each_with_object({}) do |line, acc|
    next if line.strip.empty? || line.lstrip.start_with?("#")
    key, value = line.split("=", 2)
    next if key.nil? || value.nil?

    acc[key] = value
  end
end

def manifest_value(manifest, key)
  value = manifest[key]
  return nil if value.nil? || value.strip.empty? || value == "unrecorded"

  value
end

def commit_archive_url?(url)
  url.match?(%r{\Ahttps://(?:github\.com|codeload\.github\.com)/PQClean/PQClean/(?:archive|tar\.gz)/[0-9a-f]{40}(?:\.tar\.gz)?\z}i) ||
    url.match?(%r{\Ahttps://github\.com/PQClean/PQClean/archive/[0-9a-f]{40}\.tar\.gz\z}i)
end

def build_vendor_config
  manifest = load_manifest(MANIFEST_PATH)

  version = ENV["PQCLEAN_VERSION"] || manifest_value(manifest, "pqclean_version") || DEFAULT_PQCLEAN[:version]
  url = ENV["PQCLEAN_URL"] || manifest_value(manifest, "pqclean_url") || DEFAULT_PQCLEAN[:url]
  sha256 = ENV["PQCLEAN_SHA256"] || manifest_value(manifest, "pqclean_archive_sha256") || DEFAULT_PQCLEAN[:sha256]
  strip = ENV["PQCLEAN_STRIP"] || manifest_value(manifest, "pqclean_strip") || DEFAULT_PQCLEAN[:strip]

  {
    version: version,
    url: url,
    sha256: sha256,
    strip: strip,
    keep: KEEP_DIRS
  }.freeze
end

def validate_vendor_config!(config)
  required = %i[version url strip]
  missing = required.select { |key| config[key].to_s.strip.empty? }
  return if missing.empty?

  abort <<~MSG
    Missing required vendoring configuration: #{missing.join(", ")}

    Example:
      PQCLEAN_VERSION=<full-git-commit> \
      PQCLEAN_URL=https://github.com/PQClean/PQClean/archive/<full-git-commit>.tar.gz \
      PQCLEAN_STRIP=PQClean-<full-git-commit> \
      PQCLEAN_SHA256=<archive-sha256> \
      bundle exec ruby script/vendor_libs.rb
  MSG
end

def validate_pinning!(config)
  if config[:sha256].to_s.strip.empty?
    abort <<~MSG
      Refusing to vendor without PQCLEAN_SHA256.

      Use the built-in pinned defaults, or provide all of:
        PQCLEAN_VERSION
        PQCLEAN_URL
        PQCLEAN_STRIP
        PQCLEAN_SHA256
    MSG
  end

  return if commit_archive_url?(config[:url])

  abort <<~MSG
    Refusing to vendor from a non-commit archive URL.

    Use a content-addressed full commit archive URL from the PQClean repository.
  MSG
end

def download(url, destination)
  puts "Downloading #{url}"
  URI.open(url) { |remote| File.binwrite(destination, remote.read) }
end

def verify_checksum!(archive, expected_sha256)
  actual = Digest::SHA256.file(archive).hexdigest
  abort "SHA256 mismatch: expected #{expected_sha256}, got #{actual}" unless actual == expected_sha256
  actual
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

def write_manifest!(config:, archive_sha256:, tree_sha256:)
  File.write(
    MANIFEST_PATH,
    <<~TEXT
      pqclean_version=#{config[:version]}
      pqclean_url=#{config[:url]}
      pqclean_archive_sha256=#{archive_sha256}
      pqclean_strip=#{config[:strip]}
      pqclean_tree_sha256=#{tree_sha256}
    TEXT
  )
end

def tree_sha256_for(directory)
  entries = Dir.glob(File.join(directory, "**", "*"), File::FNM_DOTMATCH)
               .reject { |path| File.directory?(path) }
               .sort

  digest = Digest::SHA256.new
  entries.each do |path|
    relative = path.delete_prefix("#{directory}/")
    digest << relative << "\0"
    digest << File.binread(path)
    digest << "\0"
  end
  digest.hexdigest
end

config = build_vendor_config
validate_vendor_config!(config)
validate_pinning!(config)

puts WARNING
puts "Vendoring PQClean into #{VENDOR_DIR}"
puts "Pinned ref: #{config[:version]}"
puts "Archive checksum: #{config[:sha256]}"

FileUtils.rm_rf(VENDOR_DIR)
FileUtils.mkdir_p(VENDOR_DIR)

Dir.mktmpdir("pq_crypto-vendor") do |tmpdir|
  archive = File.join(tmpdir, "pqclean.tar.gz")
  destination = File.join(VENDOR_DIR, "pqclean")

  download(config[:url], archive)
  archive_sha256 = verify_checksum!(archive, config[:sha256])
  extract_subset(archive, destination, strip_prefix: config[:strip], keep_dirs: config[:keep])
  write_manifest!(config: config, archive_sha256: archive_sha256, tree_sha256: tree_sha256_for(destination))
end

puts "Done. PQClean sources are now available in ext/pqcrypto/vendor/."
puts "Next step: review vendor diffs, then bundle exec rake compile"
