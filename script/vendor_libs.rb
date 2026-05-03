#!/usr/bin/env ruby
# frozen_string_literal: true

require "digest"
require "fileutils"
require "open3"

VENDOR_DIR = File.expand_path("../ext/pqcrypto/vendor", __dir__)
MANIFEST_PATH = File.join(VENDOR_DIR, ".vendored")

DEFAULTS = {
  mlkem: {
    repo: "https://github.com/pq-code-package/mlkem-native.git",
    ref: "v1.1.0",
    target: "mlkem-native"
  },
  mldsa: {
    repo: "https://github.com/pq-code-package/mldsa-native.git",
    ref: "v1.0.0-beta",
    target: "mldsa-native"
  }
}.freeze

WARNING = <<~TEXT.freeze
  WARNING: this script vendors PQ Code Package sources and removes PQClean.

  pq_crypto now has no PQClean fallback. Build failures should point at the new
  native stack only: mlkem-native / mldsa-native.
TEXT

def sh!(cmd)
  puts "+ #{cmd.join(" ")}"
  system(*cmd) || abort("command failed: #{cmd.join(" ")}")
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

def clone_project(name, config)
  env_prefix = name.to_s.upcase
  repo = ENV["#{env_prefix}_NATIVE_REPO"] || config[:repo]
  ref = ENV["#{env_prefix}_NATIVE_REF"] || config[:ref]
  target = File.join(VENDOR_DIR, config[:target])

  FileUtils.rm_rf(target)
  sh!(["git", "clone", "--depth", "1", "--branch", ref, repo, target])

  commit, status = Open3.capture2("git", "-C", target, "rev-parse", "HEAD")
  commit = status.success? ? commit.strip : "unknown"

  [repo, ref, commit, tree_sha256_for(target)]
end

puts WARNING
puts "Vendoring into #{VENDOR_DIR}"

FileUtils.rm_rf(VENDOR_DIR)
FileUtils.mkdir_p(VENDOR_DIR)

mlkem_repo, mlkem_ref, mlkem_commit, mlkem_tree = clone_project(:mlkem, DEFAULTS[:mlkem])
mldsa_repo, mldsa_ref, mldsa_commit, mldsa_tree = clone_project(:mldsa, DEFAULTS[:mldsa])

File.write(
  MANIFEST_PATH,
  <<~TEXT
    backend=PQ Code Package native only
    pqclean=removed
    mlkem_native_repo=#{mlkem_repo}
    mlkem_native_ref=#{mlkem_ref}
    mlkem_native_commit=#{mlkem_commit}
    mlkem_native_tree_sha256=#{mlkem_tree}
    mldsa_native_repo=#{mldsa_repo}
    mldsa_native_ref=#{mldsa_ref}
    mldsa_native_commit=#{mldsa_commit}
    mldsa_native_tree_sha256=#{mldsa_tree}
  TEXT
)

puts "Done. Next step: bundle exec rake compile"
