#!/usr/bin/env ruby
# frozen_string_literal: true

require "digest"
require "fileutils"
require "open3"
require "optparse"
require "tmpdir"

VENDOR_DIR = File.expand_path("../ext/pqcrypto/vendor", __dir__)
MANIFEST_PATH = File.join(VENDOR_DIR, ".vendored")

PINS = {
  mlkem: {
    repo: "https://github.com/pq-code-package/mlkem-native.git",
    ref: "v1.3.0",
    commit: "398050c877ff4353c96305c6434b63528accfc37",
    tree_sha256: "3cd7af93cde256f73ce5ffde3ac3accd31e4361616e275f1bf1c39d462c2149e",
    target: "mlkem-native",
    source_dir: "mlkem"
  },
  mldsa: {
    repo: "https://github.com/pq-code-package/mldsa-native.git",
    ref: "v1.0.0-beta2",
    commit: "9b0ee84f4cf399043eca59eca4e5f8531ca1d61b",
    tree_sha256: "2887f59926c18a877e8c5a5e30727e84497c357032093d00d7135aedf53f011e",
    target: "mldsa-native",
    source_dir: "mldsa"
  }
}.freeze

VENDORED_DOCS = %w[LICENSE LICENSE.txt README.md SECURITY.md BUILDING.md RELEASE.md META.yml].freeze
NORMALIZED_MTIME = Time.utc(2000, 1, 1).freeze
MANIFEST_HEADER = "# pq_crypto vendor manifest. Do not edit by hand. Regenerate with: ruby script/vendor_libs.rb"

options = { mode: :sync }
OptionParser.new do |opts|
  opts.banner = "Usage: vendor_libs.rb [--verify | --sync | --bump]"
  opts.on("--verify", "Verify existing vendor tree against pinned tree_sha256 (no network)") { options[:mode] = :verify }
  opts.on("--sync", "Re-clone at pinned commits and rebuild vendor tree (idempotent)") { options[:mode] = :sync }
  opts.on("--bump", "Re-clone and print new tree_sha256 values to update PINS in this file") { options[:mode] = :bump }
end.parse!

def sh!(cmd)
  system(*cmd) || abort("command failed: #{cmd.join(" ")}")
end

def capture!(*cmd)
  out, status = Open3.capture2(*cmd)
  abort("command failed: #{cmd.join(" ")}") unless status.success?
  out.strip
end

def vendor_candidate?(path)
  return false if File.symlink?(path)
  return false unless File.file?(path)
  return false if path.split(File::SEPARATOR).any? { |seg| seg.start_with?(".") && seg != "." && seg != ".." }
  true
end

def normalize_tree!(directory)
  Dir.glob(File.join(directory, "**", "*"), File::FNM_DOTMATCH).each do |path|
    base = File.basename(path)
    next if base == "." || base == ".."
    next if File.symlink?(path)
    if File.file?(path)
      File.chmod(0o644, path)
      File.utime(NORMALIZED_MTIME, NORMALIZED_MTIME, path)
    elsif File.directory?(path)
      File.chmod(0o755, path)
    end
  end
  File.utime(NORMALIZED_MTIME, NORMALIZED_MTIME, directory) if File.directory?(directory)
end

def copy_sources!(source_root, target_root, source_dir)
  required = File.join(source_root, source_dir)
  abort "missing required upstream directory: #{required}" unless Dir.exist?(required)

  FileUtils.rm_rf(File.join(target_root, source_dir))
  FileUtils.mkdir_p(File.join(target_root, source_dir))

  Dir.glob(File.join(required, "**", "*"), File::FNM_DOTMATCH).sort.each do |path|
    next unless vendor_candidate?(path)
    relative = path.sub(/\A#{Regexp.escape(required)}\//, "")
    dest = File.join(target_root, source_dir, relative)
    FileUtils.mkdir_p(File.dirname(dest))
    FileUtils.cp(path, dest, preserve: false)
  end

  VENDORED_DOCS.each do |relative|
    src = File.join(source_root, relative)
    next if File.symlink?(src)
    next unless File.file?(src)
    FileUtils.cp(src, File.join(target_root, relative), preserve: false)
  end
end

def tree_sha256_for(directory)
  entries = Dir.glob(File.join(directory, "**", "*"), File::FNM_DOTMATCH)
               .reject { |p| File.directory?(p) || File.symlink?(p) || %w[. ..].include?(File.basename(p)) }
               .sort

  digest = Digest::SHA256.new
  entries.each do |path|
    relative = path.sub(/\A#{Regexp.escape(directory)}\/?/, "")
    digest << relative << "\0"
    digest << File.binread(path)
    digest << "\0"
  end
  digest.hexdigest
end

def vendor_one(name, pin)
  target = File.join(VENDOR_DIR, pin[:target])
  FileUtils.rm_rf(target)
  FileUtils.mkdir_p(target)

  Dir.mktmpdir("pqcrypto-#{name}-") do |tmpdir|
    clone_dir = File.join(tmpdir, pin[:target])
    sh!(["git", "clone", "--depth", "1", "--branch", pin[:ref], pin[:repo], clone_dir])
    actual_commit = capture!("git", "-C", clone_dir, "rev-parse", "HEAD")

    if actual_commit != pin[:commit]
      sh!(["git", "-C", clone_dir, "fetch", "--depth", "1", "origin", pin[:commit]])
      sh!(["git", "-C", clone_dir, "checkout", "--detach", pin[:commit]])
      actual_commit = capture!("git", "-C", clone_dir, "rev-parse", "HEAD")
    end

    abort "commit mismatch for #{name}: expected #{pin[:commit]}, got #{actual_commit}" unless actual_commit == pin[:commit]

    copy_sources!(clone_dir, target, pin[:source_dir])
  end

  normalize_tree!(target)
  tree_sha256_for(target)
end

def manifest_body_lines(results)
  lines = ["backend=PQ Code Package native only", "pqclean=removed"]
  results.each do |name, data|
    prefix = "#{name}_native"
    lines << "#{prefix}_repo=#{data[:repo]}"
    lines << "#{prefix}_ref=#{data[:ref]}"
    lines << "#{prefix}_commit=#{data[:commit]}"
    lines << "#{prefix}_tree_sha256=#{data[:tree_sha256]}"
  end
  lines
end

def manifest_signature(body_lines)
  Digest::SHA256.hexdigest(body_lines.join("\n") + "\n")
end

def write_manifest(results)
  body = manifest_body_lines(results)
  sig = manifest_signature(body)
  content = ([MANIFEST_HEADER] + body + ["manifest_sha256=#{sig}"]).join("\n") + "\n"
  File.write(MANIFEST_PATH, content)
  File.chmod(0o644, MANIFEST_PATH)
  File.utime(NORMALIZED_MTIME, NORMALIZED_MTIME, MANIFEST_PATH)
end

def parse_manifest(path)
  return { kv: {}, body: [], signature: nil } unless File.exist?(path)
  body = []
  kv = {}
  signature = nil
  File.readlines(path, chomp: true).each do |line|
    next if line.start_with?("#")
    next if line.empty?
    if line.start_with?("manifest_sha256=")
      signature = line.split("=", 2).last
    else
      body << line
      k, v = line.split("=", 2)
      kv[k] = v if k && v
    end
  end
  { kv: kv, body: body, signature: signature }
end

case options[:mode]
when :verify
  manifest = parse_manifest(MANIFEST_PATH)
  failures = []

  if manifest[:signature].nil?
    failures << "manifest: missing manifest_sha256 line"
  else
    expected_sig = manifest_signature(manifest[:body])
    failures << "manifest: signature mismatch (manifest_sha256=#{manifest[:signature]}, computed=#{expected_sig})" if expected_sig != manifest[:signature]
  end

  PINS.each do |name, pin|
    target = File.join(VENDOR_DIR, pin[:target])
    unless Dir.exist?(target)
      failures << "#{name}: vendor directory missing (#{target})"
      next
    end

    manifest_commit = manifest[:kv]["#{name}_native_commit"]
    if manifest_commit != pin[:commit]
      failures << "#{name}: manifest commit (#{manifest_commit.inspect}) != PINS commit (#{pin[:commit]})"
    end

    manifest_tree = manifest[:kv]["#{name}_native_tree_sha256"]
    if manifest_tree != pin[:tree_sha256]
      failures << "#{name}: manifest tree_sha256 (#{manifest_tree.inspect}) != PINS tree_sha256 (#{pin[:tree_sha256]})"
    end

    actual_tree = tree_sha256_for(target)
    if actual_tree != pin[:tree_sha256]
      failures << "#{name}: filesystem tree_sha256 (#{actual_tree}) != PINS tree_sha256 (#{pin[:tree_sha256]})"
    end
  end

  if failures.empty?
    puts "vendor verify: ok"
    exit 0
  else
    failures.each { |f| warn f }
    exit 1
  end

when :sync
  if Dir.exist?(VENDOR_DIR) && File.exist?(MANIFEST_PATH)
    manifest = parse_manifest(MANIFEST_PATH)
    sig_ok = manifest[:signature] && manifest_signature(manifest[:body]) == manifest[:signature]
    pins_ok = sig_ok && PINS.all? do |name, pin|
      target = File.join(VENDOR_DIR, pin[:target])
      Dir.exist?(target) &&
        manifest[:kv]["#{name}_native_commit"] == pin[:commit] &&
        manifest[:kv]["#{name}_native_tree_sha256"] == pin[:tree_sha256] &&
        tree_sha256_for(target) == pin[:tree_sha256]
    end

    if pins_ok
      puts "vendor already at pinned commits and tree_sha256; nothing to do"
      exit 0
    end
  end

  FileUtils.rm_rf(VENDOR_DIR)
  FileUtils.mkdir_p(VENDOR_DIR)

  results = {}
  PINS.each do |name, pin|
    actual_tree = vendor_one(name, pin)
    if actual_tree != pin[:tree_sha256]
      abort "#{name}: tree_sha256 drift (PINS=#{pin[:tree_sha256]}, actual=#{actual_tree}). " \
            "Upstream changed under the pinned commit, or the vendor algorithm changed. " \
            "If intentional, run with --bump to print new pins."
    end
    results[name] = pin.merge(tree_sha256: actual_tree)
  end
  write_manifest(results)
  puts "vendor sync: ok"
  results.each { |name, data| puts "  #{name}: commit=#{data[:commit]} tree_sha256=#{data[:tree_sha256]}" }

when :bump
  FileUtils.rm_rf(VENDOR_DIR)
  FileUtils.mkdir_p(VENDOR_DIR)

  results = {}
  PINS.each do |name, pin|
    actual_tree = vendor_one(name, pin)
    results[name] = pin.merge(tree_sha256: actual_tree)
  end
  write_manifest(results)

  puts "Update PINS in script/vendor_libs.rb to:"
  results.each do |name, data|
    puts "  PINS[:#{name}][:tree_sha256] = #{data[:tree_sha256].inspect}"
  end
end
