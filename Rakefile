# frozen_string_literal: true

require "rake/clean"
require "rake/extensiontask"
require "rake/testtask"

spec = Gem::Specification.load("pq_crypto.gemspec")

Rake::ExtensionTask.new("pqcrypto_secure", spec) do |ext|
  ext.ext_dir = "ext/pqcrypto"
  ext.lib_dir = "lib/pqcrypto"
end

CLEAN.include("tmp", "lib/pqcrypto/*.bundle", "lib/pqcrypto/*.so", "lib/pqcrypto/*.dll")

Rake::TestTask.new(:ruby_test) do |t|
  t.libs << "test"
  t.libs << "lib"
  t.test_files = FileList["test/**/*_test.rb", "test/**/test_*.rb"]
end

def run_shell_check(script, description)
  path = File.expand_path(script, __dir__)
  unless File.exist?(path)
    abort "missing #{description} script: #{script}"
  end
  sh "bash", path
end

desc "Check ext/pqcrypto/pqcrypto_native_api.h against the vendored upstream headers"
task :native_api_conformance do
  run_shell_check("test/native_api_conformance/run.sh", "native API conformance")
end

desc "Run the direct C API tests (PQCRYPTO_SANITIZE=address for a sanitized build)"
task :c_api_test do
  run_shell_check("test/c_api/run.sh", "C API test")
end

desc "Run the Ruby suite plus the native API conformance and C API checks"
task test: %i[native_api_conformance c_api_test ruby_test]

desc "Backward-compatible alias for the old RSpec task name"
task spec: :test

namespace :vendor do
  desc "Sync vendored sources to pinned commits + tree_sha256 (idempotent)"
  task :sync do
    ruby "script/vendor_libs.rb", "--sync"
  end

  desc "Verify vendored sources match pinned tree_sha256 (no network)"
  task :verify do
    ruby "script/vendor_libs.rb", "--verify"
  end

  desc "Re-clone upstream and print new tree_sha256 to update PINS"
  task :bump do
    ruby "script/vendor_libs.rb", "--bump"
  end
end

desc "Alias for vendor:sync"
task vendor: "vendor:sync"

desc "Vendor PQ Code Package sources, compile, run tests"
task full_build: %i[vendor compile test]

task default: %i[vendor:verify compile test]

task console: :compile do
  require "irb"
  require_relative "lib/pq_crypto"
  ARGV.clear
  IRB.start
end
