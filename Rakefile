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

Rake::TestTask.new(:test) do |t|
  t.libs << "test"
  t.libs << "lib"
  t.test_files = FileList["test/**/*_test.rb", "test/**/test_*.rb"]
end

desc "Backward-compatible alias for the old RSpec task name"
task spec: :test

desc "Download and vendor PQClean sources"
task :vendor do
  ruby "script/vendor_libs.rb"
end

desc "Vendor PQClean, compile the extension, and run tests"
task full_build: %i[vendor compile test]

task default: %i[compile test]

task console: :compile do
  require "irb"
  require_relative "lib/pq_crypto"
  ARGV.clear
  IRB.start
end
