#!/usr/bin/env ruby
# frozen_string_literal: true

require "mkmf"

$CFLAGS << " -std=c99 -Wall -Wextra -O2"
$CFLAGS << " -fstack-protector-strong -D_FORTIFY_SOURCE=2"
$CFLAGS << " -Wno-c23-extensions -Wno-strict-prototypes -Wno-pedantic"
$CFLAGS << " -Wno-unused-parameter -Wno-unused-function"

$LDFLAGS << " -Wl,-no_warn_duplicate_libraries" if RbConfig::CONFIG["host_os"] =~ /darwin/

USE_SYSTEM = arg_config("--use-system-libraries") || ENV["PQCRYPTO_USE_SYSTEM_LIBRARIES"]

def configure_compiler_environment
  return unless RUBY_PLATFORM.include?("darwin")

  dir_config("homebrew", "/opt/homebrew")
  $CPPFLAGS << " -I/opt/homebrew/include"
  $LDFLAGS << " -L/opt/homebrew/lib"
end

def find_vendor_dir
  candidates = [
    File.join(__dir__, "vendor"),
    File.expand_path("../../ext/pqcrypto/vendor", __dir__),
    File.join(Dir.pwd, "ext", "pqcrypto", "vendor")
  ]

  dir = __dir__
  6.times do
    candidates << File.join(dir, "ext", "pqcrypto", "vendor")
    dir = File.dirname(dir)
  end

  candidates.find { |path| File.exist?(File.join(path, ".vendored")) }
            &.then { |path| File.expand_path(path) }
end

def configure_openssl!
  configure_compiler_environment

  abort "OpenSSL libcrypto is required" unless have_library("crypto")
  abort "OpenSSL libssl is required" unless have_library("ssl")
  abort "openssl/evp.h is required" unless have_header("openssl/evp.h")
  abort "openssl/rand.h is required" unless have_header("openssl/rand.h")
  abort "openssl/kdf.h is required" unless have_header("openssl/kdf.h")

  $CFLAGS << " -DHAVE_OPENSSL_EVP_H -DHAVE_OPENSSL_RAND_H -DHAVE_OPENSSL_KDF_H"
end

def configure_pqclean(vendor_dir)
  return nil unless vendor_dir

  pqclean_dir = File.join(vendor_dir, "pqclean")
  return nil unless Dir.exist?(pqclean_dir)

  mlkem_dir = File.join(pqclean_dir, "crypto_kem", "ml-kem-768", "clean")
  mldsa_dir = File.join(pqclean_dir, "crypto_sign", "ml-dsa-65", "clean")
  common_dir = File.join(pqclean_dir, "common")

  include_dirs = [mlkem_dir, mldsa_dir, common_dir]
  return nil unless include_dirs.all? { |dir| Dir.exist?(dir) }

  mlkem_sources = Dir.glob(File.join(mlkem_dir, "*.c")).sort
  mldsa_sources = Dir.glob(File.join(mldsa_dir, "*.c")).sort
  common_sources = %w[fips202.c sha2.c sp800-185.c randombytes.c].map { |name| File.join(common_dir, name) }

  source_groups = [
    ["pqclean_mlkem", mlkem_sources],
    ["pqclean_mldsa", mldsa_sources],
    ["pqclean_common", common_sources]
  ]

  return nil unless source_groups.all? { |_, sources| sources.all? { |path| File.exist?(path) } }

  $CFLAGS << " -DHAVE_PQCLEAN -Wno-undef"
  include_dirs.each { |dir| $CPPFLAGS << " -I#{dir}" }

  {
    include_dirs: include_dirs,
    source_groups: source_groups
  }
end

def inject_pqclean_sources!(pqclean_config)
  return unless pqclean_config

  makefile = File.read("Makefile")

  vendor_objects = []
  build_rules = []

  pqclean_config[:source_groups].each do |prefix, sources|
    sources.each do |source|
      base = File.basename(source, ".c").tr("-", "_")
      object = "#{prefix}_#{base}.o"
      vendor_objects << object
      build_rules << <<~RULE
        #{object}: #{source}
        	$(ECHO) compiling #{source}
        	$(Q) $(CC) $(INCFLAGS) $(CPPFLAGS) $(CFLAGS) $(COUTFLAG)$@ -c $(CSRCFLAG)$<
      RULE
    end
  end

  objects_line = makefile.lines.find { |line| line.start_with?("OBJS = ") }
  raise "Could not find OBJS line in generated Makefile" unless objects_line

  makefile.sub!(objects_line, objects_line.chomp + " #{vendor_objects.join(' ')}\n")

  unless makefile.include?("# vendored pqclean objects")
    rules_block = "\n# vendored pqclean objects\n" + build_rules.join("\n") + "\n"
    anchor = "$(OBJS): $(HDRS) $(ruby_headers)\n"
    raise "Could not find OBJS dependency anchor in generated Makefile" unless makefile.include?(anchor)

    makefile.sub!(anchor, anchor + rules_block)
  end

  File.write("Makefile", makefile)
end

have_func("getrandom", "sys/random.h")
have_func("arc4random_buf", "stdlib.h")

vendor_dir = USE_SYSTEM ? nil : find_vendor_dir

puts
puts "=== PQCrypto build configuration ==="
configure_openssl!
pqclean_config = configure_pqclean(vendor_dir)
puts "OpenSSL: system"
abort "PQClean vendored sources are required. Run: bundle exec rake vendor" unless pqclean_config
puts "PQClean: vendored"
puts "Output: pqcrypto/pqcrypto_secure"
puts "===================================="

create_makefile("pqcrypto/pqcrypto_secure")
inject_pqclean_sources!(pqclean_config)
