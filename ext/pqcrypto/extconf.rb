#!/usr/bin/env ruby
# frozen_string_literal: true

require "mkmf"

$CFLAGS << " -std=c11 -Wall -Wextra -O2"
$CFLAGS << " -fstack-protector-strong -D_FORTIFY_SOURCE=2"
VENDOR_ONLY_CFLAGS = "-Wno-unused-parameter -Wno-unused-function -Wno-strict-prototypes -Wno-pedantic -Wno-c23-extensions -Wno-undef"

$LDFLAGS << " -Wl,-no_warn_duplicate_libraries" if RbConfig::CONFIG["host_os"] =~ /darwin/

USE_SYSTEM = arg_config("--use-system-libraries") || ENV["PQCRYPTO_USE_SYSTEM_LIBRARIES"]

SANITIZE = ENV["PQCRYPTO_SANITIZE"]

if SANITIZE && !SANITIZE.strip.empty?
  sanitize = SANITIZE.strip
  $CFLAGS.gsub!(/\s-D_FORTIFY_SOURCE=\d+/, "")
  $CFLAGS << " -O1 -g -fno-omit-frame-pointer -fsanitize=#{sanitize}"
  $LDFLAGS << " -fsanitize=#{sanitize}"
end

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
  abort "openssl/crypto.h is required" unless have_header("openssl/crypto.h")

  version_check = <<~SRC
    #include <openssl/opensslv.h>
    #if OPENSSL_VERSION_NUMBER < 0x30000000L
    #error "OpenSSL 3.0 or later is required"
    #endif
    int main(void) { return 0; }
  SRC

  abort "OpenSSL 3.0 or later is required" unless try_compile(version_check)

  sha3_check = <<~SRC
    #include <openssl/evp.h>
    int main(void) {
        const EVP_MD *md = EVP_sha3_256();
        return md == NULL ? 1 : 0;
    }
  SRC
  abort "OpenSSL SHA3-256 is required (X-Wing combiner)" unless try_compile(sha3_check)

  shake_check = <<~SRC
    #include <openssl/evp.h>
    int main(void) {
        const EVP_MD *md = EVP_shake256();
        return md == NULL ? 1 : 0;
    }
  SRC
  abort "OpenSSL SHAKE256 is required (X-Wing key expansion)" unless try_compile(shake_check)

  $CFLAGS << " -DHAVE_OPENSSL_EVP_H -DHAVE_OPENSSL_RAND_H"
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
  common_sources = %w[fips202.c sha2.c sp800-185.c].map { |name| File.join(common_dir, name) }

  source_groups = [
    ["pqclean_mlkem", mlkem_sources],
    ["pqclean_mldsa", mldsa_sources],
    ["pqclean_common", common_sources]
  ]

  return nil unless source_groups.all? { |_, sources| sources.all? { |path| File.exist?(path) } }

  $CFLAGS << " -DHAVE_PQCLEAN"
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
        	$(Q) $(CC) $(INCFLAGS) $(CPPFLAGS) $(CFLAGS) #{VENDOR_ONLY_CFLAGS} $(COUTFLAG)$@ -c $(CSRCFLAG)$<
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

vendor_dir = USE_SYSTEM ? nil : find_vendor_dir

puts
puts "=== PQCrypto build configuration ==="
configure_openssl!
pqclean_config = configure_pqclean(vendor_dir)
puts "OpenSSL: system"
abort "PQClean vendored sources are required. Run: bundle exec rake vendor" unless pqclean_config
puts "PQClean: vendored (randombytes overridden by pq_randombytes.c)"
puts "Output: pqcrypto/pqcrypto_secure"
puts "===================================="

create_makefile("pqcrypto/pqcrypto_secure")
inject_pqclean_sources!(pqclean_config)
