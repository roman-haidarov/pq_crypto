require_relative "lib/pq_crypto/version"

Gem::Specification.new do |spec|
  spec.name          = "pq_crypto"
  spec.version       = PQCrypto::VERSION
  spec.authors       = ["Roman Haydarov"]
  spec.email         = ["romanhajdarov@gmail.com"]

  spec.summary       = "Primitive-first post-quantum cryptography for Ruby"
  spec.description   = "Native Ruby wrapper around ML-KEM, ML-DSA, and an optional hybrid ML-KEM-768+X25519 KEM, backed by PQ Code Package native sources and OpenSSL."
  spec.homepage      = "https://github.com/roman-haidarov/pq_crypto"
  spec.license       = "MIT"
  spec.required_ruby_version = ">= 3.1"

  spec.metadata["homepage_uri"]    = spec.homepage
  spec.metadata["source_code_uri"] = "#{spec.homepage}/tree/main"
  spec.metadata["changelog_uri"]   = "#{spec.homepage}/blob/main/CHANGELOG.md"

  vendor_files = Dir[
    "ext/pqcrypto/vendor/.vendored",
    "ext/pqcrypto/vendor/mlkem-native/{LICENSE,README.md,SECURITY.md,BUILDING.md,RELEASE.md,META.yml}",
    "ext/pqcrypto/vendor/mlkem-native/mlkem/**/*",
    "ext/pqcrypto/vendor/mldsa-native/{LICENSE,README.md,SECURITY.md,BUILDING.md,RELEASE.md,META.yml}",
    "ext/pqcrypto/vendor/mldsa-native/mldsa/**/*"
  ]

  spec.files = (Dir[
    "lib/**/*.rb",
    "ext/pqcrypto/*.{c,h,rb}",
    "README.md",
    "GET_STARTED.md",
    "CHANGELOG.md",
    "LICENSE.txt",
    "SECURITY.md",
    "script/vendor_libs.rb",
    ".github/workflows/ci.yml"
  ] + vendor_files).select { |path| File.file?(path) && !File.symlink?(path) }.uniq

  spec.bindir        = "exe"
  spec.executables   = []
  spec.require_paths = ["lib"]
  spec.extensions    = ["ext/pqcrypto/extconf.rb"]

  spec.add_development_dependency "rake", "~> 13.0"
  spec.add_development_dependency "rake-compiler", "~> 1.2"
  spec.add_development_dependency "minitest", "~> 5.0"
end
