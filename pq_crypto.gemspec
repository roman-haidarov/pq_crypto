require_relative "lib/pq_crypto/version"

Gem::Specification.new do |spec|
  spec.name          = "pq_crypto"
  spec.version       = PQCrypto::VERSION
  spec.authors       = ["Roman Haydarov"]
  spec.email         = ["romanhajdarov@gmail.com"]

  spec.summary       = "Primitive-first post-quantum cryptography for Ruby"
  spec.description   = "Native Ruby wrapper around ML-KEM-768, ML-DSA-65, and an optional hybrid ML-KEM-768+X25519 KEM, backed by PQClean and OpenSSL."
  spec.homepage      = "https://github.com/roman-haidarov/pq_crypto"
  spec.license       = "MIT"
  spec.required_ruby_version = ">= 3.1.0"

  spec.metadata["homepage_uri"]    = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["changelog_uri"]   = "#{spec.homepage}/blob/main/CHANGELOG.md"

  spec.files = Dir[
    "lib/**/*.rb",
    "ext/**/*.{c,h,rb}",
    "ext/pqcrypto/vendor/**/*",
    "ext/pqcrypto/vendor/.vendored",
    "README.md",
    "GET_STARTED.md",
    "CHANGELOG.md",
    "LICENSE.txt",
    "SECURITY.md",
    "script/vendor_libs.rb",
    ".github/workflows/ci.yml"
  ]

  spec.bindir        = "exe"
  spec.executables   = []
  spec.require_paths = ["lib"]
  spec.extensions    = ["ext/pqcrypto/extconf.rb"]

  spec.add_development_dependency "bundler", "~> 2.0"
  spec.add_development_dependency "rake", "~> 13.0"
  spec.add_development_dependency "rake-compiler", "~> 1.2"
  spec.add_development_dependency "minitest", "~> 5.0"
end
