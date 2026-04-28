# pq_crypto

`pq_crypto` is a primitive-first Ruby gem for post-quantum cryptography.
It provides small Ruby APIs for ML-KEM, ML-DSA, and one hybrid X-Wing KEM,
with standard key serialization where available.

The gem intentionally stays close to cryptographic primitives. It does not
provide protocol, session, transport, certificate-chain, or application-level
handshake helpers.

## Installation

Add the gem to your `Gemfile`:

```ruby
# Gemfile
gem "pq_crypto"
```

Then install it:

```bash
bundle install
```

When working from a source checkout, compile the native extension before
running tests or examples:

```bash
bundle exec rake compile
bundle exec rake test
```

## What this gem provides

| Area | Capabilities |
| --- | --- |
| ML-KEM | Key generation, encapsulation, decapsulation, raw key import/export, SPKI public keys, PKCS#8 private keys. |
| ML-DSA | Key generation, signing, verification, streaming signing/verification for large inputs, raw key import/export, SPKI public keys, PKCS#8 private keys. |
| Hybrid KEM | ML-KEM-768 + X25519 using the X-Wing combiner. |
| Serialization | Standard SPKI / PKCS#8 for NIST PQC keys, plus frozen `pqc_container_*` compatibility formats for the original algorithms. |
| Safety helpers | Best-effort secret wiping and constant-time equality for key comparisons. |
| Introspection | Supported algorithm lists, algorithm metadata, backend/version helpers. |

## Supported algorithms

| Family | Algorithms | Notes |
| --- | --- | --- |
| KEM | `:ml_kem_512`, `:ml_kem_768`, `:ml_kem_1024` | FIPS 203 ML-KEM. Standard SPKI public keys and PKCS#8 private keys. |
| Signature | `:ml_dsa_44`, `:ml_dsa_65`, `:ml_dsa_87` | FIPS 204 ML-DSA. Standard SPKI public keys and PKCS#8 private keys. |
| Hybrid KEM | `:ml_kem_768_x25519_xwing` | ML-KEM-768 + X25519 hybrid KEM using the X-Wing construction. |

Standard encodings use RFC 9935 OIDs for ML-KEM and RFC 9881 OIDs for
ML-DSA. `AlgorithmIdentifier.parameters` are omitted, not encoded as `NULL`.

The `pqc_container_*` format is project-local and kept only for backward
compatibility. It is not ASN.1, SPKI, or PKCS#8. It remains limited to the
original algorithms:

- `:ml_kem_768`
- `:ml_dsa_65`
- `:ml_kem_768_x25519_xwing`

## Requirements

- Ruby 3.4 or later
- a C toolchain with C11 support
- OpenSSL 3.0 or later with SHA3-256 and SHAKE256 available

## Security status

`pq_crypto` is experimental and not audited. Treat it as a low-level primitive
library, not a complete security protocol. See [`SECURITY.md`](SECURITY.md) for
audit status, serialization caveats, hybrid-KEM notes, and interoperability
warnings.

## Useful entry points

```ruby
PQCrypto.version
PQCrypto.backend
PQCrypto.supported_kems
PQCrypto.supported_signatures
PQCrypto.supported_hybrid_kems

PQCrypto::KEM.generate(:ml_kem_768)
PQCrypto::Signature.generate(:ml_dsa_65)
PQCrypto::HybridKEM.generate(:ml_kem_768_x25519_xwing)
```

## More examples

Detailed usage examples live in [`GET_STARTED.md`](GET_STARTED.md):

- generating keys
- ML-KEM encapsulation / decapsulation
- ML-DSA signing / verification
- streaming ML-DSA for large files
- SPKI and PKCS#8 serialization
- `pqc_container_*` compatibility serialization
- secure wiping and practical safety notes
