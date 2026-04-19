# Security Policy

## Status

`pq_crypto` is **experimental**. It has not been audited by an external cryptography review firm. Do not rely on it for production security without doing your own due diligence.

## What this gem aims to provide

- Hybrid IND-CCA2 key establishment by combining ML-KEM-768 (FIPS 203) and X25519.
- EUF-CMA signatures via ML-DSA-65 (FIPS 204).
- Authenticated encryption over AES-256-GCM for session traffic.
- Replay rejection and direction separation inside a single session.

## What this gem does NOT provide

- FIPS certification or formal compliance claims.
- Forward secrecy with automatic key ratcheting (each session uses a single shared secret; rotate by re-establishing a session).
- Sliding-window out-of-order delivery (counters must arrive strictly in order per direction).
- Cross-implementation interop with OpenSSL / Go / liboqs. The hybrid combiner is transcript-bound but is **not** X-Wing, HPKE, or any standardized construction. Payloads produced by this gem are not expected to be readable by other PQ libraries.
- Protection against side-channel attacks beyond what PQClean and OpenSSL themselves provide.
- Protection against unknown-key-share (UKS) attacks on `sign_and_seal` — identities are not bound into the signed transcript in this version.

## Threat model

Assumed capabilities of the attacker:

- Full control over the network (passive and active).
- Ability to read and tamper any ciphertext in transit.
- No access to host memory, compromised processes, or private keys that have not been leaked via the application.
- Possession of a future cryptographically-relevant quantum computer (CRQC). This is the reason the gem exists.

Out of scope:

- Side-channel attacks (timing, power, EM).
- Fault injection on the host.
- Compromised RNG at the OS level.
- Malicious libraries linked into the process.

## Algorithms

| Primitive | Algorithm | Source |
|---|---|---|
| PQ KEM | ML-KEM-768 | PQClean (FIPS 203 reference) |
| PQ Signature | ML-DSA-65 | PQClean (FIPS 204 reference) |
| Classical KEM component | X25519 | OpenSSL EVP |
| AEAD | AES-256-GCM | OpenSSL EVP |
| KDF | HKDF-SHA256 | OpenSSL EVP |
| Salt hash (combiner) | SHA-256 | OpenSSL EVP |

## Hybrid KEM combiner

```
IKM     = mlkem_shared_secret || x25519_shared_secret
transcript = "pqcrypto/v1/hybrid-kem" || recipient_x25519_pk || hybrid_ciphertext
salt    = SHA256(transcript)
shared  = HKDF(IKM, salt, info=transcript, 32 bytes)
```

The combiner is transcript-bound (recipient pubkey and both ciphertexts are mixed in via salt and info). It is **not** X-Wing — X-Wing uses SHA3-256 and a different layout. This combiner is inspired by hybrid KEM best practices (binding public keys and ciphertexts into the KDF) but does not implement any standardized draft.

## Session key schedule

```
initiator_to_responder = HKDF(shared, "", "pqcrypto/v1/session/initiator-to-responder", 32)
responder_to_initiator = HKDF(shared, "", "pqcrypto/v1/session/responder-to-initiator", 32)

if initiator:
    send_key = initiator_to_responder
    recv_key = responder_to_initiator
else:
    send_key = responder_to_initiator
    recv_key = initiator_to_responder
```

Nonce layout (12 bytes): `0x00 0x00 0x00 0x00 || counter_u64_be`.

Counter starts at 0 per direction. Decrypt rejects any counter that is not exactly `expected_recv_nonce`. This means **strict in-order delivery is required** — out-of-order or replayed ciphertexts are rejected.

## Wire format

Since v0.3.1, signed-and-sealed payloads are prefixed with a version header:

```
magic(4) = "PQ10"
version(1) = 0x01
suite_id(1) = 0x01  # ML-KEM-768 + ML-DSA-65 + X25519 + AES-256-GCM + SHA-256
signature_len(4, big-endian)
signature[signature_len]
sealed_body  (= hybrid_ciphertext || aes_gcm_header || aes_gcm_ciphertext)
```

Future versions that add new algorithm suites will bump `suite_id`. Consumers must reject unknown `magic`, `version`, or `suite_id` values.

Raw KEM ciphertexts from `kem_encapsulate` and session ciphertexts from `Session#encrypt` are **not** framed — they are plain bytes intended to be carried inside another protocol that supplies its own framing.

## Reporting vulnerabilities

Please report security issues privately by email to the maintainer listed in the gemspec. Include:

- A description of the issue and its impact.
- A minimal reproduction if possible.
- Any proposed fix or mitigation.

Please do not open public GitHub issues for security bugs.

There is no SLA for fixes on an experimental project. Best effort only.

## When to use this gem

- Learning and exploring post-quantum cryptography in Ruby.
- Internal PoCs where the author accepts the experimental label.
- Research prototypes.

## When NOT to use this gem

- Any system where data confidentiality matters to real people today.
- Any system regulated under FIPS, Common Criteria, PCI-DSS, HIPAA, or similar.
- Any system where interop with other PQ implementations is required.
- Any system where the author cannot tolerate format-breaking changes across minor versions.

For those cases, use OpenSSL 3.5+ directly (it has ML-KEM and ML-DSA), or wait for a Ruby binding to liboqs that ships KAT-verified algorithms.
