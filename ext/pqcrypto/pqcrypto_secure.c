#include "pqcrypto_secure.h"
#include "pqcrypto_version.h"

#include <stdio.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>

#ifndef HAVE_OPENSSL_EVP_H
#error \
    "OpenSSL with EVP support is required for secure cryptographic operations. Install OpenSSL development packages."
#endif

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/pkcs12.h>
#include <openssl/objects.h>

#if OPENSSL_VERSION_NUMBER < 0x30000000L
#error "OpenSSL 3.0 or later is required for pq_crypto"
#endif

#include "pqcrypto_native_api.h"

void pq_secure_wipe(void *ptr, size_t len) {
    if (ptr == NULL) {
        return;
    }
    volatile uint8_t *p = ptr;
    while (len--) {
        *p++ = 0;
    }

    __asm__ __volatile__("" : : "r"(ptr) : "memory");
}

static int pq_size_add(size_t a, size_t b, size_t *out) {
    if (!out)
        return PQ_ERROR_BUFFER;
    if (SIZE_MAX - a < b)
        return PQ_ERROR_BUFFER;
    *out = a + b;
    return PQ_SUCCESS;
}

static int pq_is_pem_whitespace(char c) {
    return c == '\n' || c == '\r' || c == ' ' || c == '\t';
}

static int x25519_public_from_private(uint8_t *pk, const uint8_t *sk) {
    EVP_PKEY *pkey = NULL;
    size_t pklen = X25519_PUBLICKEYBYTES;
    int ret = PQ_ERROR_KEYPAIR;

    if (!pk || !sk) {
        return PQ_ERROR_BUFFER;
    }

    pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, sk, X25519_SECRETKEYBYTES);
    if (!pkey)
        goto cleanup;

    if (EVP_PKEY_get_raw_public_key(pkey, pk, &pklen) <= 0)
        goto cleanup;
    if (pklen != X25519_PUBLICKEYBYTES)
        goto cleanup;

    ret = PQ_SUCCESS;

cleanup:
    if (pkey)
        EVP_PKEY_free(pkey);
    return ret;
}

static int x25519_shared_secret_with_pkey(uint8_t *shared, const uint8_t *their_pk,
                                          EVP_PKEY *pkey) {
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *peer_key = NULL;
    size_t shared_len = X25519_SHAREDSECRETBYTES;
    int ret = PQ_ERROR_ENCAPSULATE;

    if (!shared || !their_pk || !pkey) {
        return PQ_ERROR_BUFFER;
    }

    peer_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, their_pk, X25519_PUBLICKEYBYTES);
    if (!peer_key)
        goto cleanup;

    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx)
        goto cleanup;

    if (EVP_PKEY_derive_init(ctx) <= 0)
        goto cleanup;

    if (EVP_PKEY_derive_set_peer(ctx, peer_key) <= 0)
        goto cleanup;

    if (EVP_PKEY_derive(ctx, shared, &shared_len) <= 0)
        goto cleanup;

    if (shared_len != X25519_SHAREDSECRETBYTES)
        goto cleanup;

    ret = PQ_SUCCESS;

cleanup:
    if (ctx)
        EVP_PKEY_CTX_free(ctx);
    if (peer_key)
        EVP_PKEY_free(peer_key);
    return ret;
}

static int x25519_shared_secret(uint8_t *shared, const uint8_t *their_pk, const uint8_t *my_sk) {
    EVP_PKEY *pkey = NULL;
    int ret;

    if (!shared || !their_pk || !my_sk) {
        return PQ_ERROR_BUFFER;
    }

    pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, my_sk, X25519_SECRETKEYBYTES);
    if (!pkey)
        return PQ_ERROR_ENCAPSULATE;

    ret = x25519_shared_secret_with_pkey(shared, their_pk, pkey);
    EVP_PKEY_free(pkey);
    return ret;
}

static int x25519_ephemeral_keypair_and_shared_secret(uint8_t *ephemeral_pk, uint8_t *shared,
                                                      const uint8_t *their_pk) {
    EVP_PKEY_CTX *keygen_ctx = NULL;
    EVP_PKEY *ephemeral_pkey = NULL;
    size_t pklen = X25519_PUBLICKEYBYTES;
    int ret = PQ_ERROR_ENCAPSULATE;

    if (!ephemeral_pk || !shared || !their_pk) {
        return PQ_ERROR_BUFFER;
    }

    keygen_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!keygen_ctx)
        goto cleanup;

    if (EVP_PKEY_keygen_init(keygen_ctx) <= 0)
        goto cleanup;

    if (EVP_PKEY_keygen(keygen_ctx, &ephemeral_pkey) <= 0)
        goto cleanup;

    if (EVP_PKEY_get_raw_public_key(ephemeral_pkey, ephemeral_pk, &pklen) <= 0)
        goto cleanup;
    if (pklen != X25519_PUBLICKEYBYTES)
        goto cleanup;

    ret = x25519_shared_secret_with_pkey(shared, their_pk, ephemeral_pkey);

cleanup:
    if (ephemeral_pkey)
        EVP_PKEY_free(ephemeral_pkey);
    if (keygen_ctx)
        EVP_PKEY_CTX_free(keygen_ctx);
    return ret;
}

static const uint8_t XWING_LABEL[6] = {0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c};

static int xwing_combiner(uint8_t shared_secret[HYBRID_SHAREDSECRETBYTES],
                          const uint8_t ss_M[MLKEM_SHAREDSECRETBYTES],
                          const uint8_t ss_X[X25519_SHAREDSECRETBYTES],
                          const uint8_t ct_X[X25519_PUBLICKEYBYTES],
                          const uint8_t pk_X[X25519_PUBLICKEYBYTES]) {
    uint8_t input[MLKEM_SHAREDSECRETBYTES + X25519_SHAREDSECRETBYTES + X25519_PUBLICKEYBYTES +
                  X25519_PUBLICKEYBYTES + sizeof(XWING_LABEL)];
    uint8_t *cur = input;

    if (!shared_secret || !ss_M || !ss_X || !ct_X || !pk_X) {
        return PQ_ERROR_BUFFER;
    }

    memcpy(cur, ss_M, MLKEM_SHAREDSECRETBYTES);
    cur += MLKEM_SHAREDSECRETBYTES;
    memcpy(cur, ss_X, X25519_SHAREDSECRETBYTES);
    cur += X25519_SHAREDSECRETBYTES;
    memcpy(cur, ct_X, X25519_PUBLICKEYBYTES);
    cur += X25519_PUBLICKEYBYTES;
    memcpy(cur, pk_X, X25519_PUBLICKEYBYTES);
    cur += X25519_PUBLICKEYBYTES;
    memcpy(cur, XWING_LABEL, sizeof(XWING_LABEL));

    pqcr_mlkem_sha3_256(shared_secret, input, sizeof(input));
    pq_secure_wipe(input, sizeof(input));
    return PQ_SUCCESS;
}

static int xwing_expand_secret_key(hybrid_expanded_secret_key_t *expanded_key,
                                   const uint8_t seed[HYBRID_SECRETKEYBYTES]) {
    uint8_t expanded[XWING_EXPANDEDBYTES];
    int ret = PQ_ERROR_OPENSSL;

    if (!expanded_key || !seed) {
        return PQ_ERROR_BUFFER;
    }

    memset(expanded_key, 0, sizeof(*expanded_key));
    memset(expanded, 0, sizeof(expanded));

    pqcr_mlkem_shake256(expanded, sizeof(expanded), seed, HYBRID_SECRETKEYBYTES);

    ret = pqcr_mlkem768_keypair_derand(expanded_key->mlkem_pk, expanded_key->mlkem_sk, expanded);
    if (ret != 0) {
        ret = PQ_ERROR_KEYPAIR;
        goto cleanup;
    }

    memcpy(expanded_key->x25519_sk, expanded + 64, X25519_SECRETKEYBYTES);
    ret = x25519_public_from_private(expanded_key->x25519_pk, expanded_key->x25519_sk);
    if (ret != PQ_SUCCESS) {
        goto cleanup;
    }

    ret = PQ_SUCCESS;

cleanup:
    pq_secure_wipe(expanded, sizeof(expanded));
    if (ret != PQ_SUCCESS && expanded_key) {
        pq_secure_wipe(expanded_key, sizeof(*expanded_key));
    }
    return ret;
}

#define PQ_MLKEM_VARIANTS(X)   \
    X(mlkem, pqcr_mlkem768)    \
    X(mlkem512, pqcr_mlkem512) \
    X(mlkem1024, pqcr_mlkem1024)

#define PQ_DEFINE_MLKEM_SHIMS(prefix, native)                                                \
    int pq_##prefix##_keypair(uint8_t *pk, uint8_t *sk) {                                    \
        if (!pk || !sk) {                                                                    \
            return PQ_ERROR_BUFFER;                                                          \
        }                                                                                    \
        return native##_keypair(pk, sk) == 0 ? PQ_SUCCESS : PQ_ERROR_KEYPAIR;                \
    }                                                                                        \
    int pq_##prefix##_keypair_from_seed(uint8_t *pk, uint8_t *sk, const uint8_t *seed64) {   \
        if (!pk || !sk || !seed64) {                                                         \
            return PQ_ERROR_BUFFER;                                                          \
        }                                                                                    \
        return native##_keypair_derand(pk, sk, seed64) == 0 ? PQ_SUCCESS : PQ_ERROR_KEYPAIR; \
    }                                                                                        \
    int pq_##prefix##_encapsulate(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {             \
        if (!ct || !ss || !pk) {                                                             \
            return PQ_ERROR_BUFFER;                                                          \
        }                                                                                    \
        return native##_enc(ct, ss, pk) == 0 ? PQ_SUCCESS : PQ_ERROR_ENCAPSULATE;            \
    }                                                                                        \
    int pq_##prefix##_decapsulate(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {       \
        if (!ss || !ct || !sk) {                                                             \
            return PQ_ERROR_BUFFER;                                                          \
        }                                                                                    \
        return native##_dec(ss, ct, sk) == 0 ? PQ_SUCCESS : PQ_ERROR_DECAPSULATE;            \
    }

PQ_MLKEM_VARIANTS(PQ_DEFINE_MLKEM_SHIMS)

#undef PQ_DEFINE_MLKEM_SHIMS

static int pq_testing_mlkem_keypair_from_seed_with(uint8_t *public_key, uint8_t *secret_key,
                                                   const uint8_t *seed, size_t seed_len,
                                                   int (*keypair_derand)(uint8_t *, uint8_t *,
                                                                         const uint8_t *)) {
    if (!public_key || !secret_key || !seed || seed_len != 64 || !keypair_derand) {
        return PQ_ERROR_BUFFER;
    }
    return keypair_derand(public_key, secret_key, seed) == 0 ? PQ_SUCCESS : PQ_ERROR_KEYPAIR;
}

static int pq_testing_mlkem_encapsulate_from_seed_with(
    uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key, const uint8_t *seed,
    size_t seed_len, int (*enc_derand)(uint8_t *, uint8_t *, const uint8_t *, const uint8_t *)) {
    if (!ciphertext || !shared_secret || !public_key || !seed || seed_len != 32 || !enc_derand) {
        return PQ_ERROR_BUFFER;
    }
    return enc_derand(ciphertext, shared_secret, public_key, seed) == 0 ? PQ_SUCCESS
                                                                        : PQ_ERROR_ENCAPSULATE;
}

#define PQ_DEFINE_MLKEM_TESTING_SHIMS(prefix, native)                                             \
    int pq_testing_##prefix##_keypair_from_seed(uint8_t *public_key, uint8_t *secret_key,         \
                                                const uint8_t *seed, size_t seed_len) {           \
        return pq_testing_mlkem_keypair_from_seed_with(public_key, secret_key, seed, seed_len,    \
                                                       native##_keypair_derand);                  \
    }                                                                                             \
    int pq_testing_##prefix##_encapsulate_from_seed(uint8_t *ciphertext, uint8_t *shared_secret,  \
                                                    const uint8_t *public_key,                    \
                                                    const uint8_t *seed, size_t seed_len) {       \
        return pq_testing_mlkem_encapsulate_from_seed_with(ciphertext, shared_secret, public_key, \
                                                           seed, seed_len, native##_enc_derand);  \
    }

PQ_MLKEM_VARIANTS(PQ_DEFINE_MLKEM_TESTING_SHIMS)

#undef PQ_DEFINE_MLKEM_TESTING_SHIMS

#define PQ_DEFINE_MLDSA_SIGN_KEYPAIR(prefix, native)                                          \
    int pq_##prefix##_keypair(uint8_t *public_key, uint8_t *secret_key) {                     \
        if (!public_key || !secret_key) {                                                     \
            return PQ_ERROR_BUFFER;                                                           \
        }                                                                                     \
        return native##_keypair(public_key, secret_key) == 0 ? PQ_SUCCESS : PQ_ERROR_KEYPAIR; \
    }

PQ_DEFINE_MLDSA_SIGN_KEYPAIR(sign, pqcr_mldsa65)
PQ_DEFINE_MLDSA_SIGN_KEYPAIR(mldsa44_sign, pqcr_mldsa44)
PQ_DEFINE_MLDSA_SIGN_KEYPAIR(mldsa87_sign, pqcr_mldsa87)

#undef PQ_DEFINE_MLDSA_SIGN_KEYPAIR

#define PQ_DEFINE_MLDSA_SIGN(name, native, sig_bytes)                                             \
    int pq_##name(uint8_t *signature, size_t *signature_len, const uint8_t *message,              \
                  size_t message_len, const uint8_t *ctx, size_t ctx_len,                         \
                  const uint8_t *secret_key) {                                                    \
        if (!signature || !signature_len || !secret_key || (message_len > 0 && !message) ||       \
            (ctx_len > 0 && !ctx) || ctx_len > 255) {                                             \
            return PQ_ERROR_BUFFER;                                                               \
        }                                                                                         \
        if (native##_signature(signature, message, message_len, ctx, ctx_len, secret_key) != 0) { \
            *signature_len = 0;                                                                   \
            return PQ_ERROR_SIGN;                                                                 \
        }                                                                                         \
        *signature_len = (size_t)(sig_bytes);                                                     \
        return PQ_SUCCESS;                                                                        \
    }

PQ_DEFINE_MLDSA_SIGN(sign, pqcr_mldsa65, MLDSA65_BYTES)
PQ_DEFINE_MLDSA_SIGN(mldsa44_sign, pqcr_mldsa44, MLDSA44_BYTES)
PQ_DEFINE_MLDSA_SIGN(mldsa87_sign, pqcr_mldsa87, MLDSA87_BYTES)

#undef PQ_DEFINE_MLDSA_SIGN

#define PQ_DEFINE_MLDSA_VERIFY(name, native, sig_bytes)                                            \
    int pq_##name(const uint8_t *signature, size_t signature_len, const uint8_t *message,          \
                  size_t message_len, const uint8_t *ctx, size_t ctx_len,                          \
                  const uint8_t *public_key) {                                                     \
        if (!signature || !public_key || (message_len > 0 && !message) || (ctx_len > 0 && !ctx) || \
            ctx_len > 255) {                                                                       \
            return PQ_ERROR_BUFFER;                                                                \
        }                                                                                          \
        if (signature_len != (size_t)(sig_bytes)) {                                                \
            return PQ_ERROR_VERIFY;                                                                \
        }                                                                                          \
        return native##_verify(signature, message, message_len, ctx, ctx_len, public_key) == 0     \
                   ? PQ_SUCCESS                                                                    \
                   : PQ_ERROR_VERIFY;                                                              \
    }

PQ_DEFINE_MLDSA_VERIFY(verify, pqcr_mldsa65, MLDSA65_BYTES)
PQ_DEFINE_MLDSA_VERIFY(mldsa44_verify, pqcr_mldsa44, MLDSA44_BYTES)
PQ_DEFINE_MLDSA_VERIFY(mldsa87_verify, pqcr_mldsa87, MLDSA87_BYTES)

#undef PQ_DEFINE_MLDSA_VERIFY

static int pq_testing_mldsa_sign_from_seed_with(
    uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len,
    const uint8_t *secret_key, const uint8_t *seed, size_t seed_len, size_t expected_signature_len,
    int (*signature_internal)(uint8_t *, const uint8_t *, size_t, const uint8_t *, size_t,
                              const uint8_t *, const uint8_t *, int),
    size_t (*prepare_prefix)(uint8_t *, const uint8_t *, size_t, const uint8_t *, size_t, int)) {
    uint8_t pre[MLDSA_DOMAIN_SEPARATION_MAX_BYTES];
    size_t pre_len;

    if (!signature || !signature_len || !secret_key || !seed || seed_len != MLDSA_RNDBYTES ||
        !signature_internal || !prepare_prefix || expected_signature_len == 0 ||
        (message_len > 0 && !message)) {
        return PQ_ERROR_BUFFER;
    }

    /*
     * mldsa-native's signature_internal is lower-level than the public pure
     * ML-DSA signing API. It expects the FIPS 204 domain-separation prefix explicitly. Passing
     * NULL/0 signs CRH(tr, message) instead of CRH(tr, 0x00 || ctxlen || ctx || message),
     * which produces signatures that do not verify through the public pure-ML-DSA API
     * and do not match ACVP/KAT sigGen vectors.
     */
    pre_len = prepare_prefix(pre, NULL, 0, NULL, 0, MLDSA_PREHASH_NONE);
    if (pre_len == 0) {
        *signature_len = 0;
        return PQ_ERROR_SIGN;
    }

    if (signature_internal(signature, message, message_len, pre, pre_len, seed, secret_key, 0) !=
        0) {
        *signature_len = 0;
        return PQ_ERROR_SIGN;
    }

    *signature_len = expected_signature_len;
    return PQ_SUCCESS;
}

int pq_mldsa44_keypair_from_seed(uint8_t *public_key, uint8_t *secret_key, const uint8_t *seed32) {
    if (!public_key || !secret_key || !seed32) {
        return PQ_ERROR_BUFFER;
    }
    return pqcr_mldsa44_keypair_internal(public_key, secret_key, seed32) == 0 ? PQ_SUCCESS
                                                                              : PQ_ERROR_KEYPAIR;
}

int pq_mldsa_keypair_from_seed(uint8_t *public_key, uint8_t *secret_key, const uint8_t *seed32) {
    if (!public_key || !secret_key || !seed32) {
        return PQ_ERROR_BUFFER;
    }
    return pqcr_mldsa65_keypair_internal(public_key, secret_key, seed32) == 0 ? PQ_SUCCESS
                                                                              : PQ_ERROR_KEYPAIR;
}

int pq_mldsa87_keypair_from_seed(uint8_t *public_key, uint8_t *secret_key, const uint8_t *seed32) {
    if (!public_key || !secret_key || !seed32) {
        return PQ_ERROR_BUFFER;
    }
    return pqcr_mldsa87_keypair_internal(public_key, secret_key, seed32) == 0 ? PQ_SUCCESS
                                                                              : PQ_ERROR_KEYPAIR;
}

int pq_testing_mldsa_keypair_from_seed(uint8_t *public_key, uint8_t *secret_key,
                                       const uint8_t *seed, size_t seed_len) {
    if (seed_len != MLDSA_SEEDBYTES) {
        return PQ_ERROR_BUFFER;
    }
    return pq_mldsa_keypair_from_seed(public_key, secret_key, seed);
}

int pq_testing_mldsa44_keypair_from_seed(uint8_t *public_key, uint8_t *secret_key,
                                         const uint8_t *seed, size_t seed_len) {
    if (seed_len != MLDSA_SEEDBYTES) {
        return PQ_ERROR_BUFFER;
    }
    return pq_mldsa44_keypair_from_seed(public_key, secret_key, seed);
}

int pq_testing_mldsa87_keypair_from_seed(uint8_t *public_key, uint8_t *secret_key,
                                         const uint8_t *seed, size_t seed_len) {
    if (seed_len != MLDSA_SEEDBYTES) {
        return PQ_ERROR_BUFFER;
    }
    return pq_mldsa87_keypair_from_seed(public_key, secret_key, seed);
}

int pq_testing_mldsa_sign_from_seed(uint8_t *signature, size_t *signature_len,
                                    const uint8_t *message, size_t message_len,
                                    const uint8_t *secret_key, const uint8_t *seed,
                                    size_t seed_len) {
    return pq_testing_mldsa_sign_from_seed_with(
        signature, signature_len, message, message_len, secret_key, seed, seed_len, MLDSA65_BYTES,
        pqcr_mldsa65_signature_internal, pqcr_mldsa65_prepare_domain_separation_prefix);
}

int pq_testing_mldsa44_sign_from_seed(uint8_t *signature, size_t *signature_len,
                                      const uint8_t *message, size_t message_len,
                                      const uint8_t *secret_key, const uint8_t *seed,
                                      size_t seed_len) {
    return pq_testing_mldsa_sign_from_seed_with(
        signature, signature_len, message, message_len, secret_key, seed, seed_len, MLDSA44_BYTES,
        pqcr_mldsa44_signature_internal, pqcr_mldsa44_prepare_domain_separation_prefix);
}

int pq_testing_mldsa87_sign_from_seed(uint8_t *signature, size_t *signature_len,
                                      const uint8_t *message, size_t message_len,
                                      const uint8_t *secret_key, const uint8_t *seed,
                                      size_t seed_len) {
    return pq_testing_mldsa_sign_from_seed_with(
        signature, signature_len, message, message_len, secret_key, seed, seed_len, MLDSA87_BYTES,
        pqcr_mldsa87_signature_internal, pqcr_mldsa87_prepare_domain_separation_prefix);
}

int pq_hybrid_kem_keypair(uint8_t *public_key, uint8_t *secret_key) {
    hybrid_public_key_t pk;
    hybrid_expanded_secret_key_t expanded;
    uint8_t seed[HYBRID_SECRETKEYBYTES];
    int ret = PQ_SUCCESS;

    if (!public_key || !secret_key) {
        return PQ_ERROR_BUFFER;
    }

    memset(&pk, 0, sizeof(pk));
    memset(&expanded, 0, sizeof(expanded));
    memset(seed, 0, sizeof(seed));

    if (RAND_bytes(seed, sizeof(seed)) != 1) {
        ret = PQ_ERROR_RANDOM;
        goto cleanup;
    }

    ret = xwing_expand_secret_key(&expanded, seed);
    if (ret != PQ_SUCCESS) {
        goto cleanup;
    }

    memcpy(pk.mlkem_pk, expanded.mlkem_pk, MLKEM_PUBLICKEYBYTES);
    memcpy(pk.x25519_pk, expanded.x25519_pk, X25519_PUBLICKEYBYTES);
    memcpy(public_key, &pk, HYBRID_PUBLICKEYBYTES);
    memcpy(secret_key, seed, HYBRID_SECRETKEYBYTES);

cleanup:
    pq_secure_wipe(seed, sizeof(seed));
    pq_secure_wipe(&expanded, sizeof(expanded));
    return ret;
}

int pq_hybrid_kem_encapsulate(uint8_t *ciphertext, uint8_t *shared_secret,
                              const uint8_t *public_key) {
    hybrid_public_key_t pk;
    hybrid_ciphertext_t ct;
    uint8_t mlkem_ss[MLKEM_SHAREDSECRETBYTES];
    uint8_t x25519_ss[X25519_SHAREDSECRETBYTES];
    int ret = PQ_SUCCESS;

    if (!ciphertext || !shared_secret || !public_key) {
        return PQ_ERROR_BUFFER;
    }

    memcpy(&pk, public_key, HYBRID_PUBLICKEYBYTES);
    memset(&ct, 0, sizeof(ct));
    memset(mlkem_ss, 0, sizeof(mlkem_ss));
    memset(x25519_ss, 0, sizeof(x25519_ss));

    if (pqcr_mlkem768_enc(ct.mlkem_ct, mlkem_ss, pk.mlkem_pk) != 0) {
        ret = PQ_ERROR_ENCAPSULATE;
        goto cleanup;
    }

    ret = x25519_ephemeral_keypair_and_shared_secret(ct.x25519_ephemeral, x25519_ss, pk.x25519_pk);
    if (ret != PQ_SUCCESS) {
        ret = PQ_ERROR_ENCAPSULATE;
        goto cleanup;
    }

    ret = xwing_combiner(shared_secret, mlkem_ss, x25519_ss, ct.x25519_ephemeral, pk.x25519_pk);
    if (ret != PQ_SUCCESS) {
        goto cleanup;
    }

    memcpy(ciphertext, &ct, HYBRID_CIPHERTEXTBYTES);

cleanup:
    pq_secure_wipe(mlkem_ss, sizeof(mlkem_ss));
    pq_secure_wipe(x25519_ss, sizeof(x25519_ss));
    return ret;
}

int pq_hybrid_kem_expand_secret_key(uint8_t *expanded_secret_key, const uint8_t *secret_key) {
    hybrid_expanded_secret_key_t expanded;
    int ret;

    if (!expanded_secret_key || !secret_key) {
        return PQ_ERROR_BUFFER;
    }

    memset(&expanded, 0, sizeof(expanded));
    ret = xwing_expand_secret_key(&expanded, secret_key);
    if (ret == PQ_SUCCESS) {
        memcpy(expanded_secret_key, &expanded, sizeof(expanded));
    }
    pq_secure_wipe(&expanded, sizeof(expanded));
    return ret == PQ_SUCCESS ? PQ_SUCCESS : PQ_ERROR_DECAPSULATE;
}

int pq_hybrid_kem_decapsulate_expanded(uint8_t *shared_secret, const uint8_t *ciphertext,
                                       const uint8_t *expanded_secret_key) {
    hybrid_ciphertext_t ct;
    const hybrid_expanded_secret_key_t *expanded;
    uint8_t mlkem_ss[MLKEM_SHAREDSECRETBYTES];
    uint8_t x25519_ss[X25519_SHAREDSECRETBYTES];
    int ret = PQ_SUCCESS;

    if (!shared_secret || !ciphertext || !expanded_secret_key) {
        return PQ_ERROR_BUFFER;
    }

    expanded = (const hybrid_expanded_secret_key_t *)expanded_secret_key;
    memcpy(&ct, ciphertext, HYBRID_CIPHERTEXTBYTES);
    memset(mlkem_ss, 0, sizeof(mlkem_ss));
    memset(x25519_ss, 0, sizeof(x25519_ss));

    if (pqcr_mlkem768_dec(mlkem_ss, ct.mlkem_ct, expanded->mlkem_sk) != 0) {
        ret = PQ_ERROR_DECAPSULATE;
        goto cleanup;
    }

    ret = x25519_shared_secret(x25519_ss, ct.x25519_ephemeral, expanded->x25519_sk);
    if (ret != PQ_SUCCESS) {
        ret = PQ_ERROR_DECAPSULATE;
        goto cleanup;
    }

    ret = xwing_combiner(shared_secret, mlkem_ss, x25519_ss, ct.x25519_ephemeral,
                         expanded->x25519_pk);

cleanup:
    pq_secure_wipe(mlkem_ss, sizeof(mlkem_ss));
    pq_secure_wipe(x25519_ss, sizeof(x25519_ss));
    return ret;
}

int pq_hybrid_kem_decapsulate_expanded_pkey(uint8_t *shared_secret, const uint8_t *ciphertext,
                                            const uint8_t *expanded_secret_key,
                                            void *x25519_private_pkey) {
    hybrid_ciphertext_t ct;
    const hybrid_expanded_secret_key_t *expanded;
    uint8_t mlkem_ss[MLKEM_SHAREDSECRETBYTES];
    uint8_t x25519_ss[X25519_SHAREDSECRETBYTES];
    int ret = PQ_SUCCESS;

    if (!shared_secret || !ciphertext || !expanded_secret_key || !x25519_private_pkey) {
        return PQ_ERROR_BUFFER;
    }

    expanded = (const hybrid_expanded_secret_key_t *)expanded_secret_key;
    memcpy(&ct, ciphertext, HYBRID_CIPHERTEXTBYTES);
    memset(mlkem_ss, 0, sizeof(mlkem_ss));
    memset(x25519_ss, 0, sizeof(x25519_ss));

    if (pqcr_mlkem768_dec(mlkem_ss, ct.mlkem_ct, expanded->mlkem_sk) != 0) {
        ret = PQ_ERROR_DECAPSULATE;
        goto cleanup;
    }

    ret = x25519_shared_secret_with_pkey(x25519_ss, ct.x25519_ephemeral,
                                         (EVP_PKEY *)x25519_private_pkey);
    if (ret != PQ_SUCCESS) {
        ret = PQ_ERROR_DECAPSULATE;
        goto cleanup;
    }

    ret = xwing_combiner(shared_secret, mlkem_ss, x25519_ss, ct.x25519_ephemeral,
                         expanded->x25519_pk);

cleanup:
    pq_secure_wipe(mlkem_ss, sizeof(mlkem_ss));
    pq_secure_wipe(x25519_ss, sizeof(x25519_ss));
    return ret;
}

int pq_hybrid_kem_decapsulate(uint8_t *shared_secret, const uint8_t *ciphertext,
                              const uint8_t *secret_key) {
    uint8_t expanded[HYBRID_EXPANDED_SECRETKEYBYTES];
    int ret;

    if (!shared_secret || !ciphertext || !secret_key) {
        return PQ_ERROR_BUFFER;
    }

    memset(expanded, 0, sizeof(expanded));
    ret = pq_hybrid_kem_expand_secret_key(expanded, secret_key);
    if (ret != PQ_SUCCESS) {
        goto cleanup;
    }

    ret = pq_hybrid_kem_decapsulate_expanded(shared_secret, ciphertext, expanded);

cleanup:
    pq_secure_wipe(expanded, sizeof(expanded));
    return ret;
}

#define PQC_SERIALIZATION_MAGIC_0     'P'
#define PQC_SERIALIZATION_MAGIC_1     'Q'
#define PQC_SERIALIZATION_MAGIC_2     'C'
#define PQC_SERIALIZATION_MAGIC_3     '1'
#define PQC_SERIALIZATION_VERSION     0x01
#define PQC_SERIALIZATION_TYPE_PUBLIC 0x01
#define PQC_SERIALIZATION_TYPE_SECRET 0x02

static const char PQC_OID_ML_KEM_768[] = "2.25.186599352125448088867056807454444238446";

static const char PQC_OID_ML_KEM_768_X25519_XWING[] = "1.3.6.1.4.1.62253.25722";
static const char PQC_OID_ML_DSA_65[] = "2.25.305232938483772195555080795650659207792";
static const char PQC_PUBLIC_KEY_PEM_LABEL[] = "PQC PUBLIC KEY CONTAINER";
static const char PQC_PRIVATE_KEY_PEM_LABEL[] = "PQC PRIVATE KEY CONTAINER";

typedef struct {
    const char *algorithm;
    const char *oid;
    size_t public_key_len;
    size_t secret_key_len;
} pq_serialization_algorithm_t;

static const pq_serialization_algorithm_t PQC_SERIALIZATION_ALGORITHMS[] = {
    {"ml_kem_768", PQC_OID_ML_KEM_768, PQ_MLKEM_PUBLICKEYBYTES, PQ_MLKEM_SECRETKEYBYTES},
    {"ml_kem_768_x25519_xwing", PQC_OID_ML_KEM_768_X25519_XWING, PQ_HYBRID_PUBLICKEYBYTES,
     PQ_HYBRID_SECRETKEYBYTES},
    {"ml_dsa_65", PQC_OID_ML_DSA_65, MLDSA_PUBLICKEYBYTES, MLDSA_SECRETKEYBYTES},
};

static const pq_serialization_algorithm_t *pq_find_serialization_algorithm(const char *algorithm) {
    size_t i;

    if (!algorithm)
        return NULL;

    for (i = 0; i < sizeof(PQC_SERIALIZATION_ALGORITHMS) / sizeof(PQC_SERIALIZATION_ALGORITHMS[0]);
         ++i) {
        if (strcmp(algorithm, PQC_SERIALIZATION_ALGORITHMS[i].algorithm) == 0)
            return &PQC_SERIALIZATION_ALGORITHMS[i];
    }

    return NULL;
}

static const pq_serialization_algorithm_t *pq_find_serialization_algorithm_by_oid(const char *oid,
                                                                                  size_t oid_len) {
    size_t i;

    if (!oid)
        return NULL;

    for (i = 0; i < sizeof(PQC_SERIALIZATION_ALGORITHMS) / sizeof(PQC_SERIALIZATION_ALGORITHMS[0]);
         ++i) {
        const pq_serialization_algorithm_t *entry = &PQC_SERIALIZATION_ALGORITHMS[i];
        if (oid_len == strlen(entry->oid) && memcmp(oid, entry->oid, oid_len) == 0)
            return entry;
    }

    return NULL;
}

static int pq_encode_serialized_key(uint8_t **output, size_t *output_len, uint8_t type,
                                    const uint8_t *key_bytes, size_t key_len,
                                    const char *algorithm) {
    const pq_serialization_algorithm_t *entry;
    size_t expected_len;
    size_t oid_len;
    size_t total_len = 0;
    uint8_t *buf;
    int ret;

    if (!output || !output_len || !key_bytes || !algorithm)
        return PQ_ERROR_BUFFER;

    *output = NULL;
    *output_len = 0;

    entry = pq_find_serialization_algorithm(algorithm);
    if (!entry)
        return PQ_ERROR_BUFFER;

    expected_len =
        (type == PQC_SERIALIZATION_TYPE_PUBLIC) ? entry->public_key_len : entry->secret_key_len;
    if (key_len != expected_len)
        return PQ_ERROR_BUFFER;

    oid_len = strlen(entry->oid);
    if (oid_len == 0 || oid_len > UINT16_MAX)
        return PQ_ERROR_BUFFER;
    if (key_len > UINT32_MAX)
        return PQ_ERROR_BUFFER;

    ret = pq_size_add(total_len, 4, &total_len);
    if (ret != PQ_SUCCESS)
        return ret;
    ret = pq_size_add(total_len, 1 + 1 + 2, &total_len);
    if (ret != PQ_SUCCESS)
        return ret;
    ret = pq_size_add(total_len, oid_len, &total_len);
    if (ret != PQ_SUCCESS)
        return ret;
    ret = pq_size_add(total_len, 4, &total_len);
    if (ret != PQ_SUCCESS)
        return ret;
    ret = pq_size_add(total_len, key_len, &total_len);
    if (ret != PQ_SUCCESS)
        return ret;

    buf = malloc(total_len);
    if (!buf)
        return PQ_ERROR_NOMEM;

    buf[0] = PQC_SERIALIZATION_MAGIC_0;
    buf[1] = PQC_SERIALIZATION_MAGIC_1;
    buf[2] = PQC_SERIALIZATION_MAGIC_2;
    buf[3] = PQC_SERIALIZATION_MAGIC_3;
    buf[4] = PQC_SERIALIZATION_VERSION;
    buf[5] = type;
    buf[6] = (uint8_t)((oid_len >> 8) & 0xFF);
    buf[7] = (uint8_t)(oid_len & 0xFF);
    memcpy(buf + 8, entry->oid, oid_len);
    buf[8 + oid_len + 0] = (uint8_t)((key_len >> 24) & 0xFF);
    buf[8 + oid_len + 1] = (uint8_t)((key_len >> 16) & 0xFF);
    buf[8 + oid_len + 2] = (uint8_t)((key_len >> 8) & 0xFF);
    buf[8 + oid_len + 3] = (uint8_t)(key_len & 0xFF);
    memcpy(buf + 8 + oid_len + 4, key_bytes, key_len);

    *output = buf;
    *output_len = total_len;
    return PQ_SUCCESS;
}

static int pq_decode_serialized_key(const uint8_t *input, size_t input_len, uint8_t expected_type,
                                    char **algorithm_out, uint8_t **key_out, size_t *key_len_out) {
    uint16_t oid_len;
    uint32_t key_len;
    const pq_serialization_algorithm_t *entry;
    size_t offset;
    size_t expected_len = 0;
    uint8_t *key_copy = NULL;
    char *algorithm_copy = NULL;

    if (!input || !algorithm_out || !key_out || !key_len_out)
        return PQ_ERROR_BUFFER;

    *algorithm_out = NULL;
    *key_out = NULL;
    *key_len_out = 0;

    if (input_len < 12)
        return PQ_ERROR_BUFFER;
    if (input[0] != PQC_SERIALIZATION_MAGIC_0 || input[1] != PQC_SERIALIZATION_MAGIC_1 ||
        input[2] != PQC_SERIALIZATION_MAGIC_2 || input[3] != PQC_SERIALIZATION_MAGIC_3) {
        return PQ_ERROR_BUFFER;
    }
    if (input[4] != PQC_SERIALIZATION_VERSION || input[5] != expected_type)
        return PQ_ERROR_BUFFER;

    oid_len = ((uint16_t)input[6] << 8) | (uint16_t)input[7];
    if (oid_len == 0)
        return PQ_ERROR_BUFFER;
    offset = 8;
    if (input_len < offset || input_len - offset < (size_t)oid_len + 4)
        return PQ_ERROR_BUFFER;
    entry = pq_find_serialization_algorithm_by_oid((const char *)(input + offset), oid_len);
    if (!entry)
        return PQ_ERROR_BUFFER;
    offset += oid_len;
    key_len = ((uint32_t)input[offset + 0] << 24) | ((uint32_t)input[offset + 1] << 16) |
              ((uint32_t)input[offset + 2] << 8) | (uint32_t)input[offset + 3];
    offset += 4;
    if (input_len < offset || input_len - offset != (size_t)key_len)
        return PQ_ERROR_BUFFER;
    expected_len = (expected_type == PQC_SERIALIZATION_TYPE_PUBLIC) ? entry->public_key_len
                                                                    : entry->secret_key_len;
    if ((size_t)key_len != expected_len)
        return PQ_ERROR_BUFFER;

    key_copy = malloc((size_t)key_len);
    if (!key_copy)
        return PQ_ERROR_NOMEM;
    memcpy(key_copy, input + offset, (size_t)key_len);

    {
        size_t algorithm_len = strlen(entry->algorithm);
        algorithm_copy = malloc(algorithm_len + 1);
        if (!algorithm_copy) {
            pq_secure_wipe(key_copy, (size_t)key_len);
            free(key_copy);
            return PQ_ERROR_NOMEM;
        }
        memcpy(algorithm_copy, entry->algorithm, algorithm_len + 1);
    }

    *algorithm_out = algorithm_copy;
    *key_out = key_copy;
    *key_len_out = (size_t)key_len;
    return PQ_SUCCESS;
}

static int pq_base64_char_value(unsigned char c) {
    if (c >= 'A' && c <= 'Z')
        return (int)(c - 'A');
    if (c >= 'a' && c <= 'z')
        return (int)(c - 'a' + 26);
    if (c >= '0' && c <= '9')
        return (int)(c - '0' + 52);
    if (c == '+')
        return 62;
    if (c == '/')
        return 63;
    if (c == '=')
        return 64;
    return -1;
}

static const char *pq_find_pem_footer(const char *start, size_t len, const char *footer,
                                      size_t footer_len) {
    if (!start || !footer || footer_len == 0 || len < footer_len)
        return NULL;

    for (size_t i = 0; i <= len - footer_len; ++i) {
        if (start[i] == '-' && memcmp(start + i, footer, footer_len) == 0)
            return start + i;
    }
    return NULL;
}

static int pq_der_to_pem(const char *label, const uint8_t *der, size_t der_len, char **output,
                         size_t *output_len) {
    char header[64];
    char footer[64];
    int header_len, footer_len;
    char *pem = NULL;
    unsigned char *encoded = NULL;
    size_t encoded_len;
    size_t line_count;
    size_t needed;
    char *cur;

    if (!label || !der || !output || !output_len)
        return PQ_ERROR_BUFFER;
    *output = NULL;
    *output_len = 0;

    header_len = snprintf(header, sizeof(header), "-----BEGIN %s-----", label);
    footer_len = snprintf(footer, sizeof(footer), "-----END %s-----", label);
    if (header_len <= 0 || footer_len <= 0)
        return PQ_ERROR_BUFFER;
    if (der_len > (size_t)INT_MAX)
        return PQ_ERROR_BUFFER;

    encoded_len = 4 * ((der_len + 2) / 3);
    if (encoded_len > (size_t)INT_MAX)
        return PQ_ERROR_BUFFER;

    encoded = malloc(encoded_len + 1);
    if (!encoded)
        return PQ_ERROR_NOMEM;

    if (EVP_EncodeBlock(encoded, der, (int)der_len) != (int)encoded_len) {
        pq_secure_wipe(encoded, encoded_len + 1);
        free(encoded);
        return PQ_ERROR_OPENSSL;
    }

    line_count = encoded_len == 0 ? 0 : ((encoded_len + 63) / 64);
    if (SIZE_MAX - (size_t)header_len < 1 || SIZE_MAX - ((size_t)header_len + 1) < encoded_len ||
        SIZE_MAX - ((size_t)header_len + 1 + encoded_len) < line_count ||
        SIZE_MAX - ((size_t)header_len + 1 + encoded_len + line_count) < (size_t)footer_len + 1) {
        pq_secure_wipe(encoded, encoded_len + 1);
        free(encoded);
        return PQ_ERROR_BUFFER;
    }
    needed = (size_t)header_len + 1 + encoded_len + line_count + (size_t)footer_len + 1;

    pem = malloc(needed);
    if (!pem) {
        pq_secure_wipe(encoded, encoded_len + 1);
        free(encoded);
        return PQ_ERROR_NOMEM;
    }

    cur = pem;
    memcpy(cur, header, (size_t)header_len);
    cur += header_len;
    *cur++ = '\n';

    for (size_t offset = 0; offset < encoded_len; offset += 64) {
        size_t line_len = encoded_len - offset;
        if (line_len > 64)
            line_len = 64;
        memcpy(cur, encoded + offset, line_len);
        cur += line_len;
        *cur++ = '\n';
    }

    memcpy(cur, footer, (size_t)footer_len);
    cur += footer_len;
    *cur = '\0';

    *output = pem;
    *output_len = (size_t)(cur - pem);
    pq_secure_wipe(encoded, encoded_len + 1);
    free(encoded);
    return PQ_SUCCESS;
}

static int pq_pem_to_der(const char *label, const char *input, size_t input_len, uint8_t **der_out,
                         size_t *der_len_out) {
    char header[64], footer[64];
    int header_len, footer_len;
    const char *body_start, *footer_pos;
    const char *tail;
    uint8_t *der = NULL;
    unsigned char *compact = NULL;
    size_t body_len = 0;
    size_t compact_len = 0;
    size_t der_cap = 0;
    int decoded_len = 0;
    int padding = 0;
    int saw_padding = 0;

    if (!label || !input || !der_out || !der_len_out)
        return PQ_ERROR_BUFFER;
    *der_out = NULL;
    *der_len_out = 0;

    header_len = snprintf(header, sizeof(header), "-----BEGIN %s-----", label);
    footer_len = snprintf(footer, sizeof(footer), "-----END %s-----", label);
    if (header_len <= 0 || footer_len <= 0)
        return PQ_ERROR_BUFFER;
    if (input_len < (size_t)(header_len + footer_len + 2))
        return PQ_ERROR_BUFFER;
    if (strncmp(input, header, (size_t)header_len) != 0)
        return PQ_ERROR_BUFFER;

    body_start = input + header_len;
    while ((size_t)(body_start - input) < input_len && pq_is_pem_whitespace(*body_start))
        body_start++;

    footer_pos = pq_find_pem_footer(body_start, input_len - (size_t)(body_start - input), footer,
                                    (size_t)footer_len);
    if (!footer_pos)
        return PQ_ERROR_BUFFER;

    tail = footer_pos + footer_len;
    while ((size_t)(tail - input) < input_len) {
        if (!pq_is_pem_whitespace(*tail))
            return PQ_ERROR_BUFFER;
        tail++;
    }

    body_len = (size_t)(footer_pos - body_start);
    if (body_len > (size_t)INT_MAX)
        return PQ_ERROR_BUFFER;

    compact = malloc(body_len ? body_len : 1);
    if (!compact)
        return PQ_ERROR_NOMEM;

    for (size_t i = 0; i < body_len; ++i) {
        unsigned char c = (unsigned char)body_start[i];
        int value;
        if (pq_is_pem_whitespace((char)c))
            continue;

        value = pq_base64_char_value(c);
        if (value < 0) {
            pq_secure_wipe(compact, body_len);
            free(compact);
            return PQ_ERROR_BUFFER;
        }
        if (c == '=') {
            saw_padding = 1;
            padding++;
            if (padding > 2) {
                pq_secure_wipe(compact, body_len);
                free(compact);
                return PQ_ERROR_BUFFER;
            }
        } else if (saw_padding) {
            pq_secure_wipe(compact, body_len);
            free(compact);
            return PQ_ERROR_BUFFER;
        }
        compact[compact_len++] = c;
    }

    if (compact_len == 0 || (compact_len % 4) != 0 || compact_len > (size_t)INT_MAX) {
        pq_secure_wipe(compact, body_len);
        free(compact);
        return PQ_ERROR_BUFFER;
    }

    der_cap = (compact_len / 4) * 3;
    der = malloc(der_cap ? der_cap : 1);
    if (!der) {
        pq_secure_wipe(compact, body_len);
        free(compact);
        return PQ_ERROR_NOMEM;
    }

    decoded_len = EVP_DecodeBlock(der, compact, (int)compact_len);
    pq_secure_wipe(compact, body_len);
    free(compact);
    compact = NULL;
    if (decoded_len <= 0 || decoded_len < padding) {
        pq_secure_wipe(der, der_cap);
        free(der);
        return PQ_ERROR_BUFFER;
    }

    *der_len_out = (size_t)(decoded_len - padding);
    *der_out = der;
    return PQ_SUCCESS;
}

int pq_public_key_to_pqc_container_der(uint8_t **output, size_t *output_len,
                                       const uint8_t *public_key, size_t public_key_len,
                                       const char *algorithm) {
    return pq_encode_serialized_key(output, output_len, PQC_SERIALIZATION_TYPE_PUBLIC, public_key,
                                    public_key_len, algorithm);
}

int pq_public_key_to_pqc_container_pem(char **output, size_t *output_len, const uint8_t *public_key,
                                       size_t public_key_len, const char *algorithm) {
    uint8_t *der = NULL;
    size_t der_len = 0;
    int ret;
    ret = pq_public_key_to_pqc_container_der(&der, &der_len, public_key, public_key_len, algorithm);
    if (ret != PQ_SUCCESS)
        return ret;
    ret = pq_der_to_pem(PQC_PUBLIC_KEY_PEM_LABEL, der, der_len, output, output_len);
    pq_secure_wipe(der, der_len);
    free(der);
    return ret;
}

int pq_secret_key_to_pqc_container_der(uint8_t **output, size_t *output_len,
                                       const uint8_t *secret_key, size_t secret_key_len,
                                       const char *algorithm) {
    return pq_encode_serialized_key(output, output_len, PQC_SERIALIZATION_TYPE_SECRET, secret_key,
                                    secret_key_len, algorithm);
}

int pq_secret_key_to_pqc_container_pem(char **output, size_t *output_len, const uint8_t *secret_key,
                                       size_t secret_key_len, const char *algorithm) {
    uint8_t *der = NULL;
    size_t der_len = 0;
    int ret;
    ret = pq_secret_key_to_pqc_container_der(&der, &der_len, secret_key, secret_key_len, algorithm);
    if (ret != PQ_SUCCESS)
        return ret;
    ret = pq_der_to_pem(PQC_PRIVATE_KEY_PEM_LABEL, der, der_len, output, output_len);
    pq_secure_wipe(der, der_len);
    free(der);
    return ret;
}

int pq_public_key_from_pqc_container_der(char **algorithm_out, uint8_t **key_out,
                                         size_t *key_len_out, const uint8_t *input,
                                         size_t input_len) {
    return pq_decode_serialized_key(input, input_len, PQC_SERIALIZATION_TYPE_PUBLIC, algorithm_out,
                                    key_out, key_len_out);
}

int pq_public_key_from_pqc_container_pem(char **algorithm_out, uint8_t **key_out,
                                         size_t *key_len_out, const char *input, size_t input_len) {
    uint8_t *der = NULL;
    size_t der_len = 0;
    int ret;
    ret = pq_pem_to_der(PQC_PUBLIC_KEY_PEM_LABEL, input, input_len, &der, &der_len);
    if (ret != PQ_SUCCESS)
        return ret;
    ret = pq_public_key_from_pqc_container_der(algorithm_out, key_out, key_len_out, der, der_len);
    pq_secure_wipe(der, der_len);
    free(der);
    return ret;
}

int pq_secret_key_from_pqc_container_der(char **algorithm_out, uint8_t **key_out,
                                         size_t *key_len_out, const uint8_t *input,
                                         size_t input_len) {
    return pq_decode_serialized_key(input, input_len, PQC_SERIALIZATION_TYPE_SECRET, algorithm_out,
                                    key_out, key_len_out);
}

int pq_secret_key_from_pqc_container_pem(char **algorithm_out, uint8_t **key_out,
                                         size_t *key_len_out, const char *input, size_t input_len) {
    uint8_t *der = NULL;
    size_t der_len = 0;
    int ret;
    ret = pq_pem_to_der(PQC_PRIVATE_KEY_PEM_LABEL, input, input_len, &der, &der_len);
    if (ret != PQ_SUCCESS)
        return ret;
    ret = pq_secret_key_from_pqc_container_der(algorithm_out, key_out, key_len_out, der, der_len);
    pq_secure_wipe(der, der_len);
    free(der);
    return ret;
}

#define PQ_PKCS8_PRIVATE_KEY_PEM_LABEL           "PRIVATE KEY"
#define PQ_PKCS8_ENCRYPTED_PRIVATE_KEY_PEM_LABEL "ENCRYPTED PRIVATE KEY"

static size_t pq_der_length_octets(size_t len) {
    size_t octets = 0;
    size_t v = len;

    if (len < 0x80)
        return 1;
    do {
        octets++;
        v >>= 8;
    } while (v != 0);
    return 1 + octets;
}

static int pq_der_write_length(uint8_t **cursor, size_t len) {
    uint8_t *p;
    size_t octets = 0;
    size_t v = len;

    if (!cursor || !*cursor)
        return PQ_ERROR_BUFFER;

    p = *cursor;
    if (len < 0x80) {
        *p++ = (uint8_t)len;
        *cursor = p;
        return PQ_SUCCESS;
    }

    do {
        octets++;
        v >>= 8;
    } while (v != 0);
    if (octets > sizeof(size_t))
        return PQ_ERROR_BUFFER;

    *p++ = (uint8_t)(0x80u | (uint8_t)octets);
    for (size_t i = 0; i < octets; ++i) {
        size_t shift = 8 * (octets - 1 - i);
        *p++ = (uint8_t)((len >> shift) & 0xffu);
    }
    *cursor = p;
    return PQ_SUCCESS;
}

static int pq_der_read_length(const uint8_t *input, size_t input_len, size_t *offset,
                              size_t *len_out) {
    uint8_t first;
    size_t len = 0;
    size_t length_octets;

    if (!input || !offset || !len_out || *offset >= input_len)
        return PQ_ERROR_BUFFER;

    first = input[(*offset)++];
    if (first < 0x80) {
        *len_out = (size_t)first;
        return PQ_SUCCESS;
    }

    length_octets = (size_t)(first & 0x7fu);
    if (length_octets == 0 || length_octets > sizeof(size_t))
        return PQ_ERROR_BUFFER;
    if (input_len - *offset < length_octets)
        return PQ_ERROR_BUFFER;
    if (input[*offset] == 0)
        return PQ_ERROR_BUFFER;

    for (size_t i = 0; i < length_octets; ++i) {
        if (len > (SIZE_MAX >> 8))
            return PQ_ERROR_BUFFER;
        len = (len << 8) | (size_t)input[*offset + i];
    }
    if (len < 0x80)
        return PQ_ERROR_BUFFER;

    *offset += length_octets;
    *len_out = len;
    return PQ_SUCCESS;
}

static int pq_der_expect_tlv(const uint8_t *input, size_t input_len, size_t *offset,
                             uint8_t expected_tag, size_t *value_offset_out,
                             size_t *value_len_out) {
    size_t value_len;
    size_t value_offset;

    if (!input || !offset || !value_offset_out || !value_len_out || *offset >= input_len)
        return PQ_ERROR_BUFFER;
    if (input[(*offset)++] != expected_tag)
        return PQ_ERROR_BUFFER;
    if (pq_der_read_length(input, input_len, offset, &value_len) != PQ_SUCCESS)
        return PQ_ERROR_BUFFER;
    value_offset = *offset;
    if (input_len - value_offset < value_len)
        return PQ_ERROR_BUFFER;
    *offset = value_offset + value_len;
    *value_offset_out = value_offset;
    *value_len_out = value_len;
    return PQ_SUCCESS;
}

static int pq_oid_text_to_der(const char *oid_text, uint8_t **oid_der_out,
                              size_t *oid_der_len_out) {
    ASN1_OBJECT *obj = NULL;
    uint8_t *der = NULL;
    unsigned char *cursor;
    int der_len;
    int ret = PQ_ERROR_OPENSSL;

    if (!oid_text || !oid_der_out || !oid_der_len_out)
        return PQ_ERROR_BUFFER;
    *oid_der_out = NULL;
    *oid_der_len_out = 0;

    obj = OBJ_txt2obj(oid_text, 1);
    if (!obj)
        goto cleanup;
    der_len = i2d_ASN1_OBJECT(obj, NULL);
    if (der_len <= 0)
        goto cleanup;
    der = malloc((size_t)der_len);
    if (!der) {
        ret = PQ_ERROR_NOMEM;
        goto cleanup;
    }
    cursor = der;
    if (i2d_ASN1_OBJECT(obj, &cursor) != der_len || (size_t)(cursor - der) != (size_t)der_len)
        goto cleanup;

    *oid_der_out = der;
    *oid_der_len_out = (size_t)der_len;
    der = NULL;
    ret = PQ_SUCCESS;

cleanup:
    if (der) {
        pq_secure_wipe(der, (size_t)(der_len > 0 ? der_len : 0));
        free(der);
    }
    if (obj)
        ASN1_OBJECT_free(obj);
    return ret;
}

static int pq_oid_der_to_text(const uint8_t *oid_der, size_t oid_der_len, char **oid_text_out) {
    ASN1_OBJECT *obj = NULL;
    const unsigned char *cursor;
    char tmp[128];
    int text_len;
    char *copy = NULL;
    int ret = PQ_ERROR_OPENSSL;

    if (!oid_der || oid_der_len == 0 || oid_der_len > (size_t)LONG_MAX || !oid_text_out)
        return PQ_ERROR_BUFFER;
    *oid_text_out = NULL;

    cursor = oid_der;
    obj = d2i_ASN1_OBJECT(NULL, &cursor, (long)oid_der_len);
    if (!obj || cursor != oid_der + oid_der_len)
        goto cleanup;
    text_len = OBJ_obj2txt(tmp, sizeof(tmp), obj, 1);
    if (text_len <= 0 || (size_t)text_len >= sizeof(tmp))
        goto cleanup;
    copy = malloc((size_t)text_len + 1);
    if (!copy) {
        ret = PQ_ERROR_NOMEM;
        goto cleanup;
    }
    memcpy(copy, tmp, (size_t)text_len + 1);
    *oid_text_out = copy;
    copy = NULL;
    ret = PQ_SUCCESS;

cleanup:
    if (copy)
        free(copy);
    if (obj)
        ASN1_OBJECT_free(obj);
    return ret;
}

int pq_pkcs8_private_key_info_to_der(uint8_t **output, size_t *output_len, const char *oid_text,
                                     const uint8_t *private_key, size_t private_key_len) {
    uint8_t *oid_der = NULL;
    size_t oid_der_len = 0;
    size_t alg_body_len, alg_len, priv_len, inner_len, total_len;
    uint8_t *buf = NULL;
    uint8_t *cur;
    int ret;

    if (!output || !output_len || !oid_text || !private_key)
        return PQ_ERROR_BUFFER;
    *output = NULL;
    *output_len = 0;

    ret = pq_oid_text_to_der(oid_text, &oid_der, &oid_der_len);
    if (ret != PQ_SUCCESS)
        return ret;

    alg_body_len = oid_der_len;
    alg_len = 1 + pq_der_length_octets(alg_body_len) + alg_body_len;
    priv_len = 1 + pq_der_length_octets(private_key_len) + private_key_len;
    if (pq_size_add(3, alg_len, &inner_len) != PQ_SUCCESS ||
        pq_size_add(inner_len, priv_len, &inner_len) != PQ_SUCCESS) {
        ret = PQ_ERROR_BUFFER;
        goto cleanup;
    }
    if (pq_size_add(1 + pq_der_length_octets(inner_len), inner_len, &total_len) != PQ_SUCCESS) {
        ret = PQ_ERROR_BUFFER;
        goto cleanup;
    }

    buf = malloc(total_len);
    if (!buf) {
        ret = PQ_ERROR_NOMEM;
        goto cleanup;
    }

    cur = buf;
    *cur++ = 0x30;
    ret = pq_der_write_length(&cur, inner_len);
    if (ret != PQ_SUCCESS)
        goto cleanup;
    *cur++ = 0x02;
    *cur++ = 0x01;
    *cur++ = 0x00;
    *cur++ = 0x30;
    ret = pq_der_write_length(&cur, alg_body_len);
    if (ret != PQ_SUCCESS)
        goto cleanup;
    memcpy(cur, oid_der, oid_der_len);
    cur += oid_der_len;
    *cur++ = 0x04;
    ret = pq_der_write_length(&cur, private_key_len);
    if (ret != PQ_SUCCESS)
        goto cleanup;
    memcpy(cur, private_key, private_key_len);
    cur += private_key_len;
    if ((size_t)(cur - buf) != total_len) {
        ret = PQ_ERROR_BUFFER;
        goto cleanup;
    }

    *output = buf;
    *output_len = total_len;
    buf = NULL;
    ret = PQ_SUCCESS;

cleanup:
    if (buf) {
        pq_secure_wipe(buf, total_len);
        free(buf);
    }
    if (oid_der) {
        pq_secure_wipe(oid_der, oid_der_len);
        free(oid_der);
    }
    return ret;
}

int pq_pkcs8_private_key_info_from_der(char **oid_text_out, uint8_t **private_key_out,
                                       size_t *private_key_len_out, const uint8_t *input,
                                       size_t input_len) {
    size_t offset = 0;
    size_t outer_off = 0, outer_len = 0, outer_end;
    size_t alg_off = 0, alg_len = 0, alg_end;
    size_t oid_off = 0, oid_len = 0;
    size_t priv_off = 0, priv_len = 0;
    uint8_t *private_key = NULL;
    char *oid_text = NULL;
    int ret;

    if (!oid_text_out || !private_key_out || !private_key_len_out || !input)
        return PQ_ERROR_BUFFER;
    *oid_text_out = NULL;
    *private_key_out = NULL;
    *private_key_len_out = 0;

    ret = pq_der_expect_tlv(input, input_len, &offset, 0x30, &outer_off, &outer_len);
    if (ret != PQ_SUCCESS)
        return ret;
    outer_end = outer_off + outer_len;
    if (offset != input_len || outer_end != input_len)
        return PQ_ERROR_BUFFER;

    offset = outer_off;
    {
        size_t version_off = 0, version_len = 0;
        ret = pq_der_expect_tlv(input, outer_end, &offset, 0x02, &version_off, &version_len);
        if (ret != PQ_SUCCESS)
            return ret;
        if (version_len != 1 || input[version_off] != 0x00)
            return PQ_ERROR_BUFFER;
    }

    ret = pq_der_expect_tlv(input, outer_end, &offset, 0x30, &alg_off, &alg_len);
    if (ret != PQ_SUCCESS)
        return ret;
    alg_end = alg_off + alg_len;
    {
        size_t alg_cursor = alg_off;
        size_t oid_tlv_start = alg_cursor;
        ret = pq_der_expect_tlv(input, alg_end, &alg_cursor, 0x06, &oid_off, &oid_len);
        if (ret != PQ_SUCCESS)
            return ret;
        if (alg_cursor != alg_end)
            return PQ_ERROR_BUFFER;
        ret = pq_oid_der_to_text(input + oid_tlv_start, alg_cursor - oid_tlv_start, &oid_text);
    }
    if (ret != PQ_SUCCESS)
        return ret;

    ret = pq_der_expect_tlv(input, outer_end, &offset, 0x04, &priv_off, &priv_len);
    if (ret != PQ_SUCCESS)
        goto cleanup;
    if (offset != outer_end) {
        ret = PQ_ERROR_BUFFER;
        goto cleanup;
    }
    private_key = malloc(priv_len ? priv_len : 1);
    if (!private_key) {
        ret = PQ_ERROR_NOMEM;
        goto cleanup;
    }
    if (priv_len)
        memcpy(private_key, input + priv_off, priv_len);

    *oid_text_out = oid_text;
    *private_key_out = private_key;
    *private_key_len_out = priv_len;
    oid_text = NULL;
    private_key = NULL;
    ret = PQ_SUCCESS;

cleanup:
    if (oid_text)
        free(oid_text);
    if (private_key) {
        pq_secure_wipe(private_key, priv_len);
        free(private_key);
    }
    return ret;
}

int pq_pkcs8_encrypt_private_key_info_der(uint8_t **output, size_t *output_len,
                                          const uint8_t *plain_der, size_t plain_der_len,
                                          const char *passphrase, size_t passphrase_len,
                                          int iterations) {
    const unsigned char *cursor;
    PKCS8_PRIV_KEY_INFO *p8 = NULL;
    X509_SIG *encrypted = NULL;
    unsigned char salt[16];
    unsigned char *der = NULL;
    unsigned char *der_cursor;
    int der_len;
    int ret = PQ_ERROR_OPENSSL;

    if (!output || !output_len || !plain_der || !passphrase || iterations <= 0 ||
        passphrase_len > (size_t)INT_MAX || plain_der_len > (size_t)LONG_MAX)
        return PQ_ERROR_BUFFER;
    *output = NULL;
    *output_len = 0;

    cursor = plain_der;
    p8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &cursor, (long)plain_der_len);
    if (!p8 || cursor != plain_der + plain_der_len)
        goto cleanup;
    if (RAND_bytes(salt, sizeof(salt)) != 1)
        goto cleanup;

    encrypted = PKCS8_encrypt(-1, EVP_aes_256_cbc(), passphrase, (int)passphrase_len, salt,
                              (int)sizeof(salt), iterations, p8);
    if (!encrypted)
        goto cleanup;

    der_len = i2d_X509_SIG(encrypted, NULL);
    if (der_len <= 0) {
        ret = PQ_ERROR_OPENSSL;
        goto cleanup;
    }
    der = malloc((size_t)der_len);
    if (!der) {
        ret = PQ_ERROR_NOMEM;
        goto cleanup;
    }
    der_cursor = der;
    if (i2d_X509_SIG(encrypted, &der_cursor) != der_len ||
        (size_t)(der_cursor - der) != (size_t)der_len)
        goto cleanup;

    *output = der;
    *output_len = (size_t)der_len;
    der = NULL;
    ret = PQ_SUCCESS;

cleanup:
    pq_secure_wipe(salt, sizeof(salt));
    if (der) {
        pq_secure_wipe(der, (size_t)(der_len > 0 ? der_len : 0));
        free(der);
    }
    if (encrypted)
        X509_SIG_free(encrypted);
    if (p8)
        PKCS8_PRIV_KEY_INFO_free(p8);
    return ret;
}

int pq_pkcs8_decrypt_private_key_info_der(uint8_t **output, size_t *output_len,
                                          const uint8_t *encrypted_der, size_t encrypted_der_len,
                                          const char *passphrase, size_t passphrase_len) {
    const unsigned char *cursor;
    X509_SIG *encrypted = NULL;
    PKCS8_PRIV_KEY_INFO *p8 = NULL;
    unsigned char *der = NULL;
    unsigned char *der_cursor;
    int der_len;
    int ret = PQ_ERROR_OPENSSL;

    if (!output || !output_len || !encrypted_der || !passphrase ||
        passphrase_len > (size_t)INT_MAX || encrypted_der_len > (size_t)LONG_MAX)
        return PQ_ERROR_BUFFER;
    *output = NULL;
    *output_len = 0;

    cursor = encrypted_der;
    encrypted = d2i_X509_SIG(NULL, &cursor, (long)encrypted_der_len);
    if (!encrypted || cursor != encrypted_der + encrypted_der_len)
        goto cleanup;
    p8 = PKCS8_decrypt(encrypted, passphrase, (int)passphrase_len);
    if (!p8)
        goto cleanup;

    der_len = i2d_PKCS8_PRIV_KEY_INFO(p8, NULL);
    if (der_len <= 0)
        goto cleanup;
    der = malloc((size_t)der_len);
    if (!der) {
        ret = PQ_ERROR_NOMEM;
        goto cleanup;
    }
    der_cursor = der;
    if (i2d_PKCS8_PRIV_KEY_INFO(p8, &der_cursor) != der_len ||
        (size_t)(der_cursor - der) != (size_t)der_len)
        goto cleanup;

    *output = der;
    *output_len = (size_t)der_len;
    der = NULL;
    ret = PQ_SUCCESS;

cleanup:
    if (der) {
        pq_secure_wipe(der, (size_t)(der_len > 0 ? der_len : 0));
        free(der);
    }
    if (p8)
        PKCS8_PRIV_KEY_INFO_free(p8);
    if (encrypted)
        X509_SIG_free(encrypted);
    return ret;
}

int pq_pkcs8_der_is_encrypted_private_key_info(const uint8_t *input, size_t input_len) {
    const unsigned char *cursor;
    X509_SIG *encrypted = NULL;
    const X509_ALGOR *alg = NULL;
    const ASN1_OCTET_STRING *digest = NULL;
    const ASN1_OBJECT *obj = NULL;
    int ptype = 0;
    const void *pval = NULL;
    int ret = 0;

    if (!input || input_len > (size_t)LONG_MAX)
        return 0;
    cursor = input;
    encrypted = d2i_X509_SIG(NULL, &cursor, (long)input_len);
    if (!encrypted || cursor != input + input_len)
        goto cleanup;
    X509_SIG_get0(encrypted, &alg, &digest);
    if (!alg || !digest)
        goto cleanup;
    X509_ALGOR_get0(&obj, &ptype, &pval, alg);
    (void)ptype;
    (void)pval;
    if (obj && OBJ_obj2nid(obj) == NID_pbes2)
        ret = 1;

cleanup:
    if (encrypted)
        X509_SIG_free(encrypted);
    return ret;
}

int pq_pkcs8_der_to_pem(char **output, size_t *output_len, const uint8_t *der, size_t der_len,
                        int encrypted) {
    return pq_der_to_pem(encrypted ? PQ_PKCS8_ENCRYPTED_PRIVATE_KEY_PEM_LABEL
                                   : PQ_PKCS8_PRIVATE_KEY_PEM_LABEL,
                         der, der_len, output, output_len);
}

int pq_pkcs8_pem_to_der(uint8_t **der_out, size_t *der_len_out, int *encrypted_out,
                        const char *input, size_t input_len) {
    int ret;

    if (!der_out || !der_len_out || !encrypted_out || !input)
        return PQ_ERROR_BUFFER;
    *der_out = NULL;
    *der_len_out = 0;
    *encrypted_out = 0;

    ret = pq_pem_to_der(PQ_PKCS8_PRIVATE_KEY_PEM_LABEL, input, input_len, der_out, der_len_out);
    if (ret == PQ_SUCCESS) {
        *encrypted_out = 0;
        return PQ_SUCCESS;
    }

    ret = pq_pem_to_der(PQ_PKCS8_ENCRYPTED_PRIVATE_KEY_PEM_LABEL, input, input_len, der_out,
                        der_len_out);
    if (ret == PQ_SUCCESS) {
        *encrypted_out = 1;
        return PQ_SUCCESS;
    }
    return PQ_ERROR_BUFFER;
}

const char *pq_version(void) {
    return PQCRYPTO_VERSION;
}
