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
#include <openssl/bio.h>
#include <openssl/buffer.h>

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

static int x25519_keypair(uint8_t *pk, uint8_t *sk) {
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    size_t pklen = X25519_PUBLICKEYBYTES;
    size_t sklen = X25519_SECRETKEYBYTES;
    int ret = PQ_ERROR_KEYPAIR;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!ctx)
        goto cleanup;

    if (EVP_PKEY_keygen_init(ctx) <= 0)
        goto cleanup;

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
        goto cleanup;

    if (EVP_PKEY_get_raw_private_key(pkey, sk, &sklen) <= 0)
        goto cleanup;
    if (sklen != X25519_SECRETKEYBYTES)
        goto cleanup;

    if (EVP_PKEY_get_raw_public_key(pkey, pk, &pklen) <= 0)
        goto cleanup;
    if (pklen != X25519_PUBLICKEYBYTES)
        goto cleanup;

    ret = PQ_SUCCESS;

cleanup:
    if (pkey)
        EVP_PKEY_free(pkey);
    if (ctx)
        EVP_PKEY_CTX_free(ctx);
    return ret;
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

static int x25519_shared_secret(uint8_t *shared, const uint8_t *their_pk, const uint8_t *my_sk) {
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY *peer_key = NULL;
    size_t shared_len = X25519_SHAREDSECRETBYTES;
    int ret = PQ_ERROR_ENCAPSULATE;

    pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, my_sk, X25519_SECRETKEYBYTES);
    if (!pkey)
        goto cleanup;

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
    if (pkey)
        EVP_PKEY_free(pkey);
    return ret;
}

static const uint8_t XWING_LABEL[6] = {0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c};

static int xwing_combiner(uint8_t shared_secret[HYBRID_SHAREDSECRETBYTES],
                          const uint8_t ss_M[MLKEM_SHAREDSECRETBYTES],
                          const uint8_t ss_X[X25519_SHAREDSECRETBYTES],
                          const uint8_t ct_X[X25519_PUBLICKEYBYTES],
                          const uint8_t pk_X[X25519_PUBLICKEYBYTES]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int out_len = 0;
    int ret = PQ_ERROR_OPENSSL;

    if (!ctx) {
        return PQ_ERROR_OPENSSL;
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha3_256(), NULL) != 1)
        goto cleanup;
    if (EVP_DigestUpdate(ctx, ss_M, MLKEM_SHAREDSECRETBYTES) != 1)
        goto cleanup;
    if (EVP_DigestUpdate(ctx, ss_X, X25519_SHAREDSECRETBYTES) != 1)
        goto cleanup;
    if (EVP_DigestUpdate(ctx, ct_X, X25519_PUBLICKEYBYTES) != 1)
        goto cleanup;
    if (EVP_DigestUpdate(ctx, pk_X, X25519_PUBLICKEYBYTES) != 1)
        goto cleanup;
    if (EVP_DigestUpdate(ctx, XWING_LABEL, sizeof(XWING_LABEL)) != 1)
        goto cleanup;
    if (EVP_DigestFinal_ex(ctx, shared_secret, &out_len) != 1)
        goto cleanup;
    if (out_len != HYBRID_SHAREDSECRETBYTES)
        goto cleanup;

    ret = PQ_SUCCESS;

cleanup:
    EVP_MD_CTX_free(ctx);
    return ret;
}

static int xwing_expand_secret_key(hybrid_expanded_secret_key_t *expanded_key,
                                   const uint8_t seed[HYBRID_SECRETKEYBYTES]) {
    EVP_MD_CTX *ctx = NULL;
    uint8_t expanded[XWING_EXPANDEDBYTES];
    int ret = PQ_ERROR_OPENSSL;

    if (!expanded_key || !seed) {
        return PQ_ERROR_BUFFER;
    }

    memset(expanded_key, 0, sizeof(*expanded_key));
    memset(expanded, 0, sizeof(expanded));

    ctx = EVP_MD_CTX_new();
    if (!ctx)
        goto cleanup;

    if (EVP_DigestInit_ex(ctx, EVP_shake256(), NULL) != 1)
        goto cleanup;
    if (EVP_DigestUpdate(ctx, seed, HYBRID_SECRETKEYBYTES) != 1)
        goto cleanup;
    if (EVP_DigestFinalXOF(ctx, expanded, sizeof(expanded)) != 1)
        goto cleanup;

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
    if (ctx)
        EVP_MD_CTX_free(ctx);
    pq_secure_wipe(expanded, sizeof(expanded));
    if (ret != PQ_SUCCESS && expanded_key) {
        pq_secure_wipe(expanded_key, sizeof(*expanded_key));
    }
    return ret;
}

#define PQ_MLKEM_VARIANTS(X)             \
    X(mlkem, pqcr_mlkem768)             \
    X(mlkem512, pqcr_mlkem512)          \
    X(mlkem1024, pqcr_mlkem1024)

#define PQ_DEFINE_MLKEM_SHIMS(prefix, native)                                             \
    int pq_##prefix##_keypair(uint8_t *pk, uint8_t *sk) {                                \
        if (!pk || !sk) {                                                                 \
            return PQ_ERROR_BUFFER;                                                       \
        }                                                                                 \
        return native##_keypair(pk, sk) == 0 ? PQ_SUCCESS : PQ_ERROR_KEYPAIR;             \
    }                                                                                     \
    int pq_##prefix##_keypair_from_seed(uint8_t *pk, uint8_t *sk, const uint8_t *seed64) {\
        if (!pk || !sk || !seed64) {                                                      \
            return PQ_ERROR_BUFFER;                                                       \
        }                                                                                 \
        return native##_keypair_derand(pk, sk, seed64) == 0 ? PQ_SUCCESS                  \
                                                            : PQ_ERROR_KEYPAIR;           \
    }                                                                                     \
    int pq_##prefix##_encapsulate(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {          \
        if (!ct || !ss || !pk) {                                                          \
            return PQ_ERROR_BUFFER;                                                       \
        }                                                                                 \
        return native##_enc(ct, ss, pk) == 0 ? PQ_SUCCESS : PQ_ERROR_ENCAPSULATE;         \
    }                                                                                     \
    int pq_##prefix##_decapsulate(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {    \
        if (!ss || !ct || !sk) {                                                          \
            return PQ_ERROR_BUFFER;                                                       \
        }                                                                                 \
        return native##_dec(ss, ct, sk) == 0 ? PQ_SUCCESS : PQ_ERROR_DECAPSULATE;         \
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

#define PQ_DEFINE_MLKEM_TESTING_SHIMS(prefix, native)                                         \
    int pq_testing_##prefix##_keypair_from_seed(uint8_t *public_key, uint8_t *secret_key,      \
                                                const uint8_t *seed, size_t seed_len) {        \
        return pq_testing_mlkem_keypair_from_seed_with(public_key, secret_key, seed, seed_len, \
                                                       native##_keypair_derand);               \
    }                                                                                          \
    int pq_testing_##prefix##_encapsulate_from_seed(uint8_t *ciphertext, uint8_t *shared_secret,\
                                                    const uint8_t *public_key,                 \
                                                    const uint8_t *seed, size_t seed_len) {    \
        return pq_testing_mlkem_encapsulate_from_seed_with(ciphertext, shared_secret, public_key,\
                                                           seed, seed_len, native##_enc_derand);\
    }

PQ_MLKEM_VARIANTS(PQ_DEFINE_MLKEM_TESTING_SHIMS)

#undef PQ_DEFINE_MLKEM_TESTING_SHIMS

#define PQ_DEFINE_MLDSA_SIGN_KEYPAIR(prefix, native)                              \
    int pq_##prefix##_keypair(uint8_t *public_key, uint8_t *secret_key) {         \
        if (!public_key || !secret_key) {                                         \
            return PQ_ERROR_BUFFER;                                               \
        }                                                                         \
        return native##_keypair(public_key, secret_key) == 0 ? PQ_SUCCESS         \
                                                            : PQ_ERROR_KEYPAIR;   \
    }

PQ_DEFINE_MLDSA_SIGN_KEYPAIR(sign, pqcr_mldsa65)
PQ_DEFINE_MLDSA_SIGN_KEYPAIR(mldsa44_sign, pqcr_mldsa44)
PQ_DEFINE_MLDSA_SIGN_KEYPAIR(mldsa87_sign, pqcr_mldsa87)

#undef PQ_DEFINE_MLDSA_SIGN_KEYPAIR

#define PQ_DEFINE_MLDSA_SIGN(name, native)                                                \
    int pq_##name(uint8_t *signature, size_t *signature_len, const uint8_t *message,      \
                  size_t message_len, const uint8_t *secret_key) {                        \
        if (!signature || !signature_len || !secret_key || (message_len > 0 && !message)) {\
            return PQ_ERROR_BUFFER;                                                       \
        }                                                                                 \
        return native##_signature(signature, signature_len, message, message_len, NULL, 0,\
                                  secret_key) == 0                                        \
                   ? PQ_SUCCESS                                                           \
                   : PQ_ERROR_SIGN;                                                       \
    }

PQ_DEFINE_MLDSA_SIGN(sign, pqcr_mldsa65)
PQ_DEFINE_MLDSA_SIGN(mldsa44_sign, pqcr_mldsa44)
PQ_DEFINE_MLDSA_SIGN(mldsa87_sign, pqcr_mldsa87)

#undef PQ_DEFINE_MLDSA_SIGN

#define PQ_DEFINE_MLDSA_VERIFY(name, native)                                             \
    int pq_##name(const uint8_t *signature, size_t signature_len, const uint8_t *message, \
                  size_t message_len, const uint8_t *public_key) {                       \
        if (!signature || !public_key || (message_len > 0 && !message)) {                 \
            return PQ_ERROR_BUFFER;                                                       \
        }                                                                                 \
        return native##_verify(signature, signature_len, message, message_len, NULL, 0,   \
                               public_key) == 0                                          \
                   ? PQ_SUCCESS                                                           \
                   : PQ_ERROR_VERIFY;                                                     \
    }

PQ_DEFINE_MLDSA_VERIFY(verify, pqcr_mldsa65)
PQ_DEFINE_MLDSA_VERIFY(mldsa44_verify, pqcr_mldsa44)
PQ_DEFINE_MLDSA_VERIFY(mldsa87_verify, pqcr_mldsa87)

#undef PQ_DEFINE_MLDSA_VERIFY

static int pq_testing_mldsa_sign_from_seed_with(
    uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len,
    const uint8_t *secret_key, const uint8_t *seed, size_t seed_len,
    int (*signature_internal)(uint8_t *, size_t *, const uint8_t *, size_t, const uint8_t *, size_t,
                              const uint8_t *, const uint8_t *, int),
    size_t (*prepare_prefix)(uint8_t *, const uint8_t *, size_t, const uint8_t *, size_t, int)) {
    uint8_t pre[MLDSA_DOMAIN_SEPARATION_MAX_BYTES];
    size_t pre_len;

    if (!signature || !signature_len || !secret_key || !seed || seed_len != MLDSA_RNDBYTES ||
        !signature_internal || !prepare_prefix || (message_len > 0 && !message)) {
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
        return PQ_ERROR_SIGN;
    }

    return signature_internal(signature, signature_len, message, message_len, pre, pre_len, seed,
                              secret_key, 0) == 0
               ? PQ_SUCCESS
               : PQ_ERROR_SIGN;
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
    return pq_testing_mldsa_sign_from_seed_with(signature, signature_len, message, message_len,
                                                secret_key, seed, seed_len,
                                                pqcr_mldsa65_signature_internal,
                                                pqcr_mldsa65_prepare_domain_separation_prefix);
}

int pq_testing_mldsa44_sign_from_seed(uint8_t *signature, size_t *signature_len,
                                      const uint8_t *message, size_t message_len,
                                      const uint8_t *secret_key, const uint8_t *seed,
                                      size_t seed_len) {
    return pq_testing_mldsa_sign_from_seed_with(signature, signature_len, message, message_len,
                                                secret_key, seed, seed_len,
                                                pqcr_mldsa44_signature_internal,
                                                pqcr_mldsa44_prepare_domain_separation_prefix);
}

int pq_testing_mldsa87_sign_from_seed(uint8_t *signature, size_t *signature_len,
                                      const uint8_t *message, size_t message_len,
                                      const uint8_t *secret_key, const uint8_t *seed,
                                      size_t seed_len) {
    return pq_testing_mldsa_sign_from_seed_with(signature, signature_len, message, message_len,
                                                secret_key, seed, seed_len,
                                                pqcr_mldsa87_signature_internal,
                                                pqcr_mldsa87_prepare_domain_separation_prefix);
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
    uint8_t x25519_ephemeral_sk[X25519_SECRETKEYBYTES];
    int ret = PQ_SUCCESS;

    if (!ciphertext || !shared_secret || !public_key) {
        return PQ_ERROR_BUFFER;
    }

    memcpy(&pk, public_key, HYBRID_PUBLICKEYBYTES);
    memset(&ct, 0, sizeof(ct));
    memset(mlkem_ss, 0, sizeof(mlkem_ss));
    memset(x25519_ss, 0, sizeof(x25519_ss));
    memset(x25519_ephemeral_sk, 0, sizeof(x25519_ephemeral_sk));

    if (pqcr_mlkem768_enc(ct.mlkem_ct, mlkem_ss, pk.mlkem_pk) != 0) {
        ret = PQ_ERROR_ENCAPSULATE;
        goto cleanup;
    }

    ret = x25519_keypair(ct.x25519_ephemeral, x25519_ephemeral_sk);
    if (ret != PQ_SUCCESS) {
        ret = PQ_ERROR_ENCAPSULATE;
        goto cleanup;
    }

    ret = x25519_shared_secret(x25519_ss, pk.x25519_pk, x25519_ephemeral_sk);
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
    pq_secure_wipe(x25519_ephemeral_sk, sizeof(x25519_ephemeral_sk));
    return ret;
}

int pq_hybrid_kem_decapsulate(uint8_t *shared_secret, const uint8_t *ciphertext,
                              const uint8_t *secret_key) {
    hybrid_ciphertext_t ct;
    hybrid_expanded_secret_key_t expanded;
    uint8_t mlkem_ss[MLKEM_SHAREDSECRETBYTES];
    uint8_t x25519_ss[X25519_SHAREDSECRETBYTES];
    int ret = PQ_SUCCESS;

    if (!shared_secret || !ciphertext || !secret_key) {
        return PQ_ERROR_BUFFER;
    }

    memcpy(&ct, ciphertext, HYBRID_CIPHERTEXTBYTES);
    memset(&expanded, 0, sizeof(expanded));
    memset(mlkem_ss, 0, sizeof(mlkem_ss));
    memset(x25519_ss, 0, sizeof(x25519_ss));

    ret = xwing_expand_secret_key(&expanded, secret_key);
    if (ret != PQ_SUCCESS) {
        ret = PQ_ERROR_DECAPSULATE;
        goto cleanup;
    }

    if (pqcr_mlkem768_dec(mlkem_ss, ct.mlkem_ct, expanded.mlkem_sk) != 0) {
        ret = PQ_ERROR_DECAPSULATE;
        goto cleanup;
    }

    ret = x25519_shared_secret(x25519_ss, ct.x25519_ephemeral, expanded.x25519_sk);
    if (ret != PQ_SUCCESS) {
        ret = PQ_ERROR_DECAPSULATE;
        goto cleanup;
    }

    ret =
        xwing_combiner(shared_secret, mlkem_ss, x25519_ss, ct.x25519_ephemeral, expanded.x25519_pk);

cleanup:
    pq_secure_wipe(mlkem_ss, sizeof(mlkem_ss));
    pq_secure_wipe(x25519_ss, sizeof(x25519_ss));
    pq_secure_wipe(&expanded, sizeof(expanded));
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

static int pq_der_to_pem(const char *label, const uint8_t *der, size_t der_len, char **output,
                         size_t *output_len) {
    BIO *bio_mem = NULL;
    BIO *bio_b64 = NULL;
    BIO *bio_chain = NULL;
    BUF_MEM *bptr = NULL;
    char header[64];
    char footer[64];
    int header_len, footer_len;
    int ret = PQ_ERROR_OPENSSL;
    char *pem = NULL;
    size_t total_len = 0;
    size_t needed = 0;

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

    bio_b64 = BIO_new(BIO_f_base64());
    bio_mem = BIO_new(BIO_s_mem());
    if (!bio_b64 || !bio_mem) {
        ret = PQ_ERROR_NOMEM;
        goto cleanup;
    }

    bio_chain = BIO_push(bio_b64, bio_mem);

    if (BIO_write(bio_chain, der, (int)der_len) != (int)der_len)
        goto cleanup;
    if (BIO_flush(bio_chain) != 1)
        goto cleanup;
    BIO_get_mem_ptr(bio_chain, &bptr);
    if (!bptr || !bptr->data)
        goto cleanup;

    {
        size_t body_len = bptr->length;
        needed = (size_t)header_len + 1 + body_len;
        if (body_len == 0 || bptr->data[body_len - 1] != '\n')
            needed += 1;
        needed += (size_t)footer_len + 1;

        pem = malloc(needed);
        if (!pem) {
            ret = PQ_ERROR_NOMEM;
            goto cleanup;
        }
        char *cur = pem;
        memcpy(cur, header, (size_t)header_len);
        cur += header_len;
        *cur++ = '\n';
        memcpy(cur, bptr->data, body_len);
        cur += body_len;
        if (body_len == 0 || bptr->data[body_len - 1] != '\n')
            *cur++ = '\n';
        memcpy(cur, footer, (size_t)footer_len);
        cur += footer_len;
        *cur = '\0';
        total_len = (size_t)(cur - pem);
    }

    *output = pem;
    *output_len = total_len;
    pem = NULL;
    ret = PQ_SUCCESS;

cleanup:
    if (bio_chain) {
        BIO_free_all(bio_chain);
    } else {
        if (bio_b64)
            BIO_free(bio_b64);
        if (bio_mem)
            BIO_free(bio_mem);
    }
    if (pem) {
        pq_secure_wipe(pem, needed);
        free(pem);
    }
    return ret;
}

static int pq_pem_to_der(const char *label, const char *input, size_t input_len, uint8_t **der_out,
                         size_t *der_len_out) {
    char header[64], footer[64];
    int header_len, footer_len;
    const char *body_start, *footer_pos;
    const char *tail;
    uint8_t *der = NULL;
    size_t body_len = 0;
    int ret;
    BIO *bio_b64 = NULL;
    BIO *bio_mem = NULL;
    BIO *bio_chain = NULL;
    int decoded_len = 0;

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
    footer_pos = NULL;
    {
        size_t remaining = input_len - (size_t)(body_start - input);
        size_t footer_size = (size_t)footer_len;
        if (remaining < footer_size)
            return PQ_ERROR_BUFFER;
        for (size_t i = 0; i <= remaining - footer_size; ++i) {
            if (memcmp(body_start + i, footer, footer_size) == 0) {
                footer_pos = body_start + i;
                break;
            }
        }
    }
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

    {
        size_t der_cap = (body_len * 3) / 4 + 3;
        der = malloc(der_cap ? der_cap : 1);
        if (!der)
            return PQ_ERROR_NOMEM;

        bio_mem = BIO_new_mem_buf(body_start, (int)body_len);
        bio_b64 = BIO_new(BIO_f_base64());
        if (!bio_mem || !bio_b64) {
            ret = PQ_ERROR_NOMEM;
            goto cleanup;
        }
        bio_chain = BIO_push(bio_b64, bio_mem);

        decoded_len = BIO_read(bio_chain, der, (int)der_cap);
        if (decoded_len <= 0) {
            ret = PQ_ERROR_BUFFER;
            goto cleanup;
        }
        {
            unsigned char tail_byte;
            int extra = BIO_read(bio_chain, &tail_byte, 1);
            if (extra > 0) {
                ret = PQ_ERROR_BUFFER;
                goto cleanup;
            }
        }

        *der_len_out = (size_t)decoded_len;
        *der_out = der;
        der = NULL;
        ret = PQ_SUCCESS;
    }

cleanup:
    if (bio_chain) {
        BIO_free_all(bio_chain);
    } else {
        if (bio_b64)
            BIO_free(bio_b64);
        if (bio_mem)
            BIO_free(bio_mem);
    }
    if (der) {
        free(der);
    }
    return ret;
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

const char *pq_version(void) {
    return PQCRYPTO_VERSION;
}
