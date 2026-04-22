#include "pqcrypto_secure.h"

#include <stdio.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>

#if defined(__linux__)
#include <sys/random.h>
#endif

#ifndef HAVE_OPENSSL_EVP_H
#error \
    "OpenSSL with EVP support is required for secure cryptographic operations. Install OpenSSL development packages."
#endif

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>

#if OPENSSL_VERSION_NUMBER < 0x30000000L
#error "OpenSSL 3.0 or later is required for pq_crypto"
#endif

#ifndef HAVE_PQCLEAN
#error "PQClean-backed algorithms are required. Run: bundle exec rake vendor"
#endif

#include "mlkem_api.h"
#include "mldsa_api.h"
#include "fips202.h"
#include "packing.h"
#include "params.h"

void pq_secure_wipe(void *ptr, size_t len) {
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

static int pq_size_mul(size_t a, size_t b, size_t *out) {
    if (!out)
        return PQ_ERROR_BUFFER;
    if (a != 0 && SIZE_MAX / a < b)
        return PQ_ERROR_BUFFER;
    *out = a * b;
    return PQ_SUCCESS;
}

static int pq_is_pem_whitespace(char c) {
    return c == '\n' || c == '\r' || c == ' ' || c == '\t';
}

static int pq_randombytes(uint8_t *buf, size_t len) {
#ifdef HAVE_OPENSSL_RAND_H
    if (len > INT_MAX) {
        return PQ_ERROR_BUFFER;
    }
    if (RAND_bytes(buf, (int)len) == 1) {
        return 0;
    }

#endif

#if defined(__linux__)
    ssize_t ret = getrandom(buf, len, 0);
    return (ret == (ssize_t)len) ? 0 : PQ_ERROR_RANDOM;
#elif defined(__APPLE__)
    arc4random_buf(buf, len);
    return 0;
#else
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f)
        return PQ_ERROR_RANDOM;
    size_t read = fread(buf, 1, len, f);
    fclose(f);
    return (read == len) ? 0 : PQ_ERROR_RANDOM;
#endif
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

static int x25519_public_from_secret(uint8_t *pk, const uint8_t *sk) {
    EVP_PKEY *pkey = NULL;
    size_t pklen = X25519_PUBLICKEYBYTES;
    int ret = PQ_ERROR_KEYPAIR;

    pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, sk, X25519_SECRETKEYBYTES);
    if (!pkey) {
        return ret;
    }

    if (EVP_PKEY_get_raw_public_key(pkey, pk, &pklen) <= 0 || pklen != X25519_PUBLICKEYBYTES) {
        EVP_PKEY_free(pkey);
        return ret;
    }

    EVP_PKEY_free(pkey);
    return PQ_SUCCESS;
}

static int size_t_to_int_checked(size_t value, int *out) {
    if (value > INT_MAX) {
        return PQ_ERROR_BUFFER;
    }

    *out = (int)value;
    return PQ_SUCCESS;
}

static int secure_hkdf(uint8_t *output, size_t output_len, const uint8_t *ikm, size_t ikm_len,
                       const uint8_t *salt, size_t salt_len, const uint8_t *info, size_t info_len) {
    int ikm_len_i = 0;
    int salt_len_i = 0;
    int info_len_i = 0;

    if (size_t_to_int_checked(ikm_len, &ikm_len_i) != PQ_SUCCESS)
        return PQ_ERROR_BUFFER;
    if (size_t_to_int_checked(salt_len, &salt_len_i) != PQ_SUCCESS)
        return PQ_ERROR_BUFFER;
    if (size_t_to_int_checked(info_len, &info_len_i) != PQ_SUCCESS)
        return PQ_ERROR_BUFFER;

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx)
        return PQ_ERROR_OPENSSL;

    if (EVP_PKEY_derive_init(pctx) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return PQ_ERROR_OPENSSL;
    }

    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return PQ_ERROR_OPENSSL;
    }

    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm, ikm_len_i) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return PQ_ERROR_OPENSSL;
    }

    if (salt && salt_len > 0) {
        if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, salt_len_i) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            return PQ_ERROR_OPENSSL;
        }
    }

    if (info && info_len > 0) {
        if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info, info_len_i) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            return PQ_ERROR_OPENSSL;
        }
    }

    size_t outlen = output_len;
    if (EVP_PKEY_derive(pctx, output, &outlen) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return PQ_ERROR_OPENSSL;
    }

    EVP_PKEY_CTX_free(pctx);
    return (outlen == output_len) ? 0 : PQ_ERROR_KDF;
}

static int secure_sha256(uint8_t *output, const uint8_t *input, size_t input_len) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int out_len = 0;

    if (!ctx) {
        return PQ_ERROR_OPENSSL;
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(ctx, input, input_len) != 1 ||
        EVP_DigestFinal_ex(ctx, output, &out_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return PQ_ERROR_OPENSSL;
    }

    EVP_MD_CTX_free(ctx);
    return out_len == 32 ? PQ_SUCCESS : PQ_ERROR_OPENSSL;
}

static int hybrid_combiner(uint8_t *shared_secret, const uint8_t *mlkem_ss,
                           const uint8_t *x25519_ss, const uint8_t *recipient_x25519_pk,
                           const hybrid_ciphertext_t *ct) {
    static const uint8_t label[] = "pqcrypto/v1/hybrid-kem";
    uint8_t ikm[MLKEM_SHAREDSECRETBYTES + X25519_SHAREDSECRETBYTES];
    uint8_t salt[32];
    int ret = PQ_SUCCESS;
    size_t transcript_len = sizeof(label) - 1 + X25519_PUBLICKEYBYTES + HYBRID_CIPHERTEXTBYTES;
    uint8_t *transcript = malloc(transcript_len);

    if (!transcript) {
        return PQ_ERROR_NOMEM;
    }

    memcpy(ikm, mlkem_ss, MLKEM_SHAREDSECRETBYTES);
    memcpy(ikm + MLKEM_SHAREDSECRETBYTES, x25519_ss, X25519_SHAREDSECRETBYTES);

    memcpy(transcript, label, sizeof(label) - 1);
    memcpy(transcript + sizeof(label) - 1, recipient_x25519_pk, X25519_PUBLICKEYBYTES);
    memcpy(transcript + sizeof(label) - 1 + X25519_PUBLICKEYBYTES, ct, HYBRID_CIPHERTEXTBYTES);

    ret = secure_sha256(salt, transcript, transcript_len);
    if (ret == PQ_SUCCESS) {
        ret = secure_hkdf(shared_secret, HYBRID_SHAREDSECRETBYTES, ikm, sizeof(ikm), salt,
                          sizeof(salt), transcript, transcript_len);
    }

    pq_secure_wipe(ikm, sizeof(ikm));
    pq_secure_wipe(salt, sizeof(salt));
    pq_secure_wipe(transcript, transcript_len);
    free(transcript);
    return ret;
}

static int mlkem_keypair(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(pk, sk);
}

static int mlkem_encapsulate(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    return PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(ct, ss, pk);
}

static int mlkem_decapsulate(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    return PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(ss, ct, sk);
}

static int mldsa_keypair(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair(pk, sk);
}

static int mldsa_sign(uint8_t *sig, size_t *siglen, const uint8_t *msg, size_t msglen,
                      const uint8_t *sk) {
    return PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature(sig, siglen, msg, msglen, sk);
}

static int mldsa_verify(const uint8_t *sig, size_t siglen, const uint8_t *msg, size_t msglen,
                        const uint8_t *pk) {
    return PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify(sig, siglen, msg, msglen, pk);
}

int pq_testing_mlkem_keypair_from_seed(uint8_t *public_key, uint8_t *secret_key,
                                       const uint8_t *seed, size_t seed_len) {
    uint8_t expanded_seed[64];
    int ret;

    if (!public_key || !secret_key || !seed) {
        return PQ_ERROR_BUFFER;
    }

    if (seed_len == 64) {
        return PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair_derand(public_key, secret_key, seed) == 0
                   ? PQ_SUCCESS
                   : PQ_ERROR_KEYPAIR;
    }

    if (seed_len != 32) {
        return PQ_ERROR_BUFFER;
    }

    ret = secure_hkdf(expanded_seed, sizeof(expanded_seed), seed, seed_len, NULL, 0,
                      (const uint8_t *)"pqcrypto-test-mlkem-keypair", 26);
    if (ret != PQ_SUCCESS) {
        pq_secure_wipe(expanded_seed, sizeof(expanded_seed));
        return ret;
    }

    ret =
        PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair_derand(public_key, secret_key, expanded_seed) == 0
            ? PQ_SUCCESS
            : PQ_ERROR_KEYPAIR;
    pq_secure_wipe(expanded_seed, sizeof(expanded_seed));
    return ret;
}

int pq_testing_mlkem_encapsulate_from_seed(uint8_t *ciphertext, uint8_t *shared_secret,
                                           const uint8_t *public_key, const uint8_t *seed,
                                           size_t seed_len) {
    if (!ciphertext || !shared_secret || !public_key || !seed || seed_len != 32) {
        return PQ_ERROR_BUFFER;
    }

    return PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc_derand(ciphertext, shared_secret, public_key,
                                                        seed) == 0
               ? PQ_SUCCESS
               : PQ_ERROR_ENCAPSULATE;
}

static int pq_testing_mldsa_keypair_from_seed_impl(uint8_t *public_key, uint8_t *secret_key,
                                                   const uint8_t seed[SEEDBYTES]) {
    uint8_t seedbuf[2 * SEEDBYTES + CRHBYTES];
    uint8_t tr[TRBYTES];
    const uint8_t *rho, *rhoprime, *key;
    polyvecl mat[K];
    polyvecl s1, s1hat;
    polyveck s2, t1, t0;

    memcpy(seedbuf, seed, SEEDBYTES);
    seedbuf[SEEDBYTES + 0] = K;
    seedbuf[SEEDBYTES + 1] = L;
    shake256(seedbuf, 2 * SEEDBYTES + CRHBYTES, seedbuf, SEEDBYTES + 2);
    rho = seedbuf;
    rhoprime = rho + SEEDBYTES;
    key = rhoprime + CRHBYTES;

    PQCLEAN_MLDSA65_CLEAN_polyvec_matrix_expand(mat, rho);
    PQCLEAN_MLDSA65_CLEAN_polyvecl_uniform_eta(&s1, rhoprime, 0);
    PQCLEAN_MLDSA65_CLEAN_polyveck_uniform_eta(&s2, rhoprime, L);

    s1hat = s1;
    PQCLEAN_MLDSA65_CLEAN_polyvecl_ntt(&s1hat);
    PQCLEAN_MLDSA65_CLEAN_polyvec_matrix_pointwise_montgomery(&t1, mat, &s1hat);
    PQCLEAN_MLDSA65_CLEAN_polyveck_reduce(&t1);
    PQCLEAN_MLDSA65_CLEAN_polyveck_invntt_tomont(&t1);

    PQCLEAN_MLDSA65_CLEAN_polyveck_add(&t1, &t1, &s2);
    PQCLEAN_MLDSA65_CLEAN_polyveck_caddq(&t1);
    PQCLEAN_MLDSA65_CLEAN_polyveck_power2round(&t1, &t0, &t1);
    PQCLEAN_MLDSA65_CLEAN_pack_pk(public_key, rho, &t1);

    shake256(tr, TRBYTES, public_key, PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES);
    PQCLEAN_MLDSA65_CLEAN_pack_sk(secret_key, rho, tr, key, &t0, &s1, &s2);

    pq_secure_wipe(seedbuf, sizeof(seedbuf));
    pq_secure_wipe(tr, sizeof(tr));
    pq_secure_wipe(&s1, sizeof(s1));
    pq_secure_wipe(&s1hat, sizeof(s1hat));
    pq_secure_wipe(&s2, sizeof(s2));
    pq_secure_wipe(&t1, sizeof(t1));
    pq_secure_wipe(&t0, sizeof(t0));
    pq_secure_wipe(mat, sizeof(mat));
    return PQ_SUCCESS;
}

static int pq_testing_mldsa_sign_from_seed_impl(uint8_t *signature, size_t *signature_len,
                                                const uint8_t *message, size_t message_len,
                                                const uint8_t *secret_key,
                                                const uint8_t seed[RNDBYTES]) {
    unsigned int n;
    uint8_t seedbuf[2 * SEEDBYTES + TRBYTES + RNDBYTES + 2 * CRHBYTES];
    uint8_t *rho, *tr, *key, *mu, *rhoprime, *rnd;
    uint16_t nonce = 0;
    polyvecl mat[K], s1, y, z;
    polyveck t0, s2, w1, w0, h;
    poly cp;
    shake256incctx state;

    rho = seedbuf;
    tr = rho + SEEDBYTES;
    key = tr + TRBYTES;
    rnd = key + SEEDBYTES;
    mu = rnd + RNDBYTES;
    rhoprime = mu + CRHBYTES;
    PQCLEAN_MLDSA65_CLEAN_unpack_sk(rho, tr, key, &t0, &s1, &s2, secret_key);

    mu[0] = 0;
    mu[1] = 0;
    shake256_inc_init(&state);
    shake256_inc_absorb(&state, tr, TRBYTES);
    shake256_inc_absorb(&state, mu, 2);
    shake256_inc_absorb(&state, message, message_len);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(mu, CRHBYTES, &state);
    shake256_inc_ctx_release(&state);

    memcpy(rnd, seed, RNDBYTES);
    shake256(rhoprime, CRHBYTES, key, SEEDBYTES + RNDBYTES + CRHBYTES);

    PQCLEAN_MLDSA65_CLEAN_polyvec_matrix_expand(mat, rho);
    PQCLEAN_MLDSA65_CLEAN_polyvecl_ntt(&s1);
    PQCLEAN_MLDSA65_CLEAN_polyveck_ntt(&s2);
    PQCLEAN_MLDSA65_CLEAN_polyveck_ntt(&t0);

rej:
    PQCLEAN_MLDSA65_CLEAN_polyvecl_uniform_gamma1(&y, rhoprime, nonce++);

    z = y;
    PQCLEAN_MLDSA65_CLEAN_polyvecl_ntt(&z);
    PQCLEAN_MLDSA65_CLEAN_polyvec_matrix_pointwise_montgomery(&w1, mat, &z);
    PQCLEAN_MLDSA65_CLEAN_polyveck_reduce(&w1);
    PQCLEAN_MLDSA65_CLEAN_polyveck_invntt_tomont(&w1);

    PQCLEAN_MLDSA65_CLEAN_polyveck_caddq(&w1);
    PQCLEAN_MLDSA65_CLEAN_polyveck_decompose(&w1, &w0, &w1);
    PQCLEAN_MLDSA65_CLEAN_polyveck_pack_w1(signature, &w1);

    shake256_inc_init(&state);
    shake256_inc_absorb(&state, mu, CRHBYTES);
    shake256_inc_absorb(&state, signature, K * POLYW1_PACKEDBYTES);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(signature, CTILDEBYTES, &state);
    shake256_inc_ctx_release(&state);
    PQCLEAN_MLDSA65_CLEAN_poly_challenge(&cp, signature);
    PQCLEAN_MLDSA65_CLEAN_poly_ntt(&cp);

    PQCLEAN_MLDSA65_CLEAN_polyvecl_pointwise_poly_montgomery(&z, &cp, &s1);
    PQCLEAN_MLDSA65_CLEAN_polyvecl_invntt_tomont(&z);
    PQCLEAN_MLDSA65_CLEAN_polyvecl_add(&z, &z, &y);
    PQCLEAN_MLDSA65_CLEAN_polyvecl_reduce(&z);
    if (PQCLEAN_MLDSA65_CLEAN_polyvecl_chknorm(&z, GAMMA1 - BETA)) {
        goto rej;
    }

    PQCLEAN_MLDSA65_CLEAN_polyveck_pointwise_poly_montgomery(&h, &cp, &s2);
    PQCLEAN_MLDSA65_CLEAN_polyveck_invntt_tomont(&h);
    PQCLEAN_MLDSA65_CLEAN_polyveck_sub(&w0, &w0, &h);
    PQCLEAN_MLDSA65_CLEAN_polyveck_reduce(&w0);
    if (PQCLEAN_MLDSA65_CLEAN_polyveck_chknorm(&w0, GAMMA2 - BETA)) {
        goto rej;
    }

    PQCLEAN_MLDSA65_CLEAN_polyveck_pointwise_poly_montgomery(&h, &cp, &t0);
    PQCLEAN_MLDSA65_CLEAN_polyveck_invntt_tomont(&h);
    PQCLEAN_MLDSA65_CLEAN_polyveck_reduce(&h);
    if (PQCLEAN_MLDSA65_CLEAN_polyveck_chknorm(&h, GAMMA2)) {
        goto rej;
    }

    PQCLEAN_MLDSA65_CLEAN_polyveck_add(&w0, &w0, &h);
    n = PQCLEAN_MLDSA65_CLEAN_polyveck_make_hint(&h, &w0, &w1);
    if (n > OMEGA) {
        goto rej;
    }

    PQCLEAN_MLDSA65_CLEAN_pack_sig(signature, signature, &z, &h);
    *signature_len = PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES;

    pq_secure_wipe(seedbuf, sizeof(seedbuf));
    pq_secure_wipe(&s1, sizeof(s1));
    pq_secure_wipe(&y, sizeof(y));
    pq_secure_wipe(&z, sizeof(z));
    pq_secure_wipe(&t0, sizeof(t0));
    pq_secure_wipe(&s2, sizeof(s2));
    pq_secure_wipe(&w1, sizeof(w1));
    pq_secure_wipe(&w0, sizeof(w0));
    pq_secure_wipe(&h, sizeof(h));
    pq_secure_wipe(&cp, sizeof(cp));
    pq_secure_wipe(mat, sizeof(mat));
    return PQ_SUCCESS;
}

int pq_testing_mldsa_keypair_from_seed(uint8_t *public_key, uint8_t *secret_key,
                                       const uint8_t *seed, size_t seed_len) {
    if (!public_key || !secret_key || !seed || seed_len != SEEDBYTES) {
        return PQ_ERROR_BUFFER;
    }

    return pq_testing_mldsa_keypair_from_seed_impl(public_key, secret_key, seed);
}

int pq_testing_mldsa_sign_from_seed(uint8_t *signature, size_t *signature_len,
                                    const uint8_t *message, size_t message_len,
                                    const uint8_t *secret_key, const uint8_t *seed,
                                    size_t seed_len) {
    if (!signature || !signature_len || !message || !secret_key || !seed || seed_len != RNDBYTES) {
        return PQ_ERROR_BUFFER;
    }

    return pq_testing_mldsa_sign_from_seed_impl(signature, signature_len, message, message_len,
                                                secret_key, seed);
}

int pq_mlkem_keypair(uint8_t *public_key, uint8_t *secret_key) {
    return mlkem_keypair(public_key, secret_key) == 0 ? PQ_SUCCESS : PQ_ERROR_KEYPAIR;
}

int pq_mlkem_encapsulate(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key) {
    return mlkem_encapsulate(ciphertext, shared_secret, public_key) == 0 ? PQ_SUCCESS
                                                                         : PQ_ERROR_ENCAPSULATE;
}

int pq_mlkem_decapsulate(uint8_t *shared_secret, const uint8_t *ciphertext,
                         const uint8_t *secret_key) {
    return mlkem_decapsulate(shared_secret, ciphertext, secret_key) == 0 ? PQ_SUCCESS
                                                                         : PQ_ERROR_DECAPSULATE;
}

int pq_hybrid_kem_keypair(uint8_t *public_key, uint8_t *secret_key) {
    hybrid_public_key_t *pk = (hybrid_public_key_t *)public_key;
    hybrid_secret_key_t *sk = (hybrid_secret_key_t *)secret_key;

    memset(sk, 0, sizeof(*sk));

    if (mlkem_keypair(pk->mlkem_pk, sk->mlkem_sk) != 0) {
        pq_secure_wipe(sk, sizeof(*sk));
        return PQ_ERROR_KEYPAIR;
    }

    if (x25519_keypair(pk->x25519_pk, sk->x25519_sk) != 0) {
        pq_secure_wipe(sk, sizeof(*sk));
        return PQ_ERROR_KEYPAIR;
    }

    return PQ_SUCCESS;
}

int pq_hybrid_kem_encapsulate(uint8_t *ciphertext, uint8_t *shared_secret,
                              const uint8_t *public_key) {
    const hybrid_public_key_t *pk = (const hybrid_public_key_t *)public_key;
    hybrid_ciphertext_t *ct = (hybrid_ciphertext_t *)ciphertext;

    uint8_t mlkem_ss[MLKEM_SHAREDSECRETBYTES];
    uint8_t x25519_ss[X25519_SHAREDSECRETBYTES];
    uint8_t x25519_ephemeral_sk[X25519_SECRETKEYBYTES];
    int ret = PQ_SUCCESS;

    memset(mlkem_ss, 0, sizeof(mlkem_ss));
    memset(x25519_ss, 0, sizeof(x25519_ss));
    memset(x25519_ephemeral_sk, 0, sizeof(x25519_ephemeral_sk));

    if (mlkem_encapsulate(ct->mlkem_ct, mlkem_ss, pk->mlkem_pk) != 0) {
        ret = PQ_ERROR_ENCAPSULATE;
        goto cleanup;
    }

    ret = x25519_keypair(ct->x25519_ephemeral, x25519_ephemeral_sk);
    if (ret != PQ_SUCCESS) {
        ret = PQ_ERROR_ENCAPSULATE;
        goto cleanup;
    }

    ret = x25519_shared_secret(x25519_ss, pk->x25519_pk, x25519_ephemeral_sk);
    if (ret != PQ_SUCCESS) {
        ret = PQ_ERROR_ENCAPSULATE;
        goto cleanup;
    }

    ret = hybrid_combiner(shared_secret, mlkem_ss, x25519_ss, pk->x25519_pk, ct);
    if (ret != PQ_SUCCESS) {
        goto cleanup;
    }

    ret = PQ_SUCCESS;

cleanup:
    pq_secure_wipe(mlkem_ss, sizeof(mlkem_ss));
    pq_secure_wipe(x25519_ss, sizeof(x25519_ss));
    pq_secure_wipe(x25519_ephemeral_sk, sizeof(x25519_ephemeral_sk));
    return ret;
}

int pq_hybrid_kem_decapsulate(uint8_t *shared_secret, const uint8_t *ciphertext,
                              const uint8_t *secret_key) {
    const hybrid_ciphertext_t *ct = (const hybrid_ciphertext_t *)ciphertext;
    uint8_t recipient_x25519_pk[X25519_PUBLICKEYBYTES];
    const hybrid_secret_key_t *sk = (const hybrid_secret_key_t *)secret_key;

    uint8_t mlkem_ss[MLKEM_SHAREDSECRETBYTES];
    uint8_t x25519_ss[X25519_SHAREDSECRETBYTES];
    int ret = PQ_SUCCESS;

    memset(recipient_x25519_pk, 0, sizeof(recipient_x25519_pk));
    memset(mlkem_ss, 0, sizeof(mlkem_ss));
    memset(x25519_ss, 0, sizeof(x25519_ss));

    ret = mlkem_decapsulate(mlkem_ss, ct->mlkem_ct, sk->mlkem_sk) == 0 ? PQ_SUCCESS
                                                                       : PQ_ERROR_DECAPSULATE;
    if (ret != PQ_SUCCESS) {
        goto cleanup;
    }

    ret = x25519_shared_secret(x25519_ss, ct->x25519_ephemeral, sk->x25519_sk);
    if (ret != PQ_SUCCESS) {
        ret = PQ_ERROR_DECAPSULATE;
        goto cleanup;
    }

    ret = x25519_public_from_secret(recipient_x25519_pk, sk->x25519_sk);
    if (ret != PQ_SUCCESS) {
        ret = PQ_ERROR_DECAPSULATE;
        goto cleanup;
    }

    ret = hybrid_combiner(shared_secret, mlkem_ss, x25519_ss, recipient_x25519_pk, ct);

cleanup:
    pq_secure_wipe(recipient_x25519_pk, sizeof(recipient_x25519_pk));
    pq_secure_wipe(mlkem_ss, sizeof(mlkem_ss));
    pq_secure_wipe(x25519_ss, sizeof(x25519_ss));
    return ret;
}

int pq_sign_keypair(uint8_t *public_key, uint8_t *secret_key) {
    return mldsa_keypair(public_key, secret_key) == 0 ? PQ_SUCCESS : PQ_ERROR_KEYPAIR;
}

int pq_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len,
            const uint8_t *secret_key) {
    return mldsa_sign(signature, signature_len, message, message_len, secret_key) == 0
               ? PQ_SUCCESS
               : PQ_ERROR_SIGN;
}

int pq_verify(const uint8_t *signature, size_t signature_len, const uint8_t *message,
              size_t message_len, const uint8_t *public_key) {
    return mldsa_verify(signature, signature_len, message, message_len, public_key) == 0
               ? PQ_SUCCESS
               : PQ_ERROR_VERIFY;
}

#define PQC_SERIALIZATION_MAGIC_0     'P'
#define PQC_SERIALIZATION_MAGIC_1     'Q'
#define PQC_SERIALIZATION_MAGIC_2     'C'
#define PQC_SERIALIZATION_MAGIC_3     '1'
#define PQC_SERIALIZATION_VERSION     0x01
#define PQC_SERIALIZATION_TYPE_PUBLIC 0x01
#define PQC_SERIALIZATION_TYPE_SECRET 0x02

static const char PQC_OID_ML_KEM_768[] = "2.25.186599352125448088867056807454444238446";
static const char PQC_OID_ML_KEM_768_X25519_HKDF_SHA256[] =
    "2.25.260242945110721168101139140490528778800";
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
    {"ml_kem_768_x25519_hkdf_sha256", PQC_OID_ML_KEM_768_X25519_HKDF_SHA256,
     PQ_HYBRID_PUBLICKEYBYTES, PQ_HYBRID_SECRETKEYBYTES},
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
    size_t encoded_len = 0;
    size_t line_count = 0;
    size_t body_len = 0;
    size_t total_len = 0;
    unsigned char *encoded = NULL;
    char *pem = NULL;
    char header[64];
    char footer[64];
    char *cursor;
    int header_len, footer_len;
    int ret;

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

    ret = pq_size_mul((der_len + 2) / 3, 4, &encoded_len);
    if (ret != PQ_SUCCESS)
        return ret;
    ret = pq_size_add(encoded_len, 63, &line_count);
    if (ret != PQ_SUCCESS)
        return ret;
    line_count /= 64;
    ret = pq_size_add(encoded_len, line_count, &body_len);
    if (ret != PQ_SUCCESS)
        return ret;
    ret = pq_size_add((size_t)header_len, body_len, &total_len);
    if (ret != PQ_SUCCESS)
        return ret;
    ret = pq_size_add(total_len, (size_t)footer_len, &total_len);
    if (ret != PQ_SUCCESS)
        return ret;

    encoded = malloc(encoded_len + 1);
    pem = malloc(total_len + 1);
    if (!encoded || !pem) {
        free(encoded);
        free(pem);
        return PQ_ERROR_NOMEM;
    }
    if (EVP_EncodeBlock(encoded, der, (int)der_len) != (int)encoded_len) {
        free(encoded);
        pq_secure_wipe(pem, total_len + 1);
        free(pem);
        return PQ_ERROR_OPENSSL;
    }
    cursor = pem;
    memcpy(cursor, header, (size_t)header_len);
    cursor += header_len;
    for (size_t off = 0; off < encoded_len; off += 64) {
        size_t chunk = encoded_len - off;
        if (chunk > 64)
            chunk = 64;
        memcpy(cursor, encoded + off, chunk);
        cursor += chunk;
        *cursor++ = '\n';
    }
    memcpy(cursor, footer, (size_t)footer_len);
    cursor += footer_len;
    *cursor = '\0';
    *output = pem;
    *output_len = (size_t)(cursor - pem);
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
    char *encoded = NULL;
    uint8_t *der = NULL;
    size_t encoded_len = 0;
    size_t der_capacity = 0;
    int decoded_len;
    int ret;
    size_t pad = 0;

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

    encoded = malloc((size_t)(footer_pos - body_start) + 1);
    if (!encoded)
        return PQ_ERROR_NOMEM;
    for (const char *p = body_start; p < footer_pos; ++p) {
        if (pq_is_pem_whitespace(*p))
            continue;
        encoded[encoded_len++] = *p;
    }
    if (encoded_len == 0 || (encoded_len % 4) != 0) {
        free(encoded);
        return PQ_ERROR_BUFFER;
    }
    encoded[encoded_len] = '\0';

    ret = pq_size_mul(encoded_len / 4, 3, &der_capacity);
    if (ret != PQ_SUCCESS) {
        pq_secure_wipe(encoded, encoded_len + 1);
        free(encoded);
        return ret;
    }
    ret = pq_size_add(der_capacity, 1, &der_capacity);
    if (ret != PQ_SUCCESS || der_capacity == 0) {
        pq_secure_wipe(encoded, encoded_len + 1);
        free(encoded);
        return PQ_ERROR_BUFFER;
    }

    der = malloc(der_capacity);
    if (!der) {
        pq_secure_wipe(encoded, encoded_len + 1);
        free(encoded);
        return PQ_ERROR_NOMEM;
    }
    decoded_len = EVP_DecodeBlock(der, (unsigned char *)encoded, (int)encoded_len);
    if (decoded_len < 0) {
        pq_secure_wipe(encoded, encoded_len + 1);
        free(encoded);
        pq_secure_wipe(der, der_capacity);
        free(der);
        return PQ_ERROR_BUFFER;
    }
    if (encoded_len >= 1 && encoded[encoded_len - 1] == '=')
        pad++;
    if (encoded_len >= 2 && encoded[encoded_len - 2] == '=')
        pad++;
    if ((size_t)decoded_len < pad) {
        pq_secure_wipe(encoded, encoded_len + 1);
        free(encoded);
        pq_secure_wipe(der, der_capacity);
        free(der);
        return PQ_ERROR_BUFFER;
    }
    *der_len_out = (size_t)decoded_len - pad;
    *der_out = der;
    pq_secure_wipe(encoded, encoded_len + 1);
    free(encoded);
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

const char *pq_version(void) {
    return "0.2.0";
}
