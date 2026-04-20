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
#include <openssl/aes.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#error "OpenSSL 1.1.0 or later is required for security"
#endif

#ifndef HAVE_PQCLEAN
#error "PQClean-backed algorithms are required. Run: bundle exec rake vendor"
#endif

#include "mlkem_api.h"
#include "mldsa_api.h"

void pq_secure_wipe(void *ptr, size_t len) {
    volatile uint8_t *p = ptr;
    while (len--) {
        *p++ = 0;
    }

    __asm__ __volatile__("" : : "r"(ptr) : "memory");
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

static int secure_aes_gcm_encrypt(uint8_t *ciphertext, size_t *ciphertext_len, uint8_t *tag,
                                  const uint8_t *plaintext, size_t plaintext_len,
                                  const uint8_t *aad, size_t aad_len, const uint8_t *nonce,
                                  const uint8_t *key) {
    int plaintext_len_i = 0;
    int aad_len_i = 0;

    if (size_t_to_int_checked(plaintext_len, &plaintext_len_i) != PQ_SUCCESS)
        return PQ_ERROR_BUFFER;
    if (size_t_to_int_checked(aad_len, &aad_len_i) != PQ_SUCCESS)
        return PQ_ERROR_BUFFER;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return PQ_ERROR_OPENSSL;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return PQ_ERROR_OPENSSL;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_NONCE_BYTES, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return PQ_ERROR_OPENSSL;
    }

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return PQ_ERROR_OPENSSL;
    }

    int outlen = 0;
    int tmplen = 0;

    if (aad && aad_len > 0) {
        if (EVP_EncryptUpdate(ctx, NULL, &tmplen, aad, aad_len_i) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return PQ_ERROR_OPENSSL;
        }
    }

    if (EVP_EncryptUpdate(ctx, ciphertext, &outlen, plaintext, plaintext_len_i) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return PQ_ERROR_OPENSSL;
    }

    if (EVP_EncryptFinal_ex(ctx, ciphertext + outlen, &tmplen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return PQ_ERROR_OPENSSL;
    }

    *ciphertext_len = outlen + tmplen;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_TAG_BYTES, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return PQ_ERROR_OPENSSL;
    }

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

static int secure_aes_gcm_decrypt(uint8_t *plaintext, size_t *plaintext_len,
                                  const uint8_t *ciphertext, size_t ciphertext_len,
                                  const uint8_t *aad, size_t aad_len, const uint8_t *tag,
                                  const uint8_t *nonce, const uint8_t *key) {
    int ciphertext_len_i = 0;
    int aad_len_i = 0;

    if (size_t_to_int_checked(ciphertext_len, &ciphertext_len_i) != PQ_SUCCESS)
        return PQ_ERROR_BUFFER;
    if (size_t_to_int_checked(aad_len, &aad_len_i) != PQ_SUCCESS)
        return PQ_ERROR_BUFFER;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return PQ_ERROR_OPENSSL;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return PQ_ERROR_OPENSSL;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_NONCE_BYTES, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return PQ_ERROR_OPENSSL;
    }

    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return PQ_ERROR_OPENSSL;
    }

    int outlen = 0;
    int tmplen = 0;

    if (aad && aad_len > 0) {
        if (EVP_DecryptUpdate(ctx, NULL, &tmplen, aad, aad_len_i) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return PQ_ERROR_OPENSSL;
        }
    }

    if (EVP_DecryptUpdate(ctx, plaintext, &outlen, ciphertext, ciphertext_len_i) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return PQ_ERROR_OPENSSL;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_TAG_BYTES, (void *)tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return PQ_ERROR_OPENSSL;
    }

    int ret = EVP_DecryptFinal_ex(ctx, plaintext + outlen, &tmplen);

    if (ret > 0) {
        *plaintext_len = outlen + tmplen;
    }

    EVP_CIPHER_CTX_free(ctx);

    return (ret > 0) ? 0 : PQ_ERROR_AUTH;
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

static void store_be64(uint8_t *output, uint64_t value) {
    for (int i = 7; i >= 0; i--) {
        output[i] = (uint8_t)(value & 0xFF);
        value >>= 8;
    }
}

static uint64_t load_be64(const uint8_t *input) {
    uint64_t value = 0;
    for (int i = 0; i < 8; i++) {
        value = (value << 8) | input[i];
    }
    return value;
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

static int derive_session_keys(pq_session_t *session, const uint8_t *shared_secret,
                               int is_initiator) {
    static const uint8_t i2r_label[] = "pqcrypto/v1/session/initiator-to-responder";
    static const uint8_t r2i_label[] = "pqcrypto/v1/session/responder-to-initiator";
    uint8_t initiator_to_responder[AES_KEY_BYTES];
    uint8_t responder_to_initiator[AES_KEY_BYTES];
    int ret = secure_hkdf(initiator_to_responder, sizeof(initiator_to_responder), shared_secret,
                          HYBRID_SHAREDSECRETBYTES, NULL, 0, i2r_label, sizeof(i2r_label) - 1);
    if (ret != PQ_SUCCESS) {
        return ret;
    }

    ret = secure_hkdf(responder_to_initiator, sizeof(responder_to_initiator), shared_secret,
                      HYBRID_SHAREDSECRETBYTES, NULL, 0, r2i_label, sizeof(r2i_label) - 1);
    if (ret != PQ_SUCCESS) {
        pq_secure_wipe(initiator_to_responder, sizeof(initiator_to_responder));
        return ret;
    }

    if (is_initiator) {
        memcpy(session->send_key, initiator_to_responder, AES_KEY_BYTES);
        memcpy(session->recv_key, responder_to_initiator, AES_KEY_BYTES);
    } else {
        memcpy(session->send_key, responder_to_initiator, AES_KEY_BYTES);
        memcpy(session->recv_key, initiator_to_responder, AES_KEY_BYTES);
    }

    pq_secure_wipe(initiator_to_responder, sizeof(initiator_to_responder));
    pq_secure_wipe(responder_to_initiator, sizeof(responder_to_initiator));
    return PQ_SUCCESS;
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

int pq_testing_mldsa_keypair_from_seed(uint8_t *public_key, uint8_t *secret_key,
                                       const uint8_t *seed, size_t seed_len) {
    if (!public_key || !secret_key || !seed || seed_len != 32) {
        return PQ_ERROR_BUFFER;
    }

    return PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair_seed(public_key, secret_key, seed) == 0
               ? PQ_SUCCESS
               : PQ_ERROR_KEYPAIR;
}

int pq_testing_mldsa_sign_from_seed(uint8_t *signature, size_t *signature_len,
                                    const uint8_t *message, size_t message_len,
                                    const uint8_t *secret_key, const uint8_t *seed,
                                    size_t seed_len) {
    if (!signature || !signature_len || !message || !secret_key || !seed || seed_len != 32) {
        return PQ_ERROR_BUFFER;
    }

    return PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature_seed(signature, signature_len, message,
                                                            message_len, secret_key, seed) == 0
               ? PQ_SUCCESS
               : PQ_ERROR_SIGN;
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

int pq_hybrid_keypair(uint8_t *public_key, uint8_t *secret_key) {
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

int pq_hybrid_encapsulate(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key) {
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

int pq_hybrid_decapsulate(uint8_t *shared_secret, const uint8_t *ciphertext,
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

int pq_session_init(pq_session_t *session, const uint8_t *shared_secret, int is_initiator) {
    if (!session || !shared_secret) {
        return PQ_ERROR_BUFFER;
    }

    memset(session, 0, sizeof(*session));
    session->is_initiator = is_initiator ? 1 : 0;
    atomic_store(&session->send_nonce_counter, 0);
    session->expected_recv_nonce = 0;

    return derive_session_keys(session, shared_secret, session->is_initiator);
}

static void session_next_nonce(pq_session_t *session, uint8_t *nonce, uint64_t counter) {
    memset(nonce, 0, AES_NONCE_BYTES);
    store_be64(nonce + 4, counter);
}

int pq_session_encrypt(pq_session_t *session, uint8_t *output, size_t *output_len,
                       const uint8_t *plaintext, size_t plaintext_len, const uint8_t *aad,
                       size_t aad_len) {
    aes_gcm_header_t *header = (aes_gcm_header_t *)output;
    uint8_t *ciphertext = output + sizeof(aes_gcm_header_t);
    size_t ciphertext_len;
    uint64_t counter = atomic_fetch_add(&session->send_nonce_counter, 1);

    session_next_nonce(session, header->nonce, counter);

    int ret = secure_aes_gcm_encrypt(ciphertext, &ciphertext_len, header->tag, plaintext,
                                     plaintext_len, aad, aad_len, header->nonce, session->send_key);

    if (ret != 0) {
        return PQ_ERROR_ENCRYPT;
    }

    *output_len = sizeof(aes_gcm_header_t) + ciphertext_len;
    return PQ_SUCCESS;
}

int pq_session_decrypt(pq_session_t *session, uint8_t *plaintext, size_t *plaintext_len,
                       const uint8_t *input, size_t input_len, const uint8_t *aad, size_t aad_len) {
    if (input_len < sizeof(aes_gcm_header_t)) {
        return PQ_ERROR_BUFFER;
    }

    const aes_gcm_header_t *header = (const aes_gcm_header_t *)input;
    const uint8_t *ciphertext = input + sizeof(aes_gcm_header_t);
    size_t ciphertext_len = input_len - sizeof(aes_gcm_header_t);

    if (header->nonce[0] != 0 || header->nonce[1] != 0 || header->nonce[2] != 0 ||
        header->nonce[3] != 0) {
        return PQ_ERROR_AUTH;
    }

    uint64_t received_counter = load_be64(header->nonce + 4);
    if (received_counter != session->expected_recv_nonce) {
        return PQ_ERROR_AUTH;
    }

    int ret = secure_aes_gcm_decrypt(plaintext, plaintext_len, ciphertext, ciphertext_len, aad,
                                     aad_len, header->tag, header->nonce, session->recv_key);

    if (ret != 0) {
        return PQ_ERROR_AUTH;
    }

    session->expected_recv_nonce += 1;
    return PQ_SUCCESS;
}

void pq_session_destroy(pq_session_t *session) {
    if (session) {
        pq_secure_wipe(session, sizeof(*session));
    }
}

int pq_kem_keypair(uint8_t *public_key, uint8_t *secret_key) {
    return pq_hybrid_keypair(public_key, secret_key);
}

int pq_kem_encapsulate(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key) {
    return pq_hybrid_encapsulate(ciphertext, shared_secret, public_key);
}

int pq_kem_decapsulate(uint8_t *shared_secret, const uint8_t *ciphertext,
                       const uint8_t *secret_key) {
    return pq_hybrid_decapsulate(shared_secret, ciphertext, secret_key);
}

int pq_hybrid_kem_keypair(uint8_t *public_key, uint8_t *secret_key) {
    return pq_hybrid_keypair(public_key, secret_key);
}

int pq_hybrid_kem_encapsulate(uint8_t *ciphertext, uint8_t *shared_secret,
                              const uint8_t *public_key) {
    return pq_hybrid_encapsulate(ciphertext, shared_secret, public_key);
}

int pq_hybrid_kem_decapsulate(uint8_t *shared_secret, const uint8_t *ciphertext,
                              const uint8_t *secret_key) {
    return pq_hybrid_decapsulate(shared_secret, ciphertext, secret_key);
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

pq_session_t *pq_session_create(const uint8_t *shared_secret, int is_initiator) {
    pq_session_t *session = malloc(sizeof(pq_session_t));
    if (!session)
        return NULL;

    if (pq_session_init(session, shared_secret, is_initiator) != PQ_SUCCESS) {
        pq_secure_wipe(session, sizeof(*session));
        free(session);
        return NULL;
    }

    return session;
}

size_t pq_session_encrypt_len(size_t plaintext_len) {
    return plaintext_len + PQ_SESSION_OVERHEAD;
}

int pq_seal(uint8_t *output, size_t *output_len, const uint8_t *message, size_t message_len,
            const uint8_t *public_key) {
    uint8_t shared_secret[HYBRID_SHAREDSECRETBYTES];
    pq_session_t session;
    size_t encrypted_len = 0;
    int ret;

    memset(shared_secret, 0, sizeof(shared_secret));
    memset(&session, 0, sizeof(session));

    ret = pq_hybrid_encapsulate(output, shared_secret, public_key);
    if (ret != PQ_SUCCESS) {
        pq_secure_wipe(shared_secret, sizeof(shared_secret));
        return ret;
    }

    ret = pq_session_init(&session, shared_secret, 1);
    pq_secure_wipe(shared_secret, sizeof(shared_secret));
    if (ret != PQ_SUCCESS) {
        pq_session_destroy(&session);
        return ret;
    }

    ret = pq_session_encrypt(&session, output + HYBRID_CIPHERTEXTBYTES, &encrypted_len, message,
                             message_len, NULL, 0);
    pq_session_destroy(&session);
    if (ret != PQ_SUCCESS) {
        return ret;
    }

    *output_len = HYBRID_CIPHERTEXTBYTES + encrypted_len;
    return PQ_SUCCESS;
}

int pq_unseal(uint8_t *plaintext, size_t *plaintext_len, const uint8_t *sealed, size_t sealed_len,
              const uint8_t *secret_key) {
    uint8_t shared_secret[HYBRID_SHAREDSECRETBYTES];
    pq_session_t session;
    int ret;

    if (sealed_len < HYBRID_CIPHERTEXTBYTES + PQ_SESSION_OVERHEAD) {
        return PQ_ERROR_BUFFER;
    }

    memset(shared_secret, 0, sizeof(shared_secret));
    memset(&session, 0, sizeof(session));

    ret = pq_hybrid_decapsulate(shared_secret, sealed, secret_key);
    if (ret != PQ_SUCCESS) {
        pq_secure_wipe(shared_secret, sizeof(shared_secret));
        return ret;
    }

    ret = pq_session_init(&session, shared_secret, 0);
    pq_secure_wipe(shared_secret, sizeof(shared_secret));
    if (ret != PQ_SUCCESS) {
        pq_session_destroy(&session);
        return ret;
    }

    ret = pq_session_decrypt(&session, plaintext, plaintext_len, sealed + HYBRID_CIPHERTEXTBYTES,
                             sealed_len - HYBRID_CIPHERTEXTBYTES, NULL, 0);
    pq_session_destroy(&session);
    return ret;
}

#define PQ_SIGNED_SEAL_MAGIC_0      'P'
#define PQ_SIGNED_SEAL_MAGIC_1      'Q'
#define PQ_SIGNED_SEAL_MAGIC_2      '1'
#define PQ_SIGNED_SEAL_MAGIC_3      '0'
#define PQ_SIGNED_SEAL_VERSION      0x01
#define PQ_SIGNED_SEAL_SUITE_ID     0x01
#define PQ_SIGNED_SEAL_HEADER_BYTES 6

int pq_sign_and_seal(uint8_t *output, size_t *output_len, const uint8_t *message,
                     size_t message_len, const uint8_t *kem_public_key,
                     const uint8_t *sign_secret_key) {
    uint8_t *sealed = NULL;
    size_t sealed_len = 0;
    size_t signature_len = PQ_MLDSA_BYTES;
    const size_t header_off = PQ_SIGNED_SEAL_HEADER_BYTES;
    int ret;

    sealed = malloc(HYBRID_CIPHERTEXTBYTES + pq_session_encrypt_len(message_len));
    if (!sealed) {
        return PQ_ERROR_NOMEM;
    }

    ret = pq_seal(sealed, &sealed_len, message, message_len, kem_public_key);
    if (ret != PQ_SUCCESS) {
        free(sealed);
        return ret;
    }

    ret = pq_sign(output + header_off + 4, &signature_len, sealed, sealed_len, sign_secret_key);
    if (ret != PQ_SUCCESS) {
        pq_secure_wipe(sealed, sealed_len);
        free(sealed);
        return ret;
    }

    output[0] = PQ_SIGNED_SEAL_MAGIC_0;
    output[1] = PQ_SIGNED_SEAL_MAGIC_1;
    output[2] = PQ_SIGNED_SEAL_MAGIC_2;
    output[3] = PQ_SIGNED_SEAL_MAGIC_3;
    output[4] = PQ_SIGNED_SEAL_VERSION;
    output[5] = PQ_SIGNED_SEAL_SUITE_ID;

    output[header_off + 0] = (uint8_t)((signature_len >> 24) & 0xFF);
    output[header_off + 1] = (uint8_t)((signature_len >> 16) & 0xFF);
    output[header_off + 2] = (uint8_t)((signature_len >> 8) & 0xFF);
    output[header_off + 3] = (uint8_t)(signature_len & 0xFF);
    memcpy(output + header_off + 4 + signature_len, sealed, sealed_len);
    *output_len = header_off + 4 + signature_len + sealed_len;

    pq_secure_wipe(sealed, sealed_len);
    free(sealed);
    return PQ_SUCCESS;
}

int pq_unseal_and_verify(uint8_t *plaintext, size_t *plaintext_len, const uint8_t *input,
                         size_t input_len, const uint8_t *kem_secret_key,
                         const uint8_t *sign_public_key) {
    uint32_t signature_len;
    const uint8_t *sealed;
    size_t sealed_len;
    const size_t header_off = PQ_SIGNED_SEAL_HEADER_BYTES;
    int ret;

    if (input_len < header_off + 4 + HYBRID_CIPHERTEXTBYTES + PQ_SESSION_OVERHEAD) {
        return PQ_ERROR_BUFFER;
    }

    if (input[0] != PQ_SIGNED_SEAL_MAGIC_0 || input[1] != PQ_SIGNED_SEAL_MAGIC_1 ||
        input[2] != PQ_SIGNED_SEAL_MAGIC_2 || input[3] != PQ_SIGNED_SEAL_MAGIC_3) {
        return PQ_ERROR_VERIFY;
    }
    if (input[4] != PQ_SIGNED_SEAL_VERSION) {
        return PQ_ERROR_VERIFY;
    }
    if (input[5] != PQ_SIGNED_SEAL_SUITE_ID) {
        return PQ_ERROR_VERIFY;
    }

    signature_len = ((uint32_t)input[header_off + 0] << 24) |
                    ((uint32_t)input[header_off + 1] << 16) |
                    ((uint32_t)input[header_off + 2] << 8) | (uint32_t)input[header_off + 3];

    if (signature_len == 0 || signature_len > PQ_MLDSA_BYTES) {
        return PQ_ERROR_BUFFER;
    }

    if (input_len < header_off + 4 + signature_len + HYBRID_CIPHERTEXTBYTES + PQ_SESSION_OVERHEAD) {
        return PQ_ERROR_BUFFER;
    }

    sealed = input + header_off + 4 + signature_len;
    sealed_len = input_len - header_off - 4 - signature_len;

    ret = pq_verify(input + header_off + 4, signature_len, sealed, sealed_len, sign_public_key);
    if (ret != PQ_SUCCESS) {
        return PQ_ERROR_VERIFY;
    }

    return pq_unseal(plaintext, plaintext_len, sealed, sealed_len, kem_secret_key);
}

int pq_public_key_pem(char **output, size_t *output_len, const uint8_t *public_key,
                      size_t public_key_len) {
    static const char pem_begin[] = "-----BEGIN HYBRID PUBLIC KEY-----\n";
    static const char pem_end[] = "-----END HYBRID PUBLIC KEY-----\n";
    size_t encoded_len;
    size_t line_count;
    size_t body_len;
    size_t total_len;
    unsigned char *encoded = NULL;
    char *pem = NULL;
    char *cursor;

    if (!output || !output_len || !public_key || public_key_len != HYBRID_PUBLICKEYBYTES) {
        return PQ_ERROR_BUFFER;
    }

    encoded_len = 4 * ((public_key_len + 2) / 3);
    line_count = (encoded_len + 63) / 64;
    body_len = encoded_len + line_count;
    total_len = (sizeof(pem_begin) - 1) + body_len + (sizeof(pem_end) - 1);

    encoded = malloc(encoded_len + 1);
    if (!encoded) {
        return PQ_ERROR_NOMEM;
    }

    pem = malloc(total_len);
    if (!pem) {
        free(encoded);
        return PQ_ERROR_NOMEM;
    }

    if (EVP_EncodeBlock(encoded, public_key, (int)public_key_len) != (int)encoded_len) {
        pq_secure_wipe(encoded, encoded_len + 1);
        free(encoded);
        pq_secure_wipe(pem, total_len);
        free(pem);
        return PQ_ERROR_OPENSSL;
    }

    cursor = pem;
    memcpy(cursor, pem_begin, sizeof(pem_begin) - 1);
    cursor += sizeof(pem_begin) - 1;

    for (size_t offset = 0; offset < encoded_len; offset += 64) {
        size_t chunk_len = encoded_len - offset;
        if (chunk_len > 64) {
            chunk_len = 64;
        }

        memcpy(cursor, encoded + offset, chunk_len);
        cursor += chunk_len;
        *cursor++ = '\n';
    }

    memcpy(cursor, pem_end, sizeof(pem_end) - 1);
    cursor += sizeof(pem_end) - 1;

    *output = pem;
    *output_len = total_len;

    pq_secure_wipe(encoded, encoded_len + 1);
    free(encoded);
    return PQ_SUCCESS;
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

static int pq_serialization_key_bytes_for_algorithm(const char *algorithm, int is_public,
                                                    size_t *expected_len) {
    if (!algorithm || !expected_len)
        return PQ_ERROR_BUFFER;
    if (strcmp(algorithm, "ml_kem_768") == 0) {
        *expected_len = is_public ? PQ_MLKEM_PUBLICKEYBYTES : PQ_MLKEM_SECRETKEYBYTES;
        return PQ_SUCCESS;
    }
    if (strcmp(algorithm, "ml_kem_768_x25519_hkdf_sha256") == 0 ||
        strcmp(algorithm, "ml_kem_768_x25519") == 0) {
        *expected_len = is_public ? PQ_HYBRID_PUBLICKEYBYTES : PQ_HYBRID_SECRETKEYBYTES;
        return PQ_SUCCESS;
    }
    if (strcmp(algorithm, "ml_dsa_65") == 0) {
        *expected_len = is_public ? MLDSA_PUBLICKEYBYTES : MLDSA_SECRETKEYBYTES;
        return PQ_SUCCESS;
    }
    return PQ_ERROR_BUFFER;
}

static int pq_serialization_oid_for_algorithm(const char *algorithm, const char **oid_out) {
    if (!algorithm || !oid_out)
        return PQ_ERROR_BUFFER;
    if (strcmp(algorithm, "ml_kem_768") == 0) {
        *oid_out = PQC_OID_ML_KEM_768;
        return PQ_SUCCESS;
    }
    if (strcmp(algorithm, "ml_kem_768_x25519_hkdf_sha256") == 0 ||
        strcmp(algorithm, "ml_kem_768_x25519") == 0) {
        *oid_out = PQC_OID_ML_KEM_768_X25519_HKDF_SHA256;
        return PQ_SUCCESS;
    }
    if (strcmp(algorithm, "ml_dsa_65") == 0) {
        *oid_out = PQC_OID_ML_DSA_65;
        return PQ_SUCCESS;
    }
    return PQ_ERROR_BUFFER;
}

static int pq_serialization_algorithm_for_oid(const char *oid, size_t oid_len,
                                              const char **algorithm_out) {
    if (!oid || !algorithm_out)
        return PQ_ERROR_BUFFER;
    if (oid_len == strlen(PQC_OID_ML_KEM_768) && memcmp(oid, PQC_OID_ML_KEM_768, oid_len) == 0) {
        *algorithm_out = "ml_kem_768";
        return PQ_SUCCESS;
    }
    if (oid_len == strlen(PQC_OID_ML_KEM_768_X25519_HKDF_SHA256) &&
        memcmp(oid, PQC_OID_ML_KEM_768_X25519_HKDF_SHA256, oid_len) == 0) {
        *algorithm_out = "ml_kem_768_x25519_hkdf_sha256";
        return PQ_SUCCESS;
    }
    if (oid_len == strlen(PQC_OID_ML_DSA_65) && memcmp(oid, PQC_OID_ML_DSA_65, oid_len) == 0) {
        *algorithm_out = "ml_dsa_65";
        return PQ_SUCCESS;
    }
    return PQ_ERROR_BUFFER;
}

static int pq_encode_serialized_key(uint8_t **output, size_t *output_len, uint8_t type,
                                    const uint8_t *key_bytes, size_t key_len,
                                    const char *algorithm) {
    const char *oid = NULL;
    size_t expected_len = 0;
    size_t oid_len;
    size_t total_len;
    uint8_t *buf;
    int ret;

    if (!output || !output_len || !key_bytes || !algorithm)
        return PQ_ERROR_BUFFER;

    ret = pq_serialization_key_bytes_for_algorithm(algorithm, type == PQC_SERIALIZATION_TYPE_PUBLIC,
                                                   &expected_len);
    if (ret != PQ_SUCCESS || key_len != expected_len)
        return PQ_ERROR_BUFFER;
    ret = pq_serialization_oid_for_algorithm(algorithm, &oid);
    if (ret != PQ_SUCCESS)
        return ret;

    oid_len = strlen(oid);
    total_len = 4 + 1 + 1 + 2 + oid_len + 4 + key_len;
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
    memcpy(buf + 8, oid, oid_len);
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
    const char *algorithm = NULL;
    size_t offset;
    size_t expected_len = 0;
    uint8_t *key_copy;
    int ret;

    if (!input || !algorithm_out || !key_out || !key_len_out)
        return PQ_ERROR_BUFFER;
    if (input_len < 12)
        return PQ_ERROR_BUFFER;
    if (input[0] != PQC_SERIALIZATION_MAGIC_0 || input[1] != PQC_SERIALIZATION_MAGIC_1 ||
        input[2] != PQC_SERIALIZATION_MAGIC_2 || input[3] != PQC_SERIALIZATION_MAGIC_3) {
        return PQ_ERROR_BUFFER;
    }
    if (input[4] != PQC_SERIALIZATION_VERSION || input[5] != expected_type)
        return PQ_ERROR_BUFFER;

    oid_len = ((uint16_t)input[6] << 8) | (uint16_t)input[7];
    offset = 8;
    if (input_len < offset + oid_len + 4)
        return PQ_ERROR_BUFFER;
    ret = pq_serialization_algorithm_for_oid((const char *)(input + offset), oid_len, &algorithm);
    if (ret != PQ_SUCCESS)
        return ret;
    offset += oid_len;
    key_len = ((uint32_t)input[offset + 0] << 24) | ((uint32_t)input[offset + 1] << 16) |
              ((uint32_t)input[offset + 2] << 8) | (uint32_t)input[offset + 3];
    offset += 4;
    if (input_len != offset + key_len)
        return PQ_ERROR_BUFFER;
    ret = pq_serialization_key_bytes_for_algorithm(
        algorithm, expected_type == PQC_SERIALIZATION_TYPE_PUBLIC, &expected_len);
    if (ret != PQ_SUCCESS || key_len != expected_len)
        return PQ_ERROR_BUFFER;

    key_copy = malloc(key_len);
    if (!key_copy)
        return PQ_ERROR_NOMEM;
    memcpy(key_copy, input + offset, key_len);

    {
        size_t algorithm_len = strlen(algorithm);
        *algorithm_out = malloc(algorithm_len + 1);
        if (!*algorithm_out) {
            pq_secure_wipe(key_copy, key_len);
            free(key_copy);
            return PQ_ERROR_NOMEM;
        }
        memcpy(*algorithm_out, algorithm, algorithm_len + 1);
    }
    *key_out = key_copy;
    *key_len_out = key_len;
    return PQ_SUCCESS;
}

static int pq_der_to_pem(const char *label, const uint8_t *der, size_t der_len, char **output,
                         size_t *output_len) {
    size_t encoded_len, line_count, body_len, total_len;
    unsigned char *encoded = NULL;
    char *pem = NULL;
    char header[64];
    char footer[64];
    char *cursor;
    int header_len, footer_len;

    if (!label || !der || !output || !output_len)
        return PQ_ERROR_BUFFER;
    header_len = snprintf(header, sizeof(header), "-----BEGIN %s-----", label);
    footer_len = snprintf(footer, sizeof(footer), "-----END %s-----", label);
    if (header_len <= 0 || footer_len <= 0)
        return PQ_ERROR_BUFFER;

    encoded_len = 4 * ((der_len + 2) / 3);
    line_count = (encoded_len + 63) / 64;
    body_len = encoded_len + line_count;
    total_len = (size_t)header_len + body_len + (size_t)footer_len;

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
    memcpy(cursor, header, header_len);
    cursor += header_len;
    for (size_t off = 0; off < encoded_len; off += 64) {
        size_t chunk = encoded_len - off;
        if (chunk > 64)
            chunk = 64;
        memcpy(cursor, encoded + off, chunk);
        cursor += chunk;
        *cursor++ = '\n';
    }
    memcpy(cursor, footer, footer_len);
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
    char *encoded = NULL;
    uint8_t *der = NULL;
    size_t encoded_len = 0;
    int decoded_len;
    size_t pad = 0;

    if (!label || !input || !der_out || !der_len_out)
        return PQ_ERROR_BUFFER;
    header_len = snprintf(header, sizeof(header), "-----BEGIN %s-----", label);
    footer_len = snprintf(footer, sizeof(footer), "-----END %s-----", label);
    if (header_len <= 0 || footer_len <= 0)
        return PQ_ERROR_BUFFER;
    if (input_len < (size_t)(header_len + footer_len + 2))
        return PQ_ERROR_BUFFER;
    if (strncmp(input, header, (size_t)header_len) != 0)
        return PQ_ERROR_BUFFER;
    body_start = input + header_len;
    while ((size_t)(body_start - input) < input_len && (*body_start == '\n' || *body_start == '\r'))
        body_start++;
    footer_pos = NULL;
    {
        size_t remaining = input_len - (size_t)(body_start - input);
        size_t footer_size = (size_t)footer_len;
        if (remaining < footer_size) {
            return PQ_ERROR_BUFFER;
        }
        for (size_t i = 0; i <= remaining - footer_size; ++i) {
            if (memcmp(body_start + i, footer, footer_size) == 0) {
                footer_pos = body_start + i;
                break;
            }
        }
    }
    if (!footer_pos)
        return PQ_ERROR_BUFFER;

    encoded = malloc((size_t)(footer_pos - body_start) + 1);
    if (!encoded)
        return PQ_ERROR_NOMEM;
    for (const char *p = body_start; p < footer_pos; ++p) {
        if (*p == '\n' || *p == '\r' || *p == ' ' || *p == '\t')
            continue;
        encoded[encoded_len++] = *p;
    }
    if (encoded_len == 0 || (encoded_len % 4) != 0) {
        free(encoded);
        return PQ_ERROR_BUFFER;
    }
    encoded[encoded_len] = '\0';

    der = malloc((encoded_len / 4) * 3 + 1);
    if (!der) {
        free(encoded);
        return PQ_ERROR_NOMEM;
    }
    decoded_len = EVP_DecodeBlock(der, (unsigned char *)encoded, (int)encoded_len);
    if (decoded_len < 0) {
        free(encoded);
        free(der);
        return PQ_ERROR_BUFFER;
    }
    if (encoded_len >= 1 && encoded[encoded_len - 1] == '=')
        pad++;
    if (encoded_len >= 2 && encoded[encoded_len - 2] == '=')
        pad++;
    *der_len_out = (size_t)decoded_len - pad;
    *der_out = der;
    pq_secure_wipe(encoded, encoded_len + 1);
    free(encoded);
    return PQ_SUCCESS;
}

int pq_public_key_to_spki_der(uint8_t **output, size_t *output_len, const uint8_t *public_key,
                              size_t public_key_len, const char *algorithm) {
    return pq_encode_serialized_key(output, output_len, PQC_SERIALIZATION_TYPE_PUBLIC, public_key,
                                    public_key_len, algorithm);
}

int pq_public_key_to_spki_pem(char **output, size_t *output_len, const uint8_t *public_key,
                              size_t public_key_len, const char *algorithm) {
    uint8_t *der = NULL;
    size_t der_len = 0;
    int ret;
    ret = pq_public_key_to_spki_der(&der, &der_len, public_key, public_key_len, algorithm);
    if (ret != PQ_SUCCESS)
        return ret;
    ret = pq_der_to_pem("PQC PUBLIC KEY CONTAINER", der, der_len, output, output_len);
    pq_secure_wipe(der, der_len);
    free(der);
    return ret;
}

int pq_secret_key_to_pkcs8_der(uint8_t **output, size_t *output_len, const uint8_t *secret_key,
                               size_t secret_key_len, const char *algorithm) {
    return pq_encode_serialized_key(output, output_len, PQC_SERIALIZATION_TYPE_SECRET, secret_key,
                                    secret_key_len, algorithm);
}

int pq_secret_key_to_pkcs8_pem(char **output, size_t *output_len, const uint8_t *secret_key,
                               size_t secret_key_len, const char *algorithm) {
    uint8_t *der = NULL;
    size_t der_len = 0;
    int ret;
    ret = pq_secret_key_to_pkcs8_der(&der, &der_len, secret_key, secret_key_len, algorithm);
    if (ret != PQ_SUCCESS)
        return ret;
    ret = pq_der_to_pem("PQC PRIVATE KEY CONTAINER", der, der_len, output, output_len);
    pq_secure_wipe(der, der_len);
    free(der);
    return ret;
}

int pq_public_key_from_spki_der(char **algorithm_out, uint8_t **key_out, size_t *key_len_out,
                                const uint8_t *input, size_t input_len) {
    return pq_decode_serialized_key(input, input_len, PQC_SERIALIZATION_TYPE_PUBLIC, algorithm_out,
                                    key_out, key_len_out);
}

int pq_public_key_from_spki_pem(char **algorithm_out, uint8_t **key_out, size_t *key_len_out,
                                const char *input, size_t input_len) {
    uint8_t *der = NULL;
    size_t der_len = 0;
    int ret;
    ret = pq_pem_to_der("PQC PUBLIC KEY CONTAINER", input, input_len, &der, &der_len);
    if (ret != PQ_SUCCESS)
        return ret;
    ret = pq_public_key_from_spki_der(algorithm_out, key_out, key_len_out, der, der_len);
    pq_secure_wipe(der, der_len);
    free(der);
    return ret;
}

int pq_secret_key_from_pkcs8_der(char **algorithm_out, uint8_t **key_out, size_t *key_len_out,
                                 const uint8_t *input, size_t input_len) {
    return pq_decode_serialized_key(input, input_len, PQC_SERIALIZATION_TYPE_SECRET, algorithm_out,
                                    key_out, key_len_out);
}

int pq_secret_key_from_pkcs8_pem(char **algorithm_out, uint8_t **key_out, size_t *key_len_out,
                                 const char *input, size_t input_len) {
    uint8_t *der = NULL;
    size_t der_len = 0;
    int ret;
    ret = pq_pem_to_der("PQC PRIVATE KEY CONTAINER", input, input_len, &der, &der_len);
    if (ret != PQ_SUCCESS)
        return ret;
    ret = pq_secret_key_from_pkcs8_der(algorithm_out, key_out, key_len_out, der, der_len);
    pq_secure_wipe(der, der_len);
    free(der);
    return ret;
}

const char *pq_version(void) {
    return "pqcrypto-native-0.3.0+pqclean";
}
