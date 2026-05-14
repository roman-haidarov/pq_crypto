#include "pqcrypto_secure.h"

#include <openssl/evp.h>

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    EVP_MD_CTX *ctx;
} pq_mu_builder_t;

static int pq_shake256(uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int ret = PQ_ERROR_OPENSSL;

    if (!ctx) {
        return PQ_ERROR_OPENSSL;
    }
    if (EVP_DigestInit_ex(ctx, EVP_shake256(), NULL) != 1) {
        goto cleanup;
    }
    if (in_len > 0 && EVP_DigestUpdate(ctx, in, in_len) != 1) {
        goto cleanup;
    }
    if (EVP_DigestFinalXOF(ctx, out, out_len) != 1) {
        goto cleanup;
    }
    ret = PQ_SUCCESS;

cleanup:
    EVP_MD_CTX_free(ctx);
    return ret;
}

int pq_mldsa_extract_tr_from_secret_key(uint8_t *tr_out, const uint8_t *secret_key,
                                        size_t public_key_len,
                                        int (*pk_from_sk)(uint8_t *, const uint8_t *)) {
    uint8_t public_key[MLDSA87_PUBLICKEYBYTES];
    int rc;

    if (tr_out == NULL || secret_key == NULL || pk_from_sk == NULL || public_key_len == 0 ||
        public_key_len > sizeof(public_key)) {
        return PQ_ERROR_BUFFER;
    }

    memset(public_key, 0, sizeof(public_key));
    rc = pk_from_sk(public_key, secret_key);
    if (rc != 0) {
        pq_secure_wipe(public_key, sizeof(public_key));
        return PQ_ERROR_KEYPAIR;
    }

    rc = pq_shake256(tr_out, PQ_MLDSA_TRBYTES, public_key, public_key_len);
    pq_secure_wipe(public_key, sizeof(public_key));
    return rc;
}

int pq_mldsa_compute_tr_from_public_key(uint8_t *tr_out, const uint8_t *public_key,
                                        size_t public_key_len) {
    if (tr_out == NULL || public_key == NULL) {
        return PQ_ERROR_BUFFER;
    }

    return pq_shake256(tr_out, PQ_MLDSA_TRBYTES, public_key, public_key_len);
}

int pq_sign_mu(uint8_t *signature, size_t *signature_len, const uint8_t *mu,
               const uint8_t *secret_key,
               int (*signature_extmu)(uint8_t *, size_t *, const uint8_t *, const uint8_t *)) {
    if (signature == NULL || signature_len == NULL || mu == NULL || secret_key == NULL ||
        signature_extmu == NULL) {
        return PQ_ERROR_BUFFER;
    }

    return signature_extmu(signature, signature_len, mu, secret_key) == 0 ? PQ_SUCCESS
                                                                          : PQ_ERROR_SIGN;
}

int pq_verify_mu(const uint8_t *signature, size_t signature_len, const uint8_t *mu,
                 const uint8_t *public_key, size_t expected_signature_len,
                 int (*verify_extmu)(const uint8_t *, size_t, const uint8_t *, const uint8_t *)) {
    if (signature == NULL || mu == NULL || public_key == NULL || verify_extmu == NULL) {
        return PQ_ERROR_BUFFER;
    }
    if (signature_len != expected_signature_len) {
        return PQ_ERROR_VERIFY;
    }

    return verify_extmu(signature, signature_len, mu, public_key) == 0 ? PQ_SUCCESS
                                                                       : PQ_ERROR_VERIFY;
}

void *pq_mu_builder_new(void) {
    pq_mu_builder_t *builder = (pq_mu_builder_t *)calloc(1, sizeof(*builder));
    if (builder == NULL) {
        return NULL;
    }

    builder->ctx = EVP_MD_CTX_new();
    if (builder->ctx == NULL) {
        free(builder);
        return NULL;
    }
    if (EVP_DigestInit_ex(builder->ctx, EVP_shake256(), NULL) != 1) {
        EVP_MD_CTX_free(builder->ctx);
        free(builder);
        return NULL;
    }

    return builder;
}

int pq_mu_builder_init(void *state_ptr, const uint8_t *tr, const uint8_t *ctx, size_t ctxlen) {
    if (state_ptr == NULL || tr == NULL) {
        return PQ_ERROR_BUFFER;
    }
    if (ctxlen > 255) {
        return PQ_ERROR_BUFFER;
    }
    if (ctxlen > 0 && ctx == NULL) {
        return PQ_ERROR_BUFFER;
    }

    pq_mu_builder_t *builder = (pq_mu_builder_t *)state_ptr;
    uint8_t prefix[2];
    prefix[0] = 0x00;
    prefix[1] = (uint8_t)ctxlen;

    if (EVP_DigestUpdate(builder->ctx, tr, PQ_MLDSA_TRBYTES) != 1) {
        return PQ_ERROR_OPENSSL;
    }
    if (EVP_DigestUpdate(builder->ctx, prefix, sizeof(prefix)) != 1) {
        return PQ_ERROR_OPENSSL;
    }
    if (ctxlen > 0 && EVP_DigestUpdate(builder->ctx, ctx, ctxlen) != 1) {
        return PQ_ERROR_OPENSSL;
    }
    return PQ_SUCCESS;
}

int pq_mu_builder_absorb(void *state_ptr, const uint8_t *chunk, size_t chunk_len) {
    if (state_ptr == NULL) {
        return PQ_ERROR_BUFFER;
    }
    if (chunk_len == 0) {
        return PQ_SUCCESS;
    }
    if (chunk == NULL) {
        return PQ_ERROR_BUFFER;
    }

    pq_mu_builder_t *builder = (pq_mu_builder_t *)state_ptr;
    return EVP_DigestUpdate(builder->ctx, chunk, chunk_len) == 1 ? PQ_SUCCESS : PQ_ERROR_OPENSSL;
}

int pq_mu_builder_finalize(void *state_ptr, uint8_t *mu_out) {
    if (state_ptr == NULL || mu_out == NULL) {
        return PQ_ERROR_BUFFER;
    }

    pq_mu_builder_t *builder = (pq_mu_builder_t *)state_ptr;
    if (EVP_DigestFinalXOF(builder->ctx, mu_out, PQ_MLDSA_MUBYTES) != 1) {
        EVP_MD_CTX_free(builder->ctx);
        builder->ctx = NULL;
        free(builder);
        return PQ_ERROR_OPENSSL;
    }

    EVP_MD_CTX_free(builder->ctx);
    builder->ctx = NULL;
    free(builder);
    return PQ_SUCCESS;
}

void pq_mu_builder_release(void *state_ptr) {
    if (state_ptr == NULL) {
        return;
    }
    pq_mu_builder_t *builder = (pq_mu_builder_t *)state_ptr;
    if (builder->ctx != NULL) {
        EVP_MD_CTX_free(builder->ctx);
        builder->ctx = NULL;
    }
    free(builder);
}
