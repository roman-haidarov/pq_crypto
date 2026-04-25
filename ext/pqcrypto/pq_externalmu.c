#include "pqcrypto_secure.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "vendor/pqclean/crypto_sign/ml-dsa-65/clean/params.h"
#include "vendor/pqclean/crypto_sign/ml-dsa-65/clean/packing.h"
#include "vendor/pqclean/crypto_sign/ml-dsa-65/clean/polyvec.h"
#include "vendor/pqclean/crypto_sign/ml-dsa-65/clean/poly.h"
#include "vendor/pqclean/crypto_sign/ml-dsa-65/clean/symmetric.h"
#include "fips202.h"
#include "randombytes.h"

#if CRHBYTES != PQ_MLDSA_MUBYTES
#error "PQ_MLDSA_MUBYTES must match PQClean's CRHBYTES"
#endif
#if TRBYTES != PQ_MLDSA_TRBYTES
#error "PQ_MLDSA_TRBYTES must match PQClean's TRBYTES"
#endif

int pq_mldsa_extract_tr_from_secret_key(uint8_t *tr_out, const uint8_t *secret_key) {
    if (tr_out == NULL || secret_key == NULL) {
        return PQ_ERROR_BUFFER;
    }

    uint8_t rho[SEEDBYTES];
    uint8_t key[SEEDBYTES];
    polyveck t0;
    polyvecl s1;
    polyveck s2;

    PQCLEAN_MLDSA65_CLEAN_unpack_sk(rho, tr_out, key, &t0, &s1, &s2, secret_key);

    pq_secure_wipe(rho, sizeof(rho));
    pq_secure_wipe(key, sizeof(key));
    pq_secure_wipe(&t0, sizeof(t0));
    pq_secure_wipe(&s1, sizeof(s1));
    pq_secure_wipe(&s2, sizeof(s2));

    return PQ_SUCCESS;
}

int pq_mldsa_compute_tr_from_public_key(uint8_t *tr_out, const uint8_t *public_key) {
    if (tr_out == NULL || public_key == NULL) {
        return PQ_ERROR_BUFFER;
    }

    shake256(tr_out, TRBYTES, public_key, PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES);
    return PQ_SUCCESS;
}

int pq_sign_mu(uint8_t *signature, size_t *signature_len, const uint8_t *mu,
               const uint8_t *secret_key) {
    if (signature == NULL || signature_len == NULL || mu == NULL || secret_key == NULL) {
        return PQ_ERROR_BUFFER;
    }

    unsigned int n;
    uint8_t rho[SEEDBYTES];
    uint8_t tr_unused[TRBYTES];
    uint8_t key[SEEDBYTES];
    uint8_t rnd[RNDBYTES];
    uint8_t mu_local[CRHBYTES];
    uint8_t rhoprime[CRHBYTES];
    uint16_t nonce = 0;
    polyvecl mat[K], s1, y, z;
    polyveck t0, s2, w1, w0, h;
    poly cp;
    shake256incctx state;

    PQCLEAN_MLDSA65_CLEAN_unpack_sk(rho, tr_unused, key, &t0, &s1, &s2, secret_key);
    pq_secure_wipe(tr_unused, sizeof(tr_unused));

    memcpy(mu_local, mu, CRHBYTES);

    randombytes(rnd, RNDBYTES);

    {
        uint8_t kr[SEEDBYTES + RNDBYTES + CRHBYTES];
        memcpy(kr, key, SEEDBYTES);
        memcpy(kr + SEEDBYTES, rnd, RNDBYTES);
        memcpy(kr + SEEDBYTES + RNDBYTES, mu_local, CRHBYTES);
        shake256(rhoprime, CRHBYTES, kr, sizeof(kr));
        pq_secure_wipe(kr, sizeof(kr));
    }

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
    shake256_inc_absorb(&state, mu_local, CRHBYTES);
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

    pq_secure_wipe(rho, sizeof(rho));
    pq_secure_wipe(key, sizeof(key));
    pq_secure_wipe(rnd, sizeof(rnd));
    pq_secure_wipe(mu_local, sizeof(mu_local));
    pq_secure_wipe(rhoprime, sizeof(rhoprime));
    pq_secure_wipe(&s1, sizeof(s1));
    pq_secure_wipe(&s2, sizeof(s2));
    pq_secure_wipe(&t0, sizeof(t0));
    pq_secure_wipe(&y, sizeof(y));
    pq_secure_wipe(&z, sizeof(z));
    pq_secure_wipe(&w0, sizeof(w0));
    pq_secure_wipe(&cp, sizeof(cp));

    return PQ_SUCCESS;
}

int pq_verify_mu(const uint8_t *signature, size_t signature_len, const uint8_t *mu,
                 const uint8_t *public_key) {
    if (signature == NULL || mu == NULL || public_key == NULL) {
        return PQ_ERROR_BUFFER;
    }
    if (signature_len != PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES) {
        return PQ_ERROR_VERIFY;
    }

    unsigned int i;
    uint8_t buf[K * POLYW1_PACKEDBYTES];
    uint8_t rho[SEEDBYTES];
    uint8_t c[CTILDEBYTES];
    uint8_t c2[CTILDEBYTES];
    poly cp;
    polyvecl mat[K], z;
    polyveck t1, w1, h;
    shake256incctx state;

    PQCLEAN_MLDSA65_CLEAN_unpack_pk(rho, &t1, public_key);
    if (PQCLEAN_MLDSA65_CLEAN_unpack_sig(c, &z, &h, signature)) {
        return PQ_ERROR_VERIFY;
    }
    if (PQCLEAN_MLDSA65_CLEAN_polyvecl_chknorm(&z, GAMMA1 - BETA)) {
        return PQ_ERROR_VERIFY;
    }

    PQCLEAN_MLDSA65_CLEAN_poly_challenge(&cp, c);
    PQCLEAN_MLDSA65_CLEAN_polyvec_matrix_expand(mat, rho);

    PQCLEAN_MLDSA65_CLEAN_polyvecl_ntt(&z);
    PQCLEAN_MLDSA65_CLEAN_polyvec_matrix_pointwise_montgomery(&w1, mat, &z);

    PQCLEAN_MLDSA65_CLEAN_poly_ntt(&cp);
    PQCLEAN_MLDSA65_CLEAN_polyveck_shiftl(&t1);
    PQCLEAN_MLDSA65_CLEAN_polyveck_ntt(&t1);
    PQCLEAN_MLDSA65_CLEAN_polyveck_pointwise_poly_montgomery(&t1, &cp, &t1);

    PQCLEAN_MLDSA65_CLEAN_polyveck_sub(&w1, &w1, &t1);
    PQCLEAN_MLDSA65_CLEAN_polyveck_reduce(&w1);
    PQCLEAN_MLDSA65_CLEAN_polyveck_invntt_tomont(&w1);

    PQCLEAN_MLDSA65_CLEAN_polyveck_caddq(&w1);
    PQCLEAN_MLDSA65_CLEAN_polyveck_use_hint(&w1, &w1, &h);
    PQCLEAN_MLDSA65_CLEAN_polyveck_pack_w1(buf, &w1);

    shake256_inc_init(&state);
    shake256_inc_absorb(&state, mu, CRHBYTES);
    shake256_inc_absorb(&state, buf, K * POLYW1_PACKEDBYTES);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(c2, CTILDEBYTES, &state);
    shake256_inc_ctx_release(&state);

    for (i = 0; i < CTILDEBYTES; ++i) {
        if (c[i] != c2[i]) {
            return PQ_ERROR_VERIFY;
        }
    }

    return PQ_SUCCESS;
}

void *pq_mu_builder_new(void) {
    shake256incctx *state = (shake256incctx *)malloc(sizeof(shake256incctx));
    if (state == NULL) {
        return NULL;
    }

    shake256_inc_init(state);
    return state;
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

    shake256incctx *state = (shake256incctx *)state_ptr;

    uint8_t prefix[2];
    prefix[0] = 0x00;
    prefix[1] = (uint8_t)ctxlen;

    shake256_inc_absorb(state, tr, TRBYTES);
    shake256_inc_absorb(state, prefix, sizeof(prefix));
    if (ctxlen > 0) {
        shake256_inc_absorb(state, ctx, ctxlen);
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

    shake256incctx *state = (shake256incctx *)state_ptr;
    shake256_inc_absorb(state, chunk, chunk_len);
    return PQ_SUCCESS;
}

int pq_mu_builder_finalize(void *state_ptr, uint8_t *mu_out) {
    if (state_ptr == NULL || mu_out == NULL) {
        return PQ_ERROR_BUFFER;
    }

    shake256incctx *state = (shake256incctx *)state_ptr;
    shake256_inc_finalize(state);
    shake256_inc_squeeze(mu_out, CRHBYTES, state);
    shake256_inc_ctx_release(state);
    free(state);
    return PQ_SUCCESS;
}

void pq_mu_builder_release(void *state_ptr) {
    if (state_ptr == NULL) {
        return;
    }
    shake256incctx *state = (shake256incctx *)state_ptr;
    shake256_inc_ctx_release(state);
    free(state);
}
