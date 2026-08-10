#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pqcrypto_secure.h"

static int failures;
static int checks;

static void ck(int cond, const char *what) {
    checks++;
    if (!cond) {
        failures++;
        printf("  FAIL %s\n", what);
    }
}

/*
 * Deliberately does NOT touch *siglen. Clearing it on failure is the adapter's
 * job, so a stub that cleared it here would satisfy the adapter assertions on
 * its own and hide a real regression.
 */
static int stub_failing_signature_extmu(uint8_t *sig, size_t *siglen, const uint8_t *mu,
                                        const uint8_t *sk) {
    (void)sig;
    (void)siglen;
    (void)mu;
    (void)sk;
    return -1;
}

/*
 * Reaches the genuine backend error path: randomized ML-DSA signing draws from
 * randombytes(), and pq_randombytes.c fails once an installed test seed is
 * exhausted. A zero-length seed is exhausted immediately.
 */
static uint8_t exhausted_seed_marker;

static void force_rng_failure(void) { pq_testing_set_seed(&exhausted_seed_marker, 0); }

static void restore_rng(void) { pq_testing_clear_seed(); }

static void test_sign_output_length(void) {
    uint8_t pk[MLDSA65_PUBLICKEYBYTES];
    uint8_t sk[MLDSA65_SECRETKEYBYTES];
    uint8_t sig[MLDSA65_BYTES];
    size_t signature_len;
    const uint8_t message[] = "pq_crypto C API contract";

    ck(pq_sign_keypair(pk, sk) == PQ_SUCCESS, "pq_sign_keypair");

    signature_len = 0xdeadbeef;
    ck(pq_sign(sig, &signature_len, message, sizeof(message), NULL, 0, sk) == PQ_SUCCESS,
       "pq_sign succeeds");
    ck(signature_len == MLDSA65_BYTES, "pq_sign sets *signature_len to MLDSA65_BYTES");

    uint8_t big_ctx[256];
    memset(big_ctx, 0, sizeof(big_ctx));
    signature_len = 4242;
    ck(pq_sign(sig, &signature_len, message, sizeof(message), big_ctx, sizeof(big_ctx), sk) ==
           PQ_ERROR_BUFFER,
       "pq_sign rejects an over-long context");
    ck(signature_len == 4242, "argument-validation failure leaves *signature_len untouched");

    force_rng_failure();
    signature_len = 0xdeadbeef;
    ck(pq_sign(sig, &signature_len, message, sizeof(message), NULL, 0, sk) == PQ_ERROR_SIGN,
       "pq_sign propagates a backend RNG failure");
    ck(signature_len == 0, "pq_sign clears *signature_len when the operation fails");
    restore_rng();

    signature_len = 0xdeadbeef;
    ck(pq_sign(sig, &signature_len, message, sizeof(message), NULL, 0, sk) == PQ_SUCCESS,
       "signing recovers once the RNG works again");
    ck(signature_len == MLDSA65_BYTES, "and reports the right length again");
}

/*
 * ML-DSA-44 and -87 get their own key material, and every assertion is
 * unconditional. Writing these as "signing failed OR the length is right"
 * makes them vacuous: a wrapper that always errors would pass.
 */
static void test_sign_output_length_other_levels(void) {
    const uint8_t message[] = "per-level contract";
    size_t signature_len;

    {
        uint8_t pk[MLDSA44_PUBLICKEYBYTES];
        uint8_t sk[MLDSA44_SECRETKEYBYTES];
        uint8_t sig[MLDSA44_BYTES];

        ck(pq_mldsa44_sign_keypair(pk, sk) == PQ_SUCCESS, "pq_mldsa44_sign_keypair");
        signature_len = 0xdeadbeef;
        ck(pq_mldsa44_sign(sig, &signature_len, message, sizeof(message), NULL, 0, sk) ==
               PQ_SUCCESS,
           "pq_mldsa44_sign succeeds");
        ck(signature_len == MLDSA44_BYTES, "pq_mldsa44_sign sets *signature_len");
        ck(pq_mldsa44_verify(sig, signature_len, message, sizeof(message), NULL, 0, pk) ==
               PQ_SUCCESS,
           "ML-DSA-44 round trip");
        ck(pq_mldsa44_verify(sig, MLDSA44_BYTES - 1, message, sizeof(message), NULL, 0, pk) ==
               PQ_ERROR_VERIFY,
           "ML-DSA-44 rejects a short signature");
    }

    {
        uint8_t pk[MLDSA87_PUBLICKEYBYTES];
        uint8_t sk[MLDSA87_SECRETKEYBYTES];
        uint8_t sig[MLDSA87_BYTES];

        ck(pq_mldsa87_sign_keypair(pk, sk) == PQ_SUCCESS, "pq_mldsa87_sign_keypair");
        signature_len = 0xdeadbeef;
        ck(pq_mldsa87_sign(sig, &signature_len, message, sizeof(message), NULL, 0, sk) ==
               PQ_SUCCESS,
           "pq_mldsa87_sign succeeds");
        ck(signature_len == MLDSA87_BYTES, "pq_mldsa87_sign sets *signature_len");
        ck(pq_mldsa87_verify(sig, signature_len, message, sizeof(message), NULL, 0, pk) ==
               PQ_SUCCESS,
           "ML-DSA-87 round trip");
        ck(pq_mldsa87_verify(sig, MLDSA87_BYTES - 1, message, sizeof(message), NULL, 0, pk) ==
               PQ_ERROR_VERIFY,
           "ML-DSA-87 rejects a short signature");
    }
}

static void test_verify_rejects_wrong_length(void) {
    uint8_t pk[MLDSA65_PUBLICKEYBYTES];
    uint8_t sk[MLDSA65_SECRETKEYBYTES];
    uint8_t sig[MLDSA65_BYTES];
    size_t signature_len = 0;
    const uint8_t message[] = "length validation";

    ck(pq_sign_keypair(pk, sk) == PQ_SUCCESS, "keypair for verify tests");
    ck(pq_sign(sig, &signature_len, message, sizeof(message), NULL, 0, sk) == PQ_SUCCESS, "sign");
    ck(pq_verify(sig, signature_len, message, sizeof(message), NULL, 0, pk) == PQ_SUCCESS,
       "round trip verifies");

    ck(pq_verify(sig, MLDSA65_BYTES - 1, message, sizeof(message), NULL, 0, pk) == PQ_ERROR_VERIFY,
       "short signature rejected");
    ck(pq_verify(sig, MLDSA65_BYTES + 1, message, sizeof(message), NULL, 0, pk) == PQ_ERROR_VERIFY,
       "over-long signature rejected");
    ck(pq_verify(sig, 0, message, sizeof(message), NULL, 0, pk) == PQ_ERROR_VERIFY,
       "zero-length signature rejected");

    /*
     * Exact-size allocations: without the length guard the backend would read
     * MLDSA65_BYTES from these, which a sanitizer turns into a hard failure.
     * signature_len always matches the allocation, because pq_verify's contract
     * is that signature points to signature_len valid bytes -- a caller that
     * lies about the length is out of scope and no guard could catch it.
     */
    static const size_t short_lengths[] = {1, 2, 47, 48, 64, MLDSA65_BYTES / 2};
    for (size_t i = 0; i < sizeof(short_lengths) / sizeof(short_lengths[0]); ++i) {
        size_t n = short_lengths[i];
        uint8_t *exact = malloc(n);
        ck(exact != NULL, "allocation for exact-size buffer");
        if (exact == NULL) {
            continue;
        }
        memcpy(exact, sig, n);
        ck(pq_verify(exact, n, message, sizeof(message), NULL, 0, pk) == PQ_ERROR_VERIFY,
           "exact-size short buffer rejected without reading past it");
        free(exact);
    }

    {
        uint8_t *exact44 = malloc(MLDSA44_BYTES);
        ck(exact44 != NULL, "allocation for cross-level buffer");
        if (exact44 != NULL) {
            memcpy(exact44, sig, MLDSA44_BYTES);
            ck(pq_verify(exact44, MLDSA44_BYTES, message, sizeof(message), NULL, 0, pk) ==
                   PQ_ERROR_VERIFY,
               "ML-DSA-44-sized signature rejected by ML-DSA-65 verify without over-reading");
            free(exact44);
        }
    }
}

static void test_extmu_length_contract(void) {
    uint8_t pk[MLDSA65_PUBLICKEYBYTES];
    uint8_t sk[MLDSA65_SECRETKEYBYTES];
    uint8_t tr[PQ_MLDSA_TRBYTES];
    uint8_t mu[PQ_MLDSA_MUBYTES];
    uint8_t sig[MLDSA65_BYTES];
    size_t signature_len;
    const uint8_t message[] = "external mu contract";
    void *builder;

    ck(pq_sign_keypair(pk, sk) == PQ_SUCCESS, "keypair for extmu tests");
    ck(pq_mldsa_compute_tr_from_public_key(tr, pk, sizeof(pk)) == PQ_SUCCESS, "compute tr");

    builder = pq_mu_builder_new();
    ck(builder != NULL, "mu builder allocated");
    ck(pq_mu_builder_init(builder, tr, NULL, 0) == PQ_SUCCESS, "mu builder init");
    ck(pq_mu_builder_absorb(builder, message, sizeof(message)) == PQ_SUCCESS, "mu builder absorb");
    ck(pq_mu_builder_finalize(builder, mu) == PQ_SUCCESS, "mu builder finalize");

    signature_len = 0xdeadbeef;
    ck(pq_sign_mu(sig, &signature_len, mu, sk, pq_mldsa65_signature_extmu_compat) == PQ_SUCCESS,
       "pq_sign_mu succeeds");
    ck(signature_len == MLDSA65_BYTES, "pq_sign_mu output length restored by the v2 adapter");

    ck(pq_verify_mu(sig, signature_len, mu, pk, MLDSA65_BYTES, pq_mldsa65_verify_extmu_compat) ==
           PQ_SUCCESS,
       "pq_verify_mu round trip");
    ck(pq_verify_mu(sig, 1, mu, pk, MLDSA65_BYTES, pq_mldsa65_verify_extmu_compat) ==
           PQ_ERROR_VERIFY,
       "pq_verify_mu rejects a short signature");

    ck(pq_verify(sig, signature_len, message, sizeof(message), NULL, 0, pk) == PQ_SUCCESS,
       "extmu signature verifies through pq_verify");

    /*
     * The adapters are also reachable directly through the ExternalMu profile
     * table, so exercise their own guards. pq_verify_mu validates the length
     * first and would otherwise keep these branches unreached.
     */
    ck(pq_mldsa65_verify_extmu_compat(sig, MLDSA65_BYTES, mu, pk) == 0,
       "verify adapter accepts a correctly sized signature");
    ck(pq_mldsa65_verify_extmu_compat(sig, 1, mu, pk) != 0,
       "verify adapter rejects a short signature on its own");
    ck(pq_mldsa65_verify_extmu_compat(sig, MLDSA65_BYTES + 1, mu, pk) != 0,
       "verify adapter rejects an over-long signature on its own");
    ck(pq_mldsa65_verify_extmu_compat(NULL, MLDSA65_BYTES, mu, pk) != 0,
       "verify adapter rejects a NULL signature");

    signature_len = 0xdeadbeef;
    ck(pq_sign_mu(sig, &signature_len, mu, sk, stub_failing_signature_extmu) == PQ_ERROR_SIGN,
       "pq_sign_mu propagates a callback failure");

    force_rng_failure();
    signature_len = 0xdeadbeef;
    ck(pq_sign_mu(sig, &signature_len, mu, sk, pq_mldsa65_signature_extmu_compat) == PQ_ERROR_SIGN,
       "pq_sign_mu surfaces a real backend failure through the adapter");
    ck(signature_len == 0, "the v2 adapter clears *signature_len on backend failure");
    restore_rng();

    signature_len = 0xdeadbeef;
    ck(pq_sign_mu(sig, &signature_len, mu, sk, pq_mldsa65_signature_extmu_compat) == PQ_SUCCESS,
       "sign_mu recovers once the RNG works again");
    ck(signature_len == MLDSA65_BYTES, "and reports the right length again");
}

static void test_deterministic_helper_length(void) {
    uint8_t pk[MLDSA65_PUBLICKEYBYTES];
    uint8_t sk[MLDSA65_SECRETKEYBYTES];
    uint8_t sig[MLDSA65_BYTES];
    uint8_t seed[MLDSA_SEEDBYTES];
    uint8_t rnd[MLDSA_RNDBYTES];
    size_t signature_len;
    const uint8_t message[] = "deterministic";

    memset(seed, 0x5a, sizeof(seed));
    memset(rnd, 0x00, sizeof(rnd));
    ck(pq_mldsa_keypair_from_seed(pk, sk, seed) == PQ_SUCCESS, "deterministic keygen");

    signature_len = 0xdeadbeef;
    ck(pq_testing_mldsa_sign_from_seed(sig, &signature_len, message, sizeof(message), sk, rnd,
                                       sizeof(rnd)) == PQ_SUCCESS,
       "deterministic sign");
    ck(signature_len == MLDSA65_BYTES, "generic helper reports the caller-supplied length");
    ck(pq_verify(sig, signature_len, message, sizeof(message), NULL, 0, pk) == PQ_SUCCESS,
       "deterministic signature verifies");

    signature_len = 0xdeadbeef;
    ck(pq_testing_mldsa_sign_from_seed(sig, &signature_len, message, sizeof(message), sk, rnd,
                                       sizeof(rnd) - 1) == PQ_ERROR_BUFFER,
       "deterministic sign rejects a short seed");
    ck(signature_len == 0xdeadbeef,
       "seed-length rejection leaves *signature_len untouched (argument validation)");
}

int main(void) {
    test_sign_output_length();
    test_sign_output_length_other_levels();
    test_verify_rejects_wrong_length();
    test_extmu_length_contract();
    test_deterministic_helper_length();

    printf("c api: %d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
