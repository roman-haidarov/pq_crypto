#ifndef PQCRYPTO_NATIVE_API_H
#define PQCRYPTO_NATIVE_API_H

#include <stddef.h>
#include <stdint.h>

/*
 * pq_crypto now builds only against PQ Code Package native libraries:
 *   vendor/mlkem-native/mlkem
 *   vendor/mldsa-native/mldsa
 *
 * The concrete public symbols below are produced by compiling each package as a
 * multi-level build with:
 *   MLK_CONFIG_NAMESPACE_PREFIX=pqcr_mlkem
 *   MLD_CONFIG_NAMESPACE_PREFIX=pqcr_mldsa
 * and MLK/MLD_CONFIG_MULTILEVEL_BUILD enabled. Do not add PQClean aliases here:
 * we want one backend only so build/runtime failures point at the new stack.
 *
 * mldsa-native v2.0.0 removed the `siglen` in/out parameter from the signing
 * and verification APIs: signatures are always exactly MLDSA_BYTES(level) and
 * the buffer size is part of the API contract rather than a runtime value.
 *
 * Two consequences for every caller in this extension:
 *   1. Signing no longer reports the produced length. Each pq_crypto wrapper
 *      sets its own *signature_len from the compile-time constant, and clears
 *      it to 0 on failure, preserving the pre-v2 pq_crypto contract.
 *   2. Verification no longer rejects a wrongly sized signature. The caller
 *      MUST check the length itself before handing the buffer to
 *      pqcr_mldsa*_verify / pqcr_mldsa*_verify_extmu, which read
 *      MLDSA_BYTES(level) bytes unconditionally.
 */

#define MLKEM512_SECRETKEYBYTES    1632
#define MLKEM512_PUBLICKEYBYTES    800
#define MLKEM512_CIPHERTEXTBYTES   768
#define MLKEM512_SHAREDSECRETBYTES 32

#define MLKEM768_SECRETKEYBYTES    2400
#define MLKEM768_PUBLICKEYBYTES    1184
#define MLKEM768_CIPHERTEXTBYTES   1088
#define MLKEM768_SHAREDSECRETBYTES 32

#define MLKEM1024_SECRETKEYBYTES    3168
#define MLKEM1024_PUBLICKEYBYTES    1568
#define MLKEM1024_CIPHERTEXTBYTES   1568
#define MLKEM1024_SHAREDSECRETBYTES 32

#define MLKEM_PUBLICKEYBYTES    MLKEM768_PUBLICKEYBYTES
#define MLKEM_SECRETKEYBYTES    MLKEM768_SECRETKEYBYTES
#define MLKEM_CIPHERTEXTBYTES   MLKEM768_CIPHERTEXTBYTES
#define MLKEM_SHAREDSECRETBYTES MLKEM768_SHAREDSECRETBYTES

#define MLDSA44_SECRETKEYBYTES 2560
#define MLDSA44_PUBLICKEYBYTES 1312
#define MLDSA44_BYTES          2420

#define MLDSA65_SECRETKEYBYTES 4032
#define MLDSA65_PUBLICKEYBYTES 1952
#define MLDSA65_BYTES          3309

#define MLDSA87_SECRETKEYBYTES 4896
#define MLDSA87_PUBLICKEYBYTES 2592
#define MLDSA87_BYTES          4627

#define MLDSA_PUBLICKEYBYTES              MLDSA65_PUBLICKEYBYTES
#define MLDSA_SECRETKEYBYTES              MLDSA65_SECRETKEYBYTES
#define MLDSA_BYTES                       MLDSA65_BYTES
#define MLDSA_SEEDBYTES                   32
#define MLDSA_RNDBYTES                    32
#define MLDSA_TRBYTES                     64
#define MLDSA_CRHBYTES                    64
#define MLDSA_DOMAIN_SEPARATION_MAX_BYTES (2 + 255 + 11 + 64)
#define MLDSA_PREHASH_NONE                0

/* mlkem-native symbols: namespace prefix pqcr_mlkem + level suffix. */
int pqcr_mlkem512_keypair(uint8_t *pk, uint8_t *sk);
int pqcr_mlkem512_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins);
int pqcr_mlkem512_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int pqcr_mlkem512_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins);
int pqcr_mlkem512_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

int pqcr_mlkem768_keypair(uint8_t *pk, uint8_t *sk);
int pqcr_mlkem768_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins);
int pqcr_mlkem768_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int pqcr_mlkem768_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins);
int pqcr_mlkem768_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

int pqcr_mlkem1024_keypair(uint8_t *pk, uint8_t *sk);
int pqcr_mlkem1024_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins);
int pqcr_mlkem1024_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int pqcr_mlkem1024_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins);
int pqcr_mlkem1024_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

void pqcr_mlkem_shake256(uint8_t *output, size_t outlen, const uint8_t *input, size_t inlen);
void pqcr_mlkem_sha3_256(uint8_t *output, const uint8_t *input, size_t inlen);

/* mldsa-native symbols: namespace prefix pqcr_mldsa + level suffix. */
int pqcr_mldsa44_keypair(uint8_t *pk, uint8_t *sk);
int pqcr_mldsa44_keypair_internal(uint8_t *pk, uint8_t *sk, const uint8_t seed[MLDSA_SEEDBYTES]);
int pqcr_mldsa44_signature(uint8_t *sig, const uint8_t *m, size_t mlen, const uint8_t *ctx,
                           size_t ctxlen, const uint8_t *sk);
int pqcr_mldsa44_signature_internal(uint8_t *sig, const uint8_t *m, size_t mlen, const uint8_t *pre,
                                    size_t prelen, const uint8_t rnd[MLDSA_RNDBYTES],
                                    const uint8_t *sk, int externalmu);
int pqcr_mldsa44_verify(const uint8_t *sig, const uint8_t *m, size_t mlen, const uint8_t *ctx,
                        size_t ctxlen, const uint8_t *pk);
size_t
pqcr_mldsa44_prepare_domain_separation_prefix(uint8_t prefix[MLDSA_DOMAIN_SEPARATION_MAX_BYTES],
                                              const uint8_t *ph, size_t phlen, const uint8_t *ctx,
                                              size_t ctxlen, int hashalg);
int pqcr_mldsa44_signature_extmu(uint8_t *sig, const uint8_t mu[MLDSA_CRHBYTES], const uint8_t *sk);
int pqcr_mldsa44_verify_extmu(const uint8_t *sig, const uint8_t mu[MLDSA_CRHBYTES],
                              const uint8_t *pk);
int pqcr_mldsa44_pk_from_sk(uint8_t *pk, const uint8_t *sk);

int pqcr_mldsa65_keypair(uint8_t *pk, uint8_t *sk);
int pqcr_mldsa65_keypair_internal(uint8_t *pk, uint8_t *sk, const uint8_t seed[MLDSA_SEEDBYTES]);
int pqcr_mldsa65_signature(uint8_t *sig, const uint8_t *m, size_t mlen, const uint8_t *ctx,
                           size_t ctxlen, const uint8_t *sk);
int pqcr_mldsa65_signature_internal(uint8_t *sig, const uint8_t *m, size_t mlen, const uint8_t *pre,
                                    size_t prelen, const uint8_t rnd[MLDSA_RNDBYTES],
                                    const uint8_t *sk, int externalmu);
int pqcr_mldsa65_verify(const uint8_t *sig, const uint8_t *m, size_t mlen, const uint8_t *ctx,
                        size_t ctxlen, const uint8_t *pk);
size_t
pqcr_mldsa65_prepare_domain_separation_prefix(uint8_t prefix[MLDSA_DOMAIN_SEPARATION_MAX_BYTES],
                                              const uint8_t *ph, size_t phlen, const uint8_t *ctx,
                                              size_t ctxlen, int hashalg);
int pqcr_mldsa65_signature_extmu(uint8_t *sig, const uint8_t mu[MLDSA_CRHBYTES], const uint8_t *sk);
int pqcr_mldsa65_verify_extmu(const uint8_t *sig, const uint8_t mu[MLDSA_CRHBYTES],
                              const uint8_t *pk);
int pqcr_mldsa65_pk_from_sk(uint8_t *pk, const uint8_t *sk);

int pqcr_mldsa87_keypair(uint8_t *pk, uint8_t *sk);
int pqcr_mldsa87_keypair_internal(uint8_t *pk, uint8_t *sk, const uint8_t seed[MLDSA_SEEDBYTES]);
int pqcr_mldsa87_signature(uint8_t *sig, const uint8_t *m, size_t mlen, const uint8_t *ctx,
                           size_t ctxlen, const uint8_t *sk);
int pqcr_mldsa87_signature_internal(uint8_t *sig, const uint8_t *m, size_t mlen, const uint8_t *pre,
                                    size_t prelen, const uint8_t rnd[MLDSA_RNDBYTES],
                                    const uint8_t *sk, int externalmu);
int pqcr_mldsa87_verify(const uint8_t *sig, const uint8_t *m, size_t mlen, const uint8_t *ctx,
                        size_t ctxlen, const uint8_t *pk);
size_t
pqcr_mldsa87_prepare_domain_separation_prefix(uint8_t prefix[MLDSA_DOMAIN_SEPARATION_MAX_BYTES],
                                              const uint8_t *ph, size_t phlen, const uint8_t *ctx,
                                              size_t ctxlen, int hashalg);
int pqcr_mldsa87_signature_extmu(uint8_t *sig, const uint8_t mu[MLDSA_CRHBYTES], const uint8_t *sk);
int pqcr_mldsa87_verify_extmu(const uint8_t *sig, const uint8_t mu[MLDSA_CRHBYTES],
                              const uint8_t *pk);
int pqcr_mldsa87_pk_from_sk(uint8_t *pk, const uint8_t *sk);

#endif
