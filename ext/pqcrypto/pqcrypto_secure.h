#ifndef PQCRYPTO_SECURE_H
#define PQCRYPTO_SECURE_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifndef HAVE_PQCLEAN
#error "PQClean sources are required to build pq_crypto. Run: bundle exec rake vendor"
#endif

#include "mlkem_api.h"
#include "mldsa_api.h"
#define MLKEM_PUBLICKEYBYTES    PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES
#define MLKEM_SECRETKEYBYTES    PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES
#define MLKEM_CIPHERTEXTBYTES   PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES
#define MLKEM_SHAREDSECRETBYTES PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES

#define MLDSA_PUBLICKEYBYTES 1952
#define MLDSA_SECRETKEYBYTES 4032
#define MLDSA_BYTES          3309

#define X25519_PUBLICKEYBYTES    32
#define X25519_SECRETKEYBYTES    32
#define X25519_SHAREDSECRETBYTES 32

#define HYBRID_PUBLICKEYBYTES    (MLKEM_PUBLICKEYBYTES + X25519_PUBLICKEYBYTES)
#define HYBRID_SECRETKEYBYTES    (MLKEM_SECRETKEYBYTES + X25519_SECRETKEYBYTES)
#define HYBRID_CIPHERTEXTBYTES   (MLKEM_CIPHERTEXTBYTES + X25519_PUBLICKEYBYTES)
#define HYBRID_SHAREDSECRETBYTES 32

typedef enum {
    PQ_SUCCESS = 0,
    PQ_ERROR_KEYPAIR = -1,
    PQ_ERROR_ENCAPSULATE = -2,
    PQ_ERROR_DECAPSULATE = -3,
    PQ_ERROR_SIGN = -4,
    PQ_ERROR_VERIFY = -5,
    PQ_ERROR_KDF = -6,
    PQ_ERROR_RANDOM = -7,
    PQ_ERROR_BUFFER = -8,
    PQ_ERROR_NOMEM = -9,
    PQ_ERROR_OPENSSL = -10
} pq_error_t;

typedef struct {
    uint8_t mlkem_pk[MLKEM_PUBLICKEYBYTES];
    uint8_t x25519_pk[X25519_PUBLICKEYBYTES];
} hybrid_public_key_t;

typedef struct {
    uint8_t mlkem_sk[MLKEM_SECRETKEYBYTES];
    uint8_t x25519_sk[X25519_SECRETKEYBYTES];
} hybrid_secret_key_t;

typedef struct {
    uint8_t mlkem_ct[MLKEM_CIPHERTEXTBYTES];
    uint8_t x25519_ephemeral[X25519_PUBLICKEYBYTES];
} hybrid_ciphertext_t;

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(hybrid_public_key_t) == HYBRID_PUBLICKEYBYTES,
               "hybrid_public_key_t layout must be packed");
_Static_assert(sizeof(hybrid_secret_key_t) == HYBRID_SECRETKEYBYTES,
               "hybrid_secret_key_t layout must be packed");
_Static_assert(sizeof(hybrid_ciphertext_t) == HYBRID_CIPHERTEXTBYTES,
               "hybrid_ciphertext_t layout must be packed");
#endif

void pq_secure_wipe(void *ptr, size_t len);

int pq_mlkem_keypair(uint8_t *public_key, uint8_t *secret_key);
int pq_mlkem_encapsulate(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
int pq_mlkem_decapsulate(uint8_t *shared_secret, const uint8_t *ciphertext,
                         const uint8_t *secret_key);

int pq_sign_keypair(uint8_t *public_key, uint8_t *secret_key);
int pq_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len,
            const uint8_t *secret_key);
int pq_verify(const uint8_t *signature, size_t signature_len, const uint8_t *message,
              size_t message_len, const uint8_t *public_key);

int pq_public_key_to_pqc_container_der(uint8_t **output, size_t *output_len,
                                       const uint8_t *public_key,
                                       size_t public_key_len, const char *algorithm);
int pq_public_key_to_pqc_container_pem(char **output, size_t *output_len,
                                       const uint8_t *public_key,
                                       size_t public_key_len, const char *algorithm);
int pq_secret_key_to_pqc_container_der(uint8_t **output, size_t *output_len,
                                        const uint8_t *secret_key,
                                        size_t secret_key_len, const char *algorithm);
int pq_secret_key_to_pqc_container_pem(char **output, size_t *output_len,
                                        const uint8_t *secret_key,
                                        size_t secret_key_len, const char *algorithm);
int pq_public_key_from_pqc_container_der(char **algorithm_out, uint8_t **key_out,
                                         size_t *key_len_out, const uint8_t *input,
                                         size_t input_len);
int pq_public_key_from_pqc_container_pem(char **algorithm_out, uint8_t **key_out,
                                         size_t *key_len_out, const char *input,
                                         size_t input_len);
int pq_secret_key_from_pqc_container_der(char **algorithm_out, uint8_t **key_out,
                                          size_t *key_len_out, const uint8_t *input,
                                          size_t input_len);
int pq_secret_key_from_pqc_container_pem(char **algorithm_out, uint8_t **key_out,
                                          size_t *key_len_out, const char *input,
                                          size_t input_len);

int pq_testing_mlkem_keypair_from_seed(uint8_t *public_key, uint8_t *secret_key,
                                       const uint8_t *seed, size_t seed_len);
int pq_testing_mlkem_encapsulate_from_seed(uint8_t *ciphertext, uint8_t *shared_secret,
                                           const uint8_t *public_key, const uint8_t *seed,
                                           size_t seed_len);
int pq_testing_mldsa_keypair_from_seed(uint8_t *public_key, uint8_t *secret_key,
                                       const uint8_t *seed, size_t seed_len);
int pq_testing_mldsa_sign_from_seed(uint8_t *signature, size_t *signature_len,
                                    const uint8_t *message, size_t message_len,
                                    const uint8_t *secret_key, const uint8_t *seed,
                                    size_t seed_len);

void pq_testing_set_seed(const uint8_t *seed, size_t len);
void pq_testing_clear_seed(void);
int pq_testing_seed_active(void);

const char *pq_version(void);

#define PQ_MLKEM_PUBLICKEYBYTES    MLKEM_PUBLICKEYBYTES
#define PQ_MLKEM_SECRETKEYBYTES    MLKEM_SECRETKEYBYTES
#define PQ_MLKEM_CIPHERTEXTBYTES   MLKEM_CIPHERTEXTBYTES
#define PQ_MLKEM_SHAREDSECRETBYTES MLKEM_SHAREDSECRETBYTES

#define PQ_HYBRID_PUBLICKEYBYTES    HYBRID_PUBLICKEYBYTES
#define PQ_HYBRID_SECRETKEYBYTES    HYBRID_SECRETKEYBYTES
#define PQ_HYBRID_CIPHERTEXTBYTES   HYBRID_CIPHERTEXTBYTES
#define PQ_HYBRID_SHAREDSECRETBYTES HYBRID_SHAREDSECRETBYTES

#define PQ_MLDSA_PUBLICKEYBYTES MLDSA_PUBLICKEYBYTES
#define PQ_MLDSA_SECRETKEYBYTES MLDSA_SECRETKEYBYTES
#define PQ_MLDSA_BYTES          MLDSA_BYTES

int pq_hybrid_kem_keypair(uint8_t *public_key, uint8_t *secret_key);
int pq_hybrid_kem_encapsulate(uint8_t *ciphertext, uint8_t *shared_secret,
                              const uint8_t *public_key);
int pq_hybrid_kem_decapsulate(uint8_t *shared_secret, const uint8_t *ciphertext,
                              const uint8_t *secret_key);

#endif
