#ifndef PQCRYPTO_SECURE_H
#define PQCRYPTO_SECURE_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>

#ifndef HAVE_PQCLEAN
#error "PQClean sources are required to build pq_crypto. Run: bundle exec rake vendor"
#endif

#include "mlkem_api.h"
#include "mldsa_api.h"
#define MLKEM_PUBLICKEYBYTES    PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES
#define MLKEM_SECRETKEYBYTES    PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES
#define MLKEM_CIPHERTEXTBYTES   PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES
#define MLKEM_SHAREDSECRETBYTES PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES

#define MLDSA_PUBLICKEYBYTES PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES
#define MLDSA_SECRETKEYBYTES PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES
#define MLDSA_BYTES          PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES

#define X25519_PUBLICKEYBYTES    32
#define X25519_SECRETKEYBYTES    32
#define X25519_SHAREDSECRETBYTES 32

#define AES_KEY_BYTES   32
#define AES_NONCE_BYTES 12
#define AES_TAG_BYTES   16

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
    PQ_ERROR_ENCRYPT = -6,
    PQ_ERROR_DECRYPT = -7,
    PQ_ERROR_KDF = -8,
    PQ_ERROR_RANDOM = -9,
    PQ_ERROR_BUFFER = -10,
    PQ_ERROR_AUTH = -11,
    PQ_ERROR_NOMEM = -12,
    PQ_ERROR_OPENSSL = -13
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

typedef struct {
    uint8_t send_key[AES_KEY_BYTES];
    uint8_t recv_key[AES_KEY_BYTES];
    _Atomic(uint64_t) send_nonce_counter;
    uint64_t expected_recv_nonce;
    int is_initiator;
} pq_session_t;

typedef struct {
    uint8_t nonce[AES_NONCE_BYTES];
    uint8_t tag[AES_TAG_BYTES];
} aes_gcm_header_t;

void pq_secure_wipe(void *ptr, size_t len);

int pq_hybrid_keypair(uint8_t *public_key, uint8_t *secret_key);
int pq_hybrid_encapsulate(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
int pq_hybrid_decapsulate(uint8_t *shared_secret, const uint8_t *ciphertext,
                          const uint8_t *secret_key);

int pq_sign_keypair(uint8_t *public_key, uint8_t *secret_key);
int pq_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len,
            const uint8_t *secret_key);
int pq_verify(const uint8_t *signature, size_t signature_len, const uint8_t *message,
              size_t message_len, const uint8_t *public_key);

int pq_session_init(pq_session_t *session, const uint8_t *shared_secret, int is_initiator);
pq_session_t *pq_session_create(const uint8_t *shared_secret, int is_initiator);
int pq_session_encrypt(pq_session_t *session, uint8_t *output, size_t *output_len,
                       const uint8_t *plaintext, size_t plaintext_len, const uint8_t *aad,
                       size_t aad_len);
int pq_session_decrypt(pq_session_t *session, uint8_t *plaintext, size_t *plaintext_len,
                       const uint8_t *input, size_t input_len, const uint8_t *aad, size_t aad_len);
void pq_session_destroy(pq_session_t *session);

size_t pq_session_encrypt_len(size_t plaintext_len);

int pq_seal(uint8_t *output, size_t *output_len, const uint8_t *message, size_t message_len,
            const uint8_t *public_key);
int pq_unseal(uint8_t *plaintext, size_t *plaintext_len, const uint8_t *sealed, size_t sealed_len,
              const uint8_t *secret_key);
int pq_sign_and_seal(uint8_t *output, size_t *output_len, const uint8_t *message, size_t message_len,
                     const uint8_t *kem_public_key, const uint8_t *sign_secret_key);
int pq_unseal_and_verify(uint8_t *plaintext, size_t *plaintext_len, const uint8_t *input,
                         size_t input_len, const uint8_t *kem_secret_key,
                         const uint8_t *sign_public_key);
int pq_public_key_pem(char **output, size_t *output_len, const uint8_t *public_key,
                      size_t public_key_len);

int pq_public_key_to_spki_der(uint8_t **output, size_t *output_len, const uint8_t *public_key,
                              size_t public_key_len, const char *algorithm);
int pq_public_key_to_spki_pem(char **output, size_t *output_len, const uint8_t *public_key,
                              size_t public_key_len, const char *algorithm);
int pq_secret_key_to_pkcs8_der(uint8_t **output, size_t *output_len, const uint8_t *secret_key,
                               size_t secret_key_len, const char *algorithm);
int pq_secret_key_to_pkcs8_pem(char **output, size_t *output_len, const uint8_t *secret_key,
                               size_t secret_key_len, const char *algorithm);
int pq_public_key_from_spki_der(char **algorithm_out, uint8_t **key_out, size_t *key_len_out,
                                const uint8_t *input, size_t input_len);
int pq_public_key_from_spki_pem(char **algorithm_out, uint8_t **key_out, size_t *key_len_out,
                                const char *input, size_t input_len);
int pq_secret_key_from_pkcs8_der(char **algorithm_out, uint8_t **key_out, size_t *key_len_out,
                                 const uint8_t *input, size_t input_len);
int pq_secret_key_from_pkcs8_pem(char **algorithm_out, uint8_t **key_out, size_t *key_len_out,
                                 const char *input, size_t input_len);

const char *pq_version(void);

#define PQ_HYBRID_PUBLICKEYBYTES    HYBRID_PUBLICKEYBYTES
#define PQ_HYBRID_SECRETKEYBYTES    HYBRID_SECRETKEYBYTES
#define PQ_HYBRID_CIPHERTEXTBYTES   HYBRID_CIPHERTEXTBYTES
#define PQ_HYBRID_SHAREDSECRETBYTES HYBRID_SHAREDSECRETBYTES

#define PQ_MLDSA_PUBLICKEYBYTES MLDSA_PUBLICKEYBYTES
#define PQ_MLDSA_SECRETKEYBYTES MLDSA_SECRETKEYBYTES
#define PQ_MLDSA_BYTES          MLDSA_BYTES

#define PQ_SESSION_OVERHEAD (AES_NONCE_BYTES + AES_TAG_BYTES)

int pq_kem_keypair(uint8_t *public_key, uint8_t *secret_key);
int pq_kem_encapsulate(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
int pq_kem_decapsulate(uint8_t *shared_secret, const uint8_t *ciphertext,
                       const uint8_t *secret_key);

#endif
