#ifndef MLKEM_API_H
#define MLKEM_API_H

#ifdef HAVE_PQCLEAN
#include <stdint.h>

#define PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES  1632
#define PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES  800
#define PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES 768
#define PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES           32
#define PQCLEAN_MLKEM512_CLEAN_CRYPTO_ALGNAME "ML-KEM-512"

int PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
int PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
int PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins);
int PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins);

#define PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES  2400
#define PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES  1184
#define PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES 1088
#define PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES           32
#define PQCLEAN_MLKEM768_CLEAN_CRYPTO_ALGNAME "ML-KEM-768"

int PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
int PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
int PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins);
int PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins);

#define PQCLEAN_MLKEM1024_CLEAN_CRYPTO_SECRETKEYBYTES  3168
#define PQCLEAN_MLKEM1024_CLEAN_CRYPTO_PUBLICKEYBYTES  1568
#define PQCLEAN_MLKEM1024_CLEAN_CRYPTO_CIPHERTEXTBYTES 1568
#define PQCLEAN_MLKEM1024_CLEAN_CRYPTO_BYTES           32
#define PQCLEAN_MLKEM1024_CLEAN_CRYPTO_ALGNAME "ML-KEM-1024"

int PQCLEAN_MLKEM1024_CLEAN_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
int PQCLEAN_MLKEM1024_CLEAN_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int PQCLEAN_MLKEM1024_CLEAN_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
int PQCLEAN_MLKEM1024_CLEAN_crypto_kem_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins);
int PQCLEAN_MLKEM1024_CLEAN_crypto_kem_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins);

#endif

#endif
