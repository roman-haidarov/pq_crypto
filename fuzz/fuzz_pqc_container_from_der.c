#include <stdint.h>
#include <stdlib.h>

#include "pqcrypto_secure.h"

static void free_secret_result(char *algorithm, uint8_t *key, size_t key_len) {
    free(algorithm);
    pq_secure_wipe(key, key_len);
    free(key);
}

static void free_public_result(char *algorithm, uint8_t *key) {
    free(algorithm);
    free(key);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char *algorithm = NULL;
    uint8_t *key = NULL;
    size_t key_len = 0;

    if (pq_secret_key_from_pqc_container_der(&algorithm, &key, &key_len, data, size) == PQ_SUCCESS) {
        free_secret_result(algorithm, key, key_len);
    }

    algorithm = NULL;
    key = NULL;
    key_len = 0;
    if (pq_public_key_from_pqc_container_der(&algorithm, &key, &key_len, data, size) == PQ_SUCCESS) {
        free_public_result(algorithm, key);
    }

    return 0;
}
