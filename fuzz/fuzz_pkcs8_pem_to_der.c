#include <stdint.h>
#include <stdlib.h>

#include "pqcrypto_secure.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    uint8_t *der = NULL;
    size_t der_len = 0;
    int encrypted = 0;

    if (pq_pkcs8_pem_to_der(&der, &der_len, &encrypted, (const char *)data, size) == PQ_SUCCESS) {
        (void)encrypted;
        pq_secure_wipe(der, der_len);
        free(der);
    }

    return 0;
}
