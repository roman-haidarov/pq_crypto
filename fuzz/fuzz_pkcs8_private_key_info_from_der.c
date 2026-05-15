#include <stdint.h>
#include <stdlib.h>

#include "pqcrypto_secure.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char *oid = NULL;
    uint8_t *private_key = NULL;
    size_t private_key_len = 0;

    if (pq_pkcs8_private_key_info_from_der(&oid, &private_key, &private_key_len, data, size) == PQ_SUCCESS) {
        free(oid);
        pq_secure_wipe(private_key, private_key_len);
        free(private_key);
    }

    return 0;
}
