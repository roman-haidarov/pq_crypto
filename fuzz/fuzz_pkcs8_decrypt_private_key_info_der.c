#include <stdint.h>
#include <stdlib.h>

#include "pqcrypto_secure.h"

static const char kPassphrase[] = "pq_crypto fuzz passphrase";

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    uint8_t *plain = NULL;
    size_t plain_len = 0;

    if (pq_pkcs8_decrypt_private_key_info_der(&plain, &plain_len, data, size,
                                              kPassphrase, sizeof(kPassphrase) - 1) == PQ_SUCCESS) {
        pq_secure_wipe(plain, plain_len);
        free(plain);
    }

    return 0;
}
