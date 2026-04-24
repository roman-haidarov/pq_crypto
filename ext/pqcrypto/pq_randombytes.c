#include "pqcrypto_secure.h"

#include <stdint.h>
#include <string.h>

#include <openssl/rand.h>
#include "randombytes.h"

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
#define PQ_THREAD_LOCAL _Thread_local
#elif defined(__GNUC__) || defined(__clang__)
#define PQ_THREAD_LOCAL __thread
#else
#define PQ_THREAD_LOCAL
#endif

static PQ_THREAD_LOCAL const uint8_t *pq_test_seed_ptr = NULL;
static PQ_THREAD_LOCAL size_t pq_test_seed_remaining = 0;

void pq_testing_set_seed(const uint8_t *seed, size_t len) {
    pq_test_seed_ptr = seed;
    pq_test_seed_remaining = (seed != NULL) ? len : 0;
}

void pq_testing_clear_seed(void) {
    pq_test_seed_ptr = NULL;
    pq_test_seed_remaining = 0;
}

int pq_testing_seed_active(void) {
    return pq_test_seed_ptr != NULL;
}

int randombytes(uint8_t *output, size_t n) {
    if (output == NULL) {
        return -1;
    }

    if (pq_test_seed_ptr != NULL) {
        if (pq_test_seed_remaining < n) {
            return -1;
        }
        memcpy(output, pq_test_seed_ptr, n);
        pq_test_seed_ptr += n;
        pq_test_seed_remaining -= n;
        return 0;
    }

    if (n > INT_MAX) {
        return -1;
    }
    if (RAND_bytes(output, (int)n) != 1) {
        return -1;
    }
    return 0;
}
