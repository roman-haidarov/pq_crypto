#include "mlkem_native.h"
#if defined(MLK_CONFIG_MULTILEVEL_WITH_SHARED)
#include "src/fips202/fips202.h"
#endif

enum {
    UPSTREAM_PK = MLKEM_PUBLICKEYBYTES(MLK_CONFIG_PARAMETER_SET),
    UPSTREAM_SK = MLKEM_SECRETKEYBYTES(MLK_CONFIG_PARAMETER_SET),
    UPSTREAM_CT = MLKEM_CIPHERTEXTBYTES(MLK_CONFIG_PARAMETER_SET),
    UPSTREAM_SS = MLKEM_BYTES
};

#undef MLKEM_PUBLICKEYBYTES
#undef MLKEM_SECRETKEYBYTES
#undef MLKEM_CIPHERTEXTBYTES

#include "pqcrypto_native_api.h"

#define CAT_(a, b)        a##b
#define CAT(a, b)         CAT_(a, b)
#define LEVEL             MLK_CONFIG_PARAMETER_SET
#define GEM_CONST(suffix) CAT(CAT(MLKEM, LEVEL), suffix)
#define GEM_FN(sym)       CAT(CAT(pqcr_mlkem, LEVEL), _##sym)

_Static_assert(GEM_CONST(_PUBLICKEYBYTES) == UPSTREAM_PK, "ML-KEM public key size drift");
_Static_assert(GEM_CONST(_SECRETKEYBYTES) == UPSTREAM_SK, "ML-KEM secret key size drift");
_Static_assert(GEM_CONST(_CIPHERTEXTBYTES) == UPSTREAM_CT, "ML-KEM ciphertext size drift");
_Static_assert(GEM_CONST(_SHAREDSECRETBYTES) == UPSTREAM_SS, "ML-KEM shared secret size drift");

static void *const probes[] = {
    (void *)&GEM_FN(keypair),     (void *)&GEM_FN(keypair_derand),
    (void *)&GEM_FN(enc),         (void *)&GEM_FN(enc_derand),
    (void *)&GEM_FN(dec),
#if defined(MLK_CONFIG_MULTILEVEL_WITH_SHARED)
    (void *)&pqcr_mlkem_shake256, (void *)&pqcr_mlkem_sha3_256,
#endif
};
const void *CAT(pqcrypto_conformance_mlkem, LEVEL)(void) {
    return probes;
}
