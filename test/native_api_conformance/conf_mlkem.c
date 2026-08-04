#define MLK_CONFIG_API_PARAMETER_SET    LEVEL
#include "mlkem_native.h"

enum {
  UPSTREAM_PK = MLKEM_PUBLICKEYBYTES(LEVEL),
  UPSTREAM_SK = MLKEM_SECRETKEYBYTES(LEVEL),
  UPSTREAM_CT = MLKEM_CIPHERTEXTBYTES(LEVEL),
  UPSTREAM_SS = MLKEM_BYTES
};

#undef MLKEM_PUBLICKEYBYTES
#undef MLKEM_SECRETKEYBYTES
#undef MLKEM_CIPHERTEXTBYTES

#include "pqcrypto_native_api.h"

#define CAT_(a, b) a##b
#define CAT(a, b) CAT_(a, b)
#define GEM_CONST(suffix) CAT(CAT(MLKEM, LEVEL), suffix)
#define GEM_FN(sym) CAT(CAT(pqcr_mlkem, LEVEL), _##sym)

_Static_assert(GEM_CONST(_PUBLICKEYBYTES)    == UPSTREAM_PK, "ML-KEM public key size drift");
_Static_assert(GEM_CONST(_SECRETKEYBYTES)    == UPSTREAM_SK, "ML-KEM secret key size drift");
_Static_assert(GEM_CONST(_CIPHERTEXTBYTES)   == UPSTREAM_CT, "ML-KEM ciphertext size drift");
_Static_assert(GEM_CONST(_SHAREDSECRETBYTES) == UPSTREAM_SS, "ML-KEM shared secret size drift");

static void *const probes[] = {
  (void *)&GEM_FN(keypair),  (void *)&GEM_FN(keypair_derand),
  (void *)&GEM_FN(enc),      (void *)&GEM_FN(enc_derand),
  (void *)&GEM_FN(dec),
};
const void *CAT(pqcrypto_conformance_mlkem, LEVEL)(void) { return probes; }
