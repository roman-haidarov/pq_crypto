#include "mldsa_native.h"

enum {
  UPSTREAM_PK  = MLDSA_PUBLICKEYBYTES(MLD_CONFIG_API_PARAMETER_SET),
  UPSTREAM_SK  = MLDSA_SECRETKEYBYTES(MLD_CONFIG_API_PARAMETER_SET),
  UPSTREAM_SIG = MLDSA_BYTES(MLD_CONFIG_API_PARAMETER_SET),
  UPSTREAM_SEED = MLDSA_SEEDBYTES,
  UPSTREAM_RND  = MLDSA_RNDBYTES,
  UPSTREAM_TR   = MLDSA_TRBYTES,
  UPSTREAM_CRH  = MLDSA_CRHBYTES,
  UPSTREAM_DS   = MLD_DOMAIN_SEPARATION_MAX_BYTES,
  UPSTREAM_PREHASH_NONE = MLD_PREHASH_NONE
};

#undef MLDSA_PUBLICKEYBYTES
#undef MLDSA_SECRETKEYBYTES
#undef MLDSA_BYTES
#undef MLDSA_SEEDBYTES
#undef MLDSA_RNDBYTES
#undef MLDSA_TRBYTES
#undef MLDSA_CRHBYTES

#include "pqcrypto_native_api.h"

#define CAT_(a, b) a##b
#define CAT(a, b) CAT_(a, b)
#define LEVEL MLD_CONFIG_API_PARAMETER_SET
#define GEM_CONST(suffix) CAT(CAT(MLDSA, LEVEL), suffix)
#define GEM_FN(sym) CAT(CAT(pqcr_mldsa, LEVEL), _##sym)

_Static_assert(GEM_CONST(_PUBLICKEYBYTES) == UPSTREAM_PK,  "ML-DSA public key size drift");
_Static_assert(GEM_CONST(_SECRETKEYBYTES) == UPSTREAM_SK,  "ML-DSA secret key size drift");
_Static_assert(GEM_CONST(_BYTES)          == UPSTREAM_SIG, "ML-DSA signature size drift");
_Static_assert(MLDSA_SEEDBYTES == UPSTREAM_SEED, "ML-DSA seed size drift");
_Static_assert(MLDSA_RNDBYTES  == UPSTREAM_RND,  "ML-DSA rnd size drift");
_Static_assert(MLDSA_TRBYTES   == UPSTREAM_TR,   "ML-DSA tr size drift");
_Static_assert(MLDSA_CRHBYTES  == UPSTREAM_CRH,  "ML-DSA mu/CRH size drift");
_Static_assert(MLDSA_DOMAIN_SEPARATION_MAX_BYTES == UPSTREAM_DS, "ML-DSA domain-separation buffer drift");
_Static_assert(MLDSA_PREHASH_NONE == UPSTREAM_PREHASH_NONE, "MLD_PREHASH_NONE drift");

static void *const probes[] = {
  (void *)&GEM_FN(keypair),           (void *)&GEM_FN(keypair_internal),
  (void *)&GEM_FN(signature),         (void *)&GEM_FN(signature_internal),
  (void *)&GEM_FN(verify),            (void *)&GEM_FN(pk_from_sk),
  (void *)&GEM_FN(signature_extmu),   (void *)&GEM_FN(verify_extmu),
  (void *)&GEM_FN(prepare_domain_separation_prefix),
};
const void *CAT(pqcrypto_conformance_mldsa, LEVEL)(void) { return probes; }
