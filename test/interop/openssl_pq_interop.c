#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MLKEM768_PUB_BYTES 1184
#define MLKEM768_PRIV_BYTES 2400
#define MLKEM768_CT_BYTES 1088
#define MLKEM768_SS_BYTES 32

#define MLDsa65_PUB_BYTES 1952
#define MLDsa65_PRIV_BYTES 4032
#define MLDsa65_SIG_MAX_BYTES 4096

static void die(const char *msg) {
    fprintf(stderr, "%s\n", msg);
    ERR_print_errors_fp(stderr);
    exit(1);
}

static int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

static unsigned char *hex_decode(const char *hex, size_t *out_len) {
    size_t len = strlen(hex);
    if ((len % 2) != 0) die("invalid hex length");

    *out_len = len / 2;
    unsigned char *out = OPENSSL_malloc(*out_len);
    if (out == NULL) die("allocation failure");

    for (size_t i = 0; i < *out_len; i++) {
        int hi = hex_value(hex[2 * i]);
        int lo = hex_value(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) die("invalid hex");
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return out;
}

static char *hex_encode(const unsigned char *buf, size_t len) {
    static const char *digits = "0123456789abcdef";
    char *out = OPENSSL_malloc(len * 2 + 1);
    if (out == NULL) die("allocation failure");
    for (size_t i = 0; i < len; i++) {
        out[2 * i] = digits[(buf[i] >> 4) & 0x0f];
        out[2 * i + 1] = digits[buf[i] & 0x0f];
    }
    out[len * 2] = '\0';
    return out;
}

static EVP_PKEY *pkey_from_raw(const char *alg, const unsigned char *pub, size_t publen,
                               const unsigned char *priv, size_t privlen) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL);
    if (ctx == NULL) return NULL;
    if (EVP_PKEY_fromdata_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    OSSL_PARAM params[3];
    int idx = 0;
    if (pub != NULL) {
        params[idx++] = OSSL_PARAM_construct_octet_string((char *)"pub", (void *)pub, publen);
    }
    if (priv != NULL) {
        params[idx++] = OSSL_PARAM_construct_octet_string((char *)"priv", (void *)priv, privlen);
    }
    params[idx] = OSSL_PARAM_construct_end();

    EVP_PKEY *pkey = NULL;
    int selection = (priv != NULL) ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY;
    if (EVP_PKEY_fromdata(ctx, &pkey, selection, params) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

static void get_octets(EVP_PKEY *pkey, const char *name, unsigned char **out, size_t *out_len) {
    if (EVP_PKEY_get_octet_string_param(pkey, name, NULL, 0, out_len) <= 0) {
        die("EVP_PKEY_get_octet_string_param size failed");
    }
    *out = OPENSSL_malloc(*out_len);
    if (*out == NULL) die("allocation failure");
    if (EVP_PKEY_get_octet_string_param(pkey, name, *out, *out_len, out_len) <= 0) {
        die("EVP_PKEY_get_octet_string_param failed");
    }
}

static EVP_PKEY *mlkem_keygen_from_seed(const unsigned char *seed, size_t seed_len) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-768", NULL);
    if (ctx == NULL) return NULL;
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_octet_string((char *)"seed", (void *)seed, seed_len);
    params[1] = OSSL_PARAM_construct_end();
    if (EVP_PKEY_CTX_set_params(ctx, params) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_generate(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

static EVP_PKEY *mldsa_keygen_from_seed(const unsigned char *seed, size_t seed_len) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-DSA-65", NULL);
    if (ctx == NULL) return NULL;
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_octet_string((char *)"seed", (void *)seed, seed_len);
    params[1] = OSSL_PARAM_construct_end();
    if (EVP_PKEY_CTX_set_params(ctx, params) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_generate(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

static void cmd_probe(void) {
    EVP_PKEY_CTX *kem = EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-768", NULL);
    EVP_PKEY_CTX *sig = EVP_PKEY_CTX_new_from_name(NULL, "ML-DSA-65", NULL);
    unsigned long version = OpenSSL_version_num();
    printf("{\"openssl_version\":\"%s\",\"version_num\":%lu,\"mlkem\":%s,\"mldsa\":%s}\n",
           OpenSSL_version(OPENSSL_VERSION), version,
           kem ? "true" : "false",
           sig ? "true" : "false");
    EVP_PKEY_CTX_free(kem);
    EVP_PKEY_CTX_free(sig);
}

static void cmd_mlkem_keygen_from_seed(const char *seed_hex) {
    size_t seed_len = 0;
    unsigned char *seed = hex_decode(seed_hex, &seed_len);
    EVP_PKEY *pkey = mlkem_keygen_from_seed(seed, seed_len);
    if (pkey == NULL) die("mlkem keygen failed");
    unsigned char *pub = NULL, *priv = NULL;
    size_t publen = 0, privlen = 0;
    get_octets(pkey, "pub", &pub, &publen);
    get_octets(pkey, "priv", &priv, &privlen);
    char *pub_hex = hex_encode(pub, publen);
    char *priv_hex = hex_encode(priv, privlen);
    printf("%s\n%s\n", pub_hex, priv_hex);
    OPENSSL_free(seed); OPENSSL_free(pub); OPENSSL_free(priv); OPENSSL_free(pub_hex); OPENSSL_free(priv_hex); EVP_PKEY_free(pkey);
}

static void cmd_mldsa_keygen_from_seed(const char *seed_hex) {
    size_t seed_len = 0;
    unsigned char *seed = hex_decode(seed_hex, &seed_len);
    EVP_PKEY *pkey = mldsa_keygen_from_seed(seed, seed_len);
    if (pkey == NULL) die("mldsa keygen failed");
    unsigned char *pub = NULL, *priv = NULL;
    size_t publen = 0, privlen = 0;
    get_octets(pkey, "pub", &pub, &publen);
    get_octets(pkey, "priv", &priv, &privlen);
    char *pub_hex = hex_encode(pub, publen);
    char *priv_hex = hex_encode(priv, privlen);
    printf("%s\n%s\n", pub_hex, priv_hex);
    OPENSSL_free(seed); OPENSSL_free(pub); OPENSSL_free(priv); OPENSSL_free(pub_hex); OPENSSL_free(priv_hex); EVP_PKEY_free(pkey);
}

static void cmd_mlkem_encap(const char *pub_hex) {
    size_t publen = 0;
    unsigned char *pub = hex_decode(pub_hex, &publen);
    EVP_PKEY *pkey = pkey_from_raw("ML-KEM-768", pub, publen, NULL, 0);
    if (pkey == NULL) die("mlkem import public failed");

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    if (ctx == NULL) die("mlkem ctx failed");
    if (EVP_PKEY_encapsulate_init(ctx, NULL) <= 0) die("mlkem encapsulate init failed");

    unsigned char ct[MLKEM768_CT_BYTES];
    unsigned char ss[MLKEM768_SS_BYTES];
    size_t ctlen = sizeof(ct), sslen = sizeof(ss);
    if (EVP_PKEY_encapsulate(ctx, ct, &ctlen, ss, &sslen) <= 0) die("mlkem encapsulate failed");

    char *ct_hex = hex_encode(ct, ctlen);
    char *ss_hex = hex_encode(ss, sslen);
    printf("%s\n%s\n", ct_hex, ss_hex);

    OPENSSL_free(pub); EVP_PKEY_free(pkey); EVP_PKEY_CTX_free(ctx); OPENSSL_free(ct_hex); OPENSSL_free(ss_hex);
}

static void cmd_mlkem_decap(const char *priv_hex, const char *ct_hex) {
    size_t privlen = 0, ctlen = 0;
    unsigned char *priv = hex_decode(priv_hex, &privlen);
    unsigned char *ct = hex_decode(ct_hex, &ctlen);
    EVP_PKEY *pkey = pkey_from_raw("ML-KEM-768", NULL, 0, priv, privlen);
    if (pkey == NULL) die("mlkem import private failed");

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    if (ctx == NULL) die("mlkem ctx failed");
    if (EVP_PKEY_decapsulate_init(ctx, NULL) <= 0) die("mlkem decapsulate init failed");

    unsigned char ss[MLKEM768_SS_BYTES];
    size_t sslen = sizeof(ss);
    if (EVP_PKEY_decapsulate(ctx, ss, &sslen, ct, ctlen) <= 0) die("mlkem decapsulate failed");

    char *ss_hex = hex_encode(ss, sslen);
    printf("%s\n", ss_hex);

    OPENSSL_free(priv); OPENSSL_free(ct); EVP_PKEY_free(pkey); EVP_PKEY_CTX_free(ctx); OPENSSL_free(ss_hex);
}

static void cmd_mldsa_sign(const char *priv_hex, const char *msg_hex) {
    size_t privlen = 0, msglen = 0;
    unsigned char *priv = hex_decode(priv_hex, &privlen);
    unsigned char *msg = hex_decode(msg_hex, &msglen);
    EVP_PKEY *pkey = pkey_from_raw("ML-DSA-65", NULL, 0, priv, privlen);
    if (pkey == NULL) die("mldsa import private failed");

    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx = NULL;
    if (mctx == NULL) die("mldsa mdctx failed");
    if (EVP_DigestSignInit_ex(mctx, &pctx, NULL, NULL, NULL, pkey, NULL) <= 0) die("mldsa sign init failed");

    size_t siglen = 0;
    if (EVP_DigestSign(mctx, NULL, &siglen, msg, msglen) <= 0) die("mldsa sign size failed");
    unsigned char *sig = OPENSSL_malloc(siglen);
    if (sig == NULL) die("allocation failure");
    if (EVP_DigestSign(mctx, sig, &siglen, msg, msglen) <= 0) die("mldsa sign failed");

    char *sig_hex = hex_encode(sig, siglen);
    printf("%s\n", sig_hex);

    OPENSSL_free(priv); OPENSSL_free(msg); OPENSSL_free(sig); OPENSSL_free(sig_hex); EVP_MD_CTX_free(mctx); EVP_PKEY_free(pkey);
}

static void cmd_mldsa_verify(const char *pub_hex, const char *msg_hex, const char *sig_hex) {
    size_t publen = 0, msglen = 0, siglen = 0;
    unsigned char *pub = hex_decode(pub_hex, &publen);
    unsigned char *msg = hex_decode(msg_hex, &msglen);
    unsigned char *sig = hex_decode(sig_hex, &siglen);
    EVP_PKEY *pkey = pkey_from_raw("ML-DSA-65", pub, publen, NULL, 0);
    if (pkey == NULL) die("mldsa import public failed");

    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx = NULL;
    if (mctx == NULL) die("mldsa mdctx failed");
    if (EVP_DigestVerifyInit_ex(mctx, &pctx, NULL, NULL, NULL, pkey, NULL) <= 0) die("mldsa verify init failed");
    int ok = EVP_DigestVerify(mctx, sig, siglen, msg, msglen);
    if (ok == 1) {
        printf("OK\n");
    } else if (ok == 0) {
        printf("FAIL\n");
    } else {
        die("mldsa verify error");
    }

    OPENSSL_free(pub); OPENSSL_free(msg); OPENSSL_free(sig); EVP_MD_CTX_free(mctx); EVP_PKEY_free(pkey);
}

int main(int argc, char **argv) {
    ERR_load_crypto_strings();

    if (argc < 2) {
        fprintf(stderr, "usage: %s <command> [args...]\n", argv[0]);
        return 2;
    }

    if (strcmp(argv[1], "probe") == 0) {
        cmd_probe();
        return 0;
    }
    if (strcmp(argv[1], "mlkem-keygen-from-seed") == 0 && argc == 3) {
        cmd_mlkem_keygen_from_seed(argv[2]);
        return 0;
    }
    if (strcmp(argv[1], "mlkem-encap") == 0 && argc == 3) {
        cmd_mlkem_encap(argv[2]);
        return 0;
    }
    if (strcmp(argv[1], "mlkem-decap") == 0 && argc == 4) {
        cmd_mlkem_decap(argv[2], argv[3]);
        return 0;
    }
    if (strcmp(argv[1], "mldsa-keygen-from-seed") == 0 && argc == 3) {
        cmd_mldsa_keygen_from_seed(argv[2]);
        return 0;
    }
    if (strcmp(argv[1], "mldsa-sign") == 0 && argc == 4) {
        cmd_mldsa_sign(argv[2], argv[3]);
        return 0;
    }
    if (strcmp(argv[1], "mldsa-verify") == 0 && argc == 5) {
        cmd_mldsa_verify(argv[2], argv[3], argv[4]);
        return 0;
    }

    fprintf(stderr, "unknown command\n");
    return 2;
}
