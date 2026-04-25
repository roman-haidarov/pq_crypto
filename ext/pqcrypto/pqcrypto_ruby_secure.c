#include <ruby.h>
#include <ruby/thread.h>
#include <ruby/encoding.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>

#include "pqcrypto_secure.h"

#ifndef RB_NOGVL_OFFLOAD_SAFE
#define RB_NOGVL_OFFLOAD_SAFE 0
#endif

typedef struct {
    int result;
    uint8_t *public_key;
    uint8_t *secret_key;
    const uint8_t *seed;
    size_t seed_len;
} kem_keypair_call_t;

typedef struct {
    int result;
    uint8_t *ciphertext;
    uint8_t *shared_secret;
    const uint8_t *public_key;
    const uint8_t *seed;
    size_t seed_len;
} kem_encapsulate_call_t;

typedef struct {
    int result;
    uint8_t *shared_secret;
    const uint8_t *ciphertext;
    const uint8_t *secret_key;
} kem_decapsulate_call_t;

typedef struct {
    int result;
    uint8_t *public_key;
    uint8_t *secret_key;
    const uint8_t *seed;
    size_t seed_len;
} sign_keypair_call_t;

typedef struct {
    int result;
    uint8_t *signature;
    size_t signature_len;
    uint8_t *message;
    size_t message_len;
    const uint8_t *secret_key;
    const uint8_t *seed;
    size_t seed_len;
} sign_call_t;

typedef struct {
    int result;
    const uint8_t *signature;
    size_t signature_len;
    uint8_t *message;
    size_t message_len;
    const uint8_t *public_key;
} verify_call_t;

static VALUE mPQCrypto;
static VALUE ePQCryptoError;
static VALUE ePQCryptoVerificationError;

__attribute__((noreturn)) static void pq_raise_general_error(int err);

static const char *pq_algorithm_symbol_to_cstr(VALUE algorithm) {
    ID id;
    if (SYMBOL_P(algorithm)) {
        id = SYM2ID(algorithm);
    } else {
        VALUE str = StringValue(algorithm);
        id = rb_intern_str(str);
    }
    if (id == rb_intern("ml_kem_768"))
        return "ml_kem_768";
    if (id == rb_intern("ml_kem_768_x25519_xwing"))
        return "ml_kem_768_x25519_xwing";
    if (id == rb_intern("ml_dsa_65"))
        return "ml_dsa_65";
    rb_raise(rb_eArgError, "Unsupported serialization algorithm");
}

static VALUE pq_algorithm_cstr_to_symbol(const char *algorithm) {
    if (strcmp(algorithm, "ml_kem_768") == 0)
        return ID2SYM(rb_intern("ml_kem_768"));
    if (strcmp(algorithm, "ml_kem_768_x25519_xwing") == 0)
        return ID2SYM(rb_intern("ml_kem_768_x25519_xwing"));
    if (strcmp(algorithm, "ml_dsa_65") == 0)
        return ID2SYM(rb_intern("ml_dsa_65"));
    rb_raise(rb_eArgError, "Unsupported serialization algorithm");
}

static void *pq_ml_kem_keypair_nogvl(void *arg) {
    kem_keypair_call_t *call = (kem_keypair_call_t *)arg;
    call->result = pq_mlkem_keypair(call->public_key, call->secret_key);
    return NULL;
}

static void *pq_ml_kem_encapsulate_nogvl(void *arg) {
    kem_encapsulate_call_t *call = (kem_encapsulate_call_t *)arg;
    call->result = pq_mlkem_encapsulate(call->ciphertext, call->shared_secret, call->public_key);
    return NULL;
}

static void *pq_ml_kem_decapsulate_nogvl(void *arg) {
    kem_decapsulate_call_t *call = (kem_decapsulate_call_t *)arg;
    call->result = pq_mlkem_decapsulate(call->shared_secret, call->ciphertext, call->secret_key);
    return NULL;
}

static void *pq_testing_ml_kem_keypair_nogvl(void *arg) {
    kem_keypair_call_t *call = (kem_keypair_call_t *)arg;
    call->result = pq_testing_mlkem_keypair_from_seed(call->public_key, call->secret_key,
                                                      call->seed, call->seed_len);
    return NULL;
}

static void *pq_testing_ml_kem_encapsulate_nogvl(void *arg) {
    kem_encapsulate_call_t *call = (kem_encapsulate_call_t *)arg;
    call->result = pq_testing_mlkem_encapsulate_from_seed(
        call->ciphertext, call->shared_secret, call->public_key, call->seed, call->seed_len);
    return NULL;
}

static void *pq_hybrid_kem_keypair_nogvl(void *arg) {
    kem_keypair_call_t *call = (kem_keypair_call_t *)arg;
    call->result = pq_hybrid_kem_keypair(call->public_key, call->secret_key);
    return NULL;
}

static void *pq_hybrid_kem_encapsulate_nogvl(void *arg) {
    kem_encapsulate_call_t *call = (kem_encapsulate_call_t *)arg;
    call->result =
        pq_hybrid_kem_encapsulate(call->ciphertext, call->shared_secret, call->public_key);
    return NULL;
}

static void *pq_hybrid_kem_decapsulate_nogvl(void *arg) {
    kem_decapsulate_call_t *call = (kem_decapsulate_call_t *)arg;
    call->result =
        pq_hybrid_kem_decapsulate(call->shared_secret, call->ciphertext, call->secret_key);
    return NULL;
}

static void *pq_sign_keypair_nogvl(void *arg) {
    sign_keypair_call_t *call = (sign_keypair_call_t *)arg;
    call->result = pq_sign_keypair(call->public_key, call->secret_key);
    return NULL;
}

static void *pq_sign_nogvl(void *arg) {
    sign_call_t *call = (sign_call_t *)arg;
    call->result = pq_sign(call->signature, &call->signature_len, call->message, call->message_len,
                           call->secret_key);
    return NULL;
}

static void *pq_testing_sign_keypair_nogvl(void *arg) {
    sign_keypair_call_t *call = (sign_keypair_call_t *)arg;
    call->result = pq_testing_mldsa_keypair_from_seed(call->public_key, call->secret_key,
                                                      call->seed, call->seed_len);
    return NULL;
}

static void *pq_testing_sign_nogvl(void *arg) {
    sign_call_t *call = (sign_call_t *)arg;
    call->result = pq_testing_mldsa_sign_from_seed(call->signature, &call->signature_len,
                                                   call->message, call->message_len,
                                                   call->secret_key, call->seed, call->seed_len);
    return NULL;
}

static void *pq_verify_nogvl(void *arg) {
    verify_call_t *call = (verify_call_t *)arg;
    call->result = pq_verify(call->signature, call->signature_len, call->message, call->message_len,
                             call->public_key);
    return NULL;
}

static uint8_t *pq_alloc_buffer(size_t len) {
    if (len == 0) {
        return NULL;
    }

    uint8_t *buffer = malloc(len);
    if (!buffer) {
        rb_raise(rb_eNoMemError, "Memory allocation failed");
    }

    return buffer;
}

static uint8_t *pq_copy_ruby_string(VALUE string, size_t *len_out) {
    StringValue(string);

    size_t len = (size_t)RSTRING_LEN(string);
    *len_out = len;

    if (len == 0) {
        return NULL;
    }

    uint8_t *copy = pq_alloc_buffer(len);
    memcpy(copy, RSTRING_PTR(string), len);
    return copy;
}

static VALUE pq_string_from_buffer(const uint8_t *buffer, size_t len) {
    return rb_enc_str_new((const char *)buffer, (long)len, rb_ascii8bit_encoding());
}

static void pq_wipe_and_free(uint8_t *buffer, size_t len) {
    if (buffer) {
        pq_secure_wipe(buffer, len);
        free(buffer);
    }
}

static void pq_free_buffer(uint8_t *buffer) {
    free(buffer);
}

static void pq_validate_bytes_argument(VALUE value, size_t expected_len, const char *what) {
    StringValue(value);
    if ((size_t)RSTRING_LEN(value) != expected_len) {
        rb_raise(rb_eArgError, "Invalid %s length", what);
    }
}

static VALUE pq_build_binary_pair(const uint8_t *first, size_t first_len, const uint8_t *second,
                                  size_t second_len) {
    VALUE result = rb_ary_new2(2);
    rb_ary_push(result, pq_string_from_buffer(first, first_len));
    rb_ary_push(result, pq_string_from_buffer(second, second_len));
    return result;
}

static VALUE pq_build_algorithm_key_pair(const char *algorithm, const uint8_t *key,
                                         size_t key_len) {
    VALUE result = rb_ary_new2(2);
    rb_ary_push(result, pq_algorithm_cstr_to_symbol(algorithm));
    rb_ary_push(result, pq_string_from_buffer(key, key_len));
    return result;
}

static VALUE pq_run_kem_keypair(void *(*nogvl)(void *), size_t public_key_len,
                                size_t secret_key_len) {
    kem_keypair_call_t call = {0};
    VALUE result;

    call.public_key = pq_alloc_buffer(public_key_len);
    call.secret_key = pq_alloc_buffer(secret_key_len);

    rb_thread_call_without_gvl(nogvl, &call, NULL, NULL);

    if (call.result != PQ_SUCCESS) {
        pq_wipe_and_free(call.secret_key, secret_key_len);
        free(call.public_key);
        pq_raise_general_error(call.result);
    }

    result = pq_build_binary_pair(call.public_key, public_key_len, call.secret_key, secret_key_len);
    free(call.public_key);
    pq_wipe_and_free(call.secret_key, secret_key_len);
    return result;
}

static VALUE pq_run_kem_encapsulate(void *(*nogvl)(void *), VALUE public_key, size_t public_key_len,
                                    size_t ciphertext_len, size_t shared_secret_len) {
    kem_encapsulate_call_t call = {0};
    VALUE result;
    size_t copied_public_key_len = 0;

    pq_validate_bytes_argument(public_key, public_key_len, "public key");

    call.public_key = pq_copy_ruby_string(public_key, &copied_public_key_len);
    call.ciphertext = pq_alloc_buffer(ciphertext_len);
    call.shared_secret = pq_alloc_buffer(shared_secret_len);

    rb_thread_call_without_gvl(nogvl, &call, NULL, NULL);
    pq_wipe_and_free((uint8_t *)call.public_key, copied_public_key_len);

    if (call.result != PQ_SUCCESS) {
        pq_wipe_and_free(call.shared_secret, shared_secret_len);
        free(call.ciphertext);
        pq_raise_general_error(call.result);
    }

    result = pq_build_binary_pair(call.ciphertext, ciphertext_len, call.shared_secret,
                                  shared_secret_len);
    free(call.ciphertext);
    pq_wipe_and_free(call.shared_secret, shared_secret_len);
    return result;
}

static VALUE pq_run_kem_decapsulate(void *(*nogvl)(void *), VALUE ciphertext, size_t ciphertext_len,
                                    VALUE secret_key, size_t secret_key_len,
                                    size_t shared_secret_len) {
    kem_decapsulate_call_t call = {0};
    VALUE result;
    size_t copied_ciphertext_len = 0;
    size_t copied_secret_key_len = 0;

    pq_validate_bytes_argument(ciphertext, ciphertext_len, "ciphertext");
    pq_validate_bytes_argument(secret_key, secret_key_len, "secret key");

    call.ciphertext = pq_copy_ruby_string(ciphertext, &copied_ciphertext_len);
    call.secret_key = pq_copy_ruby_string(secret_key, &copied_secret_key_len);
    call.shared_secret = pq_alloc_buffer(shared_secret_len);

    rb_thread_call_without_gvl(nogvl, &call, NULL, NULL);
    pq_wipe_and_free((uint8_t *)call.ciphertext, copied_ciphertext_len);
    pq_wipe_and_free((uint8_t *)call.secret_key, copied_secret_key_len);

    if (call.result != PQ_SUCCESS) {
        pq_wipe_and_free(call.shared_secret, shared_secret_len);
        pq_raise_general_error(call.result);
    }

    result = pq_string_from_buffer(call.shared_secret, shared_secret_len);
    pq_wipe_and_free(call.shared_secret, shared_secret_len);
    return result;
}

static VALUE pq_run_sign_keypair(void *(*nogvl)(void *), size_t public_key_len,
                                 size_t secret_key_len) {
    sign_keypair_call_t call = {0};
    VALUE result;

    call.public_key = pq_alloc_buffer(public_key_len);
    call.secret_key = pq_alloc_buffer(secret_key_len);

    rb_thread_call_without_gvl(nogvl, &call, NULL, NULL);

    if (call.result != PQ_SUCCESS) {
        pq_wipe_and_free(call.secret_key, secret_key_len);
        free(call.public_key);
        pq_raise_general_error(call.result);
    }

    result = pq_build_binary_pair(call.public_key, public_key_len, call.secret_key, secret_key_len);
    free(call.public_key);
    pq_wipe_and_free(call.secret_key, secret_key_len);
    return result;
}

typedef int (*pq_export_der_fn)(uint8_t **, size_t *, const uint8_t *, size_t, const char *);
typedef int (*pq_export_pem_fn)(char **, size_t *, const uint8_t *, size_t, const char *);
typedef int (*pq_import_der_fn)(char **, uint8_t **, size_t *, const uint8_t *, size_t);
typedef int (*pq_import_pem_fn)(char **, uint8_t **, size_t *, const char *, size_t);

static VALUE pq_export_container_der(VALUE algorithm, VALUE key_bytes, pq_export_der_fn fn) {
    uint8_t *out = NULL;
    size_t out_len = 0;
    VALUE result;
    int ret;

    StringValue(key_bytes);
    ret = fn(&out, &out_len, (const uint8_t *)RSTRING_PTR(key_bytes),
             (size_t)RSTRING_LEN(key_bytes), pq_algorithm_symbol_to_cstr(algorithm));
    if (ret != PQ_SUCCESS)
        pq_raise_general_error(ret);

    result = pq_string_from_buffer(out, out_len);
    pq_secure_wipe(out, out_len);
    free(out);
    return result;
}

static VALUE pq_export_container_pem(VALUE algorithm, VALUE key_bytes, pq_export_pem_fn fn) {
    char *out = NULL;
    size_t out_len = 0;
    VALUE result;
    int ret;

    StringValue(key_bytes);
    ret = fn(&out, &out_len, (const uint8_t *)RSTRING_PTR(key_bytes),
             (size_t)RSTRING_LEN(key_bytes), pq_algorithm_symbol_to_cstr(algorithm));
    if (ret != PQ_SUCCESS)
        pq_raise_general_error(ret);

    result = rb_utf8_str_new(out, (long)out_len);
    pq_secure_wipe(out, out_len);
    free(out);
    return result;
}

static VALUE pq_import_container_der(VALUE der, pq_import_der_fn fn) {
    char *algorithm = NULL;
    uint8_t *key = NULL;
    size_t key_len = 0;
    VALUE result;
    int ret;

    StringValue(der);
    ret =
        fn(&algorithm, &key, &key_len, (const uint8_t *)RSTRING_PTR(der), (size_t)RSTRING_LEN(der));
    if (ret != PQ_SUCCESS)
        pq_raise_general_error(ret);

    result = pq_build_algorithm_key_pair(algorithm, key, key_len);
    free(algorithm);
    pq_secure_wipe(key, key_len);
    free(key);
    return result;
}

static VALUE pq_import_container_pem(VALUE pem, pq_import_pem_fn fn) {
    char *algorithm = NULL;
    uint8_t *key = NULL;
    size_t key_len = 0;
    VALUE result;
    int ret;

    StringValue(pem);
    ret = fn(&algorithm, &key, &key_len, RSTRING_PTR(pem), (size_t)RSTRING_LEN(pem));
    if (ret != PQ_SUCCESS)
        pq_raise_general_error(ret);

    result = pq_build_algorithm_key_pair(algorithm, key, key_len);
    free(algorithm);
    pq_secure_wipe(key, key_len);
    free(key);
    return result;
}

__attribute__((noreturn)) static void pq_raise_general_error(int err) {
    switch (err) {
    case PQ_ERROR_KEYPAIR:
        rb_raise(ePQCryptoError, "Keypair generation failed");
        break;
    case PQ_ERROR_ENCAPSULATE:
        rb_raise(ePQCryptoError, "Encapsulation failed");
        break;
    case PQ_ERROR_DECAPSULATE:
        rb_raise(ePQCryptoError, "Decapsulation failed");
        break;
    case PQ_ERROR_SIGN:
        rb_raise(ePQCryptoError, "Signing failed");
        break;
    case PQ_ERROR_VERIFY:
        rb_raise(ePQCryptoError, "Verification failed");
        break;
    case PQ_ERROR_RANDOM:
        rb_raise(ePQCryptoError, "Random number generation failed");
        break;
    case PQ_ERROR_KDF:
        rb_raise(ePQCryptoError, "Key derivation failed");
        break;
    case PQ_ERROR_BUFFER:
        rb_raise(ePQCryptoError, "Buffer error");
        break;
    case PQ_ERROR_NOMEM:
        rb_raise(rb_eNoMemError, "Memory allocation failed");
        break;
    case PQ_ERROR_OPENSSL:
        rb_raise(ePQCryptoError, "OpenSSL error");
        break;
    default:
        rb_raise(ePQCryptoError, "Unknown error: %d", err);
        break;
    }
}

static VALUE pqcrypto_ml_kem_keypair(VALUE self) {
    (void)self;
    return pq_run_kem_keypair(pq_ml_kem_keypair_nogvl, PQ_MLKEM_PUBLICKEYBYTES,
                              PQ_MLKEM_SECRETKEYBYTES);
}

static VALUE pqcrypto_ml_kem_encapsulate(VALUE self, VALUE public_key) {
    (void)self;
    return pq_run_kem_encapsulate(pq_ml_kem_encapsulate_nogvl, public_key, PQ_MLKEM_PUBLICKEYBYTES,
                                  PQ_MLKEM_CIPHERTEXTBYTES, PQ_MLKEM_SHAREDSECRETBYTES);
}

static VALUE pqcrypto_ml_kem_decapsulate(VALUE self, VALUE ciphertext, VALUE secret_key) {
    (void)self;
    return pq_run_kem_decapsulate(pq_ml_kem_decapsulate_nogvl, ciphertext, PQ_MLKEM_CIPHERTEXTBYTES,
                                  secret_key, PQ_MLKEM_SECRETKEYBYTES, PQ_MLKEM_SHAREDSECRETBYTES);
}

static VALUE pqcrypto_hybrid_kem_keypair(VALUE self) {
    (void)self;
    return pq_run_kem_keypair(pq_hybrid_kem_keypair_nogvl, PQ_HYBRID_PUBLICKEYBYTES,
                              PQ_HYBRID_SECRETKEYBYTES);
}

static VALUE pqcrypto_hybrid_kem_encapsulate(VALUE self, VALUE public_key) {
    (void)self;
    return pq_run_kem_encapsulate(pq_hybrid_kem_encapsulate_nogvl, public_key,
                                  PQ_HYBRID_PUBLICKEYBYTES, PQ_HYBRID_CIPHERTEXTBYTES,
                                  PQ_HYBRID_SHAREDSECRETBYTES);
}

static VALUE pqcrypto_hybrid_kem_decapsulate(VALUE self, VALUE ciphertext, VALUE secret_key) {
    (void)self;
    return pq_run_kem_decapsulate(pq_hybrid_kem_decapsulate_nogvl, ciphertext,
                                  PQ_HYBRID_CIPHERTEXTBYTES, secret_key, PQ_HYBRID_SECRETKEYBYTES,
                                  PQ_HYBRID_SHAREDSECRETBYTES);
}

static VALUE pqcrypto__test_ml_kem_keypair_from_seed(VALUE self, VALUE seed) {
    (void)self;
    StringValue(seed);

    if ((size_t)RSTRING_LEN(seed) != 64) {
        rb_raise(rb_eArgError, "Deterministic ML-KEM test seed must be 64 bytes (FIPS 203 d||z)");
    }

    kem_keypair_call_t call = {0};
    size_t seed_len = 0;
    call.public_key = pq_alloc_buffer(PQ_MLKEM_PUBLICKEYBYTES);
    call.secret_key = pq_alloc_buffer(PQ_MLKEM_SECRETKEYBYTES);
    call.seed = pq_copy_ruby_string(seed, &seed_len);
    call.seed_len = seed_len;

    rb_thread_call_without_gvl(pq_testing_ml_kem_keypair_nogvl, &call, NULL, NULL);
    pq_wipe_and_free((uint8_t *)call.seed, call.seed_len);

    if (call.result != PQ_SUCCESS) {
        pq_wipe_and_free(call.secret_key, PQ_MLKEM_SECRETKEYBYTES);
        free(call.public_key);
        pq_raise_general_error(call.result);
    }

    VALUE result = rb_ary_new2(2);
    rb_ary_push(result, pq_string_from_buffer(call.public_key, PQ_MLKEM_PUBLICKEYBYTES));
    rb_ary_push(result, pq_string_from_buffer(call.secret_key, PQ_MLKEM_SECRETKEYBYTES));

    free(call.public_key);
    pq_wipe_and_free(call.secret_key, PQ_MLKEM_SECRETKEYBYTES);
    return result;
}

static VALUE pqcrypto__test_ml_kem_encapsulate_from_seed(VALUE self, VALUE public_key, VALUE seed) {
    (void)self;
    pq_validate_bytes_argument(public_key, PQ_MLKEM_PUBLICKEYBYTES, "public key");
    StringValue(seed);

    if ((size_t)RSTRING_LEN(seed) != 32) {
        rb_raise(rb_eArgError, "Deterministic test seed must be 32 bytes");
    }

    kem_encapsulate_call_t call = {0};
    size_t public_key_len = 0;
    size_t seed_len = 0;
    call.public_key = pq_copy_ruby_string(public_key, &public_key_len);
    call.ciphertext = pq_alloc_buffer(PQ_MLKEM_CIPHERTEXTBYTES);
    call.shared_secret = pq_alloc_buffer(PQ_MLKEM_SHAREDSECRETBYTES);
    call.seed = pq_copy_ruby_string(seed, &seed_len);
    call.seed_len = seed_len;

    rb_thread_call_without_gvl(pq_testing_ml_kem_encapsulate_nogvl, &call, NULL, NULL);
    pq_wipe_and_free((uint8_t *)call.public_key, public_key_len);
    pq_wipe_and_free((uint8_t *)call.seed, call.seed_len);

    if (call.result != PQ_SUCCESS) {
        pq_wipe_and_free(call.shared_secret, PQ_MLKEM_SHAREDSECRETBYTES);
        free(call.ciphertext);
        pq_raise_general_error(call.result);
    }

    VALUE result = rb_ary_new2(2);
    rb_ary_push(result, pq_string_from_buffer(call.ciphertext, PQ_MLKEM_CIPHERTEXTBYTES));
    rb_ary_push(result, pq_string_from_buffer(call.shared_secret, PQ_MLKEM_SHAREDSECRETBYTES));

    free(call.ciphertext);
    pq_wipe_and_free(call.shared_secret, PQ_MLKEM_SHAREDSECRETBYTES);
    return result;
}

static VALUE pqcrypto__test_sign_keypair_from_seed(VALUE self, VALUE seed) {
    (void)self;
    StringValue(seed);

    if ((size_t)RSTRING_LEN(seed) != 32) {
        rb_raise(rb_eArgError, "Deterministic test seed must be 32 bytes");
    }

    sign_keypair_call_t call = {0};
    size_t seed_len = 0;
    call.public_key = pq_alloc_buffer(PQ_MLDSA_PUBLICKEYBYTES);
    call.secret_key = pq_alloc_buffer(PQ_MLDSA_SECRETKEYBYTES);
    call.seed = pq_copy_ruby_string(seed, &seed_len);
    call.seed_len = seed_len;

    rb_thread_call_without_gvl(pq_testing_sign_keypair_nogvl, &call, NULL, NULL);
    pq_wipe_and_free((uint8_t *)call.seed, call.seed_len);

    if (call.result != PQ_SUCCESS) {
        pq_wipe_and_free(call.secret_key, PQ_MLDSA_SECRETKEYBYTES);
        free(call.public_key);
        pq_raise_general_error(call.result);
    }

    VALUE result = rb_ary_new2(2);
    rb_ary_push(result, pq_string_from_buffer(call.public_key, PQ_MLDSA_PUBLICKEYBYTES));
    rb_ary_push(result, pq_string_from_buffer(call.secret_key, PQ_MLDSA_SECRETKEYBYTES));

    free(call.public_key);
    pq_wipe_and_free(call.secret_key, PQ_MLDSA_SECRETKEYBYTES);
    return result;
}

static VALUE pqcrypto__test_sign_from_seed(VALUE self, VALUE message, VALUE secret_key,
                                           VALUE seed) {
    (void)self;
    pq_validate_bytes_argument(secret_key, PQ_MLDSA_SECRETKEYBYTES, "secret key");
    StringValue(seed);

    if ((size_t)RSTRING_LEN(seed) != 32) {
        rb_raise(rb_eArgError, "Deterministic test seed must be 32 bytes");
    }

    sign_call_t call = {0};
    size_t secret_key_len = 0;
    size_t seed_len = 0;
    call.secret_key = pq_copy_ruby_string(secret_key, &secret_key_len);
    call.signature_len = PQ_MLDSA_BYTES;
    call.signature = pq_alloc_buffer(PQ_MLDSA_BYTES);
    call.message = pq_copy_ruby_string(message, &call.message_len);
    call.seed = pq_copy_ruby_string(seed, &seed_len);
    call.seed_len = seed_len;

    rb_thread_call_without_gvl(pq_testing_sign_nogvl, &call, NULL, NULL);

    pq_free_buffer(call.message);
    pq_wipe_and_free((uint8_t *)call.secret_key, secret_key_len);
    pq_wipe_and_free((uint8_t *)call.seed, call.seed_len);

    if (call.result != PQ_SUCCESS) {
        pq_free_buffer(call.signature);
        pq_raise_general_error(call.result);
    }

    VALUE result = pq_string_from_buffer(call.signature, call.signature_len);
    pq_free_buffer(call.signature);
    return result;
}

static VALUE pqcrypto_sign_keypair(VALUE self) {
    (void)self;
    return pq_run_sign_keypair(pq_sign_keypair_nogvl, PQ_MLDSA_PUBLICKEYBYTES,
                               PQ_MLDSA_SECRETKEYBYTES);
}

static VALUE pqcrypto_sign(VALUE self, VALUE message, VALUE secret_key) {
    (void)self;
    pq_validate_bytes_argument(secret_key, PQ_MLDSA_SECRETKEYBYTES, "secret key");

    sign_call_t call = {0};
    size_t secret_key_len = 0;
    call.secret_key = pq_copy_ruby_string(secret_key, &secret_key_len);
    call.signature_len = PQ_MLDSA_BYTES;
    call.signature = pq_alloc_buffer(PQ_MLDSA_BYTES);
    call.message = pq_copy_ruby_string(message, &call.message_len);

    rb_nogvl(pq_sign_nogvl, &call, NULL, NULL, RB_NOGVL_OFFLOAD_SAFE);

    pq_free_buffer(call.message);
    pq_wipe_and_free((uint8_t *)call.secret_key, secret_key_len);

    if (call.result != PQ_SUCCESS) {
        pq_free_buffer(call.signature);
        pq_raise_general_error(call.result);
    }

    VALUE result = pq_string_from_buffer(call.signature, call.signature_len);
    pq_free_buffer(call.signature);
    return result;
}

static VALUE pqcrypto_verify(VALUE self, VALUE message, VALUE signature, VALUE public_key) {
    (void)self;
    StringValue(signature);
    pq_validate_bytes_argument(public_key, PQ_MLDSA_PUBLICKEYBYTES, "public key");

    verify_call_t call = {0};
    size_t public_key_len = 0;
    size_t signature_len = 0;
    call.public_key = pq_copy_ruby_string(public_key, &public_key_len);
    call.signature = pq_copy_ruby_string(signature, &signature_len);
    call.signature_len = signature_len;
    call.message = pq_copy_ruby_string(message, &call.message_len);

    rb_nogvl(pq_verify_nogvl, &call, NULL, NULL, RB_NOGVL_OFFLOAD_SAFE);

    pq_free_buffer(call.message);
    pq_free_buffer((uint8_t *)call.public_key);
    pq_free_buffer((uint8_t *)call.signature);

    if (call.result == PQ_SUCCESS) {
        return Qtrue;
    }
    if (call.result == PQ_ERROR_VERIFY) {
        return Qfalse;
    }
    pq_raise_general_error(call.result);
}

static VALUE pqcrypto_ct_equals(VALUE self, VALUE a, VALUE b) {
    (void)self;
    StringValue(a);
    StringValue(b);
    if (RSTRING_LEN(a) != RSTRING_LEN(b)) {
        return Qfalse;
    }
    if (RSTRING_LEN(a) == 0) {
        return Qtrue;
    }
    if (CRYPTO_memcmp(RSTRING_PTR(a), RSTRING_PTR(b), (size_t)RSTRING_LEN(a)) == 0) {
        return Qtrue;
    }
    return Qfalse;
}

static VALUE pqcrypto_secure_wipe(VALUE self, VALUE str) {
    (void)self;
    StringValue(str);
    rb_str_modify(str);
    pq_secure_wipe((uint8_t *)RSTRING_PTR(str), (size_t)RSTRING_LEN(str));
    return Qnil;
}

static VALUE pqcrypto_version(VALUE self) {
    (void)self;
    return rb_str_new_cstr(pq_version());
}

typedef struct {
    void *builder;
} mu_builder_wrapper_t;

typedef struct {
    int result;
    void *builder;
    const uint8_t *chunk;
    size_t chunk_len;
} mu_absorb_call_t;

typedef struct {
    int result;
    void *builder;
    uint8_t *mu_out;
} mu_finalize_call_t;

typedef struct {
    int result;
    uint8_t *signature;
    size_t signature_len;
    const uint8_t *mu;
    const uint8_t *secret_key;
} sign_mu_call_t;

typedef struct {
    int result;
    const uint8_t *signature;
    size_t signature_len;
    const uint8_t *mu;
    const uint8_t *public_key;
} verify_mu_call_t;

static void mu_builder_wrapper_free(void *ptr) {
    mu_builder_wrapper_t *wrapper = (mu_builder_wrapper_t *)ptr;
    if (wrapper == NULL) {
        return;
    }
    if (wrapper->builder != NULL) {
        pq_mu_builder_release(wrapper->builder);
        wrapper->builder = NULL;
    }
    xfree(wrapper);
}

static size_t mu_builder_wrapper_size(const void *ptr) {
    (void)ptr;
    return sizeof(mu_builder_wrapper_t);
}

static const rb_data_type_t mu_builder_data_type = {
    "PQCrypto::MLDSA::MuBuilder",
    {NULL, mu_builder_wrapper_free, mu_builder_wrapper_size},
    NULL,
    NULL,
    RUBY_TYPED_FREE_IMMEDIATELY};

static mu_builder_wrapper_t *mu_builder_unwrap(VALUE obj) {
    mu_builder_wrapper_t *wrapper;
    TypedData_Get_Struct(obj, mu_builder_wrapper_t, &mu_builder_data_type, wrapper);
    if (wrapper == NULL || wrapper->builder == NULL) {
        rb_raise(ePQCryptoError, "mu builder used after release");
    }
    return wrapper;
}

static VALUE pqcrypto__native_mldsa_extract_tr(VALUE self, VALUE secret_key) {
    (void)self;
    pq_validate_bytes_argument(secret_key, PQ_MLDSA_SECRETKEYBYTES, "secret key");

    uint8_t tr[PQ_MLDSA_TRBYTES];
    int rc = pq_mldsa_extract_tr_from_secret_key(tr, (const uint8_t *)RSTRING_PTR(secret_key));
    if (rc != PQ_SUCCESS) {
        pq_secure_wipe(tr, sizeof(tr));
        pq_raise_general_error(rc);
    }
    VALUE result = pq_string_from_buffer(tr, sizeof(tr));
    pq_secure_wipe(tr, sizeof(tr));
    return result;
}

static VALUE pqcrypto__native_mldsa_compute_tr(VALUE self, VALUE public_key) {
    (void)self;
    pq_validate_bytes_argument(public_key, PQ_MLDSA_PUBLICKEYBYTES, "public key");

    uint8_t tr[PQ_MLDSA_TRBYTES];
    int rc = pq_mldsa_compute_tr_from_public_key(tr, (const uint8_t *)RSTRING_PTR(public_key));
    if (rc != PQ_SUCCESS) {
        pq_raise_general_error(rc);
    }
    return pq_string_from_buffer(tr, sizeof(tr));
}

static VALUE pqcrypto__native_mldsa_mu_builder_new(VALUE self, VALUE tr, VALUE ctx) {
    (void)self;
    pq_validate_bytes_argument(tr, PQ_MLDSA_TRBYTES, "tr");
    StringValue(ctx);

    size_t ctxlen = (size_t)RSTRING_LEN(ctx);
    if (ctxlen > 255) {
        rb_raise(rb_eArgError, "ML-DSA context length must be <= 255 bytes");
    }

    void *builder = pq_mu_builder_new();
    if (builder == NULL) {
        rb_raise(rb_eNoMemError, "Memory allocation failed (mu builder)");
    }

    int rc = pq_mu_builder_init(builder, (const uint8_t *)RSTRING_PTR(tr),
                                (const uint8_t *)RSTRING_PTR(ctx), ctxlen);
    if (rc != PQ_SUCCESS) {
        pq_mu_builder_release(builder);
        pq_raise_general_error(rc);
    }

    mu_builder_wrapper_t *wrapper;
    VALUE obj =
        TypedData_Make_Struct(rb_cObject, mu_builder_wrapper_t, &mu_builder_data_type, wrapper);
    wrapper->builder = builder;
    return obj;
}

static void *pq_mu_absorb_nogvl(void *arg) {
    mu_absorb_call_t *call = (mu_absorb_call_t *)arg;
    call->result = pq_mu_builder_absorb(call->builder, call->chunk, call->chunk_len);
    return NULL;
}

static VALUE pqcrypto__native_mldsa_mu_builder_update(VALUE self, VALUE builder_obj, VALUE chunk) {
    (void)self;
    mu_builder_wrapper_t *wrapper = mu_builder_unwrap(builder_obj);
    StringValue(chunk);

    size_t chunk_len = (size_t)RSTRING_LEN(chunk);
    if (chunk_len == 0) {
        return Qnil;
    }

    uint8_t *copy = pq_alloc_buffer(chunk_len);
    memcpy(copy, RSTRING_PTR(chunk), chunk_len);

    mu_absorb_call_t call = {0};
    call.builder = wrapper->builder;
    call.chunk = copy;
    call.chunk_len = chunk_len;

    rb_nogvl(pq_mu_absorb_nogvl, &call, NULL, NULL, RB_NOGVL_OFFLOAD_SAFE);
    free(copy);

    if (call.result != PQ_SUCCESS) {
        pq_raise_general_error(call.result);
    }
    return Qnil;
}

static void *pq_mu_finalize_nogvl(void *arg) {
    mu_finalize_call_t *call = (mu_finalize_call_t *)arg;
    call->result = pq_mu_builder_finalize(call->builder, call->mu_out);
    return NULL;
}

static VALUE pqcrypto__native_mldsa_mu_builder_finalize(VALUE self, VALUE builder_obj) {
    (void)self;
    mu_builder_wrapper_t *wrapper = mu_builder_unwrap(builder_obj);

    uint8_t mu[PQ_MLDSA_MUBYTES];

    mu_finalize_call_t call = {0};
    call.builder = wrapper->builder;
    call.mu_out = mu;

    rb_nogvl(pq_mu_finalize_nogvl, &call, NULL, NULL, RB_NOGVL_OFFLOAD_SAFE);

    if (call.result != PQ_SUCCESS) {
        pq_mu_builder_release(wrapper->builder);
    }
    wrapper->builder = NULL;

    if (call.result != PQ_SUCCESS) {
        pq_secure_wipe(mu, sizeof(mu));
        pq_raise_general_error(call.result);
    }

    VALUE result = pq_string_from_buffer(mu, sizeof(mu));
    pq_secure_wipe(mu, sizeof(mu));
    return result;
}

static VALUE pqcrypto__native_mldsa_mu_builder_release(VALUE self, VALUE builder_obj) {
    (void)self;
    mu_builder_wrapper_t *wrapper;
    TypedData_Get_Struct(builder_obj, mu_builder_wrapper_t, &mu_builder_data_type, wrapper);
    if (wrapper != NULL && wrapper->builder != NULL) {
        pq_mu_builder_release(wrapper->builder);
        wrapper->builder = NULL;
    }
    return Qnil;
}

static void *pq_sign_mu_nogvl(void *arg) {
    sign_mu_call_t *call = (sign_mu_call_t *)arg;
    call->result = pq_sign_mu(call->signature, &call->signature_len, call->mu, call->secret_key);
    return NULL;
}

static VALUE pqcrypto__native_mldsa_sign_mu(VALUE self, VALUE mu, VALUE secret_key) {
    (void)self;
    pq_validate_bytes_argument(mu, PQ_MLDSA_MUBYTES, "mu");
    pq_validate_bytes_argument(secret_key, PQ_MLDSA_SECRETKEYBYTES, "secret key");

    sign_mu_call_t call = {0};
    size_t secret_key_len = 0;
    size_t mu_len = 0;
    uint8_t *mu_copy = pq_copy_ruby_string(mu, &mu_len);
    uint8_t *sk_copy = pq_copy_ruby_string(secret_key, &secret_key_len);

    call.mu = mu_copy;
    call.secret_key = sk_copy;
    call.signature_len = PQ_MLDSA_BYTES;
    call.signature = pq_alloc_buffer(PQ_MLDSA_BYTES);

    rb_nogvl(pq_sign_mu_nogvl, &call, NULL, NULL, RB_NOGVL_OFFLOAD_SAFE);

    pq_wipe_and_free(mu_copy, mu_len);
    pq_wipe_and_free(sk_copy, secret_key_len);

    if (call.result != PQ_SUCCESS) {
        pq_free_buffer(call.signature);
        pq_raise_general_error(call.result);
    }

    VALUE result = pq_string_from_buffer(call.signature, call.signature_len);
    pq_free_buffer(call.signature);
    return result;
}

static void *pq_verify_mu_nogvl(void *arg) {
    verify_mu_call_t *call = (verify_mu_call_t *)arg;
    call->result = pq_verify_mu(call->signature, call->signature_len, call->mu, call->public_key);
    return NULL;
}

static VALUE pqcrypto__native_mldsa_verify_mu(VALUE self, VALUE mu, VALUE signature,
                                              VALUE public_key) {
    (void)self;
    StringValue(signature);
    pq_validate_bytes_argument(mu, PQ_MLDSA_MUBYTES, "mu");
    pq_validate_bytes_argument(public_key, PQ_MLDSA_PUBLICKEYBYTES, "public key");

    verify_mu_call_t call = {0};
    size_t public_key_len = 0;
    size_t signature_len = 0;
    size_t mu_len = 0;
    uint8_t *mu_copy = pq_copy_ruby_string(mu, &mu_len);
    uint8_t *pk_copy = pq_copy_ruby_string(public_key, &public_key_len);
    uint8_t *sig_copy = pq_copy_ruby_string(signature, &signature_len);

    call.mu = mu_copy;
    call.public_key = pk_copy;
    call.signature = sig_copy;
    call.signature_len = signature_len;

    rb_nogvl(pq_verify_mu_nogvl, &call, NULL, NULL, RB_NOGVL_OFFLOAD_SAFE);
    pq_wipe_and_free(mu_copy, mu_len);
    pq_free_buffer(pk_copy);
    pq_free_buffer(sig_copy);

    if (call.result == PQ_SUCCESS) {
        return Qtrue;
    }
    if (call.result == PQ_ERROR_VERIFY) {
        return Qfalse;
    }
    pq_raise_general_error(call.result);
}

static void define_constants(void) {
    rb_define_const(mPQCrypto, "ML_KEM_PUBLIC_KEY_BYTES", INT2NUM(PQ_MLKEM_PUBLICKEYBYTES));
    rb_define_const(mPQCrypto, "ML_KEM_SECRET_KEY_BYTES", INT2NUM(PQ_MLKEM_SECRETKEYBYTES));
    rb_define_const(mPQCrypto, "ML_KEM_CIPHERTEXT_BYTES", INT2NUM(PQ_MLKEM_CIPHERTEXTBYTES));
    rb_define_const(mPQCrypto, "ML_KEM_SHARED_SECRET_BYTES", INT2NUM(PQ_MLKEM_SHAREDSECRETBYTES));
    rb_define_const(mPQCrypto, "HYBRID_KEM_PUBLIC_KEY_BYTES", INT2NUM(PQ_HYBRID_PUBLICKEYBYTES));
    rb_define_const(mPQCrypto, "HYBRID_KEM_SECRET_KEY_BYTES", INT2NUM(PQ_HYBRID_SECRETKEYBYTES));
    rb_define_const(mPQCrypto, "HYBRID_KEM_CIPHERTEXT_BYTES", INT2NUM(PQ_HYBRID_CIPHERTEXTBYTES));
    rb_define_const(mPQCrypto, "HYBRID_KEM_SHARED_SECRET_BYTES",
                    INT2NUM(PQ_HYBRID_SHAREDSECRETBYTES));
    rb_define_const(mPQCrypto, "SIGN_PUBLIC_KEY_BYTES", INT2NUM(PQ_MLDSA_PUBLICKEYBYTES));
    rb_define_const(mPQCrypto, "SIGN_SECRET_KEY_BYTES", INT2NUM(PQ_MLDSA_SECRETKEYBYTES));
    rb_define_const(mPQCrypto, "SIGN_BYTES", INT2NUM(PQ_MLDSA_BYTES));
}

static VALUE pqcrypto_public_key_to_pqc_container_der(VALUE self, VALUE algorithm,
                                                      VALUE key_bytes) {
    (void)self;
    return pq_export_container_der(algorithm, key_bytes, pq_public_key_to_pqc_container_der);
}

static VALUE pqcrypto_public_key_to_pqc_container_pem(VALUE self, VALUE algorithm,
                                                      VALUE key_bytes) {
    (void)self;
    return pq_export_container_pem(algorithm, key_bytes, pq_public_key_to_pqc_container_pem);
}

static VALUE pqcrypto_secret_key_to_pqc_container_der(VALUE self, VALUE algorithm,
                                                      VALUE key_bytes) {
    (void)self;
    return pq_export_container_der(algorithm, key_bytes, pq_secret_key_to_pqc_container_der);
}

static VALUE pqcrypto_secret_key_to_pqc_container_pem(VALUE self, VALUE algorithm,
                                                      VALUE key_bytes) {
    (void)self;
    return pq_export_container_pem(algorithm, key_bytes, pq_secret_key_to_pqc_container_pem);
}

static VALUE pqcrypto_public_key_from_pqc_container_der(VALUE self, VALUE der) {
    (void)self;
    return pq_import_container_der(der, pq_public_key_from_pqc_container_der);
}

static VALUE pqcrypto_public_key_from_pqc_container_pem(VALUE self, VALUE pem) {
    (void)self;
    return pq_import_container_pem(pem, pq_public_key_from_pqc_container_pem);
}

static VALUE pqcrypto_secret_key_from_pqc_container_der(VALUE self, VALUE der) {
    (void)self;
    return pq_import_container_der(der, pq_secret_key_from_pqc_container_der);
}

static VALUE pqcrypto_secret_key_from_pqc_container_pem(VALUE self, VALUE pem) {
    (void)self;
    return pq_import_container_pem(pem, pq_secret_key_from_pqc_container_pem);
}

void Init_pqcrypto_secure(void) {
    mPQCrypto = rb_define_module("PQCrypto");
    ePQCryptoError = rb_define_class_under(mPQCrypto, "Error", rb_eStandardError);

    ePQCryptoVerificationError =
        rb_define_class_under(mPQCrypto, "VerificationError", ePQCryptoError);

    rb_define_module_function(mPQCrypto, "__test_ml_kem_keypair_from_seed",
                              pqcrypto__test_ml_kem_keypair_from_seed, 1);
    rb_define_module_function(mPQCrypto, "__test_ml_kem_encapsulate_from_seed",
                              pqcrypto__test_ml_kem_encapsulate_from_seed, 2);
    rb_define_module_function(mPQCrypto, "__test_sign_keypair_from_seed",
                              pqcrypto__test_sign_keypair_from_seed, 1);
    rb_define_module_function(mPQCrypto, "__test_sign_from_seed", pqcrypto__test_sign_from_seed, 3);
    rb_define_module_function(mPQCrypto, "ml_kem_keypair", pqcrypto_ml_kem_keypair, 0);
    rb_define_module_function(mPQCrypto, "ml_kem_encapsulate", pqcrypto_ml_kem_encapsulate, 1);
    rb_define_module_function(mPQCrypto, "ml_kem_decapsulate", pqcrypto_ml_kem_decapsulate, 2);
    rb_define_module_function(mPQCrypto, "hybrid_kem_keypair", pqcrypto_hybrid_kem_keypair, 0);
    rb_define_module_function(mPQCrypto, "hybrid_kem_encapsulate", pqcrypto_hybrid_kem_encapsulate,
                              1);
    rb_define_module_function(mPQCrypto, "hybrid_kem_decapsulate", pqcrypto_hybrid_kem_decapsulate,
                              2);
    rb_define_module_function(mPQCrypto, "sign_keypair", pqcrypto_sign_keypair, 0);
    rb_define_module_function(mPQCrypto, "sign", pqcrypto_sign, 2);
    rb_define_module_function(mPQCrypto, "verify", pqcrypto_verify, 3);
    rb_define_module_function(mPQCrypto, "ct_equals", pqcrypto_ct_equals, 2);
    rb_define_module_function(mPQCrypto, "secure_wipe", pqcrypto_secure_wipe, 1);
    rb_define_module_function(mPQCrypto, "version", pqcrypto_version, 0);
    rb_define_module_function(mPQCrypto, "public_key_to_pqc_container_der",
                              pqcrypto_public_key_to_pqc_container_der, 2);
    rb_define_module_function(mPQCrypto, "public_key_to_pqc_container_pem",
                              pqcrypto_public_key_to_pqc_container_pem, 2);
    rb_define_module_function(mPQCrypto, "secret_key_to_pqc_container_der",
                              pqcrypto_secret_key_to_pqc_container_der, 2);
    rb_define_module_function(mPQCrypto, "secret_key_to_pqc_container_pem",
                              pqcrypto_secret_key_to_pqc_container_pem, 2);
    rb_define_module_function(mPQCrypto, "public_key_from_pqc_container_der",
                              pqcrypto_public_key_from_pqc_container_der, 1);
    rb_define_module_function(mPQCrypto, "public_key_from_pqc_container_pem",
                              pqcrypto_public_key_from_pqc_container_pem, 1);
    rb_define_module_function(mPQCrypto, "secret_key_from_pqc_container_der",
                              pqcrypto_secret_key_from_pqc_container_der, 1);
    rb_define_module_function(mPQCrypto, "secret_key_from_pqc_container_pem",
                              pqcrypto_secret_key_from_pqc_container_pem, 1);
    rb_define_module_function(mPQCrypto, "_native_mldsa_extract_tr",
                              pqcrypto__native_mldsa_extract_tr, 1);
    rb_define_module_function(mPQCrypto, "_native_mldsa_compute_tr",
                              pqcrypto__native_mldsa_compute_tr, 1);
    rb_define_module_function(mPQCrypto, "_native_mldsa_mu_builder_new",
                              pqcrypto__native_mldsa_mu_builder_new, 2);
    rb_define_module_function(mPQCrypto, "_native_mldsa_mu_builder_update",
                              pqcrypto__native_mldsa_mu_builder_update, 2);
    rb_define_module_function(mPQCrypto, "_native_mldsa_mu_builder_finalize",
                              pqcrypto__native_mldsa_mu_builder_finalize, 1);
    rb_define_module_function(mPQCrypto, "_native_mldsa_mu_builder_release",
                              pqcrypto__native_mldsa_mu_builder_release, 1);
    rb_define_module_function(mPQCrypto, "_native_mldsa_sign_mu", pqcrypto__native_mldsa_sign_mu,
                              2);
    rb_define_module_function(mPQCrypto, "_native_mldsa_verify_mu",
                              pqcrypto__native_mldsa_verify_mu, 3);

    define_constants();
}
