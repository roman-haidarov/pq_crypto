#include <ruby.h>
#include <ruby/thread.h>
#include <ruby/encoding.h>
#include <stdlib.h>
#include <string.h>

#include "pqcrypto_secure.h"

typedef struct {
    pq_session_t *session;
} ruby_pq_session_t;

typedef struct {
    int result;
    uint8_t *public_key;
    uint8_t *secret_key;
} kem_keypair_call_t;

typedef struct {
    int result;
    uint8_t *ciphertext;
    uint8_t *shared_secret;
    const uint8_t *public_key;
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
} sign_keypair_call_t;

typedef struct {
    int result;
    uint8_t *signature;
    size_t signature_len;
    uint8_t *message;
    size_t message_len;
    const uint8_t *secret_key;
} sign_call_t;

typedef struct {
    int result;
    const uint8_t *signature;
    size_t signature_len;
    uint8_t *message;
    size_t message_len;
    const uint8_t *public_key;
} verify_call_t;

typedef struct {
    int result;
    pq_session_t *session;
    const uint8_t *shared_secret;
    int initiator;
} session_init_call_t;

typedef struct {
    int result;
    pq_session_t *session;
    uint8_t *output;
    size_t output_len;
    const uint8_t *input;
    size_t input_len;
    const uint8_t *aad;
    size_t aad_len;
} session_crypto_call_t;

typedef struct {
    int result;
    uint8_t *output;
    size_t output_len;
    uint8_t *message;
    size_t message_len;
    const uint8_t *public_key;
} seal_call_t;

typedef struct {
    int result;
    uint8_t *output;
    size_t output_len;
    const uint8_t *input;
    size_t input_len;
    const uint8_t *secret_key;
} unseal_call_t;

typedef struct {
    int result;
    uint8_t *output;
    size_t output_len;
    uint8_t *message;
    size_t message_len;
    const uint8_t *kem_public_key;
    const uint8_t *sign_secret_key;
} sign_and_seal_call_t;

typedef struct {
    int result;
    uint8_t *output;
    size_t output_len;
    const uint8_t *input;
    size_t input_len;
    const uint8_t *kem_secret_key;
    const uint8_t *sign_public_key;
} unseal_and_verify_call_t;

static VALUE mPQCrypto;
static VALUE ePQCryptoError;
static VALUE ePQCryptoVerificationError;
static VALUE ePQCryptoDecryptionError;
static VALUE cPQCryptoSession;

static const char *pq_algorithm_symbol_to_cstr(VALUE algorithm) {
    ID id;
    if (SYMBOL_P(algorithm)) {
        id = SYM2ID(algorithm);
    } else {
        VALUE str = StringValue(algorithm);
        id = rb_intern_str(str);
    }
    if (id == rb_intern("ml_kem_768") || id == rb_intern("ml_kem_768_x25519"))
        return "ml_kem_768_x25519";
    if (id == rb_intern("ml_dsa_65"))
        return "ml_dsa_65";
    rb_raise(rb_eArgError, "Unsupported serialization algorithm");
}

static VALUE pq_algorithm_cstr_to_symbol(const char *algorithm) {
    if (strcmp(algorithm, "ml_kem_768_x25519") == 0)
        return ID2SYM(rb_intern("ml_kem_768_x25519"));
    if (strcmp(algorithm, "ml_dsa_65") == 0)
        return ID2SYM(rb_intern("ml_dsa_65"));
    rb_raise(rb_eArgError, "Unsupported serialization algorithm");
}

static void *pq_kem_keypair_nogvl(void *arg) {
    kem_keypair_call_t *call = (kem_keypair_call_t *)arg;
    call->result = pq_kem_keypair(call->public_key, call->secret_key);
    return NULL;
}

static void *pq_kem_encapsulate_nogvl(void *arg) {
    kem_encapsulate_call_t *call = (kem_encapsulate_call_t *)arg;
    call->result = pq_kem_encapsulate(call->ciphertext, call->shared_secret, call->public_key);
    return NULL;
}

static void *pq_kem_decapsulate_nogvl(void *arg) {
    kem_decapsulate_call_t *call = (kem_decapsulate_call_t *)arg;
    call->result = pq_kem_decapsulate(call->shared_secret, call->ciphertext, call->secret_key);
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

static void *pq_verify_nogvl(void *arg) {
    verify_call_t *call = (verify_call_t *)arg;
    call->result = pq_verify(call->signature, call->signature_len, call->message, call->message_len,
                             call->public_key);
    return NULL;
}

static void *pq_session_init_nogvl(void *arg) {
    session_init_call_t *call = (session_init_call_t *)arg;
    call->result = pq_session_init(call->session, call->shared_secret, call->initiator);
    return NULL;
}

static void *pq_session_encrypt_nogvl(void *arg) {
    session_crypto_call_t *call = (session_crypto_call_t *)arg;
    call->result = pq_session_encrypt(call->session, call->output, &call->output_len, call->input,
                                      call->input_len, call->aad, call->aad_len);
    return NULL;
}

static void *pq_session_decrypt_nogvl(void *arg) {
    session_crypto_call_t *call = (session_crypto_call_t *)arg;
    call->result = pq_session_decrypt(call->session, call->output, &call->output_len, call->input,
                                      call->input_len, call->aad, call->aad_len);
    return NULL;
}

static void *pq_seal_nogvl(void *arg) {
    seal_call_t *call = (seal_call_t *)arg;
    call->result = pq_seal(call->output, &call->output_len, call->message, call->message_len,
                           call->public_key);
    return NULL;
}

static void *pq_unseal_nogvl(void *arg) {
    unseal_call_t *call = (unseal_call_t *)arg;
    call->result =
        pq_unseal(call->output, &call->output_len, call->input, call->input_len, call->secret_key);
    return NULL;
}

static void *pq_sign_and_seal_nogvl(void *arg) {
    sign_and_seal_call_t *call = (sign_and_seal_call_t *)arg;
    call->result = pq_sign_and_seal(call->output, &call->output_len, call->message,
                                    call->message_len, call->kem_public_key, call->sign_secret_key);
    return NULL;
}

static void *pq_unseal_and_verify_nogvl(void *arg) {
    unseal_and_verify_call_t *call = (unseal_and_verify_call_t *)arg;
    call->result =
        pq_unseal_and_verify(call->output, &call->output_len, call->input, call->input_len,
                             call->kem_secret_key, call->sign_public_key);
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

static uint8_t *pq_copy_optional_string(VALUE value, size_t *len_out) {
    if (NIL_P(value)) {
        *len_out = 0;
        return NULL;
    }

    return pq_copy_ruby_string(value, len_out);
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
    case PQ_ERROR_AUTH:
        rb_raise(ePQCryptoError, "Verification failed");
        break;
    case PQ_ERROR_RANDOM:
        rb_raise(ePQCryptoError, "Random number generation failed");
        break;
    case PQ_ERROR_KDF:
        rb_raise(ePQCryptoError, "Key derivation failed");
        break;
    case PQ_ERROR_ENCRYPT:
        rb_raise(ePQCryptoError, "Encryption failed");
        break;
    case PQ_ERROR_DECRYPT:
        rb_raise(ePQCryptoError, "Decryption failed");
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

__attribute__((noreturn)) static void pq_raise_verification_error(int err) {
    switch (err) {
    case PQ_ERROR_VERIFY:
    case PQ_ERROR_AUTH:
        rb_raise(ePQCryptoVerificationError, "Verification failed");
        break;
    default:
        pq_raise_general_error(err);
    }
}

__attribute__((noreturn)) static void pq_raise_decryption_error(int err) {
    switch (err) {
    case PQ_ERROR_BUFFER:
        rb_raise(ePQCryptoDecryptionError, "Ciphertext too short");
        break;
    case PQ_ERROR_AUTH:
    case PQ_ERROR_DECRYPT:
        rb_raise(ePQCryptoDecryptionError, "Decryption failed");
        break;
    default:
        pq_raise_general_error(err);
    }
}

__attribute__((noreturn)) static void pq_raise_unseal_and_verify_error(int err) {
    switch (err) {
    case PQ_ERROR_VERIFY:
        rb_raise(ePQCryptoVerificationError, "Verification failed");
        break;
    case PQ_ERROR_AUTH:
    case PQ_ERROR_DECRYPT:
        rb_raise(ePQCryptoDecryptionError, "Decryption failed");
        break;
    case PQ_ERROR_BUFFER:
        rb_raise(rb_eArgError, "Invalid signed sealed payload length");
        break;
    default:
        pq_raise_general_error(err);
    }
}

static void pqcrypto_session_free(void *ptr) {
    ruby_pq_session_t *wrapper = (ruby_pq_session_t *)ptr;
    if (!wrapper) {
        return;
    }

    if (wrapper->session) {
        pq_session_destroy(wrapper->session);
        free(wrapper->session);
        wrapper->session = NULL;
    }

    xfree(wrapper);
}

static size_t pqcrypto_session_memsize(const void *ptr) {
    const ruby_pq_session_t *wrapper = (const ruby_pq_session_t *)ptr;
    return sizeof(*wrapper) + (wrapper && wrapper->session ? sizeof(*wrapper->session) : 0);
}

static const rb_data_type_t pqcrypto_session_type = {
    .wrap_struct_name = "PQCrypto::Session",
    .function =
        {
            .dmark = NULL,
            .dfree = pqcrypto_session_free,
            .dsize = pqcrypto_session_memsize,
            .dcompact = NULL,
        },
    .parent = NULL,
    .data = NULL,
    .flags = RUBY_TYPED_FREE_IMMEDIATELY,
};

static VALUE pqcrypto_session_alloc(VALUE klass) {
    ruby_pq_session_t *wrapper;
    VALUE obj = TypedData_Make_Struct(klass, ruby_pq_session_t, &pqcrypto_session_type, wrapper);
    wrapper->session = NULL;
    return obj;
}

static VALUE pqcrypto_session_new_from_ptr(pq_session_t *session) {
    ruby_pq_session_t *wrapper;
    VALUE obj =
        TypedData_Make_Struct(cPQCryptoSession, ruby_pq_session_t, &pqcrypto_session_type, wrapper);
    wrapper->session = session;
    return obj;
}

static ruby_pq_session_t *pqcrypto_get_session(VALUE self) {
    ruby_pq_session_t *wrapper;
    TypedData_Get_Struct(self, ruby_pq_session_t, &pqcrypto_session_type, wrapper);

    if (!wrapper || !wrapper->session) {
        rb_raise(ePQCryptoError, "Session is not initialized");
    }

    return wrapper;
}

static VALUE pqcrypto_kem_keypair(VALUE self) {
    (void)self;

    kem_keypair_call_t call = {0};
    call.public_key = pq_alloc_buffer(PQ_HYBRID_PUBLICKEYBYTES);
    call.secret_key = pq_alloc_buffer(PQ_HYBRID_SECRETKEYBYTES);

    rb_thread_call_without_gvl(pq_kem_keypair_nogvl, &call, NULL, NULL);

    if (call.result != PQ_SUCCESS) {
        pq_wipe_and_free(call.secret_key, PQ_HYBRID_SECRETKEYBYTES);
        free(call.public_key);
        pq_raise_general_error(call.result);
    }

    VALUE result = rb_ary_new2(2);
    rb_ary_push(result, pq_string_from_buffer(call.public_key, PQ_HYBRID_PUBLICKEYBYTES));
    rb_ary_push(result, pq_string_from_buffer(call.secret_key, PQ_HYBRID_SECRETKEYBYTES));

    free(call.public_key);
    pq_wipe_and_free(call.secret_key, PQ_HYBRID_SECRETKEYBYTES);
    return result;
}

static VALUE pqcrypto_kem_encapsulate(VALUE self, VALUE public_key) {
    (void)self;
    StringValue(public_key);

    if ((size_t)RSTRING_LEN(public_key) != PQ_HYBRID_PUBLICKEYBYTES) {
        rb_raise(rb_eArgError, "Invalid public key length");
    }

    kem_encapsulate_call_t call = {0};
    call.public_key = (const uint8_t *)RSTRING_PTR(public_key);
    call.ciphertext = pq_alloc_buffer(PQ_HYBRID_CIPHERTEXTBYTES);
    call.shared_secret = pq_alloc_buffer(PQ_HYBRID_SHAREDSECRETBYTES);

    rb_thread_call_without_gvl(pq_kem_encapsulate_nogvl, &call, NULL, NULL);

    if (call.result != PQ_SUCCESS) {
        pq_wipe_and_free(call.shared_secret, PQ_HYBRID_SHAREDSECRETBYTES);
        free(call.ciphertext);
        pq_raise_general_error(call.result);
    }

    VALUE result = rb_ary_new2(2);
    rb_ary_push(result, pq_string_from_buffer(call.ciphertext, PQ_HYBRID_CIPHERTEXTBYTES));
    rb_ary_push(result, pq_string_from_buffer(call.shared_secret, PQ_HYBRID_SHAREDSECRETBYTES));

    free(call.ciphertext);
    pq_wipe_and_free(call.shared_secret, PQ_HYBRID_SHAREDSECRETBYTES);
    return result;
}

static VALUE pqcrypto_kem_decapsulate(VALUE self, VALUE ciphertext, VALUE secret_key) {
    (void)self;
    StringValue(ciphertext);
    StringValue(secret_key);

    if ((size_t)RSTRING_LEN(ciphertext) != PQ_HYBRID_CIPHERTEXTBYTES) {
        rb_raise(rb_eArgError, "Invalid ciphertext length");
    }
    if ((size_t)RSTRING_LEN(secret_key) != PQ_HYBRID_SECRETKEYBYTES) {
        rb_raise(rb_eArgError, "Invalid secret key length");
    }

    kem_decapsulate_call_t call = {0};
    call.ciphertext = (const uint8_t *)RSTRING_PTR(ciphertext);
    call.secret_key = (const uint8_t *)RSTRING_PTR(secret_key);
    call.shared_secret = pq_alloc_buffer(PQ_HYBRID_SHAREDSECRETBYTES);

    rb_thread_call_without_gvl(pq_kem_decapsulate_nogvl, &call, NULL, NULL);

    if (call.result != PQ_SUCCESS) {
        pq_wipe_and_free(call.shared_secret, PQ_HYBRID_SHAREDSECRETBYTES);
        pq_raise_general_error(call.result);
    }

    VALUE result = pq_string_from_buffer(call.shared_secret, PQ_HYBRID_SHAREDSECRETBYTES);
    pq_wipe_and_free(call.shared_secret, PQ_HYBRID_SHAREDSECRETBYTES);
    return result;
}

static VALUE pqcrypto_sign_keypair(VALUE self) {
    (void)self;

    sign_keypair_call_t call = {0};
    call.public_key = pq_alloc_buffer(PQ_MLDSA_PUBLICKEYBYTES);
    call.secret_key = pq_alloc_buffer(PQ_MLDSA_SECRETKEYBYTES);

    rb_thread_call_without_gvl(pq_sign_keypair_nogvl, &call, NULL, NULL);

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

static VALUE pqcrypto_sign(VALUE self, VALUE message, VALUE secret_key) {
    (void)self;
    StringValue(secret_key);

    if ((size_t)RSTRING_LEN(secret_key) != PQ_MLDSA_SECRETKEYBYTES) {
        rb_raise(rb_eArgError, "Invalid secret key length");
    }

    sign_call_t call = {0};
    call.secret_key = (const uint8_t *)RSTRING_PTR(secret_key);
    call.signature_len = PQ_MLDSA_BYTES;
    call.signature = pq_alloc_buffer(PQ_MLDSA_BYTES);
    call.message = pq_copy_ruby_string(message, &call.message_len);

    rb_thread_call_without_gvl(pq_sign_nogvl, &call, NULL, NULL);

    pq_wipe_and_free(call.message, call.message_len);

    if (call.result != PQ_SUCCESS) {
        pq_wipe_and_free(call.signature, PQ_MLDSA_BYTES);
        pq_raise_general_error(call.result);
    }

    VALUE result = pq_string_from_buffer(call.signature, call.signature_len);
    free(call.signature);
    return result;
}

static VALUE pqcrypto_verify(VALUE self, VALUE message, VALUE signature, VALUE public_key) {
    (void)self;
    StringValue(signature);
    StringValue(public_key);

    if ((size_t)RSTRING_LEN(public_key) != PQ_MLDSA_PUBLICKEYBYTES) {
        rb_raise(rb_eArgError, "Invalid public key length");
    }

    verify_call_t call = {0};
    call.public_key = (const uint8_t *)RSTRING_PTR(public_key);
    call.signature = (const uint8_t *)RSTRING_PTR(signature);
    call.signature_len = (size_t)RSTRING_LEN(signature);
    call.message = pq_copy_ruby_string(message, &call.message_len);

    rb_thread_call_without_gvl(pq_verify_nogvl, &call, NULL, NULL);

    pq_wipe_and_free(call.message, call.message_len);

    if (call.result != PQ_SUCCESS) {
        pq_raise_verification_error(call.result);
    }

    return Qtrue;
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

static VALUE pqcrypto_public_key_pem(VALUE self, VALUE public_key) {
    (void)self;
    StringValue(public_key);

    if ((size_t)RSTRING_LEN(public_key) != PQ_HYBRID_PUBLICKEYBYTES) {
        rb_raise(rb_eArgError, "Invalid public key length");
    }

    char *pem = NULL;
    size_t pem_len = 0;
    int ret = pq_public_key_pem(&pem, &pem_len, (const uint8_t *)RSTRING_PTR(public_key),
                                (size_t)RSTRING_LEN(public_key));
    if (ret != PQ_SUCCESS) {
        if (pem) {
            pq_secure_wipe(pem, pem_len);
            free(pem);
        }
        pq_raise_general_error(ret);
    }

    VALUE result = rb_enc_str_new(pem, (long)pem_len, rb_utf8_encoding());
    pq_secure_wipe(pem, pem_len);
    free(pem);
    return result;
}

static VALUE pqcrypto_session_initialize(int argc, VALUE *argv, VALUE self) {
    VALUE shared_secret;
    VALUE initiator = Qfalse;
    ruby_pq_session_t *wrapper;
    session_init_call_t call = {0};

    rb_scan_args(argc, argv, "11", &shared_secret, &initiator);
    StringValue(shared_secret);

    if ((size_t)RSTRING_LEN(shared_secret) != PQ_HYBRID_SHAREDSECRETBYTES) {
        rb_raise(rb_eArgError, "Invalid shared secret length");
    }

    TypedData_Get_Struct(self, ruby_pq_session_t, &pqcrypto_session_type, wrapper);
    if (wrapper->session) {
        pq_session_destroy(wrapper->session);
        free(wrapper->session);
        wrapper->session = NULL;
    }

    wrapper->session = (pq_session_t *)pq_alloc_buffer(sizeof(*wrapper->session));
    memset(wrapper->session, 0, sizeof(*wrapper->session));

    call.session = wrapper->session;
    call.shared_secret = (const uint8_t *)RSTRING_PTR(shared_secret);
    call.initiator = RTEST(initiator) ? 1 : 0;

    rb_thread_call_without_gvl(pq_session_init_nogvl, &call, NULL, NULL);

    if (call.result != PQ_SUCCESS) {
        pq_session_destroy(wrapper->session);
        free(wrapper->session);
        wrapper->session = NULL;
        pq_raise_general_error(call.result);
    }

    return self;
}

static VALUE pqcrypto_session_encrypt(int argc, VALUE *argv, VALUE self) {
    VALUE plaintext;
    VALUE options = Qnil;
    VALUE aad_value = Qnil;
    ruby_pq_session_t *wrapper = pqcrypto_get_session(self);
    session_crypto_call_t call = {0};
    size_t out_capacity;

    rb_scan_args(argc, argv, "11", &plaintext, &options);
    if (!NIL_P(options)) {
        Check_Type(options, T_HASH);
        aad_value = rb_hash_aref(options, ID2SYM(rb_intern("aad")));
    }

    call.input = pq_copy_ruby_string(plaintext, &call.input_len);
    call.aad = pq_copy_optional_string(aad_value, &call.aad_len);
    out_capacity = pq_session_encrypt_len(call.input_len);
    call.output = pq_alloc_buffer(out_capacity);
    call.output_len = out_capacity;
    call.session = wrapper->session;

    rb_thread_call_without_gvl(pq_session_encrypt_nogvl, &call, NULL, NULL);

    pq_wipe_and_free((uint8_t *)call.input, call.input_len);
    pq_wipe_and_free((uint8_t *)call.aad, call.aad_len);

    if (call.result != PQ_SUCCESS) {
        pq_wipe_and_free(call.output, out_capacity);
        pq_raise_general_error(call.result);
    }

    VALUE result = pq_string_from_buffer(call.output, call.output_len);
    free(call.output);
    return result;
}

static VALUE pqcrypto_session_decrypt(int argc, VALUE *argv, VALUE self) {
    VALUE encrypted_data;
    VALUE options = Qnil;
    VALUE aad_value = Qnil;
    ruby_pq_session_t *wrapper = pqcrypto_get_session(self);
    session_crypto_call_t call = {0};
    size_t out_capacity;

    rb_scan_args(argc, argv, "11", &encrypted_data, &options);
    if (!NIL_P(options)) {
        Check_Type(options, T_HASH);
        aad_value = rb_hash_aref(options, ID2SYM(rb_intern("aad")));
    }

    StringValue(encrypted_data);
    if ((size_t)RSTRING_LEN(encrypted_data) < PQ_SESSION_OVERHEAD) {
        rb_raise(ePQCryptoDecryptionError, "Ciphertext too short");
    }

    call.input = pq_copy_ruby_string(encrypted_data, &call.input_len);
    call.aad = pq_copy_optional_string(aad_value, &call.aad_len);
    out_capacity = call.input_len - PQ_SESSION_OVERHEAD;
    call.output = pq_alloc_buffer(out_capacity == 0 ? 1 : out_capacity);
    call.output_len = out_capacity;
    call.session = wrapper->session;

    rb_thread_call_without_gvl(pq_session_decrypt_nogvl, &call, NULL, NULL);

    pq_wipe_and_free((uint8_t *)call.input, call.input_len);
    pq_wipe_and_free((uint8_t *)call.aad, call.aad_len);

    if (call.result != PQ_SUCCESS) {
        pq_wipe_and_free(call.output, out_capacity == 0 ? 1 : out_capacity);
        pq_raise_decryption_error(call.result);
    }

    VALUE result = pq_string_from_buffer(call.output, call.output_len);
    pq_wipe_and_free(call.output, out_capacity == 0 ? 1 : out_capacity);
    return result;
}

static VALUE pqcrypto_establish_session(VALUE self, VALUE public_key) {
    (void)self;
    StringValue(public_key);

    if ((size_t)RSTRING_LEN(public_key) != PQ_HYBRID_PUBLICKEYBYTES) {
        rb_raise(rb_eArgError, "Invalid public key length");
    }

    kem_encapsulate_call_t call = {0};
    call.public_key = (const uint8_t *)RSTRING_PTR(public_key);
    call.ciphertext = pq_alloc_buffer(PQ_HYBRID_CIPHERTEXTBYTES);
    call.shared_secret = pq_alloc_buffer(PQ_HYBRID_SHAREDSECRETBYTES);

    rb_thread_call_without_gvl(pq_kem_encapsulate_nogvl, &call, NULL, NULL);

    if (call.result != PQ_SUCCESS) {
        pq_wipe_and_free(call.shared_secret, PQ_HYBRID_SHAREDSECRETBYTES);
        free(call.ciphertext);
        pq_raise_general_error(call.result);
    }

    pq_session_t *session = (pq_session_t *)pq_alloc_buffer(sizeof(*session));
    memset(session, 0, sizeof(*session));

    session_init_call_t init_call = {0};
    init_call.session = session;
    init_call.shared_secret = call.shared_secret;
    init_call.initiator = 1;

    rb_thread_call_without_gvl(pq_session_init_nogvl, &init_call, NULL, NULL);
    pq_wipe_and_free(call.shared_secret, PQ_HYBRID_SHAREDSECRETBYTES);

    if (init_call.result != PQ_SUCCESS) {
        pq_session_destroy(session);
        free(session);
        free(call.ciphertext);
        pq_raise_general_error(init_call.result);
    }

    VALUE result = rb_ary_new2(2);
    rb_ary_push(result, pqcrypto_session_new_from_ptr(session));
    rb_ary_push(result, pq_string_from_buffer(call.ciphertext, PQ_HYBRID_CIPHERTEXTBYTES));
    free(call.ciphertext);
    return result;
}

static VALUE pqcrypto_accept_session(VALUE self, VALUE ciphertext, VALUE secret_key) {
    (void)self;
    StringValue(ciphertext);
    StringValue(secret_key);

    if ((size_t)RSTRING_LEN(ciphertext) != PQ_HYBRID_CIPHERTEXTBYTES) {
        rb_raise(rb_eArgError, "Invalid ciphertext length");
    }
    if ((size_t)RSTRING_LEN(secret_key) != PQ_HYBRID_SECRETKEYBYTES) {
        rb_raise(rb_eArgError, "Invalid secret key length");
    }

    kem_decapsulate_call_t call = {0};
    call.ciphertext = (const uint8_t *)RSTRING_PTR(ciphertext);
    call.secret_key = (const uint8_t *)RSTRING_PTR(secret_key);
    call.shared_secret = pq_alloc_buffer(PQ_HYBRID_SHAREDSECRETBYTES);

    rb_thread_call_without_gvl(pq_kem_decapsulate_nogvl, &call, NULL, NULL);

    if (call.result != PQ_SUCCESS) {
        pq_wipe_and_free(call.shared_secret, PQ_HYBRID_SHAREDSECRETBYTES);
        pq_raise_general_error(call.result);
    }

    pq_session_t *session = (pq_session_t *)pq_alloc_buffer(sizeof(*session));
    memset(session, 0, sizeof(*session));

    session_init_call_t init_call = {0};
    init_call.session = session;
    init_call.shared_secret = call.shared_secret;
    init_call.initiator = 0;

    rb_thread_call_without_gvl(pq_session_init_nogvl, &init_call, NULL, NULL);
    pq_wipe_and_free(call.shared_secret, PQ_HYBRID_SHAREDSECRETBYTES);

    if (init_call.result != PQ_SUCCESS) {
        pq_session_destroy(session);
        free(session);
        pq_raise_general_error(init_call.result);
    }

    return pqcrypto_session_new_from_ptr(session);
}

static VALUE pqcrypto_seal(VALUE self, VALUE message, VALUE public_key) {
    (void)self;
    StringValue(public_key);

    if ((size_t)RSTRING_LEN(public_key) != PQ_HYBRID_PUBLICKEYBYTES) {
        rb_raise(rb_eArgError, "Invalid public key length");
    }

    seal_call_t call = {0};
    call.public_key = (const uint8_t *)RSTRING_PTR(public_key);
    call.message = pq_copy_ruby_string(message, &call.message_len);
    call.output_len = PQ_HYBRID_CIPHERTEXTBYTES + pq_session_encrypt_len(call.message_len);
    call.output = pq_alloc_buffer(call.output_len);

    rb_thread_call_without_gvl(pq_seal_nogvl, &call, NULL, NULL);

    pq_wipe_and_free(call.message, call.message_len);

    if (call.result != PQ_SUCCESS) {
        pq_wipe_and_free(call.output, call.output_len);
        pq_raise_general_error(call.result);
    }

    VALUE result = pq_string_from_buffer(call.output, call.output_len);
    free(call.output);
    return result;
}

static VALUE pqcrypto_unseal(VALUE self, VALUE sealed_data, VALUE secret_key) {
    (void)self;
    StringValue(sealed_data);
    StringValue(secret_key);

    if ((size_t)RSTRING_LEN(secret_key) != PQ_HYBRID_SECRETKEYBYTES) {
        rb_raise(rb_eArgError, "Invalid secret key length");
    }
    if ((size_t)RSTRING_LEN(sealed_data) < (PQ_HYBRID_CIPHERTEXTBYTES + PQ_SESSION_OVERHEAD)) {
        rb_raise(rb_eArgError, "Invalid sealed data length");
    }

    unseal_call_t call = {0};
    call.secret_key = (const uint8_t *)RSTRING_PTR(secret_key);
    call.input = (const uint8_t *)RSTRING_PTR(sealed_data);
    call.input_len = (size_t)RSTRING_LEN(sealed_data);
    call.output_len = call.input_len - PQ_HYBRID_CIPHERTEXTBYTES - PQ_SESSION_OVERHEAD;
    call.output = pq_alloc_buffer(call.output_len == 0 ? 1 : call.output_len);

    rb_thread_call_without_gvl(pq_unseal_nogvl, &call, NULL, NULL);

    if (call.result != PQ_SUCCESS) {
        pq_wipe_and_free(call.output, call.output_len == 0 ? 1 : call.output_len);
        pq_raise_decryption_error(call.result);
    }

    VALUE result = pq_string_from_buffer(call.output, call.output_len);
    pq_wipe_and_free(call.output, call.output_len == 0 ? 1 : call.output_len);
    return result;
}

static VALUE pqcrypto_sign_and_seal(VALUE self, VALUE message, VALUE kem_public_key,
                                    VALUE sign_secret_key) {
    (void)self;
    StringValue(kem_public_key);
    StringValue(sign_secret_key);

    if ((size_t)RSTRING_LEN(kem_public_key) != PQ_HYBRID_PUBLICKEYBYTES) {
        rb_raise(rb_eArgError, "Invalid public key length");
    }
    if ((size_t)RSTRING_LEN(sign_secret_key) != PQ_MLDSA_SECRETKEYBYTES) {
        rb_raise(rb_eArgError, "Invalid secret key length");
    }

    sign_and_seal_call_t call = {0};
    call.message = pq_copy_ruby_string(message, &call.message_len);
    call.kem_public_key = (const uint8_t *)RSTRING_PTR(kem_public_key);
    call.sign_secret_key = (const uint8_t *)RSTRING_PTR(sign_secret_key);
    call.output_len = 6 + 4 + PQ_MLDSA_BYTES + PQ_HYBRID_CIPHERTEXTBYTES +
                      pq_session_encrypt_len(call.message_len);
    call.output = pq_alloc_buffer(call.output_len);

    rb_thread_call_without_gvl(pq_sign_and_seal_nogvl, &call, NULL, NULL);

    pq_wipe_and_free(call.message, call.message_len);

    if (call.result != PQ_SUCCESS) {
        pq_wipe_and_free(call.output, call.output_len);
        pq_raise_general_error(call.result);
    }

    VALUE result = pq_string_from_buffer(call.output, call.output_len);
    free(call.output);
    return result;
}

static VALUE pqcrypto_unseal_and_verify(VALUE self, VALUE input, VALUE kem_secret_key,
                                        VALUE sign_public_key) {
    (void)self;
    StringValue(input);
    StringValue(kem_secret_key);
    StringValue(sign_public_key);

    if ((size_t)RSTRING_LEN(kem_secret_key) != PQ_HYBRID_SECRETKEYBYTES) {
        rb_raise(rb_eArgError, "Invalid secret key length");
    }
    if ((size_t)RSTRING_LEN(sign_public_key) != PQ_MLDSA_PUBLICKEYBYTES) {
        rb_raise(rb_eArgError, "Invalid public key length");
    }
    if ((size_t)RSTRING_LEN(input) < (6 + 4 + PQ_HYBRID_CIPHERTEXTBYTES + PQ_SESSION_OVERHEAD)) {
        rb_raise(rb_eArgError, "Invalid signed sealed payload length");
    }

    unseal_and_verify_call_t call = {0};
    call.input = (const uint8_t *)RSTRING_PTR(input);
    call.input_len = (size_t)RSTRING_LEN(input);
    call.kem_secret_key = (const uint8_t *)RSTRING_PTR(kem_secret_key);
    call.sign_public_key = (const uint8_t *)RSTRING_PTR(sign_public_key);
    call.output_len = call.input_len;
    call.output = pq_alloc_buffer(call.output_len == 0 ? 1 : call.output_len);

    rb_thread_call_without_gvl(pq_unseal_and_verify_nogvl, &call, NULL, NULL);

    if (call.result != PQ_SUCCESS) {
        pq_wipe_and_free(call.output, call.output_len == 0 ? 1 : call.output_len);
        pq_raise_unseal_and_verify_error(call.result);
    }

    VALUE result = pq_string_from_buffer(call.output, call.output_len);
    pq_wipe_and_free(call.output, call.output_len == 0 ? 1 : call.output_len);
    return result;
}

static void define_constants(void) {
    rb_define_const(mPQCrypto, "KEM_PUBLIC_KEY_BYTES", INT2NUM(PQ_HYBRID_PUBLICKEYBYTES));
    rb_define_const(mPQCrypto, "KEM_SECRET_KEY_BYTES", INT2NUM(PQ_HYBRID_SECRETKEYBYTES));
    rb_define_const(mPQCrypto, "KEM_CIPHERTEXT_BYTES", INT2NUM(PQ_HYBRID_CIPHERTEXTBYTES));
    rb_define_const(mPQCrypto, "KEM_SHARED_SECRET_BYTES", INT2NUM(PQ_HYBRID_SHAREDSECRETBYTES));

    rb_define_const(mPQCrypto, "SIGN_PUBLIC_KEY_BYTES", INT2NUM(PQ_MLDSA_PUBLICKEYBYTES));
    rb_define_const(mPQCrypto, "SIGN_SECRET_KEY_BYTES", INT2NUM(PQ_MLDSA_SECRETKEYBYTES));
    rb_define_const(mPQCrypto, "SIGN_BYTES", INT2NUM(PQ_MLDSA_BYTES));

    rb_define_const(mPQCrypto, "SESSION_OVERHEAD", INT2NUM(PQ_SESSION_OVERHEAD));
}

static VALUE pqcrypto_public_key_to_spki_der(VALUE self, VALUE algorithm, VALUE key_bytes) {
    uint8_t *out = NULL;
    size_t out_len = 0;
    VALUE result;
    StringValue(key_bytes);
    int ret = pq_public_key_to_spki_der(&out, &out_len, (const uint8_t *)RSTRING_PTR(key_bytes),
                                        (size_t)RSTRING_LEN(key_bytes),
                                        pq_algorithm_symbol_to_cstr(algorithm));
    if (ret != PQ_SUCCESS)
        pq_raise_general_error(ret);
    result = pq_string_from_buffer(out, out_len);
    pq_secure_wipe(out, out_len);
    free(out);
    return result;
}

static VALUE pqcrypto_public_key_to_spki_pem(VALUE self, VALUE algorithm, VALUE key_bytes) {
    char *out = NULL;
    size_t out_len = 0;
    VALUE result;
    StringValue(key_bytes);
    int ret = pq_public_key_to_spki_pem(&out, &out_len, (const uint8_t *)RSTRING_PTR(key_bytes),
                                        (size_t)RSTRING_LEN(key_bytes),
                                        pq_algorithm_symbol_to_cstr(algorithm));
    if (ret != PQ_SUCCESS)
        pq_raise_general_error(ret);
    result = rb_utf8_str_new(out, (long)out_len);
    pq_secure_wipe(out, out_len);
    free(out);
    return result;
}

static VALUE pqcrypto_secret_key_to_pkcs8_der(VALUE self, VALUE algorithm, VALUE key_bytes) {
    uint8_t *out = NULL;
    size_t out_len = 0;
    VALUE result;
    StringValue(key_bytes);
    int ret = pq_secret_key_to_pkcs8_der(&out, &out_len, (const uint8_t *)RSTRING_PTR(key_bytes),
                                         (size_t)RSTRING_LEN(key_bytes),
                                         pq_algorithm_symbol_to_cstr(algorithm));
    if (ret != PQ_SUCCESS)
        pq_raise_general_error(ret);
    result = pq_string_from_buffer(out, out_len);
    pq_secure_wipe(out, out_len);
    free(out);
    return result;
}

static VALUE pqcrypto_secret_key_to_pkcs8_pem(VALUE self, VALUE algorithm, VALUE key_bytes) {
    char *out = NULL;
    size_t out_len = 0;
    VALUE result;
    StringValue(key_bytes);
    int ret = pq_secret_key_to_pkcs8_pem(&out, &out_len, (const uint8_t *)RSTRING_PTR(key_bytes),
                                         (size_t)RSTRING_LEN(key_bytes),
                                         pq_algorithm_symbol_to_cstr(algorithm));
    if (ret != PQ_SUCCESS)
        pq_raise_general_error(ret);
    result = rb_utf8_str_new(out, (long)out_len);
    pq_secure_wipe(out, out_len);
    free(out);
    return result;
}

static VALUE pqcrypto_public_key_from_spki_der(VALUE self, VALUE der) {
    char *algorithm = NULL;
    uint8_t *key = NULL;
    size_t key_len = 0;
    VALUE ary;
    StringValue(der);
    int ret = pq_public_key_from_spki_der(
        &algorithm, &key, &key_len, (const uint8_t *)RSTRING_PTR(der), (size_t)RSTRING_LEN(der));
    if (ret != PQ_SUCCESS)
        pq_raise_general_error(ret);
    ary = rb_ary_new_capa(2);
    rb_ary_push(ary, pq_algorithm_cstr_to_symbol(algorithm));
    rb_ary_push(ary, pq_string_from_buffer(key, key_len));
    free(algorithm);
    pq_secure_wipe(key, key_len);
    free(key);
    return ary;
}

static VALUE pqcrypto_public_key_from_spki_pem(VALUE self, VALUE pem) {
    char *algorithm = NULL;
    uint8_t *key = NULL;
    size_t key_len = 0;
    VALUE ary;
    StringValue(pem);
    int ret = pq_public_key_from_spki_pem(&algorithm, &key, &key_len, RSTRING_PTR(pem),
                                          (size_t)RSTRING_LEN(pem));
    if (ret != PQ_SUCCESS)
        pq_raise_general_error(ret);
    ary = rb_ary_new_capa(2);
    rb_ary_push(ary, pq_algorithm_cstr_to_symbol(algorithm));
    rb_ary_push(ary, pq_string_from_buffer(key, key_len));
    free(algorithm);
    pq_secure_wipe(key, key_len);
    free(key);
    return ary;
}

static VALUE pqcrypto_secret_key_from_pkcs8_der(VALUE self, VALUE der) {
    char *algorithm = NULL;
    uint8_t *key = NULL;
    size_t key_len = 0;
    VALUE ary;
    StringValue(der);
    int ret = pq_secret_key_from_pkcs8_der(
        &algorithm, &key, &key_len, (const uint8_t *)RSTRING_PTR(der), (size_t)RSTRING_LEN(der));
    if (ret != PQ_SUCCESS)
        pq_raise_general_error(ret);
    ary = rb_ary_new_capa(2);
    rb_ary_push(ary, pq_algorithm_cstr_to_symbol(algorithm));
    rb_ary_push(ary, pq_string_from_buffer(key, key_len));
    free(algorithm);
    pq_secure_wipe(key, key_len);
    free(key);
    return ary;
}

static VALUE pqcrypto_secret_key_from_pkcs8_pem(VALUE self, VALUE pem) {
    char *algorithm = NULL;
    uint8_t *key = NULL;
    size_t key_len = 0;
    VALUE ary;
    StringValue(pem);
    int ret = pq_secret_key_from_pkcs8_pem(&algorithm, &key, &key_len, RSTRING_PTR(pem),
                                           (size_t)RSTRING_LEN(pem));
    if (ret != PQ_SUCCESS)
        pq_raise_general_error(ret);
    ary = rb_ary_new_capa(2);
    rb_ary_push(ary, pq_algorithm_cstr_to_symbol(algorithm));
    rb_ary_push(ary, pq_string_from_buffer(key, key_len));
    free(algorithm);
    pq_secure_wipe(key, key_len);
    free(key);
    return ary;
}

void Init_pqcrypto_secure(void) {
    mPQCrypto = rb_define_module("PQCrypto");
    ePQCryptoError = rb_define_class_under(mPQCrypto, "Error", rb_eStandardError);
    ePQCryptoVerificationError =
        rb_define_class_under(mPQCrypto, "VerificationError", ePQCryptoError);
    ePQCryptoDecryptionError = rb_define_class_under(mPQCrypto, "DecryptionError", ePQCryptoError);

    cPQCryptoSession = rb_define_class_under(mPQCrypto, "Session", rb_cObject);
    rb_define_alloc_func(cPQCryptoSession, pqcrypto_session_alloc);
    rb_define_method(cPQCryptoSession, "initialize", pqcrypto_session_initialize, -1);
    rb_define_method(cPQCryptoSession, "encrypt", pqcrypto_session_encrypt, -1);
    rb_define_method(cPQCryptoSession, "decrypt", pqcrypto_session_decrypt, -1);

    rb_define_module_function(mPQCrypto, "kem_keypair", pqcrypto_kem_keypair, 0);
    rb_define_module_function(mPQCrypto, "kem_encapsulate", pqcrypto_kem_encapsulate, 1);
    rb_define_module_function(mPQCrypto, "kem_decapsulate", pqcrypto_kem_decapsulate, 2);
    rb_define_module_function(mPQCrypto, "sign_keypair", pqcrypto_sign_keypair, 0);
    rb_define_module_function(mPQCrypto, "sign", pqcrypto_sign, 2);
    rb_define_module_function(mPQCrypto, "verify", pqcrypto_verify, 3);
    rb_define_module_function(mPQCrypto, "secure_wipe", pqcrypto_secure_wipe, 1);
    rb_define_module_function(mPQCrypto, "version", pqcrypto_version, 0);
    rb_define_module_function(mPQCrypto, "public_key_pem", pqcrypto_public_key_pem, 1);
    rb_define_module_function(mPQCrypto, "public_key_to_spki_der", pqcrypto_public_key_to_spki_der,
                              2);
    rb_define_module_function(mPQCrypto, "public_key_to_spki_pem", pqcrypto_public_key_to_spki_pem,
                              2);
    rb_define_module_function(mPQCrypto, "secret_key_to_pkcs8_der",
                              pqcrypto_secret_key_to_pkcs8_der, 2);
    rb_define_module_function(mPQCrypto, "secret_key_to_pkcs8_pem",
                              pqcrypto_secret_key_to_pkcs8_pem, 2);
    rb_define_module_function(mPQCrypto, "public_key_from_spki_der",
                              pqcrypto_public_key_from_spki_der, 1);
    rb_define_module_function(mPQCrypto, "public_key_from_spki_pem",
                              pqcrypto_public_key_from_spki_pem, 1);
    rb_define_module_function(mPQCrypto, "secret_key_from_pkcs8_der",
                              pqcrypto_secret_key_from_pkcs8_der, 1);
    rb_define_module_function(mPQCrypto, "secret_key_from_pkcs8_pem",
                              pqcrypto_secret_key_from_pkcs8_pem, 1);
    rb_define_module_function(mPQCrypto, "establish_session", pqcrypto_establish_session, 1);
    rb_define_module_function(mPQCrypto, "accept_session", pqcrypto_accept_session, 2);
    rb_define_module_function(mPQCrypto, "seal", pqcrypto_seal, 2);
    rb_define_module_function(mPQCrypto, "unseal", pqcrypto_unseal, 2);
    rb_define_module_function(mPQCrypto, "sign_and_seal", pqcrypto_sign_and_seal, 3);
    rb_define_module_function(mPQCrypto, "unseal_and_verify", pqcrypto_unseal_and_verify, 3);

    define_constants();
}
