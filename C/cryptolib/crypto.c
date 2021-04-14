#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <openssl/ossl_typ.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "crypto.h"
#include "buffer.h"
#include "errno.h"
#include "xor.h"

#define AssertAESSuccess(f) { \
    int retval = f; \
    if (retval != 1) { \
        printf("%s(): %s:%i: Failed with %i, SSL Error[%lu]: %s\n", \
                __PRETTY_FUNCTION__, __FILE__, __LINE__, retval, \
                ERR_get_error(), ERR_error_string(ERR_get_error(), NULL)); \
        fflush(stdout); \
        assert(retval == 1 && errno == 0); \
    } \
} \


void init_crypto() {
    srand(time(NULL));
}


void gen_key(MUTABLE_BUFFER_PARAM(key)) {
    for (int i = 0; i < *key_size; i++) {
        key[i] = (char) rand();
    }
}

void pkcs7_pad(IMMUTABLE_BUFFER_PARAM(block),
               MUTABLE_BUFFER_PARAM(padded)) {
    assert(*padded_size > block_size);
    assert(*padded_size - block_size < 255);

    char padded_length = (char) (*padded_size - block_size);
    memcpy(padded, block, block_size);
    memset((void *) (padded + block_size), padded_length, padded_length);
}

bool is_pkcs7_padded(IMMUTABLE_BUFFER_PARAM(block)) {
    unsigned char padded_num = block[block_size - 1];
    for (size_t i = block_size - 1; i > block_size - 1 - padded_num; i--) {
        if (block[i] != padded_num) {
            return false;
        }
    }
    return true;
}

void pkcs7_unpad(IMMUTABLE_BUFFER_PARAM(block),
                 MUTABLE_BUFFER_PARAM(unpadded)) {
    assert(*unpadded_size >= block_size);
    unsigned char padded_num = block[block_size - 1];
    for (size_t i = block_size - 1; i > block_size - 1 - padded_num; i--) {
        if (block[i] != padded_num) {
            padded_num = 0;
            break;
        }
    }

    *unpadded_size = block_size - padded_num;
    memcpy(unpadded, block, *unpadded_size);
}

void ECB_enc(IMMUTABLE_BUFFER_PARAM(raw_bytes),
             const unsigned char *key,
             MUTABLE_BUFFER_PARAM(decrypted_bytes)) {
    size_t padded_size = 0;
    unsigned char *padded = NULL;
    if (raw_bytes_size % AES_BLOCK_SIZE != 0) {
        padded_size = (raw_bytes_size / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;
        padded = calloc(1, padded_size);
        pkcs7_pad(raw_bytes, raw_bytes_size, padded, &padded_size);
    } else {
        padded_size = raw_bytes_size;
        padded = calloc(1, padded_size);
        memcpy(padded, raw_bytes, raw_bytes_size);
    }

    size_t result_size = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    AssertAESSuccess(EVP_CIPHER_CTX_reset(ctx));
    AssertAESSuccess(EVP_CipherInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL, 1));
    AssertAESSuccess(EVP_CIPHER_CTX_set_padding(ctx, 0));
    AssertAESSuccess(EVP_CipherInit_ex(ctx, NULL, NULL, key, NULL, 1));

    MKBUFFER(temp_buffer, AES_BLOCK_SIZE + EVP_MAX_BLOCK_LENGTH);
    for (size_t processed_bytes = 0; processed_bytes < padded_size; processed_bytes += AES_BLOCK_SIZE) {
        temp_buffer_size = sizeof(temp_buffer);

        size_t remaining_bytes = padded_size - processed_bytes;
        if (remaining_bytes > AES_BLOCK_SIZE) {
            remaining_bytes = AES_BLOCK_SIZE;
        }
        AssertAESSuccess(EVP_CipherUpdate(ctx, (unsigned char *) &temp_buffer, (int *) &temp_buffer_size,
                                          (unsigned char *) padded + processed_bytes,
                                          remaining_bytes));
        assert(result_size + temp_buffer_size <= *decrypted_bytes_size);
        memcpy(decrypted_bytes + result_size, temp_buffer, temp_buffer_size);
        result_size += temp_buffer_size;
    }
    temp_buffer_size = sizeof(temp_buffer);
    AssertAESSuccess(EVP_CipherFinal_ex(ctx, (unsigned char *) &temp_buffer, (int *) &temp_buffer_size));
    assert(result_size + temp_buffer_size <= *decrypted_bytes_size);
    memcpy(decrypted_bytes + result_size, temp_buffer, temp_buffer_size);
    result_size += temp_buffer_size;
    *decrypted_bytes_size = result_size;

    EVP_CIPHER_CTX_free(ctx);
    free(padded);
}

void ECB_dec(IMMUTABLE_BUFFER_PARAM(raw_bytes),
             const unsigned char *key,
             MUTABLE_BUFFER_PARAM(unpadded_bytes)) {
    size_t result_size = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    AssertAESSuccess(EVP_CIPHER_CTX_reset(ctx));
    AssertAESSuccess(EVP_CipherInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL, 0));
    AssertAESSuccess(EVP_CIPHER_CTX_set_padding(ctx, 0));
    AssertAESSuccess(EVP_CipherInit_ex(ctx, NULL, NULL, key, NULL, 0));
    print_buffer(raw_bytes, raw_bytes_size);

    size_t decrypted_bytes_size = raw_bytes_size;
    unsigned char *decrypted_bytes = (unsigned char *) calloc(1, decrypted_bytes_size);

    MKBUFFER(temp_buffer, AES_BLOCK_SIZE + EVP_MAX_BLOCK_LENGTH);
    for (size_t processed_bytes = 0; processed_bytes < raw_bytes_size; processed_bytes += AES_BLOCK_SIZE) {
        temp_buffer_size = sizeof(temp_buffer);

        size_t remaining_bytes = raw_bytes_size - processed_bytes;
        if (remaining_bytes > AES_BLOCK_SIZE) {
            remaining_bytes = AES_BLOCK_SIZE;
        }
        AssertAESSuccess(EVP_CipherUpdate(ctx, (unsigned char *) &temp_buffer, (int *) &temp_buffer_size,
                                          (unsigned char *) raw_bytes + processed_bytes,
                                          remaining_bytes));
        assert(result_size + temp_buffer_size <= decrypted_bytes_size);
        memcpy(decrypted_bytes + result_size, temp_buffer, temp_buffer_size);
        result_size += temp_buffer_size;
    }
    temp_buffer_size = sizeof(temp_buffer);
    AssertAESSuccess(EVP_CipherFinal_ex(ctx, (unsigned char *) &temp_buffer, (int *) &temp_buffer_size));
    assert(result_size + temp_buffer_size <= decrypted_bytes_size);
    memcpy(decrypted_bytes + result_size, temp_buffer, temp_buffer_size);
    result_size += temp_buffer_size;
    decrypted_bytes_size = result_size;

    pkcs7_unpad(decrypted_bytes, decrypted_bytes_size, unpadded_bytes, unpadded_bytes_size);
    free(decrypted_bytes), decrypted_bytes = NULL;

    EVP_CIPHER_CTX_free(ctx);
}

void CBC_enc(IMMUTABLE_BUFFER_PARAM(raw_bytes),
             const unsigned char key[AES_BLOCK_SIZE], const unsigned char iv[AES_BLOCK_SIZE],
             MUTABLE_BUFFER_PARAM(decrypted_bytes)) {
    size_t result_size = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_reset(ctx);
    AssertAESSuccess(EVP_CipherInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, iv, 1));
    AssertAESSuccess(EVP_CipherInit_ex(ctx, NULL, NULL, key, NULL, 1));

    MKBUFFER(temp_buffer, AES_BLOCK_SIZE);
    MKBUFFER(last_block, AES_BLOCK_SIZE);
    MKBUFFER(input_block, AES_BLOCK_SIZE);
    memcpy(last_block, iv, 16);

    for (size_t processed_bytes = 0; processed_bytes < raw_bytes_size; processed_bytes += AES_BLOCK_SIZE) {
        temp_buffer_size = sizeof(temp_buffer);

        size_t remaining_bytes = raw_bytes_size - processed_bytes;
        if (remaining_bytes > AES_BLOCK_SIZE) {
            remaining_bytes = AES_BLOCK_SIZE;
        }
        xor_bytes(last_block, last_block_size,
                  raw_bytes + processed_bytes, remaining_bytes,
                  input_block, &input_block_size);

        AssertAESSuccess(EVP_CipherUpdate(ctx, (unsigned char *) &temp_buffer, (int *) &temp_buffer_size,
                                          input_block,
                                          remaining_bytes));
        assert(result_size + temp_buffer_size < *decrypted_bytes_size);
        memcpy(decrypted_bytes + result_size, temp_buffer, temp_buffer_size);
        result_size += temp_buffer_size;

        memset(last_block, 0, last_block_size);
        memcpy(last_block, temp_buffer, temp_buffer_size);
    }
    temp_buffer_size = sizeof(temp_buffer);
    AssertAESSuccess(EVP_CipherFinal_ex(ctx, (unsigned char *) &temp_buffer, (int *) &temp_buffer_size));
    assert(result_size + temp_buffer_size < *decrypted_bytes_size);
    memcpy(decrypted_bytes + result_size, temp_buffer, temp_buffer_size);
    *decrypted_bytes_size = result_size;

    EVP_CIPHER_CTX_free(ctx);
}


void
CBC_dec(IMMUTABLE_BUFFER_PARAM(raw_bytes),
        const unsigned char key[AES_BLOCK_SIZE], const unsigned char iv[AES_BLOCK_SIZE],
        MUTABLE_BUFFER_PARAM(decrypted_bytes)) {

    unsigned char *decoded_buffer = calloc(1, raw_bytes_size);
    size_t decoded_buffer_size = raw_bytes_size;
    ECB_dec(raw_bytes, raw_bytes_size, key, decoded_buffer, &decoded_buffer_size);

    size_t first_block_size = AES_BLOCK_SIZE;
    xor_bytes(iv, AES_BLOCK_SIZE,
              decoded_buffer, AES_BLOCK_SIZE,
              decrypted_bytes, &first_block_size);
    assert(first_block_size == AES_BLOCK_SIZE);

    *decrypted_bytes_size = decoded_buffer_size - AES_BLOCK_SIZE;
    xor_bytes(decoded_buffer + AES_BLOCK_SIZE, *decrypted_bytes_size,
              raw_bytes, *decrypted_bytes_size,
              decrypted_bytes + AES_BLOCK_SIZE, decrypted_bytes_size);
    *decrypted_bytes_size += AES_BLOCK_SIZE;

    printf("%.*s\n", (int) *decrypted_bytes_size, decrypted_bytes);
    free(decoded_buffer), decoded_buffer = NULL;
}
