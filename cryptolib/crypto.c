#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <openssl/ossl_typ.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "crypto.h"
#include "buffer.h"
#include "errno.h"
#include "xor.h"

#define AES_BLOCK_SIZE 16

#define AssertAESSuccess(f) { \
    int retval = f; \
    if (retval != 1) { \
        printf("%s:%i: Failed with %i, SSL Error[%lu]: %s\n", __FILE__, __LINE__, retval, ERR_get_error(), ERR_error_string(ERR_get_error(), NULL)); \
        fflush(stdout); \
        assert(retval == 1 && errno == 0); \
    } \
} \

void pkcs7_padd(const unsigned char *block, size_t block_size,
                unsigned char *padded, size_t padded_size) {
    assert(padded_size > block_size);
    assert(padded_size - block_size < 255);

    char padded_length = (char) (padded_size - block_size);
    memcpy(padded, block, block_size);
    memset((void *) (padded + block_size), padded_length, padded_length);
}

void ECB(const unsigned char *raw_bytes, size_t raw_bytes_size, const unsigned char *key,
         unsigned char *decrypted_bytes, size_t *decrypted_bytes_size, int encrypt) {
    size_t result_size = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    AssertAESSuccess(EVP_CIPHER_CTX_reset(ctx));
    AssertAESSuccess(EVP_CipherInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL, encrypt));
    AssertAESSuccess(EVP_CipherInit_ex(ctx, NULL, NULL, key, NULL, encrypt));

    MKBUFFER(temp_buffer, AES_BLOCK_SIZE + EVP_MAX_BLOCK_LENGTH);
    for (size_t processed_bytes = 0; processed_bytes < raw_bytes_size; processed_bytes += AES_BLOCK_SIZE) {
        temp_buffer_size = sizeof(temp_buffer);

        size_t remaining_bytes = raw_bytes_size - processed_bytes;
        if (remaining_bytes > AES_BLOCK_SIZE) {
            remaining_bytes = AES_BLOCK_SIZE;
        }
        AssertAESSuccess(EVP_CipherUpdate(ctx, (unsigned char *) &temp_buffer, (int*)&temp_buffer_size,
                         (unsigned char *) raw_bytes + processed_bytes,
                         remaining_bytes));
        assert(result_size + temp_buffer_size < *decrypted_bytes_size);
        memcpy(decrypted_bytes + result_size, temp_buffer, temp_buffer_size);
        result_size += temp_buffer_size;
    }
    temp_buffer_size = sizeof(temp_buffer);
    AssertAESSuccess(EVP_CipherFinal_ex(ctx, (unsigned char *) &temp_buffer, (int*)&temp_buffer_size));
    assert(result_size + temp_buffer_size < *decrypted_bytes_size);
    memcpy(decrypted_bytes + result_size, temp_buffer, temp_buffer_size);
    result_size += temp_buffer_size;
    *decrypted_bytes_size = result_size;

    EVP_CIPHER_CTX_free(ctx);
}

void
CBC_enc(const unsigned char *raw_bytes, size_t raw_bytes_size, const unsigned char key[16], const unsigned char iv[16],
        unsigned char *decrypted_bytes, size_t *decrypted_bytes_size) {
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
CBC_dec(const unsigned char *raw_bytes, size_t raw_bytes_size,
        const unsigned char key[AES_BLOCK_SIZE], const unsigned char iv[AES_BLOCK_SIZE],
        unsigned char *decrypted_bytes, size_t *decrypted_bytes_size) {

    unsigned char *decoded_buffer = calloc(1, raw_bytes_size);
    size_t decoded_buffer_size = raw_bytes_size;
    ECB(raw_bytes, raw_bytes_size, key, decoded_buffer, &decoded_buffer_size, 0);

    print_buffer(decoded_buffer, decoded_buffer_size);
    size_t first_block_size = AES_BLOCK_SIZE;
    xor_bytes(iv, AES_BLOCK_SIZE,
            decoded_buffer, AES_BLOCK_SIZE,
            decrypted_bytes, &first_block_size);
    assert(first_block_size == AES_BLOCK_SIZE);

    *decrypted_bytes_size = decoded_buffer_size - AES_BLOCK_SIZE;
    xor_bytes(decoded_buffer + AES_BLOCK_SIZE, *decrypted_bytes_size,
              raw_bytes, *decrypted_bytes_size,
              decrypted_bytes + AES_BLOCK_SIZE, decrypted_bytes_size);
    *decrypted_bytes += AES_BLOCK_SIZE;

//    assert(*decrypted_bytes_size == raw_bytes_size);

//    for (size_t i = 0; i < decoded_buffer_size; i += AES_BLOCK_SIZE) {
//        size_t block_size = (decoded_buffer_size - i);
//        if (block_size >= AES_BLOCK_SIZE)
//        {
//            block_size = AES_BLOCK_SIZE;
//        }
//        xor_bytes(decoded_buffer + AES_BLOCK_SIZE + i, block_size,
//                  raw_bytes + i, block_size,
//                  decrypted_bytes + AES_BLOCK_SIZE + i, &block_size);
//        *decrypted_bytes_size += block_size;
//    }
    printf("%.*s\n", (int)*decrypted_bytes_size, decrypted_bytes);
    free(decoded_buffer), decoded_buffer = NULL;
}