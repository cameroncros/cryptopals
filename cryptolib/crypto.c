#include <assert.h>
#include <string.h>
#include <openssl/ossl_typ.h>
#include <openssl/evp.h>
#include "crypto.h"

#define AES_BLOCK_SIZE 16

void pkcs7_padd(const char *block, size_t block_size,
                char *padded, size_t padded_size) {
    assert(padded_size > block_size);
    assert(padded_size - block_size < 255);

    char padded_length = (char) (padded_size - block_size);
    memcpy(padded, block, block_size);
    memset((void *) (padded + block_size), padded_length, padded_length);
}

void ECB(const char *raw_bytes, size_t raw_bytes_size, const unsigned char *key,
         char *decrypted_bytes, size_t *decrypted_bytes_size, int encrypt) {
    size_t result_size = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_reset(ctx);
    EVP_CipherInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL, encrypt);
    EVP_CipherInit_ex(ctx, NULL, NULL, key, NULL, encrypt);

    char temp_buffer[AES_BLOCK_SIZE + EVP_MAX_BLOCK_LENGTH] = {};
    for (size_t processed_bytes = 0; processed_bytes < raw_bytes_size; processed_bytes += AES_BLOCK_SIZE) {
        int temp_buffer_size = sizeof(temp_buffer);

        size_t remaining_bytes = raw_bytes_size - processed_bytes;
        if (remaining_bytes > AES_BLOCK_SIZE) {
            remaining_bytes = AES_BLOCK_SIZE;
        }
        EVP_CipherUpdate(ctx, (unsigned char *) &temp_buffer, &temp_buffer_size,
                         (unsigned char *) raw_bytes + processed_bytes,
                         remaining_bytes);
        assert(result_size + temp_buffer_size < *decrypted_bytes_size);
        memcpy(decrypted_bytes + result_size, temp_buffer, temp_buffer_size);
        result_size += temp_buffer_size;
    }
    int temp_buffer_size = sizeof(temp_buffer);
    EVP_CipherFinal_ex(ctx, (unsigned char *) &temp_buffer, &temp_buffer_size);
    assert(result_size + temp_buffer_size < *decrypted_bytes_size);
    memcpy(decrypted_bytes + result_size, temp_buffer, temp_buffer_size);
    result_size += temp_buffer_size;
    *decrypted_bytes_size = result_size;

    EVP_CIPHER_CTX_free(ctx);
}