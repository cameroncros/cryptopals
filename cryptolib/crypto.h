#include <glob.h>

#ifndef CRYPTOPALS_CRYPTO_H
#define CRYPTOPALS_CRYPTO_H

#define AES_BLOCK_SIZE 16
#define EBC 0
#define CBC 1

void init_crypto();

void gen_key(unsigned char *key, size_t key_size);

void pkcs7_pad(const unsigned char *block, size_t block_size,
               char unsigned *padded, size_t padded_size);

void pkcs7_unpad(const unsigned char *block, size_t block_size,
                 char unsigned *unpadded, size_t *unpadded_size);

void ECB_enc(const unsigned char *raw_bytes, size_t raw_bytes_size,
             const unsigned char *key,
             char unsigned *decrypted_bytes, size_t *decrypted_bytes_size);

void ECB_dec(const unsigned char *raw_bytes, size_t raw_bytes_size,
             const unsigned char *key,
             char unsigned *decrypted_bytes, size_t *decrypted_bytes_size);

void CBC_enc(const unsigned char *raw_bytes, size_t raw_bytes_size,
             const unsigned char key[16], const unsigned char iv[16],
             unsigned char *decrypted_bytes, size_t *decrypted_bytes_size);

void CBC_dec(const unsigned char *raw_bytes, size_t raw_bytes_size,
             const unsigned char key[16], const unsigned char iv[16],
             unsigned char *decrypted_bytes, size_t *decrypted_bytes_size);

#endif //CRYPTOPALS_CRYPTO_H
