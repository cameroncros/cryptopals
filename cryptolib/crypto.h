#include <glob.h>

#ifndef CRYPTOPALS_CRYPTO_H
#define CRYPTOPALS_CRYPTO_H

void pkcs7_padd(const unsigned char *block, size_t block_size,
                char unsigned *padded, size_t padded_size);

void ECB(const unsigned char *raw_bytes, size_t raw_bytes_size, const unsigned char *key,
         char unsigned *decrypted_bytes, size_t *decrypted_bytes_size, int encrypt);

void CBC_enc(const unsigned char *raw_bytes, size_t raw_bytes_size,
        const unsigned char key[16], const unsigned char iv[16],
        unsigned char *decrypted_bytes, size_t *decrypted_bytes_size);
void CBC_dec(const unsigned char *raw_bytes, size_t raw_bytes_size,
        const unsigned char key[16], const unsigned char iv[16],
        unsigned char *decrypted_bytes, size_t *decrypted_bytes_size);

#endif //CRYPTOPALS_CRYPTO_H
