#include <glob.h>

#ifndef CRYPTOPALS_CRYPTO_H
#define CRYPTOPALS_CRYPTO_H

void pkcs7_padd(const char *block, size_t block_size,
                char *padded, size_t padded_size);
void ECB(const char *raw_bytes, size_t raw_bytes_size, const unsigned char *key,
         char *decrypted_bytes, size_t *decrypted_bytes_size, int encrypt);

void CBC(const char *raw_bytes, size_t raw_bytes_size, const unsigned char *key, const unsigned char *iv,
         char *decrypted_bytes, size_t *decrypted_bytes_size, int encrypt);
#endif //CRYPTOPALS_CRYPTO_H
