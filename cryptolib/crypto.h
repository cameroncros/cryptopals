#include <glob.h>
#include "buffer.h"
#include <stdbool.h>

#ifndef CRYPTOPALS_CRYPTO_H
#define CRYPTOPALS_CRYPTO_H

#define AES_BLOCK_SIZE 16
#define EBC 0
#define CBC 1

void init_crypto();

void gen_key(MUTABLE_BUFFER_PARAM(key));

void pkcs7_pad(IMMUTABLE_BUFFER_PARAM(block),
               MUTABLE_BUFFER_PARAM(padded));

bool is_pkcs7_padded(IMMUTABLE_BUFFER_PARAM(block));

void pkcs7_unpad(IMMUTABLE_BUFFER_PARAM(block),
                 MUTABLE_BUFFER_PARAM(unpadded));

void ECB_enc(IMMUTABLE_BUFFER_PARAM(raw_bytes),
             const unsigned char *key,
             MUTABLE_BUFFER_PARAM(decrypted_bytes));

void ECB_dec(IMMUTABLE_BUFFER_PARAM(raw_bytes),
             const unsigned char *key,
             MUTABLE_BUFFER_PARAM(decrypted_bytes));

void CBC_enc(IMMUTABLE_BUFFER_PARAM(raw_bytes),
             const unsigned char key[16], const unsigned char iv[16],
             MUTABLE_BUFFER_PARAM(decrypted_bytes));

void CBC_dec(IMMUTABLE_BUFFER_PARAM(raw_bytes),
             const unsigned char key[16], const unsigned char iv[16],
             MUTABLE_BUFFER_PARAM(decrypted_bytes));

#endif //CRYPTOPALS_CRYPTO_H
