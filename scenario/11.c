//
// Created by cameron on 4/4/21.
//

#include <stdlib.h>
#include <string.h>
#include "11.h"
#include "../cryptolib/crypto.h"


int random_encrypt(IMMUTABLE_BUFFER_PARAM(buffer),
                   MUTABLE_BUFFER_PARAM(output)) {
    MKBUFFER(key, 16);
    gen_key(key, &key_size);

    MKBUFFER(iv, 16);
    gen_key(iv, &iv_size);

    MKBUFFER(prepend, 10);
    gen_key(prepend, &prepend_size);
    prepend_size = 5 + rand() % 5;
    MKBUFFER(append, 10);
    gen_key(append, &append_size);
    append_size = 5 + rand() % 5;

    size_t temp_size = buffer_size + prepend_size + append_size;
    unsigned char *temp = (unsigned char *) calloc(1, temp_size);
    memcpy(temp, prepend, prepend_size);
    memcpy(temp + prepend_size, buffer, buffer_size);
    memcpy(temp + prepend_size + buffer_size, append, append_size);

    int mode = rand() % 2;
    if (mode == CBC) {
        CBC_enc(temp, temp_size, key, iv, output, output_size);
    } else if (mode == EBC) {
        ECB_enc(temp, temp_size, key, output, output_size);
    }
    free(temp), temp = NULL;
    return mode;
}