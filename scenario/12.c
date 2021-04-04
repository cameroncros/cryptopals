#include "12.h"
#include "../cryptolib/base64.h"
#include "../cryptolib/crypto.h"
#include <string.h>


MKBUFFER(static_key, 16);

void oracle12(IMMUTABLE_BUFFER_PARAM(prepend),
              MUTABLE_BUFFER_PARAM(output)) {
    MKBUFFER_S(hidden, "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
                       "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
                       "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
                       "YnkK");
    MKBUFFER(decoded, 1000);
    base64_decode(hidden, hidden_size, decoded, &decoded_size);

    size_t buffer_size = prepend_size + decoded_size;
    unsigned char *buffer = (unsigned char*)calloc(1, buffer_size);
    if (prepend_size != 0) {
        memcpy(buffer, prepend, prepend_size);
    }
    memcpy(buffer + prepend_size, decoded, decoded_size);

    ECB_enc(buffer, buffer_size, static_key, output, output_size);

    free(buffer), buffer = NULL;
}