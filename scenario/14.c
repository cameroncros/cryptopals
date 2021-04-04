//
// Created by cameron on 4/4/21.
//

#include "14.h"
#include "../cryptolib/base64.h"
#include "../cryptolib/crypto.h"
#include <string.h>

void oracle14(IMMUTABLE_BUFFER_PARAM(prepend),
              MUTABLE_BUFFER_PARAM(output)) {
    MKBUFFER(offset, INITIAL_OFFSET);
    gen_key(offset, &offset_size);  // This does diverge from the given challenge, the initial offset does not have to be random data every cycle, but its easy enough anyway

    MKBUFFER_S(hidden, "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
                       "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
                       "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
                       "YnkK");
    MKBUFFER(decoded, 1000);
    base64_decode(hidden, hidden_size, decoded, &decoded_size);

    size_t buffer_size = INITIAL_OFFSET + prepend_size + decoded_size;
    unsigned char *buffer = (unsigned char*)calloc(1, buffer_size);
    memcpy(buffer, offset, INITIAL_OFFSET);
    memcpy(buffer + INITIAL_OFFSET, prepend, prepend_size);
    memcpy(buffer + INITIAL_OFFSET + prepend_size, decoded, decoded_size);

    ECB_enc(buffer, buffer_size, static_key, output, output_size);

    free(buffer), buffer = NULL;
}