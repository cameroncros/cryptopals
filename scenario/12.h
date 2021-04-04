//
// Created by cameron on 4/4/21.
//

#ifndef CRYPTOPALS_12_H
#define CRYPTOPALS_12_H

#include "../cryptolib/buffer.h"

extern unsigned char static_key[16];
extern size_t static_key_size;


typedef void (*oracle_fn)(IMMUTABLE_BUFFER_PARAM(prepend), MUTABLE_BUFFER_PARAM(output));

void oracle12(IMMUTABLE_BUFFER_PARAM(prepend),
              MUTABLE_BUFFER_PARAM(output));
#endif //CRYPTOPALS_12_H
