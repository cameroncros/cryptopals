//
// Created by cameron on 4/4/21.
//

#ifndef CRYPTOPALS_11_H
#define CRYPTOPALS_11_H

#include "../cryptolib/buffer.h"

int random_encrypt(IMMUTABLE_BUFFER_PARAM(buffer),
                   MUTABLE_BUFFER_PARAM(output));

#endif //CRYPTOPALS_11_H
