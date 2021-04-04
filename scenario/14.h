//
// Created by cameron on 4/4/21.
//

#ifndef CRYPTOPALS_14_H
#define CRYPTOPALS_14_H

#include "12.h"
#include "../cryptolib/buffer.h"
// As chosen by a random pair of dice :D
#define  INITIAL_OFFSET 13

void oracle14(IMMUTABLE_BUFFER_PARAM(prepend),
              MUTABLE_BUFFER_PARAM(output));

#endif //CRYPTOPALS_14_H
