#ifndef BASE64_H
#define BASE64_H

#include <stdlib.h>
#include "buffer.h"

void base64_encode(IMMUTABLE_BUFFER_PARAM(input),
                   MUTABLE_BUFFER_PARAM(output));

void base64_decode(IMMUTABLE_BUFFER_PARAM(input),
                   MUTABLE_BUFFER_PARAM(output));

#endif  // BASE64_H