#ifndef UNTITLED_HEX_H
#define UNTITLED_HEX_H

#include <stdlib.h>
#include "buffer.h"

void from_hex(IMMUTABLE_BUFFER_PARAM(hexstr),
              MUTABLE_BUFFER_PARAM(output_buffer));

void to_hex(IMMUTABLE_BUFFER_PARAM(str), MUTABLE_BUFFER_PARAM(output_hex));

#endif //UNTITLED_HEX_H
