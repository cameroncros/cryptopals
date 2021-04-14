#include <assert.h>
#include <string.h>
#include "16.h"
#include "../cryptolib/buffer.h"

void oracle16(IMMUTABLE_BUFFER_PARAM(buffer), MUTABLE_BUFFER_PARAM(output))
{
    assert(strchr((const char*)buffer, ';') == NULL);
    assert(strchr((const char*)buffer, '=') == NULL);

    MKBUFFER_S(prepend, "comment1=cooking%20MCs;userdata=")
    MKBUFFER_S(postpend, ";comment2=%20like%20a%20pound%20of%20bacon")
}