#include <string.h>
#include <assert.h>
#include <stdio.h>
#include "buffer.h"

void from_hex(IMMUTABLE_BUFFER_PARAM(hexstr),
              MUTABLE_BUFFER_PARAM(output_buffer)) {
    assert(hexstr_size % 2 == 0);
    assert(hexstr_size % 2 <= *output_buffer_size);

    for (size_t count = 0; count < hexstr_size / 2; count++) {
        sscanf(&hexstr[count * 2], "%2hhx", &output_buffer[count]);
    }
    *output_buffer_size = hexstr_size / 2;
}

void to_hex(IMMUTABLE_BUFFER_PARAM(str), MUTABLE_BUFFER_PARAM(output_hex)) {
    assert(*output_hex_size > str_size * 2);
    assert(str);
    assert(output_hex);

    for (int i = 0; i < str_size; i++) {
        sprintf(&output_hex[i * 2], "%02hhx", str[i]);
    }
    output_hex[str_size * 2] = '\0';
    *output_hex_size = str_size * 2;
}
