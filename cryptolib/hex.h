#ifndef UNTITLED_HEX_H
#define UNTITLED_HEX_H

#include <stdlib.h>

void from_hex(const char *hexstr, size_t hexstr_length,
              char *output_buffer, size_t *output_buffer_size);

void to_hex(const char *str, size_t str_size,
            char *output_hex, size_t *output_hex_length);

#endif //UNTITLED_HEX_H
