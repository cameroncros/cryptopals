#ifndef BASE64_H
#define BASE64_H

#include <stdlib.h>

void base64_encode(const char *data,
                   size_t input_length,
                   char *output_buffer,
                   size_t output_length);

void base64_decode(const char *data,
                   size_t input_length,
                   char *output,
                   size_t *output_length);

#endif  // BASE64_H