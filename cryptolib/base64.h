#ifndef BASE64_H
#define BASE64_H

#include <stdlib.h>

void base64_encode(const unsigned char *data,
                   size_t input_length,
                   unsigned char *output_buffer,
                   size_t output_length);

void base64_decode(const unsigned char *data,
                   size_t input_length,
                   unsigned char *output,
                   size_t *output_length);

#endif  // BASE64_H