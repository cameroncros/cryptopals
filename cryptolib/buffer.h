#ifndef CRYPTOPALS_BUFFER_H
#define CRYPTOPALS_BUFFER_H

#include <stdbool.h>

#define MKBUFFER(a, size) unsigned char a[size] = {0}; size_t a##_size = sizeof(a);
#define MKBUFFER_S(a, str) unsigned char a[] = str; size_t a##_size = sizeof(a) - 1;

#define MUTABLE_BUFFER_PARAM(n) unsigned char *n, size_t* n##_size
#define IMMUTABLE_BUFFER_PARAM(n) const unsigned char *n, size_t n##_size

void print_buffer(IMMUTABLE_BUFFER_PARAM(buffer));

int diff_buffers(IMMUTABLE_BUFFER_PARAM(buffer), IMMUTABLE_BUFFER_PARAM(buffer1));

bool buffer_starts_with(IMMUTABLE_BUFFER_PARAM(buffer),
                        IMMUTABLE_BUFFER_PARAM(sub));

bool buffer_ends_with(IMMUTABLE_BUFFER_PARAM(buffer),
                      IMMUTABLE_BUFFER_PARAM(sub));

#endif //CRYPTOPALS_BUFFER_H
