#ifndef CRYPTOPALS_BUFFER_H
#define CRYPTOPALS_BUFFER_H

#include <stdbool.h>

#define MKBUFFER(a, size) unsigned char a[size] = {0}; size_t a##_size = sizeof(a);
#define MKBUFFER_S(a, str) unsigned char a[] = str; size_t a##_size = sizeof(a) - 1;

void print_buffer(const unsigned char *buffer, size_t buffer_size);

int diff_buffers(const unsigned char *buffer, size_t buffer_size, const unsigned char *buffer2, size_t buffer2_size);

bool buffer_starts_with(const unsigned char *buffer, size_t buffer_size,
                        const unsigned char *sub, size_t sub_size);

bool buffer_ends_with(const unsigned char *buffer, size_t buffer_size,
                      const unsigned char *sub, size_t sub_size);

#endif //CRYPTOPALS_BUFFER_H
