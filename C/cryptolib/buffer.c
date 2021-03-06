#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <assert.h>
#include <string.h>
#include "buffer.h"

#define BLOCK_WIDTH 16

void print_buffer(IMMUTABLE_BUFFER_PARAM(buffer)) {
    printf("Buffer (%p):\n\n", buffer);
    for (size_t i = 0; i < buffer_size + BLOCK_WIDTH; i += BLOCK_WIDTH) {
        for (size_t j = 0; j < BLOCK_WIDTH; j++) {
            if (i + j < buffer_size) {
                printf("%02x ", buffer[i + j]);
            }
        }
        printf("\n");
    }
}

#define KNRM  "\x1B[0m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"
#define KBLU  "\x1B[34m"
#define KMAG  "\x1B[35m"
#define KCYN  "\x1B[36m"
#define KWHT  "\x1B[37m"
#define RESET   "\033[0m"

int diff_buffers(IMMUTABLE_BUFFER_PARAM(buffer), IMMUTABLE_BUFFER_PARAM(buffer2)) {
    int diff_bytes = 0;
    size_t max_buffer = buffer_size;
    if (buffer2_size > max_buffer) {
        max_buffer = buffer2_size;
    }
    for (size_t i = 0; i < max_buffer + BLOCK_WIDTH; i += BLOCK_WIDTH) {
        int line_diff_bytes = 0;
        for (size_t j = 0; j < BLOCK_WIDTH; j++) {
            size_t position = i + j;
            if (position > buffer_size) {
                printf("   ");
            } else if (position < buffer_size && position < buffer2_size && buffer[position] != buffer2[position]) {
                printf(KMAG "%02x " RESET, buffer[position]);
                line_diff_bytes++;
            } else {
                printf(KWHT "%02x " RESET, buffer[position]);
            }
        }
        printf(" |  ");
        for (size_t j = 0; j < BLOCK_WIDTH; j++) {
            size_t position = i + j;
            if (position > buffer_size) {
                printf("   ");
            } else if (position < buffer_size && position < buffer2_size && buffer[position] != buffer2[position]) {
                printf(KMAG "%02x " RESET, buffer2[position]);
            } else {
                printf(KWHT "%02x " RESET, buffer2[position]);
            }
        }
        printf(" |  %i", line_diff_bytes);
        printf("\n");
        diff_bytes += line_diff_bytes;
    }
    return diff_bytes;
}

bool buffer_starts_with(IMMUTABLE_BUFFER_PARAM(buffer),
                        IMMUTABLE_BUFFER_PARAM(sub)) {
    assert(sub_size < buffer_size);
    return memcmp(buffer, sub, sub_size) == 0;
}

bool buffer_ends_with(IMMUTABLE_BUFFER_PARAM(buffer),
                      IMMUTABLE_BUFFER_PARAM(sub)) {
    assert(sub_size < buffer_size);
    return memcmp(buffer + buffer_size - sub_size, sub, sub_size) == 0;
}