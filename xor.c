#include "hex.h"
#include "base64.h"
#include <malloc.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include "xor.h"

void xor_bytes(const char *input1, size_t input1_len,
               const char *input2, size_t input2_len,
               char *output, size_t *output_len) {
    assert(input1);
    assert(input2);
    assert(output);
    assert(input2_len <= input1_len);
    assert(input1_len <= *output_len);
    for (size_t i = 0; i < input1_len; i++) {
        output[i] = input1[i] ^ input2[i % input2_len];
    }
    *output_len = input1_len;
}