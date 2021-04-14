#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include "base64.h"

static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/'};
static char decoding_table[256] = {};
static int mod_table[] = {0, 2, 1};


void base64_encode(IMMUTABLE_BUFFER_PARAM(input),
                   MUTABLE_BUFFER_PARAM(output)) {

    assert(output);
    assert(*output_size > (4 * ((input_size + 2) / 3)));
    *output_size = (4 * ((input_size + 2) / 3));

    for (int i = 0, j = 0; i < input_size;) {

        uint32_t octet_a = i < input_size ? (unsigned char) input[i++] : 0;
        uint32_t octet_b = i < input_size ? (unsigned char) input[i++] : 0;
        uint32_t octet_c = i < input_size ? (unsigned char) input[i++] : 0;

        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        output[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
        output[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
        output[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
        output[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
    }

    for (int i = 0; i < mod_table[input_size % 3]; i++) {
        output[*output_size - 1 - i] = '=';
    }
}


void build_decoding_table() {
    for (int i = 0; i < 64; i++)
        decoding_table[(unsigned char) encoding_table[i]] = i;
}


void base64_decode(IMMUTABLE_BUFFER_PARAM(input),
                   MUTABLE_BUFFER_PARAM(output)) {
    build_decoding_table();

    assert (input_size % 4 == 0);
    size_t expected_output_length = input_size / 4 * 3;
    if (input[input_size - 1] == '=') (expected_output_length)--;
    if (input[input_size - 2] == '=') (expected_output_length)--;
    assert(expected_output_length < *output_size);
    assert(output);

    for (int i = 0, j = 0; i < input_size;) {
        uint32_t sextet_a = input[i] == '=' ? 0 & i++ : decoding_table[input[i++]];
        uint32_t sextet_b = input[i] == '=' ? 0 & i++ : decoding_table[input[i++]];
        uint32_t sextet_c = input[i] == '=' ? 0 & i++ : decoding_table[input[i++]];
        uint32_t sextet_d = input[i] == '=' ? 0 & i++ : decoding_table[input[i++]];

        uint32_t triple = (sextet_a << 3 * 6)
                          + (sextet_b << 2 * 6)
                          + (sextet_c << 1 * 6)
                          + (sextet_d << 0 * 6);

        if (j < *output_size) output[j++] = (triple >> 2 * 8) & 0xFF;
        if (j < *output_size) output[j++] = (triple >> 1 * 8) & 0xFF;
        if (j < *output_size) output[j++] = (triple >> 0 * 8) & 0xFF;
    }
    *output_size = expected_output_length;
}