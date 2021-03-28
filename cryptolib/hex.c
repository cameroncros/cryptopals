#include <string.h>
#include <assert.h>
#include <stdio.h>

void from_hex(const unsigned char *hexstr, size_t hexstr_length,
              unsigned char *output_buffer, size_t *output_buffer_size) {
    assert(hexstr_length % 2 == 0);
    assert(hexstr_length % 2 <= *output_buffer_size);

    for (size_t count = 0; count < hexstr_length / 2; count++) {
        sscanf(&hexstr[count * 2], "%2hhx", &output_buffer[count]);
    }
    *output_buffer_size = hexstr_length / 2;
}

void to_hex(const unsigned char *str, size_t str_size,  unsigned char *output_hex, size_t *output_hex_length) {
    assert(*output_hex_length > str_size * 2);
    assert(str);
    assert(output_hex);

    for (int i = 0; i < str_size; i++) {
        sprintf(&output_hex[i * 2], "%02hhx", str[i]);
    }
    output_hex[str_size * 2] = '\0';
    *output_hex_length = str_size * 2;
}
