#ifndef CRYPTOPALS_FILE_H
#define CRYPTOPALS_FILE_H

#include <stdlib.h>

void read_b64_file(const char *filename, unsigned char *raw_bytes, size_t *raw_bytes_size);

#endif //CRYPTOPALS_FILE_H
