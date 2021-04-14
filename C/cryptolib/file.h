#ifndef CRYPTOPALS_FILE_H
#define CRYPTOPALS_FILE_H

#include <stdlib.h>
#include "buffer.h"

void read_b64_file(const char *filename, MUTABLE_BUFFER_PARAM(raw_bytes));

#endif //CRYPTOPALS_FILE_H
