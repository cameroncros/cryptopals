#ifndef UNTITLED_VALIDATE_H
#define UNTITLED_VALIDATE_H

#include <stdlib.h>
#include "buffer.h"

double is_english(IMMUTABLE_BUFFER_PARAM(str));
double entropy(IMMUTABLE_BUFFER_PARAM(str));
int hamming_distance(IMMUTABLE_BUFFER_PARAM(string1), IMMUTABLE_BUFFER_PARAM(string2));

#endif //UNTITLED_VALIDATE_H
