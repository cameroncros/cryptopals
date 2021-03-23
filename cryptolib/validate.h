#ifndef UNTITLED_VALIDATE_H
#define UNTITLED_VALIDATE_H

#include <stdlib.h>

double is_english(unsigned char *str, size_t length);
double entropy(unsigned char *str, size_t str_len);
int hamming_distance(const char *string1, const char *string2, int string1_length);

#endif //UNTITLED_VALIDATE_H
