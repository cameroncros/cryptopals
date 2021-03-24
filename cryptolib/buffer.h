#ifndef CRYPTOPALS_BUFFER_H
#define CRYPTOPALS_BUFFER_H

#define MKBUFFER(a, size) char a[size] = {0}; size_t a##_size = sizeof(a);

#endif //CRYPTOPALS_BUFFER_H
