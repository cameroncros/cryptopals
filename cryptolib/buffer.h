#ifndef CRYPTOPALS_BUFFER_H
#define CRYPTOPALS_BUFFER_H

#define MKBUFFER(a, size) unsigned char a[size] = {0}; size_t a##_size = sizeof(a);
#define MKBUFFER_S(a, str) unsigned char a[] = str; size_t a##_size = sizeof(a) - 1;

void print_buffer(unsigned char *buffer, size_t buffer_size);
int diff_buffers(unsigned char *buffer, size_t buffer_size, unsigned char *buffer2, size_t buffer2_size);

#endif //CRYPTOPALS_BUFFER_H
