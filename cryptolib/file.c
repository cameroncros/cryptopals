#include "file.h"
#include "base64.h"
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>

void read_b64_file(const char *filename, unsigned char *raw_bytes, size_t *raw_bytes_size) {
    size_t fullfile_size = *raw_bytes_size * 4/3;

    unsigned char *fullfile = (unsigned char *) calloc(1, fullfile_size);
    FILE *fp = fopen(filename, "r");
    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    assert(fp != NULL);

    size_t file_size = 0;
    while ((read = getline(&line, &len, fp)) != -1) {
        assert(file_size + read -1 < fullfile_size);
        memcpy(fullfile
               + file_size, line, read - 1);
        file_size += read - 1;

        free(line), line = NULL;
    }
    printf("File Size: %u B64 characters\n", (uint) file_size);

    base64_decode(fullfile, file_size, raw_bytes, raw_bytes_size);
    free(fullfile), fullfile = NULL;
}