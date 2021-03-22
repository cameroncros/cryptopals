#include <assert.h>
#include <string.h>
#include <malloc.h>
#include <errno.h>
#include "base64.h"
#include "hex.h"
#include "xor.h"
#include "validate.h"
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/err.h>


#pragma clang diagnostic push
#pragma ide diagnostic ignored "hicpp-signed-bitwise"

int hamming_distance(char *string1, char *string2, int string1_length) {
    size_t length = string1_length;
    char *output = malloc(length);

    xor_bytes(string1, length, string2, length, output, &length);
    int distance = 0;
    for (size_t i = 0; i < length; i++) {
        distance += output[i] >> 0 & 0x1;
        distance += output[i] >> 1 & 0x1;
        distance += output[i] >> 2 & 0x1;
        distance += output[i] >> 3 & 0x1;
        distance += output[i] >> 4 & 0x1;
        distance += output[i] >> 5 & 0x1;
        distance += output[i] >> 6 & 0x1;
        distance += output[i] >> 7 & 0x1;
    }
    free(output), output = NULL;
    return distance;
}

#pragma clang diagnostic pop

int main() {
    {
        printf("Set 1 - Challenge 1\n");
        char input[] = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        char buffer[1000] = {};
        size_t buffer_length = sizeof(buffer);
        from_hex(input, strlen(input),
                 buffer, &buffer_length);

        char outputbuffer[1000] = {0};
        base64_encode(buffer, strlen(buffer), outputbuffer, sizeof(outputbuffer));

        printf("Result: [%s]\n", outputbuffer);
        assert(strcmp("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t", outputbuffer) == 0);
        printf("\n");
    }

    {
        printf("Set 1 - Challenge 2\n");
        char input1[] = "1c0111001f010100061a024b53535009181c";
        char input2[] = "686974207468652062756c6c277320657965";
        char buffer1[1000] = {0};
        char buffer2[1000] = {0};
        size_t buffer_length1 = sizeof(buffer1);
        size_t buffer_length2 = sizeof(buffer2);
        from_hex(input1, strlen(input1), buffer1, &buffer_length1);
        from_hex(input2, strlen(input2), buffer2, &buffer_length2);

        char output[1000] = {0};
        size_t output_length = sizeof(output);
        xor_bytes(buffer1, buffer_length1, buffer2, buffer_length2, output, &output_length);

        char output_hex[1000] = {0};
        size_t output_hex_len = sizeof(output_hex);
        to_hex(output, output_length, output_hex, &output_hex_len);
        printf("Result: [%s]\n", output_hex);
        assert(strcmp("746865206b696420646f6e277420706c6179", output_hex) == 0);
        printf("\n");
    }

    {
        printf("Set 1 - Challenge 3\n");
        char input1[] = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
        char buffer1[1000] = {0};
        size_t buffer_length1 = sizeof(buffer1);
        from_hex(input1, strlen(input1), buffer1, &buffer_length1);

        char output[1000] = {0};

        for (int i = 0; i < 256; i++) {
            char xor_string[2] = "";
            xor_string[0] = (char) i;
            size_t output_length = sizeof(output);
            xor_bytes(buffer1, buffer_length1, xor_string, 1, output, &output_length);
            double ent = is_english((unsigned char *) output, output_length);
            if (ent < 0.75) {
                printf("XOR'd [%s][%.03f] => [%.*s]\n", xor_string, ent, (int) output_length, output);
            }
        }
        printf("\n");
    }

    {
        printf("Set 1 - Challenge 4\n");
        FILE *fp = fopen("../4.txt", "r");
        char *line = NULL;
        size_t len = 0;
        ssize_t read;
        if (fp == NULL)
            exit(errno);

        while ((read = getline(&line, &len, fp)) != -1) {
            char buffer1[1000] = {0};
            size_t buffer_length1 = sizeof(buffer1);
            from_hex(line, len, buffer1, &buffer_length1);

            char output[1000] = {0};
            for (int i = 0; i < 256; i++) {
                char xor_string[2] = "";
                xor_string[0] = (char) i;
                size_t output_length = sizeof(output);
                xor_bytes(buffer1, buffer_length1, xor_string, 1, output, &output_length);
                double ent = is_english((unsigned char *) output, output_length);
                if (ent < 0.8) {
                    printf("XOR'd [%s][%.03f] => [%.*s]\n", xor_string, ent, (int) output_length, output);
                }
            }
            free(line), line = NULL;
        }
        printf("\n");
    }

    {
        printf("Set 1 - Challenge 5\n");
        char *string = "Burning 'em, if you ain't quick and nimble\n"
                       "I go crazy when I hear a cymbal";
        size_t string_len = strlen(string);

        char xord[1000] = {};
        size_t xord_len = sizeof(xord);

        xor_bytes(string, string_len, "ICE", 3, xord, &xord_len);

        char output[1000] = {};
        size_t output_len = sizeof(output);

        to_hex(xord, xord_len, output, &output_len);
        printf("Result: [%s]\n", output);
        assert(strcmp("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272"
                      "a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f", output) == 0);
        printf("\n");
    }

    {
        printf("Set 1 - Challenge 6a - Hamming Distance\n");
        int distance = hamming_distance("this is a test", "wokka wokka!!!", strlen("wokka wokka!!!"));
        printf("Result: [%i]\n", distance);
        assert(distance == 37);
        printf("\n");
    }

    {
        printf("Set 1 - Challenge 6b - Guess Keysize\n");
        size_t fullfile_size = 0;
        char *fullfile = calloc(1, 1);
        FILE *fp = fopen("../6.txt", "r");
        char *line = NULL;
        size_t len = 0;
        ssize_t read;
        if (fp == NULL)
            exit(errno);

        while ((read = getline(&line, &len, fp)) != -1) {
            fullfile = realloc(fullfile, fullfile_size + read - 1);
            memcpy(fullfile + fullfile_size, line, read - 1);
            fullfile_size += read - 1;


            free(line), line = NULL;
        }
        printf("File Size: %u B64 characters\n", (uint) fullfile_size);

        size_t raw_bytes_size = fullfile_size;
        char *raw_bytes = calloc(sizeof(char), raw_bytes_size);
        base64_decode(fullfile, fullfile_size, raw_bytes, &raw_bytes_size);

        int best_key_length = 0;
        {
#define MIN_KEY_LENGTH 2
#define MAX_KEY_LENGTH 50

            double distances[MAX_KEY_LENGTH] = {0};
            for (int i = MIN_KEY_LENGTH; i < MAX_KEY_LENGTH; i++) {
#define NUM_SAMPLES 50
                for (int j = 0; j < NUM_SAMPLES; j++) {
                    distances[i] += hamming_distance(raw_bytes + j * i, raw_bytes + (j + 1) * i, i);
                }
                distances[i] /= NUM_SAMPLES;
                distances[i] /= i * 8;
            }

            double gradient =
                    (distances[MAX_KEY_LENGTH - 1] - distances[MIN_KEY_LENGTH]) / (MAX_KEY_LENGTH - 1 - MIN_KEY_LENGTH);
            double c = distances[MIN_KEY_LENGTH];
            for (int i = MIN_KEY_LENGTH; i < MAX_KEY_LENGTH; i++) {
                distances[i] = distances[i] - c - (gradient * (i - MIN_KEY_LENGTH));
                printf("Distance [%i] => %f\n", i, distances[i]);
                if (distances[i] < distances[best_key_length]) {
                    best_key_length = i;
                }
            }
            printf("Best Distance is %i -> %f\n", best_key_length, distances[best_key_length]);
        }
        {
            for (int i = 0; i < best_key_length; i++) {
                char block[NUM_SAMPLES] = {};
                for (int j = 0; j < NUM_SAMPLES; j++) {
                    block[j] = raw_bytes[j * best_key_length + i];
                }

                char output[NUM_SAMPLES] = {};
                double best_score = 100;
                char best_key = 'X';
                for (int j = 0; j < 256; j++) {
                    char xor_string[2] = "";
                    xor_string[0] = (char) j;
                    size_t output_length = sizeof(output);
                    xor_bytes(block, NUM_SAMPLES, xor_string, 1, output, &output_length);
                    double ent = is_english((unsigned char *) output, output_length);
                    if (ent < best_score) {
                        best_key = (char) j;
                        best_score = ent;
                    }
                }
                printf("Best Key [%i] -> %c\n", i, best_key);
            }
        }

        free(raw_bytes), raw_bytes = NULL;
        free(fullfile), fullfile = NULL;
        printf("\n");
    }

    {
        printf("Set 1 - Challenge 7\n");
        size_t fullfile_size = 0;
        char *fullfile = calloc(1, 1);
        FILE *fp = fopen("../7.txt", "r");
        char *line = NULL;
        size_t len = 0;
        ssize_t read;
        if (fp == NULL)
            exit(errno);

        while ((read = getline(&line, &len, fp)) != -1) {
            fullfile = realloc(fullfile, fullfile_size + read - 1);
            memcpy(fullfile + fullfile_size, line, read - 1);
            fullfile_size += read - 1;


            free(line), line = NULL;
        }
        printf("File Size: %u B64 characters\n", (uint) fullfile_size);

        size_t raw_bytes_size = fullfile_size;
        char *raw_bytes = calloc(sizeof(char), raw_bytes_size);
        base64_decode(fullfile, fullfile_size, raw_bytes, &raw_bytes_size);
        char *decrypted_bytes = calloc(sizeof(char), raw_bytes_size + EVP_MAX_BLOCK_LENGTH);
        size_t output_length = raw_bytes_size + EVP_MAX_BLOCK_LENGTH;

        unsigned char key[] = "YELLOW SUBMARINE";


        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        assert(EVP_CIPHER_CTX_reset(ctx));
        assert(EVP_CipherInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL,
                                 0));
        assert(EVP_CipherInit_ex(ctx, NULL, NULL, key, NULL, 0));
        assert(EVP_CipherUpdate(ctx,
                                (unsigned char *) decrypted_bytes, (int *) &output_length,
                                (unsigned char *) raw_bytes, raw_bytes_size));
        //EVP_CipherFinal_ex(ctx, (unsigned char *) decrypted_bytes, (int *) &output_length);
        EVP_CIPHER_CTX_free(ctx);

        printf("%.*s\n", (int) output_length, decrypted_bytes);
        printf("\n");
    }

    {
        printf("Set 1 - Challenge 8\n");
        FILE *fp = fopen("../8.txt", "r");
        char *line = NULL;
        size_t len = 0;
        ssize_t read;
        if (fp == NULL)
            exit(errno);

        while ((read = getline(&line, &len, fp)) != -1) {
            char buffer1[1000] = {0};
            size_t buffer_length1 = sizeof(buffer1);
            from_hex(line, read - 1, buffer1, &buffer_length1);

            int num_duplicates = 0;
            for (size_t i = 0; i < buffer_length1 - 16; i += 16) {
                for (size_t j = i + 16; j < buffer_length1 - 16; j += 16) {
                    if (memcmp(buffer1 + i, buffer1 + j, 16) == 0) {
                        printf("Found Duplicate block [%zu: %.32s, %zu: %.32s]\n", i * 2, line + i * 2, j * 2,
                               line + 2 * j);
                        num_duplicates++;
                    }
                }
            }
            if (num_duplicates > 0) {
                printf("Possible AES-EBC [%i]: %s\n", num_duplicates, line);
            }

            free(line), line = NULL;
        }
    }

    return 0;
}
