#include <malloc.h>

extern "C" {
#include "../cryptolib/base64.h"
#include "../cryptolib/hex.h"
#include "../cryptolib/xor.h"
#include "../cryptolib/validate.h"
#include "../cryptolib/file.h"
#include "../cryptolib/crypto.h"
#include "../cryptolib/buffer.h"
}

#include <gtest/gtest.h>

class CryptoPalsSet1 : public ::testing::Test {
    void SetUp() {
        init_crypto();
    }
};

TEST_F (CryptoPalsSet1, Challenge1) {
    printf("Set 1 - Challenge 1\n");
    MKBUFFER_S(input,
               "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
    MKBUFFER(buffer, 1000);
    from_hex(input, input_size,
             buffer, &buffer_size);

    MKBUFFER(outputbuffer, 1000);
    base64_encode(buffer, buffer_size, outputbuffer, &outputbuffer_size);

    printf("Result: [%s]\n", outputbuffer);
    ASSERT_STREQ("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t", (char *) outputbuffer);
}

TEST_F (CryptoPalsSet1, Challenge2) {
    printf("Set 1 - Challenge 2\n");
    MKBUFFER_S(input1, "1c0111001f010100061a024b53535009181c");
    MKBUFFER_S(input2, "686974207468652062756c6c277320657965");
    MKBUFFER(buffer1, 1000);
    MKBUFFER(buffer2, 1000);
    from_hex(input1, input1_size, buffer1, &buffer1_size);
    from_hex(input2, input2_size, buffer2, &buffer2_size);

    MKBUFFER(output, 1000);
    xor_bytes(buffer1, buffer1_size, buffer2, buffer2_size, output, &output_size);

    MKBUFFER(output_hex, 1000);
    size_t output_hex_len = sizeof(output_hex);
    to_hex(output, output_size, output_hex, &output_hex_len);
    printf("Result: [%s]\n", output_hex);
    ASSERT_STREQ("746865206b696420646f6e277420706c6179", (char *) output_hex);
}

TEST_F (CryptoPalsSet1, Challenge3) {
    MKBUFFER_S(input1, "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
    MKBUFFER(buffer1, 1000);
    from_hex(input1, input1_size, buffer1, &buffer1_size);

    MKBUFFER(output, 1000);

    for (int i = 0; i < 256; i++) {
        MKBUFFER(xor_string, 2);
        xor_string[0] = (char) i;
        output_size = sizeof(output);
        xor_bytes(buffer1, buffer1_size, xor_string,
                  1, output, &output_size);
        double ent = is_english((unsigned char *) output, output_size);
        if (ent < 0.75) {
            printf("XOR'd [%s][%.03f] => [%.*s]\n", xor_string, ent, (int) output_size, output);
        }
    }
}

TEST_F (CryptoPalsSet1, Challenge4) {
    FILE *fp = fopen("4.txt", "r");
    unsigned char *line = nullptr;
    size_t len = 0;
    ssize_t read;
    ASSERT_NE(nullptr, fp);

    while ((read = getline((char **) &line, &len, fp)) != -1) {
        MKBUFFER(buffer1, 1000)
        from_hex(line, len, buffer1, &buffer1_size);
        MKBUFFER(output, 1000);
        for (int i = 0; i < 256; i++) {
            MKBUFFER(xor_string, 2);
            xor_string[0] = (char) i;
            output_size = sizeof(output);
            xor_bytes(buffer1, buffer1_size, xor_string,
                      1, output, &output_size);
            double ent = is_english((unsigned char *) output, output_size);
            if (ent < 0.8) {
                printf("XOR'd [%s][%.03f] => [%.*s]\n", xor_string, ent, (int) output_size, output);
            }
        }
        free(line), line = nullptr;
    }
}

TEST_F (CryptoPalsSet1, Challenge5) {
    MKBUFFER_S(string, "Burning 'em, if you ain't quick and nimble\n"
                       "I go crazy when I hear a cymbal");

    MKBUFFER(xord, 1000);
    MKBUFFER_S(key, "ICE");
    xor_bytes(string, string_size,
              key, key_size, xord, &xord_size);

    MKBUFFER(output, 1000);

    to_hex(xord, xord_size, output, &output_size);
    printf("Result: [%s]\n", output);
    ASSERT_STREQ("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272"
                 "a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f", (char *) output);
    printf("\n");
}

TEST_F (CryptoPalsSet1, Challenge6a) {
    MKBUFFER_S(str1, "this is a test");
    MKBUFFER_S(str2, "wokka wokka!!!");
    int distance = hamming_distance(str1, str1_size, str2, str1_size);
    printf("Result: [%i]\n", distance);
    ASSERT_EQ(37, distance);
    printf("\n");
}

TEST_F (CryptoPalsSet1, Challenge6b) {
    size_t fullfile_size = 0;
    unsigned char *fullfile = static_cast<unsigned char *>(calloc(1, 1));
    FILE *fp = fopen("6.txt", "r");
    char *line = nullptr;
    size_t len = 0;
    ssize_t read;
    if (fp == nullptr)
        exit(errno);

    while ((read = getline(&line, &len, fp)) != -1) {
        fullfile = static_cast<unsigned char *>(realloc(fullfile, fullfile_size + read - 1));
        memcpy(fullfile
               + fullfile_size, line, read - 1);
        fullfile_size += read - 1;

        free(line), line = nullptr;
    }
    printf("File Size: %u B64 characters\n", (uint) fullfile_size);

    size_t raw_bytes_size = fullfile_size;
    unsigned char *raw_bytes = (unsigned char *) calloc(sizeof(unsigned char), raw_bytes_size);
    base64_decode(fullfile, fullfile_size, raw_bytes, &raw_bytes_size);

    int best_key_length = 0;
    {
#define MIN_KEY_LENGTH 2
#define MAX_KEY_LENGTH 50

        double distances[MAX_KEY_LENGTH] = {0};
        for (int i = MIN_KEY_LENGTH; i < MAX_KEY_LENGTH; i++) {
#define NUM_SAMPLES 50
            for (int j = 0; j < NUM_SAMPLES; j++) {
                distances[i] += hamming_distance(raw_bytes + j * i, i,
                                                 raw_bytes + (j + 1) * i, i);
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
            MKBUFFER(block, NUM_SAMPLES);
            for (int j = 0; j < NUM_SAMPLES; j++) {
                block[j] = raw_bytes[j * best_key_length + i];
            }

            MKBUFFER(output, NUM_SAMPLES);
            double best_score = 100;
            char best_key = 'X';
            for (int j = 0; j < 256; j++) {
                MKBUFFER(xor_string, 1)
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

    free(raw_bytes), raw_bytes = nullptr;
    free(fullfile), fullfile = nullptr;
}


TEST_F (CryptoPalsSet1, Challenge7) {
    MKBUFFER(raw_bytes, 5000);
    read_b64_file("7.txt", raw_bytes, &raw_bytes_size);

    unsigned char key[] = "YELLOW SUBMARINE";

    MKBUFFER(decrypted_bytes, 5000);
    ECB_dec(raw_bytes, raw_bytes_size, key, decrypted_bytes, &decrypted_bytes_size);

    MKBUFFER_S(start, "I'm back and I'm ringin' the bell");
    ASSERT_TRUE(buffer_starts_with(decrypted_bytes, decrypted_bytes_size,
                                   start, start_size));
    MKBUFFER_S(end, "Play that funky music");
    ASSERT_TRUE(buffer_starts_with(decrypted_bytes, decrypted_bytes_size,
                                   start, start_size));
}

TEST_F (CryptoPalsSet1, Challenge8) {
    FILE *fp = fopen("8.txt", "r");
    unsigned char *line = nullptr;
    size_t len = 0;
    ssize_t read;
    if (fp == nullptr)
        exit(errno);

    while ((read = getline((char **) &line, &len, fp)) != -1) {
        MKBUFFER(buffer1, 1000);
        from_hex(line, read - 1, buffer1, &buffer1_size);

        int num_duplicates = 0;
        for (size_t i = 0; i < buffer1_size - 16; i += 16) {
            for (size_t j = i + 16; j < buffer1_size - 16; j += 16) {
                if (memcmp(buffer1 + i, buffer1 + j, 16) == 0) {
                    printf("Found Duplicate block [%zu: %.32s, %zu: %.32s]\n",
                           i * 2, line + i * 2, j * 2, line + 2 * j);
                    num_duplicates++;
                }
            }
        }
        if (num_duplicates > 0) {
            printf("Possible AES-EBC [%i]: %s\n", num_duplicates, line);
        }

        free(line), line = nullptr;
    }
}
