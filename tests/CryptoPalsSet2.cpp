#include <malloc.h>

extern "C" {
#include "../cryptolib/base64.h"
#include "../cryptolib/hex.h"
#include "../cryptolib/xor.h"
#include "../cryptolib/validate.h"
#include "../cryptolib/crypto.h"
#include "../cryptolib/file.h"
#include "../cryptolib/buffer.h"
}

#include <cstring>
#include <gtest/gtest.h>

MKBUFFER(static_key, 16);

class CryptoPalsSet2 : public ::testing::Test {
    void SetUp() {
        init_crypto();

        gen_key(static_key, &static_key_size);
    }
};

TEST_F (CryptoPalsSet2, Challenge9) {
    MKBUFFER(buffer, 20);
    MKBUFFER_S(key, "YELLOW SUBMARINE");
    pkcs7_pad(key, key_size,
              buffer, &buffer_size);
    ASSERT_EQ(0, memcmp("YELLOW SUBMARINE", buffer, 16));
    ASSERT_EQ(0, memcmp("\x04\x04\x04\x04", buffer + 16, 4));
}

TEST_F (CryptoPalsSet2, Challenge10a) {
    MKBUFFER(raw_bytes, 5000);
    read_b64_file("7.txt", raw_bytes, &raw_bytes_size);

    MKBUFFER(decrypted, 5000);
    ECB_dec(raw_bytes, raw_bytes_size,
            (const unsigned char *) "YELLOW SUBMARINE",
            decrypted, &decrypted_size);

    MKBUFFER(reencrypted, 5000);
    ECB_enc(decrypted, decrypted_size,
            (const unsigned char *) "YELLOW SUBMARINE",
            reencrypted, &reencrypted_size);

    ASSERT_EQ(raw_bytes_size, reencrypted_size);
    ASSERT_EQ(0, memcmp(raw_bytes, reencrypted, sizeof(raw_bytes)));
}

TEST_F (CryptoPalsSet2, Challenge10b) {
    MKBUFFER(raw_bytes, 5000);
    read_b64_file("10.txt", raw_bytes, &raw_bytes_size);

    MKBUFFER(decrypted, 5000);
    MKBUFFER_S(key, "YELLOW SUBMARINE");
    MKBUFFER_S(iv, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
    CBC_dec(raw_bytes, raw_bytes_size,
            key, iv,
            decrypted, &decrypted_size);
    printf("%.*s\n", (int) decrypted_size, decrypted);
    MKBUFFER(reencrypted, 5000);
    CBC_enc(decrypted, decrypted_size,
            key, iv,
            reencrypted, &reencrypted_size);

    ASSERT_EQ(raw_bytes_size, reencrypted_size);
    ASSERT_EQ(0, diff_buffers(raw_bytes, raw_bytes_size,
                              reencrypted, reencrypted_size));
}

TEST_F (CryptoPalsSet2, Challenge11a) {
    MKBUFFER(key, 16);
    gen_key(key, &key_size);
    print_buffer(key, key_size);
}

int random_encrypt(IMMUTABLE_BUFFER_PARAM(buffer),
                   MUTABLE_BUFFER_PARAM(output)) {
    MKBUFFER(key, 16);
    gen_key(key, &key_size);

    MKBUFFER(iv, 16);
    gen_key(iv, &iv_size);

    MKBUFFER(prepend, 10);
    gen_key(prepend, &prepend_size);
    prepend_size = 5 + rand() % 5;
    MKBUFFER(append, 10);
    gen_key(append, &append_size);
    append_size = 5 + rand() % 5;

    size_t temp_size = buffer_size + prepend_size + append_size;
    unsigned char *temp = (unsigned char *) calloc(1, temp_size);
    memcpy(temp, prepend, prepend_size);
    memcpy(temp + prepend_size, buffer, buffer_size);
    memcpy(temp + prepend_size + buffer_size, append, append_size);

    int mode = rand() % 2;
    if (mode == CBC) {
        CBC_enc(temp, temp_size, key, iv, output, output_size);
    } else if (mode == EBC) {
        ECB_enc(temp, temp_size, key, output, output_size);
    }
    free(temp), temp = nullptr;
    return mode;
}

int detect_mode(IMMUTABLE_BUFFER_PARAM(buffer)) {
    if (memcmp(buffer + AES_BLOCK_SIZE, buffer + 2 * AES_BLOCK_SIZE, AES_BLOCK_SIZE) == 0) {
        return EBC;
    } else {
        return CBC;
    }
}

TEST_F (CryptoPalsSet2, Challenge11b) {
    for (int i = 0; i < 1000; i++) {
        MKBUFFER(plaintext, 4 * AES_BLOCK_SIZE);
        MKBUFFER(encrypted, 6000);

        int mode = random_encrypt(plaintext, plaintext_size, encrypted, &encrypted_size);
        int guess = detect_mode(encrypted, encrypted_size);
        print_buffer(encrypted, encrypted_size);
        ASSERT_EQ(mode, guess);
    }
}

typedef void (*oracle_fn)(IMMUTABLE_BUFFER_PARAM(prepend), MUTABLE_BUFFER_PARAM(output));

void oracle(IMMUTABLE_BUFFER_PARAM(prepend),
            MUTABLE_BUFFER_PARAM(output)) {
    MKBUFFER_S(hidden, "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
                       "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
                       "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
                       "YnkK");
    MKBUFFER(decoded, 1000);
    base64_decode(hidden, hidden_size, decoded, &decoded_size);

    size_t buffer_size = prepend_size + decoded_size;
    auto *buffer = static_cast<unsigned char *>(calloc(1, buffer_size));
    if (prepend_size != 0) {
        memcpy(buffer, prepend, prepend_size);
    }
    memcpy(buffer + prepend_size, decoded, decoded_size);

    ECB_enc(buffer, buffer_size, static_key, output, output_size);

    free(buffer), buffer = NULL;
}


#define MAX_BLOCK_SIZE 32

int detect_block_size(oracle_fn oracleFn) {
    MKBUFFER(unshifted, 5000);
    oracleFn(NULL, 0, unshifted, &unshifted_size);

    for (int i = 1; i < MAX_BLOCK_SIZE; i++) {
        MKBUFFER(shifted, 5000);
        MKBUFFER(prepend, MAX_BLOCK_SIZE);
        prepend_size = i;
        oracleFn(prepend, prepend_size, shifted, &shifted_size);
        if (shifted_size != unshifted_size) {
            return shifted_size - unshifted_size;
        }
    }
    return -1;
}

int detect_ecb_block_size(oracle_fn oracleFn) {
    MKBUFFER(unshifted, 5000);
    oracleFn(NULL, 0, unshifted, &unshifted_size);

    for (int i = 1; i < MAX_BLOCK_SIZE; i++) {
        MKBUFFER(shifted, 5000);
        MKBUFFER(prepend, MAX_BLOCK_SIZE);
        prepend_size = i;
        oracleFn(prepend, prepend_size, shifted, &shifted_size);
        if (memcmp(unshifted, shifted + i, i) == 0) {
            return i;
        }
    }
    return -1;
}

TEST_F (CryptoPalsSet2, Challenge12a) {
    ASSERT_EQ(AES_BLOCK_SIZE, detect_ecb_block_size(oracle));
    ASSERT_EQ(AES_BLOCK_SIZE, detect_block_size(oracle));
}

TEST_F (CryptoPalsSet2, Challenge12b) {
    int block_size = 16;
    int length = 144;
    MKBUFFER(seed, 5000);
    MKBUFFER(known, 5000);
    for (int i = 0; i < length; i++) {
        MKBUFFER(actual, 5000);
        memset(seed, 'A', length - i);
        memcpy(seed + length - i - 1, known, i);
        seed[length - 1] = 0;
        oracle(seed, length - i - 1, actual, &actual_size);

        for (unsigned char j = 0; j < 255; j++) {
            MKBUFFER(test, 5000);
            memset(seed, 'A', length - i);
            memcpy(seed + length - i - 1, known, i);
            seed[length - 1] = j;
            oracle(seed, length, test, &test_size);

            if (memcmp(actual + length - block_size, test + length - block_size, block_size) == 0) {
                std::cout << "Found a letter: " << j << std::endl;
                known[i] = j;
                break;
            }
        }
        if (known[i] == 0) {
            std::cout << "At the end." << std::endl;
            break;
        }
    }
    EXPECT_STREQ("Rollin' in my 5.0\n"
                 "With my rag-top down so my hair can blow\n"
                 "The girlies on standby waving just to say hi\n"
                 "Did you stop? No, I just drove by\n\x01", (char *) known);
}

void profile_for(IMMUTABLE_BUFFER_PARAM(email), MUTABLE_BUFFER_PARAM(buffer)) {
    assert(strchr((char *) email, '=') == NULL);
    assert(strchr((char *) email, '&') == NULL);

    MKBUFFER(temp, 1000);

    size_t written = snprintf((char *) temp, temp_size, "email=%.*s&uid=10&role=user", (int) email_size, email);
    assert(written > 0);
    assert(written < *buffer_size);
    temp_size = written;

    ECB_enc(temp, temp_size, static_key, buffer, buffer_size);
}

void decrypt_profile(IMMUTABLE_BUFFER_PARAM(profile), MUTABLE_BUFFER_PARAM(buffer)) {
    ECB_dec(profile, profile_size, static_key, buffer, buffer_size);
}


TEST_F(CryptoPalsSet2, Challenge13a) {
    MKBUFFER_S(email, "cameron@gmail.com");
    MKBUFFER(output, 5000);
    profile_for(email, email_size, output, &output_size);

    MKBUFFER(decrypt, 5000);
    decrypt_profile(output, output_size, decrypt, &decrypt_size);
    ASSERT_STREQ("email=cameron@gmail.com&uid=10&role=user", (char *) decrypt);
}

TEST_F(CryptoPalsSet2, Challenge13b) {
    // Get block aligned "email="(6) + email + "&uid=10&role="(13), email must be 32 - 6-13 = 13
    MKBUFFER_S(email, "abc@gmail.com")
    MKBUFFER(output, 5000);
    profile_for(email, email_size, output, &output_size);
    // Replace last block with one that contains "admin", padded to 16 instead
    MKBUFFER(poisoned_email, 5000);
    memset(poisoned_email, 'A', AES_BLOCK_SIZE - 6);
    memcpy(poisoned_email + AES_BLOCK_SIZE - 6, "admin", 5);
    memset(poisoned_email + AES_BLOCK_SIZE - 6 + 5, 16 - 5, 16 - 5);
    poisoned_email_size = AES_BLOCK_SIZE * 2;
    MKBUFFER(nasty, 5000);
    profile_for(poisoned_email, poisoned_email_size, nasty, &nasty_size);
    // Second block of nasty is now admin encoded as a block

    // Build admin profile, using the first 2 blocks of the original email and profile
    MKBUFFER(admin_profile,AES_BLOCK_SIZE * 3);
    memcpy(admin_profile, output, AES_BLOCK_SIZE * 2);
    // and the tainted block from the nasty profile.
    memcpy(admin_profile + AES_BLOCK_SIZE *2, nasty + AES_BLOCK_SIZE, AES_BLOCK_SIZE);

    MKBUFFER(decrypt, 5000);
    decrypt_profile(admin_profile, admin_profile_size, decrypt, &decrypt_size);
    ASSERT_STREQ("email=abc@gmail.com&uid=10&role=admin", (char *) decrypt);
}
