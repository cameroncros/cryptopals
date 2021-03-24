#include <malloc.h>

extern "C" {
#include "../cryptolib/base64.h"
#include "../cryptolib/hex.h"
#include "../cryptolib/xor.h"
#include "../cryptolib/validate.h"
#include "../cryptolib/crypto.h"
#include "../cryptolib/file.h"
}

#include <gtest/gtest.h>

class CryptoPalsSet2 : public ::testing::Test {

};

TEST_F (CryptoPalsSet2, Challenge9) {
    char buffer[100] = {0};
    pkcs7_padd("YELLOW SUBMARINE", strlen("YELLOW SUBMARINE"),
               buffer, 20);
    ASSERT_EQ(0, memcmp("YELLOW SUBMARINE", buffer, 16));
    ASSERT_EQ(0, memcmp("\x04\x04\x04\x04", buffer + 16, 4));
    ASSERT_EQ(buffer[20], '\0');
}

TEST_F (CryptoPalsSet2, Challenge10a) {
    char raw_bytes[5000] = {};
    size_t raw_bytes_size = sizeof(raw_bytes);
    read_b64_file("7.txt", raw_bytes, &raw_bytes_size);


    char decrypted[5000] = {};
    size_t decrypted_size = sizeof(decrypted);
    ECB(raw_bytes, raw_bytes_size,
        (const unsigned char *) "YELLOW SUBMARINE",
        decrypted, &decrypted_size,
        0);

    char reencrypted[5000] = {};
    size_t reencrypted_size = sizeof(reencrypted);
    ECB(decrypted, decrypted_size,
        (const unsigned char *) "YELLOW SUBMARINE",
        reencrypted, &reencrypted_size,
        1);

    ASSERT_EQ(raw_bytes_size, reencrypted_size);
    ASSERT_EQ(0, memcmp(raw_bytes, reencrypted, sizeof(raw_bytes)));
}

