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

#include <gtest/gtest.h>

class CryptoPalsSet2 : public ::testing::Test {

};

TEST_F (CryptoPalsSet2, Challenge9) {
    MKBUFFER(buffer, 100);
    MKBUFFER_S(key, "YELLOW SUBMARINE");
    pkcs7_padd(key, key_size,
               buffer, 20);
    ASSERT_EQ(0, memcmp("YELLOW SUBMARINE", buffer, 16));
    ASSERT_EQ(0, memcmp("\x04\x04\x04\x04", buffer + 16, 4));
    ASSERT_EQ(buffer[20], '\0');
}

TEST_F (CryptoPalsSet2, Challenge10a) {
    MKBUFFER(raw_bytes, 5000);
    read_b64_file("7.txt", raw_bytes, &raw_bytes_size);

    MKBUFFER(decrypted, 5000);
    ECB(raw_bytes, raw_bytes_size,
        (const unsigned char *) "YELLOW SUBMARINE",
        decrypted, &decrypted_size,
        0);

    MKBUFFER(reencrypted, 5000);
    ECB(decrypted, decrypted_size,
        (const unsigned char *) "YELLOW SUBMARINE",
        reencrypted, &reencrypted_size,
        1);

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
    printf("%.*s\n", (int)decrypted_size, decrypted);
    MKBUFFER(reencrypted, 5000);
    CBC_enc(decrypted, decrypted_size,
            key, iv,
            reencrypted, &reencrypted_size);

    ASSERT_EQ(raw_bytes_size, reencrypted_size);
    ASSERT_EQ(0, diff_buffers(raw_bytes, raw_bytes_size,
                              reencrypted, reencrypted_size));
}
