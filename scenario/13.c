#include <assert.h>
#include <string.h>
#include <stdio.h>
#include "13.h"
#include "../cryptolib/crypto.h"
#include "12.h"

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