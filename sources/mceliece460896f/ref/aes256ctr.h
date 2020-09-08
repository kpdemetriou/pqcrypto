#ifndef AES256CTR_H
#define AES256CTR_H

#include <stddef.h>
#include <stdint.h>

#include "aes.h"


void aes256ctr(
    uint8_t *out,
    size_t outlen,
    const uint8_t nonce[AESCTR_NONCEBYTES],
    const uint8_t key[AES256_KEYBYTES]
);

#endif
