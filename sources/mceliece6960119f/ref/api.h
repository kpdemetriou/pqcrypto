#ifndef API_H
#define API_H

#include <stdint.h>

#define CRYPTO_ALGNAME "Classic McEliece 6960119f"
#define CRYPTO_PUBLICKEYBYTES 1047319
#define CRYPTO_SECRETKEYBYTES 13908
#define CRYPTO_CIPHERTEXTBYTES 226
#define CRYPTO_BYTES 32


int crypto_kem_enc(
    uint8_t *c,
    uint8_t *key,
    const uint8_t *pk
);

int crypto_kem_dec(
    uint8_t *key,
    const uint8_t *c,
    const uint8_t *sk
);

int crypto_kem_keypair
(
    uint8_t *pk,
    uint8_t *sk
);

#endif
