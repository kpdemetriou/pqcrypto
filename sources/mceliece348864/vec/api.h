#ifndef API_H
#define API_H

#include <stdint.h>

#define CRYPTO_ALGNAME "Classic McEliece 348864"
#define CRYPTO_PUBLICKEYBYTES 261120
#define CRYPTO_SECRETKEYBYTES 6452
#define CRYPTO_CIPHERTEXTBYTES 128
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

