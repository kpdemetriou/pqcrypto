#ifndef API_H
#define API_H

#include <stddef.h>
#include <stdint.h>

#define CRYPTO_SECRETKEYBYTES 511448
#define CRYPTO_PUBLICKEYBYTES 206744
#define CRYPTO_BYTES 156
#define CRYPTO_ALGNAME "RAINBOW(256,68,36,36) - cyclic"

int crypto_sign_keypair(uint8_t *pk, uint8_t *sk);


int crypto_sign_signature(
    uint8_t *sig, size_t *siglen,
    const uint8_t *m, size_t mlen, const uint8_t *sk);

int crypto_sign_verify(
    const uint8_t *sig, size_t siglen,
    const uint8_t *m, size_t mlen, const uint8_t *pk);

int crypto_sign(uint8_t *sm, size_t *smlen,
        const uint8_t *m, size_t mlen,
        const uint8_t *sk);

int crypto_sign_open(uint8_t *m, size_t *mlen,
        const uint8_t *sm, size_t smlen,
        const uint8_t *pk);


#endif
