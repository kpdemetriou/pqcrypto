#ifndef API_H
#define API_H

#include <stdint.h>

#define CRYPTO_SECRETKEYBYTES  2400
#define CRYPTO_PUBLICKEYBYTES  1184
#define CRYPTO_CIPHERTEXTBYTES 1088
#define CRYPTO_BYTES           32
#define CRYPTO_ALGNAME "Kyber768"

int crypto_kem_keypair(uint8_t *pk, uint8_t *sk);

int crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);

int crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);


#endif
