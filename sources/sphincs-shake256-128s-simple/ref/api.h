#ifndef API_H
#define API_H

#include <stddef.h>
#include <stdint.h>



#define CRYPTO_ALGNAME "SPHINCS+"

#define CRYPTO_SECRETKEYBYTES 64
#define CRYPTO_PUBLICKEYBYTES 32
#define CRYPTO_BYTES 8080
#define CRYPTO_SEEDBYTES 48


/*
 * Returns the length of a secret key, in bytes
 */
size_t crypto_sign_secretkeybytes(void);

/*
 * Returns the length of a public key, in bytes
 */
size_t crypto_sign_publickeybytes(void);

/*
 * Returns the length of a signature, in bytes
 */
size_t crypto_sign_bytes(void);

/*
 * Returns the length of the seed required to generate a key pair, in bytes
 */
size_t crypto_sign_seedbytes(void);

/*
 * Generates a SPHINCS+ key pair given a seed.
 * Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [root || PUB_SEED]
 */
int crypto_sign_seed_keypair(
    uint8_t *pk, uint8_t *sk, const uint8_t *seed);

/*
 * Generates a SPHINCS+ key pair.
 * Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [root || PUB_SEED]
 */
int crypto_sign_keypair(
    uint8_t *pk, uint8_t *sk);

/**
 * Returns an array containing a detached signature.
 */
int crypto_sign_signature(
    uint8_t *sig, size_t *siglen,
    const uint8_t *m, size_t mlen, const uint8_t *sk);

/**
 * Verifies a detached signature and message under a given public key.
 */
int crypto_sign_verify(
    const uint8_t *sig, size_t siglen,
    const uint8_t *m, size_t mlen, const uint8_t *pk);

/**
 * Returns an array containing the signature followed by the message.
 */
int crypto_sign(
    uint8_t *sm, size_t *smlen,
    const uint8_t *m, size_t mlen, const uint8_t *sk);

/**
 * Verifies a given signature-message pair under a given public key.
 */
int crypto_sign_open(
    uint8_t *m, size_t *mlen,
    const uint8_t *sm, size_t smlen, const uint8_t *pk);

#endif
