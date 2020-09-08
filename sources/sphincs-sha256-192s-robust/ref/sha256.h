#ifndef SHA256_H
#define SHA256_H

#define SHA256_BLOCK_BYTES 64
#define SHA256_OUTPUT_BYTES 32  /* This does not necessarily equal N */
#define SHA256_ADDR_BYTES 22

#include <stddef.h>
#include <stdint.h>

#include "sha2.h"

void compress_address(unsigned char *out, const uint32_t addr[8]);

void mgf1(
    unsigned char *out, unsigned long outlen,
    unsigned char *input_plus_four_bytes, unsigned long inlen);

void seed_state(sha256ctx *hash_state_seeded, const unsigned char *pub_seed);

#endif
