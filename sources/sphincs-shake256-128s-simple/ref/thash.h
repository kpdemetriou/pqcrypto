#ifndef THASH_H
#define THASH_H

#include "hash_state.h"

#include <stdint.h>

void thash_1(
    unsigned char *out, const unsigned char *in,
    const unsigned char *pub_seed, uint32_t addr[8],
    const hash_state *hash_state_seeded);

void thash_2(
    unsigned char *out, const unsigned char *in,
    const unsigned char *pub_seed, uint32_t addr[8],
    const hash_state *hash_state_seeded);

void thash_WOTS_LEN(
    unsigned char *out, const unsigned char *in,
    const unsigned char *pub_seed, uint32_t addr[8],
    const hash_state *hash_state_seeded);

void thash_FORS_TREES(
    unsigned char *out, const unsigned char *in,
    const unsigned char *pub_seed, uint32_t addr[8],
    const hash_state *hash_state_seeded);

#endif
