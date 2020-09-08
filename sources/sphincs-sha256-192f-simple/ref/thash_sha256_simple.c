#include <stdint.h>
#include <string.h>

#include "address.h"
#include "params.h"
#include "thash.h"

#include "sha2.h"
#include "sha256.h"

/**
 * Takes an array of inblocks concatenated arrays of N bytes.
 */
static void thash(
    unsigned char *out, unsigned char *buf,
    const unsigned char *in, unsigned int inblocks,
    const unsigned char *pub_seed, uint32_t addr[8],
    const sha256ctx *hash_state_seeded) {

    unsigned char outbuf[SHA256_OUTPUT_BYTES];
    sha256ctx sha2_state;

    (void)pub_seed; /* Suppress an 'unused parameter' warning. */

    /* Retrieve precomputed state containing pub_seed */
    sha256_inc_ctx_clone(&sha2_state, hash_state_seeded);

    compress_address(buf, addr);
    memcpy(buf + SHA256_ADDR_BYTES, in, inblocks * N);

    sha256_inc_finalize(outbuf, &sha2_state, buf, SHA256_ADDR_BYTES + inblocks * N);
    memcpy(out, outbuf, N);
}

/* The wrappers below ensure that we use fixed-size buffers on the stack */

void thash_1(
    unsigned char *out, const unsigned char *in,
    const unsigned char *pub_seed, uint32_t addr[8],
    const sha256ctx *hash_state_seeded) {

    unsigned char buf[SHA256_ADDR_BYTES + 1 * N];
    thash(
        out, buf, in, 1, pub_seed, addr, hash_state_seeded);
}

void thash_2(
    unsigned char *out, const unsigned char *in,
    const unsigned char *pub_seed, uint32_t addr[8],
    const sha256ctx *hash_state_seeded) {

    unsigned char buf[SHA256_ADDR_BYTES + 2 * N];
    thash(
        out, buf, in, 2, pub_seed, addr, hash_state_seeded);
}

void thash_WOTS_LEN(
    unsigned char *out, const unsigned char *in,
    const unsigned char *pub_seed, uint32_t addr[8],
    const sha256ctx *hash_state_seeded) {

    unsigned char buf[SHA256_ADDR_BYTES + WOTS_LEN * N];
    thash(
        out, buf, in, WOTS_LEN, pub_seed, addr, hash_state_seeded);
}

void thash_FORS_TREES(
    unsigned char *out, const unsigned char *in,
    const unsigned char *pub_seed, uint32_t addr[8],
    const sha256ctx *hash_state_seeded) {

    unsigned char buf[SHA256_ADDR_BYTES + FORS_TREES * N];
    thash(
        out, buf, in, FORS_TREES, pub_seed, addr, hash_state_seeded);
}
