#include <stdint.h>
#include <string.h>

#include "address.h"
#include "params.h"
#include "thash.h"

#include "fips202.h"

/**
 * Takes an array of inblocks concatenated arrays of N bytes.
 */
static void thash(
    unsigned char *out, unsigned char *buf,
    const unsigned char *in, unsigned int inblocks,
    const unsigned char *pub_seed, uint32_t addr[8]) {

    unsigned char *bitmask = buf + N + ADDR_BYTES;
    unsigned int i;

    memcpy(buf, pub_seed, N);
    addr_to_bytes(buf + N, addr);

    shake256(bitmask, inblocks * N, buf, N + ADDR_BYTES);

    for (i = 0; i < inblocks * N; i++) {
        buf[N + ADDR_BYTES + i] = in[i] ^ bitmask[i];
    }

    shake256(out, N, buf, N + ADDR_BYTES + inblocks * N);
}

/* The wrappers below ensure that we use fixed-size buffers on the stack */

void thash_1(
    unsigned char *out, const unsigned char *in,
    const unsigned char *pub_seed, uint32_t addr[8],
    const hash_state *hash_state_seeded) {

    unsigned char buf[N + ADDR_BYTES + 1 * N];
    thash(
        out, buf, in, 1, pub_seed, addr);

    (void)hash_state_seeded;  /* Avoid unused parameter warning. */
}

void thash_2(
    unsigned char *out, const unsigned char *in,
    const unsigned char *pub_seed, uint32_t addr[8],
    const hash_state *hash_state_seeded) {

    unsigned char buf[N + ADDR_BYTES + 2 * N];
    thash(
        out, buf, in, 2, pub_seed, addr);

    (void)hash_state_seeded;  /* Avoid unused parameter warning. */
}

void thash_WOTS_LEN(
    unsigned char *out, const unsigned char *in,
    const unsigned char *pub_seed, uint32_t addr[8],
    const hash_state *hash_state_seeded) {

    unsigned char buf[N + ADDR_BYTES + WOTS_LEN * N];
    thash(
        out, buf, in, WOTS_LEN, pub_seed, addr);

    (void)hash_state_seeded;  /* Avoid unused parameter warning. */
}

void thash_FORS_TREES(
    unsigned char *out, const unsigned char *in,
    const unsigned char *pub_seed, uint32_t addr[8],
    const hash_state *hash_state_seeded) {

    unsigned char buf[N + ADDR_BYTES + FORS_TREES * N];
    thash(
        out, buf, in, FORS_TREES, pub_seed, addr);

    (void)hash_state_seeded;  /* Avoid unused parameter warning. */
}
