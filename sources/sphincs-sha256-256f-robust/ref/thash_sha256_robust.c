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
    unsigned char *bitmask = buf + N + SHA256_ADDR_BYTES + 4;
    sha256ctx sha2_state;
    unsigned int i;

    memcpy(buf, pub_seed, N);
    compress_address(buf + N, addr);
    /* MGF1 requires us to have 4 extra bytes in 'buf' */
    mgf1(bitmask, inblocks * N, buf, N + SHA256_ADDR_BYTES);

    /* Retrieve precomputed state containing pub_seed */
    sha256_inc_ctx_clone(&sha2_state, hash_state_seeded);

    for (i = 0; i < inblocks * N; i++) {
        buf[N + SHA256_ADDR_BYTES + i] = in[i] ^ bitmask[i];
    }

    sha256_inc_finalize(outbuf, &sha2_state, buf + N,
                        SHA256_ADDR_BYTES + inblocks * N);
    memcpy(out, outbuf, N);
}

/* The wrappers below ensure that we use fixed-size buffers on the stack */

void thash_1(
    unsigned char *out, const unsigned char *in,
    const unsigned char *pub_seed, uint32_t addr[8],
    const sha256ctx *hash_state_seeded) {

    unsigned char buf[N + SHA256_ADDR_BYTES + 4 + 1 * N];
    thash(
        out, buf, in, 1, pub_seed, addr, hash_state_seeded);
}

void thash_2(
    unsigned char *out, const unsigned char *in,
    const unsigned char *pub_seed, uint32_t addr[8],
    const sha256ctx *hash_state_seeded) {

    unsigned char buf[N + SHA256_ADDR_BYTES + 4 + 2 * N];
    thash(
        out, buf, in, 2, pub_seed, addr, hash_state_seeded);
}

void thash_WOTS_LEN(
    unsigned char *out, const unsigned char *in,
    const unsigned char *pub_seed, uint32_t addr[8],
    const sha256ctx *hash_state_seeded) {

    unsigned char buf[N + SHA256_ADDR_BYTES + 4 + WOTS_LEN * N];
    thash(
        out, buf, in, WOTS_LEN, pub_seed, addr, hash_state_seeded);
}

void thash_FORS_TREES(
    unsigned char *out, const unsigned char *in,
    const unsigned char *pub_seed, uint32_t addr[8],
    const sha256ctx *hash_state_seeded) {

    unsigned char buf[N + SHA256_ADDR_BYTES + 4 + FORS_TREES * N];
    thash(
        out, buf, in, FORS_TREES, pub_seed, addr, hash_state_seeded);
}
