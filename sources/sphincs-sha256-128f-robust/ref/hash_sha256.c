#include <stdint.h>
#include <string.h>

#include "address.h"
#include "hash.h"
#include "params.h"
#include "utils.h"

#include "sha2.h"
#include "sha256.h"

/* For SHA256, there is no immediate reason to initialize at the start,
   so this function is an empty operation. */
void initialize_hash_function(
    hash_state *hash_state_seeded,
    const unsigned char *pub_seed, const unsigned char *sk_seed) {
    seed_state(hash_state_seeded, pub_seed);
    (void)sk_seed; /* Suppress an 'unused parameter' warning. */
}

/* Clean up hash state */
void destroy_hash_function(hash_state *hash_state_seeded) {
    sha256_inc_ctx_release(hash_state_seeded);
}

/*
 * Computes PRF(key, addr), given a secret key of N bytes and an address
 */
void prf_addr(
    unsigned char *out, const unsigned char *key, const uint32_t addr[8],
    const hash_state *hash_state_seeded) {
    unsigned char buf[N + SHA256_ADDR_BYTES];
    unsigned char outbuf[SHA256_OUTPUT_BYTES];

    memcpy(buf, key, N);
    compress_address(buf + N, addr);

    sha256(outbuf, buf, N + SHA256_ADDR_BYTES);
    memcpy(out, outbuf, N);

    (void)hash_state_seeded; /* Prevent unused parameter warning. */
}

/**
 * Computes the message-dependent randomness R, using a secret seed as a key
 * for HMAC, and an optional randomization value prefixed to the message.
 * This requires m to have at least SHA256_BLOCK_BYTES + N space
 * available in front of the pointer, i.e. before the message to use for the
 * prefix. This is necessary to prevent having to move the message around (and
 * allocate memory for it).
 */
void gen_message_random(
    unsigned char *R,
    const unsigned char *sk_prf, const unsigned char *optrand,
    const unsigned char *m, size_t mlen, const hash_state *hash_state_seeded) {
    unsigned char buf[SHA256_BLOCK_BYTES + SHA256_OUTPUT_BYTES];
    sha256ctx state;
    int i;

    /* This implements HMAC-SHA256 */
    for (i = 0; i < N; i++) {
        buf[i] = 0x36 ^ sk_prf[i];
    }
    memset(buf + N, 0x36, SHA256_BLOCK_BYTES - N);

    sha256_inc_init(&state);
    sha256_inc_blocks(&state, buf, 1);

    memcpy(buf, optrand, N);

    /* If optrand + message cannot fill up an entire block */
    if (N + mlen < SHA256_BLOCK_BYTES) {
        memcpy(buf + N, m, mlen);
        sha256_inc_finalize(buf + SHA256_BLOCK_BYTES, &state,
                            buf, mlen + N);
    }
    /* Otherwise first fill a block, so that finalize only uses the message */
    else {
        memcpy(buf + N, m, SHA256_BLOCK_BYTES - N);
        sha256_inc_blocks(&state, buf, 1);

        m += SHA256_BLOCK_BYTES - N;
        mlen -= SHA256_BLOCK_BYTES - N;
        sha256_inc_finalize(buf + SHA256_BLOCK_BYTES, &state, m, mlen);
    }

    for (i = 0; i < N; i++) {
        buf[i] = 0x5c ^ sk_prf[i];
    }
    memset(buf + N, 0x5c, SHA256_BLOCK_BYTES - N);

    sha256(buf, buf, SHA256_BLOCK_BYTES + SHA256_OUTPUT_BYTES);
    memcpy(R, buf, N);

    (void)hash_state_seeded; /* Prevent unused parameter warning. */
}

/**
 * Computes the message hash using R, the public key, and the message.
 * Outputs the message digest and the index of the leaf. The index is split in
 * the tree index and the leaf index, for convenient copying to an address.
 */
void hash_message(
    unsigned char *digest, uint64_t *tree, uint32_t *leaf_idx,
    const unsigned char *R, const unsigned char *pk,
    const unsigned char *m, size_t mlen,
    const hash_state *hash_state_seeded) {
#define TREE_BITS (TREE_HEIGHT * (D - 1))
#define TREE_BYTES ((TREE_BITS + 7) / 8)
#define LEAF_BITS TREE_HEIGHT
#define LEAF_BYTES ((LEAF_BITS + 7) / 8)
#define DGST_BYTES (FORS_MSG_BYTES + TREE_BYTES + LEAF_BYTES)

    unsigned char seed[SHA256_OUTPUT_BYTES + 4];

    /* Round to nearest multiple of SHA256_BLOCK_BYTES */
#define INBLOCKS (((N + PK_BYTES + SHA256_BLOCK_BYTES - 1) & \
        -SHA256_BLOCK_BYTES) / SHA256_BLOCK_BYTES)
    unsigned char inbuf[INBLOCKS * SHA256_BLOCK_BYTES];

    unsigned char buf[DGST_BYTES];
    unsigned char *bufp = buf;
    sha256ctx state;

    sha256_inc_init(&state);

    memcpy(inbuf, R, N);
    memcpy(inbuf + N, pk, PK_BYTES);

    /* If R + pk + message cannot fill up an entire block */
    if (N + PK_BYTES + mlen < INBLOCKS * SHA256_BLOCK_BYTES) {
        memcpy(inbuf + N + PK_BYTES, m, mlen);
        sha256_inc_finalize(seed, &state, inbuf, N + PK_BYTES + mlen);
    }
    /* Otherwise first fill a block, so that finalize only uses the message */
    else {
        memcpy(inbuf + N + PK_BYTES, m,
               INBLOCKS * SHA256_BLOCK_BYTES - N - PK_BYTES);
        sha256_inc_blocks(&state, inbuf, INBLOCKS);

        m += INBLOCKS * SHA256_BLOCK_BYTES - N - PK_BYTES;
        mlen -= INBLOCKS * SHA256_BLOCK_BYTES - N - PK_BYTES;
        sha256_inc_finalize(seed, &state, m, mlen);
    }

    /* By doing this in two steps, we prevent hashing the message twice;
       otherwise each iteration in MGF1 would hash the message again. */
    mgf1(bufp, DGST_BYTES, seed, SHA256_OUTPUT_BYTES);

    memcpy(digest, bufp, FORS_MSG_BYTES);
    bufp += FORS_MSG_BYTES;

    *tree = bytes_to_ull(bufp, TREE_BYTES);
    *tree &= (~(uint64_t)0) >> (64 - TREE_BITS);
    bufp += TREE_BYTES;

    *leaf_idx = (uint32_t)bytes_to_ull(
                    bufp, LEAF_BYTES);
    *leaf_idx &= (~(uint32_t)0) >> (32 - LEAF_BITS);

    (void)hash_state_seeded; /* Prevent unused parameter warning. */
}
