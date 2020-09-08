#include <stdint.h>
#include <string.h>

#include "address.h"
#include "haraka.h"
#include "hash.h"
#include "params.h"
#include "utils.h"

void initialize_hash_function(
    hash_state *hash_state_seeded,
    const unsigned char *pub_seed, const unsigned char *sk_seed) {
    tweak_constants(hash_state_seeded, pub_seed, sk_seed, N);
}

/* The haraka implementation is stack based and won't be replaced in PQClean/OQS,
   so we don't need to do anything */
void destroy_hash_function(
    hash_state *hash_state_seeded) { // NOLINT(readability-non-const-parameter)
    (void)hash_state_seeded;
}

/*
 * Computes PRF(key, addr), given a secret key of N bytes and an address
 */
void prf_addr(
    unsigned char *out, const unsigned char *key, const uint32_t addr[8],
    const hash_state *hash_state_seeded) {
    unsigned char buf[ADDR_BYTES];
    /* Since N may be smaller than 32, we need a temporary buffer. */
    unsigned char outbuf[32];

    (void)key; /* Suppress an 'unused parameter' warning. */

    addr_to_bytes(buf, addr);
    haraka256_sk(outbuf, buf, hash_state_seeded);
    memcpy(out, outbuf, N);
}

/**
 * Computes the message-dependent randomness R, using a secret seed and an
 * optional randomization value as well as the message.
 */
void gen_message_random(
    unsigned char *R,
    const unsigned char *sk_prf, const unsigned char *optrand,
    const unsigned char *m, size_t mlen,
    const hash_state *hash_state_seeded) {
    uint8_t s_inc[65];

    haraka_S_inc_init(s_inc);
    haraka_S_inc_absorb(s_inc, sk_prf, N, hash_state_seeded);
    haraka_S_inc_absorb(s_inc, optrand, N, hash_state_seeded);
    haraka_S_inc_absorb(s_inc, m, mlen, hash_state_seeded);
    haraka_S_inc_finalize(s_inc);
    haraka_S_inc_squeeze(R, N, s_inc, hash_state_seeded);
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

    unsigned char buf[DGST_BYTES];
    unsigned char *bufp = buf;
    uint8_t s_inc[65];

    haraka_S_inc_init(s_inc);
    haraka_S_inc_absorb(s_inc, R, N, hash_state_seeded);
    haraka_S_inc_absorb(s_inc, pk + N, N, hash_state_seeded);
    haraka_S_inc_absorb(s_inc, m, mlen, hash_state_seeded);
    haraka_S_inc_finalize(s_inc);
    haraka_S_inc_squeeze(buf, DGST_BYTES, s_inc, hash_state_seeded);

    memcpy(digest, bufp, FORS_MSG_BYTES);
    bufp += FORS_MSG_BYTES;

    *tree = bytes_to_ull(bufp, TREE_BYTES);
    *tree &= (~(uint64_t)0) >> (64 - TREE_BITS);
    bufp += TREE_BYTES;

    *leaf_idx = (uint32_t)bytes_to_ull(
                    bufp, LEAF_BYTES);
    *leaf_idx &= (~(uint32_t)0) >> (32 - LEAF_BITS);
}
