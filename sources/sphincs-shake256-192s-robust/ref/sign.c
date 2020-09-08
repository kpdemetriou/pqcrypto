#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "address.h"
#include "api.h"
#include "fors.h"
#include "hash.h"
#include "hash_state.h"
#include "params.h"
#include "randombytes.h"
#include "thash.h"
#include "utils.h"
#include "wots.h"

/**
 * Computes the leaf at a given address. First generates the WOTS key pair,
 * then computes leaf by hashing horizontally.
 */
static void wots_gen_leaf(unsigned char *leaf, const unsigned char *sk_seed,
                          const unsigned char *pub_seed,
                          uint32_t addr_idx, const uint32_t tree_addr[8],
                          const hash_state *hash_state_seeded) {
    unsigned char pk[WOTS_BYTES];
    uint32_t wots_addr[8] = {0};
    uint32_t wots_pk_addr[8] = {0};

    set_type(
        wots_addr, ADDR_TYPE_WOTS);
    set_type(
        wots_pk_addr, ADDR_TYPE_WOTSPK);

    copy_subtree_addr(
        wots_addr, tree_addr);
    set_keypair_addr(
        wots_addr, addr_idx);
    wots_gen_pk(
        pk, sk_seed, pub_seed, wots_addr, hash_state_seeded);

    copy_keypair_addr(
        wots_pk_addr, wots_addr);
    thash_WOTS_LEN(
        leaf, pk, pub_seed, wots_pk_addr, hash_state_seeded);
}

/*
 * Returns the length of a secret key, in bytes
 */
size_t crypto_sign_secretkeybytes(void) {
    return CRYPTO_SECRETKEYBYTES;
}

/*
 * Returns the length of a public key, in bytes
 */
size_t crypto_sign_publickeybytes(void) {
    return CRYPTO_PUBLICKEYBYTES;
}

/*
 * Returns the length of a signature, in bytes
 */
size_t crypto_sign_bytes(void) {
    return CRYPTO_BYTES;
}

/*
 * Returns the length of the seed required to generate a key pair, in bytes
 */
size_t crypto_sign_seedbytes(void) {
    return CRYPTO_SEEDBYTES;
}

/*
 * Generates an SPX key pair given a seed of length
 * Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [PUB_SEED || root]
 */
int crypto_sign_seed_keypair(
    uint8_t *pk, uint8_t *sk, const uint8_t *seed) {
    /* We do not need the auth path in key generation, but it simplifies the
       code to have just one treehash routine that computes both root and path
       in one function. */
    unsigned char auth_path[TREE_HEIGHT * N];
    uint32_t top_tree_addr[8] = {0};
    hash_state hash_state_seeded;

    set_layer_addr(
        top_tree_addr, D - 1);
    set_type(
        top_tree_addr, ADDR_TYPE_HASHTREE);

    /* Initialize SK_SEED, SK_PRF and PUB_SEED from seed. */
    memcpy(sk, seed, CRYPTO_SEEDBYTES);

    memcpy(pk, sk + 2 * N, N);

    /* This hook allows the hash function instantiation to do whatever
       preparation or computation it needs, based on the public seed. */
    initialize_hash_function(&hash_state_seeded, pk, sk);

    /* Compute root node of the top-most subtree. */
    treehash_TREE_HEIGHT(
        sk + 3 * N, auth_path, sk, sk + 2 * N, 0, 0,
        wots_gen_leaf, top_tree_addr, &hash_state_seeded);

    memcpy(pk + N, sk + 3 * N, N);

    destroy_hash_function(&hash_state_seeded);
    return 0;
}

/*
 * Generates an SPX key pair.
 * Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [PUB_SEED || root]
 */
int crypto_sign_keypair(
    uint8_t *pk, uint8_t *sk) {
    unsigned char seed[CRYPTO_SEEDBYTES];
    randombytes(seed, CRYPTO_SEEDBYTES);
    crypto_sign_seed_keypair(
        pk, sk, seed);

    return 0;
}

/**
 * Returns an array containing a detached signature.
 */
int crypto_sign_signature(
    uint8_t *sig, size_t *siglen,
    const uint8_t *m, size_t mlen, const uint8_t *sk) {
    const unsigned char *sk_seed = sk;
    const unsigned char *sk_prf = sk + N;
    const unsigned char *pk = sk + 2 * N;
    const unsigned char *pub_seed = pk;

    unsigned char optrand[N];
    unsigned char mhash[FORS_MSG_BYTES];
    unsigned char root[N];
    uint32_t i;
    uint64_t tree;
    uint32_t idx_leaf;
    uint32_t wots_addr[8] = {0};
    uint32_t tree_addr[8] = {0};

    hash_state hash_state_seeded;

    /* This hook allows the hash function instantiation to do whatever
       preparation or computation it needs, based on the public seed. */
    initialize_hash_function(
        &hash_state_seeded,
        pub_seed, sk_seed);

    set_type(
        wots_addr, ADDR_TYPE_WOTS);
    set_type(
        tree_addr, ADDR_TYPE_HASHTREE);

    /* Optionally, signing can be made non-deterministic using optrand.
       This can help counter side-channel attacks that would benefit from
       getting a large number of traces when the signer uses the same nodes. */
    randombytes(optrand, N);
    /* Compute the digest randomization value. */
    gen_message_random(
        sig, sk_prf, optrand, m, mlen, &hash_state_seeded);

    /* Derive the message digest and leaf index from R, PK and M. */
    hash_message(
        mhash, &tree, &idx_leaf, sig, pk, m, mlen, &hash_state_seeded);
    sig += N;

    set_tree_addr(wots_addr, tree);
    set_keypair_addr(
        wots_addr, idx_leaf);

    /* Sign the message hash using FORS. */
    fors_sign(
        sig, root, mhash, sk_seed, pub_seed, wots_addr, &hash_state_seeded);
    sig += FORS_BYTES;

    for (i = 0; i < D; i++) {
        set_layer_addr(tree_addr, i);
        set_tree_addr(tree_addr, tree);

        copy_subtree_addr(
            wots_addr, tree_addr);
        set_keypair_addr(
            wots_addr, idx_leaf);

        /* Compute a WOTS signature. */
        wots_sign(
            sig, root, sk_seed, pub_seed, wots_addr, &hash_state_seeded);
        sig += WOTS_BYTES;

        /* Compute the authentication path for the used WOTS leaf. */
        treehash_TREE_HEIGHT(
            root, sig, sk_seed, pub_seed, idx_leaf, 0,
            wots_gen_leaf, tree_addr, &hash_state_seeded);
        sig += TREE_HEIGHT * N;

        /* Update the indices for the next layer. */
        idx_leaf = (tree & ((1 << TREE_HEIGHT) - 1));
        tree = tree >> TREE_HEIGHT;
    }

    *siglen = BYTES;

    destroy_hash_function(&hash_state_seeded);
    return 0;
}

/**
 * Verifies a detached signature and message under a given public key.
 */
int crypto_sign_verify(
    const uint8_t *sig, size_t siglen,
    const uint8_t *m, size_t mlen, const uint8_t *pk) {
    const unsigned char *pub_seed = pk;
    const unsigned char *pub_root = pk + N;
    unsigned char mhash[FORS_MSG_BYTES];
    unsigned char wots_pk[WOTS_BYTES];
    unsigned char root[N];
    unsigned char leaf[N];
    unsigned int i;
    uint64_t tree;
    uint32_t idx_leaf;
    uint32_t wots_addr[8] = {0};
    uint32_t tree_addr[8] = {0};
    uint32_t wots_pk_addr[8] = {0};

    hash_state hash_state_seeded;

    if (siglen != BYTES) {
        return -1;
    }

    /* This hook allows the hash function instantiation to do whatever
       preparation or computation it needs, based on the public seed. */
    initialize_hash_function(
        &hash_state_seeded,
        pub_seed, NULL);

    set_type(
        wots_addr, ADDR_TYPE_WOTS);
    set_type(
        tree_addr, ADDR_TYPE_HASHTREE);
    set_type(
        wots_pk_addr, ADDR_TYPE_WOTSPK);

    /* Derive the message digest and leaf index from R || PK || M. */
    /* The additional N is a result of the hash domain separator. */
    hash_message(
        mhash, &tree, &idx_leaf, sig, pk, m, mlen, &hash_state_seeded);
    sig += N;

    /* Layer correctly defaults to 0, so no need to set_layer_addr */
    set_tree_addr(wots_addr, tree);
    set_keypair_addr(
        wots_addr, idx_leaf);

    fors_pk_from_sig(
        root, sig, mhash, pub_seed, wots_addr, &hash_state_seeded);
    sig += FORS_BYTES;

    /* For each subtree.. */
    for (i = 0; i < D; i++) {
        set_layer_addr(tree_addr, i);
        set_tree_addr(tree_addr, tree);

        copy_subtree_addr(
            wots_addr, tree_addr);
        set_keypair_addr(
            wots_addr, idx_leaf);

        copy_keypair_addr(
            wots_pk_addr, wots_addr);

        /* The WOTS public key is only correct if the signature was correct. */
        /* Initially, root is the FORS pk, but on subsequent iterations it is
           the root of the subtree below the currently processed subtree. */
        wots_pk_from_sig(
            wots_pk, sig, root, pub_seed, wots_addr, &hash_state_seeded);
        sig += WOTS_BYTES;

        /* Compute the leaf node using the WOTS public key. */
        thash_WOTS_LEN(
            leaf, wots_pk, pub_seed, wots_pk_addr, &hash_state_seeded);

        /* Compute the root node of this subtree. */
        compute_root(
            root, leaf, idx_leaf, 0, sig, TREE_HEIGHT,
            pub_seed, tree_addr, &hash_state_seeded);
        sig += TREE_HEIGHT * N;

        /* Update the indices for the next layer. */
        idx_leaf = (tree & ((1 << TREE_HEIGHT) - 1));
        tree = tree >> TREE_HEIGHT;
    }

    destroy_hash_function(&hash_state_seeded);
    /* Check if the root node equals the root node in the public key. */
    if (memcmp(root, pub_root, N) != 0) {
        return -1;
    }

    return 0;
}


/**
 * Returns an array containing the signature followed by the message.
 */
int crypto_sign(
    uint8_t *sm, size_t *smlen,
    const uint8_t *m, size_t mlen, const uint8_t *sk) {
    size_t siglen;

    crypto_sign_signature(
        sm, &siglen, m, mlen, sk);

    memmove(sm + BYTES, m, mlen);
    *smlen = siglen + mlen;

    return 0;
}

/**
 * Verifies a given signature-message pair under a given public key.
 */
int crypto_sign_open(
    uint8_t *m, size_t *mlen,
    const uint8_t *sm, size_t smlen, const uint8_t *pk) {
    /* The API caller does not necessarily know what size a signature should be
       but SPHINCS+ signatures are always exactly BYTES. */
    if (smlen < BYTES) {
        memset(m, 0, smlen);
        *mlen = 0;
        return -1;
    }

    *mlen = smlen - BYTES;

    if (crypto_sign_verify(
                sm, BYTES, sm + BYTES, *mlen, pk)) {
        memset(m, 0, smlen);
        *mlen = 0;
        return -1;
    }

    /* If verification was successful, move the message to the right place. */
    memmove(m, sm + BYTES, *mlen);

    return 0;
}
