#ifndef PARAMS_H
#define PARAMS_H

/* Hash output length in bytes. */
#define N 24
/* Height of the hypertree. */
#define FULL_HEIGHT 64
/* Number of subtree layer. */
#define D 8
/* FORS tree dimensions. */
#define FORS_HEIGHT 16
#define FORS_TREES 14
/* Winternitz parameter, */
#define WOTS_W 16

/* The hash function is defined by linking a different hash.c file, as opposed
   to setting a #define constant. */

/* For clarity */
#define ADDR_BYTES 32

/* WOTS parameters. */
#define WOTS_LOGW 4

#define WOTS_LEN1 (8 * N / WOTS_LOGW)

/* WOTS_LEN2 is floor(log(len_1 * (w - 1)) / log(w)) + 1; we precompute */
#define WOTS_LEN2 3

#define WOTS_LEN (WOTS_LEN1 + WOTS_LEN2)
#define WOTS_BYTES (WOTS_LEN * N)
#define WOTS_PK_BYTES WOTS_BYTES

/* Subtree size. */
#define TREE_HEIGHT (FULL_HEIGHT / D)

/* FORS parameters. */
#define FORS_MSG_BYTES ((FORS_HEIGHT * FORS_TREES + 7) / 8)
#define FORS_BYTES ((FORS_HEIGHT + 1) * FORS_TREES * N)
#define FORS_PK_BYTES N

/* Resulting SPX sizes. */
#define BYTES (N + FORS_BYTES + D * WOTS_BYTES +\
        FULL_HEIGHT * N)
#define PK_BYTES (2 * N)
#define SK_BYTES (2 * N + PK_BYTES)

/* Optionally, signing can be made non-deterministic using optrand.
   This can help counter side-channel attacks that would benefit from
   getting a large number of traces when the signer uses the same nodes. */
#define OPTRAND_BYTES 32

#endif
