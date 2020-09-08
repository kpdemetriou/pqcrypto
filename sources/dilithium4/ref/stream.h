#ifndef STREAM_H
#define STREAM_H

#include <stdint.h>

#include "fips202.h"
#include "params.h"

void shake128_stream_init(
    shake128ctx *state, const uint8_t seed[SEEDBYTES], uint16_t nonce);

void shake256_stream_init(
    shake256ctx *state, const uint8_t seed[CRHBYTES], uint16_t nonce);

#endif
