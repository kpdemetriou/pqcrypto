#ifndef VEC_H
#define VEC_H

#include "params.h"

#include <stdint.h>

typedef uint64_t vec;

vec vec_setbits(vec b);

vec vec_set1_16b(uint16_t v);

void vec_copy(vec *out, const vec *in);

vec vec_or_reduce(const vec *a);

int vec_testz(vec a);

void vec_mul(vec * /*h*/, const vec * /*f*/, const vec * /*g*/);
void vec_sq(vec * /*out*/, const vec * /*in*/);
void vec_inv(vec * /*out*/, const vec * /*in*/);

#endif

