#ifndef GF_H
#define GF_H
/*
  This file is for functions for field arithmetic
*/


#include <stdint.h>

typedef uint16_t gf;

gf gf_iszero(gf a);
gf gf_add(gf in0, gf in1);
gf gf_mul(gf in0, gf in1);
uint64_t gf_mul2(gf a, gf b0, gf b1);
gf gf_frac(gf den, gf num);
gf gf_inv(gf in);

void GF_mul(gf *out, const gf *in0, const gf *in1);

#endif

