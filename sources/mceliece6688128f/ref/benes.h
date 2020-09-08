#ifndef BENES_H
#define BENES_H
/*
  This file is for Benes network related functions
*/

#include "gf.h"

void apply_benes(uint8_t *r, const uint8_t *bits, int rev);
void support_gen(gf *s, const uint8_t *c);

#endif

