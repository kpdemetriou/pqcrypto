#ifndef SK_GEN_H
#define SK_GEN_H
/*
  This file is for secret-key generation
*/


#include "gf.h"

#include <stdint.h>

int genpoly_gen(gf * /*out*/, gf * /*f*/);
int perm_check(const uint32_t * /*p*/);

#endif

