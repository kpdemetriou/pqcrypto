#ifndef BENES_H
#define BENES_H
/*
  This file is for Benes network related functions
*/


#include "gf.h"

void apply_benes(unsigned char * /*r*/, const unsigned char * /*bits*/, int /*rev*/);
void support_gen(gf * /*s*/, const unsigned char * /*c*/);

#endif

