#ifndef UTIL_H
#define UTIL_H
/*
  This file is for loading/storing data in a little-endian fashion
*/


#include "gf.h"
#include <stdint.h>

void store2(unsigned char * /*dest*/, gf /*a*/);
uint16_t load2(const unsigned char * /*src*/);

uint32_t load4(const unsigned char * /*in*/);

void store8(unsigned char * /*out*/, uint64_t  /*in*/);
uint64_t load8(const unsigned char * /*in*/);

gf bitrev(gf /*a*/);

#endif

