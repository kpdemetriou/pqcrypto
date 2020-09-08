#ifndef PACK_UNPACK_H
#define PACK_UNPACK_H

#include "SABER_params.h"
#include <stdint.h>
#include <stdio.h>


void pack_3bit(uint8_t *bytes, const uint16_t *data);

void un_pack3bit(const uint8_t *bytes, uint16_t *data);

void pack_4bit(uint8_t *bytes, const uint16_t *data);

void un_pack4bit(const unsigned char *bytes, uint16_t *ar);

void pack_6bit(uint8_t *bytes, const uint16_t *data);

void un_pack6bit(const unsigned char *bytes, uint16_t *data);


void BS2POL(const unsigned char *bytes, uint16_t data[SABER_N]);

void POLVEC2BS(uint8_t *bytes, uint16_t data[SABER_K][SABER_N], uint16_t modulus);

void BS2POLVEC(const unsigned char *bytes, uint16_t data[SABER_K][SABER_N], uint16_t modulus);

#endif
