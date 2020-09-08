#ifndef RANDOMBYTES_H
#define RANDOMBYTES_H
#include <stdint.h>

#ifdef _WIN32
#include <CRTDEFS.H>
#else
#ifdef __APPLE__
#include <stdlib.h>
#include <stddef.h>
#else /* __APPLE__ */
#include <unistd.h>
#endif /* __APPLE__ */
#endif

int randombytes(uint8_t *buf, size_t n);

#endif
