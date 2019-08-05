#ifndef SHA3_H
#define SHA3_H

#include "keccak-tiny.h"
#include "safebfuns.h"

#define memset_s(A,B,C,D) explicit_bzero((A),(B))

int sha3_512(uint8_t *, size_t, const uint8_t *, size_t);

#endif
