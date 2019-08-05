#ifndef CHACHA_H
#define CHACHA_H

#include "ecrypt-sync.h"

typedef ECRYPT_ctx ChaCha20_Ctxt_t;

static inline void chacha20_set_counter(ChaCha20_Ctxt_t *ctxt, uint64_t counter) { 
  union {
    uint8_t buffer[8];
    uint64_t counter;
  } c;

  c.counter = counter;

  ctxt->input[12] = U8TO32_LITTLE(c.buffer + 0);
  ctxt->input[13] = U8TO32_LITTLE(c.buffer + 4);
}

#endif
