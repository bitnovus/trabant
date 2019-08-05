#include "skein.h"
#include "libscrypt.h"
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

void Skein1024_Process_Block(Skein1024_Ctxt_t *, const uint8_t *, size_t, size_t);

static void blkxor(uint8_t *output, const uint8_t *inputA, const uint8_t *inputB, const size_t input_sz) {
  size_t i;
  for (i = 0; i < input_sz; i++) {
    output[i] = inputA[i] ^ inputB[i];
  }
}

int skein_memcmp(const uint8_t *a, const uint8_t *b, size_t n) {
  uint8_t acc = 0;

  if (!a)
    return -1;
  if (!b)
    return -1;

  for (size_t i = 0; i < n; i++) {
    acc |= a[i] ^ b[i];
  }

  return acc;
}

void skein_crypto_init(
    Skein1024_Ctxt_t *ctx, const size_t message_bit_sz,
    const uint8_t *key, const size_t key_sz,
    const uint8_t *iv, const size_t iv_sz, 
    const uint8_t *personalization, const size_t personalization_sz) {
  Skein1024_Init(ctx, message_bit_sz);
  if (key && key_sz > 0) {
    Skein1024_Update(ctx, key, key_sz);
  }
  if (iv && iv_sz > 0) {
    Skein1024_Update(ctx, iv, key_sz);
  }
  if (personalization && personalization_sz > 0) {
    Skein1024_Update(ctx, personalization, personalization_sz);
  }
}

void skein_cipher_init(
    Skein1024_Ctxt_t *ctxt,
    const uint8_t *key, const size_t key_sz,
    const uint8_t *iv, const size_t iv_sz,
    const uint8_t *personalization, const size_t personalization_sz) {
  // 2^64-1 for message length as per Skein spec when running in CTR mode
  skein_crypto_init(ctxt, -1, key, key_sz, iv, iv_sz, personalization, personalization_sz);

  ctxt->h.T[1] |= SKEIN_T1_FLAG_FINAL;
  if (ctxt->h.bCnt < SKEIN1024_BLOCK_BYTES) {
    memset(&ctxt->b[ctxt->h.bCnt], 0, SKEIN1024_BLOCK_BYTES - ctxt->h.bCnt);
  }

  Skein1024_Process_Block(ctxt, ctxt->b, 1, ctxt->h.bCnt);

  memset(ctxt->b, 0, sizeof(ctxt->b));
}

void skein_xor_block(Skein1024_Ctxt_t *ctx, uint8_t *output, const uint8_t *input, const uint64_t offset) {
  uint64_t X[SKEIN1024_STATE_WORDS];

  // store counter mode key
  memcpy(X, ctx->X, sizeof(X));

  // build counter block
  uint64_t ctr = Skein_Swap64(offset);
  memcpy(ctx->b, &ctr, sizeof(uint64_t));
  Skein_Start_New_Type(ctx, OUT_FINAL);

  // run CTR mode
  Skein1024_Process_Block(ctx, ctx->b, 1, sizeof(uint64_t));

  // output CTR mode
  Skein_Put64_LSB_First(output, ctx->X, SKEIN1024_BLOCK_BYTES); 
  blkxor(output, input, output, SKEIN1024_BLOCK_BYTES);

  // restore counter mode key
  memcpy(ctx->X, X, sizeof(X));
}

void skein_hmac_init(
    Skein1024_Ctxt_t *ctxt,
    const uint8_t *key, const size_t key_sz,
    const uint8_t *personalization, const size_t personalization_sz) {
  skein_crypto_init(
      ctxt, SKEIN1024_STATE_BITS,
      key, key_sz,
      NULL, 0,
      personalization, personalization_sz);
}

void skein_hash_init(Skein1024_Ctxt_t *ctx, const uint8_t *personalization, const size_t personalization_sz) {
  skein_crypto_init(
      ctx, SKEIN1024_STATE_BITS,
      NULL, 0, 
      NULL, 0, 
      personalization, personalization_sz);
}

void skein_hash_update(Skein1024_Ctxt_t *ctx, const uint8_t *message, const size_t message_sz) {
  Skein1024_Update(ctx, message, message_sz);
}

void skein_hash_final(Skein1024_Ctxt_t *ctx, uint8_t *output) {
  Skein1024_Final(ctx, output);
}

void skein_hash_once(
    uint8_t *output, 
    const uint8_t *input, const size_t input_sz,
    const uint8_t *personalization, const size_t personalization_sz) {
  Skein1024_Ctxt_t ctx;
  skein_hash_init(&ctx, personalization, personalization_sz);
  skein_hash_update(&ctx, input, input_sz);
  skein_hash_final(&ctx, output);
}

int skein_pbkdf(
    uint8_t *output,
    const uint8_t *password, const size_t password_sz,
    const uint8_t *salt, const size_t salt_sz,
    const uint8_t *personalization, const size_t personalization_sz,
    uint64_t N, uint32_t r, uint32_t p) {
  uint8_t hashed_password[SKEIN1024_BLOCK_BYTES];
  uint8_t hashed_salt[SKEIN1024_BLOCK_BYTES];
  uint8_t pbkdf_output[32];

  skein_hash_once(hashed_password, password, password_sz, personalization, personalization_sz);
  skein_hash_once(hashed_salt, salt, salt_sz, personalization, personalization_sz);

  int result = libscrypt_scrypt(
      hashed_password, sizeof(hashed_password),
      hashed_salt, sizeof(hashed_salt),
      N, r, p,
      pbkdf_output, sizeof(pbkdf_output));

  if (result == 0) {
    skein_hash_once(output, pbkdf_output, sizeof(pbkdf_output), personalization, personalization_sz);
  }

  return result;
}

/**************************************************************************************************
 * This is a non-standard way to initialize skein used in some old applications at PKC. This should 
 * never be used unless decrypting a legacy blob.
 * If you are using in anything but pre-public release Balboa, just compile without legacy.
 **************************************************************************************************/
#ifdef LEGACY_SUPPORT
#pragma message "legacy crypto is deprecated"

enum ubi_node_type {
  KEY,
  CFG_FINAL,
  PERS,
  NONCE
};

static void ubi_node(Skein1024_Ctxt_t *ctx, enum ubi_node_type type, const uint8_t *input, const size_t input_sz) {
  size_t i;

  union {
    uint8_t bytes[SKEIN1024_STATE_BYTES];
    uint64_t words[SKEIN1024_STATE_WORDS];
  } ubi_swap;
  memset(&ubi_swap, 0, sizeof(ubi_swap));

  switch (type) {
    case KEY:
      Skein_Start_New_Type(ctx, KEY);
      break;
    case CFG_FINAL:
      Skein_Start_New_Type(ctx, CFG_FINAL);
      break;
    case PERS:
      Skein_Start_New_Type(ctx, PERS);
      break;
    case NONCE:
      Skein_Start_New_Type(ctx, NONCE);
      break;
  }

  Skein1024_Update(ctx, input, input_sz);
  Skein1024_Final_Pad(ctx, ubi_swap.bytes);
  memcpy(ctx->X, ubi_swap.bytes, sizeof(ubi_swap.bytes));

  for (i = 0; i < SKEIN1024_STATE_WORDS; i++) {
    ctx->X[i] = Skein_Swap64(ctx->X[i]);
  }
}

void LEGACY_skein_crypto_init(
    Skein1024_Ctxt_t *ctx, size_t message_bit_sz,
    const uint8_t *key, const size_t key_sz,
    const uint8_t *iv, const size_t iv_sz, 
    const uint8_t *personalization, const size_t personalization_sz) {

  union {
    uint8_t bytes[SKEIN1024_STATE_BYTES];
    uint64_t words[SKEIN1024_STATE_WORDS];
  } config;
  memset(&config, 0, sizeof(config));

  memset(ctx, 0, sizeof(Skein1024_Ctxt_t));

  ctx->h.hashBitLen = Skein_Swap64(message_bit_sz);

  config.words[0] = Skein_Swap64(SKEIN_SCHEMA_VER);
  config.words[1] = Skein_Swap64(ctx->h.hashBitLen);
  config.words[2] = Skein_Swap64(SKEIN_CFG_TREE_INFO_SEQUENTIAL);

  if (key != NULL || key_sz == 0) {
    ubi_node(ctx, KEY, key, key_sz);
  }

  if (iv != NULL || iv_sz == 0) {
    ubi_node(ctx, NONCE, iv, iv_sz);
  }

  if (personalization != NULL || personalization_sz == 0) {
    ubi_node(ctx, PERS, personalization, personalization_sz);
  }

  Skein1024_Process_Block(ctx, config.bytes, 1, SKEIN_CFG_STR_LEN);
}

void LEGACY_skein_xor_block(Skein1024_Ctxt_t *ctx, uint8_t *output, const uint8_t *input, const uint64_t offset) {
  uint64_t counter = Skein_Swap64(offset);
  memcpy(ctx->b, &counter, sizeof(uint64_t));
  Skein1024_Process_Block(ctx, ctx->b, 1, offset);

  Skein_Put64_LSB_First(output, ctx->X, SKEIN1024_BLOCK_BYTES); 
  blkxor(output, input, output, SKEIN1024_BLOCK_BYTES);
}

void LEGACY_skein_cipher_init(
    Skein1024_Ctxt_t *ctxt, const size_t message_bit_sz,
    const uint8_t *key, const size_t key_sz,
    const uint8_t *iv, const size_t iv_sz,
    const uint8_t *personalization, const size_t personalization_sz) {
  LEGACY_skein_crypto_init(ctxt, message_bit_sz, key, key_sz, iv, iv_sz, personalization, personalization_sz);
}

void LEGACY_skein_hmac_init(
    Skein1024_Ctxt_t *ctxt,
    const uint8_t *key, const size_t key_sz,
    const uint8_t *personalization, const size_t personalization_sz) {
  LEGACY_skein_crypto_init(
      ctxt, SKEIN1024_STATE_BITS,
      key, key_sz,
      NULL, 0,
      personalization, personalization_sz);
}

void LEGACY_skein_hash_init(Skein1024_Ctxt_t *ctx, const uint8_t *personalization, const size_t personalization_sz) {
  LEGACY_skein_crypto_init(
      ctx, SKEIN1024_STATE_BITS,
      NULL, 0, 
      NULL, 0, 
      personalization, personalization_sz);
}

void LEGACY_skein_hash_once(
    uint8_t *output, 
    const uint8_t *input, const size_t input_sz,
    const uint8_t *personalization, const size_t personalization_sz) {
  Skein1024_Ctxt_t ctx;
  LEGACY_skein_hash_init(&ctx, personalization, personalization_sz);
  skein_hash_update(&ctx, input, input_sz);
  skein_hash_final(&ctx, output);
}

void LEGACY_skein_pbkdf_init(
    Skein1024_Ctxt_t *ctxt,
    const uint8_t *personalization,
    const size_t personalization_sz) {
  LEGACY_skein_hash_init(ctxt, personalization, personalization_sz);
}

void LEGACY_skein_pbkdf(
    uint8_t *output,
    const uint8_t *password, const size_t password_sz,
    const uint8_t *salt, const size_t salt_sz,
    const uint8_t *personalization, const size_t personalization_sz,
    const uint8_t work) {
  Skein1024_Ctxt_t ctxt;
  uint64_t iterations;
  iterations = 1 << work;

  memset(&ctxt, 0, sizeof(Skein1024_Ctxt_t));

  LEGACY_skein_pbkdf_init(&ctxt, personalization, personalization_sz);
  for (uint64_t i = 0; i < iterations; i++) {
    skein_hash_update(&ctxt, password, password_sz);
    skein_hash_update(&ctxt, salt, salt_sz);
  }
  skein_hash_final(&ctxt, output);
}

#endif
