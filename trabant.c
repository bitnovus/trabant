/**
 * NOTE:
 * - malloc aborts in Emscripten-space, so forget checking for null
 * - skein-1024 is deprecated, some don't trust it
 * - LEGACY skein is extremely LEGACY, i.e. should never be used unless 
 *   you need to decrypt really old PKC-internal stuff
 **/

#include <string.h>
#include "poly1305-donna.h"
#include "libscrypt.h"
#include "chacha20.h"
#include "sha3.h"
#include <stdlib.h>
#include <stdint.h>

/**
 * PBKDF: Vanilla scrypt
 **/
int scrypt_js(
    uint8_t *output,
    const uint8_t *password, const size_t password_sz,
    const uint8_t *salt, const size_t salt_sz,
    uint64_t N, uint32_t r, uint32_t p) {
  return libscrypt_scrypt(
      password, password_sz,
      salt, salt_sz,
      N, r, p,
      output, 32);
}

/**
 * PRF: Keccak-512 (SHA3 version)
 **/
void sha3_digest_js(uint8_t *output, const uint8_t *input, size_t size) {
  sha3_512(output, 64, input, size);
}

void sha3_hmac_js(uint8_t *output, const uint8_t *key, size_t key_size, const uint8_t *input, size_t input_size) {
  size_t n = key_size + input_size;
  uint8_t *buf = (uint8_t *)malloc(n);
  memcpy(buf, key, key_size);
  memcpy(buf+key_size, input, input_size);
  sha3_512(output, 64, buf, n);
}

/**
 * Stream cipher: ChaCha20
 **/
ChaCha20_Ctxt_t *chacha20_init_js(const uint8_t *key, const uint8_t *iv) {
  ChaCha20_Ctxt_t *ctxt = (ChaCha20_Ctxt_t *)malloc(sizeof(ChaCha20_Ctxt_t));
  ECRYPT_keysetup(ctxt, key, 256, 0 /* ivbits is ignored. */);
  ECRYPT_ivsetup(ctxt, iv);
  return ctxt;
}

void chacha20_xor_blocks_js(
    ChaCha20_Ctxt_t *ctxt,
    uint8_t *input,
    uint64_t start_block,
    uint64_t nbytes) {
  chacha20_set_counter(ctxt, start_block);
  ECRYPT_encrypt_bytes(ctxt, input, input, nbytes);
}

void chacha20_free_js(ChaCha20_Ctxt_t *ctxt) {
  free(ctxt);
}

/**
 * MAC: Poly1305
 **/
poly1305_context *poly1305_init_js(const uint8_t *key) {
  poly1305_context *ctxt = (poly1305_context *)malloc(sizeof(poly1305_context));
  poly1305_init(ctxt, key);
  return ctxt;
}

void poly1305_update_js(poly1305_context *ctxt, const uint8_t *message, size_t n) {
  poly1305_update(ctxt, message, n);
}

void poly1305_final_js(poly1305_context *ctxt, uint8_t *mac) {
  poly1305_finish(ctxt, mac);
  free(ctxt);
}

#ifdef LEGACY_SUPPORT
#include "pkc_skein.h"

/**
 * Buffer size calculations for Emscripten Uint8Arrays
 **/
size_t skein_context_size_js(void) {
  return sizeof(Skein1024_Ctxt_t);
}

/**
 * PRF: Skein-1024
 *
 * Symmetric Encryption: Used in CTR mode 
 * Digest
 * HMAC (keyed, not using the configuration settings in Skein paper)
 **/
void skein_cipher_init_js(
    uint8_t *ctxt_buf,
    const uint8_t *key, size_t key_sz,
    const uint8_t *iv, size_t iv_sz) {
  Skein1024_Ctxt_t ctxt;
  skein_cipher_init(&ctxt,
      key, key_sz, 
      iv, iv_sz, 
      CIPHER_PERS, CIPHER_PERS_SZ);
  memcpy(ctxt_buf, &ctxt, sizeof(Skein1024_Ctxt_t));
}

void skein_xor_block_js(
    uint8_t *ctxt_buf,
    uint8_t *output,
    const uint8_t *input,
    uint64_t offset) {
  Skein1024_Ctxt_t ctxt;
  memcpy(&ctxt, ctxt_buf, sizeof(Skein1024_Ctxt_t));
  skein_xor_block(&ctxt, output, input, offset);
}

/**
 * Added as an optimization for Emscripten, if you need to encrypt a large
 * amount of data.
 **/
void skein_xor_blocks_js(
    uint8_t *ctxt_buf,
    uint8_t *output,
    const uint8_t *input,
    uint64_t start_offset,
    uint64_t end_offset) {
  Skein1024_Ctxt_t ctxt;
  memcpy(&ctxt, ctxt_buf, sizeof(Skein1024_Ctxt_t));

  for (uint64_t i = start_offset; i < end_offset; i++) {
    skein_xor_block(&ctxt, 
        output+((i-start_offset)*SKEIN1024_BLOCK_BYTES),
        input+((i-start_offset)*SKEIN1024_BLOCK_BYTES),
        i);
  }
}

void skein_hash_init_js(uint8_t *ctxt_buf) {
  Skein1024_Ctxt_t ctxt;
  skein_hash_init(&ctxt, HASH_PERS, HASH_PERS_SZ);
  memcpy(ctxt_buf, &ctxt, sizeof(Skein1024_Ctxt_t));
}

void skein_hmac_init_js(uint8_t *ctxt_buf, const uint8_t *key, size_t key_sz) {
  Skein1024_Ctxt_t ctxt;
  skein_hmac_init(&ctxt, key, key_sz, HMAC_PERS, HMAC_PERS_SZ);
  memcpy(ctxt_buf, &ctxt, sizeof(Skein1024_Ctxt_t));
}

void skein_hash_update_js(uint8_t *ctxt_buf, const uint8_t *message, size_t message_sz) {
  Skein1024_Ctxt_t ctxt;
  memcpy(&ctxt, ctxt_buf, sizeof(Skein1024_Ctxt_t));
  skein_hash_update(&ctxt, message, message_sz);
  memcpy(ctxt_buf, &ctxt, sizeof(Skein1024_Ctxt_t));
}

void skein_hash_final_js(uint8_t *ctxt_buf, uint8_t *output) {
  Skein1024_Ctxt_t ctxt;
  memcpy(&ctxt, ctxt_buf, sizeof(Skein1024_Ctxt_t));
  skein_hash_final(&ctxt, output);
}

void skein_hash_once_js(
    uint8_t *output, 
    const uint8_t *input, size_t input_sz) {
  skein_hash_once(output, input, input_sz, HASH_PERS, HASH_PERS_SZ);
}

int skein_pbkdf_js(
    uint8_t *output,
    const uint8_t *password, size_t password_sz,
    const uint8_t *salt, size_t salt_sz,
    uint64_t N, uint32_t r, uint32_t p) {
  return skein_pbkdf(
      output, 
      password, password_sz,
      salt, salt_sz,
      PBKDF_PERS, PBKDF_PERS_SZ,
      N, r, p);
}

void LEGACY_skein_cipher_init_js(
    uint8_t *ctxt_buf, size_t message_bit_sz,
    const uint8_t *key, size_t key_sz,
    const uint8_t *iv, size_t iv_sz) {
  Skein1024_Ctxt_t ctxt;
  LEGACY_skein_cipher_init(
      &ctxt, message_bit_sz, 
      key, key_sz, 
      iv, iv_sz, 
      CIPHER_PERS, CIPHER_PERS_SZ);
  memcpy(ctxt_buf, &ctxt, sizeof(Skein1024_Ctxt_t));
}

void LEGACY_skein_xor_block_js(uint8_t *ctxt_buf, uint8_t *output, const uint8_t *input, uint64_t offset) {
  Skein1024_Ctxt_t ctxt;
  memcpy(&ctxt, ctxt_buf, sizeof(Skein1024_Ctxt_t));
  LEGACY_skein_xor_block(&ctxt, output, input, offset);
}

void LEGACY_skein_hash_once_js(
    uint8_t *output, 
    const uint8_t *input, size_t input_sz) {
  LEGACY_skein_hash_once(output, input, input_sz, HASH_PERS, HASH_PERS_SZ);
}

void LEGACY_skein_pbkdf_js(
    uint8_t *output,
    const uint8_t *password, size_t password_sz,
    const uint8_t *salt, size_t salt_sz,
    uint8_t work) {
  LEGACY_skein_pbkdf(
      output, 
      password, password_sz, 
      salt, salt_sz,
      PBKDF_PERS, PBKDF_PERS_SZ, 
      work);
}

void LEGACY_skein_pbkdf_init_js(uint8_t *ctxt_buf) {
  Skein1024_Ctxt_t ctxt;
  LEGACY_skein_pbkdf_init(&ctxt, PBKDF_PERS, PBKDF_PERS_SZ);
  memcpy(ctxt_buf, &ctxt, sizeof(Skein1024_Ctxt_t));
}

void LEGACY_skein_hash_init_js(uint8_t *ctxt_buf) {
  Skein1024_Ctxt_t ctxt;
  LEGACY_skein_hash_init(&ctxt, HASH_PERS, HASH_PERS_SZ);
  memcpy(ctxt_buf, &ctxt, sizeof(Skein1024_Ctxt_t));
}

void LEGACY_skein_hmac_init_js(uint8_t *ctxt_buf, const uint8_t *key, size_t key_sz) {
  Skein1024_Ctxt_t ctxt;
  LEGACY_skein_hmac_init(&ctxt, key, key_sz, HMAC_PERS, HMAC_PERS_SZ);
  memcpy(ctxt_buf, &ctxt, sizeof(Skein1024_Ctxt_t));
}

#endif
