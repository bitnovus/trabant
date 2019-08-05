#ifndef PKC_SKEIN_H
#define PKC_SKEIN_H

#include "skein.h"
#include <stdint.h>

#define UINT8IFY(X) ((uint8_t *)(X))

#define CIPHER_PERS_STR "PKC:Skein1024:nemo me impune lacessit"
#define CIPHER_PERS UINT8IFY(CIPHER_PERS_STR)
#define CIPHER_PERS_SZ sizeof(CIPHER_PERS_STR)-1

#define HASH_PERS_STR "PKC:Skein1024:HASH"
#define HASH_PERS UINT8IFY(HASH_PERS_STR)
#define HASH_PERS_SZ sizeof(HASH_PERS_STR)-1

#define HMAC_PERS_STR "PKC:Skein1024:HASH"
#define HMAC_PERS UINT8IFY(HMAC_PERS_STR)
#define HMAC_PERS_SZ sizeof(HMAC_PERS_STR)-1

#define PBKDF_PERS_STR "PKC:Skein1024:PBKDF"
#define PBKDF_PERS UINT8IFY(PBKDF_PERS_STR)
#define PBKDF_PERS_SZ sizeof(PBKDF_PERS_STR)-1

int skein_memcmp(const uint8_t *, const uint8_t *, size_t);

void skein_crypto_init(
    Skein1024_Ctxt_t *, size_t,
    const uint8_t *, const size_t,
    const uint8_t *, const size_t, 
    const uint8_t *, const size_t);

void skein_xor_block(
    Skein1024_Ctxt_t *,
    uint8_t *,
    const uint8_t *,
    const uint64_t);

void skein_hash_once(
    uint8_t *,
    const uint8_t *, const size_t,
    const uint8_t *, const size_t);

int skein_pbkdf(
    uint8_t *,
    const uint8_t *, const size_t,
    const uint8_t *, const size_t,
    const uint8_t *, const size_t,
    uint64_t, uint32_t, uint32_t);

void skein_cipher_init(
    Skein1024_Ctxt_t *, 
    const uint8_t *, const size_t,
    const uint8_t *, const size_t,
    const uint8_t *, const size_t);

void skein_hmac_init(
    Skein1024_Ctxt_t *,
    const uint8_t *, const size_t,
    const uint8_t *, const size_t);

void skein_hash_init(
    Skein1024_Ctxt_t *,
    const uint8_t *personalization, const size_t personalization_sz);

void skein_hash_update(
    Skein1024_Ctxt_t *, 
    const uint8_t *, const size_t);

void skein_hash_final(
    Skein1024_Ctxt_t *,
    uint8_t *);

#ifdef LEGACY_SUPPORT

void LEGACY_skein_crypto_init(
    Skein1024_Ctxt_t *, size_t,
    const uint8_t *, const size_t,
    const uint8_t *, const size_t, 
    const uint8_t *, const size_t);

void LEGACY_skein_xor_block(
    Skein1024_Ctxt_t *,
    uint8_t *,
    const uint8_t *,
    const uint64_t);

void LEGACY_skein_cipher_init(
    Skein1024_Ctxt_t *, const size_t,
    const uint8_t *, const size_t,
    const uint8_t *, const size_t,
    const uint8_t *, const size_t);

void LEGACY_skein_hmac_init(
    Skein1024_Ctxt_t *,
    const uint8_t *, const size_t,
    const uint8_t *, const size_t);

void LEGACY_skein_hash_init(
    Skein1024_Ctxt_t *,
    const uint8_t *,
    const size_t);

void LEGACY_skein_hash_once(
    uint8_t *, 
    const uint8_t *, const size_t,
    const uint8_t *, const size_t);

void LEGACY_skein_pbkdf_init(
    Skein1024_Ctxt_t *,
    const uint8_t *,
    const size_t);

void LEGACY_skein_pbkdf(
    uint8_t *,
    const uint8_t *, const size_t,
    const uint8_t *, const size_t,
    const uint8_t *, const size_t,
    const uint8_t);

#endif

#endif
