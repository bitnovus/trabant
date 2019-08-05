#!/bin/bash

FUNCTIONS="[
'_crypto_box_curve25519xsalsa20poly1305_tweet_keypair',
'_crypto_box_curve25519xsalsa20poly1305_tweet_beforenm',
'_crypto_box_curve25519xsalsa20poly1305_tweet_afternm',
'_crypto_box_curve25519xsalsa20poly1305_tweet_open_afternm',
'_crypto_onetimeauth_poly1305_tweet',
'_crypto_onetimeauth_poly1305_tweet_verify',
'_crypto_sign_ed25519_tweet',
'_crypto_sign_ed25519_tweet_open',
'_crypto_sign_ed25519_tweet_keypair',
'_malloc',
'_calloc',
'_free',
'_memset',
'_memcpy',
'cwrap',

'_scrypt_js',

'_sha3_digest_js',
'_sha3_hmac_js',

'_chacha20_init_js',
'_chacha20_xor_blocks_js',
'_chacha20_free_js',

'_poly1305_init_js',
'_poly1305_update_js',
'_poly1305_final_js',

'_skein_context_size_js',
'_skein_hash_update_js',
'_skein_hash_final_js',

'_skein_cipher_init_js',
'_skein_xor_block_js',
'_skein_xor_blocks_js',

'_skein_hash_init_js',
'_skein_hmac_init_js',

'_skein_hash_once_js',
'_skein_pbkdf_js',

'_LEGACY_skein_cipher_init_js',
'_LEGACY_skein_xor_block_js',
'_LEGACY_skein_hmac_init_js',
'_LEGACY_skein_pbkdf_js',
'_LEGACY_skein_hash_once_js',
]"

emcc \
  -DLEGACY_SUPPORT \
  -Wall -pedantic \
  -O3 \
  -Iskein \
  -Ipoly1305-donna \
  -Iscrypt \
  -Ichacha20 \
  -Isha3 \
  --llvm-lto 3 \
  --memory-init-file 0 \
  -s ASSERTIONS=1 \
  -s NO_DYNAMIC_EXECUTION=1 \
  -s TOTAL_MEMORY=67108864 \
  -s NO_EXIT_RUNTIME=1 \
  -s EXPORTED_FUNCTIONS="${FUNCTIONS}" \
  -s ALLOW_MEMORY_GROWTH=0 \
  --js-library randombytes.js \
  -o trabant.min.js \
  -DHAVE_CONFIG_H \
  scrypt/crypto_scrypt-nosse.c scrypt/sha256.c \
  poly1305-donna/poly1305-donna.c \
  skein/skein_block.c skein/skein.c \
  chacha20/chacha20.c \
  sha3/keccak-tiny-unrolled.c sha3/safebfuns.c \
  tweetnacl.c \
  pkc_skein.c \
  trabant.c

cp trabant.min.js ../web/app/static/js/trabant20160317.min.js
