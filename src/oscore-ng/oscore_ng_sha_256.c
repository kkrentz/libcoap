/*
 * Copyright 2005 Colin Percival
 * Copyright (c) 2021, Uppsala universitet.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "coap3/coap_libcoap_build.h"
#include <string.h>

#ifndef min
# define min(a,b) ((a) < (b) ? (a) : (b))
#endif

#ifdef __BIG_ENDIAN__
/* Copy a vector of big-endian uint32_t into a vector of bytes */
#define be32enc_vect memcpy

/* Copy a vector of bytes into a vector of big-endian uint32_t */
#define be32dec_vect memcpy

static void
be64enc(uint8_t *p, uint64_t u) {
  memcpy(p, &u, sizeof(uint64_t));
}

#else /* __BIG_ENDIAN__ */
static uint32_t
be32dec(uint8_t const *p) {
  return ((uint32_t)p[0] << 24)
         | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] << 8)
         | p[3];
}

static void
be32enc(uint8_t *p, uint32_t u) {
  p[0] = (u >> 24) & 0xff;
  p[1] = (u >> 16) & 0xff;
  p[2] = (u >> 8) & 0xff;
  p[3] = u & 0xff;
}

static void
be64enc(uint8_t *p, uint64_t u) {
  be32enc(p, (uint32_t)(u >> 32));
  be32enc(p + 4, (uint32_t)(u & 0xffffffffU));
}

/*
 * Encode a length len/4 vector of (uint32_t) into a length len vector of
 * (unsigned char) in big-endian form.  Assumes len is a multiple of 4.
 */
static void
be32enc_vect(uint8_t *dst, const uint32_t *src, size_t len) {
  size_t i;

  for (i = 0; i < len / 4; i++) {
    be32enc(dst + i * 4, src[i]);
  }
}

/*
 * Decode a big-endian length len vector of (unsigned char) into a length
 * len/4 vector of (uint32_t).  Assumes len is a multiple of 4.
 */
static void
be32dec_vect(uint32_t *dst, const uint8_t *src, size_t len) {
  size_t i;

  for (i = 0; i < len / 4; i++) {
    dst[i] = be32dec(src + i * 4);
  }
}
#endif /* __BIG_ENDIAN__ */

static const uint32_t K[64] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

/* Elementary functions used by SHA-256 */
#define Ch(x, y, z)  ((x & (y ^ z)) ^ z)
#define Maj(x, y, z) ((x & (y | z)) | (y & z))
#define SHR(x, n)    (x >> n)
#define ROTR(x, n)   ((x >> n) | (x << (32 - n)))
#define S0(x)        (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define S1(x)        (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define s0(x)        (ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3))
#define s1(x)        (ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10))

/* SHA256 round function */
#define RND(a, b, c, d, e, f, g, h, k) \
  h += S1(e) + Ch(e, f, g) + k; \
  d += h; \
  h += S0(a) + Maj(a, b, c);

/* Adjusted round function for rotating state */
#define RNDr(S, W, i, ii) \
  RND(S[(64 - i) % 8], S[(65 - i) % 8], \
      S[(66 - i) % 8], S[(67 - i) % 8], \
      S[(68 - i) % 8], S[(69 - i) % 8], \
      S[(70 - i) % 8], S[(71 - i) % 8], \
      W[i + ii] + K[i + ii])

/* Message schedule computation */
#define MSCH(W, ii, i) \
  W[i + ii + 16] = \
                   s1(W[i + ii + 14]) + W[i + ii + 9] + s0(W[i + ii + 1]) + W[i + ii]

/*---------------------------------------------------------------------------*/
/*
 * SHA-256 block compression function. The 256-bit state is transformed via
 * the 512-bit input block to produce a new state.
 */
static void
transform(uint32_t state[SHA_256_DIGEST_LENGTH / sizeof(uint32_t)],
          const uint8_t block[SHA_256_BLOCK_SIZE]) {
  uint32_t W[64];
  uint32_t S[8];
  uint_fast8_t i;

  /* 1. Prepare the first part of the message schedule W. */
  be32dec_vect(W, block, 64);

  /* 2. Initialize working variables. */
  memcpy(S, state, 32);

  /* 3. Mix. */
  for (i = 0; i < 64; i += 16) {
    RNDr(S, W, 0, i);
    RNDr(S, W, 1, i);
    RNDr(S, W, 2, i);
    RNDr(S, W, 3, i);
    RNDr(S, W, 4, i);
    RNDr(S, W, 5, i);
    RNDr(S, W, 6, i);
    RNDr(S, W, 7, i);
    RNDr(S, W, 8, i);
    RNDr(S, W, 9, i);
    RNDr(S, W, 10, i);
    RNDr(S, W, 11, i);
    RNDr(S, W, 12, i);
    RNDr(S, W, 13, i);
    RNDr(S, W, 14, i);
    RNDr(S, W, 15, i);

    if (i == 48) {
      break;
    }
    MSCH(W, 0, i);
    MSCH(W, 1, i);
    MSCH(W, 2, i);
    MSCH(W, 3, i);
    MSCH(W, 4, i);
    MSCH(W, 5, i);
    MSCH(W, 6, i);
    MSCH(W, 7, i);
    MSCH(W, 8, i);
    MSCH(W, 9, i);
    MSCH(W, 10, i);
    MSCH(W, 11, i);
    MSCH(W, 12, i);
    MSCH(W, 13, i);
    MSCH(W, 14, i);
    MSCH(W, 15, i);
  }

  /* 4. Mix local working variables into global state */
  for (i = 0; i < 8; i++) {
    state[i] += S[i];
  }
}
/*---------------------------------------------------------------------------*/
/* Add padding and terminating bit-count. */
static void
sha_256_pad(sha_256_context_t *ctx) {
  static const unsigned char PAD[64] = {
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
  };

  /* Figure out how many bytes we have buffered. */
  size_t r = (ctx->bit_count >> 3) & (SHA_256_BLOCK_SIZE - 1);

  /* Pad to 56 mod 64, transforming if we finish a block en route. */
  if (r < 56) {
    /* Pad to 56 mod 64. */
    memcpy(&ctx->buf[r], PAD, 56 - r);
  } else {
    /* Finish the current block and mix. */
    memcpy(&ctx->buf[r], PAD, SHA_256_BLOCK_SIZE - r);
    transform(ctx->state, ctx->buf);

    /* The start of the final block is all zeroes. */
    memset(&ctx->buf[0], 0, 56);
  }

  /* Add the terminating bit-count. */
  be64enc(&ctx->buf[56], ctx->bit_count);

  /* Mix in the final block. */
  transform(ctx->state, ctx->buf);
}
/*---------------------------------------------------------------------------*/
/* SHA-256 initialization. Begins a SHA-256 operation. */
static void
init(sha_256_context_t *ctx) {
  /* Zero bits processed so far */
  ctx->bit_count = 0;

  /* Magic initialization constants */
  ctx->state[0] = 0x6A09E667;
  ctx->state[1] = 0xBB67AE85;
  ctx->state[2] = 0x3C6EF372;
  ctx->state[3] = 0xA54FF53A;
  ctx->state[4] = 0x510E527F;
  ctx->state[5] = 0x9B05688C;
  ctx->state[6] = 0x1F83D9AB;
  ctx->state[7] = 0x5BE0CD19;
}
/*---------------------------------------------------------------------------*/
/* Add bytes into the hash */
static void
update(sha_256_context_t *ctx, const uint8_t *data, size_t len) {
  /* Number of bytes left in the buffer from previous updates */
  size_t r = (ctx->bit_count >> 3) & (SHA_256_BLOCK_SIZE - 1);

  /* Convert the length into a number of bits */
  uint64_t bitlen = len << 3;

  /* Update number of bits */
  ctx->bit_count += bitlen;

  /* Handle the case where we don't need to perform any transforms */
  if (len < SHA_256_BLOCK_SIZE - r) {
    memcpy(&ctx->buf[r], data, len);
    return;
  }

  /* Finish the current block */
  memcpy(&ctx->buf[r], data, SHA_256_BLOCK_SIZE - r);
  transform(ctx->state, ctx->buf);
  data += SHA_256_BLOCK_SIZE - r;
  len -= SHA_256_BLOCK_SIZE - r;

  /* Perform complete blocks */
  while (len >= 64) {
    transform(ctx->state, data);
    data += SHA_256_BLOCK_SIZE;
    len -= SHA_256_BLOCK_SIZE;
  }

  /* Copy left over data into buffer */
  memcpy(ctx->buf, data, len);
}
/*---------------------------------------------------------------------------*/
/*
 * SHA-256 finalization.  Pads the input data, exports the hash value,
 * and clears the context state.
 */
static void
finalize(sha_256_context_t *ctx, uint8_t digest[SHA_256_DIGEST_LENGTH]) {
  /* Add padding */
  sha_256_pad(ctx);

  /* Write the hash */
  be32enc_vect(digest, ctx->state, SHA_256_DIGEST_LENGTH);

  /* Clear the context state */
  memset(ctx, 0, sizeof(*ctx));
}
/*---------------------------------------------------------------------------*/
void
sha_256_hash(const uint8_t *data, size_t len,
             uint8_t digest[SHA_256_DIGEST_LENGTH]) {
  sha_256_context_t ctx;

  SHA_256.init(&ctx);
  SHA_256.update(&ctx, data, len);
  SHA_256.finalize(&ctx, digest);
}
/*---------------------------------------------------------------------------*/
void
sha_256_hmac_init(sha_256_hmac_context_t *hmac_ctx,
                  const uint8_t *key, size_t key_len) {
  uint8_t hashed_key[SHA_256_DIGEST_LENGTH];
  uint_fast8_t i;
  uint8_t ipad[SHA_256_BLOCK_SIZE];

  if (key_len > SHA_256_BLOCK_SIZE) {
    SHA_256.hash(key, key_len, hashed_key);
    key_len = SHA_256_DIGEST_LENGTH;
    key = hashed_key;
  }
  for (i = 0; i < key_len; i++) {
    ipad[i] = key[i] ^ 0x36;
    hmac_ctx->opad[i] = key[i] ^ 0x5c;
  }
  for (; i < SHA_256_BLOCK_SIZE; i++) {
    ipad[i] = 0x36;
    hmac_ctx->opad[i] = 0x5c;
  }
  SHA_256.init(&hmac_ctx->ctx);
  SHA_256.update(&hmac_ctx->ctx, ipad, sizeof(ipad));
}
/*---------------------------------------------------------------------------*/
void
sha_256_hmac_update(sha_256_hmac_context_t *hmac_ctx,
                    const uint8_t *data, size_t data_len) {
  SHA_256.update(&hmac_ctx->ctx, data, data_len);
}
/*---------------------------------------------------------------------------*/
void
sha_256_hmac_finish(sha_256_hmac_context_t *hmac_ctx,
                    uint8_t hmac[SHA_256_DIGEST_LENGTH]) {
  SHA_256.finalize(&hmac_ctx->ctx, hmac);
  SHA_256.init(&hmac_ctx->ctx);
  SHA_256.update(&hmac_ctx->ctx, hmac_ctx->opad, sizeof(hmac_ctx->opad));
  SHA_256.update(&hmac_ctx->ctx, hmac, SHA_256_DIGEST_LENGTH);
  SHA_256.finalize(&hmac_ctx->ctx, hmac);
  memset(hmac_ctx->opad, 0, sizeof(hmac_ctx->opad));
}
/*---------------------------------------------------------------------------*/
void
sha_256_hmac(const uint8_t *key, size_t key_len,
             const uint8_t *data, size_t data_len,
             uint8_t hmac[SHA_256_DIGEST_LENGTH]) {
  sha_256_hmac_context_t hmac_ctx;

  sha_256_hmac_init(&hmac_ctx, key, key_len);
  sha_256_hmac_update(&hmac_ctx, data, data_len);
  sha_256_hmac_finish(&hmac_ctx, hmac);
}
/*---------------------------------------------------------------------------*/
void
sha_256_hkdf_extract(const uint8_t *salt, size_t salt_len,
                     const uint8_t *ikm, size_t ikm_len,
                     uint8_t prk[SHA_256_DIGEST_LENGTH]) {
  sha_256_hmac(salt, salt_len, ikm, ikm_len, prk);
}
/*---------------------------------------------------------------------------*/
void
sha_256_hkdf_expand(const uint8_t *prk, size_t prk_len,
                    const uint8_t *info, size_t info_len,
                    uint8_t *okm, uint_fast16_t okm_len) {
  uint_fast8_t n;
  uint8_t i;
  sha_256_hmac_context_t hmac_ctx;
  uint8_t t_i[SHA_256_DIGEST_LENGTH];

  okm_len = min(okm_len, 255 * SHA_256_DIGEST_LENGTH);
  n = okm_len / SHA_256_DIGEST_LENGTH
      + (okm_len % SHA_256_DIGEST_LENGTH ? 1 : 0);

  for (i = 1; i <= n; i++) {
    sha_256_hmac_init(&hmac_ctx, prk, prk_len);
    if (i != 1) {
      sha_256_hmac_update(&hmac_ctx, t_i, sizeof(t_i));
    }
    sha_256_hmac_update(&hmac_ctx, info, info_len);
    sha_256_hmac_update(&hmac_ctx, &i, sizeof(i));
    sha_256_hmac_finish(&hmac_ctx, t_i);
    memcpy(okm + ((i - 1) * SHA_256_DIGEST_LENGTH),
           t_i,
           min(SHA_256_DIGEST_LENGTH, okm_len));
    okm_len -= SHA_256_DIGEST_LENGTH;
  }
}
/*---------------------------------------------------------------------------*/
void
sha_256_hkdf(const uint8_t *salt, size_t salt_len,
             const uint8_t *ikm, size_t ikm_len,
             const uint8_t *info, size_t info_len,
             uint8_t *okm, uint_fast16_t okm_len) {
  uint8_t prk[SHA_256_DIGEST_LENGTH];

  sha_256_hkdf_extract(salt, salt_len, ikm, ikm_len, prk);
  sha_256_hkdf_expand(prk, sizeof(prk), info, info_len, okm, okm_len);
}
/*---------------------------------------------------------------------------*/
const struct sha_256_driver sha_256_driver = {
  init,
  update,
  finalize,
  sha_256_hash,
};
/*---------------------------------------------------------------------------*/
