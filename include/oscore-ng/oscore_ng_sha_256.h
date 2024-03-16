/*
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
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 *
 */

#ifndef OSCORE_NG_SHA_256_H_
#define OSCORE_NG_SHA_256_H_

#include <stddef.h>
#include <stdint.h>

#define SHA_256_DIGEST_LENGTH 32
#define SHA_256_BLOCK_SIZE 64

#ifdef SHA_256_CONF
#define SHA_256 SHA_256_CONF
#else /* SHA_256_CONF */
#define SHA_256 sha_256_driver
#endif /* SHA_256_CONF */

typedef struct {
  uint64_t bit_count;
  uint32_t state[SHA_256_DIGEST_LENGTH / sizeof(uint32_t)];
  uint8_t buf[SHA_256_BLOCK_SIZE];
} sha_256_context_t;

typedef struct sha_256_hmac_context_t {
  sha_256_context_t ctx;
  uint8_t opad[SHA_256_BLOCK_SIZE];
  int is_error_free;
} sha_256_hmac_context_t;

/**
 * Structure of SHA-256 drivers.
 */
struct sha_256_driver {

  /**
   * Starts a hash session.
   *
   * @param ctx Pointer to the hash state to initialize.
   */
  void (* init)(sha_256_context_t *ctx);

  /**
   * Processes a chunk of data.
   *
   * @param ctx  Pointer to the hash state.
   * @param data Pointer to the data to hash.
   * @param len  Length of the data to hash in bytes.
   */
  void (* update)(sha_256_context_t *ctx,
                  const uint8_t *data, size_t len);

  /**
   * Aborts a hash session.
   *
   * @param ctx Pointer to the hash state.
   */
  void (* cancel)(sha_256_context_t *ctx);

  /**
   * Terminates a hash session and produces the digest.
   *
   * @param ctx    Pointer to the hash state.
   * @param digest Pointer to the hash value.
   *
   * @return       @c 1 on success, or @c 0 otherwise.
   */
  int (* finalize)(sha_256_context_t *ctx,
                   uint8_t digest[SHA_256_DIGEST_LENGTH]);

  /**
   * Does init, update, and finalize at once.
   *
   * @param data   Pointer to the data to hash.
   * @param len    Length of @c data in bytes.
   * @param digest Pointer to the hash value.
   *
   * @return       @c 1 on success, or @c 0 otherwise.
   */
  int (* hash)(const uint8_t *data, size_t len,
               uint8_t digest[SHA_256_DIGEST_LENGTH]);
};

extern const struct sha_256_driver SHA_256;

/**
 * Generic implementation of sha_256_driver#hash.
 *
 * @param data   Pointer to the data to hash.
 * @param len    Length of @c data in bytes.
 * @param digest Pointer to the hash value.
 *
 * @return       @c 1 on success, or @c 0 otherwise.
 */
int sha_256_hash(const uint8_t *data, size_t len,
                 uint8_t digest[SHA_256_DIGEST_LENGTH]);

/**
 * Initiates a stepwise HMAC-SHA-256 computation.
 *
 * @param hmac_ctx Pointer to the HMAC state.
 * @param key      The key to authenticate with.
 * @param key_len  Length of @c key in bytes.
 */
void sha_256_hmac_init(sha_256_hmac_context_t *hmac_ctx,
                       const uint8_t *key, size_t key_len);

/**
 * Proceeds with the computation of an HMAC-SHA-256.
 *
 * @param hmac_ctx Pointer to the HMAC state.
 * @param data     Further data to authenticate.
 * @param data_len Length of @c data in bytes.
 */
void sha_256_hmac_update(sha_256_hmac_context_t *hmac_ctx,
                         const uint8_t *data, size_t data_len);

/**
 * Finishes the computation of an HMAC-SHA-256.
 *
 * @param hmac_ctx Pointer to the HMAC state.
 * @param hmac     Pointer to where the resulting HMAC shall be stored.
 *
 * @return     @c 1 on success, or @c 0 otherwise.
 */
int sha_256_hmac_finish(sha_256_hmac_context_t *hmac_ctx,
                        uint8_t hmac[SHA_256_DIGEST_LENGTH]);

/**
 * Computes HMAC-SHA-256 as per RFC 2104.
 *
 * @param key      The key to authenticate with.
 * @param key_len  Length of @c key in bytes.
 * @param data     The data to authenticate.
 * @param data_len Length of @c data in bytes.
 * @param hmac     Pointer to where the resulting HMAC shall be stored.
 *
 * @return         @c 1 on success, or @c 0 otherwise.
 */
int sha_256_hmac(const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t hmac[SHA_256_DIGEST_LENGTH]);

/**
 * Extracts a key as per RFC 5869.
 *
 * @param salt     Optional salt value.
 * @param salt_len Length of @c salt in bytes.
 * @param ikm      Input keying material.
 * @param ikm_len  Length of @c ikm in bytes.
 * @param prk      Pointer to where the extracted key shall be stored.
 *
 * @return         @c 1 on success, or @c 0 otherwise.
 */
int sha_256_hkdf_extract(const uint8_t *salt, size_t salt_len,
                         const uint8_t *ikm, size_t ikm_len,
                         uint8_t prk[SHA_256_DIGEST_LENGTH]);

/**
 * Expands a key as per RFC 5869.
 *
 * @param prk      A pseudorandom key of at least SHA_256_DIGEST_LENGTH bytes.
 * @param prk_len  Length of @c prk in bytes.
 * @param info     Optional context and application specific information.
 * @param info_len Length of @c info in bytes.
 * @param okm      Output keying material.
 * @param okm_len  Length of @c okm in bytes (<= 255 * SHA_256_DIGEST_LENGTH).
 *
 * @return         @c 1 on success, or @c 0 otherwise.
 */
int sha_256_hkdf_expand(const uint8_t *prk, size_t prk_len,
                        const uint8_t *info, size_t info_len,
                        uint8_t *okm, uint_fast16_t okm_len);

/**
 * Performs both extraction and expansion as per RFC 5869.
 *
 * @param salt     Optional salt value.
 * @param salt_len Length of @c salt in bytes
 * @param ikm      Input keying material.
 * @param ikm_len  Length of @c ikm in bytes.
 * @param info     Optional context and application specific information.
 * @param info_len Length of @c info in bytes.
 * @param okm      Output keying material.
 * @param okm_len  Length of @c okm in bytes (<= 255 * SHA_256_DIGEST_LENGTH).
 *
 * @return         @c 1 on success, or @c 0 otherwise.
 */
int sha_256_hkdf(const uint8_t *salt, size_t salt_len,
                 const uint8_t *ikm, size_t ikm_len,
                 const uint8_t *info, size_t info_len,
                 uint8_t *okm, uint_fast16_t okm_len);

#endif /* OSCORE_NG_SHA_256_H_ */
