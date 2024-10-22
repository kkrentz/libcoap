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
 */

/**
 * \addtogroup crypto
 * @{
 *
 * \file
 * Adapter for uECC
 */

#include "coap3/coap_libcoap_build.h"

static struct pt protothread;

/*---------------------------------------------------------------------------*/
static int
csprng_adapter(uint8_t *dest, unsigned size) {
  return oscore_ng_csprng(dest, size);
}
/*---------------------------------------------------------------------------*/
static void
init(void) {
  uECC_set_rng(csprng_adapter);
}
/*---------------------------------------------------------------------------*/
static int
enable(const ecc_curve_t *curve) {
  if (curve != &ecc_curve_p_256) {
    return 1;
  }
  return 0;
}
/*---------------------------------------------------------------------------*/
static struct pt *
get_protothread(void) {
  return &protothread;
}
/*---------------------------------------------------------------------------*/
static
PT_THREAD(validate_public_key(
              const uint8_t *public_key,
              int *result)) {
  PT_BEGIN(&protothread);

  *result = !uECC_valid_public_key(public_key, uECC_secp256r1());

  PT_END(&protothread);
}
/*---------------------------------------------------------------------------*/
static void
compress_public_key(const uint8_t *uncompressed_public_key,
                    uint8_t *compressed_public_key) {
  uECC_compress(uncompressed_public_key,
                compressed_public_key,
                uECC_secp256r1());
}
/*---------------------------------------------------------------------------*/
static
PT_THREAD(decompress_public_key(
              uint8_t *uncompressed_public_key,
              const uint8_t *compressed_public_key,
              int *result)) {
  PT_BEGIN(&protothread);

  uECC_decompress(compressed_public_key,
                  uncompressed_public_key,
                  uECC_secp256r1());
  *result = 0;

  PT_END(&protothread);
}
/*---------------------------------------------------------------------------*/
static
PT_THREAD(sign(
              uint8_t *signature,
              const uint8_t *message_hash,
              const uint8_t *private_key,
              int *result)) {
  PT_BEGIN(&protothread);

  *result = !uECC_sign(private_key,
                       message_hash,
                       SHA_256_DIGEST_LENGTH,
                       signature,
                       uECC_secp256r1());

  PT_END(&protothread);
}
/*---------------------------------------------------------------------------*/
static
PT_THREAD(verify(
              const uint8_t *signature,
              const uint8_t *message_hash,
              const uint8_t *public_key,
              int *result)) {
  PT_BEGIN(&protothread);

  *result = !uECC_verify(public_key,
                         message_hash,
                         SHA_256_DIGEST_LENGTH,
                         signature,
                         uECC_secp256r1());

  PT_END(&protothread);
}
/*---------------------------------------------------------------------------*/
static
PT_THREAD(generate_key_pair(
              uint8_t *private_key,
              uint8_t *public_key,
              int *result)) {
  PT_BEGIN(&protothread);

  *result = !uECC_make_key(public_key,
                           private_key,
                           uECC_secp256r1());

  PT_END(&protothread);
}
/*---------------------------------------------------------------------------*/
static
PT_THREAD(generate_shared_secret(
              uint8_t *shared_secret,
              const uint8_t *private_key,
              const uint8_t *public_key,
              int *result)) {
  PT_BEGIN(&protothread);

  *result = !uECC_shared_secret(public_key,
                                private_key,
                                shared_secret,
                                uECC_secp256r1());

  PT_END(&protothread);
}
/*---------------------------------------------------------------------------*/
static
PT_THREAD(generate_fhmqv_secret(
              uint8_t *shared_secret,
              const uint8_t *static_private_key,
              const uint8_t *ephemeral_private_key,
              const uint8_t *static_public_key,
              const uint8_t *ephemeral_public_key,
              const uint8_t *d,
              const uint8_t *e,
              int *result)) {
  PT_BEGIN(&protothread);

  *result = !uECC_shared_fhmqv_secret(shared_secret,
                                      static_private_key,
                                      ephemeral_private_key,
                                      static_public_key,
                                      ephemeral_public_key,
                                      d,
                                      e,
                                      uECC_secp256r1());

  PT_END(&protothread);
}
/*---------------------------------------------------------------------------*/
static void
disable(void) {
}
/*---------------------------------------------------------------------------*/
const struct ecc_driver ecc_driver = {
  init,
  enable,
  get_protothread,
  validate_public_key,
  compress_public_key,
  decompress_public_key,
  sign,
  verify,
  generate_key_pair,
  generate_shared_secret,
  generate_fhmqv_secret,
  disable
};
/*---------------------------------------------------------------------------*/

/** @} */
