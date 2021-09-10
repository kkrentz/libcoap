/*
 * Copyright (c) 2018, SICS, RISE AB
 * Copyright (c) 2023, Uppsala universitet
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
 */

#ifndef OSCORE_NG_CBOR_H_
#define OSCORE_NG_CBOR_H_

#include <stdint.h>
#include <stddef.h>

int cbor_put_null(uint8_t **buffer, size_t *buffer_len);
int cbor_put_text(uint8_t **buffer, size_t *buffer_len,
                  const char *text, uint64_t text_len);
int cbor_put_array(uint8_t **buffer, size_t *buffer_len,
                   uint64_t elements);
int cbor_put_bytes(uint8_t **buffer, size_t *buffer_len,
                   const uint8_t *bytes, uint64_t bytes_len);
int cbor_put_unsigned(uint8_t **buffer, size_t *buffer_len,
                      uint64_t value);

#endif /* OSCORE_NG_CBOR_H_ */
