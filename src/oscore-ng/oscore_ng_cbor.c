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

#include "coap3/coap_internal.h"
#include <string.h>
#include <sys/types.h>

enum {
  UINT8_JUMP = 0x18,
  UINT16_JUMP = 0x19,
  UINT32_JUMP = 0x1A,
  UINT64_JUMP = 0x1B,
  BYTE_STRING_JUMP = 0x40,
  UTF_8_STRING_JUMP = 0x60,
  ARRAY_JUMP = 0x80,
  NULL_JUMP = 0xF6,
};

int
cbor_put_null(uint8_t **buffer, size_t *buffer_len) {
  if (!*buffer_len) {
    return 0;
  }
  **buffer = NULL_JUMP;
  (*buffer)++;
  (*buffer_len)--;
  return 1;
}

int
cbor_put_text(uint8_t **buffer, size_t *buffer_len,
              const char *text, uint64_t text_len) {
  uint8_t *pt = *buffer;
  if (!cbor_put_unsigned(buffer, buffer_len, text_len)) {
    return 0;
  }
  *pt |= UTF_8_STRING_JUMP;
  if (*buffer_len < text_len) {
    return 0;
  }
  memcpy(*buffer, text, text_len);
  *buffer += text_len;
  *buffer_len -= text_len;
  return 1;
}

int
cbor_put_array(uint8_t **buffer, size_t *buffer_len,
               uint64_t elements) {
  uint8_t *pt = *buffer;
  if (!cbor_put_unsigned(buffer, buffer_len, elements)) {
    return 0;
  }
  *pt |= ARRAY_JUMP;
  return 1;
}

int
cbor_put_bytes(uint8_t **buffer, size_t *buffer_len,
               const uint8_t *bytes, uint64_t bytes_len) {
  uint8_t *pt = *buffer;
  if (!cbor_put_unsigned(buffer, buffer_len, bytes_len)) {
    return 0;
  }
  *pt |= BYTE_STRING_JUMP;
  if (*buffer_len < bytes_len) {
    return 0;
  }
  memcpy(*buffer, bytes, bytes_len);
  *buffer += bytes_len;
  *buffer_len -= bytes_len;
  return 1;
}

int
cbor_put_unsigned(uint8_t **buffer, size_t *buffer_len,
                  uint64_t value) {
  /* write jump byte */
  if (!*buffer_len) {
    return 0;
  }
  size_t length_to_copy;
  if (value < UINT8_JUMP) {
    length_to_copy = 0;
    **buffer = value;
  } else if (value < UINT8_MAX) {
    length_to_copy = sizeof(uint8_t);
    **buffer = UINT8_JUMP;
  } else if (value < UINT16_MAX) {
    length_to_copy = sizeof(uint16_t);
    **buffer = UINT16_JUMP;
  } else if (value < UINT32_MAX) {
    length_to_copy = sizeof(uint32_t);
    **buffer = UINT32_JUMP;
  } else {
    length_to_copy = sizeof(uint64_t);
    **buffer = UINT64_JUMP;
  }
  (*buffer)++;
  (*buffer_len)--;
  if (!length_to_copy) {
    return 1;
  }

  /* write unsigned value */
  if (*buffer_len < length_to_copy) {
    return 0;
  }
  size_t i = length_to_copy;
  while (i--) {
    (*buffer)[i] = value;
    value >>= 8;
  }
  *buffer += length_to_copy;
  *buffer_len -= length_to_copy;
  return 1;
}
