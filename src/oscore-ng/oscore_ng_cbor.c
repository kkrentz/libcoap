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

/**
 * @file oscore_ng_cbor.h
 * @brief CBOR helpers
 */

#include "coap3/coap_libcoap_build.h"
#include <string.h>

void
cbor_init_writer(cbor_writer_state_t *state,
                 uint8_t *buffer, size_t buffer_size) {
  state->buffer = buffer + buffer_size;
  state->buffer_size = buffer_size;
  state->nesting_depth = CBOR_MAX_NESTING;
}

uint8_t *
cbor_stop_writer(cbor_writer_state_t *state) {
  return state->nesting_depth == CBOR_MAX_NESTING ? state->buffer : NULL;
}

static void
increment(cbor_writer_state_t *state) {
  if (state->nesting_depth == CBOR_MAX_NESTING) {
    return;
  }
  state->objects[state->nesting_depth]++;
}

static void
prepend_object(cbor_writer_state_t *state,
               const void *object, size_t object_size) {
  if (!object_size) {
    return;
  }
  if (state->buffer_size < object_size) {
    state->buffer = NULL;
    state->buffer_size = 0;
    return;
  }
  state->buffer -= object_size;
  state->buffer_size -= object_size;
  memcpy(state->buffer, object, object_size);
}

void
cbor_prepend_object(cbor_writer_state_t *state,
                    const void *object, size_t object_size) {
  prepend_object(state, object, object_size);
  increment(state);
}

static void
prepend_unsigned(cbor_writer_state_t *state, uint64_t value) {
  size_t length_to_copy;
  uint8_t jump_byte;

  /* determine size */
  if (value < CBOR_SIZE_1) {
    length_to_copy = 0;
    jump_byte = value;
  } else if (value < UINT8_MAX) {
    length_to_copy = 1;
    jump_byte = CBOR_SIZE_1;
  } else if (value < UINT16_MAX) {
    length_to_copy = 2;
    jump_byte = CBOR_SIZE_2;
  } else if (value < UINT32_MAX) {
    length_to_copy = 4;
    jump_byte = CBOR_SIZE_4;
  } else {
    length_to_copy = 8;
    jump_byte = CBOR_SIZE_8;
  }

  /* write unsigned value */
  if (state->buffer_size <= length_to_copy) {
    state->buffer = NULL;
    state->buffer_size = 0;
    return;
  }
  state->buffer_size -= length_to_copy;
#ifdef __BIG_ENDIAN__
  state->buffer -= length_to_copy;
  memcpy(state->buffer, &value, length_to_copy);
#else /* ! __BIG_ENDIAN__ */
  while (length_to_copy--) {
    state->buffer--;
    *state->buffer = value;
    value >>= 8;
  }
#endif /* ! __BIG_ENDIAN__ */
  state->buffer--;
  state->buffer_size--;
  *state->buffer = jump_byte;
}

void
cbor_prepend_unsigned(cbor_writer_state_t *state, uint64_t value) {
  prepend_unsigned(state, value);
  increment(state);
}

void
cbor_wrap_data(cbor_writer_state_t *state, size_t data_size) {
  cbor_prepend_unsigned(state, data_size);
  if (!state->buffer) {
    return;
  }
  *state->buffer |= CBOR_MAJOR_TYPE_BYTE_STRING;
}

void
cbor_prepend_data(cbor_writer_state_t *state,
                  const uint8_t *data, size_t data_size) {
  prepend_object(state, data, data_size);
  cbor_wrap_data(state, data_size);
}

void
cbor_prepend_text(cbor_writer_state_t *state,
                  const char *text, size_t text_size) {
  prepend_object(state, text, text_size);
  cbor_prepend_unsigned(state, text_size);
  if (!state->buffer) {
    return;
  }
  *state->buffer |= CBOR_MAJOR_TYPE_TEXT_STRING;
}

uint8_t *
cbor_open_array(cbor_writer_state_t *state) {
  if (!state->nesting_depth) {
    state->buffer = NULL;
    state->buffer_size = 0;
    return NULL;
  }
  state->objects[--state->nesting_depth] = 0;
  return state->buffer;
}

uint8_t *
cbor_wrap_array(cbor_writer_state_t *state) {
  if (state->nesting_depth == CBOR_MAX_NESTING) {
    state->buffer = NULL;
    state->buffer_size = 0;
    return NULL;
  }
  prepend_unsigned(state, state->objects[state->nesting_depth]);
  if (!state->buffer) {
    return NULL;
  }
  *state->buffer |= CBOR_MAJOR_TYPE_ARRAY;
  if (++state->nesting_depth != CBOR_MAX_NESTING) {
    state->objects[state->nesting_depth]++;
  }
  return state->buffer;
}

uint8_t *
cbor_open_map(cbor_writer_state_t *state) {
  return cbor_open_array(state);
}

uint8_t *
cbor_wrap_map(cbor_writer_state_t *state) {
  if ((state->nesting_depth == CBOR_MAX_NESTING)
      || (state->objects[state->nesting_depth] & 1)) {
    state->buffer = NULL;
    state->buffer_size = 0;
    return NULL;
  }
  prepend_unsigned(state, state->objects[state->nesting_depth] >> 1);
  if (!state->buffer) {
    return NULL;
  }
  *state->buffer |= CBOR_MAJOR_TYPE_MAP;
  if (++state->nesting_depth != CBOR_MAX_NESTING) {
    state->objects[state->nesting_depth]++;
  }
  return state->buffer;
}

static void
prepend_simple(cbor_writer_state_t *state, cbor_simple_value_t value) {
  if (!state->buffer_size) {
    state->buffer = NULL;
    return;
  }

  state->buffer--;
  state->buffer_size--;
  *state->buffer = value;
  increment(state);
}

void
cbor_prepend_null(cbor_writer_state_t *state) {
  prepend_simple(state, CBOR_SIMPLE_VALUE_NULL);
}

void
cbor_prepend_undefined(cbor_writer_state_t *state) {
  prepend_simple(state, CBOR_SIMPLE_VALUE_UNDEFINED);
}

void
cbor_prepend_bool(cbor_writer_state_t *state, int boolean) {
  prepend_simple(state,
                 boolean ? CBOR_SIMPLE_VALUE_TRUE : CBOR_SIMPLE_VALUE_FALSE);
}
