/*
 * coap_bakery.c -- DoS mitigations
 *
 * Copyright (C) 2021-2023 Uppsala universitet
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_bakery.c
 * @brief DoS mitigations
 */

#include "coap3/coap_internal.h"
#include <stdint.h>
#include <string.h>

#if COAP_RAP_SUPPORT && COAP_SERVER_SUPPORT

#define INTERVAL_DURATION \
  ((OSCORE_NG_ACK_TIMEOUT /* delay from middlebox to client */ \
    + OSCORE_NG_PROCESSING_DELAY /* turnaround time */ \
    + OSCORE_NG_MAX_TRANSMIT_SPAN /* potential retransmissions */ \
    + OSCORE_NG_ACK_TIMEOUT /* delay from client to middlebox */) \
   * 10 /* from centiseconds to milliseconds */)
#define KEY_SIZE (AES_128_KEY_LENGTH)

static void handle_knock(coap_resource_t *resource,
                         coap_session_t *session,
                         const coap_pdu_t *request,
                         const coap_string_t *query,
                         coap_pdu_t *response);

static uint64_t current_interval_start;
static uint8_t current_key[KEY_SIZE];
static uint_fast8_t current_interval;
static int has_previous_key;
static uint8_t previous_key[KEY_SIZE];

static int
update_cookie_key(void) {
  uint64_t now;
  uint32_t passed_intervals;

  if (!current_interval_start) {
    coap_log_err("update_cookie_key: bakery is not open\n");
    return 0;
  }
  now = oscore_ng_generate_timestamp();
  if (!now) {
    coap_log_err("update_cookie_key: oscore_ng_generate_timestamp failed\n");
    return 0;
  }
  passed_intervals = (now - current_interval_start) / INTERVAL_DURATION;
  if (!passed_intervals) {
    return 1;
  }
  if (passed_intervals == 1) {
    has_previous_key = 1;
    memcpy(previous_key, current_key, sizeof(previous_key));
  } else {
    has_previous_key = 0;
  }
  if (!coap_prng(current_key, sizeof(current_key))) {
    coap_log_err("update_cookie_key: coap_prng failed\n");
    return 0;
  }
  current_interval += passed_intervals;
  current_interval_start += INTERVAL_DURATION * passed_intervals;
  return 1;
}

static int
bake_specific_cookie(uint8_t cookie[COAP_BAKERY_COOKIE_SIZE],
                     const coap_address_t *address,
                     uint8_t key[KEY_SIZE],
                     uint_fast8_t interval) {
  uint8_t hmac[SHA_256_DIGEST_LENGTH];

#ifdef WITH_CONTIKI
  sha_256_hmac(key,
               KEY_SIZE,
               address->addr.u8,
               sizeof(address->addr.u8),
               hmac);
#else /* ! WITH_CONTIKI */
  switch (address->addr.sa.sa_family) {
  case AF_INET:
    sha_256_hmac(key,
                 KEY_SIZE,
                 (const uint8_t *)&address->addr.sin.sin_addr.s_addr,
                 sizeof(address->addr.sin.sin_addr.s_addr),
                 hmac);
    break;
  case AF_INET6:
    sha_256_hmac(key,
                 KEY_SIZE,
                 address->addr.sin6.sin6_addr.s6_addr,
                 sizeof(address->addr.sin6.sin6_addr.s6_addr),
                 hmac);
    break;
  default:
    return 0;
  }
#endif /* ! WITH_CONTIKI */
  memcpy(cookie, hmac, COAP_BAKERY_COOKIE_SIZE);
  /* last bit indicates interval */
  cookie[COAP_BAKERY_COOKIE_SIZE - 1] &= ~1;
  cookie[COAP_BAKERY_COOKIE_SIZE - 1] |= interval & 1;
  return 1;
}

static int
bake_cookie(uint8_t cookie[COAP_BAKERY_COOKIE_SIZE],
            const coap_address_t *address) {
  if (!update_cookie_key()) {
    return 0;
  }
  return bake_specific_cookie(cookie, address, current_key, current_interval);
}

int
coap_bakery_open(coap_context_t *context) {
  coap_str_const_t *path;
  coap_resource_t *resource;

  path = coap_make_str_const(knock_path);
  resource = coap_resource_init(path, 0);
  if (!resource) {
    coap_log_err("coap_bakery_open: coap_resource_init failed\n");
    return 0;
  }
  coap_register_handler(resource, COAP_REQUEST_GET, handle_knock);
  coap_add_resource(context, resource);
  if (!current_interval_start) {
    current_interval_start = oscore_ng_generate_timestamp();
    if (!current_interval_start) {
      coap_log_err("coap_bakery_open: oscore_ng_generate_timestamp failed\n");
      return 0;
    }
    if (!coap_prng(current_key, sizeof(current_key))) {
      coap_log_err("coap_bakery_open: coap_prng failed\n");
      return 0;
    }
  }
  return 1;
}

static void
handle_knock(coap_resource_t *resource,
             coap_session_t *session,
             const coap_pdu_t *request,
             const coap_string_t *query,
             coap_pdu_t *response) {
  (void)resource;
  (void)query;

  /* check padding bytes */
  {
    size_t payload_size;
    const uint8_t *payload;

    if (!coap_get_data(request, &payload_size, &payload)) {
      coap_log_err("handle_knock: coap_get_data failed\n");
      goto error;
    }
    if (payload_size < COAP_BAKERY_COOKIE_SIZE) {
      coap_log_err("handle_knock: insufficient padding bytes\n");
      goto error;
    }
  }

  /* TODO rate limitation */

  /* create response */
  {
    uint8_t *response_payload;

    response_payload = coap_add_data_after(response, COAP_BAKERY_COOKIE_SIZE);
    if (!response_payload) {
      coap_log_err("handle_knock: coap_add_data_after failed\n");
      goto error;
    }
    bake_cookie(response_payload, coap_session_get_addr_remote(session));
  }
  coap_pdu_set_code(response, COAP_RESPONSE_CODE_CONTENT);
  coap_pdu_set_type(response, COAP_MESSAGE_ACK);
  return;
error:
  /* these two lines cause the ACK to be suppressed */
  coap_pdu_set_code(response, COAP_EMPTY_CODE);
  coap_pdu_set_type(response, COAP_MESSAGE_NON);
}

int
coap_bakery_check_cookie(const uint8_t cookie[COAP_BAKERY_COOKIE_SIZE],
                         const coap_address_t *address) {
  int is_recent_cookie;

  if (!update_cookie_key()) {
    return 0;
  }
  is_recent_cookie = (cookie[COAP_BAKERY_COOKIE_SIZE - 1] & 1)
                     == (current_interval & 1);
  if (!is_recent_cookie && !has_previous_key) {
    coap_log_err("coap_bakery_check_cookie: outdated cookie\n");
    return 0;
  }

  {
    uint8_t expected_cookie[COAP_BAKERY_COOKIE_SIZE];

    bake_specific_cookie(expected_cookie,
                         address,
                         is_recent_cookie
                         ? current_key
                         : previous_key,
                         is_recent_cookie
                         ? current_interval
                         : current_interval - 1);
    return !memcmp(expected_cookie, cookie, COAP_BAKERY_COOKIE_SIZE);
  }
}
#else /* ! COAP_RAP_SUPPORT || ! COAP_SERVER_SUPPORT */
int
coap_bakery_open(coap_context_t *context) {
  (void)context;
  return 0;
}

int
coap_bakery_check_cookie(const uint8_t cookie[COAP_BAKERY_COOKIE_SIZE],
                         const coap_address_t *address) {
  (void)cookie;
  (void)address;
  return 0;
}
#endif /* ! COAP_RAP_SUPPORT || ! COAP_SERVER_SUPPORT */
