/*
 * coap_oscore_ng.h -- OSCORE-NG support for libcoap
 *
 * Copyright (C) 2021-2023 Uppsala universitet
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_oscore_ng.h
 * @brief CoAP OSCORE-NG support
 */

#ifndef COAP_OSCORE_NG_INTERNAL_H_
#define COAP_OSCORE_NG_INTERNAL_H_

/**
 * @defgroup oscore_ng_internal OSCORE-NG Support (Internal)
 * Internal API functions for interfacing with OSCORE-NG
 * @{
 */

struct coap_oscore_ng_general_context_t {
  coap_oscore_ng_keying_material_getter_t keying_material_getter;
  oscore_ng_id_t sender_id;
};

/**
 * Encrypts and authenticates the specified @p pdu.
 *
 * @param session The session that will handle the transport of the
 *                specified @p pdu.
 * @param pdu     The PDU to encrypt.
 *
 * @return        Encrypted pdu on success, pdu if it needs no encryption,
 *                or @c NULL on error.
 */
coap_pdu_t *coap_oscore_ng_message_encrypt(coap_session_t *session,
                                           coap_pdu_t *pdu);

/**
 * Performs decryption, authenticity check, and freshness check.
 *
 * @param session         The session that will handle the transport of the
 *                        specified @p pdu.
 * @param pdu             The PDU to check.
 * @param is_b2_request_1 Set to 1 if an Unauthorized RST shall be returned.
 *
 * @return        Decrypted pdu on success, pdu if it needs no decryption,
 *                or @c NULL on error.
 */
coap_pdu_t *coap_oscore_ng_message_decrypt(coap_session_t *session,
                                           coap_pdu_t *pdu,
                                           int *is_b2_request_1);

/**
 * Releases OSCORE-NG data of a session.
 *
 * @param context The OSCORE-NG context to be cleared.
 */
void coap_oscore_ng_clear_context(oscore_ng_context_t *context);

/** @} */

#endif /* COAP_OSCORE_NG_INTERNAL_H_ */
