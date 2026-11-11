/**
 * Copyright Notice:
 * Copyright 2026 DMTF. All rights reserved.
 * License: BSD 3-Clause License. See LICENSE.md in the repository root.
 **/

#include "internal/libspdm_device_secret_lib.h"
#include "hal/library/responder/key_pair_info.h"
#include "hal/library/memlib.h"
#include "keys.h"
#include <string.h>

/* Persistent keys are provisioned outside SPDM. Deduplicate configured handles,
 * assign contiguous endpoint-local IDs, and expose the actual key metadata.
 * Signing-key certificate associations may change; key material and IAK usage may not. */
typedef struct {
    const char *handle;
    uint8_t slots;
    uint8_t configured_slots;
    uint32_t algorithm;
    size_t public_info_size;
    /* RSA-PSS AlgorithmIdentifiers include hash, MGF and salt parameters. */
    uint8_t public_info[128];
    bool quote_only;
} libspdm_tpm_key_pair_t;

typedef struct {
    bool initialized;
    uint8_t count;
    libspdm_tpm_key_pair_t keys[SPDM_MAX_SLOT_COUNT];
} libspdm_tpm_key_pairs_t;

static const char *m_requester_handles[SPDM_MAX_SLOT_COUNT] = {
#ifdef LIBSPDM_TPM_HANDLE_REQUESTER_HANDLE_SLOT_0
    [0] = LIBSPDM_TPM_HANDLE_REQUESTER_HANDLE_SLOT_0,
#endif
#ifdef LIBSPDM_TPM_HANDLE_REQUESTER_HANDLE_SLOT_1
    [1] = LIBSPDM_TPM_HANDLE_REQUESTER_HANDLE_SLOT_1,
#endif
#ifdef LIBSPDM_TPM_HANDLE_REQUESTER_HANDLE_SLOT_2
    [2] = LIBSPDM_TPM_HANDLE_REQUESTER_HANDLE_SLOT_2,
#endif
#ifdef LIBSPDM_TPM_HANDLE_REQUESTER_HANDLE_SLOT_3
    [3] = LIBSPDM_TPM_HANDLE_REQUESTER_HANDLE_SLOT_3,
#endif
#ifdef LIBSPDM_TPM_HANDLE_REQUESTER_HANDLE_SLOT_4
    [4] = LIBSPDM_TPM_HANDLE_REQUESTER_HANDLE_SLOT_4,
#endif
#ifdef LIBSPDM_TPM_HANDLE_REQUESTER_HANDLE_SLOT_5
    [5] = LIBSPDM_TPM_HANDLE_REQUESTER_HANDLE_SLOT_5,
#endif
#ifdef LIBSPDM_TPM_HANDLE_REQUESTER_HANDLE_SLOT_6
    [6] = LIBSPDM_TPM_HANDLE_REQUESTER_HANDLE_SLOT_6,
#endif
#ifdef LIBSPDM_TPM_HANDLE_REQUESTER_HANDLE_SLOT_7
    [7] = LIBSPDM_TPM_HANDLE_REQUESTER_HANDLE_SLOT_7,
#endif
};

static const char *m_responder_handles[SPDM_MAX_SLOT_COUNT] = {
#ifdef LIBSPDM_TPM_HANDLE_RESPONDER_HANDLE_SLOT_0
    [0] = LIBSPDM_TPM_HANDLE_RESPONDER_HANDLE_SLOT_0,
#endif
#ifdef LIBSPDM_TPM_HANDLE_RESPONDER_HANDLE_SLOT_1
    [1] = LIBSPDM_TPM_HANDLE_RESPONDER_HANDLE_SLOT_1,
#endif
#ifdef LIBSPDM_TPM_HANDLE_RESPONDER_HANDLE_SLOT_2
    [2] = LIBSPDM_TPM_HANDLE_RESPONDER_HANDLE_SLOT_2,
#endif
#ifdef LIBSPDM_TPM_HANDLE_RESPONDER_HANDLE_SLOT_3
    [3] = LIBSPDM_TPM_HANDLE_RESPONDER_HANDLE_SLOT_3,
#endif
#ifdef LIBSPDM_TPM_HANDLE_RESPONDER_HANDLE_SLOT_4
    [4] = LIBSPDM_TPM_HANDLE_RESPONDER_HANDLE_SLOT_4,
#endif
#ifdef LIBSPDM_TPM_HANDLE_RESPONDER_HANDLE_SLOT_5
    [5] = LIBSPDM_TPM_HANDLE_RESPONDER_HANDLE_SLOT_5,
#endif
#ifdef LIBSPDM_TPM_HANDLE_RESPONDER_HANDLE_SLOT_6
    [6] = LIBSPDM_TPM_HANDLE_RESPONDER_HANDLE_SLOT_6,
#endif
#ifdef LIBSPDM_TPM_HANDLE_RESPONDER_HANDLE_SLOT_7
    [7] = LIBSPDM_TPM_HANDLE_RESPONDER_HANDLE_SLOT_7,
#endif
};

static libspdm_tpm_key_pairs_t m_responder_keys;
static libspdm_tpm_key_pairs_t m_requester_keys;

static bool libspdm_tpm_add_key(libspdm_tpm_key_pairs_t *pairs, const char *handle,
                                uint8_t slot, bool quote_only)
{
    libspdm_tpm_key_pair_t *key;
    uint8_t index;

    for (index = 0; index < pairs->count; index++) {
        key = &pairs->keys[index];
        if (strcmp(key->handle, handle) == 0) {
            /* A Quote-only IAK must never alias an SPDM signing key. */
            if (key->quote_only != quote_only) {
                return false;
            }
            key->slots |= (uint8_t)(1u << slot);
            key->configured_slots = key->slots;
            return true;
        }
    }
    if (pairs->count == LIBSPDM_ARRAY_SIZE(pairs->keys)) {
        return false;
    }
    key = &pairs->keys[pairs->count];
    key->handle = handle;
    key->slots = (uint8_t)(1u << slot);
    key->configured_slots = key->slots;
    key->quote_only = quote_only;
    key->public_info_size = sizeof(key->public_info);
    if (!libspdm_tpm_get_key_info(handle, &key->algorithm, key->public_info,
                                  &key->public_info_size)) {
        return false;
    }
    pairs->count++;
    return true;
}

static libspdm_tpm_key_pairs_t *libspdm_tpm_key_pairs(bool requester)
{
    libspdm_tpm_key_pairs_t *pairs;
    libspdm_tpm_key_pairs_t initialized;
    const char *const *handles;
    uint8_t slot;

    pairs = requester ? &m_requester_keys : &m_responder_keys;
    if (!pairs->initialized) {
        libspdm_zero_mem(&initialized, sizeof(initialized));
        handles = requester ? m_requester_handles : m_responder_handles;
        for (slot = 0; slot < SPDM_MAX_SLOT_COUNT; slot++) {
            if ((handles[slot] != NULL) &&
                !libspdm_tpm_add_key(&initialized, handles[slot], slot, false)) {
                return NULL;
            }
        }
        if (!requester &&
            !libspdm_tpm_add_key(&initialized, LIBSPDM_TPM_HANDLE_IAK,
                                 LIBSPDM_TPM_IAK_SLOT_ID, true)) {
            return NULL;
        }
        initialized.initialized = true;
        *pairs = initialized;
    }
    return pairs;
}

static uint32_t libspdm_tpm_key_pair_algorithm(uint32_t asym)
{
    switch (asym) {
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
        return SPDM_KEY_PAIR_ASYM_ALGO_CAP_RSA2048;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
        return SPDM_KEY_PAIR_ASYM_ALGO_CAP_RSA3072;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
        return SPDM_KEY_PAIR_ASYM_ALGO_CAP_RSA4096;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
        return SPDM_KEY_PAIR_ASYM_ALGO_CAP_ECC256;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
        return SPDM_KEY_PAIR_ASYM_ALGO_CAP_ECC384;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
        return SPDM_KEY_PAIR_ASYM_ALGO_CAP_ECC521;
    default:
        return 0;
    }
}

uint8_t libspdm_tpm_get_key_pair_id_by_slot(bool requester, uint32_t base_asym_algo,
                                            uint32_t pqc_asym_algo, uint8_t slot_id)
{
    libspdm_tpm_key_pairs_t *pairs;
    uint32_t algorithm;
    uint8_t index;

    if ((slot_id >= SPDM_MAX_SLOT_COUNT) || (pqc_asym_algo != 0)) {
        return 0;
    }
    algorithm = libspdm_tpm_key_pair_algorithm(base_asym_algo);
    if (algorithm == 0) {
        return 0;
    }
    pairs = libspdm_tpm_key_pairs(requester);
    if (pairs == NULL) {
        return 0;
    }
    for (index = 0; index < pairs->count; index++) {
        if (((pairs->keys[index].slots & (1u << slot_id)) != 0) &&
            (pairs->keys[index].algorithm == algorithm)) {
            return (uint8_t)(index + 1);
        }
    }
    return 0;
}

const void *libspdm_tpm_get_signing_key_handle(bool requester, uint8_t key_pair_id)
{
    libspdm_tpm_key_pairs_t *pairs;
    libspdm_tpm_key_pair_t *key;

    /* Legacy single-key connections pass zero, not a SlotID. */
    if (key_pair_id == 0) {
        return requester ? m_requester_handles[0] : m_responder_handles[0];
    }
    pairs = libspdm_tpm_key_pairs(requester);
    if ((pairs == NULL) || (key_pair_id > pairs->count)) {
        return NULL;
    }
    key = &pairs->keys[key_pair_id - 1];
    return key->quote_only ? NULL : key->handle;
}

#if LIBSPDM_ENABLE_CAPABILITY_GET_KEY_PAIR_INFO_CAP
uint8_t libspdm_get_key_pair_id_by_slot(uint32_t base_asym_algo, uint32_t pqc_asym_algo,
                                        uint8_t slot_id)
{
    return libspdm_tpm_get_key_pair_id_by_slot(false, base_asym_algo, pqc_asym_algo, slot_id);
}

bool libspdm_read_key_pair_info(
    void *spdm_context, const uint32_t *session_id, uint8_t key_pair_id,
    uint8_t *total_key_pairs, uint16_t *capabilities, uint16_t *key_usage_capabilities,
    uint16_t *current_key_usage, uint32_t *asym_algo_capabilities, uint32_t *current_asym_algo,
    uint32_t *pqc_asym_algo_capabilities, uint32_t *current_pqc_asym_algo,
    uint8_t *assoc_cert_slot_mask, uint16_t *public_key_info_len, uint8_t *public_key_info)
{
    libspdm_tpm_key_pairs_t *pairs;
    const libspdm_tpm_key_pair_t *key;
    uint16_t usage;
    size_t capacity;

    if (total_key_pairs == NULL) {
        return false;
    }
    pairs = libspdm_tpm_key_pairs(false);
    *total_key_pairs = pairs == NULL ? 0 : pairs->count;
    if ((pairs == NULL) || (key_pair_id == 0) || (key_pair_id > pairs->count) ||
        (capabilities == NULL) || (key_usage_capabilities == NULL) ||
        (current_key_usage == NULL) || (asym_algo_capabilities == NULL) ||
        (current_asym_algo == NULL) || (pqc_asym_algo_capabilities == NULL) ||
        (current_pqc_asym_algo == NULL) || (assoc_cert_slot_mask == NULL)) {
        return false;
    }
    key = &pairs->keys[key_pair_id - 1];
    if ((public_key_info != NULL) && (public_key_info_len == NULL)) {
        return false;
    }
    if (public_key_info_len != NULL) {
        capacity = *public_key_info_len;
        *public_key_info_len = (uint16_t)key->public_info_size;
        if (public_key_info != NULL) {
            if (capacity < key->public_info_size) {
                return false;
            }
            libspdm_copy_mem(public_key_info, capacity, key->public_info, key->public_info_size);
        }
    }
    usage = key->quote_only ? SPDM_KEY_USAGE_BIT_MASK_STANDARDS_KEY_USE :
            (SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE | SPDM_KEY_USAGE_BIT_MASK_CHALLENGE_USE |
             SPDM_KEY_USAGE_BIT_MASK_MEASUREMENT_USE | SPDM_KEY_USAGE_BIT_MASK_ENDPOINT_INFO_USE);
    *capabilities = key->quote_only ? 0 : SPDM_KEY_PAIR_CAP_CERT_ASSOC_CAP;
    if (!key->quote_only && ((key->configured_slots & (key->configured_slots - 1)) != 0)) {
        *capabilities |= SPDM_KEY_PAIR_CAP_SHAREABLE_CAP;
    }
    *key_usage_capabilities = usage;
    *current_key_usage = usage;
    *asym_algo_capabilities = key->algorithm;
    *current_asym_algo = key->algorithm;
    *pqc_asym_algo_capabilities = 0;
    *current_pqc_asym_algo = 0;
    *assoc_cert_slot_mask = key->slots;
    return true;
}
#endif

#if LIBSPDM_ENABLE_CAPABILITY_SET_KEY_PAIR_INFO_CAP
bool libspdm_write_key_pair_info(
    void *spdm_context, const uint32_t *session_id, uint8_t key_pair_id, uint8_t operation,
    uint16_t desired_key_usage, uint32_t desired_asym_algo, uint32_t desired_pqc_asym_algo,
    uint8_t desired_assoc_cert_slot_mask, bool *need_reset)
{
    libspdm_tpm_key_pairs_t *pairs;
    libspdm_tpm_key_pair_t *key;

    if (need_reset != NULL) {
        *need_reset = false;
    }
    pairs = libspdm_tpm_key_pairs(false);
    if ((pairs == NULL) || (key_pair_id == 0) || (key_pair_id > pairs->count) ||
        (operation != SPDM_SET_KEY_PAIR_INFO_CHANGE_OPERATION)) {
        return false;
    }
    key = &pairs->keys[key_pair_id - 1];
    if (key->quote_only || (desired_key_usage != 0) || (desired_asym_algo != 0) ||
        (desired_pqc_asym_algo != 0) ||
        ((desired_assoc_cert_slot_mask & ~key->configured_slots) != 0)) {
        return false;
    }
    key->slots = desired_assoc_cert_slot_mask;
    return true;
}

bool libspdm_read_cached_last_set_key_pair_info_request(uint8_t **request, size_t *size)
{
    *request = NULL;
    *size = 0;
    return false;
}

bool libspdm_cache_last_set_key_pair_info_request(const uint8_t *request, size_t size)
{
    return false;
}
#endif
