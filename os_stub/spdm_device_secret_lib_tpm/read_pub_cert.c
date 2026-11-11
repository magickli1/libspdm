/**
 *  Copyright Notice:
 *  Copyright 2025-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>

#include <base.h>
#include "library/memlib.h"
#include "internal/libspdm_device_secret_lib.h"
#include "internal/libspdm_common_lib.h"
#include "library/spdm_crypt_ext_lib.h"
#include "keys.h"

/* TCG "TPM 2.0 Keys for Device Identity and Attestation" sec. 7.3.2: IAK chains in NV
 * 0x01C90100-0x01C901FF, IDevID chains in 0x01C90200-0x01C902FF. */
#define LIBSPDM_TPM_TCG_DEVID_NV_FIRST 0x01C90100
#define LIBSPDM_TPM_TCG_DEVID_NV_LAST 0x01C902FF
#define LIBSPDM_TPM_TCG_DEVID_MAX_CERTS 16

static bool is_tcg_devid_chain_index(uint32_t index)
{
    return (index >= LIBSPDM_TPM_TCG_DEVID_NV_FIRST) &&
           (index <= LIBSPDM_TPM_TCG_DEVID_NV_LAST);
}

/* Read a DER certificate chain ordered Root CA first, leaf last.
 *
 * A TCG DevID index holds the DevID chain without the Root CA certificate, leaf at index 0
 * followed by its issuing intermediates (sec. 7.3.2). The Root CA certificate is read from
 * LIBSPDM_TPM_HANDLE_ROOT_CERT and the chain is reordered to the SPDM order. Only the first
 * NV index of a range is read (no overflow into the next index). Any other index holds the
 * chain in SPDM order already. The returned buffer is freed with free(). */
static bool read_cert_chain_der(uint32_t index, void **data, size_t *size)
{
    void *devid_chain;
    size_t devid_chain_size;
    void *root_cert;
    size_t root_cert_size;
    const uint8_t *cert[LIBSPDM_TPM_TCG_DEVID_MAX_CERTS];
    size_t cert_size[LIBSPDM_TPM_TCG_DEVID_MAX_CERTS];
    size_t cert_count;
    uint8_t *chain;
    size_t offset;

    if (!is_tcg_devid_chain_index(index)) {
        return libspdm_tpm_read_nv(index, data, size);
    }

    if (!libspdm_tpm_read_nv(index, &devid_chain, &devid_chain_size)) {
        return false;
    }
    if (!libspdm_tpm_read_nv(LIBSPDM_TPM_HANDLE_ROOT_CERT, &root_cert, &root_cert_size)) {
        free(devid_chain);
        return false;
    }

    offset = 0;
    for (cert_count = 0; cert_count < LIBSPDM_TPM_TCG_DEVID_MAX_CERTS; cert_count++) {
        if (!libspdm_x509_get_cert_from_cert_chain(devid_chain, devid_chain_size,
                                                   (int32_t)cert_count, &cert[cert_count],
                                                   &cert_size[cert_count])) {
            break;
        }
        offset += cert_size[cert_count];
    }
    if (offset != devid_chain_size) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR,
                       "TPM DevID certificate chain is invalid or exceeds the certificate limit\n"));
        free(root_cert);
        free(devid_chain);
        return false;
    }

    chain = malloc(root_cert_size + devid_chain_size);
    if ((cert_count == 0) || (chain == NULL)) {
        free(chain);
        free(root_cert);
        free(devid_chain);
        return false;
    }

    libspdm_copy_mem(chain, root_cert_size + devid_chain_size, root_cert, root_cert_size);
    offset = root_cert_size;
    while (cert_count > 0) {
        cert_count--;
        libspdm_copy_mem(chain + offset, root_cert_size + devid_chain_size - offset,
                         cert[cert_count], cert_size[cert_count]);
        offset += cert_size[cert_count];
    }

    free(root_cert);
    free(devid_chain);
    *data = chain;
    *size = offset;
    return true;
}

static bool get_root_certificate_from_chain(uint32_t chain_index, uint32_t base_hash_algo,
                                            uint32_t base_asym_algo, void **data,
                                            size_t *size, void **hash, size_t *hash_size)
{
    bool result;
    void *cert_chain_data;
    size_t cert_chain_size;
    const uint8_t *root_cert;
    size_t root_cert_len;
    spdm_cert_chain_t *cert_chain;
    size_t output_cert_chain_size;
    size_t digest_size;

    if (data == NULL || size == NULL) {
        return false;
    }
    *data = NULL;
    *size = 0;
    if (hash != NULL) {
        *hash = NULL;
    }
    if (hash_size != NULL) {
        *hash_size = 0;
    }

    if (!libspdm_tpm_device_init())
        return false;

    digest_size = libspdm_get_hash_size(base_hash_algo);
    if (digest_size == 0) {
        return false;
    }

    result = read_cert_chain_der(chain_index, &cert_chain_data, &cert_chain_size);
    if (!result)
        return false;

    /* Extract root certificate from chain */
    result = libspdm_x509_get_cert_from_cert_chain(cert_chain_data, cert_chain_size, 0,
                                                   &root_cert, &root_cert_len);
    if (!result) {
        free(cert_chain_data);
        return false;
    }

    /* Create cert chain with just root cert */
    output_cert_chain_size = sizeof(spdm_cert_chain_t) + digest_size + root_cert_len;
    cert_chain = (void *)malloc(output_cert_chain_size);
    if (cert_chain == NULL){
        free(cert_chain_data);
        return false;
    }
    cert_chain->length = (uint32_t)output_cert_chain_size;

    result = libspdm_hash_all(base_hash_algo, root_cert, root_cert_len,
                              (uint8_t *)(cert_chain + 1));
    if (!result){
        free(cert_chain);
        free(cert_chain_data);
        return false;
    }

    libspdm_copy_mem((uint8_t *)cert_chain + sizeof(spdm_cert_chain_t) + digest_size,
                     output_cert_chain_size - (sizeof(spdm_cert_chain_t) + digest_size),
                     root_cert, root_cert_len);

    *data = cert_chain;
    *size = output_cert_chain_size;

    if (hash != NULL)
        *hash = (cert_chain + 1);

    if (hash_size != NULL)
        *hash_size = digest_size;

    free(cert_chain_data);
    return true;
}

static bool get_leaf_certificate_from_chain(uint32_t chain_index, uint32_t base_asym_algo,
                                            void **data, size_t *size)
{
    bool result;
    void *cert_chain_data;
    size_t cert_chain_size;
    const uint8_t *leaf_cert;
    size_t leaf_cert_len;

    if (data == NULL || size == NULL) {
        return false;
    }
    *data = NULL;
    *size = 0;

    if (!libspdm_tpm_device_init())
        return false;

    result = read_cert_chain_der(chain_index, &cert_chain_data, &cert_chain_size);
    if (!result)
        return false;

    /* Extract leaf certificate (last in chain) */
    result = libspdm_x509_get_cert_from_cert_chain(cert_chain_data, cert_chain_size,
                                                   -1, &leaf_cert, &leaf_cert_len);
    if (!result) {
        free(cert_chain_data);
        return false;
    }

    /* Allocate and copy leaf cert */
    *data = malloc(leaf_cert_len);
    if (*data == NULL) {
        free(cert_chain_data);
        return false;
    }

    libspdm_copy_mem(*data, leaf_cert_len, leaf_cert, leaf_cert_len);
    *size = leaf_cert_len;

    free(cert_chain_data);
    return true;
}

static bool get_certificate_chain(uint32_t index, uint32_t base_hash_algo, uint32_t base_asym_algo, void **data,
                                  size_t *size, void **hash, size_t *hash_size,
                                  bool is_requester_cert, bool is_device_cert_model)
{
    bool result;
    void *cert;
    size_t cert_size;
    const uint8_t *root_cert;
    size_t root_cert_len;
    spdm_cert_chain_t *cert_chain;
    size_t cert_chain_size;
    size_t digest_size;

    if (data == NULL || size == NULL) {
        return false;
    }
    *data = NULL;
    *size = 0;
    if (hash != NULL) {
        *hash = NULL;
    }
    if (hash_size != NULL) {
        *hash_size = 0;
    }

    if (!read_cert_chain_der(index, &cert, &cert_size)){
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "failed to read nv index %d\n", index));
        return false;
    }

    digest_size = libspdm_get_hash_size(base_hash_algo);
    if (digest_size == 0) {
        free(cert);
        return false;
    }

    cert_chain_size = sizeof(spdm_cert_chain_t) + digest_size + cert_size;
    cert_chain = (void *)malloc(cert_chain_size);
    if (cert_chain == NULL){
        result = false;
        goto cleanup_cert;
    }
    cert_chain->length = (uint32_t)cert_chain_size;
    result = libspdm_verify_cert_chain_data(SPDM_MESSAGE_VERSION_12,
                                            cert, cert_size,
                                            base_asym_algo, 0, base_hash_algo,
                                            is_requester_cert, is_device_cert_model);
    if (!result)
        goto cleanup_cert_chain;

    result = libspdm_x509_get_cert_from_cert_chain(cert, cert_size, 0, &root_cert,
                                                   &root_cert_len);
    if (!result)
        goto cleanup_cert_chain;

    result = libspdm_hash_all(base_hash_algo, root_cert, root_cert_len,
                              (uint8_t *)(cert_chain + 1));
    if (!result)
        goto cleanup_cert_chain;

    libspdm_copy_mem((uint8_t *)cert_chain + sizeof(spdm_cert_chain_t) + digest_size,
                     cert_chain_size - (sizeof(spdm_cert_chain_t) + digest_size),
                     cert, cert_size);

    *data = cert_chain;
    *size = cert_chain_size;

    if (hash != NULL)
        *hash = (cert_chain + 1);

    if (hash_size != NULL)
        *hash_size = digest_size;

    if (result)
        goto cleanup_cert;

cleanup_cert_chain:
    free(cert_chain);

cleanup_cert:
    free(cert);

    return result;
}

bool libspdm_read_requester_root_public_certificate(uint32_t base_hash_algo,
                                                    uint16_t base_asym_algo,
                                                    void **data, size_t *size,
                                                    void **hash,
                                                    size_t *hash_size)
{
    return get_root_certificate_from_chain(LIBSPDM_TPM_HANDLE_REQUESTER_CERTCHAIN_SLOT_0,
                                           base_hash_algo, base_asym_algo, data, size, hash, hash_size);
}

bool libspdm_read_requester_public_certificate_chain(
    uint32_t base_hash_algo, uint16_t req_base_asym_alg, void **data,
    size_t *size, void **hash, size_t *hash_size)
{
    return get_certificate_chain(LIBSPDM_TPM_HANDLE_REQUESTER_CERTCHAIN_SLOT_0, base_hash_algo, req_base_asym_alg, data,
                                 size, hash,
                                 hash_size, true, true);
}

/* The TPM only holds one requester cert chain, so every slot returns it. */
bool libspdm_read_requester_public_certificate_chain_per_slot(
    uint8_t slot_id, uint32_t base_hash_algo, uint16_t req_base_asym_alg, void **data,
    size_t *size, void **hash, size_t *hash_size)
{
    return libspdm_read_requester_public_certificate_chain(
        base_hash_algo, req_base_asym_alg, data, size, hash, hash_size);
}

bool libspdm_read_responder_certificate(uint32_t base_asym_algo,
                                        void **data, size_t *size)
{
    if (base_asym_algo == 0) {
        return false;
    }

    return get_leaf_certificate_from_chain(LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_0,
                                           base_asym_algo, data, size);
}

bool libspdm_read_responder_root_public_certificate(uint32_t base_hash_algo,
                                                    uint32_t base_asym_algo,
                                                    void **data, size_t *size,
                                                    void **hash,
                                                    size_t *hash_size)
{
    return get_root_certificate_from_chain(LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_0,
                                           base_hash_algo, base_asym_algo, data, size, hash, hash_size);
}

bool libspdm_read_responder_public_certificate_chain(
    uint32_t base_hash_algo, uint32_t base_asym_algo, void **data,
    size_t *size, void **hash, size_t *hash_size)
{
    return get_certificate_chain(LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_0, base_hash_algo, base_asym_algo, data,
                                 size, hash, hash_size,
                                 false, true);
}

bool libspdm_read_responder_root_public_certificate_slot(uint8_t slot_id,
                                                         uint32_t base_hash_algo,
                                                         uint32_t base_asym_algo,
                                                         void **data, size_t *size,
                                                         void **hash,
                                                         size_t *hash_size)
{
    uint32_t chain_index;

    if ((slot_id >= SPDM_MAX_SLOT_COUNT) ||
        ((LIBSPDM_TPM_RESPONDER_SUPPORTED_SLOT_MASK & (1u << slot_id)) == 0)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "unsupported slot_id %d (supported mask: 0x%x)\n",
                       slot_id, LIBSPDM_TPM_RESPONDER_SUPPORTED_SLOT_MASK));
        return false;
    }

    switch (slot_id) {
#ifdef LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_0
    case 0:
        chain_index = LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_0;
        break;
#endif
#ifdef LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_1
    case 1:
        chain_index = LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_1;
        break;
#endif
#ifdef LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_2
    case 2:
        chain_index = LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_2;
        break;
#endif
#ifdef LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_3
    case 3:
        chain_index = LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_3;
        break;
#endif
#ifdef LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_4
    case 4:
        chain_index = LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_4;
        break;
#endif
#ifdef LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_5
    case 5:
        chain_index = LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_5;
        break;
#endif
#ifdef LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_6
    case 6:
        chain_index = LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_6;
        break;
#endif
#ifdef LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_7
    case 7:
        chain_index = LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_7;
        break;
#endif
    default:
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "unsupported slot_id %d\n", slot_id));
        return false;
    }

    return get_root_certificate_from_chain(chain_index, base_hash_algo, base_asym_algo,
                                           data, size, hash, hash_size);
}

/* Certificate chain of the restricted TPM IAK. It is served on LIBSPDM_TPM_IAK_SLOT_ID for
 * GET_DIGESTS/GET_CERTIFICATE only; that slot is not in LIBSPDM_TPM_RESPONDER_SUPPORTED_SLOT_MASK,
 * so it never resolves to a signing handle in sign.c. */
static bool read_responder_iak_certificate_chain(
    uint32_t base_hash_algo, uint32_t base_asym_algo,
    void **data, size_t *size, void **hash, size_t *hash_size)
{
    return get_certificate_chain(LIBSPDM_TPM_HANDLE_IAK_CERTCHAIN, base_hash_algo,
                                 base_asym_algo, data, size, hash, hash_size, false, true);
}

bool libspdm_read_responder_public_certificate_chain_per_slot(
    uint8_t slot_id, uint32_t base_hash_algo, uint32_t base_asym_algo,
    void **data, size_t *size, void **hash, size_t *hash_size)
{
    uint32_t chain_index;

    if (slot_id == LIBSPDM_TPM_IAK_SLOT_ID) {
        return read_responder_iak_certificate_chain(base_hash_algo, base_asym_algo,
                                                    data, size, hash, hash_size);
    }

    if ((slot_id >= SPDM_MAX_SLOT_COUNT) ||
        ((LIBSPDM_TPM_RESPONDER_SUPPORTED_SLOT_MASK & (1u << slot_id)) == 0)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "unsupported slot_id %d (supported mask: 0x%x)\n",
                       slot_id, LIBSPDM_TPM_RESPONDER_SUPPORTED_SLOT_MASK));
        return false;
    }

    switch (slot_id) {
#ifdef LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_0
    case 0:
        chain_index = LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_0;
        break;
#endif
#ifdef LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_1
    case 1:
        chain_index = LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_1;
        break;
#endif
#ifdef LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_2
    case 2:
        chain_index = LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_2;
        break;
#endif
#ifdef LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_3
    case 3:
        chain_index = LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_3;
        break;
#endif
#ifdef LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_4
    case 4:
        chain_index = LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_4;
        break;
#endif
#ifdef LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_5
    case 5:
        chain_index = LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_5;
        break;
#endif
#ifdef LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_6
    case 6:
        chain_index = LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_6;
        break;
#endif
#ifdef LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_7
    case 7:
        chain_index = LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_7;
        break;
#endif
    default:
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "unsupported slot_id %d\n", slot_id));
        return false;
    }

    return get_certificate_chain(chain_index, base_hash_algo, base_asym_algo, data, size, hash, hash_size,
                                 false, true);
}

/*This alias cert chain is partial, from root CA to device certificate CA.*/
bool libspdm_read_responder_public_certificate_chain_alias_cert_till_dev_cert_ca(
    uint32_t base_hash_algo, uint32_t base_asym_algo, void **data,
    size_t *size, void **hash, size_t *hash_size)
{
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR,
                   "libspdm_read_responder_public_certificate_chain_alias_cert_till_dev_cert_ca not yet implemented\n"));
    return false;
}

/*This alias cert chain is entire, from root CA to leaf certificate.*/
bool libspdm_read_responder_public_certificate_chain_alias_cert(
    uint32_t base_hash_algo, uint32_t base_asym_algo, void **data,
    size_t *size, void **hash, size_t *hash_size)
{
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR,
                   "libspdm_read_responder_public_certificate_chain_alias_cert not yet implemented\n"));
    return false;
}
