/**
 *  Copyright Notice:
 *  Copyright 2025-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include <openssl/err.h>
#include <tss2/tss2_common.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_tctildr.h>

#include <openssl/provider.h>
#include <openssl/store.h>
#include <openssl/x509.h>
#include <tss2/tss2_tcti.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_tpm2_types.h>
#include <tss2/tss2_mu.h>
#include "library/spdm_crypt_ext_lib.h"
#include "internal/libspdm_crypt_lib.h"
#include "industry_standard/spdm.h"
#include "industry_standard/spdm_secured_message.h"

#include <openssl/rsa.h>
#include "../key_context.h"

bool g_tpm_device_initialized = false;

static libspdm_key_context *create_key_context(EVP_PKEY *pkey)
{
    libspdm_key_context *context;

    if (pkey == NULL) {
        return NULL;
    }

    context = (libspdm_key_context *)malloc(sizeof(libspdm_key_context));
    if (context == NULL) {
        return NULL;
    }
    context->evp_pkey = pkey;
    return context;
}

bool libspdm_tpm_device_init()
{
    OSSL_PROVIDER *tpm_provider = NULL;

    if (g_tpm_device_initialized)
        return true;

    tpm_provider = OSSL_PROVIDER_load(NULL, "tpm2");
    if (tpm_provider == NULL){
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "failed to load tpm2\n"));
        return false;
    }

    OSSL_PROVIDER_load(NULL, "default");
    OSSL_PROVIDER_load(NULL, "legacy");

    g_tpm_device_initialized = true;
    return true;
}

/* Public part of a (TPM-backed) key as a software key: SubjectPublicKeyInfo round trip. */
static EVP_PKEY *tpm_public_part(EVP_PKEY *pkey)
{
    unsigned char *der = NULL;
    const unsigned char *ptr;
    EVP_PKEY *public_key = NULL;
    int der_size;

    if (pkey == NULL) {
        return NULL;
    }
    der_size = i2d_PUBKEY(pkey, &der);
    if (der_size <= 0) {
        return NULL;
    }
    ptr = der;
    public_key = d2i_PUBKEY(NULL, &ptr, der_size);
    OPENSSL_free(der);
    return public_key;
}

static bool get_keyinfo(const char *handle, void **context, int keyinfo_type)
{
    OSSL_STORE_CTX *store_ctx = NULL;
    OSSL_STORE_INFO *info = NULL;

    if (handle == NULL || context == NULL) {
        return false;
    }
    *context = NULL;

    /* handle must look like: "handle:0x81010002" or "tpm2tss:0x81010002" */
    store_ctx = OSSL_STORE_open_ex(handle, NULL, "provider=tpm2", NULL, NULL, NULL, NULL, NULL);
    if (!store_ctx){
        return false;
    }

    while ((info = OSSL_STORE_load(store_ctx)) != NULL)
    {
        if (OSSL_STORE_INFO_get_type(info) == keyinfo_type){
            switch (keyinfo_type)
            {
            case OSSL_STORE_INFO_PKEY:
                *context = OSSL_STORE_INFO_get1_PKEY(info);
                break;
            case OSSL_STORE_INFO_PUBKEY:
                *context = OSSL_STORE_INFO_get1_PUBKEY(info);
                break;
            case OSSL_STORE_INFO_CERT:
                *context = OSSL_STORE_INFO_get1_CERT(info);
                break;
            }
            OSSL_STORE_INFO_free(info);
            break;
        }
        /* The tpm2 provider returns a TPM key handle as PKEY only. For a public key, export
         * its public part, so the result is a plain software public key. */
        if ((keyinfo_type == OSSL_STORE_INFO_PUBKEY) &&
            (OSSL_STORE_INFO_get_type(info) == OSSL_STORE_INFO_PKEY)) {
            *context = tpm_public_part(OSSL_STORE_INFO_get0_PKEY(info));
            OSSL_STORE_INFO_free(info);
            break;
        }
        OSSL_STORE_INFO_free(info);
    }

    OSSL_STORE_close(store_ctx);

    if (*context == NULL){
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "no keyinfo %d found on handle %s\n", keyinfo_type, handle));
        return false;
    }

    return true;
}

bool libspdm_tpm_get_pvt_key_handle(const void *handle, void **context)
{
    EVP_PKEY *pkey = NULL;

    if (context == NULL) {
        return false;
    }
    *context = NULL;

    if (!get_keyinfo((const char *)handle, (void **)&pkey, OSSL_STORE_INFO_PKEY)){
        return false;
    }
    *context = create_key_context(pkey);
    if (*context == NULL) {
        EVP_PKEY_free(pkey);
        return false;
    }
    return true;
}

bool libspdm_tpm_get_pub_key_handle(const void *handle, void **context)
{
    EVP_PKEY *pkey = NULL;

    if (context == NULL) {
        return false;
    }
    *context = NULL;

    if (!get_keyinfo((const char *)handle, (void **)&pkey, OSSL_STORE_INFO_PUBKEY)){
        return false;
    }
    *context = create_key_context(pkey);
    if (*context == NULL) {
        EVP_PKEY_free(pkey);
        return false;
    }
    return true;
}

bool libspdm_tpm_get_key_info(const void *handle, uint32_t *asym_algo,
                              void *public_key_info, size_t *public_key_info_size)
{
    libspdm_key_context *context;
    EVP_PKEY *key;
    X509_PUBKEY *spki;
    X509_ALGOR *algorithm;
    unsigned char *output;
    char group[32];
    size_t group_size;
    int size;
    int bits;
    bool result;

    if ((handle == NULL) || (asym_algo == NULL) || (public_key_info_size == NULL)) {
        return false;
    }
    if (!libspdm_tpm_device_init() ||
        !libspdm_tpm_get_pub_key_handle(handle, (void **)&context)) {
        return false;
    }
    key = context->evp_pkey;
    spki = NULL;
    result = false;
    *asym_algo = 0;
    if ((EVP_PKEY_get_base_id(key) == EVP_PKEY_RSA) ||
        (EVP_PKEY_get_base_id(key) == EVP_PKEY_RSA_PSS)) {
        bits = EVP_PKEY_get_bits(key);
        switch (bits) {
        case 2048: *asym_algo = SPDM_KEY_PAIR_ASYM_ALGO_CAP_RSA2048; break;
        case 3072: *asym_algo = SPDM_KEY_PAIR_ASYM_ALGO_CAP_RSA3072; break;
        case 4096: *asym_algo = SPDM_KEY_PAIR_ASYM_ALGO_CAP_RSA4096; break;
        default: goto done;
        }
    } else if (EVP_PKEY_get_base_id(key) == EVP_PKEY_EC) {
        if (EVP_PKEY_get_group_name(key, group, sizeof(group), &group_size) != 1) {
            goto done;
        }
        if (strcmp(group, "prime256v1") == 0) {
            *asym_algo = SPDM_KEY_PAIR_ASYM_ALGO_CAP_ECC256;
        } else if (strcmp(group, "secp384r1") == 0) {
            *asym_algo = SPDM_KEY_PAIR_ASYM_ALGO_CAP_ECC384;
        } else if (strcmp(group, "secp521r1") == 0) {
            *asym_algo = SPDM_KEY_PAIR_ASYM_ALGO_CAP_ECC521;
        } else {
            goto done;
        }
    } else {
        goto done;
    }
    if ((X509_PUBKEY_set(&spki, key) != 1) ||
        (X509_PUBKEY_get0_param(NULL, NULL, NULL, &algorithm, spki) != 1)) {
        goto done;
    }
    size = i2d_X509_ALGOR(algorithm, NULL);
    if (size <= 0) {
        goto done;
    }
    if ((public_key_info == NULL) || (*public_key_info_size < (size_t)size)) {
        *public_key_info_size = (size_t)size;
        goto done;
    }
    output = public_key_info;
    result = i2d_X509_ALGOR(algorithm, &output) == size;
    *public_key_info_size = (size_t)size;
done:
    X509_PUBKEY_free(spki);
    EVP_PKEY_free(context->evp_pkey);
    free(context);
    return result;
}

bool libspdm_tpm_read_pcr(uint32_t hash_algo, uint32_t index, void *buffer, size_t *size)
{
    TSS2_RC result = 1;
    TSS2_TCTI_CONTEXT *tcti_context = NULL;
    ESYS_CONTEXT *context = NULL;
    TPML_PCR_SELECTION *out = NULL;
    TPML_DIGEST *values = NULL;
    size_t digest_size = 0;
    UINT32 uc;

    TPML_PCR_SELECTION sel = {
        .count = 1,
        .pcrSelections = {
            {
                .sizeofSelect = 3,
                .pcrSelect = {0x00, 0x00, 0x00, 0x00},
            },
        }
    };

    if (buffer == NULL || size == NULL) {
        return false;
    }

    if (index >= 24) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "invalid PCR index %u (max 23)\n", index));
        return false;
    }

    switch (hash_algo)
    {
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256:
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_256:
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SM3_256:
        sel.pcrSelections[0].hash = TPM2_ALG_SHA256;
        digest_size = 32;
        break;
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384:
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_384:
        sel.pcrSelections[0].hash = TPM2_ALG_SHA384;
        digest_size = 48;
        break;
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_512:
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_512:
        sel.pcrSelections[0].hash = TPM2_ALG_SHA512;
        digest_size = 64;
        break;
    default:
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "unsupported measurement hash algo %d\n", hash_algo));
        return false;
    }

    if (*size < digest_size) {
        *size = digest_size;
        return false;
    }

    sel.pcrSelections[0].pcrSelect[index / 8] |= (uint8_t)(1 << (index % 8));

    const char *tssconf = getenv("TPM2TOOLS_TCTI");
    if ((result = Tss2_TctiLdr_Initialize(tssconf, &tcti_context)) != TSS2_RC_SUCCESS){
        goto finish;
    }

    /* TODO: abi version check */
    if ((result = Esys_Initialize(&context, tcti_context, NULL)) != TSS2_RC_SUCCESS){
        goto cleanup_tcti;
    }

    if ((result = Esys_PCR_Read(context, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &sel, &uc, &out,
                                &values)) != TSS2_RC_SUCCESS){
        goto cleanup_esys;
    }

    if (values == NULL || values->count == 0 || values->digests[0].size < digest_size) {
        result = 1;
        goto cleanup_esys;
    }

    memcpy(buffer, values->digests[0].buffer, digest_size);
    *size = digest_size;

cleanup_esys:
    if (out != NULL) {
        Esys_Free(out);
    }
    if (values != NULL) {
        Esys_Free(values);
    }
    Esys_Finalize(&context);

cleanup_tcti:
    Tss2_TctiLdr_Finalize(&tcti_context);

finish:
    return result == TSS2_RC_SUCCESS;
}

bool libspdm_tpm_read_nv(uint32_t index, void **buffer, size_t *size)
{
    TSS2_RC rc = 1;
    TSS2_TCTI_CONTEXT *tcti = NULL;
    ESYS_CONTEXT *esys = NULL;
    ESYS_TR nv_tr = ESYS_TR_NONE;

    TPM2B_NV_PUBLIC *nv_pub = NULL;
    TPM2B_NAME *nv_name = NULL;
    TPMS_CAPABILITY_DATA *cap = NULL;

    UINT16 nv_size;
    UINT32 max_nv_buf;
    UINT16 offset = 0;

    if (buffer == NULL || size == NULL) {
        return false;
    }

    *buffer = NULL;
    *size = 0;

    rc = Tss2_TctiLdr_Initialize(getenv("TPM2TOOLS_TCTI"), &tcti);
    if (rc != TSS2_RC_SUCCESS)
        goto out;

    rc = Esys_Initialize(&esys, tcti, NULL);
    if (rc != TSS2_RC_SUCCESS)
        goto out;

    rc = Esys_TR_FromTPMPublic(
        esys,
        index, /* TPM handle */
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &nv_tr);
    if (rc != TSS2_RC_SUCCESS)
        goto out;

    rc = Esys_NV_ReadPublic(
        esys,
        nv_tr,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &nv_pub,
        &nv_name);
    if (rc != TSS2_RC_SUCCESS)
        goto out;

    nv_size = nv_pub->nvPublic.dataSize;
    if (nv_size == 0) {
        rc = 1;
        goto out;
    }

    rc = Esys_GetCapability(
        esys,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        TPM2_CAP_TPM_PROPERTIES,
        TPM2_PT_NV_BUFFER_MAX,
        1,
        NULL,
        &cap);

    if (rc == TSS2_RC_SUCCESS && cap != NULL && cap->data.tpmProperties.count > 0 &&
        cap->data.tpmProperties.tpmProperty[0].property == TPM2_PT_NV_BUFFER_MAX &&
        cap->data.tpmProperties.tpmProperty[0].value > 0) {
        max_nv_buf = cap->data.tpmProperties.tpmProperty[0].value;
    } else {
        max_nv_buf = 1024;
    }

    *buffer = malloc(nv_size);
    if (!*buffer) {
        rc = 1;
        goto out;
    }

    while (offset < nv_size)
    {
        TPM2B_MAX_NV_BUFFER *chunk = NULL;
        UINT16 to_read = (nv_size - offset > max_nv_buf)
                             ? max_nv_buf
                             : nv_size - offset;

        rc = Esys_NV_Read(
            esys,
            nv_tr,
            nv_tr,
            ESYS_TR_PASSWORD,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            to_read,
            offset,
            &chunk);
        if (rc != TSS2_RC_SUCCESS){
            Esys_Free(chunk);
            goto out;
        }

        if (chunk == NULL || chunk->size == 0) {
            rc = 1;
            Esys_Free(chunk);
            goto out;
        }

        memcpy((uint8_t *)(*buffer) + offset,
               chunk->buffer,
               chunk->size);

        offset += chunk->size;
        Esys_Free(chunk);
    }

    *size = nv_size;
    rc = TSS2_RC_SUCCESS;

out:
    if (rc != TSS2_RC_SUCCESS && *buffer != NULL) {
        free(*buffer);
        *buffer = NULL;
        *size = 0;
    }
    if (cap)
        Esys_Free(cap);
    if (nv_pub)
        Esys_Free(nv_pub);
    if (nv_name)
        Esys_Free(nv_name);
    if (nv_tr != ESYS_TR_NONE)
        Esys_TR_Close(esys, &nv_tr);
    if (esys)
        Esys_Finalize(&esys);
    if (tcti)
        Tss2_TctiLdr_Finalize(&tcti);

    return rc == TSS2_RC_SUCCESS;
}

static uint32_t parse_tpm_key_handle(const void *handle_param)
{
#define TPM_HANDLE_START_RANGE 0x80000000
#define TPM_HANDLE_END_RANGE 0x81FFFFFF
#define TPM_HANDLE_HANDLE_PREFIX "handle:"
#define TPM_HANDLE_TPM2TSS_PREFIX "tpm2tss:"

    const char *handle_str = NULL;
    if (handle_param == NULL) {
        return 0;
    }

    if ((uintptr_t)handle_param >= TPM_HANDLE_START_RANGE && (uintptr_t)handle_param <= TPM_HANDLE_END_RANGE) {
        return (uint32_t)(uintptr_t)handle_param;
    }

    handle_str = (const char *)handle_param;
    if (strncmp(handle_str, TPM_HANDLE_HANDLE_PREFIX, sizeof(TPM_HANDLE_HANDLE_PREFIX) - 1) == 0) {
        return (uint32_t)strtoul(handle_str + sizeof(TPM_HANDLE_HANDLE_PREFIX) - 1, NULL, 16);
    }
    if (strncmp(handle_str, TPM_HANDLE_TPM2TSS_PREFIX, sizeof(TPM_HANDLE_TPM2TSS_PREFIX) - 1) == 0) {
        return (uint32_t)strtoul(handle_str + sizeof(TPM_HANDLE_TPM2TSS_PREFIX) - 1, NULL, 16);
    }

#undef TPM_HANDLE_START_RANGE
#undef TPM_HANDLE_END_RANGE
#undef TPM_HANDLE_HANDLE_PREFIX
#undef TPM_HANDLE_TPM2TSS_PREFIX

    return (uint32_t)strtoul(handle_str, NULL, 0);
}

static bool map_spdm_meas_hash_to_tpm(uint32_t meas_hash_algo, TPMI_ALG_HASH *tpm_hash)
{
    switch (meas_hash_algo) {
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256:
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_256:
        *tpm_hash = TPM2_ALG_SHA256;
        return true;
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384:
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_384:
        *tpm_hash = TPM2_ALG_SHA384;
        return true;
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_512:
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_512:
        *tpm_hash = TPM2_ALG_SHA512;
        return true;
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SM3_256:
        *tpm_hash = TPM2_ALG_SM3_256;
        return true;
    default:
        return false;
    }
}

bool libspdm_tpm_quote(
    const void *key_handle_str,
    uint32_t hash_algo,
    const uint8_t *pcr_indices,
    size_t pcr_count,
    const uint8_t *nonce,
    size_t nonce_size,
    void *quote_buffer,
    size_t *quote_buffer_size)
{
    TSS2_RC rc = 1;
    TSS2_TCTI_CONTEXT *tcti = NULL;
    ESYS_CONTEXT *esys = NULL;
    ESYS_TR key_tr = ESYS_TR_NONE;
    TPM2B_ATTEST *quoted = NULL;
    TPMT_SIGNATURE *signature = NULL;
    uint32_t key_handle;
    TPMI_ALG_HASH tpm_hash;
    TPML_PCR_SELECTION pcr_selection;
    TPM2B_DATA qual_data;
    TPMT_SIG_SCHEME in_scheme;
    size_t required_size = 0;
    size_t offset = 0;
    size_t i;

    if (quote_buffer_size == NULL) {
        return false;
    }

    if (!map_spdm_meas_hash_to_tpm(hash_algo, &tpm_hash)) {
        return false;
    }

    key_handle = parse_tpm_key_handle(key_handle_str);
    if (key_handle == 0) {
        return false;
    }

    memset(&pcr_selection, 0, sizeof(pcr_selection));
    pcr_selection.count = 1;
    pcr_selection.pcrSelections[0].hash = tpm_hash;
    pcr_selection.pcrSelections[0].sizeofSelect = 3;
    if (pcr_indices != NULL && pcr_count > 0) {
        for (i = 0; i < pcr_count; i++) {
            if (pcr_indices[i] < 24) {
                pcr_selection.pcrSelections[0].pcrSelect[pcr_indices[i] / 8] |=
                    (uint8_t)(1 << (pcr_indices[i] % 8));
            }
        }
    } else {
        pcr_selection.pcrSelections[0].pcrSelect[0] = 0x03; /* Default: PCR 0 and 1 */
    }

    memset(&qual_data, 0, sizeof(qual_data));
    if (nonce != NULL && nonce_size > 0) {
        /* Never truncate the freshness value. */
        if (nonce_size > sizeof(qual_data.buffer)) {
            return false;
        }
        qual_data.size = (UINT16)nonce_size;
        memcpy(qual_data.buffer, nonce, qual_data.size);
    }

    in_scheme.scheme = TPM2_ALG_NULL;

    rc = Tss2_TctiLdr_Initialize(getenv("TPM2TOOLS_TCTI"), &tcti);
    if (rc != TSS2_RC_SUCCESS) {
        goto out;
    }

    rc = Esys_Initialize(&esys, tcti, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        goto out;
    }

    rc = Esys_TR_FromTPMPublic(esys, key_handle, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &key_tr);
    if (rc != TSS2_RC_SUCCESS) {
        goto out;
    }

    rc = Esys_Quote(
        esys,
        key_tr,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &qual_data,
        &in_scheme,
        &pcr_selection,
        &quoted,
        &signature);
    if (rc != TSS2_RC_SUCCESS) {
        goto out;
    }

    /* Compute total required size */
    rc = Tss2_MU_TPM2B_ATTEST_Marshal(quoted, NULL, 0, &required_size);
    if (rc != TSS2_RC_SUCCESS) {
        goto out;
    }
    rc = Tss2_MU_TPMT_SIGNATURE_Marshal(signature, NULL, 0, &required_size);
    if (rc != TSS2_RC_SUCCESS) {
        goto out;
    }

    if (quote_buffer == NULL || *quote_buffer_size < required_size) {
        *quote_buffer_size = required_size;
        rc = 1; /* Buffer insufficient or size query */
        goto out;
    }

    offset = 0;
    rc = Tss2_MU_TPM2B_ATTEST_Marshal(quoted, (uint8_t *)quote_buffer, *quote_buffer_size, &offset);
    if (rc != TSS2_RC_SUCCESS) {
        goto out;
    }
    rc = Tss2_MU_TPMT_SIGNATURE_Marshal(signature, (uint8_t *)quote_buffer, *quote_buffer_size, &offset);
    if (rc != TSS2_RC_SUCCESS) {
        goto out;
    }

    *quote_buffer_size = offset;
    rc = TSS2_RC_SUCCESS;

out:
    if (quoted != NULL) {
        Esys_Free(quoted);
    }
    if (signature != NULL) {
        Esys_Free(signature);
    }
    if (key_tr != ESYS_TR_NONE) {
        Esys_TR_Close(esys, &key_tr);
    }
    if (esys != NULL) {
        Esys_Finalize(&esys);
    }
    if (tcti != NULL) {
        Tss2_TctiLdr_Finalize(&tcti);
    }

    return (rc == TSS2_RC_SUCCESS);
}

static uint32_t map_tpm_hash_to_base_hash(TPMI_ALG_HASH tpm_hash)
{
    switch (tpm_hash) {
    case TPM2_ALG_SHA256:
        return SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256;
    case TPM2_ALG_SHA384:
        return SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384;
    case TPM2_ALG_SHA512:
        return SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512;
    case TPM2_ALG_SM3_256:
        return SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SM3_256;
    default:
        return 0;
    }
}

bool libspdm_tpm_verify_quote(
    const void *pub_key_context,
    uint32_t base_asym_algo,
    uint32_t hash_algo,
    const void *quote_buffer,
    size_t quote_buffer_size,
    const uint8_t *expected_nonce,
    size_t expected_nonce_size)
{
    TSS2_RC rc;
    TPM2B_ATTEST attest;
    TPMS_ATTEST tpms_attest;
    TPMT_SIGNATURE sig;
    size_t offset = 0;
    size_t attest_offset = 0;
    uint8_t hash_digest[64];
    size_t hash_size = 0;
    uint8_t raw_sig[64];

    if (pub_key_context == NULL || quote_buffer == NULL || quote_buffer_size == 0) {
        return false;
    }

    const uint8_t *raw_buf = (const uint8_t *)quote_buffer;
    size_t raw_size = quote_buffer_size;

    /* Check if quote_buffer is wrapped in SPDM Format 1 General Opaque Data Table */
    if (quote_buffer_size >= sizeof(spdm_general_opaque_data_table_header_t) +
        sizeof(opaque_element_table_header_t) + 4) {
        const spdm_general_opaque_data_table_header_t *tbl =
            (const spdm_general_opaque_data_table_header_t *)quote_buffer;
        if (tbl->total_elements >= 1 &&
            tbl->reserved[0] == 0 && tbl->reserved[1] == 0 && tbl->reserved[2] == 0) {
            const opaque_element_table_header_t *elem =
                (const opaque_element_table_header_t *)(tbl + 1);
            if (elem->id == SPDM_REGISTRY_ID_TCG) {
                const uint8_t *p = (const uint8_t *)(elem + 1) + elem->vendor_len;
                uint16_t elem_data_len = (uint16_t)(p[0] | (p[1] << 8));
                p += sizeof(uint16_t);
                if ((size_t)(p - (const uint8_t *)quote_buffer) + elem_data_len <= quote_buffer_size) {
                    raw_buf = p;
                    raw_size = elem_data_len;
                }
            }
        }
    }

    /* Unmarshal TPM2B_ATTEST */
    rc = Tss2_MU_TPM2B_ATTEST_Unmarshal(raw_buf, raw_size, &offset, &attest);
    if (rc != TSS2_RC_SUCCESS) {
        return false;
    }

    /* Unmarshal TPMT_SIGNATURE */
    rc = Tss2_MU_TPMT_SIGNATURE_Unmarshal(raw_buf, raw_size, &offset, &sig);
    if (rc != TSS2_RC_SUCCESS) {
        return false;
    }

    /* Parse inner TPMS_ATTEST to check magic, type, and nonce */
    rc = Tss2_MU_TPMS_ATTEST_Unmarshal(attest.attestationData, attest.size, &attest_offset, &tpms_attest);
    if (rc != TSS2_RC_SUCCESS) {
        return false;
    }

    if (tpms_attest.magic != TPM2_GENERATED_VALUE) {
        return false;
    }
    if (tpms_attest.type != TPM2_ST_ATTEST_QUOTE) {
        return false;
    }

    if (expected_nonce != NULL && expected_nonce_size > 0) {
        if (tpms_attest.extraData.size != expected_nonce_size ||
            memcmp(tpms_attest.extraData.buffer, expected_nonce, expected_nonce_size) != 0) {
            return false;
        }
    }

    TPMI_ALG_HASH tpm_sig_hash = TPM2_ALG_NULL;
    if (sig.sigAlg == TPM2_ALG_ECDSA) {
        tpm_sig_hash = sig.signature.ecdsa.hash;
    } else if (sig.sigAlg == TPM2_ALG_RSASSA) {
        tpm_sig_hash = sig.signature.rsassa.hash;
    } else if (sig.sigAlg == TPM2_ALG_RSAPSS) {
        tpm_sig_hash = sig.signature.rsapss.hash;
    } else {
        return false;
    }

    /* If caller specified hash_algo, verify that it matches signature hash */
    if (hash_algo != 0) {
        TPMI_ALG_HASH expected_tpm_hash;
        if (map_spdm_meas_hash_to_tpm(hash_algo, &expected_tpm_hash)) {
            if (tpm_sig_hash != expected_tpm_hash) {
                return false;
            }
        }
    }

    uint32_t base_hash = map_tpm_hash_to_base_hash(tpm_sig_hash);
    if (base_hash == 0) {
        return false;
    }

    hash_size = libspdm_get_hash_size(base_hash);
    if (hash_size == 0 || hash_size > sizeof(hash_digest)) {
        return false;
    }

    if (!libspdm_hash_all(base_hash, attest.attestationData, attest.size, hash_digest)) {
        return false;
    }

    /* Extract signature according to algorithm.
     * Use spdm_version=0 so libspdm_asym_verify_hash verifies raw message_hash
     * directly without prepending the SPDM 1.2 signing context prefix. */
    if (sig.sigAlg == TPM2_ALG_ECDSA) {
        memset(raw_sig, 0, sizeof(raw_sig));
        if (sig.signature.ecdsa.signatureR.size <= 32) {
            memcpy(raw_sig + 32 - sig.signature.ecdsa.signatureR.size,
                   sig.signature.ecdsa.signatureR.buffer,
                   sig.signature.ecdsa.signatureR.size);
        } else if (sig.signature.ecdsa.signatureR.size == 33 && sig.signature.ecdsa.signatureR.buffer[0] == 0) {
            memcpy(raw_sig, sig.signature.ecdsa.signatureR.buffer + 1, 32);
        } else {
            return false;
        }

        if (sig.signature.ecdsa.signatureS.size <= 32) {
            memcpy(raw_sig + 64 - sig.signature.ecdsa.signatureS.size,
                   sig.signature.ecdsa.signatureS.buffer,
                   sig.signature.ecdsa.signatureS.size);
        } else if (sig.signature.ecdsa.signatureS.size == 33 && sig.signature.ecdsa.signatureS.buffer[0] == 0) {
            memcpy(raw_sig + 32, sig.signature.ecdsa.signatureS.buffer + 1, 32);
        } else {
            return false;
        }

        return libspdm_asym_verify_hash(
            0, 0,
            base_asym_algo, base_hash,
            (void *)(size_t)pub_key_context,
            hash_digest, hash_size,
            raw_sig, sizeof(raw_sig));
    } else if (sig.sigAlg == TPM2_ALG_RSASSA || sig.sigAlg == TPM2_ALG_RSAPSS) {
        return libspdm_asym_verify_hash(
            0, 0,
            base_asym_algo, base_hash,
            (void *)(size_t)pub_key_context,
            hash_digest, hash_size,
            sig.signature.rsassa.sig.buffer,
            sig.signature.rsassa.sig.size);
    }

    return false;
}

/* ---------------------------------------------------------------------------------------------
* PCR snapshot, strict Quote verification and the Quote OpaqueData element (DMTF/libspdm#3721)
* ------------------------------------------------------------------------------------------- */

#define LIBSPDM_TPM_PCR_MAX 24
#define LIBSPDM_TPM_PCR_READ_RETRIES 4

static bool tpm_pcr_bank(uint32_t meas_hash_algo, TPMI_ALG_HASH *bank, size_t *digest_size)
{
    if (!map_spdm_meas_hash_to_tpm(meas_hash_algo, bank)) {
        return false;
    }
    switch (*bank) {
    case TPM2_ALG_SHA256:
    case TPM2_ALG_SM3_256:
        *digest_size = 32;
        return true;
    case TPM2_ALG_SHA384:
        *digest_size = 48;
        return true;
    case TPM2_ALG_SHA512:
        *digest_size = 64;
        return true;
    default:
        return false;
    }
}

/* Strictly ascending PCR list -> 3-byte PCR select bitmap. */
static bool tpm_pcr_bitmap(const uint8_t *pcr_indices, size_t pcr_count, uint8_t bitmap[3])
{
    size_t i;

    if ((pcr_indices == NULL) || (pcr_count == 0) || (pcr_count > LIBSPDM_TPM_PCR_MAX)) {
        return false;
    }
    memset(bitmap, 0, 3);
    for (i = 0; i < pcr_count; i++) {
        if ((pcr_indices[i] >= LIBSPDM_TPM_PCR_MAX) ||
            ((i > 0) && (pcr_indices[i] <= pcr_indices[i - 1]))) {
            return false;
        }
        bitmap[pcr_indices[i] / 8] |= (uint8_t)(1 << (pcr_indices[i] % 8));
    }
    return true;
}

bool libspdm_tpm_read_pcrs(uint32_t hash_algo, const uint8_t *pcr_indices, size_t pcr_count,
                           void *pcr_values, size_t *pcr_values_size)
{
    TSS2_RC rc;
    TSS2_TCTI_CONTEXT *tcti = NULL;
    ESYS_CONTEXT *esys = NULL;
    TPMI_ALG_HASH bank;
    size_t digest_size;
    size_t required_size;
    uint8_t wanted[3];
    uint8_t remaining[3];
    TPML_PCR_SELECTION selection;
    TPML_PCR_SELECTION *selection_out;
    TPML_DIGEST *digests;
    UINT32 update_counter;
    UINT32 first_counter;
    size_t attempt;
    size_t pos;
    size_t d;
    uint8_t pcr;
    bool first;
    bool restart;
    bool result;

    if ((pcr_values_size == NULL) || !tpm_pcr_bank(hash_algo, &bank, &digest_size) ||
        !tpm_pcr_bitmap(pcr_indices, pcr_count, wanted)) {
        return false;
    }
    required_size = pcr_count * digest_size;
    if (pcr_values == NULL) {
        *pcr_values_size = required_size;
        return true;
    }
    if (*pcr_values_size < required_size) {
        *pcr_values_size = required_size;
        return false;
    }

    if (Tss2_TctiLdr_Initialize(getenv("TPM2TOOLS_TCTI"), &tcti) != TSS2_RC_SUCCESS) {
        return false;
    }
    if (Esys_Initialize(&esys, tcti, NULL) != TSS2_RC_SUCCESS) {
        Tss2_TctiLdr_Finalize(&tcti);
        return false;
    }

    result = false;
    for (attempt = 0; (attempt < LIBSPDM_TPM_PCR_READ_RETRIES) && !result; attempt++) {
        memcpy(remaining, wanted, sizeof(remaining));
        first = true;
        first_counter = 0;
        restart = false;
        while ((remaining[0] | remaining[1] | remaining[2]) != 0) {
            memset(&selection, 0, sizeof(selection));
            selection.count = 1;
            selection.pcrSelections[0].hash = bank;
            selection.pcrSelections[0].sizeofSelect = 3;
            memcpy(selection.pcrSelections[0].pcrSelect, remaining, sizeof(remaining));
            selection_out = NULL;
            digests = NULL;
            rc = Esys_PCR_Read(esys, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &selection,
                               &update_counter, &selection_out, &digests);
            if (rc != TSS2_RC_SUCCESS) {
                Esys_Free(selection_out);
                Esys_Free(digests);
                goto out;
            }
            if (first) {
                first_counter = update_counter;
                first = false;
            } else if (update_counter != first_counter) {
                /* A PCR was extended between the reads: start over for one snapshot. */
                restart = true;
            }
            d = 0;
            if (!restart && (selection_out->count == 1) &&
                (selection_out->pcrSelections[0].hash == bank)) {
                for (pcr = 0; pcr < LIBSPDM_TPM_PCR_MAX; pcr++) {
                    if ((selection_out->pcrSelections[0].sizeofSelect <= pcr / 8) ||
                        ((selection_out->pcrSelections[0].pcrSelect[pcr / 8] &
                          (1 << (pcr % 8))) == 0)) {
                        continue;
                    }
                    if ((d >= digests->count) || (digests->digests[d].size != digest_size) ||
                        ((remaining[pcr / 8] & (1 << (pcr % 8))) == 0)) {
                        d = 0;
                        break;
                    }
                    for (pos = 0; pcr_indices[pos] != pcr; pos++) {
                    }
                    memcpy((uint8_t *)pcr_values + pos * digest_size,
                           digests->digests[d].buffer, digest_size);
                    remaining[pcr / 8] &= (uint8_t) ~(1 << (pcr % 8));
                    d++;
                }
            }
            Esys_Free(selection_out);
            Esys_Free(digests);
            if (restart) {
                break;
            }
            if (d == 0) {
                /* No progress: the bank or a PCR is not allocated. */
                goto out;
            }
        }
        result = !restart;
    }
    if (result) {
        *pcr_values_size = required_size;
    }

out:
    Esys_Finalize(&esys);
    Tss2_TctiLdr_Finalize(&tcti);
    return result;
}

/* ECDSA r||s, each left-padded to the curve size. */
static bool tpm_ecdsa_raw_signature(const TPMT_SIGNATURE *sig, size_t half_size,
                                    uint8_t *raw, size_t raw_capacity)
{
    const TPM2B_ECC_PARAMETER *part[2] = {&sig->signature.ecdsa.signatureR,
                                          &sig->signature.ecdsa.signatureS};
    const uint8_t *value;
    size_t size;
    size_t i;

    if (raw_capacity < 2 * half_size) {
        return false;
    }
    memset(raw, 0, 2 * half_size);
    for (i = 0; i < 2; i++) {
        value = part[i]->buffer;
        size = part[i]->size;
        while ((size > half_size) && (value[0] == 0)) {
            value++;
            size--;
        }
        if (size > half_size) {
            return false;
        }
        memcpy(raw + i * half_size + (half_size - size), value, size);
    }
    return true;
}

bool libspdm_tpm_verify_quote_pcrs(
    const void *pub_key_context,
    const void *quote_buffer,
    size_t quote_buffer_size,
    const uint8_t *expected_nonce,
    size_t expected_nonce_size,
    uint32_t pcr_hash_algo,
    const uint8_t *pcr_indices,
    size_t pcr_count,
    const void *pcr_values,
    size_t pcr_values_size)
{
    TPM2B_ATTEST attest;
    TPMS_ATTEST tpms_attest;
    TPMT_SIGNATURE sig;
    size_t offset;
    size_t attest_offset;
    TPMI_ALG_HASH bank;
    TPMI_ALG_HASH sig_hash;
    size_t digest_size;
    uint8_t bitmap[3];
    const TPMS_PCR_SELECTION *quoted;
    uint32_t base_hash;
    size_t hash_size;
    uint8_t attest_hash[LIBSPDM_MAX_HASH_SIZE];
    uint8_t pcr_digest[LIBSPDM_MAX_HASH_SIZE];
    uint8_t raw_sig[132];
    const uint8_t *sig_value;
    size_t sig_size;
    EVP_PKEY *pkey;
    int bits;
    uint32_t asym;
    size_t i;

    if ((pub_key_context == NULL) || (quote_buffer == NULL) || (quote_buffer_size == 0) ||
        (expected_nonce == NULL) || (expected_nonce_size == 0) ||
        (expected_nonce_size > sizeof(tpms_attest.extraData.buffer)) || (pcr_values == NULL) ||
        !tpm_pcr_bank(pcr_hash_algo, &bank, &digest_size) ||
        !tpm_pcr_bitmap(pcr_indices, pcr_count, bitmap) ||
        (pcr_values_size != pcr_count * digest_size)) {
        return false;
    }

    /* MU(TPM2B_ATTEST) || MU(TPMT_SIGNATURE), nothing else. */
    offset = 0;
    if ((Tss2_MU_TPM2B_ATTEST_Unmarshal(quote_buffer, quote_buffer_size, &offset,
                                        &attest) != TSS2_RC_SUCCESS) ||
        (Tss2_MU_TPMT_SIGNATURE_Unmarshal(quote_buffer, quote_buffer_size, &offset,
                                          &sig) != TSS2_RC_SUCCESS) ||
        (offset != quote_buffer_size)) {
        return false;
    }
    attest_offset = 0;
    if ((Tss2_MU_TPMS_ATTEST_Unmarshal(attest.attestationData, attest.size, &attest_offset,
                                       &tpms_attest) != TSS2_RC_SUCCESS) ||
        (attest_offset != attest.size)) {
        return false;
    }
    if ((tpms_attest.magic != TPM2_GENERATED_VALUE) ||
        (tpms_attest.type != TPM2_ST_ATTEST_QUOTE)) {
        return false;
    }

    /* Freshness */
    if ((tpms_attest.extraData.size != expected_nonce_size) ||
        !libspdm_consttime_is_mem_equal(tpms_attest.extraData.buffer, expected_nonce,
                                        expected_nonce_size)) {
        return false;
    }

    /* Exactly the expected PCRs of the expected bank */
    if (tpms_attest.attested.quote.pcrSelect.count != 1) {
        return false;
    }
    quoted = &tpms_attest.attested.quote.pcrSelect.pcrSelections[0];
    if ((quoted->hash != bank) || (quoted->sizeofSelect < 3)) {
        return false;
    }
    for (i = 0; i < quoted->sizeofSelect; i++) {
        if (quoted->pcrSelect[i] != (i < 3 ? bitmap[i] : 0)) {
            return false;
        }
    }

    /* Signature scheme -> hash */
    switch (sig.sigAlg) {
    case TPM2_ALG_ECDSA:
        sig_hash = sig.signature.ecdsa.hash;
        break;
    case TPM2_ALG_RSASSA:
        sig_hash = sig.signature.rsassa.hash;
        break;
    case TPM2_ALG_RSAPSS:
        sig_hash = sig.signature.rsapss.hash;
        break;
    default:
        return false;
    }
    base_hash = map_tpm_hash_to_base_hash(sig_hash);
    hash_size = libspdm_get_hash_size(base_hash);
    if ((base_hash == 0) || (hash_size == 0) || (hash_size > sizeof(attest_hash))) {
        return false;
    }

    /* pcrDigest = H_sign(PCR values in selection order) */
    if ((tpms_attest.attested.quote.pcrDigest.size != hash_size) ||
        !libspdm_hash_all(base_hash, pcr_values, pcr_values_size, pcr_digest) ||
        !libspdm_consttime_is_mem_equal(tpms_attest.attested.quote.pcrDigest.buffer,
                                        pcr_digest, hash_size)) {
        return false;
    }

    if (!libspdm_hash_all(base_hash, attest.attestationData, attest.size, attest_hash)) {
        return false;
    }

    /* The asymmetric algorithm follows the Quote key, not the SPDM negotiation. */
    pkey = ((const libspdm_key_context *)pub_key_context)->evp_pkey;
    if (pkey == NULL) {
        return false;
    }
    bits = EVP_PKEY_get_bits(pkey);
    switch (EVP_PKEY_get_base_id(pkey)) {
    case EVP_PKEY_EC:
        if (sig.sigAlg != TPM2_ALG_ECDSA) {
            return false;
        }
        switch (bits) {
        case 256:
            asym = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256;
            break;
        case 384:
            asym = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384;
            break;
        case 521:
            asym = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521;
            break;
        default:
            return false;
        }
        sig_size = 2 * (size_t)((bits + 7) / 8);
        if (!tpm_ecdsa_raw_signature(&sig, sig_size / 2, raw_sig, sizeof(raw_sig))) {
            return false;
        }
        sig_value = raw_sig;
        break;
    case EVP_PKEY_RSA:
    case EVP_PKEY_RSA_PSS:
        if (sig.sigAlg == TPM2_ALG_ECDSA) {
            return false;
        }
        switch (bits) {
        case 2048:
            asym = (sig.sigAlg == TPM2_ALG_RSAPSS) ?
                   SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048 :
                   SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048;
            break;
        case 3072:
            asym = (sig.sigAlg == TPM2_ALG_RSAPSS) ?
                   SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072 :
                   SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072;
            break;
        case 4096:
            asym = (sig.sigAlg == TPM2_ALG_RSAPSS) ?
                   SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096 :
                   SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096;
            break;
        default:
            return false;
        }
        sig_value = sig.signature.rsassa.sig.buffer;
        sig_size = sig.signature.rsassa.sig.size;
        break;
    default:
        return false;
    }

    /* spdm_version 0: verify the raw digest, without the SPDM signing context. */
    return libspdm_asym_verify_hash(0, 0, asym, base_hash, (void *)(size_t)pub_key_context,
                                    attest_hash, hash_size, sig_value, sig_size);
}
