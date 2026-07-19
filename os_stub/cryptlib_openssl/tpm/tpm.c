/**
 *  Copyright Notice:
 *  Copyright 2021-2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include <complex.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <tss2/tss2_common.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_tctildr.h>

#include <openssl/provider.h>
#include <openssl/store.h>
#include <tss2/tss2_tcti.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_tpm2_types.h>
#include "hal/library/memlib.h"
#include "library/spdm_crypt_ext_lib.h"
#include "internal/libspdm_crypt_lib.h"

#include "../key_context.h"

/**
 * Map the configured IAK base-hash algorithm to the TPM ECDSA scheme hash and
 * matching OpenSSL digest. Defaults to SHA-256 when LIBSPDM_TPM_IAK_BASE_HASH_ALGO
 * is not defined (e.g. standalone crypt unit tests).
 **/
static bool tpm_iak_sig_hash_params(TPMI_ALG_HASH *tpm_hash, const EVP_MD **evp_md)
{
    uint32_t base_hash_algo;

#if defined(LIBSPDM_TPM_IAK_BASE_HASH_ALGO)
    base_hash_algo = (uint32_t)LIBSPDM_TPM_IAK_BASE_HASH_ALGO;
#else
    base_hash_algo = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256;
#endif

    switch (base_hash_algo) {
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256:
        *tpm_hash = TPM2_ALG_SHA256;
        *evp_md = EVP_sha256();
        return true;
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384:
        *tpm_hash = TPM2_ALG_SHA384;
        *evp_md = EVP_sha384();
        return true;
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512:
        *tpm_hash = TPM2_ALG_SHA512;
        *evp_md = EVP_sha512();
        return true;
    default:
        return false;
    }
}

bool g_tpm_device_initialized = false;

static libspdm_key_context *create_key_context(EVP_PKEY *pkey)
{
    libspdm_key_context *context = (libspdm_key_context *)malloc(sizeof(libspdm_key_context));
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

static bool get_keyinfo(const char *handle, void **context, int keyinfo_type)
{
    OSSL_STORE_CTX *store_ctx = NULL;
    OSSL_STORE_INFO *info = NULL;

    /* handle must look like: "tpm2tss:0x81010002" */
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
            break;
        }
        OSSL_STORE_INFO_free(info);
    }

    OSSL_STORE_close(store_ctx);

    if (*context == NULL){
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "no keyinfo %d foun on handle %s\n", keyinfo_type, handle));
        return false;
    }

    return true;
}

bool libspdm_tpm_get_pvt_key_handle(void *handle, void **context)
{
    EVP_PKEY *pkey = NULL;
    if (!get_keyinfo((const char *)handle, (void **)&pkey, OSSL_STORE_INFO_PKEY)){
        return false;
    }
    *context = create_key_context(pkey);
    return true;
}

bool libspdm_tpm_get_pub_key_handle(void *handle, void **context)
{
    EVP_PKEY *pkey = NULL;
    if (!get_keyinfo((const char *)handle, (void **)&pkey, OSSL_STORE_INFO_PUBKEY)){
        return false;
    }
    *context = create_key_context(pkey);
    return true;
}

/**
 * Map an SPDM measurement hash algorithm (PCR bank) to the matching base-hash
 * algorithm and digest size used for TPM Quote pcrDigest.
 *
 * Per TPM 2.0, pcrDigest is HashAlg(concatenation of selected PCR values)
 * where HashAlg is the selected PCR bank's hashAlg — not a fixed SHA-256.
 **/
static bool tpm_measurement_hash_to_pcr_digest_algo(uint32_t hash_algo,
                                                    uint32_t *base_hash_algo,
                                                    size_t *digest_size)
{
    switch (hash_algo) {
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256:
        *base_hash_algo = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256;
        *digest_size = LIBSPDM_SHA256_DIGEST_SIZE;
        return true;
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384:
        *base_hash_algo = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384;
        *digest_size = LIBSPDM_SHA384_DIGEST_SIZE;
        return true;
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_512:
        *base_hash_algo = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512;
        *digest_size = LIBSPDM_SHA512_DIGEST_SIZE;
        return true;
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_256:
        *base_hash_algo = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256;
        *digest_size = LIBSPDM_SHA3_256_DIGEST_SIZE;
        return true;
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_384:
        *base_hash_algo = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384;
        *digest_size = LIBSPDM_SHA3_384_DIGEST_SIZE;
        return true;
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_512:
        *base_hash_algo = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512;
        *digest_size = LIBSPDM_SHA3_512_DIGEST_SIZE;
        return true;
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SM3_256:
        *base_hash_algo = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SM3_256;
        *digest_size = LIBSPDM_SM3_256_DIGEST_SIZE;
        return true;
    default:
        return false;
    }
}

bool libspdm_tpm_read_pcr(uint32_t hash_algo, uint32_t index, void *buffer, size_t *size)
{
    TSS2_RC result;
    TSS2_TCTI_CONTEXT *tcti_context = NULL;
    ESYS_CONTEXT *context = NULL;
    size_t buffer_size;

    TPML_PCR_SELECTION sel = {
        .count = 1,
        .pcrSelections = {
            {
                .sizeofSelect = 3,
                .pcrSelect = {0x00, 0x00, 0x00, 0x00},
            },
        }
    };

    if ((buffer == NULL) || (size == NULL) ||
        (index == 0) || (index > 24)) {
        return false;
    }

    buffer_size = *size;
    *size = 0;
    switch (hash_algo)
    {
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256:
        sel.pcrSelections[0].hash = TPM2_ALG_SHA256;
        *size = 32;
        break;
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_256:
        sel.pcrSelections[0].hash = TPM2_ALG_SHA3_256;
        *size = 32;
        break;
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SM3_256:
        sel.pcrSelections[0].hash = TPM2_ALG_SM3_256;
        *size = 32;
        break;
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384:
        sel.pcrSelections[0].hash = TPM2_ALG_SHA384;
        *size = 48;
        break;
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_384:
        sel.pcrSelections[0].hash = TPM2_ALG_SHA3_384;
        *size = 48;
        break;
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_512:
        sel.pcrSelections[0].hash = TPM2_ALG_SHA512;
        *size = 64;
        break;
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_512:
        sel.pcrSelections[0].hash = TPM2_ALG_SHA3_512;
        *size = 64;
        break;
    default:
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "unsupported measurement hash algo %d\n", hash_algo));
        return false;
    }
    if (buffer_size < *size) {
        return false;
    }
    sel.pcrSelections[0].pcrSelect[(index - 1) / 8] |= 1 << ((index - 1) % 8);

    UINT32 uc;
    TPML_PCR_SELECTION *out = NULL;
    TPML_DIGEST *values = NULL;

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

    if ((values == NULL) || (values->count != 1) ||
        (values->digests[0].size != *size)) {
        result = TSS2_ESYS_RC_GENERAL_FAILURE;
        goto cleanup_esys;
    }
    memcpy(buffer, values->digests[0].buffer, *size);

cleanup_esys:
    Esys_Free(out);
    Esys_Free(values);
    Esys_Finalize(&context);

cleanup_tcti:
    Tss2_TctiLdr_Finalize(&tcti_context);

finish:
    return result == TSS2_RC_SUCCESS;
}

bool libspdm_tpm_quote(uint32_t key_handle,
                       uint32_t hash_algo,
                       uint32_t pcr_mask,
                       const uint8_t *nonce,
                       size_t nonce_size,
                       const uint8_t *pcr_data,
                       size_t pcr_data_size,
                       uint8_t *attest,
                       size_t *attest_size,
                       uint8_t *signature,
                       size_t *signature_size)
{
    TSS2_RC result;
    TSS2_TCTI_CONTEXT *tcti_context;
    ESYS_CONTEXT *context;
    ESYS_TR key;
    TPM2B_DATA qualifying_data;
    TPMT_SIG_SCHEME scheme;
    TPML_PCR_SELECTION selection;
    TPM2B_ATTEST *quoted;
    TPMT_SIGNATURE *quote_signature;
    TPMS_ATTEST decoded_attest;
    uint8_t expected_pcr_digest[LIBSPDM_MAX_HASH_SIZE];
    uint32_t pcr_digest_hash_algo;
    size_t pcr_digest_size;
    size_t offset;
    uint8_t index;

    if ((nonce == NULL) || (nonce_size != SPDM_NONCE_SIZE) ||
        (pcr_data == NULL) || (pcr_data_size == 0) ||
        (attest == NULL) || (attest_size == NULL) ||
        (signature == NULL) || (signature_size == NULL)) {
        return false;
    }

    if (!tpm_measurement_hash_to_pcr_digest_algo(hash_algo, &pcr_digest_hash_algo,
                                                 &pcr_digest_size)) {
        return false;
    }

    libspdm_zero_mem(&qualifying_data, sizeof(qualifying_data));
    qualifying_data.size = (uint16_t)nonce_size;
    libspdm_copy_mem(qualifying_data.buffer, sizeof(qualifying_data.buffer),
                     nonce, nonce_size);

    libspdm_zero_mem(&selection, sizeof(selection));
    selection.count = 1;
    selection.pcrSelections[0].sizeofSelect = 3;
    switch (hash_algo) {
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256:
        selection.pcrSelections[0].hash = TPM2_ALG_SHA256;
        break;
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_256:
        selection.pcrSelections[0].hash = TPM2_ALG_SHA3_256;
        break;
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SM3_256:
        selection.pcrSelections[0].hash = TPM2_ALG_SM3_256;
        break;
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384:
        selection.pcrSelections[0].hash = TPM2_ALG_SHA384;
        break;
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_384:
        selection.pcrSelections[0].hash = TPM2_ALG_SHA3_384;
        break;
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_512:
        selection.pcrSelections[0].hash = TPM2_ALG_SHA512;
        break;
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_512:
        selection.pcrSelections[0].hash = TPM2_ALG_SHA3_512;
        break;
    default:
        return false;
    }

    if ((pcr_mask == 0) || (pcr_mask >= (1u << 24))) {
        return false;
    }
    for (index = 0; index < 24; index++) {
        if ((pcr_mask & (1u << index)) != 0) {
            selection.pcrSelections[0].pcrSelect[index / 8] |=
                (uint8_t)(1u << (index % 8));
        }
    }

    {
        TPMI_ALG_HASH iak_sig_hash;
        const EVP_MD *iak_evp_md;

        if (!tpm_iak_sig_hash_params(&iak_sig_hash, &iak_evp_md)) {
            return false;
        }
        (void)iak_evp_md;
        libspdm_zero_mem(&scheme, sizeof(scheme));
        scheme.scheme = TPM2_ALG_ECDSA;
        scheme.details.ecdsa.hashAlg = iak_sig_hash;
    }
    tcti_context = NULL;
    context = NULL;
    key = ESYS_TR_NONE;
    quoted = NULL;
    quote_signature = NULL;

    result = Tss2_TctiLdr_Initialize(getenv("TPM2TOOLS_TCTI"), &tcti_context);
    if (result != TSS2_RC_SUCCESS) {
        goto finish;
    }
    result = Esys_Initialize(&context, tcti_context, NULL);
    if (result != TSS2_RC_SUCCESS) {
        goto finish;
    }
    result = Esys_TR_FromTPMPublic(context, key_handle, ESYS_TR_NONE,
                                   ESYS_TR_NONE, ESYS_TR_NONE, &key);
    if (result != TSS2_RC_SUCCESS) {
        goto finish;
    }
    result = Esys_Quote(context, key, ESYS_TR_PASSWORD, ESYS_TR_NONE,
                        ESYS_TR_NONE, &qualifying_data, &scheme, &selection,
                        &quoted, &quote_signature);
    if (result != TSS2_RC_SUCCESS) {
        goto finish;
    }

    offset = 0;
    result = Tss2_MU_TPMS_ATTEST_Unmarshal(quoted->attestationData,
                                           quoted->size, &offset,
                                           &decoded_attest);
    if (result != TSS2_RC_SUCCESS) {
        goto finish;
    }
    /* Defense-in-depth: verify TPM returned a well-formed Quote. */
    if ((decoded_attest.magic != TPM2_GENERATED_VALUE) ||
        (decoded_attest.type != TPM2_ST_ATTEST_QUOTE)) {
        result = TSS2_ESYS_RC_GENERAL_FAILURE;
        goto finish;
    }
    /* Qualifying data must echo back the requester nonce. */
    if ((decoded_attest.extraData.size != nonce_size) ||
        !libspdm_consttime_is_mem_equal(decoded_attest.extraData.buffer,
                                        nonce, nonce_size)) {
        result = TSS2_ESYS_RC_GENERAL_FAILURE;
        goto finish;
    }
    /* pcrDigest must equal Hash(selected PCR values). */
    if ((decoded_attest.attested.quote.pcrDigest.size != pcr_digest_size) ||
        !libspdm_hash_all(pcr_digest_hash_algo, pcr_data, pcr_data_size,
                          expected_pcr_digest) ||
        !libspdm_consttime_is_mem_equal(
            decoded_attest.attested.quote.pcrDigest.buffer,
            expected_pcr_digest, pcr_digest_size)) {
        result = TSS2_ESYS_RC_GENERAL_FAILURE;
        goto finish;
    }

    offset = 0;
    result = Tss2_MU_TPM2B_ATTEST_Marshal(quoted, attest, *attest_size, &offset);
    if (result != TSS2_RC_SUCCESS) {
        goto finish;
    }
    *attest_size = offset;

    offset = 0;
    result = Tss2_MU_TPMT_SIGNATURE_Marshal(quote_signature, signature,
                                            *signature_size, &offset);
    if (result != TSS2_RC_SUCCESS) {
        goto finish;
    }
    *signature_size = offset;

finish:
    Esys_Free(quoted);
    Esys_Free(quote_signature);
    if (context != NULL) {
        Esys_Finalize(&context);
    }
    if (tcti_context != NULL) {
        Tss2_TctiLdr_Finalize(&tcti_context);
    }
    return result == TSS2_RC_SUCCESS;
}

bool libspdm_tpm_verify_quote(const uint8_t *cert,
                              size_t cert_size,
                              uint32_t hash_algo,
                              uint32_t pcr_mask,
                              const uint8_t *nonce,
                              size_t nonce_size,
                              const uint8_t *pcr_data,
                              size_t pcr_data_size,
                              const uint8_t *attest,
                              size_t attest_size,
                              const uint8_t *signature,
                              size_t signature_size)
{
    TPM2B_ATTEST decoded_quote;
    TPMS_ATTEST decoded_attest;
    TPMT_SIGNATURE decoded_signature;
    uint8_t expected_pcr_digest[LIBSPDM_MAX_HASH_SIZE];
    uint8_t expected_pcr_select[3];
    TPMI_ALG_HASH expected_pcr_bank;
    uint32_t pcr_digest_hash_algo;
    size_t pcr_digest_size;
    const unsigned char *cert_ptr;
    X509 *x509;
    EVP_PKEY *public_key;
    ECDSA_SIG *ecdsa_signature;
    BIGNUM *r;
    BIGNUM *s;
    unsigned char *der_signature;
    unsigned char *der_ptr;
    int der_signature_size;
    EVP_MD_CTX *md_context;
    size_t offset;
    TSS2_RC result;
    bool verified;
    uint8_t index;

    if ((cert == NULL) || (cert_size == 0) ||
        (nonce == NULL) || (nonce_size != SPDM_NONCE_SIZE) ||
        (pcr_data == NULL) || (pcr_data_size == 0) ||
        (attest == NULL) || (attest_size == 0) ||
        (signature == NULL) || (signature_size == 0)) {
        return false;
    }

    if (!tpm_measurement_hash_to_pcr_digest_algo(hash_algo, &pcr_digest_hash_algo,
                                                 &pcr_digest_size)) {
        return false;
    }

    libspdm_zero_mem(expected_pcr_select, sizeof(expected_pcr_select));
    switch (hash_algo) {
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256:
        expected_pcr_bank = TPM2_ALG_SHA256;
        break;
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_256:
        expected_pcr_bank = TPM2_ALG_SHA3_256;
        break;
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SM3_256:
        expected_pcr_bank = TPM2_ALG_SM3_256;
        break;
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384:
        expected_pcr_bank = TPM2_ALG_SHA384;
        break;
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_384:
        expected_pcr_bank = TPM2_ALG_SHA3_384;
        break;
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_512:
        expected_pcr_bank = TPM2_ALG_SHA512;
        break;
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_512:
        expected_pcr_bank = TPM2_ALG_SHA3_512;
        break;
    default:
        return false;
    }
    if ((pcr_mask == 0) || (pcr_mask >= (1u << 24))) {
        return false;
    }
    for (index = 0; index < 24; index++) {
        if ((pcr_mask & (1u << index)) != 0) {
            expected_pcr_select[index / 8] |= (uint8_t)(1u << (index % 8));
        }
    }

    offset = 0;
    result = Tss2_MU_TPM2B_ATTEST_Unmarshal(attest, attest_size, &offset,
                                            &decoded_quote);
    if ((result != TSS2_RC_SUCCESS) || (offset != attest_size)) {
        return false;
    }
    offset = 0;
    result = Tss2_MU_TPMS_ATTEST_Unmarshal(decoded_quote.attestationData,
                                           decoded_quote.size, &offset,
                                           &decoded_attest);
    if ((result != TSS2_RC_SUCCESS) || (offset != decoded_quote.size)) {
        return false;
    }
    /* Attestation structure must be a valid Quote. */
    if ((decoded_attest.magic != TPM2_GENERATED_VALUE) ||
        (decoded_attest.type != TPM2_ST_ATTEST_QUOTE)) {
        return false;
    }
    /* Qualifying data (extraData) must match the requester nonce. */
    if ((decoded_attest.extraData.size != nonce_size) ||
        !libspdm_consttime_is_mem_equal(decoded_attest.extraData.buffer,
                                        nonce, nonce_size)) {
        return false;
    }
    /* PCR selection must match the expected bank and mask. */
    if ((decoded_attest.attested.quote.pcrSelect.count != 1) ||
        (decoded_attest.attested.quote.pcrSelect.pcrSelections[0].hash !=
         expected_pcr_bank) ||
        (decoded_attest.attested.quote.pcrSelect.pcrSelections[0].sizeofSelect !=
         sizeof(expected_pcr_select)) ||
        !libspdm_consttime_is_mem_equal(
            decoded_attest.attested.quote.pcrSelect.pcrSelections[0].pcrSelect,
            expected_pcr_select, sizeof(expected_pcr_select))) {
        return false;
    }
    /* pcrDigest must equal Hash(concatenation of selected PCR values). */
    if ((decoded_attest.attested.quote.pcrDigest.size != pcr_digest_size) ||
        !libspdm_hash_all(pcr_digest_hash_algo, pcr_data, pcr_data_size,
                          expected_pcr_digest) ||
        !libspdm_consttime_is_mem_equal(
            decoded_attest.attested.quote.pcrDigest.buffer,
            expected_pcr_digest, pcr_digest_size)) {
        return false;
    }

    {
        TPMI_ALG_HASH expected_iak_sig_hash;
        const EVP_MD *iak_evp_md;

        if (!tpm_iak_sig_hash_params(&expected_iak_sig_hash, &iak_evp_md)) {
            return false;
        }
        offset = 0;
        result = Tss2_MU_TPMT_SIGNATURE_Unmarshal(signature, signature_size,
                                                  &offset, &decoded_signature);
        if ((result != TSS2_RC_SUCCESS) || (offset != signature_size) ||
            (decoded_signature.sigAlg != TPM2_ALG_ECDSA) ||
            (decoded_signature.signature.ecdsa.hash != expected_iak_sig_hash)) {
            return false;
        }

        cert_ptr = cert;
        x509 = d2i_X509(NULL, &cert_ptr, cert_size);
        if ((x509 == NULL) || (cert_ptr != cert + cert_size)) {
            X509_free(x509);
            return false;
        }
        public_key = X509_get_pubkey(x509);
        X509_free(x509);
        if (public_key == NULL) {
            return false;
        }

        /*
         * TPM ECDSA signatures store R and S as raw big-endian integers.
         * OpenSSL EVP_DigestVerify requires a DER-encoded ECDSA-Sig-Value
         * (SEQUENCE { INTEGER r, INTEGER s }). Convert R||S → ECDSA_SIG → DER.
         * After ECDSA_SIG_set0 succeeds, r and s ownership transfers to
         * ecdsa_signature and must not be freed separately.
         */
        r = BN_bin2bn(decoded_signature.signature.ecdsa.signatureR.buffer,
                      decoded_signature.signature.ecdsa.signatureR.size, NULL);
        s = BN_bin2bn(decoded_signature.signature.ecdsa.signatureS.buffer,
                      decoded_signature.signature.ecdsa.signatureS.size, NULL);
        ecdsa_signature = ECDSA_SIG_new();
        if ((r == NULL) || (s == NULL) || (ecdsa_signature == NULL)) {
            BN_free(r);
            BN_free(s);
            ECDSA_SIG_free(ecdsa_signature);
            EVP_PKEY_free(public_key);
            return false;
        }
        if (ECDSA_SIG_set0(ecdsa_signature, r, s) != 1) {
            BN_free(r);
            BN_free(s);
            ECDSA_SIG_free(ecdsa_signature);
            EVP_PKEY_free(public_key);
            return false;
        }

        /* First call with NULL buffer returns the required DER length. */
        der_signature_size = i2d_ECDSA_SIG(ecdsa_signature, NULL);
        der_signature = NULL;
        if (der_signature_size > 0) {
            der_signature = malloc((size_t)der_signature_size);
        }
        if (der_signature == NULL) {
            ECDSA_SIG_free(ecdsa_signature);
            EVP_PKEY_free(public_key);
            return false;
        }
        /* Second call writes the DER bytes and advances der_ptr. */
        der_ptr = der_signature;
        if (i2d_ECDSA_SIG(ecdsa_signature, &der_ptr) != der_signature_size) {
            free(der_signature);
            ECDSA_SIG_free(ecdsa_signature);
            EVP_PKEY_free(public_key);
            return false;
        }

        /*
         * Verify: Hash(raw TPMS_ATTEST bytes) against the DER-encoded ECDSA
         * signature using the IAK leaf public key. decoded_quote.size is the
         * inner attestationData length (not the outer TPM2B wrapper).
         */
        md_context = EVP_MD_CTX_new();
        if (md_context == NULL) {
            verified = false;
        } else if (EVP_DigestVerifyInit(md_context, NULL, iak_evp_md, NULL,
                                        public_key) != 1) {
            verified = false;
        } else {
            verified = EVP_DigestVerify(md_context, der_signature,
                                        (size_t)der_signature_size,
                                        decoded_quote.attestationData,
                                        decoded_quote.size) == 1;
        }
        EVP_MD_CTX_free(md_context);
        free(der_signature);
        ECDSA_SIG_free(ecdsa_signature);
        EVP_PKEY_free(public_key);
        return verified;
    }
}

bool libspdm_tpm_read_nv(uint32_t index, void **buffer, size_t *size)
{
    TSS2_RC rc;
    TSS2_TCTI_CONTEXT *tcti = NULL;
    ESYS_CONTEXT *esys = NULL;
    ESYS_TR nv_tr = ESYS_TR_NONE;

    TPM2B_NV_PUBLIC *nv_pub = NULL;
    TPM2B_NAME *nv_name = NULL;
    TPMS_CAPABILITY_DATA *cap = NULL;

    UINT16 nv_size;
    UINT32 max_nv_buf;
    UINT16 offset = 0;

    if ((buffer == NULL) || (size == NULL)) {
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
        rc = TSS2_ESYS_RC_GENERAL_FAILURE;
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
    if (rc != TSS2_RC_SUCCESS)
        goto out;

    max_nv_buf = cap->data.tpmProperties.tpmProperty[0].value;
    if (max_nv_buf == 0) {
        rc = TSS2_ESYS_RC_GENERAL_FAILURE;
        goto out;
    }

    *buffer = malloc(nv_size);
    if (!*buffer) {
        rc = TSS2_ESYS_RC_MEMORY;
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

        if ((chunk == NULL) || (chunk->size == 0) ||
            (chunk->size > nv_size - offset)) {
            Esys_Free(chunk);
            rc = TSS2_ESYS_RC_GENERAL_FAILURE;
            goto out;
        }

        memcpy((uint8_t *)(*buffer) + offset, chunk->buffer, chunk->size);
        offset += chunk->size;
        Esys_Free(chunk);
    }

    *size = nv_size;
    rc = TSS2_RC_SUCCESS;

out:
    if ((rc != TSS2_RC_SUCCESS) && (*buffer != NULL)) {
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
