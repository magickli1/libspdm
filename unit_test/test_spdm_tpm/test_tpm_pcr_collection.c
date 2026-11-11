/**
 * Copyright Notice:
 * Copyright 2026 DMTF. All rights reserved.
 * License: BSD 3-Clause License. See LICENSE.md in the repository root.
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_device_secret_lib.h"
#include "library/spdm_common_lib.h"
#include "library/spdm_crypt_lib.h"
#include "library/spdm_crypt_ext_lib.h"
#include "library/spdm_tpm_pcr.h"
#include "library/spdm_tpm_quote_opaque.h"
#include "hal/library/responder/measlib.h"
#include "keys.h"
#include <tss2/tss2_mu.h>

/* Compile the production collector without LTO so --wrap intercepts its
 * TPM calls. All other tests continue to use the real backend. */
static bool m_mock_collection;
static void *m_iak_key;
static uint8_t m_iak_public[64];
static uint8_t m_pcrs[LIBSPDM_TPM_PCR_COUNT][LIBSPDM_MAX_HASH_SIZE];
static size_t m_extend_before_quote;
static size_t m_quote_count;

bool __real_libspdm_tpm_device_init(void);
bool __real_libspdm_tpm_read_pcrs(uint32_t algorithm, const uint8_t *indices,
                                  size_t count, void *values, size_t *size);
bool __real_libspdm_tpm_quote(const void *handle, uint32_t algorithm,
                              const uint8_t *indices, size_t count, const uint8_t *nonce,
                              size_t nonce_size, void *quote, size_t *quote_size);
bool __real_libspdm_tpm_get_pub_key_handle(const void *handle, void **key);

bool __wrap_libspdm_tpm_device_init(void)
{
    return m_mock_collection ? true : __real_libspdm_tpm_device_init();
}

bool __wrap_libspdm_tpm_read_pcrs(uint32_t algorithm, const uint8_t *indices,
                                  size_t count, void *values, size_t *size)
{
    size_t digest_size;
    size_t index;

    if (!m_mock_collection) {
        return __real_libspdm_tpm_read_pcrs(algorithm, indices, count, values, size);
    }
    digest_size = libspdm_get_measurement_hash_size(algorithm);
    assert_true(*size >= count * digest_size);
    for (index = 0; index < count; index++) {
        assert_true(indices[index] < LIBSPDM_TPM_PCR_COUNT);
        libspdm_copy_mem((uint8_t *)values + index * digest_size, digest_size,
                         m_pcrs[indices[index]], digest_size);
    }
    *size = count * digest_size;
    return true;
}

bool __wrap_libspdm_tpm_get_pub_key_handle(const void *handle, void **key)
{
    if (!m_mock_collection) {
        return __real_libspdm_tpm_get_pub_key_handle(handle, key);
    }
    assert_string_equal(handle, LIBSPDM_TPM_HANDLE_IAK);
    *key = libspdm_ec_new_by_nid(LIBSPDM_CRYPTO_NID_SECP256R1);
    assert_non_null(*key);
    assert_true(libspdm_ec_set_pub_key(*key, m_iak_public, sizeof(m_iak_public)));
    return true;
}

bool __wrap_libspdm_tpm_quote(const void *handle, uint32_t algorithm,
                              const uint8_t *indices, size_t count, const uint8_t *nonce,
                              size_t nonce_size, void *quote, size_t *quote_size)
{
    TPM2B_ATTEST attest = {0};
    TPMS_ATTEST body = {0};
    TPMT_SIGNATURE signature = {0};
    uint8_t values[LIBSPDM_TPM_PCR_COUNT * LIBSPDM_MAX_HASH_SIZE];
    uint8_t hash[32], raw_signature[64];
    size_t signature_size = sizeof(raw_signature);
    size_t digest_size;
    size_t body_size = 0, offset = 0, index;
    TPMS_PCR_SELECTION *selection;

    if (!m_mock_collection) {
        return __real_libspdm_tpm_quote(handle, algorithm, indices, count, nonce,
                                        nonce_size, quote, quote_size);
    }
    assert_string_equal(handle, LIBSPDM_TPM_HANDLE_IAK);
    digest_size = libspdm_get_measurement_hash_size(algorithm);
    m_quote_count++;
    if (m_extend_before_quote != 0) {
        m_extend_before_quote--;
        m_pcrs[indices[0]][0] ^= 0x80;
    }
    body.magic = TPM2_GENERATED_VALUE;
    body.type = TPM2_ST_ATTEST_QUOTE;
    body.extraData.size = (UINT16)nonce_size;
    libspdm_copy_mem(body.extraData.buffer, sizeof(body.extraData.buffer), nonce, nonce_size);
    body.attested.quote.pcrSelect.count = 1;
    selection = &body.attested.quote.pcrSelect.pcrSelections[0];
    selection->hash = digest_size == 32 ? TPM2_ALG_SHA256 : TPM2_ALG_SHA384;
    selection->sizeofSelect = 3;
    for (index = 0; index < count; index++) {
        selection->pcrSelect[indices[index] / 8] |= (uint8_t)(1u << (indices[index] % 8));
        libspdm_copy_mem(values + index * digest_size, digest_size,
                         m_pcrs[indices[index]], digest_size);
    }
    body.attested.quote.pcrDigest.size = sizeof(hash);
    assert_true(libspdm_hash_all(SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
                                 values, count * digest_size, body.attested.quote.pcrDigest.buffer));
    assert_int_equal(Tss2_MU_TPMS_ATTEST_Marshal(&body, attest.attestationData,
                                                 sizeof(attest.attestationData), &body_size), 0);
    attest.size = (UINT16)body_size;
    assert_true(libspdm_hash_all(SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
                                 attest.attestationData, body_size, hash));
    assert_true(libspdm_ecdsa_sign(m_iak_key, LIBSPDM_CRYPTO_NID_SHA256, hash, sizeof(hash),
                                   raw_signature, &signature_size));
    signature.sigAlg = TPM2_ALG_ECDSA;
    signature.signature.ecdsa.hash = TPM2_ALG_SHA256;
    signature.signature.ecdsa.signatureR.size = 32;
    signature.signature.ecdsa.signatureS.size = 32;
    libspdm_copy_mem(signature.signature.ecdsa.signatureR.buffer, 32, raw_signature, 32);
    libspdm_copy_mem(signature.signature.ecdsa.signatureS.buffer, 32, raw_signature + 32, 32);
    assert_int_equal(Tss2_MU_TPM2B_ATTEST_Marshal(&attest, quote, *quote_size, &offset), 0);
    assert_int_equal(Tss2_MU_TPMT_SIGNATURE_Marshal(&signature, quote, *quote_size, &offset), 0);
    *quote_size = offset;
    return true;
}

int libspdm_tpm_collection_setup(void **state)
{
    size_t size = sizeof(m_iak_public);

    m_iak_key = libspdm_ec_new_by_nid(LIBSPDM_CRYPTO_NID_SECP256R1);
    assert_non_null(m_iak_key);
    assert_true(libspdm_ec_generate_key(m_iak_key, m_iak_public, &size));
    m_mock_collection = true;
    return 0;
}

int libspdm_tpm_collection_teardown(void **state)
{
    m_mock_collection = false;
    libspdm_ec_free(m_iak_key);
    m_iak_key = NULL;
    return 0;
}

typedef struct {
    uint8_t record[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
    size_t record_size;
    uint8_t opaque[1024];
    size_t opaque_size;
} collection_t;

static libspdm_return_t collect(uint32_t bank, uint8_t index, const uint8_t *nonce,
                                collection_t *result)
{
    uint8_t changed, count;
    libspdm_return_t status;

    result->record_size = sizeof(result->record);
    status = libspdm_measurement_collection(NULL, NULL, 0x1300,
                                            SPDM_MEASUREMENT_SPECIFICATION_DMTF, bank, index,
                                            nonce ==
                                            NULL ? 0 : SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE,
                                            nonce, 0, 0, NULL, &changed, &count, result->record, &result->record_size);
    result->opaque_size = sizeof(result->opaque);
    assert_true(libspdm_measurement_opaque_data(NULL, NULL, 0x1300,
                                                SPDM_MEASUREMENT_SPECIFICATION_DMTF, bank, index, 0, 0, NULL,
                                                result->opaque, &result->opaque_size));
    return status;
}

void test_spdm_tpm_pcr_collection(void **state)
{
    static collection_t result;
    const uint32_t banks[] = {SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256,
                              SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384};
    uint8_t nonce[SPDM_NONCE_SIZE], bad_nonce[SPDM_NONCE_SIZE];
    uint8_t slot;
    const void *quote;
    size_t quote_size, bank_index, index;
    void *public_key;

    memset(nonce, 0xA5, sizeof(nonce));
    memset(bad_nonce, 0xB6, sizeof(bad_nonce));
    for (bank_index = 0; bank_index < LIBSPDM_ARRAY_SIZE(banks); bank_index++) {
        for (index = 0; index < LIBSPDM_TPM_PCR_COUNT; index++) {
            memset(m_pcrs[index], (int)index, sizeof(m_pcrs[index]));
        }
        m_quote_count = 0;
        m_extend_before_quote = 0;
        assert_int_equal(collect(banks[bank_index], 0xFF, NULL, &result), LIBSPDM_STATUS_SUCCESS);
        assert_int_equal(m_quote_count, 0);
        assert_int_equal(result.opaque_size, 0);
        assert_int_equal(collect(banks[bank_index], 0xFF, nonce, &result), LIBSPDM_STATUS_SUCCESS);
        assert_int_equal(m_quote_count, 1);
        assert_true(libspdm_tpm_quote_opaque_decode(result.opaque, result.opaque_size,
                                                    &slot, &quote, &quote_size));
        assert_int_equal(slot, LIBSPDM_TPM_IAK_SLOT_ID);
        assert_true(__wrap_libspdm_tpm_get_pub_key_handle(LIBSPDM_TPM_HANDLE_IAK, &public_key));
        assert_true(libspdm_tpm_verify_quote_measurement_record(public_key, quote, quote_size,
                                                                nonce, sizeof(nonce), banks[bank_index], result.record,
                                                                result.record_size));
        assert_false(libspdm_tpm_verify_quote_measurement_record(public_key, quote, quote_size,
                                                                 bad_nonce, sizeof(bad_nonce), banks[bank_index],
                                                                 result.record, result.record_size));
        result.record[sizeof(spdm_measurement_block_dmtf_t)] ^= 1;
        assert_false(libspdm_tpm_verify_quote_measurement_record(public_key, quote, quote_size,
                                                                 nonce, sizeof(nonce), banks[bank_index], result.record,
                                                                 result.record_size));

        /* A single-PCR request must attest only that PCR, and consume its cache once. */
        assert_int_equal(collect(banks[bank_index], 1, nonce, &result), LIBSPDM_STATUS_SUCCESS);
        assert_true(libspdm_tpm_quote_opaque_decode(result.opaque, result.opaque_size,
                                                    &slot, &quote, &quote_size));
        assert_true(libspdm_tpm_verify_quote_measurement_record(public_key, quote, quote_size,
                                                                nonce, sizeof(nonce), banks[bank_index], result.record,
                                                                result.record_size));
        result.opaque_size = sizeof(result.opaque);
        assert_true(libspdm_measurement_opaque_data(NULL, NULL, 0x1300,
                                                    SPDM_MEASUREMENT_SPECIFICATION_DMTF, banks[bank_index], 1, 0, 0,
                                                    NULL,
                                                    result.opaque, &result.opaque_size));
        assert_int_equal(result.opaque_size, 0);

        m_quote_count = 0;
        m_extend_before_quote = 1;
        assert_int_equal(collect(banks[bank_index], 0xFF, nonce, &result), LIBSPDM_STATUS_SUCCESS);
        assert_int_equal(m_quote_count, 2);
        assert_true(libspdm_tpm_quote_opaque_decode(result.opaque, result.opaque_size,
                                                    &slot, &quote, &quote_size));
        assert_true(libspdm_tpm_verify_quote_measurement_record(public_key, quote, quote_size,
                                                                nonce, sizeof(nonce), banks[bank_index], result.record,
                                                                result.record_size));
        m_extend_before_quote = (size_t)-1;
        assert_int_equal(collect(banks[bank_index], 0xFF, nonce, &result),
                         LIBSPDM_STATUS_MEAS_INTERNAL_ERROR);
        assert_int_equal(result.opaque_size, 0);
        m_extend_before_quote = 0;
        assert_int_equal(collect(banks[bank_index], LIBSPDM_MEASUREMENT_INDEX_SVN, nonce, &result),
                         LIBSPDM_STATUS_SUCCESS);
        assert_int_equal(result.opaque_size, 0);
        libspdm_ec_free(public_key);
    }
}
