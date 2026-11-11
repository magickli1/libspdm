/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "library/spdm_common_lib.h"
#include "library/spdm_crypt_lib.h"
#include "library/spdm_crypt_ext_lib.h"
#include "internal/libspdm_device_secret_lib.h"
#include "internal/libspdm_common_lib.h"
#include "hal/library/responder/measlib.h"
#include "hal/library/responder/key_pair_info.h"
#include "industry_standard/spdm_secured_message.h"
#include "keys.h"
#include "library/spdm_tpm_quote_opaque.h"

#include <tss2/tss2_mu.h>

extern size_t libspdm_secret_lib_meas_opaque_data_size;

extern size_t libspdm_fill_measurement_image_hash_block(
    bool use_bit_stream,
    uint32_t measurement_hash_algo,
    uint8_t measurements_index,
    spdm_measurement_block_dmtf_t *measurement_block);

static bool is_tpm_available(void)
{
    return (getenv("TPM2TOOLS_TCTI") != NULL);
}

/* --------------------------------------------------------------------------
 * Offline / Parameter Validation & Invariant Tests
 * -------------------------------------------------------------------------- */

static void test_tpm_device_init(void **state)
{
    bool status;

    if (!is_tpm_available()) {
        print_message("[SKIPPED] TPM simulator not running (TPM2TOOLS_TCTI not set)\n");
        return;
    }

    status = libspdm_tpm_device_init();
    assert_true(status);

    /* Test idempotency */
    status = libspdm_tpm_device_init();
    assert_true(status);
}

static void test_tpm_key_handle_null_params(void **state)
{
    void *context = NULL;
    bool status;

    status = libspdm_tpm_get_pvt_key_handle(NULL, &context);
    assert_false(status);
    assert_null(context);

    status = libspdm_tpm_get_pvt_key_handle("handle:0x81000021", NULL);
    assert_false(status);

    status = libspdm_tpm_get_pub_key_handle(NULL, &context);
    assert_false(status);
    assert_null(context);

    status = libspdm_tpm_get_pub_key_handle("handle:0x81000021", NULL);
    assert_false(status);
}

static void test_tpm_read_pcr_validation(void **state)
{
    uint8_t buffer[64];
    size_t size;
    bool status;

    size = sizeof(buffer);

    /* NULL buffer */
    status = libspdm_tpm_read_pcr(
        SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256, 0, NULL, &size);
    assert_false(status);

    /* NULL size */
    status = libspdm_tpm_read_pcr(
        SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256, 0, buffer, NULL);
    assert_false(status);

    /* Unsupported algorithm */
    size = sizeof(buffer);
    status = libspdm_tpm_read_pcr(0xFFFFFFFF, 0, buffer, &size);
    assert_false(status);

    /* Invalid index (>= 24) */
    size = sizeof(buffer);
    status = libspdm_tpm_read_pcr(
        SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256, 24, buffer, &size);
    assert_false(status);

    status = libspdm_tpm_read_pcr(
        SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256, 100, buffer, &size);
    assert_false(status);

    /* Buffer undersize check: should return required size (32 for SHA256) */
    size = 16;
    status = libspdm_tpm_read_pcr(
        SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256, 0, buffer, &size);
    assert_false(status);
    assert_int_equal(size, 32);

    /* Buffer undersize check: SHA384 requires 48 bytes */
    size = 16;
    status = libspdm_tpm_read_pcr(
        SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384, 0, buffer, &size);
    assert_false(status);
    assert_int_equal(size, 48);
}

static void test_tpm_read_nv_validation(void **state)
{
    void *buffer = NULL;
    size_t size = 0;
    bool status;

    status = libspdm_tpm_read_nv(0x1500021, NULL, &size);
    assert_false(status);

    status = libspdm_tpm_read_nv(0x1500021, &buffer, NULL);
    assert_false(status);
    assert_null(buffer);
}

static void test_spdm_tpm_security_stubs(void **state)
{
    void *data = NULL;
    size_t size = 0;
    void *context = NULL;
    bool status;

    /* Raw private keys must never be readable from the TPM stub */
    status = libspdm_read_responder_private_key(
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256, &data, &size);
    assert_false(status);

    status = libspdm_get_responder_private_key_from_raw_data(
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256, &context);
    assert_false(status);

#if (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) || (LIBSPDM_ENABLE_CAPABILITY_ENDPOINT_INFO_CAP)
    status = libspdm_read_requester_private_key(
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256, &data, &size);
    assert_false(status);

    status = libspdm_get_requester_private_key_from_raw_data(
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256, &context);
    assert_false(status);
#endif

    status = libspdm_read_responder_public_key(
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256, &data, &size);
    assert_false(status);

    status = libspdm_read_requester_public_key(
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256, &data, &size);
    assert_false(status);
}

static void test_spdm_tpm_meas_validation(void **state)
{
    spdm_measurement_block_dmtf_t block;
    size_t block_size;

    /* use_bit_stream is not supported for TPM */
    block_size = libspdm_fill_measurement_image_hash_block(
        true, SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256, 1, &block);
    assert_int_equal(block_size, 0);

    /* measurements_index 0 is invalid */
    block_size = libspdm_fill_measurement_image_hash_block(
        false, SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256, 0, &block);
    assert_int_equal(block_size, 0);
}

static void test_spdm_tpm_cert_slot_validation(void **state)
{
    void *data = NULL;
    size_t size = 0;
    void *hash = NULL;
    size_t hash_size = 0;
    bool status;

    /* Unsupported slot (slot 7 is not in default 0;1;4 mask) */
    status = libspdm_read_responder_root_public_certificate_slot(
        7, SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
        &data, &size, &hash, &hash_size);
    assert_false(status);

    status = libspdm_read_responder_public_certificate_chain_per_slot(
        7, SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
        &data, &size, &hash, &hash_size);
    assert_false(status);

    /* Out of range slot (>= SPDM_MAX_SLOT_COUNT) */
    status = libspdm_read_responder_root_public_certificate_slot(
        8, SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
        &data, &size, &hash, &hash_size);
    assert_false(status);

    /* Algorithm 0 is invalid */
    status = libspdm_read_responder_certificate(0, &data, &size);
    assert_false(status);

    /* PQC responder root certificate slot test with invalid slot */
    status = libspdm_read_pqc_responder_root_public_certificate_slot(
        7, SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
        &data, &size, &hash, &hash_size);
    assert_false(status);
}

void test_spdm_tpm_quote_validation(void **state)
{
    uint8_t buffer[512];
    size_t size = sizeof(buffer);
    bool status;

    /* libspdm_tpm_quote with NULL quote_buffer_size */
    status = libspdm_tpm_quote(
        LIBSPDM_TPM_HANDLE_RESPONDER_HANDLE_SLOT_0,
        SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256,
        NULL, 0, NULL, 0, buffer, NULL);
    assert_false(status);

    /* libspdm_tpm_quote with invalid hash algorithm */
    size = sizeof(buffer);
    status = libspdm_tpm_quote(
        LIBSPDM_TPM_HANDLE_RESPONDER_HANDLE_SLOT_0,
        0xFFFFFFFF, NULL, 0, NULL, 0, buffer, &size);
    assert_false(status);

    /* libspdm_tpm_quote with invalid key handle string */
    size = sizeof(buffer);
    status = libspdm_tpm_quote(
        "invalid_handle",
        SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256,
        NULL, 0, NULL, 0, buffer, &size);
    assert_false(status);

    /* libspdm_tpm_verify_quote with NULL parameters */
    status = libspdm_tpm_verify_quote(
        NULL,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
        buffer, sizeof(buffer), NULL, 0);
    assert_false(status);

    status = libspdm_tpm_verify_quote(
        (void *)1,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
        NULL, sizeof(buffer), NULL, 0);
    assert_false(status);

    status = libspdm_tpm_verify_quote(
        (void *)1,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
        buffer, 0, NULL, 0);
    assert_false(status);
}

/* --------------------------------------------------------------------------
 * TPM Quote OpaqueData and PCR Quote verification (offline, software-signed Quotes)
 * -------------------------------------------------------------------------- */

#define TEST_QUOTE_MAX 1024

static void test_spdm_tpm_read_pcrs_validation(void **state)
{
    uint8_t pcrs[] = {0, 7, 15};
    uint8_t unordered[] = {7, 0};
    uint8_t duplicate[] = {7, 7};
    uint8_t out_of_range[] = {24};
    uint8_t values[3 * 32];
    size_t size;

    /* Size query does not touch the TPM. */
    size = 0;
    assert_true(libspdm_tpm_read_pcrs(SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256,
                                      pcrs, 3, NULL, &size));
    assert_int_equal(size, 3 * 32);
    size = 0;
    assert_true(libspdm_tpm_read_pcrs(SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384,
                                      pcrs, 3, NULL, &size));
    assert_int_equal(size, 3 * 48);
    /* Too small: required size returned. */
    size = sizeof(values) - 1;
    assert_false(libspdm_tpm_read_pcrs(SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256,
                                       pcrs, 3, values, &size));
    assert_int_equal(size, 3 * 32);

    size = sizeof(values);
    assert_false(libspdm_tpm_read_pcrs(SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256,
                                       NULL, 1, values, &size));
    assert_false(libspdm_tpm_read_pcrs(SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256,
                                       pcrs, 0, values, &size));
    assert_false(libspdm_tpm_read_pcrs(SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256,
                                       unordered, 2, values, &size));
    assert_false(libspdm_tpm_read_pcrs(SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256,
                                       duplicate, 2, values, &size));
    assert_false(libspdm_tpm_read_pcrs(SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256,
                                       out_of_range, 1, values, &size));
    assert_false(libspdm_tpm_read_pcrs(0xFFFFFFFF, pcrs, 3, values, &size));
    assert_false(libspdm_tpm_read_pcrs(SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256,
                                       pcrs, 3, values, NULL));
}

typedef struct {
    size_t curve_nid;
    size_t hash_nid;
    TPMI_ALG_HASH sig_hash;
    uint32_t base_hash;
    size_t half_size;
    TPMI_ALG_HASH bank;
    TPM2_ST type;
    TPM2_GENERATED magic;
} test_quote_profile_t;

/* A Quote as libspdm_tpm_quote() returns it: MU(TPM2B_ATTEST) || MU(TPMT_SIGNATURE), signed
 * with a software ECDSA key. pcrDigest = H_sign(PCR values). */
static size_t test_make_quote(void *key, const test_quote_profile_t *profile,
                              const uint8_t *nonce, size_t nonce_size,
                              const uint8_t *pcr_indices, size_t pcr_count,
                              const uint8_t *pcr_values, size_t pcr_values_size,
                              uint8_t *quote)
{
    TPM2B_ATTEST attest;
    TPMS_ATTEST body;
    TPMT_SIGNATURE signature;
    TPMS_PCR_SELECTION *selection;
    uint8_t hash[LIBSPDM_MAX_HASH_SIZE];
    uint8_t raw[132];
    size_t raw_size = sizeof(raw);
    size_t body_size = 0;
    size_t offset = 0;
    size_t i;

    libspdm_zero_mem(&attest, sizeof(attest));
    libspdm_zero_mem(&body, sizeof(body));
    libspdm_zero_mem(&signature, sizeof(signature));
    body.magic = profile->magic;
    body.type = profile->type;
    body.extraData.size = (UINT16)nonce_size;
    libspdm_copy_mem(body.extraData.buffer, sizeof(body.extraData.buffer), nonce, nonce_size);
    body.attested.quote.pcrSelect.count = 1;
    selection = &body.attested.quote.pcrSelect.pcrSelections[0];
    selection->hash = profile->bank;
    selection->sizeofSelect = 3;
    for (i = 0; i < pcr_count; i++) {
        selection->pcrSelect[pcr_indices[i] / 8] |= (uint8_t)(1 << (pcr_indices[i] % 8));
    }
    body.attested.quote.pcrDigest.size = (UINT16)libspdm_get_hash_size(profile->base_hash);
    assert_true(libspdm_hash_all(profile->base_hash, pcr_values, pcr_values_size,
                                 body.attested.quote.pcrDigest.buffer));
    assert_int_equal(Tss2_MU_TPMS_ATTEST_Marshal(&body, attest.attestationData,
                                                 sizeof(attest.attestationData), &body_size),
                     TSS2_RC_SUCCESS);
    attest.size = (UINT16)body_size;

    assert_true(libspdm_hash_all(profile->base_hash, attest.attestationData, body_size, hash));
    assert_true(libspdm_ecdsa_sign(key, profile->hash_nid, hash,
                                   libspdm_get_hash_size(profile->base_hash), raw, &raw_size));
    assert_int_equal(raw_size, profile->half_size * 2);
    signature.sigAlg = TPM2_ALG_ECDSA;
    signature.signature.ecdsa.hash = profile->sig_hash;
    signature.signature.ecdsa.signatureR.size = (UINT16)profile->half_size;
    signature.signature.ecdsa.signatureS.size = (UINT16)profile->half_size;
    libspdm_copy_mem(signature.signature.ecdsa.signatureR.buffer,
                     sizeof(signature.signature.ecdsa.signatureR.buffer), raw,
                     profile->half_size);
    libspdm_copy_mem(signature.signature.ecdsa.signatureS.buffer,
                     sizeof(signature.signature.ecdsa.signatureS.buffer),
                     raw + profile->half_size, profile->half_size);

    assert_int_equal(Tss2_MU_TPM2B_ATTEST_Marshal(&attest, quote, TEST_QUOTE_MAX, &offset),
                     TSS2_RC_SUCCESS);
    assert_int_equal(Tss2_MU_TPMT_SIGNATURE_Marshal(&signature, quote, TEST_QUOTE_MAX, &offset),
                     TSS2_RC_SUCCESS);
    return offset;
}

static void *test_new_ec_key(size_t nid, void **public_key)
{
    uint8_t point[132];
    size_t point_size = sizeof(point);
    void *key;

    key = libspdm_ec_new_by_nid(nid);
    assert_non_null(key);
    assert_true(libspdm_ec_generate_key(key, point, &point_size));
    *public_key = libspdm_ec_new_by_nid(nid);
    assert_non_null(*public_key);
    assert_true(libspdm_ec_set_pub_key(*public_key, point, point_size));
    return key;
}

static void test_spdm_tpm_quote_opaque_codec(void **state)
{
    /* MU(TPM2B_ATTEST) with a 3-byte body, then a 5-byte signature. */
    static const uint8_t quote[] = {0x00, 0x03, 0xA1, 0xA2, 0xA3, 0x00, 0x18, 0x00, 0x0B, 0x00};
    uint8_t opaque[64];
    uint8_t bad[sizeof(opaque) + 4];
    size_t opaque_size;
    size_t required;
    uint8_t slot;
    const void *decoded;
    size_t decoded_size;

    /* Size query and too-small buffer return the required size. */
    required = 0;
    assert_false(libspdm_tpm_quote_opaque_encode(LIBSPDM_TPM_IAK_SLOT_ID, quote, sizeof(quote),
                                                 NULL, &required));
    assert_int_equal(required, (LIBSPDM_TPM_QUOTE_ELEMENT_OFFSET +
                                LIBSPDM_TPM_QUOTE_ELEMENT_HEADER_SIZE + sizeof(quote) + 3) &
                     ~(size_t)3);
    opaque_size = required - 1;
    assert_false(libspdm_tpm_quote_opaque_encode(LIBSPDM_TPM_IAK_SLOT_ID, quote, sizeof(quote),
                                                 opaque, &opaque_size));
    assert_int_equal(opaque_size, required);

    opaque_size = sizeof(opaque);
    assert_true(libspdm_tpm_quote_opaque_encode(LIBSPDM_TPM_IAK_SLOT_ID, quote, sizeof(quote),
                                                opaque, &opaque_size));
    assert_int_equal(opaque_size, required);
    assert_int_equal(opaque_size % 4, 0);
    /* OpaqueDataFmt1 general opaque data table with one TCG element */
    assert_int_equal(opaque[0], 1);
    assert_int_equal(opaque[4], SPDM_REGISTRY_ID_TCG);
    assert_int_equal(opaque[5], LIBSPDM_TPM_QUOTE_VENDOR_ID_LEN);
    assert_int_equal(libspdm_read_uint16(opaque + 6), LIBSPDM_TPM_QUOTE_TCG_VENDOR_ID);
    assert_int_equal(libspdm_read_uint16(opaque + 8),
                     LIBSPDM_TPM_QUOTE_ELEMENT_HEADER_SIZE + sizeof(quote));
    assert_int_equal(opaque[LIBSPDM_TPM_QUOTE_ELEMENT_OFFSET], LIBSPDM_TPM_QUOTE_ELEMENT_VERSION);
    assert_int_equal(opaque[LIBSPDM_TPM_QUOTE_ELEMENT_OFFSET + 1], LIBSPDM_TPM_IAK_SLOT_ID);
    assert_int_equal(libspdm_read_uint16(opaque + LIBSPDM_TPM_QUOTE_ELEMENT_OFFSET + 2), 5);
    assert_int_equal(libspdm_read_uint16(opaque + LIBSPDM_TPM_QUOTE_ELEMENT_OFFSET + 4), 5);

    assert_true(libspdm_tpm_quote_opaque_decode(opaque, opaque_size, &slot, &decoded,
                                                &decoded_size));
    assert_int_equal(slot, LIBSPDM_TPM_IAK_SLOT_ID);
    assert_int_equal(decoded_size, sizeof(quote));
    assert_memory_equal(decoded, quote, sizeof(quote));

    /* Encode rejects an invalid slot and a Quote without a signature. */
    opaque_size = sizeof(opaque);
    assert_false(libspdm_tpm_quote_opaque_encode(SPDM_MAX_SLOT_COUNT, quote, sizeof(quote),
                                                 opaque + 0, &opaque_size));
    opaque_size = sizeof(opaque);
    assert_false(libspdm_tpm_quote_opaque_encode(LIBSPDM_TPM_IAK_SLOT_ID, quote, 5,
                                                 bad, &opaque_size));

    /* Decode rejects every malformation of a well-formed element. */
    opaque_size = sizeof(opaque);
    assert_true(libspdm_tpm_quote_opaque_encode(LIBSPDM_TPM_IAK_SLOT_ID, quote, sizeof(quote),
                                                opaque, &opaque_size));
#define TEST_DECODE_FAILS(offset, value) \
    do { \
        libspdm_copy_mem(bad, sizeof(bad), opaque, opaque_size); \
        bad[(offset)] = (uint8_t)(value); \
        assert_false(libspdm_tpm_quote_opaque_decode(bad, opaque_size, &slot, &decoded, \
                                                     &decoded_size)); \
    } while (0)
    TEST_DECODE_FAILS(0, 2);                                   /* TotalElements */
    TEST_DECODE_FAILS(1, 1);                                   /* reserved */
    TEST_DECODE_FAILS(4, SPDM_REGISTRY_ID_DMTF);               /* registry ID */
    TEST_DECODE_FAILS(5, 1);                                   /* VendorIDLen */
    TEST_DECODE_FAILS(6, opaque[6] ^ 1);                       /* vendor ID */
    TEST_DECODE_FAILS(8, opaque[8] + 1);                       /* OpaqueElementDataLen */
    TEST_DECODE_FAILS(LIBSPDM_TPM_QUOTE_ELEMENT_OFFSET, LIBSPDM_TPM_QUOTE_ELEMENT_VERSION + 1);
    TEST_DECODE_FAILS(LIBSPDM_TPM_QUOTE_ELEMENT_OFFSET + 1, SPDM_MAX_SLOT_COUNT);
    TEST_DECODE_FAILS(LIBSPDM_TPM_QUOTE_ELEMENT_OFFSET + 2, 4); /* attest_size */
    TEST_DECODE_FAILS(LIBSPDM_TPM_QUOTE_ELEMENT_OFFSET + 4, 4); /* signature_size */
    TEST_DECODE_FAILS(LIBSPDM_TPM_QUOTE_ELEMENT_OFFSET + 7, 4); /* TPM2B_ATTEST.size */
    TEST_DECODE_FAILS(opaque_size - 1, 1);                     /* padding */
#undef TEST_DECODE_FAILS
    /* Truncated, trailing data, empty. */
    assert_false(libspdm_tpm_quote_opaque_decode(opaque, opaque_size - 4, &slot, &decoded,
                                                 &decoded_size));
    libspdm_copy_mem(bad, sizeof(bad), opaque, opaque_size);
    libspdm_zero_mem(bad + opaque_size, 4);
    assert_false(libspdm_tpm_quote_opaque_decode(bad, opaque_size + 4, &slot, &decoded,
                                                 &decoded_size));
    assert_false(libspdm_tpm_quote_opaque_decode(opaque, 0, &slot, &decoded, &decoded_size));
    assert_false(libspdm_tpm_quote_opaque_decode(NULL, opaque_size, &slot, &decoded,
                                                 &decoded_size));
}

static void test_spdm_tpm_verify_quote_pcrs(void **state)
{
    static const test_quote_profile_t p256 = {
        LIBSPDM_CRYPTO_NID_SECP256R1, LIBSPDM_CRYPTO_NID_SHA256, TPM2_ALG_SHA256,
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256, 32, TPM2_ALG_SHA256,
        TPM2_ST_ATTEST_QUOTE, TPM2_GENERATED_VALUE
    };
    /* PCR bank (SHA-256) and Quote signing hash (SHA-384) are independent. */
    static const test_quote_profile_t p384 = {
        LIBSPDM_CRYPTO_NID_SECP384R1, LIBSPDM_CRYPTO_NID_SHA384, TPM2_ALG_SHA384,
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384, 48, TPM2_ALG_SHA256,
        TPM2_ST_ATTEST_QUOTE, TPM2_GENERATED_VALUE
    };
    const uint32_t bank = SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256;
    const test_quote_profile_t *profiles[] = {&p256, &p384};
    test_quote_profile_t profile;
    uint8_t pcrs[] = {0, 7, 15};
    uint8_t other_pcrs[] = {0, 7, 16};
    uint8_t values[3 * 32];
    uint8_t nonce[SPDM_NONCE_SIZE];
    uint8_t quote[TEST_QUOTE_MAX + 1];
    size_t quote_size;
    void *key;
    void *public_key;
    void *other_key;
    void *other_public_key;
    size_t i;

    for (i = 0; i < sizeof(values); i++) {
        values[i] = (uint8_t)i;
    }
    for (i = 0; i < sizeof(nonce); i++) {
        nonce[i] = (uint8_t)(0xA0 + i);
    }

    for (i = 0; i < LIBSPDM_ARRAY_SIZE(profiles); i++) {
        profile = *profiles[i];
        key = test_new_ec_key(profile.curve_nid, &public_key);
        other_key = test_new_ec_key(profile.curve_nid, &other_public_key);
        libspdm_ec_free(other_key);

        quote_size = test_make_quote(key, &profile, nonce, sizeof(nonce), pcrs, 3, values,
                                     sizeof(values), quote);
        assert_true(libspdm_tpm_verify_quote_pcrs(public_key, quote, quote_size, nonce,
                                                  sizeof(nonce), bank, pcrs, 3, values,
                                                  sizeof(values)));
        /* The PCR-agnostic verifier accepts it as well. */
        if (profile.half_size == 32) {
            assert_true(libspdm_tpm_verify_quote(
                            public_key, SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
                            bank, quote, quote_size, nonce, sizeof(nonce)));
        }

        /* Another key, nonce, PCR value, PCR list or bank. */
        assert_false(libspdm_tpm_verify_quote_pcrs(other_public_key, quote, quote_size, nonce,
                                                   sizeof(nonce), bank, pcrs, 3, values,
                                                   sizeof(values)));
        nonce[0] ^= 1;
        assert_false(libspdm_tpm_verify_quote_pcrs(public_key, quote, quote_size, nonce,
                                                   sizeof(nonce), bank, pcrs, 3, values,
                                                   sizeof(values)));
        nonce[0] ^= 1;
        assert_false(libspdm_tpm_verify_quote_pcrs(public_key, quote, quote_size, nonce,
                                                   sizeof(nonce) - 1, bank, pcrs, 3, values,
                                                   sizeof(values)));
        values[40] ^= 1;
        assert_false(libspdm_tpm_verify_quote_pcrs(public_key, quote, quote_size, nonce,
                                                   sizeof(nonce), bank, pcrs, 3, values,
                                                   sizeof(values)));
        values[40] ^= 1;
        assert_false(libspdm_tpm_verify_quote_pcrs(public_key, quote, quote_size, nonce,
                                                   sizeof(nonce), bank, pcrs, 2, values, 64));
        assert_false(libspdm_tpm_verify_quote_pcrs(public_key, quote, quote_size, nonce,
                                                   sizeof(nonce), bank, other_pcrs, 3, values,
                                                   sizeof(values)));
        assert_false(libspdm_tpm_verify_quote_pcrs(public_key, quote, quote_size, nonce,
                                                   sizeof(nonce), bank, pcrs, 3, values,
                                                   sizeof(values) - 1));
        assert_false(libspdm_tpm_verify_quote_pcrs(public_key, quote, quote_size, nonce,
                                                   sizeof(nonce),
                                                   SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384,
                                                   pcrs, 3, values, sizeof(values)));
        /* Truncated, trailing byte, tampered signature. */
        assert_false(libspdm_tpm_verify_quote_pcrs(public_key, quote, quote_size - 1, nonce,
                                                   sizeof(nonce), bank, pcrs, 3, values,
                                                   sizeof(values)));
        quote[quote_size] = 0;
        assert_false(libspdm_tpm_verify_quote_pcrs(public_key, quote, quote_size + 1, nonce,
                                                   sizeof(nonce), bank, pcrs, 3, values,
                                                   sizeof(values)));
        quote[quote_size - 1] ^= 1;
        assert_false(libspdm_tpm_verify_quote_pcrs(public_key, quote, quote_size, nonce,
                                                   sizeof(nonce), bank, pcrs, 3, values,
                                                   sizeof(values)));

        /* Signed by the key, but not a TPM-generated Quote, or a Quote of another bank. */
        profile.magic = 0;
        quote_size = test_make_quote(key, &profile, nonce, sizeof(nonce), pcrs, 3, values,
                                     sizeof(values), quote);
        assert_false(libspdm_tpm_verify_quote_pcrs(public_key, quote, quote_size, nonce,
                                                   sizeof(nonce), bank, pcrs, 3, values,
                                                   sizeof(values)));
        profile = *profiles[i];
        profile.type = TPM2_ST_ATTEST_CERTIFY;
        quote_size = test_make_quote(key, &profile, nonce, sizeof(nonce), pcrs, 3, values,
                                     sizeof(values), quote);
        assert_false(libspdm_tpm_verify_quote_pcrs(public_key, quote, quote_size, nonce,
                                                   sizeof(nonce), bank, pcrs, 3, values,
                                                   sizeof(values)));
        profile = *profiles[i];
        profile.bank = TPM2_ALG_SHA384;
        quote_size = test_make_quote(key, &profile, nonce, sizeof(nonce), pcrs, 3, values,
                                     sizeof(values), quote);
        assert_false(libspdm_tpm_verify_quote_pcrs(public_key, quote, quote_size, nonce,
                                                   sizeof(nonce), bank, pcrs, 3, values,
                                                   sizeof(values)));

        /* Parameter validation. */
        assert_false(libspdm_tpm_verify_quote_pcrs(NULL, quote, quote_size, nonce,
                                                   sizeof(nonce), bank, pcrs, 3, values,
                                                   sizeof(values)));
        assert_false(libspdm_tpm_verify_quote_pcrs(public_key, quote, quote_size, NULL, 0,
                                                   bank, pcrs, 3, values, sizeof(values)));
        assert_false(libspdm_tpm_verify_quote_pcrs(public_key, quote, quote_size, nonce,
                                                   sizeof(nonce), bank, NULL, 3, values,
                                                   sizeof(values)));

        libspdm_ec_free(other_public_key);
        libspdm_ec_free(public_key);
        libspdm_ec_free(key);
    }
}

static size_t test_append_block(uint8_t *record, size_t offset, uint8_t index, uint8_t type,
                                const uint8_t *value, size_t value_size)
{
    spdm_measurement_block_dmtf_t *block = (void *)(record + offset);

    block->measurement_block_common_header.index = index;
    block->measurement_block_common_header.measurement_specification =
        SPDM_MEASUREMENT_SPECIFICATION_DMTF;
    block->measurement_block_common_header.measurement_size =
        (uint16_t)(sizeof(spdm_measurement_block_dmtf_header_t) + value_size);
    block->measurement_block_dmtf_header.dmtf_spec_measurement_value_type = type;
    block->measurement_block_dmtf_header.dmtf_spec_measurement_value_size = (uint16_t)value_size;
    libspdm_copy_mem(block + 1, value_size, value, value_size);
    return offset + sizeof(*block) + value_size;
}

static void test_spdm_tpm_verify_quote_measurement_record(void **state)
{
    static const test_quote_profile_t p256 = {
        LIBSPDM_CRYPTO_NID_SECP256R1, LIBSPDM_CRYPTO_NID_SHA256, TPM2_ALG_SHA256,
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256, 32, TPM2_ALG_SHA256,
        TPM2_ST_ATTEST_QUOTE, TPM2_GENERATED_VALUE
    };
    const uint32_t bank = SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256;
    const uint8_t type = SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_IMMUTABLE_ROM;
    uint8_t pcrs[] = {0, 7, 15};
    uint8_t values[3 * 32];
    uint8_t svn[8] = {1};
    uint8_t record[512];
    uint8_t bad[512];
    size_t record_size;
    size_t size;
    uint8_t nonce[SPDM_NONCE_SIZE];
    uint8_t quote[TEST_QUOTE_MAX];
    size_t quote_size;
    void *key;
    void *public_key;
    size_t i;

    for (i = 0; i < sizeof(values); i++) {
        values[i] = (uint8_t)(0x40 + i);
    }
    libspdm_set_mem(nonce, sizeof(nonce), 0x5A);
    key = test_new_ec_key(p256.curve_nid, &public_key);
    quote_size = test_make_quote(key, &p256, nonce, sizeof(nonce), pcrs, 3, values,
                                 sizeof(values), quote);

    /* PCR 15 (0x12) before PCR 0 (0x01) and an SVN block (0x10) in between. */
    record_size = test_append_block(record, 0, 0x12, type, values + 64, 32);
    record_size = test_append_block(record, record_size, 0x10,
                                    SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_RAW_BIT_STREAM |
                                    SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_SECURE_VERSION_NUMBER,
                                    svn, sizeof(svn));
    record_size = test_append_block(record, record_size, 0x01, type, values, 32);
    record_size = test_append_block(record, record_size, 0x08, type, values + 32, 32);
    assert_true(libspdm_tpm_verify_quote_measurement_record(public_key, quote, quote_size,
                                                            nonce, sizeof(nonce), bank,
                                                            record, record_size));

    /* A PCR value the Quote does not attest. */
    libspdm_copy_mem(bad, sizeof(bad), record, record_size);
    bad[record_size - 1] ^= 1;
    assert_false(libspdm_tpm_verify_quote_measurement_record(public_key, quote, quote_size,
                                                             nonce, sizeof(nonce), bank,
                                                             bad, record_size));
    /* A quoted PCR missing from the record, a truncated record. */
    assert_false(libspdm_tpm_verify_quote_measurement_record(public_key, quote, quote_size,
                                                             nonce, sizeof(nonce), bank,
                                                             record,
                                                             record_size - sizeof(
                                                                 spdm_measurement_block_dmtf_t) -
                                                             32));
    assert_false(libspdm_tpm_verify_quote_measurement_record(public_key, quote, quote_size,
                                                             nonce, sizeof(nonce), bank,
                                                             record, record_size - 1));
    /* A PCR reported twice. */
    size = test_append_block(bad, 0, 0x01, type, values, 32);
    libspdm_copy_mem(bad + size, sizeof(bad) - size, record, record_size);
    assert_false(libspdm_tpm_verify_quote_measurement_record(public_key, quote, quote_size,
                                                             nonce, sizeof(nonce), bank,
                                                             bad, size + record_size));
    /* A raw bit stream PCR block. */
    libspdm_copy_mem(bad, sizeof(bad), record, record_size);
    ((spdm_measurement_block_dmtf_t *)bad)->measurement_block_dmtf_header
    .dmtf_spec_measurement_value_type |= SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_RAW_BIT_STREAM;
    assert_false(libspdm_tpm_verify_quote_measurement_record(public_key, quote, quote_size,
                                                             nonce, sizeof(nonce), bank,
                                                             bad, record_size));
    /* No PCR block at all, another bank, another nonce. */
    size = test_append_block(bad, 0, 0x10,
                             SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_RAW_BIT_STREAM |
                             SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_SECURE_VERSION_NUMBER,
                             svn, sizeof(svn));
    assert_false(libspdm_tpm_verify_quote_measurement_record(public_key, quote, quote_size,
                                                             nonce, sizeof(nonce), bank,
                                                             bad, size));
    assert_false(libspdm_tpm_verify_quote_measurement_record(
                     public_key, quote, quote_size, nonce, sizeof(nonce),
                     SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384, record, record_size));
    nonce[0] ^= 1;
    assert_false(libspdm_tpm_verify_quote_measurement_record(public_key, quote, quote_size,
                                                             nonce, sizeof(nonce), bank,
                                                             record, record_size));

    libspdm_ec_free(public_key);
    libspdm_ec_free(key);
}

/* Self-signed test certificates with TCG DevID fields: SubjectAltName otherName
 * hardwareModuleName {hwType 2.23.133.1.2, hwSerialNum 0011223344556677}; certificatePolicies
 * 2.23.133.11.1.1 + 2.23.133.11.1.3 (IAK) or 2.23.133.11.1.1 only (plain). */
static const uint8_t m_test_tcg_iak_cert[] = {
    0x30, 0x82, 0x01, 0xa7, 0x30, 0x82, 0x01, 0x4d, 0xa0, 0x03, 0x02, 0x01,
    0x02, 0x02, 0x14, 0x6a, 0xb0, 0x69, 0x3c, 0xc8, 0x6b, 0x5f, 0xc5, 0xb3,
    0x1a, 0x04, 0x0c, 0x6e, 0x56, 0x81, 0x38, 0x30, 0x64, 0x0a, 0xb7, 0x30,
    0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30,
    0x13, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x08,
    0x74, 0x65, 0x73, 0x74, 0x20, 0x49, 0x41, 0x4b, 0x30, 0x1e, 0x17, 0x0d,
    0x32, 0x36, 0x31, 0x31, 0x31, 0x31, 0x30, 0x36, 0x30, 0x37, 0x31, 0x36,
    0x5a, 0x17, 0x0d, 0x32, 0x36, 0x31, 0x31, 0x31, 0x32, 0x30, 0x36, 0x30,
    0x37, 0x31, 0x36, 0x5a, 0x30, 0x13, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03,
    0x55, 0x04, 0x03, 0x0c, 0x08, 0x74, 0x65, 0x73, 0x74, 0x20, 0x49, 0x41,
    0x4b, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d,
    0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
    0x03, 0x42, 0x00, 0x04, 0xcb, 0xd8, 0x99, 0x12, 0xf7, 0x1b, 0xca, 0xb2,
    0x14, 0xe7, 0xd5, 0x76, 0x6c, 0xf7, 0x3a, 0x19, 0x4a, 0x82, 0xbf, 0x8d,
    0x7c, 0x3b, 0xe7, 0xf4, 0xfe, 0xe7, 0x54, 0x50, 0xd7, 0xd7, 0x52, 0x01,
    0xdc, 0x4c, 0x0e, 0x89, 0xee, 0xd1, 0x39, 0x02, 0xf7, 0x88, 0x35, 0xe9,
    0x20, 0x1a, 0x53, 0x0d, 0x07, 0xa2, 0xb8, 0x20, 0x28, 0xf4, 0x7b, 0x3e,
    0xd0, 0x58, 0xb4, 0x81, 0x6b, 0x9a, 0x2c, 0x29, 0xa3, 0x7f, 0x30, 0x7d,
    0x30, 0x2d, 0x06, 0x03, 0x55, 0x1d, 0x11, 0x01, 0x01, 0xff, 0x04, 0x23,
    0x30, 0x21, 0xa0, 0x1f, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07,
    0x08, 0x04, 0xa0, 0x13, 0x30, 0x11, 0x06, 0x05, 0x67, 0x81, 0x05, 0x01,
    0x02, 0x04, 0x08, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x30,
    0x1d, 0x06, 0x03, 0x55, 0x1d, 0x20, 0x04, 0x16, 0x30, 0x14, 0x30, 0x08,
    0x06, 0x06, 0x67, 0x81, 0x05, 0x0b, 0x01, 0x01, 0x30, 0x08, 0x06, 0x06,
    0x67, 0x81, 0x05, 0x0b, 0x01, 0x03, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d,
    0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x07, 0x80, 0x30, 0x1d,
    0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0xb0, 0xad, 0xf6,
    0xd2, 0x08, 0xb9, 0xd5, 0x38, 0x19, 0x71, 0xa0, 0xe1, 0x1a, 0x01, 0x98,
    0x4c, 0xc9, 0xce, 0x94, 0x26, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48,
    0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x20,
    0x61, 0x7f, 0x54, 0x3c, 0x51, 0xeb, 0x60, 0x11, 0x34, 0x28, 0xdb, 0x87,
    0x20, 0x1a, 0xd4, 0x91, 0xab, 0xf6, 0x49, 0x69, 0xea, 0x2b, 0x64, 0xe9,
    0xc4, 0xd5, 0x38, 0x69, 0x8e, 0x8e, 0xd8, 0xab, 0x02, 0x21, 0x00, 0xac,
    0xb7, 0x94, 0x0e, 0xb1, 0xb3, 0x86, 0x01, 0x31, 0xa7, 0xef, 0x2e, 0x6f,
    0xb1, 0x2f, 0x59, 0x5c, 0xf6, 0x6e, 0x6b, 0x11, 0x18, 0xa0, 0x7f, 0xfe,
    0x22, 0xf4, 0xac, 0x8b, 0xd6, 0x62, 0x57,
};
static const uint8_t m_test_tcg_plain_cert[] = {
    0x30, 0x82, 0x01, 0x8e, 0x30, 0x82, 0x01, 0x33, 0xa0, 0x03, 0x02, 0x01,
    0x02, 0x02, 0x14, 0x3b, 0xc9, 0x8c, 0xf5, 0x6f, 0xe1, 0xce, 0x55, 0x85,
    0x7e, 0x05, 0x76, 0x0b, 0x4d, 0x28, 0x90, 0x8c, 0x8c, 0xdb, 0xac, 0x30,
    0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30,
    0x13, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x08,
    0x74, 0x65, 0x73, 0x74, 0x20, 0x49, 0x41, 0x4b, 0x30, 0x1e, 0x17, 0x0d,
    0x32, 0x36, 0x31, 0x31, 0x31, 0x31, 0x30, 0x36, 0x30, 0x37, 0x31, 0x36,
    0x5a, 0x17, 0x0d, 0x32, 0x36, 0x31, 0x31, 0x31, 0x32, 0x30, 0x36, 0x30,
    0x37, 0x31, 0x36, 0x5a, 0x30, 0x13, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03,
    0x55, 0x04, 0x03, 0x0c, 0x08, 0x74, 0x65, 0x73, 0x74, 0x20, 0x49, 0x41,
    0x4b, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d,
    0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
    0x03, 0x42, 0x00, 0x04, 0xcb, 0xd8, 0x99, 0x12, 0xf7, 0x1b, 0xca, 0xb2,
    0x14, 0xe7, 0xd5, 0x76, 0x6c, 0xf7, 0x3a, 0x19, 0x4a, 0x82, 0xbf, 0x8d,
    0x7c, 0x3b, 0xe7, 0xf4, 0xfe, 0xe7, 0x54, 0x50, 0xd7, 0xd7, 0x52, 0x01,
    0xdc, 0x4c, 0x0e, 0x89, 0xee, 0xd1, 0x39, 0x02, 0xf7, 0x88, 0x35, 0xe9,
    0x20, 0x1a, 0x53, 0x0d, 0x07, 0xa2, 0xb8, 0x20, 0x28, 0xf4, 0x7b, 0x3e,
    0xd0, 0x58, 0xb4, 0x81, 0x6b, 0x9a, 0x2c, 0x29, 0xa3, 0x65, 0x30, 0x63,
    0x30, 0x2d, 0x06, 0x03, 0x55, 0x1d, 0x11, 0x01, 0x01, 0xff, 0x04, 0x23,
    0x30, 0x21, 0xa0, 0x1f, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07,
    0x08, 0x04, 0xa0, 0x13, 0x30, 0x11, 0x06, 0x05, 0x67, 0x81, 0x05, 0x01,
    0x02, 0x04, 0x08, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x30,
    0x13, 0x06, 0x03, 0x55, 0x1d, 0x20, 0x04, 0x0c, 0x30, 0x0a, 0x30, 0x08,
    0x06, 0x06, 0x67, 0x81, 0x05, 0x0b, 0x01, 0x01, 0x30, 0x1d, 0x06, 0x03,
    0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0xb0, 0xad, 0xf6, 0xd2, 0x08,
    0xb9, 0xd5, 0x38, 0x19, 0x71, 0xa0, 0xe1, 0x1a, 0x01, 0x98, 0x4c, 0xc9,
    0xce, 0x94, 0x26, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
    0x04, 0x03, 0x02, 0x03, 0x49, 0x00, 0x30, 0x46, 0x02, 0x21, 0x00, 0x96,
    0xbf, 0xd8, 0x25, 0x9f, 0x03, 0xb3, 0x14, 0xf9, 0x6d, 0x4a, 0x12, 0x9e,
    0x33, 0xca, 0xf3, 0x1d, 0x84, 0x58, 0x04, 0x6e, 0x12, 0x46, 0xb7, 0xf0,
    0xf7, 0x26, 0x8d, 0xeb, 0x07, 0x57, 0xc5, 0x02, 0x21, 0x00, 0xf4, 0x76,
    0x58, 0xe5, 0xe8, 0x2e, 0x56, 0x7d, 0xc8, 0xdc, 0x2d, 0x4e, 0x79, 0x5b,
    0xfc, 0x5b, 0x4c, 0xa6, 0x68, 0xb2, 0x0b, 0xe4, 0x8e, 0x4e, 0x94, 0x1f,
    0x40, 0xf1, 0x8b, 0xb1, 0xdc, 0xcf,
};

static void test_spdm_tpm_cert_device_identity(void **state)
{
    static const uint8_t expected[] = {
        0x30, 0x11, 0x06, 0x05, 0x67, 0x81, 0x05, 0x01, 0x02,
        0x04, 0x08, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77
    };
    static const uint8_t tpm20_oid[] = {0x06, 0x05, 0x67, 0x81, 0x05, 0x01, 0x02};
    uint8_t name[LIBSPDM_TPM_HW_MODULE_NAME_MAX_SIZE];
    size_t name_size;
    bool restricted;
    uint8_t cert[sizeof(m_test_tcg_iak_cert)];
    size_t i;

    name_size = sizeof(name);
    restricted = false;
    assert_true(libspdm_tpm_get_cert_device_identity(m_test_tcg_iak_cert,
                                                     sizeof(m_test_tcg_iak_cert), name,
                                                     &name_size, &restricted));
    assert_int_equal(name_size, sizeof(expected));
    assert_memory_equal(name, expected, sizeof(expected));
    assert_true(restricted);

    name_size = sizeof(name);
    restricted = true;
    assert_true(libspdm_tpm_get_cert_device_identity(m_test_tcg_plain_cert,
                                                     sizeof(m_test_tcg_plain_cert), name,
                                                     &name_size, &restricted));
    assert_memory_equal(name, expected, sizeof(expected));
    assert_false(restricted);

    /* Buffer too small, NULL parameters. */
    name_size = sizeof(expected) - 1;
    assert_false(libspdm_tpm_get_cert_device_identity(m_test_tcg_iak_cert,
                                                      sizeof(m_test_tcg_iak_cert), name,
                                                      &name_size, &restricted));
    name_size = sizeof(name);
    assert_false(libspdm_tpm_get_cert_device_identity(NULL, sizeof(m_test_tcg_iak_cert), name,
                                                      &name_size, &restricted));
    assert_false(libspdm_tpm_get_cert_device_identity(m_test_tcg_iak_cert,
                                                      sizeof(m_test_tcg_iak_cert), name,
                                                      &name_size, NULL));

    /* hwType other than TPM 2.0. */
    libspdm_copy_mem(cert, sizeof(cert), m_test_tcg_iak_cert, sizeof(m_test_tcg_iak_cert));
    for (i = 0; i + sizeof(tpm20_oid) <= sizeof(cert); i++) {
        if (libspdm_consttime_is_mem_equal(cert + i, tpm20_oid, sizeof(tpm20_oid))) {
            break;
        }
    }
    assert_true(i + sizeof(tpm20_oid) <= sizeof(cert));
    cert[i + sizeof(tpm20_oid) - 1] = 0x03;
    name_size = sizeof(name);
    assert_false(libspdm_tpm_get_cert_device_identity(cert, sizeof(cert), name, &name_size,
                                                      &restricted));
}

/* --------------------------------------------------------------------------
 * Live TPM Simulator Tests (gated by TPM2TOOLS_TCTI)
 * -------------------------------------------------------------------------- */

static void test_tpm_live_read_pcr(void **state)
{
    uint8_t buffer[64];
    size_t size;
    bool status;

    if (!is_tpm_available()) {
        print_message("[SKIPPED] TPM simulator not running (TPM2TOOLS_TCTI not set)\n");
        return;
    }

    size = sizeof(buffer);
    status = libspdm_tpm_read_pcr(
        SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256, 0, buffer, &size);
    assert_true(status);
    assert_int_equal(size, 32);

    /* Read PCR 1 */
    size = sizeof(buffer);
    status = libspdm_tpm_read_pcr(
        SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256, 1, buffer, &size);
    assert_true(status);
    assert_int_equal(size, 32);
}

static void test_tpm_live_read_nv(void **state)
{
    void *buffer = NULL;
    size_t size = 0;
    bool status;

    if (!is_tpm_available()) {
        print_message("[SKIPPED] TPM simulator not running (TPM2TOOLS_TCTI not set)\n");
        return;
    }

    status = libspdm_tpm_read_nv(
        LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_0, &buffer, &size);
    assert_true(status);
    assert_non_null(buffer);
    assert_true(size > 0);

    free(buffer);
}

static void test_spdm_tpm_live_read_certchain(void **state)
{
    void *cert_chain = NULL;
    size_t cert_chain_size = 0;
    void *hash = NULL;
    size_t hash_size = 0;
    spdm_cert_chain_t *chain_header;
    bool status;

    if (!is_tpm_available()) {
        print_message("[SKIPPED] TPM simulator not running (TPM2TOOLS_TCTI not set)\n");
        return;
    }

    status = libspdm_read_responder_public_certificate_chain(
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
        &cert_chain, &cert_chain_size, &hash, &hash_size);
    assert_true(status);
    assert_non_null(cert_chain);
    assert_true(cert_chain_size > sizeof(spdm_cert_chain_t));
    assert_non_null(hash);
    assert_int_equal(hash_size, 32);

    chain_header = (spdm_cert_chain_t *)cert_chain;
    assert_int_equal(chain_header->length, (uint32_t)cert_chain_size);

    free(cert_chain);

    /* Test root public certificate extraction */
    status = libspdm_read_responder_root_public_certificate(
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
        &cert_chain, &cert_chain_size, &hash, &hash_size);
    assert_true(status);
    assert_non_null(cert_chain);
    assert_true(cert_chain_size > 0);
    free(cert_chain);

    /* Test leaf certificate extraction */
    status = libspdm_read_responder_certificate(
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
        &cert_chain, &cert_chain_size);
    assert_true(status);
    assert_non_null(cert_chain);
    assert_true(cert_chain_size > 0);
    free(cert_chain);

    /* Test PQC wrapper calls responder cert */
    status = libspdm_read_pqc_responder_root_public_certificate(
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
        &cert_chain, &cert_chain_size, &hash, &hash_size);
    assert_true(status);
    assert_non_null(cert_chain);
    free(cert_chain);
}

static void test_spdm_tpm_live_fill_meas_block(void **state)
{
    uint8_t buffer[512];
    spdm_measurement_block_dmtf_t *block;
    size_t block_size;

    if (!is_tpm_available()) {
        print_message("[SKIPPED] TPM simulator not running (TPM2TOOLS_TCTI not set)\n");
        return;
    }

    block = (spdm_measurement_block_dmtf_t *)buffer;
    block_size = libspdm_fill_measurement_image_hash_block(
        false, SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256, 1, block);

    assert_true(block_size > 0);
    assert_int_equal(block->measurement_block_common_header.index, 1);
    assert_int_equal(block->measurement_block_common_header.measurement_specification,
                     SPDM_MEASUREMENT_SPECIFICATION_DMTF);
    assert_int_equal(block->measurement_block_dmtf_header.dmtf_spec_measurement_value_size, 32);
    assert_int_equal(block_size, sizeof(spdm_measurement_block_dmtf_t) + 32);
}

static void test_spdm_tpm_live_sign_and_verify(void **state)
{
    uint8_t digest[32];
    uint8_t signature[128];
    size_t sig_size = sizeof(signature);
    void *cert_data = NULL;
    size_t cert_size = 0;
    void *context = NULL;
    bool status;
    size_t i;

    if (!is_tpm_available()) {
        print_message("[SKIPPED] TPM simulator not running (TPM2TOOLS_TCTI not set)\n");
        return;
    }

    /* Prepare a test digest */
    for (i = 0; i < sizeof(digest); i++) {
        digest[i] = (uint8_t)(i + 1);
    }

    /* Perform TPM signature */
    status = libspdm_responder_data_sign(
        NULL, SPDM_MESSAGE_VERSION_12, 0, 0,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256, 0,
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256, true,
        digest, sizeof(digest), signature, &sig_size);
    assert_true(status);
    assert_true(sig_size > 0);

    /* Read the leaf certificate from NV to verify the signature */
    status = libspdm_read_responder_certificate(
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
        &cert_data, &cert_size);
    assert_true(status);
    assert_non_null(cert_data);

    /* Extract public key and verify signature */
    status = libspdm_asym_get_public_key_from_x509(
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
        cert_data, cert_size, &context);
    assert_true(status);
    assert_non_null(context);

    status = libspdm_asym_verify_hash(
        SPDM_MESSAGE_VERSION_12, 0,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
        context, digest, sizeof(digest), signature, sig_size);
    assert_true(status);

    libspdm_asym_free(SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256, context);
    free(cert_data);
}

void test_spdm_tpm_live_quote(void **state)
{
    uint8_t quote_buf[1024];
    size_t quote_size = sizeof(quote_buf);
    uint8_t pcr_indices[] = {0, 1};
    uint8_t nonce[32];
    uint8_t bad_nonce[32];
    void *pub_key_ctx = NULL;
    bool status;
    size_t i;

    if (!is_tpm_available()) {
        print_message("[SKIPPED] TPM simulator not running (TPM2TOOLS_TCTI not set)\n");
        return;
    }

    for (i = 0; i < sizeof(nonce); i++) {
        nonce[i] = (uint8_t)(0xA0 + i);
        bad_nonce[i] = (uint8_t)(0xB0 + i);
    }

    /* Perform TPM2 quote directly */
    status = libspdm_tpm_quote(
        LIBSPDM_TPM_HANDLE_IAK,
        SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256,
        pcr_indices, 2,
        nonce, sizeof(nonce),
        quote_buf, &quote_size);
    assert_true(status);
    assert_true(quote_size > 0);

    /* Verify against the dedicated IAK, never the SPDM identity key. */
    assert_true(libspdm_tpm_get_pub_key_handle(LIBSPDM_TPM_HANDLE_IAK, &pub_key_ctx));

    /* Verify quote with matching nonce */
    status = libspdm_tpm_verify_quote(
        pub_key_ctx,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
        SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256,
        quote_buf, quote_size,
        nonce, sizeof(nonce));
    assert_true(status);

    /* Verification must fail with wrong nonce */
    status = libspdm_tpm_verify_quote(
        pub_key_ctx,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
        SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256,
        quote_buf, quote_size,
        bad_nonce, sizeof(bad_nonce));
    assert_false(status);

    /* Verification must fail with tampered quote buffer */
    quote_buf[quote_size - 1] ^= 0xFF;
    status = libspdm_tpm_verify_quote(
        pub_key_ctx,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
        SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256,
        quote_buf, quote_size,
        nonce, sizeof(nonce));
    assert_false(status);

    libspdm_asym_free(SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256, pub_key_ctx);
}

void test_spdm_tpm_live_quote_pcrs(void **state)
{
    const uint32_t bank = SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256;
    uint8_t quote[TEST_QUOTE_MAX];
    size_t quote_size = sizeof(quote);
    uint8_t pcrs[] = {0, 1, 7, 15};
    uint8_t values[4 * 32];
    size_t values_size = sizeof(values);
    uint8_t opaque[TEST_QUOTE_MAX + 32];
    size_t opaque_size = sizeof(opaque);
    uint8_t nonce[SPDM_NONCE_SIZE];
    uint8_t slot;
    const void *decoded;
    size_t decoded_size;
    void *public_key = NULL;
    size_t i;

    if (!is_tpm_available()) {
        print_message("[SKIPPED] TPM simulator not running (TPM2TOOLS_TCTI not set)\n");
        return;
    }
    for (i = 0; i < sizeof(nonce); i++) {
        nonce[i] = (uint8_t)(0xC0 + i);
    }

    /* The PCR values a TPM2_Quote attests, through the OpaqueData encoding. */
    assert_true(libspdm_tpm_read_pcrs(bank, pcrs, 4, values, &values_size));
    assert_int_equal(values_size, sizeof(values));
    assert_true(libspdm_tpm_quote(LIBSPDM_TPM_HANDLE_IAK, bank, pcrs, 4,
                                  nonce, sizeof(nonce), quote, &quote_size));
    assert_true(libspdm_tpm_quote_opaque_encode(LIBSPDM_TPM_IAK_SLOT_ID, quote, quote_size,
                                                opaque, &opaque_size));
    assert_true(libspdm_tpm_quote_opaque_decode(opaque, opaque_size, &slot, &decoded,
                                                &decoded_size));
    assert_true(libspdm_tpm_get_pub_key_handle(LIBSPDM_TPM_HANDLE_IAK,
                                               &public_key));
    assert_true(libspdm_tpm_verify_quote_pcrs(public_key, decoded, decoded_size, nonce,
                                              sizeof(nonce), bank, pcrs, 4, values,
                                              values_size));
    /* Another PCR value is not attested. */
    values[0] ^= 1;
    assert_false(libspdm_tpm_verify_quote_pcrs(public_key, decoded, decoded_size, nonce,
                                               sizeof(nonce), bank, pcrs, 4, values,
                                               values_size));
    libspdm_ec_free(public_key);
}

void test_spdm_tpm_live_rsa_signatures(void **state)
{
    const char *handle = "handle:0x81020003";
    const uint32_t algorithms[] = {
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048
    };
    uint8_t digest[32] = {0}, signature[256];
    size_t signature_size, i;
    void *private_key = NULL, *public_key = NULL;

    if (!is_tpm_available()) {
        print_message("[SKIPPED] TPM simulator not running (TPM2TOOLS_TCTI not set)\n");
        return;
    }
    assert_true(libspdm_tpm_get_pub_key_handle(handle, &public_key));
    assert_true(libspdm_tpm_get_pvt_key_handle(handle, &private_key));
    for (i = 0; i < LIBSPDM_ARRAY_SIZE(algorithms); i++) {
        signature_size = sizeof(signature);
        assert_true(libspdm_asym_sign_hash(SPDM_MESSAGE_VERSION_12 << 8, SPDM_CHALLENGE_AUTH,
                                           algorithms[i], SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
                                           private_key, digest, sizeof(digest), signature, &signature_size));
        assert_int_equal(signature_size, sizeof(signature));
        assert_true(libspdm_asym_verify_hash(SPDM_MESSAGE_VERSION_12 << 8, SPDM_CHALLENGE_AUTH,
                                             algorithms[i], SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
                                             public_key, digest, sizeof(digest), signature, signature_size));
        signature[0] ^= 1;
        assert_false(libspdm_asym_verify_hash(SPDM_MESSAGE_VERSION_12 << 8, SPDM_CHALLENGE_AUTH,
                                              algorithms[i], SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
                                              public_key, digest, sizeof(digest), signature, signature_size));
    }
    libspdm_rsa_free(private_key);
    libspdm_rsa_free(public_key);
}

void test_spdm_tpm_live_quote_rsapss(void **state)
{
    const char *handle = "handle:0x81020002";
    const uint32_t bank = SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256;
    uint8_t pcrs[] = {0, 1};
    uint8_t values[64], quote[TEST_QUOTE_MAX], nonce[SPDM_NONCE_SIZE];
    uint8_t info[128];
    size_t values_size = sizeof(values), quote_size = sizeof(quote), info_size = sizeof(info);
    uint32_t algorithm = 0;
    void *public_key = NULL;

    if (!is_tpm_available()) {
        print_message("[SKIPPED] TPM simulator not running (TPM2TOOLS_TCTI not set)\n");
        return;
    }
    libspdm_set_mem(nonce, sizeof(nonce), 0xA5);
    assert_true(libspdm_tpm_get_key_info(handle, &algorithm, info, &info_size));
    assert_int_equal(algorithm, SPDM_KEY_PAIR_ASYM_ALGO_CAP_RSA2048);
    assert_true(info_size > 0);
    assert_true(libspdm_tpm_read_pcrs(bank, pcrs, 2, values, &values_size));
    assert_true(libspdm_tpm_quote(handle, bank, pcrs, 2, nonce, sizeof(nonce), quote, &quote_size));
    assert_true(libspdm_tpm_get_pub_key_handle(handle, &public_key));
    assert_true(libspdm_tpm_verify_quote_pcrs(public_key, quote, quote_size, nonce,
                                              sizeof(nonce), bank, pcrs, 2, values, values_size));
    nonce[0] ^= 1;
    assert_false(libspdm_tpm_verify_quote_pcrs(public_key, quote, quote_size, nonce,
                                               sizeof(nonce), bank, pcrs, 2, values, values_size));
    libspdm_rsa_free(public_key);
}

/* The persistent identity key and restricted IAK have independent IDs/usages. */
void test_spdm_tpm_live_key_pairs(void **state)
{
    const uint32_t asym = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256;
    uint8_t identity, iak, requester;
#if LIBSPDM_ENABLE_CAPABILITY_GET_KEY_PAIR_INFO_CAP
    uint8_t total, slots, id, identity_slots = 0;
    uint16_t caps, usages, usage, info_size;
    uint32_t algorithms, algorithm, pqc_algorithms, pqc_algorithm;
    uint8_t info[32];
#endif
#if LIBSPDM_ENABLE_CAPABILITY_SET_KEY_PAIR_INFO_CAP
    bool reset = false;
#endif

    if (!is_tpm_available()) {
        print_message("[SKIPPED] TPM simulator not running (TPM2TOOLS_TCTI not set)\n");
        return;
    }
    identity = libspdm_tpm_get_key_pair_id_by_slot(false, asym, 0, 0);
    iak = libspdm_tpm_get_key_pair_id_by_slot(false, asym, 0, LIBSPDM_TPM_IAK_SLOT_ID);
    requester = libspdm_tpm_get_key_pair_id_by_slot(true, asym, 0, 0);
    assert_true(identity > 0);
    assert_true(iak > 0);
    assert_true(requester > 0);
    assert_true(identity != iak);
    assert_string_equal(libspdm_tpm_get_signing_key_handle(false, identity),
                        LIBSPDM_TPM_HANDLE_RESPONDER_HANDLE_SLOT_0);
    assert_string_equal(libspdm_tpm_get_signing_key_handle(true, requester),
                        LIBSPDM_TPM_HANDLE_REQUESTER_HANDLE_SLOT_0);
    assert_null(libspdm_tpm_get_signing_key_handle(false, iak));
    assert_null(libspdm_tpm_get_signing_key_handle(false, 255));
    assert_int_equal(libspdm_tpm_get_key_pair_id_by_slot(false, asym, 0, 8), 0);
#if LIBSPDM_ENABLE_CAPABILITY_GET_KEY_PAIR_INFO_CAP
    total = 255;
    for (id = 1; id <= total; id++) {
        info_size = sizeof(info);
        assert_true(libspdm_read_key_pair_info(NULL, NULL, id, &total, &caps,
                                               &usages, &usage, &algorithms, &algorithm, &pqc_algorithms,
                                               &pqc_algorithm,
                                               &slots, &info_size, info));
        assert_true(total >= 2);
        assert_int_equal(algorithm, SPDM_KEY_PAIR_ASYM_ALGO_CAP_ECC256);
        assert_int_equal(algorithms, algorithm);
        assert_int_equal(pqc_algorithm, 0);
        assert_true(info_size > 0);
        if (id == identity) {
            identity_slots = slots;
        }
        if (id == iak) {
            assert_int_equal(caps, 0);
            assert_int_equal(usage, SPDM_KEY_USAGE_BIT_MASK_STANDARDS_KEY_USE);
            assert_int_equal(usages, usage);
            assert_int_equal(slots, 1u << LIBSPDM_TPM_IAK_SLOT_ID);
        }
        if (id == total) {
            break;
        }
    }
    info_size = 0;
    assert_false(libspdm_read_key_pair_info(NULL, NULL, identity, &total, &caps,
                                            &usages, &usage, &algorithms, &algorithm, &pqc_algorithms, &pqc_algorithm,
                                            &slots, &info_size, info));
    assert_true(info_size > 0);
#endif
#if LIBSPDM_ENABLE_CAPABILITY_SET_KEY_PAIR_INFO_CAP
    assert_false(libspdm_write_key_pair_info(NULL, NULL, iak,
                                             SPDM_SET_KEY_PAIR_INFO_CHANGE_OPERATION, 0, 0, 0, 0, &reset));
    assert_false(libspdm_write_key_pair_info(NULL, NULL, identity,
                                             SPDM_SET_KEY_PAIR_INFO_ERASE_OPERATION, 0, 0, 0, 0, &reset));
    assert_false(libspdm_write_key_pair_info(NULL, NULL, identity,
                                             SPDM_SET_KEY_PAIR_INFO_CHANGE_OPERATION, 0, 0, 0,
                                             1u << LIBSPDM_TPM_IAK_SLOT_ID, &reset));
#if LIBSPDM_ENABLE_CAPABILITY_GET_KEY_PAIR_INFO_CAP
    assert_true(libspdm_write_key_pair_info(NULL, NULL, identity,
                                            SPDM_SET_KEY_PAIR_INFO_CHANGE_OPERATION, 0, 0, 0, 0, &reset));
    assert_int_equal(libspdm_tpm_get_key_pair_id_by_slot(false, asym, 0, 0), 0);
    assert_true(libspdm_write_key_pair_info(NULL, NULL, identity,
                                            SPDM_SET_KEY_PAIR_INFO_CHANGE_OPERATION, 0, 0, 0, identity_slots, &reset));
    assert_int_equal(libspdm_tpm_get_key_pair_id_by_slot(false, asym, 0, 0), identity);
#endif
#endif
}

/* --------------------------------------------------------------------------
 * Main Test Runner
 * -------------------------------------------------------------------------- */

#ifdef LIBSPDM_TPM_COLLECTION_TEST
int libspdm_tpm_collection_setup(void **state);
int libspdm_tpm_collection_teardown(void **state);
void test_spdm_tpm_pcr_collection(void **state);
#endif

static int libspdm_spdm_tpm_test_main(void)
{
    const struct CMUnitTest test_cases[] = {
        /* Offline tests */
        cmocka_unit_test(test_tpm_device_init),
        cmocka_unit_test(test_tpm_key_handle_null_params),
        cmocka_unit_test(test_tpm_read_pcr_validation),
        cmocka_unit_test(test_tpm_read_nv_validation),
        cmocka_unit_test(test_spdm_tpm_security_stubs),
        cmocka_unit_test(test_spdm_tpm_meas_validation),
        cmocka_unit_test(test_spdm_tpm_cert_slot_validation),
        cmocka_unit_test(test_spdm_tpm_quote_validation),
        cmocka_unit_test(test_spdm_tpm_read_pcrs_validation),
        cmocka_unit_test(test_spdm_tpm_quote_opaque_codec),
        cmocka_unit_test(test_spdm_tpm_verify_quote_pcrs),
        cmocka_unit_test(test_spdm_tpm_verify_quote_measurement_record),
        cmocka_unit_test(test_spdm_tpm_cert_device_identity),

#ifdef LIBSPDM_TPM_COLLECTION_TEST
        cmocka_unit_test_setup_teardown(test_spdm_tpm_pcr_collection,
                                        libspdm_tpm_collection_setup,
                                        libspdm_tpm_collection_teardown),
#endif
        /* Live TPM tests */
        cmocka_unit_test(test_tpm_live_read_pcr),
        cmocka_unit_test(test_tpm_live_read_nv),
        cmocka_unit_test(test_spdm_tpm_live_read_certchain),
        cmocka_unit_test(test_spdm_tpm_live_fill_meas_block),
        cmocka_unit_test(test_spdm_tpm_live_sign_and_verify),
        cmocka_unit_test(test_spdm_tpm_live_quote),
        cmocka_unit_test(test_spdm_tpm_live_quote_pcrs),
        cmocka_unit_test(test_spdm_tpm_live_quote_rsapss),
        cmocka_unit_test(test_spdm_tpm_live_rsa_signatures),
        cmocka_unit_test(test_spdm_tpm_live_key_pairs),
    };

    return cmocka_run_group_tests(test_cases, NULL, NULL);
}

int main(void)
{
    return libspdm_spdm_tpm_test_main();
}
