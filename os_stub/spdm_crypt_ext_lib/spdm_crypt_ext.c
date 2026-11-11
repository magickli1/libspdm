/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_lib_config.h"
#include "library/spdm_crypt_ext_lib.h"
#include "hal/library/cryptlib.h"
#include "hal/library/cryptlib_ext.h"
#include "industry_standard/spdm.h"
#include "hal/library/debuglib.h"
#include "hal/library/memlib.h"

/**
 * Return asymmetric GET_PRIVATE_KEY_FROM_PEM function, based upon the asymmetric algorithm.
 *
 * @param  base_asym_algo                 SPDM base_asym_algo
 *
 * @return asymmetric GET_PRIVATE_KEY_FROM_PEM function
 **/
libspdm_asym_get_private_key_from_pem_func
libspdm_get_asym_get_private_key_from_pem(uint32_t base_asym_algo)
{
    switch (base_asym_algo) {
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
#if (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT)
        return libspdm_rsa_get_private_key_from_pem;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
#if LIBSPDM_ECDSA_SUPPORT
        return libspdm_ec_get_private_key_from_pem;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448:
#if (LIBSPDM_EDDSA_ED25519_SUPPORT) || (LIBSPDM_EDDSA_ED448_SUPPORT)
        return libspdm_ecd_get_private_key_from_pem;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256:
#if LIBSPDM_SM2_DSA_SUPPORT
        return libspdm_sm2_get_private_key_from_pem;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    default:
        LIBSPDM_ASSERT(false);
        break;
    }

    return NULL;
}

/**
 * Retrieve the Private key from the password-protected PEM key data.
 *
 * @param  base_asym_algo                 SPDM base_asym_algo
 * @param  pem_data                      Pointer to the PEM-encoded key data to be retrieved.
 * @param  pem_size                      size of the PEM key data in bytes.
 * @param  password                     NULL-terminated passphrase used for encrypted PEM key data.
 * @param  context                      Pointer to newly generated asymmetric context which contain the retrieved private key component.
 *                                     Use libspdm_asym_free() function to free the resource.
 *
 * @retval  true   Private key was retrieved successfully.
 * @retval  false  Invalid PEM key data or incorrect password.
 **/
bool libspdm_asym_get_private_key_from_pem(uint32_t base_asym_algo,
                                           const uint8_t *pem_data,
                                           size_t pem_size,
                                           const char *password,
                                           void **context)
{
    libspdm_asym_get_private_key_from_pem_func asym_get_private_key_from_pem;
    asym_get_private_key_from_pem = libspdm_get_asym_get_private_key_from_pem(base_asym_algo);
    if (asym_get_private_key_from_pem == NULL) {
        return false;
    }
    return asym_get_private_key_from_pem(pem_data, pem_size, password, context);
}

/**
 * Return asymmetric GET_PRIVATE_KEY_FROM_PEM function, based upon the asymmetric algorithm.
 *
 * @param  req_base_asym_alg               SPDM req_base_asym_alg
 *
 * @return asymmetric GET_PRIVATE_KEY_FROM_PEM function
 **/
static libspdm_asym_get_private_key_from_pem_func
libspdm_get_req_asym_get_private_key_from_pem(uint16_t req_base_asym_alg)
{
    return libspdm_get_asym_get_private_key_from_pem(req_base_asym_alg);
}

/**
 * Retrieve the Private key from the password-protected PEM key data.
 *
 * @param  req_base_asym_alg               SPDM req_base_asym_alg
 * @param  pem_data                      Pointer to the PEM-encoded key data to be retrieved.
 * @param  pem_size                      size of the PEM key data in bytes.
 * @param  password                     NULL-terminated passphrase used for encrypted PEM key data.
 * @param  context                      Pointer to newly generated asymmetric context which contain the retrieved private key component.
 *                                     Use libspdm_asym_free() function to free the resource.
 *
 * @retval  true   Private key was retrieved successfully.
 * @retval  false  Invalid PEM key data or incorrect password.
 **/
bool libspdm_req_asym_get_private_key_from_pem(uint16_t req_base_asym_alg,
                                               const uint8_t *pem_data,
                                               size_t pem_size,
                                               const char *password,
                                               void **context)
{
    libspdm_asym_get_private_key_from_pem_func asym_get_private_key_from_pem;
    asym_get_private_key_from_pem =
        libspdm_get_req_asym_get_private_key_from_pem(req_base_asym_alg);
    if (asym_get_private_key_from_pem == NULL) {
        return false;
    }
    return asym_get_private_key_from_pem(pem_data, pem_size, password,
                                         context);
}

/**
 * Computes the hash of a input data buffer.
 *
 * This function performs the hash of a given data buffer, and return the hash value.
 *
 * @param  data        Pointer to the buffer containing the data to be hashed.
 * @param  data_size   Size of data buffer in bytes.
 * @param  hash_value  Pointer to a buffer that receives the hash value.
 *
 * @retval true   hash computation succeeded.
 * @retval false  hash computation failed.
 **/
typedef bool (*libspdm_hash_all_func)(const void *data, size_t data_size, uint8_t *hash_value);

/**
 * Return hash function, based upon the negotiated measurement hash algorithm.
 *
 * @param  measurement_hash_algo          SPDM measurement_hash_algo
 *
 * @return hash function
 **/
static libspdm_hash_all_func libspdm_spdm_measurement_hash_func(uint32_t measurement_hash_algo)
{
    switch (measurement_hash_algo) {
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256:
#if LIBSPDM_SHA256_SUPPORT
        return libspdm_sha256_hash_all;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384:
#if LIBSPDM_SHA384_SUPPORT
        return libspdm_sha384_hash_all;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_512:
#if LIBSPDM_SHA512_SUPPORT
        return libspdm_sha512_hash_all;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_256:
#if LIBSPDM_SHA3_256_SUPPORT
        return libspdm_sha3_256_hash_all;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_384:
#if LIBSPDM_SHA3_384_SUPPORT
        return libspdm_sha3_384_hash_all;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_512:
#if LIBSPDM_SHA3_512_SUPPORT
        return libspdm_sha3_512_hash_all;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SM3_256:
#if LIBSPDM_SM3_256_SUPPORT
        return libspdm_sm3_256_hash_all;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    default:
        LIBSPDM_ASSERT(false);
        break;
    }

    return NULL;
}

bool libspdm_measurement_hash_all(uint32_t measurement_hash_algo,
                                  const void *data, size_t data_size,
                                  uint8_t *hash_value)
{
    libspdm_hash_all_func hash_function;
    hash_function = libspdm_spdm_measurement_hash_func(measurement_hash_algo);
    if (hash_function == NULL) {
        return false;
    }
    return hash_function(data, data_size, hash_value);
}

size_t libspdm_get_aysm_nid(uint32_t base_asym_algo)
{
    switch (base_asym_algo)
    {
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
        return LIBSPDM_CRYPTO_NID_RSASSA2048;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
        return LIBSPDM_CRYPTO_NID_RSASSA3072;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
        return LIBSPDM_CRYPTO_NID_RSASSA4096;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
        return LIBSPDM_CRYPTO_NID_RSAPSS2048;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
        return LIBSPDM_CRYPTO_NID_RSAPSS3072;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
        return LIBSPDM_CRYPTO_NID_RSAPSS4096;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
        return LIBSPDM_CRYPTO_NID_ECDSA_NIST_P256;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
        return LIBSPDM_CRYPTO_NID_ECDSA_NIST_P384;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
        return LIBSPDM_CRYPTO_NID_ECDSA_NIST_P521;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519:
        return LIBSPDM_CRYPTO_NID_EDDSA_ED25519;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448:
        return LIBSPDM_CRYPTO_NID_EDDSA_ED448;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256:
        return LIBSPDM_CRYPTO_NID_SM2_DSA_P256;
    default:
        return LIBSPDM_CRYPTO_NID_NULL;
    }
}

#if LIBSPDM_TPM_SUPPORT
#include "industry_standard/spdm_secured_message.h"
#include "library/spdm_tpm_pcr.h"
#include "library/spdm_tpm_quote_opaque.h"

/* OpaqueData integers are little endian; the codec is independent of the crypto backend. */
static uint16_t tpm_read_le16(const uint8_t *p)
{
    return (uint16_t)(p[0] | (p[1] << 8));
}

static void tpm_write_le16(uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8);
}

/* quote = MU(TPM2B_ATTEST) || MU(TPMT_SIGNATURE); the TPM2B size is big endian. */
static bool tpm_quote_split(const uint8_t *quote, size_t quote_size, size_t *attest_size)
{
    if (quote_size < sizeof(uint16_t)) {
        return false;
    }
    *attest_size = sizeof(uint16_t) + (((size_t)quote[0] << 8) | quote[1]);
    return (*attest_size < quote_size) && (*attest_size <= 0xFFFF) &&
           (quote_size - *attest_size <= 0xFFFF);
}

bool libspdm_tpm_quote_opaque_encode(uint8_t iak_slot_id, const void *quote, size_t quote_size,
                                     void *opaque_data, size_t *opaque_size)
{
    spdm_general_opaque_data_table_header_t *table;
    opaque_element_table_header_t *element;
    uint8_t *ptr;
    size_t attest_size;
    size_t element_data_size;
    size_t total_size;

    if ((quote == NULL) || (opaque_size == NULL) || (iak_slot_id >= SPDM_MAX_SLOT_COUNT) ||
        !tpm_quote_split(quote, quote_size, &attest_size)) {
        return false;
    }
    element_data_size = LIBSPDM_TPM_QUOTE_ELEMENT_HEADER_SIZE + quote_size;
    if (element_data_size > 0xFFFF) {
        return false;
    }
    total_size = (LIBSPDM_TPM_QUOTE_ELEMENT_OFFSET + element_data_size + 3) & ~(size_t)3;
    if ((opaque_data == NULL) || (*opaque_size < total_size)) {
        *opaque_size = total_size;
        return false;
    }

    libspdm_zero_mem(opaque_data, total_size);
    table = opaque_data;
    table->total_elements = 1;
    element = (opaque_element_table_header_t *)(table + 1);
    element->id = SPDM_REGISTRY_ID_TCG;
    element->vendor_len = LIBSPDM_TPM_QUOTE_VENDOR_ID_LEN;
    ptr = (uint8_t *)(element + 1);
    tpm_write_le16(ptr, LIBSPDM_TPM_QUOTE_TCG_VENDOR_ID);
    ptr += LIBSPDM_TPM_QUOTE_VENDOR_ID_LEN;
    tpm_write_le16(ptr, (uint16_t)element_data_size);
    ptr += sizeof(uint16_t);
    ptr[0] = LIBSPDM_TPM_QUOTE_ELEMENT_VERSION;
    ptr[1] = iak_slot_id;
    tpm_write_le16(ptr + 2, (uint16_t)attest_size);
    tpm_write_le16(ptr + 4, (uint16_t)(quote_size - attest_size));
    libspdm_copy_mem(ptr + LIBSPDM_TPM_QUOTE_ELEMENT_HEADER_SIZE, quote_size,
                     quote, quote_size);
    *opaque_size = total_size;
    return true;
}

bool libspdm_tpm_quote_opaque_decode(const void *opaque_data, size_t opaque_size,
                                     uint8_t *iak_slot_id, const void **quote,
                                     size_t *quote_size)
{
    const spdm_general_opaque_data_table_header_t *table;
    const opaque_element_table_header_t *element;
    const uint8_t *ptr;
    size_t element_data_size;
    size_t attest_size;
    size_t signature_size;
    size_t used;
    size_t i;

    if ((opaque_data == NULL) || (iak_slot_id == NULL) || (quote == NULL) ||
        (quote_size == NULL) || (opaque_size < LIBSPDM_TPM_QUOTE_ELEMENT_OFFSET)) {
        return false;
    }
    table = opaque_data;
    if ((table->total_elements != 1) || (table->reserved[0] != 0) ||
        (table->reserved[1] != 0) || (table->reserved[2] != 0)) {
        return false;
    }
    element = (const opaque_element_table_header_t *)(table + 1);
    if ((element->id != SPDM_REGISTRY_ID_TCG) ||
        (element->vendor_len != LIBSPDM_TPM_QUOTE_VENDOR_ID_LEN)) {
        return false;
    }
    ptr = (const uint8_t *)(element + 1);
    if (tpm_read_le16(ptr) != LIBSPDM_TPM_QUOTE_TCG_VENDOR_ID) {
        return false;
    }
    ptr += LIBSPDM_TPM_QUOTE_VENDOR_ID_LEN;
    element_data_size = tpm_read_le16(ptr);
    ptr += sizeof(uint16_t);

    used = LIBSPDM_TPM_QUOTE_ELEMENT_OFFSET + element_data_size;
    if ((element_data_size < LIBSPDM_TPM_QUOTE_ELEMENT_HEADER_SIZE) ||
        (((used + 3) & ~(size_t)3) != opaque_size)) {
        return false;
    }
    for (i = used; i < opaque_size; i++) {
        if (((const uint8_t *)opaque_data)[i] != 0) {
            return false;
        }
    }
    if ((ptr[0] != LIBSPDM_TPM_QUOTE_ELEMENT_VERSION) || (ptr[1] >= SPDM_MAX_SLOT_COUNT)) {
        return false;
    }
    *iak_slot_id = ptr[1];
    attest_size = tpm_read_le16(ptr + 2);
    signature_size = tpm_read_le16(ptr + 4);
    if ((attest_size == 0) || (signature_size == 0) ||
        (LIBSPDM_TPM_QUOTE_ELEMENT_HEADER_SIZE + attest_size + signature_size !=
         element_data_size)) {
        return false;
    }
    ptr += LIBSPDM_TPM_QUOTE_ELEMENT_HEADER_SIZE;
    /* attest_size must match the TPM2B_ATTEST size field */
    if ((attest_size < sizeof(uint16_t)) ||
        (sizeof(uint16_t) + (((size_t)ptr[0] << 8) | ptr[1]) != attest_size)) {
        return false;
    }
    *quote = ptr;
    *quote_size = attest_size + signature_size;
    return true;
}

static size_t libspdm_tpm_pcr_digest_size(uint32_t measurement_hash_algo)
{
    switch (measurement_hash_algo) {
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256:
        return 32;
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384:
        return 48;
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_512:
        return 64;
    default:
        return 0;
    }
}

bool libspdm_tpm_verify_quote_measurement_record(
    const void *pub_key_context,
    const void *quote_buffer,
    size_t quote_buffer_size,
    const uint8_t *expected_nonce,
    size_t expected_nonce_size,
    uint32_t measurement_hash_algo,
    const void *measurement_record,
    size_t measurement_record_length)
{
    const uint8_t *pcr_digest[LIBSPDM_TPM_PCR_COUNT];
    uint8_t pcr_indices[LIBSPDM_TPM_PCR_COUNT];
    uint8_t pcr_values[LIBSPDM_TPM_PCR_COUNT * 64];
    const spdm_measurement_block_dmtf_t *block;
    const uint8_t *record;
    size_t digest_size;
    size_t offset;
    size_t block_size;
    size_t pcr_count;
    uint8_t pcr;

    digest_size = libspdm_tpm_pcr_digest_size(measurement_hash_algo);
    if ((digest_size == 0) || (measurement_record == NULL)) {
        return false;
    }
    for (pcr = 0; pcr < LIBSPDM_TPM_PCR_COUNT; pcr++) {
        pcr_digest[pcr] = NULL;
    }

    /* Every block must be well formed; a PCR block (index profile of spdm_tpm_pcr.h) must be a
     * digest of the PCR bank size and may appear only once. */
    record = measurement_record;
    offset = 0;
    while (offset < measurement_record_length) {
        if (measurement_record_length - offset < sizeof(*block)) {
            return false;
        }
        block = (const void *)(record + offset);
        block_size = sizeof(spdm_measurement_block_common_header_t) +
                     block->measurement_block_common_header.measurement_size;
        if ((block_size < sizeof(*block)) || (block_size > measurement_record_length - offset)) {
            return false;
        }
        pcr = libspdm_tpm_measurement_pcr_index(block->measurement_block_common_header.index);
        if (pcr < LIBSPDM_TPM_PCR_COUNT) {
            if ((pcr_digest[pcr] != NULL) ||
                (block->measurement_block_common_header.measurement_specification !=
                 SPDM_MEASUREMENT_SPECIFICATION_DMTF) ||
                (block->measurement_block_dmtf_header.dmtf_spec_measurement_value_size !=
                 digest_size) ||
                (block_size != sizeof(*block) + digest_size) ||
                ((block->measurement_block_dmtf_header.dmtf_spec_measurement_value_type &
                  SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_RAW_BIT_STREAM) != 0)) {
                return false;
            }
            pcr_digest[pcr] = (const uint8_t *)(block + 1);
        }
        offset += block_size;
    }

    /* The Quote must attest exactly the reported PCRs, in ascending PCR order. */
    pcr_count = 0;
    for (pcr = 0; pcr < LIBSPDM_TPM_PCR_COUNT; pcr++) {
        if (pcr_digest[pcr] != NULL) {
            pcr_indices[pcr_count] = pcr;
            libspdm_copy_mem(pcr_values + pcr_count * digest_size,
                             sizeof(pcr_values) - pcr_count * digest_size,
                             pcr_digest[pcr], digest_size);
            pcr_count++;
        }
    }
    if (pcr_count == 0) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "no PCR measurement block for the TPM Quote\n"));
        return false;
    }
    return libspdm_tpm_verify_quote_pcrs(pub_key_context, quote_buffer, quote_buffer_size,
                                         expected_nonce, expected_nonce_size,
                                         measurement_hash_algo, pcr_indices, pcr_count,
                                         pcr_values, pcr_count * digest_size);
}

/* TCG "TPM 2.0 Keys for Device Identity and Attestation" v1.10 sec. 8: DevID / IAK
 * certificate fields that identify the TPM. */
#define LIBSPDM_TPM_CERT_EXTENSION_MAX_SIZE 1024
/* id-on-hardwareModuleName 1.3.6.1.5.5.7.8.4 (RFC 4108) */
static const uint8_t m_oid_hw_module_name[] = {0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x08, 0x04};
/* hwType TPM 2.0: 2.23.133.1.2 */
static const uint8_t m_oid_tcg_tpm20[] = {0x67, 0x81, 0x05, 0x01, 0x02};
/* tcg-cap-verifiedTPMRestricted 2.23.133.11.1.3 */
static const uint8_t m_oid_tcg_verified_tpm_restricted[] = {0x67, 0x81, 0x05, 0x0B, 0x01, 0x03};
/* id-ce-subjectAltName 2.5.29.17, id-ce-certificatePolicies 2.5.29.32 */
static const uint8_t m_oid_subject_alt_name[] = {0x55, 0x1D, 0x11};
static const uint8_t m_oid_certificate_policies[] = {0x55, 0x1D, 0x20};

/* Minimal DER TLV reader: tag (single byte), definite length up to 4 bytes. */
static bool libspdm_tpm_der_next(const uint8_t **ptr, const uint8_t *end, uint8_t *tag,
                                 const uint8_t **value, size_t *value_size)
{
    const uint8_t *p;
    size_t len;
    size_t num;

    p = *ptr;
    if (end - p < 2) {
        return false;
    }
    *tag = *p++;
    len = *p++;
    if ((len & 0x80) != 0) {
        num = len & 0x7F;
        if ((num == 0) || (num > 4) || ((size_t)(end - p) < num)) {
            return false;
        }
        len = 0;
        while (num-- > 0) {
            len = (len << 8) | *p++;
        }
    }
    if ((size_t)(end - p) < len) {
        return false;
    }
    *value = p;
    *value_size = len;
    *ptr = p + len;
    return true;
}

static bool libspdm_tpm_der_is_oid(uint8_t tag, const uint8_t *value, size_t value_size,
                                   const uint8_t *oid, size_t oid_size)
{
    return (tag == 0x06) && (value_size == oid_size) &&
           libspdm_consttime_is_mem_equal(value, oid, oid_size);
}

/* SubjectAltName GeneralNames: find otherName {id-on-hardwareModuleName, [0] HardwareModuleName}
 * with hwType TPM 2.0 and return the HardwareModuleName DER. */
static bool libspdm_tpm_hw_module_name_from_san(const uint8_t *san, size_t san_size,
                                                uint8_t *hw_module_name, size_t *hw_module_name_size)
{
    const uint8_t *ptr;
    const uint8_t *end;
    const uint8_t *names;
    size_t names_size;
    const uint8_t *name;
    const uint8_t *name_end;
    const uint8_t *value;
    size_t value_size;
    const uint8_t *explicit_value;
    size_t explicit_size;
    const uint8_t *hw_start;
    const uint8_t *hw_end;
    const uint8_t *field;
    size_t field_size;
    const uint8_t *item;
    size_t item_size;
    uint8_t tag;

    ptr = san;
    end = san + san_size;
    if (!libspdm_tpm_der_next(&ptr, end, &tag, &names, &names_size) || (tag != 0x30)) {
        return false;
    }
    ptr = names;
    end = names + names_size;
    while (ptr < end) {
        if (!libspdm_tpm_der_next(&ptr, end, &tag, &name, &value_size)) {
            return false;
        }
        if (tag != 0xA0) {
            continue;
        }
        /* OtherName ::= SEQUENCE { type-id OID, value [0] EXPLICIT ANY } (implicit [0] tag) */
        name_end = name + value_size;
        if (!libspdm_tpm_der_next(&name, name_end, &tag, &value, &value_size) ||
            !libspdm_tpm_der_is_oid(tag, value, value_size, m_oid_hw_module_name,
                                    sizeof(m_oid_hw_module_name))) {
            continue;
        }
        if (!libspdm_tpm_der_next(&name, name_end, &tag, &explicit_value, &explicit_size) ||
            (tag != 0xA0)) {
            return false;
        }
        /* HardwareModuleName ::= SEQUENCE { hwType OID, hwSerialNum OCTET STRING } */
        hw_start = explicit_value;
        hw_end = explicit_value;
        if (!libspdm_tpm_der_next(&hw_end, explicit_value + explicit_size, &tag, &field,
                                  &field_size) || (tag != 0x30)) {
            return false;
        }
        item = field;
        if (!libspdm_tpm_der_next(&item, field + field_size, &tag, &value, &item_size) ||
            !libspdm_tpm_der_is_oid(tag, value, item_size, m_oid_tcg_tpm20,
                                    sizeof(m_oid_tcg_tpm20))) {
            return false;
        }
        if (!libspdm_tpm_der_next(&item, field + field_size, &tag, &value, &item_size) ||
            (tag != 0x04) || (item_size == 0)) {
            return false;
        }
        if ((size_t)(hw_end - hw_start) > *hw_module_name_size) {
            return false;
        }
        *hw_module_name_size = (size_t)(hw_end - hw_start);
        libspdm_copy_mem(hw_module_name, *hw_module_name_size, hw_start, *hw_module_name_size);
        return true;
    }
    return false;
}

/* certificatePolicies: SEQUENCE OF PolicyInformation { policyIdentifier, ... } */
static bool libspdm_tpm_has_policy(const uint8_t *policies, size_t policies_size,
                                   const uint8_t *policy_oid, size_t policy_oid_size)
{
    const uint8_t *ptr;
    const uint8_t *end;
    const uint8_t *list;
    size_t list_size;
    const uint8_t *info;
    size_t info_size;
    const uint8_t *value;
    size_t value_size;
    uint8_t tag;

    ptr = policies;
    end = policies + policies_size;
    if (!libspdm_tpm_der_next(&ptr, end, &tag, &list, &list_size) || (tag != 0x30)) {
        return false;
    }
    ptr = list;
    end = list + list_size;
    while (ptr < end) {
        if (!libspdm_tpm_der_next(&ptr, end, &tag, &info, &info_size) || (tag != 0x30)) {
            return false;
        }
        if (libspdm_tpm_der_next(&info, info + info_size, &tag, &value, &value_size) &&
            libspdm_tpm_der_is_oid(tag, value, value_size, policy_oid, policy_oid_size)) {
            return true;
        }
    }
    return false;
}

bool libspdm_tpm_get_cert_device_identity(const uint8_t *cert, size_t cert_size,
                                          uint8_t *hw_module_name, size_t *hw_module_name_size,
                                          bool *verified_tpm_restricted)
{
    uint8_t extension[LIBSPDM_TPM_CERT_EXTENSION_MAX_SIZE];
    size_t extension_size;

    if ((cert == NULL) || (hw_module_name == NULL) || (hw_module_name_size == NULL) ||
        (verified_tpm_restricted == NULL)) {
        return false;
    }

    extension_size = sizeof(extension);
    if (!libspdm_x509_get_extension_data(cert, cert_size, m_oid_subject_alt_name,
                                         sizeof(m_oid_subject_alt_name), extension,
                                         &extension_size) || (extension_size == 0)) {
        return false;
    }
    if (!libspdm_tpm_hw_module_name_from_san(extension, extension_size, hw_module_name,
                                             hw_module_name_size)) {
        return false;
    }

    *verified_tpm_restricted = false;
    extension_size = sizeof(extension);
    if (libspdm_x509_get_extension_data(cert, cert_size, m_oid_certificate_policies,
                                        sizeof(m_oid_certificate_policies), extension,
                                        &extension_size) && (extension_size != 0)) {
        *verified_tpm_restricted =
            libspdm_tpm_has_policy(extension, extension_size, m_oid_tcg_verified_tpm_restricted,
                                   sizeof(m_oid_tcg_verified_tpm_restricted));
    }
    return true;
}
#endif /* LIBSPDM_TPM_SUPPORT */
