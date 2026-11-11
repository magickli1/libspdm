/**
 *  Copyright Notice:
 *  Copyright 2021-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef SPDM_CRYPT_EXT_LIB_H
#define SPDM_CRYPT_EXT_LIB_H

#include "hal/base.h"

/**
 * Retrieve the Private key from the password-protected PEM key data.
 *
 * @param  pem_data  Pointer to the PEM-encoded key data to be retrieved.
 * @param  pem_size  Size of the PEM key data in bytes.
 * @param  password  NULL-terminated passphrase used for encrypted PEM key data.
 * @param  context   Pointer to newly generated asymmetric context which contain the retrieved private
 *                   key component. Use libspdm_asym_free() function to free the resource.
 *
 * @retval  true   Private key was retrieved successfully.
 * @retval  false  Invalid PEM key data or incorrect password.
 **/
typedef bool (*libspdm_asym_get_private_key_from_pem_func)(const uint8_t *pem_data,
                                                           size_t pem_size,
                                                           const char *password,
                                                           void **context);

/**
 * Retrieve the Private key from the password-protected PEM key data.
 *
 * @param  base_asym_algo  SPDM base_asym_algo
 * @param  pem_data        Pointer to the PEM-encoded key data to be retrieved.
 * @param  pem_size        Size of the PEM key data in bytes.
 * @param  password        NULL-terminated passphrase used for encrypted PEM key data.
 * @param  context         Pointer to newly generated asymmetric context which contain the retrieved
 *                         private key component.
 *                         Use libspdm_asym_free() function to free the resource.
 *
 * @retval  true   Private key was retrieved successfully.
 * @retval  false  Invalid PEM key data or incorrect password.
 **/
bool libspdm_asym_get_private_key_from_pem(uint32_t base_asym_algo,
                                           const uint8_t *pem_data,
                                           size_t pem_size,
                                           const char *password,
                                           void **context);

/**
 * Retrieve the Private key from the password-protected PEM key data.
 *
 * @param  req_base_asym_alg  SPDM req_base_asym_alg
 * @param  pem_data           Pointer to the PEM-encoded key data to be retrieved.
 * @param  pem_size           Size of the PEM key data in bytes.
 * @param  password           NULL-terminated passphrase used for encrypted PEM key data.
 * @param  context            Pointer to newly generated asymmetric context which contain the
 *                            retrieved private key component. Use libspdm_asym_free() function to
 *                            free the resource.
 *
 * @retval  true   Private key was retrieved successfully.
 * @retval  false  Invalid PEM key data or incorrect password.
 **/
bool libspdm_req_asym_get_private_key_from_pem(uint16_t req_base_asym_alg,
                                               const uint8_t *pem_data,
                                               size_t pem_size,
                                               const char *password,
                                               void **context);

/**
 * Return asym NID, based upon the negotiated asym algorithm.
 *
 * @param  base_asym_algo  SPDM base_asym_algo
 *
 * @return asym NID
 **/
size_t libspdm_get_aysm_nid(uint32_t base_asym_algo);

/**
 * Retrieve the Private key from the password-protected PEM key data.
 *
 * @param  pqc_asym_algo   SPDM pqc_asym_algo
 * @param  pem_data        Pointer to the PEM-encoded key data to be retrieved.
 * @param  pem_size        Size of the PEM key data in bytes.
 * @param  password        NULL-terminated passphrase used for encrypted PEM key data.
 * @param  context         Pointer to newly generated asymmetric context which contain the retrieved
 *                         private key component.
 *                         Use libspdm_asym_free() function to free the resource.
 *
 * @retval  true   Private key was retrieved successfully.
 * @retval  false  Invalid PEM key data or incorrect password.
 **/
bool libspdm_pqc_asym_get_private_key_from_pem(uint32_t pqc_asym_algo,
                                               const uint8_t *pem_data,
                                               size_t pem_size,
                                               const char *password,
                                               void **context);

/**
 * Retrieve the Private key from the password-protected PEM key data.
 *
 * @param  req_pqc_asym_alg   SPDM req_pqc_asym_alg
 * @param  pem_data           Pointer to the PEM-encoded key data to be retrieved.
 * @param  pem_size           Size of the PEM key data in bytes.
 * @param  password           NULL-terminated passphrase used for encrypted PEM key data.
 * @param  context            Pointer to newly generated asymmetric context which contain the
 *                            retrieved private key component. Use libspdm_asym_free() function to
 *                            free the resource.
 *
 * @retval  true   Private key was retrieved successfully.
 * @retval  false  Invalid PEM key data or incorrect password.
 **/
bool libspdm_req_pqc_asym_get_private_key_from_pem(uint32_t req_pqc_asym_alg,
                                                   const uint8_t *pem_data,
                                                   size_t pem_size,
                                                   const char *password,
                                                   void **context);

/**
 * Return asym NID, based upon the negotiated asym algorithm.
 *
 * @param  pqc_asym_algo   SPDM pqc_asym_algo
 *
 * @return asym NID
 **/
size_t libspdm_get_pqc_aysm_nid(uint32_t pqc_asym_algo);

/**
 * Computes the hash of a input data buffer, based upon the negotiated measurement hash algorithm.
 *
 * This function performs the hash of a given data buffer, and return the hash value.
 *
 * @param  measurement_hash_algo  SPDM measurement_hash_algo
 * @param  data                   Pointer to the buffer containing the data to be hashed.
 * @param  data_size              Size of data buffer in bytes.
 * @param  hash_value             Pointer to a buffer that receives the hash value.
 *
 * @retval true   Hash computation succeeded.
 * @retval false  Hash computation failed.
 **/
bool libspdm_measurement_hash_all(uint32_t measurement_hash_algo,
                                  const void *data, size_t data_size,
                                  uint8_t *hash_value);

#if LIBSPDM_TPM_SUPPORT
/**
 * Initialize the TPM device backend for libspdm.
 *
 * This function performs TPM-specific initialization required before any
 * cryptographic or measurement operations can be used by libspdm.
 * Typical responsibilities include:
 *   - Establishing a connection with the TPM (hardware or simulator)
 *   - Initializing TPM contexts or sessions
 *
 * This function must be called once during platform initialization,
 * before invoking any other libspdm TPM helper APIs.
 *
 * @retval true   TPM device initialization succeeded.
 * @retval false  TPM device initialization failed.
 */
bool libspdm_tpm_device_init();

/**
 * Retrieve a TPM-backed private key context.
 *
 * This function returns an opaque TPM context associated with a private key
 * that is protected and managed by the TPM. The private key material itself
 * is never exposed to the caller.
 *
 * The returned context is intended to be used internally by libspdm for
 * cryptographic operations such as signing during SPDM authentication flows.
 *
 * @param[in]  handle    Optional TPM or device handle (implementation-defined).
 * @param[out] context   Pointer to receive the TPM private key context.
 *
 * @retval true   Private key context was successfully retrieved.
 * @retval false  Failed to retrieve private key context.
 */
bool libspdm_tpm_get_pvt_key_handle(const void *handle, void **context);

/**
 * Retrieve a TPM-backed public key context.
 *
 * This function returns an opaque context representing the public portion
 * of a TPM-managed key. The public key is typically used for certificate
 * construction, verification, or SPDM key exchange operations.
 *
 * The format and lifetime of the returned context are implementation-defined.
 *
 * @param[in]  handle    Optional TPM or device handle (implementation-defined).
 * @param[out] context   Pointer to receive the TPM public key context.
 *
 * @retval true   Public key context was successfully retrieved.
 * @retval false  Failed to retrieve public key context.
 */
bool libspdm_tpm_get_pub_key_handle(const void *handle, void **context);

/* Read the actual TPM key algorithm (SPDM_KEY_PAIR_ASYM_ALGO_CAP_*) and its
 * DER AlgorithmIdentifier. Buffer size is updated on success or insufficient space. */
bool libspdm_tpm_get_key_info(const void *handle, uint32_t *asym_algo,
                              void *public_key_info, size_t *public_key_info_size);

/**
 * Read a TPM Platform Configuration Register (PCR) value.
 *
 * This function reads the value of a specified PCR index using the requested
 * hash algorithm and copies the result into the caller-provided buffer.
 *
 * If the provided buffer is too small, the required size is returned via
 * the size parameter and the buffer is not modified.
 *
 * @param[in]     hash_algo  Hash algorithm used for the PCR bank.
 * @param[in]     index      PCR index to read.
 * @param[out]    buffer     Buffer to receive the PCR value.
 * @param[in,out] size       On input, size of buffer; on output, size used or required.
 *
 * @retval true   PCR value was successfully read.
 * @retval false  Failed to read PCR value.
 */
bool libspdm_tpm_read_pcr(uint32_t hash_algo, uint32_t index, void *buffer, size_t *size);

/**
 * Read data from a TPM non-volatile (NV) index.
 *
 * This function reads the contents of a specified TPM NV index and returns
 * a buffer containing the NV data. The buffer allocation and ownership are
 * implementation-defined and must be documented by the platform.
 *
 * Typical use cases include retrieving certificates, measurements,
 * or persistent configuration data stored in TPM NV.
 *
 * @param[in]  index    TPM NV index to read.
 * @param[out] buffer   Pointer to receive the allocated NV data buffer.
 * @param[out] size     Pointer to receive the size of the NV data.
 *
 * @retval true   NV index was successfully read.
 * @retval false  Failed to read NV index.
 */
bool libspdm_tpm_read_nv(uint32_t index, void **buffer, size_t *size);

/**
 * Generate a TPM 2.0 Quote over specified PCRs.
 *
 * This function performs a TPM2_Quote operation using the specified signing key,
 * qualifying data (nonce), and PCR selection. The resulting quote is serialized
 * containing the marshaled TPM2B_ATTEST structure followed by the marshaled
 * TPMT_SIGNATURE structure.
 *
 * @param[in]      key_handle_str     TPM key handle string (e.g. "handle:0x81000021").
 * @param[in]      hash_algo          SPDM measurement hash algo used for the PCR bank.
 * @param[in]      pcr_indices        Array of PCR indices to include in quote (0..23).
 * @param[in]      pcr_count          Number of PCR indices in pcr_indices (0 selects PCR 0 and 1).
 * @param[in]      nonce              Qualifying data / nonce buffer.
 * @param[in]      nonce_size         Size in bytes of nonce buffer; larger than a TPM2B_DATA
 *                                    (64 bytes) fails instead of being truncated.
 * @param[out]     quote_buffer       Destination buffer to receive marshaled quote (attest + signature).
 * @param[in,out]  quote_buffer_size  On input, capacity of quote_buffer; on output, size used or required.
 *
 * @retval true   Quote was successfully generated.
 * @retval false  Failed to generate quote.
 */
bool libspdm_tpm_quote(
    const void *key_handle_str,
    uint32_t hash_algo,
    const uint8_t *pcr_indices,
    size_t pcr_count,
    const uint8_t *nonce,
    size_t nonce_size,
    void *quote_buffer,
    size_t *quote_buffer_size);

/**
 * Verify a TPM 2.0 Quote against a public key and expected qualifying data.
 *
 * Unmarshals TPM2B_ATTEST and TPMT_SIGNATURE, verifies the attestation header,
 * verifies that the qualifying data matches expected_nonce, and cryptographically
 * verifies the signature against the public key context.
 *
 * @param[in]  pub_key_context      Asymmetric public key context for the quote signing key.
 * @param[in]  base_asym_algo       SPDM base_asym_algo of the signing key (e.g. ECDSA P256).
 * @param[in]  hash_algo            SPDM base_hash_algo used for signature verification.
 * @param[in]  quote_buffer         Buffer containing marshaled quote (attest + signature).
 * @param[in]  quote_buffer_size    Size in bytes of quote_buffer.
 * @param[in]  expected_nonce       Expected qualifying data / nonce.
 * @param[in]  expected_nonce_size  Size of expected_nonce.
 *
 * @retval true   Quote is authentic and valid.
 * @retval false  Verification failed.
 */
bool libspdm_tpm_verify_quote(
    const void *pub_key_context,
    uint32_t base_asym_algo,
    uint32_t hash_algo,
    const void *quote_buffer,
    size_t quote_buffer_size,
    const uint8_t *expected_nonce,
    size_t expected_nonce_size);

/**
 * Read a set of TPM PCRs from one PCR bank in a single consistent snapshot.
 *
 * The PCRs are read with TPM2_PCR_Read (the TPM returns at most eight digests per command).
 * When the TPM pcrUpdateCounter changes between commands, the read is restarted, so all values
 * belong to the same PCR state. Values are concatenated in the order of pcr_indices.
 *
 * @param[in]     hash_algo         SPDM measurement hash algo selecting the PCR bank.
 * @param[in]     pcr_indices       PCR indices (0..23), strictly ascending.
 * @param[in]     pcr_count         Number of PCR indices (1..24).
 * @param[out]    pcr_values        Buffer to receive pcr_count digests, or NULL for a size query.
 * @param[in,out] pcr_values_size   On input, size of pcr_values; on output, size used or required.
 *
 * @retval true   The PCRs were read, or the required size was returned for a NULL pcr_values.
 * @retval false  Invalid parameters, buffer too small (required size returned), or TPM failure.
 */
bool libspdm_tpm_read_pcrs(uint32_t hash_algo, const uint8_t *pcr_indices, size_t pcr_count,
                           void *pcr_values, size_t *pcr_values_size);

/**
 * Verify a TPM 2.0 Quote of a known PCR set.
 *
 * quote_buffer is exactly MU(TPM2B_ATTEST) || MU(TPMT_SIGNATURE), as libspdm_tpm_quote()
 * produces it; trailing bytes are rejected. In addition to the checks of
 * libspdm_tpm_verify_quote(), the Quote must:
 * - be a TPM-generated TPM_ST_ATTEST_QUOTE with extraData equal to expected_nonce (required);
 * - select exactly pcr_indices in the PCR bank of pcr_hash_algo;
 * - carry pcrDigest = H(pcr_values), H being the hash of the Quote signature scheme;
 * - be signed (ECDSA, RSASSA or RSAPSS) by pub_key_context. The asymmetric algorithm is
 *   taken from the public key, so it does not have to match the SPDM BaseAsymAlgo.
 *
 * @param[in]  pub_key_context      Public key context of the Quote signing key (IAK).
 * @param[in]  quote_buffer         Marshaled quote (attest + signature).
 * @param[in]  quote_buffer_size    Size in bytes of quote_buffer.
 * @param[in]  expected_nonce       Expected qualifying data.
 * @param[in]  expected_nonce_size  Size of expected_nonce (1..64).
 * @param[in]  pcr_hash_algo        SPDM measurement hash algo of the PCR bank.
 * @param[in]  pcr_indices          Expected PCR indices (0..23), strictly ascending.
 * @param[in]  pcr_count            Number of PCR indices.
 * @param[in]  pcr_values           Expected PCR values, concatenated in pcr_indices order.
 * @param[in]  pcr_values_size      Size of pcr_values (pcr_count * PCR digest size).
 *
 * @retval true   The Quote is authentic, fresh and attests exactly these PCR values.
 * @retval false  Verification failed.
 */
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
    size_t pcr_values_size);

/**
 * Verify a TPM 2.0 Quote against the PCR measurement blocks of a MEASUREMENTS record.
 *
 * The PCR blocks are found by the index profile of library/spdm_tpm_pcr.h (PCR 0..14 at
 * index 1..15, PCR 15 at 0x12); other blocks are ignored but must be well formed. Each PCR
 * block must be a DMTF digest of the PCR bank size and appear once, and the record must hold
 * at least one. The Quote must then pass libspdm_tpm_verify_quote_pcrs() for exactly these
 * PCRs and values.
 *
 * @param[in]  pub_key_context            Public key context of the Quote signing key (IAK).
 * @param[in]  quote_buffer               MU(TPM2B_ATTEST) || MU(TPMT_SIGNATURE).
 * @param[in]  quote_buffer_size          Size in bytes of quote_buffer.
 * @param[in]  expected_nonce             Expected qualifying data (GET_MEASUREMENTS Nonce).
 * @param[in]  expected_nonce_size        Size of expected_nonce.
 * @param[in]  measurement_hash_algo      SPDM measurement hash algo (PCR bank).
 * @param[in]  measurement_record         MEASUREMENTS MeasurementRecord.
 * @param[in]  measurement_record_length  Size of measurement_record.
 *
 * @retval true   The Quote is authentic, fresh and attests exactly the reported PCRs.
 * @retval false  Malformed record, no PCR block, or Quote verification failed.
 */
bool libspdm_tpm_verify_quote_measurement_record(
    const void *pub_key_context,
    const void *quote_buffer,
    size_t quote_buffer_size,
    const uint8_t *expected_nonce,
    size_t expected_nonce_size,
    uint32_t measurement_hash_algo,
    const void *measurement_record,
    size_t measurement_record_length);

/* Maximum DER size of a TCG HardwareModuleName returned by
 * libspdm_tpm_get_cert_device_identity(). */
#define LIBSPDM_TPM_HW_MODULE_NAME_MAX_SIZE 128

/**
 * Get the TPM identity fields of a TCG DevID / IAK certificate (TCG "TPM 2.0 Keys for Device
 * Identity and Attestation" v1.10 sec. 8).
 *
 * - hw_module_name: the DER HardwareModuleName of the SubjectAltName otherName
 *   id-on-hardwareModuleName (RFC 4108), with hwType TPM 2.0 (2.23.133.1.2) and a non-empty
 *   hwSerialNum. It identifies the TPM; certificates of keys in the same TPM carry the same
 *   value. Required.
 * - verified_tpm_restricted: certificatePolicies contains tcg-cap-verifiedTPMRestricted
 *   (2.23.133.11.1.3), i.e. the CA verified that the key is a restricted TPM key.
 *
 * Comparing these values between certificates is verifier policy and left to the caller.
 *
 * @param[in]     cert                     DER X.509 certificate.
 * @param[in]     cert_size                Size of cert.
 * @param[out]    hw_module_name           Buffer for the HardwareModuleName DER.
 * @param[in,out] hw_module_name_size      On input, size of hw_module_name; on output, size used.
 * @param[out]    verified_tpm_restricted  Whether tcg-cap-verifiedTPMRestricted is asserted.
 *
 * @retval true   The certificate has a TPM 2.0 hardwareModuleName.
 * @retval false  No or malformed TPM 2.0 hardwareModuleName, or buffer too small.
 */
bool libspdm_tpm_get_cert_device_identity(const uint8_t *cert, size_t cert_size,
                                          uint8_t *hw_module_name, size_t *hw_module_name_size,
                                          bool *verified_tpm_restricted);

/**
 * Encode a TPM2_Quote as MEASUREMENTS OpaqueData (OpaqueDataFmt1 general opaque data table
 * with one SPDM_REGISTRY_ID_TCG element, see library/spdm_tpm_quote_opaque.h).
 *
 * @param[in]     iak_slot_id   SPDM slot of the IAK certificate chain.
 * @param[in]     quote         MU(TPM2B_ATTEST) || MU(TPMT_SIGNATURE).
 * @param[in]     quote_size    Size of quote.
 * @param[out]    opaque_data   Destination buffer.
 * @param[in,out] opaque_size   On input, size of opaque_data; on output, size used or required.
 *
 * @retval true   The opaque data was written.
 * @retval false  Malformed quote, or buffer too small (required size returned).
 */
bool libspdm_tpm_quote_opaque_encode(uint8_t iak_slot_id, const void *quote, size_t quote_size,
                                     void *opaque_data, size_t *opaque_size);

/**
 * Decode MEASUREMENTS OpaqueData produced by libspdm_tpm_quote_opaque_encode().
 *
 * The table must hold exactly one element: SPDM_REGISTRY_ID_TCG, the configured TCG vendor ID,
 * a supported element version, consistent attest / signature sizes, zero padding to a 4-byte
 * boundary, and no trailing data.
 *
 * @param[in]  opaque_data   OpaqueData.
 * @param[in]  opaque_size   Size of opaque_data (non-zero).
 * @param[out] iak_slot_id   SPDM slot of the IAK certificate chain named by the element.
 * @param[out] quote         Points into opaque_data at MU(TPM2B_ATTEST) || MU(TPMT_SIGNATURE).
 * @param[out] quote_size    Size of quote.
 *
 * @retval true   A well-formed Quote element was found.
 * @retval false  Malformed or unsupported opaque data.
 */
bool libspdm_tpm_quote_opaque_decode(const void *opaque_data, size_t opaque_size,
                                     uint8_t *iak_slot_id, const void **quote,
                                     size_t *quote_size);

#endif /* LIBSPDM_TPM_SUPPORT */

#endif /* SPDM_CRYPT_EXT_LIB_H */
