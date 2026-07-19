/**
 *  Copyright Notice:
 *  Copyright 2021-2025 DMTF. All rights reserved.
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
bool libspdm_tpm_get_pvt_key_handle(void *handle, void **context);

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
bool libspdm_tpm_get_pub_key_handle(void *handle, void **context);

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
 * Generate a TPM2 Quote over the selected PCRs.
 *
 * The returned buffers contain TSS2-MU encoded TPM2B_ATTEST and TPMT_SIGNATURE
 * structures. The caller supplies all storage; this function never truncates.
 *
 * @param[in]     key_handle       Persistent TPM attestation-key handle.
 * @param[in]     hash_algo        SPDM measurement hash algorithm / PCR bank.
 * @param[in]     pcr_mask          Bit mask of PCR indices to quote (PCR 0 is bit 0).
 * @param[in]     nonce            Qualifying data from GET_MEASUREMENTS.
 * @param[in]     nonce_size       Size of nonce; must be SPDM_NONCE_SIZE.
 * @param[in]     pcr_data         Concatenated PCR values in ascending index order.
 * @param[in]     pcr_data_size    Size of pcr_data.
 * @param[out]    attest           Encoded TPM2B_ATTEST.
 * @param[in,out] attest_size      Available/used attest buffer size.
 * @param[out]    signature        Encoded TPMT_SIGNATURE.
 * @param[in,out] signature_size   Available/used signature buffer size.
 *
 * @retval true   Quote generated and marshalled.
 * @retval false  Invalid parameters, insufficient output space, or TPM error.
 */
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
                       size_t *signature_size);

/**
 * Verify a marshalled TPM Quote and its binding to SPDM measurement data.
 *
 * @param[in] cert          DER-encoded IAK leaf certificate.
 * @param[in] cert_size     Size of cert.
 * @param[in] hash_algo     SPDM measurement hash algorithm / expected PCR bank.
 * @param[in] pcr_mask      Expected TPM PCR selection.
 * @param[in] nonce         Expected GET_MEASUREMENTS requester nonce.
 * @param[in] nonce_size    Size of nonce; must be SPDM_NONCE_SIZE.
 * @param[in] pcr_data      Concatenated PCR values in ascending index order.
 * @param[in] pcr_data_size Size of pcr_data.
 * @param[in] attest        TSS2-MU encoded TPM2B_ATTEST.
 * @param[in] attest_size   Size of attest.
 * @param[in] signature     TSS2-MU encoded TPMT_SIGNATURE.
 * @param[in] signature_size Size of signature.
 *
 * @retval true   Quote structure, freshness, PCR digest, and signature are valid.
 * @retval false  Quote validation failed.
 */
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
                              size_t signature_size);

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

#endif /* LIBSPDM_TPM_SUPPORT */

#endif /* SPDM_CRYPT_EXT_LIB_H */
