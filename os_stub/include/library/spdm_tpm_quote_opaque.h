/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/**
 * TPM2_Quote evidence carried in MEASUREMENTS.OpaqueData.
 *
 * The Quote is a second, TPM-native evidence layer next to the SPDM MEASUREMENTS signature: the
 * SPDM signature (identity key, e.g. slot 0) authenticates the transcript, the Quote (restricted
 * IAK) authenticates the PCR values. The Quote never replaces MEASUREMENTS.Signature.
 *
 * It is one element of the general opaque data table (OpaqueDataFmt1) with
 * ID = SPDM_REGISTRY_ID_TCG, VendorIDLen = 2 and an implementation-defined element body:
 *
 *   uint8_t   version;          LIBSPDM_TPM_QUOTE_ELEMENT_VERSION
 *   uint8_t   iak_slot_id;      SPDM slot of the IAK certificate chain
 *   uint16_t  attest_size;      little endian, size of MU(TPM2B_ATTEST)
 *   uint16_t  signature_size;   little endian, size of MU(TPMT_SIGNATURE)
 *   uint8_t   attest[attest_size];        TSS2-marshaled TPM2B_ATTEST
 *   uint8_t   signature[signature_size];  TSS2-marshaled TPMT_SIGNATURE
 *
 * TPMS_ATTEST.extraData is the 32-byte GET_MEASUREMENTS Nonce.
 **/

#ifndef SPDM_TPM_QUOTE_OPAQUE_H
#define SPDM_TPM_QUOTE_OPAQUE_H

#define LIBSPDM_TPM_QUOTE_ELEMENT_VERSION 1
#define LIBSPDM_TPM_QUOTE_ELEMENT_HEADER_SIZE 6
#define LIBSPDM_TPM_QUOTE_VENDOR_ID_LEN 2
/* Offset of the element body (version) in the OpaqueData: table header (4), element ID and
 * VendorIDLen (2), vendor ID (2), OpaqueElementDataLen (2). The element is padded to 4 bytes. */
#define LIBSPDM_TPM_QUOTE_ELEMENT_OFFSET 10

/* TCG vendor ID placed in the opaque element. Configurable at build time until a registry
 * policy is agreed (TPM manufacturer vs. evidence provider). */
#ifndef LIBSPDM_TPM_QUOTE_TCG_VENDOR_ID
#define LIBSPDM_TPM_QUOTE_TCG_VENDOR_ID 0x0000
#endif

/* Default SPDM slot of the IAK certificate chain. Slot 0/1/4 are the identity cert chains of the
 * os_stub samples; the IAK uses a dedicated slot that is never used for SPDM signing. */
#ifndef LIBSPDM_TPM_IAK_SLOT_ID
#define LIBSPDM_TPM_IAK_SLOT_ID 5
#endif

#endif /* SPDM_TPM_QUOTE_OPAQUE_H */
