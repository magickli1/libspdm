/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/**
 * TPM PCR measurement profile shared by the TPM device library and the requester-side
 * TPM2_Quote verifier: PCR 0..14 are reported as DMTF measurement blocks.
 * PCR n uses measurement index n + 1 (so PCR 0..14 map to index 1..15). Index 0x10
 * (SVN) and 0x11 (HEM) remain available for non-PCR blocks. PCR 15 is not reported yet.
 **/

#ifndef SPDM_TPM_PCR_H
#define SPDM_TPM_PCR_H

#include "hal/base.h"

#define LIBSPDM_TPM_PCR_COUNT 15

/* PCR n -> measurement index n + 1 for PCR 0..14. */
static inline uint8_t libspdm_tpm_pcr_measurement_index(uint8_t pcr_index)
{
    return (uint8_t)(pcr_index + 1);
}

/* Return LIBSPDM_TPM_PCR_COUNT for indices outside this profile. */
static inline uint8_t libspdm_tpm_measurement_pcr_index(uint8_t measurement_index)
{
    if ((measurement_index >= 1) && (measurement_index <= LIBSPDM_TPM_PCR_COUNT)) {
        return (uint8_t)(measurement_index - 1);
    }
    return LIBSPDM_TPM_PCR_COUNT;
}

#endif /* SPDM_TPM_PCR_H */
