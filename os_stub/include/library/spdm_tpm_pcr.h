/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/**
 * TPM PCR measurement profile shared by the TPM device library and the requester-side
 * TPM2_Quote verifier: PCR 0..15 are reported as DMTF measurement blocks. PCR n uses
 * measurement index n + 1 for PCR 0..14; PCR 15 uses 0x12 so that SVN (0x10) and HEM (0x11)
 * keep their indices.
 **/

#ifndef SPDM_TPM_PCR_H
#define SPDM_TPM_PCR_H

#include "hal/base.h"

#define LIBSPDM_TPM_PCR_COUNT 16

/* Preserve SVN (0x10) and HEM (0x11); PCR 15 uses measurement index 0x12. */
static inline uint8_t libspdm_tpm_pcr_measurement_index(uint8_t pcr_index)
{
    return pcr_index < 15 ? (uint8_t)(pcr_index + 1) : 0x12;
}

/* Return LIBSPDM_TPM_PCR_COUNT for indices outside this profile. */
static inline uint8_t libspdm_tpm_measurement_pcr_index(uint8_t measurement_index)
{
    if ((measurement_index >= 1) && (measurement_index <= 0x0F)) {
        return (uint8_t)(measurement_index - 1);
    }
    return measurement_index == 0x12 ? 15 : LIBSPDM_TPM_PCR_COUNT;
}

#endif /* SPDM_TPM_PCR_H */
