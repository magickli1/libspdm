# TPM Integration Guide for libspdm

This document describes how to use TPM-backed helper APIs with libspdm for secure key handling, measurements, and platform attestation.

---

## CMake Configuration

Configure TPM key handles and certificate chain NV indices at build time. The TPM sample is built
with `CRYPTO=openssl`, `DEVICE=tpm` and `LIBSPDM_TPM_SUPPORT=ON`, and the `LIBSPDM_TPM_*`
variables below have no effect with any other `DEVICE`:

```bash
cmake -B build \
    -DTOOLCHAIN=GCC \
    -DTARGET=Release \
    -DCRYPTO=openssl \
    -DDEVICE=tpm \
    -DLIBSPDM_TPM_SUPPORT=ON \
    -DLIBSPDM_TPM_REQUESTER_SLOT_IDS="0;1" \
    -DLIBSPDM_TPM_REQUESTER_HANDLES="0x81000011;0x81000011" \
    -DLIBSPDM_TPM_REQUESTER_CERTCHAINS="0x1500011;0x1500012" \
    -DLIBSPDM_TPM_RESPONDER_SLOT_IDS="0;1;4" \
    -DLIBSPDM_TPM_RESPONDER_HANDLES="0x81000021;0x81000021;0x81000021" \
    -DLIBSPDM_TPM_RESPONDER_CERTCHAINS="0x1500021;0x1500022;0x1500024"
```

### Configuration Parameters

| Parameter | Description | Format |
|-----------|-------------|--------|
| `LIBSPDM_TPM_REQUESTER_SLOT_IDS` | SPDM requester slot IDs that the following requester handles/certchains map to | Semicolon-separated decimal values, 0..7 |
| `LIBSPDM_TPM_REQUESTER_HANDLES` | TPM persistent key handles for requester | Semicolon-separated hex values |
| `LIBSPDM_TPM_REQUESTER_CERTCHAINS` | NV indices for requester certificate chains | Semicolon-separated hex values |
| `LIBSPDM_TPM_RESPONDER_SLOT_IDS` | SPDM responder slot IDs that the following responder handles/certchains map to | Semicolon-separated decimal values, 0..7 |
| `LIBSPDM_TPM_RESPONDER_HANDLES` | TPM persistent key handles for responder | Semicolon-separated hex values |
| `LIBSPDM_TPM_RESPONDER_CERTCHAINS` | NV indices for responder certificate chains | Semicolon-separated hex values |
| `LIBSPDM_TPM_IAK_SLOT_ID` | Responder slot that serves the restricted IAK certificate chain. The IAK only signs TPM2_Quote evidence, so this slot must not be in `LIBSPDM_TPM_RESPONDER_SLOT_IDS` | Decimal value, 1..7 (default `5`) |
| `LIBSPDM_TPM_IAK_HANDLE` | TPM persistent handle of the restricted IAK | Hex value (default `0x81020001`) |
| `LIBSPDM_TPM_IAK_CERTCHAIN` | NV index of the IAK certificate chain | Hex value (default `0x01C90100`) |
| `LIBSPDM_TPM_ROOT_CERT` | NV index of the Root CA certificate (DER), used for chains in the TCG DevID NV range | Hex value (default `0x1500000`) |

A certificate chain NV index in the TCG "TPM 2.0 Keys for Device Identity and Attestation"
range 0x01C90100-0x01C902FF (IAK chains from 0x01C90100, IDevID chains from 0x01C90200) holds DER
certificates, leaf first and without the Root CA, as that specification defines. The sample reads
the Root CA from `LIBSPDM_TPM_ROOT_CERT` and builds the chain in the SPDM order, Root CA first.
Other NV indices hold the chain in the SPDM order and are read as is.

The TCG vendor ID of the TPM Quote OpaqueData element is the compile-time definition
`LIBSPDM_TPM_QUOTE_TCG_VENDOR_ID` (default `0x0000`, `library/spdm_tpm_quote_opaque.h`).

**Note:** The `*_SLOT_IDS`, `*_HANDLES`, and `*_CERTCHAINS` lists are mapped by entry position. For example, `LIBSPDM_TPM_RESPONDER_SLOT_IDS="0;1;4"` maps the first responder handle/certchain pair to slot 0, the second pair to slot 1, and the third pair to slot 4. This supports empty/non-contiguous SPDM slots.

The sample reads each Responder slot's certificate chain from that slot's NV index, and the
Requester's chain from its slot 0 NV index. It does not select the signing key by slot: it signs
with the handle configured for the slot whose ID equals the KeyPairID that libspdm passes to the
signing functions, and with the slot 0 handle when no such slot exists. Without multiple keys
that KeyPairID is always 0, so every slot signs with the slot 0 handle and every Responder slot's
certificate chain must be for that key. This is why the example above, like the default
configuration, uses one handle for all slots.

---

## Overview

The TPM integration layer provides:

- Private key protection (keys never leave TPM)
- Public key access for SPDM flows
- PCR reads for measurements
- TPM2_Quote evidence for the PCR measurements, signed by a restricted IAK
- NV storage access for certificates/config

These APIs are designed to plug into libspdm cryptographic and measurement flows.

---

## Initialization

Before using any TPM functionality, the TPM backend must be initialized.

```c
if (!libspdm_tpm_device_init()) {
    printf("TPM initialization failed\n");
    return -1;
}
```

### What happens internally

- Connects to TPM (hardware or simulator like `swtpm`)
- Initializes TPM context
 
**Must be called **once** during platform initialization.**

---

## Using TPM-backed Keys

### Private Key Handle

```c
void *priv_ctx = NULL;

if (!libspdm_tpm_get_pvt_key_handle("handle:0x81000021", &priv_ctx)) {
    printf("Failed to get private key\n");
    return -1;
}
```

- The key is named as the OpenSSL TPM provider expects, such as `"handle:0x81000021"`.
  The generated `LIBSPDM_TPM_HANDLE_*_HANDLE_SLOT_n` macros have this form.
- Opaque handle
- Used for signing (SPDM `CHALLENGE_AUTH`)

---

### Public Key Handle

```c
void *pub_ctx = NULL;

if (!libspdm_tpm_get_pub_key_handle("handle:0x81000021", &pub_ctx)) {
    printf("Failed to get public key\n");
    return -1;
}
```

The key is named the same way as for the private key handle. Used for certificate and verification
flows.

---

## Reading PCR Values

```c
uint8_t buffer[64];
size_t size = sizeof(buffer);

if (!libspdm_tpm_read_pcr(SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256, 0, buffer,
                          &size)) {
    printf("Failed to read PCR\n");
    return -1;
}
```

- `hash_algo`: the PCR bank, as an SPDM `MeasurementHashAlgo` value
- `index`: PCR number

To read several PCRs in one consistent snapshot, for example the PCRs that a TPM2_Quote attests:

```c
uint8_t pcrs[] = {0, 1, 7};
uint8_t values[3 * 32];
size_t values_size = sizeof(values);

if (!libspdm_tpm_read_pcrs(SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256, pcrs, 3,
                           values, &values_size)) {
    printf("Failed to read PCRs\n");
    return -1;
}
```

- `pcr_indices`: strictly ascending PCR numbers (0..23)
- `pcr_values`: the digests, concatenated in `pcr_indices` order; with `NULL` the function
  returns the required size in `pcr_values_size`

---

## TPM Quote Evidence for Measurements

The TPM sample reports PCR 0..15 as measurement blocks (`library/spdm_tpm_pcr.h`: PCR 0..14 at
measurement index 1..15, PCR 15 at index 0x12). For a GET_MEASUREMENTS that requests a signature,
`libspdm_measurement_collection()` also produces a TPM2_Quote of the reported PCRs:

1. `libspdm_tpm_read_pcrs()` reads the reported PCRs in one snapshot.
2. `libspdm_tpm_quote()` quotes the same PCRs with the restricted IAK
   (`LIBSPDM_TPM_HANDLE_IAK`); the qualifying data is the requester nonce.
3. `libspdm_tpm_verify_quote_pcrs()` checks the Quote against the snapshot with the IAK public key.
   If a PCR was extended in between, the collection is repeated a bounded number of times and
   then fails, so the measurement record and the Quote always describe the same PCR state.
4. `libspdm_tpm_quote_opaque_encode()` encodes the Quote as one `SPDM_REGISTRY_ID_TCG` element of
   the general opaque data table (OpaqueDataFmt1). `libspdm_measurement_opaque_data()` returns it
   for that response only.

The Quote is extra evidence: `MEASUREMENTS.Signature` is still made with the SPDM signing key.
The element layout is in `library/spdm_tpm_quote_opaque.h`.

A Requester verifies the evidence with:

| API | Purpose |
| --- | ------- |
| `libspdm_tpm_quote_opaque_decode()` | Strictly parse the OpaqueData element; returns the IAK slot and the Quote |
| `libspdm_tpm_verify_quote_measurement_record()` | Verify the Quote signature, its nonce, and that it attests exactly the PCR blocks of the measurement record |
| `libspdm_tpm_verify_quote_pcrs()` | Verify a Quote against a known PCR list and values |
| `libspdm_tpm_get_cert_device_identity()` | Get the TCG `hardwareModuleName` and `tcg-cap-verifiedTPMRestricted` of an IDevID or IAK certificate, to check that the IAK is a restricted key of the same TPM |

Which slots to trust and how to compare the certificate identities is verifier policy, left to the
caller. `libspdm_tpm_get_pub_key_handle()` returns the public part of a TPM key handle as a
software key, for example to verify a Quote locally.

---

## Reading TPM NV Storage

```c
void *nv_data = NULL;
size_t nv_size = 0;

if (!libspdm_tpm_read_nv(0x1500021, &nv_data, &nv_size)) {
    printf("Failed to read NV index\n");
    return -1;
}

/* Use nv_data, then release it. */
free(nv_data);
```

Used for certificates and persistent data. The function allocates the returned buffer, which the
caller frees with `free()`. The sample reads certificate chains from the NV indices that the build
generates as `LIBSPDM_TPM_HANDLE_*_CERTCHAIN_SLOT_n`.

---

## SPDM Mapping

| SPDM Operation   | TPM API                          |
| ---------------- | -------------------------------- |
| `CERTIFICATE`    | `libspdm_tpm_read_nv` (IAK chain on `LIBSPDM_TPM_IAK_SLOT_ID`) |
| `CHALLENGE_AUTH` | `libspdm_tpm_get_pvt_key_handle` |
| `MEASUREMENTS`   | `libspdm_tpm_read_pcrs`; OpaqueData: `libspdm_tpm_quote` |
| `KEY_EXCHANGE`   | TPM-backed keys                  |

---

## Testing with spdm-emu + swtpm

You can test TPM-backed libspdm integration using the official SPDM emulator:

[SPDM-EMU DOCS](https://github.com/DMTF/spdm-emu/blob/main/doc/)
