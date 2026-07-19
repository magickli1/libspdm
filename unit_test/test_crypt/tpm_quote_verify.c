/**
 *  Copyright Notice:
 *  Copyright 2021-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "test_crypt.h"

#if defined(LIBSPDM_TPM_SUPPORT) && (LIBSPDM_TPM_SUPPORT)

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_tpm2_types.h>

#include "industry_standard/spdm.h"
#include "library/spdm_crypt_ext_lib.h"
#include "library/spdm_crypt_lib.h"

/**
 * Unit coverage for libspdm_tpm_verify_quote without a live TPM:
 *   - valid crafted Quote / signature / PCR binding
 *   - bad nonce (extraData)
 *   - bad pcrDigest
 *   - bad magic
 *   - bad attestation type
 *   - wrong signature
 *
 * libspdm_tpm_quote still requires a live TPM/swtpm and is covered by
 * emulator CI (build_CI_TPM.yml), not this offline vector test.
 **/

typedef struct {
    uint8_t *cert_der;
    size_t cert_der_size;
    EVP_PKEY *pkey;
} libspdm_tpm_quote_test_key_t;

static bool libspdm_tpm_quote_test_make_cert(libspdm_tpm_quote_test_key_t *key)
{
    EVP_PKEY_CTX *pctx;
    X509 *x509;
    X509_NAME *name;
    unsigned char *der;
    int der_size;

    libspdm_zero_mem(key, sizeof(*key));

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if ((pctx == NULL) ||
        (EVP_PKEY_keygen_init(pctx) != 1) ||
        (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) != 1) ||
        (EVP_PKEY_keygen(pctx, &key->pkey) != 1)) {
        EVP_PKEY_CTX_free(pctx);
        return false;
    }
    EVP_PKEY_CTX_free(pctx);

    x509 = X509_new();
    name = X509_NAME_new();
    if ((x509 == NULL) || (name == NULL) ||
        (X509_set_version(x509, 2) != 1) ||
        (ASN1_INTEGER_set(X509_get_serialNumber(x509), 1) != 1) ||
        (X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                    (const unsigned char *)"tpm-quote-test",
                                    -1, -1, 0) != 1) ||
        (X509_set_subject_name(x509, name) != 1) ||
        (X509_set_issuer_name(x509, name) != 1) ||
        (X509_set_pubkey(x509, key->pkey) != 1) ||
        (X509_gmtime_adj(X509_get_notBefore(x509), 0) == NULL) ||
        (X509_gmtime_adj(X509_get_notAfter(x509), 60 * 60 * 24) == NULL) ||
        (X509_sign(x509, key->pkey, EVP_sha256()) == 0)) {
        X509_NAME_free(name);
        X509_free(x509);
        EVP_PKEY_free(key->pkey);
        key->pkey = NULL;
        return false;
    }
    X509_NAME_free(name);

    der = NULL;
    der_size = i2d_X509(x509, &der);
    X509_free(x509);
    if ((der_size <= 0) || (der == NULL)) {
        EVP_PKEY_free(key->pkey);
        key->pkey = NULL;
        return false;
    }
    key->cert_der = der;
    key->cert_der_size = (size_t)der_size;
    return true;
}

static void libspdm_tpm_quote_test_free_key(libspdm_tpm_quote_test_key_t *key)
{
    OPENSSL_free(key->cert_der);
    EVP_PKEY_free(key->pkey);
    libspdm_zero_mem(key, sizeof(*key));
}

static bool libspdm_tpm_quote_test_build_attest(
    const uint8_t *nonce, size_t nonce_size,
    uint32_t pcr_mask, const uint8_t *pcr_data, size_t pcr_data_size,
    uint32_t magic, uint16_t attest_type,
    const uint8_t *pcr_digest_override, size_t pcr_digest_override_size,
    uint8_t *attest, size_t *attest_size,
    uint8_t *attestation_data, size_t *attestation_data_size)
{
    TPMS_ATTEST attest_body;
    TPM2B_ATTEST quote;
    uint8_t expected_digest[LIBSPDM_SHA256_DIGEST_SIZE];
    size_t offset;
    uint8_t index;
    TSS2_RC result;

    libspdm_zero_mem(&attest_body, sizeof(attest_body));
    attest_body.magic = magic;
    attest_body.type = attest_type;
    attest_body.qualifiedSigner.size = 0;
    attest_body.extraData.size = (uint16_t)nonce_size;
    libspdm_copy_mem(attest_body.extraData.buffer,
                     sizeof(attest_body.extraData.buffer),
                     nonce, nonce_size);
    attest_body.clockInfo.clock = 0;
    attest_body.clockInfo.resetCount = 0;
    attest_body.clockInfo.restartCount = 0;
    attest_body.clockInfo.safe = 0;
    attest_body.firmwareVersion = 0;
    attest_body.attested.quote.pcrSelect.count = 1;
    attest_body.attested.quote.pcrSelect.pcrSelections[0].hash = TPM2_ALG_SHA256;
    attest_body.attested.quote.pcrSelect.pcrSelections[0].sizeofSelect = 3;
    libspdm_zero_mem(attest_body.attested.quote.pcrSelect.pcrSelections[0].pcrSelect,
                     3);
    for (index = 0; index < 24; index++) {
        if ((pcr_mask & (1u << index)) != 0) {
            attest_body.attested.quote.pcrSelect.pcrSelections[0]
            .pcrSelect[index / 8] |= (uint8_t)(1u << (index % 8));
        }
    }

    if ((pcr_digest_override != NULL) && (pcr_digest_override_size != 0)) {
        attest_body.attested.quote.pcrDigest.size =
            (uint16_t)pcr_digest_override_size;
        libspdm_copy_mem(attest_body.attested.quote.pcrDigest.buffer,
                         sizeof(attest_body.attested.quote.pcrDigest.buffer),
                         pcr_digest_override, pcr_digest_override_size);
    } else {
        if (!libspdm_hash_all(SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
                              pcr_data, pcr_data_size, expected_digest)) {
            return false;
        }
        attest_body.attested.quote.pcrDigest.size = sizeof(expected_digest);
        libspdm_copy_mem(attest_body.attested.quote.pcrDigest.buffer,
                         sizeof(attest_body.attested.quote.pcrDigest.buffer),
                         expected_digest, sizeof(expected_digest));
    }

    libspdm_zero_mem(&quote, sizeof(quote));
    offset = 0;
    result = Tss2_MU_TPMS_ATTEST_Marshal(&attest_body, quote.attestationData,
                                         sizeof(quote.attestationData), &offset);
    if (result != TSS2_RC_SUCCESS) {
        return false;
    }
    quote.size = (uint16_t)offset;
    if (offset > *attestation_data_size) {
        return false;
    }
    libspdm_copy_mem(attestation_data, *attestation_data_size,
                     quote.attestationData, offset);
    *attestation_data_size = offset;

    offset = 0;
    result = Tss2_MU_TPM2B_ATTEST_Marshal(&quote, attest, *attest_size, &offset);
    if (result != TSS2_RC_SUCCESS) {
        return false;
    }
    *attest_size = offset;
    return true;
}

static bool libspdm_tpm_quote_test_sign(
    EVP_PKEY *pkey, const uint8_t *attestation_data, size_t attestation_data_size,
    bool corrupt_signature, uint8_t *signature, size_t *signature_size)
{
    EVP_MD_CTX *md_context;
    unsigned char der_sig[256];
    size_t der_sig_size;
    const unsigned char *der_ptr;
    ECDSA_SIG *ecdsa_sig;
    const BIGNUM *r;
    const BIGNUM *s;
    TPMT_SIGNATURE tpm_sig;
    size_t offset;
    TSS2_RC result;
    int r_size;
    int s_size;

    md_context = EVP_MD_CTX_new();
    der_sig_size = sizeof(der_sig);
    if ((md_context == NULL) ||
        (EVP_DigestSignInit(md_context, NULL, EVP_sha256(), NULL, pkey) != 1) ||
        (EVP_DigestSign(md_context, der_sig, &der_sig_size,
                        attestation_data, attestation_data_size) != 1)) {
        EVP_MD_CTX_free(md_context);
        return false;
    }
    EVP_MD_CTX_free(md_context);

    der_ptr = der_sig;
    ecdsa_sig = d2i_ECDSA_SIG(NULL, &der_ptr, (long)der_sig_size);
    if (ecdsa_sig == NULL) {
        return false;
    }
    ECDSA_SIG_get0(ecdsa_sig, &r, &s);
    r_size = BN_num_bytes(r);
    s_size = BN_num_bytes(s);
    if ((r_size <= 0) || (s_size <= 0) ||
        (r_size > (int)sizeof(tpm_sig.signature.ecdsa.signatureR.buffer)) ||
        (s_size > (int)sizeof(tpm_sig.signature.ecdsa.signatureS.buffer))) {
        ECDSA_SIG_free(ecdsa_sig);
        return false;
    }

    libspdm_zero_mem(&tpm_sig, sizeof(tpm_sig));
    tpm_sig.sigAlg = TPM2_ALG_ECDSA;
    tpm_sig.signature.ecdsa.hash = TPM2_ALG_SHA256;
    tpm_sig.signature.ecdsa.signatureR.size = (uint16_t)r_size;
    tpm_sig.signature.ecdsa.signatureS.size = (uint16_t)s_size;
    BN_bn2bin(r, tpm_sig.signature.ecdsa.signatureR.buffer);
    BN_bn2bin(s, tpm_sig.signature.ecdsa.signatureS.buffer);
    ECDSA_SIG_free(ecdsa_sig);

    if (corrupt_signature && (tpm_sig.signature.ecdsa.signatureS.size > 0)) {
        tpm_sig.signature.ecdsa.signatureS.buffer[
            tpm_sig.signature.ecdsa.signatureS.size - 1] ^= 0x01;
    }

    offset = 0;
    result = Tss2_MU_TPMT_SIGNATURE_Marshal(&tpm_sig, signature, *signature_size,
                                            &offset);
    if (result != TSS2_RC_SUCCESS) {
        return false;
    }
    *signature_size = offset;
    return true;
}

static bool libspdm_tpm_quote_test_case(
    const libspdm_tpm_quote_test_key_t *key,
    uint32_t magic, uint16_t attest_type,
    const uint8_t *nonce, const uint8_t *verify_nonce,
    const uint8_t *pcr_data, size_t pcr_data_size,
    const uint8_t *verify_pcr_data, size_t verify_pcr_data_size,
    const uint8_t *pcr_digest_override, size_t pcr_digest_override_size,
    bool corrupt_signature, bool expect_pass)
{
    uint8_t attest[1024];
    size_t attest_size;
    uint8_t attestation_data[1024];
    size_t attestation_data_size;
    uint8_t signature[256];
    size_t signature_size;
    uint32_t pcr_mask;
    bool result;

    pcr_mask = 0x3; /* PCR 0 and PCR 1 */
    attest_size = sizeof(attest);
    attestation_data_size = sizeof(attestation_data);
    if (!libspdm_tpm_quote_test_build_attest(
            nonce, SPDM_NONCE_SIZE, pcr_mask, pcr_data, pcr_data_size,
            magic, attest_type, pcr_digest_override, pcr_digest_override_size,
            attest, &attest_size, attestation_data, &attestation_data_size)) {
        return false;
    }

    signature_size = sizeof(signature);
    if (!libspdm_tpm_quote_test_sign(
            key->pkey, attestation_data, attestation_data_size,
            corrupt_signature, signature, &signature_size)) {
        return false;
    }

    result = libspdm_tpm_verify_quote(
        key->cert_der, key->cert_der_size,
        SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256, pcr_mask,
        verify_nonce, SPDM_NONCE_SIZE,
        verify_pcr_data, verify_pcr_data_size,
        attest, attest_size, signature, signature_size);
    return result == expect_pass;
}

bool libspdm_validate_crypt_tpm_quote(void)
{
    libspdm_tpm_quote_test_key_t key;
    uint8_t nonce[SPDM_NONCE_SIZE];
    uint8_t bad_nonce[SPDM_NONCE_SIZE];
    uint8_t pcr_data[64];
    uint8_t bad_pcr_data[64];
    uint8_t bad_digest[LIBSPDM_SHA256_DIGEST_SIZE];
    bool status;

    libspdm_my_print("\nCrypto TPM Quote verify Testing:\n");
    libspdm_my_print("---------------------------------------------\n");

    if (!libspdm_tpm_quote_test_make_cert(&key)) {
        libspdm_my_print("[Fail: generate test IAK cert]\n");
        return false;
    }

    libspdm_zero_mem(nonce, sizeof(nonce));
    libspdm_zero_mem(bad_nonce, sizeof(bad_nonce));
    libspdm_zero_mem(pcr_data, sizeof(pcr_data));
    libspdm_zero_mem(bad_pcr_data, sizeof(bad_pcr_data));
    libspdm_zero_mem(bad_digest, sizeof(bad_digest));
    nonce[0] = 0x11;
    bad_nonce[0] = 0x22;
    pcr_data[0] = 0xA5;
    pcr_data[32] = 0x5A;
    bad_pcr_data[0] = 0x5A;
    bad_pcr_data[32] = 0xA5;
    bad_digest[0] = 0xFF;

    status = libspdm_tpm_quote_test_case(
        &key, TPM2_GENERATED_VALUE, TPM2_ST_ATTEST_QUOTE,
        nonce, nonce, pcr_data, sizeof(pcr_data), pcr_data, sizeof(pcr_data),
        NULL, 0, false, true);
    if (!status) {
        libspdm_my_print("[Fail: valid Quote]\n");
        libspdm_tpm_quote_test_free_key(&key);
        return false;
    }
    libspdm_my_print("[Pass: valid Quote]\n");

    status = libspdm_tpm_quote_test_case(
        &key, TPM2_GENERATED_VALUE, TPM2_ST_ATTEST_QUOTE,
        nonce, bad_nonce, pcr_data, sizeof(pcr_data), pcr_data, sizeof(pcr_data),
        NULL, 0, false, false);
    if (!status) {
        libspdm_my_print("[Fail: bad nonce]\n");
        libspdm_tpm_quote_test_free_key(&key);
        return false;
    }
    libspdm_my_print("[Pass: bad nonce]\n");

    status = libspdm_tpm_quote_test_case(
        &key, TPM2_GENERATED_VALUE, TPM2_ST_ATTEST_QUOTE,
        nonce, nonce, pcr_data, sizeof(pcr_data), bad_pcr_data, sizeof(bad_pcr_data),
        NULL, 0, false, false);
    if (!status) {
        libspdm_my_print("[Fail: bad pcrDigest]\n");
        libspdm_tpm_quote_test_free_key(&key);
        return false;
    }
    libspdm_my_print("[Pass: bad pcrDigest]\n");

    status = libspdm_tpm_quote_test_case(
        &key, 0xFFFFFFFF, TPM2_ST_ATTEST_QUOTE,
        nonce, nonce, pcr_data, sizeof(pcr_data), pcr_data, sizeof(pcr_data),
        NULL, 0, false, false);
    if (!status) {
        libspdm_my_print("[Fail: bad magic]\n");
        libspdm_tpm_quote_test_free_key(&key);
        return false;
    }
    libspdm_my_print("[Pass: bad magic]\n");

    status = libspdm_tpm_quote_test_case(
        &key, TPM2_GENERATED_VALUE, TPM2_ST_ATTEST_CERTIFY,
        nonce, nonce, pcr_data, sizeof(pcr_data), pcr_data, sizeof(pcr_data),
        NULL, 0, false, false);
    if (!status) {
        libspdm_my_print("[Fail: bad type]\n");
        libspdm_tpm_quote_test_free_key(&key);
        return false;
    }
    libspdm_my_print("[Pass: bad type]\n");

    status = libspdm_tpm_quote_test_case(
        &key, TPM2_GENERATED_VALUE, TPM2_ST_ATTEST_QUOTE,
        nonce, nonce, pcr_data, sizeof(pcr_data), pcr_data, sizeof(pcr_data),
        NULL, 0, true, false);
    if (!status) {
        libspdm_my_print("[Fail: wrong signature]\n");
        libspdm_tpm_quote_test_free_key(&key);
        return false;
    }
    libspdm_my_print("[Pass: wrong signature]\n");

    status = libspdm_tpm_quote_test_case(
        &key, TPM2_GENERATED_VALUE, TPM2_ST_ATTEST_QUOTE,
        nonce, nonce, pcr_data, sizeof(pcr_data), pcr_data, sizeof(pcr_data),
        bad_digest, sizeof(bad_digest), false, false);
    if (!status) {
        libspdm_my_print("[Fail: overridden bad pcrDigest]\n");
        libspdm_tpm_quote_test_free_key(&key);
        return false;
    }
    libspdm_my_print("[Pass: overridden bad pcrDigest]\n");

    libspdm_tpm_quote_test_free_key(&key);
    return true;
}

#else /* LIBSPDM_TPM_SUPPORT */

bool libspdm_validate_crypt_tpm_quote(void)
{
    return true;
}

#endif /* LIBSPDM_TPM_SUPPORT */
