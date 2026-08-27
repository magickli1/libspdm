/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * AEAD (SM4-GCM) Wrapper Implementation.
 **/

#include "internal_crypt_lib.h"
#include <openssl/evp.h>

/**
 * Performs AEAD SM4-GCM authenticated encryption on a data buffer and additional authenticated data (AAD).
 *
 * iv_size must be 12, otherwise false is returned.
 * key_size must be 16, otherwise false is returned.
 * tag_size must be 16, otherwise false is returned.
 *
 * @param[in]   key         Pointer to the encryption key.
 * @param[in]   key_size     size of the encryption key in bytes.
 * @param[in]   iv          Pointer to the IV value.
 * @param[in]   iv_size      size of the IV value in bytes.
 * @param[in]   a_data       Pointer to the additional authenticated data (AAD).
 * @param[in]   a_data_size   size of the additional authenticated data (AAD) in bytes.
 * @param[in]   data_in      Pointer to the input data buffer to be encrypted.
 * @param[in]   data_in_size  size of the input data buffer in bytes.
 * @param[out]  tag_out      Pointer to a buffer that receives the authentication tag output.
 * @param[in]   tag_size     size of the authentication tag in bytes.
 * @param[out]  data_out     Pointer to a buffer that receives the encryption output.
 * @param[out]  data_out_size size of the output data buffer in bytes.
 *
 * @retval true   AEAD SM4-GCM authenticated encryption succeeded.
 * @retval false  AEAD SM4-GCM authenticated encryption failed.
 *
 **/
bool libspdm_aead_sm4_gcm_encrypt(const uint8_t *key, size_t key_size,
                                  const uint8_t *iv, size_t iv_size,
                                  const uint8_t *a_data, size_t a_data_size,
                                  const uint8_t *data_in, size_t data_in_size,
                                  uint8_t *tag_out, size_t tag_size,
                                  uint8_t *data_out, size_t *data_out_size)
{
    EVP_CIPHER_CTX *ctx;
    EVP_CIPHER *cipher;
    int out_len;
    int final_len;
    bool result;

    if ((key == NULL) || (key_size != 16) || (iv == NULL) || (iv_size != 12) ||
        (tag_out == NULL) || (tag_size != 16) || (data_out_size == NULL) ||
        (data_in_size > INT_MAX) || (a_data_size > INT_MAX) ||
        (*data_out_size < data_in_size) ||
        ((a_data_size != 0) && (a_data == NULL)) ||
        ((data_in_size != 0) && ((data_in == NULL) || (data_out == NULL)))) {
        return false;
    }

    cipher = EVP_CIPHER_fetch(NULL, "SM4-GCM", NULL);
    if (cipher == NULL) {
        return false;
    }
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        EVP_CIPHER_free(cipher);
        return false;
    }

    result = EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL) == 1 &&
             EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv_size, NULL) == 1 &&
             EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) == 1;
    if (result && a_data_size != 0) {
        result = EVP_EncryptUpdate(ctx, NULL, &out_len, a_data,
                                   (int)a_data_size) == 1;
    }
    out_len = 0;
    if (result && data_in_size != 0) {
        result = EVP_EncryptUpdate(ctx, data_out, &out_len, data_in,
                                   (int)data_in_size) == 1;
    }
    final_len = 0;
    if (result) {
        result = EVP_EncryptFinal_ex(ctx,
                                    data_out == NULL ? NULL : data_out + out_len,
                                    &final_len) == 1 &&
                 EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, (int)tag_size,
                                     tag_out) == 1;
    }

    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    if (!result) {
        return false;
    }
    *data_out_size = (size_t)(out_len + final_len);
    return true;
}

/**
 * Performs AEAD SM4-GCM authenticated decryption on a data buffer and additional authenticated data (AAD).
 *
 * iv_size must be 12, otherwise false is returned.
 * key_size must be 16, otherwise false is returned.
 * tag_size must be 16, otherwise false is returned.
 * If additional authenticated data verification fails, false is returned.
 *
 * @param[in]   key         Pointer to the encryption key.
 * @param[in]   key_size     size of the encryption key in bytes.
 * @param[in]   iv          Pointer to the IV value.
 * @param[in]   iv_size      size of the IV value in bytes.
 * @param[in]   a_data       Pointer to the additional authenticated data (AAD).
 * @param[in]   a_data_size   size of the additional authenticated data (AAD) in bytes.
 * @param[in]   data_in      Pointer to the input data buffer to be decrypted.
 * @param[in]   data_in_size  size of the input data buffer in bytes.
 * @param[in]   tag         Pointer to a buffer that contains the authentication tag.
 * @param[in]   tag_size     size of the authentication tag in bytes.
 * @param[out]  data_out     Pointer to a buffer that receives the decryption output.
 * @param[out]  data_out_size size of the output data buffer in bytes.
 *
 * @retval true   AEAD SM4-GCM authenticated decryption succeeded.
 * @retval false  AEAD SM4-GCM authenticated decryption failed.
 *
 **/
bool libspdm_aead_sm4_gcm_decrypt(const uint8_t *key, size_t key_size,
                                  const uint8_t *iv, size_t iv_size,
                                  const uint8_t *a_data, size_t a_data_size,
                                  const uint8_t *data_in, size_t data_in_size,
                                  const uint8_t *tag, size_t tag_size,
                                  uint8_t *data_out, size_t *data_out_size)
{
    EVP_CIPHER_CTX *ctx;
    EVP_CIPHER *cipher;
    int out_len;
    int final_len;
    bool result;

    if ((key == NULL) || (key_size != 16) || (iv == NULL) || (iv_size != 12) ||
        (tag == NULL) || (tag_size != 16) || (data_out_size == NULL) ||
        (data_in_size > INT_MAX) || (a_data_size > INT_MAX) ||
        (*data_out_size < data_in_size) ||
        ((a_data_size != 0) && (a_data == NULL)) ||
        ((data_in_size != 0) && ((data_in == NULL) || (data_out == NULL)))) {
        return false;
    }

    cipher = EVP_CIPHER_fetch(NULL, "SM4-GCM", NULL);
    if (cipher == NULL) {
        return false;
    }
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        EVP_CIPHER_free(cipher);
        return false;
    }

    result = EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL) == 1 &&
             EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv_size, NULL) == 1 &&
             EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) == 1;
    if (result && a_data_size != 0) {
        result = EVP_DecryptUpdate(ctx, NULL, &out_len, a_data,
                                   (int)a_data_size) == 1;
    }
    out_len = 0;
    if (result && data_in_size != 0) {
        result = EVP_DecryptUpdate(ctx, data_out, &out_len, data_in,
                                   (int)data_in_size) == 1;
    }
    if (result) {
        result = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, (int)tag_size,
                                     (void *)tag) == 1;
    }
    final_len = 0;
    if (result) {
        result = EVP_DecryptFinal_ex(ctx,
                                    data_out == NULL ? NULL : data_out + out_len,
                                    &final_len) == 1;
    }

    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    if (!result) {
        if ((data_out != NULL) && (data_in_size != 0)) {
            libspdm_zero_mem(data_out, data_in_size);
        }
        return false;
    }
    *data_out_size = (size_t)(out_len + final_len);
    return true;
}
