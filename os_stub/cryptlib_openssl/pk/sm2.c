/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * Shang-Mi2 Asymmetric Wrapper Implementation.
 **/

/* Suppress deprecated warnings for SM2 implementation
 * These will be replaced with modern APIs incrementally
 * Warning suppression is handled globally in CMakeLists.txt
 */

#include "internal_crypt_lib.h"
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/objects.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include "key_context.h"

static bool sm2_pkey_is_sm2(const EVP_PKEY *pkey)
{
    int32_t nid;

    if (pkey == NULL) {
        return false;
    }
    nid = EVP_PKEY_id(pkey);
    if (nid == EVP_PKEY_KEYMGMT) {
        nid = OBJ_sn2nid(EVP_PKEY_get0_type_name(pkey));
    }
    return nid == EVP_PKEY_SM2;
}

#if LIBSPDM_SM2_DSA_SUPPORT || LIBSPDM_SM2_KEY_EXCHANGE_SUPPORT
#define SM2_PUBLIC_SIZE 64

static bool sm2_get_public_key(EVP_PKEY *pkey, uint8_t *public_data,
                               size_t *public_size)
{
    uint8_t encoded[1 + SM2_PUBLIC_SIZE];
    size_t encoded_size = 0;

    if (pkey == NULL || public_size == NULL ||
        (public_data == NULL && *public_size != 0)) {
        return false;
    }
    if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY,
                                        encoded, sizeof(encoded),
                                        &encoded_size) <= 0 ||
        encoded_size != sizeof(encoded) || encoded[0] != 0x04) {
        return false;
    }
    if (*public_size < SM2_PUBLIC_SIZE) {
        *public_size = SM2_PUBLIC_SIZE;
        return false;
    }
    *public_size = SM2_PUBLIC_SIZE;
    if (public_data != NULL) {
        libspdm_copy_mem(public_data, SM2_PUBLIC_SIZE,
                         encoded + 1, SM2_PUBLIC_SIZE);
    }
    return true;
}

#endif

#if LIBSPDM_SM2_KEY_EXCHANGE_SUPPORT

typedef struct {
    libspdm_key_context key_ctx;
    uint8_t *id_a;
    size_t id_a_size;
    uint8_t *id_b;
    size_t id_b_size;
    size_t hash_nid;
    bool initialized;
    bool initiator;
} libspdm_sm2_ke_context;

#endif /* LIBSPDM_SM2_KEY_EXCHANGE_SUPPORT */

/**
 * Allocates and Initializes one Shang-Mi2 context for subsequent use.
 *
 * The key is generated before the function returns.
 *
 * @param nid cipher NID
 *
 * @return  Pointer to the Shang-Mi2 context that has been initialized.
 *         If the allocations fails, sm2_new_by_nid() returns NULL.
 *
 **/
void *libspdm_sm2_dsa_new_by_nid(size_t nid)
{
    EVP_PKEY_CTX *pkey_ctx;
    EVP_PKEY_CTX *key_ctx;
    EVP_PKEY *pkey;
    int32_t result;
    EVP_PKEY *params;

    pkey_ctx = EVP_PKEY_CTX_new_from_name(NULL, "SM2", NULL);
    if (pkey_ctx == NULL) {
        return NULL;
    }
    result = EVP_PKEY_paramgen_init(pkey_ctx);
    if (result != 1) {
        EVP_PKEY_CTX_free(pkey_ctx);
        return NULL;
    }
    result = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pkey_ctx, NID_sm2);
    if (result == 0) {
        EVP_PKEY_CTX_free(pkey_ctx);
        return NULL;
    }

    params = NULL;
    result = EVP_PKEY_paramgen(pkey_ctx, &params);
    if (result == 0) {
        EVP_PKEY_CTX_free(pkey_ctx);
        return NULL;
    }
    EVP_PKEY_CTX_free(pkey_ctx);

    key_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, params, NULL);
    if (key_ctx == NULL) {
        EVP_PKEY_free(params);
        return NULL;
    }
    EVP_PKEY_free(params);

    result = EVP_PKEY_keygen_init(key_ctx);
    if (result == 0) {
        EVP_PKEY_CTX_free(key_ctx);
        return NULL;
    }
    pkey = NULL;
    result = EVP_PKEY_keygen(key_ctx, &pkey);
    if (result == 0 || pkey == NULL) {
        EVP_PKEY_CTX_free(key_ctx);
        return NULL;
    }
    EVP_PKEY_CTX_free(key_ctx);

    result = EVP_PKEY_is_a(pkey, "SM2");
    if (result != 1) {
        EVP_PKEY_free(pkey);
        return NULL;
    }

    /* Allocate wrapper structure */
    libspdm_key_context *sm2_ctx = (libspdm_key_context *)malloc(sizeof(libspdm_key_context));
    if (sm2_ctx == NULL) {
        EVP_PKEY_free(pkey);
        return NULL;
    }
    sm2_ctx->evp_pkey = pkey;
    return (void *)sm2_ctx;
}

/**
 * Release the specified sm2 context.
 *
 * @param[in]  sm2_context  Pointer to the sm2 context to be released.
 *
 **/
void libspdm_sm2_dsa_free(void *sm2_context)
{
    libspdm_key_context *sm2_ctx;

    if (sm2_context == NULL) {
        return;
    }

    sm2_ctx = (libspdm_key_context *)sm2_context;
    if (sm2_ctx->evp_pkey != NULL) {
        EVP_PKEY_free(sm2_ctx->evp_pkey);
    }
    free(sm2_ctx);
}

/**
 * Sets the public key component into the established sm2 context.
 *
 * The public_size is 64. first 32-byte is X, second 32-byte is Y.
 *
 * @param[in, out]  ec_context      Pointer to sm2 context being set.
 * @param[in]       public         Pointer to the buffer to receive generated public X,Y.
 * @param[in]       public_size     The size of public buffer in bytes.
 *
 * @retval  true   sm2 public key component was set successfully.
 * @retval  false  Invalid sm2 public key component.
 *
 **/
bool libspdm_sm2_dsa_set_pub_key(void *sm2_context, const uint8_t *public_key,
                                 size_t public_key_size)
{
    EVP_PKEY *pkey;
    EVP_PKEY_CTX *pctx = NULL;
    uint8_t oct_key[65];
    size_t half_size = 32;
    bool ret_val = false;

    if (sm2_context == NULL || public_key == NULL) {
        return false;
    }

    pkey = ((libspdm_key_context *)sm2_context)->evp_pkey;
    if (!sm2_pkey_is_sm2(pkey)) {
        return false;
    }

    if (public_key_size != half_size * 2) {
        return false;
    }

    /* Build uncompressed octet: 0x04 || X || Y */
    if (public_key_size + 1 > sizeof(oct_key)) {
        return false;
    }
    oct_key[0] = 0x04;
    libspdm_copy_mem(oct_key + 1, sizeof(oct_key) - 1, public_key, public_key_size);

    if (EVP_PKEY_set1_encoded_public_key(pkey, oct_key, public_key_size + 1) > 0) {
        pctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
        if (pctx != NULL) {
            if (EVP_PKEY_public_check_quick(pctx) > 0) {
                ret_val = true;
            }
            EVP_PKEY_CTX_free(pctx);
            if (ret_val) {
                return true;
            }
        }
    }

    /* Try alternative: EVP_PKEY_set_octet_string_param */
    if (EVP_PKEY_settable_params(pkey) != NULL) {
        if (EVP_PKEY_set_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY,
                                            oct_key, public_key_size + 1) > 0) {
            pctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
            if (pctx != NULL) {
                if (EVP_PKEY_public_check_quick(pctx) > 0) {
                    ret_val = true;
                }
                EVP_PKEY_CTX_free(pctx);
            }
        }
    }

    return ret_val;
}

/**
 * Gets the public key component from the established sm2 context.
 *
 * The public_size is 64. first 32-byte is X, second 32-byte is Y.
 *
 * @param[in, out]  sm2_context     Pointer to sm2 context being set.
 * @param[out]      public         Pointer to the buffer to receive generated public X,Y.
 * @param[in, out]  public_size     On input, the size of public buffer in bytes.
 *                                On output, the size of data returned in public buffer in bytes.
 *
 * @retval  true   sm2 key component was retrieved successfully.
 * @retval  false  Invalid sm2 key component.
 *
 **/
bool libspdm_sm2_dsa_get_pub_key(void *sm2_context, uint8_t *public_key,
                                 size_t *public_key_size)
{
    EVP_PKEY *pkey;

    if (sm2_context == NULL || public_key_size == NULL) {
        return false;
    }

    if (public_key == NULL && *public_key_size != 0) {
        return false;
    }

    pkey = ((libspdm_key_context *)sm2_context)->evp_pkey;
    if (!sm2_pkey_is_sm2(pkey)) {
        return false;
    }

    return sm2_get_public_key(pkey, public_key, public_key_size);
}

/**
 * Validates key components of sm2 context.
 * NOTE: This function performs integrity checks on all the sm2 key material, so
 *      the sm2 key structure must contain all the private key data.
 *
 * If sm2_context is NULL, then return false.
 *
 * @param[in]  sm2_context  Pointer to sm2 context to check.
 *
 * @retval  true   sm2 key components are valid.
 * @retval  false  sm2 key components are not valid.
 *
 **/
bool libspdm_sm2_dsa_check_key(const void *sm2_context)
{
    EVP_PKEY *pkey;
    EVP_PKEY_CTX *pctx = NULL;
    int check_result;

    if (sm2_context == NULL) {
        return false;
    }

    pkey = ((libspdm_key_context *)sm2_context)->evp_pkey;
    if (!sm2_pkey_is_sm2(pkey)) {
        return false;
    }

    pctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    if (pctx == NULL) {
        return false;
    }

    check_result = EVP_PKEY_pairwise_check(pctx);
    if (check_result > 0) {
        EVP_PKEY_CTX_free(pctx);
        return true;
    }
    check_result = EVP_PKEY_public_check(pctx);
    EVP_PKEY_CTX_free(pctx);

    return (check_result > 0);
}

/**
 * Generates sm2 key and returns sm2 public key (X, Y), based upon GB/T 32918.3-2016: SM2 - Part3.
 *
 * This function generates random secret, and computes the public key (X, Y), which is
 * returned via parameter public, public_size.
 * X is the first half of public with size being public_size / 2,
 * Y is the second half of public with size being public_size / 2.
 * sm2 context is updated accordingly.
 * If the public buffer is too small to hold the public X, Y, false is returned and
 * public_size is set to the required buffer size to obtain the public X, Y.
 *
 * The public_size is 64. first 32-byte is X, second 32-byte is Y.
 *
 * If sm2_context is NULL, then return false.
 * If public_size is NULL, then return false.
 * If public_size is large enough but public is NULL, then return false.
 *
 * @param[in, out]  sm2_context     Pointer to the sm2 context.
 * @param[out]      public_data     Pointer to the buffer to receive generated public X,Y.
 * @param[in, out]  public_size     On input, the size of public buffer in bytes.
 *                                On output, the size of data returned in public buffer in bytes.
 *
 * @retval true   sm2 public X,Y generation succeeded.
 * @retval false  sm2 public X,Y generation failed.
 * @retval false  public_size is not large enough.
 *
 **/
bool libspdm_sm2_dsa_generate_key(void *sm2_context, uint8_t *public_data,
                                  size_t *public_size)
{
    libspdm_key_context *sm2_ctx;
    EVP_PKEY *pkey;
    EVP_PKEY_CTX *key_ctx = NULL;
    EVP_PKEY *new_pkey = NULL;
    bool ret_val = false;
    size_t half_size = 32;
    uint8_t pub_key_buffer[65];
    size_t pub_key_len = 0;

    if (sm2_context == NULL || public_size == NULL) {
        return false;
    }

    if (public_data == NULL && *public_size != 0) {
        return false;
    }

    sm2_ctx = (libspdm_key_context *)sm2_context;
    pkey = ((libspdm_key_context *)sm2_context)->evp_pkey;
    if (!sm2_pkey_is_sm2(pkey)) {
        return false;
    }

    /* Create key generation context from existing pkey */
    key_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    if (key_ctx == NULL) {
        return false;
    }

    if (EVP_PKEY_keygen_init(key_ctx) <= 0) {
        goto cleanup;
    }

    if (EVP_PKEY_generate(key_ctx, &new_pkey) <= 0) {
        goto cleanup;
    }

    /* Replace the old pkey with the new generated one */
    EVP_PKEY_free(sm2_ctx->evp_pkey);
    sm2_ctx->evp_pkey = new_pkey;
    new_pkey = NULL;
    pkey = sm2_ctx->evp_pkey;

    /* Extract public key for output */
    if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY,
                                        pub_key_buffer, sizeof(pub_key_buffer),
                                        &pub_key_len) <= 0) {
        goto cleanup;
    }

    /* EVP_PKEY includes an extra leading byte for the point compression format.
     * Since only the uncompressed format is supported, this byte (always 0x04)
     * can be safely ignored to maintain API compatibility. */
    if (pub_key_len < 1 || pub_key_len - 1 != half_size * 2) {
        goto cleanup;
    }

    if (*public_size < pub_key_len - 1) {
        *public_size = pub_key_len - 1;
        ret_val = false;
        goto cleanup;
    }

    *public_size = pub_key_len - 1;
    if (public_data != NULL) {
        /* pub_key_buffer[0] = 0x04 indicates the uncompressed format (EVP_PKEY uses this as a format ID).
         * Only the raw key bytes (excluding this prefix) should be copied into public_data. */
        libspdm_copy_mem(public_data, *public_size, pub_key_buffer + 1, *public_size);
    }
    ret_val = true;

cleanup:
    if (key_ctx != NULL) {
        EVP_PKEY_CTX_free(key_ctx);
    }
    if (new_pkey != NULL) {
        EVP_PKEY_free(new_pkey);
    }
    return ret_val;
}

/**
 * Allocates and Initializes one Shang-Mi2 context for subsequent use.
 *
 * The key is generated before the function returns.
 *
 * @param nid cipher NID
 *
 * @return  Pointer to the Shang-Mi2 context that has been initialized.
 *         If the allocations fails, sm2_new_by_nid() returns NULL.
 *
 **/
void *libspdm_sm2_key_exchange_new_by_nid(size_t nid)
{
#if LIBSPDM_SM2_KEY_EXCHANGE_SUPPORT
    libspdm_sm2_ke_context *ctx;
    libspdm_key_context *key_ctx;

    if (nid != LIBSPDM_CRYPTO_NID_SM2_KEY_EXCHANGE_P256) {
        return NULL;
    }
    ctx = calloc(1, sizeof(*ctx));
    if (ctx == NULL) {
        return NULL;
    }
    key_ctx = libspdm_sm2_dsa_new_by_nid(LIBSPDM_CRYPTO_NID_SM2_DSA_P256);
    if (key_ctx == NULL) {
        free(ctx);
        return NULL;
    }
    ctx->key_ctx.evp_pkey = key_ctx->evp_pkey;
    key_ctx->evp_pkey = NULL;
    libspdm_sm2_dsa_free(key_ctx);
    return ctx;
#else
    return NULL;
#endif
}

/**
 * Release the specified sm2 context.
 *
 * @param[in]  sm2_context  Pointer to the sm2 context to be released.
 *
 **/
void libspdm_sm2_key_exchange_free(void *sm2_context)
{
#if LIBSPDM_SM2_KEY_EXCHANGE_SUPPORT
    libspdm_sm2_ke_context *ctx = sm2_context;

    if (ctx == NULL) {
        return;
    }
    EVP_PKEY_free(ctx->key_ctx.evp_pkey);
    free(ctx->id_a);
    free(ctx->id_b);
    free(ctx);
#else
    (void)sm2_context;
#endif
}

/**
 * Initialize the specified sm2 context.
 *
 * @param[in]  sm2_context  Pointer to the sm2 context to be released.
 * @param[in]  hash_nid            hash NID, only SM3 is valid.
 * @param[in]  id_a                the ID-A of the key exchange context.
 * @param[in]  id_a_size           size of ID-A key exchange context.
 * @param[in]  id_b                the ID-B of the key exchange context.
 * @param[in]  id_b_size           size of ID-B key exchange context.
 * @param[in]  is_initiator        if the caller is initiator.
 *                                true: initiator
 *                                false: not an initiator
 *
 * @retval true   sm2 context is initialized.
 * @retval false  sm2 context is not initialized.
 **/
bool libspdm_sm2_key_exchange_init(const void *sm2_context, size_t hash_nid,
                                   const uint8_t *id_a, size_t id_a_size,
                                   const uint8_t *id_b, size_t id_b_size,
                                   bool is_initiator)
{
#if LIBSPDM_SM2_KEY_EXCHANGE_SUPPORT
    libspdm_sm2_ke_context *ctx = (libspdm_sm2_ke_context *)sm2_context;
    uint8_t *new_a = NULL;
    uint8_t *new_b = NULL;

    if (ctx == NULL || hash_nid != LIBSPDM_CRYPTO_NID_SM3_256 ||
        id_a == NULL || id_b == NULL || id_a_size == 0 || id_b_size == 0 ||
        id_a_size > 8191 || id_b_size > 8191) {
        return false;
    }
    new_a = malloc(id_a_size);
    if (new_a == NULL) {
        return false;
    }
    libspdm_copy_mem(new_a, id_a_size, id_a, id_a_size);
    new_b = malloc(id_b_size);
    if (new_b == NULL) {
        free(new_a);
        return false;
    }
    libspdm_copy_mem(new_b, id_b_size, id_b, id_b_size);
    free(ctx->id_a);
    free(ctx->id_b);
    ctx->id_a = new_a;
    ctx->id_a_size = id_a_size;
    ctx->id_b = new_b;
    ctx->id_b_size = id_b_size;
    ctx->hash_nid = hash_nid;
    ctx->initiator = is_initiator;
    ctx->initialized = true;
    return true;
#else
    (void)sm2_context; (void)hash_nid; (void)id_a; (void)id_a_size;
    (void)id_b; (void)id_b_size; (void)is_initiator;
    return false;
#endif
}

/**
 * Generates sm2 key and returns sm2 public key (X, Y), based upon GB/T 32918.3-2016: SM2 - Part3.
 *
 * This function generates random secret, and computes the public key (X, Y), which is
 * returned via parameter public, public_size.
 * X is the first half of public with size being public_size / 2,
 * Y is the second half of public with size being public_size / 2.
 * sm2 context is updated accordingly.
 * If the public buffer is too small to hold the public X, Y, false is returned and
 * public_size is set to the required buffer size to obtain the public X, Y.
 *
 * The public_size is 64. first 32-byte is X, second 32-byte is Y.
 *
 * If sm2_context is NULL, then return false.
 * If public_size is NULL, then return false.
 * If public_size is large enough but public is NULL, then return false.
 *
 * @param[in, out]  sm2_context     Pointer to the sm2 context.
 * @param[out]      public_data     Pointer to the buffer to receive generated public X,Y.
 * @param[in, out]  public_size     On input, the size of public buffer in bytes.
 *                                On output, the size of data returned in public buffer in bytes.
 *
 * @retval true   sm2 public X,Y generation succeeded.
 * @retval false  sm2 public X,Y generation failed.
 * @retval false  public_size is not large enough.
 *
 **/
bool libspdm_sm2_key_exchange_generate_key(void *sm2_context, uint8_t *public_data,
                                           size_t *public_size)
{
#if LIBSPDM_SM2_KEY_EXCHANGE_SUPPORT
    libspdm_sm2_ke_context *ctx = sm2_context;
    libspdm_key_context *new_key_ctx;
    EVP_PKEY *new_pkey;
    bool result;

    if (ctx == NULL || ctx->key_ctx.evp_pkey == NULL || public_size == NULL ||
        (public_data == NULL && *public_size != 0)) {
        return false;
    }
    new_key_ctx = libspdm_sm2_dsa_new_by_nid(LIBSPDM_CRYPTO_NID_SM2_DSA_P256);
    if (new_key_ctx == NULL) {
        return false;
    }
    new_pkey = new_key_ctx->evp_pkey;
    new_key_ctx->evp_pkey = NULL;
    libspdm_sm2_dsa_free(new_key_ctx);
    result = sm2_get_public_key(new_pkey, public_data, public_size);
    if (result) {
        EVP_PKEY_free(ctx->key_ctx.evp_pkey);
        ctx->key_ctx.evp_pkey = new_pkey;
        new_pkey = NULL;
    }
    EVP_PKEY_free(new_pkey);
    return result;
#else
    (void)sm2_context; (void)public_data; (void)public_size;
    return false;
#endif
}

/**
 * Computes exchanged common key, based upon GB/T 32918.3-2016: SM2 - Part3.
 *
 * Given peer's public key (X, Y), this function computes the exchanged common key,
 * based on its own context including value of curve parameter and random secret.
 * X is the first half of peer_public with size being peer_public_size / 2,
 * Y is the second half of peer_public with size being peer_public_size / 2.
 *
 * If sm2_context is NULL, then return false.
 * If peer_public is NULL, then return false.
 * If peer_public_size is 0, then return false.
 * If key is NULL, then return false.
 *
 * The id_a_size and id_b_size must be smaller than 2^16-1.
 * The peer_public_size is 64. first 32-byte is X, second 32-byte is Y.
 * The key_size must be smaller than 2^32-1, limited by KDF function.
 *
 * @param[in, out]  sm2_context         Pointer to the sm2 context.
 * @param[in]       peer_public         Pointer to the peer's public X,Y.
 * @param[in]       peer_public_size     size of peer's public X,Y in bytes.
 * @param[out]      key                Pointer to the buffer to receive generated key.
 * @param[in]       key_size            On input, the size of key buffer in bytes.
 *
 * @retval true   sm2 exchanged key generation succeeded.
 * @retval false  sm2 exchanged key generation failed.
 *
 **/
bool libspdm_sm2_key_exchange_compute_key(void *sm2_context,
                                          const uint8_t *peer_public,
                                          size_t peer_public_size, uint8_t *key,
                                          size_t *key_size)
{
#if LIBSPDM_SM2_KEY_EXCHANGE_SUPPORT
    libspdm_sm2_ke_context *ctx = sm2_context;
    EVP_PKEY *peer = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    OSSL_PARAM params[8];
    const uint8_t *self_id, *peer_id;
    size_t self_id_size, peer_id_size, outlen;
    int initiator;

    if (ctx == NULL || !ctx->initialized || ctx->key_ctx.evp_pkey == NULL ||
        peer_public == NULL || peer_public_size != SM2_PUBLIC_SIZE ||
        key == NULL || key_size == NULL || *key_size == 0) {
        return false;
    }
    peer = EVP_PKEY_new();
    if (peer == NULL || EVP_PKEY_copy_parameters(peer, ctx->key_ctx.evp_pkey) <= 0) {
        EVP_PKEY_free(peer);
        return false;
    }
    {
        uint8_t encoded[65];
        encoded[0] = 0x04;
        libspdm_copy_mem(encoded + 1, sizeof(encoded) - 1,
                         peer_public, SM2_PUBLIC_SIZE);
        if (EVP_PKEY_set1_encoded_public_key(peer, encoded, sizeof(encoded)) <= 0 &&
            EVP_PKEY_set_octet_string_param(peer, OSSL_PKEY_PARAM_PUB_KEY,
                                            encoded, sizeof(encoded)) <= 0) {
            EVP_PKEY_free(peer);
            return false;
        }
    }
    self_id = ctx->initiator ? ctx->id_a : ctx->id_b;
    self_id_size = ctx->initiator ? ctx->id_a_size : ctx->id_b_size;
    peer_id = ctx->initiator ? ctx->id_b : ctx->id_a;
    peer_id_size = ctx->initiator ? ctx->id_b_size : ctx->id_a_size;
    pctx = EVP_PKEY_CTX_new_from_pkey(NULL, ctx->key_ctx.evp_pkey, NULL);
    if (pctx == NULL) {
        EVP_PKEY_free(peer);
        return false;
    }
    initiator = ctx->initiator ? 1 : 0;
    outlen = *key_size;
    /* SPDM KEY_EXCHANGE carries one XY; use it as both static and ephemeral (R=P). */
    params[0] = OSSL_PARAM_construct_int(OSSL_EXCHANGE_PARAM_INITIATOR, &initiator);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_EXCHANGE_PARAM_SELF_ID,
                                                   (void *)self_id, self_id_size);
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_EXCHANGE_PARAM_PEER_ID,
                                                   (void *)peer_id, peer_id_size);
    params[3] = OSSL_PARAM_construct_octet_ptr(OSSL_EXCHANGE_PARAM_SELF_ENC_KEY,
                                                (void **)&ctx->key_ctx.evp_pkey,
                                                sizeof(ctx->key_ctx.evp_pkey));
    params[4] = OSSL_PARAM_construct_octet_ptr(OSSL_EXCHANGE_PARAM_PEER_ENC_KEY,
                                                (void **)&peer, sizeof(peer));
    params[5] = OSSL_PARAM_construct_utf8_string(OSSL_EXCHANGE_PARAM_DIGEST,
                                                  (char *)"SM3", 0);
    params[6] = OSSL_PARAM_construct_size_t(OSSL_EXCHANGE_PARAM_OUTLEN, &outlen);
    params[7] = OSSL_PARAM_construct_end();
    {
        bool result = EVP_PKEY_derive_init_ex(pctx, params) > 0 &&
                      EVP_PKEY_derive_set_peer(pctx, peer) > 0 &&
                      EVP_PKEY_derive(pctx, key, &outlen) > 0;
        if (result) {
            *key_size = outlen;
        }
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(peer);
        return result;
    }
#else
    (void)sm2_context; (void)peer_public; (void)peer_public_size;
    (void)key; (void)key_size;
    return false;
#endif
}

static void ecc_signature_der_to_bin(uint8_t *der_signature,
                                     size_t der_sig_size,
                                     uint8_t *signature, size_t sig_size)
{
    uint8_t der_r_size;
    uint8_t der_s_size;
    uint8_t *bn_r;
    uint8_t *bn_s;
    uint8_t r_size;
    uint8_t s_size;
    uint8_t half_size;

    half_size = (uint8_t)(sig_size / 2);

    LIBSPDM_ASSERT(der_signature[0] == 0x30);
    LIBSPDM_ASSERT((size_t)(der_signature[1] + 2) == der_sig_size);
    LIBSPDM_ASSERT(der_signature[2] == 0x02);
    der_r_size = der_signature[3];
    LIBSPDM_ASSERT(der_signature[4 + der_r_size] == 0x02);
    der_s_size = der_signature[5 + der_r_size];
    LIBSPDM_ASSERT(der_sig_size == (size_t)(der_r_size + der_s_size + 6));

    if (der_signature[4] != 0) {
        r_size = der_r_size;
        bn_r = &der_signature[4];
    } else {
        r_size = der_r_size - 1;
        bn_r = &der_signature[5];
    }
    if (der_signature[6 + der_r_size] != 0) {
        s_size = der_s_size;
        bn_s = &der_signature[6 + der_r_size];
    } else {
        s_size = der_s_size - 1;
        bn_s = &der_signature[7 + der_r_size];
    }
    LIBSPDM_ASSERT(r_size <= half_size && s_size <= half_size);
    libspdm_zero_mem(signature, sig_size);
    libspdm_copy_mem(&signature[0 + half_size - r_size],
                     sig_size - (0 + half_size - r_size),
                     bn_r, r_size);
    libspdm_copy_mem(&signature[half_size + half_size - s_size],
                     sig_size - (half_size + half_size - s_size),
                     bn_s, s_size);
}

static void ecc_signature_bin_to_der(uint8_t *signature, size_t sig_size,
                                     uint8_t *der_signature,
                                     size_t *der_sig_size_in_out)
{
    size_t der_sig_size;
    uint8_t der_r_size;
    uint8_t der_s_size;
    uint8_t *bn_r;
    uint8_t *bn_s;
    uint8_t r_size;
    uint8_t s_size;
    uint8_t half_size;
    uint8_t index;

    half_size = (uint8_t)(sig_size / 2);

    for (index = 0; index < half_size; index++) {
        if (signature[index] != 0) {
            break;
        }
    }
    r_size = (uint8_t)(half_size - index);
    bn_r = &signature[index];
    for (index = 0; index < half_size; index++) {
        if (signature[half_size + index] != 0) {
            break;
        }
    }
    s_size = (uint8_t)(half_size - index);
    bn_s = &signature[half_size + index];
    if (r_size == 0 || s_size == 0) {
        *der_sig_size_in_out = 0;
        return;
    }
    if (bn_r[0] < 0x80) {
        der_r_size = r_size;
    } else {
        der_r_size = r_size + 1;
    }
    if (bn_s[0] < 0x80) {
        der_s_size = s_size;
    } else {
        der_s_size = s_size + 1;
    }
    der_sig_size = der_r_size + der_s_size + 6;
    LIBSPDM_ASSERT(der_sig_size <= *der_sig_size_in_out);
    *der_sig_size_in_out = der_sig_size;
    libspdm_zero_mem(der_signature, der_sig_size);
    der_signature[0] = 0x30;
    der_signature[1] = (uint8_t)(der_sig_size - 2);
    der_signature[2] = 0x02;
    der_signature[3] = der_r_size;
    if (bn_r[0] < 0x80) {
        libspdm_copy_mem(&der_signature[4],
                         der_sig_size - (&der_signature[4] - der_signature),
                         bn_r, r_size);
    } else {
        libspdm_copy_mem(&der_signature[5],
                         der_sig_size - (&der_signature[5] - der_signature),
                         bn_r, r_size);
    }
    der_signature[4 + der_r_size] = 0x02;
    der_signature[5 + der_r_size] = der_s_size;
    if (bn_s[0] < 0x80) {
        libspdm_copy_mem(&der_signature[6 + der_r_size],
                         der_sig_size - (&der_signature[6 + der_r_size] - der_signature),
                         bn_s, s_size);
    } else {
        libspdm_copy_mem(&der_signature[7 + der_r_size],
                         der_sig_size - (&der_signature[7 + der_r_size] - der_signature),
                         bn_s, s_size);
    }
}

/**
 * Carries out the SM2 signature, based upon GB/T 32918.2-2016: SM2 - Part2.
 *
 * This function carries out the SM2 signature.
 * If the signature buffer is too small to hold the contents of signature, false
 * is returned and sig_size is set to the required buffer size to obtain the signature.
 *
 * If sm2_context is NULL, then return false.
 * If message is NULL, then return false.
 * hash_nid must be SM3_256.
 * If sig_size is large enough but signature is NULL, then return false.
 *
 * The id_a_size must be smaller than 2^16-1.
 * The sig_size is 64. first 32-byte is R, second 32-byte is S.
 *
 * @param[in]       sm2_context   Pointer to sm2 context for signature generation.
 * @param[in]       hash_nid      hash NID
 * @param[in]       id_a          the ID-A of the signing context.
 * @param[in]       id_a_size     size of ID-A signing context.
 * @param[in]       message      Pointer to octet message to be signed (before hash).
 * @param[in]       size         size of the message in bytes.
 * @param[out]      signature    Pointer to buffer to receive SM2 signature.
 * @param[in, out]  sig_size      On input, the size of signature buffer in bytes.
 *                              On output, the size of data returned in signature buffer in bytes.
 *
 * @retval  true   signature successfully generated in SM2.
 * @retval  false  signature generation failed.
 * @retval  false  sig_size is too small.
 *
 **/
bool libspdm_sm2_dsa_sign(const void *sm2_context, size_t hash_nid,
                          const uint8_t *id_a, size_t id_a_size,
                          const uint8_t *message, size_t size,
                          uint8_t *signature, size_t *sig_size)
{
    EVP_PKEY_CTX *pkey_ctx;
    EVP_PKEY *pkey;
    EVP_MD_CTX *ctx;
    size_t half_size;
    int32_t result;
    uint8_t der_signature[32 * 2 + 8];
    size_t der_sig_size;

    if (sm2_context == NULL || message == NULL) {
        return false;
    }

    if (signature == NULL || sig_size == NULL) {
        return false;
    }

    pkey = ((libspdm_key_context *)sm2_context)->evp_pkey;
    if (!sm2_pkey_is_sm2(pkey)) {
        return false;
    }
    half_size = 32;

    if (*sig_size < (size_t)(half_size * 2)) {
        *sig_size = half_size * 2;
        return false;
    }
    *sig_size = half_size * 2;
    libspdm_zero_mem(signature, *sig_size);

    switch (hash_nid) {
    case LIBSPDM_CRYPTO_NID_SM3_256:
        break;

    default:
        return false;
    }

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        return false;
    }
    pkey_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    if (pkey_ctx == NULL) {
        EVP_MD_CTX_free(ctx);
        return false;
    }

    if (id_a_size != 0) {
        result = EVP_PKEY_CTX_set1_id(pkey_ctx, id_a,
                                      id_a_size);
        if (result <= 0) {
            EVP_MD_CTX_free(ctx);
            EVP_PKEY_CTX_free(pkey_ctx);
            return false;
        }
    }

    EVP_MD_CTX_set_pkey_ctx(ctx, pkey_ctx);

    {
        OSSL_PARAM params[2];
        params[0] = OSSL_PARAM_construct_utf8_string("digest", (char *)"SM3", 0);
        params[1] = OSSL_PARAM_construct_end();
        result = EVP_DigestSignInit_ex(ctx, NULL, "SM3", NULL, NULL, pkey, params);
    }
    if (result != 1) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_CTX_free(pkey_ctx);
        return false;
    }
    der_sig_size = sizeof(der_signature);
    result = EVP_DigestSign(ctx, der_signature, &der_sig_size, message,
                            size);
    if (result != 1) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_CTX_free(pkey_ctx);
        return false;
    }
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_CTX_free(pkey_ctx);

    ecc_signature_der_to_bin(der_signature, der_sig_size, signature,
                             *sig_size);

    return true;
}

/**
 * Verifies the SM2 signature, based upon GB/T 32918.2-2016: SM2 - Part2.
 *
 * If sm2_context is NULL, then return false.
 * If message is NULL, then return false.
 * If signature is NULL, then return false.
 * hash_nid must be SM3_256.
 *
 * The id_a_size must be smaller than 2^16-1.
 * The sig_size is 64. first 32-byte is R, second 32-byte is S.
 *
 * @param[in]  sm2_context   Pointer to SM2 context for signature verification.
 * @param[in]  hash_nid      hash NID
 * @param[in]  id_a          the ID-A of the signing context.
 * @param[in]  id_a_size     size of ID-A signing context.
 * @param[in]  message      Pointer to octet message to be checked (before hash).
 * @param[in]  size         size of the message in bytes.
 * @param[in]  signature    Pointer to SM2 signature to be verified.
 * @param[in]  sig_size      size of signature in bytes.
 *
 * @retval  true   Valid signature encoded in SM2.
 * @retval  false  Invalid signature or invalid sm2 context.
 *
 **/
bool libspdm_sm2_dsa_verify(const void *sm2_context, size_t hash_nid,
                            const uint8_t *id_a, size_t id_a_size,
                            const uint8_t *message, size_t size,
                            const uint8_t *signature, size_t sig_size)
{
    EVP_PKEY_CTX *pkey_ctx;
    EVP_PKEY *pkey;
    EVP_MD_CTX *ctx;
    size_t half_size;
    int32_t result;
    uint8_t der_signature[32 * 2 + 8];
    size_t der_sig_size;

    if (sm2_context == NULL || message == NULL || signature == NULL) {
        return false;
    }

    if (sig_size > INT_MAX || sig_size == 0) {
        return false;
    }

    pkey = ((libspdm_key_context *)sm2_context)->evp_pkey;
    if (!sm2_pkey_is_sm2(pkey)) {
        return false;
    }
    half_size = 32;

    if (sig_size != (size_t)(half_size * 2)) {
        return false;
    }

    switch (hash_nid) {
    case LIBSPDM_CRYPTO_NID_SM3_256:
        break;

    default:
        return false;
    }

    der_sig_size = sizeof(der_signature);
    ecc_signature_bin_to_der((uint8_t *)signature, sig_size, der_signature,
                             &der_sig_size);

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        return false;
    }
    pkey_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    if (pkey_ctx == NULL) {
        EVP_MD_CTX_free(ctx);
        return false;
    }

    if (id_a_size != 0) {
        result = EVP_PKEY_CTX_set1_id(pkey_ctx, id_a,
                                      id_a_size);
        if (result <= 0) {
            EVP_MD_CTX_free(ctx);
            EVP_PKEY_CTX_free(pkey_ctx);
            return false;
        }
    }
    EVP_MD_CTX_set_pkey_ctx(ctx, pkey_ctx);

    {
        OSSL_PARAM params[2];
        params[0] = OSSL_PARAM_construct_utf8_string("digest", (char *)"SM3", 0);
        params[1] = OSSL_PARAM_construct_end();
        result = EVP_DigestVerifyInit_ex(ctx, NULL, "SM3", NULL, NULL, pkey, params);
    }
    if (result != 1) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_CTX_free(pkey_ctx);
        return false;
    }
    result = EVP_DigestVerify(ctx, der_signature, (uint32_t)der_sig_size,
                              message, size);
    if (result != 1) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_CTX_free(pkey_ctx);
        return false;
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_CTX_free(pkey_ctx);
    return true;
}
