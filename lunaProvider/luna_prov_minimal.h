/****************************************************************************\
*
* This file is part of the "Luna OpenSSL for PQC" project.
*
* The " Luna OpenSSL for PQC " project is provided under the MIT license (see the
* following Web site for further details: https://mit-license.org/ ).
*
* Copyright © 2024 Thales Group
*
\****************************************************************************/

#ifndef _LUNA_PROV_MINIMAL_H
#define _LUNA_PROV_MINIMAL_H

/* magic values */
#define LUNA_PROV_MAGIC_ZERO 0
#define LUNA_PROV_MAGIC_ERROR (-1)
#define LUNA_PROV_MAGIC_OK 0x60cafe06

/* debugging */
#ifdef NDEBUG
#define LUNA_PRINTF(a_)
#else
#define LUNA_PRINTF(a_) if (getenv("LUNAPROV")) { printf("LUNA: %s: ", __func__); printf a_; }
#endif

/* luna provider key reason (i.e., was it generated new, or, read from a file old) */
typedef enum luna_prov_key_reason_en {
    LUNA_PROV_KEY_REASON_ZERO = 0,
    LUNA_PROV_KEY_REASON_GEN = 1,
    LUNA_PROV_KEY_REASON_SET_PARAMS = 2,
    LUNA_PROV_KEY_REASON_FROM_DATA = 3,
    LUNA_PROV_KEY_REASON_FROM_ENCODING = 4
} luna_prov_key_reason;

/* forward reference to luna key context */
typedef struct luna_prov_key_ctx_st luna_prov_key_ctx;

/* forward reference to luna key info */
typedef struct luna_prov_keyinfo_st luna_prov_keyinfo;

/* luna provider flags (i.e., override CKA_TOKEN, etc) */
enum luna_prov_flags_en {
    LUNA_PROV_FLAGS_ZERO = 0x0,
    LUNA_PROV_FLAGS_SESSION_OBJECT = 0x10000,
    LUNA_PROV_FLAGS_SOFTWARE_OBJECT = 0x20000
};

#define LUNA_PROV_PKEY_PARAM_FLAGS "luna-prov-pkey-param-flags"

/* luna provider key bits */
typedef struct luna_prov_key_bits_st {
    int ok;
    int ndx;
    int is_kem;
    int is_hybrid;
    int is_composite;
} luna_prov_key_bits;

/*
 * callback functions from OQS to LUNA
 *
 * return 0 on success, -1 for general error, other specific error
 */

#define LUNA_OQS_ERROR -1
#define LUNA_OQS_OK 0

/* callbacks for malloc and free */
luna_prov_key_ctx *LUNA_OQS_malloc_from_oqs(void *oqsxkey, const char *alg_name);
luna_prov_key_ctx *LUNA_OQS_malloc_from_ecxgen(void *oqsxkey, const char *alg_name);
luna_prov_key_ctx *LUNA_OQS_malloc_from_eddsa(void *oqsxkey, const char *alg_name);
luna_prov_key_ctx *LUNA_OQS_malloc_from_eddsa_2(void *oqsxkey, const luna_prov_key_ctx *src_ctx);
luna_prov_key_ctx *LUNA_OQS_malloc_from_ecx(void *oqsxkey, const char *alg_name);
luna_prov_key_ctx *LUNA_OQS_malloc_from_ecx_2(void *oqsxkey, const luna_prov_key_ctx *src_ctx);
void LUNA_OQS_free(luna_prov_key_ctx *keyctx);
void LUNA_OQS_refresh_alg_name(luna_prov_key_ctx *keyctx, const char *alg_name);

/* callbacks to query luna capability */
int LUNA_OQS_QUERY_KEM_keypair(luna_prov_key_ctx *keyctx);
int LUNA_OQS_QUERY_KEM_encaps(luna_prov_key_ctx *keyctx);
int LUNA_OQS_QUERY_KEM_decaps(luna_prov_key_ctx *keyctx);
int LUNA_OQS_QUERY_SIG_keypair(luna_prov_key_ctx *keyctx);
int LUNA_OQS_QUERY_SIG_sign(luna_prov_key_ctx *keyctx);
int LUNA_OQS_QUERY_SIG_verify(luna_prov_key_ctx *keyctx);

/* callbacks for key encapsulation */
int LUNA_OQS_KEM_keypair(luna_prov_key_ctx *keyctx,
    luna_prov_key_bits *keybits);
int LUNA_OQS_KEM_encaps(luna_prov_key_ctx *keyctx,
    unsigned char *out, size_t *outlen,
    unsigned char *secret, size_t *secretlen);
int LUNA_OQS_KEM_decaps(luna_prov_key_ctx *keyctx,
    unsigned char *out, size_t *outlen,
    const unsigned char *in, size_t inlen);

/* callbacks for sign and verify */
int LUNA_OQS_SIG_keypair(luna_prov_key_ctx *keyctx,
    luna_prov_key_bits *keybits);
int LUNA_OQS_SIG_sign_ndx(luna_prov_key_ctx *keyctx,
    unsigned char *sig, size_t *siglen,
    const unsigned char *tbs, size_t tbslen,
    int ndx_in);
int LUNA_OQS_SIG_verify_ndx(luna_prov_key_ctx *keyctx,
    const unsigned char *tbs, size_t tbslen,
    const unsigned char *sig, size_t siglen,
    int ndx_in);

/* callbacks to notify about events related to keypair changes */
void LUNA_OQS_WRITEKEY_LOCK(luna_prov_key_ctx *keyctx, luna_prov_key_reason reason);
void LUNA_OQS_WRITEKEY_UNLOCK(luna_prov_key_ctx *keyctx);
void LUNA_OQS_READKEY_LOCK(luna_prov_key_ctx *keyctx, luna_prov_keyinfo *keyinfo);
void LUNA_OQS_READKEY_UNLOCK(luna_prov_key_ctx *keyctx, luna_prov_keyinfo *keyinfo);

/* misc */
#define LUNA_POINTER_ADD(_vp, _ofs)  ( (void*) ( ((unsigned char*)(_vp)) + (_ofs) ) )

#endif
