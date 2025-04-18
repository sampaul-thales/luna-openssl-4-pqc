// SPDX-License-Identifier: Apache-2.0 AND MIT

/*
 * OQS OpenSSL 3 key handler.
 *
 * Code strongly inspired by OpenSSL crypto/ec key handler but relocated here
 * to have code within provider.
 *
 */

#include "oqs_prov.h"
#include <assert.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <string.h>

#include "../luna_prov_minimal.h"

#ifdef NDEBUG
#    define OQS_KEY_PRINTF(a)
#    define OQS_KEY_PRINTF2(a, b)
#    define OQS_KEY_PRINTF3(a, b, c)
#else
#    define OQS_KEY_PRINTF(a) \
        if (getenv("OQSKEY")) \
        printf(a)
#    define OQS_KEY_PRINTF2(a, b) \
        if (getenv("OQSKEY"))     \
        printf(a, b)
#    define OQS_KEY_PRINTF3(a, b, c) \
        if (getenv("OQSKEY"))        \
        printf(a, b, c)
#endif // NDEBUG

typedef enum {
    KEY_OP_PUBLIC,
    KEY_OP_PRIVATE,
    KEY_OP_KEYGEN
} oqsx_key_op_t;

/// NID/name table

typedef struct {
    int nid;
    char *tlsname;
    char *oqsname;
    int keytype;
    int secbits;
} oqs_nid_name_t;

static int oqsx_key_recreate_classickey(OQSX_KEY *key, oqsx_key_op_t op);

/* added for luna hsm */
static int lunax_oqsx_key_gen_oqs_ndx(OQSX_KEY *key, int ndx_in, int is_kem, int is_hybrid,
        int is_composite, int is_delegated);

///// OQS_TEMPLATE_FRAGMENT_OQSNAMES_START

#ifdef OQS_KEM_ENCODERS
#    define NID_TABLE_LEN 101
#else
#    define NID_TABLE_LEN 48
#endif /* OQS_KEM_ENCODERS */

static oqs_nid_name_t nid_names[NID_TABLE_LEN] = {
#ifdef OQS_KEM_ENCODERS

    {0, "frodo640aes", OQS_KEM_alg_frodokem_640_aes, KEY_TYPE_KEM, 128},
    {0, "p256_frodo640aes", OQS_KEM_alg_frodokem_640_aes, KEY_TYPE_ECP_HYB_KEM,
     128},
    {0, "x25519_frodo640aes", OQS_KEM_alg_frodokem_640_aes,
     KEY_TYPE_ECX_HYB_KEM, 128},
    {0, "frodo640shake", OQS_KEM_alg_frodokem_640_shake, KEY_TYPE_KEM, 128},
    {0, "p256_frodo640shake", OQS_KEM_alg_frodokem_640_shake,
     KEY_TYPE_ECP_HYB_KEM, 128},
    {0, "x25519_frodo640shake", OQS_KEM_alg_frodokem_640_shake,
     KEY_TYPE_ECX_HYB_KEM, 128},
    {0, "frodo976aes", OQS_KEM_alg_frodokem_976_aes, KEY_TYPE_KEM, 192},
    {0, "p384_frodo976aes", OQS_KEM_alg_frodokem_976_aes, KEY_TYPE_ECP_HYB_KEM,
     192},
    {0, "x448_frodo976aes", OQS_KEM_alg_frodokem_976_aes, KEY_TYPE_ECX_HYB_KEM,
     192},
    {0, "frodo976shake", OQS_KEM_alg_frodokem_976_shake, KEY_TYPE_KEM, 192},
    {0, "p384_frodo976shake", OQS_KEM_alg_frodokem_976_shake,
     KEY_TYPE_ECP_HYB_KEM, 192},
    {0, "x448_frodo976shake", OQS_KEM_alg_frodokem_976_shake,
     KEY_TYPE_ECX_HYB_KEM, 192},
    {0, "frodo1344aes", OQS_KEM_alg_frodokem_1344_aes, KEY_TYPE_KEM, 256},
    {0, "p521_frodo1344aes", OQS_KEM_alg_frodokem_1344_aes,
     KEY_TYPE_ECP_HYB_KEM, 256},
    {0, "frodo1344shake", OQS_KEM_alg_frodokem_1344_shake, KEY_TYPE_KEM, 256},
    {0, "p521_frodo1344shake", OQS_KEM_alg_frodokem_1344_shake,
     KEY_TYPE_ECP_HYB_KEM, 256},
    {0, "kyber512", OQS_KEM_alg_kyber_512, KEY_TYPE_KEM, 128},
    {0, "p256_kyber512", OQS_KEM_alg_kyber_512, KEY_TYPE_ECP_HYB_KEM, 128},
    {0, "x25519_kyber512", OQS_KEM_alg_kyber_512, KEY_TYPE_ECX_HYB_KEM, 128},
    {0, "kyber768", OQS_KEM_alg_kyber_768, KEY_TYPE_KEM, 192},
    {0, "p384_kyber768", OQS_KEM_alg_kyber_768, KEY_TYPE_ECP_HYB_KEM, 192},
    {0, "x448_kyber768", OQS_KEM_alg_kyber_768, KEY_TYPE_ECX_HYB_KEM, 192},
    {0, "x25519_kyber768", OQS_KEM_alg_kyber_768, KEY_TYPE_ECX_HYB_KEM, 192},
    {0, "p256_kyber768", OQS_KEM_alg_kyber_768, KEY_TYPE_ECP_HYB_KEM, 192},
    {0, "kyber1024", OQS_KEM_alg_kyber_1024, KEY_TYPE_KEM, 256},
    {0, "p521_kyber1024", OQS_KEM_alg_kyber_1024, KEY_TYPE_ECP_HYB_KEM, 256},
    {0, "mlkem512", OQS_KEM_alg_ml_kem_512, KEY_TYPE_KEM, 128},
    {0, "p256_mlkem512", OQS_KEM_alg_ml_kem_512, KEY_TYPE_ECP_HYB_KEM, 128},
    {0, "x25519_mlkem512", OQS_KEM_alg_ml_kem_512, KEY_TYPE_ECX_HYB_KEM, 128},
    {0, "mlkem768", OQS_KEM_alg_ml_kem_768, KEY_TYPE_KEM, 192},
    {0, "p384_mlkem768", OQS_KEM_alg_ml_kem_768, KEY_TYPE_ECP_HYB_KEM, 192},
    {0, "x448_mlkem768", OQS_KEM_alg_ml_kem_768, KEY_TYPE_ECX_HYB_KEM, 192},
    {0, "x25519_mlkem768", OQS_KEM_alg_ml_kem_768, KEY_TYPE_ECX_HYB_KEM, 192},
    {0, "p256_mlkem768", OQS_KEM_alg_ml_kem_768, KEY_TYPE_ECP_HYB_KEM, 192},
    {0, "mlkem1024", OQS_KEM_alg_ml_kem_1024, KEY_TYPE_KEM, 256},
    {0, "p521_mlkem1024", OQS_KEM_alg_ml_kem_1024, KEY_TYPE_ECP_HYB_KEM, 256},
    {0, "p384_mlkem1024", OQS_KEM_alg_ml_kem_1024, KEY_TYPE_ECP_HYB_KEM, 256},
    {0, "bikel1", OQS_KEM_alg_bike_l1, KEY_TYPE_KEM, 128},
    {0, "p256_bikel1", OQS_KEM_alg_bike_l1, KEY_TYPE_ECP_HYB_KEM, 128},
    {0, "x25519_bikel1", OQS_KEM_alg_bike_l1, KEY_TYPE_ECX_HYB_KEM, 128},
    {0, "bikel3", OQS_KEM_alg_bike_l3, KEY_TYPE_KEM, 192},
    {0, "p384_bikel3", OQS_KEM_alg_bike_l3, KEY_TYPE_ECP_HYB_KEM, 192},
    {0, "x448_bikel3", OQS_KEM_alg_bike_l3, KEY_TYPE_ECX_HYB_KEM, 192},
    {0, "bikel5", OQS_KEM_alg_bike_l5, KEY_TYPE_KEM, 256},
    {0, "p521_bikel5", OQS_KEM_alg_bike_l5, KEY_TYPE_ECP_HYB_KEM, 256},
    {0, "hqc128", OQS_KEM_alg_hqc_128, KEY_TYPE_KEM, 128},
    {0, "p256_hqc128", OQS_KEM_alg_hqc_128, KEY_TYPE_ECP_HYB_KEM, 128},
    {0, "x25519_hqc128", OQS_KEM_alg_hqc_128, KEY_TYPE_ECX_HYB_KEM, 128},
    {0, "hqc192", OQS_KEM_alg_hqc_192, KEY_TYPE_KEM, 192},
    {0, "p384_hqc192", OQS_KEM_alg_hqc_192, KEY_TYPE_ECP_HYB_KEM, 192},
    {0, "x448_hqc192", OQS_KEM_alg_hqc_192, KEY_TYPE_ECX_HYB_KEM, 192},
    {0, "hqc256", OQS_KEM_alg_hqc_256, KEY_TYPE_KEM, 256},
    {0, "p521_hqc256", OQS_KEM_alg_hqc_256, KEY_TYPE_ECP_HYB_KEM, 256},

#endif /* OQS_KEM_ENCODERS */
    {0, "dilithium2", OQS_SIG_alg_dilithium_2, KEY_TYPE_SIG, 128},
    {0, "p256_dilithium2", OQS_SIG_alg_dilithium_2, KEY_TYPE_HYB_SIG, 128},
    {0, "rsa3072_dilithium2", OQS_SIG_alg_dilithium_2, KEY_TYPE_HYB_SIG, 128},
    {0, "dilithium3", OQS_SIG_alg_dilithium_3, KEY_TYPE_SIG, 192},
    {0, "p384_dilithium3", OQS_SIG_alg_dilithium_3, KEY_TYPE_HYB_SIG, 192},
    {0, "dilithium5", OQS_SIG_alg_dilithium_5, KEY_TYPE_SIG, 256},
    {0, "p521_dilithium5", OQS_SIG_alg_dilithium_5, KEY_TYPE_HYB_SIG, 256},
    {0, "mldsa44", OQS_SIG_alg_ml_dsa_44, KEY_TYPE_SIG, 128},
    {0, "p256_mldsa44", OQS_SIG_alg_ml_dsa_44, KEY_TYPE_HYB_SIG, 128},
    {0, "rsa3072_mldsa44", OQS_SIG_alg_ml_dsa_44, KEY_TYPE_HYB_SIG, 128},
    {0, "mldsa44_pss2048", OQS_SIG_alg_ml_dsa_44, KEY_TYPE_CMP_SIG, 112},
    {0, "mldsa44_rsa2048", OQS_SIG_alg_ml_dsa_44, KEY_TYPE_CMP_SIG, 112},
    {0, "mldsa44_ed25519", OQS_SIG_alg_ml_dsa_44, KEY_TYPE_CMP_SIG, 128},
    {0, "mldsa44_p256", OQS_SIG_alg_ml_dsa_44, KEY_TYPE_CMP_SIG, 128},
    {0, "mldsa44_bp256", OQS_SIG_alg_ml_dsa_44, KEY_TYPE_CMP_SIG, 256},
    {0, "mldsa65", OQS_SIG_alg_ml_dsa_65, KEY_TYPE_SIG, 192},
    {0, "p384_mldsa65", OQS_SIG_alg_ml_dsa_65, KEY_TYPE_HYB_SIG, 192},
    {0, "mldsa65_pss3072", OQS_SIG_alg_ml_dsa_65, KEY_TYPE_CMP_SIG, 128},
    {0, "mldsa65_rsa3072", OQS_SIG_alg_ml_dsa_65, KEY_TYPE_CMP_SIG, 128},
    {0, "mldsa65_p256", OQS_SIG_alg_ml_dsa_65, KEY_TYPE_CMP_SIG, 128},
    {0, "mldsa65_bp256", OQS_SIG_alg_ml_dsa_65, KEY_TYPE_CMP_SIG, 256},
    {0, "mldsa65_ed25519", OQS_SIG_alg_ml_dsa_65, KEY_TYPE_CMP_SIG, 128},
    {0, "mldsa87", OQS_SIG_alg_ml_dsa_87, KEY_TYPE_SIG, 256},
    {0, "p521_mldsa87", OQS_SIG_alg_ml_dsa_87, KEY_TYPE_HYB_SIG, 256},
    {0, "mldsa87_p384", OQS_SIG_alg_ml_dsa_87, KEY_TYPE_CMP_SIG, 192},
    {0, "mldsa87_bp384", OQS_SIG_alg_ml_dsa_87, KEY_TYPE_CMP_SIG, 384},
    {0, "mldsa87_ed448", OQS_SIG_alg_ml_dsa_87, KEY_TYPE_CMP_SIG, 192},
    {0, "falcon512", OQS_SIG_alg_falcon_512, KEY_TYPE_SIG, 128},
    {0, "p256_falcon512", OQS_SIG_alg_falcon_512, KEY_TYPE_HYB_SIG, 128},
    {0, "rsa3072_falcon512", OQS_SIG_alg_falcon_512, KEY_TYPE_HYB_SIG, 128},
    {0, "falconpadded512", OQS_SIG_alg_falcon_padded_512, KEY_TYPE_SIG, 128},
    {0, "p256_falconpadded512", OQS_SIG_alg_falcon_padded_512, KEY_TYPE_HYB_SIG,
     128},
    {0, "rsa3072_falconpadded512", OQS_SIG_alg_falcon_padded_512,
     KEY_TYPE_HYB_SIG, 128},
    {0, "falcon1024", OQS_SIG_alg_falcon_1024, KEY_TYPE_SIG, 256},
    {0, "p521_falcon1024", OQS_SIG_alg_falcon_1024, KEY_TYPE_HYB_SIG, 256},
    {0, "falconpadded1024", OQS_SIG_alg_falcon_padded_1024, KEY_TYPE_SIG, 256},
    {0, "p521_falconpadded1024", OQS_SIG_alg_falcon_padded_1024,
     KEY_TYPE_HYB_SIG, 256},
    {0, "sphincssha2128fsimple", OQS_SIG_alg_sphincs_sha2_128f_simple,
     KEY_TYPE_SIG, 128},
    {0, "p256_sphincssha2128fsimple", OQS_SIG_alg_sphincs_sha2_128f_simple,
     KEY_TYPE_HYB_SIG, 128},
    {0, "rsa3072_sphincssha2128fsimple", OQS_SIG_alg_sphincs_sha2_128f_simple,
     KEY_TYPE_HYB_SIG, 128},
    {0, "sphincssha2128ssimple", OQS_SIG_alg_sphincs_sha2_128s_simple,
     KEY_TYPE_SIG, 128},
    {0, "p256_sphincssha2128ssimple", OQS_SIG_alg_sphincs_sha2_128s_simple,
     KEY_TYPE_HYB_SIG, 128},
    {0, "rsa3072_sphincssha2128ssimple", OQS_SIG_alg_sphincs_sha2_128s_simple,
     KEY_TYPE_HYB_SIG, 128},
    {0, "sphincssha2192fsimple", OQS_SIG_alg_sphincs_sha2_192f_simple,
     KEY_TYPE_SIG, 192},
    {0, "p384_sphincssha2192fsimple", OQS_SIG_alg_sphincs_sha2_192f_simple,
     KEY_TYPE_HYB_SIG, 192},
    {0, "sphincsshake128fsimple", OQS_SIG_alg_sphincs_shake_128f_simple,
     KEY_TYPE_SIG, 128},
    {0, "p256_sphincsshake128fsimple", OQS_SIG_alg_sphincs_shake_128f_simple,
     KEY_TYPE_HYB_SIG, 128},
    {0, "rsa3072_sphincsshake128fsimple", OQS_SIG_alg_sphincs_shake_128f_simple,
     KEY_TYPE_HYB_SIG, 128},
    ///// OQS_TEMPLATE_FRAGMENT_OQSNAMES_END
};

int oqs_set_nid(char *tlsname, int nid)
{
    int i;
    for (i = 0; i < NID_TABLE_LEN; i++) {
        if (!strcmp(nid_names[i].tlsname, tlsname)) {
            nid_names[i].nid = nid;
            return 1;
        }
    }
    return 0;
}

static int get_secbits(int nid)
{
    int i;
    for (i = 0; i < NID_TABLE_LEN; i++) {
        if (nid_names[i].nid == nid)
            return nid_names[i].secbits;
    }
    return 0;
}

static int get_keytype(int nid)
{
    int i;
    for (i = 0; i < NID_TABLE_LEN; i++) {
        if (nid_names[i].nid == nid)
            return nid_names[i].keytype;
    }
    return 0;
}

char *get_oqsname_fromtls(char *tlsname)
{
    int i;
    for (i = 0; i < NID_TABLE_LEN; i++) {
        if (nid_names[i].keytype == KEY_TYPE_SIG) {
            if (!strcmp(nid_names[i].oqsname, tlsname)
                || !strcmp(nid_names[i].tlsname, tlsname))
                return nid_names[i].oqsname;
        }
    }
    return 0; // classical
}

char *get_oqsname(int nid)
{
    int i;
    for (i = 0; i < NID_TABLE_LEN; i++) {
        if (nid_names[i].nid == nid)
            return nid_names[i].oqsname;
    }
    return 0;
}

char *get_cmpname(int nid, int index)
{
    int i, len;
    char *name, *s;
    if ((i = get_oqsalg_idx(nid)) == -1)
        return NULL;
    s = nid_names[i].tlsname;
    len = strlen(s);
    for (i = 0; i < len; i++) {
        if (s[i] == '_') {
            break;
        }
    }
    switch (index) {
    case 0:
        name = OPENSSL_strndup(s, i);
        break;
    case 1:
        i += 1;
        name = OPENSSL_strndup(s + i, len - i);
        break;
    default:
        name = NULL;
    }

    return name;
}

int get_oqsalg_idx(int nid)
{
    int i;
    for (i = 0; i < NID_TABLE_LEN; i++) {
        if (nid_names[i].nid == nid)
            return i;
    }
    return -1;
}

/* Prepare composite data structures. RetVal 0 is error. */
static int oqsx_key_set_composites(OQSX_KEY *key)
{
    int ret = 1;

    OQS_KEY_PRINTF2("Setting composites with evp_info %p\n", key->evp_info);

    if (key->numkeys == 1) {
        key->comp_privkey[0] = key->privkey;
        key->comp_pubkey[0] = key->pubkey;
    } else { // TBD: extend for more than 1 classic key or first OQS for
             // composite:
        if (key->keytype == KEY_TYPE_CMP_SIG) {
            int i;
            int privlen = 0;
            int publen = 0;
            for (i = 0; i < key->numkeys; i++) {
                if (key->privkey) {
                    key->comp_privkey[i] = (char *)key->privkey + privlen;
                    privlen += key->privkeylen_cmp[i];
                } else {
                    key->comp_privkey[i] = NULL;
                }
                if (key->pubkey) {
                    key->comp_pubkey[i] = (char *)key->pubkey + publen;
                    publen += key->pubkeylen_cmp[i];
                } else {
                    key->comp_pubkey[i] = NULL;
                }
            }
        } else {
            int classic_pubkey_len, classic_privkey_len;

            if (key->privkey) {
                key->comp_privkey[0] = (char *)key->privkey + SIZE_OF_UINT32;
                DECODE_UINT32(classic_privkey_len, key->privkey);
                /* coverity: check for overflowed value */
                if (classic_privkey_len < 1 || classic_privkey_len > OQS_PROV_MAX_BUFFER) {
                    ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                    ret = 0;
                }
                key->comp_privkey[1] = (char *)key->privkey
                                       + classic_privkey_len + SIZE_OF_UINT32;
            } else {
                key->comp_privkey[0] = NULL;
                key->comp_privkey[1] = NULL;
            }
            if (key->pubkey) {
                key->comp_pubkey[0] = (char *)key->pubkey + SIZE_OF_UINT32;
                DECODE_UINT32(classic_pubkey_len, key->pubkey);
                /* coverity: check for overflowed value */
                if (classic_pubkey_len < 1 || classic_pubkey_len > OQS_PROV_MAX_BUFFER) {
                    ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                    ret = 0;
                }
                key->comp_pubkey[1]
                    = (char *)key->pubkey + classic_pubkey_len + SIZE_OF_UINT32;
            } else {
                key->comp_pubkey[0] = NULL;
                key->comp_pubkey[1] = NULL;
            }
        }
    }
//err:
    return ret;
}

PROV_OQS_CTX *oqsx_newprovctx(OSSL_LIB_CTX *libctx,
                              const OSSL_CORE_HANDLE *handle, BIO_METHOD *bm)
{
    PROV_OQS_CTX *ret = OPENSSL_zalloc(sizeof(PROV_OQS_CTX));
    if (ret) {
        ret->libctx = libctx;
        ret->handle = handle;
        ret->corebiometh = bm;
    }
    return ret;
}

void oqsx_freeprovctx(PROV_OQS_CTX *ctx)
{
    OSSL_LIB_CTX_free(ctx->libctx);
    BIO_meth_free(ctx->corebiometh);
    OPENSSL_free(ctx);
}

void oqsx_key_set0_libctx(OQSX_KEY *key, OSSL_LIB_CTX *libctx)
{
    key->libctx = libctx;
}

/* convenience function creating OQSX keys from nids (only for sigs) */
static OQSX_KEY *oqsx_key_new_from_nid(OSSL_LIB_CTX *libctx, const char *propq,
                                       int nid)
{
    OQS_KEY_PRINTF2("Generating OQSX key for nid %d\n", nid);

    char *tls_algname = (char *)OBJ_nid2sn(nid);
    OQS_KEY_PRINTF2("                    for tls_name %s\n", tls_algname);

    if (!tls_algname) {
        ERR_raise(ERR_LIB_USER, OQSPROV_R_WRONG_PARAMETERS);
        return NULL;
    }

    return oqsx_key_new(libctx, get_oqsname(nid), tls_algname, get_keytype(nid),
                        propq, get_secbits(nid), get_oqsalg_idx(nid));
}

/* Workaround for not functioning EC PARAM initialization
 * TBD, check https://github.com/openssl/openssl/issues/16989
 */
EVP_PKEY *setECParams(EVP_PKEY *eck, int nid)
{
    const unsigned char p256params[]
        = {0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};
    const unsigned char p384params[]
        = {0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22};
    const unsigned char p521params[]
        = {0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23};
    const char bp256params[]
        = {0x06, 0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07};
    const char bp384params[]
        = {0x06, 0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0b};

    const unsigned char *params;
    switch (nid) {
    case NID_X9_62_prime256v1:
        params = p256params;
        return d2i_KeyParams(EVP_PKEY_EC, &eck, &params, sizeof(p256params));
    case NID_secp384r1:
        params = p384params;
        return d2i_KeyParams(EVP_PKEY_EC, &eck, &params, sizeof(p384params));
    case NID_secp521r1:
        params = p521params;
        return d2i_KeyParams(EVP_PKEY_EC, &eck, &params, sizeof(p521params));
    case NID_brainpoolP256r1:
        params = bp256params;
        return d2i_KeyParams(EVP_PKEY_EC, &eck, &params, sizeof(bp256params));
    case NID_brainpoolP384r1:
        params = bp384params;
        return d2i_KeyParams(EVP_PKEY_EC, &eck, &params, sizeof(bp384params));
    default:
        return NULL;
    }
}

/* Key codes */

static const OQSX_EVP_INFO nids_sig[] = {
    {EVP_PKEY_EC, NID_X9_62_prime256v1, 0, 65, 121, 32, 72}, // 128 bit
    {EVP_PKEY_EC, NID_secp384r1, 0, 97, 167, 48, 104},       // 192 bit
    {EVP_PKEY_EC, NID_secp521r1, 0, 133, 223, 66, 141},      // 256 bit
    {EVP_PKEY_EC, NID_brainpoolP256r1, 0, 65, 122, 32, 72},  // 256 bit
    {EVP_PKEY_EC, NID_brainpoolP384r1, 0, 97, 171, 48, 104}, // 384 bit
    {EVP_PKEY_RSA, NID_rsaEncryption, 0, 398, 1770, 0, 384}, // 128 bit
    {EVP_PKEY_RSA, NID_rsaEncryption, 0, 270, 1193, 0, 256}, // 112 bit
    {EVP_PKEY_ED25519, NID_ED25519, 1, 32, 32, 32, 72},      // 128 bit
    {EVP_PKEY_ED448, NID_ED448, 1, 57, 57, 57, 122},         // 192 bit

};
// These two array need to stay synced:
// note only leading 4 chars of alg name are checked
static const char *OQSX_ECP_NAMES[] = {"p256", "p384", "p521", 0};
static const OQSX_EVP_INFO nids_ecp[] = {
    {EVP_PKEY_EC, NID_X9_62_prime256v1, 0, 65, 121, 32, 0}, // 128 bit
    {EVP_PKEY_EC, NID_secp384r1, 0, 97, 167, 48, 0},        // 192 bit
    {EVP_PKEY_EC, NID_secp521r1, 0, 133, 223, 66, 0}        // 256 bit
};

// These two array need to stay synced:
// note only leading 4 chars of alg name are checked
static const char *OQSX_ECX_NAMES[] = {"x25519", "x448", 0};
static const OQSX_EVP_INFO nids_ecx[] = {
    {EVP_PKEY_X25519, 0, 1, 32, 32, 32, 0}, // 128 bit
    {EVP_PKEY_X448, 0, 1, 56, 56, 56, 0},   // 192 bit
    {0, 0, 0, 0, 0, 0, 0}                   // 256 bit
};

static int oqsx_hybsig_init(int bit_security, OQSX_EVP_CTX *evp_ctx,
                            char *algname)
{
    int ret = 1;
    int idx = (bit_security - 128) / 64;
    ON_ERR_GOTO(idx < 0 || idx > 5, err_init);

    if (!strncmp(algname, "rsa", 3) || !strncmp(algname, "pss", 3)) {
        idx += 5;
        if (bit_security == 112)
            idx += 1;
    } else if (algname[0] != 'p' && algname[0] != 'e') {
        if (algname[0] == 'b') {   // bp
            if (algname[2] == '2') // bp256
                idx += 1;
        } else {
            OQS_KEY_PRINTF2("OQS KEY: Incorrect hybrid name: %s\n", algname);
            ret = 0;
            goto err_init;
        }
    }

    ON_ERR_GOTO(idx < 0 || idx > 6, err_init);

    if (algname[0] == 'e') // ED25519 or ED448
    {
        evp_ctx->evp_info = &nids_sig[idx + 7];

        evp_ctx->keyParam = EVP_PKEY_new();
        ON_ERR_SET_GOTO(!evp_ctx->keyParam, ret, -1, err_init);

        ret = EVP_PKEY_set_type(evp_ctx->keyParam, evp_ctx->evp_info->keytype);
        ON_ERR_SET_GOTO(ret <= 0, ret, -1, err_init);

        evp_ctx->ctx = EVP_PKEY_CTX_new(evp_ctx->keyParam, NULL);
        ON_ERR_SET_GOTO(!evp_ctx->ctx, ret, -1, err_init);
    } else {
        evp_ctx->evp_info = &nids_sig[idx];

        evp_ctx->ctx = EVP_PKEY_CTX_new_id(evp_ctx->evp_info->keytype, NULL);
        ON_ERR_GOTO(!evp_ctx->ctx, err_init);

        if (idx < 5) { // EC
            ret = EVP_PKEY_paramgen_init(evp_ctx->ctx);
            ON_ERR_GOTO(ret <= 0, err_init);

            ret = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(
                evp_ctx->ctx, evp_ctx->evp_info->nid);
            ON_ERR_GOTO(ret <= 0, free_evp_ctx);

            ret = EVP_PKEY_paramgen(evp_ctx->ctx, &evp_ctx->keyParam);
            ON_ERR_GOTO(ret <= 0 || !evp_ctx->keyParam, free_evp_ctx);
        }
    }
    // RSA bit length set only during keygen
    goto err_init;

free_evp_ctx:
    EVP_PKEY_CTX_free(evp_ctx->ctx);
    evp_ctx->ctx = NULL;

err_init:
    return ret;
}

static int oqshybkem_init_ecp(char *tls_name, OQSX_EVP_CTX *evp_ctx)
{
    int ret = 1;
    int idx = 0;
    while (idx < OSSL_NELEM(OQSX_ECP_NAMES)) {
        if (!strncmp(tls_name, OQSX_ECP_NAMES[idx], 4))
            break;
        idx++;
    }
    ON_ERR_GOTO(idx < 0 || idx > 2, err_init_ecp);

    evp_ctx->evp_info = &nids_ecp[idx];

    evp_ctx->ctx = EVP_PKEY_CTX_new_id(evp_ctx->evp_info->keytype, NULL);
    ON_ERR_GOTO(!evp_ctx->ctx, err_init_ecp);

    ret = EVP_PKEY_paramgen_init(evp_ctx->ctx);
    ON_ERR_GOTO(ret <= 0, err_init_ecp);

    ret = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(evp_ctx->ctx,
                                                 evp_ctx->evp_info->nid);
    ON_ERR_GOTO(ret <= 0, err_init_ecp);

    ret = EVP_PKEY_paramgen(evp_ctx->ctx, &evp_ctx->keyParam);
    ON_ERR_GOTO(ret <= 0 || !evp_ctx->keyParam, err_init_ecp);

err_init_ecp:
    return ret;
}

static int oqshybkem_init_ecx(char *tls_name, OQSX_EVP_CTX *evp_ctx)
{
    int ret = 1;
    int idx = 0;

    while (idx < OSSL_NELEM(OQSX_ECX_NAMES)) {
        if (!strncmp(tls_name, OQSX_ECX_NAMES[idx], 4))
            break;
        idx++;
    }
    ON_ERR_GOTO(idx < 0 || idx > 2, err_init_ecx);

    evp_ctx->evp_info = &nids_ecx[idx];

    evp_ctx->keyParam = EVP_PKEY_new();
    ON_ERR_SET_GOTO(!evp_ctx->keyParam, ret, -1, err_init_ecx);

    ret = EVP_PKEY_set_type(evp_ctx->keyParam, evp_ctx->evp_info->keytype);
    ON_ERR_SET_GOTO(ret <= 0, ret, -1, err_init_ecx);

    evp_ctx->ctx = EVP_PKEY_CTX_new(evp_ctx->keyParam, NULL);
    ON_ERR_SET_GOTO(!evp_ctx->ctx, ret, -1, err_init_ecx);

err_init_ecx:
    return ret;
}

/* Re-create OQSX_KEY from encoding(s): Same end-state as after ken-gen */
static OQSX_KEY *oqsx_key_op(const X509_ALGOR *palg, const unsigned char *p,
                             int plen, oqsx_key_op_t op, OSSL_LIB_CTX *libctx,
                             const char *propq)
{
    OQSX_KEY *key = NULL;
    //void **privkey;
    //void **pubkey;
    int nid = NID_undef;
    //int ret = 0;

    OQS_KEY_PRINTF2("OQSX KEY: key_op called with data of len %d\n", plen);
    if (palg != NULL) {
        int ptype;

        /* Algorithm parameters must be absent */
        X509_ALGOR_get0(NULL, &ptype, NULL, palg);
        if (ptype != V_ASN1_UNDEF || !palg || !palg->algorithm) {
            ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
            return 0;
        }
        nid = OBJ_obj2nid(palg->algorithm);
    }

    if (p == NULL || nid == EVP_PKEY_NONE || nid == NID_undef) {
        ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
        return 0;
    }

    key = oqsx_key_new_from_nid(libctx, propq, nid);
    if (key == NULL) {
        ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    OQS_KEY_PRINTF2("OQSX KEY: Recreated OQSX key %s\n", key->tls_name);

    if (op == KEY_OP_PUBLIC) {
#ifdef USE_ENCODING_LIB
        if (key->oqsx_encoding_ctx.encoding_ctx
            && key->oqsx_encoding_ctx.encoding_impl) {
            key->pubkeylen = key->oqsx_encoding_ctx.encoding_ctx
                                 ->raw_crypto_publickeybytes;
            if (key->oqsx_encoding_ctx.encoding_impl->crypto_publickeybytes
                != plen) {
                ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                goto err_key_op;
            }
            if (oqsx_key_allocate_keymaterial(key, 0)) {
                ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
                goto err_key_op;
            }
            if (qsc_decode(key->oqsx_encoding_ctx.encoding_ctx,
                           key->oqsx_encoding_ctx.encoding_impl, p,
                           (unsigned char **)&key->pubkey, 0, 0, 1)
                != QSC_ENC_OK) {
                ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                goto err_key_op;
            }
        } else {
#endif
            if (key->pubkeylen != plen) {
                ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                goto err_key_op;
            }
            if (oqsx_key_allocate_keymaterial(key, 0)) {
                ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
                goto err_key_op;
            }
            memcpy(key->pubkey, p, plen);
#ifdef USE_ENCODING_LIB
        }
#endif
    } else {
        int classical_privatekey_len = 0;
        // for plain OQS keys, we expect OQS priv||OQS pub key
        size_t actualprivkeylen = key->privkeylen;
        // for hybrid keys, we expect classic priv key||OQS priv key||OQS pub
        // key classic pub key must/can be re-created from classic private key
        if (key->keytype == KEY_TYPE_CMP_SIG) {
            size_t privlen = 0;
            size_t publen = 0;
            size_t previous_privlen = 0;
            size_t previous_publen = 0;
            size_t temp_pub_len, temp_priv_len;
            char *temp_priv, *temp_pub;
            int pqc_pub_enc = 0;
            int i;

            // check if key is the right size
            for (i = 0; i < key->numkeys; i++) {
                char *name = get_cmpname(OBJ_sn2nid(key->tls_name), i);
                if (name == NULL) {
                    ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                    goto err_key_op;
                }
                privlen = key->privkeylen_cmp[i];
                if (get_oqsname_fromtls(name) == 0) { // classical key
                    publen = 0;
                } else {                            // PQC key
                    publen = key->pubkeylen_cmp[i]; // pubkey in PQC privkey is
                                                    // OPTIONAL
                }
                previous_privlen += privlen;
                previous_publen += publen;
                OPENSSL_free(name);
            }
            if (previous_privlen != plen) {
                // is ok, PQC pubkey might be in privkey
                pqc_pub_enc = 1;
                if (previous_privlen + previous_publen != plen) {
                    ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                    goto err_key_op;
                }
                if (oqsx_key_allocate_keymaterial(key, 0)) {
                    ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
                    goto err_key_op;
                }
            }
            if (oqsx_key_allocate_keymaterial(key, 1)) {
                ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
                goto err_key_op;
            }
            temp_priv_len = previous_privlen;
            temp_pub_len = previous_publen;
            temp_priv = OPENSSL_secure_zalloc(temp_priv_len);
            temp_pub = OPENSSL_secure_zalloc(temp_pub_len);
            previous_privlen = 0;
            previous_publen = 0;
            for (i = 0; i < key->numkeys; i++) {
                //size_t classic_publen = 0;
                char *name;
                if ((name = get_cmpname(OBJ_sn2nid(key->tls_name), i))
                    == NULL) {
                    ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                    OPENSSL_secure_clear_free(temp_priv, temp_priv_len);
                    OPENSSL_secure_clear_free(temp_pub, temp_pub_len);
                    goto err_key_op;
                }
                if (get_oqsname_fromtls(name) == 0) { // classical key
                    publen = 0; // no pubkey encoded with privkey on classical
                                // keys. will recreate the pubkey later
                    if (key->oqsx_provider_ctx.oqsx_evp_ctx->evp_info->keytype
                        == EVP_PKEY_RSA) { // get the RSA real key size
                        unsigned char *enc_len = OPENSSL_strndup(
                            p + previous_privlen + previous_publen, 4);
                        OPENSSL_cleanse(enc_len, 2);
                        DECODE_UINT32(privlen, enc_len);
                        OPENSSL_free(enc_len);
                        /* coverity: check for overflowed value */
                        if (privlen >= 1 && privlen <= OQS_PROV_MAX_BUFFER)
                            privlen += 4;
                        if (privlen < 1 || privlen > OQS_PROV_MAX_BUFFER
                                || privlen > key->privkeylen_cmp[i]) {
                            OPENSSL_free(name);
                            OPENSSL_secure_clear_free(temp_priv, temp_priv_len);
                            OPENSSL_secure_clear_free(temp_pub, temp_pub_len);
                            ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                            goto err_key_op;
                        }
                        key->privkeylen_cmp[i] = privlen;
                    } else
                        privlen = key->privkeylen_cmp[i];
                } else { // PQC key
                    privlen = key->privkeylen_cmp[i];
                    if (pqc_pub_enc)
                        publen = key->pubkeylen_cmp[i];
                    else
                        publen = 0;
                }
                memcpy(temp_priv + previous_privlen,
                       p + previous_privlen + previous_publen, privlen);
                memcpy(temp_pub + previous_publen,
                       p + privlen + previous_privlen + previous_publen,
                       publen);
                previous_privlen += privlen;
                previous_publen += publen;
                OPENSSL_free(name);
            }
            memcpy(key->privkey, temp_priv, previous_privlen);
            memcpy(key->pubkey, temp_pub, previous_publen);
            OPENSSL_secure_clear_free(temp_priv, temp_priv_len);
            OPENSSL_secure_clear_free(temp_pub, temp_pub_len);
        } else {
            if (key->numkeys == 2) {
                DECODE_UINT32(classical_privatekey_len,
                              p); // actual classic key len
                /* coverity: check for overflowed value */
                if (classical_privatekey_len < 1 || classical_privatekey_len > OQS_PROV_MAX_BUFFER) {
                    ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                    goto err_key_op;
                }
                if (key->evp_info->length_private_key < classical_privatekey_len) {
                    ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                    goto err_key_op;
                }
                if (actualprivkeylen < (key->evp_info->length_private_key
                        - classical_privatekey_len)) {
                    ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                    goto err_key_op;
                }
                actualprivkeylen -= (key->evp_info->length_private_key
                                     - classical_privatekey_len);
            }
#ifdef USE_ENCODING_LIB
            if (key->oqsx_encoding_ctx.encoding_ctx
                && key->oqsx_encoding_ctx.encoding_impl) {
                const qsc_encoding_t *encoding_ctx
                    = key->oqsx_encoding_ctx.encoding_ctx;
#    ifdef NOPUBKEY_IN_PRIVKEY
                // if the raw private key includes the public key, the optional
                // part is needed, otherwise not.
                int withoptional
                    = (encoding_ctx->raw_private_key_encodes_public_key ? 1
                                                                        : 0);
#    else
                int withoptional = 1;
#    endif
                int pubkey_available = withoptional;
                if (oqsx_key_allocate_keymaterial(key, 1)) {
                    ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
                    goto err_key_op;
                }
                if (pubkey_available) {
                    if (oqsx_key_allocate_keymaterial(key, 0)) {
                        ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
                        goto err_key_op;
                    }
                }

                if (qsc_decode(
                        encoding_ctx, key->oqsx_encoding_ctx.encoding_impl, 0,
                        (pubkey_available ? (unsigned char **)&key->pubkey : 0),
                        p, (unsigned char **)&key->privkey, withoptional)
                    != QSC_ENC_OK) {
                    ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                    goto err_key_op;
                }

            } else {
#endif
#ifdef NOPUBKEY_IN_PRIVKEY
                if (actualprivkeylen != plen) {
                    OQS_KEY_PRINTF3(
                        "OQSX KEY: private key with unexpected length %d vs %d\n",
                        plen, (int)(actualprivkeylen));
#else
            if (actualprivkeylen + oqsx_key_get_oqs_public_key_len(key)
                != plen) {
                OQS_KEY_PRINTF3(
                    "OQSX KEY: private key with unexpected length %d vs %d\n",
                    plen,
                    (int)(actualprivkeylen
                          + oqsx_key_get_oqs_public_key_len(key)));
#endif
                    ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                    goto err_key_op;
                }
                if (oqsx_key_allocate_keymaterial(key, 1)
#ifndef NOPUBKEY_IN_PRIVKEY
                    || oqsx_key_allocate_keymaterial(key, 0)
#endif
                ) {
                    ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
                    goto err_key_op;
                }
                // first populate private key data
                memcpy(key->privkey, p, actualprivkeylen);
#ifndef NOPUBKEY_IN_PRIVKEY
                // only enough data to fill public OQS key component
                if (oqsx_key_get_oqs_public_key_len(key)
                    != plen - actualprivkeylen) {
                    ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                    goto err_key_op;
                }
                // populate OQS public key structure
                if (key->numkeys == 2) {
                    unsigned char *pubkey = (unsigned char *)key->pubkey;
                    ENCODE_UINT32(pubkey, key->evp_info->length_public_key);
                    // coverity: overflowed value 'plen - actualprivkeylen'
                    if (plen < 1 || plen > OQS_PROV_MAX_BUFFER)
                        goto err_key_op;
                    if (plen < actualprivkeylen)
                        goto err_key_op;
                    memcpy(pubkey + SIZE_OF_UINT32
                               + key->evp_info->length_public_key,
                           p + actualprivkeylen, plen - actualprivkeylen);
                } else {
                    // coverity: overflowed value 'plen - key->privkeylen'
                    if (plen < 1 || plen > OQS_PROV_MAX_BUFFER)
                        goto err_key_op;
                    if (plen < key->privkeylen)
                        goto err_key_op;
                    memcpy(key->pubkey, p + key->privkeylen,
                           plen - key->privkeylen);
                }
#endif
            }
        }
#ifdef USE_ENCODING_LIB
    }
#endif
    if (!oqsx_key_set_composites(key) || !oqsx_key_recreate_classickey(key, op))
        goto err_key_op;

    return key;

err_key_op:
    oqsx_key_free(key);
    return NULL;
}

/* Recreate EVP data structure after import. RetVal 0 is error. */
static int oqsx_key_recreate_classickey(OQSX_KEY *key, oqsx_key_op_t op)
{
    if (key->keytype == KEY_TYPE_CMP_SIG) {
        int i;
        if (op == KEY_OP_PUBLIC) {

            for (i = 0; i < key->numkeys; i++) {
                char *name;
                if ((name = get_cmpname(OBJ_sn2nid(key->tls_name), i))
                    == NULL) {
                    ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                    goto rec_err;
                }
                const unsigned char *enc_pubkey = key->comp_pubkey[i];

                if (get_oqsname_fromtls(name) == 0) {
                    if (!key->oqsx_provider_ctx.oqsx_evp_ctx->evp_info
                             ->raw_key_support) {
                        EVP_PKEY *npk = EVP_PKEY_new();
                        if (key->oqsx_provider_ctx.oqsx_evp_ctx->evp_info
                                ->keytype
                            != EVP_PKEY_RSA) {
                            npk = setECParams(npk,
                                              key->oqsx_provider_ctx
                                                  .oqsx_evp_ctx->evp_info->nid);
                        }
                        key->classical_pkey = d2i_PublicKey(
                            key->oqsx_provider_ctx.oqsx_evp_ctx->evp_info
                                ->keytype,
                            &npk, &enc_pubkey, key->pubkeylen_cmp[i]);
                    } else
                        key->classical_pkey = EVP_PKEY_new_raw_public_key(
                            key->oqsx_provider_ctx.oqsx_evp_ctx->evp_info
                                ->keytype,
                            NULL, enc_pubkey, key->pubkeylen_cmp[i]);
                    if (!key->classical_pkey) {
                        ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                        OPENSSL_free(name);
                        goto rec_err;
                    }
                }
                OPENSSL_free(name);
            }
        }

        if (op == KEY_OP_PRIVATE) {

            for (i = 0; i < key->numkeys; i++) {
                char *name;
                if ((name = get_cmpname(OBJ_sn2nid(key->tls_name), i))
                    == NULL) {
                    ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                    goto rec_err;
                }
                if (get_oqsname_fromtls(name) == 0) {
                    const unsigned char *enc_privkey = key->comp_privkey[i];
                    if (!key->oqsx_provider_ctx.oqsx_evp_ctx->evp_info
                             ->raw_key_support) {
                        //EVP_PKEY *npk;
                        key->classical_pkey = d2i_PrivateKey(
                            key->oqsx_provider_ctx.oqsx_evp_ctx->evp_info
                                ->keytype,
                            NULL, &enc_privkey, key->privkeylen_cmp[i]);
                    } else {
                        key->classical_pkey = EVP_PKEY_new_raw_private_key(
                            key->oqsx_provider_ctx.oqsx_evp_ctx->evp_info
                                ->keytype,
                            NULL, enc_privkey, key->privkeylen_cmp[i]);
                    }
                    if (!key->classical_pkey) {
                        ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                        OPENSSL_free(name);
                        goto rec_err;
                    }
                    if (!key->oqsx_provider_ctx.oqsx_evp_ctx->evp_info
                             ->raw_key_support) {
                        unsigned char *comp_pubkey = key->comp_pubkey[i];
                        int pubkeylen
                            = i2d_PublicKey(key->classical_pkey, &comp_pubkey);
                        if (pubkeylen
                            != key->oqsx_provider_ctx.oqsx_evp_ctx->evp_info
                                   ->length_public_key) {
                            ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                            OPENSSL_free(name);
                            goto rec_err;
                        }
                    } else {
                        size_t pubkeylen = key->pubkeylen_cmp[i];
                        int ret = EVP_PKEY_get_raw_public_key(
                            key->classical_pkey, key->comp_pubkey[i],
                            &pubkeylen);
                        if (ret <= 0) {
                            ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                            OPENSSL_free(name);
                            goto rec_err;
                        }
                    }
                }
                OPENSSL_free(name);
            }
        }
    } else {
        if ((key->numkeys == 2)) { // hybrid key
            int classical_pubkey_len, classical_privkey_len;
            if (!key->evp_info) {
                ERR_raise(ERR_LIB_USER, OQSPROV_R_EVPINFO_MISSING);
                goto rec_err;
            }
            if (op == KEY_OP_PUBLIC) {
                const unsigned char *enc_pubkey = key->comp_pubkey[0];
                DECODE_UINT32(classical_pubkey_len, key->pubkey);
                /* coverity: check for overflowed value */
                if (classical_pubkey_len < 1 || classical_pubkey_len > OQS_PROV_MAX_BUFFER) {
                    ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                    goto rec_err;
                }

                if (key->evp_info->raw_key_support) {
                    key->classical_pkey = EVP_PKEY_new_raw_public_key(
                        key->evp_info->keytype, NULL, enc_pubkey,
                        classical_pubkey_len);
                    if (!key->classical_pkey) {
                        ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                        goto rec_err;
                    }
                } else {
                    EVP_PKEY *npk = EVP_PKEY_new();
                    if (key->evp_info->keytype != EVP_PKEY_RSA) {
                        npk = setECParams(npk, key->evp_info->nid);
                    }
                    key->classical_pkey
                        = d2i_PublicKey(key->evp_info->keytype, &npk,
                                        &enc_pubkey, classical_pubkey_len);
                    if (!key->classical_pkey) {
                        ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                        EVP_PKEY_free(npk);
                        goto rec_err;
                    }
                }
            }
            if (op == KEY_OP_PRIVATE) {
                const unsigned char *enc_privkey = key->comp_privkey[0];
                unsigned char *enc_pubkey = key->comp_pubkey[0];
                DECODE_UINT32(classical_privkey_len, key->privkey);
                /* coverity: check for overflowed value */
                if (classical_privkey_len < 1 || classical_privkey_len > OQS_PROV_MAX_BUFFER) {
                    ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                    goto rec_err;
                }

                if (key->evp_info->raw_key_support) {
                    key->classical_pkey = EVP_PKEY_new_raw_private_key(
                        key->evp_info->keytype, NULL, enc_privkey,
                        classical_privkey_len);
                    if (!key->classical_pkey) {
                        ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                        goto rec_err;
                    }
#ifndef NOPUBKEY_IN_PRIVKEY
                    // re-create classic public key part from private key:
                    size_t pubkeylen;

                    int ret2 = EVP_PKEY_get_raw_public_key(key->classical_pkey, NULL,
                                                &pubkeylen);
                    if ( ret2 != 1 || pubkeylen != key->evp_info->length_public_key
                        || EVP_PKEY_get_raw_public_key(key->classical_pkey,
                                                       enc_pubkey, &pubkeylen)
                               != 1) {
                        ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                        goto rec_err;
                    }
#endif
                } else {
                    key->classical_pkey
                        = d2i_PrivateKey(key->evp_info->keytype, NULL,
                                         &enc_privkey, classical_privkey_len);
                    if (!key->classical_pkey) {
                        ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                        goto rec_err;
                    }
#ifndef NOPUBKEY_IN_PRIVKEY
                    // re-create classic public key part from private key:
                    int pubkeylen
                        = i2d_PublicKey(key->classical_pkey, &enc_pubkey);
                    if (pubkeylen != key->evp_info->length_public_key) {
                        ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                        goto rec_err;
                    }
#endif
                }
            }
        }
    }

    return 1;

rec_err:
    return 0;
}

OQSX_KEY *oqsx_key_from_x509pubkey(const X509_PUBKEY *xpk, OSSL_LIB_CTX *libctx,
                                   const char *propq)
{
    const unsigned char *p;
    int plen;
    X509_ALGOR *palg;
    OQSX_KEY *oqsx = NULL;
    STACK_OF(ASN1_TYPE) *sk = NULL;
    ASN1_TYPE *aType = NULL;
    //ASN1_OCTET_STRING *oct = NULL;
    const unsigned char *buf;
    unsigned char *concat_key;
    int count, aux, i, buflen;

    if (!xpk || (!X509_PUBKEY_get0_param(NULL, &p, &plen, &palg, xpk))) {
        return NULL;
    }
    if (get_keytype(OBJ_obj2nid(palg->algorithm)) == KEY_TYPE_CMP_SIG) {
        sk = d2i_ASN1_SEQUENCE_ANY(NULL, &p, plen);
        if (sk == NULL) {
            sk_ASN1_TYPE_pop_free(sk, &ASN1_TYPE_free);
            ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
            return NULL;
        } else {
            count = sk_ASN1_TYPE_num(sk);
            concat_key
                = OPENSSL_zalloc(plen); // concat_key is allocated with plen,
                                        // which is the max value for pubkey

            aux = 0;
            for (i = 0; i < count; i++) {
                aType
                    = sk_ASN1_TYPE_pop(sk); // this remove in FILO order, but we
                                            // need this in the opposite order
                buf = aType->value.sequence->data;
                buflen = aType->value.sequence->length;
                aux += buflen;
                memcpy(concat_key + plen - 1 - aux, buf,
                       buflen); // fill concat_key starting at the end
                ASN1_TYPE_free(aType);
            }

            p = OPENSSL_memdup(concat_key + plen - 1 - aux,
                               aux); // copy used memory on concat_key to p
            OPENSSL_clear_free(concat_key, plen);
            plen = aux; // update plen value
            sk_ASN1_TYPE_free(sk);
        }
    }
    oqsx = oqsx_key_op(palg, p, plen, KEY_OP_PUBLIC, libctx, propq);
    if (get_keytype(OBJ_obj2nid(palg->algorithm)) == KEY_TYPE_CMP_SIG)
        OPENSSL_clear_free((unsigned char *)p, plen);
    return oqsx;
}

OQSX_KEY *oqsx_key_from_pkcs8(const PKCS8_PRIV_KEY_INFO *p8inf,
                              OSSL_LIB_CTX *libctx, const char *propq)
{
    OQSX_KEY *oqsx = NULL;
    const unsigned char *p = NULL;
    int plen = 0;
    ASN1_OCTET_STRING *oct = NULL;
    const X509_ALGOR *palg;
    STACK_OF(ASN1_TYPE) *sk = NULL;
    ASN1_TYPE *aType = NULL;
    unsigned char *concat_key;
    const unsigned char *buf;
    int count, aux, i, buflen, key_diff = 0;
    int is_not_cmp_sig;

    if (!PKCS8_pkey_get0(NULL, &p, &plen, &palg, p8inf))
        return 0;

    is_not_cmp_sig = (get_keytype(OBJ_obj2nid(palg->algorithm)) != KEY_TYPE_CMP_SIG);
    if (is_not_cmp_sig) {
        oct = d2i_ASN1_OCTET_STRING(NULL, &p, plen);
        if (oct == NULL) {
            p = NULL;
            plen = 0;
        } else {
            p = ASN1_STRING_get0_data(oct);
            plen = ASN1_STRING_length(oct);
        }
    } else {
        sk = d2i_ASN1_SEQUENCE_ANY(NULL, &p, plen);
        if (sk == NULL) {
            sk_ASN1_TYPE_pop_free(sk, &ASN1_TYPE_free);
            ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
            return NULL;
        } else {
            count = sk_ASN1_TYPE_num(sk);
            plen = 2 * plen; // get more than necessary in case its needed
            concat_key = OPENSSL_zalloc(plen);
            PKCS8_PRIV_KEY_INFO *p8inf_internal = NULL;
            const X509_ALGOR *palg_internal;
            int keytype, nid;

            aux = 0;
            for (i = 0; i < count; i++) {
                aType
                    = sk_ASN1_TYPE_pop(sk); // this remove in FILO order, but we
                                            // need this in the opposite order
                p8inf_internal = PKCS8_PRIV_KEY_INFO_new();
                nid = 0;
                char *name;
                if ((name
                     = get_cmpname(OBJ_obj2nid(palg->algorithm), count - 1 - i))
                    == NULL) {
                    ASN1_TYPE_free(aType);
                    OPENSSL_clear_free(concat_key, plen);
                    PKCS8_PRIV_KEY_INFO_free(p8inf_internal);
                    sk_ASN1_TYPE_free(sk);
                    ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                    return NULL;
                }
                buflen = aType->value.sequence->length;
                const unsigned char *buf2 = aType->value.sequence->data;

                p8inf_internal
                    = d2i_PKCS8_PRIV_KEY_INFO(&p8inf_internal, &buf2, buflen);
                if (!PKCS8_pkey_get0(NULL, &buf, &buflen, &palg_internal,
                                     p8inf_internal)) {
                    OPENSSL_free(name);
                    ASN1_TYPE_free(aType);
                    PKCS8_PRIV_KEY_INFO_free(p8inf_internal);
                    OPENSSL_clear_free(concat_key, plen);
                    sk_ASN1_TYPE_free(sk);
                    return NULL;
                }

                keytype = OBJ_obj2nid(palg_internal->algorithm);

                // Checking OPTIONAL params on EC
                if (keytype == EVP_PKEY_EC) {
                    int j;
                    nid = OBJ_obj2nid(palg_internal->parameter->value.object);
                    for (j = 0; j < OSSL_NELEM(nids_sig); j++) {
                        if ((nids_sig[j].nid == nid)
                            && (nids_sig[j].length_private_key
                                > buflen)) { // check if the curve is the same
                                             // and if the key len is smaller
                                             // than the max key size
                            EVP_PKEY *ec_pkey;
                            OSSL_PARAM params[3];
                            int include_pub = 1;
                            const unsigned char *buf3
                                = aType->value.sequence->data;
                            unsigned char *buf4, *buf5;

                            if (buflen
                                != nids_sig[j].kex_length_secret
                                       + 7) { // no OPTIONAL ECParameter and no
                                              // OPTIONAL Pubkey
                                OPENSSL_free(name);
                                ASN1_TYPE_free(aType);
                                PKCS8_PRIV_KEY_INFO_free(p8inf_internal);
                                OPENSSL_clear_free(concat_key, plen);
                                sk_ASN1_TYPE_free(sk);
                                return NULL;
                            }
                            ec_pkey = EVP_PKEY_new();
                            d2i_PrivateKey(
                                EVP_PKEY_EC, &ec_pkey, &buf3,
                                aType->value.sequence
                                    ->length); // create a new EVP_PKEY using ec
                                               // priv key

                            // set parameters for the new priv key format
                            params[0] = OSSL_PARAM_construct_int(
                                OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC,
                                &include_pub); // add pubkey to priv key
                            params[1] = OSSL_PARAM_construct_utf8_string(
                                OSSL_PKEY_PARAM_EC_ENCODING,
                                OSSL_PKEY_EC_ENCODING_GROUP,
                                0); // add ECParam to the priv key
                            params[2] = OSSL_PARAM_construct_end();
                            EVP_PKEY_set_params(ec_pkey, params);

                            buf4 = OPENSSL_malloc(
                                nids_sig[j].length_private_key);
                            buf5 = buf4;
                            buflen = i2d_PrivateKey(
                                ec_pkey,
                                &buf5); // encode priv key including parameters

                            aux += buflen;
                            memcpy(
                                concat_key + plen - 1 - aux, buf4,
                                buflen); // fill concat_key starting at the end

                            EVP_PKEY_free(ec_pkey);
                            OPENSSL_clear_free(buf4, buflen);
                            break;
                        }
                    }
                    if (j == OSSL_NELEM(nids_sig))
                        nid = 0; // buflen is already with the correct size,
                                 // changing nid to memcpy at the end
                }

                // if is a RSA key the actual encoding size might be different
                // from max size we calculate that difference for to facilitate
                // the key reconstruction
                if (keytype == EVP_PKEY_RSA) {
                    if (name[3] == '3') // 3072
                        key_diff = nids_sig[5].length_private_key - buflen;
                    else // 2048
                        key_diff = nids_sig[6].length_private_key - buflen;
                }

                if (!nid) {
                    aux += buflen;
                    memcpy(concat_key + plen - 1 - aux, buf,
                           buflen); // fill concat_key starting at the end
                }

                OPENSSL_free(name);
                PKCS8_PRIV_KEY_INFO_free(p8inf_internal);
                ASN1_TYPE_free(aType);
            }

            p = OPENSSL_memdup(concat_key + plen - 1 - aux, aux);
            OPENSSL_clear_free(concat_key, plen);
            plen = aux; // update plen to correct size
            sk_ASN1_TYPE_free(sk);
        }
    }

    oqsx = oqsx_key_op(palg, p, plen + key_diff, KEY_OP_PRIVATE, libctx, propq);
    if (is_not_cmp_sig) {
        /* coverity: p is owned by oct */
        ASN1_OCTET_STRING_free(oct);
    } else {
        OPENSSL_clear_free((unsigned char *)p,
                           plen); // for COMPOSITE p include both privkey
    }
    return oqsx;
}

static int (*init_kex_fun[])(char *, OQSX_EVP_CTX *)
    = {oqshybkem_init_ecp, oqshybkem_init_ecx};
#ifdef USE_ENCODING_LIB
extern const char *oqs_alg_encoding_list[];
#endif
extern const char *oqs_oid_alg_list[];

static void oqsx_free_evp_ctx(OQSX_EVP_CTX *evp_ctx);

OQSX_KEY *oqsx_key_new(OSSL_LIB_CTX *libctx, char *oqs_name, char *tls_name,
                       int primitive, const char *propq, int bit_security,
                       int alg_idx)
{
    OQSX_KEY *ret = OPENSSL_zalloc(
        sizeof(*ret)); // ensure all component pointers are NULL
    OQSX_EVP_CTX *evp_ctx = NULL;
    int ret2 = 0, i;

    if (ret == NULL)
        return NULL;

#ifdef OQS_PROVIDER_NOATOMIC
    ret->lock = CRYPTO_THREAD_lock_new();
    ON_ERR_GOTO(!ret->lock, err);
#endif

    if (oqs_name == NULL) {
        OQS_KEY_PRINTF("OQSX_KEY: Fatal error: No OQS key name provided:\n");
        goto err;
    }

    if (tls_name == NULL) {
        OQS_KEY_PRINTF("OQSX_KEY: Fatal error: No TLS key name provided:\n");
        goto err;
    }

    switch (primitive) {
    case KEY_TYPE_SIG:
        ret->numkeys = 1;
        ret->comp_privkey = OPENSSL_malloc(sizeof(void *));
        ret->comp_pubkey = OPENSSL_malloc(sizeof(void *));
        ON_ERR_GOTO(!ret->comp_privkey || !ret->comp_pubkey, err);
        ret->oqsx_provider_ctx.oqsx_evp_ctx = NULL;
        ret->oqsx_provider_ctx.oqsx_qs_ctx.sig = OQS_SIG_new(oqs_name);
        if (!ret->oqsx_provider_ctx.oqsx_qs_ctx.sig) {
            fprintf(
                stderr,
                "Could not create OQS signature algorithm %s. Enabled in liboqs?\n",
                oqs_name);
            goto err;
        }

#ifdef USE_ENCODING_LIB
        if (alg_idx >= 0 && oqs_alg_encoding_list[2 * alg_idx] != NULL
            && oqs_alg_encoding_list[2 * alg_idx + 1] != NULL) {
            if (qsc_encoding_by_name_oid(&ret->oqsx_encoding_ctx.encoding_ctx,
                                         &ret->oqsx_encoding_ctx.encoding_impl,
                                         oqs_alg_encoding_list[2 * alg_idx + 1],
                                         oqs_alg_encoding_list[2 * alg_idx])
                != QSC_ENC_OK) {
                fprintf(
                    stderr,
                    "Could not create OQS signature encoding algorithm %s (%s, %s).\n",
                    oqs_alg_encoding_list[2 * alg_idx + 1], oqs_name,
                    oqs_alg_encoding_list[2 * alg_idx]);
                ret->oqsx_encoding_ctx.encoding_ctx = NULL;
                ret->oqsx_encoding_ctx.encoding_impl = NULL;
                goto err;
            }
        }
#endif
        ret->privkeylen
            = ret->oqsx_provider_ctx.oqsx_qs_ctx.sig->length_secret_key;
        ret->pubkeylen
            = ret->oqsx_provider_ctx.oqsx_qs_ctx.sig->length_public_key;
        ret->keytype = KEY_TYPE_SIG;
        break;
    case KEY_TYPE_KEM:
        ret->numkeys = 1;
        ret->comp_privkey = OPENSSL_malloc(sizeof(void *));
        ret->comp_pubkey = OPENSSL_malloc(sizeof(void *));
        ON_ERR_GOTO(!ret->comp_privkey || !ret->comp_pubkey, err);
        ret->oqsx_provider_ctx.oqsx_evp_ctx = NULL;
        ret->oqsx_provider_ctx.oqsx_qs_ctx.kem = OQS_KEM_new(oqs_name);
        if (!ret->oqsx_provider_ctx.oqsx_qs_ctx.kem) {
            fprintf(
                stderr,
                "Could not create OQS KEM algorithm %s. Enabled in liboqs?\n",
                oqs_name);
            goto err;
        }
        ret->privkeylen
            = ret->oqsx_provider_ctx.oqsx_qs_ctx.kem->length_secret_key;
        ret->pubkeylen
            = ret->oqsx_provider_ctx.oqsx_qs_ctx.kem->length_public_key;
        ret->keytype = KEY_TYPE_KEM;
        break;
    case KEY_TYPE_ECX_HYB_KEM:
    case KEY_TYPE_ECP_HYB_KEM:
        ret->oqsx_provider_ctx.oqsx_qs_ctx.kem = OQS_KEM_new(oqs_name);
        if (!ret->oqsx_provider_ctx.oqsx_qs_ctx.kem) {
            fprintf(
                stderr,
                "Could not create OQS KEM algorithm %s. Enabled in liboqs?\n",
                oqs_name);
            goto err;
        }
        evp_ctx = OPENSSL_zalloc(sizeof(OQSX_EVP_CTX));
        ON_ERR_GOTO(!evp_ctx, err);

        ret2 = (init_kex_fun[primitive - KEY_TYPE_ECP_HYB_KEM])(tls_name,
                                                                evp_ctx);
        ON_ERR_GOTO(ret2 <= 0 || !evp_ctx->keyParam || !evp_ctx->ctx, err);

        ret->numkeys = 2;
        ret->comp_privkey = OPENSSL_malloc(ret->numkeys * sizeof(void *));
        ret->comp_pubkey = OPENSSL_malloc(ret->numkeys * sizeof(void *));
        ON_ERR_GOTO(!ret->comp_privkey || !ret->comp_pubkey, err);
        ret->privkeylen
            = (ret->numkeys - 1) * SIZE_OF_UINT32
              + ret->oqsx_provider_ctx.oqsx_qs_ctx.kem->length_secret_key
              + evp_ctx->evp_info->length_private_key;
        ret->pubkeylen
            = (ret->numkeys - 1) * SIZE_OF_UINT32
              + ret->oqsx_provider_ctx.oqsx_qs_ctx.kem->length_public_key
              + evp_ctx->evp_info->length_public_key;
        ret->oqsx_provider_ctx.oqsx_evp_ctx = evp_ctx;
        ret->keytype = primitive;
        ret->evp_info = evp_ctx->evp_info;
        evp_ctx = NULL; /* ret takes ownership of evp_ctx */
        break;
    case KEY_TYPE_HYB_SIG:
        ret->oqsx_provider_ctx.oqsx_qs_ctx.sig = OQS_SIG_new(oqs_name);
        if (!ret->oqsx_provider_ctx.oqsx_qs_ctx.sig) {
            fprintf(
                stderr,
                "Could not create OQS signature algorithm %s. Enabled in liboqs?\n",
                oqs_name);
            goto err;
        }
        evp_ctx = OPENSSL_zalloc(sizeof(OQSX_EVP_CTX));
        ON_ERR_GOTO(!evp_ctx, err);

        ret2 = oqsx_hybsig_init(bit_security, evp_ctx, tls_name);
        ON_ERR_GOTO(ret2 <= 0 || !evp_ctx->ctx, err);

        ret->numkeys = 2;
        ret->comp_privkey = OPENSSL_malloc(ret->numkeys * sizeof(void *));
        ret->comp_pubkey = OPENSSL_malloc(ret->numkeys * sizeof(void *));
        ON_ERR_GOTO(!ret->comp_privkey || !ret->comp_pubkey, err);
        ret->privkeylen
            = (ret->numkeys - 1) * SIZE_OF_UINT32
              + ret->oqsx_provider_ctx.oqsx_qs_ctx.sig->length_secret_key
              + evp_ctx->evp_info->length_private_key;
        ret->pubkeylen
            = (ret->numkeys - 1) * SIZE_OF_UINT32
              + ret->oqsx_provider_ctx.oqsx_qs_ctx.sig->length_public_key
              + evp_ctx->evp_info->length_public_key;
        ret->oqsx_provider_ctx.oqsx_evp_ctx = evp_ctx;
        ret->keytype = primitive;
        ret->evp_info = evp_ctx->evp_info;
        evp_ctx = NULL; /* ret takes ownership of evp_ctx */
        break;
    case KEY_TYPE_CMP_SIG:
        ret->numkeys = 2;
        ret->privkeylen = 0;
        ret->pubkeylen = 0;
        ret->privkeylen_cmp = OPENSSL_malloc(ret->numkeys * sizeof(size_t));
        ret->pubkeylen_cmp = OPENSSL_malloc(ret->numkeys * sizeof(size_t));
        ret->comp_privkey = OPENSSL_malloc(ret->numkeys * sizeof(void *));
        ret->comp_pubkey = OPENSSL_malloc(ret->numkeys * sizeof(void *));

        for (i = 0; i < ret->numkeys; i++) {
            char *name;
            if ((name = get_cmpname(OBJ_sn2nid(tls_name), i)) == NULL) {
                ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                goto err;
            }
            if (get_oqsname_fromtls(name) != 0) {
                ret->oqsx_provider_ctx.oqsx_qs_ctx.sig
                    = OQS_SIG_new(get_oqsname_fromtls(name));
                if (!ret->oqsx_provider_ctx.oqsx_qs_ctx.sig) {
                    fprintf(
                        stderr,
                        "Could not create OQS signature algorithm %s. Enabled in liboqs?A\n",
                        name);
                    goto err;
                }
                ret->privkeylen_cmp[i]
                    = ret->oqsx_provider_ctx.oqsx_qs_ctx.sig->length_secret_key;
                ret->pubkeylen_cmp[i]
                    = ret->oqsx_provider_ctx.oqsx_qs_ctx.sig->length_public_key;
            } else {
                evp_ctx = OPENSSL_zalloc(sizeof(OQSX_EVP_CTX));
                ON_ERR_GOTO(!evp_ctx, err);

                ret2 = oqsx_hybsig_init(bit_security, evp_ctx, name);
                ON_ERR_GOTO(ret2 <= 0 || !evp_ctx->ctx, err);

                oqsx_free_evp_ctx(ret->oqsx_provider_ctx.oqsx_evp_ctx);
                ret->oqsx_provider_ctx.oqsx_evp_ctx = evp_ctx;
                ret->privkeylen_cmp[i] = ret->oqsx_provider_ctx.oqsx_evp_ctx
                                             ->evp_info->length_private_key;
                ret->pubkeylen_cmp[i] = ret->oqsx_provider_ctx.oqsx_evp_ctx
                                            ->evp_info->length_public_key;
                evp_ctx = NULL; /* ret takes ownership of evp_ctx */
            }
            ret->privkeylen += ret->privkeylen_cmp[i];
            ret->pubkeylen += ret->pubkeylen_cmp[i];
            OPENSSL_free(name);
        }
        ret->keytype = primitive;

        break;
    default:
        OQS_KEY_PRINTF2("OQSX_KEY: Unknown key type encountered: %d\n",
                        primitive);
        goto err;
    }

    ret->libctx = libctx;
    ret->references = 1;
    ret->tls_name = OPENSSL_strdup(tls_name);
    ON_ERR_GOTO(!ret->tls_name, err);
    ret->bit_security = bit_security;

    if (propq != NULL) {
        ret->propq = OPENSSL_strdup(propq);
        ON_ERR_GOTO(!ret->propq, err);
    }

    ret->lunakeyctx = LUNA_OQS_malloc_from_oqs(ret, tls_name);
    if (ret->lunakeyctx == NULL)
        goto err;

    OQS_KEY_PRINTF2("OQSX_KEY: new key created: %s\n", ret->tls_name);
    OQS_KEY_PRINTF3("OQSX_KEY: new key created: %p (type: %d)\n", ret,
                    ret->keytype);
    return ret;
err:
    ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
#ifdef OQS_PROVIDER_NOATOMIC
    if (ret->lock)
        CRYPTO_THREAD_lock_free(ret->lock);
#endif
    OPENSSL_free(ret->tls_name);
    OPENSSL_free(ret->propq);
    OPENSSL_free(ret->comp_privkey);
    OPENSSL_free(ret->comp_pubkey);
    if (ret->privkeylen_cmp != NULL)
        OPENSSL_free(ret->privkeylen_cmp);
    if (ret->pubkeylen_cmp != NULL)
        OPENSSL_free(ret->pubkeylen_cmp);
    oqsx_free_evp_ctx(ret->oqsx_provider_ctx.oqsx_evp_ctx);
    OPENSSL_free(ret);
    /* coverity: memory leak evp_ctx ? */
    oqsx_free_evp_ctx(evp_ctx);
    return NULL;
}

static void oqsx_free_evp_ctx(OQSX_EVP_CTX *evp_ctx) {
    if (evp_ctx == NULL)
        return;
    if (evp_ctx->ctx != NULL) {
        EVP_PKEY_CTX_free(evp_ctx->ctx);
        evp_ctx->ctx = NULL;
    }
    if (evp_ctx->keyParam != NULL) {
        EVP_PKEY_free(evp_ctx->keyParam);
        evp_ctx->keyParam = NULL;
    }
    OPENSSL_free(evp_ctx);
}

void oqsx_key_free(OQSX_KEY *key)
{
    int refcnt;
    if (key == NULL)
        return;

#ifndef OQS_PROVIDER_NOATOMIC
    refcnt
        = atomic_fetch_sub_explicit(&key->references, 1, memory_order_relaxed)
          - 1;
    if (refcnt == 0)
        atomic_thread_fence(memory_order_acquire);
#else
    CRYPTO_atomic_add(&key->references, -1, &refcnt, key->lock);
#endif

    OQS_KEY_PRINTF3("%p:%4d:OQSX_KEY\n", (void *)key, refcnt);
    if (refcnt > 0)
        return;
#ifndef NDEBUG
    assert(refcnt == 0);
#endif

    LUNA_OQS_free(key->lunakeyctx);
    key->lunakeyctx = 0;

    OPENSSL_free(key->propq);
    OPENSSL_free(key->tls_name);
    OPENSSL_secure_clear_free(key->privkey, key->privkeylen);
    OPENSSL_secure_clear_free(key->pubkey, key->pubkeylen);
    OPENSSL_free(key->comp_pubkey);
    OPENSSL_free(key->comp_privkey);
    if (key->keytype == KEY_TYPE_CMP_SIG) {
        OPENSSL_free(key->privkeylen_cmp);
        OPENSSL_free(key->pubkeylen_cmp);
    }
    if (key->keytype == KEY_TYPE_KEM)
        OQS_KEM_free(key->oqsx_provider_ctx.oqsx_qs_ctx.kem);
    else if (key->keytype == KEY_TYPE_ECP_HYB_KEM
             || key->keytype == KEY_TYPE_ECX_HYB_KEM) {
        OQS_KEM_free(key->oqsx_provider_ctx.oqsx_qs_ctx.kem);
    } else
        OQS_SIG_free(key->oqsx_provider_ctx.oqsx_qs_ctx.sig);
    EVP_PKEY_free(key->classical_pkey);
    oqsx_free_evp_ctx(key->oqsx_provider_ctx.oqsx_evp_ctx);

#ifdef OQS_PROVIDER_NOATOMIC
    CRYPTO_THREAD_lock_free(key->lock);
#endif
    OPENSSL_free(key);
}

int oqsx_key_up_ref(OQSX_KEY *key)
{
    int refcnt;

#ifndef OQS_PROVIDER_NOATOMIC
    refcnt
        = atomic_fetch_add_explicit(&key->references, 1, memory_order_relaxed)
          + 1;
#else
    CRYPTO_atomic_add(&key->references, 1, &refcnt, key->lock);
#endif

    OQS_KEY_PRINTF3("%p:%4d:OQSX_KEY\n", (void *)key, refcnt);
#ifndef NDEBUG
    assert(refcnt > 1);
#endif
    return (refcnt > 1);
}

int oqsx_key_allocate_keymaterial(OQSX_KEY *key, int include_private)
{
    int ret = 0, aux = 0;

    if (key->keytype != KEY_TYPE_CMP_SIG)
        aux = SIZE_OF_UINT32;

    if (!key->privkey && include_private) {
        ON_ERR_SET_GOTO( (key->privkeylen > OQS_PROV_MAX_BUFFER) , ret, 1, err_alloc);
        key->privkey = OPENSSL_secure_zalloc(key->privkeylen + aux);
        ON_ERR_SET_GOTO(!key->privkey, ret, 1, err_alloc);
    }
    if (!key->pubkey && !include_private) {
        key->pubkey = OPENSSL_secure_zalloc(key->pubkeylen);
        ON_ERR_SET_GOTO(!key->pubkey, ret, 1, err_alloc);
    }
err_alloc:
    return ret;
}

int oqsx_key_fromdata(OQSX_KEY *key, const OSSL_PARAM params[],
                      int include_private)
{
    const OSSL_PARAM *pp1, *pp2;

    OQS_KEY_PRINTF("OQSX Key from data called\n");
    pp1 = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
    pp2 = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
    // at least one parameter must be given
    if (pp1 == NULL && pp2 == NULL) {
        ERR_raise(ERR_LIB_USER, OQSPROV_R_WRONG_PARAMETERS);
        return 0;
    }
    if (pp1 != NULL) {
        if (pp1->data_type != OSSL_PARAM_OCTET_STRING) {
            ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
            return 0;
        }
        if (key->privkeylen != pp1->data_size) {
            ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_SIZE);
            return 0;
        }
        OPENSSL_secure_clear_free(key->privkey, pp1->data_size);
        key->privkey = OPENSSL_secure_malloc(pp1->data_size);
        if (key->privkey == NULL) {
            ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        memcpy(key->privkey, pp1->data, pp1->data_size);
    }
    if (pp2 != NULL) {
        if (pp2->data_type != OSSL_PARAM_OCTET_STRING) {
            OQS_KEY_PRINTF("invalid data type\n");
            return 0;
        }
        if (key->pubkeylen != pp2->data_size) {
            ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_SIZE);
            return 0;
        }
        OPENSSL_secure_clear_free(key->pubkey, pp2->data_size);
        key->pubkey = OPENSSL_secure_malloc(pp2->data_size);
        if (key->pubkey == NULL) {
            ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        memcpy(key->pubkey, pp2->data, pp2->data_size);
    }
    if (!oqsx_key_set_composites(key)
        || !oqsx_key_recreate_classickey(
            key, key->privkey != NULL ? KEY_OP_PRIVATE : KEY_OP_PUBLIC))
        return 0;
    return 1;
}

// OQS key always the last of the numkeys comp keys
static int lunax_oqsx_key_gen_oqs_ndx(OQSX_KEY *key, int ndx_in, int is_kem, int is_hybrid,
        int is_composite, int is_delegated) {
    int rc = 0;
    int ndx = ndx_in;
    luna_prov_key_bits foo = {0};

    // check for special value
    if (ndx == -1)
        ndx = (key->numkeys - 1);

    foo.ndx = ndx;
    foo.is_kem = is_kem;
    foo.is_hybrid = is_hybrid;
    foo.is_composite = is_composite;
    foo.is_delegated = is_delegated;
    foo.ok = 1;

    if ( is_kem ) {
        if ( (is_delegated == 0) && (LUNA_OQS_QUERY_KEM_keypair(key->lunakeyctx) == LUNA_OQS_OK) ) {
            rc = LUNA_OQS_KEM_keypair(key->lunakeyctx, &foo);

        } else {
            rc = OQS_KEM_keypair(key->oqsx_provider_ctx.oqsx_qs_ctx.kem, key->comp_pubkey[ndx], key->comp_privkey[ndx]);
        }

    } else {
        if (LUNA_OQS_QUERY_SIG_keypair(key->lunakeyctx) == LUNA_OQS_OK) {
            rc = LUNA_OQS_SIG_keypair(key->lunakeyctx, &foo);

        } else {
            rc = OQS_SIG_keypair(key->oqsx_provider_ctx.oqsx_qs_ctx.sig, key->comp_pubkey[ndx], key->comp_privkey[ndx]);
        }
    }

    return rc;
}

/* Generate classic keys, store length in leading SIZE_OF_UINT32 bytes of
 * pubkey/privkey buffers; returned EVP_PKEY must be freed if not used
 */
static EVP_PKEY *lunax_oqsx_key_gen_evp_key(OQSX_EVP_CTX *ctx, unsigned char *pubkey,
                                      unsigned char *privkey, int encode,
                                      int flagPqcKeyInHardware, int flagPqcKeyPersistent)
{
    int ret = 0, ret2 = 0, aux = 0;

    // Free at errhyb:
    EVP_PKEY_CTX *kgctx = NULL;
    EVP_PKEY *pkey = NULL;
    unsigned char *pubkey_encoded = NULL;

    size_t pubkeylen = 0, privkeylen = 0;

    int lunaflags = flagPqcKeyPersistent ? 0 : LUNA_PROV_FLAGS_SESSION_OBJECT;

    if (encode) { // hybrid
        aux = SIZE_OF_UINT32;
    }

    if (ctx->keyParam)
        kgctx = EVP_PKEY_CTX_new(ctx->keyParam, NULL);
    else
        kgctx = EVP_PKEY_CTX_new_id(ctx->evp_info->nid, NULL);
    ON_ERR_SET_GOTO(!kgctx, ret, -1, errhyb);

    ret2 = EVP_PKEY_keygen_init(kgctx);
    ON_ERR_SET_GOTO(ret2 <= 0, ret, -1, errhyb);
    if (ctx->evp_info->keytype == EVP_PKEY_RSA) {
        if (ctx->evp_info->length_public_key > 270) {
            ret2 = EVP_PKEY_CTX_set_rsa_keygen_bits(kgctx, 3072);
        } else {
            ret2 = EVP_PKEY_CTX_set_rsa_keygen_bits(kgctx, 2048);
        }
        ON_ERR_SET_GOTO(ret2 <= 0, ret, -1, errhyb);
    }

    /* NOTE: derive using a private key, will not work for hardware keys, unless
     * the engine implements the EC 'compute_key' method,
     * AND the engine generates the EC keypair as temporary (session) objects,
     * AND this provider checks that the PQC part of the KEM algorithm is also implemented in hardware.
     * For now, we force this temporary EC keypair to software; i.e.,
     * override engine setting EnableEcGenKeyPair, which is meant for persistent (token) objects.
     */
    LUNA_PRINTF(("EVP_PKEY_keygen\n"));
    if (flagPqcKeyInHardware == 0)
        lunaflags |= LUNA_PROV_FLAGS_SOFTWARE_OBJECT;
    ret2 = lunax_oqsx_EVP_PKEY_keygen_ex(kgctx, &pkey, lunaflags);
    ON_ERR_SET_GOTO(ret2 <= 0, ret, -2, errhyb);

    if (ctx->evp_info->raw_key_support) {
        // TODO: If available, use preallocated memory
        if (ctx->evp_info->nid != NID_ED25519
            && ctx->evp_info->nid != NID_ED448) {
            pubkeylen = EVP_PKEY_get1_encoded_public_key(pkey, &pubkey_encoded);
            ON_ERR_SET_GOTO(pubkeylen != ctx->evp_info->length_public_key
                                || !pubkey_encoded,
                            ret, -3, errhyb);
            memcpy(pubkey + aux, pubkey_encoded, pubkeylen);
        } else {
            pubkeylen = ctx->evp_info->length_public_key;
            ret2 = EVP_PKEY_get_raw_public_key(pkey, pubkey + aux, &pubkeylen);
            ON_ERR_SET_GOTO(
                ret2 <= 0 || pubkeylen != ctx->evp_info->length_public_key, ret,
                -3, errhyb);
        }
        privkeylen = ctx->evp_info->length_private_key;
        ret2 = EVP_PKEY_get_raw_private_key(pkey, privkey + aux, &privkeylen);
        ON_ERR_SET_GOTO(ret2 <= 0
                            || privkeylen != ctx->evp_info->length_private_key,
                        ret, -4, errhyb);
    } else {
        unsigned char *pubkey_enc = pubkey + aux;
        //const unsigned char *pubkey_enc2 = pubkey + aux;
        pubkeylen = i2d_PublicKey(pkey, &pubkey_enc);
        ON_ERR_SET_GOTO(
            !pubkey_enc || pubkeylen > (int)ctx->evp_info->length_public_key,
            ret, -11, errhyb);
        unsigned char *privkey_enc = privkey + aux;
        const unsigned char *privkey_enc2 = privkey + aux;
        privkeylen = i2d_PrivateKey(pkey, &privkey_enc);
        ON_ERR_SET_GOTO(
            !privkey_enc || privkeylen > (int)ctx->evp_info->length_private_key,
            ret, -12, errhyb);
        // selftest:
        EVP_PKEY *ck2 = d2i_PrivateKey(ctx->evp_info->keytype, NULL,
                                       &privkey_enc2, privkeylen);
        ON_ERR_SET_GOTO(!ck2, ret, -14, errhyb);
        EVP_PKEY_free(ck2);
    }
    if (encode) {
        ENCODE_UINT32(pubkey, pubkeylen);
        ENCODE_UINT32(privkey, privkeylen);
    }
    OQS_KEY_PRINTF3(
        "OQSKM: Storing classical privkeylen: %ld & pubkeylen: %ld\n",
        privkeylen, pubkeylen);

    EVP_PKEY_CTX_free(kgctx);
    OPENSSL_free(pubkey_encoded);
    return pkey;

errhyb:
    EVP_PKEY_CTX_free(kgctx);
    EVP_PKEY_free(pkey);
    OPENSSL_free(pubkey_encoded);
    return NULL;
}

/* allocates OQS and classical keys */
int oqsx_key_gen(OQSX_KEY *key)
{
    int ret = 0;
    EVP_PKEY *pkey = NULL;

    if (key->privkey == NULL || key->pubkey == NULL) {
        ret = oqsx_key_allocate_keymaterial(key, 0)
              || oqsx_key_allocate_keymaterial(key, 1);
        ON_ERR_GOTO(ret, err_gen);
    }

    if (key->keytype == KEY_TYPE_KEM) {
        ret = !oqsx_key_set_composites(key);
        ON_ERR_GOTO(ret, err_gen);
        ret = lunax_oqsx_key_gen_oqs_ndx(key, -1, 1, 0, 0, 0);
    } else if (key->keytype == KEY_TYPE_ECP_HYB_KEM
               || key->keytype == KEY_TYPE_ECX_HYB_KEM
               || key->keytype == KEY_TYPE_HYB_SIG) {
        const int flagPqcKeyInHardware = (LUNA_OQS_QUERY_KEM_keypair(key->lunakeyctx) == LUNA_OQS_OK);
        const int flagPqcKeyPersistent = (key->keytype == KEY_TYPE_HYB_SIG);
        const int flagKem = (key->keytype == KEY_TYPE_ECP_HYB_KEM || key->keytype == KEY_TYPE_ECX_HYB_KEM);
        const int flagHybrid = 1;
        const int flagDelegatable = (key->keytype == KEY_TYPE_ECP_HYB_KEM);
        const int flagDelegate = 0; /* FIXME:FIXME: luna_get_DelegateHwPqcKemEncapToSw(); */
        pkey = lunax_oqsx_key_gen_evp_key(key->oqsx_provider_ctx.oqsx_evp_ctx,
                                    key->pubkey, key->privkey, 1,
                                    flagPqcKeyInHardware, flagPqcKeyPersistent);
        ON_ERR_GOTO(pkey == NULL, err_gen);
        ret = !oqsx_key_set_composites(key);
        ON_ERR_GOTO(ret, err_gen);
        OQS_KEY_PRINTF3("OQSKM: OQSX_KEY privkeylen %ld & pubkeylen: %ld\n",
                        key->privkeylen, key->pubkeylen);

        key->classical_pkey = pkey;
        /* check DelegateHwPqcKemEncapToSw  */
        if (flagPqcKeyInHardware && !flagPqcKeyPersistent && flagKem && flagHybrid
                && flagDelegatable && flagDelegate) {
            ret = lunax_oqsx_key_gen_oqs_ndx(key, -1, flagKem, flagHybrid, 0, 1);
        } else {
            ret = lunax_oqsx_key_gen_oqs_ndx(key, -1, flagKem, flagHybrid, 0, 0);
        }

    } else if (key->keytype == KEY_TYPE_CMP_SIG) {
        int i;
        ret = oqsx_key_set_composites(key);
        for (i = 0; i < key->numkeys; i++) {
            char *name;
            if ((name = get_cmpname(OBJ_sn2nid(key->tls_name), i)) == NULL) {
                goto err_gen;
            }
            if (get_oqsname_fromtls(name) == 0) {
                const int flagPqcKeyInHardware = (LUNA_OQS_QUERY_KEM_keypair(key->lunakeyctx) == LUNA_OQS_OK);
                const int flagPqcKeyPersistent = (key->keytype == KEY_TYPE_CMP_SIG);
                pkey = lunax_oqsx_key_gen_evp_key(key->oqsx_provider_ctx.oqsx_evp_ctx,
                                            key->comp_pubkey[i],
                                            key->comp_privkey[i], 0,
                                            flagPqcKeyInHardware, flagPqcKeyPersistent);
                OPENSSL_free(name);
                ON_ERR_GOTO(pkey == NULL, err_gen);
                key->classical_pkey = pkey;
            } else {
                //ret = OQS_SIG_keypair(key->oqsx_provider_ctx.oqsx_qs_ctx.sig,
                //                      key->comp_pubkey[i],
                //                      key->comp_privkey[i]);
                ret = lunax_oqsx_key_gen_oqs_ndx(key, i, 0, 0, 1, 0);
                OPENSSL_free(name);
                ON_ERR_GOTO(ret, err_gen);
            }
        }

    } else if (key->keytype == KEY_TYPE_SIG) {
        ret = !oqsx_key_set_composites(key);
        ON_ERR_GOTO(ret, err_gen);
        ret = lunax_oqsx_key_gen_oqs_ndx(key, -1, 0, 0, 0, 0);
    } else {
        ret = 1;
    }
err_gen:
    if (ret) {
        EVP_PKEY_free(pkey);
        key->classical_pkey = NULL;
    }
    return ret;
}

int oqsx_key_secbits(OQSX_KEY *key)
{
    int bit_security = (int)(unsigned int)key->bit_security;
    return bit_security;
}

int oqsx_key_maxsize(OQSX_KEY *key)
{
    /* coverity: Overflowed or truncated value(s) */
    switch (key->keytype) {
    case KEY_TYPE_KEM:
        return key->oqsx_provider_ctx.oqsx_qs_ctx.kem->length_shared_secret;
    case KEY_TYPE_ECP_HYB_KEM:
    case KEY_TYPE_ECX_HYB_KEM:
        return key->oqsx_provider_ctx.oqsx_evp_ctx->evp_info->kex_length_secret
               + key->oqsx_provider_ctx.oqsx_qs_ctx.kem->length_shared_secret;
    case KEY_TYPE_SIG:
        return key->oqsx_provider_ctx.oqsx_qs_ctx.sig->length_signature;
    case KEY_TYPE_HYB_SIG:
        return key->oqsx_provider_ctx.oqsx_qs_ctx.sig->length_signature
               + key->oqsx_provider_ctx.oqsx_evp_ctx->evp_info->length_signature
               + SIZE_OF_UINT32;
    case KEY_TYPE_CMP_SIG:
        return sizeof(CompositeSignature)
               + key->oqsx_provider_ctx.oqsx_evp_ctx->evp_info->length_signature
               + key->oqsx_provider_ctx.oqsx_qs_ctx.sig->length_signature;

    default:
        OQS_KEY_PRINTF("OQSX KEY: Wrong key type\n");
        return 0;
    }
}

int oqsx_key_get_oqs_public_key_len(OQSX_KEY *k)
{
    /* coverity: Overflowed or truncated value(s) */
    switch (k->keytype) {
    case KEY_TYPE_SIG:
    case KEY_TYPE_KEM:
        return k->pubkeylen;
    case KEY_TYPE_HYB_SIG:
        return k->oqsx_provider_ctx.oqsx_qs_ctx.sig->length_public_key;
    case KEY_TYPE_ECX_HYB_KEM:
    case KEY_TYPE_ECP_HYB_KEM:
        return k->oqsx_provider_ctx.oqsx_qs_ctx.kem->length_public_key;
    default:
        OQS_KEY_PRINTF2("OQSX_KEY: Unknown key type encountered: %d\n",
                        k->keytype);
        return -1;
    }
}

/* luna wrapper function for EVP_PKEY_keygen; to override CKA_TOKEN, etc */
int lunax_oqsx_EVP_PKEY_keygen_ex(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey, int lunaflags)
{
    if (lunaflags != 0) {
        /* do something (affect ctx) to override CKA_TOKEN, etc */
        OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };
        params[0] = OSSL_PARAM_construct_int(LUNA_PROV_PKEY_PARAM_FLAGS, &lunaflags);
        if (EVP_PKEY_CTX_set_params(ctx, params) <= 0)
            return 0;
    }
    return EVP_PKEY_keygen(ctx, ppkey);
}
