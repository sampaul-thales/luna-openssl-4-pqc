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

/* AIX: _POSIX_SOURCE, _XOPEN_SOURCE_EXTENDED */
#if defined(OS_AIX) || defined(AIX) || defined(_AIX)
#define _POSIX_SOURCE (1)
#define _XOPEN_SOURCE_EXTENDED (1)
#endif /* AIX */

/* NOTE: if OS_WIN32 defined then Windows platform; otherwise, UNIX platform */

/* headers (system) */
#ifdef OS_WIN32
#include <windows.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

#ifdef OS_WIN32
#include <conio.h>
#include <sys/types.h>
#include <sys/stat.h>
#define LOCAL_SLEEP(__sec) Sleep(__sec)
#else /* OS_WIN32 */
#include <fcntl.h>
#include <termios.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/stat.h>
#define LOCAL_SLEEP(__sec) sleep(__sec)
#endif /* OS_WIN32 */

/* headers (openssl) */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/opensslconf.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
/* internal: #include <openssl/dso.h> */

#ifndef OPENSSL_NO_RSA
#include <openssl/rsa.h>
#endif /* OPENSSL_NO_RSA */
#ifndef OPENSSL_NO_DSA
#include <openssl/dsa.h>
#endif /* OPENSSL_NO_DSA */

/* assert version is 1.0.0 or higher */
#if (OPENSSL_VERSION_NUMBER < 0x10000000L)
#error "OpenSSL version is too old for this source code!"
#endif

/* detect ecdsa (minimum version is 0.9.8l or fips 1.2.3) */
#if (1) && (OPENSSL_VERSION_NUMBER >= 0x00908060L) && !defined(OPENSSL_NO_ECDSA) && !defined(OPENSSL_NO_EC)
#define LUNA_OSSL_ECDSA (1)
#endif /* OPENSSL_NO_ECDSA... */

/* detect Diffie-Hellman */
/* NOTE: Diffie-Hellman (DH) is not supported via gem engine. */
#if (0) && !defined(OPENSSL_NO_DH)
#define LUNA_OSSL_DH (1)
#endif /* OPENSSL_NO_DH... */

/* detect openssl3 */
#if (1) && (OPENSSL_VERSION_NUMBER >= 0x30000000L)
#define LUNA_OSSL3 (1)
#endif

/* detect OPENSSL_cleanup (1.1.0 and up) */
#if (1) && (OPENSSL_VERSION_NUMBER >= 0x10100000L)
#define LUNA_OSSL_CLEANUP (1)
#endif

/* detect pqc */
#if (1) && defined(LUNA_OSSL3)
#define LUNA_OSSL_PQC (1)
#endif

#if defined(LUNA_OSSL_ECDSA)
/* internal: #include <openssl/ec_lcl.h> */
/* internal: #include <openssl/ecs_locl.h> */
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#endif /* LUNA_OSSL_ECDSA */

#if defined(LUNA_OSSL_PQC)
#include <openssl/provider.h>
#endif

/* headers (luna) */
#include "e_gem.h"
#include "e_gem_compat.h"
#include "sautil.h"

#ifdef LUNA_OSSL_PQC
/* openssl security level 2 */
#define LOCAL_RSA_KEYSIZE_MIN (2048)
#define LOCAL_DSA_KEYSIZE_MIN (2048)
#define LOCAL_DSA_QBITS_MIN (224)
#define LOCAL_EC_KEYSIZE_MIN (224)
#else /* LUNA_OSSL_PQC */
/* openssl security level 1 */
#define LOCAL_RSA_KEYSIZE_MIN (1024)
#define LOCAL_DSA_KEYSIZE_MIN (1024)
#define LOCAL_DSA_QBITS_MIN (224)
#define LOCAL_EC_KEYSIZE_MIN (160)
#endif /* LUNA_OSSL_PQC */

/* Support C or C++ compiler in the field */
#ifdef __cplusplus
extern "C" {
#endif

/* For Code Warrior */
#if 0
}
#endif

/*****************************************************************************/

#define LOCAL_APP_NAME "sautil"
#define LOCAL_APP_VERSION_BASE "v3.1.0-1"
#if defined(LUNA_OSSL_PQC)
#define LOCAL_APP_VERSION LOCAL_APP_VERSION_BASE "pqc"
#else
#define LOCAL_APP_VERSION LOCAL_APP_VERSION_BASE
#endif
#define LOCAL_APP_COPYRIGHT "2009-2024"
#define LOCAL_APPID_NOT_USING(_h, _l) (((_h) == 0) || ((_l) == 0))

static int sautil_getopt(int argc, char *const argv[], const char *optstring);
static char *sautil_optarg = 0;

/* Local defs */
#undef CA3UTIL_DIFFIE_HELLMAN /* NOTE: defunct */
#define LUNA_MAX_LABEL (32)   /* 32 = maximum length of padded token label */
#define LUNA_MIN_LABEL (7)    /* 7 = minimum label length enforced by this app */
#define LUNA_MIN_PASSWORD (4) /* 4 = minimum password length enforced by this app, though the HSM may enforce a higher length */

#define LUNA_MAX_STRING_LEN (256) /* 256 = large enough for most strings, including password */
#define LUNA_MAX_LINE_LEN (1024)  /* 1024 = maximum line length based on luna conf file */

/* Macros */
#define LUNA_DIM(a__) (sizeof(a__) / sizeof((a__)[0]))
#define LUNA_MIN(a__, b__) (((a__) < (b__)) ? (a__) : (b__))
#define LUNA_DIFF(a__, b__) (((a__) < (b__)) ? ((b__) - (a__)) : ((a__) - (b__)))

/* Macros */
#define LUNACA3err(_foonum1, _foonum2) \
   do {                                \
      fprintf(stderr, "ERROR: ");      \
   } while (0)
#define ERR_add_error_data(_foonum1, _foosz1)     \
   do {                                           \
      fprintf(stderr, "%s. \n", (char *)_foosz1); \
   } while (0)
#define ERR_add_error_data2(_foonum1, _foosz1, _foosz2)              \
   do {                                                              \
      fprintf(stderr, "%s%s. \n", (char *)_foosz1, (char *)_foosz2); \
   } while (0)
#define LUNA_ERRORLOG(_foosz1) \
   do {                        \
   } while (0)
#define LUNA_ERRORLOGL(_foosz1, _foonum1) \
   do {                                   \
   } while (0)
#define LUNA_malloc malloc
#define LUNA_free free

/* Macros */
#define SAUTIL_ASSERT(_expr) \
    ((!(_expr)) ? (fprintf(stderr, "SAUTIL_ASSERT: %s: %u: %s.\n", __FILE__, __LINE__, #_expr), (exit(-1), -1)) : 0)

/* Definitions for managing session contexts */
typedef struct {
   int flagInit;               /* flag; true if valid */
   CK_SESSION_HANDLE hSession; /* the session handle */
} luna_context_t;

#define LUNA_CONTEXT_T_INIT \
   { 0, 0 }

/* Forward references */
static int luna_restore_keyfile(CK_SLOT_ID slotid, CK_OBJECT_HANDLE pub_handle, char *keypair_fname, char *szkeytype);

int loggedin(CK_SLOT_ID slotid);

static int luna_select_key(CK_SESSION_HANDLE session_handle, CK_OBJECT_HANDLE *hout, char *szkeytype);

static void sautil_sprint_unique(char *szPubLabel, size_t pubsize,
        char *szPrivLabel, size_t privsize,
        const char *szKeytype, unsigned uKeysize);

static CK_RV sautil_sha1_prng(CK_SESSION_HANDLE session_handle, CK_BYTE_PTR baSha1);

#if defined(LUNA_OSSL_ECDSA)
static int op_generate_ecdsa_key_pair(CK_SLOT_ID slotid, CK_USHORT modulussize, char *keypair_fname, char *param_fname);

static int write_pem_ecdsa_key_pair(CK_SESSION_HANDLE session_handle, CK_OBJECT_HANDLE pub_handle,
                                    CK_OBJECT_HANDLE priv_handle, char *keypair_fname);

static CK_OBJECT_HANDLE luna_find_ecdsa_handle(luna_context_t *ctx, EC_KEY *dsa, int flagPrivate);

static int op_delete_ecdsa_key_pair(CK_SLOT_ID slotid, char *keypair_fname);
#endif /* LUNA_OSSL_ECDSA */

#if defined(LUNA_OSSL_PQC)
static CK_OBJECT_HANDLE luna_find_pqc_handle(luna_context_t *ctx, EVP_PKEY *dsa, int flagPrivate);
static int op_delete_pqc_key_pair(CK_SLOT_ID slotid, char *keypair_fname);
static const char *sautil_provider_load(OSSL_PROVIDER **pprov);
static const char *sautil_provider_unload(OSSL_PROVIDER *prov);
#endif /* LUNA_OSSL_PQC */

static CK_RV luna_get_attribute(CK_SESSION_HANDLE session_handle, CK_OBJECT_HANDLE pub_handle,
                                CK_ATTRIBUTE_PTR a_template);

static CK_RV sautil_ckatab_malloc_object(CK_ATTRIBUTE *tab, CK_ULONG tabsize, CK_OBJECT_HANDLE hObject,
                                         CK_SESSION_HANDLE hSession);

static void sautil_ckatab_free_all(CK_ATTRIBUTE *tab, CK_ULONG tabsize, int free_tab);

static void luna_dump_hex(FILE *fp, const char *szContext, unsigned char *id, unsigned size);

static void sautil_ckatab_malloc_replace(CK_ATTRIBUTE *tab, CK_ULONG tabsize, CK_ATTRIBUTE_TYPE type,
                                         CK_BYTE_PTR pValue, /* can be null */
                                         CK_ULONG ulValueLen);

static char *luna_sprintf_hex(char *fp0, unsigned char *id, unsigned size);
static int luna_label_to_slotid(const char *tokenlabel, CK_SLOT_ID *pslotid);
static int luna_parse_slotid(char *arg, session_desc *desc);
static int luna_ckatab_pre_keygen(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE *tab, CK_ULONG tabsize);

static char *sautil_strncpy(char *dest, const char *src, size_t n);

/* Dynamic shared object interface */
typedef void* LUNA_DSO_T;
typedef void (*LUNA_DSO_F)(void);
static LUNA_DSO_T luna_dso_load(const char *szDll);
static LUNA_DSO_F luna_dso_bind_func(LUNA_DSO_T dso, const char *szFunction);
static void luna_dso_free(LUNA_DSO_T dso);
static LUNA_DSO_T luna_dso = NULL;
static int luna_ckinit = 0;

/* Cryptoki interface */
static struct {
   CK_C_GetFunctionList C_GetFunctionList;
   CK_FUNCTION_LIST_PTR std;
   struct ext_s {
      CK_CA_SetApplicationID CA_SetApplicationID;
      CK_CA_OpenApplicationID CA_OpenApplicationID;
      CK_CA_CloseApplicationID CA_CloseApplicationID;
   } ext;
} p11 = {0, 0};

static CK_RV sautil_init(void);
static void sautil_fini(void);
static void sautil_exit(int errcode);
static int sautil_gets_password(char *secretString, unsigned maxlen);
static int sautil_gets_passfile(const char *filename, char *password, unsigned maxlen);
static void luna_SHA1(const unsigned char *d, size_t n, unsigned char *md);

/* misc */
static int want_help = 0;
static int verbose = 0;
static CK_ULONG app_id_hi = 0;
static CK_ULONG app_id_lo = 0;
static CK_SLOT_ID slot_id = 0;
static unsigned operation = 0;
static CK_USHORT modulus_size = 0;
static char *key_filename = NULL;
static char *key_keytype = NULL;
static char *key_paramfile = NULL;
static char *passfile = NULL;
static int want_prompt = 0;
static int want_passfile = 0;
static int have_open = 0;
static int have_label = 0;
static char sautil_password[255 + 1] = {0};
static char sautil_szcurve[255 + 1] = {0};
static char sautil_szslotid[255 + 1] = {0};
static char sautil_label[255 + 1] = {0};

/* RSA public exponent */
static enum enum_opt_sel_exponent {
   OPT_SEL_EXPNULL,
   OPT_SEL_EXP3,    /* 0x3 */
   OPT_SEL_EXP4,    /* 0x10001 (default) */
   OPT_SEL_EXPOTHER /* user-defined */
} optSelExponent = OPT_SEL_EXP4;

static unsigned char *bpOptSelExponent = NULL;
static unsigned countofOptSelExponent = 0;

static unsigned char *parse_hex_bytes(const char *inptr, int separator, unsigned *outsize);

static int key_handle = 0;
static CK_SESSION_HANDLE g_hSession = 0;
static CK_USER_TYPE g_userType = CKU_USER;

#if defined(LUNA_OSSL_ECDSA)

/* ECDSA curves */

#define SAUTIL_EC_CURVE_MAX_BYTES (16)
#define SAUTIL_EC_CURVE_MIN_BYTES (7)
#define SAUTIL_EC_CURVE_MIN_STRLEN (9)

typedef struct sautil_curve_s {
   CK_BYTE pValue[SAUTIL_EC_CURVE_MAX_BYTES];
   CK_ULONG ulValueLen;
   const char *name; /* name must start with "OID_" */
} sautil_curve_t;

static sautil_curve_t sautil_curves[] = {
    {{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x06}, 7, "OID_secp112r1"},
    {{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x07}, 7, "OID_secp112r2"},
    {{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x1C}, 7, "OID_secp128r1"},
    {{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x1D}, 7, "OID_secp128r2"},
    {{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x09}, 7, "OID_secp160k1"},
    {{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x08}, 7, "OID_secp160r1"},
    {{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x1E}, 7, "OID_secp160r2"},
    {{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x1F}, 7, "OID_secp192k1"},
    {{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x20}, 7, "OID_secp224k1"},
    {{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x21}, 7, "OID_secp224r1"},
    {{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A}, 7, "OID_secp256k1"},
    {{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22}, 7, "OID_secp384r1"},
    {{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23}, 7, "OID_secp521r1"},

    {{0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x01}, 10, "OID_X9_62_prime192v1"},
    {{0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x02}, 10, "OID_X9_62_prime192v2"},
    {{0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x03}, 10, "OID_X9_62_prime192v3"},
    {{0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x04}, 10, "OID_X9_62_prime239v1"},
    {{0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x05}, 10, "OID_X9_62_prime239v2"},
    {{0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x06}, 10, "OID_X9_62_prime239v3"},
    {{0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07}, 10, "OID_X9_62_prime256v1"},

    {{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x04}, 7, "OID_sect113r1"},
    {{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x05}, 7, "OID_sect113r2"},
    {{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x16}, 7, "OID_sect131r1"},
    {{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x17}, 7, "OID_sect131r2"},
    {{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x01}, 7, "OID_sect163k1"},
    {{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x02}, 7, "OID_sect163r1"},
    {{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0F}, 7, "OID_sect163r2"},
    {{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x18}, 7, "OID_sect193r1"},
    {{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x19}, 7, "OID_sect193r2"},
    {{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x1A}, 7, "OID_sect233k1"},
    {{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x1B}, 7, "OID_sect233r1"},
    {{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x03}, 7, "OID_sect239k1"},
    {{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x10}, 7, "OID_sect283k1"},
    {{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x11}, 7, "OID_sect283r1"},
    {{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x24}, 7, "OID_sect409k1"},
    {{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x25}, 7, "OID_sect409r1"},
    {{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x26}, 7, "OID_sect571k1"},
    {{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x27}, 7, "OID_sect571r1"},

    {{0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x00, 0x01}, 10, "OID_X9_62_c2pnb163v1"},
    {{0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x00, 0x02}, 10, "OID_X9_62_c2pnb163v2"},
    {{0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x00, 0x03}, 10, "OID_X9_62_c2pnb163v3"},
    {{0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x00, 0x04}, 10, "OID_X9_62_c2pnb176v1"},
    {{0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x00, 0x05}, 10, "OID_X9_62_c2tnb191v1"},
    {{0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x00, 0x06}, 10, "OID_X9_62_c2tnb191v2"},
    {{0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x00, 0x07}, 10, "OID_X9_62_c2tnb191v3"},
    {{0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x00, 0x0A}, 10, "OID_X9_62_c2pnb208w1"},
    {{0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x00, 0x0B}, 10, "OID_X9_62_c2tnb239v1"},
    {{0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x00, 0x0C}, 10, "OID_X9_62_c2tnb239v2"},
    {{0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x00, 0x0D}, 10, "OID_X9_62_c2tnb239v3"},
    {{0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x00, 0x10}, 10, "OID_X9_62_c2pnb272w1"},
    {{0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x00, 0x11}, 10, "OID_X9_62_c2pnb304w1"},
    {{0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x00, 0x12}, 10, "OID_X9_62_c2tnb359v1"},
    {{0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x00, 0x13}, 10, "OID_X9_62_c2pnb368w1"},
    {{0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x00, 0x14}, 10, "OID_X9_62_c2tnb431r1"},
};

#endif /* LUNA_OSSL_ECDSA */

static void display_help_and_exit(void) {
   fprintf(stdout, LOCAL_APP_NAME " " LOCAL_APP_VERSION " " __DATE__ " " __TIME__
                                  " \n"
                                  "Source: " __FILE__ ": Using " OPENSSL_VERSION_TEXT " \n\n"
                                  "  Copyright " LOCAL_APP_COPYRIGHT " Thales Group. All rights reserved. \n\n"
                                  "  Options:\n"
                                  "    -o         open application connection.\n"
                                  "    -c         close application connection.\n"
                                  "    -i hi:lo   application id high and low component. 32-bit values.\n"
                                  "    -s slot    token slot number.\n"
                                  "    -p pswd    plaintext password (please use -q instead).\n"
                                  "    -q         prompt for password (instead of -p).\n"
                                  "    -u         login as Crypto-User (default is Crypto-Officer).\n"
                                  "    -w file    filename containing ascii password (instead of -p -q).\n"
                                  "    -v         verbose.\n"
                                  "    -h         show help message in full.\n"
                                  "    -g size    generate RSA key pair with size = {1024,2048,4096} bits.\n"
                                  "    -g 0       delete RSA keypair from HSM (used with -f file option).\n"
                                  "    -d size:paramfile    generate DSA key pair with size = {1024,2048,3072} bits.\n"
                                  "    -d 0       delete DSA keypair from HSM (used with -f file option).\n"
                                  "    -l label   set the label for keys (minimum 7 characters).\n"
#if defined(LUNA_OSSL_ECDSA)
                                  "    -m curve[:paramfile]   generate ECDSA key pair with curve name.\n"
                                  "    -m 0       delete ECDSA keypair from HSM (used with -f file option).\n"
                                  "    -n         print a list of supported curve names.\n"
#endif /* LUNA_OSSL_ECDSA */
#if defined(LUNA_OSSL_PQC)
                                  "    -k 0       delete PQC keypair from HSM (used with -f file option).\n"
#endif /* LUNA_OSSL_ECDSA */
#ifdef CA3UTIL_DIFFIE_HELLMAN
                                  "    -e size    generate a DH key pair.\n"
#endif /* CA3UTIL_DIFFIE_HELLMAN */
                                  "    -f file    specify name of keyfile.\n"
                                  "    -3         public exponent is 0x3 for RSA key generation.\n"
                                  "    -4         public exponent is 0x10001 for RSA key generation (default).\n"
                                  "    -x bytes   public exponent is a colon-separated list of\n"
                                  "               hex bytes for RSA key generation; e.g., 03 ; e.g., 01:00:01 .\n"
                                  "    -a 0[:keytype]  write keyfile for existing keytype = {RSA,DSA,ECDSA}.\n\n"
                                  "  EXAMPLE 1: open persistent application connection and login: \n"
                                  "    # sautil -v -s 1 -i 10:11 -o -q \n\n"
                                  "  EXAMPLE 2: close persistent application connection: \n"
                                  "    # sautil -v -s 1 -i 10:11 -c \n\n"
                                  "    NOTE: remember to close persistent connection when HSM not in use. \n\n"
                                  "  EXAMPLE 3: generate a new RSA keypair and write the keyfile: \n"
                                  "    # sautil -v -s 1 -i 10:11 -g 2048 -f tmpkey.pem \n\n"
                                  "  EXAMPLE 4: select an existing RSA key and write the keyfile: \n"
                                  "    # sautil -v -s 1 -i 10:11 -a 0:RSA -f tmpkey.pem \n\n"
                                  "  EXAMPLE 5: connect, write keyfile, and disconnect in a single command-line: \n"
                                  "    # sautil -v -s 1 -i 10:11 -a 0:RSA -f tmpkey.pem -o -q -c \n\n");

#if defined(LUNA_OSSL_ECDSA)
   {
      CK_ULONG ii = 0;

      /* if help explicitly requested then display curves */
      if (want_help) {
         fprintf(stdout, "  Note (valid curve names used with -m option):\n");
         for (ii = 0; ii < LUNA_DIM(sautil_curves); ii++) {
            if ((ii % 3) == 0) {
               fprintf(stdout, "\n ");
            }
            fprintf(stdout, "%25s ", (char *)sautil_curves[ii].name);
         }
         fprintf(stdout, "\n");
      }
   }
#endif

   sautil_exit(-1);
}

/* dump a long string of support EC curves */
static void display_oids_and_exit(void) {
#if defined(LUNA_OSSL_ECDSA)
   {
      CK_ULONG ii = 0;

      /* if help explicitly requested then display curves */
      if (1) {
         for (ii = 0; ii < LUNA_DIM(sautil_curves); ii++) {
            fprintf(stdout, "%s ", (char *)sautil_curves[ii].name);
         }
      }
   }
   sautil_exit(0);
#else
   sautil_exit(-1);
#endif
}

int parse_args(int argc, char *argv[]) {
   char app_id_buf[128];
   char *p = NULL;
   int option = 0;

   memset(app_id_buf, 0, sizeof(app_id_buf));

   if (argc > 1) {
      while ((option = sautil_getopt(argc, argv, "nqw34hexu:d:g:cos:i:vf:p:a:R:m:l:k")) != EOF) {
         switch ((char)option) {
            case 'g':
               if (sautil_optarg == NULL)
                  display_help_and_exit();
               if (!isdigit(sautil_optarg[0])) {
                  fprintf(stderr, "Must specify a valid modulus size. [%s] is not\n", sautil_optarg);
                  return -1;
               }

               modulus_size = atoi(sautil_optarg);

               if (!modulus_size) {
                  operation |= OP_DELETE_RSA_KEY_PAIR;
                  break;
               }
               operation |= OP_GENERATE_RSA_KEY_PAIR;
               if (modulus_size < LOCAL_RSA_KEYSIZE_MIN) {
                  fprintf(stderr, "Invalid modulus size %u less than %u. \n", (unsigned)modulus_size,
                          (unsigned)LOCAL_RSA_KEYSIZE_MIN);
                  return -1;
               }
               break;
            case 'd':
               if (sautil_optarg == NULL)
                  display_help_and_exit();
               if (!isdigit(sautil_optarg[0])) {
                  fprintf(stderr, "Must specify a valid modulus size. [%s] is not\n", sautil_optarg);
                  return -1;
               }
               modulus_size = atoi(sautil_optarg);
               if (!modulus_size) {
                  operation |= OP_DELETE_DSA_KEY_PAIR;
                  break;
               }
               operation |= OP_GENERATE_DSA_KEY_PAIR;
               if (modulus_size < LOCAL_DSA_KEYSIZE_MIN) {
                  fprintf(stderr, "Invalid modulus size %u less than %u. \n", (unsigned)modulus_size,
                          (unsigned)LOCAL_DSA_KEYSIZE_MIN);
                  return -1;
               }
               if ((p = strchr(sautil_optarg, ':')) != NULL) {
                  if (key_paramfile != NULL)
                     free(key_paramfile);
                  key_paramfile = strdup(p + 1);
               }
               break;
#if defined(LUNA_OSSL_ECDSA)
            case 'm':
               if (sautil_optarg == NULL) {
                  fprintf(stderr, "Missing argument for option -m.\n");
                  display_help_and_exit();
               }
               if (strcmp(sautil_optarg, "0") == 0) {
                  operation |= OP_DELETE_ECDSA_KEY_PAIR;
                  modulus_size = 0;
               } else if (strncmp(sautil_optarg, "OID_", 4) == 0) {
                  operation |= OP_GENERATE_ECDSA_KEY_PAIR;
                  modulus_size = 1024;
                  if ((p = strchr(sautil_optarg, ':')) != NULL) {
                     if (key_paramfile != NULL)
                        free(key_paramfile);
                     key_paramfile = strdup(p + 1);
                  } else {
                     sautil_strncpy(sautil_szcurve, sautil_optarg, sizeof(sautil_szcurve));
                  }
               } else {
                  fprintf(stderr, "Invalid argument for option -m.\n");
                  display_help_and_exit();
               }
               break;
            case 'n':
               display_oids_and_exit();
               break;
#endif /* LUNA_OSSL_ECDSA */
#if defined(LUNA_OSSL_PQC)
            case 'k':
               if (sautil_optarg == NULL) {
                  fprintf(stderr, "Missing argument for option -k.\n");
                  display_help_and_exit();
               }
               if (strcmp(sautil_optarg, "0") == 0) {
                  operation |= OP_DELETE_PQC_KEY_PAIR;
               } else {
                  fprintf(stderr, "Invalid argument for option -k.\n");
                  display_help_and_exit();
               }
               break;
#endif /* LUNA_OSSL_PQC */
#ifdef CA3UTIL_DIFFIE_HELLMAN
            case 'e':
               if (sautil_optarg == NULL)
                  display_help_and_exit();
               modulus_size = atoi(sautil_optarg);
               operation |= OP_GENERATE_DH_KEY_PAIR;
               switch (modulus_size) {
                  case 1024:
                     break;
                  default:
                     fprintf(stderr, "Invalid DH key size.\n");
                     return -1;
               }
               break;
#endif /* CA3UTIL_DIFFIE_HELLMAN */
            case 'o':
               operation |= OP_OPEN;
               break;
            case 'c':
               operation |= OP_CLOSE;
               break;
            case 's':
               if (sautil_optarg == NULL)
                  display_help_and_exit();
               sautil_strncpy(sautil_szslotid, sautil_optarg, sizeof(sautil_szslotid));
               slot_id = atoi(sautil_szslotid);
               break;
            case 'a':
            case 'R':
               if (sautil_optarg == NULL)
                  display_help_and_exit();
               operation |= OP_RESTORE_KEYFILE;
               if (!isdigit(sautil_optarg[0])) {
                  fprintf(stderr, "Must specify a numeric key handle (or zero)\n");
                  return -1;
               }
               if (key_keytype != NULL)
                  free(key_keytype);
               if ((p = strchr(sautil_optarg, ':')) != NULL) {
                  key_keytype = strdup(p + 1);
               } else {
                  key_keytype = strdup("RSA"); /* default */
               }
               key_handle = atoi(sautil_optarg);
               if (!key_handle) {
                  /* interactive mode */
               }
               break;
            case '3':
               optSelExponent = OPT_SEL_EXP3;
               break;
            case '4':
               optSelExponent = OPT_SEL_EXP4;
               break;
            case 'x':
               if (sautil_optarg == NULL)
                  display_help_and_exit();
               optSelExponent = OPT_SEL_EXPOTHER;
               if (bpOptSelExponent != NULL)
                  free(bpOptSelExponent);
               bpOptSelExponent = parse_hex_bytes(sautil_optarg, ':', &countofOptSelExponent);
               if (bpOptSelExponent == NULL) {
                  fprintf(stderr, "Parse error for after \'-x\'.\n");
                  return -1;
               }
               break;
            case 'p':
               if (sautil_optarg == NULL)
                  display_help_and_exit();
               sautil_strncpy(sautil_password, sautil_optarg, sizeof(sautil_password));
               if (strlen(sautil_password) < LUNA_MIN_PASSWORD) {
                  fprintf(stderr, "Failed to read password (or password too short).\n");
                  return -1;
               }
               break;
            case 'q': /* prompt for password (instead of -p) */
               want_prompt = 1;
               break;
            case 'w': /* file with password (instead of -q -p) */
               want_passfile = 1;
               if (sautil_optarg == NULL)
                  display_help_and_exit();
               if (passfile != NULL)
                  free(passfile);
               passfile = strdup(sautil_optarg);
               break;
            case 'f':
               if (sautil_optarg == NULL)
                  display_help_and_exit();
               if (key_filename != NULL)
                  free(key_filename);
               key_filename = strdup(sautil_optarg);
               break;
            case 'i':
               if (sautil_optarg == NULL)
                  display_help_and_exit();
               memset(app_id_buf, 0, 128);
               sautil_strncpy(app_id_buf, sautil_optarg, sizeof(app_id_buf));
               p = strchr(app_id_buf, ':');
               if (!p) {
                  fprintf(stderr, "Invalid App ID parameter [%s]. Must be ULONG:ULONG\n", app_id_buf);
                  return -1;
               }
               p[0] = 0;
               p++;
               app_id_hi = atoi(app_id_buf);
               app_id_lo = atoi(p);
               break;
            case 'v':
               verbose = 1;
               break;
            case 'u':
               g_userType = CKU_LIMITED_USER;
               break;
            case 'l':
               if (sautil_optarg == NULL)
                  display_help_and_exit();
               sautil_strncpy(sautil_label, sautil_optarg, sizeof(sautil_label));
               if (strlen(sautil_label) < LUNA_MIN_LABEL) {
                  fprintf(stderr, "Label too short.\n");
                  return -1;
               }
               have_label = 1;
               break;
            case 'h':
               want_help = 1;
            /* fall through */
            default:
               display_help_and_exit();
               break;
         }
      }
   } else
      display_help_and_exit();

   return 0;
}

int init_dh_key_template(CK_ATTRIBUTE **pubTemp, CK_ATTRIBUTE **privTemp, CK_USHORT *pubTempSize,
                         CK_USHORT *privTempSize, CK_BYTE *pub_key_label, CK_BYTE *priv_key_label,
                         const CK_BYTE *dh_prime, const CK_USHORT dh_prime_size, const CK_BYTE *dh_base,
                         const CK_USHORT dh_base_size) {
   CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;
   CK_ATTRIBUTE *pubTemplate, *privTemplate;

   CK_ATTRIBUTE dh_pub_template[] = {
       {CKA_LABEL, 0, 0},
       {CKA_PRIVATE, 0, sizeof(CK_BBOOL)},
       {CKA_TOKEN, 0, sizeof(CK_BBOOL)},
       {CKA_PRIME, 0, 0},
       {CKA_BASE, 0, 0},
       {CKA_DERIVE, 0, sizeof(CK_BBOOL)},
   };

   CK_ATTRIBUTE dh_priv_template[] = {
       {CKA_LABEL, 0, 0}, {CKA_TOKEN, 0, 1}, {CKA_PRIVATE, 0, 1}, {CKA_SENSITIVE, 0, 1}, {CKA_DERIVE, 0, 1},
   };

   if (!pub_key_label || !priv_key_label) {
      fprintf(stderr, "key label fields need to be specified\n");
      return -1;
   }

   dh_priv_template[0].pValue = priv_key_label;
   dh_priv_template[0].ulValueLen = (CK_ULONG)strlen((char *)priv_key_label);
   dh_priv_template[1].pValue = &bTrue;
   dh_priv_template[2].pValue = &bTrue;
   dh_priv_template[3].pValue = &bTrue;
   dh_priv_template[4].pValue = &bTrue;

   dh_pub_template[0].pValue = pub_key_label;
   dh_pub_template[0].ulValueLen = (CK_ULONG)strlen((char *)pub_key_label);
   dh_pub_template[1].pValue = &bFalse;
   dh_pub_template[2].pValue = &bTrue;
   dh_pub_template[3].pValue = (CK_BYTE *)dh_prime;
   dh_pub_template[3].ulValueLen = dh_prime_size;
   dh_pub_template[4].pValue = (CK_BYTE *)dh_base;
   dh_pub_template[4].ulValueLen = dh_base_size;
   dh_pub_template[5].pValue = &bTrue;

   pubTemplate = (CK_ATTRIBUTE *)malloc(sizeof(dh_pub_template));
   if (pubTemplate == NULL)
      return -1;
   privTemplate = (CK_ATTRIBUTE *)malloc(sizeof(dh_priv_template));
   if (privTemplate == NULL) {
      free(pubTemplate);
      return -1;
   }
   *pubTempSize = sizeof(dh_pub_template) / sizeof(CK_ATTRIBUTE);
   *privTempSize = sizeof(dh_priv_template) / sizeof(CK_ATTRIBUTE);

   memcpy(pubTemplate, dh_pub_template, sizeof(dh_pub_template));
   memcpy(privTemplate, dh_priv_template, sizeof(dh_priv_template));

   *pubTemp = pubTemplate;
   *privTemp = privTemplate;

   return 0;
}

int init_dsa_key_template(CK_ATTRIBUTE **pubTemp, CK_ATTRIBUTE **privTemp, CK_USHORT *pubTempSize,
                          CK_USHORT *privTempSize, CK_BYTE *pub_key_label, CK_BYTE *priv_key_label,
                          const CK_BYTE *dsa_prime, const CK_USHORT dsa_prime_size, const CK_BYTE *dsa_sub_prime,
                          const CK_USHORT dsa_sub_prime_size, const CK_BYTE *dsa_base, const CK_USHORT dsa_base_size,
                          CK_BYTE *dsa_id, CK_ULONG dsa_id_size) {
   CK_BBOOL bTrue = CK_TRUE;
   CK_BBOOL bModifiable = CK_TRUE;
   CK_BBOOL bExtractable = CK_TRUE;
   CK_ATTRIBUTE *pubTemplate = NULL;
   CK_ATTRIBUTE *privTemplate = NULL;

   CK_ATTRIBUTE dsa_pub_template[] = {
       {CKA_LABEL, 0, 0},
       {CKA_TOKEN, 0, 0},
       {CKA_PRIVATE, 0, 0},
       {CKA_PRIME, 0, 0},
       {CKA_SUBPRIME, 0, 0},
       {CKA_BASE, 0, 0},
       {CKA_VERIFY, 0, 0},
       {CKA_MODIFIABLE, 0, 0},
       {CKA_ID, 0, 0},
   };

   CK_ATTRIBUTE dsa_priv_template[] = {
       {CKA_LABEL, 0, 0},
       {CKA_TOKEN, 0, 0},
       {CKA_PRIVATE, 0, 0},
       {CKA_SENSITIVE, 0, 0},
       {CKA_SIGN, 0, 0},
       {CKA_MODIFIABLE, 0, 0},
       {CKA_EXTRACTABLE, 0, 0},
       {CKA_ID, 0, 0},
   };

   if (!pub_key_label || !priv_key_label) {
      fprintf(stderr, "key label fields need to be specified\n");
      return -1;
   }

   /* set attribute */
   sautil_ckatab_malloc_replace(dsa_pub_template, LUNA_DIM(dsa_pub_template), CKA_LABEL, (CK_BYTE_PTR)pub_key_label,
                                (CK_ULONG)strlen((char *)pub_key_label));
   sautil_ckatab_malloc_replace(dsa_pub_template, LUNA_DIM(dsa_pub_template), CKA_TOKEN, &bTrue, sizeof(bTrue));
   sautil_ckatab_malloc_replace(dsa_pub_template, LUNA_DIM(dsa_pub_template), CKA_PRIVATE, &bTrue,
                                sizeof(bTrue)); /* private=1 for access control */
   sautil_ckatab_malloc_replace(dsa_pub_template, LUNA_DIM(dsa_pub_template), CKA_PRIME, (CK_BYTE_PTR)dsa_prime,
                                dsa_prime_size);
   sautil_ckatab_malloc_replace(dsa_pub_template, LUNA_DIM(dsa_pub_template), CKA_SUBPRIME, (CK_BYTE_PTR)dsa_sub_prime,
                                dsa_sub_prime_size);
   sautil_ckatab_malloc_replace(dsa_pub_template, LUNA_DIM(dsa_pub_template), CKA_BASE, (CK_BYTE_PTR)dsa_base,
                                dsa_base_size);
   sautil_ckatab_malloc_replace(dsa_pub_template, LUNA_DIM(dsa_pub_template), CKA_VERIFY, &bTrue, sizeof(bTrue));
   sautil_ckatab_malloc_replace(dsa_pub_template, LUNA_DIM(dsa_pub_template), CKA_MODIFIABLE, &bModifiable, sizeof(bModifiable));
   sautil_ckatab_malloc_replace(dsa_pub_template, LUNA_DIM(dsa_pub_template), CKA_ID, dsa_id, dsa_id_size);

   sautil_ckatab_malloc_replace(dsa_priv_template, LUNA_DIM(dsa_priv_template), CKA_LABEL, (CK_BYTE_PTR)priv_key_label,
                                (CK_ULONG)strlen((char *)priv_key_label));
   sautil_ckatab_malloc_replace(dsa_priv_template, LUNA_DIM(dsa_priv_template), CKA_TOKEN, &bTrue, sizeof(bTrue));
   sautil_ckatab_malloc_replace(dsa_priv_template, LUNA_DIM(dsa_priv_template), CKA_PRIVATE, &bTrue, sizeof(bTrue));
   sautil_ckatab_malloc_replace(dsa_priv_template, LUNA_DIM(dsa_priv_template), CKA_SENSITIVE, &bTrue, sizeof(bTrue));
   sautil_ckatab_malloc_replace(dsa_priv_template, LUNA_DIM(dsa_priv_template), CKA_SIGN, &bTrue, sizeof(bTrue));
   sautil_ckatab_malloc_replace(dsa_priv_template, LUNA_DIM(dsa_priv_template), CKA_MODIFIABLE, &bModifiable, sizeof(bModifiable));
   sautil_ckatab_malloc_replace(dsa_priv_template, LUNA_DIM(dsa_priv_template), CKA_EXTRACTABLE, &bExtractable, sizeof(bExtractable));
   sautil_ckatab_malloc_replace(dsa_priv_template, LUNA_DIM(dsa_priv_template), CKA_ID, dsa_id, dsa_id_size);

   pubTemplate = (CK_ATTRIBUTE *)malloc(sizeof(dsa_pub_template));
   if (pubTemplate == NULL)
      return -1;
   privTemplate = (CK_ATTRIBUTE *)malloc(sizeof(dsa_priv_template));
   if (privTemplate == NULL) {
       free(pubTemplate);
       return -1;
    }
   (*pubTempSize) = sizeof(dsa_pub_template) / sizeof(CK_ATTRIBUTE);
   (*privTempSize) = sizeof(dsa_priv_template) / sizeof(CK_ATTRIBUTE);

   memcpy(pubTemplate, dsa_pub_template, sizeof(dsa_pub_template));
   memcpy(privTemplate, dsa_priv_template, sizeof(dsa_priv_template));

   (*pubTemp) = pubTemplate;
   (*privTemp) = privTemplate;

   return 0;
}

static int init_rsa_key_template(CK_ATTRIBUTE **pubTemp, CK_ATTRIBUTE **privTemp, CK_USHORT *pubTempSize,
                                 CK_USHORT *privTempSize, const CK_USHORT modulusBits, const CK_BYTE *publicExponent,
                                 const CK_USHORT publicExponentSize, CK_BYTE *privKeyLabel, CK_BYTE *pubKeyLabel,
                                 CK_BYTE *idSha1, CK_USHORT idSha1Len) {
   CK_BBOOL bTrue = CK_TRUE;
   CK_BBOOL bModifiable = CK_TRUE;
   CK_BBOOL bExtractable = CK_TRUE;
   CK_ATTRIBUTE *pubTemplate = NULL, *privTemplate = NULL;
   CK_ULONG ulModBits = modulusBits;

   CK_ATTRIBUTE rsa_pub_template[] = {
       {CKA_TOKEN, 0, 0},
       {CKA_PRIVATE, 0, 0},
       {CKA_ENCRYPT, 0, 0},
       {CKA_VERIFY, 0, 0},
       {CKA_MODIFIABLE, 0, 0},
       {CKA_MODULUS_BITS, 0, 0},
       {CKA_PUBLIC_EXPONENT, 0, 0},
       {CKA_LABEL, 0, 0},
       {CKA_ID, 0, 0},
   };

   CK_ATTRIBUTE rsa_priv_template[] = {
       {CKA_LABEL, 0, 0},
       {CKA_TOKEN, 0, 0},
       {CKA_PRIVATE, 0, 0},
       {CKA_SENSITIVE, 0, 0},
       {CKA_DECRYPT, 0, 0},
       {CKA_SIGN, 0, 0},
       {CKA_MODIFIABLE, 0, 0},
       {CKA_EXTRACTABLE, 0, 0},
       {CKA_ID, 0, 0},
   };

   if (!privKeyLabel || !pubKeyLabel) {
      fprintf(stderr, "BUG: !privKeyLabel || !pubKeyLabel\n");
      return -1;
   }

   /* set attribute */
   sautil_ckatab_malloc_replace(rsa_pub_template, LUNA_DIM(rsa_pub_template), CKA_TOKEN, &bTrue, sizeof(bTrue));
   sautil_ckatab_malloc_replace(rsa_pub_template, LUNA_DIM(rsa_pub_template), CKA_PRIVATE, &bTrue,
                                sizeof(bTrue)); /* private=1 for access control */
   sautil_ckatab_malloc_replace(rsa_pub_template, LUNA_DIM(rsa_pub_template), CKA_ENCRYPT, &bTrue, sizeof(bTrue));
   sautil_ckatab_malloc_replace(rsa_pub_template, LUNA_DIM(rsa_pub_template), CKA_VERIFY, &bTrue, sizeof(bTrue));
   sautil_ckatab_malloc_replace(rsa_pub_template, LUNA_DIM(rsa_pub_template), CKA_MODIFIABLE, &bModifiable, sizeof(bModifiable));
   sautil_ckatab_malloc_replace(rsa_pub_template, LUNA_DIM(rsa_pub_template), CKA_MODULUS_BITS, (CK_BYTE_PTR)&ulModBits,
                                sizeof(ulModBits));
   sautil_ckatab_malloc_replace(rsa_pub_template, LUNA_DIM(rsa_pub_template), CKA_PUBLIC_EXPONENT,
                                (CK_BYTE_PTR)publicExponent, publicExponentSize);
   sautil_ckatab_malloc_replace(rsa_pub_template, LUNA_DIM(rsa_pub_template), CKA_LABEL, (CK_BYTE_PTR)pubKeyLabel,
                                (CK_ULONG)strlen((char *)pubKeyLabel));
   sautil_ckatab_malloc_replace(rsa_pub_template, LUNA_DIM(rsa_pub_template), CKA_ID, idSha1, idSha1Len);

   sautil_ckatab_malloc_replace(rsa_priv_template, LUNA_DIM(rsa_priv_template), CKA_LABEL, (CK_BYTE_PTR)privKeyLabel,
                                (CK_ULONG)strlen((char *)privKeyLabel));
   sautil_ckatab_malloc_replace(rsa_priv_template, LUNA_DIM(rsa_priv_template), CKA_TOKEN, &bTrue, sizeof(bTrue));
   sautil_ckatab_malloc_replace(rsa_priv_template, LUNA_DIM(rsa_priv_template), CKA_PRIVATE, &bTrue, sizeof(bTrue));
   sautil_ckatab_malloc_replace(rsa_priv_template, LUNA_DIM(rsa_priv_template), CKA_SENSITIVE, &bTrue, sizeof(bTrue));
   sautil_ckatab_malloc_replace(rsa_priv_template, LUNA_DIM(rsa_priv_template), CKA_DECRYPT, &bTrue, sizeof(bTrue));
   sautil_ckatab_malloc_replace(rsa_priv_template, LUNA_DIM(rsa_priv_template), CKA_SIGN, &bTrue, sizeof(bTrue));
   sautil_ckatab_malloc_replace(rsa_priv_template, LUNA_DIM(rsa_priv_template), CKA_MODIFIABLE, &bModifiable, sizeof(bModifiable));
   sautil_ckatab_malloc_replace(rsa_priv_template, LUNA_DIM(rsa_priv_template), CKA_EXTRACTABLE, &bExtractable, sizeof(bExtractable));
   sautil_ckatab_malloc_replace(rsa_priv_template, LUNA_DIM(rsa_priv_template), CKA_ID, idSha1, idSha1Len);

   pubTemplate = (CK_ATTRIBUTE *)malloc(sizeof(rsa_pub_template));
   if (pubTemplate == NULL)
      return -1;
   privTemplate = (CK_ATTRIBUTE *)malloc(sizeof(rsa_priv_template));
   if (privTemplate == NULL) {
       free(pubTemplate);
       return -1;
    }
   memcpy(pubTemplate, rsa_pub_template, sizeof(rsa_pub_template));
   memcpy(privTemplate, rsa_priv_template, sizeof(rsa_priv_template));
   memset(rsa_pub_template, 0, sizeof(rsa_pub_template));
   memset(rsa_priv_template, 0, sizeof(rsa_priv_template));

   (*pubTemp) = pubTemplate;
   (*privTemp) = privTemplate;

   (*pubTempSize) = sizeof(rsa_pub_template) / sizeof(CK_ATTRIBUTE);
   (*privTempSize) = sizeof(rsa_priv_template) / sizeof(CK_ATTRIBUTE);

   return 0;
}

int set_application_id(CK_ULONG appid_hi, CK_ULONG appid_lo) {
   CK_RV ret;

   if (LOCAL_APPID_NOT_USING(appid_hi, appid_lo)) {
      if (verbose)
         fprintf(stdout, "Not using application id (set). \n");
      return 0;
   }

   ret = p11.ext.CA_SetApplicationID(appid_hi, appid_lo);
   if (ret != CKR_OK) {
      fprintf(stderr, "CA_SetApplicationID: failed to set id. err 0x%x\n", (int)ret);
      return -1;
   }

   if (verbose)
      fprintf(stdout, "Will use application ID [%lu:%lu].\n", appid_hi, appid_lo);

   return 0;
}

int open_session(CK_SLOT_ID slotid, CK_SESSION_HANDLE *session_handle) {
   CK_RV retCode;
   CK_FLAGS flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
   CK_SESSION_HANDLE shandle;

   retCode = p11.std->C_OpenSession(slotid, flags, (CK_BYTE_PTR) "Application", 0, &shandle);
   if (retCode != CKR_OK) {
      fprintf(stderr, "Open Session Error: Slot number %d. err 0x%x\n", (int)slotid, (int)retCode);
      return -1;
   }

   if (verbose)
      fprintf(stdout, "Session opened. Handle %x.\n", (int)shandle);

   (*session_handle) = shandle;

   return 0;
}

int close_session(CK_SESSION_HANDLE session_handle) {
   CK_RV retCode;

   retCode = p11.std->C_CloseSession(session_handle);
   session_handle = 0;
   if (retCode != CKR_OK) {
      fprintf(stderr, "Crystoki Close Session Error. Session handle %d  err 0x%x\n", (int)session_handle, (int)retCode);
      return -1;
   }

   return 0;
}

int op_open_app_id(CK_SLOT_ID slotid, CK_ULONG appid_hi, CK_ULONG appid_lo) {
   CK_SESSION_HANDLE session_handle;
   CK_RV retCode;
   int ret;
   CK_TOKEN_INFO infot;
   CK_BYTE norm2[LUNA_MAX_LABEL + 8];

   memset(&infot, 0, sizeof(infot));
   memset(norm2, 0, sizeof(norm2));

   ret = set_application_id(appid_hi, appid_lo);
   if (ret != 0)
      return -1;

   if (LOCAL_APPID_NOT_USING(appid_hi, appid_lo)) {
      if (verbose)
         fprintf(stdout, "Not using application id (open). \n");
   } else {
      retCode = p11.ext.CA_OpenApplicationID(slotid, appid_hi, appid_lo);
      if (retCode != CKR_OK) {
         fprintf(stderr, "CA_OpenApplicationID: failed to open application id. err 0x%x\n", (int)retCode);
         fprintf(stderr, "                      invalid slot id or app id already open?\n");
         return -1;
      }

      if (verbose)
         fprintf(stdout, "Application ID [%lu:%lu] opened.\n", appid_hi, appid_lo);

      have_open = 1;
      fprintf(stderr, "Open ok. \n");
   }

   if (open_session(slotid, &session_handle) != 0)
      return -1;

#if 0
  fprintf(stdout, "C_Login: PED operation required\n");
#endif

   fprintf(stdout, "HSM Slot Id is %u. \n", (unsigned)slotid);
   retCode = p11.std->C_GetTokenInfo(slotid, &infot);
   if (retCode != CKR_OK) {
      fprintf(stderr, "C_GetTokenInfo Error: %04x slotid %d \n", (unsigned)retCode, (unsigned)slotid);
      goto err;
   }

   memset(norm2, ' ', LUNA_MAX_LABEL);
   memcpy(norm2, infot.label, LUNA_MAX_LABEL);
   norm2[LUNA_MAX_LABEL] = 0;
   norm2[LUNA_MAX_LABEL + 1] = 0;
   fprintf(stdout, "HSM Label is \"%s\". \n", (char *)norm2);

   if (want_passfile) {
      if (sautil_gets_passfile(passfile, sautil_password, (sizeof(sautil_password) - 1)) < LUNA_MIN_PASSWORD) {
         fprintf(stderr, "Failed to read passfile (or password too short).\n");
         goto err;
      }
   }

   if (want_prompt || (strlen(sautil_password) < LUNA_MIN_PASSWORD)) {
      /* Enter HSM Password */
      if (g_userType == CKU_LIMITED_USER) {
         fprintf(stdout, "Enter Crypto-User Password: ");
      } else {
         fprintf(stdout, "Enter Crypto-Officer Password: ");
      }
      if (sautil_gets_password(sautil_password, (sizeof(sautil_password) - 1)) < LUNA_MIN_PASSWORD) {
         fprintf(stderr, "Failed to read password (or password too short).\n");
         goto err;
      }
   }

   retCode = p11.std->C_Login(session_handle, g_userType, (CK_BYTE_PTR)sautil_password,
                              (CK_ULONG)strlen((char *)sautil_password));
   if (retCode != CKR_OK) {
      fprintf(stderr, "Crystoki Login Error: %04x slotid %d \n", (unsigned)retCode, (unsigned)slotid);
      goto err;
   }

#if 0
#define KM_TPV_M_OF_N_ACTIVATION 0x04000000

  retCode = p11.ext.CA_GetExtendedTPV(slotid, &tpv, &tpvExt);
  if(retCode != CKR_OK) {    
    fprintf(stderr, "Crystoki CA_GetExtendedTPV Error: %04x slotid %d \n", (int) retCode, slotid);
    goto err;
  } 
    
  if (tpv & KM_TPV_M_OF_N_ACTIVATION) {
    if (verbose) 
      fprintf(stdout, "MofN activation required.\n");
    
    retCode = p11.ext.CA_ActivateMofN(session_handle, NULL_PTR, 0);
    if (retCode != CKR_OK) {  
      fprintf(stderr, "M of N activation failed.\n");
      fprintf(stderr, "Crystoki CA_ActivateMofN Error: %04x slotid %d \n", (int) retCode, slotid);
      goto err;
    }
  
  }
#endif

   if (!LOCAL_APPID_NOT_USING(appid_hi, appid_lo)) {
      fprintf(stdout, "\n\n");
      fprintf(stdout, "WARNING: Application Id %u:%u has been opened for access. Thus access will\n",
              (unsigned)appid_hi, (unsigned)appid_lo);
      fprintf(stdout, "         remain open until all sessions associated with this Application Id are\n");
      fprintf(stdout, "         closed or until the access is explicitly closed.\n\n");
   }

   /* defer close session iff not using appid */
   ret = 0;
   if (LOCAL_APPID_NOT_USING(appid_hi, appid_lo)) {
      g_hSession = session_handle;
      session_handle = 0;
   }

err:
   /* session handle may be null */
   if (session_handle != 0) {
      if (close_session(session_handle) != 0) {
         session_handle = 0;
         return -1;
      }
   }

   session_handle = 0;
   return ret;
}

int op_close_app_id(CK_SLOT_ID slotid, CK_ULONG appid_hi, CK_ULONG appid_lo) {
   CK_RV ret;

   if (LOCAL_APPID_NOT_USING(appid_hi, appid_lo)) {
      if (verbose)
         fprintf(stdout, "Not using application id (close). \n");
      return 0;
   }

   ret = p11.ext.CA_CloseApplicationID(slotid, appid_hi, appid_lo);
   if (ret != CKR_OK) {
      fprintf(stderr, "CA_CloseApplicationID: failed to close application id. err 0x%x\n", (int)ret);
      return -1;
   } else {
      CK_RV ret2 = p11.ext.CA_CloseApplicationID(slotid, appid_hi, appid_lo);
      if (ret2 == CKR_OK) {
         fprintf(stderr, "WARNING: CA_CloseApplicationID failed. \n");
         fprintf(stderr, "  [Hint: the Application Id is in use and cannot be closed at this time]. \n");
         return -2;
      }
   }

   fprintf(stderr, "Close ok. \n");
   return 0;
}

static int write_pem_dsa_key_pair(CK_SESSION_HANDLE session_handle, CK_OBJECT_HANDLE pub_handle,
                                  CK_OBJECT_HANDLE priv_handle, char *keypair_fname) {
   int ret = -1;
   CK_RV retCode = CKR_GENERAL_ERROR;
   BIO *outfile = NULL;
   DSA *dsa = NULL;
   const unsigned ndxP = 0;
   const unsigned ndxQ = 1;
   const unsigned ndxG = 2;
   const unsigned ndxV = 3;
   CK_ATTRIBUTE ckaPublic[] = {
       {CKA_PRIME, NULL_PTR, 0}, {CKA_SUBPRIME, NULL_PTR, 0}, {CKA_BASE, NULL_PTR, 0}, {CKA_VALUE, NULL_PTR, 0},
   };
   CK_BYTE baOne[1] = { 0x01 };
   CK_ATTRIBUTE attrOne = { ~0UL, &baOne, sizeof(baOne) };

   /* open file before hsm io */
   if ((outfile = BIO_new(BIO_s_file())) == NULL) {
      fprintf(stderr, "Cannot create BIO used to write out PEM key pair.\n");
      goto err;
   }

   if (BIO_write_filename(outfile, keypair_fname) <= 0) {
      fprintf(stderr, "Cannot open [%s] for writing.\n", keypair_fname);
      goto err;
   }

   /* extract public key */
   retCode = sautil_ckatab_malloc_object(ckaPublic, LUNA_DIM(ckaPublic), pub_handle, session_handle);
   if (retCode != CKR_OK) {
      fprintf(stderr, "Failed to extract DSA public key. err 0x%x\n", (int)retCode);
      goto err;
   }

   if (verbose) {
      luna_dump_hex(stdout, "CKA_VALUE=", (CK_BYTE_PTR)ckaPublic[ndxV].pValue, ckaPublic[ndxV].ulValueLen);
   }

   /* allocate the dsa structure */
   if ((dsa = DSA_new()) == NULL)
      goto err;
   if (!LUNA_DSA_SET_p_q_g(dsa, 
      BN_bin2bn(ckaPublic[ndxP].pValue, ckaPublic[ndxP].ulValueLen, NULL), 
      BN_bin2bn(ckaPublic[ndxQ].pValue, ckaPublic[ndxQ].ulValueLen, NULL), 
      BN_bin2bn(ckaPublic[ndxG].pValue, ckaPublic[ndxG].ulValueLen, NULL)))
      goto err;
   if (!LUNA_DSA_SET_pub_priv(dsa, 
      BN_bin2bn(ckaPublic[ndxV].pValue, ckaPublic[ndxV].ulValueLen, NULL), 
      BN_bin2bn(attrOne.pValue, attrOne.ulValueLen, NULL)))
      goto err;

   /* write the pem file */
   if (!PEM_write_bio_DSAPrivateKey(outfile, dsa, NULL, NULL, 0, NULL, NULL))
      goto err;

   ret = 0;

   if (verbose)
      fprintf(stdout, "Wrote file \"%s\".\n", (char *)keypair_fname);

err:
   sautil_ckatab_free_all(ckaPublic, LUNA_DIM(ckaPublic), 0);
   return ret;
}

static void luna_dump_hex(FILE *fp, const char *szContext, unsigned char *id, unsigned size) {
   unsigned ii = 0;
   fprintf(fp, "%s", (char *)szContext);
   for (ii = 0; ii < size; ii++) {
      fprintf(fp, "%02x", (unsigned)id[ii]); /* lowercase for dnssec */
   }
   fprintf(fp, "\n");
}

int write_pem_rsa_key_pair(CK_SESSION_HANDLE session_handle, CK_OBJECT_HANDLE pub_handle, CK_OBJECT_HANDLE priv_handle,
                           char *keypair_fname) {
   int ret = -1, mod_len = 0, exp_len = 0;
   CK_RV retCode;
   CK_ATTRIBUTE rsa_modulus_template[2];
   CK_BYTE_PTR n = NULL, exp_val = NULL;
   BIO *outfile = NULL;
   RSA *rsa;
   CK_BYTE baOne[1] = { 0x01 };
   CK_ATTRIBUTE attrOne = { ~0UL, &baOne, sizeof(baOne) };

   rsa_modulus_template[0].type = CKA_MODULUS;
   rsa_modulus_template[0].pValue = NULL_PTR;
   rsa_modulus_template[0].ulValueLen = 0;

   rsa_modulus_template[1].type = CKA_PUBLIC_EXPONENT;
   rsa_modulus_template[1].pValue = NULL_PTR;
   rsa_modulus_template[1].ulValueLen = 0;

   /* create a BIO to be used for writing out the keypair, do it now before we start talking
   * to hardware */
   if ((outfile = BIO_new(BIO_s_file())) == NULL) {
      fprintf(stderr, "Cannot create BIO used to write out PEM key pair.\n");
      goto err;
   }

   if (BIO_write_filename(outfile, keypair_fname) <= 0) {
      fprintf(stderr, "Cannot open [%s] for writing.\n", keypair_fname);
      goto err;
   }

   /* extract public key, modulus size first */
   /* Use the private key ALWAYS because we might not have a public key */
   retCode = p11.std->C_GetAttributeValue(session_handle, priv_handle, rsa_modulus_template, 2);
   if (retCode != CKR_OK) {
      fprintf(stderr, "Failed to extract modulus size of key pair. err 0x%x\n", (int)retCode);
      goto err;
   }

   /* allocate enough space to extract modulus itself */
   mod_len = rsa_modulus_template[0].ulValueLen;
   n = (CK_BYTE_PTR)malloc(mod_len);
   if (n == NULL)
      goto err;
   rsa_modulus_template[0].pValue = n;

   /* extract exponent */
   exp_len = rsa_modulus_template[1].ulValueLen;
   exp_val = (CK_BYTE_PTR)malloc(exp_len);
   if (exp_val == NULL)
      goto err;
   rsa_modulus_template[1].pValue = exp_val;

   /* extract public key, get modulus */
   /* Use the private key ALWAYS because we might not have a public key */
   retCode = p11.std->C_GetAttributeValue(session_handle, priv_handle, rsa_modulus_template, 2);
   if (retCode != CKR_OK) {
      fprintf(stderr, "Failed to extract modulus of key pair. err 0x%x\n", (int)retCode);
      goto err;
   }

   if (verbose) {
      luna_dump_hex(stdout, "CKA_MODULUS=", n, mod_len);
      luna_dump_hex(stdout, "CKA_PUBLIC_EXPONENT=", exp_val, exp_len);
   }

   /* allocate the rsa structure */
   if ((rsa = RSA_new()) == NULL)
      goto err;
   if (!LUNA_RSA_SET_n_e_d(rsa,
      BN_bin2bn(n, mod_len, NULL),
      BN_bin2bn(exp_val, exp_len, NULL),
      BN_bin2bn(attrOne.pValue, attrOne.ulValueLen, NULL)))
      goto err;
   if (!LUNA_RSA_SET_p_q(rsa,
      BN_bin2bn(attrOne.pValue, attrOne.ulValueLen, NULL),
      BN_bin2bn(attrOne.pValue, attrOne.ulValueLen, NULL)))
      goto err;
   if (!LUNA_RSA_SET_dmp1_dmq1_iqmp(rsa,
      BN_bin2bn(attrOne.pValue, attrOne.ulValueLen, NULL),
      BN_bin2bn(attrOne.pValue, attrOne.ulValueLen, NULL),
      BN_bin2bn(attrOne.pValue, attrOne.ulValueLen, NULL)))
      goto err;

   /* write the pem file */
   if (!PEM_write_bio_RSAPrivateKey(outfile, rsa, NULL, NULL, 0, NULL, NULL))
      goto err;

   ret = 0;

   if (verbose)
      fprintf(stdout, "Wrote file \"%s\".\n", (char *)keypair_fname);

err:

   if (n)
      free(n);

   if (exp_val)
      free(exp_val);

   return ret;
}

#ifdef LUNA_OSSL_DH

int write_pem_dh_key_pair(CK_SESSION_HANDLE session_handle, CK_OBJECT_HANDLE pub_handle, CK_OBJECT_HANDLE priv_handle,
                          const CK_BYTE *dh_prime, const CK_USHORT dh_prime_size, const CK_BYTE *dh_base,
                          const CK_USHORT dh_base_size, unsigned char *keypair_fname) {
   int ret = -1, pub_val_len;
   CK_RV retCode;
   CK_ATTRIBUTE dh_pub_value_template[] = {{CKA_VALUE, NULL_PTR, 0}};
   CK_BYTE_PTR n = NULL;
   BIO *outfile = NULL;
   DH *dh;
   unsigned char *pub_val;

   /* create a BIO to be used for writing out the keypair, do it now before we start talking
   * to hardware */
   if ((outfile = BIO_new(BIO_s_file())) == NULL) {
      fprintf(stderr, "Cannot create BIO used to write out PEM key pair.\n");
      goto err;
   }

   if (BIO_write_filename(outfile, keypair_fname) <= 0) {
      fprintf(stderr, "Cannot open [%s] for writing.\n", keypair_fname);
      goto err;
   }

   /* extract public key, modulus size first */
   retCode = p11.std->C_GetAttributeValue(session_handle, pub_handle, dh_pub_value_template, 1);
   if (retCode != CKR_OK) {
      fprintf(stderr, "Failed to extract modulus size of key pair. err 0x%x\n", (int)retCode);
      goto err;
   }

   /* allocate enough space to extract public value */
   pub_val_len = dh_pub_value_template[0].ulValueLen;
   pub_val = (CK_BYTE_PTR)malloc(pub_val_len);
   dh_pub_value_template[0].pValue = pub_val;

   /* extract public key */
   retCode = p11.std->C_GetAttributeValue(session_handle, pub_handle, dh_pub_value_template, 1);
   if (retCode != CKR_OK) {
      fprintf(stderr, "Failed to extract modulus of key pair. err 0x%x\n", (int)retCode);
      goto err;
   }

   /* get us an rsa structure and allocate its components */
   if ((dh = DH_new()) == NULL)
      goto err;
   if ((dh->p = BN_new()) == NULL)
      goto err;
   if ((dh->g = BN_new()) == NULL)
      goto err;
   if ((dh->pub_key = BN_new()) == NULL)
      goto err;
   if ((dh->priv_key = BN_new()) == NULL)
      goto err;

   dh->p = BN_bin2bn(dh_prime, dh_prime_size, dh->p);
   dh->g = BN_bin2bn(dh_base, dh_base_size, dh->g);
   dh->pub_key = BN_bin2bn(pub_val, pub_val_len, dh->pub_key);

#if 0  
  if (!PEM_write_bio_DHPrivateKey(outfile, dh, NULL, NULL, 0, NULL, NULL))
    goto err;
#endif

   ret = 0;

err:

   if (n)
      free(n);

   return ret;
}

#else

static void op_no_dh() { fprintf(stderr, "Diffie-Hellman (DH) is not supported via gem engine.\n"); }

int write_pem_dh_key_pair(CK_SESSION_HANDLE session_handle, CK_OBJECT_HANDLE pub_handle, CK_OBJECT_HANDLE priv_handle,
                          const CK_BYTE *dh_prime, const CK_USHORT dh_prime_size, const CK_BYTE *dh_base,
                          const CK_USHORT dh_base_size, unsigned char *keypair_fname) {
   op_no_dh();
   return -1;
}

#endif

int op_generate_dsa_key_pair(CK_SLOT_ID slotid, CK_USHORT modulussize, char *keypair_fname, char *param_fname) {
   int rc_final = -1;
   int ret;
   CK_RV retCode = CKR_GENERAL_ERROR;
   CK_ATTRIBUTE *dsa_pub_template = NULL;
   CK_ATTRIBUTE *dsa_priv_template = NULL;
   CK_USHORT dsa_pub_template_size = 0;
   CK_USHORT dsa_priv_template_size = 0;
   CK_OBJECT_HANDLE pub_handle = CK_INVALID_HANDLE;
   CK_OBJECT_HANDLE priv_handle = CK_INVALID_HANDLE;
   CK_SESSION_HANDLE session_handle = CK_INVALID_HANDLE;
   CK_BYTE *pubLabel = NULL;
   CK_BYTE *privLabel = NULL;
   DSA *dsaparam = NULL;
   CK_BYTE_PTR bufP = NULL;
   CK_BYTE_PTR bufQ = NULL;
   CK_BYTE_PTR bufG = NULL;
   CK_ULONG lenbufP = 0;
   CK_ULONG lenbufQ = 0;
   CK_ULONG lenbufG = 0;
   BIO *inbio = NULL;

   char szPubLabel[LUNA_MAX_STRING_LEN + 1];
   char szPrivLabel[LUNA_MAX_STRING_LEN + 1];
   CK_BYTE baCkId[20];

   memset(szPubLabel, 0, sizeof(szPubLabel));
   memset(szPrivLabel, 0, sizeof(szPrivLabel));
   memset(baCkId, 0, sizeof(baCkId));

   ret = set_application_id(app_id_hi, app_id_lo);
   if (ret != 0) {
       fprintf(stderr, "set_application_id failed. \n");
       goto err;
   }

   if (param_fname != NULL) {
      /* get p, q, g from file */
      if ((inbio = BIO_new(BIO_s_file())) == NULL) {
         fprintf(stderr, "BIO_new failed. \n");
         goto err;
      }

      if (BIO_read_filename(inbio, param_fname) <= 0) {
         fprintf(stderr, "BIO_read_filename failed. \n");
         goto err;
      }

      if ((dsaparam = PEM_read_bio_DSAparams(inbio, NULL, NULL, NULL)) == NULL) {
         fprintf(stderr, "PEM_read_bio_DSAparams failed. \n");
         goto err;
      }

      bufP = (CK_BYTE_PTR)OPENSSL_malloc(BN_num_bytes(LUNA_DSA_GET_p(dsaparam)));
      lenbufP = BN_bn2bin(LUNA_DSA_GET_p(dsaparam), bufP);
      bufQ = (CK_BYTE_PTR)OPENSSL_malloc(BN_num_bytes(LUNA_DSA_GET_q(dsaparam)));
      lenbufQ = BN_bn2bin(LUNA_DSA_GET_q(dsaparam), bufQ);
      bufG = (CK_BYTE_PTR)OPENSSL_malloc(BN_num_bytes(LUNA_DSA_GET_g(dsaparam)));
      lenbufG = BN_bn2bin(LUNA_DSA_GET_g(dsaparam), bufG);
      modulussize = (lenbufP * 8);

   } else if ((param_fname == NULL) && (modulussize == 1024)) {
      /* legacy hardcoded p, q, g */
      bufP = dsa_1024_prime;
      lenbufP = sizeof(dsa_1024_prime);
      bufQ = dsa_1024_subPrime;
      lenbufQ = sizeof(dsa_1024_subPrime);
      bufG = dsa_1024_base;
      lenbufG = sizeof(dsa_1024_base);
      modulussize = (lenbufP * 8);

   } else {
      fprintf(stderr, "Missing DSA parameters file for modulussize %u. \n", (unsigned)modulussize);
      goto err;
   }

   if (bufP == NULL || bufQ == NULL || bufG == NULL) {
      fprintf(stderr, "malloc failed.\n");
      goto err;
   }

   if (modulussize >= LOCAL_DSA_KEYSIZE_MIN) {
      sautil_sprint_unique(szPubLabel, sizeof(szPubLabel),
              szPrivLabel, sizeof(szPrivLabel),
              "DSA", modulussize);
      pubLabel = (CK_BYTE *)szPubLabel;
      privLabel = (CK_BYTE *)szPrivLabel;
   } else {
      fprintf(stderr, "DSA modulus size too small [%u]\n", (unsigned)modulussize);
      goto err;
   }

   if (open_session(slotid, &session_handle) != 0) {
      fprintf(stderr, "open_session failed. \n");
      goto err;
   }

   /* if we're not logged in here, return an error */
   if (!loggedin(slotid)) {
      fprintf(stderr, "Error: The user is not logged in to the selected slot (%d).\n", (int)slotid);
      goto err;
   }

   /* generate temporary CKA_ID */
   if (sautil_sha1_prng(session_handle, baCkId) != CKR_OK) {
      fprintf(stderr, "Failed RNG.\n");
      goto err;
   }

   sautil_strncpy(szPubLabel, "dsa-public-", sizeof(szPubLabel));
   (void)luna_sprintf_hex(&szPubLabel[11], baCkId, sizeof(baCkId));
   sautil_strncpy(szPrivLabel, "dsa-private-", sizeof(szPrivLabel));
   (void)luna_sprintf_hex(&szPrivLabel[12], baCkId, sizeof(baCkId));

   if (have_label) {
      sautil_strncpy(szPubLabel, sautil_label, sizeof(szPubLabel));
      sautil_strncpy(szPrivLabel, sautil_label, sizeof(szPrivLabel));
   }

   ret =
       init_dsa_key_template(&dsa_pub_template, &dsa_priv_template, &dsa_pub_template_size, &dsa_priv_template_size,
                             pubLabel, privLabel, bufP, lenbufP, bufQ, lenbufQ, bufG, lenbufG, baCkId, sizeof(baCkId));
   if (ret != 0) {
       fprintf(stderr, "init_dsa_key_template failed. \n");
       goto err;
   }

   if (luna_ckatab_pre_keygen(session_handle, dsa_priv_template, dsa_priv_template_size)) {
      fprintf(stderr, "luna_ckatab_pre_keygen failed. \n");
      goto err;
   }

   if (verbose)
      fprintf(stdout, "Generating %d bit DSA key pair ... (please wait) \n", (int)modulussize);

   /* C_GenerateKeyPair */
   if (1) {
      CK_MECHANISM dsa_key_gen_mech = {CKM_DSA_KEY_PAIR_GEN, NULL_PTR, 0};

      retCode = p11.std->C_GenerateKeyPair(session_handle, &dsa_key_gen_mech, dsa_pub_template, dsa_pub_template_size,
                                           dsa_priv_template, dsa_priv_template_size, &pub_handle, &priv_handle);
   }

   if (retCode != CKR_OK) {
      fprintf(stderr, "Generate DSA Key Pair Error 0x%x.\n", (int)retCode);
      if (retCode == CKR_DEVICE_ERROR)
         fprintf(stderr, "  Device Error. Not logged in with -o?\n");
      goto err;
   }

   if (verbose) {
      fprintf(stdout, "DSA Public key handle is %u\n", (unsigned)pub_handle);
      fprintf(stdout, "DSA Private key handle is %u\n", (unsigned)priv_handle);
   }

   if (verbose) {
      luna_dump_hex(stdout, "CKA_ID=", baCkId, sizeof(baCkId));
   }

   ret = write_pem_dsa_key_pair(session_handle, pub_handle, priv_handle, keypair_fname);
   if (ret != 0) {
      fprintf(stderr, "write_pem_dsa_key_pair failed. \n");
      goto err;
   }

   rc_final = 0;

err:
   sautil_ckatab_free_all(dsa_pub_template, dsa_pub_template_size, 1);
   sautil_ckatab_free_all(dsa_priv_template, dsa_priv_template_size, 1);

   if (bufP != dsa_1024_prime) {
      OPENSSL_free(bufP);
      OPENSSL_free(bufQ);
      OPENSSL_free(bufG);
   }

   if (inbio != NULL) {
      BIO_free(inbio);
   }

   close_session(session_handle);
   session_handle = 0;
   return rc_final;
}

int op_generate_rsa_key_pair(CK_SLOT_ID slotid, CK_USHORT modulussize, char *keypair_fname) {
   int ret;
   CK_RV retCode;
   CK_ATTRIBUTE *rsa_pub_template = NULL;
   CK_ATTRIBUTE *rsa_priv_template = NULL;
   CK_USHORT rsa_pub_template_size, rsa_priv_template_size;
   CK_OBJECT_HANDLE pub_handle, priv_handle;
   CK_SESSION_HANDLE session_handle;

   CK_BYTE arrExponent3[1] = {0x03};
   CK_BYTE arrExponent4[3] = {0x01, 0x00, 0x01};
   CK_BYTE *ptrExponent = NULL;
   int countofExponent = 0;

   CK_BYTE *pubLabel = NULL, *privLabel = NULL;
   char szPubLabel[LUNA_MAX_STRING_LEN + 1];
   char szPrivLabel[LUNA_MAX_STRING_LEN + 1];
   CK_BYTE baCkId[20];

   memset(szPubLabel, 0, sizeof(szPubLabel));
   memset(szPrivLabel, 0, sizeof(szPrivLabel));
   memset(baCkId, 0, sizeof(baCkId));

   ret = set_application_id(app_id_hi, app_id_lo);
   if (ret != 0)
      return -1;

   sautil_sprint_unique(szPubLabel, sizeof(szPubLabel),
           szPrivLabel, sizeof(szPrivLabel),
           "RSA", modulussize);
   pubLabel = (CK_BYTE *)szPubLabel;
   privLabel = (CK_BYTE *)szPrivLabel;

   switch (optSelExponent) {
      case OPT_SEL_EXP3:
         ptrExponent = arrExponent3;
         countofExponent = sizeof(arrExponent3);
         break;
      case OPT_SEL_EXP4:
         ptrExponent = arrExponent4;
         countofExponent = sizeof(arrExponent4);
         break;
      case OPT_SEL_EXPOTHER:
         ptrExponent = bpOptSelExponent;
         countofExponent = countofOptSelExponent;
         break;
      case OPT_SEL_EXPNULL:
      default:
         break;
   }

   if (open_session(slotid, &session_handle) != 0)
      return -1;

   /* if we're not logged in here, return an error */
   if (!loggedin(slotid)) {
      fprintf(stderr, "Error: The user is not logged in to the selected slot (%d).\n", (int)slotid);
      return -1;
   }

   /* generate temporary CKA_ID */
   if (sautil_sha1_prng(session_handle, baCkId) != CKR_OK) {
      fprintf(stderr, "Failed RNG.\n");
      return -1;
   }

   sautil_strncpy(szPubLabel, "rsa-public-", sizeof(szPubLabel));
   (void)luna_sprintf_hex(&szPubLabel[11], baCkId, sizeof(baCkId));
   sautil_strncpy(szPrivLabel, "rsa-private-", sizeof(szPrivLabel));
   (void)luna_sprintf_hex(&szPrivLabel[12], baCkId, sizeof(baCkId));

   if (have_label) {
      sautil_strncpy(szPubLabel, sautil_label, sizeof(szPubLabel));
      sautil_strncpy(szPrivLabel, sautil_label, sizeof(szPrivLabel));
   }

   /* init tmeplate */
   ret = init_rsa_key_template(&rsa_pub_template, &rsa_priv_template, &rsa_pub_template_size, &rsa_priv_template_size,
                               modulus_size, ptrExponent, countofExponent, privLabel, pubLabel, baCkId, sizeof(baCkId));
   if (ret != 0)
      return -1;

   if (luna_ckatab_pre_keygen(session_handle, rsa_priv_template, rsa_priv_template_size)) {
      goto err;
   }

   /* C_GenerateKeyPair */
   if (verbose)
      fprintf(stdout, "Generating %d bit RSA key pair ... (please wait) \n", (int)modulussize);

   if (1) {
      CK_MECHANISM rsa_key_gen_mech = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0};

      retCode = p11.std->C_GenerateKeyPair(session_handle, &rsa_key_gen_mech, rsa_pub_template, rsa_pub_template_size,
                                           rsa_priv_template, rsa_priv_template_size, &pub_handle, &priv_handle);
   }

   if (retCode != CKR_OK) {
      fprintf(stderr, "Generate Key Pair Error 0x%x.\n", (int)retCode);
      switch (retCode) {
         case CKR_DEVICE_ERROR:
            fprintf(stderr, "  Device Error. [Hint: is user logged in with sautil -o ?] \n");
            break;
         case CKR_ATTRIBUTE_VALUE_INVALID:
            fprintf(stderr, "  Attribute Value Invalid.  [Hint: is modulus size %u supported by HSM ?] \n",
                    (unsigned)modulussize);
            break;
      }
      goto err;
   }

   if (verbose) {
      fprintf(stdout, "RSA Public key handle is %u\n", (unsigned)pub_handle);
      fprintf(stdout, "RSA Private key handle is %u\n", (unsigned)priv_handle);
      fprintf(stdout, "CKA_LABEL=%s\n", (char *)szPrivLabel);
   }

   if (verbose) {
      luna_dump_hex(stdout, "CKA_ID=", baCkId, sizeof(baCkId));
   }

   ret = write_pem_rsa_key_pair(session_handle, pub_handle, priv_handle, keypair_fname);
   if (ret != 0)
      goto err;

   sautil_ckatab_free_all(rsa_pub_template, rsa_pub_template_size, 1);
   sautil_ckatab_free_all(rsa_priv_template, rsa_priv_template_size, 1);
   return 0;

err:
   sautil_ckatab_free_all(rsa_pub_template, rsa_pub_template_size, 1);
   sautil_ckatab_free_all(rsa_priv_template, rsa_priv_template_size, 1);
   close_session(session_handle);
   session_handle = 0;
   return -1;
}

#ifdef CA3UTIL_DIFFIE_HELLMAN

int op_generate_dh_key_pair(CK_SLOT_ID slotid, CK_USHORT size, char *keypair_fname) {
   DH *dh;
   int ret, retc = -1;
   CK_RV retCode;
   CK_ATTRIBUTE *dh_pub_template, *dh_priv_template;
   CK_USHORT dh_pub_template_size, dh_priv_template_size;
   CK_OBJECT_HANDLE pub_handle, priv_handle;
   CK_SESSION_HANDLE session_handle;
   unsigned char *base = NULL, *prime = NULL;
   int base_len, prime_len;

   ret = set_application_id(app_id_hi, app_id_lo);
   if (ret != 0)
      return -1;
   if (open_session(slotid, &session_handle) != 0)
      return -1;

   /* if we're not logged in here, return an error */
   if (!loggedin(slotid)) {
      fprintf(stderr, "Error: The user is not logged in to the selected slot (%d).\n", (int)slotid);
      return -1;
   }

   dh = DH_generate_parameters(size, DH_GENERATOR_2, NULL, NULL);
   if (!dh) {
      fprintf(stderr, "Failed to generate DH parameters for %ubit key.\n", (unsigned)size);
      return -1;
   }

   base = (unsigned char *)malloc(BN_num_bytes(dh->p));
   prime = (unsigned char *)malloc(BN_num_bytes(dh->g));

   prime_len = BN_bn2bin(dh->p, prime);
   base_len = BN_bn2bin(dh->g, base);

   ret = init_dh_key_template(&dh_pub_template, &dh_priv_template, &dh_pub_template_size, &dh_priv_template_size,
                              (CK_BYTE_PTR) "Public DH key", (CK_BYTE_PTR) "Private DH key", prime, prime_len, base,
                              base_len);

   if (ret != 0)
      goto err;

   if (luna_ckatab_pre_keygen(session_handle, dh_priv_template, dh_priv_template_size)) {
      goto err;
   }

   if (verbose)
      fprintf(stdout, "Generating %u bit DH key pair ... (please wait) \n", (unsigned)size);

   if (1) {
      CK_MECHANISM dh_key_gen_mech = {CKM_DH_PKCS_KEY_PAIR_GEN, NULL_PTR, 0};

      retCode = p11.std->C_GenerateKeyPair(session_handle, &dh_key_gen_mech, dh_pub_template, dh_pub_template_size,
                                           dh_priv_template, dh_priv_template_size, &pub_handle, &priv_handle);
   }

   if (retCode != CKR_OK) {
      fprintf(stderr, "Generate DH Key Pair Error 0x%x.\n", (int)retCode);
      if (retCode == CKR_DEVICE_ERROR)
         fprintf(stderr, "  Device Error. Not logged in with -o?\n");
      goto err;
   }

   if (verbose) {
      fprintf(stdout, "DH Public  key handle is %u\n", (unsigned)pub_handle);
      fprintf(stdout, "DH Private key handle is %u\n", (unsigned)priv_handle);
   }

   ret = write_pem_dh_key_pair(session_handle, pub_handle, priv_handle, keypair_fname);
   if (ret != 0)
      goto err;

   retc = 0;

err:

   if (base)
      free(base);
   if (prime)
      free(prime);
   close_session(session_handle);
   session_handle = 0;
   return retc;
}

#endif /* CA3UTIL_DIFFIE_HELLMAN */

CK_OBJECT_HANDLE
luna_find_dsa_handle(CK_SESSION_HANDLE session_handle, DSA *dsa, short flagPrivate) {
   int id_val_len;
   CK_RV retCode;
   char *bufP, *bufQ, *bufG, *bufPub;
   CK_ULONG rcCount = 0;
   CK_ULONG rcBase = 0;
   CK_ATTRIBUTE attrib[6];
   CK_OBJECT_HANDLE handle = 0;
   CK_USHORT obj_count = 0;
   CK_BYTE_PTR id_val = NULL;
   CK_ULONG ulClass = 0;
   CK_ATTRIBUTE dsa_id_value_template[] = {{CKA_ID, NULL_PTR, 0}};

   bufP = (char *)OPENSSL_malloc(BN_num_bytes(LUNA_DSA_GET_p(dsa)));
   bufQ = (char *)OPENSSL_malloc(BN_num_bytes(LUNA_DSA_GET_q(dsa)));
   bufG = (char *)OPENSSL_malloc(BN_num_bytes(LUNA_DSA_GET_g(dsa)));
   bufPub = (char *)OPENSSL_malloc(BN_num_bytes(LUNA_DSA_GET_pub_key(dsa)));

   rcCount = 0;

   attrib[rcCount].type = CKA_PRIME;
   attrib[rcCount].pValue = bufP;
   attrib[rcCount].ulValueLen = BN_bn2bin(LUNA_DSA_GET_p(dsa), (unsigned char *)attrib[rcCount].pValue);
   rcCount++;

   attrib[rcCount].type = CKA_SUBPRIME;
   attrib[rcCount].pValue = bufQ;
   attrib[rcCount].ulValueLen = BN_bn2bin(LUNA_DSA_GET_q(dsa), (unsigned char *)attrib[rcCount].pValue);
   rcCount++;
   rcBase = rcCount;

#if 0
  /* FIXME: CKA_BASE with leading zero is a problem */
  attrib[rcCount].type = CKA_BASE;
  attrib[rcCount].pValue = bufG;
  attrib[rcCount].ulValueLen = BN_bn2bin(LUNA_DSA_GET_g(dsa), (unsigned char*)attrib[rcCount].pValue);
  rcCount++;
#endif

   attrib[rcCount].type = CKA_VALUE;
   attrib[rcCount].pValue = bufPub;
   attrib[rcCount].ulValueLen = BN_bn2bin(LUNA_DSA_GET_pub_key(dsa), (unsigned char *)attrib[rcCount].pValue);
   rcCount++;

   /* Always find public DSA key first. */
   ulClass = CKO_PUBLIC_KEY;
   attrib[rcCount].type = CKA_CLASS;
   attrib[rcCount].pValue = &ulClass;
   attrib[rcCount].ulValueLen = sizeof(ulClass);
   rcCount++;

   retCode = p11.std->C_FindObjectsInit(session_handle, attrib, rcCount);
   if (retCode != CKR_OK) {
      fprintf(stderr, "C_FindObjectInit: Unable to initialize search for a %s DSA key object err 0x%x\n",
              "public", (int)retCode);
      goto err;
   }

   retCode = p11.std->C_FindObjects(session_handle, &handle, 1, &obj_count);
   if (retCode != CKR_OK) {
      fprintf(stderr, "C_FindObject: unable to find a %s DSA key object. err 0x%x\n",
              "public", (int)retCode);
      goto err;
   }

   if (!obj_count) {
      fprintf(stderr, "Token does not contain specified DSA keypair.\n");
      goto err;
   }
   /* Need to perform additional searching when looking for flagPrivate key handles.
   * We do not have the flagPrivate value and PKCS11 does not allow searching of flagPrivate
   * DSA objects based on their public values. We use instead a unique CKA_ID attribute
   * set during dsa keygen. This ID is shared by pub/priv dsa keys. First extract the
   * CKA_ID from the correct public key, then search for a flagPrivate one keyed by that value */

   if (flagPrivate) {
      /* Extract its CKA_ID attribute unique for a dsa key pair */
      retCode = p11.std->C_GetAttributeValue(session_handle, handle, dsa_id_value_template, 1);
      if (retCode != CKR_OK) {
         fprintf(stderr, "Failed to extract size of DSA keypair ID value. err 0x%x\n", (int)retCode);
         goto err;
      }
      /* allocate enough space to extract the ID value itself */
      id_val_len = dsa_id_value_template[0].ulValueLen;
      id_val = (CK_BYTE_PTR)malloc(id_val_len);
      dsa_id_value_template[0].pValue = id_val;
      /* extract the ID value */
      retCode = p11.std->C_GetAttributeValue(session_handle, handle, dsa_id_value_template, 1);
      if (retCode != CKR_OK) {
         fprintf(stderr, "Failed to extract DSA keypair ID value . err 0x%x\n", (int)retCode);
         goto err;
      }

      rcCount = rcBase;

      ulClass = CKO_PRIVATE_KEY;
      attrib[rcCount].type = CKA_CLASS;
      attrib[rcCount].pValue = &ulClass;
      attrib[rcCount].ulValueLen = sizeof(ulClass);
      rcCount++;

      attrib[rcCount].type = CKA_ID;
      attrib[rcCount].pValue = id_val;
      attrib[rcCount].ulValueLen = id_val_len;
      rcCount++;

      /* Optionally, find DSA private key second. */
      retCode = p11.std->C_FindObjectsInit(session_handle, attrib, rcCount);
      if (retCode != CKR_OK) {
         fprintf(stderr, "C_FindObjectInit: Unable to initialize search for a %s DSA key object err 0x%x\n",
                 "private", (int)retCode);
         goto err;
      }

      retCode = p11.std->C_FindObjects(session_handle, &handle, 1, &obj_count);
      if (retCode != CKR_OK) {
         fprintf(stderr, "C_FindObject: unable to find a %s DSA key object. err 0x%x\n",
                 "private", (int)retCode);
         goto err;
      }
   }

   if (!obj_count)
      handle = 0;

err:

   OPENSSL_free(bufP);
   OPENSSL_free(bufQ);
   OPENSSL_free(bufG);
   OPENSSL_free(bufPub);

   return (CK_OBJECT_HANDLE)handle;
}

/* set private to indicate you are looking for a private key */
/* reset to 0 to look for a public */
static CK_OBJECT_HANDLE luna_find_rsa_handle(CK_SESSION_HANDLE session_handle, RSA *rsa, short flagPrivate) {
   CK_OBJECT_CLASS keyclassPublic = CKO_PUBLIC_KEY;
   CK_OBJECT_CLASS keyclassPrivate = CKO_PRIVATE_KEY;
   CK_KEY_TYPE keytypeRSA = CKK_RSA;

   CK_RV retCode;
   BIGNUM *n, *e;
   char *bufN, *bufE;
   CK_OBJECT_HANDLE handle = 0;
   CK_USHORT obj_count = 0;
   unsigned ndx = 0;
   CK_ATTRIBUTE attrib[4];

   n = LUNA_RSA_GET_n(rsa);
   e = LUNA_RSA_GET_e(rsa);

   bufN = (char *)OPENSSL_malloc(BN_num_bytes(n));
   bufE = (char *)OPENSSL_malloc(BN_num_bytes(e));

   if (flagPrivate) {
      attrib[ndx = 0].type = CKA_CLASS;
      attrib[ndx].pValue = (CK_BYTE_PTR)&keyclassPrivate;
      attrib[ndx].ulValueLen = sizeof(keyclassPrivate);
   } else {
      attrib[ndx = 0].type = CKA_CLASS;
      attrib[ndx].pValue = (CK_BYTE_PTR)&keyclassPublic;
      attrib[ndx].ulValueLen = sizeof(keyclassPublic);
   }

   attrib[ndx = 1].type = CKA_KEY_TYPE;
   attrib[ndx].pValue = (CK_BYTE_PTR)&keytypeRSA;
   attrib[ndx].ulValueLen = sizeof(keytypeRSA);

   attrib[ndx = 2].type = CKA_PUBLIC_EXPONENT;
   attrib[ndx].pValue = (CK_BYTE_PTR)bufE;
   attrib[ndx].ulValueLen = BN_bn2bin(e, (unsigned char *)attrib[2].pValue);

   attrib[ndx = 3].type = CKA_MODULUS;
   attrib[ndx].pValue = (CK_BYTE_PTR)bufN;
   attrib[ndx].ulValueLen = BN_bn2bin(n, (unsigned char *)attrib[3].pValue);

   retCode = p11.std->C_FindObjectsInit(session_handle, attrib, 4);
   if (retCode != CKR_OK) {
      fprintf(stderr, "C_FindObjectInit: Unable to initialize search for a %s RSA key object err 0x%x\n",
              (flagPrivate) ? "private" : "public", (int)retCode);
      goto err;
   }

   retCode = p11.std->C_FindObjects(session_handle, &handle, 1, &obj_count);
   if (retCode != CKR_OK) {
      fprintf(stderr, "C_FindObject: unable to find %s RSA key object. err 0x%x\n",
              (flagPrivate) ? "private" : "public", (int)retCode);
      goto err;
   }

   if (!obj_count)
      handle = 0;

err:

   OPENSSL_free(bufN);
   OPENSSL_free(bufE);

   return (CK_OBJECT_HANDLE)handle;
}

static int op_delete_dsa_key_pair(CK_SLOT_ID slotid, char *keypair_fname) {
   BIO *f = NULL;
   int ret = -1;
   DSA *dsa = NULL;
   CK_OBJECT_HANDLE handle;
   CK_SESSION_HANDLE session_handle;
   CK_RV retCode;

   /* create a BIO to be used for writing out the keypair, do it now before we start talking
    * to hardware */
   if ((f = BIO_new(BIO_s_file())) == NULL) {
      fprintf(stderr, "Cannot create BIO used to read DSA PEM key pair.\n");
      goto err;
   }

   if (BIO_read_filename(f, keypair_fname) <= 0) {
      fprintf(stderr, "Cannot open [%s] for reading.\n", keypair_fname);
      goto err;
   }

   if (!(dsa = PEM_read_bio_DSAPrivateKey(f, NULL, NULL, NULL))) {
      fprintf(stderr, "Failed reading DSA key pair. file: [%s]\n", keypair_fname);
      goto err;
   }

   if (set_application_id(app_id_hi, app_id_lo) != 0)
      goto err;
   if (open_session(slotid, &session_handle) != 0)
      goto err;

   /* if we're not logged in here, return an error */
   if (!loggedin(slotid)) {
      fprintf(stderr, "Error: The user is not logged in to the selected slot (%d).\n", (int)slotid);
      goto err;
   }

   /* ALWAYS Destroy private object first, if the public dsa key is erased first
    * then we wont be able to find the private one */
   handle = luna_find_dsa_handle(session_handle, dsa, 1);
   if ((handle == CK_INVALID_HANDLE) || ((retCode = p11.std->C_DestroyObject(session_handle, handle)) != CKR_OK)) {
      fprintf(stderr, "Delete private failed.\n");
      goto err;
   }

   if (verbose) {
      fprintf(stdout, "DSA private key handle is %u\n", (unsigned)handle);
   }

   fprintf(stderr, "Delete private ok.\n");

   /* Destroy public object */
   handle = luna_find_dsa_handle(session_handle, dsa, 0);
   if ((handle == CK_INVALID_HANDLE) || ((retCode = p11.std->C_DestroyObject(session_handle, handle)) != CKR_OK)) {
      fprintf(stderr, "Delete public failed.\n");
      goto err;
   }

   if (verbose) {
      fprintf(stdout, "DSA public key handle is %u\n", (unsigned)handle);
   }

   fprintf(stderr, "Delete public ok.\n");

   ret = 0;

err:
   if (dsa)
      DSA_free(dsa);
   BIO_free(f);

   return ret;
}

int op_delete_rsa_key_pair(CK_SLOT_ID slotid, char *keypair_fname) {
   BIO *f = NULL;
   int ret = -1;
   RSA *rsa = NULL;
   CK_OBJECT_HANDLE handle;
   CK_SESSION_HANDLE session_handle;
   CK_RV retCode;

   /* create a BIO to be used for writing out the keypair, do it now before we start talking
    * to hardware */
   if ((f = BIO_new(BIO_s_file())) == NULL) {
      fprintf(stderr, "Cannot create BIO used to read RSA PEM key pair.\n");
      goto err;
   }

   if (BIO_read_filename(f, keypair_fname) <= 0) {
      fprintf(stderr, "Cannot open [%s] for reading.\n", keypair_fname);
      goto err;
   }

   if (!(rsa = PEM_read_bio_RSAPrivateKey(f, NULL, NULL, NULL))) {
      fprintf(stderr, "Failed reading RSA key pair. file: [%s]\n", keypair_fname);
      goto err;
   }

   if (set_application_id(app_id_hi, app_id_lo) != 0)
      goto err;
   if (open_session(slotid, &session_handle) != 0)
      goto err;

   /* if we're not logged in here, return an error */
   if (!loggedin(slotid)) {
      fprintf(stderr, "Error: The user is not logged in to the selected slot (%d).\n", (int)slotid);
      goto err;
   }

   /* Destroy public object */
   handle = luna_find_rsa_handle(session_handle, rsa, 0);
   if ((handle == CK_INVALID_HANDLE) || ((retCode = p11.std->C_DestroyObject(session_handle, handle)) != CKR_OK)) {
      fprintf(stderr, "Delete public failed.\n");
      goto err;
   }

   if (verbose) {
      fprintf(stdout, "RSA public key handle is %u\n", (unsigned)handle);
   }

   fprintf(stderr, "Delete public ok.\n");

   /* Destroy private object */
   handle = luna_find_rsa_handle(session_handle, rsa, 1);
   if ((handle == CK_INVALID_HANDLE) || ((retCode = p11.std->C_DestroyObject(session_handle, handle)) != CKR_OK)) {
      fprintf(stderr, "Delete private failed.\n");
      goto err;
   }

   if (verbose) {
      fprintf(stdout, "RSA private key handle is %u\n", (unsigned)handle);
   }

   fprintf(stderr, "Delete private ok.\n");
   ret = 0;

err:
   if (rsa)
      RSA_free(rsa);
   BIO_free(f);

   return ret;
}

#if defined(LUNA_OSSL_PQC)
static OSSL_PROVIDER *prov = NULL;
#endif

int main(int argc, char *argv[]) {
   CK_RV retCode = CKR_OK;

   /* zero init global data */
   memset(sautil_password, 0, sizeof(sautil_password));
   memset(sautil_szcurve, 0, sizeof(sautil_szcurve));

   /* parse command line */
   if (parse_args(argc, argv) != 0) {
      goto err;
   }

   /* NOTE: dont print anything until we had a chance to parse arguments (see parse_args) */
   fprintf(stderr, "Copyright " LOCAL_APP_COPYRIGHT " Thales Group. All rights reserved.\n");
   fprintf(stderr, LOCAL_APP_NAME " is the property of Thales Group and is provided to our customers for\n");
   fprintf(stderr, "the purpose of diagnostic and development only.  Any re-distribution of this\n");
   fprintf(stderr, "program in whole or in part is a violation of the license agreement.\n\n");

   if ((retCode = sautil_init()) != CKR_OK) {
      /* fprintf(stderr, "C_Initialize Error: 0x%x.\n", (int) retCode); */
      goto err;
   }

   /* Check for a session open request */
   if (operation & OP_OPEN) {
      if ((strlen(sautil_password) < LUNA_MIN_PASSWORD) && (!want_prompt) && (!want_passfile)) {
         fprintf(stderr, "At least 4 characters must be entered to attempt Login.\n");
         goto err;
      }
      if (op_open_app_id(slot_id, app_id_hi, app_id_lo) != 0)
         goto err;
   }

   /* Check if a key delete operation was requested */
   if (operation & OP_DELETE_RSA_KEY_PAIR) {
      if (!key_filename) {
         fprintf(stderr, "Use -f to specify RSA key pair to be deleted.\n");
         goto err;
      }
      if (op_delete_rsa_key_pair(slot_id, key_filename) != 0)
         goto err;
   } else if (operation & OP_DELETE_DSA_KEY_PAIR) {
      if (!key_filename) {
         fprintf(stderr, "Use -f to specify DSA key pair to be deleted.\n");
         goto err;
      }
      if (op_delete_dsa_key_pair(slot_id, key_filename) != 0)
         goto err;
   }

#if defined(LUNA_OSSL_ECDSA)
   if (operation & OP_DELETE_ECDSA_KEY_PAIR) {
      if (!key_filename) {
         fprintf(stderr, "Use -m to specify ECDSA key pair to be deleted.\n");
         goto err;
      }
      if (op_delete_ecdsa_key_pair(slot_id, key_filename) != 0)
         goto err;
   }
#endif /* LUNA_OSSL_ECDSA */

#if defined(LUNA_OSSL_PQC)
   if (operation & OP_DELETE_PQC_KEY_PAIR) {
      if (!key_filename) {
         fprintf(stderr, "Use -k to specify PQC key pair to be deleted.\n");
         goto err;
      }
      if (op_delete_pqc_key_pair(slot_id, key_filename) != 0)
         goto err;
   }
#endif /* LUNA_OSSL_ECDSA */

   /* Check for RSA or DSA key generation request */
   if (operation & OP_GENERATE_RSA_KEY_PAIR) {
      if (!key_filename) {
         fprintf(stderr, "No key pair output filename specified.\n");
         goto err;
      }
      if (op_generate_rsa_key_pair(slot_id, modulus_size, key_filename) != 0) {
         goto err;
      }
   } else if (operation & OP_GENERATE_DSA_KEY_PAIR) {
      if (!key_filename) {
         fprintf(stderr, "No key pair output filename specified.\n");
         goto err;
      }
      if (op_generate_dsa_key_pair(slot_id, modulus_size, key_filename, key_paramfile) != 0) {
         goto err;
      }
   }
#if defined(LUNA_OSSL_ECDSA)
   if (operation & OP_GENERATE_ECDSA_KEY_PAIR) {
      if (!key_filename) {
         fprintf(stderr, "No key pair output filename specified.\n");
         goto err;
      }
      if (op_generate_ecdsa_key_pair(slot_id, modulus_size, key_filename, key_paramfile) != 0) {
         goto err;
      }
   }
#endif /* LUNA_OSSL_ECDSA */
#ifdef CA3UTIL_DIFFIE_HELLMAN
   if (operation & OP_GENERATE_DH_KEY_PAIR) {
      if (!key_filename) {
         fprintf(stderr, "No key pair output filename specified.\n");
         goto err;
      }
      if (op_generate_dh_key_pair(slot_id, modulus_size, key_filename) != 0) {
         goto err;
      }
   }
#endif /* CA3UTIL_DIFFIE_HELLMAN */
   if (operation & OP_RESTORE_KEYFILE) {
      if (!key_filename) {
         fprintf(stderr, "No filename specified.\n");
         goto err;
      }
      if (!key_keytype) {
         fprintf(stderr, "No keytype specified (RSA, DSA, ECDSA).\n");
         goto err;
      }
      if (strcmp(key_keytype, "RSA") && strcmp(key_keytype, "DSA") && strcmp(key_keytype, "ECDSA")) {
         fprintf(stderr, "Unrecognized keytype [%s].\n", (char *)key_keytype);
         goto err;
      }
      if (luna_restore_keyfile(slot_id, (CK_OBJECT_HANDLE)key_handle, key_filename, key_keytype) != 0) {
         goto err;
      }
   }

   if (operation & OP_CLOSE) {
      if (op_close_app_id(slot_id, app_id_hi, app_id_lo) != 0)
         goto err;
   }

   sautil_exit(0);
   return 0;

err:

   sautil_exit(-1);
   return -1;
}

/* Argument list parsing */
static int lunaOptNdx = 1;

static int sautil_getopt(int argc, char *const argv[], const char *optstring) {
   char *sArg = 0;

   sautil_optarg = 0;
   if (lunaOptNdx >= argc)
      return EOF;
   sArg = argv[lunaOptNdx++];
   if (!sArg)
      return EOF;
   if (!strchr("-", (int)sArg[0]))
      return EOF;
   if ((sArg[1] == '\0'))
      return EOF;
   if (!strchr(optstring, (int)sArg[1]))
      return EOF;
   if ((sArg[2] != '\0')) {
      /* e.g., "sautil -s1" */
      sautil_optarg = &sArg[2];
      return (int)sArg[1];
   }
   if (lunaOptNdx >= argc) {
      /* e.g., "sautil -s12" */
      return (int)sArg[1];
   }
   if (!strchr("-", (int)argv[lunaOptNdx][0])) {
      /* e.g., "sautil -s 12" */
      sautil_optarg = &argv[lunaOptNdx++][0];
      return (int)sArg[1];
   }
   return (int)sArg[1];
}

int luna_find_private_rsa(CK_SESSION_HANDLE session_handle, CK_OBJECT_HANDLE pub_handle, CK_OBJECT_HANDLE_PTR pprivate);

/* Restore keyfile given key handle */
int luna_restore_keyfile(CK_SLOT_ID slotid, CK_OBJECT_HANDLE some_handle, char *keypair_fname, char *szkeytype) {
   int ret = 0;
   CK_SESSION_HANDLE session_handle = 0;

   ret = set_application_id(app_id_hi, app_id_lo);
   if (ret != 0)
      return -1;

   if (open_session(slotid, &session_handle) != 0)
      return -1;

   /* if we're not logged in here, return an error */
   if (!loggedin(slotid)) {
      fprintf(stderr, "Error: The user is not logged in to the selected slot (%d).\n", (int)slotid);
      return -1;
   }

   if (some_handle == 0) {
      some_handle = (luna_select_key(session_handle, &some_handle, szkeytype)) ? 0 : some_handle;
   }

   if (some_handle == 0) {
      fprintf(stderr, "Error: %s key handle cannot be zero.\n", (char *)szkeytype);
      return -1;
   }

   if (verbose) {
      fprintf(stdout, "%s key handle is %d\n", (char *)szkeytype, (int)some_handle);
   }

   ret = -1;
   if (strcmp(szkeytype, "RSA") == 0) {
      ret = write_pem_rsa_key_pair(session_handle, 0, some_handle, keypair_fname);
   }
   if (strcmp(szkeytype, "DSA") == 0) {
      ret = write_pem_dsa_key_pair(session_handle, some_handle, 0, keypair_fname);
   }
#if defined(LUNA_OSSL_ECDSA)
   if (strcmp(szkeytype, "ECDSA") == 0) {
      ret = write_pem_ecdsa_key_pair(session_handle, some_handle, some_handle, keypair_fname);
   }
#endif /* LUNA_OSSL_ECDSA */

   if (ret != 0)
      goto err;

   return 0;

err:
   close_session(session_handle);
   session_handle = 0;
   return -1;
}

/* luna_rsa_attributes */
typedef struct {
   CK_ATTRIBUTE attr[2];
   CK_ATTRIBUTE_PTR modulus;
   CK_ATTRIBUTE_PTR exponent;

} luna_rsa_attributes;

int luna_read_rsa_public_attributes(CK_SESSION_HANDLE session_handle, CK_OBJECT_HANDLE pub_handle,
                                    luna_rsa_attributes *lpattr);
int luna_find_rsa_private_handle(CK_SESSION_HANDLE session_handle, luna_rsa_attributes *lpattr, int flagPrivate,
                                 CK_OBJECT_HANDLE_PTR priv_handle_ptr);
void luna_rsa_attributes_init(luna_rsa_attributes *lpattr);
void luna_rsa_attributes_fini(luna_rsa_attributes *lpattr);

/* Find private key handle */
int luna_find_private_rsa(CK_SESSION_HANDLE session_handle, CK_OBJECT_HANDLE pub_handle,
                          CK_OBJECT_HANDLE_PTR pprivate) {
   CK_OBJECT_HANDLE apublic = 0;
   luna_rsa_attributes attrRsa;

   luna_rsa_attributes_init(&attrRsa);
   if (luna_read_rsa_public_attributes(session_handle, pub_handle, &attrRsa)) {
      fprintf(stderr, "Error reading RSA public attributes.\n");
      return 1;
   }
   if (luna_find_rsa_private_handle(session_handle, &attrRsa, 1, pprivate)) {
      fprintf(stderr, "Error finding RSA private handle.\n");
      return 1;
   }
   if (luna_find_rsa_private_handle(session_handle, &attrRsa, 0, &apublic)) {
      fprintf(stderr, "Error finding RSA public handle.\n");
      return 1;
   }
   if (apublic != pub_handle) {
      fprintf(stderr, "Expected RSA public key.\n");
      return 1;
   }
   if (apublic == (*pprivate)) {
      fprintf(stderr, "Search found public = private.\n");
      return 1;
   }
   luna_rsa_attributes_fini(&attrRsa);
   return 0;
}

/* Find public key handle */
int luna_find_public_rsa(CK_SESSION_HANDLE session_handle, CK_OBJECT_HANDLE priv_handle, CK_OBJECT_HANDLE_PTR ppublic) {
   CK_OBJECT_HANDLE aprivate = 0;
   luna_rsa_attributes attrRsa;

   luna_rsa_attributes_init(&attrRsa);
   if (luna_read_rsa_public_attributes(session_handle, priv_handle, &attrRsa)) {
      fprintf(stderr, "Error reading RSA public attributes.\n");
      return 1;
   }
   if (luna_find_rsa_private_handle(session_handle, &attrRsa, 1, &aprivate)) {
      fprintf(stderr, "Error finding RSA private handle.\n");
      return 1;
   }
   if (luna_find_rsa_private_handle(session_handle, &attrRsa, 0, ppublic)) {
      fprintf(stderr, "Error finding RSA public handle.\n");
      return 1;
   }
   if (aprivate != priv_handle) {
      fprintf(stderr, "Expected RSA private key.\n");
      return 1;
   }
   if (aprivate == (*ppublic)) {
      fprintf(stderr, "Search found public = private.\n");
      return 1;
   }
   luna_rsa_attributes_fini(&attrRsa);
   return 0;
}

/* Read public key attributes */
int luna_read_rsa_public_attributes(CK_SESSION_HANDLE session_handle, CK_OBJECT_HANDLE pub_handle,
                                    luna_rsa_attributes *lpattr) {
   lpattr->modulus->type = CKA_MODULUS;
   lpattr->modulus->pValue = NULL_PTR;
   lpattr->modulus->ulValueLen = 0;

   lpattr->exponent->type = CKA_PUBLIC_EXPONENT;
   lpattr->exponent->pValue = NULL_PTR;
   lpattr->exponent->ulValueLen = 0;

   if (luna_get_attribute(session_handle, pub_handle, lpattr->modulus)) {
      return 1;
   }
   if (luna_get_attribute(session_handle, pub_handle, lpattr->exponent)) {
      return 1;
   }
   return 0;
}

/* Find private key (given public key attributes) */
int luna_find_rsa_private_handle(CK_SESSION_HANDLE session_handle, luna_rsa_attributes *lpattr, int flagPrivate,
                                 CK_OBJECT_HANDLE_PTR priv_handle_ptr) {
   CK_OBJECT_CLASS keyclassPublic = CKO_PUBLIC_KEY;
   CK_OBJECT_CLASS keyclassPrivate = CKO_PRIVATE_KEY;
   CK_KEY_TYPE keytypeRSA = CKK_RSA;

   CK_RV retCode = CKR_OK;
   CK_USHORT obj_count = 0;
   unsigned ndx = 0;
   CK_OBJECT_HANDLE handles[2];
   CK_ATTRIBUTE attrib[4];

   if (flagPrivate) {
      attrib[ndx = 0].type = CKA_CLASS;
      attrib[ndx].pValue = (CK_BYTE_PTR)&keyclassPrivate;
      attrib[ndx].ulValueLen = sizeof(keyclassPrivate);
   } else {
      attrib[ndx = 0].type = CKA_CLASS;
      attrib[ndx].pValue = (CK_BYTE_PTR)&keyclassPublic;
      attrib[ndx].ulValueLen = sizeof(keyclassPublic);
   }

   attrib[ndx = 1].type = CKA_KEY_TYPE;
   attrib[ndx].pValue = (CK_BYTE_PTR)&keytypeRSA;
   attrib[ndx].ulValueLen = sizeof(keytypeRSA);

   attrib[ndx = 2].type = CKA_PUBLIC_EXPONENT;
   attrib[ndx].pValue = (CK_BYTE_PTR)lpattr->exponent->pValue;
   attrib[ndx].ulValueLen = lpattr->exponent->ulValueLen;

   attrib[ndx = 3].type = CKA_MODULUS;
   attrib[ndx].pValue = (CK_BYTE_PTR)lpattr->modulus->pValue;
   attrib[ndx].ulValueLen = lpattr->modulus->ulValueLen;

   handles[0] = 0;
   retCode = p11.std->C_FindObjectsInit(session_handle, attrib, 4);
   if (retCode != CKR_OK) {
      fprintf(stderr, "C_FindObjectsInit = 0x%x\n", (int)retCode);
      return 1;
   }

   retCode = p11.std->C_FindObjects(session_handle, &handles[0], 2, &obj_count);
   if (retCode != CKR_OK) {
      fprintf(stderr, "C_FindObjects = 0x%x\n", (int)retCode);
      return 1;
   }

   (*priv_handle_ptr) = handles[0];
   return ((handles[0]) && (obj_count == 1)) ? 0 : 1;
}

/* Init attribute data */
void luna_rsa_attributes_init(luna_rsa_attributes *lpattr) {
   memset(lpattr, 0, sizeof(luna_rsa_attributes));
   lpattr->modulus = &lpattr->attr[0];
   lpattr->exponent = &lpattr->attr[1];
}

/* Cleanup attribute data */
void luna_rsa_attributes_fini(luna_rsa_attributes *lpattr) {
   int i = 0;
   for (i = 0; i < 2; i++) {
      if (lpattr->attr[i].pValue) {
         free(lpattr->attr[i].pValue);
      }
   }
   memset(lpattr, 0, sizeof(luna_rsa_attributes));
}

/* Get attribute */
static CK_RV luna_get_attribute(CK_SESSION_HANDLE session_handle, CK_OBJECT_HANDLE pub_handle,
                                CK_ATTRIBUTE_PTR a_template) {
   CK_RV retCode = CKR_OK;

   /* extract public key, modulus size first */
   a_template[0].pValue = 0;
   a_template[0].ulValueLen = 0;
   retCode = p11.std->C_GetAttributeValue(session_handle, pub_handle, a_template, 1);
   if (retCode != CKR_OK) {
      /*fprintf(stderr, "WARNING: C_GetAttributeValue(1st) = 0x%x\n", (int) retCode);*/
      return retCode;
   }

   /* allocate enough space to extract attribute */
   a_template[0].pValue = (CK_BYTE_PTR)malloc(a_template[0].ulValueLen + 1);
   memset(a_template[0].pValue, 0, a_template[0].ulValueLen + 1);

   /* extract public key, get modulus */
   retCode = p11.std->C_GetAttributeValue(session_handle, pub_handle, a_template, 1);
   if (retCode != CKR_OK) {
      fprintf(stderr, "WARNING: C_GetAttributeValue(2nd) = 0x%x\n", (int)retCode);
      return retCode;
   }

   return CKR_OK;
}

/* Format string for binary data */
static void fprintf_bin(FILE *fp, void *data, unsigned ndata) {
   unsigned char *pdata = (unsigned char *)data;
   for (; ndata > 0; pdata++, ndata--) {
      fprintf(fp, "%02x", (unsigned)((*pdata) & 0x00ff));
   }
}

/* List private keys for selection */
static int luna_select_key(CK_SESSION_HANDLE session_handle, CK_OBJECT_HANDLE *hout, char *szkeytype) {
   CK_OBJECT_CLASS ulClass = CKO_PRIVATE_KEY;
   CK_KEY_TYPE ulType = CKK_RSA;

   CK_RV retCode = CKR_OK;
   CK_USHORT obj_count = 0;
   CK_ULONG rcCount = 0;
   char *p_szCkaPublic = NULL;

   CK_OBJECT_HANDLE handles[1];
   CK_ATTRIBUTE attrib[2];
   CK_ATTRIBUTE tmpl[1];
   CK_ATTRIBUTE tmpl_modulus[1];
   char buffer[32];

   memset(handles, 0, sizeof(handles));
   memset(attrib, 0, sizeof(attrib));
   memset(tmpl, 0, sizeof(tmpl));
   memset(tmpl, 0, sizeof(tmpl));
   memset(tmpl_modulus, 0, sizeof(tmpl_modulus));
   memset(buffer, 0, sizeof(buffer));

   hout[0] = 0;

   if (strcmp(szkeytype, "RSA") == 0) {
      /* NOTE: RSA private key has public attributes so... */
      ulClass = CKO_PRIVATE_KEY;
      ulType = CKK_RSA;
   } else if (strcmp(szkeytype, "DSA") == 0) {
      /* NOTE: DSA private key has NO public attributes so... */
      ulClass = CKO_PUBLIC_KEY;
      ulType = CKK_DSA;
   } else if (strcmp(szkeytype, "ECDSA") == 0) {
      /* NOTE: ECDSA private key has NO public attributes so... */
      ulClass = CKO_PUBLIC_KEY;
      ulType = CKK_ECDSA;
   }

   if (1) {
      rcCount = 0;

      if (ulType != CKK_ECDSA) {
         attrib[rcCount].type = CKA_CLASS;
         attrib[rcCount].pValue = (CK_BYTE_PTR)&ulClass;
         attrib[rcCount].ulValueLen = sizeof(ulClass);
         rcCount++;
      }

      attrib[rcCount].type = CKA_KEY_TYPE;
      attrib[rcCount].pValue = (CK_BYTE_PTR)&ulType;
      attrib[rcCount].ulValueLen = sizeof(ulType);
      rcCount++;
   }

   retCode = p11.std->C_FindObjectsInit(session_handle, attrib, rcCount);
   if (retCode != CKR_OK) {
      fprintf(stderr, "C_FindObjectsInit = 0x%x\n", (int)retCode);
      return 1;
   }

   /* List all objects */
   do {
      obj_count = 0;
      handles[0] = 0;
      retCode = p11.std->C_FindObjects(session_handle, &handles[0], 1, &obj_count);

      if (retCode != CKR_OK) {
         fprintf(stderr, "C_FindObjects = 0x%x\n", (int)retCode);
         return 1;

      } else if (obj_count == 1) {
         tmpl[0].type = CKA_LABEL;
         tmpl[0].pValue = 0;
         tmpl[0].ulValueLen = 0;
         if (luna_get_attribute(session_handle, handles[0], &tmpl[0])) {
            fprintf(stderr, "Get Attribute Failed (CKA_LABEL)\n");
            return 1;
         }

         /* Get the public key for display */
         if (strcmp(szkeytype, "RSA") == 0) {
            p_szCkaPublic = "CKA_MODULUS";
            tmpl_modulus[0].type = CKA_MODULUS;
            tmpl_modulus[0].pValue = 0;
            tmpl_modulus[0].ulValueLen = 0;
         } else if (strcmp(szkeytype, "DSA") == 0) {
            p_szCkaPublic = "CKA_VALUE";
            tmpl_modulus[0].type = CKA_VALUE;
            tmpl_modulus[0].pValue = 0;
            tmpl_modulus[0].ulValueLen = 0;
         } else if (strcmp(szkeytype, "ECDSA") == 0) {
            p_szCkaPublic = "CKA_EC_POINT";
            tmpl_modulus[0].type = CKA_EC_POINT;
            tmpl_modulus[0].pValue = 0;
            tmpl_modulus[0].ulValueLen = 0;
         }

         if (luna_get_attribute(session_handle, handles[0], &tmpl_modulus[0]) == CKR_OK) {
            /* Print handle, label, modulus */
            if ((tmpl[0].pValue) && (tmpl_modulus[0].pValue)) {
               fprintf(stdout, "%8u\t\"%s\"\t", (unsigned)handles[0], (char *)tmpl[0].pValue);
               fprintf_bin(stdout, (void *)tmpl_modulus[0].pValue, (unsigned)tmpl_modulus[0].ulValueLen);
               fprintf(stdout, "\n\n");
               free(tmpl[0].pValue);
               tmpl[0].pValue = 0;
               free(tmpl_modulus[0].pValue);
               tmpl_modulus[0].pValue = 0;
            }
         }
      }
   } while ((obj_count > 0) && (retCode == CKR_OK));

   /* Finalize find operation */
   p11.std->C_FindObjectsFinal(session_handle);

   /* User selects key handle */
   fprintf(stdout, "\nEnter the key handle : ");
   memset(buffer, 0, sizeof(buffer));
   fflush(stdout);
   fgets(buffer, sizeof(buffer), stdin);
   hout[0] = atoi(buffer);

   return 0;
}

/* if we're not logged in here, return an error */
int loggedin(CK_SLOT_ID slotid) {
   CK_RV retCode;
   CK_FLAGS flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
   CK_SESSION_HANDLE shandle;

   CK_SESSION_INFO sessInfo;
   memset(&sessInfo, 0, sizeof(sessInfo));

   retCode = p11.std->C_OpenSession(slotid, flags, (CK_BYTE_PTR) "Application", 0, &shandle);
   if (retCode != CKR_OK) {
      fprintf(stderr, "Open Session Error: Slot number %d. err 0x%x\n", (int)slotid, (int)retCode);
      return 0;
   }

   retCode = p11.std->C_GetSessionInfo(shandle, &sessInfo);
   if (retCode != CKR_OK) {
      fprintf(stderr, "Get Session Info Error: Slot number %d. err 0x%x\n", (int)slotid, (int)retCode);
      p11.std->C_CloseSession(shandle);
      shandle = 0;
      return 0;
   }

   if (sessInfo.state == CKS_RW_USER_FUNCTIONS) {
      if (verbose)
         fprintf(stdout, "Confirmed user is logged in.\n");
      p11.std->C_CloseSession(shandle);
      shandle = 0;
      /* return 1 because we are logged in */
      return 1;
   }

   p11.std->C_CloseSession(shandle);
   shandle = 0;
   return 0;
}

/* perform sscanf on string containing format "%02x:%02x:..." */
static unsigned char *parse_hex_bytes(const char *inptr, int separator, unsigned *outsize) {
   unsigned count = 0, utmp = 0;
   unsigned char *outptr = NULL;

   /*fprintf(stderr, "inptr = \"%s\" \n", (char*)inptr);*/
   if (inptr == NULL)
      return NULL;
   if (outsize == NULL)
      return NULL;

   size_t inlen = strlen(inptr);
   if (inlen < 1 || inlen > LUNA_MAX_STRING_LEN)
       return NULL;
   outptr = (unsigned char *)malloc(inlen + 1);
   if (outptr == NULL)
      return NULL;

   for (; (inptr != NULL); utmp = 256) {
      if (!isxdigit(inptr[0]))
         goto goto_fail;
      if (!isxdigit(inptr[1]))
         goto goto_fail;
      if (!((inptr[2] == (char)separator) || (inptr[2] == '\0')))
         goto goto_fail;
      if (sscanf(inptr, "%02x", (unsigned *)&utmp) != 1)
         goto goto_fail;
      if (utmp > 255)
         goto goto_fail;
      outptr[count++] = (unsigned char)utmp;
      /*fprintf(stderr, "outptr[count-1] = \"%x\" \n", (unsigned)outptr[count-1]);*/
      inptr = strchr(inptr, separator);
      if (inptr != NULL)
         inptr++;
   }

   (*outsize) = count;
   return outptr;

goto_fail:
   if (outptr)
      free(outptr);
   (*outsize) = 0;
   return NULL;
}

/*
 * Added for sautil v1.0.0-1
 */

/* definitions */
#ifdef OS_WIN32
#define LUNA_CONF_PATH "c:\\windows"
#define LUNA_FILE_SLASH "\\"
#define LUNA_CONF_FILE "crystoki.ini"
#define LUNA_CONF_ENVVAR "ChrystokiConfigurationPath"
#else
#define LUNA_CONF_PATH "/etc"
#define LUNA_FILE_SLASH "/"
#define LUNA_CONF_FILE "Chrystoki.conf"
#define LUNA_CONF_ENVVAR "ChrystokiConfigurationPath"
#endif

/* forward reference */
static char *luna_getprop(const char *confpath, const char *ssection, const char *svalue);

/* Create filename */
static char *luna_filenamedup(char *spath, char *sfile) {
   size_t spathlen = strlen(spath);
   size_t sfilelen = strlen(sfile);
   if (spathlen < 1 || spathlen > LUNA_MAX_STRING_LEN)
      return NULL;
   if (sfilelen < 1 || sfilelen > LUNA_MAX_STRING_LEN)
      return NULL;
   size_t fnlen = spathlen + 1 + sfilelen + 1 + 8;
   char *fn = (char *)malloc(fnlen);
   if (fn == NULL)
      return NULL;
   fn[0] = '\0';
   snprintf(fn, fnlen, "%s%s%s", (char *)spath, (char *)LUNA_FILE_SLASH, (char *)sfile);
   return fn;
}

/* Get path to conf file */
static char *luna_get_conf_path(void) {
   char *cf = NULL;
   char *envpath = 0;

   envpath = getenv(LUNA_CONF_ENVVAR);
   if (envpath != NULL) {
      cf = luna_filenamedup(envpath, LUNA_CONF_FILE);
   } else {
#ifdef OS_WIN32
      fprintf(stderr, "Environment variable is not set: %s.\n", (char *)LUNA_CONF_ENVVAR);
#else
      cf = luna_filenamedup(LUNA_CONF_PATH, LUNA_CONF_FILE);
#endif
   }

   return cf;
}

/* sautil_libname (get library name) */
static char *sautil_libname(void) {
   const char *ssection = "Chrystoki2";
   char *confpath = NULL;
   char *libname = NULL;

   /* luna_get_conf_path */
   confpath = luna_get_conf_path();
   if (confpath == NULL) {
      fprintf(stderr, "Failed to get path to config file.\n");
      return NULL;
   }

   if (verbose) {
      fprintf(stderr, "Config file: %s.\n", (char *)confpath);
   }

#ifdef OS_WIN32
   if (sizeof(void *) > 4) {
      libname = luna_getprop(confpath, ssection, "LibNT64");
      if (libname == NULL)
         libname = luna_getprop(confpath, ssection, "LibNT"); /* in case of version skew */
   } else {
      libname = luna_getprop(confpath, ssection, "LibNT");
   }
#else /* OS_WIN32 */
   if (sizeof(void *) > 4) {
#if defined(OS_HPUX) || defined(HPUX) || defined(__hpux)
      if (libname == NULL)
         libname = luna_getprop(confpath, ssection, "LibHPUX64");
      if (libname == NULL)
         libname = luna_getprop(confpath, ssection, "LibHPUX"); /* in case of version skew */
#endif /* OS_HPUX */
#if defined(OS_AIX) || defined(AIX) || defined(_AIX)
      if (libname == NULL)
         libname = luna_getprop(confpath, ssection, "LibAIX64");
      if (libname == NULL)
         libname = luna_getprop(confpath, ssection, "LibAIX"); /* in case of version skew */
#endif /* OS_AIX */
      if (libname == NULL)
         libname = luna_getprop(confpath, ssection, "LibUNIX64"); /* backstop rule */
      if (libname == NULL)
         libname = luna_getprop(confpath, ssection, "LibUNIX"); /* in case of version skew */
   } else {
#if defined(OS_HPUX) || defined(HPUX) || defined(__hpux)
      if (libname == NULL)
         libname = luna_getprop(confpath, ssection, "LibHPUX");
#endif /* OS_HPUX */
#if defined(OS_AIX) || defined(AIX) || defined(_AIX)
      if (libname == NULL)
         libname = luna_getprop(confpath, ssection, "LibAIX");
#endif /* OS_AIX */
      if (libname == NULL)
         libname = luna_getprop(confpath, ssection, "LibUNIX"); /* backstop rule */
   }
#endif /* OS_WIN32 */

   if (libname == NULL) {
      fprintf(stderr, "Failed to get path to library file.\n");
      fprintf(stderr, "  See config file: %s.\n", (char *)confpath);
      free(confpath);
      return NULL;
   }

   free(confpath);
   return libname;
}

/* sautil_load (load library) */
static CK_RV sautil_load(void) {
   char *libname = NULL;

   luna_dso = NULL;

   /* sautil_libname */
   libname = sautil_libname();
   if (libname == NULL) {
      fprintf(stderr, "Library not configured.\n");
      goto err;
   }

   /* DSO_load */
   luna_dso = luna_dso_load(libname);
   if (luna_dso == NULL) {
      fprintf(stderr, "Library not loadable: %s.\n", (char *)libname);
      goto err;
   }

   free(libname);
   return CKR_OK;

err:
   if (libname != NULL) {
      free(libname);
   }
   return CKR_GENERAL_ERROR;
}

/* stub functions */
static CK_RV STUB_CA_SetApplicationID(CK_ULONG ulHigh, CK_ULONG ulLow) { return CKR_OK; }

static CK_RV STUB_CA_OpenApplicationID(CK_SLOT_ID slotID, CK_ULONG ulHigh, CK_ULONG ulLow) { return CKR_OK; }

static CK_RV STUB_CA_CloseApplicationID(CK_SLOT_ID slotID, CK_ULONG ulHigh, CK_ULONG ulLow) { return CKR_OK; }

/* sautil_init (initialize library) */
static CK_RV sautil_init(void) {
   CK_RV retCode = CKR_OK;
   const char *funcname = NULL;

   /* sautil_load */
   if ((sautil_load()) != CKR_OK) {
      /*fprintf(stderr, "Library not loadable: %s.\n", (char*)libname);*/
      goto err;
   }

   /* DSO_bind_func */
   p11.C_GetFunctionList = (CK_C_GetFunctionList)luna_dso_bind_func(luna_dso, (funcname = "C_GetFunctionList"));
   if (p11.C_GetFunctionList == NULL) {
      fprintf(stderr, "Function not found: %s.\n", (char *)funcname);
      goto err;
   }

   p11.ext.CA_SetApplicationID = (CK_CA_SetApplicationID)luna_dso_bind_func(luna_dso, (funcname = "CA_SetApplicationID"));
   if (p11.ext.CA_SetApplicationID == NULL) {
      fprintf(stderr, "Function not found: %s.\n", (char *)funcname);
      p11.ext.CA_SetApplicationID = STUB_CA_SetApplicationID;
   }

   p11.ext.CA_OpenApplicationID = (CK_CA_OpenApplicationID)luna_dso_bind_func(luna_dso, (funcname = "CA_OpenApplicationID"));
   if (p11.ext.CA_OpenApplicationID == NULL) {
      fprintf(stderr, "Function not found: %s.\n", (char *)funcname);
      p11.ext.CA_OpenApplicationID = STUB_CA_OpenApplicationID;
   }

   p11.ext.CA_CloseApplicationID =
       (CK_CA_CloseApplicationID)luna_dso_bind_func(luna_dso, (funcname = "CA_CloseApplicationID"));
   if (p11.ext.CA_CloseApplicationID == NULL) {
      fprintf(stderr, "Function not found: %s.\n", (char *)funcname);
      p11.ext.CA_CloseApplicationID = STUB_CA_CloseApplicationID;
   }

   /* C_GetFunctionList */
   if ((retCode = p11.C_GetFunctionList(&p11.std)) != CKR_OK) {
      fprintf(stderr, "C_GetFunctionList error: 0x%x.\n", (int)retCode);
      goto err;
   }

   /* C_Initialize */
   if ((retCode = p11.std->C_Initialize(NULL_PTR)) != CKR_OK) {
      fprintf(stderr, "C_Initialize error: 0x%x.\n", (int)retCode);
      goto err;
   }
   luna_ckinit = 1;

   if (1) {
      session_desc desc;
      memset(&desc, 0, sizeof(desc));
      if (luna_parse_slotid(sautil_szslotid, &desc) != 1) {
         fprintf(stderr, "luna_parse_slotid failed. \n");
         goto err;
      }
      slot_id = desc.slot;
   }

   /* init openssl */
#if defined(LUNA_OSSL_CLEANUP)
   /* best practice: set OPENSSL_INIT_NO_ATEXIT but not OPENSSL_INIT_LOAD_CONFIG */
   OPENSSL_init_crypto(OPENSSL_INIT_NO_ATEXIT, NULL);
#else
   /* obsolete initialization routines */
   OpenSSL_add_all_algorithms();
   ERR_load_crypto_strings();
#endif

#if defined(LUNA_OSSL_PQC)
   /* load provider if the operation calls for it */
   if (operation & OP_DELETE_PQC_KEY_PAIR) {
      const char *err_load = sautil_provider_load(&prov);
      if (err_load != NULL) {
         fprintf(stderr, "ERROR: load provider: %s.\n", err_load);
         goto err;
      }
   }
#endif /* LUNA_OSSL_PQC */

   return CKR_OK;

err:
   sautil_fini();
   return CKR_GENERAL_ERROR;
}

/* sautil_fini (finalize library) */
static void sautil_fini(void) {
   if (luna_dso == NULL)
      return;

   if (luna_ckinit)
       (void)p11.std->C_Finalize(NULL_PTR);
   luna_ckinit = 0;
   luna_dso_free(luna_dso);
   luna_dso = NULL;
}

/* print and clear err messages */
static void engineperf_err_flush(int no_print) {
   BIO *bio_err = NULL;

   if (bio_err == NULL) {
      if ((bio_err = BIO_new(BIO_s_file())) != NULL) {
         BIO_set_fp(bio_err, stderr, BIO_NOCLOSE | BIO_FP_TEXT);
      }
   }

   if (bio_err != NULL) {
      if (! no_print)
         ERR_print_errors(bio_err);
      BIO_free(bio_err);
   }

   ERR_clear_error();
}

/* sautil_exit (exit application) */
static void sautil_exit(int errcode) {
    /* cleanse memory */
    memset(sautil_password, 0, sizeof(sautil_password));
    memset(sautil_szcurve, 0, sizeof(sautil_szcurve));

   /* undo open app id on error */
   if (errcode && have_open) {
      (void)op_close_app_id(slot_id, app_id_hi, app_id_lo);
      have_open = 0;
   }

   /* undo global open session */
   if (g_hSession != 0) {
      close_session(g_hSession);
      g_hSession = 0;
   }

   /* fini pkcs11 BEFORE fini provider */
   /* NOTE: as a result, fini provider may print multiple errors in cklog */
   sautil_fini();

#if defined(LUNA_OSSL_PQC)
   /* fini provider */
   /* NOTE: the provider may not fully finalize until openssl is finalized */
   if (prov != NULL) {
      (void)sautil_provider_unload(prov);
      prov = NULL;
   }
#endif /* LUNA_OSSL_PQC */

   /* flush openssl errors before fini openssl */
   engineperf_err_flush( (errcode == 0) ? 1 : 0 );

#if defined(LUNA_OSSL_CLEANUP)
   /* fini openssl (do it last to avoid impacting sautil) */
   OPENSSL_cleanup();
#endif /* LUNA_OSSL_CLEANUP */

   /* exit app */
   exit(errcode);
}

/* Read property value from config file */
static char *luna_getprop(const char *confpath, const char *ssection, const char *svalue) {
#ifndef OS_WIN32
   int rlen = 0;
   unsigned tmplen = 0;
   char *p = NULL, *e = NULL, *l = NULL;
   char *quote = NULL;
   BIO *cfgbio = NULL;
   char rbuf[LUNA_MAX_LINE_LEN + 1];

   memset(rbuf, 0, sizeof(rbuf));

   if (confpath == NULL) {
      return NULL;
   }
   cfgbio = BIO_new_file(confpath, "r");
   if (cfgbio == NULL) {
      return NULL;
   }

   for (;;) {
      if (!(rlen = BIO_gets(cfgbio, rbuf, LUNA_MAX_LINE_LEN)))
         break;

      /* find the section string, and, opening brace */
      p = strstr(rbuf, ssection);
      quote = strstr(rbuf, "{");
      if ((p == NULL) || (strlen(p) == 0))
         continue;
      if ((quote == NULL) || (strlen(quote) == 0))
         continue;

      /* found the section - let's iterate within section */
      for (quote = NULL; (quote == NULL);) {
         if (!(rlen = BIO_gets(cfgbio, rbuf, LUNA_MAX_LINE_LEN)))
            break;

         /* check for closing brace */
         quote = strstr(rbuf, "}");

         /* find the value string; beware of substrings; e.g., LibPath and LibPath64 */
         tmplen = strlen(svalue);
         p = strstr(rbuf, svalue);
         if ((p == NULL) || (strlen(p) <= tmplen))
            continue;
         if ((isalnum(p[tmplen])) || (p[tmplen] == '_'))
            continue;

         /* find and skip past = */
         p = strchr(p, '=');
         if ((p == NULL) || (strlen(p) == 0))
            continue;

         /* skip past = and eat all white space */
         while (isspace(*(++p)))
            ;

         /* find terminating ; and replace with null */
         if ((e = strchr(p, ';')) == NULL)
            continue;
         (*e) = 0;

         /* found the data - let's break */
         l = strdup(p);
         break;
      }
      break; /* Break since we already encountered the section name */
   }
   /* Close file handle */
   BIO_free(cfgbio);
   return l;

#else  /* OS_WIN32 */
   const char *pbError = "##ERROR##";
   DWORD dwrc = 0;
   char rbuf[LUNA_MAX_LINE_LEN + 1];

   memset(rbuf, 0, sizeof(rbuf));
   dwrc = GetPrivateProfileString(ssection, svalue, pbError, rbuf, LUNA_MAX_LINE_LEN, (char *)confpath);

   if ((dwrc < 1) || (strcmp(rbuf, pbError) == 0)) {
      return NULL;
   }

   return strdup(rbuf);
#endif /* OS_WIN32 */
}

/* sautil_gets_password (prompt for password; no echo) */
static int sautil_gets_password(char *secretString, unsigned maxlen) {
   char *secretString0 = secretString;
   unsigned ii = 0;
   unsigned len = 0; /* running total length of string */
   char c = 0;       /* character read in from user */
#ifdef OS_WIN32
   DWORD mode = 0;
#endif

   fflush(stdout);
   fflush(stderr);

#ifdef OS_WIN32
   /* This console mode stuff only applies to windows. */
   if (GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &mode)) {
      if (SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), mode & (!ENABLE_ECHO_INPUT))) {
         while (c != '\r') {
            /* wait for a character to be hit */
            while (!_kbhit()) {
               Sleep(100);
            }
            /* get it */
            c = _getch();

            /* check for carriage return */
            if (c != '\r') {
               /* check for backspace */
               if (c != '\b') {
                  /* neither CR nor BS -- add it to the password string */
                  printf("*");
                  *secretString++ = c;
                  len++;
               } else {
                  /* handle backspace -- delete the last character & erase it from the screen */
                  if (len > 0) {
                     secretString--;
                     len--;
                     printf("\b \b");
                  }
               }
            }
         }
         /* Add the zero-termination */
         (*secretString) = '\0';

         SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), mode);
      }
   }

#else  /* OS_WIN32 */

   {
      struct termios tio;
      int fd;
      int rc;
      cc_t old_min, old_time;
      char termbuff[200];

      /* flush prompt string before reading input */
      fflush(stdout);

      fd = open(ctermid(termbuff), O_RDONLY);
      if (fd == -1) {
         return -1;
      }

      rc = tcgetattr(fd, &tio);
      if (rc == -1) {
         close(fd);
         return -1;
      }

      /* turn off canonical mode & echo */
      old_min = tio.c_cc[VMIN];
      old_time = tio.c_cc[VTIME];
      tio.c_lflag = tio.c_lflag & ~ICANON & ~ECHO;
      tio.c_cc[VMIN] = 1;
      tio.c_cc[VTIME] = 0;

      rc = tcsetattr(fd, TCSADRAIN, &tio);
      if (rc == -1) {
         close(fd);
         return -1;
      }

      /* continue to loop until we get the 'enter' */
      while (c != '\n') {
         /* read in the next char */
         rc = read(fd, &c, 1);
         if (rc != 0) {
            if (c != '\n') {
               /* check for backspace ( and ASCII 127 which is BS in linux) */
               if ((c != '\b') && ((int)c != 127)) {
                  /* neither CR nor BS -- add it to the password string */
                  fprintf(stdout, "*");
                  fflush(stdout);
                  *secretString++ = c;
                  len++;
               } else {
                  /* handle backspace -- delete the last character & erase it from the screen */
                  if (len > 0) {
                     secretString--;
                     len--;
                     fprintf(stdout, "\b \b");
                     fflush(stdout);
                  }
               }
            }
         } else {
            /* we're having problems getting the character */
            close(fd);
            return -1;
         }
      } /* while */

      *secretString++ = '\0';

      /* return terminal to its original state */
      tio.c_lflag = tio.c_lflag | ICANON | ECHO;
      tio.c_cc[VMIN] = old_min;
      tio.c_cc[VTIME] = old_time;

      rc = tcsetattr(fd, TCSADRAIN, &tio);
      if (rc == -1) {
         close(fd);
         return -1;
      }

      close(fd);
   }
#endif /* OS_WIN32 */

   /* obscure password length */
   for (ii = len; ii < maxlen; ii++) {
      fprintf(stdout, "*");
   }
   fprintf(stdout, "\n");

   /* if we didn't get a string, return false */
   if ((len > maxlen) || (len < LUNA_MIN_PASSWORD) || (len != strlen(secretString0))) {
      return -1;
   }

   return len;
}

/* string print (unique CKA_LABEL) */
static void sautil_sprint_unique(char *szPubLabel, size_t pubsize,
        char *szPrivLabel, size_t privsize,
        const char *szKeytype, unsigned uKeysize) {
   struct tm *p_tmNow = NULL;
   time_t timeNow;
   char szUnique[LUNA_MAX_STRING_LEN + 1];

   memset(&timeNow, 0, sizeof(timeNow));
   memset(szUnique, 0, sizeof(szUnique));

   LOCAL_SLEEP(1); /* sleep so that each key has a unique timestamp */
   timeNow = time(NULL);
   p_tmNow = localtime(&timeNow);
   SAUTIL_ASSERT(p_tmNow != NULL);
   snprintf(szUnique, sizeof(szUnique), "%04u.%02u.%02u.%02u.%02u.%02u", (unsigned)(p_tmNow->tm_year + 1900), (unsigned)p_tmNow->tm_mon,
           (unsigned)p_tmNow->tm_mday, (unsigned)p_tmNow->tm_hour, (unsigned)p_tmNow->tm_min,
           (unsigned)p_tmNow->tm_sec);

   if (uKeysize > 0) {
      (void)snprintf(szPubLabel, pubsize,
              "%s %u Public - %s", (char *)szKeytype, (unsigned)uKeysize, (char *)szUnique);
      (void)snprintf(szPrivLabel, privsize,
              "%s %u Private - %s", (char *)szKeytype, (unsigned)uKeysize, (char *)szUnique);
   } else {
      (void)snprintf(szPubLabel, pubsize,
              "%s Public - %s", (char *)szKeytype, (char *)szUnique);
      (void)snprintf(szPrivLabel, privsize,
              "%s Private - %s", (char *)szKeytype, (char *)szUnique);
   }
}

/* compute sha1(prng_bytes); i.e., compute temporary CKA_ID */
static CK_RV sautil_sha1_prng(CK_SESSION_HANDLE session_handle, CK_BYTE_PTR baSha1) {
   unsigned char foobytes[512];
   if (p11.std->C_GenerateRandom(session_handle, foobytes, sizeof(foobytes)) != CKR_OK) {
      return CKR_GENERAL_ERROR;
   }
   (void)luna_SHA1(foobytes, sizeof(foobytes), baSha1);
   return CKR_OK;
}

/* duplicate memory */
static CK_VOID_PTR sautil_memdup(CK_VOID_PTR pValue, /* can be null */
                                 CK_ULONG ulValueLen) {
   CK_VOID_PTR ptr = NULL;
   if (ulValueLen < 1)
      return NULL;
   ptr = malloc(ulValueLen);
   if (ptr != NULL) {
      memset(ptr, 0, ulValueLen);
      if (pValue != NULL) {
         memcpy(ptr, pValue, ulValueLen);
      }
   }
   return ptr;
}

/* replace one item in table of CK_ATTRIBUTE */
static void sautil_ckatab_malloc_replace(CK_ATTRIBUTE *tab, CK_ULONG tabsize, CK_ATTRIBUTE_TYPE type,
                                         CK_BYTE_PTR pValue, /* can be null */
                                         CK_ULONG ulValueLen) {
   CK_ULONG ii = 0;
   if (ulValueLen < 1)
      return;
   for (ii = 0; ii < tabsize; ii++) {
      if (tab[ii].type == type) {
         tab[ii].pValue = sautil_memdup(pValue, ulValueLen);
         tab[ii].ulValueLen = ulValueLen;
         return;
      }
   }

   /* a coding error if we get this far */
   fprintf(stderr, "BUG: attribute type not found: 0x%x.\n", (unsigned)type);
   sautil_exit(-1);
}

/* free table of CK_ATTRIBUTE */
static void sautil_ckatab_free_all(CK_ATTRIBUTE *tab, CK_ULONG tabsize, int free_tab) {
   CK_ULONG ii = 0;
   if (tab == NULL)
      return;
   for (ii = 0; ii < tabsize; ii++) {
      if (tab[ii].pValue != NULL) {
         free(tab[ii].pValue);
         tab[ii].pValue = NULL;
      }
      tab[ii].ulValueLen = 0;
   }
   if (free_tab)
      free(tab);
}

/* fill table of CK_ATTRIBUTE */
static CK_RV sautil_ckatab_malloc_object(CK_ATTRIBUTE *tab, CK_ULONG tabsize, CK_OBJECT_HANDLE hObject,
                                         CK_SESSION_HANDLE hSession) {
   CK_RV retCode = CKR_GENERAL_ERROR;
   CK_ULONG ii = 0;
   CK_ULONG jj = 0;

   /* NOTE: get one attribute at a time in case P11 lib has related issue! */
   for (ii = 0; ii < tabsize; ii++) {
      retCode = luna_get_attribute(hSession, hObject, &tab[ii]);
      if (retCode != CKR_OK) {
         for (jj = 0; jj < ii; jj++) {
            free(tab[jj].pValue);
            tab[jj].pValue = NULL;
         }
         return retCode;
      }
   }

   return retCode;
}

#if defined(LUNA_OSSL_ECDSA)
/* ECDSA */

/* initialize ecdsa key templates */
static int init_ecdsa_key_template(CK_ATTRIBUTE **pubTemp, CK_USHORT *pubTempSize, CK_ATTRIBUTE **privTemp,
                                   CK_USHORT *privTempSize, CK_BYTE *pub_key_label, CK_BYTE *priv_key_label,
                                   const char *curve_name, EC_GROUP *group, CK_BYTE_PTR baCkId, CK_ULONG baCkIdLen) {
   CK_BBOOL bTrue = CK_TRUE;
   CK_BBOOL bModifiable = CK_TRUE;
   CK_BBOOL bExtractable = CK_TRUE;
   CK_ATTRIBUTE *pubTemplate = NULL;
   CK_ATTRIBUTE *privTemplate = NULL;
   CK_ULONG ii = 0;

   CK_ULONG curve_len = 0;
   CK_BYTE curve_data[SAUTIL_EC_CURVE_MAX_BYTES];

   CK_ATTRIBUTE pub_template[] = {
       {CKA_TOKEN, 0, 0},
       {CKA_PRIVATE, 0, 0},
       {CKA_VERIFY, 0, 0},
       {CKA_MODIFIABLE, 0, 0},
       {CKA_ECDSA_PARAMS, 0, 0},
       {CKA_ID, 0, 0},
       {CKA_LABEL, 0, 0},
   };

   CK_ATTRIBUTE priv_template[] = {
       {CKA_TOKEN, 0, 0},
       {CKA_PRIVATE, 0, 0},
       {CKA_SENSITIVE, 0, 0},
       {CKA_SIGN, 0, 0},
       {CKA_MODIFIABLE, 0, 0},
       {CKA_EXTRACTABLE, 0, 0},
       {CKA_ID, 0, 0},
       {CKA_LABEL, 0, 0},
   };

   /* select curve */
   if (group == NULL) {
      CK_ULONG uCurve = LUNA_DIM(sautil_curves);

      for (ii = 0; ii < LUNA_DIM(sautil_curves); ii++) {
         if (strcmp(curve_name, sautil_curves[ii].name) == 0) {
            uCurve = ii;
            break;
         }
      }

      if (uCurve >= LUNA_DIM(sautil_curves)) {
         fprintf(stderr, "Unrecognized curve name [%s]\n", (char *)curve_name);
         return -1;
      }

      curve_len = sautil_curves[uCurve].ulValueLen;
      if (curve_len > sizeof(curve_data)) {
         fprintf(stderr, "Buffer too small [curve_len=%u]\n", (unsigned)curve_len);
         return -1;
      }
      memcpy(curve_data, sautil_curves[uCurve].pValue, curve_len);

      if (verbose) {
         fprintf(stdout, "EC_CURVE_NAME=%s\n", (char *)curve_name);
         fprintf(stdout, "EC_CURVE_COMMENT=%s\n", (char *)"SAUTIL BUILTIN CURVE");
      }

   } else {
      EC_builtin_curve *curves = NULL;
      size_t crv_len = 0;
      size_t n = 0;
      int nid = 0;
      size_t field_len = 0;

      if (!EC_GROUP_check(group, NULL)) {
         fprintf(stderr, "EC_GROUP_check failed. \n");
         return -1;
      }

      if ((nid = EC_GROUP_get_curve_name(group)) < 1) {
         fprintf(stderr, "EC_GROUP_get_curve_name failed. \n");
         return -1;
      }

      /* check bare minimum ec key size (160) */
      if (!(field_len = LUNA_EC_GROUP_get_field_len(group))) {
         fprintf(stderr, "ERROR: LUNA_EC_GROUP_get_field_len failed. \n");
         return -1;
      }

      if ( field_len < ((LOCAL_EC_KEYSIZE_MIN + 7) / 8) ) {
         fprintf(stderr, "Invalid field_len size %u less than %u. \n", (unsigned)field_len,
                 (unsigned)LOCAL_EC_KEYSIZE_MIN);
         return -1;
      }

      crv_len = EC_get_builtin_curves(NULL, 0);
      curves = (EC_builtin_curve *)OPENSSL_malloc((int)(sizeof(EC_builtin_curve) * crv_len));
      if (curves == NULL) {
         fprintf(stderr, "OPENSSL_malloc failed. \n");
         return -1;
      }

      if (!EC_get_builtin_curves(curves, crv_len)) {
         fprintf(stderr, "EC_get_builtin_curves failed. \n");
         OPENSSL_free(curves);
         return -1;
      }

      for (n = 0; n < crv_len; n++) {
         const char *comment = NULL;
         const char *sname = NULL;
         ASN1_OBJECT *asnobj = NULL;

         if (curves[n].nid == nid) /* match */
         {
            comment = curves[n].comment;
            if (comment == NULL) {
               comment = "OPENSSL BUILTIN CURVE";
            }

            sname = OBJ_nid2sn(curves[n].nid);
            if (sname == NULL) {
               sname = "(NULL)";
            }

            if (verbose) {
               fprintf(stdout, "EC_CURVE_NAME=%s\n", (char *)sname);
               fprintf(stdout, "EC_CURVE_COMMENT=%s\n", (char *)comment);
            }

            asnobj = OBJ_nid2obj(curves[n].nid);
            if (asnobj == NULL) {
               fprintf(stderr, "OBJ_nid2obj failed. \n");
               OPENSSL_free(curves);
               return -1;
            }

            curve_len = (LUNA_ASN1_OBJECT_GET_length(asnobj) + 2);
            if (curve_len > sizeof(curve_data)) {
               fprintf(stderr, "Buffer too small [curve_len=%u]. \n", (unsigned)curve_len);
               OPENSSL_free(curves);
               return -1;
            }

            curve_data[0] = 0x06;
            curve_data[1] = LUNA_ASN1_OBJECT_GET_length(asnobj);
            memcpy(&curve_data[2], LUNA_ASN1_OBJECT_GET_data(asnobj), LUNA_ASN1_OBJECT_GET_length(asnobj));
            break;
         } /* match */
      }    /* for loop */

      if (n >= crv_len) {
         fprintf(stderr, "Curve does not match any builtin curves. \n");
         OPENSSL_free(curves);
         return -1;
      }

      OPENSSL_free(curves);
   }

   /* set cka value */
   sautil_ckatab_malloc_replace(pub_template, LUNA_DIM(pub_template), CKA_TOKEN, &bTrue, sizeof(bTrue));
   sautil_ckatab_malloc_replace(pub_template, LUNA_DIM(pub_template), CKA_PRIVATE, &bTrue, sizeof(bTrue));
   sautil_ckatab_malloc_replace(pub_template, LUNA_DIM(pub_template), CKA_VERIFY, &bTrue, sizeof(bTrue));
   sautil_ckatab_malloc_replace(pub_template, LUNA_DIM(pub_template), CKA_MODIFIABLE, &bModifiable, sizeof(bModifiable));
   sautil_ckatab_malloc_replace(pub_template, LUNA_DIM(pub_template), CKA_ECDSA_PARAMS, curve_data, curve_len);
   sautil_ckatab_malloc_replace(pub_template, LUNA_DIM(pub_template), CKA_ID, baCkId, baCkIdLen);
   sautil_ckatab_malloc_replace(pub_template, LUNA_DIM(pub_template), CKA_LABEL, pub_key_label,
                                (CK_ULONG)strlen((char *)pub_key_label));

   sautil_ckatab_malloc_replace(priv_template, LUNA_DIM(priv_template), CKA_TOKEN, &bTrue, sizeof(bTrue));
   sautil_ckatab_malloc_replace(priv_template, LUNA_DIM(priv_template), CKA_PRIVATE, &bTrue, sizeof(bTrue));
   sautil_ckatab_malloc_replace(priv_template, LUNA_DIM(priv_template), CKA_SENSITIVE, &bTrue, sizeof(bTrue));
   sautil_ckatab_malloc_replace(priv_template, LUNA_DIM(priv_template), CKA_SIGN, &bTrue, sizeof(bTrue));
   sautil_ckatab_malloc_replace(priv_template, LUNA_DIM(priv_template), CKA_MODIFIABLE, &bModifiable, sizeof(bModifiable));
   sautil_ckatab_malloc_replace(priv_template, LUNA_DIM(priv_template), CKA_EXTRACTABLE, &bExtractable, sizeof(bExtractable));
   sautil_ckatab_malloc_replace(priv_template, LUNA_DIM(priv_template), CKA_ID, baCkId, baCkIdLen);
   sautil_ckatab_malloc_replace(priv_template, LUNA_DIM(priv_template), CKA_LABEL, priv_key_label,
                                (CK_ULONG)strlen((char *)priv_key_label));

   /* return public template */
   pubTemplate = (CK_ATTRIBUTE *)malloc(sizeof(pub_template));
   if (pubTemplate == NULL)
      return -1;
   memcpy(pubTemplate, pub_template, sizeof(pub_template));
   (*pubTemp) = pubTemplate;
   (*pubTempSize) = LUNA_DIM(pub_template);

   /* return private template */
   privTemplate = (CK_ATTRIBUTE *)malloc(sizeof(priv_template));
   if (privTemplate == NULL) {
       free(pubTemplate);
       return -1;
    }
   memcpy(privTemplate, priv_template, sizeof(priv_template));
   (*privTemp) = privTemplate;
   (*privTempSize) = LUNA_DIM(priv_template);

   return 0;
}

/* generate new ecdsa keypair */
static int op_generate_ecdsa_key_pair(CK_SLOT_ID slotid, CK_USHORT modulussize, char *keypair_fname,
                                      char *param_fname) {
   int ret;
   CK_RV retCode;
   CK_ATTRIBUTE *pub_template = NULL;
   CK_ATTRIBUTE *priv_template = NULL;
   CK_USHORT pub_template_size = 0;
   CK_USHORT priv_template_size = 0;
   CK_OBJECT_HANDLE pub_handle = CK_INVALID_HANDLE;
   CK_OBJECT_HANDLE priv_handle = CK_INVALID_HANDLE;
   CK_SESSION_HANDLE session_handle = CK_INVALID_HANDLE;
   CK_BYTE *pubLabel = NULL;
   CK_BYTE *privLabel = NULL;
   EC_GROUP *group = NULL;

   CK_MECHANISM key_gen_mech = {CKM_EC_KEY_PAIR_GEN, NULL_PTR, 0};

   char szPubLabel[LUNA_MAX_STRING_LEN + 1];
   char szPrivLabel[LUNA_MAX_STRING_LEN + 1];
   CK_BYTE baCkId[20];

   memset(szPubLabel, 0, sizeof(szPubLabel));
   memset(szPrivLabel, 0, sizeof(szPrivLabel));
   memset(baCkId, 0, sizeof(baCkId));

   ret = set_application_id(app_id_hi, app_id_lo);
   if (ret != 0)
      return -1;

   group = NULL;
   if (param_fname != NULL) {
      /* get p, q, g from file */
      BIO *f = NULL;

      if ((f = BIO_new(BIO_s_file())) == NULL) {
         fprintf(stderr, "BIO_new failed. \n");
         return -1;
      }

      if (BIO_read_filename(f, param_fname) <= 0) {
         fprintf(stderr, "BIO_read_filename failed. \n");
         return -1;
      }

      if ((group = PEM_read_bio_ECPKParameters(f, NULL, NULL, NULL)) == NULL) {
         fprintf(stderr, "PEM_read_bio_ECPKParameters failed. \n");
         return -1;
      }
   }

   switch (modulussize) {
      case 1024:
         sautil_sprint_unique(szPubLabel, sizeof(szPubLabel),
                 szPrivLabel, sizeof(szPrivLabel),
                 "ECDSA", 0);
         pubLabel = (CK_BYTE *)szPubLabel;
         privLabel = (CK_BYTE *)szPrivLabel;
         break;
      default:
         fprintf(stderr, "BUG: coding error. \n");
         return -1;
   }

   if (open_session(slotid, &session_handle) != 0)
      return -1;

   /* if we're not logged in here, return an error */
   if (!loggedin(slotid)) {
      fprintf(stderr, "Error: The user is not logged in to the selected slot (%d).\n", (int)slotid);
      return -1;
   }

   /* generate temporary CKA_ID */
   if (sautil_sha1_prng(session_handle, baCkId) != CKR_OK) {
      fprintf(stderr, "Failed RNG.\n");
      return -1;
   }

   sautil_strncpy(szPubLabel, "ecdsa-public-", sizeof(szPubLabel));
   (void)luna_sprintf_hex(&szPubLabel[13], baCkId, sizeof(baCkId));
   sautil_strncpy(szPrivLabel, "ecdsa-private-", sizeof(szPrivLabel));
   (void)luna_sprintf_hex(&szPrivLabel[14], baCkId, sizeof(baCkId));

   if (have_label) {
      sautil_strncpy(szPubLabel, sautil_label, sizeof(szPubLabel));
      sautil_strncpy(szPrivLabel, sautil_label, sizeof(szPrivLabel));
   }

   ret = init_ecdsa_key_template(&pub_template, &pub_template_size, &priv_template, &priv_template_size, pubLabel,
                                 privLabel, sautil_szcurve, group, baCkId, sizeof(baCkId));
   if (ret != 0)
      return -1;

   if (luna_ckatab_pre_keygen(session_handle, priv_template, priv_template_size)) {
      goto err;
   }

   /* C_GenerateKeyPair */
   if (verbose)
      fprintf(stdout, "Generating ECDSA key pair ... (please wait) \n");

   retCode = p11.std->C_GenerateKeyPair(session_handle, &key_gen_mech, pub_template, pub_template_size, priv_template,
                                        priv_template_size, &pub_handle, &priv_handle);
   if ((retCode != CKR_OK) || (pub_handle == CK_INVALID_HANDLE) || (priv_handle == CK_INVALID_HANDLE)) {
      fprintf(stderr, "Generate ECDSA Key Pair Error 0x%x.\n", (int)retCode);
      goto err;
   }

   if (verbose) {
      fprintf(stdout, "ECDSA Public key handle is %u\n", (unsigned)pub_handle);
      fprintf(stdout, "ECDSA Private key handle is %u\n", (unsigned)priv_handle);
   }

   if (verbose) {
      luna_dump_hex(stdout, "CKA_ID=", baCkId, sizeof(baCkId));
   }

   ret = write_pem_ecdsa_key_pair(session_handle, pub_handle, priv_handle, keypair_fname);
   if (ret != 0)
      goto err;

   sautil_ckatab_free_all(pub_template, pub_template_size, 1);
   sautil_ckatab_free_all(priv_template, priv_template_size, 1);
   return 0;

err:
   sautil_ckatab_free_all(pub_template, pub_template_size, 1);
   sautil_ckatab_free_all(priv_template, priv_template_size, 1);
   close_session(session_handle);
   session_handle = 0;
   return -1;
}

/* write ecdsa key to file */
static int write_pem_ecdsa_key_pair(CK_SESSION_HANDLE session_handle, CK_OBJECT_HANDLE pub_handle,
                                    CK_OBJECT_HANDLE priv_handle, char *keypair_fname) {
   int ret = -1;
   int have_ec_point = 0;
   CK_RV retCode = CKR_GENERAL_ERROR;
   BIO *outfile = NULL;
   EC_KEY *dsa = NULL;
   const unsigned ndxP = 0;
   const unsigned ndxQ = 1;
   const unsigned ndxId = 2;

   CK_ATTRIBUTE ckaPublic[] = {{CKA_EC_PARAMS, NULL_PTR, 0}, {CKA_EC_POINT, NULL_PTR, 0}, {CKA_ID, NULL_PTR, 0}};

   CK_ATTRIBUTE ckaPrivate[] = {{CKA_EC_PARAMS, NULL_PTR, 0}, {CKA_EC_POINT, NULL_PTR, 0}, {CKA_ID, NULL_PTR, 0}};

   CK_ATTRIBUTE attrP;
   CK_ATTRIBUTE attrQ;

   /* open file for writing (before hsm io) */
   if ((outfile = BIO_new(BIO_s_file())) == NULL) {
      fprintf(stderr, "Cannot open output file.\n");
      goto err;
   }

   if (BIO_write_filename(outfile, keypair_fname) <= 0) {
      fprintf(stderr, "Cannot open file for writing: %s.\n", (char *)keypair_fname);
      goto err;
   }

   /* extract ec point from private key */
   if ((!have_ec_point) && (priv_handle != 0)) {
      retCode = sautil_ckatab_malloc_object(ckaPrivate, LUNA_DIM(ckaPrivate), priv_handle, session_handle);
      if ((retCode != CKR_OK) || (ckaPrivate[ndxP].pValue == NULL) || (ckaPrivate[ndxQ].pValue == NULL) ||
          (ckaPrivate[ndxId].pValue == NULL) || (ckaPrivate[ndxP].ulValueLen < SAUTIL_EC_CURVE_MIN_BYTES) ||
          (ckaPrivate[ndxQ].ulValueLen < 2) || (ckaPrivate[ndxId].ulValueLen < 20)) {
         /*fprintf(stderr, "WARNING: Failed to extract private ECDSA key: 0x%x\n", (int) retCode);*/
      } else {
         attrP = ckaPrivate[ndxP];
         attrQ = ckaPrivate[ndxQ];
         have_ec_point = 1;
      }
   }

   /* extract ec point from public key */
   if ((!have_ec_point) && (pub_handle != 0)) {
      retCode = sautil_ckatab_malloc_object(ckaPublic, LUNA_DIM(ckaPublic), pub_handle, session_handle);
      if ((retCode != CKR_OK) || (ckaPublic[ndxP].pValue == NULL) || (ckaPublic[ndxQ].pValue == NULL) ||
          (ckaPublic[ndxId].pValue == NULL) || (ckaPublic[ndxP].ulValueLen < SAUTIL_EC_CURVE_MIN_BYTES) ||
          (ckaPublic[ndxQ].ulValueLen < 2) || (ckaPublic[ndxId].ulValueLen < 20)) {
         /*fprintf(stderr, "WARNING: Failed to extract public ECDSA key: 0x%x\n", (int) retCode);*/
      } else {
         attrP = ckaPublic[ndxP];
         attrQ = ckaPublic[ndxQ];
         have_ec_point = 1;
      }
   }

   /* check error after trying public and private key */
   if (!have_ec_point) {
      fprintf(stderr, "ERROR: failed to read ec point: 0x%x\n", (int)retCode);
      goto err;
   }

   if (verbose) {
      luna_dump_hex(stdout, "CKA_EC_POINT=", (CK_BYTE_PTR)attrQ.pValue, attrQ.ulValueLen);
   }

   if ((dsa = EC_KEY_new()) == NULL)
      goto err;

   /* set group */
   if (1) {
      CK_BYTE_PTR buf_ptr = NULL;
      CK_ULONG buf_len = 0;
      const unsigned char **in = NULL;
      const EC_GROUP *group = NULL;

      buf_ptr = (CK_BYTE_PTR)attrP.pValue;
      buf_len = attrP.ulValueLen;
      in = (const unsigned char **)&buf_ptr;
      if (d2i_ECParameters(&dsa, in, buf_len) == NULL) {
         LUNACA3err(LUNACA3_F_LOADKEY, LUNACA3_R_EGETATTR);
         ERR_add_error_data(1, "d2i_ECParameters");
         goto err;
      }

      if ((group = EC_KEY_get0_group(dsa)) == NULL)
         goto err;
      if (!EC_GROUP_check(group, NULL)) {
         LUNACA3err(LUNACA3_F_LOADKEY, LUNACA3_R_EGETATTR);
         ERR_add_error_data(1, "EC_GROUP_check");
         goto err;
      }
   }
   /* set public key */
   if (1) {
      CK_BYTE_PTR buf_ptr = (CK_BYTE_PTR)attrQ.pValue;
      CK_ULONG buf_len = attrQ.ulValueLen;
      if (!LUNA_o2i_ECPublicKey(&dsa, buf_ptr, buf_len)) {
         LUNACA3err(LUNACA3_F_LOADKEY, LUNACA3_R_EGETATTR);
         ERR_add_error_data(1, "LUNA_o2i_ECPublicKey");
         goto err;
      }
   }

   /* Setting the value of the private key ta a series of 0x5A with a leading byte to make value one bit less than the
    * order. */
   /* This is to prevent openssh from not liking the key but still giving us the ability to recognize that is is a
    * hardware key */
   if (1) {
      int i;
      char private_bin[512];
      int order = 0;
      int bits = 0;
      BIGNUM *num = NULL;
      const EC_GROUP *group = NULL;
      const BIGNUM *p_order = NULL;
      BIGNUM *p_alloc = NULL;

      if ((group = LUNA_EC_KEY_get0_group(dsa)) == NULL)
         goto err;
      if ((p_order = LUNA_EC_GROUP_get0_order(group, &p_alloc)) == NULL)
         goto err;
      if ((num = BN_new()) == NULL)
         goto err;

      order = BN_num_bytes(p_order);
      order = LUNA_MIN(order, LUNA_DIM(private_bin));
      bits = BN_num_bits(p_order);
      private_bin[0] = (0x80 >> (order * 8 - bits + 1));
      for (i = 1; i < order; i++)
         private_bin[i] = 0x5A;
      if (!BN_bin2bn(private_bin, order, num)) {
         BN_free(num);
         if (p_alloc)
            BN_free(p_alloc);
         goto err;
      }
      if (p_alloc)
         BN_free(p_alloc);
      /* set private key */
      if (!LUNA_EC_KEY_set_private_key(dsa, num))
         goto err;
   }

   /* Write keyfile */
   /* NOTE: we know EC_KEY_check_key fails because private key is pseudo */
   if (!PEM_write_bio_ECPrivateKey(outfile, dsa, NULL, NULL, 0, NULL, NULL)) {
      fprintf(stderr, "PEM_write_bio_ECPrivateKey failed.\n");
      goto err;
   }

   ret = 0;
   if (verbose)
      fprintf(stdout, "Wrote file \"%s\".\n", (char *)keypair_fname);

err:
   if (dsa != NULL) {
      EC_KEY_free(dsa);
      dsa = NULL;
   }

   sautil_ckatab_free_all(ckaPublic, LUNA_DIM(ckaPublic), 0);
   return ret;
}

/* delete ecdsa keypair */
static int op_delete_ecdsa_key_pair(CK_SLOT_ID slotid, char *keypair_fname) {
   BIO *f = NULL;
   int ret = -1;
   EC_KEY *dsa = NULL;
   CK_OBJECT_HANDLE handle = CK_INVALID_HANDLE;
   CK_SESSION_HANDLE session_handle = 0;
   CK_RV retCode = CKR_GENERAL_ERROR;
   luna_context_t ctx = LUNA_CONTEXT_T_INIT;

   /* open file before hsm io */
   if ((f = BIO_new(BIO_s_file())) == NULL) {
      fprintf(stderr, "Cannot open file.\n");
      goto err;
   }

   if (BIO_read_filename(f, keypair_fname) <= 0) {
      fprintf(stderr, "Cannot open [%s] for reading.\n", keypair_fname);
      goto err;
   }

   if (!(dsa = PEM_read_bio_ECPrivateKey(f, NULL, NULL, NULL))) {
      fprintf(stderr, "Failed reading ECDSA key pair. file: [%s]\n", keypair_fname);
      goto err;
   }

   if (set_application_id(app_id_hi, app_id_lo) != 0)
      goto err;
   if (open_session(slotid, &session_handle) != 0)
      goto err;

   /* if we're not logged in here, return an error */
   if (!loggedin(slotid)) {
      fprintf(stderr, "Error: The user is not logged in to the selected slot (%d).\n", (int)slotid);
      goto err;
   }

   /* fill luna_context_t */
   ctx.hSession = session_handle;
   ctx.flagInit = 1;

   /* ALWAYS Destroy private object first, if the public dsa key is erased first
    * then we wont be able to find the private one */
   handle = luna_find_ecdsa_handle(&ctx, dsa, 1);
   if ((handle == CK_INVALID_HANDLE) || ((retCode = p11.std->C_DestroyObject(session_handle, handle)) != CKR_OK)) {
      fprintf(stderr, "Delete private failed.\n");
      goto err;
   }

   if (verbose) {
      fprintf(stdout, "ECDSA private key handle is %u\n", (unsigned)handle);
   }

   fprintf(stderr, "Delete private ok.\n");

   /* Destroy public object */
   handle = luna_find_ecdsa_handle(&ctx, dsa, 0);
   if ((handle == CK_INVALID_HANDLE) || ((retCode = p11.std->C_DestroyObject(session_handle, handle)) != CKR_OK)) {
      fprintf(stderr, "Delete public failed.\n");
      goto err;
   }

   if (verbose) {
      fprintf(stdout, "ECDSA public key handle is %u\n", (unsigned)handle);
   }

   fprintf(stderr, "Delete public ok.\n");

   ret = 0;

err:
   if (dsa)
      EC_KEY_free(dsa);
   BIO_free(f);

   return ret;
}

/* Code adapted from gem engine uses OpenSSL indentation. */

#define LUNA_INVALID_HANDLE CK_INVALID_HANDLE
#define LUNA_malloc malloc
#define LUNA_free free

#define LUNA_MEMCMP_MIN_LEN (14)
#define LUNA_MEMCMP_MAX_DIFF (4)

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "luna_attribute_malloc"

/* Get attribute value */
static int luna_attribute_malloc(luna_context_t *ctx, CK_OBJECT_HANDLE handle, CK_ATTRIBUTE_PTR pAttr) {
   CK_RV retCode = 0;

   pAttr->ulValueLen = 0;
   pAttr->pValue = 0;
   retCode = p11.std->C_GetAttributeValue(ctx->hSession, handle, pAttr, 1);
   if (retCode != CKR_OK) {
      fprintf(stderr, LUNA_FUNC_NAME ": C_GetAttributeValue.\n");
      goto err;
   }
   /* NOTE: assert length is non-zero; esp. for CKA_ID */
   if (pAttr->ulValueLen < 1) {
      fprintf(stderr, LUNA_FUNC_NAME ": ulValueLen < 1.\n");
      goto err;
   }
   /* NOTE: always allocated on heap */
   pAttr->pValue = (CK_BYTE_PTR)LUNA_malloc(pAttr->ulValueLen);
   retCode = p11.std->C_GetAttributeValue(ctx->hSession, handle, pAttr, 1);
   if (retCode != CKR_OK) {
      fprintf(stderr, LUNA_FUNC_NAME ": C_GetAttributeValue.\n");
      goto err;
   }
   return 1;
err:
   if (pAttr->pValue != NULL)
      LUNA_free(pAttr->pValue);
   pAttr->ulValueLen = 0;
   pAttr->pValue = 0;
   return 0;
}

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "luna_attribute_free"

/* helper function (free data for attribute) */
static void luna_attribute_free(CK_ATTRIBUTE_PTR p_attr) {
   unsigned ii = 0;

   for (ii = 0; ii < 1; ii++) {
      if (p_attr[ii].pValue != NULL) {
         LUNA_free(p_attr[ii].pValue);
         p_attr[ii].pValue = NULL;
         p_attr[ii].ulValueLen = 0;
      }
   }

   /* NOTE: dont zeroize p_attr because that wipes out the "type" field too! */
}

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "luna_find_object_ex1"

/* Find object */
static int luna_find_object_ex1(luna_context_t *ctx, CK_ATTRIBUTE_PTR pAttr, CK_ULONG nAttr,
                                CK_OBJECT_HANDLE_PTR pHandle, int flagCountMustEqualOne) {
   CK_RV retCode = 0;
   CK_OBJECT_HANDLE arrayHandle[2] = {LUNA_INVALID_HANDLE, LUNA_INVALID_HANDLE};
   CK_ULONG nObjFound = 0;

   retCode = p11.std->C_FindObjectsInit(ctx->hSession, pAttr, nAttr);
   if (retCode != CKR_OK) {
      fprintf(stderr, LUNA_FUNC_NAME ": C_FindObjectsInit=0x%x.\n", (unsigned)retCode);
      goto err;
   }

   if (flagCountMustEqualOne) {
      retCode = p11.std->C_FindObjects(ctx->hSession, arrayHandle, LUNA_DIM(arrayHandle), &nObjFound);
   } else {
      retCode = p11.std->C_FindObjects(ctx->hSession, arrayHandle, 1, &nObjFound); /* possible optimization */
   }
   if (retCode != CKR_OK) {
      fprintf(stderr, LUNA_FUNC_NAME ": C_FindObjects=0x%x.\n", (unsigned)retCode);
      goto err;
   }

   (void)p11.std->C_FindObjectsFinal(ctx->hSession);
   if (nObjFound < 1)
      goto err;
   if (arrayHandle[0] == LUNA_INVALID_HANDLE)
      goto err;
   if (flagCountMustEqualOne && (nObjFound != 1)) {
      fprintf(stderr, LUNA_FUNC_NAME ": nObjFound=0x%x.\n", (unsigned)nObjFound);
      goto err;
   }
   (*pHandle) = arrayHandle[0];
   return 1;

err:
   (*pHandle) = 0;
   return 0;
}

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "luna_memcmp_rev_inexact"

/* Compare memory (reverse order, inexact) */
static int luna_memcmp_rev_inexact(CK_BYTE_PTR base_p, CK_ULONG base_len, CK_BYTE_PTR token_p, CK_ULONG token_len) {
   CK_ULONG max_count = 0;
   CK_ULONG diff_count = 0;
   CK_ULONG ii = 0;

   max_count = LUNA_MIN(base_len, token_len);
   if (max_count < LUNA_MEMCMP_MIN_LEN)
      return -1; /* not enough bytes to compare */

   diff_count = LUNA_DIFF(base_len, token_len);
   if (diff_count > LUNA_MEMCMP_MAX_DIFF)
      return -2; /* the sizes are not close enough */

   for (ii = 0; ii < max_count; ii++) {
      /* compare in reverse order */
      if (token_p[token_len - ii - 1] != base_p[base_len - ii - 1])
         break;
   }

   /* ii = number of bytes that matched */
   diff_count = LUNA_DIFF(ii, base_len);
   if (diff_count > LUNA_MEMCMP_MAX_DIFF)
      return -3; /* not enough matching bytes */

   /* TODO: we should check the value of the ignored bytes (e.g., asn1 header stuff) */

   return 0; /* success */
}

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "luna_find_object_inexact"

/* Find object; must be unique; use inexact algorithm */
static int luna_find_object_inexact(luna_context_t *ctx, CK_ATTRIBUTE_PTR pAttr, CK_ULONG nAttr,
                                    CK_OBJECT_HANDLE_PTR pHandle, CK_ATTRIBUTE_PTR attrBase) {
   int have_init = 0;
   CK_RV retCodeTotal = CKR_OK;
   CK_RV retLoop = CKR_OK;
   CK_RV retCode = CKR_OK;
   CK_ULONG obj_count = 0;
   CK_ULONG match_count = 0;
   CK_OBJECT_HANDLE match_handle = LUNA_INVALID_HANDLE;

   CK_ATTRIBUTE attrFoo[1];
   CK_OBJECT_HANDLE handles[1] = {LUNA_INVALID_HANDLE};

   memset(attrFoo, 0, sizeof(attrFoo));

   if ((attrBase == NULL) || (attrBase[0].pValue == NULL) || (attrBase[0].ulValueLen < LUNA_MEMCMP_MIN_LEN)) {
      fprintf(stderr, LUNA_FUNC_NAME ": attrBase invalid.\n");
      goto err;
   }

   /* FindObjectsInit */
   if (retCode == CKR_OK) {
      retCode = p11.std->C_FindObjectsInit(ctx->hSession, pAttr, nAttr);
      have_init = (retCode == CKR_OK) ? 1 : 0;
   }

   /* FindObjects */
   if (retCode == CKR_OK) {
      do {
         retLoop = CKR_GENERAL_ERROR; /* initially assume error */
         handles[0] = 0;
         obj_count = 0;
         retCode = p11.std->C_FindObjects(ctx->hSession, &handles[0], 1, &obj_count);
         if ((retCode == CKR_OK) && (obj_count == 1) && (handles[0] != LUNA_INVALID_HANDLE)) {
            attrFoo[0].type = attrBase[0].type;
            attrFoo[0].pValue = NULL;
            attrFoo[0].ulValueLen = 0;
            if (luna_attribute_malloc(ctx, handles[0], attrFoo)) {
               retLoop = CKR_OK; /* continue looping */
               if (luna_memcmp_rev_inexact((CK_BYTE_PTR)attrBase[0].pValue, attrBase[0].ulValueLen,
                                           (CK_BYTE_PTR)attrFoo[0].pValue, attrFoo[0].ulValueLen) == 0) {
                  /* found a match... maybe not the only match */
                  match_count++;
                  match_handle = handles[0];
               }

               /* Undo luna_attribute_malloc */
               luna_attribute_free(attrFoo);
            } else {
               /* failing to get attribute constitutes total failure */
               retCodeTotal = retLoop = CKR_GENERAL_ERROR;
            }
         } else {
            /* failing to iterate constitutes total failure */
            if (retCode != CKR_OK) {
               retCodeTotal = retLoop = retCode;
            }
         }
      } while (retLoop == CKR_OK);
   }

   /* FindObjectsFinal */
   if (have_init) {
      (void)p11.std->C_FindObjectsFinal(ctx->hSession);
   }

   /* Undo luna_attribute_malloc */
   luna_attribute_free(attrFoo);

   /* Check result (silent) */
   if (match_count < 1)
      goto err;

   /* Check result (non-silent) */
   if (match_count != 1) {
      fprintf(stderr, LUNA_FUNC_NAME ": match_count != 1.\n");
      goto err;
   }

   /* Return success */
   (*pHandle) = match_handle;
   return 1;

err:
   /* Return failure */
   (*pHandle) = LUNA_INVALID_HANDLE;
   return 0;
}

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "luna_find_ecdsa_handle"

/* find ecdsa key (typically for deletion) */
static CK_OBJECT_HANDLE luna_find_ecdsa_handle(luna_context_t *ctx, EC_KEY *dsa, int bPrivate) {
   CK_OBJECT_HANDLE rethandle = CK_INVALID_HANDLE;

   int rcSize1 = -1;
   CK_BYTE_PTR bufP = NULL;
   CK_BYTE_PTR bufQ = NULL;
   CK_ULONG rcCount = 0;
   CK_ULONG rcBase = 0;
   CK_OBJECT_HANDLE tmphandle = CK_INVALID_HANDLE;
   CK_OBJECT_CLASS ulClass = 0;
   CK_KEY_TYPE ulKeyType = 0;

   CK_ATTRIBUTE attrib[6];
   CK_ATTRIBUTE attribId[1];
   CK_ATTRIBUTE attribPoint[1];

   memset(attrib, 0, sizeof(attrib));
   memset(attribId, 0, sizeof(attribId));
   memset(attribPoint, 0, sizeof(attribPoint));

   /* Define base attributes (common to public and private key) */
   rcCount = 0;

   ulKeyType = CKK_EC;
   attrib[rcCount].type = CKA_KEY_TYPE;
   attrib[rcCount].pValue = &ulKeyType;
   attrib[rcCount].ulValueLen = sizeof(ulKeyType);
   rcCount++;

   if ((rcSize1 = i2d_ECParameters(dsa, &bufP)) < 1)
      goto done;
   attrib[rcCount].type = CKA_EC_PARAMS;
   attrib[rcCount].pValue = bufP;
   attrib[rcCount].ulValueLen = (CK_ULONG)rcSize1;
   rcCount++;

   /* Define public key attributes */
   rcBase = rcCount;

   ulClass = CKO_PUBLIC_KEY;
   attrib[rcCount].type = CKA_CLASS;
   attrib[rcCount].pValue = &ulClass;
   attrib[rcCount].ulValueLen = sizeof(ulClass);
   rcCount++;

   /* NOTE: i2o_ECPublicKey does not encode the exact same CKA_EC_POINT found on token! */
   if ((rcSize1 = i2o_ECPublicKey(dsa, &bufQ)) < 1)
      goto done;
   attribPoint[0].type = CKA_EC_POINT;
   attribPoint[0].pValue = bufQ;
   attribPoint[0].ulValueLen = (CK_ULONG)rcSize1;

   /* Find public key (using inexact search algorithm; see i2o_ECPublicKey) */
   if (!luna_find_object_inexact(ctx, attrib, rcCount, &tmphandle, attribPoint)) {
      fprintf(stderr, LUNA_FUNC_NAME ": luna_find_object_inexact.\n");
      goto done;
   }

   /* Find private key using CKA_ID of public key */
   if (bPrivate) {
      attribId[0].type = CKA_ID;
      attribId[0].pValue = NULL_PTR;
      attribId[0].ulValueLen = 0;
      if (!luna_attribute_malloc(ctx, tmphandle, attribId)) {
         fprintf(stderr, LUNA_FUNC_NAME ": luna_attribute_malloc.\n");
         goto done;
      }

      /* Define private key attributes */
      rcCount = rcBase;

      ulClass = CKO_PRIVATE_KEY;
      attrib[rcCount].type = CKA_CLASS;
      attrib[rcCount].pValue = &ulClass;
      attrib[rcCount].ulValueLen = sizeof(ulClass);
      rcCount++;

      attrib[rcCount] = attribId[0]; /* copy struct */
      rcCount++;

      /* Find private key; must be unique */
      if (!luna_find_object_ex1(ctx, attrib, rcCount, &tmphandle, 1)) {
         fprintf(stderr, LUNA_FUNC_NAME ": luna_find_object_ex1.\n");
         goto done;
      }
   }

   /* on success, set 'rethandle' */
   rethandle = tmphandle;

done:
   /* undo luna_attribute_malloc */
   luna_attribute_free(attribId);

   /* undo i2d_ECParameters */
   if (bufP != NULL) {
      OPENSSL_free(bufP);
   }

   /* undo i2o_ECPublicKey */
   if (bufQ != NULL) {
      OPENSSL_free(bufQ);
   }

   return rethandle;
}

#if (0) /* dead code */
/* extract encoded "EC_KEY->priv_key" */
static unsigned _luna_ecdsa_priv2bin(EC_KEY *dsa, CK_BYTE_PTR *in) {
   CK_BYTE baHeader[] = {'s', 'a', 'u', 't', 'i', 'l', ':', 'C', 'K', 'A', '_', 'I', 'D', ':'};
   unsigned num = 0;
   CK_BYTE_PTR bufX = NULL;
   CK_BYTE_PTR bufW = NULL;

   /* check null */
   if (dsa == NULL)
      goto err;
   if (dsa->priv_key == NULL)
      goto err;
   /* CKA_ID should size of sha1 hash or larger */
   if ((num = BN_num_bytes(dsa->priv_key)) < (sizeof(baHeader) + 20))
      goto err;
   /* check out of memory */
   if ((bufX = (CK_BYTE_PTR)LUNA_malloc(num)) == NULL)
      goto err;
   if ((bufW = (CK_BYTE_PTR)LUNA_malloc(num)) == NULL)
      goto err;
   if (num != BN_bn2bin(dsa->priv_key, bufX))
      goto err;
   /* check the encoding */
   if (memcmp(baHeader, bufX, sizeof(baHeader)) != 0)
      goto err;
   if (in != NULL) {
      memcpy(bufW, (bufX + sizeof(baHeader)), (num - sizeof(baHeader)));
      (*in) = bufW;
   } else {
      LUNA_free(bufW);
      bufW = NULL;
   }
   LUNA_free(bufX);
   bufX = NULL;
   return (num - sizeof(baHeader));

err:

   if (bufW != NULL)
      LUNA_free(bufW);
   if (bufX != NULL)
      LUNA_free(bufX);
   return 0;
}
#endif

#endif /* LUNA_OSSL_ECDSA */

/* Format string with ascii hex bytes */
static char *luna_sprintf_hex(char *fp0, unsigned char *id, unsigned size) {
   unsigned ii = 0;
   char *fp = (char *)fp0;
   fp[0] = 0;
   for (ii = 0; ii < size; ii++) {
      snprintf(&fp[ii << 1], 3, "%02x", (unsigned)id[ii]); /* lowercase for dnssec */
   }
   return fp0;
}

/* find character within string iff at end of the string */
static char *luna_strchr_eos(const char *s, int c) {
   char *ptr = strchr((char *)s, c);

   for (; ptr != NULL; ptr = strchr(ptr + 1, c)) {
      if (ptr[1] == '\0') {
         return ptr;
      }
   }

   return NULL;
}

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "luna_parse_slotid"

/* Parse string and initialize session descriptor */
/* NOTE: slotid is either a numeric slot number or a token label (within quotes) */
/* NOTE: assumes C_GetSlotList will succeed. */
static int luna_parse_slotid(char *arg, session_desc *desc) {
   char *s0 = NULL, *sslot = NULL;
   char *ptr = NULL;

   memset(desc, 0, sizeof(*desc));

   /* Parse string format:  "slotid" */
   sslot = s0 = strdup(arg);
   if (s0 == NULL)
      goto err;

   /* eat whitespace */
   for (; *sslot; sslot++) {
      if (!isspace(*sslot))
         break;
   }

   /* look for starting quote and ending quote (or alternative quote) */
   if ((((*sslot) == '\"') && ((ptr = luna_strchr_eos((sslot + 1), '\"')) != NULL)) ||
       (((*sslot) == '@') && ((ptr = luna_strchr_eos((sslot + 1), '@')) != NULL)) ||
       (((*sslot) == '#') && ((ptr = luna_strchr_eos((sslot + 1), '#')) != NULL)) ||
       (((*sslot) == '%') && ((ptr = luna_strchr_eos((sslot + 1), '%')) != NULL)) ||
       (((*sslot) == '^') && ((ptr = luna_strchr_eos((sslot + 1), '^')) != NULL)) ||
       (((*sslot) == '~') && ((ptr = luna_strchr_eos((sslot + 1), '~')) != NULL))) {
      /* string slotid */
      sslot++;
      (*ptr) = 0;
      ptr++;
      if (luna_label_to_slotid(sslot, &desc->slot) != 1)
         goto err;
   } else {
      /* numeric slotid */
      for (ptr = sslot; *ptr; ptr++) {
         if (!isdigit(*ptr))
            goto err;
      }
      desc->slot = atoi(sslot);
   }

   if (s0 != NULL) {
      LUNA_free(s0);
   }
   return 1;

err:
   if (s0 != NULL) {
      LUNACA3err(LUNACA3_F_INIT, LUNACA3_R_EENGINE);
      ERR_add_error_data2(2, "malformed slotid ", sslot);
      LUNA_free(s0);
   }
   return 0;
}

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "luna_label_to_slotid"

#define LUNA_MAX_LABEL (32)

/* search for token with label and return slot id; return 1 on success */
static int luna_label_to_slotid(const char *tokenlabel, CK_SLOT_ID *pslotid) {
   size_t slen = 0;
   CK_RV rv = CKR_OK;
   CK_ULONG ii = 0;
   CK_ULONG jj = 0;
   CK_ULONG kk = 0;
   CK_ULONG ulCount = 0;
   CK_ULONG ulCount2 = 0;
   CK_SLOT_ID *tab = NULL;

   CK_TOKEN_INFO infot;
   CK_BYTE norm1[LUNA_MAX_LABEL + 8];
   CK_BYTE norm2[LUNA_MAX_LABEL + 8];

   memset(norm1, 0, sizeof(norm1));
   memset(norm2, 0, sizeof(norm2));

   if ((slen = strlen(tokenlabel)) > LUNA_MAX_LABEL)
      goto err;
   if (slen < 1)
      goto err;

   rv = p11.std->C_GetSlotList(TRUE, NULL, &ulCount);
   if ((rv != CKR_OK) || (ulCount < 1))
      goto err;

   tab = (CK_SLOT_ID *)LUNA_malloc(sizeof(CK_SLOT_ID) * ulCount);
   if (tab == NULL)
      goto err;

   ulCount2 = ulCount;
   rv = p11.std->C_GetSlotList(TRUE, tab, &ulCount2);
   if ((rv != CKR_OK) || (ulCount2 != ulCount))
      goto err;

   memset(norm1, ' ', LUNA_MAX_LABEL);
   memcpy(norm1, tokenlabel, slen);
   norm1[LUNA_MAX_LABEL] = '\"';
   norm1[LUNA_MAX_LABEL + 1] = 0;
   for (ii = 0; ii < ulCount; ii++) {
      memset(&infot, 0, sizeof(infot));
      rv = p11.std->C_GetTokenInfo(tab[ii], &infot);
      if (rv != CKR_OK)
         goto err;

      memset(norm2, ' ', LUNA_MAX_LABEL);
      memcpy(norm2, infot.label, LUNA_MAX_LABEL);
      norm2[LUNA_MAX_LABEL] = '\"';
      norm2[LUNA_MAX_LABEL + 1] = 0;
      /* enforce label padded with space (not '\0') */
      for (jj = 0, kk = 0; jj < LUNA_MAX_LABEL; jj++) {
         if (kk || (norm2[jj] == '\0')) {
            kk = 1;
            norm2[jj] = ' ';
         }
      }

      if (memcmp(norm1, norm2, LUNA_MAX_LABEL) == 0) {
         (*pslotid) = tab[ii];
         LUNA_free(tab);
         return 1;
      }
   }

err:
   if (tab != NULL) {
      LUNA_free(tab);
   }

   LUNACA3err(LUNACA3_F_INIT, LUNACA3_R_EENGINE);
   ERR_add_error_data2(2, "token not found \"", tokenlabel);
   LUNA_ERRORLOG(LUNA_FUNC_NAME ": token not found");

   (*pslotid) = 0;
   return 0;
}

/* Buffer size large enough to receive formatted string */
#define LUNA_ATOI_BYTES (64)

/* Translate integer to string */
static char *luna_itoa(char *buffer, unsigned value) {
   snprintf(buffer, LUNA_ATOI_BYTES, "%08X", (unsigned)value);
   return buffer;
}

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "luna_ckatab_test_unique"

/* test attribute for match against any object on token */
static int luna_ckatab_test_unique(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE *tab) {
   CK_RV retCode = CKR_OK;
   CK_ULONG obj_count = 0;
   CK_OBJECT_HANDLE handles[2] = {0};
   char itoabuf[LUNA_ATOI_BYTES];

   memset(&handles, 0, sizeof(handles));
   memset(itoabuf, 0, sizeof(itoabuf));

   if (tab->ulValueLen < LUNA_MIN_LABEL) {
      LUNACA3err(LUNACA3_F_FINDOBJECT, LUNACA3_R_EPKCS11);
      ERR_add_error_data2(2, "ulValueLen=0x", luna_itoa(itoabuf, tab->ulValueLen));
      LUNA_ERRORLOGL(LUNA_FUNC_NAME ": ulValueLen", tab->ulValueLen);
      return 1;
   }

   retCode = p11.std->C_FindObjectsInit(hSession, tab, 1);
   if (retCode != CKR_OK) {
      LUNACA3err(LUNACA3_F_FINDOBJECT, LUNACA3_R_EPKCS11);
      ERR_add_error_data2(2, "C_FindObjectsInit=0x", luna_itoa(itoabuf, retCode));
      LUNA_ERRORLOGL(LUNA_FUNC_NAME ": C_FindObjectsInit", retCode);
      return 1;
   }

   obj_count = 0;
   retCode = p11.std->C_FindObjects(hSession, &handles[0], 2, &obj_count);
   if (retCode != CKR_OK) {
      LUNACA3err(LUNACA3_F_FINDOBJECT, LUNACA3_R_EPKCS11);
      ERR_add_error_data2(2, "C_FindObjects=0x", luna_itoa(itoabuf, retCode));
      LUNA_ERRORLOGL(LUNA_FUNC_NAME ": C_FindObjects", retCode);
      return 1;
   }

   if (obj_count != 0) {
      LUNACA3err(LUNACA3_F_FINDOBJECT, LUNACA3_R_EPKCS11);
      ERR_add_error_data2(2, "obj_count=0x", luna_itoa(itoabuf, obj_count));
      LUNA_ERRORLOGL(LUNA_FUNC_NAME ": obj_count", obj_count);
      return 1;
   }

   return 0;
}

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "luna_ckatab_pre_keygen"

/* test attribute list before key gen */
static int luna_ckatab_pre_keygen(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE *tab, CK_ULONG tabsize) {
   int have_attr = 0;
   CK_ULONG ii = 0;
   CK_ATTRIBUTE attr;

   memset(&attr, 0, sizeof(attr));
   have_attr = 0;
   for (ii = 0; ii < tabsize; ii++) {
      if (tab[ii].type == CKA_LABEL) {
         if (have_attr)
            return -1;
         attr = tab[ii];
         have_attr = 1;
      }
   }

   if (have_attr == 0)
      return -2;
   if (luna_ckatab_test_unique(hSession, &attr))
      return -3;

   memset(&attr, 0, sizeof(attr));
   have_attr = 0;
   for (ii = 0; ii < tabsize; ii++) {
      if (tab[ii].type == CKA_ID) {
         if (have_attr)
            return -4;
         attr = tab[ii];
         have_attr = 1;
      }
   }

   if (have_attr == 0)
      return -5;
   if (luna_ckatab_test_unique(hSession, &attr))
      return -6;

   return 0;
}

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "sautil_gets_passfile"

/* read password from file */
static int sautil_gets_passfile(const char *filename, char *password, unsigned maxlen) {
   FILE *fp = NULL;
   char *ptr = NULL;

   /* check input */
   if (filename == NULL)
      return 0;
   if (password == NULL)
      return 0;
   if ((fp = fopen(filename, "r")) == NULL)
      return 0;

   /* read file */
   fflush(stdout);
   ptr = fgets(password, maxlen, fp);
   fclose(fp);
   if (ptr == NULL)
      return 0;

   /* clean end of string */
   if ((ptr = strstr(password, "\r")) != NULL)
      ptr[0] = '\0';
   if ((ptr = strstr(password, "\n")) != NULL)
      ptr[0] = '\0';

   return (int)strlen(password);
}

/* function SHA1() not available in FIPS mode; use EVP */
static void luna_SHA1(const unsigned char *d, size_t n, unsigned char *md) {
   EVP_Digest(d, n, md, NULL, EVP_sha1(), NULL);
}

#ifdef OS_WIN32

/* luna_dso */
static LUNA_DSO_T luna_dso_load(const char *szDll) {
   HMODULE h = LoadLibrary(szDll);
   LUNA_DSO_T dso = (LUNA_DSO_T)h;
   return dso;
}

static LUNA_DSO_F luna_dso_bind_func(LUNA_DSO_T dso, const char *szFunction) {
   HMODULE h = (HMODULE)dso;
   LUNA_DSO_F f = (LUNA_DSO_F)GetProcAddress(h, szFunction);
   return f;
}

static void luna_dso_free(LUNA_DSO_T dso) {
   HMODULE h = (HMODULE)dso;
   (void)FreeLibrary(h);
}

#else /* OS_WIN32 */

/* luna_dso */
static LUNA_DSO_T luna_dso_load(const char *szDll) {
   void *h = dlopen(szDll, RTLD_NOW);
   LUNA_DSO_T dso = (LUNA_DSO_T)h;
   return dso;
}

static LUNA_DSO_F luna_dso_bind_func(LUNA_DSO_T dso, const char *szFunction) {
   void *h = (void *)dso;
   LUNA_DSO_F f = (LUNA_DSO_F)dlsym(h, szFunction);
   return f;
}

static void luna_dso_free(LUNA_DSO_T dso) {
   void *h = (void *)dso;
   (void)dlclose(h);
}

#endif /* OS_WIN32 */

#if defined(LUNA_OSSL_PQC)

#include <openssl/store.h>

/* delete ecdsa keypair */
static int op_delete_pqc_key_pair(CK_SLOT_ID slotid, char *keypair_fname) {
   int ret = -1;
   EVP_PKEY *dsa = NULL;
   CK_OBJECT_HANDLE handlePriv = CK_INVALID_HANDLE;
   CK_OBJECT_HANDLE handlePub = CK_INVALID_HANDLE;
   CK_SESSION_HANDLE session_handle = CK_INVALID_HANDLE;
   CK_RV retCode = CKR_GENERAL_ERROR;
   luna_context_t ctx = LUNA_CONTEXT_T_INIT;

   OSSL_STORE_CTX *osc = OSSL_STORE_open_ex(keypair_fname, NULL, NULL,
           NULL, NULL,
           NULL, NULL, NULL);
   if (osc == NULL) {
       fprintf(stderr, "ERROR: failed to open store \"%s\".\n", keypair_fname);
       goto err;
   }
   if (OSSL_STORE_expect(osc, OSSL_STORE_INFO_PKEY) == 0) {
       fprintf(stderr, "ERROR: failed to find a private key within the store.\n");
       goto err;
   }
   dsa = NULL;
   while ( (dsa == NULL) && (OSSL_STORE_eof(osc) == 0) ) {
       OSSL_STORE_INFO *info = OSSL_STORE_load(osc);
       int infotype = 0;
       const char *infostr = NULL;
       if (info == NULL)
           continue; /* skip */
       infotype = OSSL_STORE_INFO_get_type(info);
       infostr = OSSL_STORE_INFO_type_string(infotype);
       if (verbose)
           fprintf(stderr, "INFO: found store item type \"%s\"\n", infostr);
       switch (infotype) {
       case OSSL_STORE_INFO_PKEY:
           /* NOTE: calling the get1 variant works, the get0 variant fails */
           dsa = OSSL_STORE_INFO_get1_PKEY(info);
           break;
       default:
           break;
       }
       OSSL_STORE_INFO_free(info);
   }
   OSSL_STORE_close(osc);
   if (dsa == NULL) {
       fprintf(stderr, "ERROR: failed to get a private key from the store.\n");
       goto err;
   }

   if (set_application_id(app_id_hi, app_id_lo) != 0)
      goto err;
   if (open_session(slotid, &session_handle) != 0)
      goto err;

   /* if we're not logged in here, return an error */
   if (!loggedin(slotid)) {
      fprintf(stderr, "ERROR: the user is not logged in to the selected slot (%d).\n", (int)slotid);
      goto err;
   }

   /* fill luna_context_t */
   ctx.hSession = session_handle;
   ctx.flagInit = 1;

   /* find private key AND public key, to avoid partial deletion */
   handlePriv = luna_find_pqc_handle(&ctx, dsa, 1);
   if (handlePriv == CK_INVALID_HANDLE) {
      fprintf(stderr, "ERROR: find private failed.\n");
      goto err;
   }

   if (verbose)
       fprintf(stderr, "INFO: find private ok (handle %u).\n", (unsigned)handlePriv);

   handlePub = luna_find_pqc_handle(&ctx, dsa, 0);
   if (handlePub == CK_INVALID_HANDLE) {
      fprintf(stderr, "ERROR: find public failed.\n");
      goto err;
   }

   if (verbose)
       fprintf(stderr, "INFO: find public ok (handle %u).\n", (unsigned)handlePub);

   /* destroy private key AND public key */
   if ( (retCode = p11.std->C_DestroyObject(session_handle, handlePriv)) != CKR_OK ) {
      fprintf(stderr, "ERROR: delete private failed.\n");
      goto err;
   }

   if (verbose)
       fprintf(stderr, "INFO: delete private ok (handle %u).\n", (unsigned)handlePriv);

   if ( (retCode = p11.std->C_DestroyObject(session_handle, handlePub)) != CKR_OK ) {
      fprintf(stderr, "ERROR: delete public failed.\n");
      goto err;
   }

   if (verbose)
       fprintf(stderr, "INFO: delete public ok (handle %u).\n", (unsigned)handlePub);

   ret = 0;

err:
   if (dsa)
      EVP_PKEY_free(dsa);

   return ret;
}

// return 0 if ch is an acceptable utf8 character
static int luna_prov_test_utf8(unsigned char ch) {
    if (ch == '\0')
        return -1;
    if (ch < 0x20)
        return -1;
    return (ch <= 126) ? 0 : -1;
}

// return 0 if buf points to an acceptable utf8 character buffer of length 1 or more
static int luna_prov_test_utf8_buffer(const unsigned char *buf, unsigned buflen) {
    int beyondEndOfString = 0;
    int count = 0;
    unsigned i;
    for (i = 0; i < buflen; i++) {
        if (beyondEndOfString) {
            // must be padded with zero beyond end of string
            if (buf[i] != '\0') {
                return -1;
            }
        } else {
            if (buf[i] == '\0') {
                beyondEndOfString = 1;
            } else {
                if (luna_prov_test_utf8(buf[i])) {
                    return -1;
                }
                count++;
            }
        }
    }
    return (count >= 1 ? 0 : -1);
}

/* find pqc key (typically for deletion) */
/* version 1 (exactly 64-bytes as in LUNA_PQC_PRIVATEBLOB_BYTES_64, for pqc keys)
 *   reserved xx xx xx xx                   (4 bytes, big endian) oqs actual length
 *   priv  "sk112233445566778899aabbccddee" (30 bytes) label for private or secret key
 *   pub   "pk112233445566778899aabbccddee" (30 bytes) label for public key
 * version 2 (exactly 32-bytes as in LUNA_PQC_PRIVATEBLOB_BYTES_32, for ed keys)
 *   reserved xx xx xx xx                   (4 bytes, big endian) reserved
 *   magic    xx xx xx xx                   (4 bytes, big endian) magic value
 *   priv    "sk1234567890ABCDEabcde-_"     (24 bytes) label for private or secret key (no public key label)
 */
static CK_OBJECT_HANDLE luna_find_pqc_handle(luna_context_t *ctx, EVP_PKEY *dsa, int bPrivate) {
   CK_OBJECT_HANDLE rethandle = CK_INVALID_HANDLE;

   CK_BYTE_PTR pk = NULL;
   CK_ULONG pklen = 0;
   CK_BYTE_PTR sk = NULL;
   CK_ULONG sklen = 0;
   CK_ULONG rcCount = 0;
   CK_ULONG rcBase = 0;
   CK_OBJECT_HANDLE tmphandle = CK_INVALID_HANDLE;

   CK_ATTRIBUTE attrib[6];
   CK_ATTRIBUTE attribId[1];

   memset(attrib, 0, sizeof(attrib));
   memset(attribId, 0, sizeof(attribId));

   /* Define base attributes (common to public and private key) */
   rcBase = 0;

   /* decode private/public key blob */
   /* FIXME: the code below fails to iterate over multiple keys as in hybrid/composite */
   CK_BYTE blob[1024 * 8] = {0xFF,0xFF,0xFF,0xFF,0x00};
   size_t bloblen = sizeof(blob);
   if ( (EVP_PKEY_get_raw_private_key(dsa, blob, &bloblen) <= 0) || (bloblen < 32) ) {
       fprintf(stderr, "ERROR: EVP_PKEY_get_raw_private_key failed.\n");
       goto done;
   }

   if (bloblen < 64) {
       /* possibly version 2 */
       CK_BYTE headerV2[8] = {
               0, 0, 0, 0,
               0x80, 0xca, 0xfe, 0x82
       };
       if (memcmp(headerV2, blob, sizeof(headerV2)) != 0) {
           fprintf(stderr, "ERROR: expected header version 2.\n");
           goto done;
       }

       sk = &blob[8];
       sklen = strnlen(sk, 24);

       // pk is not stored; pk is derived from sk
       pk = &blob[8+24];
       pklen = sklen;
       memcpy(pk, sk, 24);
       if (sk[0] == 's' && sk[1] == 'k') {
           pk[0] = 'p';
           pk[1] = 'k';
       } else {
           fprintf(stderr, "ERROR: expected label starting with \"sk\".\n");
           goto done;
       }

       if ( (sklen != 24) || (pklen != 24) ) {
           fprintf(stderr, "ERROR: expected label length 24: sklen = %u, pklen = %u.\n",
                   (unsigned)sklen, (unsigned)pklen);
           goto done;
       }

   } else {

       /* possibly version 1 */
       CK_BYTE headerV1[4] = {0,0,0,0};
       if (memcmp(headerV1, blob, sizeof(headerV1)) != 0) {
           fprintf(stderr, "ERROR: expected header version 1.\n");
           goto done;
       }

       sk = &blob[4];
       sklen = strnlen(sk, 30);
       pk = &blob[4+30];
       pklen = strnlen(pk, 30);

       if ( (sklen != 30) || (pklen != 30) ) {
           fprintf(stderr, "ERROR: expected label length 30: sklen = %u, pklen = %u.\n",
                   (unsigned)sklen, (unsigned)pklen);
           goto done;
       }
   }

   /* test utf8, printable */
   if ( luna_prov_test_utf8_buffer(sk, sklen) ||
           luna_prov_test_utf8_buffer(pk, pklen) ) {
       fprintf(stderr, "ERROR: expected utf8, printable label.\n");
       goto done;
   }

   /* reset attribute count before gathering attributes */
   rcCount = rcBase;

   /* gather cka_label (public) */
   attrib[rcCount].type = CKA_LABEL;
   attrib[rcCount].pValue = pk;
   attrib[rcCount].ulValueLen = pklen;
   rcCount++;

#if defined(LUNA_PQC_FIND_BY_ANY_ATTRIBUTE)
   /* FIXME: the PQC FM/SHIM can find object by label, but, not if the template includes some other attribute */
   /* gather cka_class */
   ulClass = CKO_PUBLIC_KEY;
   attrib[rcCount].type = CKA_CLASS;
   attrib[rcCount].pValue = &ulClass;
   attrib[rcCount].ulValueLen = sizeof(ulClass);
   rcCount++;
#endif

   /* Find public key */
   if (!luna_find_object_ex1(ctx, attrib, rcCount, &tmphandle, 1)) {
      fprintf(stderr, "ERROR: luna_find_object_ex1 (public).\n");
      goto done;
   }

   /* Find private key using CKA_ID of public key */
   if (bPrivate) {

#if defined(LUNA_PQC_GET_CKA_ID)
      attribId[0].type = CKA_ID;
      attribId[0].pValue = NULL_PTR;
      attribId[0].ulValueLen = 0;
      if (!luna_attribute_malloc(ctx, tmphandle, attribId) || (attribId[0].ulValueLen != 14)) {
         fprintf(stderr, "ERROR: luna_attribute_malloc (CKA_ID, %u).\n", (unsigned)attribId[0].ulValueLen);
         goto done;
      }
#endif
      /* reset attribute count before gathering attributes */
      rcCount = rcBase;

      /* gather cka_label (private) */
      attrib[rcCount].type = CKA_LABEL;
      attrib[rcCount].pValue = sk;
      attrib[rcCount].ulValueLen = sklen;
      rcCount++;

#if defined(LUNA_PQC_FIND_BY_ANY_ATTRIBUTE)
      /* gather cka_class */
      ulClass = CKO_PRIVATE_KEY;
      attrib[rcCount].type = CKA_CLASS;
      attrib[rcCount].pValue = &ulClass;
      attrib[rcCount].ulValueLen = sizeof(ulClass);
      rcCount++;
#endif

#if defined(LUNA_PQC_GET_CKA_ID)
      /* gather cka_id */
      attrib[rcCount] = attribId[0]; /* copy struct */
      rcCount++;
#endif

      /* Find private key; must be unique */
      if (!luna_find_object_ex1(ctx, attrib, rcCount, &tmphandle, 1)) {
         fprintf(stderr, "ERROR: luna_find_object_ex1 (private).\n");
         goto done;
      }
   }

   /* on success, set 'rethandle' */
   rethandle = tmphandle;

done:
   /* undo luna_attribute_malloc */
   luna_attribute_free(attribId);

   return rethandle;
}

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "sautil_provider_load"

static OSSL_PROVIDER *fips = NULL;
static OSSL_PROVIDER *dflt = NULL; /* default provider */
static OSSL_PROVIDER *base = NULL;
static OSSL_LIB_CTX *libctx = NULL;

/* load openssl3 provider */
static const char *sautil_provider_load(OSSL_PROVIDER **prov) {
   OSSL_PROVIDER *luna = NULL;

   /* load multiple providers, lunaprov first */
   luna = OSSL_PROVIDER_load(NULL, "lunaprov");
   if (luna == NULL) {
      return "Failed to load lunaprov provider";
   }

#if 0
   /* load fips provider */
   if (strstr(local_param.providers, "fips") != NULL) {
      fips = OSSL_PROVIDER_load(NULL, "fips");
      if (fips == NULL) {
         OSSL_PROVIDER_unload(luna);
         return "Failed to load fips provider";
      }
   }
#endif

   /* load default provider */
   if (1) { //strstr(local_param.providers, "default") != NULL) {
      dflt = OSSL_PROVIDER_load(NULL, "default");
      if (dflt == NULL) {
         OSSL_PROVIDER_unload(luna);
         return "Failed to load default provider";
      }
   }

#if 0
   /* load base provider */
   if (strstr(local_param.providers, "base") != NULL) {
      base = OSSL_PROVIDER_load(NULL, "base");
      if (base == NULL) {
         OSSL_PROVIDER_unload(luna);
         return "Failed to load base provider";
      }
   }
#endif

   *prov = luna;
   libctx = OSSL_LIB_CTX_new();
   return NULL; /* success */
}

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "sautil_provider_unload"

/* unload openssl3 provider */
static const char *sautil_provider_unload(OSSL_PROVIDER *prov) {
   if (prov)
      OSSL_PROVIDER_unload(prov);
#if 0
   if (fips)
      OSSL_PROVIDER_unload(fips);
#endif
   if (dflt)
      OSSL_PROVIDER_unload(dflt);
#if 0
   if (base)
      OSSL_PROVIDER_unload(base);
#endif
   fips = dflt = base = NULL;
   return NULL; /* success */
}

#endif /* LUNA_OSSL_PQC */

static char *sautil_strncpy(char *dest, const char *src, size_t n) {
    if (dest == NULL || n < 1)
        return NULL;
    dest[0] = 0;
    if (src != NULL)
        strncpy(dest, src, (n - 1));
    dest[n - 1] = 0;
    return dest;
}

/*****************************************************************************/

/* For Code Warrior */
#if 0
extern "C" {
#endif

/* Support C or C++ compiler in the field */
#ifdef __cplusplus
}
#endif

/* FIXME: bad style */
#include "e_gem_compat.c"

/* eof */
