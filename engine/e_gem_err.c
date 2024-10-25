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

#include <stdio.h>
#include <openssl/err.h>

#include "e_gem_err.h"

/* Support C or C++ compiler in the field */
#ifdef __cplusplus
extern "C" {
#endif

/*****************************************************************************/

/* BEGIN ERROR CODES */
#ifndef OPENSSL_NO_ERR

static ERR_STRING_DATA LUNACA3_str_functs[] = {
    {ERR_PACK(0, LUNACA3_F_CMDARG, 0), "LUNA_CMDARG"},
    {ERR_PACK(0, LUNACA3_F_CTRL, 0), "LUNA_CTRL"},
    {ERR_PACK(0, LUNACA3_F_DSA_SIGN, 0), "LUNA_DSA_SIGN"},
    {ERR_PACK(0, LUNACA3_F_DSA_VERIFY, 0), "LUNA_DSA_VERIFY"},
    {ERR_PACK(0, LUNACA3_F_FINISH, 0), "LUNA_FINISH"},
    {ERR_PACK(0, LUNACA3_F_INIT, 0), "LUNA_INIT"},
    {ERR_PACK(0, LUNACA3_F_RSA_GENERATE_KEY, 0), "LUNA_RSA_GENERATE_KEY"},
    {ERR_PACK(0, LUNACA3_F_RSA_PRIVATE_DECRYPT, 0), "LUNA_RSA_PRIVATE_DECRYPT"},
    {ERR_PACK(0, LUNACA3_F_RSA_PRIVATE_ENCRYPT, 0), "LUNA_RSA_PRIVATE_ENCRYPT"},
    {ERR_PACK(0, LUNACA3_F_RSA_PUBLIC_DECRYPT, 0), "LUNA_RSA_PUBLIC_DECRYPT"},
    {ERR_PACK(0, LUNACA3_F_RSA_PUBLIC_ENCRYPT, 0), "LUNA_RSA_PUBLIC_ENCRYPT"},
    {ERR_PACK(0, LUNACA3_F_GENERATE_RANDOM, 0), "LUNA_F_GENERATE_RANDOM"},
    {ERR_PACK(0, LUNACA3_F_DIGEST_INIT, 0), "LUNACA3_F_DIGEST_INIT"},
    {ERR_PACK(0, LUNACA3_F_DIGEST_UPDATE, 0), "LUNACA3_F_DIGEST_UPDATE"},
    {ERR_PACK(0, LUNACA3_F_DIGEST_FINAL, 0), "LUNACA3_F_DIGEST_FINAL"},
    {ERR_PACK(0, LUNACA3_F_CIPHER_INIT, 0), "LUNACA3_F_CIPHER_INIT"},
    {ERR_PACK(0, LUNACA3_F_CIPHER_UPDATE, 0), "LUNACA3_F_CIPHER_UPDATE"},
    {ERR_PACK(0, LUNACA3_F_CIPHER_FINAL, 0), "LUNACA3_F_CIPHER_FINAL"},
    {ERR_PACK(0, LUNACA3_F_ENGINE, 0), "engine function"},
    {ERR_PACK(0, LUNACA3_F_PKCS11, 0), "PKCS#11 function"},
    {ERR_PACK(0, LUNACA3_F_FIND_RSA, 0), "LUNACA3_F_FIND_RSA"},
    {ERR_PACK(0, LUNACA3_F_FIND_DSA, 0), "LUNACA3_F_FIND_DSA"},
    {ERR_PACK(0, LUNACA3_F_LOADKEY, 0), "LUNACA3_F_LOADKEY"},
    {ERR_PACK(0, LUNACA3_F_OPENSESSION, 0), "LUNACA3_F_OPENSESSION"},
    {ERR_PACK(0, LUNACA3_F_CLOSESESSION, 0), "LUNACA3_F_CLOSESESSION"},
    {ERR_PACK(0, LUNACA3_F_LOGIN, 0), "LUNACA3_F_LOGIN"},
    {ERR_PACK(0, LUNACA3_F_LOGOUT, 0), "LUNACA3_F_LOGOUT"},
    {ERR_PACK(0, LUNACA3_F_SETAPPID, 0), "LUNACA3_F_SETAPPID"},
    {ERR_PACK(0, LUNACA3_F_GETATTRVALUE, 0), "LUNACA3_F_GETATTRVALUE"},
    {ERR_PACK(0, LUNACA3_F_FINDOBJECT, 0), "LUNACA3_F_FINDOBJECT"},
    {ERR_PACK(0, LUNACA3_F_FIND_ECDSA, 0), "LUNACA3_F_FIND_ECDSA"},
    {ERR_PACK(0, LUNACA3_F_ECDSA_SIGN, 0), "LUNACA3_F_ECDSA_SIGN"},
    {ERR_PACK(0, LUNACA3_F_ECDSA_VERIFY, 0), "LUNACA3_F_ECDSA_VERIFY"},
    {ERR_PACK(0, LUNACA3_F_RSA_KEYGEN, 0), "LUNACA3_F_RSA_KEYGEN"},
    {ERR_PACK(0, LUNACA3_F_DSA_KEYGEN, 0), "LUNACA3_F_DSA_KEYGEN"},
    {ERR_PACK(0, LUNACA3_F_RSA_SIGN, 0), "LUNACA3_F_RSA_SIGN"},
    {ERR_PACK(0, LUNACA3_F_RSA_VERIFY, 0), "LUNACA3_F_RSA_VERIFY"},
    {ERR_PACK(0, LUNACA3_F_GET_HA_STATE, 0), "LUNACA3_F_GET_HA_STATE"},
    {ERR_PACK(0, LUNACA3_F_EC_GENERATE_KEY, 0), "LUNACA3_F_EC_GENERATE_KEY"},
    {ERR_PACK(0, LUNACA3_F_EC_COMPUTE_KEY, 0), "LUNACA3_F_EC_COMPUTE_KEY"},
    {0, NULL}};

static ERR_STRING_DATA LUNACA3_str_reasons[] = {{LUNACA3_R_EZERO, "no error"},
                                                {LUNACA3_R_ENOFILE, "no such file"},
                                                {LUNACA3_R_ENOMEM, "out of memory"},
                                                {LUNACA3_R_ENODEV, "no such device"},
                                                {LUNACA3_R_EINVAL, "invalid argument"},
                                                {LUNACA3_R_ENOSYS, "not implemented"},
                                                {LUNACA3_R_EENGINE, "engine error"},
                                                {LUNACA3_R_EPKCS11, "PKCS#11 error"},
                                                {LUNACA3_R_EPADDING, "invalid padding"},
                                                {LUNACA3_R_EFINDKEY, "no such key"},
                                                {LUNACA3_R_EGETATTR, "no such attribute"},
                                                {LUNACA3_R_DUPLICATE, "duplicate object"},
                                                {LUNACA3_R_EINKEY, "invalid key structure"},
                                                {LUNACA3_R_EINVHASTATUSVER, "invalid ha status version"},
                                                {0, NULL}};

#endif

#ifdef LUNACA3_LIB_NAME
static ERR_STRING_DATA LUNACA3_lib_name[] = {{0, LUNACA3_LIB_NAME}, {0, NULL}};
#endif

static int LUNACA3_lib_error_code = 0;
static int LUNACA3_error_init = 1;

static void ERR_load_LUNACA3_strings(void) {
   if (LUNACA3_lib_error_code == 0) {
      LUNACA3_lib_error_code = ERR_get_next_error_library();
   }

   if (LUNACA3_error_init) {
      LUNACA3_error_init = 0;
#ifndef OPENSSL_NO_ERR
      ERR_load_strings(LUNACA3_lib_error_code, LUNACA3_str_functs);
      ERR_load_strings(LUNACA3_lib_error_code, LUNACA3_str_reasons);
#endif

#ifdef LUNACA3_LIB_NAME
      LUNACA3_lib_name->error = ERR_PACK(LUNACA3_lib_error_code, 0, 0);
      ERR_load_strings(0, LUNACA3_lib_name);
#endif
   }
}

static void ERR_unload_LUNACA3_strings(void) {
   if (LUNACA3_error_init == 0) {
#ifndef OPENSSL_NO_ERR
      ERR_unload_strings(LUNACA3_lib_error_code, LUNACA3_str_functs);
      ERR_unload_strings(LUNACA3_lib_error_code, LUNACA3_str_reasons);
#endif

#ifdef LUNACA3_LIB_NAME
      ERR_unload_strings(0, LUNACA3_lib_name);
#endif
      LUNACA3_error_init = 1;
   }
}

static void ERR_LUNACA3_error(int function, int reason, char *file, int line) {
   if (LUNACA3_lib_error_code == 0) {
      LUNACA3_lib_error_code = ERR_get_next_error_library();
   }
   ERR_PUT_error(LUNACA3_lib_error_code, function, reason, file, line);
}

/*****************************************************************************/

/* Support C or C++ compiler in the field */
#ifdef __cplusplus
}
#endif
