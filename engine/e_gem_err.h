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

#ifndef header_e_lunaca3_err_h
#define header_e_lunaca3_err_h

/* Support C or C++ compiler in the field */
#ifdef __cplusplus
extern "C" {
#endif

static void ERR_load_LUNACA3_strings(void);
static void ERR_unload_LUNACA3_strings(void);
static void ERR_LUNACA3_error(int function, int reason, char *file, int line);
#define LUNACA3err(f, r) ERR_LUNACA3_error((f), (r), __FILE__, __LINE__)

/* Function codes for engine entry points, engine internal functions */
#define LUNACA3_F_ZERO 100
#define LUNACA3_F_DSA_SIGN 103
#define LUNACA3_F_DSA_VERIFY 104
#define LUNACA3_F_CMDARG 105
#define LUNACA3_F_CTRL 106
#define LUNACA3_F_INIT 107
#define LUNACA3_F_FINISH 108
#define LUNACA3_F_RSA_GENERATE_KEY 113
#define LUNACA3_F_RSA_PRIVATE_DECRYPT 114
#define LUNACA3_F_RSA_PRIVATE_ENCRYPT 115
#define LUNACA3_F_RSA_PUBLIC_DECRYPT 116
#define LUNACA3_F_RSA_PUBLIC_ENCRYPT 117
#define LUNACA3_F_GENERATE_RANDOM 120
#define LUNACA3_F_DIGEST_INIT 122
#define LUNACA3_F_DIGEST_UPDATE 123
#define LUNACA3_F_DIGEST_FINAL 124
#define LUNACA3_F_CIPHER_INIT 125
#define LUNACA3_F_CIPHER_UPDATE 126
#define LUNACA3_F_CIPHER_FINAL 127
#define LUNACA3_F_ENGINE 140
#define LUNACA3_F_PKCS11 141
#define LUNACA3_F_FIND_RSA 142
#define LUNACA3_F_FIND_DSA 143

#define LUNACA3_F_LOADKEY 144
#define LUNACA3_F_OPENSESSION 145
#define LUNACA3_F_CLOSESESSION 146
#define LUNACA3_F_LOGIN 147
#define LUNACA3_F_LOGOUT 148
#define LUNACA3_F_SETAPPID 149
#define LUNACA3_F_GETATTRVALUE 150
#define LUNACA3_F_FINDOBJECT 151
#define LUNACA3_F_FIND_ECDSA 152
#define LUNACA3_F_ECDSA_SIGN 153
#define LUNACA3_F_ECDSA_VERIFY 154
#define LUNACA3_F_RSA_KEYGEN 155
#define LUNACA3_F_DSA_KEYGEN 156
#define LUNACA3_F_RSA_SIGN 157
#define LUNACA3_F_RSA_VERIFY 158
#define LUNACA3_F_GET_HA_STATE 159

#define LUNACA3_F_EC_GENERATE_KEY 160
#define LUNACA3_F_EC_COMPUTE_KEY 161

/* Reason codes */
#define LUNACA3_R_EZERO 100           /* No error */
#define LUNACA3_R_ENOFILE 102         /* No such file/directory */
#define LUNACA3_R_ENOMEM 112          /* Out of memory */
#define LUNACA3_R_ENODEV 119          /* No such device */
#define LUNACA3_R_EINVAL 122          /* Invalid argument */
#define LUNACA3_R_ENOSYS 138          /* Function not implemented */
#define LUNACA3_R_EENGINE 140         /* Internal engine error */
#define LUNACA3_R_EPKCS11 141         /* External PKCS#11 error*/
#define LUNACA3_R_EPADDING 142        /* Padding error */
#define LUNACA3_R_EFINDKEY 143        /* Findkey error */
#define LUNACA3_R_EGETATTR 144        /* Get attribute error */
#define LUNACA3_R_DUPLICATE 145       /* Duplicate objects */
#define LUNACA3_R_EINKEY 146          /* invalid key structure */
#define LUNACA3_R_EINVHASTATUSVER 147 /* invalid ha status version */

/* Support C or C++ compiler in the field */
#ifdef __cplusplus
}
#endif

#endif
