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

#ifndef __H_ENGINEPERF_H
#define __H_ENGINEPERF_H

/* system headers */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#ifdef OS_WIN32
#include <windows.h>
#include <process.h>
typedef unsigned long LUNA_PID_T;
typedef DWORD LUNA_TIME_UNIT_T;
#define LUNA_GETPID() ((LUNA_PID_T)_getpid())
#define LUNA_OSSL_WINDOWS (1)
#else /* OS_WIN32 */
#include <sys/time.h>
#include <unistd.h>
#include <pthread.h>
typedef unsigned long LUNA_PID_T;
typedef unsigned long LUNA_TIME_UNIT_T;
#define LUNA_GETPID() ((LUNA_PID_T)getpid())
#endif /* OS_WIN32 */

/* headers (openssl) */
#include <openssl/opensslconf.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
/* internal: #include <openssl/dso.h> */
#include <openssl/engine.h>

#ifndef OPENSSL_NO_RSA
#include <openssl/rsa.h>
#endif /* OPENSSL_NO_RSA */
#ifndef OPENSSL_NO_DSA
#include <openssl/dsa.h>
#endif /* OPENSSL_NO_DSA */

/* detect ecdsa (minimum version is 0.9.8l or fips 1.2.3) */
#if (1) && (OPENSSL_VERSION_NUMBER >= 0x00908060L) && !defined(OPENSSL_NO_ECDSA) && !defined(OPENSSL_NO_EC)
#define LUNA_OSSL_ECDSA (1)
#endif /* OPENSSL_NO_ECDSA... */

/* detect openssl3 */
#if (1) && (OPENSSL_VERSION_NUMBER >= 0x30000000)
#define LUNA_OSSL3 (1)
#endif

/* detect OPENSSL_cleanup (1.1.0 and up) */
#if (1) && (OPENSSL_VERSION_NUMBER >= 0x10100000L)
#define LUNA_OSSL_CLEANUP (1)
#endif

#if defined(LUNA_OSSL_ECDSA)
/* internal: #include <openssl/ec_lcl.h> */
/* internal: #include <openssl/ecs_locl.h> */
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#endif /* LUNA_OSSL_ECDSA */

#if defined(LUNA_OSSL3)
#include <openssl/provider.h>
#endif

/* Support C or C++ compiler in the field */
#ifdef __cplusplus
extern "C" {
#endif

/*****************************************************************************/

/* Macros */
#define LUNA_DIM(a__) (sizeof(a__) / sizeof((a__)[0]))
#define LUNA_MIN(a__, b__) (((a__) < (b__)) ? (a__) : (b__))
#define LUNA_MAX(a__, b__) (((a__) < (b__)) ? (b__) : (a__))
#define LUNA_DIFF(a__, b__) (((a__) < (b__)) ? ((b__) - (a__)) : ((a__) - (b__)))

//#define DEBUG 1
#if defined(DEBUG)
#define IF_DEBUG(_code) \
   do {                 \
      _code;            \
   } while (0)
#else
#define IF_DEBUG(_code) \
   do {                 \
   } while (0)
#endif

/*****************************************************************************/

/* Support C or C++ compiler in the field */
#ifdef __cplusplus
}
#endif

#endif /* __H_ENGINEPERF_H */
