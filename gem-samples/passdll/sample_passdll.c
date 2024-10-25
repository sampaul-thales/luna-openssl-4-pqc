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

/* WARNING:  This is an example of the passdll mechanism and is not meant to be used as a secure implementation. */

/* purpose: header files in proper order */
#include <stdio.h>
#include <string.h>
#include "e_gem.h"

/* purpose: debug print */
#define MY_PRINTF(_x) printf _x

/* purpose: support C or C++ compiler in the field */
#ifdef __cplusplus
extern "C" {
#endif
#if 0
}
#endif

/* purpose: define error codes for my sample passdll */
typedef enum passdll_errno_s {
   PASSDLL_ERR_OK = 0,
   PASSDLL_ERR_UNKNOWN,
   PASSDLL_ERR_POINTER,
   PASSDLL_ERR_VERSION,
   PASSDLL_ERR_SIZEOF,
   PASSDLL_ERR_SLOTID,
   PASSDLL_ERR_LABEL,
   PASSDLL_ERR_BUFFER_TOO_SMALL,
   PASSDLL_ERR_USER_TYPE
} passdll_errno_t;

/* purpose: query highest version supported */
/* return: positive integer on success; otherwise, zero */
int luna_passdll_version(void *pnull) {
   /* check input values */
   if (pnull != NULL)
      return 0;

   /* return: positive integer on success */
   return LUNA_PASSDLL_VERSION_1;
}

/* WARNING:  This is an example of the passdll mechanism and is not meant to be used as a secure implementation. */

/* purpose: define expected slotid / label */
#define MY_SLOTID (1)    /* FIXME: hardcoded */
#define MY_LABEL "steve" /* FIXME: hardcoded */
#define MY_XOR_PIN                                                                       \
   {                                                                                     \
      0x10 ^ 'u', 0x58 ^ 's', 0x6b ^ 'e', 0x86 ^ 'r', 0xc1 ^ 'p', 0x6d ^ 'i', 0x77 ^ 'n' \
   } /* FIXME: Change to match user PIN and MY_XOR_PAD */
#define MY_XOR_PAD                             \
   {                                           \
      0x10, 0x58, 0x6b, 0x86, 0xc1, 0x6d, 0x77 \
   }                          /* FIXME: Change to different random byte values with same length as MY_XOR_PIN */
#define MY_PIN_LEN 7          /* FIXME: Change to match length of MY_XOR_PIN */
#define MY_USER_TYPE_1 CKU_USER
#define MY_USER_TYPE_2 CKU_LIMITED_USER

/* WARNING:  This is an example of the passdll mechanism and is not meant to be used as a secure implementation. */

static void my_xor_pad(unsigned char *pad) {
   int i;
   unsigned char xor_pad[] = MY_XOR_PAD;
   for (i = 0; i < MY_PIN_LEN; i++) {
      pad[i] = xor_pad[i];
   }
}

/* purpose: get the passphrase (hardcoded) */
/* return: 0 on success; otherwise, error code */
static int my_passphrase_hardcoded(luna_passdll_t *pobj) {
   int ii;

   /* check input values */
   if (pobj == NULL)
      return PASSDLL_ERR_POINTER;
   if (pobj->version != LUNA_PASSDLL_VERSION_1)
      return PASSDLL_ERR_VERSION;
   if (pobj->size != sizeof(*pobj))
      return PASSDLL_ERR_SIZEOF;

   /* check usertype */
   if ( (pobj->user_type != MY_USER_TYPE_1) && (pobj->user_type != MY_USER_TYPE_2) )
      return PASSDLL_ERR_USER_TYPE;

   /* check slotid or slotlabel */
   if (pobj->have_slotid) {
      if (pobj->slotid != MY_SLOTID)
         return PASSDLL_ERR_SLOTID;
      MY_PRINTF(("Retrieving passphrase for slot id 0x%X... ", (unsigned)pobj->slotid));
   } else {
      if (strcmp(pobj->label, MY_LABEL))
         return PASSDLL_ERR_LABEL;
      MY_PRINTF(("Retrieving passphrase for slot label \"%s\"... ", (char *)pobj->label));
   }

   /* store pin, pin_length */
   if (1) {
      unsigned char pin[256] = MY_XOR_PIN;
      unsigned char pad[256];
      int pinlen = (int)MY_PIN_LEN;
      my_xor_pad(pad);
      if (pinlen > sizeof(pobj->pin))
         return PASSDLL_ERR_BUFFER_TOO_SMALL;
      for (ii = 0; ii < pinlen; ii++) {
         pobj->pin[ii] = (char)pad[ii] ^ pin[ii];
      }
      pobj->pin[ii] = 0;
      pobj->pin_length = pinlen;
   }

   /* return: 0 on success */
   MY_PRINTF(("success. \n"));
   return 0;
}

/* purpose: get the passphrase (wrapper function) */
/* return: 0 on success; otherwise, error code */
int luna_passdll_passphrase(luna_passdll_t *pobj) { return my_passphrase_hardcoded(pobj); }

/* purpose: support C or C++ compiler in the field */
#if 0
extern "C" {
#endif
#ifdef __cplusplus
}
#endif

#if defined(_WIN32) || defined(OS_WIN32)
#include <windows.h>
/* purpose: standard dll entry function */
BOOL APIENTRY DllMain(HANDLE hModule, DWORD dwReason, LPVOID lpReserved) {
   hModule = hModule;
   dwReason = dwReason;
   lpReserved = lpReserved;
   return TRUE;
}
#endif
