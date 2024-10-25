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

#ifndef INC_PQCDEFS_H
#define INC_PQCDEFS_H

/* for uint64_t */
#include <stdint.h>

// PQC KE FM Commands
#define PQC_CMD_GEN_KEY_PAIR               1
#define PQC_CMD_ENCAP_AND_DERIVE_KEY       2
#define PQC_CMD_DECAP_AND_DERIVE_KEY       3
#define PQC_CMD_REMOVE_KEY                 4
#define PQC_CMD_WRAPKEY                    5
#define PQC_CMD_HBSS_SIGN                  6
#define PQC_CMD_HBSS_VERIFY                7
#define PQC_CMD_UNWRAPKEY                  8
#define PQC_CMD_INIT                       9
#define PQC_CMD_FINI                       10
#define PQC_CMD_OPEN_SESSION               11
#define PQC_CMD_CLOSE_SESSION              12

#define MAX_SIZE_SERIALNUM 32
#define MAX_KYBER_CIPHERTEXT 1568
#define MAX_CIPHERTEXT MAX_KYBER_CIPHERTEXT

#define PQC_KEYFILE_VERSION 4

/*************************************************************
**************************************************************
    PKCS#11 Customer Definitions
**************************************************************
**************************************************************/

typedef CK_ULONG            CK_KEY_PARAMS;
typedef uint64_t            CK_REMAINING_SIGS;

/* HSS */
typedef CK_ULONG                   CK_HSS_LEVELS;
typedef CK_ULONG                   CK_LMS_TYPE;
typedef CK_ULONG                   CK_LMOTS_TYPE;
typedef CK_ULONG                   CK_AUX_DATA_LEN;

typedef CK_ULONG                   CK_XMSS_OID;
typedef CK_ULONG                   CK_XMSSMT_OID;
typedef CK_ULONG                   CK_XMSSMT_DIST_LEVEL;
typedef uint64_t                   CK_XMSSMT_DIST_TREE;
typedef CK_ULONG                   CK_XMSSMT_DIST_LEVELS;
typedef uint64_t                   CK_XMSSMT_DIST_INDEX;

typedef struct CK_KEM_ENCAP_PARAMS {
   CK_BYTE_PTR pPublicKey;
   CK_ULONG ulPubKeyLen;
   CK_KEY_PARAMS params;
   CK_KDF_PRF_TYPE kdfType;
   CK_BYTE_PTR pInfo;
   CK_ULONG ulInfoLen;
   CK_BYTE_PTR pCiphertext;
   CK_ULONG_PTR pulCiphertextLen;
} CK_KEM_ENCAP_PARAMS;

typedef CK_KEM_ENCAP_PARAMS CK_PTR CK_KEM_ENCAP_PARAMS_PTR;

typedef struct CK_KEM_DECAP_PARAMS {
   CK_KDF_PRF_TYPE kdfType;
   CK_BYTE_PTR pInfo;
   CK_ULONG ulInfoLen;
   CK_BYTE_PTR pCiphertext;
   CK_ULONG ulCiphertextLen;
} CK_KEM_DECAP_PARAMS;

typedef CK_KEM_DECAP_PARAMS CK_PTR CK_KEM_DECAP_PARAMS_PTR;

typedef CK_KEM_ENCAP_PARAMS CK_KYBER_ENCAP_PARAMS;
typedef CK_KEM_DECAP_PARAMS CK_KYBER_DECAP_PARAMS;

#ifndef CKD_SHA224_KDF_SP800
#define CKD_SHA224_KDF_SP800     0x0000000FUL
#endif
#ifndef CKD_SHA256_KDF_SP800
#define CKD_SHA256_KDF_SP800     0x00000010UL
#endif
#ifndef CKD_SHA384_KDF_SP800
#define CKD_SHA384_KDF_SP800     0x00000011UL
#endif
#ifndef CKD_SHA512_KDF_SP800
#define CKD_SHA512_KDF_SP800     0x00000012UL
#endif
#ifndef CKD_SHA3_224_KDF_SP800
#define CKD_SHA3_224_KDF_SP800   0x00000013UL
#endif
#ifndef CKD_SHA3_256_KDF_SP800
#define CKD_SHA3_256_KDF_SP800   0x00000014UL
#endif
#ifndef CKD_SHA3_384_KDF_SP800
#define CKD_SHA3_384_KDF_SP800   0x00000015UL
#endif
#ifndef CKD_SHA3_512_KDF_SP800
#define CKD_SHA3_512_KDF_SP800   0x00000016UL
#endif

#define FM_USAGE_ATTR_ENCRYPT        0x01 // mask byte 0
#define FM_USAGE_ATTR_DECRYPT        0x02
#define FM_USAGE_ATTR_SIGN           0x04
#define FM_USAGE_ATTR_VERIFY         0x08
#define FM_USAGE_ATTR_WRAP           0x10
#define FM_USAGE_ATTR_UNWRAP         0x20
#define FM_USAGE_ATTR_DERIVE         0x40
#define FM_USAGE_ATTR_PRIVATE        0x80
#define FM_USAGE_ATTR_MODIFIABLE     0x01 // mask byte 1
#define FM_USAGE_ATTR_EXTRACTABLE    0x02
#define FM_USAGE_ATTR_TOKEN          0x04


// Variant Definitions

#define CKP_KYBER_512                0x01
#define CKP_KYBER_768                0x02
#define CKP_KYBER_1024               0x03

#define CKP_ML_KEM_512               0x01
#define CKP_ML_KEM_768               0x02
#define CKP_ML_KEM_1024              0x03
#define CKP_ML_KEM_512_IPD           0x04
#define CKP_ML_KEM_768_IPD           0x05
#define CKP_ML_KEM_1024_IPD          0x06

#define CKP_DILITHIUM_2              0x01
#define CKP_DILITHIUM_3              0x02
#define CKP_DILITHIUM_5              0x03

#define CKP_ML_DSA_44                0x01
#define CKP_ML_DSA_65                0x02
#define CKP_ML_DSA_87                0x03
#define CKP_ML_DSA_44_IPD            0x04
#define CKP_ML_DSA_65_IPD            0x05
#define CKP_ML_DSA_87_IPD            0x06

#define CKP_XMSS_SHA2_10_256         0x01
#define CKP_XMSS_SHA2_16_256         0x02
#define CKP_XMSS_SHA2_20_256         0x03

#define CKP_XMSSMT_SHA2_20_2_256     0x01
#define CKP_XMSSMT_SHA2_20_4_256     0x02
#define CKP_XMSSMT_SHA2_40_2_256     0x03
#define CKP_XMSSMT_SHA2_40_4_256     0x04
#define CKP_XMSSMT_SHA2_40_8_256     0x05
#define CKP_XMSSMT_SHA2_60_3_256     0x06
#define CKP_XMSSMT_SHA2_60_6_256     0x07
#define CKP_XMSSMT_SHA2_60_12_256    0x08

#define CKP_FALCON_512               0x01
#define CKP_FALCON_1024              0x02

#define CKP_SPHINCS_SHA256_128F_SIMPLE 0x0E
#define CKP_SPHINCS_SHA256_128S_SIMPLE 0x10
#define CKP_SPHINCS_SHA256_192F_SIMPLE 0x12
#define CKP_SPHINCS_SHA256_192S_SIMPLE 0x14
#define CKP_SPHINCS_SHA256_256F_SIMPLE 0x16
#define CKP_SPHINCS_SHA256_256S_SIMPLE 0x18
#define CKP_SPHINCS_SHAKE256_128F_SIMPLE 0x1A
#define CKP_SPHINCS_SHAKE256_128S_SIMPLE 0x1C
#define CKP_SPHINCS_SHAKE256_192F_SIMPLE 0x1E
#define CKP_SPHINCS_SHAKE256_192S_SIMPLE 0x20
#define CKP_SPHINCS_SHAKE256_256F_SIMPLE 0x22
#define CKP_SPHINCS_SHAKE256_256S_SIMPLE 0x24

// PQC Key Types
#define CKK_CUSTOMER_DEFINED         0xC0000000

#define CKK_KYBER                    (CKK_CUSTOMER_DEFINED + 0x01)
#define CKK_DILITHIUM                (CKK_CUSTOMER_DEFINED + 0x02)
#define CKK_XMSS                     (CKK_CUSTOMER_DEFINED + 0x03)
#define CKK_XMSSMT                   (CKK_CUSTOMER_DEFINED + 0x04)
#define CKK_XMSSMT_DIST              (CKK_CUSTOMER_DEFINED + 0x05)
#define CKK_HSS                      0x00000046UL
#define CKK_FALCON                   (CKK_CUSTOMER_DEFINED + 0x06)
#define CKK_SPHINCS                  (CKK_CUSTOMER_DEFINED + 0x07)
#define CKK_ML_DSA                   (CKK_CUSTOMER_DEFINED + 0x08)
#define CKK_ML_KEM                   (CKK_CUSTOMER_DEFINED + 0x09)
#define CKK_LMS                      (CKK_CUSTOMER_DEFINED + 0x0A)
#define CKK_CHUNK                    (CKK_CUSTOMER_DEFINED + 0xFFFF)

#define CKA_CUSTOMER_DEFINED         0xC0000000

#define CKA_KEY_PARAMS               (CKA_CUSTOMER_DEFINED + 0x01)
#define CKA_REMAINING_SIGS           (CKA_CUSTOMER_DEFINED + 0x02)

/* HSS */
#define CKA_HSS_LEVELS                  0x00000617UL
#define CKA_HSS_LMS_TYPE                0x00000618UL
#define CKA_HSS_LMOTS_TYPE              0x00000619UL
#define CKA_HSS_LMS_TYPES               0x0000061aUL
#define CKA_HSS_LMOTS_TYPES             0x0000061bUL
#define CKA_HSS_KEYS_REMAINING          0x0000061cUL
#define CKA_HSS_AUX_DATA_LEN            (CKA_CUSTOMER_DEFINED + 0x10)

/* LMS */
#define CKA_LMS_TYPE                    (CKA_CUSTOMER_DEFINED + 0x30)
#define CKA_LMOTS_TYPE                  (CKA_CUSTOMER_DEFINED + 0x31)
#define CKA_KEYS_REMAINING              (CKA_CUSTOMER_DEFINED + 0x32)
#define CKA_AUX_DATA_LEN                (CKA_CUSTOMER_DEFINED + 0x10)

#define CKA_XMSSMT_OID                       (CKA_CUSTOMER_DEFINED + 0x20)
#define CKA_XMSS_FAST                        (CKA_CUSTOMER_DEFINED + 0x21)
#define CKA_XMSSMT_DIST_LEVEL                (CKA_CUSTOMER_DEFINED + 0x22)
#define CKA_XMSSMT_DIST_TREE                 (CKA_CUSTOMER_DEFINED + 0x23)
#define CKA_XMSSMT_DIST_LEVELS               (CKA_CUSTOMER_DEFINED + 0x24)
#define CKA_XMSSMT_DIST_TOP_LEVEL_PUBLIC_KEY (CKA_CUSTOMER_DEFINED + 0x25)
#define CKA_XMSSMT_DIST_INDEX                (CKA_CUSTOMER_DEFINED + 0x26)

/* Defined LM parameter sets */
#define LMS_SHA256_N32_H5  0x00000005
#define LMS_SHA256_N32_H10 0x00000006
#define LMS_SHA256_N32_H15 0x00000007
#define LMS_SHA256_N32_H20 0x00000008
#define LMS_SHA256_N32_H25 0x00000009

#define LMS_SHA256_N24_H5  0x0000000a
#define LMS_SHA256_N24_H10 0x0000000b
#define LMS_SHA256_N24_H15 0x0000000c
#define LMS_SHA256_N24_H20 0x0000000d
#define LMS_SHA256_N24_H25 0x0000000e

/* LM-OTS registry */
#define LMOTS_SHA256_N32_W1 0x00000001
#define LMOTS_SHA256_N32_W2 0x00000002
#define LMOTS_SHA256_N32_W4 0x00000003
#define LMOTS_SHA256_N32_W8 0x00000004

#define LMOTS_SHA256_N24_W1 0x00000005
#define LMOTS_SHA256_N24_W2 0x00000006
#define LMOTS_SHA256_N24_W4 0x00000007
#define LMOTS_SHA256_N24_W8 0x00000008

// Post-Quantum Crypto Key Encapsulation
// key generation and signing mechanisms
#define CKM_CUSTOMER_DEFINED           0xC0000000

#define CKM_KYBER_KEM_KEY_PAIR_GEN     (CKM_CUSTOMER_DEFINED + 0x10)
#define CKM_KYBER_KEM_KEY_ENCAP        (CKM_CUSTOMER_DEFINED + 0x11)
#define CKM_KYBER_KEM_KEY_DECAP        (CKM_CUSTOMER_DEFINED + 0x12)

#define CKM_ML_KEM_KEY_PAIR_GEN        (CKM_CUSTOMER_DEFINED + 0x13)
#define CKM_ML_KEM_KEY_ENCAP           (CKM_CUSTOMER_DEFINED + 0x14)
#define CKM_ML_KEM_KEY_DECAP           (CKM_CUSTOMER_DEFINED + 0x15)

#define CKM_HSS_KEY_PAIR_GEN           0x00004032UL
#define CKM_HSS                        0x00004033UL

#define CKM_XMSS_KEY_PAIR_GEN          (CKM_CUSTOMER_DEFINED + 0x30)
#define CKM_XMSS                       (CKM_CUSTOMER_DEFINED + 0x31)
#define CKM_SHA512_XMSS                (CKM_CUSTOMER_DEFINED + 0x32)

#define CKM_XMSSMT_KEY_PAIR_GEN        (CKM_CUSTOMER_DEFINED + 0x40)
#define CKM_XMSSMT                     (CKM_CUSTOMER_DEFINED + 0x41)
#define CKM_SHA512_XMSSMT              (CKM_CUSTOMER_DEFINED + 0x42)

#define CKM_XMSSMT_DIST_KEY_PAIR_GEN   (CKM_CUSTOMER_DEFINED + 0x50)
#define CKM_XMSSMT_DIST                (CKM_CUSTOMER_DEFINED + 0x51)

#define CKM_DILITHIUM_KEY_PAIR_GEN     (CKM_CUSTOMER_DEFINED + 0x60)
#define CKM_DILITHIUM                  (CKM_CUSTOMER_DEFINED + 0x61)
#define CKM_SHA512_DILITHIUM           (CKM_CUSTOMER_DEFINED + 0x62)

#define CKM_ML_DSA_KEY_PAIR_GEN        (CKM_CUSTOMER_DEFINED + 0x65)
#define CKM_ML_DSA                     (CKM_CUSTOMER_DEFINED + 0x66)

#define CKM_FALCON_KEY_PAIR_GEN        (CKM_CUSTOMER_DEFINED + 0x70)
#define CKM_FALCON                     (CKM_CUSTOMER_DEFINED + 0x71)

#define CKM_SPHINCS_KEY_PAIR_GEN       (CKM_CUSTOMER_DEFINED + 0x80)
#define CKM_SPHINCS                    (CKM_CUSTOMER_DEFINED + 0x81)

#define CKM_LMS_KEY_PAIR_GEN           (CKM_CUSTOMER_DEFINED + 0x91)
#define CKM_LMS                        (CKM_CUSTOMER_DEFINED + 0x92)

#define CKR_CUSTOMER_DEFINED           0xC0000000

#define CKR_KEY_EXHAUSTED              0x00000203UL

#endif /* INC_PQCDEFS_H */
