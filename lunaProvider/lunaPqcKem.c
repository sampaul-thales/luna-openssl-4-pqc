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

#ifdef CKK_MLKEM
#define CK_KEYTYPE_IS_PQC_KEM(_t) ( (_t) == CKK_KYBER || (_t) == CKK_MLKEM )
#else
#define CK_KEYTYPE_IS_PQC_KEM(_t) ( (_t) == CKK_KYBER || 0 )
#endif

#define CK_KEYTYPE_IS_ECX_KEM(_t) ( (_t) == CKK_EC_MONTGOMERY )

static CK_RV LunaPqcKemEncap(luna_prov_key_ctx *keyctx, luna_prov_keyinfo *pkeyinfo,
    void **ppdata, CK_ULONG *plen, CK_BYTE *psecret, CK_ULONG secretLen) {
    CK_OBJECT_HANDLE encapObjectHandle = 0;
    CK_BYTE_PTR cipherText = NULL;
    CK_ULONG cipherTextLen = 0;

    CK_KEY_TYPE keytype = CKK_INVALID;
    CK_KEY_PARAMS params = CKP_INVALID;
    CK_MECHANISM encapMech = {0,0,0};
    CK_RV rvlookup = LunaLookupAlgName(keyctx, &keytype, &params, NULL, NULL, &encapMech, NULL);
    if (rvlookup != CKR_OK)
        return rvlookup;
    if ( ! (CK_KEYTYPE_IS_PQC_KEM(keytype) || 0) )
        return CKR_ARGUMENTS_BAD;
    if ( ! luna_prov_is_ecdh_len(secretLen) )
        return CKR_ARGUMENTS_BAD;

    // If the public key isn't in the HSM, encapsulation can take a byte array for pPublicKey and
    // the length is specified with ulPubKeyLen. In this case, the params must give the CKP_KYBER_* value as well
    CK_OBJECT_HANDLE publicObjectHandle = 0;
    CK_KEM_ENCAP_PARAMS kyberEncapParams; /* same as CK_KYBER_ENCAP_PARAMS */
    if (CK_KEYTYPE_IS_PQC_KEM(keytype)) {
        memset(&kyberEncapParams, 0, sizeof(kyberEncapParams));
        if (luna_prov_key_reason_pubkey(keyctx->reason)) {
            LUNA_PRINTF(("encapsulate using buffer\n"));
            publicObjectHandle = 0;
            kyberEncapParams.pPublicKey = pkeyinfo->pubkey;
            kyberEncapParams.ulPubKeyLen = pkeyinfo->pubkeylen;
            kyberEncapParams.params = params;
        } else if (keyctx->reason == LUNA_PROV_KEY_REASON_GEN) {
            LUNA_PRINTF(("encapsulate using object\n"));
            publicObjectHandle = keyctx->hPublic;
            if (publicObjectHandle == 0) {
                return CKR_KEY_CHANGED;
            }
            kyberEncapParams.pPublicKey = NULL;
            kyberEncapParams.ulPubKeyLen = 0;
            kyberEncapParams.params = 0;
        } else {
            return CKR_KEY_CHANGED;
        }
        kyberEncapParams.kdfType = CKD_NULL;
        kyberEncapParams.pInfo = NULL;
        kyberEncapParams.ulInfoLen = 0;
        kyberEncapParams.pCiphertext = NULL;
        kyberEncapParams.pulCiphertextLen = &cipherTextLen;

        //encapMech.mechanism = CKM_KYBER_KEM_KEY_ENCAP;
        encapMech.pParameter = &kyberEncapParams;
        encapMech.ulParameterLen = sizeof(kyberEncapParams);
    }

    CK_ULONG valueLen = secretLen;
    CK_KEY_TYPE aesKeyType = CKK_GENERIC_SECRET;
    char *encapLabel = "temp-luna-kem-encap";

    CK_BBOOL yes = CK_TRUE;
    CK_BBOOL no = CK_FALSE;
    CK_ATTRIBUTE encapTemplate[] = {
        {CKA_TOKEN, &no, sizeof(no)},
        {CKA_LABEL, encapLabel, strlen(encapLabel)},
        {CKA_VALUE_LEN, &valueLen, sizeof(valueLen)},
        {CKA_KEY_TYPE, &aesKeyType, sizeof(aesKeyType)},
        {CKA_MODIFIABLE, &no, sizeof(no)},
        {CKA_EXTRACTABLE, &yes, sizeof(yes)},
        {CKA_ENCRYPT, &yes, sizeof(yes)},
        {CKA_DECRYPT, &yes, sizeof(yes)},
    };
    CK_RV rv = CKR_OK;

    if (plen == NULL)
        return CKR_ARGUMENTS_BAD;

    // check for stale object handle
    if (rv == CKR_OK && publicObjectHandle != 0) {
        if (KEYCTX_CHECK_COUNT(keyctx)) {
            rv = CKR_KEY_CHANGED;
            LUNA_PRINTF(("key handle is stale\n"));
        }
    }

    // Perform the encapsulation using the kyber public key. First get the length of the ciphertext
    CK_SESSION_HANDLE session = pkeyinfo->sess.hSession;
    if (rv == CKR_OK) {
        rv = P11->C_DeriveKey(session, &encapMech, publicObjectHandle, encapTemplate, DIM(encapTemplate), &encapObjectHandle);
        if (rv != CKR_OK) {
            LUNA_PRINTF(("Failed to get ciphertext length: 0x%lx\n", rv));
        } else {
            LUNA_PRINTF(("Ciphertext length: %lu\n", cipherTextLen));
        }
    }

    if ( ppdata == NULL || psecret == NULL ) {
        *plen = cipherTextLen;

    } else {
        if (*plen < cipherTextLen)
            rv = CKR_BUFFER_TOO_SMALL;
        *plen = cipherTextLen;

        if (rv == CKR_OK) {
            //allocate the ciphertext buffer and the derive the key. The cipherText buffer will be populated after this operation.
            cipherText = malloc(cipherTextLen);
            if (cipherText == NULL)
                return CKR_GENERAL_ERROR;
            kyberEncapParams.pCiphertext = cipherText;
            rv = P11->C_DeriveKey(session, &encapMech, publicObjectHandle, encapTemplate, DIM(encapTemplate), &encapObjectHandle);
            if (rv != CKR_OK) {
                LUNA_PRINTF(("PQC encap failed: 0x%lx\n", rv));
            } else {
                LUNA_PRINTF(("PQC encap was successful: encap=%lu\n", encapObjectHandle));
            }
        }

        // unwrap key and get key bytes
        if (rv == CKR_OK) {
            rv = LunaUnwrapKeyBytes(keyctx, pkeyinfo, encapObjectHandle, psecret, secretLen);
            if (rv != CKR_OK) {
                LUNA_PRINTF(("PQC unwrap failed: 0x%lx\n", rv));
            } else {
                LUNA_PRINTF(("PQC unwrap was successful\n"));
            }
        }

        // clean buffers
        if (rv != CKR_OK) {
            free(cipherText);
        } else {
            *ppdata = cipherText;
        }

        // clean objects
        if (encapObjectHandle != 0) {
            (void)P11->C_DestroyObject(session, encapObjectHandle);
        }

    }

    luna_context_set_last_error(&pkeyinfo->sess, rv);
    return rv;
}

static CK_RV LunaPqcKemDecap(luna_prov_key_ctx *keyctx, luna_prov_keyinfo *pkeyinfo,
    CK_BYTE *psecret, CK_ULONG secretLen, const CK_BYTE *cipherText, CK_ULONG cipherTextLen) {
    CK_RV rv = CKR_OK;

    CK_OBJECT_HANDLE privateObjectHandle = keyctx->hPrivate;
    CK_OBJECT_HANDLE decapObjectHandle = 0;

    CK_ULONG valueLen = secretLen;
    CK_KEY_TYPE aesKeyType = CKK_GENERIC_SECRET;
    char *decapLabel = "temp-luna-kem-decap";

    CK_KEY_TYPE keytype = CKK_INVALID;
    CK_KEY_PARAMS params = CKP_INVALID;
    CK_MECHANISM decapMech = {0,0,0};
    CK_RV rvlookup = LunaLookupAlgName(keyctx, &keytype, &params, NULL, NULL, NULL, &decapMech);
    if (rvlookup != CKR_OK)
        return rvlookup;
    if ( ! (CK_KEYTYPE_IS_PQC_KEM(keytype) || CK_KEYTYPE_IS_ECX_KEM(keytype)) )
        return CKR_ARGUMENTS_BAD;
    if ( ! luna_prov_is_ecdh_len(secretLen) )
        return CKR_ARGUMENTS_BAD;

    CK_KEM_DECAP_PARAMS kyberDecapParams; /* same as CK_KYBER_DECAP_PARAMS */
    CK_ECDH1_DERIVE_PARAMS ecxDecapParams;
    CK_BYTE bufEcxPubKey[64] = {0};

    if (CK_KEYTYPE_IS_PQC_KEM(keytype)) {
        memset(&kyberDecapParams, 0, sizeof(kyberDecapParams));
        kyberDecapParams.kdfType = CKD_NULL;
        kyberDecapParams.pCiphertext = (CK_BYTE*)cipherText;
        kyberDecapParams.ulCiphertextLen = cipherTextLen;
        kyberDecapParams.pInfo = NULL;
        kyberDecapParams.ulInfoLen = 0;

        decapMech.pParameter = &kyberDecapParams;
        decapMech.ulParameterLen = sizeof(CK_KYBER_DECAP_PARAMS);

    } else if (CK_KEYTYPE_IS_ECX_KEM(keytype)) {

        LUNA_ASSERT( cipherTextLen <= (sizeof(bufEcxPubKey) - 2) );
        memcpy(&bufEcxPubKey[2], cipherText, cipherTextLen);
        bufEcxPubKey[0] = 0x04;
        bufEcxPubKey[1] = (CK_BYTE)(unsigned)cipherTextLen;

        memset(&ecxDecapParams, 0, sizeof(ecxDecapParams));
        ecxDecapParams.kdf = CKD_NULL;
        ecxDecapParams.ulSharedDataLen = 0;
        ecxDecapParams.pSharedData = NULL;
        ecxDecapParams.pPublicData = bufEcxPubKey;
        ecxDecapParams.ulPublicDataLen = (cipherTextLen + 2);

        decapMech.pParameter = &ecxDecapParams;
        decapMech.ulParameterLen = sizeof(ecxDecapParams);
    }

    CK_BBOOL yes = CK_TRUE;
    CK_BBOOL no = CK_FALSE;
    CK_ATTRIBUTE decapTemplate[] = {
        {CKA_TOKEN, &no, sizeof(no)},
        {CKA_LABEL, decapLabel, strlen(decapLabel)},
        {CKA_VALUE_LEN, &valueLen, sizeof(valueLen)},
        {CKA_KEY_TYPE, &aesKeyType, sizeof(aesKeyType)},
        {CKA_MODIFIABLE, &no, sizeof(no)},
        {CKA_EXTRACTABLE, &yes, sizeof(yes)},
        {CKA_ENCRYPT, &yes, sizeof(yes)},
        {CKA_DECRYPT, &yes, sizeof(yes)},
    };

    // check for stale object handle
    if (rv == CKR_OK) {
        if (KEYCTX_CHECK_COUNT(keyctx)) {
            rv = CKR_KEY_CHANGED;
            LUNA_PRINTF(("key handle is stale\n"));
        }
    }

    // Perform the decapsulation using the private key
    CK_SESSION_HANDLE session = pkeyinfo->sess.hSession;
    if (rv == CKR_OK) {
        rv = P11->C_DeriveKey(session, &decapMech, privateObjectHandle, decapTemplate, DIM(decapTemplate), &decapObjectHandle);
        if (rv != CKR_OK) {
            LUNA_PRINTF(("PQC decap failed: 0x%lx\n", rv));
        } else {
            LUNA_PRINTF(("PQC decap was successful: hObject=%lu\n", decapObjectHandle));
        }
    }

    // unwrap key and get key bytes
    if (rv == CKR_OK) {
        rv = LunaUnwrapKeyBytes(keyctx, pkeyinfo, decapObjectHandle, psecret, secretLen);
        if (rv != CKR_OK) {
            LUNA_PRINTF(("PQC unwrap failed: 0x%lx\n", rv));
        } else {
            LUNA_PRINTF(("PQC unwrap was successful\n"));
        }
    }

    if (decapObjectHandle != 0) {
        (void)P11->C_DestroyObject(session, decapObjectHandle);
        decapObjectHandle = 0;
    }

    luna_context_set_last_error(&pkeyinfo->sess, rv);
    return rv;
}

static CK_RV LunaExportPublic(luna_prov_key_ctx *keyctx, luna_prov_keyinfo *pkeyinfo, CK_ATTRIBUTE_TYPE attrType) {
    CK_OBJECT_HANDLE hPublic = keyctx->hPublic;
    CK_BYTE *pubkey = (CK_BYTE*)pkeyinfo->pubkey;
    CK_ULONG pubkeylen = pkeyinfo->pubkeylen;
    CK_ATTRIBUTE attributeTemplate[] = {
        {0, NULL, 0}
    };
    attributeTemplate[0].type = attrType;
    CK_SESSION_HANDLE session = pkeyinfo->sess.hSession;
    CK_RV rv = CKR_OK;

    // check for stale object handle
    if (rv == CKR_OK) {
        if (KEYCTX_CHECK_COUNT(keyctx)) {
            rv = CKR_KEY_CHANGED;
            LUNA_PRINTF(("key handle is stale\n"));
        }
    }

    if (rv == CKR_OK) {
        rv = P11->C_GetAttributeValue(session, hPublic,
            attributeTemplate, DIM(attributeTemplate));
    }

    /* check if we are dealing with an encoded attribute (x25519/ed25519) */
    if ( (rv == CKR_OK)
            && ( (attrType == CKA_EC_POINT) && (attributeTemplate[0].ulValueLen == (pubkeylen + 2)))
            ) {
        CK_BYTE bufDebug[64] = {0};
        if (attributeTemplate[0].ulValueLen <= sizeof(bufDebug)) {
            CK_ATTRIBUTE attrDebug;
            attrDebug.type = attrType;
            attrDebug.pValue = bufDebug;
            attrDebug.ulValueLen = attributeTemplate[0].ulValueLen;
            if (P11->C_GetAttributeValue(session, hPublic, &attrDebug, 1) == CKR_OK) {
                _LUNA_debug_ex("LunaExportPublic", "attr.pValue", bufDebug, attrDebug.ulValueLen);
                /* extract the raw attribute */
                if ( (bufDebug[0] == 0x04) && ((CK_ULONG)(bufDebug[1]) == pubkeylen) ) {
                    LUNA_PRINTF(("fixing %lu bytes\n", pubkeylen));
                    memcpy(pubkey, &bufDebug[2], pubkeylen);
                    rv = CKR_OK;
                    luna_context_set_last_error(&pkeyinfo->sess, rv);
                    return rv;
                }
            }
        }
    }

    if (rv != CKR_OK) {
        LUNA_PRINTF(("Failed to get public key value size: rv = 0x%lx, pubkeylen = %u\n",
            rv, (unsigned)pubkeylen));
        luna_context_set_last_error(&pkeyinfo->sess, rv);
        return rv;
    }

    if (attributeTemplate[0].ulValueLen != pubkeylen) {
        if (attributeTemplate[0].ulValueLen < pubkeylen) {
            LUNA_PRINTF(("WARNING: public key value size: expected = %u, actual = %u\n",
                (unsigned)pubkeylen, (unsigned)attributeTemplate[0].ulValueLen));
        } else {
            LUNA_PRINTF(("ERROR: public key value size: expected = %u, actual = %u\n",
                (unsigned)pubkeylen, (unsigned)attributeTemplate[0].ulValueLen));
            rv = CKR_GENERAL_ERROR;
            luna_context_set_last_error(&pkeyinfo->sess, rv);
            return rv;
        }
    }

    CK_ULONG padlen = (pubkeylen - attributeTemplate[0].ulValueLen);
    memset(pubkey, 0, padlen);
    attributeTemplate[0].pValue = &pubkey[padlen];
    attributeTemplate[0].ulValueLen = pubkeylen;
    rv = P11->C_GetAttributeValue(session, hPublic, attributeTemplate, DIM(attributeTemplate));
    luna_context_set_last_error(&pkeyinfo->sess, rv);
    return rv;
}

static CK_RV LunaPqcExportPublic(luna_prov_key_ctx *keyctx, luna_prov_keyinfo *pkeyinfo) {
    return LunaExportPublic(keyctx, pkeyinfo, CKA_VALUE);
}

static CK_RV LunaEcxExportPublic(luna_prov_key_ctx *keyctx, luna_prov_keyinfo *pkeyinfo) {
    return LunaExportPublic(keyctx, pkeyinfo, CKA_EC_POINT);
}

