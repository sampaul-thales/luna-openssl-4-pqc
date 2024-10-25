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

#include "e_gem_compat.h"

/* Support C or C++ compiler in the field */
#ifdef __cplusplus
extern "C" {
#endif

/*****************************************************************************/

#ifdef LUNA_NO_RSA_STRUCTURE

static BIGNUM *LUNA_RSA_GET_n(RSA *rsa) {
   const BIGNUM *x = NULL;
   RSA_get0_key(rsa, &x, NULL, NULL);
   return (BIGNUM *)x;
}

static BIGNUM *LUNA_RSA_GET_e(RSA *rsa) {
   const BIGNUM *x = NULL;
   RSA_get0_key(rsa, NULL, &x, NULL);
   return (BIGNUM *)x;
}

static BIGNUM *LUNA_RSA_GET_d(RSA *rsa) {
   const BIGNUM *x = NULL;
   RSA_get0_key(rsa, NULL, NULL, &x);
   return (BIGNUM *)x;
}

static BIGNUM *LUNA_RSA_GET_p(RSA *rsa) {
   const BIGNUM *x = NULL;
   RSA_get0_factors(rsa, &x, NULL);
   return (BIGNUM *)x;
}

static BIGNUM *LUNA_RSA_GET_q(RSA *rsa) {
   const BIGNUM *x = NULL;
   RSA_get0_factors(rsa, NULL, &x);
   return (BIGNUM *)x;
}

static BIGNUM *LUNA_RSA_GET_dmp1(RSA *rsa) {
   const BIGNUM *x = NULL;
   RSA_get0_crt_params(rsa, &x, NULL, NULL);
   return (BIGNUM *)x;
}

static BIGNUM *LUNA_RSA_GET_dmq1(RSA *rsa) {
   const BIGNUM *x = NULL;
   RSA_get0_crt_params(rsa, NULL, &x, NULL);
   return (BIGNUM *)x;
}

static BIGNUM *LUNA_RSA_GET_iqmp(RSA *rsa) {
   const BIGNUM *x = NULL;
   RSA_get0_crt_params(rsa, NULL, NULL, &x);
   return (BIGNUM *)x;
}

static int LUNA_RSA_SET_n_e_d(RSA *rsa, BIGNUM *n, BIGNUM *e, BIGNUM *d) {
   int rc = RSA_set0_key(rsa, n, e, d);
   return rc;
}

static int LUNA_RSA_SET_p_q(RSA *rsa, BIGNUM *p, BIGNUM *q) {
   int rc = RSA_set0_factors(rsa, p, q);
   return rc;
}

static int LUNA_RSA_SET_dmp1_dmq1_iqmp(RSA *rsa, BIGNUM *dmp1, BIGNUM *dmq1, BIGNUM *iqmp) {
   int rc = RSA_set0_crt_params(rsa, dmp1, dmq1, iqmp);
   return rc;
}

static BIGNUM *LUNA_DSA_GET_p(DSA *dsa) {
   const BIGNUM *x = NULL;
   DSA_get0_pqg(dsa, &x, NULL, NULL);
   return (BIGNUM *)x;
}

static BIGNUM *LUNA_DSA_GET_q(DSA *dsa) {
   const BIGNUM *x = NULL;
   DSA_get0_pqg(dsa, NULL, &x, NULL);
   return (BIGNUM *)x;
}

static BIGNUM *LUNA_DSA_GET_g(DSA *dsa) {
   const BIGNUM *x = NULL;
   DSA_get0_pqg(dsa, NULL, NULL, &x);
   return (BIGNUM *)x;
}

static BIGNUM *LUNA_DSA_GET_pub_key(DSA *dsa) {
   const BIGNUM *x = NULL;
   DSA_get0_key(dsa, &x, NULL);
   return (BIGNUM *)x;
}

static BIGNUM *LUNA_DSA_GET_priv_key(DSA *dsa) {
   const BIGNUM *x = NULL;
   DSA_get0_key(dsa, NULL, &x);
   return (BIGNUM *)x;
}

static int LUNA_DSA_SET_p_q_g(DSA *dsa, BIGNUM *p, BIGNUM *q, BIGNUM *g) {
   int rc = DSA_set0_pqg(dsa, p, q, g);
   return rc;
}

static int LUNA_DSA_SET_pub_priv(DSA *dsa, BIGNUM *pub_key, BIGNUM *priv_key) {
   int rc = DSA_set0_key(dsa, pub_key, priv_key);
   return rc;
}

static BIGNUM *LUNA_DSA_SIG_GET_r(const DSA_SIG *sig) {
   const BIGNUM *x = NULL;
   DSA_SIG_get0(sig, &x, NULL);
   return (BIGNUM *)x;
}

static BIGNUM *LUNA_DSA_SIG_GET_s(const DSA_SIG *sig) {
   const BIGNUM *x = NULL;
   DSA_SIG_get0(sig, NULL, &x);
   return (BIGNUM *)x;
}

static int LUNA_DSA_SIG_SET_r_s(DSA_SIG *sig, BIGNUM *r, BIGNUM *s) {
   int rc = DSA_SIG_set0(sig, r, s);
   return rc;
}

static RSA_METHOD *LUNA_RSA_meth_new(const char *name, int flags) {
   return RSA_meth_new(name, flags);
}

static DSA_METHOD *LUNA_DSA_meth_new(const char *name, int flags) {
   return DSA_meth_new(name, flags);
}

static EVP_MD_CTX *LUNA_EVP_MD_CTX_new(void) {
   EVP_MD_CTX *meth = EVP_MD_CTX_new();
   return meth;
}

static void LUNA_EVP_MD_CTX_free(EVP_MD_CTX *pctx) {
   EVP_MD_CTX_free(pctx);
}

static void LUNA_RSA_meth_free(RSA_METHOD *meth) {
   RSA_meth_free(meth);
}

static void LUNA_DSA_meth_free(DSA_METHOD *meth) {
   DSA_meth_free(meth);
}

#else /* LUNA_NO_RSA_STRUCTURE */

static int LUNA_RSA_SET_n_e_d(RSA *rsa, BIGNUM *n, BIGNUM *e, BIGNUM *d) {
   int rc = n && e && d;
   rsa->n = n;
   rsa->e = e;
   rsa->d = d;
   return rc;
}

static int LUNA_RSA_SET_p_q(RSA *rsa, BIGNUM *p, BIGNUM *q) {
   int rc = p && q;
   rsa->p = p;
   rsa->q = q;
   return rc;
}

static int LUNA_RSA_SET_dmp1_dmq1_iqmp(RSA *rsa, BIGNUM *dmp1, BIGNUM *dmq1, BIGNUM *iqmp) {
   int rc = dmp1 && dmq1 && iqmp;
   rsa->dmp1 = dmp1;
   rsa->dmq1 = dmq1;
   rsa->iqmp = iqmp;
   return rc;
}

static int LUNA_DSA_SET_p_q_g(DSA *dsa, BIGNUM *p, BIGNUM *q, BIGNUM *g) {
   int rc = p && q && g;
   dsa->p = p;
   dsa->q = q;
   dsa->g = g;
   return rc;
}

static int LUNA_DSA_SET_pub_priv(DSA *dsa, BIGNUM *pub_key, BIGNUM *priv_key) {
   int rc = pub_key && priv_key;
   dsa->pub_key = pub_key;
   dsa->priv_key = priv_key;
   return rc;
}

static int LUNA_DSA_SIG_SET_r_s(DSA_SIG *sig, BIGNUM *r, BIGNUM *s) {
   int rc = r && s;
   sig->r = r;
   sig->s = s;
   return rc;
}

static RSA_METHOD *LUNA_RSA_meth_new(const char *name, int flags) {
   RSA_METHOD *meth = (RSA_METHOD *)LUNA_OPENSSL_zalloc(sizeof(*meth));
   if (meth != NULL) {
      meth->flags = flags;
      meth->name = OPENSSL_strdup(name);
      if (meth->name != NULL)
         return meth;
      OPENSSL_free(meth);
   }
   return NULL;
}

static DSA_METHOD *LUNA_DSA_meth_new(const char *name, int flags) {
   DSA_METHOD *meth = (DSA_METHOD *)LUNA_OPENSSL_zalloc(sizeof(*meth));
   if (meth != NULL) {
      meth->flags = flags;
      meth->name = OPENSSL_strdup(name);
      if (meth->name != NULL)
         return meth;
      OPENSSL_free(meth);
   }
   return NULL;
}

static void LUNA_RSA_meth_free(RSA_METHOD *meth) {
   OPENSSL_free(meth);
}

static void LUNA_DSA_meth_free(DSA_METHOD *meth) {
   OPENSSL_free(meth);
}

static EVP_MD_CTX *LUNA_EVP_MD_CTX_new(void) {
   EVP_MD_CTX *meth = (EVP_MD_CTX *)LUNA_OPENSSL_zalloc(sizeof(*meth));
   return meth;
}

static void LUNA_EVP_MD_CTX_free(EVP_MD_CTX *pctx) {
   EVP_MD_CTX_destroy(pctx);
}

#endif /* LUNA_NO_RSA_STRUCTURE */



#ifdef LUNA_NO_EC_KEY_SIG_STRUCTURE

static BIGNUM *LUNA_EC_KEY_SIG_GET_r(const ECDSA_SIG *sig) {
   const BIGNUM *x = NULL;
   ECDSA_SIG_get0(sig, &x, NULL);
   return (BIGNUM *)x;
}

static BIGNUM *LUNA_EC_KEY_SIG_GET_s(const ECDSA_SIG *sig) {
   const BIGNUM *x = NULL;
   ECDSA_SIG_get0(sig, NULL, &x);
   return (BIGNUM *)x;
}

static int LUNA_EC_KEY_SIG_SET_r_s(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s) {
   int rc = ECDSA_SIG_set0(sig, r, s);
   return rc;
}

#else /* LUNA_NO_EC_KEY_SIG_STRUCTURE */

static int LUNA_EC_KEY_SIG_SET_r_s(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s) {
   int rc = r && s;
   sig->r = r;
   sig->s = s;
   return rc;
}

#endif /* LUNA_NO_EC_KEY_SIG_STRUCTURE */



static void *LUNA_OPENSSL_zalloc(size_t num) {
   void *ptr = OPENSSL_malloc(num);
   if (ptr != NULL)
      memset(ptr, 0, num);
   return ptr;
}

static void LUNA_OPENSSL_free(void *ptr) {
   OPENSSL_free(ptr);
}



#ifdef LUNA_NO_EC_KEY_STRUCTURE

static LUNA_EC_KEY_METHOD *LUNA_EC_KEY_meth_new(const char *name, int flags) {
   /* duplicate the ec key method here, then override using LUNA_EC_KEY_METH_SET_DEFAULT */
#ifdef LUNA_EC_KEY_FUNCTIONS
   LUNA_EC_KEY_METHOD *meth = EC_KEY_METHOD_new(LUNA_EC_KEY_OpenSSL());
#else
   LUNA_EC_KEY_METHOD *meth = ECDSA_METHOD_new(LUNA_EC_KEY_OpenSSL());
#endif
   if (meth != NULL) {
#ifdef LUNA_EC_KEY_FUNCTIONS
      /* FIXME: EC_KEY_METHOD_set_flags(meth, flags); */
      /* FIXME: EC_KEY_METHOD_set_name(meth, OPENSSL_strdup(name)); */
#else
      ECDSA_METHOD_set_flags(meth, flags);
      ECDSA_METHOD_set_name(meth, OPENSSL_strdup(name));
#endif
      return meth;
   }
   return NULL;
}
static void LUNA_EC_KEY_meth_free(LUNA_EC_KEY_METHOD *meth) {
#ifdef LUNA_EC_KEY_FUNCTIONS
   EC_KEY_METHOD_free(meth);
#else
   ECDSA_METHOD_free(meth);
#endif
}

static const EC_GROUP *LUNA_EC_KEY_get0_group(const EC_KEY *key) {
   return EC_KEY_get0_group(key);
}

static const BIGNUM *LUNA_EC_GROUP_get0_order(const EC_GROUP *group, BIGNUM **p_alloc) {
   const BIGNUM *order = NULL;
   (*p_alloc) = NULL;
#ifdef LUNA_EC_KEY_FUNCTIONS
   order = EC_GROUP_get0_order(group);
#else
   order = BN_new();
   if (order != NULL) {
      if (EC_GROUP_get_order(group, (BIGNUM*)order, NULL) == 1) {
         (*p_alloc) = (BIGNUM*)order;
      } else {
         BN_free((BIGNUM*)order);
         order = NULL;
      }
   }
#endif
   return order;
}

static const BIGNUM *LUNA_EC_KEY_get0_private_key(const EC_KEY *key) {
   return EC_KEY_get0_private_key(key);
}

static const EC_POINT *LUNA_EC_KEY_get0_public_key(const EC_KEY *key) {
   return EC_KEY_get0_public_key(key);
}

static int LUNA_EC_KEY_set_private_key(EC_KEY *key, BIGNUM *priv_key) {
   int ret = 0;
   if (priv_key != NULL) {
      ret = EC_KEY_set_private_key(key, priv_key);
      /* NOTE: free priv_key since EC_KEY_set_private_key makes a copy */
      BN_free(priv_key);
   }
   return ret;
}

#else /* LUNA_NO_EC_KEY_STRUCTURE */

static LUNA_EC_KEY_METHOD *LUNA_EC_KEY_meth_new(const char *name, int flags) {
   LUNA_EC_KEY_METHOD *meth = (LUNA_EC_KEY_METHOD *)LUNA_OPENSSL_zalloc(sizeof(*meth));
   if (meth != NULL) {
      meth->flags = flags;
      meth->name = OPENSSL_strdup(name);
      if (meth->name != NULL)
         return meth;
      OPENSSL_free(meth);
   }
   return NULL;
}

static void LUNA_EC_KEY_meth_free(LUNA_EC_KEY_METHOD *meth) {
   OPENSSL_free(meth);
}

static const EC_GROUP *LUNA_EC_KEY_get0_group(const EC_KEY *key) {
   return key->group;
}

static const BIGNUM *LUNA_EC_GROUP_get0_order(const EC_GROUP *group, BIGNUM **p_alloc) {
   (*p_alloc) = NULL;
   return &(group->order);
}

static const BIGNUM *LUNA_EC_KEY_get0_private_key(const EC_KEY *key) {
   return key->priv_key;
}

static const EC_POINT *LUNA_EC_KEY_get0_public_key(const EC_KEY *key) {
   return key->pub_key;
}

static int LUNA_EC_KEY_set_private_key(EC_KEY *key, BIGNUM *priv_key) {
   int ret = 0;
   if (priv_key != NULL) {
      key->priv_key = priv_key;
      ret = 1;
   }
   return ret;
}

#endif /* LUNA_NO_EC_KEY_STRUCTURE */



#ifdef LUNA_NO_ASN1_STRUCTURE

static int LUNA_ASN1_OBJECT_GET_length(ASN1_OBJECT *asn1) {
   return (int)(unsigned)OBJ_length(asn1);
}

static const unsigned char *LUNA_ASN1_OBJECT_GET_data(ASN1_OBJECT *asn1) {
   return OBJ_get0_data(asn1);
}

#else /* LUNA_NO_ASN1_STRUCTURE */

static int LUNA_ASN1_OBJECT_GET_length(ASN1_OBJECT *asn1) {
   return asn1->length;
}

static const unsigned char *LUNA_ASN1_OBJECT_GET_data(ASN1_OBJECT *asn1) {
   return asn1->data;
}

#endif /* LUNA_NO_ASN1_STRUCTURE */



#ifdef LUNA_NO_PKEY_STRUCTURE

static RSA *LUNA_EVP_PKEY_get0_RSA(EVP_PKEY *pkey) {
   return (RSA*)EVP_PKEY_get0_RSA(pkey);
}

static DSA *LUNA_EVP_PKEY_get0_DSA(EVP_PKEY *pkey) {
   return (DSA*)EVP_PKEY_get0_DSA(pkey);
}

static EC_KEY *LUNA_EVP_PKEY_get0_EC_KEY(EVP_PKEY *pkey) {
   return (EC_KEY*)EVP_PKEY_get0_EC_KEY(pkey);
}

#else /* LUNA_NO_PKEY_STRUCTURE */

static RSA *LUNA_EVP_PKEY_get0_RSA(EVP_PKEY *pkey) {
   return (RSA*)pkey->pkey.rsa;
}

static DSA *LUNA_EVP_PKEY_get0_DSA(EVP_PKEY *pkey) {
   return (DSA*)pkey->pkey.dsa;
}

static EC_KEY *LUNA_EVP_PKEY_get0_EC_KEY(EVP_PKEY *pkey) {
   return (EC_KEY*)pkey->pkey.ec;
}

#endif /* LUNA_NO_PKEY_STRUCTURE */

static size_t LUNA_EC_GROUP_get_field_len(const EC_GROUP *group) {
   size_t field_len = ( EC_GROUP_get_degree(group) + 7) / 8;
   return field_len;
}

/* convert ecPoint from pkcs11 form to openssl form */
static int LUNA_o2i_ECPublicKey(EC_KEY **dsa, const unsigned char *in, const size_t inlen) {
   int ret = 0;
   const EC_GROUP *group = NULL;
   size_t field_len = 0;
   const unsigned char *out = 0;
   size_t outlen = 0;
   size_t len = 0;
   point_conversion_form_t form = 0;

   /* check input parameters */
   if (!dsa || !(*dsa) || !in || (inlen < 5))
      goto err;

   /* get group, field_len */
   if ((group = EC_KEY_get0_group(*dsa)) == NULL)
      goto err;
   if ((field_len = LUNA_EC_GROUP_get_field_len(group)) == 0)
      goto err;

   /* decode DER for new firmware, or, BER for old firmware */
   out = in;
   outlen = inlen;
   if (*out != 0x04)
      goto err;

   /* detected DER prefix or BER prefix; ie { 04 } */
   out++;
   outlen--;

   if (*out == 0x81) {
      /* detected new firmware, large keysize; ie { 04 81 LEN FORM X Y} */
      out++;
      outlen--;
   } else if (*out == 0x82) {
      if (*(out+1) != 0x00)
         goto err;
      /* detected old firmware, large keysize; ie { 04 82 00 LEN FORM X Y} */
      out += 2;
      outlen -= 2;
   }

   /* validate remaining { LEN FORM X Y } */
   len = (size_t)*out;
   out++;
   outlen--;

   form = (point_conversion_form_t)*out;
   if ( form != POINT_CONVERSION_UNCOMPRESSED )
      goto err;
   if ( len != outlen )
      goto err;
   if ( outlen != (1 + (field_len*2)) )
      goto err;

   /* finally convert { FORM X Y } to openssl form */
   if (o2i_ECPublicKey(dsa, &out, (long)outlen))
      ret = 1;

err:
   return ret;
}

/* convert ecPoint from openssl form to pkcs11 form (two forms, new and old firmware) */
static int LUNA_i2o_ECPublicKey(const EC_KEY *dsa, unsigned char **pout, unsigned char **pout2, int *plen2) {
    /* length of { FORM X Y } */
    int tmplen = i2o_ECPublicKey(dsa, NULL);
    if ( tmplen < 1 || tmplen > 255 )
        return 0;
    int isLarge = (tmplen >= 0x80);
    /* new firmware, large keysize; ie { 04 81 LEN FORM X Y} */
    unsigned char *out1 = (unsigned char *)OPENSSL_malloc(3 + tmplen);
    unsigned char *p1 = out1;
    /* old firmware, large keysize; ie { 04 82 00 LEN FORM X Y} */
    unsigned char *out2 = (unsigned char *)OPENSSL_malloc(4 + tmplen);
    unsigned char *p2 = out2;
    if (out1 == NULL || out2 == NULL) {
        if (out1)
            OPENSSL_free(out1);
        if (out2)
            OPENSSL_free(out2);
        return 0;
    }
    (*p1++) = 0x04;
    (*p2++) = 0x04;
    if (isLarge) {
        (*p1++) = 0x81;
        (*p2++) = 0x82;
        (*p2++) = 0x00;
    }
    (*p1++) = (unsigned char)tmplen;
    (*p2++) = (unsigned char)tmplen;
    unsigned char *tmpout = p1;
    (void)i2o_ECPublicKey(dsa, &tmpout);
    if ( ((point_conversion_form_t)*p1) != POINT_CONVERSION_UNCOMPRESSED ) {
        OPENSSL_free(out1);
        OPENSSL_free(out2);
        return 0;
    }
    memcpy(p2, p1, tmplen);
    p1 += tmplen;
    p2 += tmplen;
    if (pout2 != NULL) {
        *pout2 = out2;
        *plen2 = (int)(p2 - out2);
    } else {
        OPENSSL_free(out2);
    }
    *pout = out1;
    return (int)(p1 - out1);
}

static int LUNA_RSA_copy_from_pkey(RSA *rsa, const EVP_PKEY *pkey) {
   int rc = 0;
   /* get1_RSA is more backward portable to openssl 1.0.2 */
   RSA *rsa1 = (RSA *)EVP_PKEY_get1_RSA((EVP_PKEY *)pkey); /* get1 increments reference count */
   if (rsa1 == NULL)
      goto err;
   /* calling set increments the dirty count */
   if (LUNA_RSA_SET_n_e_d(rsa, BN_dup(LUNA_RSA_GET_n(rsa1)),
      BN_dup(LUNA_RSA_GET_e(rsa1)),
      BN_dup(LUNA_RSA_GET_d(rsa1))) <= 0)
      goto err;
   if (LUNA_RSA_SET_p_q(rsa, BN_dup(LUNA_RSA_GET_p(rsa1)),
      BN_dup(LUNA_RSA_GET_q(rsa1))) <= 0)
      goto err;
   if (LUNA_RSA_SET_dmp1_dmq1_iqmp(rsa, BN_dup(LUNA_RSA_GET_dmp1(rsa1)),
      BN_dup(LUNA_RSA_GET_dmq1(rsa1)),
      BN_dup(LUNA_RSA_GET_iqmp(rsa1))) <= 0)
      goto err;
   LUNA_RSA_OR_FLAGS(rsa, LUNA_RSA_GET_FLAGS(rsa1));
   rc = 1;
err:
   if (rsa1 != NULL) {
      RSA_free(rsa1); /* free decrements reference count */
   }
   return rc;
}

static int LUNA_DSA_copy_from_pkey(DSA *dsa, const EVP_PKEY *pkey) {
   int rc = 0;
   /* get1_DSA is more backward portable to openssl 1.0.2 */
   DSA *dsa1 = (DSA *)EVP_PKEY_get1_DSA((EVP_PKEY *)pkey); /* get1 increments reference count */
   if (dsa1 == NULL)
      goto err;
   /* calling set increments the dirty count */
   if (LUNA_DSA_SET_p_q_g(dsa, BN_dup(LUNA_DSA_GET_p(dsa1)),
      BN_dup(LUNA_DSA_GET_q(dsa1)),
      BN_dup(LUNA_DSA_GET_g(dsa1))) <= 0)
      goto err;
   if (LUNA_DSA_SET_pub_priv(dsa,
      BN_dup(LUNA_DSA_GET_pub_key(dsa1)),
      BN_dup(LUNA_DSA_GET_priv_key(dsa1))) <= 0)
      goto err;
   LUNA_DSA_OR_FLAGS(dsa, LUNA_DSA_GET_FLAGS(dsa1));
   rc = 1;
err:
   if (dsa1 != NULL) {
      DSA_free(dsa1); /* free decrements reference count */
   }
   return rc;
}

static int LUNA_EC_copy_from_pkey(EC_KEY *dsa, const EVP_PKEY *pkey) {
   int rc = 0;
   /* get1_EC_KEY is more backward portable */
   EC_KEY *dsa1 = (EC_KEY *)EVP_PKEY_get1_EC_KEY((EVP_PKEY *)pkey); /* get1 increments reference count */
   if (dsa1 == NULL)
      goto err;
   /* TODO: follow similar pattern for RSA, DSA */
   if (EC_KEY_copy(dsa, dsa1) == NULL)
      goto err;
   rc = 1;
err:
   if (dsa1 != NULL) {
      EC_KEY_free(dsa1); /* free decrements reference count */
   }
   return rc;
}

/*****************************************************************************/

/* Support C or C++ compiler in the field */
#ifdef __cplusplus
}
#endif
