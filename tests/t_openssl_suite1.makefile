#!/bin/false
##############################################################################
#
# This file is part of the "Luna OpenSSL for PQC" project.
#
# The " Luna OpenSSL for PQC " project is provided under the MIT license (see the
# following Web site for further details: https://mit-license.org/ ).
#
# Copyright © 2024 Thales Group
#
##############################################################################

#
# test all algorithms (ec, rsa, dsa) via openssl command-line
#
# optional tests available (pqc, cms)

# include common
#include t_openssl_common.include

# sub makefiles
EC_MAK=t_openssl_ec.makefile
RSA_MAK=t_openssl_rsa.makefile
DSA_MAK=t_openssl_dsa.makefile
PQC_MAK=t_openssl_pqc.makefile

# default target
default0: all
	@echo

all: prep0 ec0 rsa0 rsa_salt0 dsa0
	@echo

all_cms: rsa_cms0
	@echo

all_pqc: pqc0
	@echo

#
# test by key type
#

EC_KEY=key0

ec0:
	make -f $(EC_MAK) EC_KEY=$(EC_KEY) all
	@echo

RSA_KEY=key0

rsa0:
	make -f $(RSA_MAK) RSA_KEY=$(RSA_KEY) all
	@echo

DSA_KEY=key0

dsa0:
	make -f $(DSA_MAK) DSA_KEY=$(DSA_KEY) all
	@echo

PQCTYPE=dilithium3

pqc0:
	make -f $(PQC_MAK) PQCTYPE=$(PQCTYPE) all
	@echo

# prep temp files
prep0:
	echo "[TOP SECRET MESSAGE 1]" > message.txt
	echo "[PLAINTEXT MESSAGE 1]" > plain.txt
	@echo

prep1:
	echo -n sha1abcdefghijklmnop > message20.txt
	echo -n sha256abcdefghijklmnopqrstuvwxyz > message32.txt
	echo -n sha384abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP > message48.txt
	echo -n sha512abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456 > message64.txt
	@echo

# clean temp files
clean:
	rm -f message.txt plain.txt
	make -f $(EC_MAK) clean
	make -f $(RSA_MAK) clean
	make -f $(DSA_MAK) clean
	make -f $(PQC_MAK) clean
	@echo

# clean hsm objects
cleanhsm:
	make -f $(EC_MAK) cleanhsm
	make -f $(RSA_MAK) cleanhsm
	make -f $(DSA_MAK) cleanhsm
	make -f $(PQC_MAK) cleanhsm
	@echo

################################################################################
#
# more specialized testcases
#

# TODO: cms not working in openssl3 for software keys so hardware has no chance!
rsa_cms0:
	make -f $(RSA_MAK) BASE_MD=sha256  all_cms
	@echo

TARGET_SALT=sign1 sign2

# vary the salt
rsa_salt0:
	make -f $(RSA_MAK) PSS_SALT=digest  $(TARGET_SALT)
	make -f $(RSA_MAK) PSS_SALT=max  $(TARGET_SALT)
	make -f $(RSA_MAK) PSS_SALT=auto  $(TARGET_SALT)
	make -f $(RSA_MAK) PSS_SALT=0  $(TARGET_SALT)
	make -f $(RSA_MAK) PSS_SALT=64  $(TARGET_SALT)
	@echo

#eof

