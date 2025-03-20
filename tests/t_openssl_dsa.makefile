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
# test dsa keygen
# and dsa sign
#

# include provider, keyform, engine
include t_openssl_common.include

# sender/recipient cert file and key file
KEYF1=tmpdsa.pkey
CERTF1=tmpdsa.crt

# CA cert file
# if using self-signed cert then
CERTF2=$(CERTF1)
# otherwise
#CERTF2=tmpdsaCA.crt

# default target
default0: all
	@echo

#FIXME:DSA_KEY=key0
DSA_KEY=key1

all: $(DSA_KEY) check0 req0 sign1 param0
	@echo

# FIXME: broken due to provider load order
all_dgst: check0 sign2
	@echo

# generate key
# NOTE: for keypair in HSM, set GemEngine = { EnableDsaGenKeyPair = 1; }.
#   NOTE: feature is broken in openssl3, for both engine and provider.
# NOTE: otherwise, use sautil to generate keypair
# NOTE: dsa params must be passed on the command-line
# NOTE: use keysize 3072:256 to prove we can override the default of 2048:224

# first choice: generate key via openssl genpkey (openssl3, openssl 1.1.1)
key0: tmpdsa.pkey.0

tmpdsa.pkey.0: tmpdsa.foo
	openssl genpkey $(HW_ENGINE) -out tmpdsa.pkey -paramfile tmpdsaparam.pem
	cp tmpdsa.pkey tmpdsa.pkey.0
	@echo '--------'

check0:
	openssl pkey -check -in tmpdsa.pkey $(HW_ENGINE)
	@echo '--------'

# second choice: generate key via sautil
key1: tmpdsa.pkey.1

tmpdsa.pkey.1: tmpdsa.foo
	sautil -v -s 0 -i 0:0 -o -q -c -d 3072:tmpdsaparam.pem -f tmpdsa.pkey
	cp tmpdsa.pkey tmpdsa.pkey.1
	@echo '--------'

# last choice: generate key via openssl gendsa (openssl 1.0.2)
tmpdsa.pkey.2: tmpdsa.foo
	openssl gendsa $(HW_ENGINE) -out tmpdsa.pkey tmpdsaparam.pem
	cp tmpdsa.pkey tmpdsa.pkey.2
	@echo '--------'

tmpdsa.foo:
		touch tmpdsa.foo

# NOTE: set digest to prove we can override the default of sha256
# TODO: ... however, openssl cannot set it stronger than sha256 for DSA, so use sha224 instead
BASE_MD=sha224

PKCS_MD=$(BASE_MD)
#SIGOPT_REQ=-sigopt digest:$(PKCS_MD)
SIGOPT_REQ=
#SIGOPT_X509=-sigopt digest:$(PKCS_MD)
SIGOPT_X509=

# sign cert request
# NOTE: it is discouraged to add options after "-pkeyopt OPTIONS" or "-sigopt OPTIONS"
req0:
	rm -f tmp.csr tmpdsa.crt
	openssl req $(HW_ENGINE) $(HW_KEYFORM) -$(PKCS_MD) -verbose -new -nodes -key $(KEYF1) -out tmp.csr -verify -subj "/CN=t_openssl_dsa" $(SIGOPT_REQ)
	openssl x509 $(HW_ENGINE) $(HW_KEYFORM) -$(PKCS_MD) -trustout -outform PEM -req -days 90 -in tmp.csr -signkey $(KEYF1) -out tmpdsa.crt $(SIGOPT_X509)
	@echo '--------'

# extra tests
# the engine should not block dsa param generation
# choose a small keysize to avoid the long wait
param0:
	openssl genpkey -genparam $(HW_ENGINE) -algorithm DSA -out tmp.tmp -pkeyopt dsa_paramgen_bits:1024 -pkeyopt dsa_paramgen_q_bits:160
	@echo '--------'

DSA_MD=$(BASE_MD)
PKEYOPT_DSA=-pkeyopt digest:$(DSA_MD)
#SIGOPT_DSA=-sigopt digest:$(DSA_MD)
SIGOPT_DSA=

# using pkeyutl
# digest in software, sign in hardware, verify in software
sign1:
	openssl dgst -$(DSA_MD) -out message.dig -binary message.txt
	openssl pkeyutl $(HW_ENGINE) $(HW_KEYFORM) -sign -in message.dig -inkey tmpdsa.pkey -out message.sig $(PKEYOPT_DSA)
	openssl pkeyutl $(SW_ENGINE) -verify -in message.dig -inkey tmpdsa.pkey -sigfile message.sig $(PKEYOPT_DSA)
	@echo '--------'

# using dgst
# digest in software, sign in hardware, verify in software
sign2:
	openssl dgst $(HW_ENGINE) $(HW_KEYFORM) -sign tmpdsa.pkey -$(DSA_MD) -out message.sig $(SIGOPT_DSA)  message.txt
	openssl dgst $(SW_ENGINE) -prverify tmpdsa.pkey -$(DSA_MD) -signature message.sig $(SIGOPT_DSA)  message.txt
	@echo '--------'

# clean all temp files
clean:
	rm -f tmpdsa.pkey tmp.csr
	rm -f tmpdsa.foo tmpdsa.pkey.0 tmpdsa.pkey.1 tmpdsa.pkey.2
	@echo

# clean hsm objects
cleanhsm:
	sautil -v -s 0 -i 0:0 -o -q -c -d 0 -f tmpdsa.pkey
	@echo

#eof

