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

# Name of application:
APPNAME=engineperf
OPENSSL_INCLUDES?="/usr/include"
OPENSSL_LIBS?=""
LUNA_CONFIG_FIPS?=no
FIPS_PREFIX?=/usr/local

# default target:
default all:
	OPENSSL_INCLUDES=$(OPENSSL_INCLUDES) OPENSSL_LIBS=$(OPENSSL_LIBS) LUNA_CONFIG_FIPS=$(LUNA_CONFIG_FIPS) FIPS_PREFIX=$(FIPS_PREFIX) sh configure.sh
	@echo

# clean target:
clean cleanall:
	rm -f a.out core 
	rm -f $(APPNAME) $(APPNAME).exe $(APPNAME).obj 
	@echo

#eof

