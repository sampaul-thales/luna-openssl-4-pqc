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
APPNAME=sautil
OPENSSL_INCLUDES?="/usr/include"
OPENSSL_LIBS?=""

# default target:
default all:
	OPENSSL_INCLUDES=$(OPENSSL_INCLUDES) OPENSSL_LIBS=$(OPENSSL_LIBS) sh configure.sh
	@echo

# clean target:
clean:
	rm -f a.out core 
	rm -f $(APPNAME) $(APPNAME).exe $(APPNAME).obj 
	rm -f $(APPNAME).exe.manifest 
	@echo

.PHONY: default all clean

#eof

