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
# PURPOSE:
#
#   build application within unix environment
#

# Name of application:
APPNAME=sample_passdll
APP_INSTALL_DOS=""
APP_INSTALL_UNIX=""

# default target:
default all:
	APP_INSTALL_DOS=$(APP_INSTALL_DOS) APP_INSTALL_UNIX=$(APP_INSTALL_UNIX) sh configure.sh
	@echo

# clean target:
clean cleanall:
	rm -f a.out core 
	rm -f $(APPNAME).so $(APPNAME).sl 
	rm -f $(APPNAME).dll $(APPNAME).obj 
	rm -f $(APPNAME).dll.manifest 
	@echo

#eof

