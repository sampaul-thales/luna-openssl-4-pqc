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

# flags consistent with openssl
include ..\..\win-cl-ssl.mk

# flags consistent with luna
INCLUDES_ENGINE=-I..\..\engine
INCLUDES=/I$(CFG_INSTALLDIR)\include $(INCLUDES_ENGINE)
LIBCRYPTO=libcrypto.lib
LIB2=$(CFG_INSTALLDIR)\lib\$(LIBCRYPTO)
SSL_PATH=$(CFG_INSTALLDIR)

# flags consistent with engineperf
APPNAME=engineperf
CL_OPTS32=$(BIN_CPPFLAGS) $(BIN_CFLAGS) /D"OS_WIN32"
CL_OPTS64=$(BIN_CPPFLAGS) $(BIN_CFLAGS) /D"OS_WIN32" /D"OS_WIN64"
LD_OPTS32=$(BIN_LDFLAGS)
LD_OPTS64=$(BIN_LDFLAGS) /machine:amd64
LIBSTD=$(BIN_EX_LIBS)

default0: default64

default32:
	$(CC) $(CL_OPTS32) $(APPNAME).c $(INCLUDES) /link $(LD_OPTS32) /out:$(APPNAME).exe $(APPNAME).obj $(LIB2) $(LIBSTD)

default64:
	$(CC) $(CL_OPTS64) $(APPNAME).c $(INCLUDES) /link $(LD_OPTS64) /out:$(APPNAME).exe $(APPNAME).obj $(LIB2) $(LIBSTD)

clean:
	$(RM) $(APPNAME).exe
	$(RM) $(APPNAME).pdb
	$(RM) $(APPNAME).obj

.PHONY: default0 default32 default64 clean fips64 fips32

#
# The following examples show how to build a fips-enabled application
# using a fips-capable openssl.
#
# Assuming openssl version 1.0.2u and openssl-fips-2.0.16.
#

FIPSDIR=\usr\local\ssl\fips-2.0

fips64:
	$(CC) $(CL_OPTS64) /c /I "$(SSL_PATH)\include" $(APPNAME).c 
	SET FIPSDIR=$(FIPSDIR)
	SET FIPS_LINK=$(LD)
	SET FIPS_CC=$(CC)
	SET FIPS_CC_ARGS=/Fofips_premain.obj /Zl /Zi -c
	SET PREMAIN_DSO_EXE=
	SET FIPS_TARGET=$(APPNAME).exe
	SET FIPS_SHA1_EXE=$(FIPSDIR)\bin\fips_standalone_sha1.exe
	SET FIPSLIB_D=$(FIPSDIR)\lib
	perl $(FIPSDIR)\bin\fipslink.pl  /nologo /subsystem:console /opt:ref /debug /map /out:$(APPNAME).exe 	setargv.obj $(APPNAME).obj fips_premain.obj "$(SSL_PATH)\lib\ssleay32.lib" "$(SSL_PATH)\lib\libeay32.lib" "$(FIPSDIR)\lib\fipscanister.lib" $(LIBSTD)

fips32:
	$(CC) $(CL_OPTS32) /c /I "$(SSL_PATH)\include" $(APPNAME).c 
	SET FIPSDIR=$(FIPSDIR)
	SET FIPS_LINK=$(LD)
	SET FIPS_CC=$(CC)
	SET FIPS_CC_ARGS=/Fofips_premain.obj /Zl /Zi -c
	SET PREMAIN_DSO_EXE=
	SET FIPS_TARGET=$(APPNAME).exe
	SET FIPS_SHA1_EXE=$(FIPSDIR)\bin\fips_standalone_sha1.exe
	SET FIPSLIB_D=$(FIPSDIR)\lib
	perl $(FIPSDIR)\bin\fipslink.pl  /nologo /subsystem:console /opt:ref /debug /map /out:$(APPNAME).exe 	setargv.obj $(APPNAME).obj fips_premain.obj "$(SSL_PATH)\lib\ssleay32.lib" "$(SSL_PATH)\lib\libeay32.lib" "$(FIPSDIR)\lib\fipscanister.lib" $(LIBSTD)

#eof
