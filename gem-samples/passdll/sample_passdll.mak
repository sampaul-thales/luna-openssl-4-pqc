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

# flags consistent with sample_passdll
APPNAME=sample_passdll
CL_OPTS32=$(DSO_CPPFLAGS) $(DSO_CFLAGS) /D"OS_WIN32"
CL_OPTS64=$(DSO_CPPFLAGS) $(DSO_CFLAGS) /D"OS_WIN32" /D"OS_WIN64"
LD_OPTS32=$(DSO_LDFLAGS)
LD_OPTS64=$(DSO_LDFLAGS) /machine:amd64
LIBSTD=$(DSO_EX_LIBS)

default0: default64

default32:
	$(CC) $(CL_OPTS32) $(APPNAME).c $(INCLUDES) /link $(LD_OPTS32) /out:$(APPNAME).dll /DEF:"$(APPNAME).def" $(APPNAME).obj

default64:
	$(CC) $(CL_OPTS64) $(APPNAME).c $(INCLUDES) /link $(LD_OPTS64) /out:$(APPNAME).dll /DEF:"$(APPNAME).def" $(APPNAME).obj

clean:
	$(RM) $(APPNAME).dll
	$(RM) $(APPNAME).pdb
	$(RM) $(APPNAME).obj

.PHONY: default0 default32 default64 clean

#eof
