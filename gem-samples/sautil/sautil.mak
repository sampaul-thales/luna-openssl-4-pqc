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

# flags consistent with sautil
APPNAME=sautil
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

install:
	$(CP) "$(APPNAME).exe" "$(CFG_INSTALLDIR)/sautil/bin/"
	$(CP) "$(APPNAME).pdb" "$(CFG_INSTALLDIR)/sautil/bin/"

uninstall:
	$(RM) "$(CFG_INSTALLDIR)/sautil/bin/$(APPNAME).exe"
	$(RM) "$(CFG_INSTALLDIR)/sautil/bin/$(APPNAME).pdb"

.PHONY: default0 default32 default64 clean install uninstall

# eof
