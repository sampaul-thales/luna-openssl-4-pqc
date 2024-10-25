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
include ..\win-cl-ssl.mk
# NOTE: engines are typically compiled without unicode
# for reference: CNF_CPPFLAGS=$(CNF_CPPFLAGS_BASE) -D"UNICODE" -D"_UNICODE"

# flags consistent with luna
INCLUDES=/I$(CFG_INSTALLDIR)\include
LIBCRYPTO=libcrypto.lib
LIB2=$(CFG_INSTALLDIR)\lib\$(LIBCRYPTO)

# flags consistent with gem
APPNAME=gem
CL_OPTS32=$(DSO_CPPFLAGS) $(DSO_CFLAGS) /D"OS_WIN32"
CL_OPTS64=$(DSO_CPPFLAGS) $(DSO_CFLAGS) /D"OS_WIN32" /D"OS_WIN64"
LD_OPTS32=$(DSO_LDFLAGS)
LD_OPTS64=$(DSO_LDFLAGS) /machine:amd64
LIBSTD=$(DSO_EX_LIBS)

default0: default64

default32:
	$(CC) e_gem.c $(CL_OPTS32) $(INCLUDES) /link $(LD_OPTS32) /DEF:gem.def /OUT:gem.dll $(LIB2) $(LIBSTD)

default64:
	$(CC) e_gem.c $(CL_OPTS64) $(INCLUDES) /link $(LD_OPTS64) /DEF:gem.def /OUT:gem.dll $(LIB2) $(LIBSTD)

clean:
	$(RM) gem.dll gem.pdb
	$(RM) e_gem.obj

install:
	$(CP) "gem.dll" "$(CFG_INSTALLDIR)/lib/engines-3/"
	$(CP) "gem.pdb" "$(CFG_INSTALLDIR)/lib/engines-3/"

uninstall:
	$(RM) "$(CFG_INSTALLDIR)/lib/engines-3/gem.dll"
	$(RM) "$(CFG_INSTALLDIR)/lib/engines-3/gem.pdb"

.PHONY: default0 default32 default64 clean install uninstall

#eof
