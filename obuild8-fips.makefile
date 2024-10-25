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
# Description: Build OpenSSL FIPS Module and OpenSSL for Windows platform only
#


# NOTE: the following makefile supports openssl 1.0.2 plus fips module 2.0 (legacy).
VERSION=1.0.2u
CFG_FIPS=fips --withfipsdir=c:\usr\local\ssl\fips-2.0
OSSLVERFIPS=fips-2.0.16


## User-configurable variables:
CC=cl
CXX=cl
OUTPATH=FOOPATH
CFG_TGT=DEFAULT
CFG_OPTS=
CFG_SUFFIX=win32
CFG_BITS=32


## dll or not
DLLEX=dll


## Readonly variables:
FILENAME=obuild8-fips.makefile


## OpenSSL config options:
# NOTE: set --openssldir and --prefix to the same value.
CFG_BASEOPTS_NO=no-asm
CFG_BASEOPTS_YES=$(CFG_FIPS)
CFG_INSTALLDIR=c:\cygwin\usr\local\ssl
CFG_BASEOPTS=$(CFG_BASEOPTS_YES)  $(CFG_BASEOPTS_NO)  --openssldir=$(CFG_INSTALLDIR) --prefix=$(CFG_INSTALLDIR)
CFG_SAUTILDIR=$(CFG_INSTALLDIR)\sautil


## default:
default:
	@echo "Usage:"
	@echo
	@echo "  nmake /f $(FILENAME) cleanall"
	@echo
	@echo "  nmake /f $(FILENAME) all-win32  CFG_SUFFIX=win32"
	@echo "or "
	@echo "  nmake /f $(FILENAME) all-win64  CFG_SUFFIX=win64"
	@echo
	@echo
	@echo "NOTE: requires some UNIX commands on Windows platform."
	@echo


## unpack source:
# FIXME: tar mishandles symbolic links!
unpack.tmp:
	if not exist openssl-build  mkdir openssl-build
	if not exist LUNAlocal  mkdir LUNAlocal
	cd openssl-build 
	  copy ..\openssl-$(VERSION).tar.gz  .\foo.tar.gz
	  -tar xzf .\foo.tar.gz
	  cd ..
	cd openssl-build
	  copy ..\openssl-$(OSSLVERFIPS).tar.gz  .\foo2.tar.gz
	  -tar xzf .\foo2.tar.gz
	  cd ..
	touch unpack.tmp
	@echo


## patch source:
# NOTE: nothing to patch
patch.tmp:  unpack.tmp
	touch patch.tmp
	@echo


## Win32 hacks
# reference: ms/do_ms.bat
cfg-win32.tmp: patch.tmp
	cd "openssl-build\openssl-$(VERSION)"
	  perl Configure VC-WIN32  $(CFG_BASEOPTS) $(CFG_OPTS)
	  perl util\mkfiles.pl  > MINFO
	  perl util\mk1mf.pl $(CFG_BASEOPTS_NO) VC-WIN32  > ms\nt.mak
	  perl util\mk1mf.pl dll $(CFG_BASEOPTS_NO) VC-WIN32  > ms\ntdll.mak
	  perl util\mkdef.pl 32 libeay  > ms\libeay32.def
	  perl util\mkdef.pl 32 ssleay  > ms\ssleay32.def
	  cd ..\..
	touch cfg-win32.tmp cfg.tmp
	@echo


## Win64 hacks
# reference: ms/do_win64a.bat
cfg-win64.tmp: patch.tmp
	cd "openssl-build\openssl-$(VERSION)"
	  if not exist "masm"     mkdir "masm"
	  if not exist "ms\masm"  mkdir "ms\masm"
	  perl Configure VC-WIN64A  $(CFG_BASEOPTS) $(CFG_OPTS)
	  perl util\mkfiles.pl  > MINFO
	  perl ms\uplink-x86_64.pl masm > ms\uptable.asm
	    ml64 -c -Foms\uptable.obj ms\uptable.asm
	  perl util\mk1mf.pl $(CFG_BASEOPTS_NO) VC-WIN64A  > ms\nt.mak
	  perl util\mk1mf.pl dll $(CFG_BASEOPTS_NO) VC-WIN64A  > ms\ntdll.mak
	  perl util\mkdef.pl 32 libeay  > ms\libeay32.def
	  perl util\mkdef.pl 32 ssleay  > ms\ssleay32.def
	  cd ..\..
	touch cfg-win64.tmp cfg.tmp
	@echo

## build and install (Win32/Win64):
module.tmp: cfg.tmp
	cd "openssl-build\openssl-$(OSSLVERFIPS)"
	  cmd.exe /C ms\do_fips no-asm
	  cd ..\..
	touch module.tmp
	@echo


## build and install (Win32/Win64):
guts-winxx: module.tmp
	rm -rf "$(CFG_INSTALLDIR)"
	if not exist "$(CFG_INSTALLDIR)"                   mkdir "$(CFG_INSTALLDIR)"
	if not exist "$(CFG_INSTALLDIR)\include"           mkdir "$(CFG_INSTALLDIR)\include"
	if not exist "$(CFG_INSTALLDIR)\include\openssl"   mkdir "$(CFG_INSTALLDIR)\include\openssl"
	if not exist "$(CFG_INSTALLDIR)\lib"               mkdir "$(CFG_INSTALLDIR)\lib"
	if not exist "$(CFG_INSTALLDIR)\lib\engines"       mkdir "$(CFG_INSTALLDIR)\lib\engines"
	if not exist "$(CFG_INSTALLDIR)\bin"               mkdir "$(CFG_INSTALLDIR)\bin"
	@echo
	cd "openssl-build\openssl-$(VERSION)"
	  nmake /f ms\nt$(DLLEX).mak
	  cd ..\.. 
	@echo
	copy "openssl-build\openssl-$(VERSION)\crypto\ec\ec_lcl.h"     "$(CFG_INSTALLDIR)\include\openssl\"
	if exist "openssl-build\openssl-$(VERSION)\crypto\ecdsa\ecs_locl.h"   copy "openssl-build\openssl-$(VERSION)\crypto\ecdsa\ecs_locl.h"   "$(CFG_INSTALLDIR)\include\openssl\"
	copy "openssl-build\openssl-$(VERSION)\inc32\openssl\*.h"   "$(CFG_INSTALLDIR)\include\openssl\"
	copy "openssl-build\openssl-$(VERSION)\out32$(DLLEX)\libeay*32.dll*"  "$(CFG_INSTALLDIR)\lib\"
	copy "openssl-build\openssl-$(VERSION)\out32$(DLLEX)\libeay*32.lib*"  "$(CFG_INSTALLDIR)\lib\"
	copy "openssl-build\openssl-$(VERSION)\out32$(DLLEX)\ssleay*32.dll*"  "$(CFG_INSTALLDIR)\lib\"
	copy "openssl-build\openssl-$(VERSION)\out32$(DLLEX)\ssleay*32.lib*"  "$(CFG_INSTALLDIR)\lib\"
	copy "openssl-build\openssl-$(VERSION)\out32$(DLLEX)\libeay*32.dll*"  "$(CFG_INSTALLDIR)\bin\"
	copy "openssl-build\openssl-$(VERSION)\out32$(DLLEX)\libeay*32.lib*"  "$(CFG_INSTALLDIR)\bin\"
	copy "openssl-build\openssl-$(VERSION)\out32$(DLLEX)\ssleay*32.dll*"  "$(CFG_INSTALLDIR)\bin\"
	copy "openssl-build\openssl-$(VERSION)\out32$(DLLEX)\ssleay*32.lib*"  "$(CFG_INSTALLDIR)\bin\"
	copy "openssl-build\openssl-$(VERSION)\out32$(DLLEX)\openssl.exe"   "$(CFG_INSTALLDIR)\bin\"
	copy "openssl-build\openssl-$(VERSION)\apps\openssl.cnf"    "$(CFG_INSTALLDIR)\"
	@echo

ssl-tar:
	rm -f  LUNAlocal\ssl-$(CFG_SUFFIX)-openssl-$(VERSION).tar.gz
	tar czf LUNAlocal\ssl-$(CFG_SUFFIX)-openssl-$(VERSION).tar.gz  $(CFG_INSTALLDIR)
	@echo "###########################################################################"
	@dir   LUNAlocal\ssl-$(CFG_SUFFIX)-openssl-$(VERSION).tar.gz
	@echo "###########################################################################"
	@echo
	rm -f  LUNAlocal\module-$(CFG_SUFFIX)-$(OSSLVERFIPS).tar.gz
	tar czf LUNAlocal\module-$(CFG_SUFFIX)-$(OSSLVERFIPS).tar.gz  c:/usr/local/ssl/fips-2.0
	@echo "###########################################################################"
	@dir   LUNAlocal\module-$(CFG_SUFFIX)-$(OSSLVERFIPS).tar.gz
	@echo "###########################################################################"
	touch build.tmp binsave.tmp bininstall.tmp
	@echo

engine-win32:
	cd "engine"
	  nmake /f engine.mak clean default CFG_INSTALLDIR=$(CFG_INSTALLDIR) LIBCRYPTO=libeay32.lib
	  copy "gem.dll"   "$(CFG_INSTALLDIR)\lib\engines\"
	  cd ..

engine-win64:
	cd "engine"
	  nmake /f engine.mak clean default64 CFG_INSTALLDIR=$(CFG_INSTALLDIR) LIBCRYPTO=libeay32.lib
	  copy "gem.dll"   "$(CFG_INSTALLDIR)\lib\engines\"
	  cd ..

all-win32:  cfg-win32.tmp guts-winxx engine-win32 ssl-tar
	rm -rf "$(CFG_SAUTILDIR)"
	if not exist "$(CFG_SAUTILDIR)"                   mkdir "$(CFG_SAUTILDIR)"
	if not exist "$(CFG_SAUTILDIR)\bin"               mkdir "$(CFG_SAUTILDIR)\bin"
	@echo
	echo "===================="
	cd "gem-samples\sautil"
	  nmake /f sautil.mak clean default CFG_INSTALLDIR=$(CFG_INSTALLDIR) LIBCRYPTO=libeay32.lib
	  copy "sautil.exe"  "$(CFG_SAUTILDIR)\bin\"
	  cd ..\..
	@echo
	rm -f  LUNAlocal\sautil-$(CFG_SUFFIX)-openssl-$(VERSION).tar.gz
	tar czf LUNAlocal\sautil-$(CFG_SUFFIX)-openssl-$(VERSION).tar.gz  $(CFG_SAUTILDIR)
	@echo "###########################################################################"
	@dir   LUNAlocal\sautil-$(CFG_SUFFIX)-openssl-$(VERSION).tar.gz
	@echo "###########################################################################"
	@echo


all-win64:  cfg-win64.tmp guts-winxx engine-win64 ssl-tar
	rm -rf "$(CFG_SAUTILDIR)"
	if not exist "$(CFG_SAUTILDIR)"                   mkdir "$(CFG_SAUTILDIR)"
	if not exist "$(CFG_SAUTILDIR)\bin"               mkdir "$(CFG_SAUTILDIR)\bin"
	@echo
	cd "gem-samples\sautil"
	  nmake /f sautil.mak clean default64 CFG_INSTALLDIR=$(CFG_INSTALLDIR) LIBCRYPTO=libeay32.lib
	  copy "sautil.exe"  "$(CFG_SAUTILDIR)\bin\"
	  cd ..\..
	@echo
	rm -f  LUNAlocal\sautil-$(CFG_SUFFIX)-openssl-$(VERSION).tar
	rm -f  LUNAlocal\sautil-$(CFG_SUFFIX)-openssl-$(VERSION).tar.gz
	tar czf LUNAlocal\sautil-$(CFG_SUFFIX)-openssl-$(VERSION).tar.gz  $(CFG_SAUTILDIR)
	@echo "###########################################################################"
	@dir   LUNAlocal\sautil-$(CFG_SUFFIX)-openssl-$(VERSION).tar.gz
	@echo "###########################################################################"
	@echo


## clean:
cleantemp:
	rm -f cfg.tmp build.tmp binsave.tmp bininstall.tmp
	rm -f cfg-win32.tmp MINFO ms\nt.mak ms\libeay32.def ms\ssleay32.def
	rm -f cfg-win64.tmp MINFO ms\nt.mak ms\libeay64.def ms\ssleay64.def
	rm -f ms\ntdll.mak
	rm -f module.tmp
	@echo


cleanall clean: cleantemp
	rm -f unpack*.tmp patch*.tmp repack*.tmp
	rm -rf "openssl-build\openssl-$(VERSION)"
	rm -rf "openssl-build\openssl-$(OSSLVERFIPS)"
	rm -f "openssl-build\foo.tar.gz"
	@echo


#eof
