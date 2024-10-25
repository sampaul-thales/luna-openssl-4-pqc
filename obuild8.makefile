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
# Description: Build OpenSSL for Windows platform only
#


# NOTE: the following makefile supports openssl 1.1.1.
VERSION=1.1.1w
CFG_FIPS=


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
FILENAME=obuild8.makefile


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
	touch unpack.tmp
	@echo


## patch source:
# NOTE: nothing to patch
patch.tmp:  unpack.tmp
	touch patch.tmp
	@echo


## Win32 hacks
cfg-win32.tmp: patch.tmp
	cd "openssl-build\openssl-$(VERSION)"
	  perl Configure VC-WIN32  $(CFG_BASEOPTS) $(CFG_OPTS) -D_WIN32_WINNT=0x0501
	  cd ..\..
	touch cfg-win32.tmp cfg.tmp
	@echo


## Win64 hacks
cfg-win64.tmp: patch.tmp
	cd "openssl-build\openssl-$(VERSION)"
	  perl Configure VC-WIN64A  $(CFG_BASEOPTS) $(CFG_OPTS)
	  cd ..\..
	touch cfg-win64.tmp cfg.tmp
	@echo

## build and install (Win32/Win64):
# NOTE: The build procedure for 1.1.0 has changed to:
#   perl Configure VC-WIN32 --prefix=xx --openssldir=xx
#   nmake
#   nmake test
#   nmake install_sw
# NOTE: copying file "ec_lcl.h" is not necessary for openssl 1.1.0.
# NOTE: file "ecs_locl.h" does not exist in openssl 1.1.0.
guts-winxx:
	rm -rf "$(CFG_INSTALLDIR)"
	if not exist "$(CFG_INSTALLDIR)"                   mkdir "$(CFG_INSTALLDIR)"
	if not exist "$(CFG_INSTALLDIR)\include"           mkdir "$(CFG_INSTALLDIR)\include"
	if not exist "$(CFG_INSTALLDIR)\include\openssl"   mkdir "$(CFG_INSTALLDIR)\include\openssl"
	if not exist "$(CFG_INSTALLDIR)\lib"               mkdir "$(CFG_INSTALLDIR)\lib"
	if not exist "$(CFG_INSTALLDIR)\lib\engines-1_1"   mkdir "$(CFG_INSTALLDIR)\lib\engines-1_1"
	if not exist "$(CFG_INSTALLDIR)\bin"               mkdir "$(CFG_INSTALLDIR)\bin"
	@echo
	cd "openssl-build\openssl-$(VERSION)"
	  nmake
	  nmake install_sw
	  cd ..\..
	@echo

ssl-tar:
	rm -f  LUNAlocal\ssl-$(CFG_SUFFIX)-openssl-$(VERSION).tar.gz
	tar czf LUNAlocal\ssl-$(CFG_SUFFIX)-openssl-$(VERSION).tar.gz  $(CFG_INSTALLDIR)
	@echo "###########################################################################"
	@dir   LUNAlocal\ssl-$(CFG_SUFFIX)-openssl-$(VERSION).tar.gz
	@echo "###########################################################################"
	touch build.tmp binsave.tmp bininstall.tmp
	@echo

engine-win32:
	cd "engine"
	nmake /f engine.mak clean default CFG_INSTALLDIR=$(CFG_INSTALLDIR)
	copy "gem.dll"   "$(CFG_INSTALLDIR)\lib\engines-1_1\"
	cd ..

engine-win64:
	cd "engine"
	nmake /f engine.mak clean default64 CFG_INSTALLDIR=$(CFG_INSTALLDIR)
	copy "gem.dll"   "$(CFG_INSTALLDIR)\lib\engines-1_1\"
	cd ..

all-win32:  cfg-win32.tmp guts-winxx engine-win32 ssl-tar
	rm -rf "$(CFG_SAUTILDIR)"
	if not exist "$(CFG_SAUTILDIR)"                   mkdir "$(CFG_SAUTILDIR)"
	if not exist "$(CFG_SAUTILDIR)\bin"               mkdir "$(CFG_SAUTILDIR)\bin"
	@echo
	cd "gem-samples\sautil"
	  nmake /f sautil.mak clean default CFG_INSTALLDIR=$(CFG_INSTALLDIR)
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
	  nmake /f sautil.mak clean default64 CFG_INSTALLDIR=$(CFG_INSTALLDIR)
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
	@echo


cleanall clean: cleantemp
	rm -f unpack*.tmp patch*.tmp repack*.tmp
	rm -rf "openssl-build\openssl-$(VERSION)"
	rm -f "openssl-build\foo.tar.gz"
	@echo


#eof
