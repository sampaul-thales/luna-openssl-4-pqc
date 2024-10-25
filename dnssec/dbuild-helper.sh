#!/bin/sh
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
# this is helper script for makefile dbuild.makefile.
#

. ../dbuild.inc

echo "Command-line... $0"

CONFIG_IN=../../config.in
#if the configuration in file exists, source it
if [ -f $CONFIG_IN ]; then
        . $CONFIG_IN
fi

#SFNT_PROJ:
echo "SFNT_PROJ... $SFNT_PROJ"
if [ "$SFNT_PROJ" != "dnssec" ]; then
  if [ "$SFNT_PROJ" != "dnssec1" ]; then
    if [ "$SFNT_PROJ" != "dnssec2" ]; then
      exit 1
    fi
  fi
fi


#--libxml2-config:
if [ "$1" = "--libxml2-config" ]; then
  ./configure --prefix=/opt/SFNT$SFNT_PROJ/libxml2
  RC0=$?
  exit $RC0
fi


#--libxml2-install:
# NOTE: not all the header files get installed; e.g., on AIX.
#   e.g.,
#   /usr/bin/install -c -m 644 SAX.h entities.h encoding.h parser.h parserInternals.h xmlerror.h HTMLparser.h HTMLtree.h debugXML.h tree.h list.h hash.h xpath.h xpathInternals.h xpointer.h xinclude.h xmlIO.h xmlmemory.h nanohttp.h nanoftp.h uri.h valid.h xlink.h xmlversion.h DOCBparser.h catalog.h threads.h globals.h c14n.h xmlautomata.h xmlregexp.h xmlmodule.h xmlschemas.h schemasInternals.h xmlschemastypes.h xmlstring.h xmlunicode.h xmlreader.h relaxng.h dict.h '/opt/SFNTdnssec1/libxml2/include/libxml2/libxml'.
#   /usr/bin/install -c -m 644 SAX2.h xmlexports.h xmlwriter.h chvalid.h pattern.h xmlsave.h schematron.h '/opt/SFNTdnssec1/libxml2/include/libxml2/libxml'.
if [ "$1" = "--libxml2-install" ]; then
  TMP_HEADERS1="SAX.h entities.h encoding.h parser.h parserInternals.h xmlerror.h HTMLparser.h HTMLtree.h debugXML.h tree.h list.h hash.h xpath.h xpathInternals.h xpointer.h xinclude.h xmlIO.h xmlmemory.h nanohttp.h nanoftp.h uri.h valid.h xlink.h xmlversion.h DOCBparser.h catalog.h threads.h globals.h c14n.h xmlautomata.h xmlregexp.h xmlmodule.h xmlschemas.h schemasInternals.h xmlschemastypes.h xmlstring.h xmlunicode.h xmlreader.h relaxng.h dict.h"
  TMP_HEADERS2="SAX2.h xmlexports.h xmlwriter.h chvalid.h pattern.h xmlsave.h schematron.h"
  for tmpfilex in $TMP_HEADERS1 $TMP_HEADERS2
  do
    if [ ! -f /opt/SFNT$SFNT_PROJ/libxml2/include/libxml2/libxml/$tmpfilex ]; then
      cp include/libxml/$tmpfilex  /opt/SFNT$SFNT_PROJ/libxml2/include/libxml2/libxml/$tmpfilex
    fi
  done
  exit 0
fi


#--ldns-config:
# NOTE: missing non-standard libraries; e.g., on Solaris.
if [ "$1" = "--ldns-config" ]; then
  if [ "`uname -s`" = "SunOS" ]; then
    ./configure --prefix=/opt/SFNT$SFNT_PROJ/ldns --disable-shared --with-ssl=$PREFIX/ssl LDFLAGS="-lsocket -lnsl"
    RC0=$?
    exit $RC0
  fi
  ./configure --prefix=/opt/SFNT$SFNT_PROJ/ldns --disable-shared --disable-dane-verify --with-ssl=$PREFIX/ssl
  RC0=$?
  exit $RC0
fi


#--opendnssec-config:
# FIXME: auditor support is disabled [--disable-auditor].
# FIXME: opendnssec requires gcc compiler.
if [ "$1" = "--opendnssec-config" ]; then
  LUNA_CONFIG_OPENDNSSEC="--disable-shared --disable-auditor --prefix=/opt/SFNT$SFNT_PROJ/opendnssec --with-ssl=$PREFIX/ssl --with-libxml2=/opt/SFNT$SFNT_PROJ/libxml2 --with-ldns=/opt/SFNT$SFNT_PROJ/ldns --with-sqlite3=/opt/SFNT$SFNT_PROJ/sqlite"
  LUNA_CFLAGS="-I/$PREFIX/ssl/include"
  LUNA_LDFLAGS="-L/$PREFIX/ssl/lib"
  PYTHON=/opt/SFNT$SFNT_PROJ/python/bin/python  CC=gcc  CFLAGS="$LUNA_CFLAGS"  LDFLAGS="$LUNA_LDFLAGS"  ./configure $LUNA_CONFIG_OPENDNSSEC
  RC0=$?
  exit $RC0
fi


#exit 1:
exit 1

#eof
