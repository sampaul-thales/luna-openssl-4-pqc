#!/bin/true
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
# PURPOSE:
#
# .build incrementally
# .build opendnssec
# .build bind
# .build other related packages
# .install packages to '/opt/SFNT$(SFNT_PROJ)/<package>'
#
#
# BUILD-TIME REQUIREMENTS:
#
# .gnu make (gmake 3.80+)
# .ansi C compiler
# .some packages require C++ compiler
# .bourne shell (or bash)
# .define LD_LIBRARY_PATH (you should use the script "SFNTdnssec.profile")
#
#
# RUN-TIME REQUIREMENTS:
#
# .bind (see README-BIND);
#
#

#include (definitions);
include dbuild.inc
include ../config.in

#override:
DBUILD_UNAMES:=${shell uname -s}

#define (targets):
#  FIXME: have trouble building ruby! [tmpruby.tmp]
#  FIXME: 4suite is obsolete! [tmp4suite.tmp]
ALL_TMP_BIND=tmplibxml2.tmp
ALL_TMP_OPENDNSSEC=tmplibxml2.tmp tmpldns.tmp tmpsqlite.tmp
ALL_TMP_CLEAN=$(ALL_TMP_BIND) $(ALL_TMP_OPENDNSSEC)
ALL_TMP_CLEANALL=tmptcl.tmp tmptk.tmp tmplibxml2.tmp tmpldns.tmp tmpsqlite.tmp tmpopendnssec.tmp tmpbind.tmp tmppython.tmp tmp4suite.tmp tmpruby.tmp tmppkcs11.tmp

#default:
default:
	@echo "Usage:"
	@echo
	@echo "  cleanall"
	@echo "  clean"
	@echo "  all  or bind-only"
	@echo

#all:
all: tmpunpack.tmp $(ALL_TMP_BIND) tmpbind.tmp tmppkcs11.tmp $(ALL_TMP_OPENDNSSEC) tmpopendnssec.tmp
	@echo

#bind-only:
bind-only: tmpunpackbind.tmp $(ALL_TMP_BIND) tmpbind.tmp tmppkcs11.tmp
	@echo

#clean:
clean:
	gmake -v
	rm -f $(ALL_TMP_CLEAN)
	@echo

#cleanall:
# NOTE: not cleaning [tmpunpack.tmp].
cleanall: clean
	gmake -v
	rm -f $(ALL_TMP_CLEANALL)
	touch /opt/SFNT$(SFNT_PROJ)
	mv -f /opt/SFNT$(SFNT_PROJ) /opt/SFNT$(SFNT_PROJ).date`date +%Y%m%d%H%M%S`
	@echo

#untar the files:
tmpunpack.tmp:
	gmake -v
	tar xzvf tcl$(VER_TCL)-src.tar.gz
	tar xzvf tk$(VER_TK)-src.tar.gz
	tar xzvf libxml2-$(VER_LIBXML2).tar.gz
	tar xzvf ldns-$(VER_LDNS).tar.gz
	tar xzvf sqlite-$(VER_SQLITE).tar.gz
	tar xzvf Python-$(VER_PYTHON).tar.gz
	tar xzvf 4Suite-XML-$(VER_4SUITE).tar.gz
	tar xzvf ruby-$(VER_RUBY).tar.gz
	tar xzvf opendnssec-$(VER_OPENDNSSEC).tar.gz
	tar xzvf bind-$(VER_BIND).tar.gz
	touch $@
	@echo


#untar the files for bind only:
tmpunpackbind.tmp:
	gmake -v
	tar xzvf libxml2-$(VER_LIBXML2).tar.gz
	tar xzvf bind-$(VER_BIND).tar.gz
	touch $@
	@echo

#build tcl:
#  FIXME: file does not exist [/opt/SFNT$(SFNT_PROJ)/tcl/tclConfig.sh].
#  FIXME: some systems do not have [tclsh].
tmptcl.tmp:
	gmake -v
	cd tcl$(VER_TCL)/unix ;  ./configure --prefix=/opt/SFNT$(SFNT_PROJ)/tcl  --enable-threads  --enable-shared
	gmake -C tcl$(VER_TCL)/unix  clean
	gmake -C tcl$(VER_TCL)/unix
	gmake -C tcl$(VER_TCL)/unix  install
	if [ ! -f /opt/SFNT$(SFNT_PROJ)/tcl/tclConfig.sh ]; then ln -s /opt/SFNT$(SFNT_PROJ)/tcl/lib/tclConfig.sh /opt/SFNT$(SFNT_PROJ)/tcl/tclConfig.sh  ; fi
	if [ ! -f /usr/bin/tclsh ]; then  cp -f ./tcl$(VER_TCL)/unix/tclsh /usr/bin/tclsh  ; fi
	touch $@
	@echo

#build tk:
#  NOTE: using same '--prefix' as tcl.
tmptk.tmp: tmptcl.tmp
	gmake -v
	cd tk$(VER_TK)/unix ;  ./configure --prefix=/opt/SFNT$(SFNT_PROJ)/tcl  --enable-threads  --enable-shared  --with-tcl=/opt/SFNT$(SFNT_PROJ)/tcl
	gmake -C tk$(VER_TK)/unix  clean
	gmake -C tk$(VER_TK)/unix
	gmake -C tk$(VER_TK)/unix  install
	touch $@
	@echo

#build libxml2:
tmplibxml2.tmp:
	gmake -v
	cd libxml2-$(VER_LIBXML2) ;  sh ../dbuild-helper.sh --libxml2-config
	gmake -C libxml2-$(VER_LIBXML2)  clean
	gmake -C libxml2-$(VER_LIBXML2)
	gmake -C libxml2-$(VER_LIBXML2)  install
	cd libxml2-$(VER_LIBXML2) ;  sh ../dbuild-helper.sh --libxml2-install
	touch $@
	@echo

#build ldns:
tmpldns.tmp:
	gmake -v
	cd ldns-$(VER_LDNS) ;  sh ../dbuild-helper.sh --ldns-config
	gmake -C ldns-$(VER_LDNS)  clean
	gmake -C ldns-$(VER_LDNS)
	gmake -C ldns-$(VER_LDNS)  install
	touch $@
	@echo

#build sqlite:
# NOTE: sqlite depends on [tmptcl.tmp] not [tmptk.tmp].
tmpsqlite.tmp: tmptcl.tmp
	gmake -v
	cd sqlite-$(VER_SQLITE) ;  ./configure --prefix=/opt/SFNT$(SFNT_PROJ)/sqlite --enable-threadsafe --with-tcl=/opt/SFNT$(SFNT_PROJ)/tcl
	gmake -C sqlite-$(VER_SQLITE)  clean
	gmake -C sqlite-$(VER_SQLITE)
	gmake -C sqlite-$(VER_SQLITE)  install
	touch $@
	@echo

#build python:
# NOTE: not using option [--enable-shared].
tmppython.tmp:
	gmake -v
	cd Python-$(VER_PYTHON) ;  ./configure --prefix=/opt/SFNT$(SFNT_PROJ)/python --disable-shared --with-threads
	gmake -C Python-$(VER_PYTHON)  clean
	gmake -C Python-$(VER_PYTHON)
	gmake -C Python-$(VER_PYTHON)  install
	touch $@
	@echo

#build 4suite xml:
#    'python setup.py --help'
#    'python setup.py config --help'
#    'python setup.py build --help'
#    'python setup.py install --help'
tmp4suite.tmp: tmppython.tmp
	gmake -v
	cd 4Suite-XML-$(VER_4SUITE) ;  /opt/SFNT$(SFNT_PROJ)/python/bin/python setup.py --provides
	cd 4Suite-XML-$(VER_4SUITE) ;  /opt/SFNT$(SFNT_PROJ)/python/bin/python setup.py --requires
	cd 4Suite-XML-$(VER_4SUITE) ;  /opt/SFNT$(SFNT_PROJ)/python/bin/python setup.py --obsoletes
	@echo
	cd 4Suite-XML-$(VER_4SUITE) ;  /opt/SFNT$(SFNT_PROJ)/python/bin/python setup.py config --prefix=/opt/SFNT$(SFNT_PROJ)/4suite
	@echo
	cd 4Suite-XML-$(VER_4SUITE) ;  /opt/SFNT$(SFNT_PROJ)/python/bin/python setup.py build
	@echo
	cd 4Suite-XML-$(VER_4SUITE) ;  /opt/SFNT$(SFNT_PROJ)/python/bin/python setup.py install
	@echo
	touch $@
	@echo

#build ruby
# NOTE: not using option [--enable-shared].
tmpruby.tmp:
	gmake -v
	touch ruby-$(VER_RUBY)/ext/Setup
	mv -f ruby-$(VER_RUBY)/ext/Setup ruby-$(VER_RUBY)/ext/Setup.`date +%Y%m%d%H%M%S`
	echo "syslog" >> ruby-$(VER_RUBY)/ext/Setup
	echo "openssl" >> ruby-$(VER_RUBY)/ext/Setup
	echo "dnsruby" >> ruby-$(VER_RUBY)/ext/Setup
	echo "xsd/datatypes" >> ruby-$(VER_RUBY)/ext/Setup
	echo "rexml/document" >> ruby-$(VER_RUBY)/ext/Setup
	cd ruby-$(VER_RUBY) ;  ./configure --prefix=/opt/SFNT$(SFNT_PROJ)/ruby --enable-pthread --disable-shared
	gmake -C ruby-$(VER_RUBY)  clean
	gmake -C ruby-$(VER_RUBY)
	gmake -C ruby-$(VER_RUBY)  install
	touch $@
	@echo

#build opendnssec
tmpopendnssec.tmp: $(ALL_TMP_OPENDNSSEC)
	gmake -v
	cd opendnssec-$(VER_OPENDNSSEC) ;  sh ../dbuild-helper.sh --opendnssec-config
	gmake -C opendnssec-$(VER_OPENDNSSEC)  clean
	gmake -C opendnssec-$(VER_OPENDNSSEC)
	gmake -C opendnssec-$(VER_OPENDNSSEC)  install
	touch $@
	@echo

#build bind
tmpbind.tmp: $(ALL_TMP_BIND)
	gmake -v
	cd bind-$(VER_BIND) ;  ./configure --prefix=/opt/SFNT$(SFNT_PROJ)/bind --enable-threads --disable-atomic --with-openssl=$(PREFIX)/ssl --with-pkcs11=/opt/SFNT$(SFNT_PROJ)/pkcs11/lib/libpkcs11.so --with-libxml2=/opt/SFNT$(SFNT_PROJ)/libxml2
	gmake -C bind-$(VER_BIND)  clean
	gmake -C bind-$(VER_BIND)
	gmake -C bind-$(VER_BIND)  install
	touch $@
	@echo

#tmppkcs11.tmp:
tmppkcs11.tmp:
	if [ ! -f /opt/SFNT$(SFNT_PROJ)/SFNTdnssec.profile ]; then  cp -f SFNTdnssec.profile  /opt/SFNT$(SFNT_PROJ)/SFNTdnssec.profile  ; fi
	if [ ! -d /opt/SFNT$(SFNT_PROJ)/pkcs11/lib ]; then mkdir -p /opt/SFNT$(SFNT_PROJ)/pkcs11/lib ;  fi
	if [ ! -f /opt/SFNT$(SFNT_PROJ)/pkcs11/lib/libpkcs11.so ]; then if [ -f /usr/lib/libCryptoki2_64.so ]; then ln -s /usr/lib/libCryptoki2_64.so /opt/SFNT$(SFNT_PROJ)/pkcs11/lib/libpkcs11.so ;  fi ; fi
	if [ ! -f /opt/SFNT$(SFNT_PROJ)/pkcs11/lib/libpkcs11.so ]; then if [ -f /usr/lib/libCryptoki2.so ]; then ln -s /usr/lib/libCryptoki2.so /opt/SFNT$(SFNT_PROJ)/pkcs11/lib/libpkcs11.so ;  fi ; fi
	touch $@
	@echo

#eof
