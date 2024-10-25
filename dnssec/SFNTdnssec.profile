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

LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/SFNTdnssec1/libxml2/lib
LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/SFNTdnssec1/ldns/lib
LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/SFNTdnssec1/ssl/lib
LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/SFNTdnssec1/ssl/lib/engines-1.1
LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/SFNTdnssec1/ssl/lib/engines
export LD_LIBRARY_PATH

PATH=$PATH:/opt/SFNTdnssec1/bind/sbin:/opt/SFNTdnssec1/bind/bin
PATH=$PATH:/opt/SFNTdnssec1/opendnssec/sbin:/opt/SFNTdnssec1/opendnssec/bin
PATH=$PATH:/opt/SFNTdnssec1/ldns/bin
PATH=$PATH:/opt/SFNTdnssec1/sautil/bin
PATH=$PATH:/opt/SFNTdnssec1/ssl/bin
export PATH

MANPATH=$MANPATH:/opt/SFNTdnssec1/bind/share/man
MANPATH=$MANPATH:/opt/SFNTdnssec1/opendnssec/share/man
export MANPATH

#eof

