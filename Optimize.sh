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
# Description:
#	Update config file "/etc/Chrystoki.conf" to make the Luna HSM visible
#	from OpenSSL/DNSSEC and OpenSSL/Apache integration
#

# Luna installed in /opt or /usr:
MY_LUNA_ROOT_DIR=/usr/safenet/lunaclient
configurator=$MY_LUNA_ROOT_DIR/bin/configurator
if [ ! -x $configurator ]; then
  MY_LUNA_ROOT_DIR=/opt/safenet/lunaclient
  configurator=$MY_LUNA_ROOT_DIR/bin/configurator
fi
if [ ! -x $configurator ]; then
  MY_LUNA_ROOT_DIR=/opt/lunasa
  configurator=$MY_LUNA_ROOT_DIR/bin/configurator
fi
if [ ! -x $configurator ]; then
  MY_LUNA_ROOT_DIR=/usr/lunasa
  configurator=$MY_LUNA_ROOT_DIR/bin/configurator
fi
if [ ! -x $configurator ]; then
  MY_LUNA_ROOT_DIR=/opt/lunapci
  configurator=$MY_LUNA_ROOT_DIR/bin/configurator
fi
if [ ! -x $configurator ]; then
  MY_LUNA_ROOT_DIR=/usr/lunapci
  configurator=$MY_LUNA_ROOT_DIR/bin/configurator
fi
if [ ! -x $configurator ]; then
  MY_LUNA_ROOT_DIR=/opt/lunapcm
  configurator=$MY_LUNA_ROOT_DIR/bin/configurator
fi
if [ ! -x $configurator ]; then
  MY_LUNA_ROOT_DIR=/usr/lunapcm
  configurator=$MY_LUNA_ROOT_DIR/bin/configurator
fi
# backstop rule:
if [ ! -x $configurator ]; then
  MY_LUNA_ROOT_DIR=/opt/lunasa
  configurator=$MY_LUNA_ROOT_DIR/bin/configurator
fi

# Luna configured in /etc:
if [ "$ChrystokiConfigurationPath" = "" ]; then
  ChrystokiConfigurationPath=/etc
fi


f_fork()
{
# configure for applications that fork (e.g., apache webserver).
if [ ! -x $configurator ]; then
  echo "WARNING: Configuring file $ChrystokiConfigurationPath/Chrystoki.conf using echo."
  echo "GemEngine = {" >>  $ChrystokiConfigurationPath/Chrystoki.conf
  echo "  DisableRand = 1;" >>  $ChrystokiConfigurationPath/Chrystoki.conf
  echo "  DisableDsa = 1;" >>  $ChrystokiConfigurationPath/Chrystoki.conf
  echo "  DisableEcdsa = 1;" >>  $ChrystokiConfigurationPath/Chrystoki.conf
  echo "  DisableCheckFinalize = 0;" >>  $ChrystokiConfigurationPath/Chrystoki.conf
  echo "  EnableRsaGenKeyPair = 0;" >>  $ChrystokiConfigurationPath/Chrystoki.conf
  echo "  EnableDsaGenKeyPair = 0;" >>  $ChrystokiConfigurationPath/Chrystoki.conf
  echo "}" >>  $ChrystokiConfigurationPath/Chrystoki.conf
  echo "Please review file $ChrystokiConfigurationPath/Chrystoki.conf for accuracy."
else
  echo "Configuring file $ChrystokiConfigurationPath/Chrystoki.conf using $configurator."
  $configurator setValue -q -s GemEngine -e DisableRand -v 1 > /dev/null
  $configurator setValue -q -s GemEngine -e DisableDsa -v 1 > /dev/null
  $configurator setValue -q -s GemEngine -e DisableEcdsa -v 1 > /dev/null
  $configurator setValue -q -s GemEngine -e DisableCheckFinalize -v 0 > /dev/null
  $configurator setValue -q -s GemEngine -e EnableRsaGenKeyPair -v 0 > /dev/null
  $configurator setValue -q -s GemEngine -e EnableDsaGenKeyPair -v 0 > /dev/null
fi
}

f_nofork()
{
# configure for applications that do not fork (e.g., openssl command-line).
if [ ! -x $configurator ]; then
  echo "WARNING: Configuring file $ChrystokiConfigurationPath/Chrystoki.conf using echo."
  echo "GemEngine = {" >>  $ChrystokiConfigurationPath/Chrystoki.conf
  echo "  DisableRand = 0;" >>  $ChrystokiConfigurationPath/Chrystoki.conf
  echo "  DisableDsa = 0;" >>  $ChrystokiConfigurationPath/Chrystoki.conf
  echo "  DisableEcdsa = 0;" >>  $ChrystokiConfigurationPath/Chrystoki.conf
  echo "  DisableCheckFinalize = 1;" >>  $ChrystokiConfigurationPath/Chrystoki.conf
  echo "  EnableRsaGenKeyPair = 1;" >>  $ChrystokiConfigurationPath/Chrystoki.conf
  echo "  EnableDsaGenKeyPair = 1;" >>  $ChrystokiConfigurationPath/Chrystoki.conf
  echo "}" >>  $ChrystokiConfigurationPath/Chrystoki.conf
  echo "Please review file $ChrystokiConfigurationPath/Chrystoki.conf for accuracy."
else
  echo "Configuring file $ChrystokiConfigurationPath/Chrystoki.conf using $configurator."
  $configurator setValue -q -s GemEngine -e DisableRand -v 0 > /dev/null
  $configurator setValue -q -s GemEngine -e DisableDsa -v 0 > /dev/null
  $configurator setValue -q -s GemEngine -e DisableEcdsa -v 0 > /dev/null
  $configurator setValue -q -s GemEngine -e DisableCheckFinalize -v 1 > /dev/null
  $configurator setValue -q -s GemEngine -e EnableRsaGenKeyPair -v 1 > /dev/null
  $configurator setValue -q -s GemEngine -e EnableDsaGenKeyPair -v 1 > /dev/null
fi
}

f_bind()
{
# configure for bind.
if [ ! -x $configurator ]; then
  echo "WARNING: Configuring file $ChrystokiConfigurationPath/Chrystoki.conf using echo."
  echo "GemEngine = {" >>  $ChrystokiConfigurationPath/Chrystoki.conf
  echo "  DisableRand = 0;" >>  $ChrystokiConfigurationPath/Chrystoki.conf
  echo "  DisableDsa = 0;" >>  $ChrystokiConfigurationPath/Chrystoki.conf
  echo "  DisableEcdsa = 1;" >>  $ChrystokiConfigurationPath/Chrystoki.conf
  echo "  DisableCheckFinalize = 1;" >>  $ChrystokiConfigurationPath/Chrystoki.conf
  echo "  EnableRsaGenKeyPair = 1;" >>  $ChrystokiConfigurationPath/Chrystoki.conf
  echo "  EnableDsaGenKeyPair = 1;" >>  $ChrystokiConfigurationPath/Chrystoki.conf
  echo "  EnableLoadPrivKey = 1;" >>  $ChrystokiConfigurationPath/Chrystoki.conf
  echo "  EnableLoadPubKey = 1;" >>  $ChrystokiConfigurationPath/Chrystoki.conf
  echo "}" >>  $ChrystokiConfigurationPath/Chrystoki.conf
  echo "Please review file $ChrystokiConfigurationPath/Chrystoki.conf for accuracy."
else
  echo "Configuring file $ChrystokiConfigurationPath/Chrystoki.conf using $configurator."
  $configurator setValue -q -s GemEngine -e DisableRand -v 0 > /dev/null
  $configurator setValue -q -s GemEngine -e DisableDsa -v 0 > /dev/null
  $configurator setValue -q -s GemEngine -e DisableEcdsa -v 1 > /dev/null
  $configurator setValue -q -s GemEngine -e DisableCheckFinalize -v 1 > /dev/null
  $configurator setValue -q -s GemEngine -e EnableRsaGenKeyPair -v 1 > /dev/null
  $configurator setValue -q -s GemEngine -e EnableDsaGenKeyPair -v 1 > /dev/null
  $configurator setValue -q -s GemEngine -e EnableLoadPrivKey -v 1 > /dev/null
  $configurator setValue -q -s GemEngine -e EnableLoadPubKey -v 1 > /dev/null
fi
}


f_common()
{
# common configuration (safe settings).
# NOTE: EnableRsaGenKeyPair=0 otherwise temporary keys in hardware.
# NOTE: EnableDsaGenKeyPair=0 otherwise temporary keys in hardware.
if [ ! -x $configurator ]; then
  echo "Misc = {" >>  $ChrystokiConfigurationPath/Chrystoki.conf
  echo "  Apache = 0;" >>  $ChrystokiConfigurationPath/Chrystoki.conf
  echo "}" >>  $ChrystokiConfigurationPath/Chrystoki.conf
  echo "GemEngine = {" >>  $ChrystokiConfigurationPath/Chrystoki.conf
  echo "  LibPath = $MY_LUNA_ROOT_DIR/lib/libCryptoki2.so;" >>  $ChrystokiConfigurationPath/Chrystoki.conf
  echo "  LibPath64 = $MY_LUNA_ROOT_DIR/lib/libCryptoki2_64.so;" >>  $ChrystokiConfigurationPath/Chrystoki.conf
  echo "  EngineInit = 1:10:11;" >>  $ChrystokiConfigurationPath/Chrystoki.conf
  echo "  EnableRsaGenKeyPair = 0;" >>  $ChrystokiConfigurationPath/Chrystoki.conf
  echo "  EnableDsaGenKeyPair = 0;" >>  $ChrystokiConfigurationPath/Chrystoki.conf
  echo "}" >>  $ChrystokiConfigurationPath/Chrystoki.conf
  echo "Please review file $ChrystokiConfigurationPath/Chrystoki.conf for accuracy."
else
  $configurator setValue -q -s Misc -e Apache -v 0 > /dev/null
  $configurator setValue -q -s GemEngine -e LibPath -v $MY_LUNA_ROOT_DIR/lib/libCryptoki2.so > /dev/null
  $configurator setValue -q -s GemEngine -e LibPath64 -v $MY_LUNA_ROOT_DIR/lib/libCryptoki2_64.so > /dev/null
  $configurator setValue -q -s GemEngine -e EngineInit -v 1:10:11 > /dev/null
  $configurator setValue -q -s GemEngine -e EnableRsaGenKeyPair -v 0 > /dev/null
  $configurator setValue -q -s GemEngine -e EnableDsaGenKeyPair -v 0 > /dev/null
fi
}


if [ "$1" = "optimize" ]; then
  echo "optimize has been deprecated"
elif [ "$1" = "remove" ]; then
  echo "remove has been deprecated"
elif [ "$1" = "fork" ]; then
  f_common
  f_fork
elif [ "$1" = "nofork" ]; then
  f_common
  f_nofork
elif [ "$1" = "default" ]; then
  f_common
  f_fork
elif [ "$1" = "bind" ]; then
  f_common
  f_bind
elif [ "$1" = "opendnssec" ]; then
  f_common
  f_bind
else
# echo "---------|---------|---------|---------|---------|---------|---------|---------|"
  echo "Optimize.sh  fork       -- configure for apache."
  echo "Optimize.sh  nofork     -- configure for non-forking application."
  echo "Optimize.sh  default    -- same as fork."
  echo
  echo "Optimize.sh  bind       -- configure for bind (DNSSEC)."
  echo "Optimize.sh  opendnssec -- configure for opendnssec."
  echo
  exit 1
fi
