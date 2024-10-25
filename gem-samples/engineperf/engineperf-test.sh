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
# PURPOSE:
#
#  Setup for the engineperf utility.
#
# DEPENDENCIES
#
#  "openssl in PATH".
#  "sautil in PATH".
#

#const
ENGINE="gem"
SAUTILARG="-v -s 0 -i 0:0 -o -q -c"
SAUTILEXE="sautil"
OPENSSLEXE="openssl"
IN_SOFTWARE="0"

TEST_ALL=0
DELETE_ALL=0
# TODO FIPS=1
FIPS=0
PROVIDER=0

# common curves
#CURVE_NAME=prime256v1
#CURVE_NAME=secp384r1
CURVE_NAME=secp521r1

# less common curves
#CURVE_NAME=prime192v1
#CURVE_NAME=secp224r1
#CURVE_NAME=secp256k1

# other large curves
#CURVE_NAME=sect409r1
#CURVE_NAME=c2tnb431r1
#CURVE_NAME=sect571r1



usage()
{
  echo
  echo "Usage: ./engineperf-test.sh <options>"
  echo
  echo "Valid options are:"
  echo "  --test-all         Run all of the tests."
  echo "  --delete-all       Delete all of the keys."
  echo "  --fips=<mode>      1 for FIPS mode, 0 for non FIPS mode."
  echo "  --provider=<mode>  1 for provider, 0 for engine (default)."
  echo
}

while [ -n "$1" ]; do
  PARAM=`echo $1 | awk -F= '{print $1}'`
  VALUE=`echo $1 | awk -F= '{print $2}'`
  case $PARAM in
    -h | --help)
      usage
      exit 1
      ;;
    --test-all)
      TEST_ALL=1
      ;;
    --delete-all)
      DELETE_ALL=1
      ;;
    --fips)
      FIPS=$VALUE
      ;;
    --provider)
      PROVIDER=$VALUE
      ;;
    *)
      usage
      echo "ERROR:  Unrecognized option: $PARAM"
      exit 1
      ;;
  esac
  shift
done

if [ "$TEST_ALL" = "0" ]; then
	if [ "$DELETE_ALL" = "0" ]; then
		usage
		echo "ERROR:  Either --test-all or --delete-all must be specified"
		exit 1
	fi
fi


#target-default:
if [ "$TEST_ALL" = "1" ]; then
echo ; echo "Generate RSA key and keyfile..."
if [ ! -f tmprsakey.pem ]; then
  if [ "$IN_SOFTWARE" = "1" ]; then
    $OPENSSLEXE genrsa -out tmprsakey.pem -f4 3072
  else
    $SAUTILEXE  $SAUTILARG -f tmprsakey.pem -x 01:00:01 -g 3072
  fi
  if [ ! "$?" = "0" ]; then 
    exit 1 
  fi
fi

# openssl 1.0.2 does not support dsa 3072
#DSA_BITS=2048
DSA_BITS=3072
DSA_Q_BITS=256

echo ; echo "Generate DSA param file..."
if [ ! -f tmpdsaparam.pem ]; then
  $OPENSSLEXE genpkey -genparam -algorithm DSA -out tmpdsaparam.pem -pkeyopt dsa_paramgen_bits:$DSA_BITS -pkeyopt dsa_paramgen_q_bits:$DSA_Q_BITS
fi
echo ; echo "Generate DSA key and keyfile..."
if [ ! -f tmpdsakey.pem ]; then
  if [ "$IN_SOFTWARE" = "1" ]; then
    $OPENSSLEXE gendsa -out tmpdsakey.pem tmpdsaparam.pem 
  else
    $SAUTILEXE  $SAUTILARG -f tmpdsakey.pem -d $DSA_BITS:tmpdsaparam.pem
  fi
  if [ ! "$?" = "0" ]; then 
    exit 1
  fi
fi

echo ; echo "Generate EC param file..."
if [ ! -f tmpecparam.pem ]; then
  $OPENSSLEXE ecparam -out tmpecparam.pem -name $CURVE_NAME
  $OPENSSLEXE ecparam -in tmpecparam.pem -text
  if [ ! "$?" = "0" ]; then 
    exit 1
  fi
fi
echo ; echo "Generate ECDSA key and keyfile..."
if [ ! -f tmpecdsakey.pem ]; then
  if [ "$IN_SOFTWARE" = "1" ]; then
    $OPENSSLEXE ecparam -in tmpecparam.pem -out tmpecdsakey.pem -genkey 
  else
    $SAUTILEXE  $SAUTILARG -f tmpecdsakey.pem -m OID_:tmpecparam.pem 
  fi
  if [ ! "$?" = "0" ]; then 
    exit 1
  fi
fi

echo ; echo "Running ./engineperf..."
if [ "$IN_SOFTWARE" = "1" ]; then
  echo ; echo "WARNING: using software engine!" ; sleep 2
  if [ ! "$PROVIDER" = "1" ]; then
    ./engineperf --fips=$FIPS --threads=15 --seconds=2 --engine   --software
  else
    ./engineperf --fips=$FIPS --threads=15 --seconds=2 --provider --software
  fi
else
  if [ ! "$PROVIDER" = "1" ]; then
    ./engineperf --fips=$FIPS --threads=15 --seconds=2 --engine   --load_private
  else
    ./engineperf --fips=$FIPS --threads=15 --seconds=2 --provider
  fi
fi
if [ ! "$?" = "0" ]; then 
  exit 1
fi

echo "Done."
exit 0
fi


# You can delete temporary keys and keyfiles.
if [ $DELETE_ALL = "1" ]; then
  if [ -f tmprsakey.pem ]; then
    $SAUTILEXE  $SAUTILARG -f tmprsakey.pem -g 0 
    if [ ! "$?" = "0" ]; then 
      exit 1
    fi
    rm -f tmprsakey.pem 
  fi

  if [ -f tmpdsakey.pem ]; then
    $SAUTILEXE  $SAUTILARG -f tmpdsakey.pem -d 0 
    if [ ! "$?" = "0" ]; then 
      exit 1
    fi
    rm -f tmpdsakey.pem 
  fi

  if [ -f tmpecdsakey.pem ]; then
    $SAUTILEXE  $SAUTILARG -f tmpecdsakey.pem -m 0 
    if [ ! "$?" = "0" ]; then 
      exit 1
    fi
    rm -f tmpecdsakey.pem 
  fi

# use cached dsa param
#  if [ -f tmpdsaparam.pem ]; then
#    rm -f tmpdsaparam.pem
#  fi

  if [ -f tmpecparam.pem ]; then
    rm -f tmpecparam.pem 
  fi
echo "Done."
exit 0
fi




#eof

