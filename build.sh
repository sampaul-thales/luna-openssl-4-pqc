#!/bin/bash
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
#
#   script to build luna provider from coverity analysis
#
#   dependencies (openssl, liboqs) are not subject to coverity analysis here
#

if [ -z "$1" ] || [ -z "$2" ] || [ -z "$3" ]; then
    echo
    echo "Usage:"
    echo "       $0 SA64client clean all"
    echo "       $0 SA64client build all"
    echo 
    echo "  Alternatives to option all:"
    echo "    provider|sautil|engineperf"
    echo 
    echo "  Legacy alternatives to option all:"
    echo "    engine"
    echo 
    echo "  Dependencies (openssl, liboqs) you want to build just once:"
    echo "    depends"
    echo
    exit 1
fi

product="$1"
goal="$2"
target="$3"
if [ -n "$4" ]; then
    build_type="BLDTYPE=$4"
fi
# Use build_type=ci to skip the slow process of signing the jar files if you don't need signed jars
# Before running this script, create SA64.env and SA64client.env files containing all the required
# build environmnet variables such as OpenSSL and kernel versions. etc.
#
#Sample SA64.env file:
#
if [ ! -s "SA64.env" ]; then
    cat  << EOF  > SA64.env
#Environment variables to build SA64 appliance
export PRODUCT=SA64
export ROOT_DIR=\$PWD/artifacts/\$product
export BLDDIR=\$ROOT_DIR/output
export PKG_EXPORT_DIR=\$ROOT_DIR/packages
export PRODUCT_PKG_DIR=\$ROOT_DIR/personalization-packages
export OPEN_SOURCE_DIR=\$PWD/../Open-Source
export VERSION=7.8.3
export RELEASE=2
export DEBUG=0
export openssl_VERSION=1.1.1q
export KERNEL_VERSION=3.10.0-1160.81.1.el7.x86_64
EOF
    echo "Added the build environment varibales to a new SA64.env file. You can update it as you wish."
fi



# Sample SA64client.env file:
if [ ! -s "SA64client.env" ]; then
    cat  << EOF  > SA64client.env
#Environment varibales to build SA64client
export PRODUCT=SA64client
export ROOT_DIR=\$PWD/artifacts/\$product
export BLDDIR=\$ROOT_DIR/output
export PKG_EXPORT_DIR=\$ROOT_DIR/packages/
export VERSION=7.8.3
export RELEASE=2
export OPEN_SOURCE_DIR=\$PWD/../Open-Source
export DEBUG=0
export openssl_VERSION=1.1.1q
export KERNEL_VERSION=3.10.0-1160.83.1.el7.x86_64
export JAR_SIGNING_STATION=nobody@localhost
export WIN_SIGNING_STATION=nobody@localhost
export JDK=\$JAVA_HOME
export JAVA_HOME=\$JAVA_HOME
export ANT_HOME=\$ANT_HOME
EOF
    echo "Added the build environment variables to a new SA64client.env file. You can update it as you wish."
fi

if [ -s "./$product.env" ]; then
    echo source "./$product.env"
    file "./$product.env"
    source "./$product.env"
else
    echo "Please add all the required environment variables to the $product.env file, or export them before running this script."
    echo
fi

if [ -z "$BLDDIR" ]; then
    echo "Error! BLDDIR environment variable is not defined. Please set it in the $product.env file and try again."
    echo "Usage: $0 SA64|SA64client clean|build|pkg target"
    exit 1
fi

if [ -z "$PKG_EXPORT_DIR" ]; then
    echo "Error! PKG_EXPORT_DIR environment variable is not defined. Please set it in the $product.env file and try again."
    echo "Usage: $0 SA64|SA64client clean|build|pkg target"
    exit 1
fi

echo "Building $product $BLDDIR  $PKG_EXPORT_DIR"
mkdir -p "$BLDDIR" || exit 1
mkdir -p "$PKG_EXPORT_DIR" || exit 1

# build luna client
#make -j 1 $build_type  PRODUCT="$product" GOAL="$goal" "$target"

# build all (not including dependencies {openssl,liboqs})
false
if [ "$goal" = "build" ]; then
  # provider
  if [ "$target" = "provider" -o "$target" = "all" ]; then
    ./gembuild provider-build
  fi
  # engine is a subset of provider, hence not a part of all
  if [ "$target" = "engine" ]; then
    ./gembuild engine-build
  fi
  # sautil
  if [ "$target" = "sautil" -o "$target" = "all" ]; then
    ./gembuild sautil-build
  fi
  # engineperf 
  if [ "$target" = "engineperf" -o "$target" = "all" ]; then
    ./gembuild engineperf-build
  fi
  # depends
  if [ "$target" = "depends" ]; then
    ./generate.sh
  fi
fi

# clean all
if [ "$goal" = "clean" ]; then
  if [ "$target" = "provider" -o "$target" = "all" ]; then
    make -C lunaProvider clean
  fi
  if [ "$target" = "engine" -o "$target" = "all" ]; then
    make -C engine clean
  fi
  if [ "$target" = "sautil" -o "$target" = "all" ]; then
    make -C gem-samples/sautil clean
  fi
  if [ "$target" = "engineperf" -o "$target" = "all" ]; then
    make -C gem-samples/engineperf clean
  fi
fi

rc=$?
echo "Build done for PRODUCT=$product GOAL=$goal $target $build_type"
if [ "$rc" -ne 0 ]; then
    echo "Build failed with error code: $rc"
fi
exit $rc

#eof

