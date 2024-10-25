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
#   build application within unix environment
#
#
# PRE-REQUISITES:
#
# - openssl toolkit headers and libcrypto
#
#
# NOTES:
#
# - source code can be compiled using C or C++ compiler (if not true then report this as a bug)
#

# Name of application:
APPNAME=sautil

# Operating system:
UNAMES=`uname -s`
UNAMEM=`uname -m`
UNAMEP=`uname -p`
UNAMEO=`uname -o 2> /dev/null`
UNAMEA=`uname -a`
echo "System... $UNAMES"
echo "uname -a... $UNAMEA"

# C/C++ Compiler:
echo "which cc... `which cc`"
echo "which cc_r... `which cc_r`"
echo "which gcc... `which gcc`"
echo "which cl... `which cl`"

# Compiler:
CC="cc"
CFLAGS_MT="-D_REENTRANT -DTHREAD_SAFE"
CFLAGS_64="-m64"
CFLAGS_32="-m32"
LDFLAGS_END="-lpthread -ldl"
LDFLAGS_EXTRA=""
GEM_INCLUDES="../../engine"

# try_compile:
try_compile() {
  if [ ! "$CC" = "" ]; then
    echo "CC=$CC"
    echo "CFLAGS_64=$CFLAGS_64"
    echo "CFLAGS_32=$CFLAGS_32"
    echo "LDFLAGS_END=$LDFLAGS_END"
    echo "OPENSSL_INCLUDES=$OPENSSL_INCLUDES"
    echo "OPENSSL_LIBS=$OPENSSL_LIBS"

    STATIC_LIBS=""
    SHARED_LIBS=""
    if [ ! "$OPENSSL_LIBS" = "" ]; then
      # NOTE: prefer dynamic libraries
      #   legacy: STATIC_LIBS="$OPENSSL_LIBS/libssl.a $OPENSSL_LIBS/libcrypto.a"
      SHARED_LIBS="-L$OPENSSL_LIBS -lcrypto -lssl"
    else
      SHARED_LIBS="-lcrypto -lssl"
    fi

    # try 64-bit before 32-bit on unix:
    if [ ! -x $APPNAME ]; then
      COMMAND="$CC $CFLAGS_64 -o $APPNAME $APPNAME.c  -DOS_UNIX  $CFLAGS_MT  -I$OPENSSL_INCLUDES -I$GEM_INCLUDES $SHARED_LIBS $STATIC_LIBS $LDFLAGS_END"
      echo $COMMAND
      $COMMAND
      ls $APPNAME
    fi
    if [ ! -x $APPNAME ]; then
      $CC $CFLAGS_32 -o $APPNAME $APPNAME.c  -DOS_UNIX  $CFLAGS_MT  -I$OPENSSL_INCLUDES -I$GEM_INCLUDES $SHARED_LIBS $STATIC_LIBS $LDFLAGS_END
    fi
    if [ ! -x $APPNAME ]; then
      $CC -o $APPNAME $APPNAME.c  -DOS_UNIX  $CFLAGS_MT  -I$OPENSSL_INCLUDES -I$GEM_INCLUDES $SHARED_LIBS $STATIC_LIBS $LDFLAGS_END
    fi
    if [ -x $APPNAME ]; then
      file $APPNAME 
      #echo "mkdir -p $APP_INSTALL_UNIX/$APPNAME/bin"
      #mkdir -p $APP_INSTALL_UNIX/$APPNAME/bin
      #echo "cp -f $APPNAME $APP_INSTALL_UNIX/$APPNAME/bin/$APPNAME"
      #cp -f $APPNAME $APP_INSTALL_UNIX/$APPNAME/bin/$APPNAME
      #if [ "$?" = "0" ]; then
        echo "Success."
        exit 0
      #fi
    fi
  fi
}


# try_compile_win32:
try_compile_win32() {
  if [ "" = "" ]; then
    if [ "$APP_INSTALL_DOS" = "" ]; then
      APP_INSTALL_DOS="c:\cygwin\usr\local"
      APP_INSTALL_UNIX="/usr/local"
    fi
    if [ "$SSL_PATH" = "" ]; then
      SSL_PATH="$APP_INSTALL_DOS\ssl"
    fi
    echo "APP_INSTALL_DOS=$APP_INSTALL_DOS"
    echo "SSL_PATH=$SSL_PATH"
    CL_OPTS="/Ox /O2 /Ob2 /W3 /WX /Gs0 /GF /Gy /nologo $CFLAGS_MT -DWIN32_LEAN_AND_MEAN -D_CRT_SECURE_NO_DEPRECATE -D_CRT_NONSTDC_NO_DEPRECATE"
    LDFLAGS_BASE="kernel32.lib user32.lib gdi32.lib winspool.lib  comdlg32.lib advapi32.lib shell32.lib ole32.lib  oleaut32.lib uuid.lib odbc32.lib odbccp32.lib  wsock32.lib  ssleay32.lib  libeay32.lib"
    # try 64-bit before 32-bit on windows:
    if [ ! -x $APPNAME.exe ]; then
      cl $CL_OPTS /MD  $APPNAME.c  /D "OS_WIN32" /D "OS_WIN64"  /I "$SSL_PATH\include" /link /machine:amd64 /out:$APPNAME.exe $APPNAME.obj /libpath:"$SSL_PATH\lib" $LDFLAGS_BASE $LDFLAGS_END 
      mt -nologo -manifest $APPNAME.exe.manifest -outputresource:"$APPNAME.exe;1" 
    fi
    if [ ! -x $APPNAME.exe ]; then
      cl $CL_OPTS /MD  $APPNAME.c  /D "OS_WIN32"  /I "$SSL_PATH\include" /link /out:$APPNAME.exe $APPNAME.obj /libpath:"$SSL_PATH\lib" $LDFLAGS_BASE $LDFLAGS_END 
      mt -nologo -manifest $APPNAME.exe.manifest -outputresource:"$APPNAME.exe;1" 
    fi
    if [ -x $APPNAME.exe ]; then
      echo "mkdir -p $APP_INSTALL_UNIX/$APPNAME/bin"
      mkdir -p $APP_INSTALL_UNIX/$APPNAME/bin 
      echo "cp -f $APPNAME.exe $APP_INSTALL_UNIX/$APPNAME/bin/$APPNAME.exe"
      cp -f $APPNAME.exe $APP_INSTALL_UNIX/$APPNAME/bin/$APPNAME.exe 
      if [ "$?" = "0" ]; then
        echo "Success."
        exit 0
      fi
    fi
  fi
}


# try_compile_gcc:
try_compile_gcc() {
  CC="gcc -g"
  CFLAGS_64="-m64"
  CFLAGS_32="-m32"
  LDFLAGS_END="-lpthread -ldl"
  try_compile
  LDFLAGS_END="-lrt -lsocket"
  try_compile
  LDFLAGS_END=""
  try_compile
}


# SunOS:
if [ "$UNAMES" = "SunOS" ]; then
  CC="cc -mt"
  LDFLAGS_END="-lpthread -lrt -lsocket -ldl"
  if [ "$UNAMEP" = "sparc" ]; then
    CFLAGS_64="-xarch=v9"
  else
    CFLAGS_64="-xarch=amd64"
  fi
  try_compile
  if [ "$UNAMEP" = "sparc" ]; then
    CFLAGS_64="-m64"
  else
    CFLAGS_64="-m64"
  fi
  try_compile
  try_compile_gcc
  exit 1
fi


# AIX:
if [ "$UNAMES" = "AIX" ]; then
  CC="cc_r -qcpluscmt -O2 -qstrict -qmaxmem=16384 -qtbtable=none"
  LDFLAGS_END="-lpthread"
  CFLAGS_64="-q64"
  try_compile
  CC="cc"
  try_compile
  try_compile_gcc
  exit 1
fi


# HP-UX:
if [ "$UNAMES" = "HP-UX" ]; then
  LDFLAGS_END="-lpthread -ldl"
  if [ "$UNAMEM" = "ia64" ]; then
    CC="cc -D__NO_PA_HDRS"
    CFLAGS_64="-Ae +DD64 +DSitanium2"
  else
    CC="cc -DPARISC -D__NO_EM_HDRS -D__hp9000s800"
    CFLAGS_64="-Ae +DD64 +DS2.0"
  fi
  try_compile
  try_compile_gcc
  exit 1
fi


# Cygwin:
if [ "$UNAMEO" = "Cygwin" ]; then
  LDFLAGS_END=""
  try_compile_win32
  LDFLAGS_END="bufferoverflowu.lib"
  try_compile_win32
  exit 1
fi


# Backstop:
try_compile_gcc
exit 1


#eof

