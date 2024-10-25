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
# - cryptoki library configured via "$ChrystokiConfigurationPath/Chrystoki.conf" (UNIX only)
# - or, cryptoki library configured via "%ChrystokiConfigurationPath%\crystoki.ini" (Windows only)
#
#
# NOTES:
#
# - source code can be compiled using C or C++ compiler (if not true then report this as a bug)
#

# Name of application:
APPNAME=engineperf

# Operating system:
UNAMES=`uname -s`
UNAMEM=`uname -m`
UNAMEP=`uname -p`
UNAMEO=`uname -o 2> /dev/null`
echo "System... $UNAMES"

# C/C++ Compiler:
echo "uname -a... `uname -a`"
echo "which cc... `which cc`"
echo "which gcc... `which gcc`"
echo "which cl... `which cl`"
echo "which xlc... `which xlc`"
echo "which CC... `which CC`"
echo "which g++... `which g++`"
echo "which aCC... `which aCC`"

# Compiler:
# coverity expects gcc
CC="gcc"
CFLAGS="-D_REENTRANT"
CFLAGS_64="$CFLAGS -m64"
CFLAGS_32="$CFLAGS -m32"
LDFLAGS_END="-lpthread -ldl"
GEM_INCLUDES="../../engine"

# try_compile:
try_compile() {
  if [ ! "$CC" = "" ]; then
    if [ "$LUNA_CONFIG_FIPS" = "" ]; then
      LUNA_CONFIG_FIPS=no
    fi

    if [ "$LUNA_CONFIG_FIPS" = "yes" ]; then
       SSL_PATH2="$FIPS_PREFIX/ssl-fips"
    fi

    SHARED_LIBS=""
    if [ ! "$OPENSSL_LIBS" = "" ]; then
        SHARED_LIBS="-L$OPENSSL_LIBS -lcrypto -lssl"
    else
        SHARED_LIBS="-lcrypto -lssl"
    fi

    echo "LUNA_CONFIG_FIPS=$LUNA_CONFIG_FIPS"
    echo "SSL_PATH2=$SSL_PATH2"
    echo "CC=$CC"
    echo "CFLAGS=$CFLAGS"
    echo "CFLAGS_32=$CFLAGS_32"
    echo "CFLAGS_64=$CFLAGS_64"
    echo "LDFLAGS_END=$LDFLAGS_END"
    echo "OPENSSL_INCLUDES=$OPENSSL_INCLUDES"
    echo "OPENSSL_LIBS=$OPENSSL_LIBS"
    echo "SHARED_LIBS=$SHARED_LIBS"
    # try 64-bit before 32-bit on unix:
    if [ ! -x $APPNAME ]; then
      if [ "$LUNA_CONFIG_FIPS" = "yes" ]; then
        echo env FIPSLD_CC="$CC"  $SSL_PATH2/bin/fipsld  $CFLAGS_64 -o $APPNAME $APPNAME.c  -DOS_UNIX  -I$OPENSSL_INCLUDES -I$GEM_INCLUDES $SSL_PATH2/lib/fipscanister.o $SHARED_LIBS $LDFLAGS_END
      else
        COMMAND="$CC $CFLAGS_64 -o $APPNAME $APPNAME.c  -DOS_UNIX  -I$OPENSSL_INCLUDES -I$GEM_INCLUDES -ggdb $SHARED_LIBS $LDFLAGS_END"
        # coverity: need to echo command for coverity to see it
        echo $COMMAND
        $COMMAND
      fi
    fi
    if [ ! -x $APPNAME ]; then
      if [ "$LUNA_CONFIG_FIPS" = "yes" ]; then
        env FIPSLD_CC="$CC"  $SSL_PATH2/bin/fipsld  $CFLAGS_32 -o $APPNAME $APPNAME.c  -DOS_UNIX  -I$OPENSSL_INCLUDES -I$GEM_INCLUDES $SSL_PATH2/lib/fipscanister.o $SHARED_LIBS $LDFLAGS_END
      else
        $CC $CFLAGS_32  -o $APPNAME $APPNAME.c  -DOS_UNIX  -I$OPENSSL_INCLUDES -I$GEM_INCLUDES $SHARED_LIBS $LDFLAGS_END
      fi
    fi
    if [ ! -x $APPNAME ]; then
      if [ "$LUNA_CONFIG_FIPS" = "yes" ]; then
        env FIPSLD_CC="$CC"  $SSL_PATH2/bin/fipsld  $CFLAGS    -o $APPNAME $APPNAME.c  -DOS_UNIX  -I$OPENSSL_INCLUDES -I$GEM_INCLUDES $SSL_PATH2/lib/fipscanister.o  $SHARED_LIBS  $LDFLAGS_END
      else
        $CC $CFLAGS                          -o $APPNAME $APPNAME.c  -DOS_UNIX  -I$OPENSSL_INCLUDES -I$GEM_INCLUDES $SHARED_LIBS  $LDFLAGS_END
      fi
    fi
    if [ -x $APPNAME ]; then
      file $APPNAME 
      echo "Installing to ./$APPNAME" 
      echo "Success."
      exit 0
    fi
  fi
}


# try_compile_win32:
try_compile_win32() {
  if [ "" = "" ]; then
    if [ "$SSL_PATH" = "" ]; then
      SSL_PATH="c:\cygwin\usr\local\ssl"
    fi
    CL_OPTS="-DMONOLITH -D_REENTRANT /MD /Ox /O2 /Ob2 /W3 /WX /Gs0 /GF /Gy /nologo -DWIN32_LEAN_AND_MEAN -DL_ENDIAN -DDSO_WIN32 -D_CRT_SECURE_NO_DEPRECATE -D_CRT_NONSTDC_NO_DEPRECATE"
    LDFLAGS_END="kernel32.lib user32.lib gdi32.lib winspool.lib  comdlg32.lib advapi32.lib crypt32.lib shell32.lib ole32.lib  oleaut32.lib uuid.lib odbc32.lib odbccp32.lib  wsock32.lib  ssleay32.lib  libeay32.lib"
    LDFLAGS_FOO="bufferoverflowu.lib"
    # try 64-bit before 32-bit on windows:
    if [ ! -x $APPNAME.exe ]; then
      cl $CL_OPTS  $APPNAME.c  /D "OS_WIN32" /D "OS_WIN64"  /I "$SSL_PATH\include" /link /machine:amd64 /out:$APPNAME.exe $APPNAME.obj /libpath:"$SSL_PATH\lib" $LDFLAGS_END 
      mt -nologo -manifest $APPNAME.exe.manifest -outputresource:"$APPNAME.exe;1" 
    fi
    if [ ! -x $APPNAME.exe ]; then
      cl $CL_OPTS  $APPNAME.c  /D "OS_WIN32"  /I "$SSL_PATH\include" /link /out:$APPNAME.exe $APPNAME.obj /libpath:"$SSL_PATH\lib" $LDFLAGS_END 
      mt -nologo -manifest $APPNAME.exe.manifest -outputresource:"$APPNAME.exe;1" 
    fi
    if [ -x $APPNAME.exe ]; then
      file $APPNAME.exe 
      echo "Installing to ./$APPNAME.exe" 
      echo "Success."
      exit 0
    fi
  fi
}


# SunOS:
if [ "$UNAMES" = "SunOS" ]; then
  CC="cc"
  CFLAGS="-mt -D_REENTRANT"
  LDFLAGS_END="-lpthread -lrt -lsocket -ldl"
  if [ "$UNAMEP" = "sparc" ]; then
    CFLAGS_64="$CFLAGS -xarch=v9"
    #CFLAGS_64="$CFLAGS -m64"
  else
    CFLAGS_64="$CFLAGS -xarch=amd64"
    #CFLAGS_64="$CFLAGS -m64"
  fi
  try_compile
  exit 1
fi


# AIX:
if [ "$UNAMES" = "AIX" ]; then
  CC="cc_r"
  CFLAGS="-D_REENTRANT -qcpluscmt -O2 -qstrict -qmaxmem=16384 -qtbtable=none"
  CFLAGS_32="$CFLAGS"
  CFLAGS_64="$CFLAGS -q64"
  LDFLAGS_END="-lpthread"
  try_compile
  exit 1
fi


# HP-UX:
if [ "$UNAMES" = "HP-UX" ]; then
  LDFLAGS_END="-lpthread -ldl"
  if [ "$UNAMEM" = "ia64" ]; then
    CC="cc"
    CFLAGS="-D__NO_PA_HDRS -D_REENTRANT"
    CFLAGS_32="$CFLAGS"
    CFLAGS_64="$CFLAGS -Ae +DD64 +DSitanium2"
  else
    CC="cc"
    CFLAGS=" -DPARISC -D__NO_EM_HDRS -D__hp9000s800 -D_REENTRANT"
    CFLAGS_32="$CFLAGS"
    CFLAGS_64="$CFLAGS -Ae +DD64 +DS2.0"
  fi
  try_compile
  exit 1
fi


# Cygwin:
if [ "$UNAMEO" = "Cygwin" ]; then
  CC="cl"
  try_compile_win32
  exit 1
fi


# Backstop:
if [ "Backstop" = "Backstop" ]; then
  try_compile
fi

exit 1


#eof

