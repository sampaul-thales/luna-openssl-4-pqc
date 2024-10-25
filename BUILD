
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


BUILD INSTRUCTIONS

Follow these instructions in order to create the gemengine package.  The procedures should be performed in order.


PROCEDURE A - Build windows binaries.

  This procedure needs to be performed on 64 bit windows with Visual Studio installed.

  1. Install the x86 version of Cygwin and add the Cygwin bin directory to PATH.

  2. Install perl and ensure the bin directory is in PATH.

  3. Obtain the gemengine source from git (crypto/ssl_toolkit/gemengine).

  4. Download openssl-<version>.tar.gz from https://www.openssl.org/source/ and place directly in the gemengine directory.

    e.g., version 1.1.1g

  6. In a Visual Studio Command Prompt compile the binaries for windows 32 bit.

    # cd <path to crypto repo>/ssl_toolkit/gemengine

    # nmake /f obuild8.makefile cleanall

    # nmake /f obuild8.makefile all-win32  CFG_SUFFIX=win32

  7. In a Visual Studio x64 Command Prompt compile the binaries for windows 64 bit.

    # cd <path to crypto repo>/ssl_toolkit/gemengine

    # nmake /f obuild8.makefile cleanall

    # nmake /f obuild8.makefile all-win64  CFG_SUFFIX=win64

  8.  The following files should be in the gemengine/LUNAlocal directory (They are needed later):

    sautil-win32-openssl-<version>.tar.gz
    ssl-win32-openssl-<version>.tar.gz
    sautil-win64-openssl-<version>.tar.gz
    ssl-win64-openssl-<version>.tar.gz


PROCEDURE B - Generate the Linux libgem.so and sautil binaries.

  This procedure should be performed on an older x86_64 Linux system to allow the shared objects to be compatible with older Linux
  distributions (same version of Linux as used to create the Luna client).  This has been performed on CentOS 6.0 x86_64.

  1. Install the necessary dependencies.

    # yum install wget

    # yum groupinstall "Development tools"

    # yum install glibc-devel.i686 libgcc.i686

  2. Obtain the gemengine source from git (crypto/ssl_toolkit/gemengine).

  3. Download the OpenSSL tar.gz files from https://www.openssl.org/source for each version specified in the VERSIONS variable in generate.sh.

  4. Run the generate.sh script.

    # cd <path to crypto repo>/ssl_toolkit/gemengine

    # ./generate.sh

    This script will download and compile various versions of openssl and compile the dynamic gem engine and place the libgem.so files in the
    gemengine/builds directory.  As well sautil executables are created and copied to the gemengine/builds directory.


PROCEDURE C - Package the gemengine in to a tar.gz

  This procedure should be run on the same host as PROCEDURE B.  This will create the tar.gz that should be delivered to customers.

  1. Create a directory called LUNAlocal in the gemengine directory.

  2. Copy the sautil and ssl tar.gz files identified in step 8 of PROCEDURE A into the LUNAlocal directory.

  3. Run the package.sh script to generate the gemengine-<version>.tar.gz file.

    # ./package.sh

    This will create a gemengine-<version>.tar.gz file inside of the package directory to be delivered.

