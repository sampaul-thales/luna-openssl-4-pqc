

if not "%1" == "step1"  goto skip_step1
set OPENSSL_ROOT_DIR=c:\cygwin\usr\local\ssl
:skip_step1

if not "%1" == "step2"  goto skip_step2
set MY_OPT_1=-A x64 -DBUILD_SHARED_LIBS=OFF -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="c:\cygwin\usr\local\liboqs001"
set MY_OPT_2=-DOQS_ALGS_ENABLED="STD"
set MY_OPT_3=-DOQS_BUILD_ONLY_LIB=ON
set MY_OPT_4=-DOQS_MINIMAL_BUILD="KEM_kyber_512;KEM_kyber_768;KEM_kyber_1024;SIG_dilithium_2;SIG_dilithium_3;SIG_dilithium_5;SIG_falcon_512;SIG_falcon_1024"
set MY_OPT_5=-DOQS_DIST_BUILD=OFF 
set MY_OPT_6=-DOQS_USE_OPENSSL=ON -DOQS_USE_AES_OPENSSL=ON -DOQS_USE_SHA2_OPENSSL=ON -DOQS_USE_SHA3_OPENSSL=ON
cmake %MY_OPT_1% %MY_OPT_2% %MY_OPT_3% %MY_OPT_4% %MY_OPT_5% %MY_OPT_6% ..
:skip_step2

if not "%1" == "step3"  goto skip_step3
msbuild ALL_BUILD.vcxproj
:skip_step3

if not "%1" == "step4"  goto skip_step4
msbuild INSTALL.vcxproj
:skip_step4

rem eof
