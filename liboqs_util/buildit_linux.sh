

if [ "$1" = "step1" ]; then
export OPENSSL_ROOT_DIR="/opt/SFNTpiggy/ssl"
echo "OPENSSL_ROOT_DIR=$OPENSSL_ROOT_DIR"
fi

if [ "$1" = "step2" ]; then
MY_OPT_1="-DOQS_OPT_TARGET=x86-64 -DBUILD_SHARED_LIBS=OFF -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/opt/SFNTpiggy/liboqs"
MY_OPT_2="-DOQS_ALGS_ENABLED=\"STD\""
MY_OPT_3="-DOQS_BUILD_ONLY_LIB=ON"
MY_OPT_4="-DOQS_MINIMAL_BUILD=\"KEM_kyber_512;KEM_kyber_768;KEM_kyber_1024;SIG_dilithium_2;SIG_dilithium_3;SIG_dilithium_5;SIG_falcon_512;SIG_falcon_1024\""
MY_OPT_5="-DOQS_DIST_BUILD=OFF"
MY_OPT_6="-DOQS_USE_OPENSSL=ON -DOQS_USE_AES_OPENSSL=ON -DOQS_USE_SHA2_OPENSSL=ON -DOQS_USE_SHA3_OPENSSL=ON"
MY_OPT_7="-DOPENSSL_ROOT_DIR=\"/opt/SFNTpiggy/ssl\""
cmake3 $MY_OPT_1 $MY_OPT_2 $MY_OPT_3 $MY_OPT_4 $MY_OPT_5 $MY_OPT_6 $MY_OPT_7 ..
fi

if [ "$1" = "step3" ]; then
make
echo
fi

if [ "$1" = "step4" ]; then
make install
echo
fi

#eof

