#!/bin/bash

conf=softhsm2.conf
lib=$(bash ./find-softhsm-lib.sh)
echo "using pkcs11 module: ${lib}"
pin=2171

[ -e ${conf} ] || exit 1


tokendir=$(awk '/^directories.tokendir/{print $3;}' ${conf})

mkdir -p ${tokendir}
export SOFTHSM2_CONF=${conf}

softhsm2-util --init-token --slot 0 --label 'ziti-test-token' --so-pin ${pin} --pin ${pin}
pkcs11-tool --module ${lib} -p ${pin} -k --key-type rsa:2048 --id 01 --label ziti-rsa-key
pkcs11-tool --module ${lib} -p ${pin} -k --key-type EC:prime256v1 --id 02 --label ziti-ecdsa-key

