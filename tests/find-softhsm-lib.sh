#!/bin/bash -e

libname=libsofthsm2.so
libdirs="$(compgen -G /usr/lib/softhsm) $(compgen -G /usr/lib64) $(compgen -G /usr/local/Cellar/softhsm)"
lib=$(find -L ${libdirs} -type f -a -name "${libname}" 2> /dev/null | head -n 1)
if [ -z "${lib}" ]; then
  echo "ERROR: unable to find ${libname}. Have you installed softhsm2?"
  exit 1
fi
echo "${lib}" | tee SOFTHSM2_LIB.txt