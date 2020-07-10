#!/bin/bash

variants=("$@")
if [[ $# == 0 ]]; then
  echo "Building all variants"
  variants=$(< build.variants)
fi
cmake_gen=""
ninja=$(command -v ninja)
if [ "x$ninja" != "x" ]; then
  cmake_gen="-G Ninja"
fi


native_variant="$(uname)-$(uname -m)"
projroot=$(readlink -f $(dirname "$0") )

die() {
echo "$@" 1>&2
exit 127
}

build_variant() {
    variant="$1"
    echo "Building for $variant"
    mkdir -p build-${variant}
    cd build-${variant}
    cmake_opts="${cmake_gen} -DCMAKE_BUILD_TYPE=Debug"
    toolchain="${projroot}/toolchains/${variant}.cmake"

    if [[ -f "$toolchain" ]]; then
    cmake_opts="${cmake_opts} -DCMAKE_TOOLCHAIN_FILE=$toolchain ${projroot}"
    elif [[ ${variant} != ${native_variant} ]]; then
    echo "ERROR: could not find $toolchain"
    return
    fi

    cmake $cmake_opts

    cmake --build .
    cmake --build . --target package

    cd ${projroot}
}

for v in ${variants[@]} ; do
    build_variant $v
done
