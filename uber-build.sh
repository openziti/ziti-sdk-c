#!/bin/bash

variants=$(< build.variants)

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
    cmake_opts="-DCMAKE_BUILD_TYPE=Debug ${projroot}"
    toolchain="${projroot}/toolchains/${variant}.cmake"

    if [[ -f "$toolchain" ]]; then
    cmake_opts="-DCMAKE_TOOLCHAIN_FILE=$toolchain ${cmake_opts}"
    elif [[ ${variant} != ${native_variant} ]]; then
    echo "ERROR: could not find $toolchain"
    return
    fi

    cmake $cmake_opts

    cmake --build .
    cmake --build . --target package

    cd ${projroot}
}

# build native first to make sure proto-gen-c is built
build_variant $native_variant

for v in ${variants[@]} ; do
    if [[ $v != ${native_variant} ]]; then
        build_variant $v
    fi
done
