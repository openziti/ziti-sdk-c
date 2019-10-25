#!/usr/bin/env bash


variants=$(< build.variants)

for var in ${variants[@]}; do
    echo "publishing for ${var} variant"
    cmake --build build-$var --target publish
done
