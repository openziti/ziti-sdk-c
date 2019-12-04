# Ziti C SDK - Setup for Development

The following steps should get your C SDK for Ziti building. C development is specific to your operating system and tool chain used. These steps should work properly for you but if your OS has variations you may need to adapt these steps accordingly.

## Status 
[![Build Status](https://travis-ci.org/netfoundry/ziti-sdk-c.svg?branch=master)](https://travis-ci.org/netfoundry/ziti-sdk-c)

## Prerequisites

### Build

* [Cmake (3.12+)](https://cmake.org/install/)
* protobuf-c - only needed when you change `.proto` files, see [below](#working-with-protobuf)

### Test

* ubuntu: `softhsm2`, `opensc`
* fedora: `softhsm`, `opensc`
* macOS (brew): `softhsm (cask)`, `opensc`

## Init

The C SDK requires additional dependencies to be retreived. This is accomplished via the `git submodule` command. Fetch third party libs using:

```bash
$ git submodule update --init --recursive
```

## Build

### Linux/MacOS

Building the SDK on linux/mac can be accomplished with:

```bash
$ mkdir build
$ cd build
$ cmake .. && make
```

If you are cross compiling, you _must_ name the build directory as `build-$(uname -s)-$(uname -m)`

### Windows

The easiest method to build on windows is to open a "Developer Command Prompt for VS 2019" and execute `msvc-build.bat`. Open that file to see the individual steps needed to build the C SDK on Windows. The steps the script will do are:

```
mkdir build
cd build
cmake .. -DCMAKE_INSTALL_INCLUDEDIR=include -DCMAKE_INSTALL_LIBDIR=lib
cmake --build . --config Debug [Release]
```

## Working with protobuf
Required version of protobuf-c compiler (get it for your specific environment)

```bash
$ protoc-c --version
protobuf-c 1.3.1
libprotoc 3.6.1

Generate source files from protocol definitions and check them in
```

$ cd library/proto/
$ protoc-c --c_out=. *.proto
$ git add *.h *.c
...
```
Copyright&copy; 2018-2019. NetFoundry, Inc.
