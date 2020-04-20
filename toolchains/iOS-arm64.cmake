# build-iphoneos-arm64

set(CMAKE_SYSTEM_NAME iOS)
set(CMAKE_SYSTEM_PROCESSOR arm64)

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -arch arm64")
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -arch arm64")

# for libsodium
set(triple arm-apple-darwin10)
execute_process(COMMAND /usr/bin/xcrun -sdk iphoneos --show-sdk-path
                OUTPUT_VARIABLE CMAKE_OSX_SYSROOT
                OUTPUT_STRIP_TRAILING_WHITESPACE)

set(ENV{CFLAGS} "-arch arm64 -isysroot ${CMAKE_OSX_SYSROOT}")
set(ENV{LDFLAGS} "-arch arm64 -isysroot ${CMAKE_OSX_SYSROOT}")

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
