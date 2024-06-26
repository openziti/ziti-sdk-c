# build-macOS-arm64

if (NOT (CMAKE_HOST_SYSTEM_NAME STREQUAL "Darwin") AND
        NOT(CMAKE_HOST_SYSTEM_PROCESSOR STREQUAL "arm64") )
    set(CMAKE_SYSTEM_NAME Darwin)
    set(CMAKE_SYSTEM_PROCESSOR arm64)
endif ()

set(ZITI_BUILD_TESTS OFF CACHE BOOL "" FORCE)

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -arch arm64")
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -arch arm64")

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
