cmake_minimum_required(VERSION 3.14)
include(git.cmake)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_C_STANDARD 99)
project(ziti-sdk
        VERSION ${ver}
        LANGUAGES C CXX
        )

option(ZITI_BUILD_PROGRAMS "Build programs." ON)
option(ZITI_BUILD_TESTS "Build tests." ON)

option(HAVE_LIBSODIUM "use and link installed shared libsodium library" OFF)

message("project version: ${PROJECT_VERSION}")
message("git info:")
message("   branch : ${GIT_BRANCH}")
message("     hash : ${GIT_COMMIT_HASH}")
message("	  date : ${BUILD_DATE}")

message("")
message("using ${CMAKE_GENERATOR}")

if (WIN32)
    if(MINGW)
        #on server 2016 msvcrt.dll does not process %z formatting
        #that can lead to a crash if the string format is something like: %zd(%s)
        add_compile_definitions(__USE_MINGW_ANSI_STDIO=1)
    endif()
    set(CMAKE_INSTALL_LIBDIR lib)
    set(CMAKE_INSTALL_INCLUDEDIR include)
    if(NOT CMAKE_INSTALL_PREFIX)
        message("WIN32 build. Creating: ${CMAKE_BINARY_DIR}/cmake_install")
        file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/cmake_install)
        message("WIN32 build. Creating: ${CMAKE_BINARY_DIR}/cmake_install/ziti-sdk-${PROJECT_VERSION}")
        file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/cmake_install/ziti-sdk-${PROJECT_VERSION})
        set(CMAKE_INSTALL_PREFIX ${CMAKE_BINARY_DIR}/cmake_install/ziti-sdk-${PROJECT_VERSION})
    endif()
else()
    set(CMAKE_INSTALL_PREFIX /opt/openziti/ziti-sdk-${PROJECT_VERSION})
endif()

message("cross-compiling ${CMAKE_CROSSCOMPILING}")

enable_testing()

if (DEFINED ENV{BUILD_NUMBER})
    set(ZITI_BUILDNUM $ENV{BUILD_NUMBER})
endif ()

link_directories(${CMAKE_BINARY_DIR}/lib)

add_subdirectory(deps)

set(CPACK_INSTALL_CMAKE_PROJECTS
        "${CMAKE_CURRENT_BINARY_DIR};${PROJECT_NAME};ziti-sdk;/"
        )
set(CPACK_PACKAGE_NAME ${PROJECT_NAME})
set(CPACK_INCLUDE_TOPLEVEL_DIRECTORY 0)
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_OUTPUT_FILE_PREFIX ${CMAKE_BINARY_DIR}/package)
set(CPACK_GENERATOR "ZIP")
set(archive_sfx "zip")

find_program(ZIP NAMES 7z)
if (ZIP)
    set(ZIP_OPTS a -tzip)
else ()
    find_program(ZIP NAMES zip)
    if (ZIP)
        set(ZIP_OPTS "-jv")
    else ()
        message("zip program not found")
    endif ()
endif ()

set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-${CMAKE_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR}")

include(CPack)

# use prefix length to trim path for logging, see utils.c
if (CMAKE_GENERATOR STREQUAL "Ninja" AND CMAKE_BINARY_DIR MATCHES "${CMAKE_SOURCE_DIR}")
    # if CMAKE_BINARY_DIR is inside CMAKE_SOURCE_DIR Ninja uses relative paths which screws logging of the filename
    # so we just leave it be -- it shows enough information to find the source
    set(SOURCE_PATH_SIZE 0)
else()
    string(LENGTH "${CMAKE_SOURCE_DIR}/" SOURCE_PATH_SIZE)
endif()

add_subdirectory(library)

if (ZITI_BUILD_PROGRAMS)
    add_subdirectory(programs)
endif ()

if (ZITI_BUILD_TESTS)
    add_subdirectory(tests)
endif ()

if (EXISTS "${CMAKE_CURRENT_LIST_DIR}/local.cmake")
    include("${CMAKE_CURRENT_LIST_DIR}/local.cmake")
endif ()

