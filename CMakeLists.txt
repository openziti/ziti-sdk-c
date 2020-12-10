cmake_minimum_required(VERSION 3.12)
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
else ()
    set(ZITI_BUILDNUM local)
endif ()

set(ZITI_VERSION ${PROJECT_VERSION}-${ZITI_BUILDNUM})

link_directories(${CMAKE_BINARY_DIR}/lib)

add_subdirectory(deps)

set(CPACK_PACKAGE_NAME ${PROJECT_NAME})
set(CPACK_INCLUDE_TOPLEVEL_DIRECTORY 0)
set(CPACK_PACKAGE_VERSION ${ZITI_VERSION})
set(CPACK_OUTPUT_FILE_PREFIX ${CMAKE_BINARY_DIR})
if (UNIX)
    set(CPACK_GENERATOR "TGZ")
    set(archive_sfx "tar.gz")
elseif (WIN32)
    set(CPACK_GENERATOR "ZIP")
    set(archive_sfx "zip")
endif ()

include(CPack)
add_custom_target(publish
        COMMENT "generate publish specs"
        )

if(${GIT_BRANCH} STREQUAL master)
    set(PUB_PFX ziti-staging)
else()
    set(PUB_PFX ziti-snapshot/${GIT_BRANCH})
endif()

set(PUB_OPTS --apikey=$ENV{JFROG_API_KEY} --url https://netfoundry.jfrog.io/netfoundry --build-name=ziti --build-number=${ZITI_VERSION})
string(TOLOWER ${CMAKE_SYSTEM_NAME} PUB_OS)
string(TOLOWER ${CMAKE_SYSTEM_PROCESSOR} PUB_ARCH)

if(${PUB_ARCH} STREQUAL "x86_64" )
    set(PUB_ARCH "amd64")
endif()

macro(PUBCOMP comp)
    set(${comp}_PUB_PATH ${PUB_PFX}/${comp}/${PUB_ARCH}/${PUB_OS}/${ZITI_VERSION}/${comp}.${archive_sfx})
    set(${comp}_PUB_PROPS "version=${ZITI_VERSION}\;name=${comp}\;arch=${PUB_ARCH}\;os=${PUB_OS}\;branch=${GIT_BRANCH}")

    add_custom_target(${comp}-pub
            BYPRODUCTS ${CMAKE_BINARY_DIR}/${comp}-pub-spec.json
            DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/${comp}-${ZITI_VERSION}-${CPACK_SYSTEM_NAME}.${archive_sfx}
            COMMAND echo "{"
            \"target\": \"${${comp}_PUB_PATH}\",
            \"pattern\": \"${CMAKE_CURRENT_BINARY_DIR}/${comp}-${ZITI_VERSION}-${CPACK_SYSTEM_NAME}.${archive_sfx}\",
            \"props\": \"${${comp}_PUB_PROPS}\"
            "}" > ${CMAKE_BINARY_DIR}/${comp}-pub-spec.json
            VERBATIM
            )

    add_dependencies(publish ${comp}-pub)
endmacro(PUBCOMP)

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
    if (NOT ${PUB_OS} STREQUAL "ios")
        add_subdirectory(programs)
    endif ()
endif ()

if (ZITI_BUILD_TESTS)
    add_subdirectory(tests)
endif ()

