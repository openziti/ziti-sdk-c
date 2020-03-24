cmake_minimum_required (VERSION 3.12)
include(git.cmake)

project (ziti-sdk
        VERSION ${ver}
        LANGUAGES C CXX
        )

message("project version: ${PROJECT_VERSION}")
message("git info:")
message("   branch : ${GIT_BRANCH}")
message("     hash : ${GIT_COMMIT_HASH}")
message("     date : ${BUILD_DATE}")

if (WIN32)
    set(CMAKE_INSTALL_LIBDIR lib)
    set(CMAKE_INSTALL_INCLUDEDIR include)
    message("WIN32 build. Creating: ${CMAKE_BINARY_DIR}/cmake_install")
    file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/cmake_install)
    message("WIN32 build. Creating: ${CMAKE_BINARY_DIR}/cmake_install/ziti-sdk-${PROJECT_VERSION}")
    file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/cmake_install/ziti-sdk-${PROJECT_VERSION})
    set(CMAKE_INSTALL_PREFIX ${CMAKE_BINARY_DIR}/cmake_install/ziti-sdk-${PROJECT_VERSION})
    # TODO 
    # add_subdirectory(windows)
else()
    set(CMAKE_INSTALL_PREFIX /opt/netfoundry/ziti-sdk-${PROJECT_VERSION})
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

set(CPACK_INCLUDE_TOPLEVEL_DIRECTORY 0)
set(CPACK_PACKAGE_VERSION ${ZITI_VERSION})
set(CPACK_OUTPUT_FILE_PREFIX ${CMAKE_CURRENT_BINARY_DIR})
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

# use prefix length to trim path for logging, see inc_internal/utils.h __FILENAME__
string(LENGTH "${CMAKE_SOURCE_DIR}/" SOURCE_PATH_SIZE)
add_definitions("-DSOURCE_PATH_SIZE=${SOURCE_PATH_SIZE}")

add_subdirectory(library)

if(NOT ${PUB_OS} STREQUAL "ios" )
    add_subdirectory(programs)
endif()

if(NOT ${CMAKE_CROSSCOMPILING})
    add_subdirectory(tests)
endif()

PUBCOMP(ziti-sdk)

