cmake_minimum_required(VERSION 3.22)

include(cmake/version.cmake)
get_version(${CMAKE_CURRENT_LIST_DIR}/version.txt GIT_VERSION GIT_BRANCH GIT_COMMIT_HASH)

project(ziti-sdk
        DESCRIPTION "OpenZiti C SDK"
        HOMEPAGE_URL "https://github.com/openziti/ziti-sdk-c"
        LANGUAGES C CXX
)

set(PROJECT_VERSION ${GIT_VERSION})
include(cmake/variables.cmake)

set(tlsuv_DIR "" CACHE FILEPATH "developer option: use local tlsuv checkout")
# developer setting: tlsuv branch or tag to use (if tlsuv_DIR is unset)
if (NOT tlsuv_VERSION)
    set(tlsuv_VERSION "v0.40.10")
endif (NOT tlsuv_VERSION)

message("project version: ${PROJECT_VERSION}")
message("git info:")
message(" branch : ${GIT_BRANCH}")
message("   hash : ${GIT_COMMIT_HASH}")

message("")
message("using ${CMAKE_GENERATOR}")

if (ziti_DEVELOPER_MODE)
    set(complist GNU Clang AppleClang)
    if (CMAKE_C_COMPILER_ID IN_LIST complist)
        option(ziti_ASAN "build with sanitizers")
        option(ziti_TEST_COVERAGE "enable test coverage")
    endif ()
    unset(complist)
endif ()

if (ziti_ASAN)
    if (MSVC)
        add_compile_options(/fsanitize=address)
        add_compile_definitions(
                _DISABLE_VECTOR_ANNOTATION
                _DISABLE_STRING_ANNOTATION
        )
    else ()
        add_compile_options(-fsanitize=address -fno-omit-frame-pointer)
        add_link_options(-fsanitize=address)
    endif ()
endif (ziti_ASAN)

if (ziti_TEST_COVERAGE)
    add_compile_options(--coverage)
    add_link_options(--coverage)
endif (ziti_TEST_COVERAGE)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

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

set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CMAKE_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR}")

if(NOT CPack_CMake_INCLUDED)
    include(CPack)
endif()

# use prefix length to trim path for logging, see utils.c
if (CMAKE_GENERATOR STREQUAL "Ninja" AND CMAKE_BINARY_DIR MATCHES "${CMAKE_SOURCE_DIR}")
    # if CMAKE_BINARY_DIR is inside CMAKE_SOURCE_DIR Ninja uses relative paths which screws logging of the filename
    # so we just leave it be -- it shows enough information to find the source
    set(SOURCE_PATH_SIZE 0)
else()
    string(LENGTH "${CMAKE_SOURCE_DIR}/" SOURCE_PATH_SIZE)
endif()

add_subdirectory(library)

if (PROJECT_IS_TOP_LEVEL)
    option(BUILD_EXAMPLES "Build examples tree." "${ziti_DEVELOPER_MODE}")
    if (BUILD_EXAMPLES)
        add_subdirectory(programs)
    endif ()
endif ()

if (ziti_DEVELOPER_MODE AND NOT CMAKE_CROSSCOMPILING)
    ENABLE_TESTING()
    add_subdirectory(tests)
endif ()

if (ziti-sdk_IS_TOP_LEVEL AND EXISTS "${CMAKE_CURRENT_LIST_DIR}/local.cmake")
    include("${CMAKE_CURRENT_LIST_DIR}/local.cmake")
endif ()

