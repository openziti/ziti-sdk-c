project(ziti-deps)

include(ExternalProject)

set(ENABLE_UM_TESTS OFF CACHE BOOL "" FORCE)

add_subdirectory(uv-mbed)

add_library(subcommand INTERFACE)
target_include_directories(subcommand INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/subcommand)


include(libsodium.cmake)


