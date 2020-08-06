project(ziti-deps)

include(FetchContent)
FetchContent_Declare(uv-mbed
        GIT_REPOSITORY https://github.com/netfoundry/uv-mbed.git
        GIT_TAG v0.7.0
        )
set(ENABLE_UM_TESTS OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(uv-mbed)


add_library(subcommand INTERFACE)
target_include_directories(subcommand INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/subcommand)


include(libsodium.cmake)


