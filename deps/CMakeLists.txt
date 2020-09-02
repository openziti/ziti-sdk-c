project(ziti-deps)

include(FetchContent)

FetchContent_Declare(uv-mbed
        GIT_REPOSITORY https://github.com/netfoundry/uv-mbed.git
        GIT_TAG v0.9.0
        )
set(ENABLE_UM_TESTS OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(uv-mbed)


FetchContent_Declare(subcommand
        GIT_REPOSITORY https://github.com/dimitri/subcommands.c.git
        GIT_TAG master
        )
FetchContent_GetProperties(subcommand)
if (NOT subcommand_POPULATED)
    FetchContent_Populate(subcommand)
endif ()
add_library(subcommand INTERFACE)
target_include_directories(subcommand INTERFACE ${subcommand_SOURCE_DIR})


if (NOT HAVE_LIBSODIUM)
    include(libsodium.cmake)
endif ()


