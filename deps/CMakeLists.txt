project(ziti-deps)

include(FetchContent)

FetchContent_Declare(tlsuv
        GIT_REPOSITORY https://github.com/openziti/tlsuv.git
        GIT_TAG v0.23.3
        )
FetchContent_MakeAvailable(tlsuv)


FetchContent_Declare(subcommand
        GIT_REPOSITORY https://github.com/openziti/subcommands.c.git
        GIT_TAG main
        )
FetchContent_GetProperties(subcommand)
if (NOT subcommand_POPULATED)
    FetchContent_Populate(subcommand)
endif ()
add_library(subcommand INTERFACE)
target_include_directories(subcommand INTERFACE ${subcommand_SOURCE_DIR})




