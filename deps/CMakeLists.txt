
include(FetchContent)

if (tlsuv_DIR)
    add_subdirectory(${tlsuv_DIR}
            ${CMAKE_CURRENT_BINARY_DIR}/tlsuv)
else ()

    FetchContent_Declare(tlsuv
            GIT_REPOSITORY https://github.com/openziti/tlsuv.git
            GIT_TAG v0.28.5
            )
    FetchContent_MakeAvailable(tlsuv)

endif (tlsuv_DIR)

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




