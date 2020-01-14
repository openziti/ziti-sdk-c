project(ziti-deps)

include(ExternalProject)

set(ENABLE_UM_TESTS OFF CACHE BOOL "" FORCE)
add_subdirectory(uv-mbed)

add_library(subcommand INTERFACE)
target_include_directories(subcommand INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/subcommand)

## Testing library
# need to preprocess that to be able to use Cmake integration later
execute_process(COMMAND "mkdir" "${CMAKE_CURRENT_BINARY_DIR}/Catch2")
execute_process(COMMAND "${CMAKE_COMMAND}" -G "${CMAKE_GENERATOR}"
        -DCATCH_BUILD_TESTING=OFF
        -DCATCH_INSTALL_DOCS=OFF
        -DCMAKE_INSTALL_PREFIX=${PROJECT_BINARY_DIR}/Catch2
        ${PROJECT_SOURCE_DIR}/Catch2
        WORKING_DIRECTORY "${PROJECT_BINARY_DIR}/Catch2")

execute_process(COMMAND "${CMAKE_COMMAND}" --build . --target install
        WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/Catch2")
