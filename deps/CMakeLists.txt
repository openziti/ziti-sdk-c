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


#ExternalProject_Add(libsodium_proj
#        GIT_REPOSITORY http://github.com/jedisct1/libsodium
#        GIT_TAG stable
#        BUILD_IN_SOURCE true
#        CONFIGURE_COMMAND <SOURCE_DIR>/configure --prefix=${CMAKE_BINARY_DIR}
#        BUILD_COMMAND make
#        INSTALL_COMMAND make install
#        PREFIX=${CMAKE_CURRENT_BINARY_DIR}/libsodium-stable
#        )
#
#ExternalProject_Get_Property(libsodium_proj binary_dir)
#
#message("libsodium binary_dir = ${binary_dir}")
#
#add_library(sodium IMPORTED STATIC GLOBAL)
#
#target_include_directories(sodium INTERFACE
#        $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>)
#
#
##set_property(TARGET sodium PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_BINARY_DIR}/include)
#set_target_properties(sodium PROPERTIES IMPORTED_LOCATION ${CMAKE_BINARY_DIR}/lib)
#
#
#add_dependencies(sodium libsodium_proj)

include(FetchContent)

FetchContent_Declare (
        libsodium
        GIT_REPOSITORY http://github.com/jedisct1/libsodium
        GIT_TAG stable
)

FetchContent_GetProperties(libsodium)

if(NOT libsodium_POPULATED)
    FetchContent_Populate(libsodium)

    if(NOT EXISTS ${libsodium_BINARY_DIR}/config.status)
        execute_process(
                COMMAND "${libsodium_SOURCE_DIR}/configure" "--prefix=${libsodium_BINARY_DIR}" --enable-debug
                WORKING_DIRECTORY ${libsodium_BINARY_DIR}
        )
    endif()
    execute_process(
            COMMAND make
            WORKING_DIRECTORY ${libsodium_BINARY_DIR}
    )
    execute_process(
            COMMAND make install
            WORKING_DIRECTORY ${libsodium_BINARY_DIR}
    )
endif()

add_library(sodium IMPORTED STATIC GLOBAL)
target_include_directories(sodium INTERFACE ${libsodium_BINARY_DIR}/include)
set_target_properties(sodium PROPERTIES IMPORTED_LOCATION ${libsodium_BINARY_DIR}/lib/libsodium.a)


