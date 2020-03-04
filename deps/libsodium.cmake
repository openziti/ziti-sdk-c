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
                COMMAND "${libsodium_SOURCE_DIR}/configure" "--prefix=${libsodium_BINARY_DIR}" --enable-debug --host=${triple}
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