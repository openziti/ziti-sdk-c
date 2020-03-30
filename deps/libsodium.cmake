include(FetchContent)

if (WIN32)
FetchContent_Declare (
        libsodium
        URL https://download.libsodium.org/libsodium/releases/libsodium-1.0.18-stable-mingw.tar.gz
    )
else()
FetchContent_Declare (
        libsodium
        GIT_REPOSITORY http://github.com/jedisct1/libsodium
        GIT_TAG stable
)
endif()

FetchContent_GetProperties(libsodium)

if(NOT libsodium_POPULATED)
    FetchContent_Populate(libsodium)
    if (NOT WIN32)
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
endif()

add_library(sodium IMPORTED STATIC GLOBAL)

if (WIN32)
    target_include_directories(sodium INTERFACE ${libsodium_SOURCE_DIR}/libsodium-win64/include)
    target_compile_definitions(sodium INTERFACE SODIUM_STATIC)
    target_link_directories(sodium INTERFACE ${libsodium_SOURCE_DIR}/libsodium-win64/lib)
    set_target_properties(sodium PROPERTIES IMPORTED_LOCATION ${libsodium_SOURCE_DIR}/libsodium-win64/lib/libsodium.a)
else()
    target_include_directories(sodium INTERFACE ${libsodium_BINARY_DIR}/include)
    set_target_properties(sodium PROPERTIES IMPORTED_LOCATION ${libsodium_BINARY_DIR}/lib/libsodium.a)
endif()