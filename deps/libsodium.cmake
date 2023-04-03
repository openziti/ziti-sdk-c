include(FetchContent)

if (WIN32)
    if(CMAKE_C_COMPILER_ID STREQUAL "MSVC")
        if(CMAKE_EXE_LINKER_FLAGS MATCHES "/machine:x64")
            set(arch "x64")
        else()
            set(arch "Win32")
        endif()
        if(CMAKE_BUILD_TYPE)
            set(build_type ${CMAKE_BUILD_TYPE})
        else()
            set(build_type "Debug")
        endif()
        if (NOT CMAKE_SYSTEM_PROCESSOR STREQUAL "ARM64")
            FetchContent_Declare (
                    libsodium
                    URL	https://download.libsodium.org/libsodium/releases/libsodium-1.0.18-stable-msvc.zip
            )
            set(libsodium_include_path include)
            set(libsodium_lib_path ${arch}/${build_type}/v${MSVC_TOOLSET_VERSION}/static/libsodium${CMAKE_STATIC_LIBRARY_SUFFIX})
        else()
            # arm builds are not included in libsodium release tarballs (yet?), so we need to build it.
            # windows/arm build support has been added to master, but not stable. See https://github.com/jedisct1/libsodium/pull/1130
            set(arch "ARM64")
            FetchContent_Declare (
                    libsodium
                    GIT_REPOSITORY http://github.com/jedisct1/libsodium
                    GIT_TAG master
            )
            set(libsodium_include_path src/libsodium/include)
            # v142 matches toolset version that's used in libsodium.sln below. vs2019 --> v142.
            set(libsodium_lib_path bin/${arch}/${build_type}/v142/static/libsodium${CMAKE_STATIC_LIBRARY_SUFFIX})
        endif()
    else()
        FetchContent_Declare (
                libsodium
                URL	https://download.libsodium.org/libsodium/releases/libsodium-1.0.18-stable-mingw.tar.gz
        )
        set(libsodium_include_path libsodium-win64/include)
        set(libsodium_lib_path libsodium-win64/lib/libsodium.a)
    endif()
    message("libsodium = ${libsodium_lib_path}")
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
    if (NOT EXISTS ${libsodium_BINARY_DIR})
        file(MAKE_DIRECTORY	${libsodium_BINARY_DIR})
    endif ()
    # perform the build if the source was fetched.
    if (EXISTS ${libsodium_SOURCE_DIR}/src)
        if (NOT EXISTS ${libsodium_BINARY_DIR}/config.status)
            if (NOT CMAKE_C_COMPILER_ID STREQUAL "MSVC")
                # first build on macos fails because CMake picks up xcode
                if (APPLE)
                    unset(ENV{CC})
                    unset(ENV{CXX})
                endif()
                execute_process(
                        COMMAND "${libsodium_SOURCE_DIR}/configure" "--prefix=${libsodium_BINARY_DIR}"
                        --disable-opt --without-pthreads --with-pic --host=${triple}
                        --with-sysroot=${CMAKE_SYSROOT}
                        COMMAND_ECHO STDOUT
                        COMMAND_ERROR_IS_FATAL ANY
                        WORKING_DIRECTORY ${libsodium_BINARY_DIR}
                )
                execute_process(
                        COMMAND make -j4
                        COMMAND_ECHO STDOUT
                        COMMAND_ERROR_IS_FATAL ANY
                        WORKING_DIRECTORY ${libsodium_BINARY_DIR}
                )
                execute_process(
                        COMMAND make install
                        COMMAND_ECHO STDOUT
                        COMMAND_ERROR_IS_FATAL ANY
                        WORKING_DIRECTORY ${libsodium_BINARY_DIR}
                )
            else()
                execute_process(
                        COMMAND msbuild ${libsodium_SOURCE_DIR}/builds/msvc/vs2019/libsodium.sln -property:Configuration=Static${build_type} -property:Platform=${arch}
                        COMMAND_ECHO STDOUT
                        COMMAND_ERROR_IS_FATAL ANY
                        WORKING_DIRECTORY ${libsodium_BINARY_DIR}
                )
            endif()
        endif()
    endif()
endif ()

add_library(sodium IMPORTED STATIC GLOBAL)

if (WIN32)
    target_include_directories(sodium INTERFACE ${libsodium_SOURCE_DIR}/${libsodium_include_path})
    target_compile_definitions(sodium INTERFACE SODIUM_STATIC)
    #target_link_directories(sodium INTERFACE ${libsodium_SOURCE_DIR})
    set_target_properties(sodium PROPERTIES	IMPORTED_LOCATION ${libsodium_SOURCE_DIR}/${libsodium_lib_path})
else()
    target_include_directories(sodium INTERFACE ${libsodium_BINARY_DIR}/include)
    set_target_properties(sodium PROPERTIES IMPORTED_LOCATION ${libsodium_BINARY_DIR}/lib/libsodium.a)
endif()
