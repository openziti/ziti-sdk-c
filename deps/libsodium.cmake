include(FetchContent)

if (WIN32)

    if(CMAKE_C_COMPILER_ID STREQUAL "MSVC")
        if (NOT CMAKE_EXE_LINKER_FLAGS MATCHES "/machine:ARM64")
            FetchContent_Declare (
                    libsodium
                    URL	https://download.libsodium.org/libsodium/releases/libsodium-1.0.18-stable-msvc.zip
            )
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

            set(libsodium_include_path include)
            set(libsodium_lib_path ${arch}/${build_type}/v${MSVC_TOOLSET_VERSION}/static/libsodium${CMAKE_STATIC_LIBRARY_SUFFIX})
            message("libsodium = ${libsodium_lib_path}")
        else()
            # arm builds are not included in libsodium release tarballs (yet?), so we need to build it.
            # windows/arm build support has been added to master, but not stable (yet?) (https://github.com/jedisct1/libsodium/pull/1130)
            set(arch "ARM64")
            FetchContent_Declare (
                    libsodium
                    GIT_REPOSITORY http://github.com/jedisct1/libsodium
                    GIT_TAG master
            )
            set(libsodium_include_path src/libsodium/include)
            # bin\ARM64\Debug\v142\static
            set(libsodium_lib_path bin/${arch}/${CMAKE_BUILD_TYPE}/v${MSVC_TOOLSET_VERSION}/static/libsodium${CMAKE_STATIC_LIBRARY_SUFFIX})
        endif()
    else()
        FetchContent_Declare (
                libsodium
                URL	https://download.libsodium.org/libsodium/releases/libsodium-1.0.18-stable-mingw.tar.gz
        )
        set(libsodium_include_path libsodium-win64/include)
        set(libsodium_lib_path libsodium-win64/lib/libsodium.a)
    endif()
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
    if (NOT WIN32)
        if (NOT EXISTS ${libsodium_BINARY_DIR}/config.status)
            # first build on macos fails because CMake picks up xcode
            if (APPLE)
                unset(ENV{CC})
                unset(ENV{CXX})
            endif()
            execute_process(
                    COMMAND "${libsodium_SOURCE_DIR}/configure" "--prefix=${libsodium_BINARY_DIR}"
                    --disable-opt --without-pthreads --with-pic --host=${triple}
                    --with-sysroot=${CMAKE_SYSROOT}
                    WORKING_DIRECTORY ${libsodium_BINARY_DIR}
            )
        endif()
        execute_process(
                COMMAND make -j4
                WORKING_DIRECTORY ${libsodium_BINARY_DIR}
        )
        execute_process(
                COMMAND make install
                WORKING_DIRECTORY ${libsodium_BINARY_DIR}
        )
    else()
        execute_process(
                COMMAND msbuild ${libsodium_SOURCE_DIR}/builds/msvc/vs2019/libsodium.sln -property:Configuration=StaticDebug -property:Platform=${arch}
                WORKING_DIRECTORY ${libsodium_BINARY_DIR}
        )
    endif ()
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
