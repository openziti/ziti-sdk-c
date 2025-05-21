include(FindPkgConfig)
find_package(PkgConfig)

if (TARGET sodium)
    set(sodium_libs sodium)
else ()
    # prefer package config (libsodium provided)
    # over unofficial VCPKG CMake Config
    pkg_check_modules(sodium IMPORTED_TARGET libsodium)
    if (sodium_FOUND)
        set(sodium_libs PkgConfig::sodium)
        message("sodium[${sodium_VERSION}] is ${sodium_LINK_LIBRARIES}")
    else ()
        find_package(unofficial-sodium REQUIRED)
        set(sodium_libs unofficial-sodium::sodium)
        get_target_property(sodium_loc unofficial-sodium::sodium LOCATION)
        message("sodium is ${sodium_loc}")
    endif ()
endif ()
if (NOT sodium_libs)
    message(FATAL_ERROR "could not find required library[sodium]")
endif ()

pkg_check_modules(PBUFC REQUIRED IMPORTED_TARGET libprotobuf-c)

if (ziti_DEVELOPER_MODE)
    find_program(PROTO_GEN protoc)
    find_program(PROTO_GEN_C protoc-gen-c)
    if (PROTO_GEN AND PROTO_GEN_C)
        message(NOTICE "protobuf generator: ${PROTO_GEN}")
        FetchContent_Declare(sdk_golang
                GIT_REPOSITORY https://github.com/openziti/sdk-golang.git
                GIT_TAG main
                GIT_SHALLOW 1
        )
        FetchContent_MakeAvailable(sdk_golang)

        set(PROTO_FILES
                edge_client.proto
                google/protobuf/timestamp.proto
        )
        add_custom_target(generate-protobuf
                WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/proto
                COMMAND protoc --c_out=. -I ${PBUFC_INCLUDE_DIRS} -I ${sdk_golang_SOURCE_DIR}/pb/edge_client_pb ${PROTO_FILES}
        )
        message(NOTICE "dev mode: use generate-protobuf target to update protobuf objects")
    endif ()
endif ()

find_package(json-c CONFIG REQUIRED)

set(ZITI_HEADER_FILES
        ${PROJECT_SOURCE_DIR}/includes/ziti/errors.h
        ${PROJECT_SOURCE_DIR}/includes/ziti/ziti.h
        ${PROJECT_SOURCE_DIR}/includes/ziti/enums.h
        ${PROJECT_SOURCE_DIR}/includes/ziti/ziti_src.h
        ${PROJECT_SOURCE_DIR}/includes/ziti/ziti_events.h
        ${PROJECT_SOURCE_DIR}/includes/ziti/ziti_buffer.h
        ${PROJECT_SOURCE_DIR}/includes/ziti/zitilib.h
        ${PROJECT_SOURCE_DIR}/includes/ziti/model_collections.h
        ${PROJECT_SOURCE_DIR}/includes/ziti/types.h
        )

SET(ZITI_SRC_FILES
        sdk_info.c
        utils.c
        ziti.c
        config.c
        errors.c
        ziti_enroll.c
        ziti_ctrl.c
        model_support.c
        internal_model.c
        connect.c
        channel.c
        message.c
        buffer.c
        ziti_src.c
        metrics.c
        posture.c
        auth_queries.c
        conn_bridge.c
        zitilib.c
        pool.c
        model_collections.c
        authenticators.c
        crypto.c
        bind.c
        oidc.c
        proto/edge_client.pb-c.c
        proto/google/protobuf/timestamp.pb-c.c
        legacy_auth.c
        ha_auth.c
        util/future.c
        external_auth.c
        edge_protocol.c
        )

SET(ZITI_INCLUDE_DIRS
    PUBLIC ../includes
    PRIVATE ../inc_internal
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/proto
    PRIVATE ${PROJECT_BINARY_DIR}/include
    PRIVATE ${tlsuv_SOURCE_DIR}/src
)

set(ziti_compile_defs
        ZITI_VERSION=${PROJECT_VERSION}
        ZITI_BRANCH=${GIT_BRANCH}
        ZITI_COMMIT=${GIT_COMMIT_HASH}
        PRIVATE ZITI_LOG_MODULE="${PROJECT_NAME}"
)

function(config_ziti_library target)
    target_sources(${target} PRIVATE
            ${ZITI_SRC_FILES}
            ${ZITI_HEADER_FILES})

    if (WIN32)
        set_target_properties(${target} PROPERTIES PREFIX "")
        #without this libsodium was complaining:
    endif ()

    set_target_properties(${target} PROPERTIES
            C_STANDARD 11
            POSITION_INDEPENDENT_CODE ON
            C_VISIBILITY_PRESET hidden
            CXX_VISIBILITY_PRESET hidden
    )

    target_sources(${target} PRIVATE ${ZITI_PRIVATE_SRC_FILES})

    target_link_libraries(${target} PUBLIC
            tlsuv
            ${sodium_libs}
            json-c::json-c
            PkgConfig::PBUFC
    )

    if (CMAKE_SYSTEM_NAME MATCHES "Linux")
        target_link_libraries(${target} PUBLIC atomic)
    endif ()

    if (NOT WIN32)
        target_link_libraries(${target} PUBLIC m)
    endif ()

    target_include_directories(${target} ${ZITI_INCLUDE_DIRS})
    target_compile_definitions(${target} PUBLIC
            ${ziti_compile_defs}
    )

    if (WIN32)
        # on windows GDI defines ERROR which conflicts with the SDK declaration of DEBUG_LEVELS in utils.h
        target_compile_definitions(${target} PUBLIC NOGDI _CRT_NONSTDC_NO_DEPRECATE)
        target_link_libraries(${target} PUBLIC crypt32 netapi32)
    endif ()

    if (MSVC)
        target_compile_options(${target} PUBLIC /experimental:c11atomics)
    endif (MSVC)

    install(TARGETS ${target}
            COMPONENT ziti-sdk
            DESTINATION ${CMAKE_INSTALL_LIBDIR}
    )
endfunction(config_ziti_library)

add_library(ziti STATIC)
config_ziti_library(ziti)

if (BUILD_SHARED_LIBS)
    add_library(ziti_dll SHARED)
    config_ziti_library(ziti_dll)
    set_target_properties(ziti_dll PROPERTIES OUTPUT_NAME "ziti")

    # when building on windows an "import library" is generated which is overwriting the
    # static library (ziti.lib) (google/see /IMPLIB (Name Import Library))
    # work around discovered at stack overflow:
    #     https://stackoverflow.com/questions/34575066/how-to-prevent-cmake-from-issuing-implib
    #
    # I chose to set the suffix and not the prefix
    # set_target_properties(ziti_dll PROPERTIES IMPORT_PREFIX "import-lib-")
    set_target_properties(ziti_dll PROPERTIES
            IMPORT_SUFFIX ".imp.lib"
            OUTPUT_NAME "ziti")

    target_compile_definitions(ziti_dll PUBLIC
            INTERFACE USING_ZITI_SHARED=1
            PRIVATE BUILDING_ZITI_SHARED=1
    )
endif ()

set(includedir ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_INCLUDEDIR})
set(libdir ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR})
set(prefix ${CMAKE_INSTALL_PREFIX})

configure_file(${PROJECT_SOURCE_DIR}/ziti.pc.in ${CMAKE_CURRENT_BINARY_DIR}/ziti.pc @ONLY)

set(CMAKE_INSTALL_DOCDIR share/doc)

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/../includes/
        COMPONENT ziti-sdk
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/ziti.pc DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

